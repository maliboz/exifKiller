"""
Native, pure-Python metadata stripping for TIFF and TIFF-based camera RAW.

Covers CR2, NEF/NRW, ARW/SR2/SRF, DNG, ORF, RW2, PEF, SRW, 3FR, MEF, ERF, DCR,
KDC, MOS, and plain TIFF. All of them are TIFF containers: a header, then a
chain of IFDs (tag directories), with the actual sensor data parked elsewhere in
the file and referenced by absolute byte offsets (StripOffsets/TileOffsets).

Those absolute offsets are why rewriting a RAW file is dangerous: repacking the
directories shifts everything after them and silently corrupts an irreplaceable
original. So this engine never moves a byte.

Removing a tag is done by compacting the IFD entry array in place:

    [count=N][entry 0][entry 1]...[entry N-1][next-IFD offset]
    [count=M][kept entries...][next-IFD offset][dead space]

The kept entries shift up, the count drops to M, and the next-IFD pointer is
rewritten at its new position. The 12*(N-M) trailing bytes become unreferenced
padding - nothing in TIFF requires IFDs to be tightly packed. Value blobs that
lived outside the entry array are zeroed only once we have confirmed no
surviving tag still points into them.

Net effect: the file size never changes, every offset stays valid, and the raw
sensor data is bit-for-bit identical.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Set, Tuple

from .lossless_image import LosslessStripError, _jpeg_keep_segment, strip_jpeg


class TiffError(Exception):
    """Raised when a file cannot be parsed as TIFF/RAW."""


# --------------------------------------------------------------------------- #
# TIFF primitives
# --------------------------------------------------------------------------- #

_TYPE_SIZES = {
    1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1, 7: 1, 8: 2,
    9: 4, 10: 8, 11: 4, 12: 8, 13: 4,
}

# Magic numbers of TIFF and its RAW dialects. BigTIFF (43) is refused below.
_TIFF_MAGIC = 42
_ACCEPTED_MAGIC = {
    _TIFF_MAGIC,
    0x55,    # Panasonic RW2
    0x4F52,  # Olympus ORF ("IIRO")
    0x5352,  # Olympus ORF ("IIRS")
    0x4F1A,  # Olympus ORF variant
}
_BIGTIFF_MAGIC = 43

# Pointer tags whose value is the offset of another IFD.
TAG_EXIF_IFD = 34665
TAG_GPS_IFD = 34853
TAG_INTEROP_IFD = 40965
TAG_SUB_IFDS = 330

_IFD_POINTER_TAGS = {TAG_EXIF_IFD, TAG_GPS_IFD, TAG_INTEROP_IFD, TAG_SUB_IFDS}

# Structural tags consulted while deciding whether an image is a preview.
TAG_NEW_SUBFILE_TYPE = 254
TAG_COMPRESSION = 259
TAG_PHOTOMETRIC = 262
TAG_STRIP_OFFSETS = 273
TAG_STRIP_BYTE_COUNTS = 279
TAG_JPEG_IF_OFFSET = 513
TAG_JPEG_IF_LENGTH = 514

# Photometric values that mean "this is raw sensor data, do not touch".
_RAW_PHOTOMETRIC = {32803, 34892}
# Photometric values that mean "this is an ordinary viewable image".
_VIEWABLE_PHOTOMETRIC = {0, 1, 2, 6}


class Entry:
    """One IFD entry."""

    __slots__ = ("tag", "type", "count", "pos", "value_offset", "value_size")

    def __init__(self, tag: int, type_: int, count: int, pos: int,
                 value_offset: Optional[int], value_size: int) -> None:
        self.tag = tag
        self.type = type_
        self.count = count
        self.pos = pos  # absolute offset of the 12-byte entry
        self.value_offset = value_offset  # None when stored inline
        self.value_size = value_size


class IFD:
    """One image file directory."""

    __slots__ = ("offset", "entries", "next_offset", "next_pos", "kind")

    def __init__(self, offset: int, entries: List[Entry], next_offset: int,
                 next_pos: int, kind: str) -> None:
        self.offset = offset
        self.entries = entries
        self.next_offset = next_offset
        self.next_pos = next_pos  # where the next-IFD pointer currently lives
        self.kind = kind  # 'main' | 'exif' | 'gps' | 'interop' | 'sub'

    def get(self, tag: int) -> Optional[Entry]:
        for entry in self.entries:
            if entry.tag == tag:
                return entry
        return None


class TiffFile:
    """A parsed TIFF/RAW container."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.little = self._read_byte_order()
        self.magic = self._u16(2)
        if self.magic == _BIGTIFF_MAGIC:
            raise TiffError("BigTIFF is not supported yet (refusing to guess)")
        if self.magic not in _ACCEPTED_MAGIC:
            raise TiffError(f"unrecognised TIFF magic: {self.magic}")
        self.ifds: List[IFD] = []
        self._parse()

    # -- primitives -------------------------------------------------------- #

    def _read_byte_order(self) -> bool:
        if len(self.data) < 8:
            raise TiffError("file too small to be TIFF")
        order = self.data[:2]
        if order == b"II":
            return True
        if order == b"MM":
            return False
        raise TiffError(
            f"not a TIFF container: expected the file to start with 'II' or "
            f"'MM' but found {order!r}. Refusing to guess at the layout - the "
            f"file is probably corrupt, truncated, or has the wrong extension"
        )

    def _u16(self, pos: int) -> int:
        return int.from_bytes(self.data[pos : pos + 2],
                              "little" if self.little else "big")

    def _u32(self, pos: int) -> int:
        return int.from_bytes(self.data[pos : pos + 4],
                              "little" if self.little else "big")

    def pack_u16(self, value: int) -> bytes:
        return value.to_bytes(2, "little" if self.little else "big")

    def pack_u32(self, value: int) -> bytes:
        return value.to_bytes(4, "little" if self.little else "big")

    # -- parsing ----------------------------------------------------------- #

    def _parse(self) -> None:
        seen: Set[int] = set()
        offset = self._u32(4)
        while offset and offset not in seen and offset + 2 <= len(self.data):
            seen.add(offset)
            ifd = self._parse_ifd(offset, "main")
            self.ifds.append(ifd)
            offset = ifd.next_offset

        # Pointer tags open further directories; walk them breadth-first.
        queue = list(self.ifds)
        while queue:
            current = queue.pop(0)
            for entry in current.entries:
                if entry.tag not in _IFD_POINTER_TAGS:
                    continue
                for target in self._pointer_targets(entry):
                    if target in seen or not target or target + 2 > len(self.data):
                        continue
                    seen.add(target)
                    kind = {
                        TAG_EXIF_IFD: "exif",
                        TAG_GPS_IFD: "gps",
                        TAG_INTEROP_IFD: "interop",
                        TAG_SUB_IFDS: "sub",
                    }[entry.tag]
                    try:
                        child = self._parse_ifd(target, kind)
                    except TiffError:
                        continue
                    self.ifds.append(child)
                    queue.append(child)

    def _pointer_targets(self, entry: Entry) -> List[int]:
        """SubIFDs can hold several offsets; the others hold exactly one."""
        if entry.value_size <= 4:
            return [self._u32(entry.pos + 8)] if entry.count >= 1 else []
        if entry.value_offset is None:
            return []
        targets = []
        for i in range(entry.count):
            pos = entry.value_offset + 4 * i
            if pos + 4 <= len(self.data):
                targets.append(self._u32(pos))
        return targets

    def _parse_ifd(self, offset: int, kind: str) -> IFD:
        count = self._u16(offset)
        entries: List[Entry] = []
        end = offset + 2 + 12 * count
        if end + 4 > len(self.data):
            raise TiffError(f"IFD at {offset} overruns the file")

        for i in range(count):
            pos = offset + 2 + 12 * i
            tag = self._u16(pos)
            type_ = self._u16(pos + 2)
            value_count = self._u32(pos + 4)
            unit = _TYPE_SIZES.get(type_, 0)
            value_size = unit * value_count
            value_offset = None
            if value_size > 4:
                value_offset = self._u32(pos + 8)
                if value_offset + value_size > len(self.data):
                    # Truncated/garbage value: keep the entry, but do not trust
                    # the range for zeroing.
                    value_offset = None
                    value_size = 0
            entries.append(Entry(tag, type_, value_count, pos, value_offset,
                                 value_size))

        return IFD(offset, entries, self._u32(end), end, kind)

    # -- value access ------------------------------------------------------ #

    def value_ints(self, entry: Entry) -> List[int]:
        """Read an entry's value as a list of integers (SHORT/LONG/BYTE)."""
        unit = _TYPE_SIZES.get(entry.type, 0)
        if unit not in (1, 2, 4) or entry.count == 0:
            return []
        base = entry.pos + 8 if entry.value_size <= 4 else entry.value_offset
        if base is None:
            return []
        out = []
        for i in range(entry.count):
            pos = base + unit * i
            if pos + unit > len(self.data):
                break
            out.append(int.from_bytes(self.data[pos : pos + unit],
                                      "little" if self.little else "big"))
        return out

    def value_int(self, ifd: IFD, tag: int) -> Optional[int]:
        entry = ifd.get(tag)
        if entry is None:
            return None
        values = self.value_ints(entry)
        return values[0] if values else None

    def value_bytes(self, entry: Entry) -> bytes:
        if entry.value_size <= 4:
            return self.data[entry.pos + 8 : entry.pos + 8 + entry.value_size]
        if entry.value_offset is None:
            return b""
        return self.data[entry.value_offset : entry.value_offset + entry.value_size]

    def value_str(self, ifd: IFD, tag: int) -> Optional[str]:
        entry = ifd.get(tag)
        if entry is None:
            return None
        raw = self.value_bytes(entry)
        text = raw.split(b"\x00")[0].decode("utf-8", "ignore").strip()
        return text or None


def is_tiff(data: bytes) -> bool:
    if len(data) < 8 or data[:2] not in (b"II", b"MM"):
        return False
    little = data[:2] == b"II"
    magic = int.from_bytes(data[2:4], "little" if little else "big")
    return magic in _ACCEPTED_MAGIC or magic == _BIGTIFF_MAGIC


# --------------------------------------------------------------------------- #
# Tag policy
# --------------------------------------------------------------------------- #

# Tags removed under every profile: pure metadata with no role in decoding.
_DROP_ALWAYS: Dict[int, str] = {
    270: "ImageDescription",
    305: "Software",
    306: "DateTime",
    315: "Artist",
    700: "XMP",
    33432: "Copyright",
    33723: "IPTC",
    34377: "PhotoshopIRB",
    37500: "MakerNote",
    37510: "UserComment",
    37520: "SubSecTime",
    37521: "SubSecTimeOriginal",
    37522: "SubSecTimeDigitized",
    36867: "DateTimeOriginal",
    36868: "DateTimeDigitized",
    40091: "XPTitle",
    40092: "XPComment",
    40093: "XPAuthor",
    40094: "XPKeywords",
    40095: "XPSubject",
    42016: "ImageUniqueID",
    42032: "CameraOwnerName",
    42033: "BodySerialNumber",
    42035: "LensMake",
    42036: "LensModel",
    42037: "LensSerialNumber",
    # DNG identity/provenance tags.
    50735: "CameraSerialNumber",
    50740: "DNGPrivateData",
    50781: "RawDataUniqueID",
    50827: "OriginalRawFileName",
    50828: "OriginalRawFileData",
    50971: "PreviewApplicationName",
    50972: "PreviewApplicationVersion",
    50973: "PreviewSettingsName",
    50974: "PreviewSettingsDigest",
}

# Removed only under the aggressive profile: real fingerprints, but RAW
# decoders use them to pick a demosaic/colour profile, so dropping them can
# make the file undecodable by some converters.
_DROP_AGGRESSIVE: Dict[int, str] = {
    271: "Make",
    272: "Model",
    34675: "ICCProfile",
    50708: "UniqueCameraModel",
    50709: "LocalizedCameraModel",
}

# The GPS directory is removed wholesale via its pointer tag.
_GPS_POINTER = TAG_GPS_IFD


def _drop_map(aggressive: bool) -> Dict[int, str]:
    drop = dict(_DROP_ALWAYS)
    if aggressive:
        drop.update(_DROP_AGGRESSIVE)
    return drop


# --------------------------------------------------------------------------- #
# Cleaning
# --------------------------------------------------------------------------- #


def clean_tiff(data: bytes, aggressive: bool = False) -> Tuple[bytes, List[str]]:
    """Strip metadata from a TIFF/RAW file without moving a single byte."""
    tiff = TiffFile(data)
    out = bytearray(data)
    removed: List[str] = []
    drop = _drop_map(aggressive)

    # Ranges belonging to removed entries, to be zeroed once we know that no
    # surviving tag points into them.
    orphan_ranges: List[Tuple[int, int]] = []
    gps_ifds = [ifd for ifd in tiff.ifds if ifd.kind == "gps"]

    # Preview stripping must run before the directories are compacted: it edits
    # entries in place, and compaction moves them to new offsets.
    if aggressive:
        removed += _strip_previews(tiff, out)

    for ifd in tiff.ifds:
        keep: List[Entry] = []
        for entry in ifd.entries:
            name = drop.get(entry.tag)
            if entry.tag == _GPS_POINTER:
                name = "GPS"
            if name is None:
                keep.append(entry)
                continue
            removed.append(name)
            if entry.value_offset is not None and entry.value_size:
                orphan_ranges.append(
                    (entry.value_offset, entry.value_offset + entry.value_size)
                )

        if len(keep) != len(ifd.entries):
            _rewrite_ifd(tiff, out, ifd, keep)

    # A removed GPS pointer orphans the whole GPS directory; wipe its bytes.
    for ifd in gps_ifds:
        end = ifd.next_pos + 4
        orphan_ranges.append((ifd.offset, end))
        for entry in ifd.entries:
            if entry.value_offset is not None and entry.value_size:
                orphan_ranges.append(
                    (entry.value_offset, entry.value_offset + entry.value_size)
                )

    _zero_orphans(tiff, out, orphan_ranges, drop)

    if not removed:
        return data, []
    return bytes(out), sorted(set(removed))


def _rewrite_ifd(tiff: TiffFile, out: bytearray, ifd: IFD,
                 keep: List[Entry]) -> None:
    """Compact an IFD's entry array in place, leaving dead space at the end.

    Entries are copied out of `out`, not the pristine input, so edits already
    applied in place (a rewritten preview byte count) are carried across.
    Kept entries only ever move to lower offsets, so the copy cannot overlap
    a source it has not read yet.
    """
    out[ifd.offset : ifd.offset + 2] = tiff.pack_u16(len(keep))
    cursor = ifd.offset + 2
    for entry in keep:
        payload = bytes(out[entry.pos : entry.pos + 12])
        out[cursor : cursor + 12] = payload
        cursor += 12

    # The next-IFD pointer follows the (now shorter) entry array.
    out[cursor : cursor + 4] = tiff.pack_u32(ifd.next_offset)
    cursor += 4

    # Everything after it, up to where the IFD used to end, is unreferenced.
    for i in range(cursor, ifd.next_pos + 4):
        out[i] = 0


def _zero_orphans(tiff: TiffFile, out: bytearray,
                  ranges: List[Tuple[int, int]],
                  drop: Dict[int, str]) -> None:
    """Zero orphaned value blobs, but never a byte a surviving tag still uses.

    `drop` must be the same map the caller removed with: protecting a tag that
    was actually removed would leave its bytes readable in the output.
    """
    protected: List[Tuple[int, int]] = []

    for ifd in tiff.ifds:
        # The directory structure itself, for IFDs we kept.
        if ifd.kind != "gps":
            protected.append((ifd.offset, ifd.next_pos + 4))
        for entry in ifd.entries:
            if entry.tag in drop or entry.tag == _GPS_POINTER:
                continue
            if entry.value_offset is not None and entry.value_size:
                protected.append(
                    (entry.value_offset, entry.value_offset + entry.value_size)
                )
            # Image data referenced by this entry must never be touched.
            if entry.tag in (TAG_STRIP_OFFSETS, 324, TAG_JPEG_IF_OFFSET):
                for start, length in _image_ranges(tiff, ifd, entry):
                    protected.append((start, start + length))

    for start, end in ranges:
        if start < 0 or end > len(out) or start >= end:
            continue
        if any(start < p_end and p_start < end for p_start, p_end in protected):
            continue  # overlaps something still in use; leave it alone
        for i in range(start, end):
            out[i] = 0


def _image_ranges(tiff: TiffFile, ifd: IFD, offsets_entry: Entry
                  ) -> List[Tuple[int, int]]:
    """Pair an offsets tag with its byte-counts tag."""
    counts_tag = {
        TAG_STRIP_OFFSETS: TAG_STRIP_BYTE_COUNTS,
        324: 325,
        TAG_JPEG_IF_OFFSET: TAG_JPEG_IF_LENGTH,
    }[offsets_entry.tag]
    counts_entry = ifd.get(counts_tag)
    if counts_entry is None:
        return []
    offsets = tiff.value_ints(offsets_entry)
    counts = tiff.value_ints(counts_entry)
    return list(zip(offsets, counts))


# --------------------------------------------------------------------------- #
# Embedded preview JPEGs
# --------------------------------------------------------------------------- #


def _is_preview_ifd(tiff: TiffFile, ifd: IFD) -> bool:
    """Decide whether an IFD holds a viewable preview rather than sensor data.

    This guard is the difference between stripping a thumbnail and destroying a
    RAW file: lossless-JPEG-compressed sensor data also starts with an SOI
    marker, and is distinguished only by its photometric interpretation.
    """
    compression = tiff.value_int(ifd, TAG_COMPRESSION)
    photometric = tiff.value_int(ifd, TAG_PHOTOMETRIC)
    if compression not in (6, 7):
        return False
    if photometric is None or photometric in _RAW_PHOTOMETRIC:
        return False
    return photometric in _VIEWABLE_PHOTOMETRIC


def _jpeg_carries_metadata(blob: bytes) -> bool:
    """Header-only scan: does this JPEG hold any metadata segment?

    Reads segment headers and stops at the scan, so it stays cheap even on a
    multi-megabyte preview.
    """
    if blob[:2] != b"\xff\xd8":
        return False
    i = 2
    n = len(blob)
    while i < n:
        if blob[i] != 0xFF:
            return False
        while i < n and blob[i] == 0xFF:
            i += 1
        if i >= n:
            return False
        marker = blob[i]
        i += 1
        if marker in (0xDA, 0xD9):  # scan begins / image ends: no metadata left
            return False
        if marker == 0x01 or 0xD0 <= marker <= 0xD7:
            continue
        if i + 2 > n:
            return False
        seg_len = int.from_bytes(blob[i : i + 2], "big")
        if seg_len < 2:
            return False
        if not _jpeg_keep_segment(marker, blob[i + 2 : i + 18], aggressive=True):
            return True
        i += seg_len
    return False


def _preview_blobs(tiff: TiffFile, ifd: IFD) -> List[bytes]:
    """The JPEG bytes of a preview IFD, if it stores exactly one."""
    blobs: List[bytes] = []
    for off_tag, cnt_tag in ((TAG_JPEG_IF_OFFSET, TAG_JPEG_IF_LENGTH),
                             (TAG_STRIP_OFFSETS, TAG_STRIP_BYTE_COUNTS)):
        offsets_entry, counts_entry = ifd.get(off_tag), ifd.get(cnt_tag)
        if offsets_entry is None or counts_entry is None:
            continue
        offsets = tiff.value_ints(offsets_entry)
        counts = tiff.value_ints(counts_entry)
        if len(offsets) != 1 or len(counts) != 1:
            continue
        start, length = offsets[0], counts[0]
        if start + length <= len(tiff.data) and length > 3:
            blobs.append(tiff.data[start : start + length])
    return blobs


def _strip_previews(tiff: TiffFile, out: bytearray) -> List[str]:
    """Strip EXIF out of embedded preview JPEGs, in place.

    The preview is rewritten at its original offset, the freed tail is zeroed,
    and its byte-count tag is updated. Offsets never move.
    """
    removed: List[str] = []

    for ifd in tiff.ifds:
        if not _is_preview_ifd(tiff, ifd):
            continue

        for offsets_tag, counts_tag in (
            (TAG_JPEG_IF_OFFSET, TAG_JPEG_IF_LENGTH),
            (TAG_STRIP_OFFSETS, TAG_STRIP_BYTE_COUNTS),
        ):
            offsets_entry = ifd.get(offsets_tag)
            counts_entry = ifd.get(counts_tag)
            if offsets_entry is None or counts_entry is None:
                continue
            offsets = tiff.value_ints(offsets_entry)
            counts = tiff.value_ints(counts_entry)
            if len(offsets) != 1 or len(counts) != 1:
                continue  # multi-strip previews are not worth the risk

            start, length = offsets[0], counts[0]
            if start + length > len(out) or length < 4:
                continue
            blob = bytes(out[start : start + length])
            if blob[:2] != b"\xff\xd8":
                continue

            try:
                stripped = strip_jpeg(blob, aggressive=True)
            except LosslessStripError:
                continue
            if len(stripped) >= len(blob) or not stripped:
                continue

            out[start : start + len(stripped)] = stripped
            for i in range(start + len(stripped), start + length):
                out[i] = 0
            if not _write_int(tiff, out, counts_entry, len(stripped)):
                # Could not update the length safely: restore and skip.
                out[start : start + length] = blob
                continue
            removed.append("PreviewEXIF")

    return removed


def _write_int(tiff: TiffFile, out: bytearray, entry: Entry, value: int) -> bool:
    """Overwrite a single-valued SHORT/LONG entry, in place."""
    if entry.count != 1:
        return False
    if entry.type == 3:  # SHORT
        if value > 0xFFFF:
            return False
        out[entry.pos + 8 : entry.pos + 10] = tiff.pack_u16(value)
        out[entry.pos + 10 : entry.pos + 12] = b"\x00\x00"
        return True
    if entry.type == 4:  # LONG
        out[entry.pos + 8 : entry.pos + 12] = tiff.pack_u32(value)
        return True
    return False


# --------------------------------------------------------------------------- #
# Description (for the metadata extractor)
# --------------------------------------------------------------------------- #

_DESCRIBE_STRINGS = {
    271: "Make",
    272: "Model",
    305: "Software",
    306: "DateTime",
    315: "Artist",
    33432: "Copyright",
    270: "ImageDescription",
    42032: "CameraOwnerName",
    42033: "BodySerialNumber",
    42036: "LensModel",
    50708: "UniqueCameraModel",
    50827: "OriginalRawFileName",
    36867: "DateTimeOriginal",
}

_DESCRIBE_PRESENT = {
    700: "XMP",
    33723: "IPTC",
    34377: "PhotoshopIRB",
    37500: "MakerNote",
    37510: "UserComment",
    50740: "DNGPrivateData",
    50781: "RawDataUniqueID",
    42016: "ImageUniqueID",
    34675: "ICCProfile",
}


def describe_tiff(data: bytes) -> Dict[str, str]:
    """Report the metadata a TIFF/RAW currently exposes."""
    found: Dict[str, str] = {}
    try:
        tiff = TiffFile(data)
    except TiffError:
        return found

    for ifd in tiff.ifds:
        if ifd.kind == "gps":
            if ifd.entries:
                found["RAW.GPS"] = "PRESENT"
            continue
        for entry in ifd.entries:
            name = _DESCRIBE_STRINGS.get(entry.tag)
            if name:
                value = tiff.value_str(ifd, entry.tag)
                if value:
                    found[f"RAW.{name}"] = value[:100]
                continue
            present = _DESCRIBE_PRESENT.get(entry.tag)
            if present:
                found[f"RAW.{present}"] = "PRESENT"
            elif entry.tag == TAG_GPS_IFD:
                found["RAW.GPS"] = "PRESENT"

    # An embedded preview is a rendering of the same photo, so its existence is
    # informational, not a leak. What matters is whether the preview JPEG still
    # carries metadata of its own - report that separately, and only when true.
    previews = [ifd for ifd in tiff.ifds if _is_preview_ifd(tiff, ifd)]
    if previews:
        found["RAW.EmbeddedPreview"] = f"{len(previews)} previews"
        dirty = any(
            _jpeg_carries_metadata(blob)
            for ifd in previews
            for blob in _preview_blobs(tiff, ifd)
        )
        if dirty:
            found["RAW.PreviewEXIF"] = "PRESENT"

    return found
