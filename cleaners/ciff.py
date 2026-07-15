"""
Native, pure-Python metadata stripping for Canon CRW (CIFF).

CRW is Canon's pre-2004 RAW format and is not a TIFF: it is CIFF, the Camera
Image File Format, which stores its directory at the *end* of each block rather
than the front.

    [header: "II" + uint32 header_length + "HEAPCCDR" + version + reserved]
    [heap ...................................................................]
        [value data ...]
        [directory: uint16 count, then count * 10-byte entries]
        [uint32: where the directory starts, relative to the block]

Each 10-byte entry is (uint16 tag, uint32 length, uint32 offset), where the
offset is relative to the enclosing block. A tag with 0x4000 set stores its
value inline in those last 8 bytes instead of out in the heap. Tags whose
high byte is 0x28xx or 0x30xx open a sub-block, parsed the same way.

The sensor data (tag 0x2005) sits in the heap and is reached purely by offset,
so this engine follows the same rule as the TIFF/RAW and Matroska ones: nothing
moves. Removing a tag compacts the directory's entry array in place, drops the
count, and leaves the trailing slot as unreferenced padding - the block's
trailing pointer still points at the directory start, which has not changed.
Orphaned heap values are zeroed only once no surviving tag still points into
them.

Validation note: this engine is built to the CIFF layout as documented by the
format specification and implemented by dcraw and ExifTool, and is covered by
hand-built fixtures. Unlike the other engines it has not yet been exercised
against a real camera file - see the README's known limitations.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

_SIGNATURE = b"HEAPCCDR"
# dcraw's sanity guard: a real CIFF directory never holds this many records.
_MAX_RECORDS = 127
_MAX_DEPTH = 6

_ENTRY_SIZE = 10
# Set in a tag when its value lives inline in the entry, not out in the heap.
_TAG_INLINE = 0x4000


class CIFFError(Exception):
    """Raised when a file cannot be parsed as CIFF/CRW."""


# --------------------------------------------------------------------------- #
# Tag policy
# --------------------------------------------------------------------------- #

TAG_RAW_DATA = 0x2005
TAG_JPEG_FROM_RAW = 0x2007
TAG_THUMBNAIL = 0x2008

# Pure metadata: removed under every profile.
_DROP_ALWAYS: Dict[int, str] = {
    0x0805: "CanonFileDescription",
    0x080B: "CanonFirmwareVersion",
    0x080C: "ComponentVersion",
    0x080D: "ROMOperationMode",
    0x0810: "OwnerName",
    0x0815: "CanonImageType",
    0x1093: "CanonFileInfo",
    0x1033: "CustomFunctions",
    0x180B: "SerialNumber",
    0x180E: "TimeStamp",
    0x1817: "FileNumber",
    0x183B: "SerialNumberFormat",
}

# Removed only under aggressive: dcraw and friends pick their decoder from the
# make/model strings, so dropping them can leave a file some converters refuse.
_DROP_AGGRESSIVE: Dict[int, str] = {
    0x080A: "CanonRawMakeModel",
    0x1834: "CanonModelID",
    TAG_JPEG_FROM_RAW: "JpgFromRaw",
    TAG_THUMBNAIL: "ThumbnailImage",
}

# Never removable, whatever a policy says: without these the raw data cannot be
# located, decompressed, or demosaiced. Checked as a guard, not documentation.
_NEVER_DROP = frozenset({
    TAG_RAW_DATA,  # the sensor data itself
    0x1803,        # ImageFormat
    0x1810,        # ImageSpec (dimensions, rotation)
    0x1830,        # decoder-relevant
    0x1031,        # SensorInfo
    0x1030,        # WhiteSample
    0x1835,        # DecoderTable - required to decompress the raw data
    0x10A9,        # ColorBalance
    0x10AE,        # ColorTemperature
    0x10B4,        # ColorSpace
    0x102C,        # CanonColorInfo2
    0x102D,        # CanonCameraSettings
    0x0032,        # CanonColorInfo1
})

_TAG_NAMES: Dict[int, str] = {
    0x0805: "CanonFileDescription",
    0x080A: "CanonRawMakeModel",
    0x080B: "CanonFirmwareVersion",
    0x0810: "OwnerName",
    0x0815: "CanonImageType",
    0x180B: "SerialNumber",
    0x180E: "TimeStamp",
    0x1817: "FileNumber",
    0x1834: "CanonModelID",
    TAG_JPEG_FROM_RAW: "JpgFromRaw",
    TAG_THUMBNAIL: "ThumbnailImage",
}


def _drop_map(aggressive: bool) -> Dict[int, str]:
    drop = dict(_DROP_ALWAYS)
    if aggressive:
        drop.update(_DROP_AGGRESSIVE)
    return {tag: name for tag, name in drop.items() if tag not in _NEVER_DROP}


# --------------------------------------------------------------------------- #
# Model
# --------------------------------------------------------------------------- #


class Entry:
    """One 10-byte CIFF directory record."""

    __slots__ = ("tag", "length", "offset", "pos", "block_offset")

    def __init__(self, tag: int, length: int, offset: int, pos: int,
                 block_offset: int) -> None:
        self.tag = tag
        self.length = length
        self.offset = offset  # relative to the enclosing block
        self.pos = pos  # absolute position of the entry itself
        self.block_offset = block_offset

    @property
    def inline(self) -> bool:
        return bool(self.tag & _TAG_INLINE)

    @property
    def absolute_offset(self) -> int:
        return self.block_offset + self.offset

    @property
    def is_subdirectory(self) -> bool:
        if self.inline:
            return False
        return ((self.tag >> 8) & 0x38) in (0x28, 0x30)


class Directory:
    """One CIFF block's directory."""

    __slots__ = ("block_offset", "block_length", "dir_offset", "entries")

    def __init__(self, block_offset: int, block_length: int, dir_offset: int,
                 entries: List[Entry]) -> None:
        self.block_offset = block_offset
        self.block_length = block_length
        self.dir_offset = dir_offset  # absolute
        self.entries = entries

    @property
    def entries_end(self) -> int:
        """Where the entry array currently ends."""
        return self.dir_offset + 2 + _ENTRY_SIZE * len(self.entries)

    @property
    def block_end(self) -> int:
        return self.block_offset + self.block_length


class CIFFFile:
    """A parsed CRW/CIFF container."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.little = self._read_header()
        self.directories: List[Directory] = []
        self._parse(self.header_length, len(data) - self.header_length, 0)

    # -- primitives -------------------------------------------------------- #

    def _read_header(self) -> bool:
        data = self.data
        if len(data) < 26:
            raise CIFFError("file too small to be CIFF")
        order = data[:2]
        if order not in (b"II", b"MM"):
            raise CIFFError(
                f"not a CIFF container: expected the file to start with 'II' or "
                f"'MM' but found {order!r}. Refusing to guess at the layout - "
                f"the file is probably corrupt, truncated, or has the wrong "
                f"extension"
            )
        little = order == b"II"
        self.header_length = int.from_bytes(
            data[2:6], "little" if little else "big"
        )
        if data[6:14] != _SIGNATURE:
            raise CIFFError(
                f"not a Canon CRW: expected the {_SIGNATURE.decode()} signature "
                f"at offset 6 but found {data[6:14]!r}"
            )
        if not 14 <= self.header_length <= len(data):
            raise CIFFError(f"implausible CIFF header length: {self.header_length}")
        return little

    def _u16(self, pos: int) -> int:
        return int.from_bytes(self.data[pos : pos + 2],
                              "little" if self.little else "big")

    def _u32(self, pos: int) -> int:
        return int.from_bytes(self.data[pos : pos + 4],
                              "little" if self.little else "big")

    def pack_u16(self, value: int) -> bytes:
        return value.to_bytes(2, "little" if self.little else "big")

    # -- parsing ----------------------------------------------------------- #

    def _parse(self, block_offset: int, block_length: int, depth: int) -> None:
        if depth > _MAX_DEPTH or block_length < 6:
            return
        block_end = block_offset + block_length
        if block_end > len(self.data):
            raise CIFFError("CIFF block overruns the file")

        dir_offset = self._u32(block_end - 4) + block_offset
        if not block_offset <= dir_offset < block_end - 2:
            raise CIFFError(f"CIFF directory offset {dir_offset} outside its block")

        count = self._u16(dir_offset)
        if count > _MAX_RECORDS:
            raise CIFFError(f"implausible CIFF record count: {count}")
        if dir_offset + 2 + _ENTRY_SIZE * count > block_end:
            raise CIFFError("CIFF directory overruns its block")

        entries: List[Entry] = []
        for i in range(count):
            pos = dir_offset + 2 + _ENTRY_SIZE * i
            entries.append(
                Entry(
                    tag=self._u16(pos),
                    length=self._u32(pos + 2),
                    offset=self._u32(pos + 6),
                    pos=pos,
                    block_offset=block_offset,
                )
            )

        directory = Directory(block_offset, block_length, dir_offset, entries)
        self.directories.append(directory)

        for entry in entries:
            if not entry.is_subdirectory:
                continue
            start = entry.absolute_offset
            if start + entry.length > len(self.data) or entry.length < 6:
                continue  # tolerate a bad sub-block rather than refuse the file
            self._parse(start, entry.length, depth + 1)

    # -- values ------------------------------------------------------------ #

    def value_bytes(self, entry: Entry) -> bytes:
        if entry.inline:
            return self.data[entry.pos + 2 : entry.pos + 10]
        start = entry.absolute_offset
        if start + entry.length > len(self.data):
            return b""
        return self.data[start : start + entry.length]

    def value_str(self, entry: Entry) -> str:
        raw = self.value_bytes(entry)
        return raw.split(b"\x00")[0].decode("utf-8", "ignore").strip()


def is_crw(data: bytes) -> bool:
    return (
        len(data) >= 26
        and data[:2] in (b"II", b"MM")
        and data[6:14] == _SIGNATURE
    )


# --------------------------------------------------------------------------- #
# Cleaning
# --------------------------------------------------------------------------- #


def clean_crw(data: bytes, aggressive: bool = False) -> Tuple[bytes, List[str]]:
    """Strip metadata from a Canon CRW without moving a single byte."""
    ciff = CIFFFile(data)
    out = bytearray(data)
    drop = _drop_map(aggressive)

    removed: List[str] = []
    orphan_ranges: List[Tuple[int, int]] = []

    for directory in ciff.directories:
        keep: List[Entry] = []
        for entry in directory.entries:
            name = drop.get(entry.tag)
            if name is None:
                keep.append(entry)
                continue
            removed.append(name)
            if not entry.inline and entry.length:
                start = entry.absolute_offset
                if start + entry.length <= len(out):
                    orphan_ranges.append((start, start + entry.length))

        if len(keep) != len(directory.entries):
            _rewrite_directory(ciff, out, directory, keep)

    _zero_orphans(ciff, out, orphan_ranges, drop)

    if not removed:
        return data, []
    return bytes(out), sorted(set(removed))


def _rewrite_directory(ciff: CIFFFile, out: bytearray, directory: Directory,
                       keep: List[Entry]) -> None:
    """Compact a directory's entry array in place, zeroing the freed slots.

    The block's trailing pointer names where the directory *starts*, and that
    does not move, so shortening the array is invisible to a reader.
    """
    out[directory.dir_offset : directory.dir_offset + 2] = ciff.pack_u16(len(keep))

    cursor = directory.dir_offset + 2
    for entry in keep:
        payload = bytes(out[entry.pos : entry.pos + _ENTRY_SIZE])
        out[cursor : cursor + _ENTRY_SIZE] = payload
        cursor += _ENTRY_SIZE

    for i in range(cursor, directory.entries_end):
        out[i] = 0


def _zero_orphans(ciff: CIFFFile, out: bytearray,
                  ranges: List[Tuple[int, int]], drop: Dict[int, str]) -> None:
    """Zero orphaned heap values, but never a byte still in use."""
    protected: List[Tuple[int, int]] = []

    for directory in ciff.directories:
        # The directory structure and the block's trailing pointer.
        protected.append((directory.dir_offset, directory.block_end))
        for entry in directory.entries:
            if entry.tag in drop or entry.inline or not entry.length:
                continue
            if entry.is_subdirectory:
                # Its own leaves are protected in their own iteration; the block
                # as a whole must not be blanket-protected or nothing inside it
                # could ever be cleaned.
                continue
            start = entry.absolute_offset
            if start + entry.length <= len(out):
                protected.append((start, start + entry.length))

    for start, end in ranges:
        if start < 0 or end > len(out) or start >= end:
            continue
        if any(start < p_end and p_start < end for p_start, p_end in protected):
            continue
        for i in range(start, end):
            out[i] = 0


# --------------------------------------------------------------------------- #
# Description
# --------------------------------------------------------------------------- #


def describe_crw(data: bytes) -> Dict[str, str]:
    """Report the metadata a CRW currently exposes."""
    found: Dict[str, str] = {}
    try:
        ciff = CIFFFile(data)
    except CIFFError:
        return found

    for directory in ciff.directories:
        for entry in directory.entries:
            name = _TAG_NAMES.get(entry.tag)
            if name is None:
                continue
            if entry.tag in (TAG_JPEG_FROM_RAW, TAG_THUMBNAIL):
                found[f"CRW.{name}"] = "PRESENT"
                continue
            if entry.tag == 0x180E:  # TimeStamp is binary
                found["CRW.TimeStamp"] = "PRESENT"
                continue
            text = ciff.value_str(entry)
            if text:
                found[f"CRW.{name}"] = text[:100]

    return found
