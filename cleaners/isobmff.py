"""
Native, pure-Python metadata stripping for the ISO Base Media File Format.

One container family covers the highest-value leak sources:
- Video: MP4, MOV (QuickTime), M4V  -> `moov/udta` holds GPS (`\xa9xyz` on
  iPhone), device, and software tags.
- Audio: M4A  -> iTunes-style `ilst` metadata.
- Images: HEIC, HEIF, AVIF  -> EXIF/XMP stored as items in the top-level `meta`
  box.

Safety model: metadata boxes are *neutralised in place* — the box type is
renamed to `free` (which every ISOBMFF reader ignores) and its payload zeroed —
so the file size and every internal offset (`stco`/`co64` sample tables,
`iloc` item locations) stay valid. For HEIF, only the EXIF/XMP item payloads in
`mdat` are zeroed; the image items are untouched. Nothing is ever re-encoded.

If the structure does not match expectations, the routines make no change and
report it, rather than risk corrupting a photo or video.
"""

from __future__ import annotations

from typing import Iterator, List, Tuple


class ISOBMFFError(Exception):
    """Raised when a file is not valid ISOBMFF or cannot be parsed safely."""


# Boxes we descend into while looking for metadata.
_CONTAINER_BOXES = {
    b"moov",
    b"trak",
    b"mdia",
    b"minf",
    b"stbl",
    b"edts",
    b"mvex",
    b"moof",
    b"traf",
    b"udta",
}

_HEIF_BRANDS = {b"heic", b"heix", b"heim", b"heis", b"hevc", b"hevx",
                b"mif1", b"msf1", b"avif", b"avis"}


def is_isobmff(data: bytes) -> bool:
    """Cheap structural check: a valid file starts with an ftyp/styp box."""
    if len(data) < 12:
        return False
    return data[4:8] in (b"ftyp", b"styp")


def is_heif(data: bytes) -> bool:
    """Detect HEIC/HEIF/AVIF via the ftyp major brand or compatible brands."""
    if not is_isobmff(data):
        return False
    try:
        size = int.from_bytes(data[0:4], "big")
        ftyp = data[8:size] if 8 < size <= len(data) else data[8:32]
    except Exception:
        ftyp = data[8:32]
    major = ftyp[0:4]
    if major in _HEIF_BRANDS:
        return True
    # Scan compatible brands (4-byte entries after major brand + minor version).
    compat = ftyp[8:]
    for i in range(0, len(compat) - 3, 4):
        if compat[i : i + 4] in _HEIF_BRANDS:
            return True
    return False


def iter_boxes(data: bytes, start: int, end: int) -> Iterator[Tuple[int, int, bytes, int]]:
    """Yield (box_start, header_size, box_type, box_end) for boxes in a range."""
    i = start
    while i + 8 <= end:
        size = int.from_bytes(data[i : i + 4], "big")
        btype = bytes(data[i + 4 : i + 8])
        header = 8
        if size == 1:
            if i + 16 > end:
                break
            size = int.from_bytes(data[i + 8 : i + 16], "big")
            header = 16
        elif size == 0:
            size = end - i
        box_end = i + size
        if size < header or box_end > end:
            break
        yield i, header, btype, box_end
        i = box_end


# --------------------------------------------------------------------------- #
# Video / audio (moov-based) cleaning
# --------------------------------------------------------------------------- #


def clean_movie(data: bytes, aggressive: bool = False) -> Tuple[bytes, List[str]]:
    """Neutralise metadata boxes in a movie/audio ISOBMFF file, in place."""
    out = bytearray(data)
    removed: List[str] = []

    def neutralize(box_start: int, header: int, box_end: int, label: str) -> None:
        out[box_start + 4 : box_start + 8] = b"free"
        for j in range(box_start + header, box_end):
            out[j] = 0
        removed.append(label)

    def walk(start: int, end: int, parent: bytes) -> None:
        for box_start, header, btype, box_end in iter_boxes(out, start, end):
            if btype == b"udta":
                neutralize(box_start, header, box_end, "udta")
                continue
            if btype == b"meta" and parent in (b"moov", b"trak"):
                neutralize(box_start, header, box_end, "meta")
                continue
            if btype == b"uuid":
                # uuid boxes commonly carry XMP packets.
                neutralize(box_start, header, box_end, "uuid")
                continue
            if btype in _CONTAINER_BOXES:
                walk(box_start + header, box_end, btype)

    walk(0, len(out), b"")
    return bytes(out), removed


# --------------------------------------------------------------------------- #
# HEIF / HEIC / AVIF cleaning (item-based)
# --------------------------------------------------------------------------- #


def clean_heif(data: bytes, aggressive: bool = False) -> Tuple[bytes, List[str]]:
    """Zero the EXIF/XMP item payloads in a HEIF image, keeping the picture."""
    meta_box = _find_top_level_box(data, b"meta")
    if meta_box is None:
        raise ISOBMFFError("no meta box found in HEIF file")

    meta_start, meta_header, meta_end = meta_box
    # meta is a FullBox: 4 bytes version/flags after the header.
    inner_start = meta_start + meta_header + 4

    item_types = _parse_iinf(data, inner_start, meta_end)
    if not item_types:
        raise ISOBMFFError("could not parse HEIF item information")

    target_ids = [
        item_id
        for item_id, itype in item_types.items()
        if itype in (b"Exif", b"exif", b"mime")
    ]
    if not target_ids:
        return data, []  # nothing sensitive to remove

    extents = _parse_iloc(data, inner_start, meta_end)
    out = bytearray(data)
    removed: List[str] = []

    for item_id in target_ids:
        for offset, length in extents.get(item_id, []):
            if offset <= 0 or length <= 0 or offset + length > len(out):
                raise ISOBMFFError("HEIF item extent out of range; aborting")
            for j in range(offset, offset + length):
                out[j] = 0
            label = "Exif" if item_types[item_id] in (b"Exif", b"exif") else "XMP"
            removed.append(label)

    return bytes(out), removed


def _find_top_level_box(data: bytes, target: bytes):
    for box_start, header, btype, box_end in iter_boxes(data, 0, len(data)):
        if btype == target:
            return box_start, header, box_end
    return None


def _parse_iinf(data: bytes, start: int, end: int) -> dict[int, bytes]:
    """Map item_ID -> item_type by parsing the iinf/infe boxes."""
    items: dict[int, bytes] = {}
    for box_start, header, btype, box_end in iter_boxes(data, start, end):
        if btype != b"iinf":
            continue
        version = data[box_start + header]
        p = box_start + header + 4  # skip version/flags
        if version == 0:
            p += 2  # 16-bit entry count
        else:
            p += 4  # 32-bit entry count
        for infe_start, infe_hdr, infe_type, infe_end in iter_boxes(data, p, box_end):
            if infe_type != b"infe":
                continue
            iv = data[infe_start + infe_hdr]
            q = infe_start + infe_hdr + 4
            if iv >= 2:
                if iv == 2:
                    item_id = int.from_bytes(data[q : q + 2], "big")
                    q += 2
                else:  # version 3: 32-bit item_id
                    item_id = int.from_bytes(data[q : q + 4], "big")
                    q += 4
                q += 2  # item_protection_index
                item_type = data[q : q + 4]
                items[item_id] = item_type
    return items


def _parse_iloc(data: bytes, start: int, end: int) -> dict[int, list[tuple[int, int]]]:
    """Map item_ID -> list of (absolute_offset, length) from the iloc box."""
    result: dict[int, list[tuple[int, int]]] = {}
    for box_start, header, btype, box_end in iter_boxes(data, start, end):
        if btype != b"iloc":
            continue
        p = box_start + header
        version = data[p]
        p += 4  # version + flags

        sizes = data[p]
        offset_size = sizes >> 4
        length_size = sizes & 0x0F
        p += 1
        base_sizes = data[p]
        base_offset_size = base_sizes >> 4
        index_size = base_sizes & 0x0F
        p += 1

        if version < 2:
            item_count = int.from_bytes(data[p : p + 2], "big")
            p += 2
            id_size = 2
        else:
            item_count = int.from_bytes(data[p : p + 4], "big")
            p += 4
            id_size = 4

        for _ in range(item_count):
            item_id = int.from_bytes(data[p : p + id_size], "big")
            p += id_size
            if version in (1, 2):
                p += 2  # construction_method
            p += 2  # data_reference_index
            base_offset = _read_int(data, p, base_offset_size)
            p += base_offset_size
            extent_count = int.from_bytes(data[p : p + 2], "big")
            p += 2
            extents: list[tuple[int, int]] = []
            for _ in range(extent_count):
                if index_size and version in (1, 2):
                    p += index_size
                extent_offset = _read_int(data, p, offset_size)
                p += offset_size
                extent_length = _read_int(data, p, length_size)
                p += length_size
                extents.append((base_offset + extent_offset, extent_length))
            result[item_id] = extents
    return result


def _read_int(data: bytes, pos: int, size: int) -> int:
    if size == 0:
        return 0
    return int.from_bytes(data[pos : pos + size], "big")


# --------------------------------------------------------------------------- #
# Detection helpers for the extractor (read-only)
# --------------------------------------------------------------------------- #


def describe_movie_metadata(data: bytes) -> dict[str, str]:
    """Return a small map describing metadata present in a movie/audio file."""
    found: dict[str, str] = {}

    def walk(start: int, end: int, parent: bytes) -> None:
        for box_start, header, btype, box_end in iter_boxes(data, start, end):
            if btype == b"udta":
                found["QuickTime.UserData"] = "PRESENT"
                _describe_udta(data, box_start + header, box_end, found)
                continue
            if btype == b"meta" and parent in (b"moov", b"trak"):
                found["QuickTime.Metadata"] = "PRESENT"
                continue
            if btype == b"uuid":
                found["XMP"] = "PRESENT"
                continue
            if btype in _CONTAINER_BOXES:
                walk(box_start + header, box_end, btype)

    walk(0, len(data), b"")
    return found


def _describe_udta(data: bytes, start: int, end: int, found: dict[str, str]) -> None:
    for box_start, header, btype, box_end in iter_boxes(data, start, end):
        if btype == b"\xa9xyz":
            raw = data[box_start + header : box_end]
            text = raw[4:].decode("utf-8", errors="ignore").strip()
            found["QuickTime.GPS"] = text or "PRESENT"
        elif btype in (b"\xa9nam", b"\xa9ART", b"\xa9too", b"\xa9cmt", b"\xa9day"):
            found[f"QuickTime.{btype[1:].decode('ascii', 'ignore')}"] = "PRESENT"


def describe_heif_metadata(data: bytes) -> dict[str, str]:
    """Return a map describing EXIF/XMP items present in a HEIF image.

    Cleaning zeroes an item's payload but leaves its `infe` declaration in the
    `meta` box, because removing the declaration would shift every following
    byte and invalidate `iloc`. So the declaration alone proves nothing: an item
    is only reported when its payload still holds data.
    """
    found: dict[str, str] = {}
    meta_box = _find_top_level_box(data, b"meta")
    if meta_box is None:
        return found
    meta_start, meta_header, meta_end = meta_box
    inner_start = meta_start + meta_header + 4

    item_types = _parse_iinf(data, inner_start, meta_end)
    extents = _parse_iloc(data, inner_start, meta_end)

    for item_id, itype in item_types.items():
        if itype not in (b"Exif", b"exif", b"mime"):
            continue
        if not _item_has_content(data, extents.get(item_id, [])):
            continue
        label = "EXIF" if itype in (b"Exif", b"exif") else "XMP"
        found[label] = "PRESENT"
    return found


def _item_has_content(data: bytes, extents: list[tuple[int, int]]) -> bool:
    """True when any of an item's extents still holds non-zero bytes."""
    for offset, length in extents:
        if offset <= 0 or length <= 0 or offset + length > len(data):
            continue
        if any(data[offset : offset + length]):
            return True
    return False
