"""
Native, pure-Python metadata stripping for Matroska containers (MKV/WebM).

Matroska is an EBML document. The tricky part is that a Segment carries
absolute byte offsets in its SeekHead index and in the Cues (seek) index, so
naively deleting a metadata element shifts every following byte and silently
breaks seeking.

EBML solves this for us: the Void element (ID 0xEC) is defined as ignorable
padding. So instead of deleting, we overwrite a metadata element *in place*
with a Void element of the exact same total size. Byte offsets never move,
SeekHead/Cues stay valid, and the clusters (the actual audio/video frames) are
never touched.

Two neutralisation strategies are used:

- Void: for elements that may legally disappear (Tags, Attachments, Title,
  DateUTC, SegmentUID, SegmentFilename, track Name...).
- Zero-fill: for the two mandatory string elements (MuxingApp, WritingApp).
  EBML permits zero-padded strings, so blanking the payload keeps the document
  conformant while erasing the encoder fingerprint.

Stale SeekHead entries that point at now-voided elements are voided too, so no
reader is sent chasing a removed index target.
"""

from __future__ import annotations

from typing import Dict, Iterator, List, Optional, Set, Tuple


class MatroskaError(Exception):
    """Raised when a file cannot be parsed as Matroska/EBML."""


# --------------------------------------------------------------------------- #
# Element IDs (stored with their VINT marker bits, as Matroska defines them)
# --------------------------------------------------------------------------- #

ID_EBML_HEADER = 0x1A45DFA3
ID_SEGMENT = 0x18538067

ID_SEEK_HEAD = 0x114D9B74
ID_SEEK = 0x4DBB
ID_SEEK_ID = 0x53AB

ID_INFO = 0x1549A966
ID_SEGMENT_UID = 0x73A4
ID_SEGMENT_FILENAME = 0x7384
ID_PREV_UID = 0x3CB923
ID_PREV_FILENAME = 0x3C83AB
ID_NEXT_UID = 0x3EB923
ID_NEXT_FILENAME = 0x3E83BB
ID_SEGMENT_FAMILY = 0x4444
ID_TITLE = 0x7BA9
ID_MUXING_APP = 0x4D80
ID_WRITING_APP = 0x5741
ID_DATE_UTC = 0x4461

ID_TRACKS = 0x1654AE6B
ID_TRACK_ENTRY = 0xAE
ID_TRACK_NAME = 0x536E
ID_CODEC_NAME = 0x258688

ID_TAGS = 0x1254C367
ID_ATTACHMENTS = 0x1941A469
ID_CHAPTERS = 0x1043A770
ID_CLUSTER = 0x1F43B675
ID_CUES = 0x1C53BB6B
ID_VOID = 0xEC

# Top-level Segment children removed outright.
_SEGMENT_DROP = {
    ID_TAGS: "Tags",
    ID_ATTACHMENTS: "Attachments",
}
# Removed only under the aggressive profile (navigational, but names can leak).
_SEGMENT_DROP_AGGRESSIVE = {
    ID_CHAPTERS: "Chapters",
}

# Info children removed outright.
_INFO_DROP = {
    ID_TITLE: "Title",
    ID_DATE_UTC: "DateUTC",
    ID_SEGMENT_FILENAME: "SegmentFilename",
    ID_PREV_FILENAME: "PrevFilename",
    ID_NEXT_FILENAME: "NextFilename",
    ID_SEGMENT_UID: "SegmentUID",
    ID_PREV_UID: "PrevUID",
    ID_NEXT_UID: "NextUID",
    ID_SEGMENT_FAMILY: "SegmentFamily",
}
# Info children blanked in place (mandatory elements).
_INFO_BLANK = {
    ID_MUXING_APP: "MuxingApp",
    ID_WRITING_APP: "WritingApp",
}

_TRACK_DROP = {
    ID_TRACK_NAME: "TrackName",
}
_TRACK_DROP_AGGRESSIVE = {
    ID_CODEC_NAME: "CodecName",
}


# --------------------------------------------------------------------------- #
# EBML primitives
# --------------------------------------------------------------------------- #


def _read_vint(data: bytes, pos: int, keep_marker: bool) -> Tuple[int, int]:
    """Read an EBML variable-length integer at pos -> (value, byte_length).

    Element IDs keep their marker bit (that is how Matroska writes them);
    sizes have it stripped.
    """
    if pos >= len(data):
        raise MatroskaError("unexpected end of data while reading VINT")
    first = data[pos]
    if first == 0:
        raise MatroskaError(f"invalid VINT at offset {pos}")

    length = 1
    mask = 0x80
    while not (first & mask):
        mask >>= 1
        length += 1
        if length > 8:
            raise MatroskaError(f"VINT too long at offset {pos}")
    if pos + length > len(data):
        raise MatroskaError("truncated VINT")

    if keep_marker:
        return int.from_bytes(data[pos : pos + length], "big"), length

    value = first & (mask - 1)
    for i in range(1, length):
        value = (value << 8) | data[pos + i]
    return value, length


def _is_unknown_size(value: int, length: int) -> bool:
    """An all-ones payload means 'size unknown' (live/streamed elements)."""
    return value == (1 << (7 * length)) - 1


def _encode_vint(value: int, length: int) -> bytes:
    """Encode value as a size VINT of exactly `length` bytes."""
    return (value | (1 << (7 * length))).to_bytes(length, "big")


class Element:
    """One parsed EBML element."""

    __slots__ = ("eid", "start", "payload_start", "payload_end", "unknown_size")

    def __init__(
        self, eid: int, start: int, payload_start: int, payload_end: int,
        unknown_size: bool,
    ) -> None:
        self.eid = eid
        self.start = start
        self.payload_start = payload_start
        self.payload_end = payload_end
        self.unknown_size = unknown_size

    @property
    def end(self) -> int:
        return self.payload_end

    @property
    def total_size(self) -> int:
        return self.payload_end - self.start


def iter_elements(data: bytes, start: int, end: int) -> Iterator[Element]:
    """Yield direct child elements between start and end.

    Stops cleanly at an unknown-size element (other than the Segment itself),
    because siblings after it cannot be located without decoding the media.
    """
    i = start
    while i < end:
        try:
            eid, id_len = _read_vint(data, i, keep_marker=True)
            size, size_len = _read_vint(data, i + id_len, keep_marker=False)
        except MatroskaError:
            return

        payload_start = i + id_len + size_len
        unknown = _is_unknown_size(size, size_len)
        payload_end = end if unknown else payload_start + size
        if payload_end > end:
            payload_end = end

        yield Element(eid, i, payload_start, payload_end, unknown)

        if unknown:
            return
        i = payload_end


def _void_element(out: bytearray, start: int, total: int) -> bool:
    """Overwrite [start, start+total) with a Void element of identical size."""
    if total < 2:
        return False
    for vlen in range(1, 9):
        payload = total - 1 - vlen
        if payload < 0:
            continue
        if payload <= (1 << (7 * vlen)) - 2:
            out[start] = ID_VOID
            out[start + 1 : start + 1 + vlen] = _encode_vint(payload, vlen)
            for i in range(start + 1 + vlen, start + total):
                out[i] = 0
            return True
    return False


def _blank_payload(out: bytearray, element: Element) -> None:
    """Zero an element's payload, keeping its ID and size intact."""
    for i in range(element.payload_start, element.payload_end):
        out[i] = 0


# --------------------------------------------------------------------------- #
# Detection
# --------------------------------------------------------------------------- #


def is_matroska(data: bytes) -> bool:
    return len(data) >= 4 and data[:4] == b"\x1a\x45\xdf\xa3"


def _find_segment(data: bytes) -> Optional[Element]:
    for element in iter_elements(data, 0, len(data)):
        if element.eid == ID_SEGMENT:
            return element
    return None


# --------------------------------------------------------------------------- #
# Cleaning
# --------------------------------------------------------------------------- #


def clean_matroska(data: bytes, aggressive: bool = False) -> Tuple[bytes, List[str]]:
    """Strip metadata from an MKV/WebM without moving a single byte.

    Every removal is an in-place Void (or zero-fill) of identical size, so
    SeekHead/Cues offsets stay valid and the clusters are untouched.
    """
    if not is_matroska(data):
        raise MatroskaError("not a Matroska/WebM file (missing EBML header)")

    segment = _find_segment(data)
    if segment is None:
        raise MatroskaError("no Segment element found")

    out = bytearray(data)
    removed: List[str] = []
    voided_ids: List[int] = []

    drop = dict(_SEGMENT_DROP)
    if aggressive:
        drop.update(_SEGMENT_DROP_AGGRESSIVE)

    seek_heads: List[Element] = []

    for child in iter_elements(data, segment.payload_start, segment.payload_end):
        if child.eid in drop:
            if _void_element(out, child.start, child.total_size):
                removed.append(drop[child.eid])
                voided_ids.append(child.eid)
        elif child.eid == ID_INFO:
            removed += _clean_info(data, out, child)
        elif child.eid == ID_TRACKS:
            removed += _clean_tracks(data, out, child, aggressive)
        elif child.eid == ID_SEEK_HEAD:
            seek_heads.append(child)

    # Drop index entries that now point at Void padding.
    for seek_head in seek_heads:
        _prune_seek_head(data, out, seek_head, voided_ids)

    if not removed:
        return data, []
    return bytes(out), removed


def _clean_info(data: bytes, out: bytearray, info: Element) -> List[str]:
    removed: List[str] = []
    for child in iter_elements(data, info.payload_start, info.payload_end):
        if child.eid in _INFO_DROP:
            if _void_element(out, child.start, child.total_size):
                removed.append(_INFO_DROP[child.eid])
        elif child.eid in _INFO_BLANK:
            if child.payload_end > child.payload_start:
                _blank_payload(out, child)
                removed.append(_INFO_BLANK[child.eid])
    return removed


def _clean_tracks(
    data: bytes, out: bytearray, tracks: Element, aggressive: bool
) -> List[str]:
    drop = dict(_TRACK_DROP)
    if aggressive:
        drop.update(_TRACK_DROP_AGGRESSIVE)

    removed: List[str] = []
    for entry in iter_elements(data, tracks.payload_start, tracks.payload_end):
        if entry.eid != ID_TRACK_ENTRY:
            continue
        for child in iter_elements(data, entry.payload_start, entry.payload_end):
            if child.eid in drop:
                if _void_element(out, child.start, child.total_size):
                    removed.append(drop[child.eid])
    return removed


def _prune_seek_head(
    data: bytes, out: bytearray, seek_head: Element, voided_ids: List[int]
) -> None:
    """Void Seek entries whose SeekID references an element we removed."""
    if not voided_ids:
        return
    targets = set(voided_ids)
    for seek in iter_elements(data, seek_head.payload_start, seek_head.payload_end):
        if seek.eid != ID_SEEK:
            continue
        for field in iter_elements(data, seek.payload_start, seek.payload_end):
            if field.eid != ID_SEEK_ID:
                continue
            raw = data[field.payload_start : field.payload_end]
            if raw and int.from_bytes(raw, "big") in targets:
                _void_element(out, seek.start, seek.total_size)
            break


# --------------------------------------------------------------------------- #
# Description (for the metadata extractor)
# --------------------------------------------------------------------------- #

_TEXT_INFO_FIELDS = {
    ID_TITLE: "Matroska.Title",
    ID_MUXING_APP: "Matroska.MuxingApp",
    ID_WRITING_APP: "Matroska.WritingApp",
    ID_SEGMENT_FILENAME: "Matroska.SegmentFilename",
}


def describe_matroska(data: bytes) -> Dict[str, str]:
    """Report the metadata an MKV/WebM currently exposes."""
    found: Dict[str, str] = {}
    if not is_matroska(data):
        return found
    segment = _find_segment(data)
    if segment is None:
        return found

    for child in iter_elements(data, segment.payload_start, segment.payload_end):
        if child.eid == ID_TAGS:
            found["Matroska.Tags"] = "PRESENT"
        elif child.eid == ID_ATTACHMENTS:
            found["Matroska.Attachments"] = "PRESENT"
        elif child.eid == ID_CHAPTERS:
            found["Matroska.Chapters"] = "PRESENT"
        elif child.eid == ID_INFO:
            found.update(_describe_info(data, child))
        elif child.eid == ID_TRACKS:
            found.update(_describe_tracks(data, child))
    return found


def _describe_info(data: bytes, info: Element) -> Dict[str, str]:
    found: Dict[str, str] = {}
    for child in iter_elements(data, info.payload_start, info.payload_end):
        raw = data[child.payload_start : child.payload_end]
        if not raw.strip(b"\x00"):
            continue
        name = _TEXT_INFO_FIELDS.get(child.eid)
        if name:
            found[name] = raw.decode("utf-8", "ignore").strip("\x00")[:100]
        elif child.eid == ID_DATE_UTC:
            found["Matroska.DateUTC"] = "PRESENT"
        elif child.eid == ID_SEGMENT_UID:
            found["Matroska.SegmentUID"] = raw.hex()[:32]
    return found


def _describe_tracks(data: bytes, tracks: Element) -> Dict[str, str]:
    found: Dict[str, str] = {}
    for entry in iter_elements(data, tracks.payload_start, tracks.payload_end):
        if entry.eid != ID_TRACK_ENTRY:
            continue
        for child in iter_elements(data, entry.payload_start, entry.payload_end):
            if child.eid != ID_TRACK_NAME:
                continue
            raw = data[child.payload_start : child.payload_end]
            if raw.strip(b"\x00"):
                found["Matroska.TrackName"] = raw.decode("utf-8", "ignore")[:100]
    return found
