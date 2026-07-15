"""
Native, pure-Python metadata stripping for Ogg containers.

Covers Vorbis (`.ogg`/`.oga`), Opus (`.opus`), Theora (`.ogv`), and Speex —
every one of them carries its metadata in a "comment header" packet holding a
vendor string (an encoder fingerprint) plus arbitrary user tags, which is where
artist/title/location/cover-art leaks live.

Ogg is a streaming format with no offset index, so unlike Matroska or ISOBMFF
the comment packet can genuinely be shrunk instead of neutralised in place.
That does mean the header pages must be rebuilt: the segment (lacing) table is
recomputed, page sequence numbers of the stream are renumbered, and the Ogg
CRC32 (its own polynomial, not zlib's) is recalculated. Audio pages are copied
through untouched, so the encoded media stays byte-identical.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

_OGG_MAGIC = b"OggS"
_MAX_SEGMENTS = 255


class OggError(Exception):
    """Raised when a file cannot be parsed as Ogg."""


# --------------------------------------------------------------------------- #
# Ogg CRC32 (poly 0x04C11DB7, no reflection, no final xor)
# --------------------------------------------------------------------------- #


def _build_crc_table() -> List[int]:
    table = []
    for i in range(256):
        r = i << 24
        for _ in range(8):
            if r & 0x80000000:
                r = ((r << 1) ^ 0x04C11DB7) & 0xFFFFFFFF
            else:
                r = (r << 1) & 0xFFFFFFFF
        table.append(r)
    return table


_CRC_TABLE = _build_crc_table()


def _ogg_crc(data: bytes) -> int:
    crc = 0
    for byte in data:
        crc = ((crc << 8) & 0xFFFFFFFF) ^ _CRC_TABLE[((crc >> 24) & 0xFF) ^ byte]
    return crc


# --------------------------------------------------------------------------- #
# Page model
# --------------------------------------------------------------------------- #


class Page:
    """One parsed Ogg page."""

    __slots__ = ("header_type", "granule", "serial", "sequence", "segments",
                 "body", "start", "end")

    def __init__(self, header_type: int, granule: int, serial: int, sequence: int,
                 segments: List[int], body: bytes, start: int, end: int) -> None:
        self.header_type = header_type
        self.granule = granule
        self.serial = serial
        self.sequence = sequence
        self.segments = segments
        self.body = body
        self.start = start
        self.end = end

    @property
    def is_bos(self) -> bool:
        return bool(self.header_type & 0x02)

    @property
    def continues(self) -> bool:
        return bool(self.header_type & 0x01)


def is_ogg(data: bytes) -> bool:
    return len(data) >= 4 and data[:4] == _OGG_MAGIC


def parse_pages(data: bytes) -> List[Page]:
    """Parse every Ogg page in the file, in physical order."""
    pages: List[Page] = []
    i = 0
    n = len(data)
    while i + 27 <= n:
        if data[i : i + 4] != _OGG_MAGIC:
            raise OggError(f"lost page sync at offset {i}")
        if data[i + 4] != 0:
            raise OggError(f"unsupported Ogg version at offset {i}")

        header_type = data[i + 5]
        granule = int.from_bytes(data[i + 6 : i + 14], "little")
        serial = int.from_bytes(data[i + 14 : i + 18], "little")
        sequence = int.from_bytes(data[i + 18 : i + 22], "little")
        seg_count = data[i + 26]

        table_start = i + 27
        body_start = table_start + seg_count
        if body_start > n:
            raise OggError("truncated Ogg segment table")
        segments = list(data[table_start:body_start])
        body_len = sum(segments)
        body_end = body_start + body_len
        if body_end > n:
            raise OggError("truncated Ogg page body")

        pages.append(Page(header_type, granule, serial, sequence, segments,
                          data[body_start:body_end], i, body_end))
        i = body_end

    if not pages:
        raise OggError("no Ogg pages found")
    return pages


def build_page(header_type: int, granule: int, serial: int, sequence: int,
               segments: List[int], body: bytes) -> bytes:
    """Serialise one Ogg page, computing its CRC."""
    header = bytearray(_OGG_MAGIC)
    header.append(0)  # version
    header.append(header_type)
    header += (granule & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
    header += serial.to_bytes(4, "little")
    header += sequence.to_bytes(4, "little")
    header += b"\x00\x00\x00\x00"  # CRC placeholder
    header.append(len(segments))
    header += bytes(segments)

    page = bytes(header) + body
    crc = _ogg_crc(page)
    return page[:22] + crc.to_bytes(4, "little") + page[26:]


def _lace(packet_len: int) -> List[int]:
    """Segment (lacing) values for one packet, including the terminator."""
    return [255] * (packet_len // 255) + [packet_len % 255]


def _paginate(packets: List[bytes], serial: int, first_sequence: int,
              bos: bool) -> List[bytes]:
    """Repackage packets into pages of at most 255 segments each."""
    lacings: List[int] = []
    body = bytearray()
    for packet in packets:
        lacings += _lace(len(packet))
        body += packet

    pages: List[bytes] = []
    if not lacings:
        return pages
    seg_index = 0
    body_pos = 0
    sequence = first_sequence
    continued = False

    while seg_index < len(lacings):
        chunk = lacings[seg_index : seg_index + _MAX_SEGMENTS]
        chunk_len = sum(chunk)
        header_type = 0
        if continued:
            header_type |= 0x01
        if bos and not pages:
            header_type |= 0x02

        pages.append(build_page(header_type, 0, serial, sequence, chunk,
                                bytes(body[body_pos : body_pos + chunk_len])))
        # A trailing 255 means the packet spills into the next page.
        continued = chunk[-1] == 255
        body_pos += chunk_len
        seg_index += _MAX_SEGMENTS
        sequence += 1

    return pages


# --------------------------------------------------------------------------- #
# Codec knowledge
# --------------------------------------------------------------------------- #

# codec -> (header packet count, clean comment packet)
_CODECS = {
    "vorbis": (3, b"\x03vorbis" + (0).to_bytes(4, "little")
               + (0).to_bytes(4, "little") + b"\x01"),
    "opus": (2, b"OpusTags" + (0).to_bytes(4, "little")
             + (0).to_bytes(4, "little")),
    "theora": (3, b"\x81theora" + (0).to_bytes(4, "little")
               + (0).to_bytes(4, "little") + b"\x01"),
    "speex": (2, (0).to_bytes(4, "little") + (0).to_bytes(4, "little")),
}


def _identify_codec(first_packet: bytes) -> Optional[str]:
    if first_packet.startswith(b"\x01vorbis"):
        return "vorbis"
    if first_packet.startswith(b"OpusHead"):
        return "opus"
    if first_packet.startswith(b"\x80theora"):
        return "theora"
    if first_packet.startswith(b"Speex   "):
        return "speex"
    return None


def _is_comment_packet(codec: str, packet: bytes) -> bool:
    if codec == "vorbis":
        return packet.startswith(b"\x03vorbis")
    if codec == "opus":
        return packet.startswith(b"OpusTags")
    if codec == "theora":
        return packet.startswith(b"\x81theora")
    if codec == "speex":
        return True  # Speex's second packet is the comment, with no magic
    return False


def _extract_packets(pages: List[Page], wanted: int) -> Tuple[List[bytes], int]:
    """Reassemble the first `wanted` complete packets -> (packets, pages used).

    Ogg mandates that header packets never share a page with media data, so the
    pages consumed here are normally exactly the stream's header pages. The
    caller re-checks that assumption before rewriting anything.
    """
    packets: List[bytes] = []
    current = bytearray()
    used = 0

    for index, page in enumerate(pages):
        offset = 0
        for seg in page.segments:
            current += page.body[offset : offset + seg]
            offset += seg
            if seg < 255:  # a lacing below 255 terminates the packet
                packets.append(bytes(current))
                current = bytearray()
                if len(packets) == wanted:
                    return packets, index + 1
        used = index + 1

    return packets, used


# --------------------------------------------------------------------------- #
# Cleaning
# --------------------------------------------------------------------------- #


def clean_ogg(data: bytes, aggressive: bool = False) -> Tuple[bytes, List[str]]:
    """Strip vendor strings and user tags from every logical stream in an Ogg."""
    if not is_ogg(data):
        raise OggError("not an Ogg file (missing OggS magic)")

    pages = parse_pages(data)

    # Group pages per logical stream, preserving physical order.
    by_serial: Dict[int, List[Page]] = {}
    for page in pages:
        by_serial.setdefault(page.serial, []).append(page)

    removed: List[str] = []
    rebuilt: Dict[int, _Rebuilt] = {}

    for serial, stream_pages in by_serial.items():
        result = _clean_stream(stream_pages)
        if result is None:
            continue
        rebuilt[serial] = result
        removed.append(f"{result.codec.capitalize()}Comment")

    if not rebuilt:
        return data, []

    # Reassemble: swap each stream's header pages for the rebuilt ones at the
    # position of its first header page, then renumber that stream's tail.
    emitted: set = set()
    sequence_next: Dict[int, int] = {}

    out = bytearray()
    for page in pages:
        serial = page.serial
        entry = rebuilt.get(serial)

        if entry is not None and page.start in entry.replaced_starts:
            if serial not in emitted:
                for raw in entry.new_pages:
                    out += raw
                sequence_next[serial] = entry.first_sequence + len(entry.new_pages)
                emitted.add(serial)
            continue  # the stream's other header pages are superseded

        if serial in sequence_next:
            seq = sequence_next[serial]
            sequence_next[serial] = seq + 1
            out += build_page(page.header_type, page.granule, serial, seq,
                              page.segments, page.body)
        else:
            out += data[page.start : page.end]

    return bytes(out), removed


class _Rebuilt:
    """A logical stream's rebuilt header pages."""

    __slots__ = ("codec", "replaced_starts", "new_pages", "first_sequence")

    def __init__(self, codec: str, replaced_starts: set, new_pages: List[bytes],
                 first_sequence: int) -> None:
        self.codec = codec
        self.replaced_starts = replaced_starts
        self.new_pages = new_pages
        self.first_sequence = first_sequence


def _clean_stream(stream_pages: List[Page]) -> Optional[_Rebuilt]:
    """Rebuild one logical stream's header pages without its comment tags.

    Returns None (leaving the stream byte-identical) whenever the layout is not
    what the codec spec promises — refusing to touch a stream is always better
    than emitting one that no longer decodes.
    """
    if not stream_pages or not stream_pages[0].is_bos:
        return None

    first_packets, _ = _extract_packets(stream_pages, 1)
    if not first_packets:
        return None
    codec = _identify_codec(first_packets[0])
    if codec is None:
        return None

    header_count, clean_comment = _CODECS[codec]
    packets, page_count = _extract_packets(stream_pages, header_count)
    if len(packets) < header_count:
        return None

    comment_index = 1  # the comment header is always the second packet
    if not _is_comment_packet(codec, packets[comment_index]):
        return None
    if packets[comment_index] == clean_comment:
        return None  # already clean; nothing to do

    # The header pages must hold the header packets and nothing else. If any
    # media rode along in them, repaging would drop it -> leave the file alone.
    header_pages = stream_pages[:page_count]
    if sum(len(p.body) for p in header_pages) != sum(len(p) for p in packets):
        return None

    packets[comment_index] = clean_comment
    serial = stream_pages[0].serial
    first_sequence = stream_pages[0].sequence

    # The identification header must stay alone on the first page.
    new_pages = _paginate([packets[0]], serial, first_sequence, bos=True)
    new_pages += _paginate(packets[1:], serial, first_sequence + len(new_pages),
                           bos=False)

    return _Rebuilt(codec, {p.start for p in header_pages}, new_pages,
                    first_sequence)


# --------------------------------------------------------------------------- #
# Description (for the metadata extractor)
# --------------------------------------------------------------------------- #


def describe_ogg(data: bytes) -> Dict[str, str]:
    """Report the vendor string and tag names an Ogg currently exposes."""
    found: Dict[str, str] = {}
    if not is_ogg(data):
        return found
    try:
        pages = parse_pages(data)
    except OggError:
        return found

    by_serial: Dict[int, List[Page]] = {}
    for page in pages:
        by_serial.setdefault(page.serial, []).append(page)

    for stream_pages in by_serial.values():
        if not stream_pages or not stream_pages[0].is_bos:
            continue
        first_packets, _ = _extract_packets(stream_pages, 1)
        if not first_packets:
            continue
        codec = _identify_codec(first_packets[0])
        if codec is None:
            continue
        found["Ogg.Codec"] = codec

        header_count, _clean = _CODECS[codec]
        packets, _ = _extract_packets(stream_pages, header_count)
        if len(packets) < 2 or not _is_comment_packet(codec, packets[1]):
            continue
        found.update(_describe_comment(codec, packets[1]))
    return found


_COMMENT_PREFIX = {
    "vorbis": 7,
    "opus": 8,
    "theora": 7,
    "speex": 0,
}


def _describe_comment(codec: str, packet: bytes) -> Dict[str, str]:
    """Decode a Vorbis-comment block into reportable field names."""
    found: Dict[str, str] = {}
    p = _COMMENT_PREFIX[codec]
    try:
        vendor_len = int.from_bytes(packet[p : p + 4], "little")
        p += 4
        vendor = packet[p : p + vendor_len].decode("utf-8", "ignore")
        p += vendor_len
        if vendor:
            found["Ogg.Vendor"] = vendor[:100]

        count = int.from_bytes(packet[p : p + 4], "little")
        p += 4
        for _ in range(min(count, 64)):
            length = int.from_bytes(packet[p : p + 4], "little")
            p += 4
            entry = packet[p : p + length].decode("utf-8", "ignore")
            p += length
            name, _, value = entry.partition("=")
            if name:
                found[f"Ogg.{name.upper()}"] = value[:100] or "PRESENT"
    except (IndexError, ValueError):
        pass
    return found
