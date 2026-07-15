"""Tests for the native Matroska (EBML) and Ogg container engines."""

from __future__ import annotations

import io
import os
import shutil
from contextlib import contextmanager
from pathlib import Path
from uuid import uuid4

import pytest

from cleaners import matroska, ogg
from exif_killer.models import ToolConfig
from exif_killer.service import MetadataToolService


@contextmanager
def workspace_tempdir():
    path = Path(os.getcwd()) / f"exif-killer-containers-{uuid4().hex}"
    path.mkdir(parents=True, exist_ok=False)
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


# --------------------------------------------------------------------------- #
# Matroska fixtures
# --------------------------------------------------------------------------- #


def _eid(value: int) -> bytes:
    """Encode an EBML element ID (marker bits are already part of the value)."""
    return value.to_bytes((value.bit_length() + 7) // 8, "big")


def _esize(n: int) -> bytes:
    for length in range(1, 9):
        if n <= (1 << (7 * length)) - 2:
            return (n | (1 << (7 * length))).to_bytes(length, "big")
    raise ValueError("size too large")


def _el(eid: int, payload: bytes) -> bytes:
    return _eid(eid) + _esize(len(payload)) + payload


def _build_mkv() -> bytes:
    ebml_header = _el(matroska.ID_EBML_HEADER, _el(0x4282, b"matroska"))

    info = _el(
        matroska.ID_INFO,
        _el(matroska.ID_MUXING_APP, b"Lavf58.29.100")
        + _el(matroska.ID_WRITING_APP, b"HandBrake 1.3.1")
        + _el(matroska.ID_TITLE, b"Operation Nightfall")
        + _el(matroska.ID_DATE_UTC, b"\x01\x02\x03\x04\x05\x06\x07\x08")
        + _el(matroska.ID_SEGMENT_UID, bytes(range(16)))
        + _el(matroska.ID_SEGMENT_FILENAME, b"C:/Users/alice/secret.mkv")
        + _el(0x2AD7B1, b"\x0f\x42\x40"),  # TimestampScale (kept)
    )
    tracks = _el(
        matroska.ID_TRACKS,
        _el(
            matroska.ID_TRACK_ENTRY,
            _el(0xD7, b"\x01")  # TrackNumber (kept)
            + _el(matroska.ID_TRACK_NAME, b"Alice Camera A")
            + _el(matroska.ID_CODEC_NAME, b"x264 core 155"),
        ),
    )
    tags = _el(
        matroska.ID_TAGS,
        _el(0x7373, _el(0x67C8, _el(0x45A3, b"ARTIST") + _el(0x4487, b"Alice"))),
    )
    attachments = _el(
        matroska.ID_ATTACHMENTS,
        _el(0x61A7, _el(0x466E, b"cover.jpg") + _el(0x465C, b"\xff\xd8\xff\xe0COVER")),
    )
    cluster = _el(matroska.ID_CLUSTER, b"\xa3" + b"\x81" + b"\x11" * 64)

    seek_head = _el(
        matroska.ID_SEEK_HEAD,
        _el(
            matroska.ID_SEEK,
            _el(matroska.ID_SEEK_ID, _eid(matroska.ID_TAGS))
            + _el(0x53AC, b"\x00\x00\x10\x00"),  # SeekPosition
        )
        + _el(
            matroska.ID_SEEK,
            _el(matroska.ID_SEEK_ID, _eid(matroska.ID_INFO))
            + _el(0x53AC, b"\x00\x00\x00\x40"),
        ),
    )

    segment_body = seek_head + info + tracks + tags + attachments + cluster
    return ebml_header + _el(matroska.ID_SEGMENT, segment_body)


# --------------------------------------------------------------------------- #
# Matroska tests
# --------------------------------------------------------------------------- #


def test_matroska_describe_finds_metadata() -> None:
    described = matroska.describe_matroska(_build_mkv())

    assert described["Matroska.Title"] == "Operation Nightfall"
    assert described["Matroska.WritingApp"] == "HandBrake 1.3.1"
    assert described["Matroska.MuxingApp"] == "Lavf58.29.100"
    assert described["Matroska.SegmentFilename"] == "C:/Users/alice/secret.mkv"
    assert described["Matroska.TrackName"] == "Alice Camera A"
    assert described["Matroska.Tags"] == "PRESENT"
    assert described["Matroska.Attachments"] == "PRESENT"
    assert described["Matroska.DateUTC"] == "PRESENT"


def test_matroska_strips_metadata_without_moving_bytes() -> None:
    data = _build_mkv()
    cleaned, removed = matroska.clean_matroska(data)

    # Every removal is an in-place Void, so offsets (SeekHead/Cues) survive.
    assert len(cleaned) == len(data)
    assert b"\x11" * 64 in cleaned  # cluster payload untouched

    assert b"Operation Nightfall" not in cleaned
    assert b"HandBrake 1.3.1" not in cleaned
    assert b"Lavf58.29.100" not in cleaned
    assert b"C:/Users/alice/secret.mkv" not in cleaned
    assert b"Alice Camera A" not in cleaned
    assert b"cover.jpg" not in cleaned
    assert b"ARTIST" not in cleaned

    for name in ("Tags", "Attachments", "Title", "DateUTC", "SegmentUID",
                 "SegmentFilename", "MuxingApp", "WritingApp", "TrackName"):
        assert name in removed

    assert matroska.describe_matroska(cleaned) == {}


def test_matroska_cleaned_output_still_parses_as_ebml() -> None:
    """The Void replacements must leave a walkable EBML document."""
    cleaned, _ = matroska.clean_matroska(_build_mkv())

    segment = matroska._find_segment(cleaned)
    assert segment is not None

    children = list(
        matroska.iter_elements(cleaned, segment.payload_start, segment.payload_end)
    )
    # Nothing overruns the segment: the last child must end exactly at its end.
    assert children[-1].end == segment.payload_end
    ids = [child.eid for child in children]
    assert matroska.ID_VOID in ids
    assert matroska.ID_TAGS not in ids
    assert matroska.ID_ATTACHMENTS not in ids
    assert matroska.ID_CLUSTER in ids  # Cluster survives


def test_matroska_keeps_mandatory_elements_as_zeroed_strings() -> None:
    cleaned, _ = matroska.clean_matroska(_build_mkv())
    segment = matroska._find_segment(cleaned)
    info = next(
        c for c in matroska.iter_elements(cleaned, segment.payload_start,
                                          segment.payload_end)
        if c.eid == matroska.ID_INFO
    )
    fields = {
        c.eid: cleaned[c.payload_start : c.payload_end]
        for c in matroska.iter_elements(cleaned, info.payload_start, info.payload_end)
    }
    # MuxingApp/WritingApp are mandatory: kept, but blanked (zero-padded).
    assert fields[matroska.ID_MUXING_APP] == b"\x00" * len(b"Lavf58.29.100")
    assert fields[matroska.ID_WRITING_APP] == b"\x00" * len(b"HandBrake 1.3.1")
    # TimestampScale is functional and must be preserved verbatim.
    assert fields[0x2AD7B1] == b"\x0f\x42\x40"


def test_matroska_prunes_stale_seek_entries() -> None:
    """A SeekHead entry pointing at a voided element must itself be voided."""
    cleaned, _ = matroska.clean_matroska(_build_mkv())
    segment = matroska._find_segment(cleaned)
    seek_head = next(
        c for c in matroska.iter_elements(cleaned, segment.payload_start,
                                          segment.payload_end)
        if c.eid == matroska.ID_SEEK_HEAD
    )
    entries = list(
        matroska.iter_elements(cleaned, seek_head.payload_start,
                               seek_head.payload_end)
    )
    kinds = [e.eid for e in entries]
    assert matroska.ID_VOID in kinds  # the Tags pointer was pruned
    assert matroska.ID_SEEK in kinds  # the Info pointer survives


def test_matroska_chapters_only_dropped_when_aggressive() -> None:
    chapters = _el(matroska.ID_CHAPTERS, _el(0x45B9, b"\x01\x02\x03\x04"))
    body = _el(matroska.ID_INFO, _el(matroska.ID_TITLE, b"x")) + chapters
    data = _el(matroska.ID_EBML_HEADER, b"") + _el(matroska.ID_SEGMENT, body)

    safe, _ = matroska.clean_matroska(data, aggressive=False)
    assert "Matroska.Chapters" in matroska.describe_matroska(safe)

    hard, removed = matroska.clean_matroska(data, aggressive=True)
    assert "Chapters" in removed
    assert "Matroska.Chapters" not in matroska.describe_matroska(hard)


def test_matroska_rejects_non_matroska() -> None:
    try:
        matroska.clean_matroska(b"not an ebml document at all")
    except matroska.MatroskaError:
        pass
    else:
        raise AssertionError("expected MatroskaError")


def test_void_element_roundtrip_preserves_size() -> None:
    """Void encoding must hit the exact target size for any plausible length."""
    for total in [2, 3, 4, 10, 127, 128, 129, 500, 16_000, 20_000]:
        buf = bytearray(b"\xAA" * (total + 4))
        assert matroska._void_element(buf, 2, total)
        elements = list(matroska.iter_elements(bytes(buf), 2, 2 + total))
        assert len(elements) == 1
        assert elements[0].eid == matroska.ID_VOID
        assert elements[0].total_size == total


# --------------------------------------------------------------------------- #
# Ogg fixtures
# --------------------------------------------------------------------------- #

_SERIAL = 0x12345678


def _vorbis_comment_body(vendor: bytes, comments: list) -> bytes:
    out = len(vendor).to_bytes(4, "little") + vendor
    out += len(comments).to_bytes(4, "little")
    for comment in comments:
        out += len(comment).to_bytes(4, "little") + comment
    return out


def _opus_head() -> bytes:
    return (
        b"OpusHead" + bytes([1, 2]) + (312).to_bytes(2, "little")
        + (48000).to_bytes(4, "little") + (0).to_bytes(2, "little") + b"\x00"
    )


def _build_opus(comments=None, cover_bytes: int = 0):
    comments = comments if comments is not None else [
        b"ARTIST=Alice Secret",
        b"TITLE=Private Recording",
        b"LOCATION=41.0082,28.9784",
    ]
    if cover_bytes:
        comments = comments + [b"METADATA_BLOCK_PICTURE=" + b"P" * cover_bytes]

    head = _opus_head()
    tags = b"OpusTags" + _vorbis_comment_body(b"libopus 1.3.1", comments)
    audio = [b"\xfc" + b"\xAA" * 100, b"\xfc" + b"\xBB" * 100]

    pages = [
        ogg.build_page(0x02, 0, _SERIAL, 0, ogg._lace(len(head)), head),
    ]
    tag_pages = ogg._paginate([tags], _SERIAL, 1, bos=False)
    pages += tag_pages
    seq = 1 + len(tag_pages)
    pages.append(ogg.build_page(0x00, 960, _SERIAL, seq,
                                ogg._lace(len(audio[0])), audio[0]))
    pages.append(ogg.build_page(0x04, 1920, _SERIAL, seq + 1,
                                ogg._lace(len(audio[1])), audio[1]))
    return b"".join(pages), audio


# --------------------------------------------------------------------------- #
# Ogg tests
# --------------------------------------------------------------------------- #


def _naive_ogg_crc(data: bytes) -> int:
    """Reference bit-by-bit Ogg CRC, independent of the table-driven version."""
    crc = 0
    for byte in data:
        crc ^= byte << 24
        for _ in range(8):
            if crc & 0x80000000:
                crc = ((crc << 1) ^ 0x04C11DB7) & 0xFFFFFFFF
            else:
                crc = (crc << 1) & 0xFFFFFFFF
    return crc


def test_ogg_crc_matches_reference_implementation() -> None:
    for sample in [b"", b"a", b"123456789", b"OggS" + bytes(range(256)) * 3]:
        assert ogg._ogg_crc(sample) == _naive_ogg_crc(sample)


def _assert_every_page_crc_valid(data: bytes) -> None:
    for page in ogg.parse_pages(data):
        raw = data[page.start : page.end]
        stored = int.from_bytes(raw[22:26], "little")
        recomputed = _naive_ogg_crc(raw[:22] + b"\x00\x00\x00\x00" + raw[26:])
        assert stored == recomputed, f"bad CRC on page {page.sequence}"


def test_ogg_describe_finds_tags() -> None:
    data, _ = _build_opus()
    described = ogg.describe_ogg(data)

    assert described["Ogg.Codec"] == "opus"
    assert described["Ogg.Vendor"] == "libopus 1.3.1"
    assert described["Ogg.ARTIST"] == "Alice Secret"
    assert described["Ogg.TITLE"] == "Private Recording"
    assert described["Ogg.LOCATION"] == "41.0082,28.9784"


def test_opus_strips_tags_keeping_audio() -> None:
    data, audio = _build_opus()
    cleaned, removed = ogg.clean_ogg(data)

    assert "OpusComment" in removed
    assert b"Alice Secret" not in cleaned
    assert b"41.0082" not in cleaned
    assert b"libopus 1.3.1" not in cleaned

    # Audio packets survive byte-for-byte.
    for packet in audio:
        assert packet in cleaned

    assert ogg.describe_ogg(cleaned) == {"Ogg.Codec": "opus"}
    _assert_every_page_crc_valid(cleaned)


def test_opus_output_keeps_ident_header_alone_on_first_page() -> None:
    """RFC 7845: the identification header must be alone on the BOS page."""
    data, _ = _build_opus()
    cleaned, _ = ogg.clean_ogg(data)

    pages = ogg.parse_pages(cleaned)
    assert pages[0].is_bos
    assert pages[0].body == _opus_head()
    assert pages[0].segments == ogg._lace(len(_opus_head()))


def test_opus_pages_are_renumbered_when_cover_art_is_dropped() -> None:
    """A multi-page comment header collapses to one page; the tail renumbers."""
    data, audio = _build_opus(cover_bytes=70_000)
    original_pages = ogg.parse_pages(data)
    # The oversized comment header really did need more than one page.
    assert sum(1 for p in original_pages if not p.is_bos and p.granule == 0) > 1

    cleaned, removed = ogg.clean_ogg(data)
    assert "OpusComment" in removed
    assert b"P" * 1000 not in cleaned

    pages = ogg.parse_pages(cleaned)
    assert [p.sequence for p in pages] == list(range(len(pages)))
    assert len(pages) < len(original_pages)
    for packet in audio:
        assert packet in cleaned
    _assert_every_page_crc_valid(cleaned)


def test_ogg_preserves_granule_and_eos_on_audio_pages() -> None:
    data, _ = _build_opus()
    cleaned, _ = ogg.clean_ogg(data)

    audio_pages = [p for p in ogg.parse_pages(cleaned) if p.granule > 0]
    assert [p.granule for p in audio_pages] == [960, 1920]
    assert audio_pages[-1].header_type & 0x04  # EOS flag kept


def test_ogg_leaves_already_clean_file_untouched() -> None:
    data, _ = _build_opus(comments=[])
    # Rebuild with an empty vendor too, so it is already minimal.
    head = _opus_head()
    tags = b"OpusTags" + _vorbis_comment_body(b"", [])
    pristine = (
        ogg.build_page(0x02, 0, _SERIAL, 0, ogg._lace(len(head)), head)
        + ogg.build_page(0x00, 0, _SERIAL, 1, ogg._lace(len(tags)), tags)
    )
    cleaned, removed = ogg.clean_ogg(pristine)
    assert removed == []
    assert cleaned == pristine


def test_ogg_rejects_non_ogg() -> None:
    try:
        ogg.clean_ogg(b"ID3\x03\x00\x00 this is an mp3")
    except ogg.OggError:
        pass
    else:
        raise AssertionError("expected OggError")


# --------------------------------------------------------------------------- #
# Independent cross-check
#
# Everything above validates our parsers against our own parsers, which cannot
# catch a blind spot shared by both. mutagen is a third-party Ogg implementation
# used here purely as an oracle: it must see the tags before cleaning, and must
# still parse the result as a valid OggOpus afterwards. It is a dev/test extra
# only — the tool itself never imports it.
# --------------------------------------------------------------------------- #

try:  # pragma: no cover - depends on the dev environment
    from mutagen.oggopus import OggOpus as _OggOpus
except ImportError:  # pragma: no cover
    _OggOpus = None

requires_mutagen = pytest.mark.skipif(
    _OggOpus is None, reason="mutagen not installed (dev-only cross-check)"
)


@requires_mutagen
def test_opus_verified_by_independent_parser() -> None:
    data, _audio = _build_opus()

    before = _OggOpus(io.BytesIO(data))
    assert dict(before.tags) == {
        "artist": ["Alice Secret"],
        "title": ["Private Recording"],
        "location": ["41.0082,28.9784"],
    }

    cleaned, _removed = ogg.clean_ogg(data)

    after = _OggOpus(io.BytesIO(cleaned))
    assert dict(after.tags) == {}
    assert after.tags.vendor == ""
    # The stream still decodes: mutagen re-read OpusHead out of the rebuilt page.
    assert after.info.channels == before.info.channels


@requires_mutagen
def test_opus_with_cover_art_verified_by_independent_parser() -> None:
    data, _audio = _build_opus(cover_bytes=70_000)

    before = _OggOpus(io.BytesIO(data))
    assert "metadata_block_picture" in dict(before.tags)

    cleaned, _removed = ogg.clean_ogg(data)

    after = _OggOpus(io.BytesIO(cleaned))
    assert dict(after.tags) == {}
    assert after.info.channels == before.info.channels


# --------------------------------------------------------------------------- #
# End-to-end through the service
# --------------------------------------------------------------------------- #


def test_service_cleans_mkv_end_to_end() -> None:
    with workspace_tempdir() as tmp:
        src = tmp / "clip.mkv"
        src.write_bytes(_build_mkv())

        service = MetadataToolService(ToolConfig(profile="safe"))
        before = service.scan_file(str(src))
        assert before.status == "warning"
        assert before.file_type == "video"

        result = service.clean_file(str(src))
        assert result.status == "clean"

        out = Path(result.output_path).read_bytes()
        assert b"Operation Nightfall" not in out
        assert b"HandBrake" not in out
        assert b"\x11" * 64 in out


def test_service_cleans_opus_end_to_end() -> None:
    with workspace_tempdir() as tmp:
        src = tmp / "voice.opus"
        data, audio = _build_opus()
        src.write_bytes(data)

        service = MetadataToolService(ToolConfig(profile="safe"))
        before = service.scan_file(str(src))
        assert before.status == "warning"
        assert before.file_type == "audio"

        result = service.clean_file(str(src))
        assert result.status == "clean"

        out = Path(result.output_path).read_bytes()
        assert b"Alice Secret" not in out
        assert audio[0] in out
