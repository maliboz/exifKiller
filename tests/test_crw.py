"""Tests for the native Canon CRW (CIFF) engine.

CRW is not TIFF: its directory sits at the end of each block and the block's
last four bytes say where it starts. These fixtures build that layout by hand.
"""

from __future__ import annotations

import os
import shutil
from contextlib import contextmanager
from pathlib import Path
from uuid import uuid4

from cleaners import ciff
from cleaners.integrity import check_integrity
from exif_killer.models import ToolConfig
from exif_killer.service import MetadataToolService


@contextmanager
def workspace_tempdir():
    path = Path(os.getcwd()) / f"exif-killer-crw-{uuid4().hex}"
    path.mkdir(parents=True, exist_ok=False)
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


# --------------------------------------------------------------------------- #
# CIFF builder
# --------------------------------------------------------------------------- #

RAW_DATA = bytes(range(256)) * 8  # 2048 bytes standing in for sensor data
DECODER_TABLE = b"\x11\x22\x33\x44" * 4


def _u16(v: int) -> bytes:
    return v.to_bytes(2, "little")


def _u32(v: int) -> bytes:
    return v.to_bytes(4, "little")


def _build_block(records):
    """Build a CIFF block from (tag, payload_or_None, inline_bytes) records.

    Returns the block bytes. Heap values come first, then the directory, then
    the 4-byte pointer back to the directory start.
    """
    heap = bytearray()
    placed = []  # (tag, length, offset)

    for tag, payload in records:
        if tag & ciff._TAG_INLINE:
            # Inline: the 8 bytes of length+offset hold the value itself.
            placed.append((tag, payload))
            continue
        offset = len(heap)
        heap += payload
        if len(heap) & 1:
            heap += b"\x00"  # keep values even-aligned
        placed.append((tag, (len(payload), offset)))

    dir_start = len(heap)
    directory = bytearray(_u16(len(placed)))
    for tag, value in placed:
        directory += _u16(tag)
        if tag & ciff._TAG_INLINE:
            directory += value.ljust(8, b"\x00")[:8]
        else:
            length, offset = value
            directory += _u32(length) + _u32(offset)

    return bytes(heap) + bytes(directory) + _u32(dir_start)


def _build_crw(owner=b"Alice Photographer\x00",
               serial=b"1234567890\x00",
               make_model=b"Canon\x00Canon EOS 10D\x00",
               with_subdir=True,
               header_len=26):
    """Assemble a CRW: header + a heap whose directory sits at the end."""
    header = (
        b"II"
        + _u32(header_len)
        + b"HEAPCCDR"
        + b"\x00\x01\x00\x02"
        + b"\x00" * (header_len - 18)
    )

    records = [
        (0x2005, RAW_DATA),                 # RawData - must survive
        (0x1835, DECODER_TABLE),            # DecoderTable - must survive
        (0x0810, owner),                    # OwnerName - must go
        (0x180B, serial),                   # SerialNumber - must go
        (0x080A, make_model),               # Make/Model - aggressive only
        (0x080B, b"Firmware Version 1.0.4\x00"),
        (0x0815, b"CRW:EOS DIGITAL REBEL CMOS RAW\x00"),
        (0x1817, b"\x01\x02\x03\x04"),      # FileNumber - must go
        (0x4810, b"\x01\x02\x03\x04"),      # inline tag, kept
    ]

    if with_subdir:
        sub = _build_block([
            (0x180E, b"\xde\xad\xbe\xef\x00\x00\x00\x00"),  # TimeStamp
            (0x1031, b"SENSORINFO-KEEPME"),                  # must survive
        ])
        records.append((0x300A, sub))  # ImageProps subdirectory

    return header + _build_block(records)


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #


def test_crw_is_detected() -> None:
    data = _build_crw()
    assert ciff.is_crw(data)
    assert not ciff.is_crw(b"II*\x00" + b"\x00" * 32)  # a TIFF is not a CRW


def test_crw_parses_directory_tree() -> None:
    ciff_file = ciff.CIFFFile(_build_crw())

    # The root plus the ImageProps sub-block.
    assert len(ciff_file.directories) == 2
    root = ciff_file.directories[0]
    tags = [entry.tag for entry in root.entries]
    assert 0x2005 in tags and 0x0810 in tags and 0x300A in tags

    subdir_entry = next(e for e in root.entries if e.tag == 0x300A)
    assert subdir_entry.is_subdirectory
    sub_tags = [e.tag for e in ciff_file.directories[1].entries]
    assert 0x180E in sub_tags and 0x1031 in sub_tags


def test_crw_reads_values() -> None:
    ciff_file = ciff.CIFFFile(_build_crw())
    root = ciff_file.directories[0]
    owner = next(e for e in root.entries if e.tag == 0x0810)
    assert ciff_file.value_str(owner) == "Alice Photographer"

    raw = next(e for e in root.entries if e.tag == 0x2005)
    assert ciff_file.value_bytes(raw) == RAW_DATA


def test_crw_inline_values_are_read_from_the_entry() -> None:
    ciff_file = ciff.CIFFFile(_build_crw())
    root = ciff_file.directories[0]
    inline = next(e for e in root.entries if e.tag == 0x4810)
    assert inline.inline
    assert ciff_file.value_bytes(inline)[:4] == b"\x01\x02\x03\x04"


def test_crw_describe_finds_metadata() -> None:
    described = ciff.describe_crw(_build_crw())
    assert described["CRW.OwnerName"] == "Alice Photographer"
    assert described["CRW.SerialNumber"] == "1234567890"
    assert described["CRW.CanonRawMakeModel"] == "Canon"
    assert described["CRW.CanonFirmwareVersion"] == "Firmware Version 1.0.4"
    assert described["CRW.TimeStamp"] == "PRESENT"


# --------------------------------------------------------------------------- #
# Cleaning
# --------------------------------------------------------------------------- #


def test_crw_strips_identity_without_moving_bytes() -> None:
    data = _build_crw()
    cleaned, removed = ciff.clean_crw(data)

    assert len(cleaned) == len(data)  # offsets into the heap stay valid
    assert RAW_DATA in cleaned         # sensor data untouched
    assert DECODER_TABLE in cleaned    # still decodable

    for secret in [b"Alice Photographer", b"1234567890",
                   b"Firmware Version 1.0.4", b"CRW:EOS DIGITAL REBEL"]:
        assert secret not in cleaned, f"{secret!r} survived"

    for name in ("OwnerName", "SerialNumber", "CanonFirmwareVersion",
                 "CanonImageType", "FileNumber", "TimeStamp"):
        assert name in removed

    described = ciff.describe_crw(cleaned)
    assert "CRW.OwnerName" not in described
    assert "CRW.SerialNumber" not in described
    assert "CRW.TimeStamp" not in described


def test_crw_safe_keeps_make_and_model() -> None:
    data = _build_crw()

    safe, _ = ciff.clean_crw(data, aggressive=False)
    assert b"Canon EOS 10D" in safe
    assert ciff.describe_crw(safe)["CRW.CanonRawMakeModel"] == "Canon"

    hard, removed = ciff.clean_crw(data, aggressive=True)
    assert "CanonRawMakeModel" in removed
    assert b"Canon EOS 10D" not in hard


def test_crw_cleans_nested_subdirectory() -> None:
    """The TimeStamp lives in a sub-block, which must be cleaned too."""
    data = _build_crw()
    assert b"\xde\xad\xbe\xef" in data

    cleaned, removed = ciff.clean_crw(data)

    assert "TimeStamp" in removed
    assert b"\xde\xad\xbe\xef" not in cleaned
    assert b"SENSORINFO-KEEPME" in cleaned  # its sibling must survive


def test_crw_cleaned_file_still_parses_and_directory_is_consistent() -> None:
    data = _build_crw()
    cleaned, _ = ciff.clean_crw(data)

    parsed = ciff.CIFFFile(cleaned)
    assert len(parsed.directories) == 2
    for directory in parsed.directories:
        # The count must match the entries, and they must fit in the block.
        assert len(directory.entries) == parsed._u16(directory.dir_offset)
        assert directory.entries_end <= directory.block_end
    root = parsed.directories[0]
    assert any(e.tag == 0x2005 for e in root.entries)  # RawData still reachable


def test_crw_never_drops_structural_records() -> None:
    """A policy bug must not be able to remove what decoding depends on."""
    for tag in (ciff.TAG_RAW_DATA, 0x1835, 0x1031, 0x1810, 0x10A9):
        assert tag not in ciff._drop_map(aggressive=True)


def test_crw_rejects_a_tiff() -> None:
    try:
        ciff.clean_crw(b"II*\x00" + b"\x08\x00\x00\x00" + b"\x00" * 64)
    except ciff.CIFFError as exc:
        assert "HEAPCCDR" in str(exc)
    else:
        raise AssertionError("expected CIFFError")


def test_crw_rejects_headerless_data_with_an_actionable_message() -> None:
    """What the user's own CRW_0441.CRW turned out to be: no CIFF header."""
    try:
        ciff.clean_crw(b"\x82\x08\x80\x00\x07\x21\xf0\x41" * 8)
    except ciff.CIFFError as exc:
        message = str(exc)
        assert "corrupt" in message or "wrong extension" in message
    else:
        raise AssertionError("expected CIFFError")


def test_crw_rejects_implausible_record_count() -> None:
    """dcraw's guard: a real directory never holds hundreds of records."""
    data = bytearray(_build_crw())
    root_dir_offset = 26 + int.from_bytes(data[-4:], "little")
    data[root_dir_offset : root_dir_offset + 2] = (9999).to_bytes(2, "little")
    try:
        ciff.clean_crw(bytes(data))
    except ciff.CIFFError as exc:
        assert "record count" in str(exc)
    else:
        raise AssertionError("expected CIFFError")


# --------------------------------------------------------------------------- #
# Integrity + service
# --------------------------------------------------------------------------- #


def test_crw_integrity_passes_on_correct_output() -> None:
    data = _build_crw()
    cleaned, _ = ciff.clean_crw(data, aggressive=True)
    checks = check_integrity(".crw", data, cleaned)
    failed = {c.name for c in checks if not c.passed}
    assert not failed, f"unexpected failures: {failed}"


def test_crw_integrity_catches_damaged_raw_data() -> None:
    data = _build_crw()
    cleaned = bytearray(ciff.clean_crw(data)[0])
    index = cleaned.find(RAW_DATA)
    assert index != -1
    cleaned[index + 10] ^= 0xFF

    checks = check_integrity(".crw", data, bytes(cleaned))
    assert "sensor-data" in {c.name for c in checks if not c.passed}


def test_service_cleans_crw_end_to_end() -> None:
    with workspace_tempdir() as tmp:
        src = tmp / "CRW_0001.CRW"
        src.write_bytes(_build_crw())
        original_size = src.stat().st_size

        service = MetadataToolService(ToolConfig(profile="aggressive"))
        before = service.scan_file(str(src))
        assert before.status == "warning"
        assert before.file_type == "raw"
        assert any(f.key == "CRW.SerialNumber" for f in before.blocking_findings)

        result = service.clean_file(str(src))
        assert result.status == "clean", result.remaining_findings

        out = Path(result.output_path)
        assert out.stat().st_size == original_size
        blob = out.read_bytes()
        assert b"Alice Photographer" not in blob
        assert b"1234567890" not in blob
        assert RAW_DATA in blob
