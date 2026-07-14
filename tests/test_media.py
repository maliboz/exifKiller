from __future__ import annotations

import os
import shutil
from contextlib import contextmanager
from pathlib import Path
from uuid import uuid4

from cleaners import isobmff, native_media
from exif_killer.models import ToolConfig
from exif_killer.service import MetadataToolService


@contextmanager
def workspace_tempdir() -> Path:
    path = Path(os.getcwd()) / f"exif-killer-media-{uuid4().hex}"
    path.mkdir(parents=True, exist_ok=False)
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


def _box(box_type: bytes, payload: bytes) -> bytes:
    return (8 + len(payload)).to_bytes(4, "big") + box_type + payload


def _build_mp4_with_gps() -> bytes:
    xyz = _box(b"\xa9xyz", b"\x00\x14\x00\x00+40.7128-074.0060/")
    software = _box(b"\xa9too", b"iPhone 14 Pro")
    udta = _box(b"udta", xyz + software)
    stco = _box(b"stco", b"\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x02\x00")
    stbl = _box(b"stbl", stco)
    moov = _box(b"moov", _box(b"trak", _box(b"mdia", _box(b"minf", stbl))) + udta)
    ftyp = _box(b"ftyp", b"isom\x00\x00\x02\x00isomiso2mp41")
    mdat = _box(b"mdat", b"\xDE\xAD\xBE\xEF" * 16)
    return ftyp + moov + mdat


def test_isobmff_movie_strips_gps_preserving_offsets() -> None:
    data = _build_mp4_with_gps()
    assert isobmff.describe_movie_metadata(data)["QuickTime.GPS"].startswith("+40.7128")

    cleaned, removed = isobmff.clean_movie(data)

    assert "udta" in removed
    assert b"+40.7128" not in cleaned
    assert b"iPhone 14 Pro" not in cleaned
    assert len(cleaned) == len(data)  # offsets preserved
    assert b"\xDE\xAD\xBE\xEF" * 16 in cleaned  # media payload intact
    assert b"\x00\x00\x02\x00" in cleaned  # stco offset table intact
    assert isobmff.describe_movie_metadata(cleaned) == {}


def _build_heif_with_exif() -> tuple[bytes, bytes, bytes]:
    """Craft a minimal HEIF with one Exif item; returns (data, img_a, img_b)."""
    exif_payload = b"\x00\x00\x00\x06Exif\x00\x00II*\x00SECRET-GPS-DATA"
    length = len(exif_payload)
    infe_payload = (
        b"\x02\x00\x00\x00" + (1).to_bytes(2, "big") + (0).to_bytes(2, "big")
        + b"Exif" + b"\x00"
    )
    infe = _box(b"infe", infe_payload)
    iinf = _box(b"iinf", b"\x00\x00\x00\x00" + (1).to_bytes(2, "big") + infe)
    img_before = b"IMAGEDATA-BEFORE"
    img_after = b"IMAGEDATA-AFTER"

    def build(offset: int) -> tuple[bytes, int]:
        iloc_payload = (
            b"\x01\x00\x00\x00" + bytes([0x44, 0x00]) + (1).to_bytes(2, "big")
            + (1).to_bytes(2, "big") + (0).to_bytes(2, "big") + (0).to_bytes(2, "big")
            + (1).to_bytes(2, "big") + offset.to_bytes(4, "big")
            + length.to_bytes(4, "big")
        )
        iloc = _box(b"iloc", iloc_payload)
        meta = _box(b"meta", b"\x00\x00\x00\x00" + iinf + iloc)
        ftyp = _box(b"ftyp", b"heic\x00\x00\x00\x00heicmif1")
        mdat = _box(b"mdat", img_before + exif_payload + img_after)
        data = ftyp + meta + mdat
        exif_abs = len(ftyp) + len(meta) + 8 + len(img_before)
        return data, exif_abs

    data, exif_abs = build(0)
    data, _ = build(exif_abs)  # second pass fixes the (fixed-width) offset
    return data, img_before, img_after


def test_heif_zeroes_exif_item_keeping_image() -> None:
    data, img_before, img_after = _build_heif_with_exif()
    assert isobmff.is_heif(data)
    assert isobmff.describe_heif_metadata(data) == {"EXIF": "PRESENT"}

    cleaned, removed = isobmff.clean_heif(data)

    assert "Exif" in removed
    assert b"SECRET-GPS-DATA" not in cleaned
    assert img_before in cleaned  # image bytes before the exif item survive
    assert img_after in cleaned  # image bytes after the exif item survive
    assert len(cleaned) == len(data)


def _synchsafe(n: int) -> bytes:
    return bytes([(n >> 21) & 0x7F, (n >> 14) & 0x7F, (n >> 7) & 0x7F, n & 0x7F])


def _build_mp3() -> tuple[bytes, bytes]:
    payload = b"\x00Alice Artist"
    frame = b"TPE1" + len(payload).to_bytes(4, "big") + b"\x00\x00" + payload
    id3v2 = b"ID3\x03\x00\x00" + _synchsafe(len(frame)) + frame
    audio = b"\xff\xfb\x90\x00" + b"\x00" * 256
    id3v1 = b"TAG" + b"song".ljust(30, b"\x00") + b"\x00" * 95
    return id3v2 + audio + id3v1, audio


def test_mp3_strips_id3_keeping_audio() -> None:
    mp3, audio = _build_mp3()
    assert native_media.describe_mp3(mp3)["ID3v2"] == "PRESENT"

    cleaned, removed = native_media.strip_mp3(mp3)

    assert "ID3v2" in removed and "ID3v1" in removed
    assert cleaned == audio
    assert b"Alice Artist" not in cleaned


def _build_flac() -> tuple[bytes, bytes]:
    def block(last: bool, btype: int, payload: bytes) -> bytes:
        return bytes([(0x80 if last else 0) | btype]) + len(payload).to_bytes(3, "big") + payload

    streaminfo = block(False, 0, b"\x00" * 34)
    vorbis = block(False, 4, b"reference libFLAC secret")
    picture = block(True, 6, b"\x00" * 40)
    audio = b"\xff\xf8" + b"\x11" * 128
    return b"fLaC" + streaminfo + vorbis + picture + audio, audio


def test_flac_strips_comment_and_picture() -> None:
    flac, audio = _build_flac()
    described = native_media.describe_flac(flac)
    assert described["FLAC.VorbisComment"] == "PRESENT"

    cleaned, removed = native_media.strip_flac(flac)

    assert "VorbisComment" in removed and "Picture" in removed
    assert b"libFLAC secret" not in cleaned
    assert audio in cleaned
    assert native_media.describe_flac(cleaned) == {}


def _rchunk(cid: bytes, payload: bytes) -> bytes:
    pad = b"\x00" if len(payload) & 1 else b""
    return cid + len(payload).to_bytes(4, "little") + payload + pad


def _build_wav() -> bytes:
    fmt = _rchunk(b"fmt ", b"\x01\x00" * 8)
    info = _rchunk(b"LIST", b"INFO" + _rchunk(b"IART", b"Alice Artist"))
    data = _rchunk(b"data", b"\x7f" * 100)
    body = fmt + info + data
    return b"RIFF" + (len(body) + 4).to_bytes(4, "little") + b"WAVE" + body


def test_wav_strips_info_keeping_audio() -> None:
    wav = _build_wav()
    assert native_media.describe_riff(wav)["RIFF.INFO"] == "PRESENT"

    cleaned, removed = native_media.strip_riff(wav)

    assert "INFO" in removed
    assert b"Alice Artist" not in cleaned
    assert b"\x7f" * 100 in cleaned
    assert b"fmt " in cleaned


def test_service_cleans_mp4_end_to_end() -> None:
    with workspace_tempdir() as tmp:
        src = tmp / "clip.mp4"
        src.write_bytes(_build_mp4_with_gps())

        service = MetadataToolService(ToolConfig(profile="safe"))
        result = service.clean_file(str(src))

        assert result.status == "clean"
        out = Path(result.output_path).read_bytes()
        assert b"+40.7128" not in out
        assert b"\xDE\xAD\xBE\xEF" * 16 in out


def test_service_cleans_mp3_end_to_end() -> None:
    with workspace_tempdir() as tmp:
        src = tmp / "song.mp3"
        mp3, _ = _build_mp3()
        src.write_bytes(mp3)

        service = MetadataToolService(ToolConfig(profile="safe"))
        result = service.clean_file(str(src))

        assert result.status == "clean"
        assert b"Alice Artist" not in Path(result.output_path).read_bytes()
