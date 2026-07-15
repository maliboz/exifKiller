"""Tests for the integrity checks and the corpus self-test harness.

The point of these tests is adversarial: a harness that always says PASS is
worse than no harness, so most of what follows deliberately damages a cleaned
file and asserts the checks notice.
"""

from __future__ import annotations

import os
import shutil
import zipfile
from contextlib import contextmanager
from pathlib import Path
from uuid import uuid4

from cleaners import isobmff, matroska, ogg, tiff_raw
from cleaners.integrity import check_integrity
from exif_killer.selftest import (
    STATUS_DAMAGED,
    STATUS_PASS,
    STATUS_RESIDUAL,
    render_selftest,
    render_wishlist,
    run_selftest,
)

from test_containers import _build_mkv, _build_opus
from test_media import _build_mp3, _build_mp4_with_gps
from test_raw_odf import _build_odt, _build_tiff, _dirty_tags, _gps_tags


@contextmanager
def workspace_tempdir():
    path = Path(os.getcwd()) / f"exif-killer-selftest-{uuid4().hex}"
    path.mkdir(parents=True, exist_ok=False)
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


def _failed(checks):
    return {c.name for c in checks if not c.passed}


# --------------------------------------------------------------------------- #
# The checks must pass on genuinely correct output
# --------------------------------------------------------------------------- #


def test_integrity_passes_on_correctly_cleaned_files() -> None:
    cases = [
        (".dng", _build_tiff(_dirty_tags(), gps_tags=_gps_tags()),
         lambda d: tiff_raw.clean_tiff(d, True)[0]),
        (".mkv", _build_mkv(), lambda d: matroska.clean_matroska(d, True)[0]),
        (".mp4", _build_mp4_with_gps(), lambda d: isobmff.clean_movie(d, True)[0]),
        (".opus", _build_opus()[0], lambda d: ogg.clean_ogg(d, True)[0]),
    ]
    for ext, original, clean in cases:
        checks = check_integrity(ext, original, clean(original))
        assert not _failed(checks), f"{ext}: unexpected failures {_failed(checks)}"


# --------------------------------------------------------------------------- #
# ...and must fail when the payload is damaged
# --------------------------------------------------------------------------- #


def test_integrity_catches_damaged_raw_sensor_data() -> None:
    original = _build_tiff(_dirty_tags())
    cleaned = bytearray(tiff_raw.clean_tiff(original)[0])

    # Corrupt one byte of the sensor strip, keeping the file size identical.
    tiff = tiff_raw.TiffFile(bytes(cleaned))
    offset = tiff.value_ints(tiff.ifds[0].get(273))[0]
    cleaned[offset + 5] ^= 0xFF

    checks = check_integrity(".dng", original, bytes(cleaned))
    assert "sensor-data" in _failed(checks)


def test_integrity_catches_resized_raw() -> None:
    original = _build_tiff(_dirty_tags())
    cleaned = tiff_raw.clean_tiff(original)[0] + b"\x00"
    checks = check_integrity(".dng", original, cleaned)
    assert "size-preserved" in _failed(checks)


def test_integrity_catches_dropped_structural_tag() -> None:
    """Deleting StripOffsets makes the image undecodable; the check must see it."""
    original = _build_tiff(_dirty_tags())
    cleaned = bytearray(tiff_raw.clean_tiff(original)[0])

    tiff = tiff_raw.TiffFile(bytes(cleaned))
    entry = tiff.ifds[0].get(273)
    # Rename StripOffsets to an unrelated private tag, in place.
    cleaned[entry.pos : entry.pos + 2] = (60000).to_bytes(2, "little")

    checks = check_integrity(".dng", original, bytes(cleaned))
    assert _failed(checks)  # structural-tags and/or sensor-data must complain


def test_integrity_catches_damaged_matroska_cluster() -> None:
    original = _build_mkv()
    cleaned = bytearray(matroska.clean_matroska(original)[0])
    index = cleaned.find(b"\x11" * 64)
    assert index != -1
    cleaned[index + 3] ^= 0xFF

    checks = check_integrity(".mkv", original, bytes(cleaned))
    assert "clusters-preserved" in _failed(checks)


def test_integrity_catches_damaged_mp4_mdat() -> None:
    original = _build_mp4_with_gps()
    cleaned = bytearray(isobmff.clean_movie(original)[0])
    index = cleaned.find(b"\xDE\xAD\xBE\xEF")
    assert index != -1
    cleaned[index] = 0x00

    checks = check_integrity(".mp4", original, bytes(cleaned))
    assert "mdat-preserved" in _failed(checks)


def test_integrity_catches_bad_ogg_crc() -> None:
    original, _audio = _build_opus()
    cleaned = bytearray(ogg.clean_ogg(original)[0])
    # Flip a byte inside the first page's CRC field.
    cleaned[22] ^= 0xFF

    checks = check_integrity(".opus", original, bytes(cleaned))
    assert "crc" in _failed(checks)


def test_integrity_catches_reencoded_jpeg() -> None:
    """A quality-95 re-encode keeps the pixels close but rewrites the scan."""
    from PIL import Image

    import io

    image = Image.new("RGB", (32, 32), (120, 60, 30))
    buf = io.BytesIO()
    image.save(buf, format="JPEG", quality=92)
    original = buf.getvalue()

    reencoded = io.BytesIO()
    Image.open(io.BytesIO(original)).save(reencoded, format="JPEG", quality=95)

    checks = check_integrity(".jpg", original, reencoded.getvalue())
    assert "scan-preserved" in _failed(checks)


def test_integrity_catches_odf_with_misplaced_mimetype() -> None:
    with workspace_tempdir() as tmp:
        src = tmp / "doc.odt"
        _build_odt(src)
        original = src.read_bytes()

        broken = tmp / "broken.odt"
        with zipfile.ZipFile(broken, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("content.xml", "<office:document-content/>")
            zf.writestr("META-INF/manifest.xml", "<manifest:manifest/>")
            zf.writestr("mimetype", "application/vnd.oasis.opendocument.text")

        checks = check_integrity(".odt", original, broken.read_bytes())
        assert "mimetype-first" in _failed(checks)


def test_integrity_catches_odf_manifest_pointing_at_missing_part() -> None:
    with workspace_tempdir() as tmp:
        src = tmp / "doc.odt"
        _build_odt(src)
        original = src.read_bytes()

        broken = tmp / "broken.odt"
        with zipfile.ZipFile(broken, "w", zipfile.ZIP_DEFLATED) as zf:
            info = zipfile.ZipInfo("mimetype")
            info.compress_type = zipfile.ZIP_STORED
            zf.writestr(info, "application/vnd.oasis.opendocument.text")
            zf.writestr(
                "META-INF/manifest.xml",
                '<manifest:manifest xmlns:manifest="urn:oasis:names:tc:'
                'opendocument:xmlns:manifest:1.0">'
                '<manifest:file-entry manifest:full-path="content.xml"/>'
                '<manifest:file-entry manifest:full-path="Thumbnails/thumbnail.png"/>'
                "</manifest:manifest>",
            )
            zf.writestr("content.xml", "<office:document-content/>")

        checks = check_integrity(".odt", original, broken.read_bytes())
        assert "manifest-sync" in _failed(checks)


def test_integrity_catches_empty_output() -> None:
    checks = check_integrity(".png", b"\x89PNG\r\n\x1a\n rest", b"")
    assert "non-empty" in _failed(checks)


# --------------------------------------------------------------------------- #
# The harness itself
# --------------------------------------------------------------------------- #


def _write_corpus(folder: Path) -> None:
    (folder / "clip.mkv").write_bytes(_build_mkv())
    (folder / "voice.opus").write_bytes(_build_opus()[0])
    (folder / "shot.dng").write_bytes(_build_tiff(_dirty_tags(), gps_tags=_gps_tags()))
    (folder / "song.mp3").write_bytes(_build_mp3()[0])
    (folder / "movie.mp4").write_bytes(_build_mp4_with_gps())
    _build_odt(folder / "notes.odt")


def test_selftest_passes_on_a_healthy_corpus() -> None:
    with workspace_tempdir() as tmp:
        corpus = tmp / "corpus"
        corpus.mkdir()
        _write_corpus(corpus)

        report = run_selftest([str(corpus)], profile="aggressive")

        assert len(report.results) == 6
        assert report.damaged == []
        assert report.errored == []
        assert {r.status for r in report.results} == {STATUS_PASS}
        assert report.exit_code() == 0


def test_selftest_never_modifies_the_originals() -> None:
    with workspace_tempdir() as tmp:
        corpus = tmp / "corpus"
        corpus.mkdir()
        _write_corpus(corpus)

        before = {p.name: p.read_bytes() for p in corpus.iterdir()}
        names_before = sorted(p.name for p in corpus.iterdir())

        run_selftest([str(corpus)], profile="aggressive")

        after = {p.name: p.read_bytes() for p in corpus.iterdir()}
        assert sorted(after) == names_before, "self-test left files behind"
        assert after == before, "self-test modified an original file"


def test_selftest_reports_residual_for_safe_profile_raw() -> None:
    """Safe keeps RAW Make/Model, so the harness must say residual, not pass."""
    with workspace_tempdir() as tmp:
        corpus = tmp / "corpus"
        corpus.mkdir()
        (corpus / "shot.dng").write_bytes(_build_tiff(_dirty_tags()))

        report = run_selftest([str(corpus)], profile="safe")

        assert len(report.results) == 1
        result = report.results[0]
        assert result.status == STATUS_RESIDUAL
        assert set(result.remaining_blocking) == {"RAW.Make", "RAW.Model"}
        assert not result.failed_checks  # intact, just not fully stripped
        assert report.exit_code() == 2


def test_selftest_flags_a_damaged_file() -> None:
    """Sanity-check the harness end-to-end by breaking a cleaner on purpose."""
    with workspace_tempdir() as tmp:
        corpus = tmp / "corpus"
        corpus.mkdir()
        (corpus / "clip.mkv").write_bytes(_build_mkv())

        import cleaners.matroska as mod

        original_clean = mod.clean_matroska

        def sabotaged(data, aggressive=False):
            cleaned, removed = original_clean(data, aggressive)
            broken = bytearray(cleaned)
            index = broken.find(b"\x11" * 64)
            broken[index] ^= 0xFF  # corrupt the media payload
            return bytes(broken), removed

        mod.clean_matroska = sabotaged
        try:
            report = run_selftest([str(corpus)], profile="aggressive")
        finally:
            mod.clean_matroska = original_clean

        assert len(report.damaged) == 1
        assert report.damaged[0].status == STATUS_DAMAGED
        assert "clusters-preserved" in {c.name for c in report.damaged[0].failed_checks}
        assert report.exit_code() == 1


def test_selftest_reports_missing_coverage() -> None:
    with workspace_tempdir() as tmp:
        corpus = tmp / "corpus"
        corpus.mkdir()
        (corpus / "clip.mkv").write_bytes(_build_mkv())

        report = run_selftest([str(corpus)], profile="safe")

        assert report.covered_extensions == [".mkv"]
        assert ".mkv" not in report.missing_extensions
        assert ".heic" in report.missing_extensions
        assert ".cr2" in report.missing_extensions

        text = render_selftest(report)
        assert "worth finding" in text
        assert ".heic" in text


def test_selftest_on_empty_folder_reports_no_files() -> None:
    with workspace_tempdir() as tmp:
        corpus = tmp / "corpus"
        corpus.mkdir()

        report = run_selftest([str(corpus)], profile="safe")
        assert report.results == []
        assert report.exit_code() == 3
        assert "No supported files found" in render_selftest(report)


def test_wishlist_lists_formats_by_family() -> None:
    text = render_wishlist()
    assert "Camera RAW:" in text
    assert ".cr2" in text and ".nef" in text
    assert "Images:" in text
    # HEIC is an ISOBMFF container but to anyone collecting samples it is a photo.
    heic_line = next(line for line in text.splitlines() if ".heic" in line)
    images_index = text.index("Images:")
    assert text.index(heic_line) > images_index
    assert text.index(heic_line) < text.index("Camera RAW:")


def test_selftest_json_report_shape() -> None:
    with workspace_tempdir() as tmp:
        corpus = tmp / "corpus"
        corpus.mkdir()
        (corpus / "clip.mkv").write_bytes(_build_mkv())

        report = run_selftest([str(corpus)], profile="aggressive")
        payload = report.to_dict()

        assert payload["command"] == "selftest"
        assert payload["profile"] == "aggressive"
        assert payload["summary"]["total"] == 1
        assert payload["summary"]["pass"] == 1
        assert payload["results"][0]["extension"] == ".mkv"
        assert all(c["passed"] for c in payload["results"][0]["checks"])
        assert ".heic" in payload["missing_extensions"]
