"""Tests for the native TIFF/RAW engine and the OpenDocument cleaner."""

from __future__ import annotations

import os
import shutil
import zipfile
from contextlib import contextmanager
from pathlib import Path
from uuid import uuid4

from cleaners import odf_cleaner, tiff_raw
from exif_killer.models import ToolConfig
from exif_killer.service import MetadataToolService


@contextmanager
def workspace_tempdir():
    path = Path(os.getcwd()) / f"exif-killer-rawodf-{uuid4().hex}"
    path.mkdir(parents=True, exist_ok=False)
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


# --------------------------------------------------------------------------- #
# TIFF builder
# --------------------------------------------------------------------------- #


def _build_tiff(
    extra_tags=(),
    little: bool = True,
    magic: int = 42,
    gps_tags=None,
    image: bytes = b"\xAB" * 128,
    photometric: int = 2,
    compression: int = 1,
) -> bytes:
    """Assemble a structurally valid TIFF.

    `extra_tags` and `gps_tags` are (tag, type, payload_bytes, count) tuples.
    Offsets for StripOffsets and the GPS pointer are resolved automatically.
    """
    order = "little" if little else "big"

    def u16(v: int) -> bytes:
        return v.to_bytes(2, order)

    def u32(v: int) -> bytes:
        return v.to_bytes(4, order)

    tags = [
        (256, 3, u16(16), 1),
        (257, 3, u16(16), 1),
        (258, 3, u16(8), 1),
        (259, 3, u16(compression), 1),
        (262, 3, u16(photometric), 1),
        (277, 3, u16(3), 1),
    ]
    tags += list(extra_tags)
    tags.append((273, 4, None, 1))  # StripOffsets, resolved below
    tags.append((279, 4, u32(len(image)), 1))  # StripByteCounts
    if gps_tags is not None:
        tags.append((34853, 4, None, 1))  # GPS IFD pointer, resolved below
    tags.sort(key=lambda t: t[0])

    n = len(tags)
    ifd0_end = 8 + 2 + 12 * n + 4

    cursor = ifd0_end
    value_offsets = {}
    for i, (_tag, _typ, payload, _cnt) in enumerate(tags):
        if payload is not None and len(payload) > 4:
            value_offsets[i] = cursor
            cursor += len(payload) + (len(payload) & 1)

    gps_offset = cursor
    gps_value_offsets = {}
    if gps_tags is not None:
        gn = len(gps_tags)
        cursor += 2 + 12 * gn + 4
        for i, (_tag, _typ, payload, _cnt) in enumerate(gps_tags):
            if payload is not None and len(payload) > 4:
                gps_value_offsets[i] = cursor
                cursor += len(payload) + (len(payload) & 1)

    image_offset = cursor

    def render_ifd(entries, offsets, next_offset: int) -> bytes:
        out = bytearray(u16(len(entries)))
        for i, (tag, typ, payload, count) in enumerate(entries):
            out += u16(tag) + u16(typ) + u32(count)
            if payload is None:
                resolved = image_offset if tag == 273 else gps_offset
                out += u32(resolved)
            elif len(payload) > 4:
                out += u32(offsets[i])
            else:
                out += payload.ljust(4, b"\x00")
        out += u32(next_offset)
        return bytes(out)

    blob = bytearray()
    blob += (b"II" if little else b"MM") + u16(magic) + u32(8)
    blob += render_ifd(tags, value_offsets, 0)

    for i, (_tag, _typ, payload, _cnt) in enumerate(tags):
        if payload is not None and len(payload) > 4:
            blob += payload
            if len(payload) & 1:
                blob += b"\x00"

    if gps_tags is not None:
        blob += render_ifd(gps_tags, gps_value_offsets, 0)
        for i, (_tag, _typ, payload, _cnt) in enumerate(gps_tags):
            if payload is not None and len(payload) > 4:
                blob += payload
                if len(payload) & 1:
                    blob += b"\x00"

    blob += image
    return bytes(blob)


def _ascii(text: str) -> bytes:
    return text.encode("ascii") + b"\x00"


def _dirty_tags():
    return [
        (270, 2, _ascii("Shot at the safehouse"), 22),
        (271, 2, _ascii("Canon"), 6),
        (272, 2, _ascii("EOS R5"), 7),
        (305, 2, _ascii("Adobe Photoshop 25.0"), 21),
        (306, 2, _ascii("2024:03:11 14:22:07"), 20),
        (315, 2, _ascii("Alice Photographer"), 19),
        (33432, 2, _ascii("(c) Alice 2024"), 15),
        (37500, 7, b"CANON-MAKERNOTE-SERIAL-0123456789", 33),
        (42033, 2, _ascii("BODY-SN-778899"), 15),
        (700, 1, b"<x:xmpmeta>secret</x:xmpmeta>", 29),
    ]


def _gps_tags():
    return [
        (1, 2, b"N\x00", 2),
        (2, 5, b"\x00" * 24, 3),
        (3, 2, b"E\x00", 2),
        (4, 5, b"\x00" * 24, 3),
    ]


# --------------------------------------------------------------------------- #
# TIFF/RAW tests
# --------------------------------------------------------------------------- #


def test_raw_describe_finds_metadata() -> None:
    data = _build_tiff(_dirty_tags(), gps_tags=_gps_tags())
    described = tiff_raw.describe_tiff(data)

    assert described["RAW.Make"] == "Canon"
    assert described["RAW.Model"] == "EOS R5"
    assert described["RAW.Artist"] == "Alice Photographer"
    assert described["RAW.Software"] == "Adobe Photoshop 25.0"
    assert described["RAW.ImageDescription"] == "Shot at the safehouse"
    assert described["RAW.BodySerialNumber"] == "BODY-SN-778899"
    assert described["RAW.MakerNote"] == "PRESENT"
    assert described["RAW.XMP"] == "PRESENT"
    assert described["RAW.GPS"] == "PRESENT"


def test_raw_strips_metadata_without_moving_bytes() -> None:
    data = _build_tiff(_dirty_tags(), gps_tags=_gps_tags())
    cleaned, removed = tiff_raw.clean_tiff(data)

    # The whole point: sensor data offsets stay valid because nothing moves.
    assert len(cleaned) == len(data)
    assert b"\xAB" * 128 in cleaned  # sensor data bit-for-bit intact

    for secret in [b"Shot at the safehouse", b"Adobe Photoshop 25.0",
                   b"Alice Photographer", b"(c) Alice 2024",
                   b"CANON-MAKERNOTE-SERIAL-0123456789", b"BODY-SN-778899",
                   b"<x:xmpmeta>secret</x:xmpmeta>"]:
        assert secret not in cleaned, f"{secret!r} survived"

    for name in ("ImageDescription", "Software", "DateTime", "Artist",
                 "Copyright", "MakerNote", "BodySerialNumber", "XMP", "GPS"):
        assert name in removed

    described = tiff_raw.describe_tiff(cleaned)
    assert "RAW.GPS" not in described
    assert "RAW.MakerNote" not in described


def test_raw_safe_profile_keeps_make_and_model() -> None:
    """RAW converters identify the sensor from Make/Model, so safe keeps them."""
    data = _build_tiff(_dirty_tags())

    safe, _ = tiff_raw.clean_tiff(data, aggressive=False)
    assert tiff_raw.describe_tiff(safe)["RAW.Make"] == "Canon"
    assert tiff_raw.describe_tiff(safe)["RAW.Model"] == "EOS R5"

    hard, removed = tiff_raw.clean_tiff(data, aggressive=True)
    assert "Make" in removed and "Model" in removed
    assert b"EOS R5" not in hard
    assert "RAW.Make" not in tiff_raw.describe_tiff(hard)


def test_raw_preserves_structural_tags_and_strip_pointers() -> None:
    data = _build_tiff(_dirty_tags(), gps_tags=_gps_tags())
    before = tiff_raw.TiffFile(data)
    cleaned, _ = tiff_raw.clean_tiff(data)
    after = tiff_raw.TiffFile(cleaned)

    ifd_before, ifd_after = before.ifds[0], after.ifds[0]
    for tag in (256, 257, 258, 259, 262, 277, 273, 279):
        assert ifd_before.get(tag) is not None
        assert ifd_after.get(tag) is not None, f"structural tag {tag} was dropped"
        assert before.value_ints(ifd_before.get(tag)) == \
            after.value_ints(ifd_after.get(tag)), f"tag {tag} value changed"


def test_raw_cleaned_file_still_parses_and_ifd_is_consistent() -> None:
    data = _build_tiff(_dirty_tags(), gps_tags=_gps_tags())
    cleaned, _ = tiff_raw.clean_tiff(data)

    tiff = tiff_raw.TiffFile(cleaned)
    ifd = tiff.ifds[0]
    # The entry count must match the entries actually present, and the
    # next-IFD pointer must sit right after them.
    assert len(ifd.entries) == tiff._u16(ifd.offset)
    assert ifd.next_pos == ifd.offset + 2 + 12 * len(ifd.entries)
    assert ifd.next_offset == 0
    assert ifd.get(34853) is None  # GPS pointer gone


def test_raw_works_big_endian() -> None:
    data = _build_tiff(_dirty_tags(), little=False)
    assert tiff_raw.describe_tiff(data)["RAW.Make"] == "Canon"

    cleaned, removed = tiff_raw.clean_tiff(data)
    assert "Artist" in removed
    assert b"Alice Photographer" not in cleaned
    assert len(cleaned) == len(data)
    assert tiff_raw.TiffFile(cleaned).ifds[0].get(273) is not None


def test_raw_rejects_bigtiff_rather_than_guessing() -> None:
    data = bytearray(_build_tiff(_dirty_tags()))
    data[2:4] = (43).to_bytes(2, "little")  # BigTIFF magic
    try:
        tiff_raw.clean_tiff(bytes(data))
    except tiff_raw.TiffError as exc:
        assert "BigTIFF" in str(exc)
    else:
        raise AssertionError("expected TiffError for BigTIFF")


def test_raw_rejects_non_tiff() -> None:
    try:
        tiff_raw.clean_tiff(b"\x89PNG\r\n\x1a\n" + b"\x00" * 32)
    except tiff_raw.TiffError:
        pass
    else:
        raise AssertionError("expected TiffError")


# --------------------------------------------------------------------------- #
# The safety guard that matters most
# --------------------------------------------------------------------------- #


def _jpeg_with_exif() -> bytes:
    """A tiny JPEG carrying an APP1/EXIF segment."""
    exif = b"\xff\xe1" + (2 + 6 + 8).to_bytes(2, "big") + b"Exif\x00\x00" + b"II*\x00" + b"\x08\x00\x00\x00"
    return (
        b"\xff\xd8"
        + exif
        + b"\xff\xdb" + (67).to_bytes(2, "big") + b"\x00" + b"\x01" * 64
        + b"\xff\xda" + (8).to_bytes(2, "big") + b"\x01\x00\x00\x3f\x00\x00"
        + b"\x12\x34\x56\x78"
        + b"\xff\xd9"
    )


def test_raw_never_touches_lossless_jpeg_sensor_data() -> None:
    """Lossless-JPEG raw data starts with SOI just like a preview does.

    Only the photometric interpretation distinguishes them, so a CFA image
    (photometric 32803) must survive aggressive cleaning untouched.
    """
    sensor = _jpeg_with_exif()
    data = _build_tiff(
        _dirty_tags(),
        image=sensor,
        photometric=32803,  # CFA -> this is sensor data, not a preview
        compression=7,      # lossless JPEG
    )

    cleaned, _removed = tiff_raw.clean_tiff(data, aggressive=True)

    tiff = tiff_raw.TiffFile(cleaned)
    ifd = tiff.ifds[0]
    offset = tiff.value_ints(ifd.get(273))[0]
    length = tiff.value_ints(ifd.get(279))[0]
    assert cleaned[offset : offset + length] == sensor, "sensor data was modified!"
    assert length == len(sensor)


def test_raw_strips_exif_from_embedded_preview_when_aggressive() -> None:
    preview = _jpeg_with_exif()
    data = _build_tiff(
        _dirty_tags(),
        image=preview,
        photometric=6,  # YCbCr -> a viewable preview
        compression=6,
    )
    assert tiff_raw.describe_tiff(data)["RAW.EmbeddedPreview"] == "1 previews"

    cleaned, removed = tiff_raw.clean_tiff(data, aggressive=True)
    assert "PreviewEXIF" in removed
    assert len(cleaned) == len(data)

    tiff = tiff_raw.TiffFile(cleaned)
    ifd = tiff.ifds[0]
    offset = tiff.value_ints(ifd.get(273))[0]
    length = tiff.value_ints(ifd.get(279))[0]
    blob = cleaned[offset : offset + length]

    assert length < len(preview)  # byte count was updated to the shorter JPEG
    assert blob[:2] == b"\xff\xd8" and blob[-2:] == b"\xff\xd9"
    assert b"Exif\x00\x00" not in blob
    assert b"\x12\x34\x56\x78" in blob  # the actual scan data survived


def test_raw_preview_left_alone_on_safe_profile() -> None:
    preview = _jpeg_with_exif()
    data = _build_tiff(_dirty_tags(), image=preview, photometric=6, compression=6)

    cleaned, removed = tiff_raw.clean_tiff(data, aggressive=False)
    assert "PreviewEXIF" not in removed
    assert preview in cleaned


# --------------------------------------------------------------------------- #
# Pillow as an independent oracle for the TIFF path
# --------------------------------------------------------------------------- #


def test_raw_pixels_verified_by_pillow() -> None:
    """Build a real TIFF with Pillow, clean it, and re-read it with Pillow."""
    from PIL import Image, TiffImagePlugin

    with workspace_tempdir() as tmp:
        src = tmp / "shot.tiff"
        image = Image.new("RGB", (32, 24))
        for x in range(32):
            for y in range(24):
                image.putpixel((x, y), (x * 8 % 256, y * 10 % 256, (x + y) % 256))

        info = TiffImagePlugin.ImageFileDirectory_v2()
        info[270] = "Shot at the safehouse"
        info[271] = "Canon"
        info[272] = "EOS R5"
        info[305] = "Adobe Photoshop 25.0"
        info[315] = "Alice Photographer"
        info[33432] = "(c) Alice 2024"
        image.save(src, tiffinfo=info)

        original = src.read_bytes()
        before = tiff_raw.describe_tiff(original)
        assert before["RAW.Artist"] == "Alice Photographer"

        cleaned, removed = tiff_raw.clean_tiff(original)
        assert "Artist" in removed
        assert len(cleaned) == len(original)

        out = tmp / "shot_clean.tiff"
        out.write_bytes(cleaned)

        # Pillow (third-party) must still decode it, with identical pixels.
        with Image.open(out) as reopened:
            assert reopened.size == (32, 24)
            assert list(reopened.convert("RGB").getdata()) == \
                list(image.getdata())
            assert 315 not in reopened.tag_v2
            assert 305 not in reopened.tag_v2
            assert 270 not in reopened.tag_v2


# --------------------------------------------------------------------------- #
# ODF fixtures
# --------------------------------------------------------------------------- #

_META_XML = """<?xml version="1.0" encoding="UTF-8"?>
<office:document-meta xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0"
 xmlns:meta="urn:oasis:names:tc:opendocument:xmlns:meta:1.0"
 xmlns:dc="http://purl.org/dc/elements/1.1/" office:version="1.3">
<office:meta>
<meta:creation-date>2024-02-01T09:15:00</meta:creation-date>
<dc:creator>Alice Analyst</dc:creator>
<dc:date>2024-02-03T18:40:00</dc:date>
<meta:initial-creator>Alice Analyst</meta:initial-creator>
<meta:editing-cycles>17</meta:editing-cycles>
<meta:editing-duration>PT4H12M</meta:editing-duration>
<meta:generator>LibreOffice/7.4.2.3$Windows_X86_64 LibreOffice_project/1234</meta:generator>
<dc:title>Operation Nightfall Brief</dc:title>
<meta:printed-by>Bob Printer</meta:printed-by>
<meta:user-defined meta:name="Case">Internal only</meta:user-defined>
</office:meta>
</office:document-meta>"""

_CONTENT_XML = """<?xml version="1.0" encoding="UTF-8"?>
<office:document-content xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0"
 xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0"
 xmlns:dc="http://purl.org/dc/elements/1.1/" office:version="1.3">
<office:body><office:text>
<text:tracked-changes>
<text:changed-region text:id="ct1"><text:deletion>
<office:change-info><dc:creator>Alice Analyst</dc:creator><dc:date>2024-02-02T10:00:00</dc:date></office:change-info>
</text:deletion></text:changed-region>
</text:tracked-changes>
<text:p>The visible body text of the document.</text:p>
<office:annotation><dc:creator>Bob Reviewer</dc:creator><dc:date>2024-02-03T11:30:00</dc:date>
<text:p>Check this figure.</text:p></office:annotation>
<text:p><text:author-name>Alice Analyst</text:author-name></text:p>
</office:text></office:body>
</office:document-content>"""

_MANIFEST_XML = """<?xml version="1.0" encoding="UTF-8"?>
<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0" manifest:version="1.3">
<manifest:file-entry manifest:full-path="/" manifest:media-type="application/vnd.oasis.opendocument.text"/>
<manifest:file-entry manifest:full-path="content.xml" manifest:media-type="text/xml"/>
<manifest:file-entry manifest:full-path="meta.xml" manifest:media-type="text/xml"/>
<manifest:file-entry manifest:full-path="settings.xml" manifest:media-type="text/xml"/>
<manifest:file-entry manifest:full-path="Thumbnails/thumbnail.png" manifest:media-type="image/png"/>
</manifest:manifest>"""

_SETTINGS_XML = """<?xml version="1.0" encoding="UTF-8"?>
<office:document-settings xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0"
 xmlns:config="urn:oasis:names:tc:opendocument:xmlns:config:1.0">
<office:settings><config:config-item config:name="PrinterName" config:type="string">HP-Office-Alice</config:config-item>
</office:settings></office:document-settings>"""


def _png_with_text() -> bytes:
    """A minimal PNG carrying a tEXt metadata chunk."""
    import struct
    import zlib

    def chunk(ctype: bytes, payload: bytes) -> bytes:
        return (
            struct.pack(">I", len(payload))
            + ctype
            + payload
            + struct.pack(">I", zlib.crc32(ctype + payload) & 0xFFFFFFFF)
        )

    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    raw = zlib.compress(b"\x00\xff\x00\x00")
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", ihdr)
        + chunk(b"tEXt", b"Author\x00Alice Analyst")
        + chunk(b"IDAT", raw)
        + chunk(b"IEND", b"")
    )


def _build_odt(path: Path) -> None:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        info = zipfile.ZipInfo("mimetype")
        info.compress_type = zipfile.ZIP_STORED
        zf.writestr(info, "application/vnd.oasis.opendocument.text")
        zf.writestr("META-INF/manifest.xml", _MANIFEST_XML)
        zf.writestr("meta.xml", _META_XML)
        zf.writestr("content.xml", _CONTENT_XML)
        zf.writestr("styles.xml", "<office:styles/>")
        zf.writestr("settings.xml", _SETTINGS_XML)
        zf.writestr("Thumbnails/thumbnail.png", _png_with_text())
        zf.writestr("Pictures/image1.png", _png_with_text())


# --------------------------------------------------------------------------- #
# ODF tests
# --------------------------------------------------------------------------- #


def test_odf_describe_finds_metadata() -> None:
    with workspace_tempdir() as tmp:
        src = tmp / "brief.odt"
        _build_odt(src)

        described = odf_cleaner.describe_odf(str(src))
        assert described["ODF.Creator"] == "Alice Analyst"
        assert described["ODF.InitialCreator"] == "Alice Analyst"
        assert described["ODF.Title"] == "Operation Nightfall Brief"
        assert described["ODF.EditingCycles"] == "17"
        assert described["ODF.PrintedBy"] == "Bob Printer"
        assert "LibreOffice" in described["ODF.Generator"]
        assert described["ODF.Annotations"] == "PRESENT"
        assert described["ODF.TrackedChanges"] == "PRESENT"
        assert described["ODF.Thumbnail"] == "PRESENT"
        assert described["ODF.EmbeddedImages"] == "1 images"


def test_odf_safe_clean_removes_meta_and_identities() -> None:
    """Safe strips every identity but keeps the structures that hold them.

    Verification therefore still reports a warning, naming exactly what was
    left behind - which is the honest answer, not a failure.
    """
    with workspace_tempdir() as tmp:
        src = tmp / "brief.odt"
        _build_odt(src)

        service = MetadataToolService(ToolConfig(profile="safe"))
        result = service.clean_file(str(src))

        assert result.status == "warning"
        assert {f.key for f in result.blocking_findings} == {
            "ODF.Annotations",
            "ODF.TrackedChanges",
            "ODF.Thumbnail",
            "ODF.Settings",
        }
        # Every identity field is gone even on the safe profile.
        for key in ("ODF.Creator", "ODF.InitialCreator", "ODF.Generator",
                    "ODF.Title", "ODF.PrintedBy", "ODF.EditingCycles"):
            assert key not in result.after_scan.metadata

        out = Path(result.output_path)
        with zipfile.ZipFile(out) as zf:
            names = zf.namelist()
            meta = zf.read("meta.xml").decode()
            content = zf.read("content.xml").decode()

        assert "Alice Analyst" not in meta
        assert "LibreOffice" not in meta
        assert "Operation Nightfall Brief" not in meta
        assert "Alice Analyst" not in content
        assert "Bob Reviewer" not in content
        # Safe keeps the document's actual content and its comment text.
        assert "The visible body text of the document." in content
        assert "Check this figure." in content
        assert "Pictures/image1.png" in names


def test_odf_aggressive_removes_annotations_thumbnail_and_settings() -> None:
    with workspace_tempdir() as tmp:
        src = tmp / "brief.odt"
        _build_odt(src)

        service = MetadataToolService(ToolConfig(profile="aggressive"))
        result = service.clean_file(str(src))
        assert result.status == "clean", result.remaining_findings

        with zipfile.ZipFile(Path(result.output_path)) as zf:
            names = zf.namelist()
            content = zf.read("content.xml").decode()
            manifest = zf.read("META-INF/manifest.xml").decode()

        assert not any(n.startswith("Thumbnails/") for n in names)
        assert "settings.xml" not in names
        assert "Check this figure." not in content  # annotation removed outright
        assert "The visible body text of the document." in content
        # The manifest must not advertise parts that no longer exist.
        assert "Thumbnails/thumbnail.png" not in manifest
        assert "settings.xml" not in manifest
        assert "content.xml" in manifest


def test_odf_keeps_mimetype_first_and_stored() -> None:
    """ODF stops being recognised if mimetype is not the first, stored entry."""
    with workspace_tempdir() as tmp:
        src = tmp / "brief.odt"
        _build_odt(src)

        service = MetadataToolService(ToolConfig(profile="aggressive"))
        result = service.clean_file(str(src))

        with zipfile.ZipFile(Path(result.output_path)) as zf:
            infos = zf.infolist()
            assert infos[0].filename == "mimetype"
            assert infos[0].compress_type == zipfile.ZIP_STORED
            assert zf.read("mimetype").decode() == \
                "application/vnd.oasis.opendocument.text"


def test_odf_strips_embedded_picture_metadata() -> None:
    with workspace_tempdir() as tmp:
        src = tmp / "brief.odt"
        _build_odt(src)

        service = MetadataToolService(ToolConfig(profile="safe"))
        result = service.clean_file(str(src))

        with zipfile.ZipFile(Path(result.output_path)) as zf:
            picture = zf.read("Pictures/image1.png")

        assert b"Alice Analyst" not in picture
        assert b"tEXt" not in picture
        assert picture.startswith(b"\x89PNG\r\n\x1a\n")
        assert b"IDAT" in picture and b"IEND" in picture


def test_odf_zip_entry_timestamps_are_fixed() -> None:
    """ZIP entry dates otherwise record when the document was last edited."""
    with workspace_tempdir() as tmp:
        src = tmp / "brief.odt"
        _build_odt(src)

        service = MetadataToolService(ToolConfig(profile="safe"))
        result = service.clean_file(str(src))

        with zipfile.ZipFile(Path(result.output_path)) as zf:
            for info in zf.infolist():
                assert info.date_time == (1980, 1, 1, 0, 0, 0), info.filename


def test_service_scan_flags_odf_and_raw() -> None:
    with workspace_tempdir() as tmp:
        odt = tmp / "brief.odt"
        _build_odt(odt)
        raw = tmp / "shot.dng"
        raw.write_bytes(_build_tiff(_dirty_tags(), gps_tags=_gps_tags()))

        service = MetadataToolService(ToolConfig(profile="safe"))

        odf_scan = service.scan_file(str(odt))
        assert odf_scan.status == "warning"
        assert odf_scan.file_type == "opendocument"

        raw_scan = service.scan_file(str(raw))
        assert raw_scan.status == "warning"
        assert raw_scan.file_type == "raw"
        assert any(f.key == "RAW.GPS" for f in raw_scan.blocking_findings)


def test_service_cleans_dng_end_to_end_safe_reports_kept_make_model() -> None:
    """Safe keeps Make/Model for decodability and says so, rather than lying."""
    with workspace_tempdir() as tmp:
        src = tmp / "shot.dng"
        src.write_bytes(_build_tiff(_dirty_tags(), gps_tags=_gps_tags()))
        original_size = src.stat().st_size

        service = MetadataToolService(ToolConfig(profile="safe"))
        result = service.clean_file(str(src))

        assert result.status == "warning"
        assert {f.key for f in result.blocking_findings} == {"RAW.Make",
                                                             "RAW.Model"}

        out = Path(result.output_path)
        assert out.stat().st_size == original_size  # never resized
        blob = out.read_bytes()
        assert b"Alice Photographer" not in blob
        assert b"CANON-MAKERNOTE-SERIAL-0123456789" not in blob
        assert b"\xAB" * 128 in blob  # sensor data intact


def test_service_cleans_dng_end_to_end_aggressive_is_clean() -> None:
    with workspace_tempdir() as tmp:
        src = tmp / "shot.dng"
        src.write_bytes(_build_tiff(_dirty_tags(), gps_tags=_gps_tags()))
        original_size = src.stat().st_size

        service = MetadataToolService(ToolConfig(profile="aggressive"))
        result = service.clean_file(str(src))
        assert result.status == "clean", result.remaining_findings

        out = Path(result.output_path)
        assert out.stat().st_size == original_size
        blob = out.read_bytes()
        for secret in (b"Alice Photographer", b"Canon", b"EOS R5",
                       b"CANON-MAKERNOTE-SERIAL-0123456789", b"BODY-SN-778899"):
            assert secret not in blob
        assert b"\xAB" * 128 in blob
