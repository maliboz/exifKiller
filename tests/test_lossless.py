from __future__ import annotations

import os
import shutil
from contextlib import contextmanager
from io import BytesIO
from pathlib import Path
from uuid import uuid4

import pytest
from PIL import Image, PngImagePlugin

from cleaners.lossless_image import (
    LosslessStripError,
    strip_gif,
    strip_jpeg,
    strip_png,
    strip_svg,
    strip_webp,
)
from exif_killer.models import ToolConfig
from exif_killer.service import MetadataToolService


@contextmanager
def workspace_tempdir() -> Path:
    path = Path(os.getcwd()) / f"exif-killer-lossless-{uuid4().hex}"
    path.mkdir(parents=True, exist_ok=False)
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


def _gradient(mode: str = "RGB", size=(64, 48)) -> Image.Image:
    img = Image.new(mode, size)
    px = img.load()
    for y in range(size[1]):
        for x in range(size[0]):
            px[x, y] = ((x * 3) % 256, (y * 5) % 256, ((x + y) * 2) % 256)[
                : len(mode)
            ] if mode != "RGB" else ((x * 3) % 256, (y * 5) % 256, ((x + y) * 2) % 256)
    return img


def _jpeg_scan_bytes(data: bytes) -> bytes:
    start = data.find(b"\xff\xda")
    end = data.find(b"\xff\xd9", start)
    return data[start : end + 2]


def test_strip_jpeg_is_lossless_and_removes_exif() -> None:
    exif = Image.Exif()
    exif[315] = "Secret Author"
    exif[305] = "SecretApp"
    exif[34853] = {1: "N"}  # GPS
    buf = BytesIO()
    _gradient().save(buf, format="JPEG", exif=exif.tobytes(), quality=88)
    original = buf.getvalue()

    cleaned = strip_jpeg(original, aggressive=False)

    before = Image.open(BytesIO(original))
    after = Image.open(BytesIO(cleaned))
    assert len(before.getexif()) == 3
    assert len(after.getexif()) == 0
    # Pixels and the compressed scan data are byte-identical -> truly lossless.
    assert list(before.getdata()) == list(after.getdata())
    assert _jpeg_scan_bytes(original) == _jpeg_scan_bytes(cleaned)
    assert len(cleaned) < len(original)


def test_strip_jpeg_drops_trailing_appended_data() -> None:
    buf = BytesIO()
    _gradient().save(buf, format="JPEG", quality=80)
    payload = buf.getvalue() + b"HIDDEN-STEGO-PAYLOAD"

    cleaned = strip_jpeg(payload)

    assert b"HIDDEN-STEGO-PAYLOAD" not in cleaned
    assert cleaned.endswith(b"\xff\xd9")


def test_strip_png_removes_text_chunks_losslessly() -> None:
    info = PngImagePlugin.PngInfo()
    info.add_text("Author", "Secret")
    info.add_text("Software", "GIMP")
    buf = BytesIO()
    _gradient().save(buf, format="PNG", pnginfo=info)
    original = buf.getvalue()

    cleaned = strip_png(original)

    before = Image.open(BytesIO(original))
    after = Image.open(BytesIO(cleaned))
    assert before.info.get("Author") == "Secret"
    assert after.info.get("Author") is None
    assert list(before.getdata()) == list(after.getdata())


def test_strip_webp_removes_exif() -> None:
    exif = Image.Exif()
    exif[315] = "WebAuthor"
    buf = BytesIO()
    _gradient().save(buf, format="WEBP", exif=exif.tobytes(), lossless=True)
    original = buf.getvalue()

    cleaned = strip_webp(original)

    after = Image.open(BytesIO(cleaned))
    assert len(after.getexif()) == 0
    assert Image.open(BytesIO(original)).size == after.size


def test_strip_gif_removes_comment() -> None:
    buf = BytesIO()
    Image.new("P", (32, 32)).save(buf, format="GIF", comment=b"secret comment")
    original = buf.getvalue()

    cleaned = strip_gif(original)

    assert b"secret comment" in original
    assert b"secret comment" not in cleaned
    assert Image.open(BytesIO(cleaned)).size == (32, 32)


def test_strip_svg_removes_metadata_keeps_geometry() -> None:
    svg = (
        b'<svg xmlns="http://www.w3.org/2000/svg">'
        b"<!-- Generator: Adobe Illustrator -->"
        b"<metadata><rdf>author</rdf></metadata>"
        b'<rect x="0" y="0" width="10" height="10"/></svg>'
    )
    cleaned = strip_svg(svg)
    assert b"metadata" not in cleaned
    assert b"Adobe" not in cleaned
    assert b"<rect" in cleaned


def test_strip_jpeg_rejects_non_jpeg() -> None:
    with pytest.raises(LosslessStripError):
        strip_jpeg(b"not a jpeg at all")


def test_service_cleans_gif_end_to_end() -> None:
    with workspace_tempdir() as tmp:
        src = tmp / "anim.gif"
        buf = BytesIO()
        Image.new("P", (24, 24)).save(buf, format="GIF", comment=b"leak")
        src.write_bytes(buf.getvalue())

        service = MetadataToolService(ToolConfig(profile="safe"))
        result = service.clean_file(str(src))

        assert result.status == "clean"
        assert b"leak" not in Path(result.output_path).read_bytes()


def test_service_cleans_svg_end_to_end() -> None:
    with workspace_tempdir() as tmp:
        src = tmp / "vector.svg"
        src.write_bytes(
            b'<svg xmlns="http://www.w3.org/2000/svg">'
            b"<metadata>owner</metadata>"
            b'<circle cx="5" cy="5" r="4"/></svg>'
        )

        service = MetadataToolService(ToolConfig(profile="safe"))
        result = service.clean_file(str(src))

        assert result.status == "clean"
        out = Path(result.output_path).read_bytes()
        assert b"metadata" not in out
        assert b"<circle" in out


def test_service_image_clean_does_not_reencode_jpeg() -> None:
    with workspace_tempdir() as tmp:
        src = tmp / "photo.jpg"
        exif = Image.Exif()
        exif[315] = "Author"
        buf = BytesIO()
        _gradient().save(buf, format="JPEG", exif=exif.tobytes(), quality=77)
        src.write_bytes(buf.getvalue())

        service = MetadataToolService(ToolConfig(profile="safe"))
        result = service.clean_file(str(src))

        assert result.status == "clean"
        # Not overwrite mode, so the source is intact; compare its compressed
        # scan data with the cleaned copy to prove no re-encode happened.
        out_bytes = Path(result.output_path).read_bytes()
        src_bytes = src.read_bytes()
        assert _jpeg_scan_bytes(src_bytes) == _jpeg_scan_bytes(out_bytes)
