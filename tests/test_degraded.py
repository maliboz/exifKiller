"""The tool must survive an optional engine that cannot load.

pikepdf is a C extension, and on Windows it fails to import whenever the Visual
C++ runtime is missing. Importing it at module scope would take the whole
application down - GUI included - over one unavailable format family. These
tests simulate that failure and assert the rest of the tool keeps working.
"""

from __future__ import annotations

import builtins
import importlib
import os
import shutil
import sys
from contextlib import contextmanager
from pathlib import Path
from uuid import uuid4

import pytest


@contextmanager
def workspace_tempdir():
    path = Path(os.getcwd()) / f"exif-killer-degraded-{uuid4().hex}"
    path.mkdir(parents=True, exist_ok=False)
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


@contextmanager
def pikepdf_broken():
    """Reimport the PDF stack with `import pikepdf` raising, as a bad DLL does."""
    real_import = builtins.__import__
    saved = {
        name: module
        for name, module in sys.modules.items()
        if name.startswith(("pikepdf", "cleaners", "exif_killer"))
    }

    def fake_import(name, *args, **kwargs):
        if name == "pikepdf" or name.startswith("pikepdf."):
            raise ImportError(
                "DLL load failed while importing _core: "
                "the specified module could not be found."
            )
        return real_import(name, *args, **kwargs)

    for name in list(sys.modules):
        if name.startswith(("pikepdf", "cleaners", "exif_killer")):
            del sys.modules[name]

    builtins.__import__ = fake_import
    try:
        yield
    finally:
        builtins.__import__ = real_import
        for name in list(sys.modules):
            if name.startswith(("pikepdf", "cleaners", "exif_killer")):
                del sys.modules[name]
        sys.modules.update(saved)


def _jpeg_with_exif() -> bytes:
    from PIL import Image
    import io

    image = Image.new("RGB", (24, 16), (200, 40, 40))
    exif = Image.Exif()
    exif[271] = "Apple"
    exif[315] = "Alice Photographer"
    buf = io.BytesIO()
    image.save(buf, format="JPEG", quality=90, exif=exif)
    return buf.getvalue()


def test_pdf_support_is_available_normally() -> None:
    from cleaners.pdf_cleaner import pdf_support_available, pdf_support_error

    assert pdf_support_available()
    assert pdf_support_error() == ""


def test_importing_cleaners_survives_a_broken_pikepdf() -> None:
    with pikepdf_broken():
        # The whole package must still import - this is the regression.
        import cleaners

        assert cleaners.PDFCleaner is not None

        from cleaners.pdf_cleaner import pdf_support_available, pdf_support_error

        assert not pdf_support_available()
        message = pdf_support_error()
        assert "PDF support is disabled" in message
        assert "every other format still works" in message


def test_service_starts_and_says_so_when_pdf_support_is_missing() -> None:
    with pikepdf_broken():
        from exif_killer.models import ToolConfig
        from exif_killer.service import MetadataToolService

        logged: list[str] = []
        service = MetadataToolService(ToolConfig(profile="safe"),
                                      logger=logged.append)

        assert service is not None
        assert any("PDF support is disabled" in line for line in logged), logged


def test_images_still_clean_when_pdf_support_is_missing() -> None:
    """The point of the fix: a photo does not need the PDF engine."""
    with pikepdf_broken():
        from exif_killer.models import ToolConfig
        from exif_killer.service import MetadataToolService

        with workspace_tempdir() as tmp:
            src = tmp / "photo.jpg"
            src.write_bytes(_jpeg_with_exif())

            service = MetadataToolService(ToolConfig(profile="aggressive"),
                                          logger=lambda _m: None)
            result = service.clean_file(str(src))

            assert result.status == "clean", result.remaining_findings
            cleaned = Path(result.output_path).read_bytes()
            assert b"Alice Photographer" not in cleaned
            assert cleaned.startswith(b"\xff\xd8")


def test_pdf_reports_a_clear_error_instead_of_crashing() -> None:
    with pikepdf_broken():
        from exif_killer.models import ToolConfig
        from exif_killer.service import MetadataToolService

        with workspace_tempdir() as tmp:
            src = tmp / "doc.pdf"
            src.write_bytes(b"%PDF-1.4\n% minimal\n")

            service = MetadataToolService(ToolConfig(profile="safe"),
                                          logger=lambda _m: None)
            result = service.clean_file(str(src))

            # It must fail for this one file, with a reason, not take down the run.
            assert result.status == "error"
            assert "pikepdf" in (result.error or "")


def test_gui_module_imports_when_pdf_support_is_missing() -> None:
    """A broken PDF engine must not stop the desktop app from opening."""
    pytest.importorskip("customtkinter")
    with pikepdf_broken():
        module = importlib.import_module("exif_killer.gui")
        assert hasattr(module, "ExifKillerApp")
