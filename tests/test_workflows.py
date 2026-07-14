from __future__ import annotations

import os
import zipfile
import shutil
from contextlib import contextmanager
from pathlib import Path
from uuid import uuid4

import pikepdf
import pytest
from PIL import Image

from exif_killer.cli import main as cli_main
from exif_killer.reporting import render_csv_report
from exif_killer.service import MetadataToolService
from exif_killer.models import ToolConfig


@contextmanager
def workspace_tempdir() -> Path:
    path = Path(os.getcwd()) / f"exif-killer-tests-{uuid4().hex}"
    path.mkdir(parents=True, exist_ok=False)
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


def create_image_with_exif(path: Path) -> None:
    image = Image.new("RGB", (12, 12), (20, 40, 60))
    exif = Image.Exif()
    exif[315] = "Unit Tester"
    exif[305] = "ExifKillerTest"
    image.save(path, exif=exif)


def create_pdf_with_docinfo(path: Path) -> None:
    pdf = pikepdf.Pdf.new()
    pdf.add_blank_page(page_size=(100, 100))
    pdf.docinfo["/Author"] = "Unit Tester"
    pdf.docinfo["/Creator"] = "ExifKillerTest"
    pdf.save(path)


def create_docx_with_metadata(path: Path) -> None:
    content_types = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Default Extension="jpeg" ContentType="image/jpeg"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
  <Override PartName="/word/comments.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.comments+xml"/>
  <Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
  <Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>
  <Override PartName="/docProps/thumbnail.jpeg" ContentType="image/jpeg"/>
</Types>
"""
    rels = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>
  <Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>
</Relationships>
"""
    core = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <dc:creator>Unit Tester</dc:creator>
  <cp:lastModifiedBy>Unit Tester</cp:lastModifiedBy>
  <dcterms:created xsi:type="dcterms:W3CDTF">2026-04-22T12:00:00Z</dcterms:created>
  <dcterms:modified xsi:type="dcterms:W3CDTF">2026-04-22T12:00:00Z</dcterms:modified>
  <cp:revision>7</cp:revision>
</cp:coreProperties>
"""
    app = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">
  <Application>Microsoft Office Word</Application>
  <Company>Example Corp</Company>
  <Pages>1</Pages>
</Properties>
"""
    document = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    <w:p w:rsidR="00112233" w:rsidRDefault="00112233">
      <w:r><w:t>Hello</w:t></w:r>
    </w:p>
    <w:p>
      <w:ins w:author="Unit Tester" w:date="2026-04-22T12:00:00Z">
        <w:r><w:t>Tracked</w:t></w:r>
      </w:ins>
    </w:p>
  </w:body>
</w:document>
"""
    comments = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:comments xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:comment w:id="0" w:author="Unit Tester" w:initials="UT">
    <w:p><w:r><w:t>Note</w:t></w:r></w:p>
  </w:comment>
</w:comments>
"""

    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", content_types)
        archive.writestr("_rels/.rels", rels)
        archive.writestr("docProps/core.xml", core)
        archive.writestr("docProps/app.xml", app)
        archive.writestr("docProps/thumbnail.jpeg", b"fake-jpeg-data")
        archive.writestr("word/document.xml", document)
        archive.writestr("word/comments.xml", comments)


def test_safe_image_clean_removes_identifying_metadata() -> None:
    with workspace_tempdir() as tmp_path:
        source = tmp_path / "photo.jpg"
        create_image_with_exif(source)

        service = MetadataToolService(ToolConfig(profile="safe"))
        result = service.clean_file(str(source))

        assert result.status == "clean"
        assert any(field in result.removed_fields for field in ("Artist", "Software"))
        assert not result.blocking_findings


def test_safe_pdf_clean_removes_docinfo_even_if_pdf_id_remains() -> None:
    with workspace_tempdir() as tmp_path:
        source = tmp_path / "sample.pdf"
        create_pdf_with_docinfo(source)

        service = MetadataToolService(ToolConfig(profile="safe"))
        result = service.clean_file(str(source))

        assert result.status == "warning"
        assert "DocInfo.Author" in result.removed_fields
        assert "DocInfo.Creator" in result.removed_fields
        assert any(finding.key == "Document_ID" for finding in result.remaining_findings)


def test_aggressive_docx_clean_removes_revision_and_thumbnail() -> None:
    with workspace_tempdir() as tmp_path:
        source = tmp_path / "report.docx"
        create_docx_with_metadata(source)

        service = MetadataToolService(ToolConfig(profile="aggressive"))
        result = service.clean_file(str(source))

        assert result.status == "clean"
        assert "RevisionIDs" in result.removed_fields
        assert "Thumbnail" in result.removed_fields
        assert "CommentAuthors" in result.removed_fields


def test_cli_scan_and_verify_use_stable_exit_codes(capsys: pytest.CaptureFixture[str]) -> None:
    with workspace_tempdir() as tmp_path:
        source = tmp_path / "photo.jpg"
        create_image_with_exif(source)

        scan_exit = cli_main(["scan", str(source), "--format", "json"])
        captured = capsys.readouterr()

        assert scan_exit == 2
        assert '"status": "warning"' in captured.out

        service = MetadataToolService(ToolConfig(profile="safe"))
        clean_result = service.clean_file(str(source))
        verify_exit = cli_main(
            ["verify", str(source), clean_result.output_path, "--format", "json"]
        )
        verify_output = capsys.readouterr().out

        assert verify_exit == 0
        assert '"status": "clean"' in verify_output


def test_csv_report_contains_expected_columns() -> None:
    with workspace_tempdir() as tmp_path:
        source = tmp_path / "sample.pdf"
        create_pdf_with_docinfo(source)

        service = MetadataToolService(ToolConfig(profile="safe"))
        batch = service.clean_paths([str(source)])
        csv_output = render_csv_report(batch)

        assert "path,file_type,profile,status,before_count,after_count,remaining_risk_count,sha256_before,sha256_after" in csv_output
        assert "sample.pdf" in csv_output


def test_timestamp_epoch_resets_modification_time() -> None:
    with workspace_tempdir() as tmp_path:
        source = tmp_path / "photo.jpg"
        create_image_with_exif(source)

        service = MetadataToolService(
            ToolConfig(profile="safe", timestamp_mode="epoch")
        )
        result = service.clean_file(str(source))

        assert result.status == "clean"
        mtime = os.path.getmtime(result.output_path)
        # Epoch reset -> modification time at (or extremely close to) 1970.
        assert mtime < 60 * 60 * 24  # within the first day of 1970


def test_timestamp_custom_sets_requested_date() -> None:
    from datetime import datetime, timezone

    with workspace_tempdir() as tmp_path:
        source = tmp_path / "photo.jpg"
        create_image_with_exif(source)

        service = MetadataToolService(
            ToolConfig(
                profile="safe",
                timestamp_mode="custom",
                timestamp_value="2020-05-01",
            )
        )
        result = service.clean_file(str(source))

        assert result.status == "clean"
        expected = datetime(2020, 5, 1, tzinfo=timezone.utc).timestamp()
        assert abs(os.path.getmtime(result.output_path) - expected) < 5


def test_timestamp_random_stays_in_plausible_window() -> None:
    from datetime import datetime, timezone

    with workspace_tempdir() as tmp_path:
        source = tmp_path / "photo.jpg"
        create_image_with_exif(source)

        service = MetadataToolService(
            ToolConfig(profile="safe", timestamp_mode="random")
        )
        result = service.clean_file(str(source))

        assert result.status == "clean"
        mtime = os.path.getmtime(result.output_path)
        lower = datetime(2016, 1, 1, tzinfo=timezone.utc).timestamp()
        upper = datetime.now(timezone.utc).timestamp() + 30 * 24 * 3600
        assert lower <= mtime <= upper


def test_timestamp_keep_leaves_modification_time_recent() -> None:
    from datetime import datetime, timezone

    with workspace_tempdir() as tmp_path:
        source = tmp_path / "photo.jpg"
        create_image_with_exif(source)

        # aggressive would normally reset to epoch; keep must override that.
        service = MetadataToolService(
            ToolConfig(profile="aggressive", timestamp_mode="keep")
        )
        result = service.clean_file(str(source))

        assert result.status == "clean"
        mtime = os.path.getmtime(result.output_path)
        assert mtime > datetime(2020, 1, 1, tzinfo=timezone.utc).timestamp()


def test_cli_rejects_custom_timestamp_without_date(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with workspace_tempdir() as tmp_path:
        source = tmp_path / "photo.jpg"
        create_image_with_exif(source)

        with pytest.raises(SystemExit) as excinfo:
            cli_main(["clean", str(source), "--timestamp", "custom"])

        assert excinfo.value.code == 2  # argparse usage error
