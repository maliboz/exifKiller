"""
ODF Cleaner - native metadata removal for OpenDocument files.

Handles ODT/ODS/ODP (and the template variants) as ZIP packages, with no
external tools.

OpenDocument keeps its metadata in a few well-defined places:
- `meta.xml`        : author, dates, editing cycles/duration, generator string,
                      title/subject/keywords, and user-defined fields.
- `content.xml`     : `<office:annotation>` comments and `<text:tracked-changes>`
                      revisions, each carrying `<dc:creator>` and `<dc:date>`.
- `styles.xml`      : headers/footers can embed author fields.
- `settings.xml`    : application state, including local file paths.
- `Thumbnails/`     : a rendered preview of the document's first page.
- `Pictures/`       : embedded images, which keep their own EXIF.

Two ODF-specific rules drive the repackaging:
1. `mimetype` must be the first entry and stored uncompressed, or the file
   stops being recognised as OpenDocument.
2. `META-INF/manifest.xml` lists every part, so anything removed must be
   removed from the manifest too.

ZIP entry timestamps are also rewritten to a fixed value: they otherwise record
when the document was last edited, which is exactly the kind of timeline hint
this tool exists to remove.
"""

from __future__ import annotations

import os
import re
import zipfile
from typing import Callable, Dict, List, Optional, Tuple

from .base import BaseCleaner
from .lossless_image import LosslessStripError, strip_file, supports_lossless

# ODF requires the mimetype entry first and uncompressed.
_MIMETYPE = "mimetype"
_MANIFEST = "META-INF/manifest.xml"
_META = "meta.xml"
_CONTENT = "content.xml"
_STYLES = "styles.xml"
_SETTINGS = "settings.xml"

# A fixed ZIP timestamp (the earliest the format allows) so archive entries
# stop leaking edit times.
_FIXED_ZIP_DATE = (1980, 1, 1, 0, 0, 0)

_NS_OFFICE = "urn:oasis:names:tc:opendocument:xmlns:office:1.0"
_NS_META = "urn:oasis:names:tc:opendocument:xmlns:meta:1.0"

_EXT_TO_MIME = {
    ".odt": "application/vnd.oasis.opendocument.text",
    ".ods": "application/vnd.oasis.opendocument.spreadsheet",
    ".odp": "application/vnd.oasis.opendocument.presentation",
    ".odg": "application/vnd.oasis.opendocument.graphics",
    ".odf": "application/vnd.oasis.opendocument.formula",
    ".ott": "application/vnd.oasis.opendocument.text-template",
    ".ots": "application/vnd.oasis.opendocument.spreadsheet-template",
    ".otp": "application/vnd.oasis.opendocument.presentation-template",
}


class ODFError(Exception):
    """Raised when a file cannot be handled as an OpenDocument package."""


def _empty_meta_xml(office_version: str) -> bytes:
    """Build a valid but completely empty meta.xml."""
    version_attr = f' office:version="{office_version}"' if office_version else ""
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<office:document-meta xmlns:office="{_NS_OFFICE}"'
        f' xmlns:meta="{_NS_META}"'
        ' xmlns:dc="http://purl.org/dc/elements/1.1/"'
        f'{version_attr}>'
        "<office:meta/>"
        "</office:document-meta>"
    ).encode("utf-8")


def _office_version(meta_xml: bytes) -> str:
    match = re.search(rb'office:version="([^"]*)"', meta_xml)
    if match:
        return match.group(1).decode("ascii", "ignore")
    return "1.3"


def strip_meta_xml(data: bytes) -> Tuple[bytes, List[str]]:
    """Replace meta.xml with an empty one, reporting what was dropped."""
    removed = [name for name, _ in _iter_meta_fields(data)]
    return _empty_meta_xml(_office_version(data)), removed


_META_FIELD_PATTERNS = (
    ("Creator", rb"<dc:creator>"),
    ("InitialCreator", rb"<meta:initial-creator>"),
    ("Date", rb"<dc:date>"),
    ("CreationDate", rb"<meta:creation-date>"),
    ("EditingCycles", rb"<meta:editing-cycles>"),
    ("EditingDuration", rb"<meta:editing-duration>"),
    ("Generator", rb"<meta:generator>"),
    ("Title", rb"<dc:title>"),
    ("Subject", rb"<dc:subject>"),
    ("Description", rb"<dc:description>"),
    ("Keyword", rb"<meta:keyword>"),
    ("UserDefined", rb"<meta:user-defined"),
    ("PrintedBy", rb"<meta:printed-by>"),
    ("PrintDate", rb"<meta:print-date>"),
    ("Template", rb"<meta:template"),
    ("DocumentStatistic", rb"<meta:document-statistic"),
    ("AutoReload", rb"<meta:auto-reload"),
)


def _iter_meta_fields(data: bytes):
    for name, pattern in _META_FIELD_PATTERNS:
        if re.search(pattern, data):
            yield name, pattern


def strip_content_identities(data: bytes, aggressive: bool) -> Tuple[bytes, List[str]]:
    """Remove annotation/track-change identities from content.xml or styles.xml.

    The comment and revision *text* is preserved unless aggressive is set; only
    the identity and timestamp of who wrote it is erased. Aggressive removes the
    annotations and the revision history outright.
    """
    removed: List[str] = []
    text = data.decode("utf-8", errors="ignore")
    original = text

    if aggressive:
        text, n = re.subn(
            r"<office:annotation\b.*?</office:annotation>", "", text, flags=re.DOTALL
        )
        if n:
            removed.append("Annotations")
        text, n = re.subn(
            r"<text:tracked-changes\b.*?</text:tracked-changes>", "", text,
            flags=re.DOTALL,
        )
        if n:
            removed.append("TrackedChanges")
        # Annotation anchors left behind by the removals above.
        text = re.sub(r"<office:annotation-end\b[^>]*/>", "", text)
    else:
        # Keep the comment/revision, drop the identity inside it.
        text, n = re.subn(r"<dc:creator>.*?</dc:creator>", "", text, flags=re.DOTALL)
        if n:
            removed.append("CommentAuthors")
        text, n = re.subn(r"<dc:date>.*?</dc:date>", "", text, flags=re.DOTALL)
        if n:
            removed.append("CommentDates")

    # Author name fields render the editing user's name into the document.
    text, n = re.subn(
        r"<text:author-name\b[^>]*>.*?</text:author-name>", "", text, flags=re.DOTALL
    )
    if n:
        removed.append("AuthorFields")
    text, n = re.subn(r"<text:author-initials\b[^>]*>.*?</text:author-initials>", "",
                      text, flags=re.DOTALL)
    if n:
        removed.append("AuthorInitials")

    if text == original:
        return data, []
    return text.encode("utf-8"), removed


def _manifest_without(data: bytes, dropped: List[str]) -> bytes:
    """Remove manifest file-entries for parts that no longer exist."""
    text = data.decode("utf-8", errors="ignore")
    for path in dropped:
        text = re.sub(
            rf'<manifest:file-entry[^>]*manifest:full-path="{re.escape(path)}"[^>]*/>',
            "",
            text,
        )
        # Long form with a closing tag.
        text = re.sub(
            rf'<manifest:file-entry[^>]*manifest:full-path="{re.escape(path)}"'
            rf"[^>]*>.*?</manifest:file-entry>",
            "",
            text,
            flags=re.DOTALL,
        )
    return text.encode("utf-8")


def clean_odf(data_map: Dict[str, bytes], ext: str, aggressive: bool
              ) -> Tuple[Dict[str, bytes], List[str], List[str]]:
    """Clean a parsed ODF package.

    Returns (new entries, removed metadata names, dropped part paths).
    """
    out: Dict[str, bytes] = dict(data_map)
    removed: List[str] = []
    dropped: List[str] = []

    if _META in out:
        out[_META], meta_removed = strip_meta_xml(out[_META])
        removed += meta_removed

    for part in (_CONTENT, _STYLES):
        if part in out:
            out[part], part_removed = strip_content_identities(out[part], aggressive)
            removed += part_removed

    # Rendered preview of the document's own content.
    for name in list(out):
        if name.startswith("Thumbnails/"):
            if aggressive:
                del out[name]
                dropped.append(name)
                removed.append("Thumbnail")

    if aggressive:
        # Application state: window geometry, last-used printer, local paths.
        if _SETTINGS in out:
            del out[_SETTINGS]
            dropped.append(_SETTINGS)
            removed.append("Settings")
        for name in list(out):
            if name.startswith("Configurations2/"):
                del out[name]
                dropped.append(name)

    # Embedded images keep their own EXIF; strip them losslessly.
    for name in list(out):
        if not name.startswith("Pictures/"):
            continue
        picture_ext = os.path.splitext(name)[1].lower()
        if not supports_lossless(picture_ext):
            continue
        try:
            stripped = strip_file(picture_ext, out[name], aggressive)
        except (LosslessStripError, ValueError):
            continue
        if stripped != out[name]:
            out[name] = stripped
            removed.append("EmbeddedImageMetadata")

    if _MANIFEST in out and dropped:
        out[_MANIFEST] = _manifest_without(out[_MANIFEST], dropped)

    # A missing/incorrect mimetype breaks type detection; restore it.
    expected = _EXT_TO_MIME.get(ext)
    if expected and out.get(_MIMETYPE, b"").decode("ascii", "ignore") != expected:
        out[_MIMETYPE] = expected.encode("ascii")

    return out, sorted(set(removed)), dropped


def read_package(file_path: str) -> Dict[str, bytes]:
    """Read every entry of an ODF package into memory, preserving order."""
    entries: Dict[str, bytes] = {}
    with zipfile.ZipFile(file_path, "r") as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            entries[info.filename] = zf.read(info.filename)
    return entries


def write_package(entries: Dict[str, bytes], output_path: str) -> None:
    """Write an ODF package, honouring the mimetype-first-and-stored rule."""
    with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zf:
        if _MIMETYPE in entries:
            info = zipfile.ZipInfo(_MIMETYPE, date_time=_FIXED_ZIP_DATE)
            info.compress_type = zipfile.ZIP_STORED
            zf.writestr(info, entries[_MIMETYPE])

        for name, payload in entries.items():
            if name == _MIMETYPE:
                continue
            info = zipfile.ZipInfo(name, date_time=_FIXED_ZIP_DATE)
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, payload)


def describe_odf(file_path: str) -> Dict[str, str]:
    """Report the metadata an ODF package currently exposes."""
    found: Dict[str, str] = {}
    try:
        entries = read_package(file_path)
    except (zipfile.BadZipFile, OSError):
        return found

    meta = entries.get(_META, b"")
    for name, pattern in _META_FIELD_PATTERNS:
        if not re.search(pattern, meta):
            continue
        value = _meta_value(meta, pattern)
        found[f"ODF.{name}"] = value or "PRESENT"

    content = entries.get(_CONTENT, b"")
    if re.search(rb"<office:annotation\b", content):
        found["ODF.Annotations"] = "PRESENT"
    if re.search(rb"<text:tracked-changes\b", content):
        found["ODF.TrackedChanges"] = "PRESENT"
    if re.search(rb"<text:author-name\b", content):
        found["ODF.AuthorField"] = "PRESENT"

    if any(name.startswith("Thumbnails/") for name in entries):
        found["ODF.Thumbnail"] = "PRESENT"
    if _SETTINGS in entries:
        found["ODF.Settings"] = "PRESENT"

    pictures = sum(1 for name in entries if name.startswith("Pictures/"))
    if pictures:
        found["ODF.EmbeddedImages"] = f"{pictures} images"

    return found


def _meta_value(meta: bytes, pattern: bytes) -> str:
    """Best-effort read of a simple <tag>value</tag> meta field."""
    tag = pattern.lstrip(b"<").rstrip(b">")
    match = re.search(
        rb"<" + re.escape(tag) + rb">(.*?)</" + re.escape(tag) + rb">",
        meta,
        re.DOTALL,
    )
    if not match:
        return ""
    return match.group(1).decode("utf-8", "ignore").strip()[:100]


class ODFCleaner(BaseCleaner):
    """Cleaner for OpenDocument (LibreOffice/OpenOffice) files."""

    SUPPORTED_EXTENSIONS = sorted(_EXT_TO_MIME)

    def __init__(self, log_callback: Optional[Callable[[str], None]] = None):
        super().__init__(log_callback)

    def get_supported_extensions(self) -> List[str]:
        return self.SUPPORTED_EXTENSIONS

    def clean(self, file_path: str) -> str:
        ext = os.path.splitext(file_path)[1].lower()
        aggressive = self._cleaning_profile == "aggressive"
        output_path = self.generate_output_path(file_path)

        self.log(f"[>] Opening OpenDocument: {os.path.basename(file_path)}")

        try:
            entries = read_package(file_path)
        except zipfile.BadZipFile as exc:
            raise ODFError(f"not a valid OpenDocument package: {exc}") from exc

        if _CONTENT not in entries and _META not in entries:
            raise ODFError("no content.xml or meta.xml; not an OpenDocument package")

        cleaned, removed, dropped = clean_odf(entries, ext, aggressive)
        write_package(cleaned, output_path)

        if removed:
            self.log(f"[OK] Removed metadata: {', '.join(removed)}")
        else:
            self.log("[*] No removable metadata found")
        for path in dropped:
            self.log(f"[OK] Dropped part: {path}")
        self.log(f"[OK] OpenDocument cleaned: {os.path.basename(output_path)}")
        return output_path
