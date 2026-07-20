"""Project-wide constants."""

from __future__ import annotations

from typing import Final

# Still images cleaned by the native lossless / pixel-copy image engine.
IMAGE_EXTENSIONS: Final[tuple[str, ...]] = (
    ".jpg",
    ".jpeg",
    ".jpe",
    ".png",
    ".webp",
    ".bmp",
    ".tiff",
    ".tif",
    ".gif",
    ".svg",
)

# Audio/video/modern-image containers cleaned by the native media engine
# (pure-Python ISOBMFF, Matroska/EBML, Ogg, RIFF, ID3, FLAC parsers — no
# external tools).
MEDIA_EXTENSIONS: Final[tuple[str, ...]] = (
    ".mp4",
    ".mov",
    ".m4v",
    ".m4a",
    ".heic",
    ".heif",
    ".avif",
    ".mp3",
    ".flac",
    ".wav",
    ".avi",
    ".mkv",
    ".webm",
    ".ogg",
    ".oga",
    ".ogv",
    ".opus",
    ".spx",
)

# TIFF-based camera RAW, cleaned by the native TIFF engine. Metadata tags are
# removed in place so sensor data and byte offsets never move.
RAW_EXTENSIONS: Final[tuple[str, ...]] = (
    ".crw",  # Canon CIFF (not TIFF; handled by the CIFF engine)
    ".cr2",
    ".nef",
    ".nrw",
    ".arw",
    ".sr2",
    ".srf",
    ".dng",
    ".orf",
    ".rw2",
    ".pef",
    ".srw",
    ".3fr",
    ".mef",
    ".mos",
    ".erf",
    ".dcr",
    ".kdc",
)

DOCUMENT_EXTENSIONS: Final[tuple[str, ...]] = (
    ".pdf",
    ".docx",
    ".xlsx",
    ".pptx",
    ".odt",
    ".ods",
    ".odp",
    ".odg",
    ".odf",
    ".ott",
    ".ots",
    ".otp",
)

SUPPORTED_EXTENSIONS: Final[tuple[str, ...]] = (
    IMAGE_EXTENSIONS + MEDIA_EXTENSIONS + RAW_EXTENSIONS + DOCUMENT_EXTENSIONS
)

BLOCKING_RISK_CATEGORIES: Final[frozenset[str]] = frozenset(
    {"identifying", "tracking", "embedded-content"}
)

TECHNICAL_EXACT_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "Format",
        "Mode",
        "Size",
        "PageCount",
        "FileSize",
        "EmbeddedImages",
        "Document_ID_Static",
        "Info.jfif",
        "Info.jfif_version",
        "Info.jfif_unit",
        "Info.jfif_density",
        "ICC_Profile",
        "MarkInfo",
        "NamedDestinations",
        # A RAW's embedded preview renders the same photo it is stored in, so it
        # discloses nothing extra. Its own metadata is reported as
        # RAW.PreviewEXIF, which is blocking.
        "RAW.EmbeddedPreview",
        "ODF.EmbeddedImages",
    }
)

TECHNICAL_PREFIX_FIELDS: Final[tuple[str, ...]] = (
    "App.Pages",
    "App.Words",
    "App.Characters",
    "App.Lines",
    "App.Paragraphs",
)

FILESYSTEM_FIELDS: Final[frozenset[str]] = frozenset(
    {"FileCreated", "FileModified", "FileAccessed"}
)

BACKEND_NAME: Final[str] = "native-python"
