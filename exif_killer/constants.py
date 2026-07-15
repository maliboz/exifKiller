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

DOCUMENT_EXTENSIONS: Final[tuple[str, ...]] = (
    ".pdf",
    ".docx",
    ".xlsx",
    ".pptx",
)

SUPPORTED_EXTENSIONS: Final[tuple[str, ...]] = (
    IMAGE_EXTENSIONS + MEDIA_EXTENSIONS + DOCUMENT_EXTENSIONS
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
        "Info.jfif",
        "Info.jfif_version",
        "Info.jfif_unit",
        "Info.jfif_density",
        "ICC_Profile",
        "MarkInfo",
        "NamedDestinations",
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
