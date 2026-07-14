"""Project-wide constants."""

from __future__ import annotations

from typing import Final

# Formats handled natively (no external tools required).
NATIVE_EXTENSIONS: Final[tuple[str, ...]] = (
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
    ".pdf",
    ".docx",
    ".xlsx",
    ".pptx",
)

# Formats handled only when the optional ExifTool backend is available
# (hybrid backend): modern images, video, audio, and camera RAW.
EXIFTOOL_EXTENSIONS: Final[tuple[str, ...]] = (
    ".heic",
    ".heif",
    ".avif",
    ".mp4",
    ".mov",
    ".m4v",
    ".mkv",
    ".avi",
    ".webm",
    ".mp3",
    ".flac",
    ".m4a",
    ".wav",
    ".ogg",
    ".opus",
    ".aac",
    ".cr2",
    ".cr3",
    ".nef",
    ".arw",
    ".dng",
    ".orf",
    ".rw2",
    ".raf",
    ".pef",
    ".srw",
)

SUPPORTED_EXTENSIONS: Final[tuple[str, ...]] = NATIVE_EXTENSIONS + EXIFTOOL_EXTENSIONS

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
