"""
Media Cleaner - native metadata removal for audio and video containers.

Dispatches to the pure-Python ISOBMFF, Matroska, Ogg, and RIFF/ID3/FLAC
strippers. No external binaries, no re-encoding: media payloads are preserved
byte-for-byte.
"""

from __future__ import annotations

import os
from typing import Callable, List, Optional

from . import isobmff, matroska, native_media, ogg
from .base import BaseCleaner

# ISOBMFF (MP4/QuickTime) family.
_ISOBMFF_MOVIE = {".mp4", ".mov", ".m4v", ".m4a"}
_ISOBMFF_HEIF = {".heic", ".heif", ".avif"}
# RIFF/tag-based audio.
_MP3 = {".mp3"}
_FLAC = {".flac"}
_RIFF = {".wav", ".avi"}
# EBML and Ogg families.
_MATROSKA = {".mkv", ".webm"}
_OGG = {".ogg", ".oga", ".ogv", ".opus", ".spx"}


class MediaCleaner(BaseCleaner):
    """Cleaner for audio/video/modern-image container formats."""

    SUPPORTED_EXTENSIONS = sorted(
        _ISOBMFF_MOVIE | _ISOBMFF_HEIF | _MP3 | _FLAC | _RIFF | _MATROSKA | _OGG
    )

    def __init__(self, log_callback: Optional[Callable[[str], None]] = None):
        super().__init__(log_callback)

    def get_supported_extensions(self) -> List[str]:
        return self.SUPPORTED_EXTENSIONS

    def clean(self, file_path: str) -> str:
        ext = os.path.splitext(file_path)[1].lower()
        aggressive = self._cleaning_profile == "aggressive"
        output_path = self.generate_output_path(file_path)

        with open(file_path, "rb") as handle:
            data = handle.read()

        self.log(f"[>] Cleaning media (native): {os.path.basename(file_path)}")
        cleaned, removed = self._dispatch(ext, data, aggressive)

        with open(output_path, "wb") as handle:
            handle.write(cleaned)

        if removed:
            self.log(f"[OK] Removed metadata: {', '.join(sorted(set(removed)))}")
        else:
            self.log("[*] No removable metadata found")
        self.log(f"[OK] Media cleaned: {os.path.basename(output_path)}")
        return output_path

    def _dispatch(self, ext: str, data: bytes, aggressive: bool):
        if ext in _ISOBMFF_MOVIE:
            if not isobmff.is_isobmff(data):
                raise ValueError("not a valid ISOBMFF file")
            return isobmff.clean_movie(data, aggressive)
        if ext in _ISOBMFF_HEIF:
            if not isobmff.is_isobmff(data):
                raise ValueError("not a valid HEIF/AVIF file")
            return isobmff.clean_heif(data, aggressive)
        if ext in _MP3:
            return native_media.strip_mp3(data, aggressive)
        if ext in _FLAC:
            return native_media.strip_flac(data, aggressive)
        if ext in _RIFF:
            return native_media.strip_riff(data, aggressive)
        if ext in _MATROSKA:
            return matroska.clean_matroska(data, aggressive)
        if ext in _OGG:
            return ogg.clean_ogg(data, aggressive)
        raise ValueError(f"unsupported media extension: {ext}")
