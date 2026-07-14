"""
ExifTool-backed cleaner for formats without a safe native path.

Handles modern images (HEIC/HEIF/AVIF), video (MP4/MOV/MKV/...), audio
(MP3/FLAC/M4A/...), and camera RAW. Only registered by the service when the
ExifTool binary is actually present, so the tool stays fully native otherwise.
"""

from __future__ import annotations

import os
from typing import Callable, List, Optional

from .base import BaseCleaner
from .exiftool_backend import clean_metadata, exiftool_available


class ExiftoolCleaner(BaseCleaner):
    """Delegate cleaning of exotic formats to a local ExifTool binary."""

    def __init__(
        self,
        supported_extensions: List[str],
        log_callback: Optional[Callable[[str], None]] = None,
    ):
        super().__init__(log_callback)
        self._supported = [ext.lower() for ext in supported_extensions]

    def get_supported_extensions(self) -> List[str]:
        return self._supported

    def clean(self, file_path: str) -> str:
        if not exiftool_available():
            raise RuntimeError("ExifTool backend is not available")

        aggressive = self._cleaning_profile == "aggressive"
        output_path = self.generate_output_path(file_path)

        self.log(
            f"[>] Cleaning via ExifTool: {os.path.basename(file_path)} "
            f"(profile={self._cleaning_profile})"
        )
        clean_metadata(file_path, output_path, aggressive)
        self.log(f"[OK] Metadata removed via ExifTool: {os.path.basename(output_path)}")
        return output_path
