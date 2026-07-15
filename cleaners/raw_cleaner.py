"""
RAW Cleaner - native metadata removal for TIFF-based camera RAW files.

Dispatches to the pure-Python TIFF engine. No external tools, no re-encoding:
the sensor data is preserved bit-for-bit and the file size never changes.
"""

from __future__ import annotations

import os
from typing import Callable, List, Optional

from . import ciff, tiff_raw
from .base import BaseCleaner

# Canon CRW is CIFF, not TIFF, and has its own engine.
_CIFF_EXTENSIONS = {".crw"}

# TIFF-based RAW dialects. CR3 (Canon's ISOBMFF-based successor), RAF (Fuji),
# and X3F (Sigma) are deliberately absent: they are not TIFF containers and
# would need their own engines.
_TIFF_EXTENSIONS = {
    ".cr2",   # Canon
    ".nef", ".nrw",  # Nikon
    ".arw", ".sr2", ".srf",  # Sony
    ".dng",   # Adobe / Google / Leica
    ".orf",   # Olympus
    ".rw2",   # Panasonic
    ".pef",   # Pentax
    ".srw",   # Samsung
    ".3fr",   # Hasselblad
    ".mef",   # Mamiya
    ".mos",   # Leaf
    ".erf",   # Epson
    ".dcr", ".kdc",  # Kodak
}

_RAW_EXTENSIONS = _TIFF_EXTENSIONS | _CIFF_EXTENSIONS


class RawCleaner(BaseCleaner):
    """Cleaner for camera RAW formats (TIFF-based, plus Canon's CIFF-based CRW)."""

    SUPPORTED_EXTENSIONS = sorted(_RAW_EXTENSIONS)

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

        self.log(f"[>] Cleaning RAW (native): {os.path.basename(file_path)}")
        if ext in _CIFF_EXTENSIONS:
            cleaned, removed = ciff.clean_crw(data, aggressive)
        else:
            cleaned, removed = tiff_raw.clean_tiff(data, aggressive)

        if len(cleaned) != len(data):  # pragma: no cover - defensive
            raise ValueError("internal error: RAW cleaning changed the file size")

        with open(output_path, "wb") as handle:
            handle.write(cleaned)

        if removed:
            self.log(f"[OK] Removed metadata: {', '.join(removed)}")
        else:
            self.log("[*] No removable metadata found")

        if aggressive:
            self.log(
                "[!] Aggressive profile removed Make/Model: some RAW converters "
                "identify the sensor from these and may refuse the file"
            )

        self.log(f"[OK] RAW cleaned: {os.path.basename(output_path)}")
        return output_path
