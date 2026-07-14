"""
Optional ExifTool backend (hybrid mode).

ExifTool is the industry-standard metadata engine and cleans formats that pure
Python cannot handle safely or losslessly: HEIC/HEIF/AVIF, video (MP4/MOV/MKV),
audio (MP3/FLAC/M4A), and camera RAW. When the `exiftool` binary is present on
PATH it is used for those formats; when it is absent the tool stays fully
offline and native, and these formats are simply reported as unsupported.

Nothing here ever phones home: ExifTool runs locally as a subprocess.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from functools import lru_cache
from typing import Optional


@lru_cache(maxsize=1)
def exiftool_path() -> Optional[str]:
    """Return the path to the exiftool binary, or None if unavailable."""
    override = os.environ.get("EXIFTOOL_PATH")
    if override and os.path.isfile(override):
        return override
    return shutil.which("exiftool")


def exiftool_available() -> bool:
    return exiftool_path() is not None


@lru_cache(maxsize=1)
def exiftool_version() -> Optional[str]:
    path = exiftool_path()
    if not path:
        return None
    try:
        result = subprocess.run(
            [path, "-ver"],
            capture_output=True,
            text=True,
            timeout=15,
            check=True,
        )
        return result.stdout.strip()
    except (subprocess.SubprocessError, OSError):
        return None


class ExifToolError(Exception):
    """Raised when an ExifTool invocation fails."""


def read_metadata(file_path: str) -> dict[str, str]:
    """Return a flat mapping of metadata tags for a file via ExifTool.

    Excludes the bulky/derived groups (File system, composite) that are not
    intrinsic metadata, so scan/verify focus on removable fields.
    """
    path = exiftool_path()
    if not path:
        raise ExifToolError("exiftool is not available")

    try:
        result = subprocess.run(
            [
                path,
                "-json",
                "-a",  # allow duplicate tags
                "-G1",  # group names, so callers can see EXIF/XMP/etc.
                "-n",  # numeric values (stable, machine-friendly)
                "--ExifTool:all",  # drop exiftool's own version tags
                "-ExifTool:Warning",
                file_path,
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
    except (subprocess.SubprocessError, OSError) as exc:
        raise ExifToolError(str(exc)) from exc

    if result.returncode != 0 and not result.stdout.strip():
        raise ExifToolError(result.stderr.strip() or "exiftool read failed")

    try:
        payload = json.loads(result.stdout or "[]")
    except json.JSONDecodeError as exc:
        raise ExifToolError(f"invalid exiftool JSON: {exc}") from exc

    if not payload:
        return {}

    record = payload[0]
    metadata: dict[str, str] = {}
    skip_prefixes = ("SourceFile", "System:", "File:", "Composite:", "ExifTool:")
    for key, value in record.items():
        if key == "SourceFile" or any(key.startswith(p) for p in skip_prefixes):
            continue
        metadata[key] = _stringify(value)
    return metadata


def clean_metadata(file_path: str, output_path: str, aggressive: bool) -> None:
    """Copy file_path to output_path with metadata removed by ExifTool."""
    path = exiftool_path()
    if not path:
        raise ExifToolError("exiftool is not available")

    # -all= strips every writable tag group. For aggressive we also drop any
    # trailing data (thumbnails, previews, appended payloads). -P preserves the
    # filesystem modification time so our own timestamp policy stays in charge.
    args = [
        path,
        "-all=",
        "-P",
        "-overwrite_original",
    ]
    if aggressive:
        # Also drop trailing payloads and the ICC colour profile.
        args += ["-Trailer:all=", "-icc_profile:all="]

    # ExifTool edits in place, so operate on a copy at output_path.
    shutil.copy2(file_path, output_path)

    try:
        result = subprocess.run(
            args + [output_path],
            capture_output=True,
            text=True,
            timeout=300,
        )
    except (subprocess.SubprocessError, OSError) as exc:
        _safe_remove(output_path)
        raise ExifToolError(str(exc)) from exc

    if result.returncode != 0:
        _safe_remove(output_path)
        raise ExifToolError(result.stderr.strip() or "exiftool clean failed")


def _safe_remove(path: str) -> None:
    try:
        os.remove(path)
    except OSError:
        pass


def _stringify(value: object) -> str:
    if isinstance(value, (list, tuple)):
        return ", ".join(str(item) for item in value)
    return str(value)
