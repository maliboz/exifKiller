"""Hash helpers used for audit-friendly reports."""

from __future__ import annotations

import hashlib


def sha256_file(file_path: str) -> str:
    """Return the SHA-256 checksum of a file."""
    hasher = hashlib.sha256()
    with open(file_path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()
