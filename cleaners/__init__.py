"""
Exif Killer - Cleaner Classes Package
Forensic-level metadata removal for various file types.

v3.0 Features:
- Image EXIF/IPTC cleaning
- PDF metadata and XMP removal
- Office revision history cleaning
- File timestamp reset
- Zone.Identifier removal
"""

from .base import BaseCleaner
from .image_cleaner import ImageCleaner
from .pdf_cleaner import PDFCleaner
from .office_cleaner import OfficeCleaner
from .timestamp_cleaner import TimestampCleaner
from .exiftool_cleaner import ExiftoolCleaner
from .exiftool_backend import exiftool_available, exiftool_version
from .metadata_extractor import MetadataExtractor, MetadataReport, compare_reports

__all__ = [
    'BaseCleaner',
    'ImageCleaner',
    'PDFCleaner',
    'OfficeCleaner',
    'TimestampCleaner',
    'ExiftoolCleaner',
    'exiftool_available',
    'exiftool_version',
    'MetadataExtractor',
    'MetadataReport',
    'compare_reports',
]
