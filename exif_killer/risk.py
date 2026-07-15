"""Risk classification shared by scan, clean, and verify workflows."""

from __future__ import annotations

import re
from typing import Iterable, Mapping

from .constants import FILESYSTEM_FIELDS, TECHNICAL_EXACT_FIELDS, TECHNICAL_PREFIX_FIELDS
from .models import RiskCategory, RiskFinding, RiskSeverity


def _normalize(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.lower())


def _message_for(category: RiskCategory, key: str) -> str:
    if category == "identifying":
        return f"{key} may reveal a person, device, or software fingerprint."
    if category == "tracking":
        return f"{key} can be used to correlate, trace, or timeline the file."
    if category == "embedded-content":
        return f"{key} points to embedded or active content that should be reviewed."
    if category == "filesystem":
        return f"{key} is filesystem metadata and may matter for OPSEC-sensitive use."
    return f"{key} is a technical field retained for compatibility or file integrity."


def _severity_for(category: RiskCategory) -> RiskSeverity:
    if category in {"identifying", "tracking", "embedded-content"}:
        return "high"
    if category == "filesystem":
        return "medium"
    return "low"


def classify_metadata(
    file_type: str, metadata: Mapping[str, object]
) -> list[RiskFinding]:
    """Convert extracted metadata into stable, categorized findings."""
    findings: list[RiskFinding] = []

    for key, raw_value in sorted(metadata.items(), key=lambda item: item[0].lower()):
        value = str(raw_value)
        category = classify_key(file_type=file_type, key=key, value=value)
        findings.append(
            RiskFinding(
                key=key,
                value=value,
                category=category,
                message=_message_for(category, key),
                severity=_severity_for(category),
            )
        )

    return findings


def classify_key(file_type: str, key: str, value: str) -> RiskCategory:
    """Classify a metadata key into the shared risk taxonomy."""
    del file_type
    normalized_key = _normalize(key)
    normalized_value = _normalize(value)

    if key in FILESYSTEM_FIELDS:
        return "filesystem"

    if key in TECHNICAL_EXACT_FIELDS:
        return "technical"

    if any(key.startswith(prefix) for prefix in TECHNICAL_PREFIX_FIELDS):
        return "technical"

    if normalized_key in {
        "embeddedfiles",
        "associatedfiles",
        "javascript",
        "renditions",
        "photoshopdata",
    }:
        return "embedded-content"

    # Substring match: a thumbnail is namespaced in some formats (ODF.Thumbnail)
    # and bare in others. RAW.PreviewEXIF is the metadata inside an embedded
    # preview; the preview itself (RAW.EmbeddedPreview) only renders the same
    # photo and is treated as technical below.
    if _contains_any(normalized_key, {"thumbnail", "previewexif"}):
        return "embedded-content"

    if _contains_any(
        normalized_key,
        {
            "zoneidentifier",
            "zonezoneid",
            "zonehosturl",
            "zonereferrerurl",
            "documentid",
            "revisionids",
            "pieceinfo",
            "customproperties",
            "xmpmetadata",
            "segmentuid",
            "segmentfamily",
        },
    ):
        return "tracking"

    if _contains_any(
        normalized_key,
        {
            "gps",
            "location",
            "geolocation",
            "created",
            "modified",
            "creationdate",
            "moddate",
            "datecreated",
            "timestamp",
            "totaltime",
            "template",
            # Any date field is a timeline leak, however it is namespaced
            # (RAW.DateTimeOriginal, ODF.PrintDate, ODF.Date...).
            "date",
            "editingcycles",
            "editingduration",
        },
    ):
        return "tracking"

    if _contains_any(
        normalized_key,
        {
            "author",
            "authors",
            "creator",
            "artist",
            "owner",
            "manager",
            "company",
            "software",
            "producer",
            "make",
            "model",
            "device",
            "camera",
            "phone",
            "application",
            "apptool",
            "lastmodifiedby",
            "byline",
            "commentauthors",
            "threadedcommentidentities",
            "credit",
            "copyright",
            "source",
            "keywords",
            "subject",
            "description",
            "title",
            # Container-level encoder/muxer fingerprints and name leaks.
            "muxingapp",
            "writingapp",
            "vendor",
            "encoder",
            "encodedby",
            "trackname",
            "filename",
            "generator",
            "printedby",
            "keyword",
            "serialnumber",
            "makernote",
        },
    ):
        return "identifying"

    if "xmp" in normalized_key and (
        "creator" in normalized_key
        or "producer" in normalized_key
        or "tool" in normalized_key
        or "author" in normalized_key
    ):
        return "identifying"

    if "url" in normalized_key or "uri" in normalized_key:
        return "tracking"

    if normalized_value == "present" and normalized_key not in {"embeddedimages"}:
        return "tracking"

    return "technical"


def _contains_any(normalized_key: str, candidates: Iterable[str]) -> bool:
    for candidate in candidates:
        if candidate in normalized_key:
            return True
    return False
