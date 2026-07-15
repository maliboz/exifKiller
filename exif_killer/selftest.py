"""
Corpus self-test: prove the engines against real files.

Hand-built fixtures can only test what their author already thought of. Real
camera and encoder output is where the surprises live - unusual tag orders,
maker-specific dialects, previews in odd places. This harness takes a folder of
real files, cleans each one, and then asks the question the normal verify pass
cannot: *did the file survive?*

Each file gets three verdicts:
- `pass`     : cleaned, still intact, nothing blocking left.
- `residual` : cleaned and intact, but metadata the profile deliberately keeps
               (safe leaves RAW Make/Model, ODF annotations) is still there.
- `damaged`  : an integrity check failed. This is the only real failure - it
               means the tool corrupted a file, and no amount of metadata
               removal excuses it.

Originals are never modified: everything is cleaned into a temp directory.
The report also lists which supported formats had no sample, so it can say what
to go and find next.
"""

from __future__ import annotations

import os
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence

from cleaners.integrity import Check, check_integrity

from .constants import (
    DOCUMENT_EXTENSIONS,
    IMAGE_EXTENSIONS,
    MEDIA_EXTENSIONS,
    RAW_EXTENSIONS,
    SUPPORTED_EXTENSIONS,
)
from .models import ProfileName, ToolConfig
from .service import MetadataToolService

LogCallback = Callable[[str], None]

STATUS_PASS = "pass"
STATUS_RESIDUAL = "residual"
STATUS_DAMAGED = "damaged"
STATUS_ERROR = "error"

# Formats worth prioritising when collecting a corpus, and why. Used to tell the
# user what to go and find.
CORPUS_WISHLIST: Dict[str, str] = {
    ".jpg": "phone/camera photo straight out of the device, with GPS",
    ".heic": "iPhone photo (the default format since iOS 11)",
    ".png": "screenshot, ideally from a phone",
    ".webp": "image saved from a browser",
    ".gif": "any animated GIF",
    ".tiff": "scanner output",
    ".mp4": "phone video (carries GPS in a udta atom)",
    ".mov": "iPhone video",
    ".mkv": "anything remuxed by ffmpeg/HandBrake (rich Tags + SeekHead)",
    ".webm": "video downloaded from the web",
    ".avi": "older camera or screen recorder output",
    ".mp3": "music file with cover art (ID3v2 + APIC)",
    ".flac": "music file with cover art and VorbisComment",
    ".m4a": "iTunes/Apple Music or a voice memo",
    ".opus": "voice note (WhatsApp/Telegram/Signal export)",
    ".ogg": "Vorbis music file",
    ".wav": "voice recorder output (may carry a bext chunk)",
    ".cr2": "Canon RAW (pre-2018 bodies)",
    ".nef": "Nikon RAW",
    ".arw": "Sony RAW",
    ".dng": "Adobe/Lightroom or Google Pixel RAW",
    ".orf": "Olympus RAW",
    ".rw2": "Panasonic/Lumix RAW",
    ".pdf": "document exported from Word/Chrome/a scanner",
    ".docx": "Word document with comments and tracked changes",
    ".xlsx": "Excel workbook",
    ".pptx": "PowerPoint deck",
    ".odt": "LibreOffice Writer document",
    ".ods": "LibreOffice Calc spreadsheet",
    ".odp": "LibreOffice Impress deck",
}


@dataclass
class SelfTestResult:
    """One real file, cleaned and checked."""

    input_path: str
    ext: str
    file_type: str
    status: str
    size_before: int = 0
    size_after: int = 0
    before_count: int = 0
    after_count: int = 0
    removed_fields: List[str] = field(default_factory=list)
    remaining_blocking: List[str] = field(default_factory=list)
    checks: List[Check] = field(default_factory=list)
    error: Optional[str] = None

    @property
    def failed_checks(self) -> List[Check]:
        return [check for check in self.checks if not check.passed]

    def to_dict(self) -> dict:
        return {
            "input_path": self.input_path,
            "extension": self.ext,
            "file_type": self.file_type,
            "status": self.status,
            "size_before": self.size_before,
            "size_after": self.size_after,
            "metadata_before": self.before_count,
            "metadata_after": self.after_count,
            "removed_fields": self.removed_fields,
            "remaining_blocking": self.remaining_blocking,
            "checks": [
                {"name": c.name, "passed": c.passed, "detail": c.detail}
                for c in self.checks
            ],
            "error": self.error,
        }


@dataclass
class SelfTestReport:
    """The outcome of a corpus run."""

    profile: ProfileName
    results: List[SelfTestResult] = field(default_factory=list)
    unsupported: List[str] = field(default_factory=list)

    @property
    def damaged(self) -> List[SelfTestResult]:
        return [r for r in self.results if r.status == STATUS_DAMAGED]

    @property
    def errored(self) -> List[SelfTestResult]:
        return [r for r in self.results if r.status == STATUS_ERROR]

    @property
    def residual(self) -> List[SelfTestResult]:
        return [r for r in self.results if r.status == STATUS_RESIDUAL]

    @property
    def passed(self) -> List[SelfTestResult]:
        return [r for r in self.results if r.status == STATUS_PASS]

    @property
    def covered_extensions(self) -> List[str]:
        return sorted({r.ext for r in self.results})

    @property
    def missing_extensions(self) -> List[str]:
        covered = set(self.covered_extensions)
        return [ext for ext in SUPPORTED_EXTENSIONS if ext not in covered]

    def exit_code(self) -> int:
        if not self.results:
            return 3
        if self.damaged or self.errored:
            return 1
        if self.residual:
            return 2
        return 0

    def to_dict(self) -> dict:
        return {
            "command": "selftest",
            "profile": self.profile,
            "summary": {
                "total": len(self.results),
                "pass": len(self.passed),
                "residual": len(self.residual),
                "damaged": len(self.damaged),
                "error": len(self.errored),
            },
            "results": [r.to_dict() for r in self.results],
            "covered_extensions": self.covered_extensions,
            "missing_extensions": self.missing_extensions,
            "unsupported_inputs": self.unsupported,
        }


def run_selftest(
    paths: Sequence[str],
    profile: ProfileName = "safe",
    logger: Optional[LogCallback] = None,
    recursive: bool = True,
) -> SelfTestReport:
    """Clean every supported file under `paths` into a temp dir and check it."""
    log = logger or (lambda message: None)
    report = SelfTestReport(profile=profile)

    workdir = tempfile.mkdtemp(prefix="exif-killer-selftest-")
    try:
        service = MetadataToolService(
            ToolConfig(
                profile=profile,
                output_dir=workdir,
                recursive=recursive,
                # Never rewrite timestamps here: it would change the originals'
                # neighbours and tells us nothing about container integrity.
                timestamp_mode="keep",
            ),
            logger=lambda _m: None,  # the per-file cleaner chatter is noise here
        )
        supported, unsupported = service.discover_inputs(paths)
        report.unsupported = unsupported

        for index, file_path in enumerate(supported, start=1):
            name = os.path.basename(file_path)
            log(f"[*] ({index}/{len(supported)}) {name}")
            report.results.append(_check_one(service, file_path, log))
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    return report


def _check_one(service: MetadataToolService, file_path: str,
               log: LogCallback) -> SelfTestResult:
    ext = Path(file_path).suffix.lower()
    result = SelfTestResult(
        input_path=file_path, ext=ext, file_type="unknown", status=STATUS_ERROR
    )

    try:
        original = Path(file_path).read_bytes()
    except OSError as exc:
        result.error = f"could not read input: {exc}"
        return result

    result.size_before = len(original)

    try:
        clean = service.clean_file(file_path)
    except Exception as exc:  # pragma: no cover - defensive
        result.error = f"cleaning raised: {exc}"
        return result

    result.file_type = clean.file_type
    if clean.status == "error":
        result.error = clean.error or "cleaning failed"
        return result

    try:
        cleaned = Path(clean.output_path).read_bytes()
    except OSError as exc:
        result.error = f"could not read output: {exc}"
        return result

    result.size_after = len(cleaned)
    result.before_count = clean.before_count
    result.after_count = clean.after_count
    result.removed_fields = list(clean.removed_fields)
    result.remaining_blocking = [f.key for f in clean.blocking_findings]

    try:
        result.checks = check_integrity(ext, original, cleaned)
    except Exception as exc:  # a crashing check is itself a finding
        result.error = f"integrity check raised: {exc}"
        return result

    if result.failed_checks:
        result.status = STATUS_DAMAGED
    elif result.remaining_blocking:
        result.status = STATUS_RESIDUAL
    else:
        result.status = STATUS_PASS
    return result


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #

_STATUS_LABEL = {
    STATUS_PASS: "PASS",
    STATUS_RESIDUAL: "RESIDUAL",
    STATUS_DAMAGED: "DAMAGED",
    STATUS_ERROR: "ERROR",
}


def render_selftest(report: SelfTestReport) -> str:
    """Render a self-test report as text."""
    lines: List[str] = []
    lines.append(f"Self-test | profile={report.profile}")
    lines.append(
        f"Files: {len(report.results)} | pass={len(report.passed)} "
        f"residual={len(report.residual)} damaged={len(report.damaged)} "
        f"error={len(report.errored)}"
    )
    lines.append("")

    if not report.results:
        lines.append("No supported files found. Point this at a folder of real files.")
        lines.append("")
        lines.append(_wishlist_block(report))
        return "\n".join(lines)

    for result in report.results:
        label = _STATUS_LABEL[result.status]
        lines.append(f"[{label}] {os.path.basename(result.input_path)} ({result.ext})")
        lines.append(
            f"    type={result.file_type} size={result.size_before}"
            f"->{result.size_after} metadata={result.before_count}"
            f"->{result.after_count}"
        )
        if result.error:
            lines.append(f"    error: {result.error}")
        for check in result.checks:
            mark = "ok " if check.passed else "FAIL"
            detail = f" - {check.detail}" if check.detail else ""
            lines.append(f"    [{mark}] {check.name}{detail}")
        if result.remaining_blocking:
            lines.append(
                f"    residual: {', '.join(sorted(result.remaining_blocking))}"
            )
        lines.append("")

    if report.damaged or report.errored:
        lines.append("!! Files the tool did not handle correctly:")
        for result in report.damaged + report.errored:
            reason = result.error or "; ".join(
                f"{c.name}: {c.detail}" for c in result.failed_checks
            )
            lines.append(f"   - {os.path.basename(result.input_path)}: {reason}")
        lines.append("")

    lines.append(_wishlist_block(report))
    return "\n".join(lines)


# HEIC/HEIF/AVIF live in MEDIA_EXTENSIONS because they are ISOBMFF containers,
# but to anyone collecting samples they are photos.
_MODERN_IMAGE = {".heic", ".heif", ".avif"}


def _family_of(ext: str) -> str:
    if ext in IMAGE_EXTENSIONS or ext in _MODERN_IMAGE:
        return "Images"
    if ext in RAW_EXTENSIONS:
        return "Camera RAW"
    if ext in MEDIA_EXTENSIONS:
        return "Audio/Video"
    if ext in DOCUMENT_EXTENSIONS:
        return "Documents"
    return "Other"


def _wishlist_block(report: SelfTestReport) -> str:
    """Say what to go and find next, prioritising the formats that matter."""
    missing = report.missing_extensions
    if not missing:
        return "Coverage: every supported format has at least one real sample."

    wanted = [ext for ext in missing if ext in CORPUS_WISHLIST]
    lines = ["Still untested by a real file - worth finding:"]
    if not wanted:
        lines.append(
            "   (only rare variants left: " + ", ".join(missing[:12]) + ")"
        )
        return "\n".join(lines)

    by_family: Dict[str, List[str]] = {}
    for ext in wanted:
        by_family.setdefault(_family_of(ext), []).append(ext)

    for family in ("Images", "Camera RAW", "Audio/Video", "Documents", "Other"):
        exts = by_family.get(family)
        if not exts:
            continue
        lines.append(f"  {family}:")
        for ext in exts:
            lines.append(f"    {ext:<8} {CORPUS_WISHLIST[ext]}")

    rest = [ext for ext in missing if ext not in CORPUS_WISHLIST]
    if rest:
        lines.append(f"  Lower priority variants: {', '.join(rest)}")
    return "\n".join(lines)


def render_wishlist() -> str:
    """The full 'go find these' list, without running anything."""
    lines = [
        "Put real files into one folder, then run:",
        "    exif-killer selftest <folder> --profile aggressive",
        "",
        "Every file is cleaned into a temp directory - your originals are never",
        "modified. The tool then checks that each cleaned file still parses and",
        "that its media payload is byte-identical.",
        "",
        "Worth collecting (one real file each is enough):",
    ]
    by_family: Dict[str, List[str]] = {}
    for ext in CORPUS_WISHLIST:
        by_family.setdefault(_family_of(ext), []).append(ext)

    for family in ("Images", "Camera RAW", "Audio/Video", "Documents", "Other"):
        exts = by_family.get(family)
        if not exts:
            continue
        lines.append(f"  {family}:")
        for ext in exts:
            lines.append(f"    {ext:<8} {CORPUS_WISHLIST[ext]}")
    return "\n".join(lines)
