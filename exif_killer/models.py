"""Shared data models for the CLI, GUI, and reporting layers."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal, Optional, Sequence, Union

from .constants import BLOCKING_RISK_CATEGORIES, BACKEND_NAME

RiskCategory = Literal[
    "identifying",
    "tracking",
    "embedded-content",
    "filesystem",
    "technical",
]
RiskSeverity = Literal["high", "medium", "low"]
ProfileName = Literal["safe", "aggressive"]
ResultStatus = Literal["clean", "warning", "error", "unsupported"]
TimestampMode = Literal["auto", "keep", "epoch", "random", "custom"]


@dataclass(frozen=True, slots=True)
class RiskFinding:
    """A normalized risk finding derived from extracted metadata."""

    key: str
    value: str
    category: RiskCategory
    message: str
    severity: RiskSeverity
    source: str = "metadata"

    @property
    def is_blocking(self) -> bool:
        """Return True when the finding should fail verification."""
        return self.category in BLOCKING_RISK_CATEGORIES

    def to_dict(self) -> dict[str, str | bool]:
        """Serialize to a JSON-friendly mapping."""
        return {
            "key": self.key,
            "value": self.value,
            "category": self.category,
            "message": self.message,
            "severity": self.severity,
            "source": self.source,
            "blocking": self.is_blocking,
        }


@dataclass(slots=True)
class ToolConfig:
    """Runtime configuration shared by the GUI and CLI."""

    profile: ProfileName = "safe"
    output_dir: Optional[str] = None
    overwrite: bool = False
    recursive: bool = False
    backend: str = BACKEND_NAME
    # Timestamp policy for cleaned files.
    #   auto   -> follow the profile (aggressive rewrites to epoch, safe keeps)
    #   keep   -> leave filesystem timestamps untouched
    #   epoch  -> reset to 1970-01-01
    #   random -> plausible random date per file
    #   custom -> use timestamp_value (ISO date/datetime)
    timestamp_mode: TimestampMode = "auto"
    timestamp_value: Optional[str] = None


@dataclass(slots=True)
class ScanResult:
    """Normalized scan output for a single file."""

    input_path: str
    file_type: str
    metadata: dict[str, str]
    warnings: list[str]
    findings: list[RiskFinding]
    sha256_before: Optional[str]
    backend: str = BACKEND_NAME
    status: ResultStatus = "clean"
    error: Optional[str] = None

    @property
    def before_count(self) -> int:
        return len(self.metadata)

    @property
    def blocking_findings(self) -> list[RiskFinding]:
        return [finding for finding in self.findings if finding.is_blocking]

    @property
    def risk_count(self) -> int:
        return len(
            [finding for finding in self.findings if finding.category != "technical"]
        )


@dataclass(slots=True)
class VerificationResult:
    """Before/after verification result for a single file pair."""

    input_path: str
    output_path: str
    file_type: str
    profile: ProfileName
    before_scan: ScanResult
    after_scan: ScanResult
    removed_fields: list[str]
    remaining_findings: list[RiskFinding]
    warnings: list[str]
    sha256_before: Optional[str]
    sha256_after: Optional[str]
    backend: str = BACKEND_NAME
    status: ResultStatus = "clean"
    error: Optional[str] = None

    @property
    def before_count(self) -> int:
        return self.before_scan.before_count

    @property
    def after_count(self) -> int:
        return self.after_scan.before_count

    @property
    def blocking_findings(self) -> list[RiskFinding]:
        return [finding for finding in self.remaining_findings if finding.is_blocking]

    @property
    def risk_count(self) -> int:
        return len(
            [
                finding
                for finding in self.remaining_findings
                if finding.category != "technical"
            ]
        )


@dataclass(slots=True)
class CleanResult:
    """Cleaning output plus verification details for a single file."""

    input_path: str
    output_path: str
    file_type: str
    profile: ProfileName
    before_scan: ScanResult
    after_scan: ScanResult
    removed_fields: list[str]
    remaining_findings: list[RiskFinding]
    warnings: list[str]
    sha256_before: Optional[str]
    sha256_after: Optional[str]
    backend: str = BACKEND_NAME
    status: ResultStatus = "clean"
    error: Optional[str] = None

    @property
    def before_count(self) -> int:
        return self.before_scan.before_count

    @property
    def after_count(self) -> int:
        return self.after_scan.before_count

    @property
    def blocking_findings(self) -> list[RiskFinding]:
        return [finding for finding in self.remaining_findings if finding.is_blocking]

    @property
    def risk_count(self) -> int:
        return len(
            [
                finding
                for finding in self.remaining_findings
                if finding.category != "technical"
            ]
        )


AnyResult = Union[ScanResult, VerificationResult, CleanResult]


@dataclass(slots=True)
class BatchResult:
    """Batch wrapper used by the CLI, GUI, and report exporters."""

    command: str
    profile: ProfileName
    # Sequence, not list: callers build a homogeneous list[ScanResult] or
    # list[CleanResult], and list is invariant so those would not fit a
    # list[AnyResult] parameter.
    results: Sequence[AnyResult] = field(default_factory=list)
    unsupported_inputs: list[str] = field(default_factory=list)
    backend: str = BACKEND_NAME

    @property
    def has_errors(self) -> bool:
        return any(result.status == "error" for result in self.results)

    @property
    def has_blocking_findings(self) -> bool:
        return any(
            getattr(result, "blocking_findings", [])
            for result in self.results
            if result.status != "error"
        )

    @property
    def clean_count(self) -> int:
        return len([result for result in self.results if result.status == "clean"])

    @property
    def warning_count(self) -> int:
        return len([result for result in self.results if result.status == "warning"])

    @property
    def error_count(self) -> int:
        return len([result for result in self.results if result.status == "error"])

    def exit_code(self) -> int:
        """Return the stable CLI exit code for this batch."""
        if not self.results:
            return 3 if self.unsupported_inputs else 0
        if self.has_errors:
            return 1
        if self.has_blocking_findings:
            return 2
        return 0
