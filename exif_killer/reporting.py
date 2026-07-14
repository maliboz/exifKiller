"""Structured and human-readable report rendering."""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone

from .models import BatchResult, CleanResult, ScanResult, VerificationResult
from .version import DISPLAY_VERSION


def render_report(batch: BatchResult, output_format: str) -> str:
    """Render a batch result using the requested format."""
    if output_format == "json":
        return render_json_report(batch)
    if output_format == "csv":
        return render_csv_report(batch)
    return render_text_report(batch)


def write_report(batch: BatchResult, file_path: str, output_format: str) -> None:
    """Write a rendered report to disk."""
    rendered = render_report(batch, output_format)
    with open(file_path, "w", encoding="utf-8", newline="") as handle:
        handle.write(rendered)


def render_json_report(batch: BatchResult) -> str:
    """Return the JSON batch report."""
    report = {
        "tool_version": DISPLAY_VERSION,
        "command": batch.command,
        "profile": batch.profile,
        "backend": batch.backend,
        "timestamp_utc": _timestamp_utc(),
        "summary": {
            "total_results": len(batch.results),
            "clean": batch.clean_count,
            "warning": batch.warning_count,
            "error": batch.error_count,
            "unsupported": len(batch.unsupported_inputs),
            "exit_code": batch.exit_code(),
        },
        "unsupported_inputs": batch.unsupported_inputs,
        "results": [_result_to_report_item(batch, result) for result in batch.results],
    }
    return json.dumps(report, indent=2, sort_keys=True)


def render_csv_report(batch: BatchResult) -> str:
    """Return a deterministic CSV summary."""
    fieldnames = [
        "path",
        "file_type",
        "profile",
        "status",
        "before_count",
        "after_count",
        "remaining_risk_count",
        "sha256_before",
        "sha256_after",
    ]
    stream = io.StringIO()
    writer = csv.DictWriter(stream, fieldnames=fieldnames)
    writer.writeheader()
    for row in (_result_to_csv_row(batch, result) for result in batch.results):
        writer.writerow(row)
    return stream.getvalue()


def render_text_report(batch: BatchResult) -> str:
    """Return a readable CLI/GUI summary."""
    lines = [
        f"Exif Killer {DISPLAY_VERSION}",
        f"Command: {batch.command}",
        f"Profile: {batch.profile}",
        f"Backend: {batch.backend}",
        f"Results: {len(batch.results)} | clean={batch.clean_count} warning={batch.warning_count} error={batch.error_count} unsupported={len(batch.unsupported_inputs)}",
    ]

    if batch.unsupported_inputs:
        lines.append("Unsupported inputs:")
        lines.extend(f"  - {value}" for value in batch.unsupported_inputs)

    for result in batch.results:
        lines.extend(_result_to_text_lines(result))

    lines.append(f"Exit code: {batch.exit_code()}")
    return "\n".join(lines) + "\n"


def _result_to_report_item(
    batch: BatchResult,
    result: ScanResult | CleanResult | VerificationResult,
) -> dict[str, object]:
    timestamp_utc = _timestamp_utc()
    if isinstance(result, ScanResult):
        remaining_findings = result.findings
        sha256_after = None
        output_path = None
        removed_fields: list[str] = []
        after_count = result.before_count
        findings = result.findings
        warnings = result.warnings
    else:
        remaining_findings = result.remaining_findings
        sha256_after = result.sha256_after
        output_path = result.output_path
        removed_fields = result.removed_fields
        after_count = result.after_count
        findings = result.before_scan.findings
        warnings = result.warnings

    before_count = result.before_count
    return {
        "tool_version": DISPLAY_VERSION,
        "command": batch.command,
        "profile": batch.profile,
        "status": result.status,
        "backend": batch.backend,
        "input_path": result.input_path,
        "output_path": output_path,
        "file_type": result.file_type,
        "sha256_before": result.sha256_before,
        "sha256_after": sha256_after,
        "before_count": before_count,
        "after_count": after_count,
        "findings": [finding.to_dict() for finding in findings],
        "removed_fields": removed_fields,
        "remaining_findings": [finding.to_dict() for finding in remaining_findings],
        "warnings": warnings,
        "timestamp_utc": timestamp_utc,
        "error": result.error,
    }


def _result_to_csv_row(
    batch: BatchResult,
    result: ScanResult | CleanResult | VerificationResult,
) -> dict[str, object]:
    if isinstance(result, ScanResult):
        after_count = result.before_count
        risk_count = result.risk_count
        sha256_after = ""
    else:
        after_count = result.after_count
        risk_count = result.risk_count
        sha256_after = result.sha256_after or ""

    return {
        "path": result.input_path,
        "file_type": result.file_type,
        "profile": batch.profile,
        "status": result.status,
        "before_count": result.before_count,
        "after_count": after_count,
        "remaining_risk_count": risk_count,
        "sha256_before": result.sha256_before or "",
        "sha256_after": sha256_after,
    }


def _result_to_text_lines(
    result: ScanResult | CleanResult | VerificationResult,
) -> list[str]:
    lines = [
        "",
        f"- {result.input_path}",
        f"  status={result.status} type={result.file_type} before={result.before_count}",
    ]

    if isinstance(result, ScanResult):
        lines[-1] += f" findings={len(result.findings)}"
        remaining_findings = result.findings
    else:
        lines[-1] += f" after={result.after_count} removed={len(result.removed_fields)}"
        if result.output_path != result.input_path:
            lines.append(f"  output={result.output_path}")
        remaining_findings = result.remaining_findings

    if remaining_findings:
        grouped: dict[str, list[str]] = {}
        for finding in remaining_findings:
            grouped.setdefault(finding.category, []).append(finding.key)
        for category, keys in sorted(grouped.items()):
            joined = ", ".join(keys[:5])
            suffix = "" if len(keys) <= 5 else f", +{len(keys) - 5} more"
            lines.append(f"  {category}: {joined}{suffix}")

    if result.error:
        lines.append(f"  error={result.error}")

    return lines


def _timestamp_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )
