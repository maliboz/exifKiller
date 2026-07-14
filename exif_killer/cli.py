"""Command-line interface for Exif Killer."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

from .constants import BACKEND_NAME
from .models import BatchResult, ToolConfig
from .reporting import render_report, write_report
from .service import MetadataToolService
from .version import DISPLAY_VERSION


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI parser."""
    parser = argparse.ArgumentParser(
        prog="exif-killer",
        description="Offline metadata sanitizer and verification tool for DFIR, OSINT, and OPSEC.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {DISPLAY_VERSION}")

    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Scan files and classify metadata findings.")
    _add_common_scan_args(scan_parser)

    clean_parser = subparsers.add_parser("clean", help="Clean supported files and verify the outputs.")
    _add_common_scan_args(clean_parser)
    clean_parser.add_argument(
        "--profile",
        choices=("safe", "aggressive"),
        default="safe",
        help="Cleaning profile to use. Default: safe.",
    )
    target_group = clean_parser.add_mutually_exclusive_group()
    target_group.add_argument("--output-dir", help="Directory for cleaned outputs.")
    target_group.add_argument(
        "--overwrite",
        action="store_true",
        help="Replace the original file after a successful clean.",
    )
    clean_parser.add_argument(
        "--timestamp",
        choices=("auto", "keep", "epoch", "random", "custom"),
        default="auto",
        dest="timestamp_mode",
        help=(
            "Filesystem timestamp policy for cleaned files. "
            "auto: follow profile; keep: leave untouched; epoch: 1970-01-01; "
            "random: plausible random date per file; custom: use --timestamp-date. "
            "Default: auto."
        ),
    )
    clean_parser.add_argument(
        "--timestamp-date",
        dest="timestamp_value",
        help="Date for --timestamp custom (e.g. 2020-05-01 or 2020-05-01T13:00:00).",
    )

    verify_parser = subparsers.add_parser(
        "verify", help="Compare an original file and a cleaned file."
    )
    verify_parser.add_argument("original", help="Path to the original file.")
    verify_parser.add_argument("cleaned", help="Path to the cleaned file.")
    verify_parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format. Default: text.",
    )
    verify_parser.add_argument("--report", help="Optional file to write the report to.")
    verify_parser.add_argument(
        "--profile",
        choices=("safe", "aggressive"),
        default="safe",
        help="Profile label to embed in the report. Default: safe.",
    )

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if getattr(args, "timestamp_mode", None) == "custom":
        if not args.timestamp_value:
            parser.error("--timestamp custom requires --timestamp-date")
        try:
            _validate_custom_date(args.timestamp_value)
        except ValueError as exc:
            parser.error(str(exc))
    elif getattr(args, "timestamp_value", None):
        parser.error("--timestamp-date is only valid with --timestamp custom")

    if args.command == "scan":
        batch = _run_scan(args)
    elif args.command == "clean":
        batch = _run_clean(args)
    else:
        batch = _run_verify(args)

    rendered = render_report(batch, args.format)
    if args.report:
        write_report(batch, args.report, args.format)
        if args.format != "text":
            print(render_report(batch, "text").rstrip())
            print(f"\nReport written to {Path(args.report).resolve()}")
        else:
            print(rendered.rstrip())
    else:
        print(rendered.rstrip())

    return batch.exit_code()


def _run_scan(args: argparse.Namespace) -> BatchResult:
    service = MetadataToolService(
        ToolConfig(
            profile="safe",
            recursive=args.recursive,
            backend=BACKEND_NAME,
        ),
        logger=_stderr_logger,
    )
    return service.scan_paths(args.paths)


def _run_clean(args: argparse.Namespace) -> BatchResult:
    service = MetadataToolService(
        ToolConfig(
            profile=args.profile,
            output_dir=args.output_dir,
            overwrite=args.overwrite,
            recursive=args.recursive,
            backend=BACKEND_NAME,
            timestamp_mode=args.timestamp_mode,
            timestamp_value=args.timestamp_value,
        ),
        logger=_stderr_logger,
    )
    return service.clean_paths(args.paths)


def _run_verify(args: argparse.Namespace) -> BatchResult:
    service = MetadataToolService(
        ToolConfig(profile=args.profile, backend=BACKEND_NAME),
        logger=_stderr_logger,
    )
    result = service.verify_pair(args.original, args.cleaned)
    return BatchResult(
        command="verify",
        profile=args.profile,
        results=[result],
        backend=BACKEND_NAME,
    )


def _add_common_scan_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("paths", nargs="+", help="One or more files or directories.")
    parser.add_argument(
        "--recursive",
        action="store_true",
        help="Recurse into directories when a directory input is supplied.",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json", "csv"),
        default="text",
        help="Output format. Default: text.",
    )
    parser.add_argument("--report", help="Optional file to write the report to.")


def _validate_custom_date(value: str) -> None:
    """Raise ValueError if value is not a parseable date/datetime."""
    from datetime import datetime

    text = value.strip().replace("Z", "+00:00")
    try:
        datetime.fromisoformat(text)
        return
    except ValueError:
        pass
    try:
        datetime.strptime(text, "%Y-%m-%d")
    except ValueError as exc:
        raise ValueError(
            f"invalid --timestamp-date '{value}' (use YYYY-MM-DD or ISO 8601)"
        ) from exc


def _stderr_logger(message: str) -> None:
    print(message, file=sys.stderr)
