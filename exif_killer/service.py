"""Shared engine used by the CLI and GUI frontends."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Callable, Iterable, Optional

from cleaners import (
    ImageCleaner,
    MediaCleaner,
    MetadataExtractor,
    ODFCleaner,
    OfficeCleaner,
    PDFCleaner,
    RawCleaner,
)

from .constants import RAW_EXTENSIONS, SUPPORTED_EXTENSIONS
from .hashes import sha256_file
from .models import (
    BatchResult,
    CleanResult,
    ResultStatus,
    ScanResult,
    ToolConfig,
    VerificationResult,
)
from .risk import classify_metadata

LogCallback = Callable[[str], None]
ProgressCallback = Callable[[int, int, str], None]


class MetadataToolService:
    """Thin orchestration layer around extractors and cleaners."""

    def __init__(
        self,
        config: Optional[ToolConfig] = None,
        logger: Optional[LogCallback] = None,
    ) -> None:
        self.config = config or ToolConfig()
        self._log = logger or (lambda message: None)
        self.extractor = MetadataExtractor(self._log)
        self.cleaners = [
            ImageCleaner(self._log),
            MediaCleaner(self._log),
            RawCleaner(self._log),
            PDFCleaner(self._log),
            OfficeCleaner(self._log),
            ODFCleaner(self._log),
        ]
        self.supported_extensions = set(SUPPORTED_EXTENSIONS)
        self._configure_cleaners()
        self._warn_about_degraded_support()

    def _warn_about_degraded_support(self) -> None:
        """Say up front if an optional engine cannot run in this environment.

        A missing C extension disables one format family, not the tool. The user
        should hear that when the app starts rather than discovering it halfway
        through a batch.
        """
        from cleaners.pdf_cleaner import pdf_support_available, pdf_support_error

        if not pdf_support_available():
            self._log(f"[!] {pdf_support_error()}")

    def scan_paths(
        self,
        paths: Iterable[str],
        progress_callback: Optional[ProgressCallback] = None,
    ) -> BatchResult:
        """Scan one or many files and return a batch result."""
        supported, unsupported = self.discover_inputs(paths)
        results: list[ScanResult] = []

        total = len(supported)
        for index, file_path in enumerate(supported, start=1):
            if progress_callback:
                progress_callback(index, total, file_path)
            self._log(f"[*] Scanning {os.path.basename(file_path)}")
            results.append(self.scan_file(file_path))

        return BatchResult(
            command="scan",
            profile=self.config.profile,
            results=results,
            unsupported_inputs=unsupported,
            backend=self.config.backend,
        )

    def clean_paths(
        self,
        paths: Iterable[str],
        progress_callback: Optional[ProgressCallback] = None,
    ) -> BatchResult:
        """Clean one or many files and verify the outputs."""
        supported, unsupported = self.discover_inputs(paths)
        results: list[CleanResult] = []

        total = len(supported)
        for index, file_path in enumerate(supported, start=1):
            if progress_callback:
                progress_callback(index, total, file_path)
            results.append(self.clean_file(file_path))

        return BatchResult(
            command="clean",
            profile=self.config.profile,
            results=results,
            unsupported_inputs=unsupported,
            backend=self.config.backend,
        )

    def verify_pair(
        self,
        original_path: str,
        cleaned_path: str,
        before_scan: Optional[ScanResult] = None,
    ) -> VerificationResult:
        """Compare an original file and a cleaned file."""
        original_scan = before_scan or self.scan_file(original_path)
        cleaned_scan = self.scan_file(cleaned_path)

        if original_scan.status == "error":
            return VerificationResult(
                input_path=original_path,
                output_path=cleaned_path,
                file_type=cleaned_scan.file_type,
                profile=self.config.profile,
                before_scan=original_scan,
                after_scan=cleaned_scan,
                removed_fields=[],
                remaining_findings=cleaned_scan.findings,
                warnings=cleaned_scan.warnings,
                sha256_before=original_scan.sha256_before,
                sha256_after=cleaned_scan.sha256_before,
                backend=self.config.backend,
                status="error",
                error=original_scan.error,
            )

        if cleaned_scan.status == "error":
            return VerificationResult(
                input_path=original_path,
                output_path=cleaned_path,
                file_type=original_scan.file_type,
                profile=self.config.profile,
                before_scan=original_scan,
                after_scan=cleaned_scan,
                removed_fields=[],
                remaining_findings=[],
                warnings=cleaned_scan.warnings,
                sha256_before=original_scan.sha256_before,
                sha256_after=cleaned_scan.sha256_before,
                backend=self.config.backend,
                status="error",
                error=cleaned_scan.error,
            )

        removed_fields = sorted(
            set(original_scan.metadata.keys()) - set(cleaned_scan.metadata.keys()),
            key=str.lower,
        )
        status: ResultStatus = (
            "warning" if cleaned_scan.blocking_findings else "clean"
        )

        return VerificationResult(
            input_path=original_path,
            output_path=cleaned_path,
            file_type=cleaned_scan.file_type,
            profile=self.config.profile,
            before_scan=original_scan,
            after_scan=cleaned_scan,
            removed_fields=removed_fields,
            remaining_findings=cleaned_scan.findings,
            warnings=cleaned_scan.warnings,
            sha256_before=original_scan.sha256_before,
            sha256_after=cleaned_scan.sha256_before,
            backend=self.config.backend,
            status=status,
        )

    def clean_file(self, file_path: str) -> CleanResult:
        """Clean a single supported file and verify the output."""
        before_scan = self.scan_file(file_path)
        file_type = before_scan.file_type

        if before_scan.status == "error":
            return CleanResult(
                input_path=file_path,
                output_path=file_path,
                file_type=file_type,
                profile=self.config.profile,
                before_scan=before_scan,
                after_scan=before_scan,
                removed_fields=[],
                remaining_findings=[],
                warnings=before_scan.warnings,
                sha256_before=before_scan.sha256_before,
                sha256_after=before_scan.sha256_before,
                backend=self.config.backend,
                status="error",
                error=before_scan.error,
            )

        cleaner = self._get_cleaner(file_path)
        if cleaner is None:
            return CleanResult(
                input_path=file_path,
                output_path=file_path,
                file_type=file_type,
                profile=self.config.profile,
                before_scan=before_scan,
                after_scan=before_scan,
                removed_fields=[],
                remaining_findings=before_scan.findings,
                warnings=before_scan.warnings,
                sha256_before=before_scan.sha256_before,
                sha256_after=before_scan.sha256_before,
                backend=self.config.backend,
                status="error",
                error="No suitable cleaner found for the input file.",
            )

        self._log(
            f"[>] Cleaning {os.path.basename(file_path)} with profile={self.config.profile}"
        )

        try:
            output_path = cleaner.full_clean(file_path)
        except Exception as exc:  # pragma: no cover - exercised by runtime failures
            return CleanResult(
                input_path=file_path,
                output_path=file_path,
                file_type=file_type,
                profile=self.config.profile,
                before_scan=before_scan,
                after_scan=before_scan,
                removed_fields=[],
                remaining_findings=before_scan.findings,
                warnings=before_scan.warnings,
                sha256_before=before_scan.sha256_before,
                sha256_after=before_scan.sha256_before,
                backend=self.config.backend,
                status="error",
                error=str(exc),
            )

        verification = self.verify_pair(
            original_path=file_path,
            cleaned_path=output_path,
            before_scan=before_scan,
        )

        return CleanResult(
            input_path=file_path,
            output_path=output_path,
            file_type=verification.file_type,
            profile=self.config.profile,
            before_scan=verification.before_scan,
            after_scan=verification.after_scan,
            removed_fields=verification.removed_fields,
            remaining_findings=verification.remaining_findings,
            warnings=verification.warnings,
            sha256_before=verification.sha256_before,
            sha256_after=verification.sha256_after,
            backend=self.config.backend,
            status=verification.status,
            error=verification.error,
        )

    def scan_file(self, file_path: str) -> ScanResult:
        """Scan a single file and classify its findings."""
        try:
            report = self.extractor.extract(file_path)
            metadata = {
                key: str(value)
                for key, value in sorted(report.metadata.items(), key=lambda item: item[0].lower())
            }
            findings = classify_metadata(report.file_type.lower(), metadata)
            status: ResultStatus = (
                "warning"
                if any(finding.is_blocking for finding in findings)
                else "clean"
            )
            sha256 = sha256_file(file_path)
            return ScanResult(
                input_path=str(Path(file_path).resolve()),
                file_type=report.file_type.lower(),
                metadata=metadata,
                warnings=list(report.warnings),
                findings=findings,
                sha256_before=sha256,
                backend=self.config.backend,
                status=status,
            )
        except Exception as exc:  # pragma: no cover - exercised by runtime failures
            return ScanResult(
                input_path=str(Path(file_path).resolve()),
                file_type=self._file_type_from_path(file_path),
                metadata={},
                warnings=[str(exc)],
                findings=[],
                sha256_before=None,
                backend=self.config.backend,
                status="error",
                error=str(exc),
            )

    def discover_inputs(self, paths: Iterable[str]) -> tuple[list[str], list[str]]:
        """Resolve files from user-supplied paths."""
        supported: list[str] = []
        unsupported: list[str] = []
        seen: set[str] = set()

        for raw_path in paths:
            if raw_path is None:
                continue

            path = Path(raw_path).expanduser()
            if not path.exists():
                unsupported.append(str(path))
                continue

            if path.is_dir():
                iterator = path.rglob("*") if self.config.recursive else path.glob("*")
                file_paths = sorted(
                    [item for item in iterator if item.is_file()],
                    key=lambda item: str(item).lower(),
                )
            else:
                file_paths = [path]

            for file_path in file_paths:
                resolved = str(file_path.resolve())
                extension = file_path.suffix.lower()
                if extension not in self.supported_extensions:
                    unsupported.append(resolved)
                    continue
                if resolved in seen:
                    continue
                supported.append(resolved)
                seen.add(resolved)

        return supported, sorted(set(unsupported), key=str.lower)

    def _configure_cleaners(self) -> None:
        aggressive = self.config.profile == "aggressive"
        reset_timestamps, timestamp_mode = self._resolve_timestamp_policy(aggressive)

        for cleaner in self.cleaners:
            cleaner.set_output_folder(self.config.output_dir)
            cleaner.set_overwrite_mode(self.config.overwrite)
            cleaner.set_cleaning_profile(self.config.profile)
            cleaner.set_forensic_post_processing(
                reset_timestamps=reset_timestamps,
                remove_zone_identifier=aggressive,
            )
            if reset_timestamps:
                cleaner.set_timestamp_policy(timestamp_mode, self.config.timestamp_value)

    def _resolve_timestamp_policy(self, aggressive: bool) -> tuple[bool, str]:
        """Resolve the configured timestamp mode into (reset?, effective_mode).

        'auto' preserves the historical behavior: aggressive resets to epoch,
        safe leaves timestamps untouched. Explicit modes always win.
        """
        mode = self.config.timestamp_mode
        if mode == "auto":
            return (aggressive, "epoch")
        if mode == "keep":
            return (False, "epoch")
        return (True, mode)

    def _get_cleaner(self, file_path: str):
        for cleaner in self.cleaners:
            if cleaner.supports(file_path):
                return cleaner
        return None

    def _file_type_from_path(self, file_path: str) -> str:
        extension = Path(file_path).suffix.lower()
        if extension == ".pdf":
            return "pdf"
        if extension in {".docx", ".xlsx", ".pptx"}:
            return "office"
        if extension in {".odt", ".ods", ".odp", ".odg", ".odf", ".ott",
                         ".ots", ".otp"}:
            return "opendocument"
        if extension in RAW_EXTENSIONS:
            return "raw"
        if extension in {".mp4", ".mov", ".m4v", ".mkv", ".avi", ".webm", ".ogv"}:
            return "video"
        if extension in {
            ".mp3", ".flac", ".m4a", ".wav", ".ogg", ".oga", ".opus", ".spx",
            ".aac",
        }:
            return "audio"
        if extension in {
            ".jpg", ".jpeg", ".jpe", ".png", ".webp", ".bmp", ".tiff", ".tif",
            ".gif", ".svg", ".heic", ".heif", ".avif",
        }:
            return "image"
        return "unknown"
