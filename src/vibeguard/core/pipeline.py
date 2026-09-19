"""Scan pipeline: orchestrate analyzers, aggregate, enforce the AI clamp.

ARCHITECTURE §6 hard invariant: AI findings can never cause verdict block.
The pipeline enforces this by clamping provider output — it never trusts
the provider, even though the AIProvider doesn't exist until Phase 3.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from vibeguard.core.result import Finding, ScanReport, Severity, aggregate

if TYPE_CHECKING:
    from vibeguard.analyzers.base import Analyzer
    from vibeguard.core.diff import DiffFile


MAX_DIFF_BYTES_DEFAULT = 1_000_000


@dataclass
class ScanConfig:
    """Scan options (Phase 1: strict + max_diff_bytes; config file is P2.3)."""

    strict: bool = False
    max_diff_bytes: int = MAX_DIFF_BYTES_DEFAULT


@runtime_checkable
class AIProvider(Protocol):
    """Advisory AI provider (ARCHITECTURE §6). Implemented in Phase 3."""

    name: str

    def review(
        self,
        files: list[DiffFile],
        findings: list[Finding],
        config: object,
    ) -> list[Finding]: ...


def _diff_bytes(files: list[DiffFile]) -> int:
    return sum(
        len(text.encode("utf-8", errors="replace"))
        for f in files
        for _, text in f.added_lines
    )


def clamp_ai_findings(findings: list[Finding]) -> list[Finding]:
    """Force every finding from the AI provider path to severity <= warn and
    source='ai'.

    Hard invariant: AI-source findings can NEVER cause verdict block. The
    clamp is applied by the pipeline and does NOT trust the provider-reported
    ``source`` field — a malicious provider reporting ``source="rule"`` /
    ``severity="error"`` is still rewritten to ``source="ai"`` and downgraded
    to warn. Only this function is the boundary between "provider output" and
    "pipeline findings"; it must treat its entire input as untrusted.
    """
    clamped: list[Finding] = []
    for f in findings:
        sev = f.severity if f.severity is not Severity.ERROR else Severity.WARN
        clamped.append(
            Finding(
                rule_id=f.rule_id,
                severity=sev,
                file=f.file,
                line=f.line,
                message=f.message,
                snippet=f.snippet,
                source="ai",
            )
        )
    return clamped


def run_scan(
    diff_files: list[DiffFile],
    analyzers: list[Analyzer],
    ai_provider: AIProvider | None,
    config: ScanConfig,
) -> ScanReport:
    """Run deterministic analyzers, aggregate, then (if enabled) AI review + clamp.

    Order per TASKS.md P1.4: analyzers -> aggregate -> AI review -> clamp ->
    re-aggregate. max_diff_bytes: beyond the limit, content rules are skipped
    and a warn finding "diff-too-large" is emitted.
    """
    start = time.monotonic()
    findings: list[Finding] = []

    too_large = _diff_bytes(diff_files) > config.max_diff_bytes
    if too_large:
        findings.append(
            Finding(
                rule_id="diff-too-large",
                severity=Severity.WARN,
                file="",
                line=None,
                message="diff exceeds max_diff_bytes; content analysis skipped",
                source="rule",
            )
        )
        scan_files: list[DiffFile] = []
    else:
        scan_files = diff_files

    for analyzer in analyzers:
        findings.extend(analyzer.analyze(scan_files, config))

    report = aggregate(findings, strict=config.strict)

    if ai_provider is not None:
        ai_findings = ai_provider.review(scan_files, list(report.findings), config)
        # Clamp ONLY the provider's own output (untrusted), never the
        # deterministic findings that already went through aggregate().
        all_findings = [*report.findings, *clamp_ai_findings(ai_findings)]
        report = aggregate(all_findings, strict=config.strict)

    duration_ms = (time.monotonic() - start) * 1000.0
    metadata: dict[str, str | int] = {
        "files_scanned": len(diff_files),
        "vibeguard_version": _version(),
    }
    if too_large:
        metadata["diff_too_large"] = 1
    return ScanReport(
        findings=report.findings,
        verdict=report.verdict,
        duration_ms=round(duration_ms, 3),
        metadata=metadata,
    )


def _version() -> str:
    from vibeguard import __version__

    return __version__
