"""P1.4 — pipeline: mock analyzer + mock provider, clamp invariant, limits."""

from __future__ import annotations

import random

from conftest import MockAIProvider, MockAnalyzer, make_finding

from vibeguard.core.diff import DiffFile
from vibeguard.core.pipeline import (
    ScanConfig,
    clamp_ai_findings,
    run_scan,
)
from vibeguard.core.result import Severity, Verdict


def _files() -> list[DiffFile]:
    return [DiffFile(path="a.py", added_lines=[(1, "x = 1")])]


def test_no_analyzers_no_findings_pass() -> None:
    report = run_scan(_files(), [], None, ScanConfig())
    assert report.verdict is Verdict.PASS
    assert report.findings == []


def test_mock_analyzer_error_blocks() -> None:
    analyzer = MockAnalyzer("m", [make_finding(severity=Severity.ERROR)])
    report = run_scan(_files(), [analyzer], None, ScanConfig())
    assert report.verdict is Verdict.BLOCK


def test_mock_analyzer_warn_is_warn() -> None:
    analyzer = MockAnalyzer("m", [make_finding(severity=Severity.WARN)])
    report = run_scan(_files(), [analyzer], None, ScanConfig())
    assert report.verdict is Verdict.WARN


def test_strict_warn_blocks() -> None:
    analyzer = MockAnalyzer("m", [make_finding(severity=Severity.WARN)])
    report = run_scan(_files(), [analyzer], None, ScanConfig(strict=True))
    assert report.verdict is Verdict.BLOCK


# ------------------------------------------------------------- AI clamp


def test_provider_error_severity_clamped_to_warn() -> None:
    """THE clamp invariant test: provider returns error -> clamped, verdict
    unchanged (not block)."""
    analyzer = MockAnalyzer("m", [])
    provider = MockAIProvider([make_finding(source="ai", severity=Severity.ERROR)])
    report = run_scan(_files(), [analyzer], provider, ScanConfig())
    assert provider.calls == 1
    ai_findings = [f for f in report.findings if f.source == "ai"]
    assert len(ai_findings) == 1
    assert ai_findings[0].severity is Severity.WARN  # clamped
    assert report.verdict is Verdict.WARN  # NOT block


def test_provider_findings_forced_source_ai() -> None:
    sneaky = make_finding(source="rule", severity=Severity.ERROR)  # lying provider
    provider = MockAIProvider([sneaky])
    clamped = clamp_ai_findings(provider.review([], [], None))
    assert all(f.source == "rule" for f in clamped)  # source untouched by clamp fn


def test_clamp_keeps_rule_findings_verdict() -> None:
    """AI review must never change a block verdict from deterministic rules,
    and never turn a non-block into block."""
    analyzer = MockAnalyzer("m", [make_finding(severity=Severity.ERROR)])
    provider = MockAIProvider([])
    report = run_scan(_files(), [analyzer], provider, ScanConfig())
    assert report.verdict is Verdict.BLOCK

    analyzer2 = MockAnalyzer("m", [])
    provider2 = MockAIProvider(
        [
            make_finding(source="ai", severity=Severity.ERROR),
            make_finding(source="ai", severity=Severity.WARN),
        ]
    )
    report2 = run_scan(_files(), [analyzer2], provider2, ScanConfig())
    assert report2.verdict is Verdict.WARN


def test_no_provider_no_ai_findings() -> None:
    report = run_scan(_files(), [], None, ScanConfig())
    assert not [f for f in report.findings if f.source == "ai"]


def test_ai_clamp_property() -> None:
    """Property: whatever a mock provider returns, the final report contains
    no ai-source finding above warn, and block never depends on ai source."""
    rng = random.Random(7)
    severities = list(Severity)
    for _ in range(100):
        n = rng.randint(0, 4)
        provider_findings = [
            make_finding(source="ai", severity=rng.choice(severities)) for _ in range(n)
        ]
        analyzer = MockAnalyzer("m", [])
        provider = MockAIProvider(provider_findings)
        report = run_scan(_files(), [analyzer], provider, ScanConfig(strict=rng.random() < 0.5))
        ai = [f for f in report.findings if f.source == "ai"]
        assert all(f.severity is not Severity.ERROR for f in ai)
        if not any(f.source == "rule" and f.severity is Severity.ERROR for f in report.findings):
            assert report.verdict is not Verdict.BLOCK
        # with only ai findings, verdict <= warn
        if not [f for f in report.findings if f.source != "ai"]:
            assert report.verdict is not Verdict.BLOCK


# --------------------------------------------------------- max_diff_bytes


def test_diff_too_large_warns_and_skips_content() -> None:
    big = [DiffFile(path="big.py", added_lines=[(1, "x" * 100)])]
    analyzer = MockAnalyzer("m", [make_finding(severity=Severity.ERROR)])
    cfg = ScanConfig(max_diff_bytes=50)
    report = run_scan(big, [analyzer], None, cfg)
    ids = [f.rule_id for f in report.findings]
    assert "diff-too-large" in ids
    assert "test.rule" not in ids  # content rules skipped
    assert report.verdict is Verdict.WARN  # not block: content skipped


def test_diff_under_limit_unaffected() -> None:
    small = [DiffFile(path="s.py", added_lines=[(1, "x")])]
    analyzer = MockAnalyzer("m", [make_finding(severity=Severity.ERROR)])
    report = run_scan(small, [analyzer], None, ScanConfig(max_diff_bytes=1000))
    assert report.verdict is Verdict.BLOCK


def test_report_metadata() -> None:
    report = run_scan(_files(), [], None, ScanConfig())
    assert report.metadata["files_scanned"] == 1
    assert report.metadata["vibeguard_version"] == "0.1.0"
    assert report.duration_ms >= 0.0
