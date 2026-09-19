"""P1.5 — text formatter unit tests (colors, empty report)."""

from __future__ import annotations

from conftest import make_finding

from vibeguard.core.result import Severity, aggregate


def test_format_empty_report_no_changes() -> None:
    from vibeguard.formatters.text import format_text

    report = aggregate([], strict=False)
    out = format_text(report, use_color=False)
    # no findings AND no diff files at all -> "no changes" (ARCHITECTURE §8)
    assert "no changes" in out or "no findings" in out
    assert "verdict: pass" in out


def test_format_empty_diff_prints_no_changes() -> None:
    from vibeguard.formatters.text import format_text

    report = aggregate([], strict=False)
    report = type(report)(
        findings=[],
        verdict=report.verdict,
        duration_ms=0.0,
        metadata={"files_scanned": 0},
    )
    out = format_text(report, use_color=False)
    assert "no changes" in out


def test_format_finding_contains_rule_id_and_location() -> None:
    from vibeguard.formatters.text import format_text

    finding = make_finding(rule_id="secret.aws-access-key")
    report = aggregate([finding], strict=False)
    out = format_text(report, use_color=False)
    assert "secret.aws-access-key" in out
    assert "a.py:1" in out
    assert "verdict: warn" in out


def test_format_no_ansi_when_disabled() -> None:
    from vibeguard.formatters.text import format_text

    report = aggregate([make_finding(severity=Severity.ERROR)], strict=False)
    assert "\033[" not in format_text(report, use_color=False)


def test_format_ansi_when_enabled() -> None:
    from vibeguard.formatters.text import format_text

    report = aggregate([make_finding(severity=Severity.ERROR)], strict=False)
    assert "\033[" in format_text(report, use_color=True)
