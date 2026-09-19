"""P1.1 — result dataclasses + verdict aggregation matrix + AI invariant."""

from __future__ import annotations

import random

from conftest import make_finding

from vibeguard.core.result import (
    ScanReport,
    Severity,
    Verdict,
    aggregate,
)


def test_finding_is_frozen() -> None:
    f = make_finding()
    try:
        f.severity = Severity.ERROR  # type: ignore[misc]
    except Exception:
        return
    raise AssertionError("Finding should be frozen")


def test_scan_report_defaults() -> None:
    r = aggregate([], strict=False)
    assert isinstance(r, ScanReport)
    assert r.findings == []
    assert r.verdict is Verdict.PASS


# Full severity x source x strict matrix.
# (source, severity, strict) -> expected verdict
MATRIX: list[tuple[str, Severity, bool, Verdict]] = [
    # rule-source findings
    ("rule", Severity.INFO, False, Verdict.PASS),
    ("rule", Severity.WARN, False, Verdict.WARN),
    ("rule", Severity.ERROR, False, Verdict.BLOCK),
    ("rule", Severity.INFO, True, Verdict.PASS),
    ("rule", Severity.WARN, True, Verdict.BLOCK),  # strict: warn blocks
    ("rule", Severity.ERROR, True, Verdict.BLOCK),
    # ai-source findings: NEVER block, regardless of severity or strict
    ("ai", Severity.INFO, False, Verdict.PASS),
    ("ai", Severity.WARN, False, Verdict.WARN),
    ("ai", Severity.ERROR, False, Verdict.WARN),
    ("ai", Severity.INFO, True, Verdict.PASS),
    ("ai", Severity.WARN, True, Verdict.WARN),  # strict does not escalate ai
    ("ai", Severity.ERROR, True, Verdict.WARN),
]


def test_aggregation_matrix() -> None:
    for source, severity, strict, expected in MATRIX:
        findings = [make_finding(source=source, severity=severity)]
        report = aggregate(findings, strict=strict)
        assert report.verdict is expected, (
            f"source={source} severity={severity.value} strict={strict}: "
            f"expected {expected.value}, got {report.verdict.value}"
        )


def test_mixed_ai_error_plus_rule_info_is_not_block() -> None:
    findings = [
        make_finding(source="ai", severity=Severity.ERROR),
        make_finding(source="rule", severity=Severity.INFO),
    ]
    assert aggregate(findings, strict=False).verdict is Verdict.WARN


def test_rule_error_dominates_ai() -> None:
    findings = [
        make_finding(source="ai", severity=Severity.INFO),
        make_finding(source="rule", severity=Severity.ERROR),
    ]
    assert aggregate(findings, strict=False).verdict is Verdict.BLOCK


def test_unknown_source_treated_as_rule_for_blocking() -> None:
    # Only "ai" is exempt; anything else with error severity blocks.
    findings = [make_finding(source="other", severity=Severity.ERROR)]
    assert aggregate(findings, strict=False).verdict is Verdict.BLOCK


def test_ai_invariant_property() -> None:
    """Randomized property: ai-source findings never yield block.

    Whatever the severity mix, a report whose findings are ALL ai-source
    can never be block, strict or not. And adding ai findings to any
    rule-only set never flips the verdict from non-block to block.
    """
    rng = random.Random(42)
    severities = list(Severity)
    for _ in range(200):
        n = rng.randint(0, 5)
        findings = [
            make_finding(source="ai", severity=rng.choice(severities)) for _ in range(n)
        ]
        for strict in (False, True):
            report = aggregate(findings, strict=strict)
            assert report.verdict is not Verdict.BLOCK

        # adding ai findings never changes a non-block rule verdict to block
        rule_findings = [
            make_finding(source="rule", severity=rng.choice(severities)) for _ in range(n)
        ]
        base = aggregate(rule_findings, strict=False)
        if base.verdict is not Verdict.BLOCK:
            mixed = aggregate([*rule_findings, *findings], strict=False)
            assert mixed.verdict is not Verdict.BLOCK
