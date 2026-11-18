"""Tests for the eval harness itself (not for the analyzers' accuracy).

The dataset's numbers are allowed to move; these tests pin the harness
contract: every diff parses, metrics are internally consistent, the CLI
emits valid JSON, and the CI gate returns the documented exit codes.
"""

from __future__ import annotations

import json

import pytest

from vibeguard.cli import EXIT_BLOCK, EXIT_PASS, main
from vibeguard.eval import CASES, run_eval
from vibeguard.eval.runner import format_eval_text


def test_dataset_shape() -> None:
    assert len(CASES) == 33
    categories = {c.category for c in CASES}
    assert categories == {"secret", "dangerous-cmd", "safe"}
    unsafe = [c for c in CASES if c.category != "safe"]
    assert len(unsafe) == 20
    assert all(c.expect for c in unsafe), "every unsafe case must name a rule"
    assert all(not c.expect for c in CASES if c.category == "safe")


def test_every_diff_parses() -> None:
    report = run_eval()
    unparsed = [c.name for c in report.cases if c.parsed_files == 0]
    assert unparsed == [], f"diffs that did not parse: {unparsed}"


def test_metrics_are_consistent_with_cases() -> None:
    report = run_eval()
    tp = sum(len(c.expected & c.detected) for c in report.cases)
    fn = sum(len(c.missing) for c in report.cases)
    fp = sum(len(c.unexpected) for c in report.cases)
    assert (report.tp, report.fn, report.fp) == (tp, fn, fp)
    assert report.cases_passed == sum(1 for c in report.cases if c.passed)
    assert 0.0 <= report.precision <= 1.0
    assert 0.0 <= report.recall <= 1.0
    assert 0.0 <= report.f1 <= 1.0


def test_recall_is_not_zero() -> None:
    """A detector that catches nothing must not look healthy."""
    report = run_eval()
    assert report.recall > 0.5
    assert report.tp > 0


def test_text_report_mentions_metrics() -> None:
    text = format_eval_text(run_eval(), verbose=True)
    assert "precision:" in text
    assert "recall:" in text
    assert "cases:" in text


def test_cli_json_output_is_valid(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["eval", "--format", "json"])
    assert code == EXIT_PASS
    payload = json.loads(capsys.readouterr().out)
    assert payload["cases_total"] == len(CASES)
    assert {"tp", "fp", "fn", "precision", "recall", "f1"} <= set(payload)
    assert len(payload["cases"]) == len(CASES)


def test_cli_gate_fails_below_threshold(capsys: pytest.CaptureFixture[str]) -> None:
    # 1.01 is unreachable, so the gate must trip regardless of current scores.
    code = main(["eval", "--min-precision", "1.01"])
    capsys.readouterr()
    assert code == EXIT_BLOCK


def test_cli_gate_passes_with_zero_threshold(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["eval", "--min-precision", "0", "--min-recall", "0"])
    capsys.readouterr()
    assert code == EXIT_PASS
