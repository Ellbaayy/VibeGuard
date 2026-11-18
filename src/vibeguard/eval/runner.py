"""Eval runner: measure the analyzers against the labelled dataset.

Rule-level metrics (the ones that matter for a detector):

    TP = expected rule ids that fired
    FN = expected rule ids that did not fire
    FP = rule ids that fired but were not expected

    precision = TP / (TP + FP)      how often a finding is real
    recall    = TP / (TP + FN)      how much of the truth is caught
    F1        = 2PR / (P + R)

Case-level pass means: every expected id fired AND nothing else did.
"""

from __future__ import annotations

from dataclasses import dataclass

from vibeguard.analyzers import Analyzer, default_analyzers
from vibeguard.core.diff import parse_unified_diff
from vibeguard.core.pipeline import ScanConfig, run_scan
from vibeguard.eval.cases import CASES, EvalCase


@dataclass(frozen=True)
class CaseResult:
    """Outcome for one labelled diff."""

    name: str
    category: str
    expected: frozenset[str]
    detected: frozenset[str]
    parsed_files: int
    verdict: str

    @property
    def missing(self) -> frozenset[str]:
        return self.expected - self.detected

    @property
    def unexpected(self) -> frozenset[str]:
        return self.detected - self.expected

    @property
    def passed(self) -> bool:
        return not self.missing and not self.unexpected and self.parsed_files > 0


@dataclass(frozen=True)
class EvalReport:
    """Aggregate metrics over the dataset."""

    cases: tuple[CaseResult, ...]
    tp: int
    fp: int
    fn: int
    precision: float
    recall: float
    f1: float

    @property
    def cases_passed(self) -> int:
        return sum(1 for c in self.cases if c.passed)

    @property
    def cases_total(self) -> int:
        return len(self.cases)

    def by_category(self) -> dict[str, tuple[int, int]]:
        """category -> (passed, total)."""
        out: dict[str, tuple[int, int]] = {}
        for case in self.cases:
            passed, total = out.get(case.category, (0, 0))
            out[case.category] = (passed + (1 if case.passed else 0), total + 1)
        return out


def _ratio(num: float, den: float) -> float:
    return num / den if den else 0.0


def run_eval(
    cases: list[EvalCase] | None = None,
    analyzers: list[Analyzer] | None = None,
    config: ScanConfig | None = None,
) -> EvalReport:
    """Run every case through the real scan pipeline and aggregate metrics."""
    dataset = CASES if cases is None else cases
    active = default_analyzers() if analyzers is None else analyzers
    scan_config = ScanConfig() if config is None else config

    results: list[CaseResult] = []
    tp = fp = fn = 0

    for case in dataset:
        files = parse_unified_diff(case.diff)
        report = run_scan(files, active, None, scan_config)
        detected = frozenset(f.rule_id for f in report.findings)
        result = CaseResult(
            name=case.name,
            category=case.category,
            expected=case.expect,
            detected=detected,
            parsed_files=len(files),
            verdict=report.verdict.value,
        )
        results.append(result)
        tp += len(result.expected & result.detected)
        fn += len(result.missing)
        fp += len(result.unexpected)

    precision = _ratio(tp, tp + fp)
    recall = _ratio(tp, tp + fn)
    f1 = _ratio(2 * precision * recall, precision + recall)

    return EvalReport(
        cases=tuple(results),
        tp=tp,
        fp=fp,
        fn=fn,
        precision=precision,
        recall=recall,
        f1=f1,
    )


def format_eval_text(report: EvalReport, verbose: bool = False) -> str:
    """Render the report as a table plus a summary."""
    lines: list[str] = []
    if verbose:
        lines.append(f"{'case':<44} {'cat':<14} {'result':<6} detail")
        for case in report.cases:
            status = "ok" if case.passed else "FAIL"
            detail = ""
            if case.parsed_files == 0:
                detail = "diff did not parse"
            elif case.missing:
                detail = f"missed: {', '.join(sorted(case.missing))}"
            elif case.unexpected:
                detail = f"false positive: {', '.join(sorted(case.unexpected))}"
            lines.append(f"{case.name:<44} {case.category:<14} {status:<6} {detail}")
        lines.append("")

    lines.append(f"cases:     {report.cases_passed}/{report.cases_total} passed")
    for category, (passed, total) in sorted(report.by_category().items()):
        lines.append(f"  {category:<14} {passed}/{total}")
    lines.append("")
    lines.append(f"tp={report.tp}  fp={report.fp}  fn={report.fn}")
    lines.append(f"precision: {report.precision:.3f}")
    lines.append(f"recall:    {report.recall:.3f}")
    lines.append(f"f1:        {report.f1:.3f}")
    return "\n".join(lines)
