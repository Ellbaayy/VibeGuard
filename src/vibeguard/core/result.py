"""Finding / Verdict / ScanReport dataclasses and verdict aggregation.

Implements ARCHITECTURE §4 verdict rules exactly:
- block iff any finding with source="rule" and severity="error"
  (strict mode: also warn-severity rule findings)
- AI-source findings NEVER contribute to block (hard invariant).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(Enum):
    """Finding severity: info < warn < error."""

    INFO = "info"
    WARN = "warn"
    ERROR = "error"


class Verdict(Enum):
    """Final decision for a run: pass | warn | block."""

    PASS = "pass"
    WARN = "warn"
    BLOCK = "block"


@dataclass(frozen=True)
class Finding:
    """One detected issue (ARCHITECTURE §4)."""

    rule_id: str
    severity: Severity
    file: str
    line: int | None
    message: str
    snippet: str = ""
    source: str = "rule"  # "rule" | "ai"


@dataclass(frozen=True)
class ScanReport:
    """Result of one scan: findings + verdict + duration + metadata."""

    findings: list[Finding]
    verdict: Verdict
    duration_ms: float = 0.0
    metadata: dict[str, str | int] = field(default_factory=dict)


def aggregate(findings: list[Finding], strict: bool = False) -> ScanReport:
    """Aggregate findings into a ScanReport with the contract verdict.

    - block iff any non-AI finding at error severity
      (strict mode: also non-AI warn findings)
    - AI-source findings can never produce block, regardless of severity.
      Only source="ai" is exempt; any other source is treated as rule-like
      (defensive: a lying/unknown source cannot dodge the block contract).
    """
    blocking = any(
        f.source != "ai"
        and (f.severity is Severity.ERROR or (strict and f.severity is Severity.WARN))
        for f in findings
    )
    if blocking:
        verdict = Verdict.BLOCK
    elif any(f.severity in (Severity.WARN, Severity.ERROR) for f in findings):
        verdict = Verdict.WARN
    else:
        verdict = Verdict.PASS
    return ScanReport(findings=list(findings), verdict=verdict)
