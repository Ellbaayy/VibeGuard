"""Human-readable text formatter (ARCHITECTURE §6 Formatter contract).

Colors only when stdout is a tty; plain text otherwise (CI/piped safe).
"""

from __future__ import annotations

import sys

from vibeguard.core.result import Finding, ScanReport, Severity, Verdict

_RESET = "\033[0m"
_RED = "\033[31m"
_YELLOW = "\033[33m"
_CYAN = "\033[36m"
_BOLD = "\033[1m"


def _color(use_color: bool, code: str, text: str) -> str:
    return f"{code}{text}{_RESET}" if use_color else text


def _severity_label(sev: Severity, use_color: bool) -> str:
    if sev is Severity.ERROR:
        return _color(use_color, _RED, "error")
    if sev is Severity.WARN:
        return _color(use_color, _YELLOW, "warn")
    return "info"


def format_finding(f: Finding, use_color: bool) -> str:
    loc = f"{f.file}:{f.line}" if f.line is not None else f.file
    src = "" if f.source == "rule" else f" [{f.source}]"
    return f"  {loc}: {_severity_label(f.severity, use_color)} {f.rule_id}{src}: {f.message}"


def format_text(report: ScanReport, use_color: bool | None = None) -> str:
    """Format a ScanReport as human-readable text.

    use_color: None = auto-detect via sys.stdout.isatty().
    """
    if use_color is None:
        use_color = sys.stdout.isatty()

    lines: list[str] = []
    if not report.findings:
        lines.append("no changes" if not report.metadata.get("files_scanned") else "no findings")
        lines.append(f"verdict: {report.verdict.value}")
        return "\n".join(lines)

    verdict_color = {_RED: Verdict.BLOCK, _YELLOW: Verdict.WARN, _CYAN: Verdict.PASS}
    code = next((c for c, v in verdict_color.items() if v is report.verdict), _CYAN)
    lines.append(_color(use_color, _BOLD, f"{len(report.findings)} finding(s):"))
    for f in report.findings:
        lines.append(format_finding(f, use_color))
    lines.append(f"verdict: {_color(use_color, code, report.verdict.value)}")
    return "\n".join(lines)
