"""Dangerous-command analyzer (TASKS.md P2.1): risky shell on ADDED lines only.

Owns every ``cmd.*`` rule in ``rules/builtins.toml`` (curl|sh pipelines,
``rm -rf /``, fork bombs, chmod 777, sudo, ``git push --force``). Line scope
only: binary files carry no added lines to analyze, so they are skipped.
Severity is conservative per the Architect decision — when in doubt, warn —
except for commands that are destructive or remote-code-execution by
construction (curl|sh, rm -rf /, fork bomb), which block. ``cmd.curl-pipe-shell``
being error-severity is what lets the Phase-2 hook gate (TASKS.md P2.4) block
a commit containing ``curl ... | sh``.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from vibeguard.analyzers.base import RuleDef, load_builtin_rules

if TYPE_CHECKING:
    from vibeguard.core.diff import DiffFile
    from vibeguard.core.result import Finding


PREFIX = "cmd."
ANALYZER_ID = "dangerous-cmd"


class DangerousCmdAnalyzer:
    """Detect dangerous shell commands in added lines."""

    def __init__(self, rules: list[RuleDef] | None = None) -> None:
        self.id = ANALYZER_ID
        own = load_builtin_rules() if rules is None else rules
        self._compiled = [
            (rule, re.compile(rule.pattern)) for rule in own if rule.id.startswith(PREFIX)
        ]

    def analyze(self, files: list[DiffFile], config: object) -> list[Finding]:
        from vibeguard.core.result import Finding

        _ = config
        findings: list[Finding] = []
        for f in files:
            if f.binary:
                continue  # binary files have no added lines to analyze
            for rule, pattern in self._compiled:
                if rule.scope != "line":
                    continue
                for lineno, text in f.added_lines:
                    if pattern.search(text):
                        findings.append(
                            Finding(
                                rule_id=rule.id,
                                severity=rule.severity,
                                file=f.path,
                                line=lineno,
                                message=rule.message,
                                snippet=text,
                                source="rule",
                            )
                        )
        return findings
