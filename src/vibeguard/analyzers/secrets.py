"""Secrets analyzer (TASKS.md P2.1): credential patterns on ADDED lines only.

Owns every ``secret.*`` rule in ``rules/builtins.toml`` (including the Phase-1
seed ``secret.aws-access-key``). Line scope only: binary files carry no added
lines to analyze, so they are skipped. Removed lines are never visible here —
``DiffFile`` only carries added lines, which is what makes the
added-lines-only invariant structural rather than conventional.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from vibeguard.analyzers.base import RuleDef, load_builtin_rules

if TYPE_CHECKING:
    from vibeguard.core.diff import DiffFile
    from vibeguard.core.result import Finding


PREFIX = "secret."
ANALYZER_ID = "secrets"


class SecretsAnalyzer:
    """Detect committed credentials (AWS keys, tokens, private keys, JWTs)."""

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
