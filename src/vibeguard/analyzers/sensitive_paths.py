"""Sensitive-paths analyzer (TASKS.md P2.1): risky file paths, any content.

Owns every ``path.*`` rule in ``rules/builtins.toml`` (.env files, private
keys, credential files, .git internals, CI workflows). Path scope only, and
path rules run regardless of ``DiffFile.binary``: per ARCHITECTURE §8 a binary
diff skips *content* analysis but never *path* analysis — a committed
``.env`` or ``id_rsa`` is dangerous whatever bytes it holds.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from vibeguard.analyzers.base import RuleDef, load_builtin_rules

if TYPE_CHECKING:
    from vibeguard.core.diff import DiffFile
    from vibeguard.core.result import Finding


PREFIX = "path."
ANALYZER_ID = "sensitive-paths"


class SensitivePathsAnalyzer:
    """Flag sensitive file paths (.env, keys, credentials, .git, CI files)."""

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
            for rule, pattern in self._compiled:
                if rule.scope != "path":
                    continue
                # NOTE: no binary skip here — path analysis always runs.
                if pattern.search(f.path):
                    findings.append(
                        Finding(
                            rule_id=rule.id,
                            severity=rule.severity,
                            file=f.path,
                            line=None,
                            message=rule.message,
                            snippet="",
                            source="rule",
                        )
                    )
        return findings
