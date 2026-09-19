"""Shared test helpers: fake analyzers/providers, temp git repos."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from vibeguard.core.result import Finding, Severity


class MockAnalyzer:
    """Deterministic analyzer mock: returns canned findings."""

    def __init__(self, analyzer_id: str, findings: list[Finding]) -> None:
        self.id = analyzer_id
        self._findings = findings

    def analyze(self, files: list[object], config: object) -> list[Finding]:
        if not files:
            return []  # faithful to real analyzers: no input, no findings
        return list(self._findings)


class MockAIProvider:
    """AI provider mock: returns canned findings, records the call."""

    def __init__(self, findings: list[Finding]) -> None:
        self.name = "mock"
        self._findings = findings
        self.calls = 0

    def review(
        self,
        files: list[object],
        findings: list[Finding],
        config: object,
    ) -> list[Finding]:
        self.calls += 1
        return list(self._findings)


def make_finding(
    *,
    source: str = "rule",
    severity: Severity = Severity.WARN,
    rule_id: str = "test.rule",
) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity,
        file="a.py",
        line=1,
        message="msg",
        snippet="x",
        source=source,
    )


def git(cwd: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, f"git {args} failed: {proc.stderr}"
    return proc.stdout


@pytest.fixture()
def temp_repo(tmp_path: Path) -> Path:
    """A temp git repo with an initial clean commit."""
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-q")
    git(repo, "config", "user.email", "test@example.com")
    git(repo, "config", "user.name", "Test")
    (repo / "README.md").write_text("hello\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "init")
    return repo
