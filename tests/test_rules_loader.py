"""P1.3 — rules loader: valid file, invalid regex, unknown severity/keys."""

from __future__ import annotations

from pathlib import Path

import pytest
from conftest import MockAnalyzer

from vibeguard.analyzers.base import (
    ConfigError,
    Registry,
    RuleAnalyzer,
    RuleDef,
    load_builtin_rules,
    load_rules,
)
from vibeguard.core.diff import DiffFile
from vibeguard.core.result import Severity

VALID = """
[[rule]]
id = "test.ok"
severity = "warn"
pattern = "foo"
message = "found foo"
scope = "line"
"""


def _write(tmp_path: Path, text: str) -> Path:
    p = tmp_path / "rules.toml"
    p.write_text(text)
    return p


def test_load_valid_file(tmp_path: Path) -> None:
    rules = load_rules(_write(tmp_path, VALID))
    assert len(rules) == 1
    r = rules[0]
    assert r.id == "test.ok"
    assert r.severity.value == "warn"
    assert r.pattern == "foo"
    assert r.scope == "line"


def test_builtin_rules_load() -> None:
    rules = load_builtin_rules()
    ids = [r.id for r in rules]
    assert "secret.aws-access-key" in ids
    for r in rules:
        assert r.scope in ("line", "path")


def test_invalid_regex(tmp_path: Path) -> None:
    bad = VALID.replace('pattern = "foo"', 'pattern = "foo(["')
    with pytest.raises(ConfigError, match="invalid regex"):
        load_rules(_write(tmp_path, bad))


def test_unknown_severity(tmp_path: Path) -> None:
    bad = VALID.replace('severity = "warn"', 'severity = "fatal"')
    with pytest.raises(ConfigError, match="unknown severity"):
        load_rules(_write(tmp_path, bad))


def test_unknown_key(tmp_path: Path) -> None:
    bad = VALID + 'extra_key = "nope"\n'
    with pytest.raises(ConfigError, match="unknown rule key"):
        load_rules(_write(tmp_path, bad))


def test_missing_key(tmp_path: Path) -> None:
    bad = VALID.replace('scope = "line"\n', "")
    with pytest.raises(ConfigError, match="missing rule key"):
        load_rules(_write(tmp_path, bad))


def test_unknown_scope(tmp_path: Path) -> None:
    bad = VALID.replace('scope = "line"', 'scope = "file"')
    with pytest.raises(ConfigError, match="unknown scope"):
        load_rules(_write(tmp_path, bad))


def test_duplicate_rule_id(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="duplicate rule id"):
        load_rules(_write(tmp_path, VALID + VALID))


def test_empty_file_ok(tmp_path: Path) -> None:
    assert load_rules(_write(tmp_path, "")) == []


def test_missing_file(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="cannot read"):
        load_rules(tmp_path / "nope.toml")


def test_invalid_toml(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="invalid TOML"):
        load_rules(_write(tmp_path, "this is [not toml"))


# ------------------------------------------------------------------ registry


def test_registry_register_and_lookup() -> None:
    reg = Registry()
    analyzer = MockAnalyzer("a1", [])
    reg.register(analyzer)
    assert reg["a1"] is analyzer


def test_registry_rejects_duplicate() -> None:
    reg = Registry()
    reg.register(MockAnalyzer("a1", []))
    try:
        reg.register(MockAnalyzer("a1", []))
    except ConfigError:
        return
    raise AssertionError("duplicate id should be rejected")


def test_registry_rejects_no_id() -> None:
    reg = Registry()
    try:
        reg.register(object())  # type: ignore[arg-type]
    except ConfigError:
        return
    raise AssertionError("analyzer without id should be rejected")


# ------------------------------------------------------------ RuleAnalyzer


def test_aws_key_boundaries_no_false_positive() -> None:
    """Regression (QA P2.1): `XXAKIA...` must NOT match — the pattern requires
    a non-alphanumeric boundary on BOTH sides, so an AWS key embedded in a
    longer identifier is not flagged."""
    from vibeguard.analyzers.base import RuleAnalyzer, load_builtin_rules
    from vibeguard.core.diff import DiffFile

    analyzer = RuleAnalyzer(load_builtin_rules())
    # 'AKIA' + 16 uppercase alnum inside a longer alphanumeric identifier.
    fp = DiffFile(path="a.py", added_lines=[(1, "const XXAKIAABCDEFGHIJKLMNOPYZ = 1")])
    findings = analyzer.analyze([fp], object())
    assert not [f for f in findings if f.rule_id == "secret.aws-access-key"]


def test_aws_key_boundaries_still_matches_real_key() -> None:
    """Regression: a standalone AWS key (proper 16-char suffix, non-alnum
    boundaries) still matches."""
    from vibeguard.analyzers.base import RuleAnalyzer, load_builtin_rules
    from vibeguard.core.diff import DiffFile

    analyzer = RuleAnalyzer(load_builtin_rules())
    df = DiffFile(path="a.py", added_lines=[(1, "key = 'AKIAABCDEFGHIJKLMNOP'")])
    findings = analyzer.analyze([df], object())
    assert any(f.rule_id == "secret.aws-access-key" for f in findings)


# ------------------------------------------------ binary files (B1 regression)


def _path_analyzer(*patterns: str) -> RuleAnalyzer:
    rules = [
        RuleDef(
            id=f"sensitive.path{i}",
            severity=Severity.WARN,
            pattern=p,
            message="sensitive path",
            scope="path",
        )
        for i, p in enumerate(patterns)
    ]
    return RuleAnalyzer(rules)


def test_binary_file_still_triggers_path_scope_rule() -> None:
    """Regression (B1): a binary file must still be evaluated by path-scope
    rules (ARCH §8 skips *content* analysis only, never path analysis)."""
    analyzer = _path_analyzer(r"(^|/)\.env$", r"id_rsa", r"\.pem$")
    for path in (".env", "secrets/id_rsa", "private.pem"):
        df = DiffFile(path=path, added_lines=[], binary=True)
        findings = analyzer.analyze([df], object())
        assert any(f.rule_id.startswith("sensitive.path") for f in findings), path


def test_binary_file_skips_line_content_analysis() -> None:
    """Regression (B1): binary files must NOT undergo line/content analysis —
    added lines (if any) are never scanned for line-scope rules."""
    secret = RuleDef(
        id="secret.leak",
        severity=Severity.ERROR,
        pattern="SECRET",
        message="leak",
        scope="line",
    )
    analyzer = RuleAnalyzer([secret])
    df = DiffFile(path="blob.bin", added_lines=[(1, "SECRET_VALUE")], binary=True)
    findings = analyzer.analyze([df], object())
    assert findings == []  # no line analysis for binary files
