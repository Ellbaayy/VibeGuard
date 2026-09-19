"""Analyzer protocol + registry, and the rules loader (TASKS.md P1.3)."""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from vibeguard.core.result import Severity

if TYPE_CHECKING:
    from vibeguard.core.diff import DiffFile
    from vibeguard.core.result import Finding


class ConfigError(Exception):
    """Invalid rules/config data. Maps to exit code 2 (internal error)."""


@dataclass(frozen=True)
class RuleDef:
    """One data-driven rule record from builtins.toml."""

    id: str
    severity: Severity
    pattern: str
    message: str
    scope: str  # "line" | "path"


@runtime_checkable
class Analyzer(Protocol):
    """Deterministic analyzer: DiffFiles + config in, Findings out."""

    id: str

    def analyze(self, files: list[DiffFile], config: object) -> list[Finding]: ...


class Registry(dict[str, Analyzer]):
    """Analyzer registry keyed by analyzer id."""

    def register(self, analyzer: Analyzer) -> None:
        key = getattr(analyzer, "id", None)
        if not isinstance(key, str) or not key:
            raise ConfigError(f"analyzer {analyzer!r} has no valid id")
        if key in self:
            raise ConfigError(f"duplicate analyzer id: {key}")
        self[key] = analyzer


RULE_KEYS = {"id", "severity", "pattern", "message", "scope"}
VALID_SEVERITIES = {s.value for s in Severity}
VALID_SCOPES = {"line", "path"}


def _validate_rule(record: object, where: str) -> RuleDef:
    if not isinstance(record, dict):
        raise ConfigError(f"{where}: rule must be a table, got {type(record).__name__}")
    unknown = set(record) - RULE_KEYS
    if unknown:
        raise ConfigError(f"{where}: unknown rule key(s): {sorted(unknown)}")
    missing = RULE_KEYS - set(record)
    if missing:
        raise ConfigError(f"{where}: missing rule key(s): {sorted(missing)}")

    rid = record["id"]
    if not isinstance(rid, str) or not rid:
        raise ConfigError(f"{where}: rule id must be a non-empty string")

    sev = record["severity"]
    if sev not in VALID_SEVERITIES:
        raise ConfigError(f"{where}: rule {rid}: unknown severity {sev!r}")

    scope = record["scope"]
    if scope not in VALID_SCOPES:
        raise ConfigError(f"{where}: rule {rid}: unknown scope {scope!r}")

    pattern = record["pattern"]
    if not isinstance(pattern, str) or not pattern:
        raise ConfigError(f"{where}: rule {rid}: pattern must be a non-empty string")
    try:
        re.compile(pattern)
    except re.error as exc:
        raise ConfigError(f"{where}: rule {rid}: invalid regex: {exc}") from exc

    message = record["message"]
    if not isinstance(message, str) or not message:
        raise ConfigError(f"{where}: rule {rid}: message must be a non-empty string")

    return RuleDef(
        id=rid,
        severity=Severity(sev),
        pattern=pattern,
        message=message,
        scope=scope,
    )


def load_rules(path: str | Path) -> list[RuleDef]:
    """Load and validate rule records from a TOML file (tomllib, stdlib)."""
    path = Path(path)
    try:
        with open(path, "rb") as fh:
            data = tomllib.load(fh)
    except OSError as exc:
        raise ConfigError(f"cannot read rules file {path}: {exc}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"invalid TOML in {path}: {exc}") from exc

    raw = data.get("rule")
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ConfigError(f"{path}: [[rule]] must be an array of tables")

    rules: list[RuleDef] = []
    seen: set[str] = set()
    for i, record in enumerate(raw):
        where = f"{path} rule[{i}]"
        rule = _validate_rule(record, where)
        if rule.id in seen:
            raise ConfigError(f"{where}: duplicate rule id {rule.id!r}")
        seen.add(rule.id)
        rules.append(rule)
    return rules


BUILTIN_RULES_PATH = Path(__file__).resolve().parent.parent / "rules" / "builtins.toml"


def load_builtin_rules() -> list[RuleDef]:
    """Load the shipped rules/builtins.toml (minimal Phase-1 seed set)."""
    return load_rules(BUILTIN_RULES_PATH)
