"""Deterministic analyzers (Phase 1: protocol, registry, rule loader)."""

from vibeguard.analyzers.base import (
    BUILTIN_RULES_PATH,
    Analyzer,
    ConfigError,
    Registry,
    RuleAnalyzer,
    RuleDef,
    load_builtin_rules,
    load_rules,
)
from vibeguard.analyzers.dangerous_cmd import PREFIX as CMD_PREFIX
from vibeguard.analyzers.dangerous_cmd import DangerousCmdAnalyzer
from vibeguard.analyzers.secrets import PREFIX as SECRET_PREFIX
from vibeguard.analyzers.secrets import SecretsAnalyzer
from vibeguard.analyzers.sensitive_paths import PREFIX as PATH_PREFIX
from vibeguard.analyzers.sensitive_paths import SensitivePathsAnalyzer


def default_analyzers() -> list[Analyzer]:
    """The built-in analyzer set: dedicated analyzers + the generic rest.

    The dedicated analyzers claim their id-prefix subsets of builtins.toml;
    unclaimed rules (e.g. merge.*) keep running through the generic
    RuleAnalyzer, so no rule fires twice and none is dropped.
    """
    rules = load_builtin_rules()
    claimed = (SECRET_PREFIX, PATH_PREFIX, CMD_PREFIX)
    rest = [r for r in rules if not r.id.startswith(claimed)]
    return [
        SecretsAnalyzer(rules),
        SensitivePathsAnalyzer(rules),
        DangerousCmdAnalyzer(rules),
        RuleAnalyzer(rest),
    ]


__all__ = [
    "BUILTIN_RULES_PATH",
    "Analyzer",
    "ConfigError",
    "DangerousCmdAnalyzer",
    "Registry",
    "RuleAnalyzer",
    "RuleDef",
    "SecretsAnalyzer",
    "SensitivePathsAnalyzer",
    "default_analyzers",
    "load_builtin_rules",
    "load_rules",
]
