"""VibeGuard CLI.

Phase 1: `scan` is fully wired (diff source -> pipeline -> text formatter,
exit codes 0/1/2/3 per ARCHITECTURE §4). rules/hook/mcp remain stubs
(Phase 2/3). Bad usage exits 3 (argparse default 2, overridden per contract).
"""

from __future__ import annotations

import argparse
import re
import sys

from vibeguard import __version__
from vibeguard.analyzers.base import (
    Analyzer,
    ConfigError,
    RuleDef,
    load_builtin_rules,
)
from vibeguard.core.diff import (
    DiffError,
    DiffFile,
    DiffFileSource,
    DiffSource,
    GitCommit,
    GitStaged,
    GitWorktree,
    StdinSource,
)
from vibeguard.core.pipeline import ScanConfig, run_scan
from vibeguard.core.result import Finding
from vibeguard.formatters.text import format_text

# Exit codes (ARCHITECTURE §4, frozen contract).
EXIT_PASS = 0
EXIT_BLOCK = 1
EXIT_INTERNAL = 2
EXIT_USAGE = 3


class VibeGuardParser(argparse.ArgumentParser):
    """ArgumentParser that exits 3 (usage error) instead of argparse's default 2."""

    def error(self, message: str) -> None:  # type: ignore[override]
        self.print_usage(sys.stderr)
        self.exit(EXIT_USAGE, f"{self.prog}: error: {message}\n")


def build_parser() -> VibeGuardParser:
    parser = VibeGuardParser(
        prog="vibeguard",
        description="Local-first safety layer that reviews diffs before they land.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    sub = parser.add_subparsers(dest="command", metavar="<command>")

    # ---- scan ----
    scan_p = sub.add_parser("scan", help="scan a diff")
    scan_p.add_argument("--staged", action="store_true", help="scan staged changes")
    scan_p.add_argument("--worktree", action="store_true", help="scan worktree changes")
    scan_p.add_argument("--commit", metavar="SHA", default=None, help="scan a commit")
    scan_p.add_argument("--diff-file", metavar="F", default=None, help="scan a diff file")
    scan_p.add_argument(
        "stdin_marker",
        nargs="?",
        default=None,
        help="use '-' to read diff from stdin",
    )
    scan_p.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="output format (default: text)",
    )
    scan_p.add_argument("--strict", action="store_true", help="warns also block")
    scan_p.add_argument("--config", metavar="PATH", default=None, help="config file path")
    scan_p.add_argument("--only", nargs="+", metavar="RULE_ID", default=None)
    scan_p.add_argument("--skip", nargs="+", metavar="RULE_ID", default=None)
    scan_p.add_argument("--max-findings", metavar="N", type=int, default=None)
    scan_p.set_defaults(func=_cmd_scan)

    # ---- rules ----
    rules_p = sub.add_parser("rules", help="list rules")
    rules_sub = rules_p.add_subparsers(dest="rules_command", metavar="<subcommand>")
    rules_list_p = rules_sub.add_parser("list", help="list rules")
    rules_list_p.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
    )
    rules_list_p.set_defaults(func=_cmd_rules_list)
    rules_p.set_defaults(func=_cmd_rules_missing)

    # ---- hook ----
    hook_p = sub.add_parser("hook", help="manage git hook")
    hook_sub = hook_p.add_subparsers(dest="hook_command", metavar="<subcommand>")
    hook_install_p = hook_sub.add_parser("install", help="install pre-commit hook")
    hook_install_p.set_defaults(func=_cmd_hook_install)
    hook_uninstall_p = hook_sub.add_parser("uninstall", help="uninstall pre-commit hook")
    hook_uninstall_p.set_defaults(func=_cmd_hook_uninstall)
    hook_p.set_defaults(func=_cmd_hook_missing)

    # ---- mcp ----
    mcp_p = sub.add_parser("mcp", help="MCP server (optional extra)")
    mcp_sub = mcp_p.add_subparsers(dest="mcp_command", metavar="<subcommand>")
    mcp_serve_p = mcp_sub.add_parser("serve", help="serve MCP over stdio")
    mcp_serve_p.set_defaults(func=_cmd_mcp_serve)
    mcp_p.set_defaults(func=_cmd_mcp_missing)

    return parser


# ------------------------------------------------------------ rule analyzer


class RuleAnalyzer:
    """Data-driven analyzer over rule definitions (line + path scope).

    Phase 1 ships this generic engine so the seed rules in
    rules/builtins.toml run end-to-end; Phase 2 adds the full rule set and
    the dedicated analyzer modules (secrets.py, sensitive_paths.py,
    dangerous_cmd.py) on top of the same contracts.
    """

    def __init__(self, rules: list[RuleDef]) -> None:
        self.id = "rules"
        self._rules = rules
        self._compiled = [(r, re.compile(r.pattern)) for r in rules]

    def analyze(self, files: list[DiffFile], config: object) -> list[Finding]:
        findings: list[Finding] = []
        for f in files:
            if f.binary:
                continue
            for rule, pattern in self._compiled:
                if rule.scope == "line":
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
                else:  # path scope
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


def _default_analyzers() -> list[Analyzer]:
    return [RuleAnalyzer(load_builtin_rules())]


# ------------------------------------------------------------ scan command


def _cmd_scan(args: argparse.Namespace) -> int:
    sources = [
        args.staged,
        args.worktree,
        args.commit is not None,
        args.diff_file is not None,
        args.stdin_marker == "-",
    ]
    if sum(sources) != 1:
        print(
            "vibeguard: error: exactly one of --staged, --worktree, --commit, "
            "--diff-file, or '-' is required",
            file=sys.stderr,
        )
        return EXIT_USAGE

    if args.staged:
        source: DiffSource = GitStaged()
    elif args.worktree:
        source = GitWorktree()
    elif args.commit is not None:
        source = GitCommit(args.commit)
    elif args.diff_file is not None:
        source = DiffFileSource(args.diff_file)
    else:
        source = StdinSource()

    diff_files = source.collect()

    if args.format == "json":
        print("vibeguard: error: --format json not implemented until Phase 2", file=sys.stderr)
        return EXIT_INTERNAL
    if args.only or args.skip or args.max_findings is not None:
        print(
            "vibeguard: error: --only/--skip/--max-findings not implemented until Phase 2",
            file=sys.stderr,
        )
        return EXIT_INTERNAL

    config = ScanConfig(strict=args.strict)
    analyzers = _default_analyzers()

    report = run_scan(diff_files, analyzers, None, config)

    print(format_text(report, use_color=None))

    if report.verdict.value == "block":
        return EXIT_BLOCK
    return EXIT_PASS


def _empty_report_text() -> str:
    return "no changes\nverdict: pass"


# ------------------------------------------------------------ stub commands


def _not_implemented(what: str) -> int:
    print(f"vibeguard: {what} not implemented (Phase 0 stub)", file=sys.stderr)
    return EXIT_INTERNAL


def _cmd_rules_list(args: argparse.Namespace) -> int:
    _ = args
    return _not_implemented("rules list")


def _cmd_rules_missing(args: argparse.Namespace) -> int:
    _ = args
    print("vibeguard: error: rules requires a subcommand (list)", file=sys.stderr)
    return EXIT_USAGE


def _cmd_hook_install(args: argparse.Namespace) -> int:
    _ = args
    return _not_implemented("hook install")


def _cmd_hook_uninstall(args: argparse.Namespace) -> int:
    _ = args
    return _not_implemented("hook uninstall")


def _cmd_hook_missing(args: argparse.Namespace) -> int:
    _ = args
    print("vibeguard: error: hook requires a subcommand (install|uninstall)", file=sys.stderr)
    return EXIT_USAGE


def _cmd_mcp_serve(args: argparse.Namespace) -> int:
    _ = args
    return _not_implemented("mcp serve")


def _cmd_mcp_missing(args: argparse.Namespace) -> int:
    _ = args
    print("vibeguard: error: mcp requires a subcommand (serve)", file=sys.stderr)
    return EXIT_USAGE


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        # argparse uses SystemExit for --help / --version / usage errors.
        # Normalize to an int return so `main()` honors the 0/3 contract.
        if isinstance(exc.code, int):
            return exc.code
        return 0 if exc.code is None else EXIT_INTERNAL
    if args.command is None:
        parser.print_usage(sys.stderr)
        return EXIT_USAGE
    func = getattr(args, "func", None)
    if func is None:
        parser.print_usage(sys.stderr)
        return EXIT_USAGE
    try:
        return int(func(args))
    except (DiffError, ConfigError) as exc:
        print(f"vibeguard: internal error: {exc}", file=sys.stderr)
        return EXIT_INTERNAL
    except Exception as exc:  # contract: internal errors -> exit 2
        print(f"vibeguard: internal error: {exc}", file=sys.stderr)
        return EXIT_INTERNAL


if __name__ == "__main__":
    raise SystemExit(main())
