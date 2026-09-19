"""VibeGuard CLI.

Phase 1: `scan` is fully wired (diff source -> pipeline -> text formatter,
exit codes 0/1/2/3 per ARCHITECTURE §4). rules/hook/mcp remain stubs
(Phase 2/3). Bad usage exits 3 (argparse default 2, overridden per contract).
"""

from __future__ import annotations

import argparse
import sys

from vibeguard import __version__
from vibeguard.analyzers import dangerous_cmd, secrets, sensitive_paths
from vibeguard.analyzers.base import (
    Analyzer,
    ConfigError,
    RuleAnalyzer,
    load_builtin_rules,
)
from vibeguard.core.diff import (
    DiffError,
    DiffFileSource,
    DiffSource,
    GitCommit,
    GitStaged,
    GitWorktree,
    StdinSource,
)
from vibeguard.core.pipeline import ScanConfig, run_scan
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


def _default_analyzers() -> list[Analyzer]:
    """The built-in analyzer set (Phase 2: dedicated modules + generic rest).

    P2.1 compatibility change: the dedicated analyzers claim their id-prefix
    subsets of builtins.toml; unclaimed rules (e.g. merge.*) keep running
    through the generic RuleAnalyzer, so Phase-1 behavior is preserved and no
    rule fires twice.
    """
    rules = load_builtin_rules()
    claimed = (secrets.PREFIX, sensitive_paths.PREFIX, dangerous_cmd.PREFIX)
    rest = [r for r in rules if not r.id.startswith(claimed)]
    return [
        secrets.SecretsAnalyzer(rules),
        sensitive_paths.SensitivePathsAnalyzer(rules),
        dangerous_cmd.DangerousCmdAnalyzer(rules),
        RuleAnalyzer(rest),
    ]


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
    if args.config is not None or args.only or args.skip or args.max_findings is not None:
        print(
            "vibeguard: error: --config/--only/--skip/--max-findings not implemented "
            "until Phase 2",
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
