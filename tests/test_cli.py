"""CLI unit tests for main() return codes (Phase 0 + Phase 1 wiring)."""

from __future__ import annotations

from vibeguard import __version__
from vibeguard.cli import main


def test_version_matches_package() -> None:
    assert __version__ == "0.1.0"


def test_bare_invocation_exits_3() -> None:
    assert main([]) == 3


def test_scan_bogus_flag_exits_3() -> None:
    assert main(["scan", "--bogus"]) == 3


def test_scan_without_source_exits_3() -> None:
    assert main(["scan"]) == 3


def test_scan_two_sources_exits_3() -> None:
    assert main(["scan", "--staged", "--worktree"]) == 3


def test_rules_without_subcommand_exits_3() -> None:
    assert main(["rules"]) == 3


def test_hook_without_subcommand_exits_3() -> None:
    assert main(["hook"]) == 3


def test_mcp_without_subcommand_exits_3() -> None:
    assert main(["mcp"]) == 3


def test_scan_stdin_marker_only_accepted() -> None:
    # '-' alone is a valid source selection; parsing must not be a usage error
    rc = main(["scan", "-"])
    assert rc in (0, 1, 2)
