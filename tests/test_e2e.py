"""Phase-1 gate e2e (TASKS.md P1.5): real CLI subprocess in a temp git repo.

- stage a file containing a fake AWS key -> `vibeguard scan --staged` exits 1,
  output contains the rule id.
- clean diff -> exit 0.
- `vibeguard scan --bogus` (real subprocess) exits 3.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest
from conftest import git

REPO_ROOT = Path(__file__).resolve().parent.parent


def _run_cli(args: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    # repo-local venv's console script if available, else module fallback
    venv_bin = REPO_ROOT / ".venv" / "bin"
    exe = venv_bin / "vibeguard"
    if exe.exists():
        return subprocess.run(
            [str(exe), *args], cwd=cwd, capture_output=True, text=True, env=env
        )
    env["PYTHONPATH"] = str(REPO_ROOT / "src")
    return subprocess.run(
        [sys.executable, "-m", "vibeguard.cli_check", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        env=env,
    )


@pytest.fixture(scope="module")
def cli(tmp_path_factory: pytest.TempPathFactory) -> dict[str, str]:
    """The vibeguard entry point as an absolute path (module fallback ok)."""
    exe = REPO_ROOT / ".venv" / "bin" / "vibeguard"
    if exe.exists():
        return {"argv0": str(exe)}
    # fallback: run via python -c against src/
    return {"argv0": ""}


def _scan(cwd: Path, *args: str) -> subprocess.CompletedProcess[str]:
    exe = REPO_ROOT / ".venv" / "bin" / "vibeguard"
    if exe.exists():
        argv = [str(exe), *args]
    else:
        argv = [
            sys.executable,
            "-c",
            "from vibeguard.cli import main; raise SystemExit(main())",
            *args,
        ]
    env = dict(os.environ)
    if not exe.exists():
        env["PYTHONPATH"] = str(REPO_ROOT / "src")
    return subprocess.run(argv, cwd=cwd, capture_output=True, text=True, env=env)


def test_e2e_staged_aws_key_blocks(temp_repo: Path) -> None:
    """THE Phase-1 gate: fake AWS key in staged file -> exit 1 + rule id."""
    (temp_repo / "deploy.py").write_text(
        "# config\nAWS_KEY = 'AKIAABCDEFGHIJKLMNOP'\nD = 2\n"
    )
    git(temp_repo, "add", "deploy.py")
    proc = _scan(temp_repo, "scan", "--staged")
    assert proc.returncode == 1, f"stdout={proc.stdout!r} stderr={proc.stderr!r}"
    assert "secret.aws-access-key" in proc.stdout
    assert "deploy.py" in proc.stdout


def test_e2e_clean_diff_exits_0(temp_repo: Path) -> None:
    (temp_repo / "fine.py").write_text("print('all good')\n")
    git(temp_repo, "add", "fine.py")
    proc = _scan(temp_repo, "scan", "--staged")
    assert proc.returncode == 0, f"stdout={proc.stdout!r} stderr={proc.stderr!r}"
    assert "no findings" in proc.stdout or "no changes" in proc.stdout


def test_e2e_empty_staged_exits_0_no_changes(temp_repo: Path) -> None:
    proc = _scan(temp_repo, "scan", "--staged")
    assert proc.returncode == 0
    assert "no changes" in proc.stdout


def test_e2e_bogus_flag_exits_3(temp_repo: Path) -> None:
    proc = _scan(temp_repo, "scan", "--bogus")
    assert proc.returncode == 3
    assert "usage" in proc.stderr.lower()


def test_e2e_no_source_selected_exits_3(temp_repo: Path) -> None:
    proc = _scan(temp_repo, "scan")
    assert proc.returncode == 3


def test_e2e_two_sources_exits_3(temp_repo: Path) -> None:
    proc = _scan(temp_repo, "scan", "--staged", "--worktree")
    assert proc.returncode == 3


def test_e2e_conflict_marker_warns_not_blocks(temp_repo: Path) -> None:
    (temp_repo / "c.txt").write_text("<<<<<<< HEAD\nours\n=======\ntheirs\n>>>>>>> b\n")
    git(temp_repo, "add", "c.txt")
    proc = _scan(temp_repo, "scan", "--staged")
    assert proc.returncode == 0  # warn severity -> exit 0 in non-strict mode
    assert "merge.conflict-marker" in proc.stdout


def test_e2e_strict_warn_blocks(temp_repo: Path) -> None:
    (temp_repo / "c.txt").write_text("<<<<<<< HEAD\nours\n=======\ntheirs\n>>>>>>> b\n")
    git(temp_repo, "add", "c.txt")
    proc = _scan(temp_repo, "scan", "--staged", "--strict")
    assert proc.returncode == 1
    assert "merge.conflict-marker" in proc.stdout


def test_e2e_worktree_scan(temp_repo: Path) -> None:
    # git diff (worktree) covers tracked files: modify README.md without staging
    (temp_repo / "README.md").write_text("hello\nk = 'AKIAABCDEFGHIJKLMNOP'\n")
    proc = _scan(temp_repo, "scan", "--worktree")
    assert proc.returncode == 1
    assert "secret.aws-access-key" in proc.stdout


def test_e2e_diff_file_scan(tmp_path: Path) -> None:
    diff_text = (
        "diff --git a/x.py b/x.py\n"
        "--- a/x.py\n+++ b/x.py\n@@ -1 +1 @@\n-old\n"
        "+AKIAABCDEFGHIJKLMNOP\n"
    )
    p = tmp_path / "d.diff"
    p.write_text(diff_text)
    proc = _scan(tmp_path, "scan", "--diff-file", str(p))
    assert proc.returncode == 1
    assert "secret.aws-access-key" in proc.stdout


def test_e2e_stdin_scan(temp_repo: Path) -> None:
    diff_text = (
        "diff --git a/y.py b/y.py\n--- a/y.py\n+++ b/y.py\n@@ -1 +1 @@\n-old\n+new\n"
    )
    exe = REPO_ROOT / ".venv" / "bin" / "vibeguard"
    if exe.exists():
        argv = [str(exe), "scan", "-"]
    else:
        argv = [
            sys.executable,
            "-c",
            "from vibeguard.cli import main; raise SystemExit(main())",
            "scan",
            "-",
        ]
    env = dict(os.environ)
    if not exe.exists():
        env["PYTHONPATH"] = str(REPO_ROOT / "src")
    proc = subprocess.run(
        argv,
        cwd=temp_repo,
        capture_output=True,
        text=True,
        env=env,
        input=diff_text,
    )
    assert proc.returncode == 0
    assert "no findings" in proc.stdout


def test_e2e_version() -> None:
    proc = _scan(REPO_ROOT, "--version")
    assert proc.returncode == 0
    assert "0.1.0" in proc.stdout


def test_e2e_git_error_exits_2(tmp_path: Path) -> None:
    not_a_repo = tmp_path / "plain"
    not_a_repo.mkdir()
    proc = _scan(not_a_repo, "scan", "--staged")
    assert proc.returncode == 2
    assert "internal error" in proc.stderr.lower()
