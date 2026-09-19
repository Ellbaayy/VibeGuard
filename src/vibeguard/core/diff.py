"""Unified-diff parsing and diff sources (ARCHITECTURE §5/§6).

- DiffFile dataclass (frozen). `binary` is a Phase-1 contract amendment
  recorded in TASKS.md P1.2.
- DiffSource protocol + implementations: GitStaged / GitWorktree /
  GitCommit (subprocess git, run with `-C <repo root>`), DiffFileSource,
  StdinSource.
- parse_unified_diff: our own minimal parser (stdlib only) — file entries,
  added-line extraction, renames, deletions, binary markers, /dev/null
  paths, CRLF, non-UTF-8 handled by callers via errors="replace".
"""

from __future__ import annotations

import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol


@dataclass(frozen=True)
class DiffFile:
    """One file inside a unified diff.

    added_lines: (new_line_number, text) for every '+' line in the diff.
    binary: True when git reported "Binary files ... differ" (no added lines).
    """

    path: str
    added_lines: list[tuple[int, str]]
    binary: bool = False


class DiffSource(Protocol):
    def collect(self) -> list[DiffFile]: ...


class DiffError(Exception):
    """Diff collection failure. Maps to exit code 2 (internal error)."""


# ---------------------------------------------------------------- parser

_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")
_BINARY_RE = re.compile(r"^Binary files (.*?) and (.*) differ$")


def _unquote(token: str) -> str:
    """Unquote a C-style quoted diff path (git quotes unusual filenames)."""
    if len(token) >= 2 and token.startswith('"') and token.endswith('"'):
        return (
            token[1:-1]
            .replace("\\\\", "\\")
            .replace('\\"', '"')
            .replace("\\n", "\n")
            .replace("\\t", "\t")
        )
    return token


def _clean_path(token: str) -> str | None:
    """Normalize a diff path token: /dev/null -> None, strip a/ b/ prefixes."""
    token = token.strip()
    if token == "/dev/null":
        return None
    if token.startswith("a/") or token.startswith("b/"):
        token = token[2:]
    return _unquote(token) or None


def _header_paths(rest: str) -> tuple[str | None, str | None]:
    """Fallback path extraction from the 'diff --git a/x b/x' header line.

    Only used when ---/+++/rename lines are absent (e.g. mode-only changes).
    """
    if " b/" in rest:
        old, new = rest.split(" b/", 1)
        return _clean_path(old), _clean_path("b/" + new)
    return None, None


class _Entry:
    """Accumulator for one file entry while parsing."""

    def __init__(self) -> None:
        self.old: str | None = None
        self.new: str | None = None
        self.header: tuple[str | None, str | None] = (None, None)
        self.binary = False
        self.added: list[tuple[int, str]] = []
        self.lineno = 0
        self.in_hunk = False

    def diff_file(self) -> DiffFile | None:
        path = self.new or self.old or self.header[1] or self.header[0]
        if path is None:
            return None
        return DiffFile(path=path, added_lines=self.added, binary=self.binary)


def parse_unified_diff(text: str) -> list[DiffFile]:
    """Parse a unified diff into a list of DiffFile (pure function).

    Handles: new files, modified files, renames, deletions (no added lines),
    binary markers, /dev/null paths, CRLF line endings (trailing CR stripped
    from added-line text), and hunk no-newline-at-eof markers.
    """
    files: list[DiffFile] = []
    entry: _Entry | None = None

    def finalize(current: _Entry) -> None:
        df = current.diff_file()
        if df is not None:
            files.append(df)

    for raw in text.split("\n"):
        line = raw[:-1] if raw.endswith("\r") else raw
        if line.startswith("diff --git "):
            if entry is not None:
                finalize(entry)
            entry = _Entry()
            entry.header = _header_paths(line[len("diff --git ") :])
            continue
        if entry is None:
            continue  # preamble (e.g. commit message) — ignore
        if line.startswith("--- "):
            entry.old = _clean_path(line[4:])
        elif line.startswith("+++ "):
            entry.new = _clean_path(line[4:])
        elif line.startswith("rename from "):
            entry.old = line[len("rename from ") :]
        elif line.startswith("rename to "):
            entry.new = line[len("rename to ") :]
        elif line.startswith("Binary files ") and line.endswith(" differ"):
            match = _BINARY_RE.match(line)
            if match:
                entry.binary = True
                entry.old = entry.old or _clean_path(match.group(1))
                entry.new = entry.new or _clean_path(match.group(2))
        elif line.startswith("@@"):
            match = _HUNK_RE.match(line)
            if match:
                entry.in_hunk = True
                entry.lineno = int(match.group(1))
        elif not entry.in_hunk:
            continue
        elif line.startswith("+"):
            entry.added.append((entry.lineno, line[1:]))
            entry.lineno += 1
        elif line.startswith("-"):
            pass  # removed line
        elif line.startswith("\\"):
            pass  # "\ No newline at end of file"
        else:
            entry.lineno += 1  # context line

    if entry is not None:
        finalize(entry)
    return files


# ---------------------------------------------------------------- sources


def _run_git(args: list[str], cwd: Path | None = None) -> str:
    try:
        proc = subprocess.run(["git", *args], capture_output=True, cwd=cwd)
    except OSError as exc:
        raise DiffError(f"failed to run git: {exc}") from exc
    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", errors="replace").strip()
        raise DiffError(f"git {' '.join(args)} failed: {err or proc.returncode}")
    return proc.stdout.decode("utf-8", errors="replace")


def _repo_root(cwd: Path | None = None) -> Path:
    out = _run_git(["rev-parse", "--show-toplevel"], cwd)
    lines = out.strip().splitlines()
    if not lines or not lines[-1]:
        raise DiffError("could not determine repository root")
    return Path(lines[-1])


class GitStaged:
    """Staged changes: `git diff --cached` (index vs HEAD)."""

    def __init__(self, cwd: Path | None = None) -> None:
        self._cwd = cwd

    def collect(self) -> list[DiffFile]:
        root = _repo_root(self._cwd)
        text = _run_git(["-C", str(root), "diff", "--cached", "--no-color", "-M"])
        return parse_unified_diff(text)


class GitWorktree:
    """Unstaged worktree changes: `git diff` (worktree vs index)."""

    def __init__(self, cwd: Path | None = None) -> None:
        self._cwd = cwd

    def collect(self) -> list[DiffFile]:
        root = _repo_root(self._cwd)
        text = _run_git(["-C", str(root), "diff", "--no-color", "-M"])
        return parse_unified_diff(text)


class GitCommit:
    """One commit's diff: `git show --format= <sha>` (works for root commits)."""

    def __init__(self, sha: str, cwd: Path | None = None) -> None:
        self._sha = sha
        self._cwd = cwd

    def collect(self) -> list[DiffFile]:
        root = _repo_root(self._cwd)
        text = _run_git(["-C", str(root), "show", "--format=", "--no-color", "-M", self._sha])
        return parse_unified_diff(text)


class DiffFileSource:
    """Read a unified diff from a file on disk (--diff-file F)."""

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)

    def collect(self) -> list[DiffFile]:
        try:
            data = self._path.read_bytes()
        except OSError as exc:
            raise DiffError(f"cannot read diff file {self._path}: {exc}") from exc
        return parse_unified_diff(data.decode("utf-8", errors="replace"))


class StdinSource:
    """Read a unified diff from stdin (`vibeguard scan -`)."""

    def collect(self) -> list[DiffFile]:
        return parse_unified_diff(sys.stdin.read())
