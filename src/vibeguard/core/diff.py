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
    """Unquote a C-style quoted diff path (git quotes unusual filenames).

    Handles the full git escape set: ``\\\\`` -> ``\\``, ``\\"`` -> ``"``,
    ``\\n``/``\\t``/``\\r`` control escapes, and octal byte escapes
    (``\\303\\251`` -> ``é``) which git emits for non-ASCII path bytes.
    The inner text is decoded byte-by-byte and re-decoded as UTF-8 so that
    multi-byte octal sequences form correct characters.
    """
    if not (len(token) >= 2 and token.startswith('"') and token.endswith('"')):
        return token
    inner = token[1:-1]
    out = bytearray()
    i = 0
    n = len(inner)
    while i < n:
        ch = inner[i]
        if ch != "\\" or i + 1 >= n:
            out.extend(ch.encode("utf-8", errors="replace"))
            i += 1
            continue
        nxt = inner[i + 1]
        if nxt == "\\":
            out.extend(b"\\")
            i += 2
        elif nxt == '"':
            out.extend(b'"')
            i += 2
        elif nxt == "n":
            out.extend(b"\n")
            i += 2
        elif nxt == "t":
            out.extend(b"\t")
            i += 2
        elif nxt == "r":
            out.extend(b"\r")
            i += 2
        elif nxt in "01234567" and i + 4 <= n and all(
            c in "01234567" for c in inner[i + 1 : i + 4]
        ):
            out.append(int(inner[i + 1 : i + 4], 8))
            i += 4
        else:
            # Unknown escape: keep the backslash literally.
            out.extend(b"\\")
            i += 1
    return out.decode("utf-8", errors="replace")


def _clean_path(token: str) -> str | None:
    """Normalize a diff path token: /dev/null -> None, strip a/ b/ prefixes.

    Handles BOTH quoting layouts git has emitted over time:
      - ``b/"we ird.py"``  (prefix outside the quotes)
      - ``"b/we ird.py"``  (prefix inside the quotes)
    by unquoting and prefix-stripping in two passes.
    """
    token = token.strip()
    if token == "/dev/null":
        return None
    token = _unquote(token)
    if token.startswith("a/") or token.startswith("b/"):
        token = token[2:]
    token = _unquote(token)
    return token or None


def _header_paths(rest: str) -> tuple[str | None, str | None]:
    """Fallback path extraction from the 'diff --git a/x b/x' header line.

    Only used when ---/+++/rename lines are absent (e.g. mode-only changes).
    Handles both unquoted and quoted paths.
    """
    m = re.match(r"^a/(.*?) b/(.*)$", rest)
    if m:
        return _clean_path("a/" + m.group(1)), _clean_path("b/" + m.group(2))
    # Quoted form: 'diff --git "a/x y" "b/x y"' — split on the ' ' boundary.
    m = re.match(r'^"(.*?)" "(.*)"$', rest)
    if m:
        return _clean_path('"' + m.group(1) + '"'), _clean_path('"' + m.group(2) + '"')
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


def _strip_ts(token: str) -> str:
    """Strip the tab + timestamp GNU diff appends to ``---``/``+++`` paths.

    Git also emits a trailing tab after quoted paths; cutting at the first tab
    normalizes both. (Raw tabs inside a path are quoted by git, so this split
    never corrupts a real filename.)
    """
    return token.split("\t", 1)[0]


def parse_unified_diff(text: str) -> list[DiffFile]:
    """Parse a unified diff into a list of DiffFile (pure function).

    Handles: new files, modified files, renames, deletions (no added lines),
    binary markers, /dev/null paths, CRLF line endings, hunk no-newline-at-eof
    markers, plain ``diff -u`` output without git headers (used by the future
    MCP review_diff), and quoted/non-ASCII git paths.

    A ``--- ``/``+++ `` PAIR is a file header; a lone ``+++ ``/``--- `` inside a
    hunk is content (this prevents an added line that looks like ``+++ ...``
    from being mis-attributed as a new file header).
    """
    files: list[DiffFile] = []
    entry: _Entry | None = None
    lines = text.split("\n")

    def finalize(current: _Entry) -> None:
        df = current.diff_file()
        if df is not None:
            files.append(df)

    i = 0
    n = len(lines)
    while i < n:
        raw = lines[i]
        line = raw[:-1] if raw.endswith("\r") else raw

        if line.startswith("diff --git "):
            if entry is not None:
                finalize(entry)
            entry = _Entry()
            entry.header = _header_paths(line[len("diff --git ") :])
            i += 1
            continue

        # A `--- `/`+++ ` pair is a file header (git content changes AND plain
        # `diff -u` which has no `diff --git` line).
        if (
            line.startswith("--- ")
            and i + 1 < n
            and lines[i + 1].lstrip("\r").startswith("+++ ")
        ):
            if entry is not None and (entry.old is not None or entry.new is not None):
                finalize(entry)  # previous file (plain diff -u multi-file)
                entry = None
            if entry is None:
                entry = _Entry()
            entry.old = _clean_path(_strip_ts(line[4:]))
            entry.new = _clean_path(_strip_ts(lines[i + 1].lstrip("\r")[4:]))
            i += 2
            continue

        if entry is None:
            i += 1  # preamble (e.g. commit message) — ignore
            continue

        if entry.in_hunk:
            if line.startswith("@@"):
                match = _HUNK_RE.match(line)
                if match:
                    entry.lineno = int(match.group(1))
            elif line.startswith("+"):
                entry.added.append((entry.lineno, line[1:]))
                entry.lineno += 1
            elif line.startswith("-"):
                pass  # removed line
            elif line.startswith("\\"):
                pass  # "\ No newline at end of file"
            else:
                entry.lineno += 1  # context line
            i += 1
            continue

        # Not in a hunk: file metadata / headers.
        if line.startswith("--- "):
            entry.old = _clean_path(_strip_ts(line[4:]))
        elif line.startswith("+++ "):
            entry.new = _clean_path(_strip_ts(line[4:]))
        elif line.startswith("rename from "):
            entry.old = _unquote(line[len("rename from ") :].strip())
        elif line.startswith("rename to "):
            entry.new = _unquote(line[len("rename to ") :].strip())
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
        # else: index/mode/similarity lines — ignored.
        i += 1

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
    """Read a unified diff from stdin (`vibeguard scan -`).

    Reads raw bytes and decodes with ``errors="replace"`` so non-UTF-8 input
    never crashes (ARCHITECTURE §8) — mirroring DiffFileSource's behavior.
    Raises a clean DiffError when stdin is unavailable (e.g. closed or
    redirected from a non-tty without data) instead of leaking a Python
    AttributeError.
    """

    def collect(self) -> list[DiffFile]:
        stream = sys.stdin
        if stream is None or getattr(stream, "buffer", None) is None:
            raise DiffError("no stdin available")
        data = stream.buffer.read()
        return parse_unified_diff(data.decode("utf-8", errors="replace"))
