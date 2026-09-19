"""P1.2 — golden diff-parser tests over REAL `git diff` outputs.

Cases (TASKS.md): staged change, rename, deletion, binary file, empty diff,
CRLF file, merge-conflict markers surviving into added_lines.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from conftest import git

from vibeguard.core.diff import (
    DiffFileSource,
    GitCommit,
    GitStaged,
    GitWorktree,
    parse_unified_diff,
)


def _staged_diff(repo: Path) -> str:
    return git(repo, "diff", "--cached", "--no-color", "-M")


# ------------------------------------------------------------- staged change


def test_staged_modified_file(temp_repo: Path) -> None:
    (temp_repo / "app.py").write_text("a = 1\nb = 2\n")
    git(temp_repo, "add", "app.py")
    files = GitStaged(temp_repo).collect()
    assert len(files) == 1
    df = files[0]
    assert df.path == "app.py"
    assert df.binary is False
    assert df.added_lines == [(1, "a = 1"), (2, "b = 2")]


def test_staged_new_file_line_numbers(temp_repo: Path) -> None:
    (temp_repo / "new.txt").write_text("one\ntwo\n")
    git(temp_repo, "add", "new.txt")
    files = GitStaged(temp_repo).collect()
    assert files[0].added_lines == [(1, "one"), (2, "two")]


def test_staged_change_to_existing_file_line_numbers(temp_repo: Path) -> None:
    # Modify line 2 of README.md (context line 1 preserved) — added line
    # must carry the NEW line number (2), not the hunk offset.
    (temp_repo / "README.md").write_text("hello\nworld\n")
    git(temp_repo, "add", "README.md")
    files = GitStaged(temp_repo).collect()
    assert files[0].path == "README.md"
    assert files[0].added_lines == [(2, "world")]


# -------------------------------------------------------------------- rename


def test_rename_only(temp_repo: Path) -> None:
    git(temp_repo, "mv", "README.md", "RENAMED.md")
    files = GitStaged(temp_repo).collect()
    assert len(files) == 1
    df = files[0]
    assert df.path == "RENAMED.md"
    assert df.added_lines == []  # pure rename: nothing added
    assert df.binary is False


def test_rename_with_edit(temp_repo: Path) -> None:
    # Keep similarity above git's 50% default so the rename is detected
    # as one entry: most content identical, one line appended.
    git(temp_repo, "mv", "README.md", "RENAMED.md")
    (temp_repo / "RENAMED.md").write_text("hello\n")
    git(temp_repo, "add", "-A")
    git(temp_repo, "commit", "-q", "-m", "rename")  # commit so the edit below diffs
    (temp_repo / "RENAMED.md").write_text("hello\nplus new line\n")
    git(temp_repo, "add", "RENAMED.md")
    files = GitStaged(temp_repo).collect()
    assert len(files) == 1
    assert files[0].path == "RENAMED.md"
    texts = [t for _, t in files[0].added_lines]
    assert "plus new line" in texts


# ------------------------------------------------------------------ deletion


def test_deletion_no_added_lines(temp_repo: Path) -> None:
    git(temp_repo, "rm", "README.md")
    files = GitStaged(temp_repo).collect()
    assert len(files) == 1
    df = files[0]
    assert df.path == "README.md"
    assert df.added_lines == []
    assert df.binary is False


# -------------------------------------------------------------------- binary


def test_binary_file(temp_repo: Path) -> None:
    (temp_repo / "blob.bin").write_bytes(b"\x00\x01\x02\xff\xfe" * 20)
    git(temp_repo, "add", "blob.bin")
    files = GitStaged(temp_repo).collect()
    assert len(files) == 1
    df = files[0]
    assert df.path == "blob.bin"
    assert df.binary is True
    assert df.added_lines == []


# --------------------------------------------------------------- empty diff


def test_empty_diff(temp_repo: Path) -> None:
    assert GitStaged(temp_repo).collect() == []


def test_parse_empty_string() -> None:
    assert parse_unified_diff("") == []


# ---------------------------------------------------------------------- CRLF


def test_crlf_file(temp_repo: Path) -> None:
    (temp_repo / "crlf.txt").write_bytes(b"line1\r\nline2\r\n")
    git(temp_repo, "add", "crlf.txt")
    files = GitStaged(temp_repo).collect()
    df = files[0]
    assert df.path == "crlf.txt"
    # CR must not leak into the added-line text the analyzers see.
    assert df.added_lines == [(1, "line1"), (2, "line2")]


# ------------------------------------------------------ merge-conflict markers


def test_merge_conflict_markers_survive(temp_repo: Path) -> None:
    content = "clean\n<<<<<<< HEAD\nours\n=======\ntheirs\n>>>>>>> branch\nend\n"
    (temp_repo / "conflicted.txt").write_text(content)
    git(temp_repo, "add", "conflicted.txt")
    files = GitStaged(temp_repo).collect()
    texts = [t for _, t in files[0].added_lines]
    assert "<<<<<<< HEAD" in texts
    assert "=======" in texts
    assert ">>>>>>> branch" in texts


# ------------------------------------------------------- other source classes


def test_worktree_source(temp_repo: Path) -> None:
    # `git diff` (no --cached) shows tracked files only: modify a tracked file
    # WITHOUT staging it.
    (temp_repo / "README.md").write_text("hello\nx = 1\n")  # unstaged modification
    files = GitWorktree(temp_repo).collect()
    assert [f.path for f in files] == ["README.md"]
    texts = [t for _, t in files[0].added_lines]
    assert "x = 1" in texts


def test_commit_source_includes_root_commit(temp_repo: Path) -> None:
    files = GitCommit("HEAD", temp_repo).collect()
    assert [f.path for f in files] == ["README.md"]
    assert files[0].added_lines == [(1, "hello")]


def test_diff_file_source(tmp_path: Path) -> None:
    diff_text = (
        "diff --git a/x.py b/x.py\n"
        "new file mode 100644\n"
        "--- /dev/null\n"
        "+++ b/x.py\n"
        "@@ -0,0 +1,1 @@\n"
        "+key = 'AKIAABCDEFGHIJKLMNOP'\n"
    )
    p = tmp_path / "d.diff"
    p.write_text(diff_text)
    files = DiffFileSource(p).collect()
    assert files == [
        parse_unified_diff(diff_text)[0]
    ]
    assert files[0].path == "x.py"
    assert files[0].added_lines == [(1, "key = 'AKIAABCDEFGHIJKLMNOP'")]


def test_parse_non_utf8_replaced() -> None:
    # Caller decodes with errors="replace" before parsing; parser must not
    # crash on the resulting replacement chars.
    diff_text = (
        "diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -1,1 +1,1 @@\n"
        "-old\n+new \ufffd line\n"
    )
    files = parse_unified_diff(diff_text)
    assert files[0].added_lines == [(1, "new \ufffd line")]


def test_parse_dev_null_new_file() -> None:
    diff_text = (
        "diff --git a/newfile.py b/newfile.py\n"
        "new file mode 100644\n"
        "--- /dev/null\n"
        "+++ b/newfile.py\n"
        "@@ -0,0 +1,2 @@\n"
        "+a\n"
        "+b\n"
    )
    files = parse_unified_diff(diff_text)
    assert len(files) == 1
    assert files[0].path == "newfile.py"
    assert files[0].added_lines == [(1, "a"), (2, "b")]


def test_parse_quoted_path() -> None:
    diff_text = (
        'diff --git a/"we ird.py" b/"we ird.py"\n'
        '--- a/"we ird.py"\n'
        '+++ b/"we ird.py"\n'
        "@@ -1 +1 @@\n"
        "-a\n"
        "+b\n"
    )
    files = parse_unified_diff(diff_text)
    assert files[0].path == "we ird.py"


def test_parse_no_newline_marker() -> None:
    diff_text = (
        "diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -1 +1 @@\n"
        "-a\n"
        "+b\n"
        "\\ No newline at end of file\n"
    )
    files = parse_unified_diff(diff_text)
    assert files[0].added_lines == [(1, "b")]


# ------------------------------------------------- plain `diff -u` (no git)


def test_parse_plain_diff_u_without_git_headers() -> None:
    """Regression (QA P2): plain `diff -u` output has no `diff --git` header and
    appends a tab+timestamp to ---/+++ paths. It must NOT be silently ignored."""
    diff_text = (
        "--- a.txt\t2024-01-01 00:00:00.000000000 +0000\n"
        "+++ b.txt\t2024-01-01 00:00:00.000000000 +0000\n"
        "@@ -1,2 +1,3 @@\n"
        " context\n"
        "-old\n"
        "+new\n"
    )
    files = parse_unified_diff(diff_text)
    assert len(files) == 1
    assert files[0].path == "b.txt"
    assert files[0].added_lines == [(2, "new")]


def test_parse_plain_diff_u_no_timestamp() -> None:
    diff_text = (
        "--- a.txt\n"
        "+++ b.txt\n"
        "@@ -1 +1 @@\n"
        "-x\n"
        "+y\n"
    )
    files = parse_unified_diff(diff_text)
    assert len(files) == 1
    assert files[0].path == "b.txt"
    assert files[0].added_lines == [(1, "y")]


# ------------------------------------------------- quoted / non-ASCII paths


def test_parse_quoted_path_git_prefix_inside_quotes() -> None:
    """Regression (QA P2): git's REAL quoted form wraps the whole `b/...`
    segment in quotes. The `b/` prefix must be stripped, not retained."""
    diff_text = (
        'diff --git "a/we ird.py" "b/we ird.py"\n'
        '--- "a/we ird.py"\n'
        '+++ "b/we ird.py"\n'
        "@@ -1 +1 @@\n"
        "-a\n"
        "+b\n"
    )
    files = parse_unified_diff(diff_text)
    assert files[0].path == "we ird.py"


def test_parse_quoted_path_non_ascii_octal_escapes() -> None:
    """Regression (QA P2): git quotes non-ASCII path bytes as octal escapes
    (`\\303\\251` = 'é'). These must decode, not be left literal."""
    diff_text = (
        'diff --git "a/caf\\303\\251.py" "b/caf\\303\\251.py"\n'
        '--- "a/caf\\303\\251.py"\n'
        '+++ "b/caf\\303\\251.py"\n'
        "@@ -1 +1 @@\n"
        "-a\n"
        "+b\n"
    )
    files = parse_unified_diff(diff_text)
    assert files[0].path == "café.py"


def test_parse_quoted_path_retains_escaped_quote_and_backslash() -> None:
    diff_text = (
        'diff --git "a/x\\"y.py" "b/x\\"y.py"\n'
        '--- "a/x\\"y.py"\n'
        '+++ "b/x\\"y.py"\n'
        "@@ -1 +1 @@\n"
        "-a\n"
        "+b\n"
    )
    files = parse_unified_diff(diff_text)
    assert files[0].path == 'x"y.py'


def test_parse_normal_path_unaffected() -> None:
    diff_text = (
        "diff --git a/plain.py b/plain.py\n--- a/plain.py\n+++ b/plain.py\n"
        "@@ -1 +1 @@\n-a\n+b\n"
    )
    files = parse_unified_diff(diff_text)
    assert files[0].path == "plain.py"


# ------------------------------------------------- spoofed +++ inside hunk


def test_parse_spoofed_plusplusplus_inside_hunk_is_content() -> None:
    """Regression (QA P3): an added line that looks like `+++ ...` inside a hunk
    must be treated as content, NOT as a new file header (attribution)."""
    diff_text = (
        "diff --git a/real.py b/real.py\n"
        "--- a/real.py\n"
        "+++ b/real.py\n"
        "@@ -1 +1,2 @@\n"
        "-old\n"
        "+new\n"
        "+++ b/evil.py\n"
    )
    files = parse_unified_diff(diff_text)
    assert len(files) == 1  # not two files
    assert files[0].path == "real.py"
    texts = [t for _, t in files[0].added_lines]
    assert "++ b/evil.py" in texts


# ------------------------------------------------- stdin source (B2)


def test_stdin_source_none_stdin_raises_diff_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """Regression (B2): `sys.stdin` None must raise a clean DiffError, not a
    raw AttributeError."""
    import sys

    from vibeguard.core.diff import DiffError, StdinSource

    monkeypatch.setattr(sys, "stdin", None)
    with pytest.raises(DiffError, match="no stdin available"):
        StdinSource().collect()


def test_stdin_source_without_buffer_raises_diff_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Regression (B2): a stdin stream without a ``.buffer`` attribute (e.g. a
    closed/unavailable stream) must raise a clean DiffError."""
    import sys

    from vibeguard.core.diff import DiffError, StdinSource

    class NoBuffer:
        pass

    monkeypatch.setattr(sys, "stdin", NoBuffer())
    with pytest.raises(DiffError, match="no stdin available"):
        StdinSource().collect()


def test_stdin_source_reads_bytes_when_available(monkeypatch: pytest.MonkeyPatch) -> None:
    """Regression (B2): normal stdin with a buffer still works (non-regression
    for the existing successful path)."""
    import sys

    from vibeguard.core.diff import StdinSource

    class FakeBuffer:
        def __init__(self, data: bytes) -> None:
            self._data = data

        def read(self) -> bytes:
            return self._data

    class FakeStdin:
        def __init__(self, data: bytes) -> None:
            self.buffer = FakeBuffer(data)

    monkeypatch.setattr(
        sys,
        "stdin",
        FakeStdin(
            b"diff --git a/x.py b/x.py\n--- a/x.py\n+++ b/x.py\n@@ -1 +1 @@\n-old\n+new\n"
        ),
    )
    files = StdinSource().collect()
    assert [f.path for f in files] == ["x.py"]
    assert files[0].added_lines == [(1, "new")]


# ------------------------------------------------- malformed hunk header (B3)


def test_parse_malformed_hunk_header_does_not_crash() -> None:
    """Regression (B3): a hunk header that does not match the expected
    ``@@ -a,b +c,d @@`` shape must not crash the parser. The line is ignored
    (no hunk opens, so no added lines are recorded) — aligned with the current
    contract which only recognizes well-formed hunk headers."""
    diff_text = (
        "diff --git a/x.py b/x.py\n"
        "--- a/x.py\n"
        "+++ b/x.py\n"
        "@@ this is not a valid hunk header @@\n"
        "+should_not_be_treated_as_added\n"
    )
    files = parse_unified_diff(diff_text)
    assert len(files) == 1
    assert files[0].path == "x.py"
    # No valid hunk opened, so the '+' line is not recorded as an added line.
    assert files[0].added_lines == []


# ------------------------------------------------- removed-line lookalike (B4)


def test_parse_removed_line_minusminusminus_lookalike() -> None:
    """Regression (B4): a removed line whose content looks like `--- ...` must
    remain a removed line, not be mistaken for a file header. It must not
    create a phantom file entry nor enter added_lines."""
    diff_text = (
        "diff --git a/real.py b/real.py\n"
        "--- a/real.py\n"
        "+++ b/real.py\n"
        "@@ -1,2 +1,1 @@\n"
        " context\n"
        "---- removed content lookalike\n"
    )
    files = parse_unified_diff(diff_text)
    assert len(files) == 1
    assert files[0].path == "real.py"
    assert files[0].added_lines == []


def test_parse_removed_line_plusplusplus_lookalike() -> None:
    """Regression (B4): a removed line whose content looks like `+++ ...` must
    remain a removed line, not be mistaken for a file header."""
    diff_text = (
        "diff --git a/real.py b/real.py\n"
        "--- a/real.py\n"
        "+++ b/real.py\n"
        "@@ -1,2 +1,1 @@\n"
        " context\n"
        "-+++ removed content lookalike\n"
    )
    files = parse_unified_diff(diff_text)
    assert len(files) == 1
    assert files[0].path == "real.py"
    assert files[0].added_lines == []


# ------------------------------------- quoted/non-ASCII fixture from real git


def test_parse_quoted_path_from_real_git_output() -> None:
    """Lock the exact quoted-path shape real git emits (prefix inside quotes,
    octal escapes for non-ASCII bytes) with a literal golden fixture."""
    diff_text = (
        'diff --git "a/we ird caf\\303\\251.txt" "b/we ird caf\\303\\251.txt"\n'
        "new file mode 100644\n"
        "--- /dev/null\n"
        '+++ "b/we ird caf\\303\\251.txt"\n'
        "@@ -0,0 +1 @@\n"
        "+x\n"
    )
    files = parse_unified_diff(diff_text)
    assert len(files) == 1
    assert files[0].path == "we ird café.txt"
    assert files[0].added_lines == [(1, "x")]
