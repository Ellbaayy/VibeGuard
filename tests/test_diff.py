"""P1.2 — golden diff-parser tests over REAL `git diff` outputs.

Cases (TASKS.md): staged change, rename, deletion, binary file, empty diff,
CRLF file, merge-conflict markers surviving into added_lines.
"""

from __future__ import annotations

from pathlib import Path

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
