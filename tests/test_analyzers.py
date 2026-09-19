"""P2.1 — analyzers: table-driven tests incl. documented false-positive cases.

Conventions:
- Every rule ships with at least one positive case and one FP case.
- Line-scope rules only ever see ``DiffFile.added_lines`` (removed lines are
  not representable there — the invariant is structural, from the P1.2 parser).
- Path-scope rules run regardless of ``binary``; line-scope rules skip binary.
"""

from __future__ import annotations

import pytest

from vibeguard.analyzers.base import Registry, load_builtin_rules
from vibeguard.analyzers.dangerous_cmd import DangerousCmdAnalyzer
from vibeguard.analyzers.secrets import SecretsAnalyzer
from vibeguard.analyzers.sensitive_paths import SensitivePathsAnalyzer
from vibeguard.cli import _default_analyzers
from vibeguard.core.diff import DiffFile


def _file(path: str, *lines: str, binary: bool = False) -> DiffFile:
    return DiffFile(
        path=path,
        added_lines=[(i + 1, text) for i, text in enumerate(lines)],
        binary=binary,
    )


SECRETS = SecretsAnalyzer()
PATHS = SensitivePathsAnalyzer()
CMDS = DangerousCmdAnalyzer()


def _ids(analyzer: object, f: DiffFile) -> set[str]:
    assert hasattr(analyzer, "analyze")
    return {found.rule_id for found in analyzer.analyze([f], None)}  # type: ignore[union-attr]


# ---------------------------------------------------------------- secrets

SECRETS_CASES: list[tuple[str, set[str]]] = [
    # (added line, expected rule ids)
    ("AWS_KEY = 'AKIAABCDEFGHIJKLMNOP'", {"secret.aws-access-key"}),
    ("token = 'ghp_" + "A" * 36 + "'", {"secret.github-token"}),
    ("-----BEGIN RSA PRIVATE KEY-----", {"secret.private-key-block"}),
    ("-----BEGIN PRIVATE KEY-----", {"secret.private-key-block"}),
    (
        'auth = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM In0.SflKxwRJSMeKKF2QT"',
        set(),  # segments too short / spaces — not JWT-shaped
    ),
    (
        'auth = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'
        '.eyJzdWIiOiIxMjM0NTY3ODkwIn0'
        '.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c"',
        {"secret.jwt-token"},
    ),
    # Underscore-adjacent AKIA keys MUST match: `_` is not [A-Za-z0-9], so the
    # approved Phase 0+1 boundary treats it as a valid boundary (QA B2).
    ("secret_AKIAABCDEFGHIJKLMNOP", {"secret.aws-access-key"}),
    ("AKIAABCDEFGHIJKLMNOP_SUFFIX", {"secret.aws-access-key"}),
    ("_AKIAABCDEFGHIJKLMNOP", {"secret.aws-access-key"}),
    ("AKIAABCDEFGHIJKLMNOP_", {"secret.aws-access-key"}),
]

SECRETS_FP_CASES: list[str] = [
    "XAKIAABCDEFGHIJKLMNOP",  # key glued into a longer identifier — must NOT match
    "AKIASHORT",  # too short — must NOT match
    'token = "ghp_short"',  # placeholder, not a 40-char token
    "we use a private key for ssh access",  # prose, not a PEM block
    'version = "eyJabc"',  # too short to be a JWT
    "print('all good')",  # ordinary code
]


@pytest.mark.parametrize(("line", "expected"), SECRETS_CASES)
def test_secrets_positives(line: str, expected: set[str]) -> None:
    assert _ids(SECRETS, _file("app.py", line)) == expected


@pytest.mark.parametrize("line", SECRETS_FP_CASES)
def test_secrets_false_positives(line: str) -> None:
    assert _ids(SECRETS, _file("app.py", line)) == set()


def test_secrets_skips_binary_content() -> None:
    f = _file("k.py", "AKIAABCDEFGHIJKLMNOP", binary=True)
    assert _ids(SECRETS, f) == set()


# -------------------------------------------------------- sensitive paths

PATHS_CASES: list[tuple[str, set[str]]] = [
    (".env", {"path.dotenv-file"}),
    ("proj/.env.local", {"path.dotenv-file"}),
    ("a/.env.production", {"path.dotenv-file"}),
    ("config/id_rsa", {"path.private-key-file"}),
    ("certs/server.pem", {"path.private-key-file"}),
    ("a/b.key", {"path.private-key-file"}),
    ("config/credentials.json", {"path.credentials-file"}),
    ("secrets.yaml", {"path.credentials-file"}),
    (".git/hooks/pre-commit", {"path.git-internal"}),
    (".github/workflows/ci.yml", {"path.ci-workflow-file"}),
]

PATHS_FP_CASES: list[str] = [
    ".env.example",  # sample env files are committed legitimately
    ".env.sample",
    ".gitignore",  # every repo commits this — must NOT match .git-internal
    ".github/README.md",  # not a workflow file
    ".github/workflows/README.md",  # not a yaml workflow
    "docs/credentials-guide.md",  # prose about credentials
    "src/keyboard.py",  # merely contains "key"
    "id_rsa.pub",  # public key — safe to commit
    "deploy.py",
]


@pytest.mark.parametrize(("path", "expected"), PATHS_CASES)
def test_paths_positives(path: str, expected: set[str]) -> None:
    assert _ids(PATHS, _file(path, "anything")) == expected


@pytest.mark.parametrize("path", PATHS_FP_CASES)
def test_paths_false_positives(path: str) -> None:
    assert _ids(PATHS, _file(path, "anything")) == set()


def test_paths_run_on_binary_files() -> None:
    # Path analysis never skips binary: a committed .env is dangerous anyway.
    assert _ids(PATHS, _file(".env", binary=True)) == {"path.dotenv-file"}


# -------------------------------------------------------- dangerous commands

CMDS_CASES: list[tuple[str, set[str]]] = [
    ("curl -fsSL https://x/install.sh | sh", {"cmd.curl-pipe-shell"}),
    ("wget -qO- http://x/setup | sudo bash", {"cmd.curl-pipe-shell", "cmd.sudo-usage"}),
    ("curl https://x | zsh", {"cmd.curl-pipe-shell"}),
    ("rm -rf /", {"cmd.rm-rf-root"}),
    ("rm -r -f /", {"cmd.rm-rf-root"}),
    ("rm -rf --no-preserve-root /", {"cmd.rm-rf-root"}),
    (":(){ :|:& };:", {"cmd.fork-bomb"}),
    ("chmod -R 777 /app", {"cmd.chmod-777"}),
    ("chmod 777 x.sh", {"cmd.chmod-777"}),
    ("sudo apt install -y curl", {"cmd.sudo-usage"}),
    ("git push --force origin main", {"cmd.git-push-force"}),
]

CMDS_FP_CASES: list[str] = [
    "rm -rf /tmp/build",  # scoped delete — must NOT match rm-rf-root
    'rm -rf "$DIR"/',  # variable dir — must NOT match
    'echo "see curl docs | show all"',  # prose mentioning curl + pipe
    "curl -fsSL https://x/install.sh",  # download without pipe-to-shell
    "chmod 755 run.sh",  # sane permissions
    "echo 777",  # number without chmod
    "assert_sudo_available()",  # identifier merely containing sudo
    "git push origin main",  # normal push
    "f() { echo hi; }",  # harmless function, not a fork bomb
    "print('all good')",
]


@pytest.mark.parametrize(("line", "expected"), CMDS_CASES)
def test_cmds_positives(line: str, expected: set[str]) -> None:
    assert _ids(CMDS, _file("deploy.sh", line)) == expected


@pytest.mark.parametrize("line", CMDS_FP_CASES)
def test_cmds_false_positives(line: str) -> None:
    assert _ids(CMDS, _file("deploy.sh", line)) == set()


def test_cmds_skips_binary_content() -> None:
    f = _file("s.sh", "rm -rf /", binary=True)
    assert _ids(CMDS, f) == set()


# -------------------------------------------------------- scope separation

def test_line_rules_do_not_scan_paths() -> None:
    # Dangerous text in the PATH must not trigger line-scope rules.
    f = _file("curl-pipe.sh", "echo hi")
    assert _ids(CMDS, f) == set()
    assert _ids(SECRETS, f) == set()


def test_path_rules_do_not_scan_content() -> None:
    # Sensitive text in added LINES must not trigger path-scope rules.
    f = _file("notes.txt", "remember the .env file", "id_rsa is secret")
    assert _ids(PATHS, f) == set()


# -------------------------------------------------------- default wiring

def test_default_analyzers_claim_every_rule_exactly_once() -> None:
    analyzers = _default_analyzers()
    ids = [a.id for a in analyzers]
    assert sorted(ids) == ["dangerous-cmd", "rules", "secrets", "sensitive-paths"]
    rules = load_builtin_rules()
    covered: list[str] = []
    for a in analyzers:
        if hasattr(a, "_compiled"):
            covered.extend(r.id for r, _ in a._compiled)  # type: ignore[union-attr]
    assert sorted(covered) == sorted(r.id for r in rules)
    assert len(set(covered)) == len(covered)  # no rule fires twice


def test_default_analyzers_register_cleanly() -> None:
    registry = Registry()
    for a in _default_analyzers():
        registry.register(a)
    assert set(registry) == {"dangerous-cmd", "rules", "secrets", "sensitive-paths"}


def test_wired_scan_reports_each_finding_once() -> None:
    f = _file("deploy.py", "AWS_KEY = 'AKIAABCDEFGHIJKLMNOP'")
    seen: list[str] = []
    for a in _default_analyzers():
        seen.extend(found.rule_id for found in a.analyze([f], None))
    assert seen == ["secret.aws-access-key"]
