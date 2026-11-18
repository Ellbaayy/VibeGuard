<p align="center">
  <img src="assets/logo.svg" alt="VibeGuard" width="112" height="112">
</p>

<h1 align="center">VibeGuard</h1>

<p align="center">
  <strong>Local-first safety layer that reviews AI-generated diffs before they land.</strong>
</p>

<p align="center">
  <a href="https://github.com/Ellbaayy/VibeGuard/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/Ellbaayy/VibeGuard/actions/workflows/ci.yml/badge.svg"></a>
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-blue.svg"></a>
  <img alt="Python 3.11+" src="https://img.shields.io/badge/python-3.11%2B-blue.svg">
  <img alt="Telemetry: none" src="https://img.shields.io/badge/telemetry-none-success.svg">
</p>

---

Vibe coding produces large diffs fast. Nobody reads them. Secrets get
committed, `curl | bash` slips into a setup script, `rm -rf /` ends up in a
Makefile, and `.env` is added to the index.

VibeGuard reads the diff **before it lands** and returns a verdict. It is
deterministic, offline, and needs no account: every rule is a regex over added
lines or paths, and the same input always produces the same output.

```
$ vibeguard scan --staged
2 finding(s):
  app/config.py:2: error secret.aws-access-key: Possible AWS access key
  scripts/install.sh:2: error cmd.curl-pipe-shell: Piped remote script to shell (curl|wget ... | sh)
verdict: block
```

## What works today

| Command | Status | Notes |
|---|---|---|
| `vibeguard scan` | ✅ works | `--staged`, `--worktree`, `--commit`, `--diff-file`, `-` (stdin), `--strict` |
| `vibeguard eval` | ✅ works | 33 labelled diffs, precision/recall, CI gate |
| `vibeguard rules list` | 🚧 stub | exits 2 — rules ship in `src/vibeguard/rules/builtins.toml` |
| `vibeguard hook install` | 🚧 stub | use `scan --staged` in `.git/hooks/pre-commit` for now |
| `vibeguard mcp serve` | 🚧 stub | planned; see `ARCHITECTURE.md` |
| `scan --format json` | 🚧 stub | text output only |

This is an honest line: `scan` and `eval` are complete, the other surfaces are
scaffolded and exit `2` (internal error) rather than pretending to work.

## Install

Requires Python 3.11+.

```sh
git clone https://github.com/Ellbaayy/VibeGuard.git
cd VibeGuard

# with uv (recommended, ~2s)
uv sync --extra dev
uv run vibeguard --version
```

Without `uv`:

```sh
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
vibeguard --version
```

Optional — install as a global command:

```sh
uv tool install --editable .
vibeguard --version   # now on PATH
```

## Quick start

```sh
# 1. scan whatever you are about to commit
vibeguard scan --staged

# 2. scan the working tree instead
vibeguard scan --worktree

# 3. scan a diff file someone sent you
git diff main...feature > /tmp/pr.diff
vibeguard scan --diff-file /tmp/pr.diff

# 4. scan stdin (pipes, agent output, CI)
git diff | vibeguard scan -

# 5. treat warnings as blocking (stricter CI)
vibeguard scan --staged --strict
```

## Commands

### `vibeguard scan`

| Flag | Meaning |
|---|---|
| `--staged` | scan the git index (what `git commit` would write) |
| `--worktree` | scan unstaged changes |
| `--commit SHA` | scan a single commit |
| `--diff-file PATH` | scan a unified diff on disk |
| `-` | read the diff from stdin |
| `--strict` | `warn` findings also block |
| `--format text` | output format (only `text` today) |

Exactly one input source is required. Passing none or several exits `3`.

### `vibeguard eval`

```sh
vibeguard eval                    # summary
vibeguard eval --verbose          # per-case table
vibeguard eval --format json      # machine-readable
vibeguard eval --min-precision 0.9 --min-recall 0.9   # CI gate
```

Measures the analyzers against 33 labelled diffs (20 unsafe, 13 safe
near-misses) and reports rule-level precision / recall / F1.

Current baseline on `main`:

| Metric | Value | Meaning |
|---|---|---|
| Precision | **0.875** | 21 true findings, 3 false positives |
| Recall | **1.000** | every expected rule fired |
| F1 | **0.933** | |

The three false positives are documentation lines that *mention* a dangerous
command (`# run with sudo if …`). They are kept in the dataset on purpose so
the number reports the real weakness instead of hiding it.

## Rules

16 built-in rules, all data-driven from
[`src/vibeguard/rules/builtins.toml`](src/vibeguard/rules/builtins.toml).

| Rule | Severity | Scope | Catches |
|---|---|---|---|
| `secret.aws-access-key` | error | line | `AKIA…` key ids |
| `secret.github-token` | error | line | `ghp_…` personal access tokens |
| `secret.private-key-block` | error | line | `BEGIN … PRIVATE KEY` blocks |
| `secret.jwt-token` | warn | line | three-segment JWTs |
| `path.dotenv-file` | error | path | `.env`, `.env.local`, `.env.prod`, … |
| `path.private-key-file` | error | path | `id_rsa`, `*.pem`, `*.key`, `*.p12` |
| `path.credentials-file` | error | path | `credentials*`, `secrets*` |
| `path.git-internal` | error | path | anything under `.git/` |
| `path.ci-workflow-file` | warn | path | `.github/workflows/*.yml` |
| `cmd.curl-pipe-shell` | error | line | `curl … \| bash`, `wget … \| sh` |
| `cmd.rm-rf-root` | error | line | `rm -rf /` |
| `cmd.fork-bomb` | error | line | `:(){ :\|:& };:` |
| `cmd.chmod-777` | warn | line | `chmod 777`, `chmod -R 777` |
| `cmd.sudo-usage` | warn | line | `sudo <command>` |
| `cmd.git-push-force` | warn | line | `git push --force` |
| `merge.conflict-marker` | warn | line | `<<<<<<<` left in a file |

Rules only look at **added** lines — removed code is never reported, because
`DiffFile` does not carry it.

## Exit codes

The contract hooks and CI depend on:

| Code | Meaning |
|---|---|
| `0` | pass — safe to land |
| `1` | block — a rule found something at `error` severity (or `warn` with `--strict`) |
| `2` | internal error — bug, unreadable diff, bad config |
| `3` | usage error — bad arguments |

## Use it with an AI agent

VibeGuard reads a diff, so anything that can produce one can feed it:

```sh
# opencode / codex / hermes: scan the agent's own working tree
vibeguard scan --worktree

# scan only what the agent staged before you let it commit
git diff --cached | vibeguard scan -
```

A pre-commit hook works today without waiting for `hook install`:

```sh
cat > .git/hooks/pre-commit <<'EOF'
#!/bin/sh
exec vibeguard scan --staged
EOF
chmod +x .git/hooks/pre-commit
```

## How it works

```
diff (git / file / stdin)
   -> core.diff      parse into DiffFile(path, added_lines)
   -> analyzers.*    secrets · sensitive paths · dangerous commands · generic rules
   -> core.pipeline  aggregate + optional advisory AI (clamped to warn)
   -> core.result    verdict: pass | warn | block
```

Two invariants hold regardless of input:

1. **Added lines only.** Removed code can never be reported.
2. **AI can never block.** Findings from the optional AI provider are rewritten
   to `source="ai"` and capped at `warn`; only deterministic rules produce a
   block.

## Development

```sh
uv sync --extra dev
uv run pytest -q          # 170 tests
uv run ruff check .       # lint
uv run mypy src           # types
uv run vibeguard eval     # accuracy baseline
```

Architecture and the frozen contracts live in
[`ARCHITECTURE.md`](ARCHITECTURE.md); the task breakdown is in
[`TASKS.md`](TASKS.md).

When you add or change a rule, add an eval case in
[`src/vibeguard/eval/cases.py`](src/vibeguard/eval/cases.py). A regression then
shows up as a drop in precision/recall instead of a silent behavior change.

## License

MIT — see [LICENSE](LICENSE).
