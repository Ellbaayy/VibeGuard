# VibeGuard

Local-first, CLI-first safety layer that reviews code changes produced by AI agents BEFORE they land.

Status: Phase 0 skeleton (see `ARCHITECTURE.md` and `TASKS.md`).

## Install

```sh
uv sync --extra dev
```

Or with pip:

```sh
pip install -e ".[dev]"
```

## Usage

```sh
vibeguard --version
vibeguard scan --staged
vibeguard eval
vibeguard rules list
vibeguard hook install
```

Exit codes: `0` pass · `1` block · `2` internal error · `3` usage error.

## Eval

`vibeguard eval` runs 33 labelled diffs through the real scan pipeline and
reports rule-level precision/recall — the number that says whether a finding
is worth trusting.

```sh
uv run vibeguard eval            # summary
uv run vibeguard eval --verbose  # per-case table
uv run vibeguard eval --format json
```

Use it as a CI gate:

```sh
uv run vibeguard eval --min-precision 0.9 --min-recall 0.9   # exit 1 if below
```

The dataset lives in `src/vibeguard/eval/cases.py`; each case is a unified
diff plus the exact rule ids that must fire. Add a case whenever a bug is
found — a regression then shows up as a metric drop instead of a silent
behavior change.

