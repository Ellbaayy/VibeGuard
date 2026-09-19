# VibeGuard

Local-first, CLI-first safety layer that reviews code changes produced by AI agents BEFORE they land.

Status: Phase 0 skeleton (see `ARCHITECTURE.md` and `TASKS.md`).

## Install

```sh
pip install -e .
```

With dev tools:

```sh
pip install -e ".[dev]"
```

## Usage

```sh
vibeguard --version
vibeguard scan --staged
vibeguard rules list
vibeguard hook install
```

Exit codes: `0` pass · `1` block · `2` internal error · `3` usage error.
