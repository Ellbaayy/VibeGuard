# VibeGuard — Architecture

Status: DRAFT v1 (pre-implementation)
Owner: VibeGuard Architect
Audience: Senior Developer (DeepSeek V4 Pro), Implementation Builder (Muse Spark 1.3), QA (DeepSeek V4-1 Flash)

Legend: [REQUIRED] = MVP scope · [OPTIONAL] = extra, shipped behind an install extra / flag · [FUTURE] = explicitly out of current scope

---

## 1. Goal

VibeGuard is a local-first, CLI-first safety layer that reviews code changes
produced by AI agents BEFORE they land in the repository.

Primary invocation surfaces:

1. CLI (interactive + scripting)
2. Git hook (pre-commit)
3. CI (exit codes + machine-readable output)
4. MCP server (so agents can call VibeGuard directly as a tool)

Core promise: deterministic, fast, offline. AI is an optional amplifier, never
a dependency and never a blocker.

## 2. User problem

Vibe coding produces large diffs quickly. Nobody reads them. Secrets get
committed, dangerous commands get pasted, sensitive files get touched, and
destructive changes slip into main. Existing tools are either too heavy,
cloud-dependent, or not composable with agent workflows.

## 3. Non-goals (scope fence)

- NOT a linter / formatter / type checker (use ruff, black, mypy).
- NOT an SAST powerhouse (use semgrep for that; we may emit compatible output later [FUTURE]).
- NOT an auto-fixer in v1 — findings only. [FUTURE]
- NOT a cloud service. No telemetry, no network calls unless the user enables the AI extra.

## 4. Core concepts

- Finding: one detected issue. Fields: `rule_id`, `severity`, `file`, `line`,
  `message`, `snippet`, `source` (`rule` | `ai`).
- Severity levels: `info` < `warn` < `error`.
- Verdict (final decision for the run): `pass` | `warn` | `block`.
  - `block` = any `error`-severity finding from a deterministic rule.
  - AI findings can produce at most `warn`, never `block`. This is a hard invariant.
- ScanReport: list of findings + verdict + duration + metadata.

Exit codes (contract for hooks/CI):
- 0 = pass
- 1 = block (findings at error severity, or warn in strict mode)
- 2 = internal error (bug, bad config)
- 3 = usage error (bad args)

## 5. Architecture

Data flow:

```
        ┌────────────────────────────────────────────┐
        │  Invocation surfaces                       │
        │  CLI · git hook · CI · MCP server          │
        └───────────────┬────────────────────────────┘
                        │ unified input: "what to scan"
                        ▼
        ┌────────────────────────────────────────────┐
        │  core.diff  (collect + parse unified diff) │
        └───────────────┬────────────────────────────┘
                        ▼
        ┌────────────────────────────────────────────┐
        │  core.pipeline (orchestration)            │
        │   ├── analyzers.*  (deterministic) [REQ]  │
        │   └── ai.provider   (advisory)   [OPT]     │
        └───────────────┬────────────────────────────┘
                        ▼
        ┌────────────────────────────────────────────┐
        │  core.result  (aggregate → ScanReport)     │
        └───────────────┬────────────────────────────┘
                        ▼
        ┌────────────────────────────────────────────┐
        │  formatters  (text / json) + exit code     │
        └────────────────────────────────────────────┘
```

Module map (package `vibeguard`):

```
vibeguard/
  __init__.py          version + public API
  cli.py               [REQUIRED] argparse entry point (`vibeguard`)
  config.py            [REQUIRED] load + merge config (.vibeguard.toml + CLI flags)
  core/
    diff.py            [REQUIRED] diff sources: --staged, --worktree, --commit, file, stdin
    result.py          [REQUIRED] Finding, Verdict, ScanReport dataclasses
    pipeline.py        [REQUIRED] run analyzers over parsed diff, aggregate
  analyzers/
    base.py            [REQUIRED] Analyzer protocol + registry
    secrets.py         [REQUIRED] secret/token patterns on ADDED lines only
    sensitive_paths.py [REQUIRED] .env, credentials, keys, .git changes...
    dangerous_cmd.py   [REQUIRED] rm -rf /, curl|sh, chmod 777, sudo, :(){ fork bomb...
  rules/
    builtins.toml      [REQUIRED] data-driven rule definitions (ids, patterns, severity, message)
  ai/
    provider.py        [OPTIONAL] Provider protocol, NoopProvider default
    openai_compat.py   [OPTIONAL] stdlib-HTTP OpenAI-compatible client (extra: vibeguard[ai])
  hooks/
    pre_commit.py      [REQUIRED] `vibeguard hook install|uninstall` (writes .git/hooks/pre-commit)
  mcp/
    server.py          [OPTIONAL] stdio MCP server (extra: vibeguard[mcp])
  formatters/
    text.py            [REQUIRED] human output, colorized, no color when piped
    json_out.py        [REQUIRED] --format json (machine output for CI/agents)
```

Dependency policy (hard rule):

- Core (`pip install vibeguard`): ZERO runtime dependencies. stdlib only.
  Config + rules use TOML via `tomllib`. Diff parsing is our own minimal
  unified-diff parser (reason: avoids the `unidiff` dep; scope is only file +
  added-line extraction, ~100 lines, fully tested).
- Extras: `vibeguard[ai]` (still zero extra deps — provider uses stdlib
  `urllib.request`), `vibeguard[mcp]` (depends on `mcp` package).
- Dev deps (pytest, ruff, mypy) live in the dev extra only.

## 6. Contracts (the interfaces builders implement against)

```python
# core/diff.py
@dataclass(frozen=True)
class DiffFile:
    path: str
    added_lines: list[tuple[int, str]]   # (new_line_number, text)

class DiffSource(Protocol):
    def collect(self) -> list[DiffFile]: ...

# analyzers/base.py
class Analyzer(Protocol):
    id: str
    def analyze(self, files: list[DiffFile], config: Config) -> list[Finding]: ...

# rules (data-driven, rules/builtins.toml)
[[rule]]
id = "secret.aws-access-key"
severity = "error"
pattern = 'AKIA[0-9A-Z]{16}'
message = "Possible AWS access key"
scope = "line"            # "line" | "path"

# ai/provider.py
class AIProvider(Protocol):
    name: str
    def review(self, files: list[DiffFile], findings: list[Finding],
               config: Config) -> list[Finding]: ...
    # Invariant: returned findings MUST have severity <= warn and source="ai".
    # pipeline enforces this by clamping, never trusting the provider.

# formatters
class Formatter(Protocol):
    def format(self, report: ScanReport, config: Config) -> str: ...
```

CLI surface (stable, agents and hooks depend on it):

```
vibeguard scan [--staged | --worktree | --commit <sha> | --diff-file F | -]
               [--format text|json] [--strict] [--config PATH]
               [--only RULE_ID...] [--skip RULE_ID...] [--max-findings N]
vibeguard rules list [--format json]
vibeguard hook install | uninstall
vibeguard mcp serve        # [OPTIONAL] only when extra installed
vibeguard --version
```

MCP tools [OPTIONAL]:
- `review_diff(diff: str) -> ScanReport` — agent sends a unified diff, gets findings.
- `review_staged() -> ScanReport` — run against the repo VibeGuard is invoked in.
- `list_rules() -> list[...]`

MCP server runs the SAME pipeline + rules as CLI. No code duplication: MCP is a
thin adapter over core.pipeline.

## 7. Config

`.vibeguard.toml` at repo root, discovered by walking up from cwd. Merge order
(low → high): built-in defaults < repo config < CLI flags.

```toml
[scan]
strict = false
max_diff_bytes = 1_000_000      # bail out politely on giant diffs

[allowlist]
paths = ["tests/fixtures/*"]
rule_exemptions = ["secret.example-key"]   # e.g. docs use fake keys

[ai]                              # inert unless extra installed + enabled
enabled = false
url = "https://your-gateway/v1"
model = "..."
max_input_chars = 120_000
```

## 8. Edge cases (must be handled in v1)

- Empty diff → verdict pass, exit 0, print "no changes".
- Binary files in diff → skip content analysis, note in report.
- Non-UTF-8 files → decode with errors="replace", never crash.
- Renames / deletions → analyzed for path rules, no line rules (nothing added).
- Huge diffs → truncate with a warning; never OOM.
- CRLF and merge-conflict markers (<<<<<<<) → conflict markers themselves are a
  `warn` finding (agents commit broken states surprisingly often).
- Running inside a subdirectory of the repo → config discovery walks up; git
  commands use `git -C <repo_root>`.
- Detached HEAD / rebase in progress during hook run → fail with clear message,
  exit 2, do not silently pass.
- Secrets in test fixtures → allowlist via rule_exemptions, documented.
- stdout piped (CI) → disable ANSI colors automatically (check `sys.stdout.isatty()`).
- MCP server long-running → stateless per call; no caching in v1.

## 9. Testing strategy

- Unit (per analyzer): table-driven tests over DiffFile fixtures, including
  known false-positive cases (e.g. `AKIA` inside a longer identifier).
- Diff parser: golden tests — real `git diff` outputs (staged, rename, binary,
  CRLF, empty) → expected DiffFile lists.
- Pipeline: verdict aggregation matrix (severity × strict × ai-clamp invariant).
- AI clamp: property test — whatever a mock provider returns, report contains
  no ai-source finding above warn, and block verdict never depends on ai source.
- CLI e2e: pytest fixtures create temp git repos via subprocess, run `vibeguard
  scan --staged` as a real subprocess, assert exit codes + output.
- Hook e2e: install hook in temp repo, `git commit` a bad change, assert commit
  blocked; assert good change passes.
- MCP (when built): stdio round-trip test against a subprocess server.
- CI: GitHub Actions — pytest + ruff + mypy on 3.11–3.13. Python floor: 3.11
  (tomllib availability).

## 10. Risks

- False positives destroy trust fast → ship conservative defaults, allowlist
  first-class, every rule documented with rationale.
- Rule regex performance on huge diffs → precompiled patterns, one pass, hard
  byte limit before scanning.
- `mcp` package churn → isolated in optional extra; core never imports it.
- Prompt-injection via reviewed code → AI is read-only consumer, output clamped
  to advisory; AI can never write files, exit codes, or rules.
- Scope creep (this project attracts "one more feature") → changes to this
  document require an explicit architecture decision record (ADR in docs/adr/).

## 11. Implementation tasks

Phase 0 — skeleton [REQUIRED]
0.1 pyproject (hatchling), src layout, zero deps, entry point `vibeguard=vibeguard.cli:main`
0.2 CI workflow (pytest/ruff/mypy), README stub, LICENSE (MIT)
0.3 Empty CLI that parses `scan` and exits 3 on bad usage

Phase 1 — core [REQUIRED]
1.1 core/result.py — dataclasses + severity/verdict logic
1.2 core/diff.py — unified diff parser + git sources (staged/worktree/commit/file/stdin)
1.3 analyzers/base.py — protocol + registry; rules/builtins.toml loader (tomllib)
1.4 core/pipeline.py — orchestrate, aggregate, enforce AI clamp
1.5 cli.py scan wiring + formatters/text.py + exit codes
→ Acceptance: e2e test — temp repo, stage a diff containing a fake AWS key,
`vibeguard scan --staged` exits 1 and prints the finding.

Phase 2 — analyzers + UX [REQUIRED]
2.1 secrets.py, sensitive_paths.py, dangerous_cmd.py with data-driven rules
2.2 formatters/json_out.py, --strict, --only/--skip, allowlist handling
2.3 config.py — discovery + merge + CLI override
2.4 hooks/pre_commit.py — install/uninstall + e2e hook test
→ Acceptance: pre-commit e2e test blocks a commit containing `curl ... | sh`.

Phase 3 — optional surfaces [OPTIONAL]
3.1 mcp/server.py behind extra, thin adapter over pipeline, stdio tests
3.2 ai/provider.py + openai_compat.py (stdlib HTTP), advisory clamp tests
→ Acceptance: with extra installed, `vibeguard mcp serve` answers review_diff;
ai findings never escalate verdict beyond warn.

Phase 4 — community [REQUIRED for 1.0]
4.1 CONTRIBUTING, rule authoring guide, ADR template
4.2 Docs for hook + CI + MCP usage

Suggested ownership: DeepSeek V4 Pro → Phase 1 (contracts + core), Muse Spark
1.3 → Phase 2 (analyzers, formatters, hooks) against frozen contracts, Pi-Agent
→ QA gate at the end of each phase (tests must pass + review checklist: zero
runtime deps, no AI in blocking path, stdlib-only imports in core).

## 12. Open questions (need jagi's decision, not blocking Phase 0–1)

- PyPI name availability for `vibeguard`.
- Default rule set aggressiveness: conservative (fewer rules, warn-leaning) vs
  strict-by-default (block-leaning). Architect recommendation: conservative.
