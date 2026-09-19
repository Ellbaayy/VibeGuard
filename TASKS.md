# VibeGuard — Implementation Task Breakdown

Status: DRAFT v1
Prerequisite: ARCHITECTURE.md must be read first. All contracts referenced here
are defined there and are FROZEN — if a task seems to require changing a
contract, stop and escalate to the Architect instead of improvising.

Repo root: vibeguard/
Layout: src-layout (`src/vibeguard/`), Python >= 3.11, zero runtime deps in core.

Task ID convention: P<phase>.<n>. Each task lists: spec, files, depends-on,
acceptance. A task is DONE only when its acceptance is demonstrated by a real
test run, not by "code looks right".

════════════════════════════════════════════════════════════════════════
PHASE 0 — skeleton [REQUIRED]
Owner: Muse Spark 1.3 (mechanical, no design decisions)
════════════════════════════════════════════════════════════════════════

P0.1 Project scaffold
  Files: pyproject.toml, src/vibeguard/__init__.py, LICENSE (MIT),
         .gitignore, README.md (stub: one-line description + install + usage)
  Spec:
    - pyproject: build backend hatchling; project name "vibeguard";
      requires-python ">=3.11"; NO runtime dependencies; entry point
      console script `vibeguard = vibeguard.cli:main`;
      optional-dependencies: dev = [pytest, ruff, mypy], mcp = ["mcp"].
      NOTE: no [ai] extra needed — AI provider uses stdlib only (per ARCHITECTURE §5).
    - __init__.py exposes __version__ = "0.1.0".
  Acceptance: `pip install -e .` in a fresh venv succeeds; `vibeguard --version`
  prints 0.1.0; `pip show vibeguard` lists zero requires.

P0.2 CI workflow
  Files: .github/workflows/ci.yml
  Spec: matrix Python 3.11/3.12/3.13; steps = install -e .[dev], ruff check,
  mypy src, pytest. Fail on any red.
  Acceptance: workflow file passes actionlint (or YAML parse + local run of the
  same commands green).

P0.3 CLI stub
  Files: src/vibeguard/cli.py
  Spec: argparse with subcommands scan/rules/hook/mcp. `scan` accepts all flags
  from ARCHITECTURE §6 but does nothing yet beyond printing "not implemented".
  Bad usage → exit 3 (argparse default exit is 2; override to 3 per contract).
  Internal errors → exit 2 with message on stderr.
  Acceptance: `vibeguard scan --bogus` exits 3; `vibeguard` alone exits 3 with
  usage text.

════════════════════════════════════════════════════════════════════════
PHASE 1 — core [REQUIRED]
Owner: DeepSeek V4 Pro (contract-bearing code)
════════════════════════════════════════════════════════════════════════

P1.1 core/result.py
  Spec: dataclasses Finding, ScanReport; Severity enum (info/warn/error);
  Verdict enum (pass/warn/block); function
  `aggregate(findings, strict) -> ScanReport` implementing ARCHITECTURE §4
  verdict rules exactly:
    - block iff any finding with source="rule" and severity="error"
      (strict mode: also warn-severity rule findings)
    - AI-source findings NEVER contribute to block (property-test this).
  Acceptance: unit tests cover the full severity × source × strict matrix;
  property test with Hypothesis-style random findings (or plain randomized
  table) asserting the AI invariant.

P1.2 core/diff.py
  Spec: DiffFile dataclass (frozen) per contract; DiffSource implementations:
    - GitStaged / GitWorktree / GitCommit(sha): subprocess git, run with
      repo root from `git rev-parse --show-toplevel`, `-C <root>`.
    - DiffFileSource(path) and StdinSource for --diff-file / '-'.
  Unified-diff parser: pure function `parse_unified_diff(text) -> list[DiffFile]`
  handling: new files, modified, renames (--- +++), deletions (no added lines),
  binary ("Binary files ... differ" → DiffFile with empty added_lines and a
  flag `binary: bool` — ADD this field to DiffFile, it is a contract amendment
  recorded here), /dev/null null paths, CRLF, non-UTF-8 (errors="replace").
  Acceptance: golden tests over real `git diff` outputs for: staged change,
  rename, deletion, binary file, empty diff, CRLF file, file with merge-conflict
  markers (markers must survive into added_lines — analyzer flags them later).

P1.3 analyzers/base.py + rules/builtins.toml loader
  Spec: Analyzer protocol + registry (dict keyed by analyzer id). Rule file
  loader using tomllib: rule records with id/severity/pattern/message/scope.
  Validation: unknown keys or bad regex → ConfigError (exit 2 path).
  Ship builtins.toml with a MINIMAL seed set (the full rule set is Phase 2 —
  do not front-load it here).
  Acceptance: loader unit tests (valid file, invalid regex, unknown severity).

P1.4 core/pipeline.py
  Spec: `run_scan(diff_files, analyzers, ai_provider, config) -> ScanReport`.
  Order: deterministic analyzers → aggregate → (if ai enabled) AI review →
  clamp AI findings to severity<=warn, source="ai" → re-aggregate.
  Enforce max_diff_bytes: skip content rules beyond limit, emit warn finding
  "diff-too-large".
  Acceptance: mock analyzer + mock provider tests; clamp invariant test
  (provider returns error-severity → clamped to warn, verdict unchanged).

P1.5 cli.py scan wiring + formatters/text.py
  Spec: wire diff sources → pipeline → text formatter; exit codes per §4;
  colors only when sys.stdout.isatty(). Empty diff → "no changes", exit 0.
  Acceptance (THE Phase-1 gate, run as real e2e): temp git repo via subprocess;
  stage a file containing a fake AWS key `AKIAABCDEFGHIJKLMNOP`; run
  `vibeguard scan --staged` as a subprocess; assert exit 1 and output contains
  the rule id. Also: clean diff → exit 0.

════════════════════════════════════════════════════════════════════════
PHASE 2 — analyzers + UX [REQUIRED]
Owner: Muse Spark 1.3 (works against frozen Phase-1 contracts)
════════════════════════════════════════════════════════════════════════

P2.1 analyzers
  Files: secrets.py, sensitive_paths.py, dangerous_cmd.py + rule data in
  builtins.toml.
  Spec: secrets = line-scope regexes (AWS key, GitHub token ghp_, generic
  private-key blocks, JWT-looking strings) on ADDED lines only — never removed
  lines. sensitive_paths = path-scope (.env*, id_rsa*, *.pem/*.key,
  credentials*, .git/ internal changes, CI workflow files → warn not error).
  dangerous_cmd = line-scope (rm -rf /, curl|sh pipelines, chmod -R 777,
  sudo in scripts, fork bomb, `git push --force` → warn).
  EVERY rule ships with a documented false-positive test case.
  Severity policy: conservative defaults (per Architect decision) — when in
  doubt, warn.
  Acceptance: table-driven tests per analyzer incl. FP cases (e.g. `AKIA...`
  inside longer identifier must NOT match; `rm -rf /tmp/x` must NOT match).

P2.2 formatters/json_out.py + scan options
  Spec: --format json emits ScanReport as stable JSON schema (document the
  schema in a docstring: findings[], verdict, duration_ms, vibeguard_version).
  Implement --strict, --only/--skip (filter BEFORE aggregation), --max-findings.
  Acceptance: json output round-trips through json.loads with the documented
  schema; --only/--skip filters verified by unit test.

P2.3 config.py
  Spec: discovery walks up from cwd to find .vibeguard.toml; merge order
  builtins < repo file < CLI flags per ARCHITECTURE §7. Allowlist:
  paths (fnmatch) suppress path+line findings for that file; rule_exemptions
  suppress by rule id. Unknown config keys → exit 2 with the offending key.
  Acceptance: unit tests for each merge layer + allowlist suppression +
  unknown-key rejection.

P2.4 hooks/pre_commit.py
  Spec: `vibeguard hook install` writes .git/hooks/pre-commit that execs
  `vibeguard scan --staged --format text` (shebang sh, set -e semantics: hook
  exits with vibeguard's code). Refuses to overwrite an existing non-vibeguard
  hook without --force. `uninstall` removes it only if it was ours (marker line).
  Acceptance (Phase-2 gate, e2e): temp repo → hook install → stage file with
  `curl http://x | sh` → `git commit` fails → fix file → commit succeeds.

════════════════════════════════════════════════════════════════════════
PHASE 3 — optional surfaces [OPTIONAL]
Owner: DeepSeek V4 Pro
════════════════════════════════════════════════════════════════════════

P3.1 mcp/server.py
  Spec: behind extra; `vibeguard mcp serve` starts stdio MCP server exposing
  review_diff(diff) / review_staged() / list_rules(). Thin adapter: parse diff
  text with core.diff.parse_unified_diff → pipeline → json formatter's data.
  Core must NOT import the mcp package — import lazily inside the command,
  with a friendly error if extra not installed.
  Acceptance: subprocess stdio round-trip test (only runs when extra installed;
  skip marker otherwise).

P3.2 ai/provider.py + ai/openai_compat.py
  Spec: Provider protocol per contract; NoopProvider default. OpenAI-compat
  client via urllib.request only; config [ai] section; findings from provider
  are dataclass-validated and clamped by pipeline (already enforced in P1.4 —
  this task must NOT weaken it). Network errors → warn finding "ai-unavailable",
  scan continues, never blocks.
  Acceptance: mock-HTTP tests (local http.server) proving: normal advisory
  findings pass through clamped; provider returning garbage/error-severity is
  clamped; connection refused → scan still completes with exit code driven by
  deterministic findings only.

════════════════════════════════════════════════════════════════════════
PHASE 4 — community [REQUIRED for 1.0]
Owner: split
════════════════════════════════════════════════════════════════════════

P4.1 CONTRIBUTING.md + rule-authoring guide (docs/rules.md) + ADR template
  (docs/adr/0000-template.md). P4.2 usage docs: hook, CI, MCP.

════════════════════════════════════════════════════════════════════════
QA GATE (Pi-Agent DeepSeek V4-1 Flash) — end of every phase
════════════════════════════════════════════════════════════════════════
Checklist (each item = pass/fail with evidence):
  1. All phase acceptance criteria demonstrated by real test runs (paste output).
  2. `pip install .` in clean venv → zero runtime deps (core extras excluded).
  3. No import of requests/third-party in src/vibeguard outside mcp/ and ai/
     (grep gate).
  4. AI-invariant test present and green (ai can never cause block).
  5. Exit codes match contract 0/1/2/3 in e2e tests.
  6. ruff + mypy clean.
  7. No scope creep: diff vs task list — anything not in a task gets flagged,
     not merged silently.

Dependency graph (what can run in parallel):

  P0.* → P1.1 → P1.2 ─┐
           │          ├→ P1.4 → P1.5 → P2.1 ─┐
           └→ P1.3 ──┘          → P2.2 ──────┼→ P2.4
                                  → P2.3 ──────┘
  P1.5 → P3.1, P3.2 (after Phase 1 gate; independent of Phase 2)
  P2.4 → P4.*
