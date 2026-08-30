# actionsieve

Multi-platform CI/CD pipeline security scanner. Pattern-driven detection of
injection vulnerabilities, supply chain risks, and misconfigurations in
GitHub Actions, GitLab CI, Azure Pipelines, Jenkins, CircleCI, and
Bitbucket Pipelines.

Architecture doc: `docs/architecture.md`

## Build environment

- Python 3.12+
- Package manager: uv (preferred) or pip
- Package config: `pyproject.toml` (no setup.py, no setup.cfg)
- CLI framework: click
- YAML parsing: pyyaml (safe_load only — never yaml.load)
- Output formats: built-in json, pyyaml, jinja2 (markdown), sarif via dict

## Dependencies

Runtime:
- `click` — CLI framework
- `pyyaml` — YAML parsing (safe_load only)
- `jsonschema` — pattern and profile schema validation
- `jinja2` — Markdown report templates
- `tree-sitter` + `tree-sitter-groovy` — Jenkins Groovy AST parsing

Dev:
- `pytest` — test runner
- `ruff` — linter + formatter
- `mypy` — type checker
- `pre-commit` — git hook management

## Development setup

```
uv venv
uv pip install -e ".[dev]"
pre-commit install
```

## Project structure

Properly separated modules — no god files:

```
actionsieve/
  cli.py          — click entry point, no business logic
  scanner.py      — orchestrates scan: find files → parse → match → score → output
  search.py       — forge-wide code search (GitHub/GitLab API, clone-and-scan)
  model.py        — normalized WorkflowModel dataclasses (platform-agnostic)
  engine.py       — pattern matching against WorkflowModel
  matchers.py     — structural pattern matchers
  cross_step.py   — cross-step chain-based matchers
  chains.py       — cross-step/job data flow analysis
  severity.py     — two-stage severity: static context + environment profile
  profiles.py     — environment profile loader + built-in presets
  patterns.py     — pattern catalog loader (globs directory) + schema validation
  inventory.py    — component bill of materials
  advisories.py   — advisory database loader + checker
  trust.py        — component trust scoring
  output.py       — result formatting (JSON, YAML, Markdown, SARIF, CycloneDX)
  search.py       — forge-wide code search
  providers/
    __init__.py     — provider interface (Protocol class) + auto-detection
    github.py       — GitHub Actions provider
    github_parse.py — expression extraction, ref parsing, utility helpers
    gitlab.py       — GitLab CI provider
    azure.py        — Azure Pipelines provider
    jenkins.py      — Jenkins provider (declarative + scripted)
    jenkins_ast.py  — tree-sitter Groovy AST walker
    circleci.py       — CircleCI provider
    circleci_parse.py — CircleCI orb, step, expression parsing
    bitbucket.py      — Bitbucket Pipelines provider
    buildkite.py      — Buildkite Pipelines provider
    drone.py          — Drone CI provider
    codebuild.py      — AWS CodeBuild provider
    cloudbuild.py     — Google Cloud Build provider

patterns/                  — YAML pattern catalog (data, not code)
patterns/advisories/       — known-compromised component database
tests/fixtures/{platform}/ — sample pipelines (vulnerable/ and safe/)
```

Each module has a single responsibility. If a module grows past ~600 lines,
it's probably doing too much — split it.

## Testing

### Strategy

- **Unit tests** for every module: parser, model, engine, severity, patterns,
  providers, inventory, trust, output formatters
- **Fixture-based** — tests/fixtures/ has real and synthetic pipeline files
  organized by platform, each with vulnerable/ and safe/ subdirectories
- **E2E tests** — full `actionsieve scan <fixture-repo>` runs that verify
  CLI exit codes, output format correctness, and expected findings
- **Pattern validation tests** — every pattern in the catalog must load
  without errors, have required fields, and match at least one fixture
- **Provider tests** — each provider is tested independently against its
  platform's fixtures, producing the same normalized WorkflowModel shape

### Running tests

```
pytest                     # full suite
pytest tests/unit/         # unit tests only
pytest tests/e2e/          # end-to-end only
pytest -x                  # stop on first failure
pytest -k "github"         # platform-specific tests
```

### Rules

- **Always run the full test suite before committing.** No exceptions.
- Tests must pass in CI. Flaky tests get fixed or deleted, not skipped.
- New code needs tests. New patterns need at least one vulnerable and one
  safe fixture.
- Test the boundary: if severity depends on trigger type, test each trigger.
- Fixtures are real workflow snippets where possible (anonymized from
  actual repos we've analyzed).

## Code style

Code is poetry. Flow and naming describe intent — comments are a last
resort.

- **No comments by default.** A well-named function, clear variable, and
  obvious control flow don't need narration.
- **Comment only the why**, never the what. If the reader needs a comment
  to understand what the code does, rename things until they don't.
- **One line max.** If a comment needs a paragraph, the code needs a
  refactor.
- **No docstring novels.** Type hints and a good name are the
  documentation. A one-line docstring is fine when the name alone is
  ambiguous. Multi-line docstrings are almost never warranted.
- **No commented-out code.** Delete it. Git remembers.
- **Be concise everywhere.** Short functions, short variable names that
  are still clear, short modules. If it feels verbose, it is.

## Code quality

- **Formatter**: ruff format
- **Linter**: ruff check
- **Type checker**: mypy --strict
- **Pre-commit hooks**: ruff + mypy + pytest (configured in .pre-commit-config.yaml)

```
ruff check .               # lint
ruff format .              # format
mypy actionsieve/          # type check
```

All three must pass before commit. Pre-commit hooks enforce this
automatically.

## Patterns

Pattern catalog lives in `patterns/` — one YAML file per attack class:

```
patterns/
  expression-injection.yml    — ${{ }}, $CI_*, $[ ] injection
  artifact-trust.yml          — workflow_run artifacts, cross-pipeline deps
  dangerous-triggers.yml      — pull_request_target, trigger:, etc.
  output-injection.yml        — GITHUB_OUTPUT/ENV delimiter, step outputs
  supply-chain.yml            — unpinned refs, mutable tags, advisories
  self-hosted-runners.yml     — persistence, escape, shared runner risks
  secret-exposure.yml         — logging, env leaks, token scope abuse
  template-injection.yml      — GitLab include:, Azure templates, Jenkins @Library
  schema.json                 — JSON Schema for validation
```

Patterns are data — adding a pattern should never require changing scanner
code. The loader globs all `*.yml` files in the patterns directory and
merges them. Pattern IDs must be globally unique across files.

Every pattern needs:
- `id` — unique kebab-case identifier
- `platforms` — list of platforms or "all"
- `detection` — matching rules (type, match, checks)
- `attacker_model` — who can trigger this (fork_pr, contributor, admin)
- `impact` — what happens (rce, secret_exfil, supply_chain)
- `severity_base` — starting severity before context modifiers

The `patterns.py` loader validates against `patterns/schema.json`.
Invalid patterns fail loud. `--patterns` accepts a directory or single file.

## Security

This tool scans for CI/CD vulnerabilities — it must not introduce any.

- YAML: `yaml.safe_load()` only. Never `yaml.load()`.
- No `eval()`, no `exec()`, no `subprocess` with shell=True on user input.
- No importing or executing code from scanned repos.
- File size caps on parsed files (1MB per workflow).
- Recursion depth limits for composite resolution.
- Never load config from the scanned repo by default — a malicious repo
  could suppress findings via `.actionsieve.yml`. Repo profiles require
  explicit `--trust-repo-profile`.
- Reference CI workflows use `pull_request` (not `pull_request_target`),
  load patterns from base branch, pin all action refs to SHA.

## Definition of done (per commit)

Every commit must pass this checklist. Don't build fast and audit later —
enforce quality at each commit.

- [ ] **Tests exist** — every new function has at least one test, every
  new pattern has vulnerable + safe fixtures
- [ ] **Types are strict** — no `Any` where a concrete type works, no
  `object` + `assert isinstance` workarounds, use `TYPE_CHECKING` imports
- [ ] **Line counts** — no module over 600 lines (split before committing,
  not after)
- [ ] **No dead code** — no unused imports, variables, functions, or
  constants
- [ ] **E2E coverage** — every CLI flag/command has at least one E2E test
- [ ] **Patterns fire** — if you add a pattern, run it against a fixture
  and verify it produces findings before committing

## Git workflow

- `main` is the default branch
- Feature branches for new work
- Conventional commits: `feat:`, `fix:`, `test:`, `docs:`, `refactor:`
- No force-push to main
- Pre-commit hooks must pass
- **Commit after every major change.** Don't batch a whole phase into one
  commit. Each logical unit of work (new module, new pattern file, new
  provider, new test suite) gets its own commit. Small, reviewable commits.
- CLAUDE.md, TODO.md, and docs/ are committed with the project — they're
  project instructions, not personal config.

## Files that are committed

- `CLAUDE.md` — yes, project instructions for all contributors (human + AI)
- `TODO.md` — yes, shared task tracking
- `docs/` — yes, architecture and design docs
- `patterns/` — yes, shipped as package data
- `.pre-commit-config.yaml`, `ruff.toml` — yes, shared dev tooling config

## .gitignore

```
__pycache__/
*.pyc
*.pyo
.venv/
dist/
build/
*.egg-info/
.mypy_cache/
.ruff_cache/
.pytest_cache/
.coverage
htmlcov/
```

## Current phase

Phases 1–7 complete. All platform providers implemented:
GitHub, GitLab, Azure, Jenkins, CircleCI, Bitbucket, Buildkite, Drone,
CodeBuild, Cloud Build. Phase 5 (forge search) complete: GitHub and
GitLab backends with org search and pattern-targeted code search.
See `TODO.md` for remaining backlog items.
