# actionsieve — TODO

## Phase 0: Project scaffolding

- [x] `.gitignore` (Python: __pycache__, *.pyc, .venv/, dist/, *.egg-info/, .mypy_cache/, .ruff_cache/, .pytest_cache/)
- [x] `pyproject.toml` with project metadata, entry point, dependencies, dev extras:
  - Runtime: click, pyyaml, jsonschema, jinja2
  - Dev: pytest, ruff, mypy, pre-commit
- [ ] `uv.lock` for reproducible builds
- [x] `.pre-commit-config.yaml` (ruff check, ruff format, mypy, pytest)
- [x] `ruff.toml` (line length, target version, select rules)
- [x] `mypy.ini` or pyproject section (strict mode)
- [x] `patterns/schema.json` — JSON Schema for pattern catalog validation
- [x] Directory structure: actionsieve/, actionsieve/providers/, tests/unit/, tests/unit/providers/, tests/e2e/, tests/fixtures/
- [x] Empty `__init__.py` files, basic cli.py with click group
- [x] Verify: `uv pip install -e ".[dev]" && pytest && ruff check . && mypy actionsieve/`
- [x] Initial commit

## Phase 1: GitHub Actions scanner (MVP)

### Provider interface + GitHub provider
- [x] `providers/__init__.py` — Provider Protocol class (detect, find_files, parse, resolve_ref, expression_syntax, search_query)
- [x] `providers/__init__.py` — auto_detect(repo_path) returns list of matching providers
- [x] `providers/github.py` — detect: `.github/workflows/` exists
- [x] `providers/github.py` — find_files: glob `*.yml` + `*.yaml` in `.github/workflows/`
- [x] `providers/github.py` — parse: YAML → WorkflowModel
- [x] `providers/github.py` — expression_syntax: `${{ }}` interpolation rules
- [x] Unit tests for GitHub provider (parse known fixtures, reject malformed)

### Workflow model
- [x] `model.py` — dataclasses: WorkflowModel, Job, Step, Trigger, Expression, ComponentRef, Permission
- [x] Platform field on WorkflowModel
- [x] Normalized block types (shell_command, expression, component_ref)
- [x] Unit tests for model construction and validation

### Pattern catalog
- [x] `patterns.py` — load all `*.yml` from patterns directory, merge, validate
- [x] `patterns.py` — filter patterns by platform
- [x] `patterns.py` — enforce globally unique IDs across files
- [x] Split `cicd-attack-patterns.yml` from disclosures project into per-class files:
  - [x] `patterns/expression-injection.yml`
  - [x] `patterns/artifact-trust.yml`
  - [x] `patterns/dangerous-triggers.yml`
  - [x] `patterns/output-injection.yml`
  - [x] `patterns/supply-chain.yml`
  - [x] `patterns/self-hosted-runners.yml`
  - [x] `patterns/secret-exposure.yml`
  - [x] `patterns/template-injection.yml`
- [x] Add `platforms` field to each pattern (default: all)
- [x] `patterns/schema.json` — JSON Schema for pattern structure
- [x] Unit tests: load catalog, validate schema, reject bad patterns, detect duplicate IDs

### Pattern engine
- [x] `engine.py` — single_step pattern matching (regex in specific block types)
- [x] `engine.py` — structural pattern matching (trigger checks, permission checks, checkout ref analysis)
- [x] `engine.py` — platform_rules handling (pick rules for current provider)
- [x] Unit tests for each pattern type against vulnerable + safe fixtures

### Severity + environment profiles
- [x] `severity.py` — stage 1: static severity from base + trigger + runner + secrets + permissions + fork_reachable
- [x] `severity.py` — stage 2: adjust by environment profile (suppress, elevate, modifier rules)
- [x] `severity.py` — output both static_severity and computed_severity in results
- [x] `profiles.py` — load profile from `.actionsieve.yml`, `~/.config/actionsieve/profile.yml`, or `--profile`
- [ ] `profiles.py` — profile schema validation
- [x] `profiles.py` — built-in presets: hosted-public, hosted-private, self-hosted, hardened
- [x] `profiles.py` — `extends:` support (inherit preset, override specific fields)
- [x] `profiles.py` — suppress/elevate category handling
- [x] `cli.py` — `--profile` flag (path or preset name)
- [x] `cli.py` — `--show-suppressed` flag (include suppressed findings in output)
- [x] Unit tests: same pattern, different contexts → different severities
- [x] Unit tests: same finding, different profiles → different computed severities
- [x] Unit tests: suppress category hides findings, --show-suppressed reveals them

### Output
- [x] `output.py` — JSON output (findings list)
- [x] `output.py` — YAML output
- [x] `output.py` — SARIF output (for GitHub code scanning integration)
- [x] Unit tests for each output format

### CLI
- [x] `cli.py` — `actionsieve scan <path>` command
- [x] `cli.py` — `--platform` flag (auto-detect by default)
- [x] `cli.py` — `--format` flag (json, yaml, sarif)
- [x] `cli.py` — `--output` flag (write to file instead of stdout)
- [x] `cli.py` — `--patterns` flag (custom catalog path, directory or file)
- [x] `cli.py` — `--profile` flag (path or preset name)
- [x] `cli.py` — `--fail-on` flag (warning, critical, etc.)
- [x] `cli.py` — `--show-suppressed` flag
- [x] `cli.py` — `--diff <base-ref>` flag (scan only changed pipeline files)
- [x] `cli.py` — `--offline` flag (skip network calls in resolve_ref)
- [x] `cli.py` — exit codes (0/1/2/3)
- [x] E2E tests: scan fixture repos, verify exit codes and output
- [ ] E2E tests: --diff mode only reports findings in changed files
- [x] E2E tests: --profile adjusts severity and suppresses as expected

### Test fixtures (GitHub)
- [x] Vulnerable: expression injection in run block
- [x] Vulnerable: pull_request_target + checkout head
- [x] Vulnerable: unpinned third-party action
- [x] Vulnerable: self-hosted runner with secrets
- [x] Safe: expression injection mitigated via env var indirection
- [x] Safe: pull_request_target with base-only checkout
- [x] Safe: all actions pinned to SHA
- [x] Safe: minimal permissions, no secrets

## Phase 2: Component inventory + supply chain

- [x] `inventory.py` — parse all `uses:` refs from WorkflowModel
- [x] `inventory.py` — classify ref type (sha, tag, branch)
- [x] `inventory.py` — detect first-party (actions/*, github/*)
- [ ] `inventory.py` — recursive composite action resolution
- [x] `advisories.py` — load advisory database (abom-advisories YAML format)
- [x] `advisories.py` — match components against advisories
- [x] `trust.py` — trust score computation (ref type, owner, advisory, popularity)
- [x] `cli.py` — `actionsieve inventory <path>` command
- [x] `cli.py` — `actionsieve inventory --check <path>` command
- [x] `output.py` — CycloneDX SBOM output
- [x] Unit tests for inventory, advisories, trust
- [x] E2E tests for inventory commands

## Phase 3: Chain detection

- [ ] `chains.py` — cross-step data flow (GITHUB_OUTPUT → expression interpolation)
- [ ] `chains.py` — cross-job data flow (job outputs → needs → expression)
- [ ] `chains.py` — checkout ref analysis (what code is checked out, fork-controlled?)
- [ ] `chains.py` — taint propagation through env vars
- [ ] `chains.py` — GITHUB_ENV injection detection
- [ ] `engine.py` — cross_step and cross_job pattern matching using chain analysis
- [ ] Vulnerable fixtures: multi-step chains (readdirSync→output→matrix→shell)
- [ ] Safe fixtures: chains broken by env var indirection
- [ ] Unit tests for chain tracing
- [ ] E2E tests for chain detection findings

## Phase 4: GitLab CI + Azure Pipelines

- [ ] `providers/gitlab.py` — full provider implementation
- [ ] GitLab fixtures (vulnerable + safe)
- [ ] GitLab-specific patterns (CI_JOB_TOKEN, trigger injection, include remote)
- [ ] `providers/azure.py` — full provider implementation
- [ ] Azure fixtures (vulnerable + safe)
- [ ] Azure-specific patterns (template expressions, service connections)
- [ ] Cross-platform pattern coverage tests (same pattern, multiple platforms)

## Phase 5: Forge search

- [ ] `search.py` — query generator from pattern catalog (per-provider)
- [ ] `search.py` — GitHub: `gh search code` with rate limiting + pagination
- [ ] `search.py` — GitLab: API search integration
- [ ] `search.py` — result dedup, caching, candidate prioritization
- [ ] `search.py` — clone-and-scan pipeline
- [ ] `cli.py` — `actionsieve search <org>` and `actionsieve search --all <pattern>`
- [ ] E2E tests (mocked API responses)

## Phase 6: Jenkins + reporting + polish

- [ ] `providers/jenkins.py` — declarative pipeline parser (regex-based)
- [ ] Jenkins fixtures (vulnerable + safe)
- [ ] Jenkins-specific patterns (shared library injection, sandbox escape)
- [ ] `output.py` — Markdown report generation
- [ ] CI wrapper distribution (GitHub Action YAML, GitLab template, Azure task)
- [ ] Pattern catalog versioning and update mechanism
- [ ] Interactive TUI for triaging search results (textual or rich)
- [ ] Groovy AST parser for scripted Jenkins pipelines (stretch)

## Ongoing

- [ ] Keep pattern catalog updated as new attack patterns are discovered
- [ ] Keep advisory database updated (new compromised actions/components)
- [ ] Dogfood: scan actionsieve's own CI workflows with actionsieve
