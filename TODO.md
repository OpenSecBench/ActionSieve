# actionsieve — TODO

## Phase 0: Project scaffolding

- [ ] `.gitignore` (Python: __pycache__, *.pyc, .venv/, dist/, *.egg-info/, .mypy_cache/, .ruff_cache/, .pytest_cache/)
- [ ] `pyproject.toml` with project metadata, entry point, dependencies, dev extras:
  - Runtime: click, pyyaml, jsonschema, jinja2
  - Dev: pytest, ruff, mypy, pre-commit
- [ ] `uv.lock` for reproducible builds
- [ ] `.pre-commit-config.yaml` (ruff check, ruff format, mypy, pytest)
- [ ] `ruff.toml` (line length, target version, select rules)
- [ ] `mypy.ini` or pyproject section (strict mode)
- [ ] `patterns/schema.json` — JSON Schema for pattern catalog validation
- [ ] Directory structure: actionsieve/, actionsieve/providers/, tests/unit/, tests/unit/providers/, tests/e2e/, tests/fixtures/
- [ ] Empty `__init__.py` files, basic cli.py with click group
- [ ] Verify: `uv pip install -e ".[dev]" && pytest && ruff check . && mypy actionsieve/`
- [ ] Initial commit

## Phase 1: GitHub Actions scanner (MVP)

### Provider interface + GitHub provider
- [ ] `providers/__init__.py` — Provider Protocol class (detect, find_files, parse, resolve_ref, expression_syntax, search_query)
- [ ] `providers/__init__.py` — auto_detect(repo_path) returns list of matching providers
- [ ] `providers/github.py` — detect: `.github/workflows/` exists
- [ ] `providers/github.py` — find_files: glob `*.yml` + `*.yaml` in `.github/workflows/`
- [ ] `providers/github.py` — parse: YAML → WorkflowModel
- [ ] `providers/github.py` — expression_syntax: `${{ }}` interpolation rules
- [ ] Unit tests for GitHub provider (parse known fixtures, reject malformed)

### Workflow model
- [ ] `model.py` — dataclasses: WorkflowModel, Job, Step, Trigger, Expression, ComponentRef, Permission
- [ ] Platform field on WorkflowModel
- [ ] Normalized block types (shell_command, expression, component_ref)
- [ ] Unit tests for model construction and validation

### Pattern catalog
- [ ] `patterns.py` — load all `*.yml` from patterns directory, merge, validate
- [ ] `patterns.py` — filter patterns by platform
- [ ] `patterns.py` — enforce globally unique IDs across files
- [ ] Split `cicd-attack-patterns.yml` from disclosures project into per-class files:
  - [ ] `patterns/expression-injection.yml`
  - [ ] `patterns/artifact-trust.yml`
  - [ ] `patterns/dangerous-triggers.yml`
  - [ ] `patterns/output-injection.yml`
  - [ ] `patterns/supply-chain.yml`
  - [ ] `patterns/self-hosted-runners.yml`
  - [ ] `patterns/secret-exposure.yml`
  - [ ] `patterns/template-injection.yml`
- [ ] Add `platforms` field to each pattern (default: all)
- [ ] `patterns/schema.json` — JSON Schema for pattern structure
- [ ] Unit tests: load catalog, validate schema, reject bad patterns, detect duplicate IDs

### Pattern engine
- [ ] `engine.py` — single_step pattern matching (regex in specific block types)
- [ ] `engine.py` — structural pattern matching (trigger checks, permission checks, checkout ref analysis)
- [ ] `engine.py` — platform_rules handling (pick rules for current provider)
- [ ] Unit tests for each pattern type against vulnerable + safe fixtures

### Severity + environment profiles
- [ ] `severity.py` — stage 1: static severity from base + trigger + runner + secrets + permissions + fork_reachable
- [ ] `severity.py` — stage 2: adjust by environment profile (suppress, elevate, modifier rules)
- [ ] `severity.py` — output both static_severity and computed_severity in results
- [ ] `profiles.py` — load profile from `.actionsieve.yml`, `~/.config/actionsieve/profile.yml`, or `--profile`
- [ ] `profiles.py` — profile schema validation
- [ ] `profiles.py` — built-in presets: hosted-public, hosted-private, self-hosted, hardened
- [ ] `profiles.py` — `extends:` support (inherit preset, override specific fields)
- [ ] `profiles.py` — suppress/elevate category handling
- [ ] `cli.py` — `--profile` flag (path or preset name)
- [ ] `cli.py` — `--show-suppressed` flag (include suppressed findings in output)
- [ ] Unit tests: same pattern, different contexts → different severities
- [ ] Unit tests: same finding, different profiles → different computed severities
- [ ] Unit tests: suppress category hides findings, --show-suppressed reveals them

### Output
- [ ] `output.py` — JSON output (findings list)
- [ ] `output.py` — YAML output
- [ ] `output.py` — SARIF output (for GitHub code scanning integration)
- [ ] Unit tests for each output format

### CLI
- [ ] `cli.py` — `actionsieve scan <path>` command
- [ ] `cli.py` — `--platform` flag (auto-detect by default)
- [ ] `cli.py` — `--format` flag (json, yaml, sarif)
- [ ] `cli.py` — `--output` flag (write to file instead of stdout)
- [ ] `cli.py` — `--patterns` flag (custom catalog path, directory or file)
- [ ] `cli.py` — `--profile` flag (path or preset name)
- [ ] `cli.py` — `--fail-on` flag (warning, critical, etc.)
- [ ] `cli.py` — `--show-suppressed` flag
- [ ] `cli.py` — `--diff <base-ref>` flag (scan only changed pipeline files)
- [ ] `cli.py` — `--offline` flag (skip network calls in resolve_ref)
- [ ] `cli.py` — exit codes (0/1/2/3)
- [ ] E2E tests: scan fixture repos, verify exit codes and output
- [ ] E2E tests: --diff mode only reports findings in changed files
- [ ] E2E tests: --profile adjusts severity and suppresses as expected

### Test fixtures (GitHub)
- [ ] Vulnerable: expression injection in run block
- [ ] Vulnerable: pull_request_target + checkout head
- [ ] Vulnerable: unpinned third-party action
- [ ] Vulnerable: self-hosted runner with secrets
- [ ] Safe: expression injection mitigated via env var indirection
- [ ] Safe: pull_request_target with base-only checkout
- [ ] Safe: all actions pinned to SHA
- [ ] Safe: minimal permissions, no secrets

## Phase 2: Component inventory + supply chain

- [ ] `inventory.py` — parse all `uses:` refs from WorkflowModel
- [ ] `inventory.py` — classify ref type (sha, tag, branch)
- [ ] `inventory.py` — detect first-party (actions/*, github/*)
- [ ] `inventory.py` — recursive composite action resolution
- [ ] `advisories.py` — load advisory database (abom-advisories YAML format)
- [ ] `advisories.py` — match components against advisories
- [ ] `trust.py` — trust score computation (ref type, owner, advisory, popularity)
- [ ] `cli.py` — `actionsieve inventory <path>` command
- [ ] `cli.py` — `actionsieve inventory --check <path>` command
- [ ] `output.py` — CycloneDX SBOM output
- [ ] Unit tests for inventory, advisories, trust
- [ ] E2E tests for inventory commands

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
