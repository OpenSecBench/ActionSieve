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
- [x] `profiles.py` — profile schema validation
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
- [x] E2E tests: --diff mode only reports findings in changed files
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
- [x] `inventory.py` — recursive composite action resolution
- [x] `advisories.py` — load advisory database (abom-advisories YAML format)
- [x] `advisories.py` — match components against advisories
- [x] `trust.py` — trust score computation (ref type, owner, advisory, popularity)
- [x] `cli.py` — `actionsieve inventory <path>` command
- [x] `cli.py` — `actionsieve inventory --check <path>` command
- [x] `output.py` — CycloneDX SBOM output
- [x] Unit tests for inventory, advisories, trust
- [x] E2E tests for inventory commands

## Phase 3: Chain detection

- [x] `chains.py` — cross-step data flow (GITHUB_OUTPUT → expression interpolation)
- [x] `chains.py` — cross-job data flow (job outputs → needs → expression)
- [x] `chains.py` — checkout ref analysis (what code is checked out, fork-controlled?)
- [x] `chains.py` — taint propagation through env vars
- [x] `chains.py` — GITHUB_ENV injection detection
- [x] `engine.py` — cross_step and cross_job pattern matching using chain analysis
- [x] Vulnerable fixtures: multi-step chains (readdirSync→output→matrix→shell)
- [x] Safe fixtures: chains broken by env var indirection
- [x] Unit tests for chain tracing
- [x] E2E tests for chain detection findings

## Phase 4: GitLab CI + Azure Pipelines

- [x] `providers/gitlab.py` — full provider implementation
- [x] GitLab fixtures (vulnerable + safe)
- [x] GitLab-specific patterns (CI_JOB_TOKEN, trigger injection, include remote)
- [x] `providers/azure.py` — full provider implementation
- [x] Azure fixtures (vulnerable + safe)
- [x] Azure-specific patterns (template expressions, service connections)
- [x] Cross-platform pattern coverage tests (same pattern, multiple platforms)

## Phase 5: Forge search

- [x] `search.py` — ForgeBackend protocol + GitHub/GitLab backends
- [x] `search.py` — GitHub REST API: code search + org repo listing with rate limiting + pagination
- [x] `search.py` — GitLab REST API: group project listing + blob search with project cache
- [x] `search.py` — result dedup by repo, fork filtering
- [x] `search.py` — clone-and-scan pipeline (shallow clone → scanner.scan → stream results)
- [x] `cli.py` — `actionsieve search <org>` and `actionsieve search --pattern <id>`
- [x] Token resolution: `--token`, `ACTIONSIEVE_GITHUB_TOKEN`, `GITHUB_TOKEN` (same for GitLab)
- [x] Unit + E2E tests (mocked API responses)

## Phase 6: Jenkins + reporting + polish

- [x] `providers/jenkins.py` — declarative pipeline parser (regex-based → tree-sitter)
- [x] `providers/jenkins_ast.py` — tree-sitter Groovy AST walker
- [x] Jenkins fixtures (vulnerable + safe, declarative + scripted + script-block)
- [x] Jenkins-specific patterns (parameter injection, change variable injection)
- [x] Scripted pipeline support (node {}, script {} blocks, sh named args)
- [x] `output.py` — Markdown report generation (Jinja2 template)
- [x] CI wrapper distribution (GitHub Action YAML, GitLab template, Azure task)
- [ ] Pattern catalog versioning and update mechanism
- [ ] Interactive TUI for triaging search results (textual or rich)

## Phase 7: Additional platforms

### CircleCI
- [x] `providers/circleci.py` — detect `.circleci/config.yml`, parse to WorkflowModel
- [x] Orb references as ComponentRef (supply chain vector — unpinned orbs, volatile tags)
- [x] Context-based secret scoping analysis
- [x] Expression injection in `run:` steps (environment variable interpolation)
- [x] `config.yml` processing/dynamic config (`setup: true`, continuation orb)
- [x] CircleCI fixtures (vulnerable + safe)
- [x] CircleCI-specific patterns (orb trust, context leaks, self-hosted runner)
- [x] Unit + E2E tests

### Bitbucket Pipelines
- [x] `providers/bitbucket.py` — detect `bitbucket-pipelines.yml`, parse to WorkflowModel
- [x] Pipe references as ComponentRef (supply chain — unpinned pipe tags)
- [x] Variable injection in `script:` steps
- [x] Self-hosted runner detection (Bitbucket Runners)
- [x] Repository variable / deployment variable scoping
- [x] Bitbucket fixtures (vulnerable + safe)
- [x] Bitbucket-specific patterns (pipe trust, variable injection)
- [x] Unit + E2E tests

### Buildkite
- [x] `providers/buildkite.py` — detect `pipeline.yml` / `.buildkite/`, parse to WorkflowModel
- [x] Plugin references as ComponentRef (supply chain)
- [x] Dynamic pipeline upload injection (`buildkite-agent pipeline upload`)
- [x] Environment variable injection in `command:` steps
- [x] Buildkite fixtures (vulnerable + safe)
- [x] Unit + E2E tests

### Drone / Harness CI
- [x] `providers/drone.py` — detect `.drone.yml`, parse to WorkflowModel
- [x] Plugin image references as ComponentRef
- [x] Variable injection in `commands:`
- [x] Drone fixtures (vulnerable + safe)
- [x] Unit + E2E tests

### Cloud vendor CI
- [x] `providers/codebuild.py` — AWS CodeBuild `buildspec.yml`
- [x] `providers/cloudbuild.py` — Google Cloud Build `cloudbuild.yaml`
- [x] IAM/secret misconfig patterns for cloud-native CI

## Backlog — from corpus testing

- [x] Composite action scanning — resolve `uses: ./path` to `action.yml`, scan composite steps for injection
- [x] Reusable workflow ref pinning — extend `mutable-action-ref` to job-level `uses:` for reusable workflow refs
- [x] Missing `permissions:` block — flag GitHub workflows without top-level or job-level `permissions:` (`patterns/hardening.yml`)
- [x] Checkout `persist-credentials` — flag `actions/checkout` without `persist-credentials: false` (`patterns/hardening.yml`)
- [x] SHA pin verification — verify pinned SHA belongs to the referenced repo, pin is not outdated. `--online` mode in scan and inventory. `api_client.py` for shared HTTP/caching, `pins.py` for verification logic. Offline `truncated-sha-pin` pattern for short SHA refs. Severity `info` (outdated/untagged) to `medium` (wrong-repo SHA). TODO: stale trailing comment detection, GitLab/Azure forge support.
- [x] Advisory matching during scan — `action-version-advisory` pattern checks refs against bundled advisory database during scan

## Backlog — ideas from plumber

- [x] `actionsieve explain <pattern-id>` — CLI subcommand that pretty-prints a pattern's full details (description, attack scenario, mitigations, references, CWE). Helps triage findings without leaving the terminal.
- [x] Container image pinning — detect unpinned container images (`image: node:20` vs `image: node@sha256:...`) as supply chain risk. All six providers extract `Job.image` and structural matcher flags missing `@sha256:` digest. Pattern file `patterns/container-images.yml`.
- [x] Unverified script execution — detect `curl | bash`, `wget | sh`, `base64 -d | sh` and similar pipe-to-shell patterns in run blocks. Universal grep pattern across all platforms. New pattern file `patterns/unsafe-scripts.yml`.
- [x] Docker-in-Docker detection — flag `docker run` / `docker build` inside CI steps, GitLab `services: [docker:dind]`, `--privileged` containers. Privilege escalation vector on shared runners.
- [x] `actionsieve profile resolve` — CLI subcommand that prints the effective profile after overlay resolution. Debugging aid for custom profile configs.
- [x] OCSF output format — OCSF Detection Finding (class_uid 2004, schema 1.4.0) for GRC platform integration. `--format ocsf` in CLI.
- [x] Static cloud credentials detection — flag long-lived AWS access keys (`AWS_ACCESS_KEY_ID`), GCP service account JSON, Azure client secrets in env/secrets when OIDC federation is available (`aws-actions/configure-aws-credentials` with `role-to-assume`, `google-github-actions/auth` with `workload_identity_provider`). OIDC is the secure path; static keys are a secret exposure risk. New pattern file `patterns/cloud-credentials.yml`.
- [x] Cache poisoning detection — flag CI cache writes (`actions/cache`, `save_cache`, `cache:` directives) in workflows reachable from fork PRs. Attacker-controlled fork can poison the cache with malicious build artifacts or dependencies that persist into trusted branch builds. Structural matcher: cache save step + fork-reachable trigger.

## Phase 8: Diff-aware scanning (PR mode)

Full spec + design decisions: `../actionsieve-corpus/bugs/diff-aware-scanning.md`

### Step 1: Rename `--diff` to `--changed-since`
- [x] Rename CLI option `--diff` → `--changed-since` in `cli.py`
- [x] Remove `--diff` (no external consumers)
- [x] Rename `diff_base` parameter through `scanner.py`
- [x] Fix silent fallback: error when git unavailable or ref invalid (not scan everything)
- [x] Update E2E tests referencing `--diff`
- [x] Tests for error cases (bad ref, not a repo)

### Step 2: Pattern schema changes
- [x] Add optional `diff_scope` (`always` | `changeset`) to `patterns/schema.json`
- [x] Add optional `diff_effect` (`suppress` | `elevate`) to `patterns/schema.json`
- [x] Add optional `reachable_files` (array of glob strings) to `patterns/schema.json`
- [x] Conditional validation: `diff_scope: changeset` requires `reachable_files` + `diff_effect`
- [x] Schema validation tests

### Step 3: Context module
- [x] `context.py` — `ScanContext` dataclass (changed_files, trigger, actor, mode)
- [x] `--changed-files` parsing: comma-separated inline, or read from file/stdin if value is `-` or a file path
- [x] CI auto-detection: GitHub Actions (`GITHUB_EVENT_NAME`, `GITHUB_BASE_REF`)
- [x] CI auto-detection: GitLab CI (`CI_PIPELINE_SOURCE`, `CI_MERGE_REQUEST_DIFF_BASE_SHA`)
- [x] CI auto-detection: Azure Pipelines (`BUILD_REASON`, `SYSTEM_PULLREQUEST_TARGETBRANCH`)
- [x] CI auto-detection: Jenkins, CircleCI, Bitbucket, Buildkite, Drone
- [x] `detect_ci_context()` — try each platform, return `ScanContext` or `None`
- [x] `--context` file parsing (YAML dict with same fields)
- [x] Precedence: explicit flags > context file > auto-detected > None (static mode)
- [x] Changed files derived via `git diff --name-only` against detected base ref
- [x] Unit tests with mocked env vars for each platform

### Step 4: CLI flags
- [ ] `--changed-files` option in `cli.py`
- [ ] `--trigger` option in `cli.py`
- [ ] `--actor` option in `cli.py`
- [ ] `--context` option in `cli.py` (path to YAML context file)
- [ ] `--mode` option (`static` | `pr`) — force override, default auto
- [ ] Wire flags into `scanner.scan()` via `ScanContext`
- [ ] Conflict handling: `--changed-since` ignored with warning in PR mode
- [ ] E2E tests for new flags

### Step 5: Scanner/engine integration
- [ ] `scanner.scan()` accepts `ScanContext`
- [ ] In PR mode, scan all pipeline files (ignore `--changed-since`)
- [ ] After matching, apply changeset suppression: `diff_scope: changeset` + `diff_effect: suppress` + no reachable file in changeset → suppress with `suppressed_by: changeset`
- [ ] After matching, apply changeset elevation: `diff_scope: changeset` + `diff_effect: elevate` + reachable file in changeset → bump severity one level
- [ ] Glob matching for `reachable_files` against changed-files list (repo-root-relative)
- [ ] `--show-suppressed` includes changeset-suppressed findings
- [ ] Exit code based on unsuppressed findings only (consistent with profile suppression)
- [ ] Coverage note in output when pipeline file count seems low
- [ ] Unit tests: suppress path, elevate path, always-fire path
- [ ] Unit tests: exit code with mixed suppressed/unsuppressed findings

### Step 6: Annotate pattern catalog
- [ ] Review every pattern, assign `diff_scope` (`always` or `changeset`)
- [ ] For `changeset` patterns: add `diff_effect` and `reachable_files` with narrow globs
- [ ] Validate all patterns still load and pass schema
- [ ] Test annotated patterns against existing fixtures (no regressions)

## Ongoing

- [ ] Keep pattern catalog updated as new attack patterns are discovered
- [ ] Keep advisory database updated (new compromised actions/components)
- [ ] Dogfood: scan actionsieve's own CI workflows with actionsieve
