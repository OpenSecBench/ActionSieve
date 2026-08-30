# actionsieve

## What this is

A pattern-driven scanner for CI/CD pipeline security. It loads a YAML
catalog of attack patterns and applies them to workflow definitions — GitHub
Actions, GitLab CI, Azure Pipelines, and Jenkins — either locally against a
repo on disk, across forges via code search, or inline as a CI/CD check in
your own pipelines.

The core vulnerability patterns (expression injection, artifact trust,
mutable refs, secret scoping) are platform-agnostic. Each CI platform
expresses them differently, so actionsieve uses a **provider model**: a thin
parsing/normalization layer per platform feeds a single shared detection
engine.

## Modes of operation

```
actionsieve scan <path>                Scan a local repo's pipelines
actionsieve scan --diff <base>         Scan only changed files (CI mode)
actionsieve scan --platform github     Force platform (auto-detected by default)
actionsieve search <org>               Search a GitHub/GitLab org for patterns
actionsieve search --all <pattern>     Search all public repos
actionsieve inventory <path>           Actions/tasks/includes bill of materials
actionsieve inventory --check <path>   BOM + check against advisory database
```

**Auto-detection**: actionsieve detects the CI platform from the repo
structure — `.github/workflows/` (GitHub Actions), `.gitlab-ci.yml`
(GitLab CI), `azure-pipelines.yml` or `.azure-pipelines/` (Azure),
`Jenkinsfile` or `jenkins/` (Jenkins). A repo can use more than one; all
are scanned by default. Override with `--platform`.

**As a CI/CD check** — runs inside any pipeline on every PR that modifies
workflow/pipeline definitions. Fails the check if new dangerous patterns are
introduced. Same model as trufflehog for secrets: catch it before merge.

**As an external audit tool** — runs against a local clone or across an
entire GitHub/GitLab org. Produces a report of all findings, component
inventory, and supply chain risk assessment.

## Tool landscape

### What exists

| Tool | Focus | Strengths | Gaps |
|------|-------|-----------|------|
| **zizmor** (`zizmorcore/zizmor`) | Static analysis for GHA security | Template injection, excessive permissions, dangerous triggers, unpinned actions, impostor commits. SARIF output. | Single-step only — no cross-step/job chain detection. No custom patterns. No action supply chain checks. |
| **actionlint** | Workflow syntax linter | Correctness checks, type checking for expressions, shellcheck integration. | Security is secondary. No adversarial pattern detection. |
| **Gato-X** (`AdnaneKhan/gato-x`) | Offensive GHA enumeration + exploitation | Finds pwn requests, injection, TOCTOU, self-hosted takeover. Scans 35-40K repos in 1-2 hours. Cross-repo workflow analysis. | Requires API access. Fixed ruleset. Focused on exploitation, not audit/compliance. |
| **poutine** (`boostsecurityio/poutine`) | SAST for GHA and GitLab CI | Detects actions with known CVEs, unverified creators. Org-wide scanning. Multi-platform (GHA + GitLab). | No multi-step chain detection. No custom patterns. No Azure/Jenkins. |
| **abom** (`JulietSecurity/abom`) | Actions bill of materials | Recursively resolves all actions including nested composites and reusable workflows. `--check` flags known-compromised actions from `abom-advisories` database. | Inventory only — no vulnerability pattern detection. |
| **plumber** (`getplumber/plumber`) | CI/CD pipeline security scanner | Rego policy engine for GHA + GitLab CI. Configurable controls via `.plumber.yaml`. Many output formats (SARIF, CycloneDX, PBOM, OCSF). Score badges. Official GHA Action and GitLab CI Component. | Two platforms only (GitHub + GitLab). Rego-based rules, not pattern data. No cross-step chain detection. No Azure/Jenkins/CircleCI/Bitbucket. |
| **StepSecurity Harden-Runner** | Runtime EDR for GHA runners | Monitors network egress, file integrity, process activity. Detects anomalous outbound calls. Caught tj-actions and Trivy compromises in real time. | Runtime only — can't prevent, only detect. Requires per-workflow integration. |

### Where actionsieve fits

actionsieve is **not** a replacement for any of these. It complements them:

- **zizmor** catches single-step issues → actionsieve adds chain detection and
  impact classification on top
- **abom** produces action inventory → actionsieve consumes it for supply chain
  risk scoring and advisory checks
- **Gato-X** finds candidates at scale → actionsieve provides deeper local
  analysis with custom patterns
- **plumber** covers GitHub + GitLab with Rego policies → actionsieve adds
  chain detection, more platforms, and YAML-data patterns instead of Rego
- **Harden-Runner** detects at runtime → actionsieve prevents at review time

The unique value:

1. **Multi-step chain detection** — traces data flow across steps, jobs,
   and workflows (e.g., `readdirSync` → `GITHUB_OUTPUT` → `fromJson` →
   matrix → `${{ matrix.x }}` in `run:`).
2. **Impact classification** — same injection sink gets different severity
   based on trigger type, runner type, and available secrets.
3. **Custom patterns** — rules are YAML data, not code. Security
   researchers add patterns from their own findings.
4. **Actions supply chain** — inventory all actions, check against
   advisories, flag unpinned/mutable refs, score trust.
5. **Dual-mode** — works as a CI check (block bad patterns before merge)
   and as an external audit tool (scan at scale).

## Platform providers

### Provider model

Each CI platform implements a common interface that normalizes its pipeline
definitions into a shared workflow model. The detection engine operates on the
normalized model — patterns match the same way regardless of platform.

```
┌────────────────────────────────────────────────────────────────┐
│                     Provider Interface                         │
│                                                                │
│  detect(repo_path) -> bool         Does this repo use me?      │
│  find_files(repo_path) -> [path]   Locate pipeline definitions │
│  parse(file) -> WorkflowModel      Normalize to shared model   │
│  resolve_ref(ref) -> ComponentRef  Resolve external components │
│  search_query(pattern) -> str      Generate forge search query  │
│  expression_syntax() -> Syntax     Expression interpolation fmt │
└────────────────────────────────────────────────────────────────┘
```

### Platform comparison

| Aspect | GitHub Actions | GitLab CI | Azure Pipelines | Jenkins |
|--------|---------------|-----------|-----------------|---------|
| **Config format** | YAML | YAML | YAML | Groovy DSL / Declarative |
| **Expression syntax** | `${{ expr }}` | `$CI_*` env vars, `!reference` | `$[ expr ]`, `$( expr )`, template params | `${params.*}`, `env.*` |
| **External components** | `uses: owner/action@ref` | `include: remote/template`, `component:` | `- task: TaskName@version`, `- template:` | `@Library('name')`, plugin refs |
| **Fork trust model** | Secret withholding for fork PRs, `pull_request` vs `pull_request_target` | Protected variables, protected branches, merge request pipelines | Fork build policies, `trust_forks: false` | Untrusted multibranch, sandbox mode |
| **Dangerous sinks** | `run:` blocks, `github-script` | `script:` blocks, `before_script:`, `after_script:` | `script:` task input, `bash:` | `sh`, `bat`, `powershell` steps |
| **Artifact passing** | `upload-artifact`/`download-artifact`, `workflow_run` | `artifacts:`, `dependencies:`, `needs:` | Pipeline artifacts, `publish`/`download` | `archiveArtifacts`, `stash`/`unstash` |
| **Secret injection** | `${{ secrets.X }}`, env mapping | `$SECRET_VAR` (masked), Vault integration | `$(SecretName)` from variable groups, Key Vault | `withCredentials`, credentials binding |
| **Self-hosted risk** | Shared runners possible, labels only | Shared runners default, tags for selection | Agent pools, self-hosted agents | All runners are self-managed |

### Platform-specific patterns

Some vulnerability patterns exist on all platforms, others are unique:

**Universal patterns** (all platforms):
- Expression injection (user input → string interpolation → shell)
- Mutable external component references (unpinned tags, branches)
- Secret logging/exposure through unmasked output
- Self-hosted runner persistence and escape

**GitHub-specific**:
- `pull_request_target` + checkout head (pwn request)
- `workflow_run` artifact trust gap
- `GITHUB_OUTPUT` / `GITHUB_ENV` delimiter injection
- `fromJson()` → matrix injection

**GitLab-specific**:
- `include: remote` pulling untrusted templates
- `CI_JOB_TOKEN` scope abuse (default project access)
- Merge request pipeline vs branch pipeline confusion
- `trigger:` downstream pipeline injection
- Parent-child pipeline secret leaking
- `rules:` vs `only:/except:` evaluation differences

**Azure-specific**:
- Template expression injection (`$[ ]` compile-time vs `$( )` runtime)
- Service connection scope abuse
- Variable group secret extraction
- Decorators/gates bypass
- Pipeline resource authorization (all pipelines vs specific)

**Jenkins-specific**:
- Shared library injection (untrusted `@Library` override)
- Groovy sandbox escape
- Agent label manipulation
- `readTrusted` vs `readFile` confusion
- Credentials binding in untrusted contexts
- Declarative vs scripted pipeline trust differences

### Provider implementation priority

1. **GitHub Actions** — our existing patterns, deepest expertise, most research
2. **GitLab CI** — YAML-based (similar parsing), widely used, unique patterns
3. **Azure Pipelines** — YAML-based, enterprise-heavy, template expression quirks
4. **Jenkins** — Groovy parsing challenge, but massive install base

### Parsing strategy

GitHub, GitLab, Azure: standard YAML parsing with platform-specific schema
validation. Jenkins requires either:
- **Groovy AST parsing** via a JVM helper or tree-sitter grammar
- **Regex heuristics** for the declarative subset (covers ~70% of Jenkinsfiles)
- **Hybrid**: declarative parser + AST for scripted blocks

MVP ships with the declarative regex parser; full Groovy AST is Phase 5+.

## Security of actionsieve itself

actionsieve scans for CI/CD vulnerabilities — it must not introduce any.

### Fork PR safety

When actionsieve runs as a CI check, a fork PR could attempt to:
- Modify the actionsieve workflow to skip checks or exfiltrate secrets
- Modify pattern files to suppress detections
- Add workflow files designed to crash the parser (DoS / resource exhaustion)

**Mitigations built into the reference workflow:**

1. **Use `pull_request`, never `pull_request_target`** — the check runs in
   the fork's context with read-only `GITHUB_TOKEN` and no repo secrets.
   The fork can modify the workflow file in their PR, but it runs with no
   privileges. This is the safe default.

2. **Pin all action refs to SHA** — the reference workflow pins every
   `uses:` to a full SHA. No mutable tags. Practice what we preach.

3. **Pattern catalog loaded from base branch** — when running in CI diff
   mode, patterns are loaded from the base branch (main), not from the PR
   head. A fork PR that modifies `patterns/*.yml` to whitelist their payload
   gets the unmodified patterns applied. Implementation:
   ```yaml
   - uses: actions/checkout@<sha>
     with:
       ref: ${{ github.event.pull_request.base.sha }}
       path: actionsieve-base
       sparse-checkout: patterns
   ```

4. **Scan scope is workflow YAML only** — the parser reads `.yml`/`.yaml`
   files in known CI directories. It does not execute anything from the
   repo, `import` repo code, or `eval` any content. YAML parsing uses
   `safe_load` (no arbitrary object construction). Malformed YAML is
   caught and reported, not crashed on.

5. **Resource limits** — file size cap (1MB per workflow file), recursion
   depth limit for composite action resolution, timeout on the scan itself.

### Reference CI workflows

**GitHub Actions** (safe for public repos with fork PRs):

```yaml
# .github/workflows/actionsieve.yml
name: actionsieve
on:
  pull_request:
    paths:
      - '.github/workflows/**'
      - '.github/actions/**'

permissions:
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<sha>

      - uses: actions/checkout@<sha>
        with:
          ref: ${{ github.event.pull_request.base.sha }}
          path: _actionsieve_base
          sparse-checkout: patterns

      - name: Install actionsieve
        run: pip install actionsieve

      - name: Scan workflow changes
        run: |
          actionsieve scan . \
            --patterns _actionsieve_base/patterns/ \
            --diff ${{ github.event.pull_request.base.sha }} \
            --format sarif \
            --output results.sarif

      - name: Check exit code
        run: |
          actionsieve scan . \
            --patterns _actionsieve_base/patterns/ \
            --diff ${{ github.event.pull_request.base.sha }} \
            --fail-on warning
```

**GitLab CI** (safe for merge requests from forks):

```yaml
# .gitlab-ci.yml (or included template)
actionsieve:
  stage: test
  image: python:3.12-slim
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
      changes:
        - .gitlab-ci.yml
        - .gitlab/**/*
  script:
    - pip install actionsieve
    - git fetch origin $CI_MERGE_REQUEST_TARGET_BRANCH_NAME
    - actionsieve scan . --platform gitlab
        --diff origin/$CI_MERGE_REQUEST_TARGET_BRANCH_NAME
        --fail-on warning
```

**Azure Pipelines**:

```yaml
# azure-pipelines.yml (template for PR validation)
trigger: none
pr:
  paths:
    include:
      - azure-pipelines.yml
      - .azure-pipelines/*

pool:
  vmImage: ubuntu-latest

steps:
  - checkout: self
  - script: |
      pip install actionsieve
      actionsieve scan . --platform azure \
        --diff $(System.PullRequest.TargetBranch) \
        --fail-on warning
    displayName: actionsieve scan
```

### What the reference workflows do NOT do

- No `pull_request_target` — no privileged context for fork PRs
- No secrets in the scan job — nothing to exfiltrate
- No checkout of fork code for pattern loading — base branch only
- No `actions/github-script` — no expression injection surface
- No `workflow_run` follow-up — no artifact trust gap
- No write permissions beyond `contents: read`

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                         CLI (actionsieve)                     │
│                                                              │
│  actionsieve scan <path>               Local repo scan       │
│  actionsieve scan --diff <base>        CI mode (changes only)│
│  actionsieve scan --platform <name>    Force platform         │
│  actionsieve search <org>              Forge-wide search      │
│  actionsieve inventory <path>          Component BOM          │
│  actionsieve inventory --check <path>  BOM + advisory check   │
└────────┬──────────┬──────────┬──────────┬────────────────────┘
         │          │          │          │
         ▼          ▼          ▼          ▼
┌──────────────────────────────────────────────────────────────┐
│                    Platform Providers                         │
│                                                              │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐            │
│  │ GitHub  │ │ GitLab  │ │ Azure   │ │ Jenkins │            │
│  │ Actions │ │ CI      │ │ Pipes   │ │         │            │
│  └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘            │
│       │           │           │           │                  │
│  Each provider:                                              │
│    detect(path) — auto-detect from repo structure            │
│    find_files(path) — locate pipeline definitions            │
│    parse(file) → WorkflowModel (shared format)               │
│    resolve_ref(ref) → ComponentRef                           │
│    search_query(pattern) → forge search string               │
│    expression_syntax() → interpolation rules                 │
└───────┬──────────────────────────────────────────────────────┘
        │ normalized WorkflowModel
        ▼
┌──────────────────────────────────────────────────────────────┐
│                      Pattern Engine                           │
│                                                              │
│  Loads YAML catalog (patterns/*.yml)                          │
│  Each pattern has:                                            │
│    - platforms: [github, gitlab, azure, jenkins]             │
│    - detection rules (grep, AST checks, chain defs)          │
│    - attacker model (fork_pr, contributor, admin)             │
│    - impact class (rce, secret_exfil, supply_chain)          │
│    - severity modifiers (self-hosted, secrets in env)         │
│                                                              │
│  Pattern types:                                              │
│    - single_step: grep/regex match in one step                │
│    - cross_step: data flows from step A to step B             │
│    - cross_job: data flows from job A to job B                │
│    - structural: pipeline-level properties                    │
│    - supply_chain: external component reference properties    │
└───────┬──────────────────────────────────────────────────────┘
        │
        ▼
┌──────────────────────────────────────────────────────────────┐
│                      Workflow Model                           │
│  (normalized — same structure regardless of platform)         │
│                                                              │
│    - platform: github | gitlab | azure | jenkins             │
│    - triggers with event types and trust context              │
│    - permissions / scopes (normalized per platform)           │
│    - jobs/stages with steps, data flow graph                  │
│    - runner labels (managed vs self-hosted)                   │
│    - secret references and env var propagation                │
│    - expressions with platform-specific interpolation rules   │
│    - external component refs with resolution metadata:        │
│        source, ref, type (sha/tag/branch/version),           │
│        resolved_sha, is_pinned, is_first_party               │
└───────┬──────────────────────────────────────────────────────┘
        │
        ▼
┌──────────────────────────────────────────────────────────────┐
│                      Results / Output                         │
│                                                              │
│  Findings:                                                   │
│    - pattern_id, platform, file, line, severity               │
│    - attacker_model, impact_class, chain, evidence            │
│                                                              │
│  Component Inventory:                                        │
│    - All external refs with type, pinned status, trust score  │
│    - Advisory matches (known compromised components)          │
│    - Nested resolution (composites, templates, shared libs)   │
│                                                              │
│  Formats: JSON, YAML, Markdown, SARIF, CycloneDX (SBOM)      │
└──────────────────────────────────────────────────────────────┘
```

## Scanner orchestration

`scanner.py` is the glue. It connects providers, engine, severity, profiles,
and output in a fixed pipeline:

```
scan(repo_path, options):
  1. providers = auto_detect(repo_path)        # or [get_provider(options.platform)]
  2. profile = load_profile(options.profile)    # CLI flag, .actionsieve.yml, or default
  3. patterns = load_patterns(options.patterns) # glob *.yml, validate schema, filter by platform
  4. for provider in providers:
  5.   files = provider.find_files(repo_path)
  6.   if options.diff:
  7.     files = filter_changed(files, options.diff_base)
  8.   for file in files:
  9.     model = provider.parse(file)            # YAML → WorkflowModel
  10.    matches = engine.match(model, patterns) # pattern matching + chain detection
  11.    for match in matches:
  12.      match.static_severity = severity.compute_static(match, model)
  13.      match.severity = severity.apply_profile(match.static_severity, profile)
  14.  findings = dedupe_and_sort(all_matches)
  15.  output.render(findings, options.format, options.output_file)
  16.  return exit_code(findings, profile, options.fail_on)
```

`inventory` follows a similar pipeline but calls `provider.resolve_ref()`
for each component reference and checks against the advisory database.
`resolve_ref()` is called during inventory only (not during scan) and may
make network calls (GitHub/GitLab API) to resolve tags to SHAs. In offline
mode (`--offline`), it skips resolution and reports refs as-is.

## Workflow model (dataclass spec)

The normalized model that all providers produce. These are the concrete
fields an implementer should create as Python dataclasses.

```python
@dataclass
class WorkflowModel:
    platform: str                        # "github" | "gitlab" | "azure" | "jenkins"
    file_path: str                       # path relative to repo root
    raw: dict                            # original parsed YAML (for evidence/context)
    triggers: list[Trigger]
    permissions: Permissions | None       # workflow-level permissions
    env: dict[str, str]                  # workflow-level env vars
    jobs: list[Job]

@dataclass
class Trigger:
    event: str                           # normalized: "pull_request", "push", "merge_request",
                                         #   "workflow_run", "schedule", "manual", "trigger"
    raw_event: str                       # platform-specific: "pull_request_target",
                                         #   "merge_request_event", "pr_validation", etc.
    filters: dict                        # paths, branches, types, etc.
    is_privileged: bool                  # does this trigger run with secrets for fork PRs?
                                         #   True for pull_request_target, workflow_run, push
    is_fork_reachable: bool              # can an external fork trigger this?

@dataclass
class Permissions:
    contents: str | None                 # "read" | "write" | "none"
    issues: str | None
    pull_requests: str | None
    actions: str | None
    security_events: str | None
    raw: dict                            # platform-specific permissions/scopes

@dataclass
class Job:
    id: str                              # job key/name
    name: str | None                     # display name
    runner: Runner
    permissions: Permissions | None       # job-level override
    env: dict[str, str]                  # job-level env vars
    needs: list[str]                     # job dependencies (normalized from needs/dependsOn)
    outputs: dict[str, str]              # declared outputs (key → expression)
    steps: list[Step]
    secrets_referenced: list[str]        # secret names used anywhere in this job
    conditions: list[str]               # if: conditions on the job

@dataclass
class Runner:
    labels: list[str]                    # ["ubuntu-latest"] or ["self-hosted", "linux"]
    is_self_hosted: bool                 # True if self-hosted label present
    is_managed: bool                     # True if known managed runner (ubuntu-*, windows-*, macos-*)
    raw: str | list[str]                 # original runs-on / tags / pool value

@dataclass
class Step:
    index: int                           # 0-based position in job
    id: str | None                       # step id (for output references)
    name: str | None                     # display name
    type: str                            # "shell" | "action" | "script"
    shell_command: str | None            # run: block content (GitHub), script: content (GitLab/Azure)
    action_ref: ComponentRef | None      # uses: reference (if type == "action")
    inputs: dict[str, str]              # with: inputs (action steps) or task inputs
    env: dict[str, str]                  # step-level env vars
    outputs_written: list[str]           # GITHUB_OUTPUT keys written (detected by >> "$GITHUB_OUTPUT")
    expressions: list[Expression]        # all ${{ }} or equivalent expressions found in this step
    conditions: list[str]               # if: conditions on the step

@dataclass
class Expression:
    raw: str                             # "${{ github.event.pull_request.title }}"
    context_path: str                    # "github.event.pull_request.title"
    location: str                        # "run" | "env" | "with" | "if" | "name"
    is_in_shell: bool                    # True if inside a run:/script: block (injection risk)
    is_tainted: bool                     # True if references user-controllable input
    line: int                            # line number in the file

@dataclass
class ComponentRef:
    raw: str                             # "actions/checkout@abc123" or "include: remote: ..."
    owner: str | None                    # "actions"
    name: str                            # "checkout"
    ref: str                             # "abc123" or "v4" or "main"
    ref_type: str                        # "sha" | "tag" | "branch" | "version" | "unknown"
    is_pinned: bool                      # True if ref_type == "sha"
    is_first_party: bool                 # True if owner in platform's first-party list
    resolved_sha: str | None             # filled by resolve_ref() during inventory
    line: int                            # line number in the file
```

## Severity scale

Five levels, used for both `severity_base` on patterns and computed severity:

```
critical  — RCE with secrets, supply chain compromise, credential exfiltration
high      — RCE without secrets, write access to repo/issues/PRs, secret exposure
medium    — information disclosure, workflow state manipulation, cache poisoning
low       — resource abuse, minor information leak, ephemeral runner RCE (read-only)
info      — style issue, best practice violation, no direct security impact
```

Numeric mapping for modifier arithmetic: info=0, low=1, medium=2, high=3,
critical=4. Profile modifiers add/subtract from this. Clamped to [0, 4].

Pattern `severity_base` uses these same levels. Examples:
- Expression injection in `run:` block → `severity_base: high`
  (adjusted to critical if secrets in scope, low if fork PR + ephemeral runner)
- Unpinned third-party action → `severity_base: medium`
  (adjusted to critical if advisory match)
- Self-hosted runner persistence → `severity_base: high`
  (adjusted to info if profile says ephemeral runners)

## Provider interface detail

```python
class Provider(Protocol):
    name: str                                    # "github", "gitlab", "azure", "jenkins"

    def detect(self, repo_path: Path) -> bool:
        """Does this repo contain pipeline definitions for this platform?"""

    def find_files(self, repo_path: Path) -> list[Path]:
        """Return all pipeline definition files."""

    def parse(self, file_path: Path) -> WorkflowModel:
        """Parse a pipeline definition file into a normalized WorkflowModel.
        Uses yaml.safe_load(). Raises ParseError on malformed input."""

    def resolve_ref(self, ref: ComponentRef) -> ComponentRef:
        """Resolve a mutable ref to a SHA via API. Network call.
        Returns the ref unchanged if resolution fails or --offline."""

    def expression_syntax(self) -> ExpressionSyntax:
        """Return the expression interpolation rules for this platform."""

    def search_query(self, pattern: Pattern) -> str | None:
        """Generate a forge-native code search query for this pattern.
        Returns None if the pattern can't be searched remotely."""

@dataclass
class ExpressionSyntax:
    delimiters: tuple[str, str]          # ("${{", "}}") for GitHub, ("$[", "]") for Azure
    env_prefix: str | None               # "$CI_" for GitLab, None for GitHub
    context_roots: list[str]             # ["github", "env", "secrets", "steps", "needs", "matrix"]
    tainted_roots: list[str]             # ["github.event"] — user-controllable context paths
    safe_indirection: list[str]          # ["env"] — passing through env var neutralizes injection
```

## Complete pattern example

A full pattern with every required and optional field, for reference when
writing new patterns or implementing the schema:

```yaml
# In patterns/expression-injection.yml
patterns:
  - id: expr-injection-run-pr-title
    title: "PR title injected into shell command"
    description: >
      The pull request title is interpolated directly into a run: block
      via ${{ github.event.pull_request.title }}, allowing arbitrary
      command injection by any user who can open a PR.
    platforms: [github]
    attacker_model: fork_pr              # fork_pr | contributor | admin | any
    impact: rce                          # rce | secret_exfil | supply_chain |
                                         # repo_write | info_disclosure | dos |
                                         # state_manipulation
    severity_base: high                  # critical | high | medium | low | info
    detection:
      type: single_step
      in_block: shell_command
      match: '${{ github.event.pull_request.title }}'
      grep_patterns:                     # for forge search mode
        - 'github.event.pull_request.title'
    mitigations:
      - "Pass the value through an environment variable instead"
      - "Use an intermediate step that sanitizes the input"
    references:
      - https://securitylab.github.com/resources/github-actions-untrusted-input/
    cwe: CWE-78                          # OS command injection
    tags: [injection, shell, pr-input]
```

## Component supply chain

### Component inventory (BOM)

`actionsieve inventory` produces a bill of materials for all external CI
components used in a repo — GitHub Actions, GitLab CI includes/components,
Azure Pipelines tasks/templates, Jenkins shared libraries and plugins. For
each component reference:

```yaml
actions:
  # GitHub Actions example
  - ref: "actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd"
    platform: github
    owner: actions
    name: checkout
    version: de0fac2e4500dabe0009e67214ff5f5447ce83dd
    ref_type: sha             # sha | tag | branch | version
    tag_comment: "v6.0.2"    # from trailing comment if present
    is_pinned: true
    is_first_party: true      # actions/*, github/*, gitlab-org/*, microsoft/*
    locations:
      - file: .github/workflows/ci.yml
        job: build
        step: 1
        line: 15
    trust_score: high

  # GitLab include example
  - ref: "https://gitlab.com/some-org/templates/-/raw/main/ci.yml"
    platform: gitlab
    owner: some-org
    name: templates/ci.yml
    version: main             # branch ref
    ref_type: branch
    is_pinned: false
    is_first_party: false
    trust_score: low
    risk_factors:
      - unpinned_mutable_ref
      - remote_include

  # Unpinned GitHub Action
  - ref: "some-org/some-action@v2"
    platform: github
    owner: some-org
    name: some-action
    version: v2
    ref_type: tag
    is_pinned: false
    is_first_party: false
    advisory_match: null
    trust_score: low
    risk_factors:
      - unpinned_mutable_ref
      - low_star_count
      - no_verified_creator
```

### Advisory database

`actionsieve inventory --check` queries an advisory database (compatible with
`JulietSecurity/abom-advisories` format) to flag known-compromised components.
Advisory entries track:

```yaml
advisories:
  - action: "tj-actions/changed-files"
    cve: "CVE-2025-30066"
    compromised_versions:
      - ref: "v1"  # tag was moved to malicious commit
        sha_malicious: "0e58ed8671d6b60d0890c21b07f8835ace038e67"
        sha_safe_before: "abc123..."  # last known good
    severity: critical
    description: "Tag pointed to commit that exfiltrated secrets via stdout"
    date_disclosed: "2025-03-15"
    references:
      - https://github.com/advisories/GHSA-xxx

  - action: "aquasecurity/trivy-action"
    cve: "CVE-2026-33634"
    compromised_versions:
      - ref: "v0.28.0"
        sha_malicious: "def456..."
    severity: critical
    date_disclosed: "2026-06-15"
```

### Trust scoring

Each external component gets a trust score based on:

| Factor | Weight | Values |
|--------|--------|--------|
| Ref type | high | sha/digest (good), tag/version (weak), branch (bad) |
| Owner | high | first-party per platform (good), verified (medium), unknown (low) |
| Advisory match | critical | any match → critical risk |
| Stars/usage | low | popularity is a weak signal but nonzero |
| Last updated | low | abandoned components are riskier |
| Permissions requested | medium | components requesting write/admin are riskier |

First-party owner lists per platform:
- **GitHub**: `actions/*`, `github/*`
- **GitLab**: `gitlab-org/*`, `components/*`
- **Azure**: `microsoft/*` tasks, built-in tasks
- **Jenkins**: core steps, `jenkins-infra/*` plugins

## CI/CD integration mode

Reference CI workflows for each platform are in the **Security of
actionsieve itself** section above — they serve as both the recommended
integration pattern and a demonstration of fork-safe CI design.

### Diff mode

`actionsieve scan --diff <base-ref>` scans only pipeline files changed since
`<base-ref>`. This keeps CI fast — no need to re-scan unchanged definitions.
Useful for PR/MR checks where you only care about newly introduced issues.

### Exit codes

```
0 — no findings (or only informational)
1 — findings at warning level or above
2 — findings at critical level
3 — known-compromised component detected (advisory match)
```

### As part of a broader pipeline

actionsieve slots in alongside other security tools:

```
PR/MR opened
  ├── trufflehog — scan for leaked secrets
  ├── actionsieve scan --diff — scan changed pipelines for injection patterns
  ├── actionsieve inventory --check — verify no compromised components
  ├── zizmor — single-step GHA linting (GitHub repos)
  └── dependabot/renovate — keep pinned refs up to date
```

## Pattern engine design

### Pattern organization

Patterns are split across multiple YAML files by attack class (expression
injection, artifact trust, dangerous triggers, etc.). The loader globs all
`*.yml` files in the patterns directory and merges them into a single
catalog. Each file contains a list of patterns under a top-level `patterns:`
key. Pattern IDs must be globally unique across all files.

```yaml
# patterns/expression-injection.yml
patterns:
  - id: expr-injection-run-pr-title
    platforms: [github]
    # ...

  - id: expr-injection-run-mr-title
    platforms: [gitlab]
    # ...

  - id: expr-injection-template-param
    platforms: [azure]
    # ...
```

The `--patterns` CLI flag accepts either a directory (load all `*.yml`
files) or a single file (for backwards compatibility or focused scans).

### Pattern structure

Every pattern declares which platforms it applies to. The engine skips
patterns that don't match the current provider.

```yaml
- id: expr-injection-run
  platforms: [github, gitlab, azure]     # or "all"
  detection:
    type: single_step
    # platform-specific variants under detection.platform_rules
    # or a single rule that the provider normalizes
```

### Pattern types

**Single-step patterns** — match a dangerous string in a specific context.

```yaml
# GitHub: expression in run block
detection:
  type: single_step
  in_block: run                      # normalized: "shell_command"
  match: '${{ github.event.pull_request.title }}'

# GitLab equivalent (same pattern, different syntax):
detection:
  type: single_step
  in_block: script                   # normalized: "shell_command"
  match: '$CI_MERGE_REQUEST_TITLE'   # unquoted in shell
```

When a pattern applies to multiple platforms, it can use normalized block
names (`shell_command`, `expression`, `component_ref`) and the provider
maps them. Or it can specify `platform_rules` with per-platform overrides:

```yaml
detection:
  type: single_step
  in_block: shell_command            # normalized
  platform_rules:
    github:
      match: '${{ github.event.pull_request.title }}'
    gitlab:
      match: '$CI_MERGE_REQUEST_TITLE'
    azure:
      match: '$(System.PullRequest.SourceBranch)'
```

**Cross-step patterns** — trace data flow between steps in the same job.

```yaml
detection:
  type: cross_step
  chain:
    - step: source
      match: '>> "$GITHUB_OUTPUT"'
      captures: [output_name]
    - step: sink
      match: '${{ steps.{source}.outputs.{output_name} }}'
      in_block: run
```

**Cross-job patterns** — trace data flow between jobs via dependencies.

```yaml
detection:
  type: cross_job
  chain:
    - job: producer
      match_output: some_value
      source: untrusted
    - job: consumer
      depends_on: producer           # normalized: needs (GHA), needs (GL), dependsOn (Azure)
      match: '${{ needs.producer.outputs.some_value }}'
      in_block: run
```

**Structural patterns** — check pipeline-level properties.

```yaml
# GitHub: pwn request pattern
detection:
  type: structural
  platforms: [github]
  checks:
    - trigger_includes: pull_request_target
    - has_step:
        uses: actions/checkout
        with_ref_contains: github.event.pull_request.head
    - job_has_secrets: true

# GitLab: include remote template (untrusted source)
detection:
  type: structural
  platforms: [gitlab]
  checks:
    - has_include:
        type: remote
        url_not_match: "^https://gitlab\\.com/your-org/"
```

**Supply chain patterns** — check external component references.

```yaml
detection:
  type: supply_chain
  checks:
    - ref_type: [tag, branch]       # not pinned to SHA/digest
    - not_first_party: true          # not actions/*, gitlab-org/*, microsoft/*
    - advisory_match: any            # known compromised
    - owner_match: "known-bad-org"   # known malicious owner
```

### Data flow analysis

The workflow model tracks taint propagation across all platforms:

- **Taint sources** (platform-normalized):
  - Event context fields (`github.event.*`, `$CI_*`, `$(Build.*))`, `params.*`)
  - Fork-controlled file content (checked-out PR head code)
  - Script output from checked-out code
  - Artifact/dependency content from other pipelines or runs
  - External template/include inputs
- **Taint sinks** (platform-specific, mapped by provider):
  - GitHub: `run:` blocks, `github-script` `script:`, sensitive action inputs
  - GitLab: `script:`, `before_script:`, `after_script:`, `trigger:` inputs
  - Azure: `script:` task input, `bash:`/`powershell:`, template parameters
  - Jenkins: `sh`, `bat`, `powershell` steps, `evaluate()`, `load()`
- **Taint propagation** (platform-normalized):
  - Expression interpolation (syntax per provider)
  - Step/stage output mechanisms
  - Environment variable propagation
  - Job/stage outputs through dependencies
- **Cut-off**: if a value passes through a shell env var (not expression
  interpolation), it's safe from expression injection but may still be
  unsafe if unquoted in shell. Each provider defines what counts as
  "safe indirection" for its platform.

This is practical taint tracking, not formal verification — designed to
catch the patterns we've seen in real-world CI/CD exploitation.

### Severity computation

Severity is computed in two stages: first from what the scanner can observe
in the workflow definition (static context), then adjusted by the user's
environment profile (deployment context).

**Stage 1 — static context** (from the workflow itself):

```
base_severity (from pattern)
  x platform
  x trigger_context:
      github: pull_request | pull_request_target | workflow_run | push
      gitlab: merge_request_event | push | trigger | schedule
      azure:  pr_validation | ci_trigger | manual | template
      jenkins: multibranch_pr | push | manual | cron
  x runner_type (managed | self_hosted — if detectable from labels)
  x secrets_in_scope (none | read_only_token | repo_secrets | env_secrets)
  x permissions (default | elevated)
  x fork_reachable (does this fire for fork PRs/MRs?)
  = static_severity
```

**Stage 2 — environment profile** (from user config):

The static severity is adjusted by the user's environment profile, which
describes what their infrastructure actually looks like. The same finding
can be informational or critical depending on the environment.

```
static_severity
  x profile.runner_isolation     → adjusts runner-related findings
  x profile.fork_policy          → adjusts fork PR attack feasibility
  x profile.secret_backend       → adjusts secret exposure impact
  x profile.network_exposure     → adjusts exfiltration feasibility
  x profile.suppressed_categories → drops entire pattern classes
  = computed_severity
```

### Environment profiles

A profile is a YAML file that describes the user's CI/CD environment:

```yaml
# .actionsieve.yml (repo root) or ~/.config/actionsieve/profile.yml
profile:
  name: our-github-setup

  runners:
    type: ephemeral              # ephemeral | persistent | mixed
    isolation: container         # container | vm | bare_metal | unknown
    network: restricted          # restricted | open | unknown
    # ephemeral + container + restricted = runner persistence and
    # exfiltration findings get downgraded

  forks:
    policy: open                 # open | restricted | disabled
    # open = fork PR attacks are feasible (default for public repos)
    # disabled = fork PR patterns suppressed entirely

  secrets:
    backend: vault               # env_vars | vault | oidc | managed_identity
    rotation: automatic          # automatic | manual | none
    # vault + automatic rotation = secret exposure findings downgraded
    # (still flagged, but attacker window is shorter)

  branch_protection:
    level: strict                # strict | moderate | none
    required_reviews: 2
    # strict = compromised-contributor scenarios are harder

  # Suppress entire pattern categories you don't care about
  suppress:
    - self-hosted-runners        # we don't use self-hosted runners
    - template-injection         # we don't use GitLab includes

  # Elevate specific categories beyond what static analysis says
  elevate:
    - secret-exposure            # we have high-value secrets, treat exposure as critical
```

**Profile resolution order** (first match wins):

1. `--profile <path>` CLI flag
2. `.actionsieve.yml` in the scanned repo root
3. `~/.config/actionsieve/profile.yml` user default
4. Built-in `default` profile (no adjustments)

### Built-in profiles

Presets are platform-agnostic — they describe deployment models, not
forges. A public GitLab SaaS repo has the same risk profile as a public
GitHub repo: ephemeral shared runners, forks enabled, secrets in env vars.
The platform-specific differences (expression syntax, trigger types) are
already handled by providers.

```yaml
# actionsieve scan . --profile hosted-public
profiles:
  hosted-public:
    runners: { type: ephemeral, isolation: container, network: open }
    forks: { policy: open }
    secrets: { backend: env_vars }
    # Public repos on any managed CI (GitHub, GitLab SaaS, Azure
    # Hosted). Fork/MR attacks are feasible. Runner persistence is
    # not a concern. Secret exposure is the primary risk.

  hosted-private:
    runners: { type: ephemeral, isolation: container, network: open }
    forks: { policy: disabled }
    secrets: { backend: env_vars }
    # Private repos on managed CI. Fork/MR patterns suppressed.
    # Focus shifts to compromised contributor and push-triggered
    # issues.

  self-hosted:
    runners: { type: persistent, isolation: bare_metal, network: open }
    forks: { policy: restricted }
    secrets: { backend: env_vars }
    elevate: [self-hosted-runners]
    # Self-managed runners (GitHub self-hosted, GitLab self-managed,
    # Jenkins, Azure self-hosted agents). Runner persistence and
    # escape findings are elevated. Cache poisoning matters.

  hardened:
    runners: { type: ephemeral, isolation: vm, network: restricted }
    forks: { policy: disabled }
    secrets: { backend: oidc, rotation: automatic }
    branch_protection: { level: strict, required_reviews: 2 }
    suppress: [self-hosted-runners]
    # Locked-down environment. Ephemeral VMs, short-lived tokens,
    # network egress restricted, no forks. Most findings get
    # downgraded. Only supply chain and novel chains are critical.
```

Users can also extend a preset with overrides:

```yaml
# .actionsieve.yml
profile:
  extends: self-hosted
  runners:
    isolation: container       # we use Docker, not bare metal
  secrets:
    backend: vault
    rotation: automatic
  suppress:
    - template-injection       # we don't use remote includes
```

### How profiles adjust severity

Each profile dimension maps to a severity modifier:

| Profile dimension | Effect |
|-------------------|--------|
| `runners.type: ephemeral` | Runner persistence findings → informational |
| `runners.type: persistent` | Runner persistence findings → severity +1 |
| `runners.isolation: bare_metal` | Container escape findings → critical |
| `runners.isolation: container` | Container escape findings → informational |
| `runners.network: restricted` | OOB exfiltration findings → downgraded |
| `forks.policy: disabled` | Fork PR attack patterns → suppressed |
| `forks.policy: open` | Fork PR patterns → full severity |
| `secrets.backend: oidc` | Static secret exposure → downgraded (short-lived tokens) |
| `secrets.rotation: automatic` | Secret exposure → severity -1 (reduced window) |
| `suppress: [category]` | All patterns in category → hidden from output |
| `elevate: [category]` | All patterns in category → severity +1 |

Suppressed findings are still detected but excluded from output and don't
affect exit codes. `--show-suppressed` includes them for audit purposes.

Profiles never reduce severity below `informational` or raise it above
`critical`. The raw static severity is always available in JSON/SARIF
output alongside the profile-adjusted severity, so users can compare.

## Forge search mode

### Query generation

Each provider translates pattern `detection.grep_patterns` into
forge-native search queries:

```
# GitHub
"${{ github.event.pull_request.title }}" language:yaml path:.github/workflows

# GitLab (API search)
CI_MERGE_REQUEST_TITLE path:.gitlab-ci.yml
```

### Rate limiting

- GitHub code search: 30 requests/minute (authenticated)
- GitLab API: 10 requests/second (authenticated)

The search mode:

1. Generates queries from patterns via the platform provider
2. Deduplicates by repo
3. Prioritizes by expected signal
4. Caches results
5. Optionally clones candidates for deep local scan

### Search output

```yaml
results:
  - repo: owner/repo
    platform: github
    stars: 15000
    matched_patterns:
      - pattern_id: expr-injection-run
        file: .github/workflows/ci.yml
        line: 42
    scan_status: pending  # pending | scanned | false_positive | confirmed
```

## Implementation plan

### Phase 1: GitHub Actions scanner (MVP)

- [ ] Project setup (Python, click CLI, pyyaml)
- [ ] Provider interface definition
- [ ] GitHub Actions provider (detect, find_files, parse, resolve_ref)
- [ ] Workflow model (normalized representation)
- [ ] Single-step pattern matching
- [ ] Structural pattern matching (triggers, permissions, runner type)
- [ ] Severity computation from context
- [ ] JSON/YAML/SARIF output
- [ ] Load pattern catalog from YAML file
- [ ] Exit codes for CI integration
- [ ] `platform` field on patterns (default: all)

### Phase 2: Component inventory + supply chain

- [ ] Parse all external component refs across pipelines
- [ ] Classify ref type (sha, tag, branch, version)
- [ ] Detect first-party vs third-party
- [ ] Advisory database integration (abom-advisories format)
- [ ] Trust scoring
- [ ] CycloneDX SBOM output
- [ ] `actionsieve inventory` and `actionsieve inventory --check` commands

### Phase 3: Chain detection

- [ ] Cross-step data flow (GITHUB_OUTPUT → expression interpolation)
- [ ] Cross-job data flow (job outputs → needs → expression)
- [ ] Checkout ref analysis (what code is checked out, fork-controlled?)
- [ ] Taint propagation through env vars
- [ ] GITHUB_ENV injection detection

### Phase 4: GitLab CI + Azure Pipelines providers

- [ ] GitLab CI provider (`.gitlab-ci.yml`, `include:`, `!reference`)
- [ ] GitLab-specific patterns (CI_JOB_TOKEN, trigger injection, MR vs branch)
- [ ] Azure Pipelines provider (`azure-pipelines.yml`, templates)
- [ ] Azure-specific patterns (template expressions, service connections)
- [ ] Cross-platform pattern coverage tests

### Phase 5: Forge search

- [ ] Query generator from pattern catalog (per-platform search syntax)
- [ ] GitHub: `gh search code` with rate limiting
- [ ] GitLab: API search integration
- [ ] Result deduplication and caching
- [ ] Candidate prioritization (stars, fork count)
- [ ] Clone-and-scan pipeline

### Phase 6: Jenkins + reporting + polish

- [ ] Jenkins declarative pipeline parser (regex-based)
- [ ] Jenkins-specific patterns (shared library, sandbox escape)
- [ ] Markdown report generation
- [ ] Diff mode (`--diff <base>` for CI)
- [ ] CI wrapper distribution (GitHub Action, GitLab template, Azure task)
- [ ] Pattern catalog versioning and update mechanism
- [ ] Interactive TUI for triaging search results
- [ ] Groovy AST parser for scripted Jenkins pipelines (stretch)

## File structure

```
github-scanner/
├── docs/
│   └── architecture.md              # this file
├── patterns/
│   ├── expression-injection.yml     # ${{ }}, $CI_*, $[ ] injection patterns
│   ├── artifact-trust.yml           # workflow_run artifacts, cross-pipeline deps
│   ├── dangerous-triggers.yml       # pull_request_target, trigger:, etc.
│   ├── output-injection.yml         # GITHUB_OUTPUT/ENV delimiter, step outputs
│   ├── supply-chain.yml             # unpinned refs, mutable tags, advisory matches
│   ├── self-hosted-runners.yml      # persistence, escape, shared runner risks
│   ├── secret-exposure.yml          # logging, env leaks, token scope abuse
│   ├── template-injection.yml       # GitLab include:, Azure templates, Jenkins @Library
│   ├── schema.json                  # JSON Schema for pattern file validation
│   └── advisories/                  # known-compromised component database
│       └── actions.yml
├── actionsieve/
│   ├── __init__.py
│   ├── cli.py                       # click CLI entry point
│   ├── scanner.py                   # local scan orchestration
│   ├── search.py                    # forge search mode
│   ├── inventory.py                 # component bill of materials
│   ├── advisories.py                # advisory database loader + checker
│   ├── trust.py                     # component trust scoring
│   ├── patterns.py                  # pattern catalog loader (globs directory)
│   ├── model.py                     # normalized workflow model
│   ├── engine.py                    # pattern matching engine
│   ├── chains.py                    # cross-step/job data flow analysis
│   ├── severity.py                  # severity computation (static + profile)
│   ├── profiles.py                  # environment profile loader + built-in presets
│   ├── output.py                    # result formatting (JSON, YAML, MD, SARIF, CycloneDX)
│   └── providers/
│       ├── __init__.py              # provider interface + auto-detection
│       ├── github.py                # GitHub Actions provider
│       ├── gitlab.py                # GitLab CI provider
│       ├── azure.py                 # Azure Pipelines provider
│       └── jenkins.py               # Jenkins provider (declarative + scripted)
├── tests/
│   ├── unit/                        # unit tests per module
│   │   ├── test_model.py
│   │   ├── test_engine.py
│   │   ├── test_patterns.py
│   │   ├── test_severity.py
│   │   ├── test_profiles.py
│   │   ├── test_inventory.py
│   │   ├── test_trust.py
│   │   ├── test_output.py
│   │   └── providers/
│   │       ├── test_github.py
│   │       ├── test_gitlab.py
│   │       ├── test_azure.py
│   │       └── test_jenkins.py
│   ├── e2e/                         # full CLI scan runs
│   │   ├── test_scan.py             # actionsieve scan against fixture repos
│   │   ├── test_inventory.py        # actionsieve inventory commands
│   │   └── test_exit_codes.py       # verify exit code behavior
│   └── fixtures/                    # sample pipeline files
│       ├── github/
│       │   ├── vulnerable/
│       │   └── safe/
│       ├── gitlab/
│       │   ├── vulnerable/
│       │   └── safe/
│       ├── azure/
│       │   ├── vulnerable/
│       │   └── safe/
│       └── jenkins/
│           ├── vulnerable/
│           └── safe/
├── pyproject.toml
└── README.md
```

## Design principles

1. **Patterns are data, not code.** Adding a new pattern should never
   require modifying the scanner. If it does, the engine is too rigid.

2. **False positives over false negatives.** Flag anything suspicious and
   let the human triage. A missed finding is worse than a noisy one.

3. **Impact context matters.** The same injection sink has wildly different
   severity depending on trigger type, runner type, and available secrets.
   The scanner must capture this context, not just the pattern match.

4. **Chain detection is the differentiator.** Any grep can find
   `${{ github.event.pull_request.title }}` in a `run:` block. Tracing
   `readdirSync() -> JSON -> GITHUB_OUTPUT -> fromJson -> matrix ->
   ${{ matrix.x }}` across steps and jobs is what makes this tool worth
   building.

5. **Searchability at scale.** The catalog should generate effective forge
   search queries. Pattern authors should think about both local detection
   (AST-level) and remote discovery (text search).

6. **Works in CI and on the command line.** Same binary, same patterns,
   same output formats. Diff mode and exit codes for CI; full scan and
   reports for external audits. Like trufflehog — you can run it in a
   pipeline or from your laptop.

7. **Complement, don't replace.** Use zizmor for GHA linting, abom for
   inventory format compatibility, Harden-Runner for runtime detection.
   actionsieve adds the chain detection, impact classification, and custom
   patterns that sit between the linters and manual review.

8. **Platform-agnostic core, platform-specific edges.** The vulnerability
   patterns, data flow model, severity computation, and output formats are
   shared. Only parsing, expression syntax, and component resolution are
   platform-specific. Adding a new platform means writing one provider
   file, not touching the engine.

9. **Eat your own dogfood.** The reference CI workflows for actionsieve
   must be safe against every attack class the tool detects. Fork PRs
   cannot modify patterns, exfiltrate secrets, or bypass checks. If a fork
   PR can break the scanner's own CI, the scanner has failed its first
   user.
