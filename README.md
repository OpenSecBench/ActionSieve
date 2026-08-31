# ActionSieve

> **Note:** ActionSieve is under active development and testing. APIs, output formats, and detection behavior are subject to change.

Multi-platform CI/CD pipeline security scanner. Finds injection
vulnerabilities, supply chain risks, and misconfigurations across 10
CI/CD platforms using a pattern-driven detection engine.

## Features

- **Security scanning** — pattern-driven detection of expression
  injection, dangerous triggers, secret exposure, privilege escalation,
  cache poisoning, and hardening gaps
- **Actions Bill of Materials (ABOM)** — inventory every external
  action, orb, pipe, and plugin across your pipelines with
  `actionsieve inventory`
- **Supply chain analysis** — trust scoring for components, SHA pin
  verification, and advisory database checks against known-compromised
  dependencies
- **Cross-step data flow** — taint propagation through `GITHUB_OUTPUT`,
  matrix injection, and composite action output laundering
- **Forge-wide search** — scan an entire GitHub org or GitLab group for
  vulnerable CI/CD patterns with `actionsieve search`
- **PR-aware scanning** — diff-aware mode filters and elevates findings
  based on what changed, with auto-detection in CI environments
- **Multiple output formats** — JSON, YAML, SARIF, Markdown, OCSF, and
  CycloneDX SBOM
- **10 CI/CD platforms** — GitHub Actions, GitLab CI, Azure Pipelines,
  Jenkins, CircleCI, Bitbucket, Buildkite, Drone, CodeBuild, Cloud Build

## What it detects

- **Expression injection** — untrusted PR/issue data interpolated into
  shell commands via `${{ }}`, `$CI_*`, or platform equivalents
- **Supply chain risks** — unpinned action/orb/pipe/plugin refs, mutable
  tags, known-compromised components (advisory database)
- **Dangerous triggers** — `pull_request_target` with head checkout,
  `issue_comment` with fork access, and platform equivalents
- **Secret exposure** — static cloud credentials where OIDC is available,
  secrets logged or leaked through env vars
- **Privilege escalation** — Docker-in-Docker on shared runners, socket
  mounts, privileged containers
- **Cross-step data flow** — taint propagation through `GITHUB_OUTPUT`,
  matrix injection, composite action output laundering
- **Cache poisoning** — cache writes reachable from fork PRs
- **Hardening gaps** — missing `permissions:` blocks, checkout with
  persisted credentials, unpinned container images

## Supported platforms

| Platform | Provider | Detection |
|----------|----------|-----------|
| GitHub Actions | `github` | Workflows, composite actions, reusable workflows |
| GitLab CI | `gitlab` | `.gitlab-ci.yml`, includes, CI variables |
| Azure Pipelines | `azure` | YAML pipelines, template expressions |
| Jenkins | `jenkins` | Declarative + scripted pipelines (tree-sitter Groovy AST) |
| CircleCI | `circleci` | Config, orbs, dynamic config |
| Bitbucket Pipelines | `bitbucket` | Pipelines, pipes, deployment variables |
| Buildkite | `buildkite` | Pipeline YAML, plugins, dynamic upload |
| Drone CI | `drone` | Pipeline YAML, plugins |
| AWS CodeBuild | `codebuild` | `buildspec.yml`, IAM/secret misconfig |
| Google Cloud Build | `cloudbuild` | `cloudbuild.yaml`, service account config |

Platform is auto-detected from repository structure. Use `--platform` to
force a specific one.

## Install

```
pip install actionsieve
```

Or for development:

```
git clone https://github.com/OpenSecBench/ActionSieve.git
cd ActionSieve
uv sync --dev
pre-commit install
```

Requires Python 3.12+.

## Quick start

```bash
# Scan a repository for security issues
actionsieve scan --patterns patterns/ .

# Output as SARIF for GitHub Code Scanning
actionsieve scan --patterns patterns/ --format sarif --output results.sarif .

# Generate an Actions Bill of Materials (ABOM)
actionsieve inventory .

# ABOM with trust scores and advisory checks
actionsieve inventory --online --check .

# Export ABOM as CycloneDX SBOM
actionsieve inventory --format cyclonedx .
```

## Patterns

Security scanning requires a pattern catalog — YAML files that define
what to detect. Patterns are maintained separately from the scanner so
teams can use community patterns, private patterns, or both. The
`inventory` command works without patterns.

Community patterns: [ActionSieve-corpus](https://github.com/OpenSecBench/ActionSieve-corpus)

```bash
# Point to your patterns directory
actionsieve scan --patterns path/to/patterns .

# Or set the environment variable
export ACTIONSIEVE_PATTERNS=path/to/patterns
actionsieve scan .

# Inspect a pattern's full description, attack scenario, and mitigations
actionsieve explain --patterns patterns/ expr-injection-run
```

## Scanning modes

### Static mode (default)

Scans all pipeline files at a point in time. Every pattern fires based on
what's in the definitions. This is the default when running locally.

```bash
actionsieve scan --patterns patterns/ .
```

### PR mode (diff-aware)

Scans in the context of a specific change. Findings are filtered or
elevated based on which files changed in the PR. Auto-activates in CI
environments where trigger and base ref can be detected.

```bash
# Explicit changed files
actionsieve scan --patterns patterns/ --changed-files "Dockerfile,src/app.py" .

# From git diff output
git diff --name-only origin/main | actionsieve scan --patterns patterns/ --changed-files - .

# Context file (for scripted/corpus use)
actionsieve scan --patterns patterns/ --context context.yaml .

# Force mode
actionsieve scan --patterns patterns/ --mode pr --changed-files "Dockerfile" .
actionsieve scan --patterns patterns/ --mode static .    # disable auto-detection in CI
```

In PR mode, patterns declare how they interact with the changeset:

- **Suppress** — finding hidden when no relevant file is in the changeset
- **Elevate** — severity bumped when a relevant file IS in the changeset
- **Always** — fires identically regardless of changeset (default)

CI auto-detection works for GitHub Actions, GitLab CI, Azure Pipelines,
Jenkins, CircleCI, Bitbucket Pipelines, Buildkite, and Drone.

### Incremental scanning

Scan only pipeline files changed since a git ref:

```bash
actionsieve scan --patterns patterns/ --changed-since main .
```

This is orthogonal to PR mode — it controls which pipeline files enter the
scanner, not how findings are filtered.

## Output formats

| Format | Flag | Use case |
|--------|------|----------|
| JSON | `--format json` | Default, machine-readable |
| YAML | `--format yaml` | Human-readable |
| SARIF | `--format sarif` | GitHub/Azure Code Scanning integration |
| Markdown | `--format markdown` | Reports, PR comments |
| OCSF | `--format ocsf` | GRC platform integration (Detection Finding 2004) |
| CycloneDX | `--format cyclonedx` | ABOM/SBOM export (inventory command) |

## Environment profiles

Profiles adjust severity based on deployment context. A finding on a
public repo with self-hosted runners is more severe than the same finding
on a private repo with ephemeral runners.

```bash
# Built-in presets
actionsieve scan --patterns patterns/ --profile hosted-public .
actionsieve scan --patterns patterns/ --profile self-hosted .
actionsieve scan --patterns patterns/ --profile hardened .

# Custom profile file
actionsieve scan --patterns patterns/ --profile my-profile.yml .

# See effective profile after resolution
actionsieve profile resolve --profile hosted-public
```

Profiles can suppress categories, elevate patterns, and extend presets.

## Actions Bill of Materials (ABOM)

Generate a complete inventory of every external CI/CD component —
actions, orbs, pipes, plugins — across all pipelines in a repository.
No patterns required.

```bash
# Basic inventory
actionsieve inventory .

# With trust scores and SHA pin verification
actionsieve inventory --online .

# Check components against the advisory database
actionsieve inventory --online --check .

# Export as CycloneDX SBOM
actionsieve inventory --format cyclonedx --output sbom.json .
```

Each component includes its ref type (SHA, tag, branch), pin status,
first-party classification, and locations where it's used. Online mode
adds trust scores and verifies that pinned SHAs match their claimed
repositories.

## Online checks

Verify that SHA-pinned actions actually point to the claimed repository:

```bash
actionsieve scan --patterns patterns/ --online .
actionsieve inventory --online --check .
```

Reads `GITHUB_TOKEN` from the environment, or pass `--token`.

## Forge search

Search an organization's repositories for vulnerable CI/CD patterns:

```bash
# Scan all repos in an org
actionsieve search my-org --patterns patterns/ --forge github

# Targeted pattern search
actionsieve search --pattern expr-injection-run --patterns patterns/ --forge github

# GitLab group
actionsieve search my-group --patterns patterns/ --forge gitlab --token $GITLAB_TOKEN
```

## CI integration

- **GitHub Actions** — [ActionSieve-action](https://github.com/OpenSecBench/ActionSieve-action)
  (composite action with SARIF upload to Code Scanning)
- **GitLab CI / Azure Pipelines** — template examples in the
  [action repo](https://github.com/OpenSecBench/ActionSieve-action/tree/main/examples)

PR mode auto-activates in CI — no configuration needed.

## Corpus testing

Run detection patterns against a test corpus to validate accuracy:

```bash
# Run all corpus cases
actionsieve corpus run corpus/ --verbose

# Generate a coverage report
actionsieve corpus table corpus/
```

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | No findings (or all suppressed) |
| 1 | Findings at medium severity or above (or above `--fail-on` threshold) |
| 2 | Critical findings |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and guidelines.

## License

MIT
