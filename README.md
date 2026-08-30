# actionsieve

Multi-platform CI/CD pipeline security scanner. Finds injection
vulnerabilities, supply chain risks, and misconfigurations across 10
CI/CD platforms using a pattern-driven detection engine.

## What it finds

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

45+ detection patterns, validated against a JSON Schema.

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
uv venv
uv pip install -e ".[dev]"
```

Requires Python 3.12+.

## Quick start

Scan a repository for CI/CD security issues:

```bash
actionsieve scan .
```

Output as SARIF for GitHub Code Scanning:

```bash
actionsieve scan --format sarif --output results.sarif .
```

Generate a component inventory (bill of materials):

```bash
actionsieve inventory .
```

Check components against the advisory database:

```bash
actionsieve inventory --check .
```

## Scanning modes

### Static mode (default)

Scans all pipeline files at a point in time. Every pattern fires based on
what's in the definitions. This is the default when running locally.

```bash
actionsieve scan .
```

### PR mode (diff-aware)

Scans in the context of a specific change. Findings are filtered or
elevated based on which files changed in the PR. Auto-activates in CI
environments where trigger and base ref can be detected.

```bash
# Explicit changed files
actionsieve scan --changed-files "Dockerfile,src/app.py" .

# From git diff output
git diff --name-only origin/main | actionsieve scan --changed-files - .

# Context file (for scripted/corpus use)
actionsieve scan --context context.yaml .

# Force mode
actionsieve scan --mode pr --changed-files "Dockerfile" .
actionsieve scan --mode static .    # disable auto-detection in CI
```

In PR mode, patterns declare how they interact with the changeset:

- **Suppress** — finding hidden when no relevant file is in the changeset
  (e.g. `docker-in-docker` suppressed when no Dockerfile changed)
- **Elevate** — severity bumped when a relevant file IS in the changeset
  (e.g. expression injection elevated when workflow file is modified)
- **Always** — fires identically regardless of changeset (default)

CI auto-detection works for GitHub Actions, GitLab CI, Azure Pipelines,
Jenkins, CircleCI, Bitbucket Pipelines, Buildkite, and Drone.

### Incremental scanning

Scan only pipeline files changed since a git ref:

```bash
actionsieve scan --changed-since main .
actionsieve scan --changed-since abc123 .
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
| CycloneDX | inventory only | SBOM for dependency tracking |

## Environment profiles

Profiles adjust severity based on deployment context. A finding on a
public repo with self-hosted runners is more severe than the same finding
on a private repo with ephemeral runners.

```bash
# Built-in presets
actionsieve scan --profile hosted-public .
actionsieve scan --profile hosted-private .
actionsieve scan --profile self-hosted .
actionsieve scan --profile hardened .

# Custom profile file
actionsieve scan --profile my-profile.yml .

# See effective profile after resolution
actionsieve profile resolve --profile hosted-public
```

Profiles can suppress categories, elevate patterns, and extend presets.

## Online checks

Verify that SHA-pinned actions actually point to the claimed repository:

```bash
actionsieve scan --online .
actionsieve inventory --online --check .
```

Reads `GITHUB_TOKEN` from the environment, or pass `--token`.

## Forge search

Search an organization's repositories for vulnerable CI/CD patterns:

```bash
# Scan all repos in an org
actionsieve search my-org --forge github

# Targeted pattern search
actionsieve search --pattern expr-injection-run --forge github

# GitLab group
actionsieve search my-group --forge gitlab --token $GITLAB_TOKEN
```

## CI integration

Ready-made templates for running actionsieve in CI:

- **GitHub Actions** — `ci/github/action.yml` (composite action with
  SARIF upload to Code Scanning)
- **GitLab CI** — `ci/gitlab/.gitlab-ci-template.yml` (include template)
- **Azure Pipelines** — `ci/azure/actionsieve.yml` (step template)

PR mode auto-activates in all three — no configuration needed.

## Pattern details

Inspect any pattern's full description, attack scenario, mitigations,
and references:

```bash
actionsieve explain expr-injection-run
actionsieve explain mutable-action-ref
actionsieve explain docker-in-docker
```

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | No findings (or all suppressed) |
| 1 | Findings at medium severity or above (or above `--fail-on` threshold) |
| 2 | Critical findings |

## License

MIT
