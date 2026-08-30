# actionsieve

Multi-platform CI/CD pipeline security scanner. Pattern-driven detection of
injection vulnerabilities, supply chain risks, and misconfigurations in
GitHub Actions, GitLab CI, Azure Pipelines, and Jenkins.

## Install

```
uv pip install -e ".[dev]"
```

## Usage

```
actionsieve scan <path>
actionsieve scan --diff <base-ref>
actionsieve inventory <path>
actionsieve inventory --check <path>
```

See `docs/architecture.md` for full documentation.
