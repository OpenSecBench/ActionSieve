# Contributing to ActionSieve

## Architecture

ActionSieve is the scanner — a pure tool that matches patterns against
normalized CI/CD pipeline models. Patterns are data, maintained separately
in a corpus repo.

- **Scanner code** → this repo
- **Detection patterns** → [actionsieve-corpus](https://github.com/OpenSecBench/ActionSieve-corpus)

If you want to add a new detection rule, contribute it to the corpus repo.
If you want to improve how the scanner works, you're in the right place.

## Setup

```
uv sync --dev
pre-commit install
```

## Running tests

```
pytest                     # full suite
pytest tests/unit/         # unit tests only
pytest tests/e2e/          # end-to-end only
pytest -x                  # stop on first failure
pytest -k "github"         # platform-specific
```

Tests in this repo cover scanner mechanics — parsing, matching, scoring,
output formatting. Detection accuracy tests live in the corpus repo.

## Before committing

Pre-commit hooks run automatically, but you can check manually:

```
ruff check .
ruff format .
mypy --strict actionsieve/
pytest
```

All four must pass.

## Code style

- No comments by default — comment only the *why*, never the *what*
- No docstring novels — type hints and a good name are the documentation
- No commented-out code
- No module over 600 lines
- Conventional commits: `feat:`, `fix:`, `test:`, `refactor:`

## Adding a new CI platform provider

1. Create `actionsieve/providers/{platform}.py`
2. Implement the `Provider` protocol from `providers/__init__.py`
3. Add fixtures in `tests/fixtures/{platform}/vulnerable/` and `safe/`
4. Add provider tests in `tests/unit/providers/test_{platform}.py`
5. Register in `providers/__init__.py` detection list
6. Add to `PLATFORMS` in `cli.py`
