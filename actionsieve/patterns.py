"""Pattern catalog loader — loads, validates, and filters YAML patterns."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import jsonschema
import yaml

SCHEMA_PATH = Path(__file__).parent / "schema.json"

ENV_VAR = "ACTIONSIEVE_PATTERNS"


class PatternError(Exception):
    """Raised when a pattern file is invalid."""


def _resolve_path(path: Path | None) -> Path:
    if path is not None:
        return path
    env = os.environ.get(ENV_VAR)
    if env:
        return Path(env)
    msg = f"No patterns path. Pass --patterns or set {ENV_VAR}."
    raise PatternError(msg)


def load_patterns(
    path: Path | None = None,
    platform: str | None = None,
) -> list[dict[str, Any]]:
    source = _resolve_path(path)
    raw_patterns = _load_from_path(source)
    _enforce_unique_ids(raw_patterns)
    if platform:
        raw_patterns = _filter_by_platform(raw_patterns, platform)
    return raw_patterns


def _load_from_path(path: Path) -> list[dict[str, Any]]:
    if path.is_file():
        return _load_file(path)
    if path.is_dir():
        patterns: list[dict[str, Any]] = []
        for yml_file in sorted(path.glob("*.yml")):
            patterns.extend(_load_file(yml_file))
        return patterns
    msg = f"Pattern path does not exist: {path}"
    raise PatternError(msg)


def _load_file(path: Path) -> list[dict[str, Any]]:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as e:
        raise PatternError(f"Invalid YAML in {path}: {e}") from e

    if not isinstance(data, dict) or "patterns" not in data:
        raise PatternError(f"Missing 'patterns' key in {path}")

    schema = _load_schema()
    try:
        jsonschema.validate(data, schema)
    except jsonschema.ValidationError as e:
        raise PatternError(f"Schema validation failed in {path}: {e.message}") from e

    patterns = data["patterns"]
    if not isinstance(patterns, list):
        raise PatternError(f"'patterns' must be a list in {path}")

    return list(patterns)


def _load_schema() -> dict[str, Any]:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))  # type: ignore[no-any-return]


def _enforce_unique_ids(patterns: list[dict[str, Any]]) -> None:
    seen: dict[str, int] = {}
    for i, p in enumerate(patterns):
        pid = p.get("id", f"<missing-id-at-index-{i}>")
        if pid in seen:
            msg = f"Duplicate pattern ID: {pid}"
            raise PatternError(msg)
        seen[pid] = i


def get_pattern(
    pattern_id: str,
    path: Path | None = None,
) -> dict[str, Any] | None:
    patterns = load_patterns(path=path)
    for p in patterns:
        if p["id"] == pattern_id:
            return p
    return None


def list_pattern_ids(path: Path | None = None) -> list[str]:
    return [p["id"] for p in load_patterns(path=path)]


def _filter_by_platform(
    patterns: list[dict[str, Any]],
    platform: str,
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for p in patterns:
        platforms = p.get("platforms", "all")
        if platforms == "all" or (isinstance(platforms, list) and platform in platforms):
            result.append(p)
    return result
