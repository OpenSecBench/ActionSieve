"""Environment profile loader — presets, files, and extends support."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import jsonschema
import yaml

SCHEMA_PATH = Path(__file__).parent / "profile_schema.json"

BUILTIN_PROFILES: dict[str, dict[str, Any]] = {
    "default": {},
    "hosted-public": {
        "runners": {"type": "ephemeral", "isolation": "container", "network": "open"},
        "forks": {"policy": "open"},
        "secrets": {"backend": "env_vars"},
    },
    "hosted-private": {
        "runners": {"type": "ephemeral", "isolation": "container", "network": "open"},
        "forks": {"policy": "disabled"},
        "secrets": {"backend": "env_vars"},
    },
    "self-hosted": {
        "runners": {"type": "persistent", "isolation": "bare_metal", "network": "open"},
        "forks": {"policy": "restricted"},
        "secrets": {"backend": "env_vars"},
        "elevate": ["self-hosted-runners"],
    },
    "hardened": {
        "runners": {"type": "ephemeral", "isolation": "vm", "network": "restricted"},
        "forks": {"policy": "disabled"},
        "secrets": {"backend": "oidc", "rotation": "automatic"},
        "branch_protection": {"level": "strict", "required_reviews": 2},
        "suppress": ["self-hosted-runners"],
    },
}


class ProfileError(Exception):
    """Raised when a profile is invalid or not found."""


def load_profile(
    profile_arg: str | None = None,
    repo_path: Path | None = None,
) -> dict[str, Any]:
    if profile_arg:
        if profile_arg in BUILTIN_PROFILES:
            return dict(BUILTIN_PROFILES[profile_arg])
        path = Path(profile_arg)
        if path.is_file():
            return _load_from_file(path)
        msg = f"Profile not found: {profile_arg} (not a preset or file)"
        raise ProfileError(msg)

    if repo_path:
        repo_profile = repo_path / ".actionsieve.yml"
        if repo_profile.is_file():
            return _load_from_file(repo_profile)

    user_profile = Path.home() / ".config" / "actionsieve" / "profile.yml"
    if user_profile.is_file():
        return _load_from_file(user_profile)

    return dict(BUILTIN_PROFILES["default"])


def _load_from_file(path: Path) -> dict[str, Any]:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as e:
        raise ProfileError(f"Invalid YAML in profile {path}: {e}") from e

    if not isinstance(data, dict):
        raise ProfileError(f"Profile must be a mapping: {path}")

    _validate_schema(data, path)

    profile = data.get("profile", data)
    if not isinstance(profile, dict):
        raise ProfileError(f"Profile must be a mapping: {path}")

    extends = profile.pop("extends", None)
    if extends:
        if extends not in BUILTIN_PROFILES:
            msg = f"Unknown base profile: {extends}"
            raise ProfileError(msg)
        base = dict(BUILTIN_PROFILES[extends])
        _deep_merge(base, profile)
        return base

    return dict(profile)


def _validate_schema(data: dict[str, Any], path: Path) -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    try:
        jsonschema.validate(data, schema)
    except jsonschema.ValidationError as e:
        raise ProfileError(f"Profile validation failed in {path}: {e.message}") from e


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> None:
    for key, value in override.items():
        if key in base and isinstance(base[key], dict) and isinstance(value, dict):
            _deep_merge(base[key], value)
        else:
            base[key] = value
