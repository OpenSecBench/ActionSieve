"""Severity computation — static context + environment profile adjustment."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from actionsieve.engine import Finding
    from actionsieve.model import WorkflowModel

SEVERITY_LEVELS = ("info", "low", "medium", "high", "critical")
SEVERITY_MAP = {level: i for i, level in enumerate(SEVERITY_LEVELS)}


def compute_static(finding: Finding, model: WorkflowModel) -> str:
    base = SEVERITY_MAP.get(finding.severity_base, 2)
    modifier = 0

    has_privileged_trigger = any(t.is_privileged for t in model.triggers)
    has_fork_trigger = any(t.is_fork_reachable for t in model.triggers)

    job = next((j for j in model.jobs if j.id == finding.job_id), None)

    has_secrets = bool(job and job.secrets_referenced)
    is_self_hosted = bool(job and job.runner.is_self_hosted)

    if has_privileged_trigger and has_secrets:
        modifier += 1
    if is_self_hosted:
        modifier += 1
    if has_fork_trigger and not has_privileged_trigger and not has_secrets:
        modifier -= 1

    return _clamp(base + modifier)


def apply_profile(
    static_severity: str,
    profile: dict[str, Any],
) -> str:
    base = SEVERITY_MAP.get(static_severity, 2)
    modifier = 0

    runners = profile.get("runners", {})
    if isinstance(runners, dict):
        if runners.get("type") == "ephemeral":
            modifier -= _severity_category_adjustment("self-hosted-runners", profile)
        elif runners.get("type") == "persistent":
            modifier += 1
        if runners.get("isolation") == "bare_metal":
            modifier += 1
        elif runners.get("isolation") == "container":
            pass
        if runners.get("network") == "restricted":
            modifier -= 1

    forks = profile.get("forks", {})
    if isinstance(forks, dict) and forks.get("policy") == "disabled":
        modifier -= 1

    secrets = profile.get("secrets", {})
    if isinstance(secrets, dict):
        if secrets.get("backend") == "oidc":
            modifier -= 1
        if secrets.get("rotation") == "automatic":
            modifier -= 1

    return _clamp(base + modifier)


def is_suppressed(finding: Finding, profile: dict[str, Any]) -> bool:
    suppress = profile.get("suppress", [])
    if not isinstance(suppress, list):
        return False
    tags = finding.tags
    pattern_id = finding.pattern_id
    return any(c in tags or pattern_id.startswith(c) for c in suppress)


def is_elevated(finding: Finding, profile: dict[str, Any]) -> bool:
    elevate = profile.get("elevate", [])
    if not isinstance(elevate, list):
        return False
    tags = finding.tags
    pattern_id = finding.pattern_id
    return any(c in tags or pattern_id.startswith(c) for c in elevate)


def elevate_severity(severity: str) -> str:
    return _clamp(SEVERITY_MAP.get(severity, 2) + 1)


def _severity_category_adjustment(category: str, profile: dict[str, Any]) -> int:
    suppress = profile.get("suppress", [])
    if isinstance(suppress, list) and category in suppress:
        return 2
    return 1


def _clamp(level: int) -> str:
    clamped = max(0, min(len(SEVERITY_LEVELS) - 1, level))
    return SEVERITY_LEVELS[clamped]
