"""Normalized workflow model — platform-agnostic dataclasses."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Expression:
    raw: str
    context_path: str
    location: str
    is_in_shell: bool
    is_tainted: bool
    line: int


@dataclass
class ComponentRef:
    raw: str
    owner: str | None
    name: str
    ref: str
    ref_type: str
    is_pinned: bool
    is_first_party: bool
    line: int
    resolved_sha: str | None = None


@dataclass
class Runner:
    labels: list[str]
    is_self_hosted: bool
    is_managed: bool
    raw: str | list[str]


MANAGED_RUNNER_PREFIXES = ("ubuntu-", "windows-", "macos-")


def make_runner(raw: str | list[str]) -> Runner:
    labels = [raw] if isinstance(raw, str) else list(raw)
    normalized = [label.lower() for label in labels]
    is_self_hosted = "self-hosted" in normalized
    is_managed = not is_self_hosted and any(
        label.startswith(prefix) for label in normalized for prefix in MANAGED_RUNNER_PREFIXES
    )
    return Runner(labels=labels, is_self_hosted=is_self_hosted, is_managed=is_managed, raw=raw)


@dataclass
class Step:
    index: int
    type: str
    id: str | None = None
    name: str | None = None
    shell_command: str | None = None
    action_ref: ComponentRef | None = None
    inputs: dict[str, str] = field(default_factory=dict)
    env: dict[str, str] = field(default_factory=dict)
    outputs_written: list[str] = field(default_factory=list)
    expressions: list[Expression] = field(default_factory=list)
    conditions: list[str] = field(default_factory=list)


@dataclass
class Permissions:
    contents: str | None = None
    issues: str | None = None
    pull_requests: str | None = None
    actions: str | None = None
    security_events: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class Job:
    id: str
    runner: Runner
    name: str | None = None
    permissions: Permissions | None = None
    image: str | None = None
    env: dict[str, str] = field(default_factory=dict)
    needs: list[str] = field(default_factory=list)
    outputs: dict[str, str] = field(default_factory=dict)
    steps: list[Step] = field(default_factory=list)
    secrets_referenced: list[str] = field(default_factory=list)
    conditions: list[str] = field(default_factory=list)


@dataclass
class Trigger:
    event: str
    raw_event: str
    filters: dict[str, Any] = field(default_factory=dict)
    is_privileged: bool = False
    is_fork_reachable: bool = False


@dataclass
class WorkflowModel:
    platform: str
    file_path: str
    raw: dict[str, Any]
    triggers: list[Trigger] = field(default_factory=list)
    permissions: Permissions | None = None
    env: dict[str, str] = field(default_factory=dict)
    jobs: list[Job] = field(default_factory=list)
