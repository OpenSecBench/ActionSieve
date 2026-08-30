"""Scan context — changed files, trigger, actor, and CI auto-detection."""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class ScanContext:
    changed_files: list[str] = field(default_factory=list)
    trigger: str | None = None
    actor: str | None = None


def parse_changed_files(value: str) -> list[str]:
    path = Path(value)
    if value == "-":
        import sys

        return _lines_to_files(sys.stdin.read())
    if path.is_file():
        return _lines_to_files(path.read_text(encoding="utf-8"))
    return [f.strip() for f in value.split(",") if f.strip()]


def _lines_to_files(text: str) -> list[str]:
    return [line.strip() for line in text.splitlines() if line.strip()]


def load_context_file(path: Path) -> ScanContext:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        msg = f"Context file must be a YAML mapping: {path}"
        raise ContextError(msg)
    ctx = ScanContext()
    if "changed_files" in data:
        raw = data["changed_files"]
        if isinstance(raw, list):
            ctx.changed_files = [str(f) for f in raw]
        elif isinstance(raw, str):
            ctx.changed_files = parse_changed_files(raw)
    if "trigger" in data:
        ctx.trigger = str(data["trigger"])
    if "actor" in data:
        ctx.actor = str(data["actor"])
    return ctx


class ContextError(Exception):
    pass


def _detect_github() -> ScanContext | None:
    if not os.environ.get("GITHUB_ACTIONS"):
        return None
    ctx = ScanContext()
    ctx.trigger = os.environ.get("GITHUB_EVENT_NAME")
    base_ref = os.environ.get("GITHUB_BASE_REF")
    if base_ref:
        ctx.changed_files = _git_changed_files(f"origin/{base_ref}")
    head_ref = os.environ.get("GITHUB_HEAD_REF")
    if head_ref and base_ref:
        ctx.actor = "fork" if head_ref != base_ref else None
    return ctx


def _detect_gitlab() -> ScanContext | None:
    if not os.environ.get("GITLAB_CI"):
        return None
    ctx = ScanContext()
    source = os.environ.get("CI_PIPELINE_SOURCE", "")
    ctx.trigger = source
    base_sha = os.environ.get("CI_MERGE_REQUEST_DIFF_BASE_SHA")
    if base_sha:
        ctx.changed_files = _git_changed_files(base_sha)
    return ctx


def _detect_azure() -> ScanContext | None:
    if not os.environ.get("TF_BUILD"):
        return None
    ctx = ScanContext()
    reason = os.environ.get("BUILD_REASON", "")
    ctx.trigger = reason
    target = os.environ.get("SYSTEM_PULLREQUEST_TARGETBRANCH")
    if target:
        ctx.changed_files = _git_changed_files(f"origin/{target}")
    return ctx


def _detect_jenkins() -> ScanContext | None:
    if not os.environ.get("JENKINS_URL"):
        return None
    ctx = ScanContext()
    change_target = os.environ.get("CHANGE_TARGET")
    if change_target:
        ctx.trigger = "pull_request"
        ctx.changed_files = _git_changed_files(f"origin/{change_target}")
    else:
        ctx.trigger = "push"
    return ctx


def _detect_circleci() -> ScanContext | None:
    if not os.environ.get("CIRCLECI"):
        return None
    ctx = ScanContext()
    pr = os.environ.get("CIRCLE_PULL_REQUEST")
    ctx.trigger = "pull_request" if pr else "push"
    return ctx


def _detect_bitbucket() -> ScanContext | None:
    if not os.environ.get("BITBUCKET_BUILD_NUMBER"):
        return None
    ctx = ScanContext()
    pr_id = os.environ.get("BITBUCKET_PR_ID")
    ctx.trigger = "pull_request" if pr_id else "push"
    dest = os.environ.get("BITBUCKET_PR_DESTINATION_BRANCH")
    if dest:
        ctx.changed_files = _git_changed_files(f"origin/{dest}")
    return ctx


def _detect_buildkite() -> ScanContext | None:
    if not os.environ.get("BUILDKITE"):
        return None
    ctx = ScanContext()
    pr = os.environ.get("BUILDKITE_PULL_REQUEST")
    ctx.trigger = "pull_request" if pr and pr != "false" else "push"
    base = os.environ.get("BUILDKITE_PULL_REQUEST_BASE_BRANCH")
    if base:
        ctx.changed_files = _git_changed_files(f"origin/{base}")
    return ctx


def _detect_drone() -> ScanContext | None:
    if not os.environ.get("DRONE"):
        return None
    ctx = ScanContext()
    event = os.environ.get("DRONE_BUILD_EVENT", "")
    ctx.trigger = event
    target = os.environ.get("DRONE_TARGET_BRANCH")
    if target and event == "pull_request":
        ctx.changed_files = _git_changed_files(f"origin/{target}")
    return ctx


_DETECTORS = [
    _detect_github,
    _detect_gitlab,
    _detect_azure,
    _detect_jenkins,
    _detect_circleci,
    _detect_bitbucket,
    _detect_buildkite,
    _detect_drone,
]


def detect_ci_context() -> ScanContext | None:
    for detector in _DETECTORS:
        ctx = detector()
        if ctx is not None:
            return ctx
    return None


def resolve_context(
    *,
    changed_files_raw: str | None = None,
    trigger: str | None = None,
    actor: str | None = None,
    context_file: Path | None = None,
    mode: str | None = None,
) -> ScanContext | None:
    if mode == "static":
        return None

    file_ctx = load_context_file(context_file) if context_file else None
    auto_ctx = detect_ci_context()

    base = auto_ctx or ScanContext()
    if file_ctx:
        if file_ctx.changed_files:
            base.changed_files = file_ctx.changed_files
        if file_ctx.trigger:
            base.trigger = file_ctx.trigger
        if file_ctx.actor:
            base.actor = file_ctx.actor

    if changed_files_raw:
        base.changed_files = parse_changed_files(changed_files_raw)
    if trigger:
        base.trigger = trigger
    if actor:
        base.actor = actor

    has_context = base.changed_files or base.trigger or base.actor

    if mode == "pr" and not has_context:
        msg = "--mode pr requires changeset context but none was found."
        raise ContextError(msg)

    if not has_context:
        return None

    return base


def _git_changed_files(ref: str) -> list[str]:
    try:
        result = subprocess.run(  # noqa: S603
            ["git", "diff", "--name-only", "--diff-filter=ACMRD", ref],  # noqa: S607
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        return []
    if result.returncode != 0:
        return []
    return _lines_to_files(result.stdout)
