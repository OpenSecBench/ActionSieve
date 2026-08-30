"""Buildkite provider."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pathlib import Path

import yaml

from actionsieve.model import (
    ComponentRef,
    Expression,
    Job,
    Runner,
    Step,
    Trigger,
    WorkflowModel,
    make_runner,
)
from actionsieve.providers import ExpressionSyntax, ParseError

MAX_FILE_SIZE = 1_048_576

CONFIG_PATHS = (
    ".buildkite/pipeline.yml",
    ".buildkite/pipeline.yaml",
    "pipeline.yml",
)

TAINTED_ENV_VARS = (
    "$BUILDKITE_BRANCH",
    "${BUILDKITE_BRANCH}",
    "$BUILDKITE_MESSAGE",
    "${BUILDKITE_MESSAGE}",
    "$BUILDKITE_COMMIT_MESSAGE",
    "${BUILDKITE_COMMIT_MESSAGE}",
    "$BUILDKITE_PULL_REQUEST_BASE_BRANCH",
    "${BUILDKITE_PULL_REQUEST_BASE_BRANCH}",
    "$BUILDKITE_PULL_REQUEST_TITLE",
    "${BUILDKITE_PULL_REQUEST_TITLE}",
    "$BUILDKITE_PULL_REQUEST_DESCRIPTION",
    "${BUILDKITE_PULL_REQUEST_DESCRIPTION}",
    "$BUILDKITE_BUILD_CREATOR",
    "${BUILDKITE_BUILD_CREATOR}",
    "$BUILDKITE_TAG",
    "${BUILDKITE_TAG}",
)


class BuildkiteProvider:
    name: str = "buildkite"

    def detect(self, repo_path: Path) -> bool:
        return any((repo_path / p).is_file() for p in CONFIG_PATHS)

    def find_files(self, repo_path: Path) -> list[Path]:
        return [repo_path / p for p in CONFIG_PATHS if (repo_path / p).is_file()]

    def parse(self, file_path: Path) -> WorkflowModel:
        if file_path.stat().st_size > MAX_FILE_SIZE:
            raise ParseError(f"File exceeds {MAX_FILE_SIZE} byte limit: {file_path}")

        text = file_path.read_text(encoding="utf-8")
        try:
            raw = yaml.safe_load(text)
        except yaml.YAMLError as e:
            raise ParseError(f"Invalid YAML in {file_path}: {e}") from e

        if not isinstance(raw, dict):
            raise ParseError(f"Expected mapping at top level: {file_path}")

        lines = text.splitlines()
        env = _parse_env(raw)
        jobs = _parse_steps(raw, lines, env)
        triggers = _infer_triggers(raw, jobs)

        return WorkflowModel(
            platform="buildkite",
            file_path=str(file_path),
            raw=raw,
            triggers=triggers,
            permissions=None,
            env=env,
            jobs=jobs,
        )

    def resolve_ref(self, ref: ComponentRef) -> ComponentRef:
        return ref

    def expression_syntax(self) -> ExpressionSyntax:
        return ExpressionSyntax(
            delimiters=("${", "}"),
            env_prefix=None,
            context_roots=[],
            tainted_roots=[
                "BUILDKITE_BRANCH",
                "BUILDKITE_MESSAGE",
                "BUILDKITE_COMMIT_MESSAGE",
                "BUILDKITE_PULL_REQUEST_TITLE",
                "BUILDKITE_PULL_REQUEST_DESCRIPTION",
                "BUILDKITE_BUILD_CREATOR",
                "BUILDKITE_TAG",
            ],
            safe_indirection=[],
        )

    def search_query(self, pattern: dict[str, object]) -> str | None:
        return None


def _parse_env(raw: dict[str, Any]) -> dict[str, str]:
    env = raw.get("env", {})
    if isinstance(env, dict):
        return {str(k): str(v) for k, v in env.items()}
    return {}


def _parse_steps(raw: dict[str, Any], lines: list[str], global_env: dict[str, str]) -> list[Job]:
    steps = raw.get("steps", [])
    if not isinstance(steps, list):
        return []

    jobs: list[Job] = []
    for i, step_data in enumerate(steps):
        if not isinstance(step_data, dict):
            continue

        if "group" in step_data:
            group_steps = step_data.get("steps", [])
            if isinstance(group_steps, list):
                for j, gs in enumerate(group_steps):
                    if isinstance(gs, dict):
                        job = _parse_command_step(f"group-{i}-{j}", gs, lines, global_env)
                        if job:
                            jobs.append(job)
            continue

        if "trigger" in step_data:
            continue

        if "wait" in step_data or step_data.get("wait") is not None:
            continue

        if "block" in step_data or "input" in step_data:
            continue

        job = _parse_command_step(f"step-{i}", step_data, lines, global_env)
        if job:
            jobs.append(job)

    return jobs


def _parse_command_step(
    job_id: str, data: dict[str, Any], lines: list[str], global_env: dict[str, str]
) -> Job | None:
    commands = _extract_commands(data)
    if not commands:
        return None

    name = data.get("label") or data.get("name") or job_id
    runner = _parse_agents(data)
    step_env = _parse_env(data)
    merged_env = {**global_env, **step_env}
    steps = _build_steps(commands, lines)
    plugin_steps = _parse_plugins(data, lines, len(steps))

    return Job(
        id=job_id,
        runner=runner,
        name=str(name),
        env=merged_env,
        steps=steps + plugin_steps,
    )


def _extract_commands(data: dict[str, Any]) -> list[str]:
    cmd = data.get("command") or data.get("commands")
    if isinstance(cmd, str):
        return [cmd]
    if isinstance(cmd, list):
        return [str(c) for c in cmd if isinstance(c, str)]
    return []


def _parse_agents(data: dict[str, Any]) -> Runner:
    agents = data.get("agents", {})
    if not isinstance(agents, dict) or not agents:
        return make_runner("buildkite")

    labels = [f"{k}={v}" for k, v in agents.items()]
    is_queue = "queue" in agents
    queue_val = str(agents.get("queue", ""))
    is_managed = is_queue and queue_val in ("default", "hosted")

    return Runner(
        labels=labels,
        is_self_hosted=not is_managed,
        is_managed=is_managed,
        raw=",".join(labels),
    )


def _build_steps(commands: list[str], lines: list[str]) -> list[Step]:
    steps: list[Step] = []
    for i, cmd in enumerate(commands):
        expressions = _extract_expressions(cmd, lines)
        steps.append(
            Step(
                index=i,
                type="shell",
                name=None,
                shell_command=cmd,
                expressions=expressions,
            )
        )
    return steps


def _parse_plugins(data: dict[str, Any], lines: list[str], offset: int) -> list[Step]:
    plugins = data.get("plugins", [])
    if not isinstance(plugins, list):
        return []

    steps: list[Step] = []
    for item in plugins:
        if isinstance(item, str):
            ref = _parse_plugin_ref(item, lines)
            steps.append(
                Step(
                    index=offset + len(steps),
                    type="action",
                    name=f"plugin:{item}",
                    action_ref=ref,
                )
            )
        elif isinstance(item, dict):
            for plugin_name, config in item.items():
                ref = _parse_plugin_ref(str(plugin_name), lines)
                inputs = {}
                if isinstance(config, dict):
                    inputs = {str(k): str(v) for k, v in config.items()}
                steps.append(
                    Step(
                        index=offset + len(steps),
                        type="action",
                        name=f"plugin:{plugin_name}",
                        action_ref=ref,
                        inputs=inputs,
                    )
                )
    return steps


def _parse_plugin_ref(raw: str, lines: list[str]) -> ComponentRef:
    if "#" in raw:
        name_part, version = raw.split("#", 1)
    else:
        name_part = raw
        version = "latest"

    owner = name_part.split("/")[0] if "/" in name_part else None
    name = name_part.split("/")[-1] if "/" in name_part else name_part
    is_sha = bool(re.match(r"^[0-9a-f]{40}$", version))
    is_semver = bool(re.match(r"^v?\d+\.\d+\.\d+$", version))

    return ComponentRef(
        raw=raw,
        owner=owner,
        name=name,
        ref=version,
        ref_type="sha" if is_sha else "tag",
        is_pinned=is_sha or is_semver,
        is_first_party=owner == "buildkite-plugins" if owner else False,
        line=_find_line(lines, raw),
    )


def _extract_expressions(text: str, lines: list[str]) -> list[Expression]:
    expressions: list[Expression] = []
    seen: set[str] = set()

    for tainted_var in TAINTED_ENV_VARS:
        if tainted_var in text:
            var_name = tainted_var.lstrip("$").strip("{}")
            if var_name in seen:
                continue
            seen.add(var_name)
            expressions.append(
                Expression(
                    raw=tainted_var,
                    context_path=var_name,
                    location="command",
                    is_in_shell=True,
                    is_tainted=True,
                    line=_find_line(lines, tainted_var),
                )
            )

    return expressions


def _infer_triggers(raw: dict[str, Any], jobs: list[Job]) -> list[Trigger]:
    has_upload = any("pipeline upload" in (s.shell_command or "") for j in jobs for s in j.steps)

    return [
        Trigger(
            event="push",
            raw_event="webhook",
            is_privileged=True,
            is_fork_reachable=True,
        ),
        *(
            [
                Trigger(
                    event="dynamic",
                    raw_event="pipeline_upload",
                    is_privileged=False,
                    is_fork_reachable=True,
                )
            ]
            if has_upload
            else []
        ),
    ]


def _find_line(lines: list[str], needle: str) -> int:
    for i, line in enumerate(lines, 1):
        if needle in line:
            return i
    return 0
