"""Drone CI provider."""

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

CONFIG_FILE = ".drone.yml"

TAINTED_ENV_VARS = (
    "$DRONE_BRANCH",
    "${DRONE_BRANCH}",
    "$DRONE_COMMIT_MESSAGE",
    "${DRONE_COMMIT_MESSAGE}",
    "$DRONE_TAG",
    "${DRONE_TAG}",
    "$DRONE_PULL_REQUEST_TITLE",
    "${DRONE_PULL_REQUEST_TITLE}",
    "$DRONE_SOURCE_BRANCH",
    "${DRONE_SOURCE_BRANCH}",
    "$DRONE_COMMIT_AUTHOR",
    "${DRONE_COMMIT_AUTHOR}",
    "$DRONE_COMMIT_AUTHOR_NAME",
    "${DRONE_COMMIT_AUTHOR_NAME}",
    "$DRONE_TARGET_BRANCH",
    "${DRONE_TARGET_BRANCH}",
)


class DroneProvider:
    name: str = "drone"

    def detect(self, repo_path: Path) -> bool:
        return (repo_path / CONFIG_FILE).is_file()

    def find_files(self, repo_path: Path) -> list[Path]:
        p = repo_path / CONFIG_FILE
        return [p] if p.is_file() else []

    def parse(self, file_path: Path) -> WorkflowModel:
        if file_path.stat().st_size > MAX_FILE_SIZE:
            raise ParseError(f"File exceeds {MAX_FILE_SIZE} byte limit: {file_path}")

        text = file_path.read_text(encoding="utf-8")
        try:
            docs = list(yaml.safe_load_all(text))
        except yaml.YAMLError as e:
            raise ParseError(f"Invalid YAML in {file_path}: {e}") from e

        lines = text.splitlines()
        jobs: list[Job] = []
        triggers: list[Trigger] = []
        first_pipeline: dict[str, Any] = {}

        for i, doc in enumerate(docs):
            if not isinstance(doc, dict):
                continue
            if doc.get("kind", "pipeline") != "pipeline":
                continue
            if not first_pipeline:
                first_pipeline = doc
            triggers.extend(_parse_triggers(doc))
            job = _parse_pipeline(doc, i, lines)
            if job:
                jobs.append(job)

        if not triggers:
            triggers.append(
                Trigger(
                    event="push",
                    raw_event="default",
                    is_privileged=True,
                    is_fork_reachable=True,
                )
            )

        return WorkflowModel(
            platform="drone",
            file_path=str(file_path),
            raw=first_pipeline,
            triggers=triggers,
            permissions=None,
            env={},
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
                "DRONE_BRANCH",
                "DRONE_COMMIT_MESSAGE",
                "DRONE_TAG",
                "DRONE_PULL_REQUEST_TITLE",
                "DRONE_SOURCE_BRANCH",
                "DRONE_COMMIT_AUTHOR",
                "DRONE_COMMIT_AUTHOR_NAME",
                "DRONE_TARGET_BRANCH",
            ],
            safe_indirection=[],
        )

    def search_query(self, pattern: dict[str, object]) -> str | None:
        return None


def _parse_triggers(doc: dict[str, Any]) -> list[Trigger]:
    trigger = doc.get("trigger", {})
    if not isinstance(trigger, dict):
        return [
            Trigger(
                event="push",
                raw_event="default",
                is_privileged=True,
                is_fork_reachable=True,
            )
        ]

    events = _extract_trigger_list(trigger.get("event"))
    if not events:
        events = ["push", "pull_request", "tag"]

    return [
        Trigger(
            event=ev,
            raw_event=ev,
            is_privileged=ev != "pull_request",
            is_fork_reachable=ev == "pull_request",
        )
        for ev in events
    ]


def _extract_trigger_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(v) for v in value]
    if isinstance(value, dict):
        include = value.get("include")
        if isinstance(include, list):
            return [str(v) for v in include]
    if isinstance(value, str):
        return [value]
    return []


def _parse_pipeline(doc: dict[str, Any], index: int, lines: list[str]) -> Job | None:
    name = str(doc.get("name", f"pipeline-{index}"))
    runner = _parse_runner(doc)
    env = _parse_env(doc)

    raw_steps = doc.get("steps", [])
    if not isinstance(raw_steps, list):
        return None

    steps: list[Step] = []
    secrets: list[str] = []

    for step_data in raw_steps:
        if not isinstance(step_data, dict):
            continue
        secrets.extend(_extract_secrets(step_data))
        new_steps = _parse_step(step_data, len(steps), lines)
        steps.extend(new_steps)

    if not steps:
        return None

    return Job(
        id=name,
        runner=runner,
        name=name,
        env=env,
        steps=steps,
        secrets_referenced=secrets,
    )


def _parse_step(data: dict[str, Any], offset: int, lines: list[str]) -> list[Step]:
    step_name = str(data["name"]) if "name" in data else None
    is_privileged = data.get("privileged") is True

    commands = data.get("commands", [])
    if isinstance(commands, list) and commands:
        str_cmds = [str(c) for c in commands if isinstance(c, str)]
        inputs = {"privileged": "true"} if is_privileged else {}
        return [
            Step(
                index=offset + i,
                type="shell",
                name=step_name,
                shell_command=cmd,
                inputs=inputs,
                expressions=_extract_expressions(cmd, lines),
            )
            for i, cmd in enumerate(str_cmds)
        ]

    image = data.get("image")
    if isinstance(image, str):
        ref = _parse_image_ref(image, lines)
        inputs = {}
        settings = data.get("settings", {})
        if isinstance(settings, dict):
            inputs = {str(k): str(v) for k, v in settings.items()}
        if is_privileged:
            inputs["privileged"] = "true"
        return [
            Step(
                index=offset,
                type="action",
                name=step_name,
                action_ref=ref,
                inputs=inputs,
            )
        ]

    return []


def _parse_runner(doc: dict[str, Any]) -> Runner:
    pipeline_type = doc.get("type", "docker")

    if pipeline_type in ("exec", "ssh"):
        return Runner(
            labels=[str(pipeline_type)],
            is_self_hosted=True,
            is_managed=False,
            raw=str(pipeline_type),
        )

    node = doc.get("node", {})
    if isinstance(node, dict) and node:
        labels = [f"{k}={v}" for k, v in node.items()]
        return Runner(
            labels=labels,
            is_self_hosted=True,
            is_managed=False,
            raw=",".join(labels),
        )

    return make_runner("drone")


def _parse_env(doc: dict[str, Any]) -> dict[str, str]:
    env = doc.get("environment", {})
    if not isinstance(env, dict):
        return {}
    return {str(k): str(v) for k, v in env.items() if isinstance(v, str | int | float | bool)}


def _extract_secrets(step_data: dict[str, Any]) -> list[str]:
    env = step_data.get("environment", {})
    if not isinstance(env, dict):
        return []
    return [
        str(v["from_secret"]) for v in env.values() if isinstance(v, dict) and "from_secret" in v
    ]


def _parse_image_ref(raw: str, lines: list[str]) -> ComponentRef:
    digest: str | None = None
    name_tag = raw
    if "@sha256:" in raw:
        name_tag, digest = raw.split("@sha256:", 1)

    if ":" in name_tag:
        name_part, version = name_tag.rsplit(":", 1)
    else:
        name_part = name_tag
        version = "latest"

    owner = name_part.split("/")[0] if "/" in name_part else None
    name = name_part.rsplit("/", 1)[-1]
    is_digest = digest is not None
    is_semver = bool(re.match(r"^v?\d+\.\d+\.\d+$", version))

    return ComponentRef(
        raw=raw,
        owner=owner,
        name=name,
        ref=f"sha256:{digest}" if is_digest else version,
        ref_type="sha" if is_digest else "tag",
        is_pinned=is_digest or is_semver,
        is_first_party=owner == "plugins",
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


def _find_line(lines: list[str], needle: str) -> int:
    for i, line in enumerate(lines, 1):
        if needle in line:
            return i
    return 0
