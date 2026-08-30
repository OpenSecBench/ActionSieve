"""CircleCI provider."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pathlib import Path

import yaml

from actionsieve.model import (
    ComponentRef,
    Job,
    Runner,
    Step,
    Trigger,
    WorkflowModel,
    make_runner,
)
from actionsieve.providers import ExpressionSyntax, ParseError
from actionsieve.providers.circleci_parse import parse_orbs, parse_steps

MAX_FILE_SIZE = 1_048_576

CONFIG_PATH = ".circleci/config.yml"

MANAGED_RESOURCE_CLASSES = frozenset(
    {
        "small",
        "medium",
        "medium+",
        "large",
        "xlarge",
        "2xlarge",
        "2xlarge+",
        "arm.medium",
        "arm.large",
        "arm.xlarge",
        "arm.2xlarge",
        "gpu.nvidia.small",
        "gpu.nvidia.medium",
        "gpu.nvidia.large",
        "macos.m1.medium.gen1",
        "macos.m1.large.gen1",
        "macos.x86.medium.gen2",
    }
)


class CircleCIProvider:
    name: str = "circleci"

    def detect(self, repo_path: Path) -> bool:
        return (repo_path / CONFIG_PATH).is_file()

    def find_files(self, repo_path: Path) -> list[Path]:
        p = repo_path / CONFIG_PATH
        return [p] if p.is_file() else []

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
        executors = _parse_executors(raw)
        orbs = parse_orbs(raw, lines)
        jobs = _parse_jobs(raw, executors, orbs, lines)
        triggers = _parse_triggers(raw)
        _apply_contexts(raw, jobs)

        return WorkflowModel(
            platform="circleci",
            file_path=str(file_path),
            raw=raw,
            triggers=triggers,
            permissions=None,
            env={},
            jobs=jobs,
        )

    def resolve_ref(self, ref: ComponentRef) -> ComponentRef:
        return ref

    def expression_syntax(self) -> ExpressionSyntax:
        return ExpressionSyntax(
            delimiters=("<<", ">>"),
            context_roots=["pipeline", "parameters"],
            tainted_roots=["pipeline.git.branch", "pipeline.git.tag"],
            safe_indirection=[],
        )

    def search_query(self, pattern: dict[str, object]) -> str | None:
        return None


def _parse_executors(raw: dict[str, Any]) -> dict[str, str]:
    executors: dict[str, str] = {}
    execs = raw.get("executors", {})
    if not isinstance(execs, dict):
        return executors
    for name, spec in execs.items():
        if isinstance(spec, dict):
            executors[name] = _executor_to_runner(spec)
    return executors


def _executor_to_runner(spec: dict[str, Any]) -> str:
    if "docker" in spec:
        images = spec["docker"]
        if isinstance(images, list) and images:
            first = images[0]
            if isinstance(first, dict):
                return str(first.get("image", "docker"))
        return "docker"
    if "machine" in spec:
        machine = spec["machine"]
        if isinstance(machine, dict):
            return str(machine.get("image", "machine"))
        return "machine"
    if "macos" in spec:
        return "macos"
    return "docker"


def _is_self_hosted(resource_class: str) -> bool:
    return "/" in resource_class and resource_class not in MANAGED_RESOURCE_CLASSES


def _parse_jobs(
    raw: dict[str, Any],
    executors: dict[str, str],
    orbs: list[ComponentRef],
    lines: list[str],
) -> list[Job]:
    jobs_section = raw.get("jobs", {})
    if not isinstance(jobs_section, dict):
        return []

    jobs: list[Job] = []
    for job_name, job_data in jobs_section.items():
        if not isinstance(job_data, dict):
            continue
        jobs.append(_parse_job(str(job_name), job_data, executors, orbs, lines))
    return jobs


def _parse_job(
    name: str,
    data: dict[str, Any],
    executors: dict[str, str],
    orbs: list[ComponentRef],
    lines: list[str],
) -> Job:
    runner_raw = _resolve_runner(data, executors)
    resource_class = str(data.get("resource_class", ""))
    if resource_class:
        runner_raw = resource_class

    self_hosted = _is_self_hosted(resource_class) if resource_class else False
    if self_hosted:
        runner = Runner(
            labels=[runner_raw],
            is_self_hosted=True,
            is_managed=False,
            raw=runner_raw,
        )
    else:
        runner = make_runner(runner_raw)

    steps_raw = data.get("steps", [])
    steps = parse_steps(steps_raw, lines) if isinstance(steps_raw, list) else []

    orb_steps = [
        Step(
            index=len(steps) + i,
            type="action",
            name=f"orb:{ref.raw}",
            action_ref=ref,
        )
        for i, ref in enumerate(orbs)
    ]

    env = _parse_env(data)
    image = _extract_image(data, executors)

    return Job(
        id=name,
        runner=runner,
        image=image,
        steps=steps + orb_steps,
        env=env,
    )


def _resolve_runner(data: dict[str, Any], executors: dict[str, str]) -> str:
    executor_ref = data.get("executor")
    if isinstance(executor_ref, str) and executor_ref in executors:
        return executors[executor_ref]
    if isinstance(executor_ref, dict):
        name = executor_ref.get("name", "")
        if name in executors:
            return executors[name]

    if "docker" in data:
        return _executor_to_runner(data)
    if "machine" in data:
        return _executor_to_runner(data)
    if "macos" in data:
        return "macos"

    return "docker"


def _parse_env(data: dict[str, Any]) -> dict[str, str]:
    env = data.get("environment", {})
    return {str(k): str(v) for k, v in env.items()} if isinstance(env, dict) else {}


def _extract_image(data: dict[str, Any], executors: dict[str, str] | None = None) -> str | None:
    docker = data.get("docker")
    if isinstance(docker, list) and docker:
        first = docker[0]
        if isinstance(first, dict):
            img = first.get("image")
            if isinstance(img, str):
                return img
    machine = data.get("machine")
    if isinstance(machine, dict):
        img = machine.get("image")
        if isinstance(img, str):
            return img
    if executors:
        executor_ref = data.get("executor")
        name = executor_ref if isinstance(executor_ref, str) else None
        if isinstance(executor_ref, dict):
            name = executor_ref.get("name")
        if name and name in executors:
            resolved = executors[name]
            if resolved not in ("docker", "machine", "macos"):
                return resolved
    return None


def _parse_triggers(raw: dict[str, Any]) -> list[Trigger]:
    triggers: list[Trigger] = []

    workflows = raw.get("workflows", {})
    has_schedule = False
    if isinstance(workflows, dict):
        for wf_data in workflows.values():
            if isinstance(wf_data, dict):
                wf_triggers = wf_data.get("triggers", [])
                if isinstance(wf_triggers, list):
                    for t in wf_triggers:
                        if isinstance(t, dict) and "schedule" in t:
                            has_schedule = True

    if has_schedule:
        triggers.append(
            Trigger(
                event="schedule",
                raw_event="schedule",
                is_privileged=True,
                is_fork_reachable=False,
            )
        )

    triggers.append(
        Trigger(
            event="push",
            raw_event="push",
            is_privileged=True,
            is_fork_reachable=False,
        )
    )

    triggers.append(
        Trigger(
            event="pull_request",
            raw_event="pull_request",
            is_privileged=False,
            is_fork_reachable=True,
        )
    )

    return triggers


def _apply_contexts(raw: dict[str, Any], jobs: list[Job]) -> None:
    workflows = raw.get("workflows", {})
    if not isinstance(workflows, dict):
        return

    job_contexts: dict[str, list[str]] = {}
    for wf_data in workflows.values():
        if not isinstance(wf_data, dict):
            continue
        wf_jobs = wf_data.get("jobs", [])
        if not isinstance(wf_jobs, list):
            continue
        for entry in wf_jobs:
            if isinstance(entry, str):
                continue
            if isinstance(entry, dict):
                for job_name, config in entry.items():
                    if not isinstance(config, dict):
                        continue
                    ctx = config.get("context")
                    if isinstance(ctx, list):
                        job_contexts.setdefault(str(job_name), []).extend(str(c) for c in ctx)
                    elif isinstance(ctx, str):
                        job_contexts.setdefault(str(job_name), []).append(ctx)

    for job in jobs:
        contexts = job_contexts.get(job.id, [])
        if contexts:
            job.secrets_referenced = contexts
