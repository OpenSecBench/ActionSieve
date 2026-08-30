"""Bitbucket Pipelines provider."""

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

CONFIG_FILE = "bitbucket-pipelines.yml"

TAINTED_ENV_VARS = (
    "$BITBUCKET_BRANCH",
    "${BITBUCKET_BRANCH}",
    "$BITBUCKET_TAG",
    "${BITBUCKET_TAG}",
    "$BITBUCKET_BOOKMARK",
    "${BITBUCKET_BOOKMARK}",
    "$BITBUCKET_PR_DESTINATION_BRANCH",
    "${BITBUCKET_PR_DESTINATION_BRANCH}",
)

SELF_HOSTED_LABEL = "self.hosted"


class BitbucketProvider:
    name: str = "bitbucket"

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
            raw = yaml.safe_load(text)
        except yaml.YAMLError as e:
            raise ParseError(f"Invalid YAML in {file_path}: {e}") from e

        if not isinstance(raw, dict):
            raise ParseError(f"Expected mapping at top level: {file_path}")

        lines = text.splitlines()
        pipelines = raw.get("pipelines", {})
        if not isinstance(pipelines, dict):
            pipelines = {}

        jobs: list[Job] = []
        triggers: list[Trigger] = []

        for section, trigger in _iter_pipeline_sections(pipelines):
            triggers.append(trigger)
            section_jobs = _parse_section(section, trigger.event, lines)
            jobs.extend(section_jobs)

        if not triggers:
            triggers.append(
                Trigger(
                    event="push",
                    raw_event="default",
                    is_privileged=True,
                    is_fork_reachable=False,
                )
            )

        return WorkflowModel(
            platform="bitbucket",
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
            delimiters=("${", "}"),
            env_prefix=None,
            context_roots=[],
            tainted_roots=[
                "BITBUCKET_BRANCH",
                "BITBUCKET_TAG",
                "BITBUCKET_BOOKMARK",
            ],
            safe_indirection=[],
        )

    def search_query(self, pattern: dict[str, object]) -> str | None:
        return None


def _iter_pipeline_sections(
    pipelines: dict[str, Any],
) -> list[tuple[Any, Trigger]]:
    results: list[tuple[Any, Trigger]] = []

    default = pipelines.get("default")
    if isinstance(default, list):
        results.append(
            (
                default,
                Trigger(
                    event="push",
                    raw_event="default",
                    is_privileged=True,
                    is_fork_reachable=False,
                ),
            )
        )

    branches = pipelines.get("branches", {})
    if isinstance(branches, dict):
        for pattern, steps in branches.items():
            if isinstance(steps, list):
                results.append(
                    (
                        steps,
                        Trigger(
                            event="push",
                            raw_event=f"branches:{pattern}",
                            is_privileged=True,
                            is_fork_reachable=False,
                        ),
                    )
                )

    prs = pipelines.get("pull-requests", {})
    if isinstance(prs, dict):
        for pattern, steps in prs.items():
            if isinstance(steps, list):
                results.append(
                    (
                        steps,
                        Trigger(
                            event="pull_request",
                            raw_event=f"pull-requests:{pattern}",
                            is_privileged=False,
                            is_fork_reachable=True,
                        ),
                    )
                )

    tags = pipelines.get("tags", {})
    if isinstance(tags, dict):
        for pattern, steps in tags.items():
            if isinstance(steps, list):
                results.append(
                    (
                        steps,
                        Trigger(
                            event="tag",
                            raw_event=f"tags:{pattern}",
                            is_privileged=True,
                            is_fork_reachable=False,
                        ),
                    )
                )

    custom = pipelines.get("custom", {})
    if isinstance(custom, dict):
        for name, steps in custom.items():
            if isinstance(steps, list):
                results.append(
                    (
                        steps,
                        Trigger(
                            event="manual",
                            raw_event=f"custom:{name}",
                            is_privileged=True,
                            is_fork_reachable=False,
                        ),
                    )
                )

    return results


def _parse_section(items: list[Any], event: str, lines: list[str]) -> list[Job]:
    jobs: list[Job] = []
    for i, item in enumerate(items):
        if not isinstance(item, dict):
            continue
        if "step" in item:
            step_data = item["step"]
            if isinstance(step_data, dict):
                job = _parse_step_as_job(f"{event}-step-{i}", step_data, lines)
                jobs.append(job)
        elif "parallel" in item:
            parallel = item["parallel"]
            if isinstance(parallel, list):
                for j, par_item in enumerate(parallel):
                    if isinstance(par_item, dict) and "step" in par_item:
                        step_data = par_item["step"]
                        if isinstance(step_data, dict):
                            job = _parse_step_as_job(
                                f"{event}-parallel-{i}-{j}",
                                step_data,
                                lines,
                            )
                            jobs.append(job)
    return jobs


def _parse_step_as_job(job_id: str, data: dict[str, Any], lines: list[str]) -> Job:
    name = data.get("name", job_id)
    runner = _parse_runner(data)
    steps = _parse_scripts(data, lines)
    pipe_steps = _parse_pipes(data, lines, len(steps))

    return Job(
        id=job_id,
        runner=runner,
        name=str(name),
        steps=steps + pipe_steps,
    )


def _parse_runner(data: dict[str, Any]) -> Runner:
    runs_on = data.get("runs-on")
    if isinstance(runs_on, list):
        labels = [str(lbl) for lbl in runs_on]
        is_self_hosted = SELF_HOSTED_LABEL in labels
        return Runner(
            labels=labels,
            is_self_hosted=is_self_hosted,
            is_managed=not is_self_hosted,
            raw=",".join(labels),
        )
    image = data.get("image")
    if isinstance(image, str):
        return make_runner(image)
    if isinstance(image, dict):
        return make_runner(str(image.get("name", "default")))
    return make_runner("default")


def _parse_scripts(data: dict[str, Any], lines: list[str]) -> list[Step]:
    steps: list[Step] = []
    for key in ("script", "after-script"):
        scripts = data.get(key, [])
        if not isinstance(scripts, list):
            continue
        for cmd in scripts:
            if isinstance(cmd, str):
                steps.append(
                    Step(
                        index=len(steps),
                        type="shell",
                        name=key,
                        shell_command=cmd,
                        expressions=_extract_expressions(cmd, lines),
                    )
                )
    return steps


def _parse_pipes(data: dict[str, Any], lines: list[str], offset: int) -> list[Step]:
    steps: list[Step] = []
    scripts = data.get("script", [])
    if not isinstance(scripts, list):
        return steps

    for item in scripts:
        if not isinstance(item, dict) or "pipe" not in item:
            continue
        pipe_ref = str(item["pipe"])
        ref = _parse_pipe_ref(pipe_ref, lines)
        steps.append(
            Step(
                index=offset + len(steps),
                type="action",
                name=f"pipe:{pipe_ref}",
                action_ref=ref,
                inputs={str(k): str(v) for k, v in item.get("variables", {}).items()}
                if isinstance(item.get("variables"), dict)
                else {},
            )
        )
    return steps


def _parse_pipe_ref(raw: str, lines: list[str]) -> ComponentRef:
    is_docker = raw.startswith("docker://")
    clean = raw.removeprefix("docker://")

    if ":" in clean:
        name_part, _, version = clean.rpartition(":")
    else:
        name_part = clean
        version = "latest"

    owner = name_part.split("/")[0] if "/" in name_part else None
    name = name_part.split("/")[-1] if "/" in name_part else name_part
    is_first_party = owner == "atlassian" if owner else False
    is_exact = bool(re.match(r"^\d+\.\d+\.\d+$", version))

    return ComponentRef(
        raw=raw,
        owner=owner,
        name=name,
        ref=version,
        ref_type="tag",
        is_pinned=is_exact and not is_docker,
        is_first_party=is_first_party,
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
                    location="script",
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
