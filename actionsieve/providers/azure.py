"""Azure Pipelines provider."""

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
    Step,
    Trigger,
    WorkflowModel,
    make_runner,
)
from actionsieve.providers import ExpressionSyntax, ParseError

MAX_FILE_SIZE = 1_048_576

MACRO_RE = re.compile(r"\$\(\s*(\w[\w.]*)\s*\)")
TEMPLATE_EXPR_RE = re.compile(r"\$\{\{\s*(.*?)\s*\}\}")

PIPELINE_FILES = ("azure-pipelines.yml", "azure-pipelines.yaml")

TAINTED_VARIABLES = (
    "Build.SourceBranchName",
    "Build.SourceVersionMessage",
    "Build.RequestedFor",
    "Build.RequestedForEmail",
    "System.PullRequest.SourceBranch",
    "System.PullRequest.TargetBranch",
)

PRIVILEGED_TRIGGERS = frozenset({"push", "schedule", "manual"})
FORK_REACHABLE_TRIGGERS = frozenset({"pr", "pull_request"})


class AzureProvider:
    name: str = "azure"

    def detect(self, repo_path: Path) -> bool:
        return any((repo_path / f).is_file() for f in PIPELINE_FILES)

    def find_files(self, repo_path: Path) -> list[Path]:
        files: list[Path] = []
        for name in PIPELINE_FILES:
            p = repo_path / name
            if p.is_file():
                files.append(p)
        return files

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

        triggers = _parse_triggers(raw)
        env = _parse_variables(raw)
        jobs = _parse_pipeline(raw, text)

        return WorkflowModel(
            platform="azure",
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
            delimiters=("$(", ")"),
            context_roots=["variables", "Build", "System", "Pipeline"],
            tainted_roots=["Build.SourceVersionMessage", "Build.SourceBranchName"],
            safe_indirection=[],
        )

    def search_query(self, pattern: dict[str, object]) -> str | None:
        return None


def _parse_triggers(raw: dict[str, Any]) -> list[Trigger]:
    triggers: list[Trigger] = []

    trigger = raw.get("trigger")
    if isinstance(trigger, list):
        triggers.append(_make_trigger("push", {"branches": trigger}))
    elif isinstance(trigger, dict):
        triggers.append(_make_trigger("push", trigger))
    elif trigger == "none":
        pass
    elif trigger is None and "pr" not in raw:
        triggers.append(_make_trigger("push", {}))

    pr = raw.get("pr")
    if isinstance(pr, list | dict):
        filters = pr if isinstance(pr, dict) else {"branches": pr}
        triggers.append(_make_trigger("pr", filters))
    elif pr is None and trigger != "none":
        triggers.append(_make_trigger("pr", {}))

    schedules = raw.get("schedules")
    if isinstance(schedules, list):
        for sched in schedules:
            if isinstance(sched, dict):
                triggers.append(_make_trigger("schedule", sched))

    if not triggers:
        triggers.append(_make_trigger("push", {}))

    return triggers


def _make_trigger(event: str, filters: dict[str, Any]) -> Trigger:
    return Trigger(
        event=event,
        raw_event=event,
        filters=filters,
        is_privileged=event in PRIVILEGED_TRIGGERS,
        is_fork_reachable=event in FORK_REACHABLE_TRIGGERS,
    )


def _parse_variables(raw: dict[str, Any]) -> dict[str, str]:
    variables = raw.get("variables", [])
    result: dict[str, str] = {}
    if isinstance(variables, list):
        for item in variables:
            if isinstance(item, dict):
                name = item.get("name", "")
                value = item.get("value", "")
                if name:
                    result[str(name)] = str(value)
    elif isinstance(variables, dict):
        for k, v in variables.items():
            result[str(k)] = str(v)
    return result


def _pool_to_runner(pool: Any) -> str:
    if isinstance(pool, dict):
        return str(pool.get("vmImage") or pool.get("name") or "default")
    if isinstance(pool, str):
        return pool
    return "default"


def _parse_pipeline(raw: dict[str, Any], file_text: str) -> list[Job]:
    lines = file_text.splitlines()

    stages = raw.get("stages")
    if isinstance(stages, list):
        return _parse_stages(stages, lines)

    jobs = raw.get("jobs")
    if isinstance(jobs, list):
        return _parse_jobs(jobs, lines)

    steps = raw.get("steps")
    if isinstance(steps, list):
        return [
            Job(
                id="default",
                runner=make_runner(_pool_to_runner(raw.get("pool"))),
                steps=_parse_steps(steps, lines),
                secrets_referenced=_find_secrets({"steps": steps}),
            )
        ]

    return []


def _parse_stages(stages: list[Any], lines: list[str]) -> list[Job]:
    jobs: list[Job] = []
    for stage in stages:
        if not isinstance(stage, dict):
            continue
        stage_name = str(stage.get("stage", "unknown"))
        stage_jobs = stage.get("jobs", [])
        if isinstance(stage_jobs, list):
            for job_data in stage_jobs:
                if not isinstance(job_data, dict):
                    continue
                jobs.extend(_parse_job_entry(job_data, stage_name, lines))
    return jobs


def _parse_jobs(jobs: list[Any], lines: list[str]) -> list[Job]:
    result: list[Job] = []
    for job_data in jobs:
        if not isinstance(job_data, dict):
            continue
        result.extend(_parse_job_entry(job_data, "default", lines))
    return result


def _parse_job_entry(
    data: dict[str, Any],
    stage: str,
    lines: list[str],
) -> list[Job]:
    if "job" in data:
        return [_parse_job(data, stage, lines)]
    if "deployment" in data:
        return [_parse_job(data, stage, lines, is_deployment=True)]
    if "template" in data:
        return []
    for key, value in data.items():
        if isinstance(value, dict) and "steps" in value:
            entry = dict(value)
            entry["job"] = key
            return [_parse_job(entry, stage, lines)]
    return []


def _parse_job(
    data: dict[str, Any],
    stage: str,
    lines: list[str],
    *,
    is_deployment: bool = False,
) -> Job:
    job_key = "deployment" if is_deployment else "job"
    job_id = str(data.get(job_key, stage))

    runner_raw = _pool_to_runner(data.get("pool"))

    depends = data.get("dependsOn", [])
    needs: list[str] = []
    if isinstance(depends, str):
        needs = [depends]
    elif isinstance(depends, list):
        needs = [str(d) for d in depends]

    env = _parse_variables(data)
    steps_raw = data.get("steps", [])
    steps = _parse_steps(steps_raw, lines) if isinstance(steps_raw, list) else []

    conditions: list[str] = []
    condition = data.get("condition")
    if condition:
        conditions.append(str(condition))

    container = data.get("container")
    image: str | None = None
    if isinstance(container, str):
        image = container
    elif isinstance(container, dict):
        img = container.get("image")
        if isinstance(img, str):
            image = img

    return Job(
        id=job_id,
        runner=make_runner(runner_raw),
        name=data.get("displayName"),
        permissions=None,
        image=image,
        env=env,
        needs=needs,
        outputs={},
        steps=steps,
        secrets_referenced=_find_secrets(data),
        conditions=conditions,
    )


def _parse_steps(steps_raw: list[Any], lines: list[str]) -> list[Step]:
    steps: list[Step] = []
    for i, step_data in enumerate(steps_raw):
        if not isinstance(step_data, dict):
            continue
        step = _parse_step(i, step_data, lines)
        if step:
            steps.append(step)
    return steps


def _parse_step(index: int, data: dict[str, Any], lines: list[str]) -> Step | None:
    for key in ("script", "bash", "powershell", "pwsh"):
        if key in data:
            cmd = str(data[key])
            return Step(
                index=index,
                type="shell",
                name=data.get("displayName"),
                shell_command=cmd,
                expressions=_extract_expressions(cmd, lines),
                env=_parse_step_env(data),
            )

    if "task" in data:
        task_ref = str(data["task"])
        inputs = data.get("inputs", {})
        inputs_str = (
            {str(k): str(v) for k, v in inputs.items()} if isinstance(inputs, dict) else {}
        )
        all_text = task_ref + "\n" + "\n".join(inputs_str.values())
        return Step(
            index=index,
            type="action",
            name=data.get("displayName"),
            action_ref=_parse_task_ref(task_ref, lines),
            inputs=inputs_str,
            expressions=_extract_expressions(all_text, lines),
            env=_parse_step_env(data),
        )

    if "checkout" in data:
        ref_val = str(data["checkout"])
        return Step(
            index=index,
            type="action",
            name="checkout",
            action_ref=ComponentRef(
                raw=f"checkout@{ref_val}",
                owner=None,
                name="checkout",
                ref=ref_val,
                ref_type="branch" if ref_val != "none" else "unknown",
                is_pinned=False,
                is_first_party=True,
                line=_find_line(lines, "checkout"),
            ),
        )

    return None


def _parse_task_ref(task_str: str, lines: list[str]) -> ComponentRef:
    name, ref = task_str.rsplit("@", 1) if "@" in task_str else (task_str, "")
    return ComponentRef(
        raw=task_str,
        owner=None,
        name=name,
        ref=ref,
        ref_type="tag" if ref else "unknown",
        is_pinned=False,
        is_first_party=name.lower().startswith(("azure", "ms", "microsoft")),
        line=_find_line(lines, task_str),
    )


def _parse_step_env(data: dict[str, Any]) -> dict[str, str]:
    env = data.get("env", {})
    return {str(k): str(v) for k, v in env.items()} if isinstance(env, dict) else {}


def _extract_expressions(text: str, lines: list[str]) -> list[Expression]:
    expressions: list[Expression] = []
    for m in MACRO_RE.finditer(text):
        var_name = m.group(1)
        raw = m.group(0)

        is_tainted = any(var_name == tv or var_name.startswith(tv) for tv in TAINTED_VARIABLES)
        line = _find_line(lines, raw)

        expressions.append(
            Expression(
                raw=raw,
                context_path=var_name,
                location="script",
                is_in_shell=True,
                is_tainted=is_tainted,
                line=line,
            )
        )

    for m in TEMPLATE_EXPR_RE.finditer(text):
        context_path = m.group(1).strip()
        raw = m.group(0)
        is_tainted = any(context_path.startswith(tv) for tv in TAINTED_VARIABLES)
        line = _find_line(lines, raw)

        expressions.append(
            Expression(
                raw=raw,
                context_path=context_path,
                location="template",
                is_in_shell=False,
                is_tainted=is_tainted,
                line=line,
            )
        )

    return expressions


def _find_secrets(data: dict[str, Any]) -> list[str]:
    secret_keywords = ("secret", "password", "token", "key", "credential")
    secrets: list[str] = []
    text = str(data).lower()
    for m in MACRO_RE.finditer(text):
        var_name = m.group(1)
        if any(kw in var_name for kw in secret_keywords) and var_name not in secrets:
            secrets.append(var_name)
    return secrets


def _find_line(lines: list[str], needle: str) -> int:
    for i, line in enumerate(lines, 1):
        if needle in line:
            return i
    return 0
