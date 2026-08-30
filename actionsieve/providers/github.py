"""GitHub Actions provider."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

if TYPE_CHECKING:
    from pathlib import Path

import yaml

from actionsieve.model import (
    Job,
    Permissions,
    Step,
    Trigger,
    WorkflowModel,
    make_runner,
)
from actionsieve.providers import ExpressionSyntax, ParseError
from actionsieve.providers.github_parse import (
    detect_outputs_written,
    extract_expressions,
    find_secrets,
    parse_uses,
    step_text,
    str_dict,
)

MAX_FILE_SIZE = 1_048_576  # 1MB

PRIVILEGED_TRIGGERS = frozenset(
    {
        "pull_request_target",
        "workflow_run",
        "push",
        "schedule",
        "workflow_dispatch",
        "repository_dispatch",
    }
)

FORK_REACHABLE_TRIGGERS = frozenset(
    {
        "pull_request",
        "pull_request_target",
        "issue_comment",
        "issues",
        "fork",
    }
)


class GitHubProvider:
    name: str = "github"

    def detect(self, repo_path: Path) -> bool:
        return (repo_path / ".github" / "workflows").is_dir()

    def find_files(self, repo_path: Path) -> list[Path]:
        workflows_dir = repo_path / ".github" / "workflows"
        if not workflows_dir.is_dir():
            return []
        files: list[Path] = []
        for pattern in ("*.yml", "*.yaml"):
            files.extend(sorted(workflows_dir.glob(pattern)))
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
        permissions = _parse_permissions(raw.get("permissions"))
        env = str_dict(raw.get("env", {}))
        jobs = _parse_jobs(raw.get("jobs", {}), text)

        return WorkflowModel(
            platform="github",
            file_path=str(file_path),
            raw=raw,
            triggers=triggers,
            permissions=permissions,
            env=env,
            jobs=jobs,
        )

    def resolve_ref(self, ref: Any) -> Any:
        return ref

    def expression_syntax(self) -> ExpressionSyntax:
        return ExpressionSyntax(
            delimiters=("${{", "}}"),
            context_roots=["github", "env", "secrets", "steps", "needs", "matrix", "inputs"],
            tainted_roots=["github.event", "github.head_ref"],
            safe_indirection=["env"],
        )

    def search_query(self, pattern: dict[str, object]) -> str | None:
        detection = pattern.get("detection")
        if not isinstance(detection, dict):
            return None
        grep_patterns = detection.get("grep_patterns")
        if not isinstance(grep_patterns, list) or not grep_patterns:
            return None
        term = grep_patterns[0]
        if not isinstance(term, str):
            return None
        return f'"{term}" language:yaml path:.github/workflows'


def _parse_triggers(raw: dict[str, Any]) -> list[Trigger]:
    on: Any = raw.get("on")
    if on is None:
        on = cast("dict[Any, Any]", raw).get(True)
    if on is None:
        return []

    if isinstance(on, str):
        return [_make_trigger(on, {})]

    if isinstance(on, list):
        return [_make_trigger(event, {}) for event in on]

    if isinstance(on, dict):
        return [_make_trigger(event, config or {}) for event, config in on.items()]

    return []


def _make_trigger(event: Any, config: Any) -> Trigger:
    event_str = str(event)
    normalized = _normalize_event(event_str)
    filters: dict[str, Any] = config if isinstance(config, dict) else {}
    return Trigger(
        event=normalized,
        raw_event=event_str,
        filters=filters,
        is_privileged=event_str in PRIVILEGED_TRIGGERS,
        is_fork_reachable=event_str in FORK_REACHABLE_TRIGGERS,
    )


def _normalize_event(event: str) -> str:
    if event == "pull_request_target":
        return "pull_request"
    return event


def _parse_permissions(raw: Any) -> Permissions | None:
    if raw is None:
        return None
    if isinstance(raw, str):
        return Permissions(raw={"_all": raw})
    if isinstance(raw, dict):
        return Permissions(
            contents=raw.get("contents"),
            issues=raw.get("issues"),
            pull_requests=raw.get("pull-requests"),
            actions=raw.get("actions"),
            security_events=raw.get("security-events"),
            raw=raw,
        )
    return None


def _parse_jobs(jobs_raw: Any, file_text: str) -> list[Job]:
    if not isinstance(jobs_raw, dict):
        return []
    lines = file_text.splitlines()
    return [_parse_job(job_id, job_data, lines) for job_id, job_data in jobs_raw.items()]


def _parse_job(job_id: str, data: Any, lines: list[str]) -> Job:
    if not isinstance(data, dict):
        data = {}

    runs_on = data.get("runs-on", "ubuntu-latest")
    runner_raw: str | list[str] = (
        [str(r) for r in runs_on] if isinstance(runs_on, list) else str(runs_on)
    )

    needs_raw = data.get("needs", [])
    if isinstance(needs_raw, str):
        needs = [needs_raw]
    elif isinstance(needs_raw, list):
        needs = [str(n) for n in needs_raw]
    else:
        needs = []

    outputs = str_dict(data.get("outputs", {}))

    steps_raw = data.get("steps", [])
    steps = [_parse_step(i, s, lines) for i, s in enumerate(steps_raw) if isinstance(s, dict)]

    job_uses = data.get("uses")
    if isinstance(job_uses, str) and job_uses:
        ref = parse_uses(job_uses, lines)
        steps.append(Step(index=0, type="action", name=job_uses, action_ref=ref))

    secrets_referenced = find_secrets(data)

    conditions: list[str] = []
    if "if" in data:
        conditions.append(str(data["if"]))

    return Job(
        id=str(job_id),
        runner=make_runner(runner_raw),
        name=data.get("name"),
        permissions=_parse_permissions(data.get("permissions")),
        env=str_dict(data.get("env", {})),
        needs=needs,
        outputs=outputs,
        steps=steps,
        secrets_referenced=secrets_referenced,
        conditions=conditions,
    )


def _parse_step(index: int, data: dict[str, Any], lines: list[str]) -> Step:
    step_type = "shell"
    shell_command: str | None = None
    action_ref = None
    inputs: dict[str, str] = {}

    if "run" in data:
        step_type = "shell"
        shell_command = str(data["run"])
    elif "uses" in data:
        step_type = "action"
        action_ref = parse_uses(str(data["uses"]), lines)
        inputs = str_dict(data.get("with", {}))
    else:
        step_type = "script"

    env = str_dict(data.get("env", {}))

    all_text = step_text(data)
    expressions = extract_expressions(all_text, shell_command, lines)

    outputs_written = detect_outputs_written(shell_command)

    conditions: list[str] = []
    if "if" in data:
        conditions.append(str(data["if"]))

    return Step(
        index=index,
        type=step_type,
        id=data.get("id"),
        name=data.get("name"),
        shell_command=shell_command,
        action_ref=action_ref,
        inputs=inputs,
        env=env,
        outputs_written=outputs_written,
        expressions=expressions,
        conditions=conditions,
    )
