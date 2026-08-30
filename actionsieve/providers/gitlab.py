"""GitLab CI provider."""

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

RESERVED_KEYS = frozenset(
    {
        "stages",
        "variables",
        "default",
        "include",
        "workflow",
        "image",
        "services",
        "before_script",
        "after_script",
        "cache",
        "artifacts",
        "pages",
    }
)

TAINTED_VARIABLES = (
    "$CI_COMMIT_MESSAGE",
    "$CI_COMMIT_TITLE",
    "$CI_MERGE_REQUEST_TITLE",
    "$CI_MERGE_REQUEST_DESCRIPTION",
    "$CI_COMMIT_TAG_MESSAGE",
    "$CI_COMMIT_REF_NAME",
    "$CI_MERGE_REQUEST_SOURCE_BRANCH_NAME",
    "$CI_EXTERNAL_PULL_REQUEST_SOURCE_BRANCH_NAME",
    "$TRIGGER_PAYLOAD",
)

VARIABLE_RE = re.compile(r"\$(?:\{([A-Za-z_]\w*)\}|([A-Za-z_]\w*))")

PIPELINE_SOURCE_MAP: dict[str, str] = {
    "external_pull_request_event": "external_pull_request",
    "merge_request_event": "merge_request",
    "parent_pipeline": "parent_pipeline",
    "pipeline": "pipeline",
    "trigger": "trigger",
    "schedule": "schedule",
    "push": "push",
    "web": "web",
    "api": "api",
}

FORK_REACHABLE_SOURCES = frozenset(
    {
        "merge_request_event",
        "external_pull_request_event",
    }
)

PRIVILEGED_SOURCES = frozenset(
    {
        "push",
        "schedule",
        "web",
        "api",
        "trigger",
        "pipeline",
    }
)


class GitLabProvider:
    name: str = "gitlab"

    def detect(self, repo_path: Path) -> bool:
        return (repo_path / ".gitlab-ci.yml").is_file()

    def find_files(self, repo_path: Path) -> list[Path]:
        main_file = repo_path / ".gitlab-ci.yml"
        if not main_file.is_file():
            return []
        return [main_file]

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

        triggers = _extract_triggers(raw)
        env = _extract_variables(raw)
        jobs = _parse_jobs(raw, text)

        return WorkflowModel(
            platform="gitlab",
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
            delimiters=("$", ""),
            env_prefix="$",
            context_roots=["CI_", "GITLAB_"],
            tainted_roots=["CI_COMMIT_MESSAGE", "CI_MERGE_REQUEST_TITLE"],
            safe_indirection=[],
        )

    def search_query(self, pattern: dict[str, object]) -> str | None:
        return None


def _extract_triggers(raw: dict[str, Any]) -> list[Trigger]:
    triggers: list[Trigger] = []
    workflow = raw.get("workflow")
    if isinstance(workflow, dict):
        rules = workflow.get("rules", [])
        if isinstance(rules, list):
            for rule in rules:
                if not isinstance(rule, dict):
                    continue
                condition = rule.get("if", "")
                source = _extract_pipeline_source(str(condition))
                if source:
                    triggers.append(_make_trigger(source, rule))

    if not triggers:
        triggers.append(_make_trigger("push", {}))

    return triggers


_PIPELINE_SOURCE_RE = re.compile(
    r"\b(" + "|".join(re.escape(k) for k in PIPELINE_SOURCE_MAP) + r")\b"
)


def _extract_pipeline_source(condition: str) -> str | None:
    m = _PIPELINE_SOURCE_RE.search(condition)
    return m.group(1) if m else None


def _make_trigger(source: str, rule: dict[str, Any]) -> Trigger:
    normalized = PIPELINE_SOURCE_MAP.get(source, source)
    return Trigger(
        event=normalized,
        raw_event=source,
        filters=rule,
        is_privileged=source in PRIVILEGED_SOURCES,
        is_fork_reachable=source in FORK_REACHABLE_SOURCES,
    )


def _extract_variables(raw: dict[str, Any]) -> dict[str, str]:
    variables = raw.get("variables", {})
    if not isinstance(variables, dict):
        return {}
    return {
        str(k): str(v) if not isinstance(v, dict) else str(v.get("value", ""))
        for k, v in variables.items()
    }


def _parse_jobs(raw: dict[str, Any], file_text: str) -> list[Job]:
    lines = file_text.splitlines()
    default = raw.get("default", {})
    if not isinstance(default, dict):
        default = {}

    jobs: list[Job] = []
    for key, value in raw.items():
        if key in RESERVED_KEYS or key.startswith("."):
            continue
        if not isinstance(value, dict):
            continue
        if "script" not in value and "trigger" not in value:
            continue
        jobs.append(_parse_job(str(key), value, default, lines))

    return jobs


def _parse_job(
    job_id: str,
    data: dict[str, Any],
    default: dict[str, Any],
    lines: list[str],
) -> Job:
    image_raw = data.get("image") or default.get("image")
    runner_raw = str(image_raw) if image_raw else "default"
    image_str: str | None = None
    if isinstance(image_raw, str):
        image_str = image_raw
    elif isinstance(image_raw, dict):
        img = image_raw.get("name")
        if isinstance(img, str):
            image_str = img

    tags = data.get("tags", [])
    is_self_hosted = bool(tags)

    needs_raw = data.get("needs", [])
    needs: list[str] = []
    if isinstance(needs_raw, list):
        for n in needs_raw:
            if isinstance(n, str):
                needs.append(n)
            elif isinstance(n, dict) and "job" in n:
                needs.append(str(n["job"]))

    env = _extract_variables(data)
    steps = _parse_steps(data, default, lines)
    secrets = _find_secrets(data)

    conditions: list[str] = []
    rules = data.get("rules", [])
    if isinstance(rules, list):
        for rule in rules:
            if isinstance(rule, dict) and "if" in rule:
                conditions.append(str(rule["if"]))

    runner = make_runner(runner_raw)
    if is_self_hosted:
        runner = _runner_with_tags(tags, runner_raw)

    return Job(
        id=job_id,
        runner=runner,
        name=data.get("name"),
        permissions=None,
        image=image_str,
        env=env,
        needs=needs,
        outputs={},
        steps=steps,
        secrets_referenced=secrets,
        conditions=conditions,
    )


def _runner_with_tags(tags: list[Any], image: str) -> Runner:
    labels = [str(t) for t in tags]
    return Runner(
        labels=labels,
        is_self_hosted=True,
        is_managed=False,
        raw=image,
    )


def _parse_steps(
    data: dict[str, Any],
    default: dict[str, Any],
    lines: list[str],
) -> list[Step]:
    steps: list[Step] = []
    index = 0

    before = data.get("before_script") or default.get("before_script")
    if isinstance(before, list):
        for cmd in before:
            steps.append(_make_shell_step(index, str(cmd), lines))
            index += 1

    script = data.get("script", [])
    if isinstance(script, list):
        for cmd in script:
            steps.append(_make_shell_step(index, str(cmd), lines))
            index += 1

    after = data.get("after_script") or default.get("after_script")
    if isinstance(after, list):
        for cmd in after:
            steps.append(_make_shell_step(index, str(cmd), lines))
            index += 1

    trigger = data.get("trigger")
    if isinstance(trigger, str | dict):
        steps.append(_make_trigger_step(index, trigger, lines))

    return steps


def _make_shell_step(index: int, command: str, lines: list[str]) -> Step:
    expressions = _extract_expressions(command, lines)
    return Step(
        index=index,
        type="shell",
        shell_command=command,
        expressions=expressions,
    )


def _make_trigger_step(index: int, trigger: str | dict[str, Any], lines: list[str]) -> Step:
    raw = str(trigger)
    return Step(
        index=index,
        type="trigger",
        name=f"trigger: {raw}",
        shell_command=None,
        expressions=_extract_expressions(raw, lines),
    )


def _extract_expressions(text: str, lines: list[str]) -> list[Expression]:
    expressions: list[Expression] = []
    for m in VARIABLE_RE.finditer(text):
        var_name = m.group(1) or m.group(2)
        raw = m.group(0)

        is_tainted = any(
            raw == tv or var_name == tv.lstrip("$").lstrip("{").rstrip("}")
            for tv in TAINTED_VARIABLES
        )

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

    return expressions


def _find_secrets(data: dict[str, Any]) -> list[str]:
    secret_keywords = ("SECRET", "TOKEN", "PASSWORD", "KEY")
    secrets: list[str] = []
    text = str(data)
    for match in VARIABLE_RE.finditer(text):
        var_name = match.group(1) or match.group(2)
        if not var_name:
            continue
        upper = var_name.upper()
        if any(kw in upper for kw in secret_keywords) and var_name not in secrets:
            secrets.append(var_name)
    return secrets


def _find_line(lines: list[str], needle: str) -> int:
    for i, line in enumerate(lines, 1):
        if needle in line:
            return i
    return 0
