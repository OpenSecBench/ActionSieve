"""GitHub Actions provider."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any, cast

if TYPE_CHECKING:
    from pathlib import Path

import yaml

from actionsieve.model import (
    ComponentRef,
    Expression,
    Job,
    Permissions,
    Step,
    Trigger,
    WorkflowModel,
    make_runner,
)
from actionsieve.providers import ExpressionSyntax, ParseError

MAX_FILE_SIZE = 1_048_576  # 1MB

EXPRESSION_RE = re.compile(r"\$\{\{\s*(.*?)\s*\}\}")

GITHUB_FIRST_PARTY = frozenset({"actions", "github"})

TAINTED_CONTEXT_PREFIXES = (
    "github.event.pull_request.title",
    "github.event.pull_request.body",
    "github.event.pull_request.head.ref",
    "github.event.pull_request.head.label",
    "github.event.issue.title",
    "github.event.issue.body",
    "github.event.comment.body",
    "github.event.review.body",
    "github.event.review_comment.body",
    "github.event.discussion.title",
    "github.event.discussion.body",
    "github.event.head_commit.message",
    "github.event.head_commit.author.name",
    "github.event.head_commit.author.email",
    "github.event.commits",
    "github.event.workflow_run.display_title",
    "github.event.workflow_run.head_branch",
    "github.event.pages",
    "github.head_ref",
)

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

GITHUB_OUTPUT_RE = re.compile(r""">>?\s*["']?\$(?:GITHUB_OUTPUT|\{GITHUB_OUTPUT\})["']?""")
OUTPUT_KEY_RE = re.compile(r"""(\w[\w-]*)=""")


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
        env = _str_dict(raw.get("env", {}))
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

    def resolve_ref(self, ref: ComponentRef) -> ComponentRef:
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
        # YAML parses bare `on:` as boolean True key
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

    outputs = _str_dict(data.get("outputs", {}))

    steps_raw = data.get("steps", [])
    steps = [_parse_step(i, s, lines) for i, s in enumerate(steps_raw) if isinstance(s, dict)]

    secrets_referenced = _find_secrets(data)

    conditions: list[str] = []
    if "if" in data:
        conditions.append(str(data["if"]))

    return Job(
        id=str(job_id),
        runner=make_runner(runner_raw),
        name=data.get("name"),
        permissions=_parse_permissions(data.get("permissions")),
        env=_str_dict(data.get("env", {})),
        needs=needs,
        outputs=outputs,
        steps=steps,
        secrets_referenced=secrets_referenced,
        conditions=conditions,
    )


def _parse_step(index: int, data: dict[str, Any], lines: list[str]) -> Step:
    step_type = "shell"
    shell_command: str | None = None
    action_ref: ComponentRef | None = None
    inputs: dict[str, str] = {}

    if "run" in data:
        step_type = "shell"
        shell_command = str(data["run"])
    elif "uses" in data:
        step_type = "action"
        action_ref = _parse_uses(str(data["uses"]), lines)
        inputs = _str_dict(data.get("with", {}))
    else:
        step_type = "script"

    env = _str_dict(data.get("env", {}))

    all_text = _step_text(data)
    expressions = _extract_expressions(all_text, shell_command, lines)

    outputs_written = _detect_outputs_written(shell_command)

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


def _parse_uses(uses: str, lines: list[str]) -> ComponentRef:
    line_num = _find_line(lines, uses)

    if "@" in uses:
        path_part, ref = uses.rsplit("@", 1)
    else:
        path_part = uses
        ref = ""

    owner: str | None = None
    name = path_part
    if "/" in path_part:
        parts = path_part.split("/", 1)
        owner = parts[0]
        name = parts[1]

    ref_type = _classify_ref(ref)
    is_first_party = owner in GITHUB_FIRST_PARTY if owner else False

    return ComponentRef(
        raw=uses,
        owner=owner,
        name=name,
        ref=ref,
        ref_type=ref_type,
        is_pinned=ref_type == "sha",
        is_first_party=is_first_party,
        line=line_num,
    )


def _classify_ref(ref: str) -> str:
    if not ref:
        return "unknown"
    if len(ref) == 40 and all(c in "0123456789abcdef" for c in ref):
        return "sha"
    if re.match(r"^v?\d+(\.\d+)*$", ref):
        return "tag"
    return "branch"


def _extract_expressions(
    text: str,
    shell_command: str | None,
    file_lines: list[str] | None = None,
) -> list[Expression]:
    expressions: list[Expression] = []
    for m in EXPRESSION_RE.finditer(text):
        context_path = m.group(1).strip()
        raw = m.group(0)

        in_shell = shell_command is not None and raw in (shell_command or "")
        location = "run" if in_shell else "other"

        is_tainted = any(context_path.startswith(prefix) for prefix in TAINTED_CONTEXT_PREFIXES)

        line = _find_line(file_lines or [], raw) if file_lines else 0

        expressions.append(
            Expression(
                raw=raw,
                context_path=context_path,
                location=location,
                is_in_shell=in_shell,
                is_tainted=is_tainted,
                line=line,
            )
        )

    return expressions


def _detect_outputs_written(shell_command: str | None) -> list[str]:
    if not shell_command:
        return []
    keys: list[str] = []
    for line in shell_command.splitlines():
        if GITHUB_OUTPUT_RE.search(line):
            key_match = OUTPUT_KEY_RE.search(line)
            if key_match:
                keys.append(key_match.group(1))
    return keys


def _find_secrets(data: Any) -> list[str]:
    secrets: list[str] = []
    text = str(data)
    for match in re.finditer(r"\$\{\{\s*secrets\.(\w+)\s*\}\}", text):
        name = match.group(1)
        if name not in secrets:
            secrets.append(name)
    return secrets


def _step_text(data: dict[str, Any]) -> str:
    parts: list[str] = []
    for key in ("run", "name", "if"):
        if key in data:
            parts.append(str(data[key]))
    with_data = data.get("with", {})
    if isinstance(with_data, dict):
        for v in with_data.values():
            parts.append(str(v))
    env_data = data.get("env", {})
    if isinstance(env_data, dict):
        for v in env_data.values():
            parts.append(str(v))
    return "\n".join(parts)


def _find_line(lines: list[str], needle: str) -> int:
    for i, line in enumerate(lines, 1):
        if needle in line:
            return i
    return 0


def _str_dict(raw: Any) -> dict[str, str]:
    if not isinstance(raw, dict):
        return {}
    return {str(k): str(v) for k, v in raw.items()}
