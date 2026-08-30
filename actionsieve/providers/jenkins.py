"""Jenkins pipeline provider — tree-sitter Groovy parser."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

from actionsieve.model import (
    ComponentRef,
    Expression,
    Job,
    Runner,
    Step,
    Trigger,
    WorkflowModel,
)
from actionsieve.providers import ExpressionSyntax, ParseError
from actionsieve.providers.jenkins_ast import (
    AgentInfo,
    LibraryRef,
    ShellCall,
    extract_pipeline_info,
    find_shell_calls,
    parse_groovy,
)

MAX_FILE_SIZE = 1_048_576

JENKINSFILE_NAMES = ("Jenkinsfile", "Jenkinsfile.groovy")

INTERPOLATION_RE = re.compile(r"\$\{([^}]+)\}")
GSTRING_VAR_RE = re.compile(r"\$(\w[\w.]*)")

DSL_BLOCKS_RE = re.compile(r"^\s*(?:parameters|options|triggers)\s*\{", re.MULTILINE)

TAINTED_CONTEXTS = (
    "params.",
    "env.BRANCH_NAME",
    "env.CHANGE_TITLE",
    "env.CHANGE_AUTHOR",
    "env.CHANGE_AUTHOR_DISPLAY_NAME",
    "env.CHANGE_TARGET",
    "env.CHANGE_BRANCH",
    "env.CHANGE_FORK",
    "env.TAG_NAME",
)


class JenkinsProvider:
    name: str = "jenkins"

    def detect(self, repo_path: Path) -> bool:
        return any((repo_path / f).is_file() for f in JENKINSFILE_NAMES)

    def find_files(self, repo_path: Path) -> list[Path]:
        return [repo_path / f for f in JENKINSFILE_NAMES if (repo_path / f).is_file()]

    def parse(self, file_path: Path) -> WorkflowModel:
        if file_path.stat().st_size > MAX_FILE_SIZE:
            raise ParseError(f"File exceeds {MAX_FILE_SIZE} byte limit: {file_path}")

        text = file_path.read_text(encoding="utf-8")
        tree = parse_groovy(_strip_dsl_blocks(text))
        info = extract_pipeline_info(tree)
        lines = text.splitlines()

        libraries = [_to_component_ref(lib) for lib in info.libraries]
        triggers = _extract_triggers(text)
        runner = _to_runner(info.agent)

        jobs: list[Job] = []
        if info.stages:
            for stage in info.stages:
                calls = find_shell_calls(stage.node)
                steps = _to_steps(calls, lines)
                lib_steps = _library_steps(libraries, lines, len(steps))
                secrets = [c.cred_id for c in info.credentials]
                jobs.append(
                    Job(
                        id=stage.name,
                        runner=runner,
                        name=stage.name,
                        steps=lib_steps + steps,
                        secrets_referenced=secrets,
                    )
                )
        elif info.shell_calls:
            steps = _to_steps(info.shell_calls, lines)
            lib_steps = _library_steps(libraries, lines, len(steps))
            secrets = [c.cred_id for c in info.credentials]
            jobs.append(
                Job(
                    id="pipeline",
                    runner=runner,
                    steps=lib_steps + steps,
                    secrets_referenced=secrets,
                )
            )

        return WorkflowModel(
            platform="jenkins",
            file_path=str(file_path),
            raw={"_text": text},
            triggers=triggers,
            permissions=None,
            env=info.env,
            jobs=jobs,
        )

    def resolve_ref(self, ref: ComponentRef) -> ComponentRef:
        return ref

    def expression_syntax(self) -> ExpressionSyntax:
        return ExpressionSyntax(
            delimiters=("${", "}"),
            env_prefix="env.",
            context_roots=["params", "env", "currentBuild"],
            tainted_roots=["params", "env.BRANCH_NAME", "env.CHANGE_TITLE"],
            safe_indirection=[],
        )

    def search_query(self, pattern: dict[str, object]) -> str | None:
        return None


def _strip_dsl_blocks(text: str) -> str:
    result = text
    for m in reversed(list(DSL_BLOCKS_RE.finditer(result))):
        brace_start = result.index("{", m.start())
        depth = 0
        end = brace_start
        for i in range(brace_start, len(result)):
            if result[i] == "{":
                depth += 1
            elif result[i] == "}":
                depth -= 1
                if depth == 0:
                    end = i + 1
                    break
        newlines = result[m.start() : end].count("\n")
        result = result[: m.start()] + ("\n" * newlines) + result[end:]
    return result


def _to_component_ref(lib: LibraryRef) -> ComponentRef:
    return ComponentRef(
        raw=f"@Library('{lib.raw}')",
        owner=None,
        name=lib.name,
        ref=lib.version,
        ref_type=_ref_type(lib.version),
        is_pinned=False,
        is_first_party=lib.name.startswith("jenkins-"),
        line=lib.line,
    )


def _ref_type(version: str) -> str:
    if not version:
        return "unknown"
    if re.match(r"^v?\d+(\.\d+)*$", version):
        return "tag"
    return "branch"


def _to_runner(agent: AgentInfo | None) -> Runner:
    if not agent:
        return Runner(labels=["any"], is_self_hosted=True, is_managed=False, raw="any")
    if agent.kind == "docker":
        lbl = agent.label
        return Runner(labels=[lbl], is_self_hosted=False, is_managed=False, raw=lbl)
    if agent.kind == "none":
        return Runner(labels=["none"], is_self_hosted=False, is_managed=False, raw="none")
    if agent.kind == "label":
        return Runner(labels=[agent.label], is_self_hosted=True, is_managed=False, raw=agent.label)
    return Runner(labels=["any"], is_self_hosted=True, is_managed=False, raw="any")


def _extract_triggers(text: str) -> list[Trigger]:
    triggers: list[Trigger] = []

    if re.search(r"""cron\s*\(\s*['"]([^'"]+)['"]\s*\)""", text):
        triggers.append(
            Trigger(
                event="cron",
                raw_event="cron",
                is_privileged=True,
                is_fork_reachable=False,
            )
        )

    if re.search(r"""pollSCM\s*\(\s*['"]([^'"]+)['"]\s*\)""", text):
        triggers.append(
            Trigger(
                event="pollSCM",
                raw_event="pollSCM",
                is_privileged=True,
                is_fork_reachable=False,
            )
        )

    if "CHANGE_ID" in text or "BRANCH_NAME" in text:
        triggers.append(
            Trigger(
                event="multibranch",
                raw_event="multibranch",
                is_privileged=False,
                is_fork_reachable=True,
            )
        )

    if not triggers:
        triggers.append(
            Trigger(
                event="push",
                raw_event="push",
                is_privileged=True,
                is_fork_reachable=False,
            )
        )

    return triggers


def _to_steps(calls: list[ShellCall], lines: list[str]) -> list[Step]:
    steps: list[Step] = []
    for i, call in enumerate(calls):
        exprs = _extract_expressions(call.command, lines) if not call.is_safe_string else []
        steps.append(
            Step(
                index=i,
                type="shell",
                name=call.cmd_type,
                shell_command=call.command,
                expressions=exprs,
            )
        )
    return steps


def _library_steps(
    libraries: list[ComponentRef],
    lines: list[str],
    offset: int,
) -> list[Step]:
    return [
        Step(
            index=offset + i,
            type="action",
            name=f"@Library('{lib.name}')",
            action_ref=lib,
        )
        for i, lib in enumerate(libraries)
    ]


def _extract_expressions(text: str, lines: list[str]) -> list[Expression]:
    expressions: list[Expression] = []
    seen: set[str] = set()

    for m in INTERPOLATION_RE.finditer(text):
        context_path = m.group(1).strip()
        raw = m.group(0)
        if raw in seen:
            continue
        seen.add(raw)
        is_tainted = any(context_path.startswith(t) for t in TAINTED_CONTEXTS)
        expressions.append(
            Expression(
                raw=raw,
                context_path=context_path,
                location="script",
                is_in_shell=True,
                is_tainted=is_tainted,
                line=_find_line(lines, raw),
            )
        )

    for m in GSTRING_VAR_RE.finditer(text):
        raw = m.group(0)
        if raw in seen or raw.startswith("${"):
            continue
        context_path = m.group(1)
        if not any(context_path.startswith(t) for t in TAINTED_CONTEXTS):
            continue
        seen.add(raw)
        expressions.append(
            Expression(
                raw=raw,
                context_path=context_path,
                location="script",
                is_in_shell=True,
                is_tainted=True,
                line=_find_line(lines, raw),
            )
        )

    return expressions


def _find_line(lines: list[str], needle: str) -> int:
    for i, line in enumerate(lines, 1):
        if needle in line:
            return i
    return 0
