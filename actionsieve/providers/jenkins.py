"""Jenkins declarative pipeline provider — regex-based parser."""

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

MAX_FILE_SIZE = 1_048_576

JENKINSFILE_NAMES = ("Jenkinsfile", "Jenkinsfile.groovy")

LIBRARY_RE = re.compile(r"""@Library\(\s*['"]([^'"]+)['"]\s*\)""")
LIBRARY_VERSION_RE = re.compile(r"^(.+?)@(.+)$")

STAGE_RE = re.compile(r"""stage\s*\(\s*['"]([^'"]+)['"]\s*\)\s*\{""")

SHELL_STEP_RE = re.compile(r"""\b(sh|bat|powershell)\s*(?:\(\s*)?""")

INTERPOLATION_RE = re.compile(r"\$\{([^}]+)\}")
GSTRING_VAR_RE = re.compile(r"\$(\w[\w.]*)")

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

AGENT_LABEL_RE = re.compile(r"""agent\s*\{[^}]*label\s+['"]([^'"]+)['"]""", re.DOTALL)
AGENT_ANY_RE = re.compile(r"agent\s+any\b")
AGENT_NONE_RE = re.compile(r"agent\s+none\b")
AGENT_DOCKER_RE = re.compile(
    r"""agent\s*\{[^}]*docker\s*\{[^}]*image\s+['"]([^'"]+)['"]""", re.DOTALL
)

TRIGGER_CRON_RE = re.compile(r"""cron\s*\(\s*['"]([^'"]+)['"]\s*\)""")
TRIGGER_POLLSCM_RE = re.compile(r"""pollSCM\s*\(\s*['"]([^'"]+)['"]\s*\)""")

CREDENTIALS_RE = re.compile(r"""withCredentials\s*\(\s*\[([^\]]*)\]\s*\)""", re.DOTALL)
CREDENTIAL_BINDING_RE = re.compile(
    r"""(?:usernamePassword|string|file|sshUserPrivateKey|certificate)\s*\("""
)
CREDENTIAL_ID_RE = re.compile(r"""credentialsId:\s*['"]([^'"]+)['"]""")

ENV_BLOCK_RE = re.compile(r"environment\s*\{([^}]*)\}", re.DOTALL)
ENV_LINE_RE = re.compile(r"""(\w+)\s*=\s*['"]?([^'"\n]*)['"]?""")

WHEN_BRANCH_RE = re.compile(r"""when\s*\{[^}]*branch\s+['"]([^'"]+)['"]""", re.DOTALL)

PARAMS_RE = re.compile(
    r"""(?:string|text|choice|booleanParam)\s*\([^)]*name:\s*['"](\w+)['"]""",
    re.DOTALL,
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
        if "pipeline" not in text:
            raise ParseError(f"No pipeline block found: {file_path}")

        libraries = _extract_libraries(text)
        triggers = _extract_triggers(text)
        env = _extract_env(text)
        runner = _extract_agent(text)
        jobs = _parse_stages(text, runner, libraries)

        return WorkflowModel(
            platform="jenkins",
            file_path=str(file_path),
            raw={"_text": text},
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
            env_prefix="env.",
            context_roots=["params", "env", "currentBuild"],
            tainted_roots=["params", "env.BRANCH_NAME", "env.CHANGE_TITLE"],
            safe_indirection=[],
        )

    def search_query(self, pattern: dict[str, object]) -> str | None:
        return None


def _extract_libraries(text: str) -> list[ComponentRef]:
    refs: list[ComponentRef] = []
    lines = text.splitlines()
    for m in LIBRARY_RE.finditer(text):
        raw = m.group(1)
        vm = LIBRARY_VERSION_RE.match(raw)
        name = vm.group(1) if vm else raw
        ref = vm.group(2) if vm else ""
        refs.append(
            ComponentRef(
                raw=f"@Library('{raw}')",
                owner=None,
                name=name,
                ref=ref,
                ref_type="branch" if ref and not _is_tag(ref) else "tag" if ref else "unknown",
                is_pinned=False,
                is_first_party=name.startswith("jenkins-"),
                line=_find_line(lines, raw),
            )
        )
    return refs


def _is_tag(ref: str) -> bool:
    return bool(re.match(r"^v?\d+(\.\d+)*$", ref))


def _extract_triggers(text: str) -> list[Trigger]:
    triggers: list[Trigger] = []

    for m in TRIGGER_CRON_RE.finditer(text):
        triggers.append(
            Trigger(
                event="cron",
                raw_event=m.group(1),
                is_privileged=True,
                is_fork_reachable=False,
            )
        )

    for m in TRIGGER_POLLSCM_RE.finditer(text):
        triggers.append(
            Trigger(
                event="pollSCM",
                raw_event=m.group(1),
                is_privileged=True,
                is_fork_reachable=False,
            )
        )

    is_multibranch = "CHANGE_ID" in text or "BRANCH_NAME" in text
    if is_multibranch:
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


def _extract_agent(text: str) -> Runner:
    m = AGENT_LABEL_RE.search(text)
    if m:
        label = m.group(1)
        return Runner(
            labels=[label],
            is_self_hosted=True,
            is_managed=False,
            raw=label,
        )

    m = AGENT_DOCKER_RE.search(text)
    if m:
        image = m.group(1)
        return Runner(labels=[image], is_self_hosted=False, is_managed=False, raw=image)

    if AGENT_NONE_RE.search(text):
        return Runner(labels=["none"], is_self_hosted=False, is_managed=False, raw="none")

    return Runner(labels=["any"], is_self_hosted=True, is_managed=False, raw="any")


def _extract_env(text: str) -> dict[str, str]:
    env: dict[str, str] = {}
    for m in ENV_BLOCK_RE.finditer(text):
        block = m.group(1)
        for em in ENV_LINE_RE.finditer(block):
            env[em.group(1)] = em.group(2).strip()
    return env


def _parse_stages(
    text: str,
    default_runner: Runner,
    libraries: list[ComponentRef],
) -> list[Job]:
    jobs: list[Job] = []
    lines = text.splitlines()
    stage_matches = list(STAGE_RE.finditer(text))

    for i, sm in enumerate(stage_matches):
        stage_name = sm.group(1)
        start = sm.end()
        end = stage_matches[i + 1].start() if i + 1 < len(stage_matches) else len(text)
        stage_text = text[start:end]

        steps = _parse_steps(stage_text, lines)
        secrets = _find_secrets(stage_text)
        conditions = _extract_conditions(stage_text)

        agent_m = AGENT_LABEL_RE.search(stage_text)
        runner = default_runner
        if agent_m:
            label = agent_m.group(1)
            runner = Runner(labels=[label], is_self_hosted=True, is_managed=False, raw=label)

        lib_steps = _library_steps(libraries, lines, len(steps))
        all_steps = lib_steps + steps

        jobs.append(
            Job(
                id=stage_name,
                runner=runner,
                name=stage_name,
                steps=all_steps,
                secrets_referenced=secrets,
                conditions=conditions,
            )
        )

    if not jobs and _has_steps_outside_stages(text):
        steps = _parse_steps(text, lines)
        secrets = _find_secrets(text)
        lib_steps = _library_steps(libraries, lines, len(steps))
        jobs.append(
            Job(
                id="pipeline",
                runner=default_runner,
                steps=lib_steps + steps,
                secrets_referenced=secrets,
            )
        )

    return jobs


def _has_steps_outside_stages(text: str) -> bool:
    return bool(SHELL_STEP_RE.search(text))


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


def _parse_steps(stage_text: str, lines: list[str]) -> list[Step]:
    steps: list[Step] = []
    idx = 0

    for m in SHELL_STEP_RE.finditer(stage_text):
        cmd_type = m.group(1)
        start = m.end()
        cmd = _extract_string_arg(stage_text, start)
        if cmd is None:
            continue

        exprs = _extract_expressions(cmd, lines)
        steps.append(
            Step(
                index=idx,
                type="shell",
                name=cmd_type,
                shell_command=cmd,
                expressions=exprs,
            )
        )
        idx += 1

    return steps


_SCRIPT_ARG_RE = re.compile(r"script\s*:\s*")


def _extract_string_arg(text: str, pos: int) -> str | None:
    remaining = text[pos:].lstrip()

    m = _SCRIPT_ARG_RE.match(remaining)
    if m:
        remaining = remaining[m.end() :]

    for triple in ("'''", '"""'):
        if remaining.startswith(triple):
            end = remaining.find(triple, len(triple))
            if end == -1:
                return None
            return remaining[len(triple) : end]

    for quote in ("'", '"'):
        if remaining.startswith(quote):
            end = remaining.find(quote, 1)
            if end == -1:
                return None
            return remaining[1:end]

    return None


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


def _find_secrets(text: str) -> list[str]:
    secrets: list[str] = []
    for m in CREDENTIALS_RE.finditer(text):
        block = m.group(1)
        for cm in CREDENTIAL_ID_RE.finditer(block):
            cred_id = cm.group(1)
            if cred_id not in secrets:
                secrets.append(cred_id)
    return secrets


def _extract_conditions(text: str) -> list[str]:
    conditions: list[str] = []
    m = WHEN_BRANCH_RE.search(text)
    if m:
        conditions.append(f"branch == '{m.group(1)}'")
    return conditions


def _find_line(lines: list[str], needle: str) -> int:
    for i, line in enumerate(lines, 1):
        if needle in line:
            return i
    return 0
