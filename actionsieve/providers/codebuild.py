"""AWS CodeBuild provider."""

from __future__ import annotations

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

CONFIG_FILES = ("buildspec.yml", "buildspec.yaml")

PHASES = ("install", "pre_build", "build", "post_build")

TAINTED_ENV_VARS = (
    "$CODEBUILD_WEBHOOK_HEAD_REF",
    "${CODEBUILD_WEBHOOK_HEAD_REF}",
    "$CODEBUILD_WEBHOOK_TRIGGER",
    "${CODEBUILD_WEBHOOK_TRIGGER}",
    "$CODEBUILD_WEBHOOK_BASE_REF",
    "${CODEBUILD_WEBHOOK_BASE_REF}",
    "$CODEBUILD_SOURCE_VERSION",
    "${CODEBUILD_SOURCE_VERSION}",
    "$CODEBUILD_WEBHOOK_ACTOR_ACCOUNT_ID",
    "${CODEBUILD_WEBHOOK_ACTOR_ACCOUNT_ID}",
)


class CodeBuildProvider:
    name: str = "codebuild"

    def detect(self, repo_path: Path) -> bool:
        return any((repo_path / f).is_file() for f in CONFIG_FILES)

    def find_files(self, repo_path: Path) -> list[Path]:
        return [repo_path / f for f in CONFIG_FILES if (repo_path / f).is_file()]

    def parse(self, file_path: Path) -> WorkflowModel:
        if file_path.stat().st_size > MAX_FILE_SIZE:
            raise ParseError(f"File exceeds {MAX_FILE_SIZE} byte limit: {file_path}")

        text = file_path.read_text(encoding="utf-8")
        try:
            doc = yaml.safe_load(text)
        except yaml.YAMLError as e:
            raise ParseError(f"Invalid YAML in {file_path}: {e}") from e

        if not isinstance(doc, dict):
            raise ParseError(f"Expected mapping in {file_path}")

        lines = text.splitlines()
        env, secrets = _parse_env(doc)
        steps = _parse_phases(doc, lines)
        image = _parse_build_image(doc)

        job = Job(
            id="build",
            runner=make_runner("codebuild"),
            name="build",
            env=env,
            steps=steps,
            secrets_referenced=secrets,
            image=image,
        )

        return WorkflowModel(
            platform="codebuild",
            file_path=str(file_path),
            raw=doc,
            triggers=[
                Trigger(
                    event="webhook",
                    raw_event="webhook",
                    is_privileged=True,
                    is_fork_reachable=True,
                )
            ],
            permissions=None,
            env=env,
            jobs=[job] if steps else [],
        )

    def resolve_ref(self, ref: ComponentRef) -> ComponentRef:
        return ref

    def expression_syntax(self) -> ExpressionSyntax:
        return ExpressionSyntax(
            delimiters=("${", "}"),
            env_prefix=None,
            context_roots=[],
            tainted_roots=[
                "CODEBUILD_WEBHOOK_HEAD_REF",
                "CODEBUILD_WEBHOOK_TRIGGER",
                "CODEBUILD_WEBHOOK_BASE_REF",
                "CODEBUILD_SOURCE_VERSION",
                "CODEBUILD_WEBHOOK_ACTOR_ACCOUNT_ID",
            ],
            safe_indirection=[],
        )

    def search_query(self, pattern: dict[str, object]) -> str | None:
        return None


def _parse_env(doc: dict[str, Any]) -> tuple[dict[str, str], list[str]]:
    env_section = doc.get("env", {})
    if not isinstance(env_section, dict):
        return {}, []

    variables: dict[str, str] = {}
    secrets: list[str] = []

    raw_vars = env_section.get("variables", {})
    if isinstance(raw_vars, dict):
        variables = {str(k): str(v) for k, v in raw_vars.items()}

    for store in ("parameter-store", "secrets-manager"):
        refs = env_section.get(store, {})
        if isinstance(refs, dict):
            secrets.extend(str(v) for v in refs.values())

    return variables, secrets


def _parse_phases(doc: dict[str, Any], lines: list[str]) -> list[Step]:
    phases = doc.get("phases", {})
    if not isinstance(phases, dict):
        return []

    steps: list[Step] = []
    for phase_name in PHASES:
        phase = phases.get(phase_name)
        if not isinstance(phase, dict):
            continue
        for block in ("commands", "finally"):
            cmds = phase.get(block, [])
            if not isinstance(cmds, list):
                continue
            for cmd in cmds:
                if not isinstance(cmd, str):
                    continue
                steps.append(
                    Step(
                        index=len(steps),
                        type="shell",
                        name=f"{phase_name}.{block}" if block == "finally" else phase_name,
                        shell_command=cmd,
                        expressions=_extract_expressions(cmd, lines),
                    )
                )

    return steps


def _parse_build_image(doc: dict[str, Any]) -> str | None:
    env_section = doc.get("env", {})
    if not isinstance(env_section, dict):
        return None
    image = env_section.get("image")
    return str(image) if isinstance(image, str) else None


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
