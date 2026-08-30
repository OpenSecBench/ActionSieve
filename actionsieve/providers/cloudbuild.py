"""Google Cloud Build provider."""

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

CONFIG_FILES = ("cloudbuild.yaml", "cloudbuild.yml")

TAINTED_SUBSTITUTIONS = (
    "$BRANCH_NAME",
    "${BRANCH_NAME}",
    "$TAG_NAME",
    "${TAG_NAME}",
    "$REF_NAME",
    "${REF_NAME}",
    "$REPO_NAME",
    "${REPO_NAME}",
    "$REPO_FULL_NAME",
    "${REPO_FULL_NAME}",
)

GCR_FIRST_PARTY = (
    "gcr.io/cloud-builders/",
    "gcr.io/google.com/cloudsdktool/",
    "us-docker.pkg.dev/cloudbuild-tests/",
)


class CloudBuildProvider:
    name: str = "cloudbuild"

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
        secrets = _parse_secrets(doc)
        steps = _parse_steps(doc, lines)
        is_private_pool = _has_private_pool(doc)

        runner = make_runner("cloudbuild")
        if is_private_pool:
            pool = doc.get("options", {}).get("pool", {}).get("name", "private-pool")
            runner = _make_self_hosted_runner(str(pool))

        job = Job(
            id="build",
            runner=runner,
            name="build",
            steps=steps,
            secrets_referenced=secrets,
        )

        return WorkflowModel(
            platform="cloudbuild",
            file_path=str(file_path),
            raw=doc,
            triggers=[
                Trigger(
                    event="push",
                    raw_event="push",
                    is_privileged=True,
                    is_fork_reachable=True,
                )
            ],
            permissions=None,
            env={},
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
                "BRANCH_NAME",
                "TAG_NAME",
                "REF_NAME",
                "REPO_NAME",
                "REPO_FULL_NAME",
            ],
            safe_indirection=[],
        )

    def search_query(self, pattern: dict[str, object]) -> str | None:
        return None


def _make_self_hosted_runner(pool_name: str) -> Runner:
    return Runner(
        labels=[pool_name],
        is_self_hosted=True,
        is_managed=False,
        raw=pool_name,
    )


def _parse_secrets(doc: dict[str, Any]) -> list[str]:
    available = doc.get("availableSecrets", {})
    if not isinstance(available, dict):
        return []
    sm = available.get("secretManager", [])
    if not isinstance(sm, list):
        return []
    return [
        str(entry["versionName"])
        for entry in sm
        if isinstance(entry, dict) and "versionName" in entry
    ]


def _parse_steps(doc: dict[str, Any], lines: list[str]) -> list[Step]:
    raw_steps = doc.get("steps", [])
    if not isinstance(raw_steps, list):
        return []

    steps: list[Step] = []

    for i, step_data in enumerate(raw_steps):
        if not isinstance(step_data, dict):
            continue

        image = step_data.get("name")
        if not isinstance(image, str):
            continue

        ref = _parse_image_ref(image, lines)
        step_env = _parse_step_env(step_data)

        script = step_data.get("script")
        args = step_data.get("args", [])
        entrypoint = step_data.get("entrypoint", "")

        if isinstance(script, str):
            steps.append(
                Step(
                    index=len(steps),
                    type="shell",
                    name=step_data.get("id") or f"step-{i}",
                    shell_command=script,
                    action_ref=ref,
                    env=step_env,
                    expressions=_extract_expressions(script, lines),
                )
            )
        elif isinstance(args, list) and args:
            cmd = _args_to_command(entrypoint, args)
            steps.append(
                Step(
                    index=len(steps),
                    type="shell",
                    name=step_data.get("id") or f"step-{i}",
                    shell_command=cmd,
                    action_ref=ref,
                    env=step_env,
                    expressions=_extract_expressions(cmd, lines),
                )
            )
        else:
            steps.append(
                Step(
                    index=len(steps),
                    type="action",
                    name=step_data.get("id") or f"step-{i}",
                    action_ref=ref,
                    env=step_env,
                )
            )

    return steps


def _parse_step_env(step_data: dict[str, Any]) -> dict[str, str]:
    env_list = step_data.get("env", [])
    if not isinstance(env_list, list):
        return {}
    result: dict[str, str] = {}
    for item in env_list:
        if isinstance(item, str) and "=" in item:
            key, _, val = item.partition("=")
            result[key] = val
    return result


def _coerce_arg(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return ": ".join(f"{k}: {v}" for k, v in value.items())
    return str(value)


def _args_to_command(entrypoint: Any, args: list[Any]) -> str:
    parts = []
    if isinstance(entrypoint, str) and entrypoint:
        parts.append(entrypoint)
    parts.extend(_coerce_arg(a) for a in args)
    return " ".join(parts)


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
    short_name = name_part.rsplit("/", 1)[-1]
    is_digest = digest is not None
    is_semver = bool(re.match(r"^v?\d+\.\d+\.\d+$", version))
    is_first_party = any(raw.startswith(prefix) for prefix in GCR_FIRST_PARTY)

    return ComponentRef(
        raw=raw,
        owner=owner,
        name=short_name,
        ref=f"sha256:{digest}" if is_digest else version,
        ref_type="sha" if is_digest else "tag",
        is_pinned=is_digest or is_semver,
        is_first_party=is_first_party,
        line=_find_line(lines, raw),
    )


def _has_private_pool(doc: dict[str, Any]) -> bool:
    options = doc.get("options", {})
    if not isinstance(options, dict):
        return False
    pool = options.get("pool", {})
    return isinstance(pool, dict) and "name" in pool


def _extract_expressions(text: str, lines: list[str]) -> list[Expression]:
    expressions: list[Expression] = []
    seen: set[str] = set()

    for tainted_var in TAINTED_SUBSTITUTIONS:
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
