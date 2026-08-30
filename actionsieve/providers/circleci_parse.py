"""CircleCI config parsing helpers — orbs, steps, expressions."""

from __future__ import annotations

import re
from typing import Any

from actionsieve.model import ComponentRef, Expression, Step

PIPELINE_EXPR_RE = re.compile(r"<<\s*(pipeline\.\S+?|parameters\.\S+?)\s*>>")

TAINTED_ENV_VARS = (
    "$CIRCLE_BRANCH",
    "$CIRCLE_USERNAME",
    "$CIRCLE_PR_USERNAME",
    "${CIRCLE_BRANCH}",
    "${CIRCLE_USERNAME}",
    "${CIRCLE_PR_USERNAME}",
)

TAINTED_PIPELINE_PARAMS = (
    "pipeline.git.branch",
    "pipeline.git.tag",
    "pipeline.parameters.",
    "parameters.",
)


def find_line(lines: list[str], needle: str) -> int:
    for i, line in enumerate(lines, 1):
        if needle in line:
            return i
    return 0


def parse_orbs(raw: dict[str, Any], lines: list[str]) -> list[ComponentRef]:
    orbs_section = raw.get("orbs", {})
    if not isinstance(orbs_section, dict):
        return []

    refs: list[ComponentRef] = []
    for _alias, spec in orbs_section.items():
        if isinstance(spec, str):
            ref = _parse_orb_ref(spec, lines)
            if ref:
                refs.append(ref)
    return refs


def _parse_orb_ref(spec: str, lines: list[str]) -> ComponentRef | None:
    if "@" not in spec:
        return None
    full_name, _, version = spec.partition("@")
    owner = full_name.split("/")[0] if "/" in full_name else None
    name = full_name.split("/")[-1] if "/" in full_name else full_name
    is_first_party = owner == "circleci" if owner else False
    is_volatile = version == "volatile"
    is_exact = bool(re.match(r"^\d+\.\d+\.\d+$", version))

    return ComponentRef(
        raw=spec,
        owner=owner,
        name=name,
        ref=version,
        ref_type="tag" if is_exact else "branch" if is_volatile else "tag",
        is_pinned=is_exact and not is_volatile,
        is_first_party=is_first_party,
        line=find_line(lines, spec),
    )


def orb_command_ref(key: str, lines: list[str]) -> ComponentRef:
    parts = key.split("/", 1)
    return ComponentRef(
        raw=key,
        owner=parts[0] if len(parts) > 1 else None,
        name=parts[1] if len(parts) > 1 else key,
        ref="",
        ref_type="unknown",
        is_pinned=False,
        is_first_party=parts[0] == "circleci" if len(parts) > 1 else False,
        line=find_line(lines, key),
    )


BUILTIN_STEPS = frozenset(
    {
        "checkout",
        "setup_remote_docker",
        "store_artifacts",
        "store_test_results",
        "persist_to_workspace",
        "attach_workspace",
        "add_ssh_keys",
        "restore_cache",
        "save_cache",
    }
)


def parse_steps(steps_raw: list[Any], lines: list[str]) -> list[Step]:
    steps: list[Step] = []
    for i, step_data in enumerate(steps_raw):
        step = _parse_step(i, step_data, lines)
        if step:
            steps.append(step)
    return steps


def _parse_step(index: int, data: Any, lines: list[str]) -> Step | None:
    if isinstance(data, str):
        if data == "checkout":
            return Step(index=index, type="action", name="checkout")
        return None

    if not isinstance(data, dict):
        return None

    if "run" in data:
        return _parse_run_step(index, data["run"], lines)

    for key, value in data.items():
        if key in BUILTIN_STEPS:
            return Step(index=index, type="action", name=key)

        if "/" in key:
            return Step(
                index=index,
                type="action",
                name=key,
                action_ref=orb_command_ref(key, lines),
                inputs={str(k): str(v) for k, v in value.items()}
                if isinstance(value, dict)
                else {},
            )

    return None


def _parse_run_step(index: int, data: Any, lines: list[str]) -> Step:
    if isinstance(data, str):
        cmd = data
        name = None
    elif isinstance(data, dict):
        cmd = str(data.get("command", ""))
        name = data.get("name")
    else:
        cmd = str(data)
        name = None

    env: dict[str, str] = {}
    if isinstance(data, dict):
        raw_env = data.get("environment", {})
        if isinstance(raw_env, dict):
            env = {str(k): str(v) for k, v in raw_env.items()}

    return Step(
        index=index,
        type="shell",
        name=name,
        shell_command=cmd,
        expressions=extract_expressions(cmd, lines),
        env=env,
    )


def extract_expressions(text: str, lines: list[str]) -> list[Expression]:
    expressions: list[Expression] = []
    seen: set[str] = set()

    for m in PIPELINE_EXPR_RE.finditer(text):
        raw = m.group(0)
        context_path = m.group(1).strip()
        if raw in seen:
            continue
        seen.add(raw)
        is_tainted = any(context_path.startswith(t) for t in TAINTED_PIPELINE_PARAMS)
        expressions.append(
            Expression(
                raw=raw,
                context_path=context_path,
                location="pipeline_value",
                is_in_shell=True,
                is_tainted=is_tainted,
                line=find_line(lines, raw),
            )
        )

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
                    line=find_line(lines, tainted_var),
                )
            )

    return expressions
