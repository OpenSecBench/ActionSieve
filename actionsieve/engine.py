"""Pattern matching engine — applies patterns to normalized WorkflowModels."""

from __future__ import annotations

import warnings
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from actionsieve.matchers import match_cross_step, match_structural

if TYPE_CHECKING:
    from actionsieve.model import Job, Step, WorkflowModel


@dataclass
class Finding:
    pattern_id: str
    pattern_title: str
    file_path: str
    platform: str
    line: int
    job_id: str
    step_index: int | None
    severity_base: str
    attacker_model: str
    impact: str | list[str]
    severity_computed: str | None = None
    evidence: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    cwe: str | None = None
    mitigations: list[str] = field(default_factory=list)


_WARNED_TYPES: set[str] = set()

SUPPORTED_TYPES = frozenset({"single_step", "structural", "supply_chain", "cross_step"})


def match(model: WorkflowModel, patterns: list[dict[str, Any]]) -> list[Finding]:
    findings: list[Finding] = []
    for pattern in patterns:
        detection = pattern.get("detection", {})
        dtype = detection.get("type", "")

        if dtype == "single_step":
            findings.extend(_match_single_step(model, pattern))
        elif dtype == "structural":
            findings.extend(match_structural(model, pattern, _make_finding))
        elif dtype == "supply_chain":
            findings.extend(_match_supply_chain(model, pattern))
        elif dtype == "cross_step":
            findings.extend(match_cross_step(model, pattern, _make_finding))
        elif dtype and dtype not in _WARNED_TYPES:
            _WARNED_TYPES.add(dtype)
            warnings.warn(
                f"Unsupported detection type '{dtype}' in pattern "
                f"'{pattern.get('id', '?')}' — skipped",
                stacklevel=1,
            )

    return findings


def _match_single_step(
    model: WorkflowModel,
    pattern: dict[str, Any],
) -> list[Finding]:
    detection = pattern["detection"]
    in_block = detection.get("in_block", "")
    grep_patterns: list[str] = detection.get("grep_patterns", [])
    exclude_if_in: list[str] = detection.get("exclude_if_in", [])

    if not grep_patterns:
        return []

    findings: list[Finding] = []

    for job in model.jobs:
        for step in job.steps:
            text = _get_block_text(step, in_block)
            if text is None:
                continue

            for grep in grep_patterns:
                if grep not in text:
                    continue

                if _should_exclude(step, grep, exclude_if_in):
                    continue

                findings.append(
                    _make_finding(
                        pattern=pattern,
                        model=model,
                        job=job,
                        step=step,
                        evidence=[f"Found '{grep}' in {in_block or 'step'} block"],
                        line=_find_expression_line(step, grep),
                    )
                )

    return findings


def _match_supply_chain(
    model: WorkflowModel,
    pattern: dict[str, Any],
) -> list[Finding]:
    findings: list[Finding] = []

    for job in model.jobs:
        for step in job.steps:
            ref = step.action_ref
            if ref is None:
                continue

            if not ref.is_pinned and not ref.is_first_party:
                findings.append(
                    _make_finding(
                        pattern=pattern,
                        model=model,
                        job=job,
                        step=step,
                        evidence=[
                            f"{ref.raw}: ref_type={ref.ref_type}, unpinned third-party action",
                        ],
                        line=ref.line,
                    )
                )

    return findings


def _get_block_text(step: Step, in_block: str) -> str | None:
    if in_block in ("run", "shell_command"):
        return step.shell_command
    if in_block == "script":
        if step.type == "action" and step.action_ref and "github-script" in step.action_ref.name:
            return step.inputs.get("script")
        return step.shell_command
    if in_block == "with":
        return "\n".join(str(v) for v in step.inputs.values()) if step.inputs else None
    if in_block == "env":
        return "\n".join(str(v) for v in step.env.values()) if step.env else None
    if not in_block:
        parts = []
        if step.shell_command:
            parts.append(step.shell_command)
        for v in step.inputs.values():
            parts.append(str(v))
        return "\n".join(parts) if parts else None
    return None


def _should_exclude(step: Step, grep: str, exclude_if_in: list[str]) -> bool:
    if not exclude_if_in:
        return False

    for exclude_block in exclude_if_in:
        block_name = exclude_block.rstrip(":")
        if block_name == "env" and _expression_only_in_env(step, grep):
            return True
        if block_name == "with" and _expression_only_in_with(step, grep):
            return True

    return False


def _expression_only_in_env(step: Step, grep: str) -> bool:
    in_env = any(grep in str(v) for v in step.env.values())
    in_shell = step.shell_command is not None and grep in step.shell_command
    in_inputs = any(grep in str(v) for v in step.inputs.values())
    return in_env and not in_shell and not in_inputs


def _expression_only_in_with(step: Step, grep: str) -> bool:
    in_inputs = any(grep in str(v) for v in step.inputs.values())
    in_shell = step.shell_command is not None and grep in step.shell_command
    return in_inputs and not in_shell


def _find_expression_line(step: Step, grep: str) -> int:
    for expr in step.expressions:
        if (grep in expr.raw or grep in expr.context_path) and expr.line > 0:
            return expr.line
    return 0


def _make_finding(
    pattern: dict[str, Any],
    model: WorkflowModel,
    job: Job,
    step: Step | None,
    evidence: list[str],
    line: int,
) -> Finding:
    return Finding(
        pattern_id=pattern["id"],
        pattern_title=pattern["title"],
        file_path=model.file_path,
        platform=model.platform,
        line=line,
        job_id=job.id,
        step_index=step.index if step else None,
        severity_base=pattern["severity_base"],
        attacker_model=pattern["attacker_model"],
        impact=pattern["impact"],
        evidence=evidence,
        tags=pattern.get("tags", []),
        cwe=pattern.get("cwe"),
        mitigations=pattern.get("mitigations", []),
    )
