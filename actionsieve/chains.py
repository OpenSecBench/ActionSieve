"""Cross-step data flow analysis — taint propagation through step outputs."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from actionsieve.model import Job, WorkflowModel

STEP_OUTPUT_RE = re.compile(r"steps\.(\w+)\.outputs\.(\w+)")
MATRIX_RE = re.compile(r"matrix\.(\w+)")
FROM_JSON_RE = re.compile(r"fromJson\s*\(\s*steps\.(\w+)\.outputs\.(\w+)\s*\)")
GITHUB_ENV_RE = re.compile(r""">>?\s*["']?\$(?:GITHUB_ENV|\{GITHUB_ENV\})["']?""")
FS_READ_PATTERNS = ("readdirSync", "readdir", "ls ", "find ", "glob")


@dataclass
class DataFlow:
    source_job: str
    source_step: int
    sink_job: str
    sink_step: int
    output_name: str
    flow_type: str
    is_tainted: bool
    taint_reasons: list[str] = field(default_factory=list)
    sink_in_shell: bool = False


@dataclass
class ChainAnalysis:
    flows: list[DataFlow]
    github_env_writes: list[tuple[str, int]]


def analyze(model: WorkflowModel) -> ChainAnalysis:
    flows: list[DataFlow] = []
    env_writes: list[tuple[str, int]] = []

    for job in model.jobs:
        flows.extend(_analyze_job(model, job))
        env_writes.extend(_find_env_writes(job))

    return ChainAnalysis(flows=flows, github_env_writes=env_writes)


def _analyze_job(model: WorkflowModel, job: Job) -> list[DataFlow]:
    flows: list[DataFlow] = []
    step_id_map = {s.id: s.index for s in job.steps if s.id}
    output_writers = _find_output_writers(job)

    for step in job.steps:
        for expr in step.expressions:
            m = STEP_OUTPUT_RE.search(expr.context_path)
            if not m:
                continue

            src_id = m.group(1)
            output_name = m.group(2)
            src_index = step_id_map.get(src_id)

            if src_index is None:
                continue

            tainted, reasons = _is_source_tainted(model, job, src_index, output_name)

            flows.append(
                DataFlow(
                    source_job=job.id,
                    source_step=src_index,
                    sink_job=job.id,
                    sink_step=step.index,
                    output_name=output_name,
                    flow_type="step_output",
                    is_tainted=tainted,
                    taint_reasons=reasons,
                    sink_in_shell=expr.is_in_shell,
                )
            )

        _check_matrix_flows(model, job, step, output_writers, step_id_map, flows)

    return flows


def _find_output_writers(job: Job) -> dict[int, list[str]]:
    writers: dict[int, list[str]] = {}
    for step in job.steps:
        if step.outputs_written:
            writers[step.index] = step.outputs_written
    return writers


def _check_matrix_flows(
    model: WorkflowModel,
    job: Job,
    step: object,
    output_writers: dict[int, list[str]],
    step_id_map: dict[str, int],
    flows: list[DataFlow],
) -> None:
    from actionsieve.model import Step

    assert isinstance(step, Step)

    for expr in step.expressions:
        if not MATRIX_RE.search(expr.context_path):
            continue

        strategy_raw = str(job.outputs) if hasattr(job, "outputs") else ""
        from_json_matches = FROM_JSON_RE.findall(strategy_raw)

        for src_id, output_name in from_json_matches:
            src_index = step_id_map.get(src_id)
            if src_index is None:
                continue

            tainted, reasons = _is_source_tainted(model, job, src_index, output_name)
            if tainted:
                reasons.append("matrix via fromJson")

            flows.append(
                DataFlow(
                    source_job=job.id,
                    source_step=src_index,
                    sink_job=job.id,
                    sink_step=step.index,
                    output_name=output_name,
                    flow_type="matrix_fromjson",
                    is_tainted=tainted,
                    taint_reasons=reasons,
                    sink_in_shell=expr.is_in_shell,
                )
            )


def _is_source_tainted(
    model: WorkflowModel,
    job: Job,
    src_index: int,
    output_name: str,
) -> tuple[bool, list[str]]:
    reasons: list[str] = []
    src_step = job.steps[src_index] if src_index < len(job.steps) else None
    if src_step is None:
        return False, reasons

    if _reads_filesystem(src_step):
        reasons.append("reads filesystem content from checked-out code")

    if _runs_checked_out_script(job, src_index):
        reasons.append("executes script from checked-out code")

    is_fork = any(t.is_fork_reachable for t in model.triggers)
    if is_fork and reasons:
        reasons.append("fork-reachable trigger")
        return True, reasons

    for expr in src_step.expressions:
        if expr.is_tainted and output_name in src_step.outputs_written:
            reasons.append(f"tainted expression: {expr.context_path}")
            return True, reasons

    return bool(reasons), reasons


def _reads_filesystem(step: object) -> bool:
    from actionsieve.model import Step

    assert isinstance(step, Step)
    cmd = step.shell_command
    if not cmd:
        return False
    return any(pattern in cmd for pattern in FS_READ_PATTERNS)


def _runs_checked_out_script(job: Job, step_index: int) -> bool:
    has_checkout = False
    for step in job.steps:
        if step.index >= step_index:
            break
        if step.action_ref and "checkout" in step.action_ref.name:
            has_checkout = True

    if not has_checkout:
        return False

    src_step = job.steps[step_index]
    cmd = src_step.shell_command
    if not cmd:
        return False

    script_indicators = ("./", "bash ", "sh ", "python ", "node ", "npm ", "npx ")
    return any(ind in cmd for ind in script_indicators)


def _find_env_writes(job: Job) -> list[tuple[str, int]]:
    writes: list[tuple[str, int]] = []
    for step in job.steps:
        cmd = step.shell_command
        if cmd and GITHUB_ENV_RE.search(cmd):
            writes.append((job.id, step.index))
    return writes
