"""Cross-step data flow analysis — taint propagation through step outputs."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from actionsieve.model import Job, Step, WorkflowModel

STEP_OUTPUT_RE = re.compile(r"steps\.(\w+)\.outputs\.(\w+)")
MATRIX_RE = re.compile(r"matrix\.(\w+)")
FROM_JSON_RE = re.compile(r"fromJson\s*\(\s*steps\.(\w+)\.outputs\.(\w+)\s*\)")
NEEDS_OUTPUT_RE = re.compile(r"needs\.(\w+)\.outputs\.(\w+)")
FROM_JSON_NEEDS_RE = re.compile(r"fromJson\s*\(\s*needs\.(\w+)\.outputs\.(\w+)\s*\)")
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

    flows.extend(_analyze_cross_job_flows(model))

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
    step: Step,
    output_writers: dict[int, list[str]],
    step_id_map: dict[str, int],
    flows: list[DataFlow],
) -> None:
    for expr in step.expressions:
        if not MATRIX_RE.search(expr.context_path):
            continue

        strategy_raw = _get_strategy_raw(model, job)
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


def _get_strategy_raw(model: WorkflowModel, job: Job) -> str:
    jobs_raw = model.raw.get("jobs", {})
    if not isinstance(jobs_raw, dict):
        return ""
    job_raw = jobs_raw.get(job.id, {})
    if not isinstance(job_raw, dict):
        return ""
    return str(job_raw.get("strategy", ""))


def _analyze_cross_job_flows(model: WorkflowModel) -> list[DataFlow]:
    flows: list[DataFlow] = []
    job_map = {j.id: j for j in model.jobs}
    job_output_sources = _map_job_output_sources(model)

    for job in model.jobs:
        if not job.needs:
            continue

        for step in job.steps:
            flows.extend(_check_needs_expressions(model, job, step, job_map, job_output_sources))
            flows.extend(_check_cross_job_matrix(model, job, step, job_map, job_output_sources))

    return flows


def _map_job_output_sources(
    model: WorkflowModel,
) -> dict[tuple[str, str], tuple[str, str]]:
    sources: dict[tuple[str, str], tuple[str, str]] = {}
    for job in model.jobs:
        step_id_map = {s.id: s for s in job.steps if s.id}
        for output_name, expr_str in job.outputs.items():
            m = STEP_OUTPUT_RE.search(expr_str)
            if m:
                step_id = m.group(1)
                step_output = m.group(2)
                if step_id in step_id_map:
                    sources[(job.id, output_name)] = (step_id, step_output)
    return sources


def _check_needs_expressions(
    model: WorkflowModel,
    job: Job,
    step: Step,
    job_map: dict[str, Job],
    job_output_sources: dict[tuple[str, str], tuple[str, str]],
) -> list[DataFlow]:
    flows: list[DataFlow] = []
    for expr in step.expressions:
        m = NEEDS_OUTPUT_RE.search(expr.context_path)
        if not m:
            continue

        src_job_id = m.group(1)
        output_name = m.group(2)
        source = job_output_sources.get((src_job_id, output_name))
        if source is None:
            continue

        src_job = job_map.get(src_job_id)
        if src_job is None:
            continue

        step_id, step_output = source
        src_step = next((s for s in src_job.steps if s.id == step_id), None)
        if src_step is None:
            continue

        tainted, reasons = _is_source_tainted(
            model,
            src_job,
            src_step.index,
            step_output,
        )
        if tainted:
            reasons.append("cross-job output propagation")

        flows.append(
            DataFlow(
                source_job=src_job_id,
                source_step=src_step.index,
                sink_job=job.id,
                sink_step=step.index,
                output_name=output_name,
                flow_type="cross_job_output",
                is_tainted=tainted,
                taint_reasons=reasons,
                sink_in_shell=expr.is_in_shell,
            )
        )
    return flows


def _check_cross_job_matrix(
    model: WorkflowModel,
    job: Job,
    step: Step,
    job_map: dict[str, Job],
    job_output_sources: dict[tuple[str, str], tuple[str, str]],
) -> list[DataFlow]:
    flows: list[DataFlow] = []

    for expr in step.expressions:
        if not MATRIX_RE.search(expr.context_path):
            continue

        strategy_raw = _get_strategy_raw(model, job)
        for src_job_id, output_name in FROM_JSON_NEEDS_RE.findall(strategy_raw):
            source = job_output_sources.get((src_job_id, output_name))
            if source is None:
                continue

            src_job = job_map.get(src_job_id)
            if src_job is None:
                continue

            step_id, step_output = source
            src_step = next((s for s in src_job.steps if s.id == step_id), None)
            if src_step is None:
                continue

            tainted, reasons = _is_source_tainted(
                model,
                src_job,
                src_step.index,
                step_output,
            )
            if tainted:
                reasons.append("cross-job matrix via fromJson")

            flows.append(
                DataFlow(
                    source_job=src_job_id,
                    source_step=src_step.index,
                    sink_job=job.id,
                    sink_step=step.index,
                    output_name=output_name,
                    flow_type="matrix_fromjson",
                    is_tainted=tainted,
                    taint_reasons=reasons,
                    sink_in_shell=expr.is_in_shell,
                )
            )
    return flows


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


def _reads_filesystem(step: Step) -> bool:
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
