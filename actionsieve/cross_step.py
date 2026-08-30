"""Cross-step pattern matchers — chain-based detection logic."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable

    from actionsieve.chains import ChainAnalysis
    from actionsieve.engine import Finding
    from actionsieve.model import WorkflowModel

    MakeFinding = Callable[..., Finding]


def match_cross_step(
    model: WorkflowModel,
    pattern: dict[str, Any],
    make_finding: MakeFinding,
) -> list[Finding]:
    from actionsieve.chains import analyze

    pid = pattern["id"]
    analysis = analyze(model)

    if pid == "fs-to-matrix-injection":
        return _match_fs_to_matrix(model, pattern, analysis, make_finding)
    if pid == "fork-script-output-injection":
        return _match_fork_script_output(model, pattern, analysis, make_finding)
    if pid == "composite-output-injection":
        return _match_composite_output(model, pattern, analysis, make_finding)

    return _match_generic_cross_step(model, pattern, analysis, make_finding)


def _match_fs_to_matrix(
    model: WorkflowModel,
    pattern: dict[str, Any],
    analysis: ChainAnalysis,
    make_finding: MakeFinding,
) -> list[Finding]:
    findings: list[Finding] = []
    for flow in analysis.flows:
        if not flow.is_tainted:
            continue
        if not flow.sink_in_shell:
            continue
        has_fs_read = any("filesystem" in r for r in flow.taint_reasons)
        has_matrix = flow.flow_type == "matrix_fromjson"
        if has_fs_read or has_matrix:
            job = next((j for j in model.jobs if j.id == flow.sink_job), None)
            if job is None:
                continue
            step = job.steps[flow.sink_step] if flow.sink_step < len(job.steps) else None
            findings.append(
                make_finding(
                    pattern=pattern,
                    model=model,
                    job=job,
                    step=step,
                    evidence=[
                        f"Data flow: step {flow.source_step} → step {flow.sink_step}",
                        f"Output: {flow.output_name}",
                        f"Flow type: {flow.flow_type}",
                        *flow.taint_reasons,
                    ],
                    line=step.expressions[0].line if step and step.expressions else 0,
                )
            )
    return findings


def _match_fork_script_output(
    model: WorkflowModel,
    pattern: dict[str, Any],
    analysis: ChainAnalysis,
    make_finding: MakeFinding,
) -> list[Finding]:
    findings: list[Finding] = []
    for flow in analysis.flows:
        if not flow.is_tainted:
            continue
        if not flow.sink_in_shell:
            continue
        has_script = any("script" in r for r in flow.taint_reasons)
        if has_script and flow.flow_type == "step_output":
            job = next((j for j in model.jobs if j.id == flow.sink_job), None)
            if job is None:
                continue
            step = job.steps[flow.sink_step] if flow.sink_step < len(job.steps) else None
            findings.append(
                make_finding(
                    pattern=pattern,
                    model=model,
                    job=job,
                    step=step,
                    evidence=[
                        f"Data flow: step {flow.source_step} → step {flow.sink_step}",
                        f"Output: {flow.output_name}",
                        "Fork script output consumed in shell interpolation",
                        *flow.taint_reasons,
                    ],
                    line=step.expressions[0].line if step and step.expressions else 0,
                )
            )
    return findings


def _match_composite_output(
    model: WorkflowModel,
    pattern: dict[str, Any],
    analysis: ChainAnalysis,
    make_finding: MakeFinding,
) -> list[Finding]:
    findings: list[Finding] = []
    for flow in analysis.flows:
        if not flow.is_tainted or not flow.sink_in_shell:
            continue
        if flow.flow_type != "step_output":
            continue
        src_job = next((j for j in model.jobs if j.id == flow.source_job), None)
        if src_job is None:
            continue
        src_idx = flow.source_step
        src_step = src_job.steps[src_idx] if src_idx < len(src_job.steps) else None
        if src_step is None:
            continue
        if not any(e.location == "composite_output" for e in src_step.expressions):
            continue
        sink_job = next((j for j in model.jobs if j.id == flow.sink_job), None)
        if sink_job is None:
            continue
        sink_step = (
            sink_job.steps[flow.sink_step] if flow.sink_step < len(sink_job.steps) else None
        )
        findings.append(
            make_finding(
                pattern=pattern,
                model=model,
                job=sink_job,
                step=sink_step,
                evidence=[
                    f"Composite output taint: step {flow.source_step} → step {flow.sink_step}",
                    f"Output: {flow.output_name}",
                    *flow.taint_reasons,
                ],
                line=sink_step.expressions[0].line if sink_step and sink_step.expressions else 0,
            )
        )
    return findings


def _match_generic_cross_step(
    model: WorkflowModel,
    pattern: dict[str, Any],
    analysis: ChainAnalysis,
    make_finding: MakeFinding,
) -> list[Finding]:
    findings: list[Finding] = []
    grep_patterns: list[str] = pattern.get("detection", {}).get("grep_patterns", [])

    for flow in analysis.flows:
        if not flow.is_tainted or not flow.sink_in_shell:
            continue

        job = next((j for j in model.jobs if j.id == flow.sink_job), None)
        if job is None:
            continue
        step = job.steps[flow.sink_step] if flow.sink_step < len(job.steps) else None
        if not step:
            continue

        text = step.shell_command or ""
        if grep_patterns and not any(g in text for g in grep_patterns):
            continue

        findings.append(
            make_finding(
                pattern=pattern,
                model=model,
                job=job,
                step=step,
                evidence=[
                    f"Tainted data flow: step {flow.source_step} → step {flow.sink_step}",
                    f"Output: {flow.output_name}",
                    *flow.taint_reasons,
                ],
                line=step.expressions[0].line if step.expressions else 0,
            )
        )
    return findings
