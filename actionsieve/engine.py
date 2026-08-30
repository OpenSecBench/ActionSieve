"""Pattern matching engine — applies patterns to normalized WorkflowModels."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

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
    evidence: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    cwe: str | None = None
    mitigations: list[str] = field(default_factory=list)


def match(model: WorkflowModel, patterns: list[dict[str, Any]]) -> list[Finding]:
    findings: list[Finding] = []
    for pattern in patterns:
        detection = pattern.get("detection", {})
        dtype = detection.get("type", "")

        if dtype == "single_step":
            findings.extend(_match_single_step(model, pattern))
        elif dtype == "structural":
            findings.extend(_match_structural(model, pattern))
        elif dtype == "supply_chain":
            findings.extend(_match_supply_chain(model, pattern))

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


def _match_structural(
    model: WorkflowModel,
    pattern: dict[str, Any],
) -> list[Finding]:
    pid = pattern["id"]

    if pid == "prt-checkout-head":
        return _match_prt_checkout(model, pattern)
    if pid == "self-hosted-runner-persistence":
        return _match_self_hosted(model, pattern)
    if pid == "oidc-token-fork":
        return _match_oidc_fork(model, pattern)
    if pid == "actions-cache-poisoning":
        return _match_cache_poisoning(model, pattern)
    if pid == "workflow-run-artifact-trust":
        return _match_workflow_run_artifacts(model, pattern)
    if pid == "artifact-supply-chain":
        return _match_artifact_supply_chain(model, pattern)

    checks: list[dict[str, Any]] = pattern["detection"].get("checks", [])
    if checks:
        return _match_structural_checks(model, pattern, checks)

    return []


def _match_prt_checkout(
    model: WorkflowModel,
    pattern: dict[str, Any],
) -> list[Finding]:
    has_prt = any(t.raw_event == "pull_request_target" for t in model.triggers)
    if not has_prt:
        return []

    head_ref_markers = (
        "github.event.pull_request.head.sha",
        "github.event.pull_request.head.ref",
        "github.head_ref",
    )

    findings: list[Finding] = []
    for job in model.jobs:
        for step in job.steps:
            if step.action_ref is None or "checkout" not in step.action_ref.name:
                continue
            ref_input = step.inputs.get("ref", "")
            if any(marker in ref_input for marker in head_ref_markers):
                findings.append(
                    _make_finding(
                        pattern=pattern,
                        model=model,
                        job=job,
                        step=step,
                        evidence=[
                            "pull_request_target trigger with checkout of PR head",
                            f"ref: {ref_input}",
                        ],
                        line=step.action_ref.line,
                    )
                )
    return findings


def _match_self_hosted(
    model: WorkflowModel,
    pattern: dict[str, Any],
) -> list[Finding]:
    findings: list[Finding] = []
    for job in model.jobs:
        if job.runner.is_self_hosted:
            findings.append(
                _make_finding(
                    pattern=pattern,
                    model=model,
                    job=job,
                    step=None,
                    evidence=[f"Self-hosted runner: {job.runner.labels}"],
                    line=0,
                )
            )
    return findings


def _match_oidc_fork(
    model: WorkflowModel,
    pattern: dict[str, Any],
) -> list[Finding]:
    is_fork_reachable = any(t.is_fork_reachable for t in model.triggers)
    if not is_fork_reachable:
        return []

    findings: list[Finding] = []
    for job in model.jobs:
        perms = job.permissions or model.permissions
        if perms and perms.raw.get("id-token") == "write":
            findings.append(
                _make_finding(
                    pattern=pattern,
                    model=model,
                    job=job,
                    step=None,
                    evidence=["id-token: write on fork-reachable workflow"],
                    line=0,
                )
            )
    return findings


def _match_cache_poisoning(
    model: WorkflowModel,
    pattern: dict[str, Any],
) -> list[Finding]:
    findings: list[Finding] = []
    for job in model.jobs:
        for step in job.steps:
            if (
                step.action_ref
                and "cache" in step.action_ref.name
                and "restore-keys" in step.inputs
            ):
                findings.append(
                    _make_finding(
                        pattern=pattern,
                        model=model,
                        job=job,
                        step=step,
                        evidence=[
                            f"actions/cache with restore-keys: {step.inputs['restore-keys']}",
                        ],
                        line=step.action_ref.line,
                    )
                )
    return findings


def _match_workflow_run_artifacts(
    model: WorkflowModel,
    pattern: dict[str, Any],
) -> list[Finding]:
    has_workflow_run = any(t.raw_event == "workflow_run" for t in model.triggers)
    if not has_workflow_run:
        return []

    findings: list[Finding] = []
    for job in model.jobs:
        for step in job.steps:
            if step.action_ref and "download-artifact" in step.action_ref.raw:
                findings.append(
                    _make_finding(
                        pattern=pattern,
                        model=model,
                        job=job,
                        step=step,
                        evidence=["workflow_run trigger with artifact download"],
                        line=step.action_ref.line,
                    )
                )
    return findings


def _match_artifact_supply_chain(
    model: WorkflowModel,
    pattern: dict[str, Any],
) -> list[Finding]:
    has_workflow_run = any(t.raw_event == "workflow_run" for t in model.triggers)
    if not has_workflow_run:
        return []

    findings: list[Finding] = []
    for job in model.jobs:
        for step in job.steps:
            has_download = step.action_ref and "download-artifact" in step.action_ref.raw
            runs_after = step.shell_command or any(
                s.shell_command for s in job.steps if s.index > step.index
            )
            if has_download and runs_after:
                findings.append(
                    _make_finding(
                        pattern=pattern,
                        model=model,
                        job=job,
                        step=step,
                        evidence=[
                            "Artifact downloaded in workflow_run, then executed",
                        ],
                        line=step.action_ref.line if step.action_ref else 0,
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


def _match_structural_checks(
    model: WorkflowModel,
    pattern: dict[str, Any],
    checks: list[dict[str, Any]],
) -> list[Finding]:
    findings: list[Finding] = []
    for job in model.jobs:
        if _all_checks_pass(model, job, checks):
            findings.append(
                _make_finding(
                    pattern=pattern,
                    model=model,
                    job=job,
                    step=None,
                    evidence=_describe_checks(model, job, checks),
                    line=0,
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


def _all_checks_pass(
    model: WorkflowModel,
    job: Job,
    checks: list[dict[str, Any]],
) -> bool:
    return all(_check_passes(model, job, check) for check in checks)


def _check_passes(
    model: WorkflowModel,
    job: Job,
    check: dict[str, Any],
) -> bool:
    if "trigger_includes" in check:
        return any(t.raw_event == check["trigger_includes"] for t in model.triggers)

    if "has_step" in check:
        return _has_step_check(job, check["has_step"])

    if "job_has_secrets" in check:
        if check["job_has_secrets"]:
            return len(job.secrets_referenced) > 0
        return len(job.secrets_referenced) == 0

    if "runner_is_self_hosted" in check:
        return bool(job.runner.is_self_hosted == check["runner_is_self_hosted"])

    if "fork_reachable" in check:
        return bool(any(t.is_fork_reachable for t in model.triggers) == check["fork_reachable"])

    return False


def _has_step_check(job: Job, spec: dict[str, Any]) -> bool:
    uses = spec.get("uses", "")
    with_ref_contains = spec.get("with_ref_contains", "")

    for step in job.steps:
        if step.action_ref is None:
            continue
        if uses and uses not in step.action_ref.raw:
            continue
        if with_ref_contains:
            ref_input = step.inputs.get("ref", "")
            if with_ref_contains not in ref_input:
                continue
        return True

    return False


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


def _describe_checks(
    model: WorkflowModel,
    job: Job,
    checks: list[dict[str, Any]],
) -> list[str]:
    evidence: list[str] = []
    for check in checks:
        if "trigger_includes" in check:
            evidence.append(f"Trigger includes {check['trigger_includes']}")
        if "has_step" in check:
            evidence.append(f"Job has step matching {check['has_step']}")
        if "job_has_secrets" in check:
            evidence.append(f"Job references secrets: {job.secrets_referenced}")
        if "runner_is_self_hosted" in check:
            evidence.append(f"Runner is self-hosted: {job.runner.is_self_hosted}")
        if "fork_reachable" in check:
            reachable = any(t.is_fork_reachable for t in model.triggers)
            evidence.append(f"Fork reachable: {reachable}")
    return evidence
