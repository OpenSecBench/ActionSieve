"""Pattern matchers — structural detection logic."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from actionsieve.matchers_cloud import (
    match_cloudbuild_default_sa,
    match_cloudbuild_secret_in_env,
    match_codebuild_exported_secrets,
    match_codebuild_plaintext_secrets,
    match_codebuild_privileged_mode,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from actionsieve.engine import Finding
    from actionsieve.model import Job, Step, WorkflowModel

    MakeFinding = Callable[..., Finding]


def match_structural(
    model: WorkflowModel,
    pattern: dict[str, Any],
    make_finding: MakeFinding,
) -> list[Finding]:
    pid = pattern["id"]

    dispatch = {
        "prt-checkout-head": _match_prt_checkout,
        "self-hosted-runner-persistence": _match_self_hosted,
        "oidc-token-fork": _match_oidc_fork,
        "actions-cache-poisoning": _match_cache_poisoning,
        "workflow-run-artifact-trust": _match_workflow_run_artifacts,
        "artifact-supply-chain": _match_artifact_supply_chain,
        "circleci-dynamic-config": _match_circleci_dynamic_config,
        "missing-permissions-block": _match_missing_permissions,
        "checkout-persists-credentials": _match_checkout_persists_creds,
        "unpinned-container-image": _match_unpinned_image,
        "fork-pr-cache-write": _match_fork_cache_write,
        "docker-plugin-privileged": _match_docker_plugin_privileged,
        "issue-comment-fork-checkout": _match_issue_comment_fork_checkout,
        "codebuild-plaintext-secrets": match_codebuild_plaintext_secrets,
        "codebuild-privileged-mode": match_codebuild_privileged_mode,
        "codebuild-exported-secrets": match_codebuild_exported_secrets,
        "cloudbuild-secret-in-env": match_cloudbuild_secret_in_env,
        "cloudbuild-default-service-account": match_cloudbuild_default_sa,
        "truncated-sha-pin": _match_truncated_sha,
    }

    matcher = dispatch.get(pid)
    if matcher:
        return matcher(model, pattern, make_finding)

    checks: list[dict[str, Any]] = pattern["detection"].get("checks", [])
    if checks:
        return _match_structural_checks(model, pattern, checks, make_finding)

    return []


def _match_prt_checkout(
    model: WorkflowModel,
    pattern: dict[str, Any],
    make_finding: MakeFinding,
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
                    make_finding(
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
    make_finding: MakeFinding,
) -> list[Finding]:
    findings: list[Finding] = []
    for job in model.jobs:
        if job.runner.is_self_hosted:
            findings.append(
                make_finding(
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
    make_finding: MakeFinding,
) -> list[Finding]:
    is_fork_reachable = any(t.is_fork_reachable for t in model.triggers)
    if not is_fork_reachable:
        return []

    findings: list[Finding] = []
    for job in model.jobs:
        perms = job.permissions or model.permissions
        if perms and perms.raw.get("id-token") == "write":
            findings.append(
                make_finding(
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
    make_finding: MakeFinding,
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
                    make_finding(
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
    make_finding: MakeFinding,
) -> list[Finding]:
    has_workflow_run = any(t.raw_event == "workflow_run" for t in model.triggers)
    if not has_workflow_run:
        return []

    findings: list[Finding] = []
    for job in model.jobs:
        for step in job.steps:
            if step.action_ref and "download-artifact" in step.action_ref.raw:
                findings.append(
                    make_finding(
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
    make_finding: MakeFinding,
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
                    make_finding(
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


def _match_circleci_dynamic_config(
    model: WorkflowModel,
    pattern: dict[str, Any],
    make_finding: MakeFinding,
) -> list[Finding]:
    if model.raw.get("setup") is not True or not model.jobs:
        return []
    return [
        make_finding(
            pattern=pattern,
            model=model,
            job=model.jobs[0],
            step=None,
            evidence=["setup: true — dynamic config, generated pipeline not analyzable"],
            line=0,
        )
    ]


def _match_missing_permissions(
    model: WorkflowModel, pattern: dict[str, Any], make_finding: MakeFinding
) -> list[Finding]:
    if model.platform != "github" or model.permissions is not None or not model.jobs:
        return []
    if all(j.permissions is not None for j in model.jobs):
        return []
    return [
        make_finding(
            pattern=pattern,
            model=model,
            job=model.jobs[0],
            step=None,
            evidence=["No top-level or per-job permissions: block"],
            line=0,
        )
    ]


def _match_checkout_persists_creds(
    model: WorkflowModel, pattern: dict[str, Any], make_finding: MakeFinding
) -> list[Finding]:
    if model.platform != "github":
        return []
    return [
        make_finding(
            pattern=pattern,
            model=model,
            job=job,
            step=step,
            evidence=["actions/checkout without persist-credentials: false"],
            line=step.action_ref.line,
        )
        for job in model.jobs
        for step in job.steps
        if step.action_ref
        and "checkout" in step.action_ref.name
        and step.inputs.get("persist-credentials", "").lower() != "false"
    ]


def _match_structural_checks(
    model: WorkflowModel,
    pattern: dict[str, Any],
    checks: list[dict[str, Any]],
    make_finding: MakeFinding,
) -> list[Finding]:
    return [
        make_finding(
            pattern=pattern,
            model=model,
            job=job,
            step=None,
            evidence=_describe_checks(model, job, checks),
            line=0,
        )
        for job in model.jobs
        if all(_check_passes(model, job, c) for c in checks)
    ]


def _check_passes(model: WorkflowModel, job: Job, check: dict[str, Any]) -> bool:
    if "trigger_includes" in check:
        return any(t.raw_event == check["trigger_includes"] for t in model.triggers)
    if "has_step" in check:
        return _has_step_check(job, check["has_step"])
    if "job_has_secrets" in check:
        return bool(job.secrets_referenced) is bool(check["job_has_secrets"])
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


def _describe_checks(model: WorkflowModel, job: Job, checks: list[dict[str, Any]]) -> list[str]:
    ev: list[str] = []
    for c in checks:
        if "trigger_includes" in c:
            ev.append(f"Trigger includes {c['trigger_includes']}")
        if "has_step" in c:
            ev.append(f"Job has step matching {c['has_step']}")
        if "job_has_secrets" in c:
            ev.append(f"Job references secrets: {job.secrets_referenced}")
        if "runner_is_self_hosted" in c:
            ev.append(f"Runner is self-hosted: {job.runner.is_self_hosted}")
        if "fork_reachable" in c:
            ev.append(f"Fork reachable: {any(t.is_fork_reachable for t in model.triggers)}")
    return ev


def _match_unpinned_image(
    model: WorkflowModel, pattern: dict[str, Any], make_finding: MakeFinding
) -> list[Finding]:
    return [
        make_finding(
            pattern=pattern,
            model=model,
            job=job,
            step=None,
            evidence=[f"Unpinned container image: {job.image}"],
            line=0,
        )
        for job in model.jobs
        if job.image and "@sha256:" not in job.image
    ]


def _is_cache_write(step: Step) -> bool:
    if step.action_ref:
        name = step.action_ref.name.lower()
        return "cache" in name and "restore" not in step.action_ref.raw.lower()
    return step.name == "save_cache"


def _match_fork_cache_write(
    model: WorkflowModel, pattern: dict[str, Any], make_finding: MakeFinding
) -> list[Finding]:
    if not any(t.is_fork_reachable for t in model.triggers):
        return []
    return [
        make_finding(
            pattern=pattern,
            model=model,
            job=job,
            step=step,
            evidence=[f"Cache write in fork-reachable workflow: {step.name or step.action_ref}"],
            line=step.action_ref.line if step.action_ref else 0,
        )
        for job in model.jobs
        for step in job.steps
        if _is_cache_write(step)
    ]


def _match_docker_plugin_privileged(
    model: WorkflowModel, pattern: dict[str, Any], make_finding: MakeFinding
) -> list[Finding]:
    findings: list[Finding] = []

    host_volumes = _drone_host_volume_paths(model) if model.platform == "drone" else set()

    for job in model.jobs:
        for step in job.steps:
            evidence: list[str] = []

            if model.platform == "drone":
                if step.inputs.get("privileged", "").lower() == "true":
                    evidence.append("Step runs with privileged: true")
            elif step.type == "action" and step.action_ref:
                name = step.action_ref.name.lower()
                if "docker" not in name:
                    continue
                if step.inputs.get("privileged", "").lower() == "true":
                    evidence.append("Docker plugin with privileged: true")
                volumes = step.inputs.get("volumes", "")
                if "/var/run/docker.sock" in volumes:
                    evidence.append("Docker plugin mounts docker socket")

            if not evidence and host_volumes:
                step_vols = _drone_step_volume_names(step, model)
                if step_vols & host_volumes:
                    evidence.append("Step mounts host docker socket via volume")

            if evidence:
                line = step.action_ref.line if step.action_ref else 0
                findings.append(
                    make_finding(
                        pattern=pattern,
                        model=model,
                        job=job,
                        step=step,
                        evidence=evidence,
                        line=line,
                    )
                )
    return findings


def _drone_host_volume_paths(model: WorkflowModel) -> set[str]:
    volumes = model.raw.get("volumes", [])
    if not isinstance(volumes, list):
        return set()
    names: set[str] = set()
    for vol in volumes:
        if not isinstance(vol, dict):
            continue
        host = vol.get("host", {})
        if isinstance(host, dict):
            path = host.get("path", "")
            if "/var/run/docker.sock" in str(path) or "/var/run/containerd" in str(path):
                names.add(str(vol.get("name", "")))
    return names


def _drone_step_volume_names(step: Step, model: WorkflowModel) -> set[str]:
    raw_steps = model.raw.get("steps", [])
    if not isinstance(raw_steps, list):
        return set()
    for raw_step in raw_steps:
        if not isinstance(raw_step, dict):
            continue
        if raw_step.get("name") != step.name:
            continue
        vols = raw_step.get("volumes", [])
        if isinstance(vols, list):
            return {str(v.get("name", "")) for v in vols if isinstance(v, dict)}
    return set()


_FORK_CHECKOUT_MARKERS = (
    "pull/",
    "github.event.pull_request.head.sha",
    "github.event.pull_request.head.ref",
    "github.head_ref",
)


def _job_checks_out_fork(job: Job) -> list[str]:
    evidence: list[str] = []
    for step in job.steps:
        cmd = step.shell_command or ""
        if "pull/" in cmd and ("git fetch" in cmd or "git checkout" in cmd):
            evidence.append(f"Shell fetches PR head: {cmd[:80]}")
        if step.action_ref and "checkout" in step.action_ref.name:
            ref_input = step.inputs.get("ref", "")
            if any(m in ref_input for m in _FORK_CHECKOUT_MARKERS):
                evidence.append(f"Checkout with PR head ref: {ref_input}")
    return evidence


def _job_has_elevated_permissions(model: WorkflowModel, job: Job) -> list[str]:
    evidence: list[str] = []
    perms = job.permissions or model.permissions
    if perms:
        for scope in ("id-token", "contents", "packages"):
            if perms.raw.get(scope) == "write":
                evidence.append(f"{scope}: write")
    if job.secrets_referenced:
        evidence.append(f"Secrets: {', '.join(job.secrets_referenced[:3])}")
    return evidence


def _match_issue_comment_fork_checkout(
    model: WorkflowModel, pattern: dict[str, Any], make_finding: MakeFinding
) -> list[Finding]:
    has_issue_comment = any(t.raw_event == "issue_comment" for t in model.triggers)
    if not has_issue_comment:
        return []

    findings: list[Finding] = []
    for job in model.jobs:
        checkout_ev = _job_checks_out_fork(job)
        if not checkout_ev:
            continue
        perms_ev = _job_has_elevated_permissions(model, job)
        if not perms_ev:
            continue
        findings.append(
            make_finding(
                pattern=pattern,
                model=model,
                job=job,
                step=None,
                evidence=[
                    "issue_comment trigger with fork checkout + elevated permissions",
                    *checkout_ev,
                    *perms_ev,
                ],
                line=0,
            )
        )
    return findings


_HEX = frozenset("0123456789abcdef")


def _match_truncated_sha(
    model: WorkflowModel, pattern: dict[str, Any], make_finding: MakeFinding
) -> list[Finding]:
    findings: list[Finding] = []
    for job in model.jobs:
        for step in job.steps:
            ref = step.action_ref
            if ref is None or ref.owner == "." or ref.raw.startswith("./"):
                continue
            r = ref.ref.lower()
            if 7 <= len(r) < 40 and all(c in _HEX for c in r):
                findings.append(
                    make_finding(
                        pattern=pattern,
                        model=model,
                        job=job,
                        step=step,
                        evidence=[
                            f"{ref.raw}: ref is {len(r)}-char hex, expected 40-char SHA",
                        ],
                        line=ref.line,
                    )
                )
    return findings
