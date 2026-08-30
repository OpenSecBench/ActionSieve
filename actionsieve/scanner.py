"""Scanner orchestration — connects providers, engine, severity, profiles, output."""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import yaml

from actionsieve import engine
from actionsieve.engine import Finding
from actionsieve.model import ComponentRef, Expression, Step
from actionsieve.output import render
from actionsieve.patterns import load_patterns
from actionsieve.profiles import load_profile
from actionsieve.providers import ParseError, auto_detect, get_provider
from actionsieve.severity import (
    apply_profile,
    compute_static,
    elevate_severity,
    is_elevated,
    is_suppressed,
)

if TYPE_CHECKING:
    from pathlib import Path

    from actionsieve.context import ScanContext
    from actionsieve.model import WorkflowModel

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_CRITICAL = 2

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class ScanResult:
    findings: list[Finding]
    suppressed: list[Finding]
    exit_code: int
    output_text: str


def scan(
    repo_path: Path,
    platform: str | None = None,
    output_format: str = "json",
    output_file: Path | None = None,
    patterns_path: Path | None = None,
    profile_name: str | None = None,
    trust_repo_profile: bool = False,
    fail_on: str | None = None,
    show_suppressed: bool = False,
    changed_since: str | None = None,
    scan_context: ScanContext | None = None,
    offline: bool = False,
    online: bool = False,
    token: str | None = None,
) -> ScanResult:
    providers = [get_provider(platform)] if platform else auto_detect(repo_path)

    if not providers:
        return ScanResult(
            findings=[],
            suppressed=[],
            exit_code=EXIT_CLEAN,
            output_text=render([], output_format, output_file),
        )

    repo_profile = (repo_path / ".actionsieve.yml") if trust_repo_profile else None
    profile = load_profile(profile_name, repo_profile=repo_profile)

    all_findings: list[Finding] = []
    models: list[WorkflowModel] = []

    for provider in providers:
        patterns = load_patterns(patterns_path, platform=provider.name)
        files = provider.find_files(repo_path)

        if changed_since:
            files = _filter_changed_files(repo_path, files, changed_since)

        resolved_actions: set[str] = set()
        for file_path in files:
            try:
                model = provider.parse(file_path)
            except ParseError:
                continue

            _resolve_composite_actions(model, repo_path, resolved_actions)
            findings = engine.match(model, patterns)

            for finding in findings:
                finding.severity_base = compute_static(finding, model)

            all_findings.extend(findings)
            models.append(model)

        if hasattr(provider, "find_action_files"):
            action_files = provider.find_action_files(repo_path)
            if changed_since:
                action_files = _filter_changed_files(repo_path, action_files, changed_since)
            for file_path in action_files:
                if str(file_path.parent.resolve()) in resolved_actions:
                    continue
                action_model = _parse_standalone_action(file_path, provider.name)
                if action_model is None:
                    continue
                _resolve_composite_actions(action_model, repo_path)
                findings = engine.match(action_model, patterns)
                for finding in findings:
                    finding.severity_base = compute_static(finding, action_model)
                all_findings.extend(findings)
                models.append(action_model)

    if online:
        all_findings.extend(_run_pin_checks(models, token))

    visible: list[Finding] = []
    suppressed: list[Finding] = []

    for finding in all_findings:
        if is_suppressed(finding, profile):
            suppressed.append(finding)
        else:
            visible.append(finding)

    for finding in visible:
        computed = apply_profile(finding.severity_base, profile)
        if is_elevated(finding, profile):
            computed = elevate_severity(computed)
        finding.severity_computed = computed

    visible.sort(
        key=lambda f: SEVERITY_ORDER.get(f.severity_computed or f.severity_base, 0),
        reverse=True,
    )

    output_findings = visible + suppressed if show_suppressed else visible
    output_text = render(output_findings, output_format, output_file)

    exit_code = _compute_exit_code(visible, fail_on)

    return ScanResult(
        findings=visible,
        suppressed=suppressed,
        exit_code=exit_code,
        output_text=output_text,
    )


class ChangedSinceError(Exception):
    pass


def _filter_changed_files(
    repo_path: Path,
    files: list[Path],
    ref: str,
) -> list[Path]:
    try:
        result = subprocess.run(  # noqa: S603
            ["git", "diff", "--name-only", "--diff-filter=ACMR", ref],  # noqa: S607
            capture_output=True,
            text=True,
            cwd=repo_path,
            check=False,
        )
    except FileNotFoundError:
        msg = "--changed-since requires git, but git was not found."
        raise ChangedSinceError(msg) from None

    if result.returncode != 0:
        stderr = result.stderr.strip()
        msg = f"--changed-since: git diff failed for ref '{ref}': {stderr}"
        raise ChangedSinceError(msg)

    changed = set(result.stdout.strip().splitlines())
    return [f for f in files if _relative_path(f, repo_path) in changed]


def _relative_path(file_path: Path, repo_path: Path) -> str:
    try:
        return str(file_path.relative_to(repo_path))
    except ValueError:
        return str(file_path)


MAX_COMPOSITE_DEPTH = 3
MAX_COMPOSITE_FILE_SIZE = 1_048_576


def _resolve_composite_actions(
    model: WorkflowModel, repo_path: Path, resolved: set[str] | None = None
) -> set[str]:
    if resolved is None:
        resolved = set()
    for job in model.jobs:
        start = 0
        for _depth in range(MAX_COMPOSITE_DEPTH):
            extra: list[Step] = []
            for step in job.steps[start:]:
                ref = step.action_ref
                if ref is None:
                    continue
                local_path = _local_action_path(ref)
                if local_path is None:
                    continue
                resolved.add(str((repo_path / local_path).resolve()))
                steps, output_exprs = _parse_composite_action(repo_path, local_path)
                if steps:
                    extra.extend(steps)
                if output_exprs:
                    _propagate_composite_taint(step, output_exprs)
            if not extra:
                break
            base = len(job.steps)
            for i, s in enumerate(extra):
                s.index = base + i
            start = base
            job.steps.extend(extra)
    return resolved


def _local_action_path(ref: ComponentRef) -> str | None:
    if ref.raw.startswith("./"):
        return ref.raw.removeprefix("./")
    if ref.raw.startswith(".\\"):
        return ref.raw.removeprefix(".\\")
    if ref.owner == ".":
        return ref.name
    return None


def _parse_composite_action(
    repo_path: Path, action_path: str
) -> tuple[list[Step], dict[str, str]]:
    for filename in ("action.yml", "action.yaml"):
        candidate = repo_path / action_path / filename
        if candidate.is_file():
            return _read_composite_steps(candidate, action_path)
    return [], {}


def _read_composite_steps(path: Path, action_path: str) -> tuple[list[Step], dict[str, str]]:
    if path.stat().st_size > MAX_COMPOSITE_FILE_SIZE:
        return [], {}
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (yaml.YAMLError, OSError):
        return [], {}
    if not isinstance(data, dict):
        return [], {}
    runs = data.get("runs", {})
    if not isinstance(runs, dict) or runs.get("using") != "composite":
        return [], {}
    raw_steps = runs.get("steps", [])
    if not isinstance(raw_steps, list):
        return [], {}

    steps: list[Step] = []
    lines = path.read_text(encoding="utf-8").splitlines()
    for i, s in enumerate(raw_steps):
        if not isinstance(s, dict):
            continue
        step = _composite_step(i, s, action_path, lines)
        if step:
            steps.append(step)

    output_exprs = _parse_composite_outputs(data)
    return steps, output_exprs


def _composite_step(
    index: int, data: dict[str, Any], action_path: str, lines: list[str]
) -> Step | None:
    shell_command: str | None = data.get("run")
    if isinstance(shell_command, str):
        expressions = _extract_composite_expressions(shell_command)
        return Step(
            index=index,
            type="shell",
            name=data.get("name") or f"composite:{action_path}:{index}",
            shell_command=shell_command,
            expressions=expressions,
        )
    uses = data.get("uses")
    if isinstance(uses, str) and uses:
        from actionsieve.providers.github_parse import parse_uses

        ref = parse_uses(uses, lines)
        return Step(
            index=index,
            type="action",
            name=data.get("name") or uses,
            action_ref=ref,
        )
    return None


def _parse_composite_outputs(data: dict[str, Any]) -> dict[str, str]:
    raw_outputs = data.get("outputs", {})
    if not isinstance(raw_outputs, dict):
        return {}
    result: dict[str, str] = {}
    for name, spec in raw_outputs.items():
        val = spec.get("value", "") if isinstance(spec, dict) else str(spec) if spec else ""
        if val:
            result[str(name)] = str(val)
    return result


def _propagate_composite_taint(step: Step, output_exprs: dict[str, str]) -> None:
    from actionsieve.providers.github_parse import TAINTED_CONTEXT_PREFIXES

    for output_name, value_expr in output_exprs.items():
        for m in re.finditer(r"\$\{\{\s*(.*?)\s*\}\}", value_expr):
            ctx = m.group(1).strip()
            if any(ctx.startswith(p) for p in TAINTED_CONTEXT_PREFIXES):
                step.outputs_written.append(output_name)
                step.expressions.append(
                    Expression(
                        raw=m.group(0),
                        context_path=ctx,
                        location="composite_output",
                        is_in_shell=False,
                        is_tainted=True,
                        line=0,
                    )
                )


def _parse_standalone_action(file_path: Path, platform: str) -> WorkflowModel | None:
    from actionsieve.model import Job, Permissions, Trigger, WorkflowModel, make_runner

    if file_path.stat().st_size > MAX_COMPOSITE_FILE_SIZE:
        return None
    try:
        data = yaml.safe_load(file_path.read_text(encoding="utf-8"))
    except (yaml.YAMLError, OSError):
        return None
    if not isinstance(data, dict):
        return None
    runs = data.get("runs", {})
    if not isinstance(runs, dict) or runs.get("using") != "composite":
        return None

    action_path = str(file_path.parent)
    lines = file_path.read_text(encoding="utf-8").splitlines()
    raw_steps = runs.get("steps", [])
    if not isinstance(raw_steps, list):
        return None

    steps: list[Step] = []
    for i, s in enumerate(raw_steps):
        if not isinstance(s, dict):
            continue
        step = _composite_step(i, s, action_path, lines)
        if step:
            steps.append(step)

    if not steps:
        return None

    job = Job(
        id="composite",
        runner=make_runner("ubuntu-latest"),
        steps=steps,
    )
    return WorkflowModel(
        platform=platform,
        file_path=str(file_path),
        raw=data,
        triggers=[Trigger(event="composite", raw_event="composite")],
        permissions=Permissions(raw={}),
        jobs=[job],
    )


def _extract_composite_expressions(text: str) -> list[Expression]:
    exprs: list[Expression] = []
    for m in re.finditer(r"\$\{\{\s*(.*?)\s*\}\}", text):
        context_path = m.group(1).strip()
        is_tainted = context_path.startswith("inputs.")
        exprs.append(
            Expression(
                raw=m.group(0),
                context_path=context_path,
                location="run",
                is_in_shell=True,
                is_tainted=is_tainted,
                line=0,
            )
        )
    return exprs


def _compute_exit_code(findings: list[Finding], fail_on: str | None) -> int:
    if not findings:
        return EXIT_CLEAN

    max_severity = max(
        SEVERITY_ORDER.get(f.severity_computed or f.severity_base, 0) for f in findings
    )

    if max_severity >= SEVERITY_ORDER.get("critical", 4):
        return EXIT_CRITICAL

    if fail_on:
        threshold = SEVERITY_ORDER.get(fail_on, 0)
        if max_severity >= threshold:
            return EXIT_FINDINGS

    if max_severity >= SEVERITY_ORDER.get("medium", 2):
        return EXIT_FINDINGS

    return EXIT_CLEAN


def _run_pin_checks(models: list[WorkflowModel], token: str | None) -> list[Finding]:
    from actionsieve.api_client import DiskCache, GitHubAPI, resolve_token
    from actionsieve.inventory import collect
    from actionsieve.pins import verify_pins

    resolved_token = resolve_token("github", token)
    api = GitHubAPI(token=resolved_token, cache=DiskCache())
    inv = collect(models)
    results = verify_pins(inv.components, api)

    pin_severity: dict[str, str] = {"wrong_repo": "medium", "outdated": "info"}
    findings: list[Finding] = []
    for r in results:
        findings.append(
            Finding(
                pattern_id=f"pin-{r.status.replace('_', '-')}",
                pattern_title=f"SHA pin: {r.status.replace('_', ' ')}",
                file_path="",
                platform="github",
                line=0,
                job_id="",
                step_index=None,
                severity_base=pin_severity.get(r.status, "info"),
                attacker_model="action_maintainer_compromise",
                impact="supply_chain",
                evidence=[r.detail, f"ref: {r.ref}"],
                tags=["supply-chain", "pinning", "online"],
            )
        )
    return findings
