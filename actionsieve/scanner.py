"""Scanner orchestration — connects providers, engine, severity, profiles, output."""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import yaml

from actionsieve import engine
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

    from actionsieve.engine import Finding
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
    diff_base: str | None = None,
    offline: bool = False,
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

    for provider in providers:
        patterns = load_patterns(patterns_path, platform=provider.name)
        files = provider.find_files(repo_path)

        if diff_base:
            files = _filter_changed_files(repo_path, files, diff_base)

        for file_path in files:
            try:
                model = provider.parse(file_path)
            except ParseError:
                continue

            _resolve_composite_actions(model, repo_path)
            findings = engine.match(model, patterns)

            for finding in findings:
                finding.severity_base = compute_static(finding, model)

            all_findings.extend(findings)

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


def _filter_changed_files(
    repo_path: Path,
    files: list[Path],
    diff_base: str,
) -> list[Path]:
    try:
        result = subprocess.run(  # noqa: S603
            ["git", "diff", "--name-only", "--diff-filter=ACMR", diff_base],  # noqa: S607
            capture_output=True,
            text=True,
            cwd=repo_path,
            check=False,
        )
    except FileNotFoundError:
        return files

    if result.returncode != 0:
        return files

    changed = set(result.stdout.strip().splitlines())
    return [f for f in files if _relative_path(f, repo_path) in changed]


def _relative_path(file_path: Path, repo_path: Path) -> str:
    try:
        return str(file_path.relative_to(repo_path))
    except ValueError:
        return str(file_path)


MAX_COMPOSITE_DEPTH = 3
MAX_COMPOSITE_FILE_SIZE = 1_048_576


def _resolve_composite_actions(model: WorkflowModel, repo_path: Path, depth: int = 0) -> None:
    if depth >= MAX_COMPOSITE_DEPTH:
        return
    for job in model.jobs:
        extra: list[Step] = []
        for step in job.steps:
            ref = step.action_ref
            if ref is None:
                continue
            local_path = _local_action_path(ref)
            if local_path is None:
                continue
            steps = _parse_composite_action(repo_path, local_path)
            if steps:
                extra.extend(steps)
        if extra:
            base = len(job.steps)
            for i, s in enumerate(extra):
                s.index = base + i
            job.steps.extend(extra)


def _local_action_path(ref: ComponentRef) -> str | None:
    if ref.raw.startswith("./"):
        return ref.raw.removeprefix("./")
    if ref.raw.startswith(".\\"):
        return ref.raw.removeprefix(".\\")
    if ref.owner == ".":
        return ref.name
    return None


def _parse_composite_action(repo_path: Path, action_path: str) -> list[Step]:
    for filename in ("action.yml", "action.yaml"):
        candidate = repo_path / action_path / filename
        if candidate.is_file():
            return _read_composite_steps(candidate, action_path)
    return []


def _read_composite_steps(path: Path, action_path: str) -> list[Step]:
    if path.stat().st_size > MAX_COMPOSITE_FILE_SIZE:
        return []
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (yaml.YAMLError, OSError):
        return []
    if not isinstance(data, dict):
        return []
    runs = data.get("runs", {})
    if not isinstance(runs, dict) or runs.get("using") != "composite":
        return []
    raw_steps = runs.get("steps", [])
    if not isinstance(raw_steps, list):
        return []

    steps: list[Step] = []
    lines = path.read_text(encoding="utf-8").splitlines()
    for i, s in enumerate(raw_steps):
        if not isinstance(s, dict):
            continue
        step = _composite_step(i, s, action_path, lines)
        if step:
            steps.append(step)
    return steps


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
    return None


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
