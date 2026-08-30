"""Scanner orchestration — connects providers, engine, severity, profiles, output."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import TYPE_CHECKING

from actionsieve import engine
from actionsieve.output import render
from actionsieve.patterns import load_patterns
from actionsieve.profiles import load_profile
from actionsieve.providers import ParseError, auto_detect, get_provider
from actionsieve.severity import apply_profile, compute_static, is_suppressed

if TYPE_CHECKING:
    from pathlib import Path

    from actionsieve.engine import Finding

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_CRITICAL = 2
EXIT_ADVISORY = 3

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

    profile = load_profile(profile_name, repo_path)

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
        finding.severity_base = computed

    visible.sort(key=lambda f: SEVERITY_ORDER.get(f.severity_base, 0), reverse=True)

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


def _compute_exit_code(findings: list[Finding], fail_on: str | None) -> int:
    if not findings:
        return EXIT_CLEAN

    max_severity = max(SEVERITY_ORDER.get(f.severity_base, 0) for f in findings)

    if max_severity >= SEVERITY_ORDER.get("critical", 4):
        return EXIT_CRITICAL

    if fail_on:
        threshold = SEVERITY_ORDER.get(fail_on, 0)
        if max_severity >= threshold:
            return EXIT_FINDINGS

    if max_severity >= SEVERITY_ORDER.get("medium", 2):
        return EXIT_FINDINGS

    return EXIT_CLEAN
