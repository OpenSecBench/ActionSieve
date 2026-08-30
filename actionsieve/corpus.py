"""Corpus test runner and reporting — validate detection against curated cases."""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

import click
import yaml

if TYPE_CHECKING:
    from actionsieve.engine import Finding

EXPECTED_FILE = ".actionsieve.repo.yaml"


@dataclass
class CaseResult:
    name: str
    path: str
    passed: bool
    exit_code_ok: bool
    findings_ok: bool
    expected_exit: int
    actual_exit: int
    missing_findings: list[str] = field(default_factory=list)
    false_positives: list[str] = field(default_factory=list)
    extra_findings: list[str] = field(default_factory=list)
    error: str | None = None


def discover_cases(
    corpus_dir: Path,
    platform_filter: str | None = None,
    case_filter: str | None = None,
) -> list[tuple[Path, dict[str, Any]]]:
    cases: list[tuple[Path, dict[str, Any]]] = []
    for expected_path in sorted(corpus_dir.rglob(EXPECTED_FILE)):
        case_dir = expected_path.parent

        if platform_filter:
            parts = case_dir.relative_to(corpus_dir).parts
            if not parts or parts[0] != platform_filter:
                continue

        if case_filter and not fnmatch.fnmatch(case_dir.name, case_filter):
            continue

        data = yaml.safe_load(expected_path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            cases.append((case_dir, data))
    return cases


def run_case(case_dir: Path, expected: dict[str, Any], corpus_dir: Path) -> CaseResult:
    from actionsieve.scanner import scan

    rel = str(case_dir.relative_to(corpus_dir))
    platform = expected.get("platform")
    extra_args = expected.get("actionsieve_args", [])
    expected_exit = expected.get("expected_exit_code", 0)

    fail_on: str | None = None
    for i, arg in enumerate(extra_args):
        if arg == "--fail-on" and i + 1 < len(extra_args):
            fail_on = extra_args[i + 1]

    try:
        result = scan(
            repo_path=case_dir,
            platform=platform,
            fail_on=fail_on,
        )
    except Exception as e:
        return CaseResult(
            name=rel,
            path=str(case_dir),
            passed=False,
            exit_code_ok=False,
            findings_ok=False,
            expected_exit=expected_exit,
            actual_exit=-1,
            error=f"scan error: {e}",
        )

    exit_ok = result.exit_code == expected_exit
    findings_ok, missing, fps, extra = _check_findings(expected, result.findings, case_dir)
    passed = exit_ok and findings_ok and not fps

    return CaseResult(
        name=rel,
        path=str(case_dir),
        passed=passed,
        exit_code_ok=exit_ok,
        findings_ok=findings_ok,
        expected_exit=expected_exit,
        actual_exit=result.exit_code,
        missing_findings=missing,
        false_positives=fps,
        extra_findings=extra,
    )


def update_expected(case_dir: Path, expected: dict[str, Any]) -> None:
    from actionsieve.scanner import scan

    platform = expected.get("platform")
    result = scan(repo_path=case_dir, platform=platform)

    expected["expected_exit_code"] = result.exit_code
    expected["expected_findings"] = [
        {
            "pattern_id": f.pattern_id,
            "severity": f.severity_computed or f.severity_base,
            "file": _relative_file_path(f.file_path, case_dir),
        }
        for f in result.findings
    ]

    path = case_dir / EXPECTED_FILE
    path.write_text(
        yaml.dump(expected, default_flow_style=False, sort_keys=False),
        encoding="utf-8",
    )


def _relative_file_path(file_path: str, case_dir: Path) -> str:
    try:
        return str(Path(file_path).relative_to(case_dir))
    except ValueError:
        return file_path


def _check_findings(
    expected: dict[str, Any],
    actual_findings: list[Finding],
    case_dir: Path,
) -> tuple[bool, list[str], list[str], list[str]]:
    expected_findings = expected.get("expected_findings", [])

    if not expected_findings:
        if actual_findings:
            fps = [
                f"{f.pattern_id} ({f.severity_computed or f.severity_base})"
                f" in {_relative_file_path(f.file_path, case_dir)}"
                for f in actual_findings
            ]
            return False, [], fps, []
        return True, [], [], []

    missing: list[str] = []
    matched: set[int] = set()

    for exp in expected_findings:
        exp_id = exp["pattern_id"]
        exp_severity = exp.get("severity")
        exp_file = exp.get("file")
        exp_count = exp.get("count", 1)

        matches = 0
        for i, actual in enumerate(actual_findings):
            if i in matched:
                continue
            if actual.pattern_id != exp_id:
                continue
            if exp_severity:
                actual_sev = actual.severity_computed or actual.severity_base
                if actual_sev != exp_severity:
                    continue
            if exp_file:
                actual_rel = _relative_file_path(actual.file_path, case_dir)
                if actual_rel != exp_file:
                    continue
            matched.add(i)
            matches += 1
            if matches >= exp_count:
                break

        if matches < exp_count:
            label = exp_id
            if exp_severity:
                label += f" ({exp_severity})"
            if exp_file:
                label += f" in {exp_file}"
            if exp_count > 1:
                label += f" x{exp_count} (got {matches})"
            missing.append(label)

    extra = [
        f"{f.pattern_id} ({f.severity_computed or f.severity_base})"
        f" in {_relative_file_path(f.file_path, case_dir)}"
        for i, f in enumerate(actual_findings)
        if i not in matched
    ]

    return len(missing) == 0, missing, [], extra


def collect_coverage(
    cases: list[tuple[Path, dict[str, Any]]],
    corpus_dir: Path,
) -> dict[str, dict[str, list[str]]]:
    from actionsieve.patterns import list_pattern_ids

    coverage: dict[str, dict[str, list[str]]] = {
        pid: {"vulnerable": [], "safe": []} for pid in list_pattern_ids()
    }

    for case_dir, expected in cases:
        rel = str(case_dir.relative_to(corpus_dir))
        is_safe = "/safe/" in rel

        for finding in expected.get("expected_findings", []):
            pid = finding["pattern_id"]
            if pid in coverage:
                coverage[pid]["vulnerable"].append(rel)

        if is_safe:
            tags = expected.get("tags", [])
            for pid in coverage:
                short = pid.replace("-", " ")
                if any(short in t.replace("-", " ") for t in tags):
                    coverage[pid]["safe"].append(rel)

    return coverage


# --- Table generation ---


def load_table_cases(corpus_dir: Path) -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    for path in sorted(corpus_dir.rglob(EXPECTED_FILE)):
        case_dir = path.parent
        rel = case_dir.relative_to(corpus_dir)
        parts = rel.parts

        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}

        findings = data.get("expected_findings", [])
        pattern_ids = sorted({f["pattern_id"] for f in findings}) if findings else []

        cases.append(
            {
                "platform": parts[0] if parts else "",
                "category": parts[1] if len(parts) > 1 else "",
                "name": parts[-1] if parts else "",
                "path": str(rel),
                "description": data.get("description", ""),
                "exit_code": data.get("expected_exit_code", 0),
                "pattern_ids": pattern_ids,
                "finding_count": len(findings),
                "tags": data.get("tags", []),
                "source": data.get("source", ""),
            }
        )
    return cases


def generate_report(
    cases: list[dict[str, Any]],
    section: str = "full",
    platform_filter: str | None = None,
) -> str:
    if section == "summary":
        return _platform_summary(cases)
    if section == "cases":
        return _case_table(cases, platform_filter)
    if section == "patterns":
        return _pattern_coverage_table(cases)

    return (
        "\n".join(
            [
                "# Corpus Index",
                "",
                f"*{len(cases)} cases across {len({c['platform'] for c in cases})} platforms.*",
                "",
                _platform_summary(cases),
                "",
                _pattern_coverage_table(cases),
                "",
                "## All Cases",
                "",
                _case_table(cases, platform_filter),
            ]
        )
        + "\n"
    )


def _platform_summary(cases: list[dict[str, Any]]) -> str:
    lines = [
        "## Platform Summary",
        "",
        "| Platform | Vulnerable | Safe | Total | Patterns Detected |",
        "|----------|-----------|------|-------|-------------------|",
    ]
    platforms: dict[str, dict[str, Any]] = {}
    for c in cases:
        p = c["platform"]
        if p not in platforms:
            platforms[p] = {"vulnerable": 0, "safe": 0, "patterns": set()}
        platforms[p][c["category"]] = platforms[p].get(c["category"], 0) + 1
        platforms[p]["patterns"].update(c["pattern_ids"])

    for p in sorted(platforms):
        d = platforms[p]
        vuln = d.get("vulnerable", 0)
        safe = d.get("safe", 0)
        lines.append(f"| {p} | {vuln} | {safe} | {vuln + safe} | {len(d['patterns'])} |")

    total_v = sum(d.get("vulnerable", 0) for d in platforms.values())
    total_s = sum(d.get("safe", 0) for d in platforms.values())
    total_p = len({pid for c in cases for pid in c["pattern_ids"]})
    lines.append(
        f"| **Total** | **{total_v}** | **{total_s}** | **{total_v + total_s}** | **{total_p}** |"
    )
    return "\n".join(lines)


def _case_table(cases: list[dict[str, Any]], platform_filter: str | None = None) -> str:
    filtered = cases
    if platform_filter:
        filtered = [c for c in cases if c["platform"] == platform_filter]

    lines = [
        "| Platform | Category | Case | Patterns | Source | Description |",
        "|----------|----------|------|----------|--------|-------------|",
    ]
    for c in filtered:
        patterns = ", ".join(f"`{p}`" for p in c["pattern_ids"]) if c["pattern_ids"] else "—"
        desc = c["description"][:80] + "..." if len(c["description"]) > 80 else c["description"]
        lines.append(
            f"| {c['platform']} | {c['category']} | {c['name']}"
            f" | {patterns} | {c['source']} | {desc} |"
        )
    return "\n".join(lines)


def _pattern_coverage_table(cases: list[dict[str, Any]]) -> str:
    patterns: dict[str, dict[str, Any]] = {}
    for c in cases:
        for pid in c["pattern_ids"]:
            if pid not in patterns:
                patterns[pid] = {"platforms": set(), "cases": 0}
            patterns[pid]["platforms"].add(c["platform"])
            patterns[pid]["cases"] += 1

    lines = [
        "## Pattern Coverage",
        "",
        "| Pattern ID | Platforms | Cases |",
        "|------------|-----------|-------|",
    ]
    for pid in sorted(patterns):
        d = patterns[pid]
        plats = ", ".join(sorted(d["platforms"]))
        lines.append(f"| `{pid}` | {plats} | {d['cases']} |")
    return "\n".join(lines)


# --- CLI ---


PLATFORMS = [
    "github",
    "gitlab",
    "azure",
    "jenkins",
    "circleci",
    "bitbucket",
    "buildkite",
    "drone",
    "codebuild",
    "cloudbuild",
]


@click.group()
def corpus() -> None:
    """Run and report on a corpus of test cases."""


@corpus.command()
@click.argument("path", type=click.Path(exists=True, path_type=Path))
@click.option("--platform", type=click.Choice(PLATFORMS), help="Filter by platform.")
@click.option("--case", "case_filter", type=str, help="Filter by case name (glob).")
@click.option("--verbose", "-v", is_flag=True, help="Show extra findings.")
@click.option("--update", is_flag=True, help="Update expected results from actual output.")
@click.option("--json", "as_json", is_flag=True, help="Output results as JSON.")
@click.option("--coverage", is_flag=True, help="Show pattern coverage report.")
def run(
    path: Path,
    platform: str | None,
    case_filter: str | None,
    verbose: bool,
    update: bool,
    as_json: bool,
    coverage: bool,
) -> None:
    """Run corpus tests against actionsieve and compare to expected results."""
    import json

    cases = discover_cases(path, platform, case_filter)
    if not cases:
        click.echo("No cases found.")
        raise SystemExit(1)

    if coverage:
        cov = collect_coverage(cases, path)
        click.echo("\nPattern coverage:")
        click.echo(f"  {'Pattern ID':<40} {'Vuln':>5} {'Safe':>5}")
        click.echo(f"  {'-' * 40} {'-' * 5} {'-' * 5}")
        for pid in sorted(cov):
            vuln = len(cov[pid]["vulnerable"])
            safe = len(cov[pid]["safe"])
            marker = " *" if vuln == 0 else ""
            click.echo(f"  {pid:<40} {vuln:>5} {safe:>5}{marker}")
        uncovered = [p for p in cov if not cov[p]["vulnerable"]]
        if uncovered:
            click.echo(f"\n  * {len(uncovered)} patterns with no vulnerable corpus case")
        return

    if update:
        for case_dir, expected in cases:
            rel = case_dir.relative_to(path)
            click.echo(f"  Updating {rel}...")
            update_expected(case_dir, expected)
        click.echo(f"\nUpdated {len(cases)} cases.")
        return

    results: list[CaseResult] = []
    if not as_json:
        click.echo(f"Running {len(cases)} corpus cases...\n")

    for case_dir, expected in cases:
        result = run_case(case_dir, expected, path)
        results.append(result)
        if not as_json:
            _print_result(result, verbose)

    passed = sum(1 for r in results if r.passed)
    failed = sum(1 for r in results if not r.passed)

    if as_json:
        import dataclasses

        output = {
            "passed": passed,
            "failed": failed,
            "total": len(results),
            "results": [dataclasses.asdict(r) for r in results],
        }
        click.echo(json.dumps(output, indent=2))
    else:
        click.echo(f"\n{passed} passed, {failed} failed, {len(results)} total")
        extras = sum(len(r.extra_findings) for r in results)
        if extras:
            click.echo(f"({extras} extra findings not in expectations — run with -v to see)")

    raise SystemExit(1 if failed else 0)


@corpus.command()
@click.argument("path", type=click.Path(exists=True, path_type=Path))
@click.option("--platform", type=str, help="Filter by platform.")
@click.option(
    "--section",
    type=click.Choice(["full", "summary", "cases", "patterns"]),
    default="full",
    help="Which section to generate.",
)
@click.option(
    "--output",
    "-o",
    "output_file",
    type=click.Path(path_type=Path),
    help="Write to file.",
)
def table(
    path: Path,
    platform: str | None,
    section: str,
    output_file: Path | None,
) -> None:
    """Generate a markdown report of corpus cases."""
    cases = load_table_cases(path)
    if not cases:
        click.echo("No cases found.", err=True)
        raise SystemExit(1)

    text = generate_report(cases, section=section, platform_filter=platform)

    if output_file:
        output_file.write_text(text, encoding="utf-8")
        click.echo(f"Wrote {output_file}", err=True)
    else:
        click.echo(text)


def _print_result(result: CaseResult, verbose: bool = False) -> None:
    status = "PASS" if result.passed else "FAIL"
    click.echo(f"  [{status}] {result.name}")

    if result.error:
        click.echo(f"         error: {result.error}")
        return

    if not result.exit_code_ok:
        click.echo(
            f"         exit code: expected {result.expected_exit}, got {result.actual_exit}"
        )

    for m in result.missing_findings:
        click.echo(f"         missing: {m}")

    for fp in result.false_positives:
        click.echo(f"         false positive: {fp}")

    if verbose:
        for e in result.extra_findings:
            click.echo(f"         extra (warning): {e}")
