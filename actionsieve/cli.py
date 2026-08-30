"""CLI entry point for actionsieve."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import click

from actionsieve import __version__

FORMATS = ["json", "yaml", "sarif", "markdown", "ocsf"]
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
FAIL_LEVELS = ["info", "low", "medium", "high", "critical"]


@click.group()
@click.version_option(version=__version__, prog_name="actionsieve")
def main() -> None:
    """Multi-platform CI/CD pipeline security scanner."""


@main.command()
@click.argument("path", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--platform",
    type=click.Choice(PLATFORMS),
    help="Force platform (auto-detected by default).",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(FORMATS),
    default="json",
    help="Output format.",
)
@click.option(
    "--output",
    "output_file",
    type=click.Path(path_type=Path),
    help="Write output to file instead of stdout.",
)
@click.option(
    "--patterns",
    type=click.Path(exists=True, path_type=Path),
    help="Custom pattern catalog path (directory or file).",
)
@click.option(
    "--profile",
    type=str,
    help="Environment profile (path or preset name).",
)
@click.option(
    "--trust-repo-profile",
    is_flag=True,
    default=False,
    help="Load .actionsieve.yml from the scanned repo (off by default).",
)
@click.option(
    "--fail-on",
    type=click.Choice(FAIL_LEVELS),
    default=None,
    help="Exit non-zero if findings at this level or above.",
)
@click.option(
    "--show-suppressed",
    is_flag=True,
    default=False,
    help="Include profile-suppressed findings in output.",
)
@click.option(
    "--diff",
    "diff_base",
    type=str,
    default=None,
    help="Only scan pipeline files changed since this ref.",
)
@click.option(
    "--offline",
    is_flag=True,
    default=False,
    help="Skip network calls for ref resolution.",
)
def scan(
    path: Path,
    platform: str | None,
    output_format: str,
    output_file: Path | None,
    patterns: Path | None,
    profile: str | None,
    trust_repo_profile: bool,
    fail_on: str | None,
    show_suppressed: bool,
    diff_base: str | None,
    offline: bool,
) -> None:
    """Scan a repo's CI/CD pipeline definitions for security issues."""
    from actionsieve.scanner import scan as run_scan

    result = run_scan(
        repo_path=path,
        platform=platform,
        output_format=output_format,
        output_file=output_file,
        patterns_path=patterns,
        profile_name=profile,
        trust_repo_profile=trust_repo_profile,
        fail_on=fail_on,
        show_suppressed=show_suppressed,
        diff_base=diff_base,
        offline=offline,
    )

    if not output_file:
        click.echo(result.output_text)

    raise SystemExit(result.exit_code)


@main.command()
@click.argument("path", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--check",
    is_flag=True,
    default=False,
    help="Check components against advisory database.",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["json", "yaml", "cyclonedx"]),
    default="json",
    help="Output format.",
)
@click.option(
    "--output",
    "output_file",
    type=click.Path(path_type=Path),
    help="Write output to file instead of stdout.",
)
@click.option(
    "--platform",
    type=click.Choice(PLATFORMS),
    help="Force platform (auto-detected by default).",
)
@click.option(
    "--offline",
    is_flag=True,
    default=False,
    help="Skip network calls for ref resolution.",
)
def inventory(
    path: Path,
    check: bool,
    output_format: str,
    output_file: Path | None,
    platform: str | None,
    offline: bool,
) -> None:
    """Generate a bill of materials for CI/CD components."""
    from actionsieve.inventory import run_inventory
    from actionsieve.output import render_inventory

    inv = run_inventory(
        repo_path=path,
        platform=platform,
        check=check,
        offline=offline,
    )

    text = render_inventory(inv, output_format, output_file)

    if not output_file:
        click.echo(text)

    exit_code = 3 if inv.advisory_matches > 0 else 0
    raise SystemExit(exit_code)


@main.command()
@click.argument("pattern_id")
@click.option(
    "--patterns",
    type=click.Path(exists=True, path_type=Path),
    help="Custom pattern catalog path.",
)
def explain(pattern_id: str, patterns: Path | None) -> None:
    """Show full details for a pattern by ID."""
    from actionsieve.patterns import get_pattern, list_pattern_ids

    pattern = get_pattern(pattern_id, path=patterns)
    if pattern is None:
        all_ids = list_pattern_ids(path=patterns)
        click.echo(f"Unknown pattern: {pattern_id}", err=True)
        matches = [pid for pid in all_ids if pattern_id in pid]
        if matches:
            click.echo("\nDid you mean:", err=True)
            for m in matches:
                click.echo(f"  {m}", err=True)
        raise SystemExit(1)

    _print_pattern(pattern)


def _print_pattern(p: dict[str, Any]) -> None:
    click.secho(str(p["id"]), bold=True)
    click.echo(f"  {p['title']}")
    click.echo()

    desc = str(p.get("description", "")).strip()
    if desc:
        for line in desc.splitlines():
            click.echo(f"  {line}")
        click.echo()

    platforms = p.get("platforms", "all")
    click.echo(f"  Platforms:      {platforms}")
    click.echo(f"  Severity:       {p['severity_base']}")
    click.echo(f"  Attacker model: {p['attacker_model']}")
    click.echo(f"  Impact:         {p['impact']}")
    if p.get("cwe"):
        click.echo(f"  CWE:            {p['cwe']}")
    click.echo()

    notes = str(p.get("severity_notes", "")).strip()
    if notes:
        click.secho("  Severity notes:", bold=True)
        for line in notes.splitlines():
            click.echo(f"    {line}")
        click.echo()

    mitigations = p.get("mitigations", [])
    if mitigations:
        click.secho("  Mitigations:", bold=True)
        for m in mitigations:
            click.echo(f"    - {m}")
        click.echo()

    refs = p.get("references", [])
    if refs:
        click.secho("  References:", bold=True)
        for r in refs:
            click.echo(f"    {r}")
        click.echo()

    tags = p.get("tags", [])
    if tags:
        click.echo(f"  Tags: {', '.join(str(t) for t in tags)}")


@main.group()
def profile() -> None:
    """Environment profile management."""


@profile.command()
@click.option(
    "--profile",
    "profile_name",
    type=str,
    help="Profile preset name or path to profile file.",
)
@click.option(
    "--repo-path",
    type=click.Path(exists=True, path_type=Path),
    help="Repo path (for --trust-repo-profile).",
)
@click.option(
    "--trust-repo-profile",
    is_flag=True,
    default=False,
    help="Load .actionsieve.yml from the repo.",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["yaml", "json"]),
    default="yaml",
    help="Output format.",
)
@click.option(
    "--output",
    "output_file",
    type=click.Path(path_type=Path),
    help="Write output to file instead of stdout.",
)
def resolve(
    profile_name: str | None,
    repo_path: Path | None,
    trust_repo_profile: bool,
    output_format: str,
    output_file: Path | None,
) -> None:
    """Print the effective profile after overlay resolution."""
    import json

    import yaml

    from actionsieve.profiles import BUILTIN_PROFILES, load_profile

    repo_profile = None
    if trust_repo_profile and repo_path:
        repo_profile = repo_path / ".actionsieve.yml"

    resolved = load_profile(profile_name, repo_profile=repo_profile)

    source = "default"
    if profile_name:
        source = profile_name if profile_name in BUILTIN_PROFILES else str(profile_name)
    elif repo_profile and repo_profile.is_file():
        source = str(repo_profile)

    click.secho(f"# Resolved from: {source}", fg="green", err=True)

    if output_format == "json":
        text = json.dumps(resolved, indent=2)
    else:
        text = yaml.dump(resolved, default_flow_style=False, sort_keys=False).rstrip()

    if output_file:
        output_file.write_text(text + "\n", encoding="utf-8")
        click.echo(f"Written to {output_file}", err=True)
    else:
        click.echo(text)
