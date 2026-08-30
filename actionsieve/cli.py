"""CLI entry point for actionsieve."""

from __future__ import annotations

from pathlib import Path

import click

from actionsieve import __version__

FORMATS = ["json", "yaml", "sarif", "markdown"]
FAIL_LEVELS = ["info", "low", "medium", "high", "critical"]


@click.group()
@click.version_option(version=__version__, prog_name="actionsieve")
def main() -> None:
    """Multi-platform CI/CD pipeline security scanner."""


@main.command()
@click.argument("path", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--platform",
    type=click.Choice(["github", "gitlab", "azure", "jenkins"]),
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
    type=click.Choice(["github", "gitlab", "azure", "jenkins"]),
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
