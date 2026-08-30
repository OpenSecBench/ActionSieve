from pathlib import Path

from click.testing import CliRunner

from actionsieve.cli import main
from actionsieve.context import ScanContext
from actionsieve.engine import Finding
from actionsieve.scanner import (
    _changeset_elevated,
    _changeset_suppressed,
    _matches_reachable_files,
)

SUPPRESS_PATTERN = {
    "id": "docker-in-docker",
    "diff_scope": "changeset",
    "diff_effect": "suppress",
    "reachable_files": ["Dockerfile*", "*.dockerfile", "docker-compose*"],
}

ELEVATE_PATTERN = {
    "id": "expr-injection-run",
    "diff_scope": "changeset",
    "diff_effect": "elevate",
    "reachable_files": [".github/workflows/*.yml"],
}

ALWAYS_PATTERN = {
    "id": "static-credentials",
    "diff_scope": "always",
}

NO_SCOPE_PATTERN = {
    "id": "some-pattern",
}


def _finding(pattern_id: str) -> Finding:
    return Finding(
        pattern_id=pattern_id,
        pattern_title="Test",
        file_path="test.yml",
        platform="github",
        line=1,
        job_id="build",
        step_index=0,
        severity_base="medium",
        attacker_model="any",
        impact="rce",
    )


class TestMatchesReachableFiles:
    def test_exact_match(self) -> None:
        assert _matches_reachable_files(["Dockerfile"], ["Dockerfile"])

    def test_glob_match(self) -> None:
        assert _matches_reachable_files(["Dockerfile*"], ["Dockerfile.prod"])

    def test_no_match(self) -> None:
        assert not _matches_reachable_files(["Dockerfile*"], ["src/app.py"])

    def test_path_glob(self) -> None:
        assert _matches_reachable_files([".github/workflows/*.yml"], [".github/workflows/ci.yml"])

    def test_multiple_globs(self) -> None:
        assert _matches_reachable_files(["Dockerfile*", "*.dockerfile"], ["build.dockerfile"])

    def test_empty_globs(self) -> None:
        assert not _matches_reachable_files([], ["Dockerfile"])

    def test_empty_files(self) -> None:
        assert not _matches_reachable_files(["Dockerfile*"], [])


class TestChangesetSuppressed:
    def test_suppressed_when_no_reachable_file(self) -> None:
        index = {SUPPRESS_PATTERN["id"]: SUPPRESS_PATTERN}
        ctx = ScanContext(changed_files=["src/app.py", "README.md"])
        assert _changeset_suppressed(_finding("docker-in-docker"), index, ctx)

    def test_not_suppressed_when_reachable_file_present(self) -> None:
        index = {SUPPRESS_PATTERN["id"]: SUPPRESS_PATTERN}
        ctx = ScanContext(changed_files=["Dockerfile", "src/app.py"])
        assert not _changeset_suppressed(_finding("docker-in-docker"), index, ctx)

    def test_always_scope_never_suppressed(self) -> None:
        index = {ALWAYS_PATTERN["id"]: ALWAYS_PATTERN}
        ctx = ScanContext(changed_files=["README.md"])
        assert not _changeset_suppressed(_finding("static-credentials"), index, ctx)

    def test_no_scope_never_suppressed(self) -> None:
        index = {NO_SCOPE_PATTERN["id"]: NO_SCOPE_PATTERN}
        ctx = ScanContext(changed_files=["README.md"])
        assert not _changeset_suppressed(_finding("some-pattern"), index, ctx)

    def test_elevate_pattern_not_suppressed(self) -> None:
        index = {ELEVATE_PATTERN["id"]: ELEVATE_PATTERN}
        ctx = ScanContext(changed_files=["README.md"])
        assert not _changeset_suppressed(_finding("expr-injection-run"), index, ctx)

    def test_unknown_pattern_not_suppressed(self) -> None:
        ctx = ScanContext(changed_files=["README.md"])
        assert not _changeset_suppressed(_finding("unknown"), {}, ctx)


class TestChangesetElevated:
    def test_elevated_when_reachable_file_present(self) -> None:
        index = {ELEVATE_PATTERN["id"]: ELEVATE_PATTERN}
        ctx = ScanContext(changed_files=[".github/workflows/ci.yml"])
        assert _changeset_elevated(_finding("expr-injection-run"), index, ctx)

    def test_not_elevated_when_no_reachable_file(self) -> None:
        index = {ELEVATE_PATTERN["id"]: ELEVATE_PATTERN}
        ctx = ScanContext(changed_files=["src/app.py"])
        assert not _changeset_elevated(_finding("expr-injection-run"), index, ctx)

    def test_suppress_pattern_not_elevated(self) -> None:
        index = {SUPPRESS_PATTERN["id"]: SUPPRESS_PATTERN}
        ctx = ScanContext(changed_files=["Dockerfile"])
        assert not _changeset_elevated(_finding("docker-in-docker"), index, ctx)

    def test_always_scope_not_elevated(self) -> None:
        index = {ALWAYS_PATTERN["id"]: ALWAYS_PATTERN}
        ctx = ScanContext(changed_files=["anything"])
        assert not _changeset_elevated(_finding("static-credentials"), index, ctx)


DOCKER_PATTERN_WITH_SCOPE = """\
patterns:
  - id: docker-in-docker
    title: Docker commands inside CI steps
    description: Test
    platforms: all
    attacker_model: contributor
    impact: rce
    severity_base: medium
    diff_scope: changeset
    diff_effect: suppress
    reachable_files:
      - "Dockerfile*"
      - "*.dockerfile"
      - "docker-compose*"
    detection:
      type: single_step
      in_block: run
      grep_patterns:
        - "docker build "
"""


class TestExitCodeWithSuppression:
    def test_suppressed_by_changeset_in_output(self, tmp_path: Path) -> None:
        repo = tmp_path / "repo"
        wf_dir = repo / ".github" / "workflows"
        wf_dir.mkdir(parents=True)
        wf_dir.joinpath("ci.yml").write_text(
            "name: CI\n"
            "on: [pull_request]\n"
            "jobs:\n"
            "  build:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - run: docker build .\n"
        )
        pat = tmp_path / "patterns"
        pat.mkdir()
        (pat / "docker.yml").write_text(DOCKER_PATTERN_WITH_SCOPE)

        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "scan",
                "--format",
                "json",
                "--patterns",
                str(pat),
                "--changed-files",
                "README.md",
                "--show-suppressed",
                str(repo),
            ],
        )

        import json

        data = json.loads(result.output)
        docker = [f for f in data["findings"] if f["pattern_id"] == "docker-in-docker"]
        assert len(docker) > 0
        assert all(f["suppressed_by"] == "changeset" for f in docker)

    def test_not_suppressed_when_reachable(self, tmp_path: Path) -> None:
        repo = tmp_path / "repo"
        wf_dir = repo / ".github" / "workflows"
        wf_dir.mkdir(parents=True)
        wf_dir.joinpath("ci.yml").write_text(
            "name: CI\n"
            "on: [pull_request]\n"
            "jobs:\n"
            "  build:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - run: docker build .\n"
        )
        pat = tmp_path / "patterns"
        pat.mkdir()
        (pat / "docker.yml").write_text(DOCKER_PATTERN_WITH_SCOPE)

        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "scan",
                "--format",
                "json",
                "--patterns",
                str(pat),
                "--changed-files",
                "Dockerfile",
                str(repo),
            ],
        )

        import json

        data = json.loads(result.output)
        docker = [f for f in data["findings"] if f["pattern_id"] == "docker-in-docker"]
        assert len(docker) > 0
        assert all(f.get("suppressed_by") is None for f in docker)
