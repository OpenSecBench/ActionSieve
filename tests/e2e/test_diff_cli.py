import json
import subprocess
from pathlib import Path

from click.testing import CliRunner

from actionsieve.cli import main

VULN_WORKFLOW = """\
name: PR Greeting
on:
  pull_request:
    types: [opened]

jobs:
  greet:
    runs-on: ubuntu-latest
    steps:
      - name: Greet PR author
        run: |
          echo "PR title: ${{ github.event.pull_request.title }}"
"""

SAFE_WORKFLOW = """\
name: CI
on: push

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: echo "hello"
"""

MINIMAL_PATTERNS = str(Path(__file__).parent.parent / "fixtures" / "minimal_patterns")
SCAN_ARGS = ["scan", "--format", "json", "--patterns", MINIMAL_PATTERNS]


def _git(repo: Path, *args: str) -> None:
    subprocess.run(  # noqa: S603
        ["git", *args],  # noqa: S607
        cwd=repo,
        check=True,
        capture_output=True,
    )


def _init_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    wf_dir = repo / ".github" / "workflows"
    wf_dir.mkdir(parents=True)

    _git(repo, "init")
    _git(repo, "config", "user.email", "test@test.com")
    _git(repo, "config", "user.name", "Test")

    (wf_dir / "safe.yml").write_text(SAFE_WORKFLOW)
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "baseline")
    _git(repo, "tag", "baseline")

    return repo


class TestChangedSince:
    def test_only_scans_changed_files(self, tmp_path: Path, clean_ci_env: None) -> None:
        repo = _init_repo(tmp_path)
        wf_dir = repo / ".github" / "workflows"

        (wf_dir / "vuln.yml").write_text(VULN_WORKFLOW)
        _git(repo, "add", ".")
        _git(repo, "commit", "-m", "add vuln")

        runner = CliRunner()
        result = runner.invoke(main, [*SCAN_ARGS, "--changed-since", "baseline", str(repo)])

        data = json.loads(result.output)
        files = {f["file_path"] for f in data["findings"]}
        assert any("vuln.yml" in f for f in files)
        assert not any("safe.yml" in f for f in files)

    def test_no_changes_returns_clean(self, tmp_path: Path, clean_ci_env: None) -> None:
        repo = _init_repo(tmp_path)

        runner = CliRunner()
        result = runner.invoke(main, [*SCAN_ARGS, "--changed-since", "baseline", str(repo)])

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["findings"] == []

    def test_modified_file_scanned(self, tmp_path: Path, clean_ci_env: None) -> None:
        repo = _init_repo(tmp_path)
        wf_dir = repo / ".github" / "workflows"

        (wf_dir / "safe.yml").write_text(VULN_WORKFLOW)
        _git(repo, "add", ".")
        _git(repo, "commit", "-m", "make it vulnerable")

        runner = CliRunner()
        result = runner.invoke(main, [*SCAN_ARGS, "--changed-since", "baseline", str(repo)])

        data = json.loads(result.output)
        assert len(data["findings"]) > 0

    def test_not_a_repo_errors(self, tmp_path: Path, clean_ci_env: None) -> None:
        repo = tmp_path / "no-git"
        wf_dir = repo / ".github" / "workflows"
        wf_dir.mkdir(parents=True)
        (wf_dir / "vuln.yml").write_text(VULN_WORKFLOW)

        runner = CliRunner()
        result = runner.invoke(main, [*SCAN_ARGS, "--changed-since", "HEAD~1", str(repo)])

        assert result.exit_code != 0
        assert "git diff failed" in result.output

    def test_bad_ref_errors(self, tmp_path: Path, clean_ci_env: None) -> None:
        repo = _init_repo(tmp_path)

        runner = CliRunner()
        result = runner.invoke(
            main,
            [*SCAN_ARGS, "--changed-since", "nonexistent-ref", str(repo)],
        )

        assert result.exit_code != 0
        assert "git diff failed" in result.output
