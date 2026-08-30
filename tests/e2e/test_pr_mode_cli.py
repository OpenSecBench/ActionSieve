import json
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

SCAN_ARGS = ["scan", "--format", "json"]


def _make_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    wf_dir = repo / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "ci.yml").write_text(VULN_WORKFLOW)
    return repo


class TestPRModeFlags:
    def test_changed_files_flag(self, tmp_path: Path) -> None:
        repo = _make_repo(tmp_path)
        runner = CliRunner()
        result = runner.invoke(
            main,
            [*SCAN_ARGS, "--changed-files", "Dockerfile", str(repo)],
        )
        assert result.exit_code in (0, 1)
        data = json.loads(result.output)
        assert "findings" in data

    def test_trigger_and_actor_flags(self, tmp_path: Path) -> None:
        repo = _make_repo(tmp_path)
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                *SCAN_ARGS,
                "--changed-files",
                "src/app.py",
                "--trigger",
                "pull_request",
                "--actor",
                "fork",
                str(repo),
            ],
        )
        assert result.exit_code in (0, 1)
        data = json.loads(result.output)
        assert "findings" in data

    def test_context_file(self, tmp_path: Path) -> None:
        repo = _make_repo(tmp_path)
        ctx = tmp_path / "context.yaml"
        ctx.write_text("trigger: pull_request\nactor: fork\nchanged_files:\n  - Dockerfile\n")
        runner = CliRunner()
        result = runner.invoke(
            main,
            [*SCAN_ARGS, "--context", str(ctx), str(repo)],
        )
        assert result.exit_code in (0, 1)
        data = json.loads(result.output)
        assert "findings" in data

    def test_mode_static_ignores_context(self, tmp_path: Path) -> None:
        repo = _make_repo(tmp_path)
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                *SCAN_ARGS,
                "--changed-files",
                "Dockerfile",
                "--mode",
                "static",
                str(repo),
            ],
        )
        assert result.exit_code in (0, 1)
        data = json.loads(result.output)
        assert len(data["findings"]) > 0

    def test_mode_pr_without_context_errors(self, tmp_path: Path) -> None:
        repo = _make_repo(tmp_path)
        runner = CliRunner()
        result = runner.invoke(
            main,
            [*SCAN_ARGS, "--mode", "pr", str(repo)],
        )
        assert result.exit_code != 0
        assert "--mode pr requires" in result.output

    def test_changed_since_warning_in_pr_mode(self, tmp_path: Path) -> None:
        repo = _make_repo(tmp_path)
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                *SCAN_ARGS,
                "--changed-files",
                "Dockerfile",
                "--changed-since",
                "main",
                str(repo),
            ],
        )
        assert "ignored in PR mode" in (result.output + (result.stderr or ""))

    def test_changed_files_from_file(self, tmp_path: Path) -> None:
        repo = _make_repo(tmp_path)
        files = tmp_path / "changed.txt"
        files.write_text("Dockerfile\nsrc/app.py\n")
        runner = CliRunner()
        result = runner.invoke(
            main,
            [*SCAN_ARGS, "--changed-files", str(files), str(repo)],
        )
        assert result.exit_code in (0, 1)
        data = json.loads(result.output)
        assert "findings" in data
