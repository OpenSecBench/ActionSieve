import json
from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from actionsieve.cli import main

FIXTURES = Path(__file__).parent.parent / "fixtures" / "github"
MINIMAL_PATTERNS = str(Path(__file__).parent.parent / "fixtures" / "minimal_patterns")


class TestScanCommand:
    def test_scan_vulnerable_finds_issues(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main, ["scan", "--patterns", MINIMAL_PATTERNS, str(FIXTURES / "vulnerable")]
        )
        assert result.exit_code != 0
        data = json.loads(result.output)
        assert len(data["findings"]) > 0

    def test_scan_safe_clean(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main, ["scan", "--patterns", MINIMAL_PATTERNS, str(FIXTURES / "safe")]
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["findings"] == []

    def test_scan_json_format(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "scan",
                "--format",
                "json",
                "--patterns",
                MINIMAL_PATTERNS,
                str(FIXTURES / "vulnerable"),
            ],
        )
        data = json.loads(result.output)
        assert "findings" in data

    def test_scan_yaml_format(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "scan",
                "--format",
                "yaml",
                "--patterns",
                MINIMAL_PATTERNS,
                str(FIXTURES / "vulnerable"),
            ],
        )
        data = yaml.safe_load(result.output)
        assert "findings" in data

    def test_scan_sarif_format(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "scan",
                "--format",
                "sarif",
                "--patterns",
                MINIMAL_PATTERNS,
                str(FIXTURES / "vulnerable"),
            ],
        )
        data = json.loads(result.output)
        assert data["version"] == "2.1.0"
        assert len(data["runs"][0]["results"]) > 0

    def test_scan_markdown_format(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "scan",
                "--format",
                "markdown",
                "--patterns",
                MINIMAL_PATTERNS,
                str(FIXTURES / "vulnerable"),
            ],
        )
        assert result.exit_code != 0
        assert "# actionsieve Security Report" in result.output

    def test_scan_ocsf_format(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "scan",
                "--format",
                "ocsf",
                "--patterns",
                MINIMAL_PATTERNS,
                str(FIXTURES / "vulnerable"),
            ],
        )
        data = json.loads(result.output)
        assert "detection_findings" in data
        assert len(data["detection_findings"]) > 0
        event = data["detection_findings"][0]
        assert event["class_uid"] == 2004
        assert "finding_info" in event

    def test_scan_markdown_output_file(self, tmp_path: Path) -> None:
        out = tmp_path / "report.md"
        runner = CliRunner()
        runner.invoke(
            main,
            [
                "scan",
                "--format",
                "markdown",
                "--output",
                str(out),
                "--patterns",
                MINIMAL_PATTERNS,
                str(FIXTURES / "vulnerable"),
            ],
        )
        assert out.exists()
        text = out.read_text()
        assert "# actionsieve Security Report" in text

    def test_scan_platform_github(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "scan",
                "--platform",
                "github",
                "--patterns",
                MINIMAL_PATTERNS,
                str(FIXTURES / "vulnerable"),
            ],
        )
        data = json.loads(result.output)
        assert len(data["findings"]) > 0

    def test_scan_output_file(self, tmp_path: Path) -> None:
        out = tmp_path / "output.json"
        runner = CliRunner()
        runner.invoke(
            main,
            [
                "scan",
                "--output",
                str(out),
                "--patterns",
                MINIMAL_PATTERNS,
                str(FIXTURES / "vulnerable"),
            ],
        )
        assert out.exists()
        data = json.loads(out.read_text())
        assert len(data["findings"]) > 0

    def test_scan_with_profile(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "scan",
                "--profile",
                "hardened",
                "--patterns",
                MINIMAL_PATTERNS,
                str(FIXTURES / "vulnerable"),
            ],
        )
        data = json.loads(result.output)
        assert "findings" in data

    def test_scan_fail_on_info(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "scan",
                "--fail-on",
                "info",
                "--patterns",
                MINIMAL_PATTERNS,
                str(FIXTURES / "vulnerable"),
            ],
        )
        assert result.exit_code != 0

    def test_scan_show_suppressed(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "scan",
                "--profile",
                "hardened",
                "--show-suppressed",
                "--patterns",
                MINIMAL_PATTERNS,
                str(FIXTURES / "vulnerable"),
            ],
        )
        data = json.loads(result.output)
        assert "findings" in data

    def test_scan_empty_dir_clean(self, tmp_path: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["scan", str(tmp_path)])
        assert result.exit_code == 0

    def test_no_patterns_errors(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("ACTIONSIEVE_PATTERNS", raising=False)
        repo = tmp_path / "repo"
        wf_dir = repo / ".github" / "workflows"
        wf_dir.mkdir(parents=True)
        (wf_dir / "ci.yml").write_text(
            "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
        )
        runner = CliRunner()
        result = runner.invoke(main, ["scan", str(repo)])
        assert result.exit_code != 0
        error_text = result.output or str(result.exception)
        assert "No patterns path" in error_text or "ACTIONSIEVE_PATTERNS" in error_text


class TestTrustRepoProfile:
    def _make_repo(self, tmp_path: Path) -> Path:
        wf_dir = tmp_path / ".github" / "workflows"
        wf_dir.mkdir(parents=True)
        (wf_dir / "ci.yml").write_text(
            """\
name: CI
on: [pull_request]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.pull_request.title }}"
"""
        )
        (tmp_path / ".actionsieve.yml").write_text(
            """\
profile:
  suppress:
    - test-expr-injection
"""
        )
        return tmp_path

    def test_repo_profile_ignored_by_default(self, tmp_path: Path) -> None:
        repo = self._make_repo(tmp_path)
        runner = CliRunner()
        result = runner.invoke(main, ["scan", "--patterns", MINIMAL_PATTERNS, str(repo)])
        data = json.loads(result.output)
        ids = [f["pattern_id"] for f in data["findings"]]
        assert "test-expr-injection" in ids

    def test_repo_profile_loaded_with_flag(self, tmp_path: Path) -> None:
        repo = self._make_repo(tmp_path)
        runner = CliRunner()
        result = runner.invoke(
            main, ["scan", "--patterns", MINIMAL_PATTERNS, "--trust-repo-profile", str(repo)]
        )
        data = json.loads(result.output)
        ids = [f["pattern_id"] for f in data["findings"]]
        assert "test-expr-injection" not in ids


class TestExplainCommand:
    def test_explain_known_pattern(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main, ["explain", "--patterns", MINIMAL_PATTERNS, "test-expr-injection"]
        )
        assert result.exit_code == 0
        assert "Test expression injection" in result.output
        assert "CWE-78" in result.output

    def test_explain_unknown_pattern(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main, ["explain", "--patterns", MINIMAL_PATTERNS, "nonexistent-pattern"]
        )
        assert result.exit_code == 1
        assert "Unknown pattern" in result.output

    def test_explain_fuzzy_match(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["explain", "--patterns", MINIMAL_PATTERNS, "injection"])
        assert result.exit_code == 1
        assert "Did you mean:" in result.output
        assert "test-expr-injection" in result.output


class TestProfileResolve:
    def test_resolve_default(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["profile", "resolve"])
        assert result.exit_code == 0
        assert "Resolved from: default" in result.output

    def test_resolve_preset(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["profile", "resolve", "--profile", "self-hosted"])
        assert result.exit_code == 0
        assert "persistent" in result.output
        assert "elevate" in result.output

    def test_resolve_json_format(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main, ["profile", "resolve", "--profile", "hardened", "--format", "json"]
        )
        assert result.exit_code == 0
        lines = [ln for ln in result.output.splitlines() if not ln.startswith("#")]
        data = json.loads("\n".join(lines))
        assert data["runners"]["isolation"] == "vm"
        assert "self-hosted-runners" in data["suppress"]

    def test_resolve_custom_file(self, tmp_path: Path) -> None:
        p = tmp_path / "custom.yml"
        p.write_text("extends: hosted-public\nsuppress:\n  - docker-in-docker\n")
        runner = CliRunner()
        result = runner.invoke(main, ["profile", "resolve", "--profile", str(p)])
        assert result.exit_code == 0
        assert "docker-in-docker" in result.output
        assert "open" in result.output

    def test_resolve_output_file(self, tmp_path: Path) -> None:
        out = tmp_path / "profile.yml"
        runner = CliRunner()
        result = runner.invoke(
            main, ["profile", "resolve", "--profile", "self-hosted", "--output", str(out)]
        )
        assert result.exit_code == 0
        assert out.exists()
        data = yaml.safe_load(out.read_text())
        assert "runners" in data

    def test_resolve_output_file_json(self, tmp_path: Path) -> None:
        out = tmp_path / "profile.json"
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "profile",
                "resolve",
                "--profile",
                "hardened",
                "--format",
                "json",
                "--output",
                str(out),
            ],
        )
        assert result.exit_code == 0
        data = json.loads(out.read_text())
        assert "runners" in data

    def test_resolve_unknown_profile_errors(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["profile", "resolve", "--profile", "nonexistent"])
        assert result.exit_code != 0


class TestOnlineFlag:
    def test_online_offline_mutually_exclusive(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["scan", "--online", "--offline", str(FIXTURES / "safe")],
        )
        assert result.exit_code != 0
        assert "mutually exclusive" in result.output

    def test_online_flag_accepted(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["scan", "--help"])
        assert "--online" in result.output
        assert "--token" in result.output

    def test_offline_flag_accepted(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["scan", "--offline", "--patterns", MINIMAL_PATTERNS, str(FIXTURES / "safe")],
        )
        assert result.exit_code == 0


class TestVersionFlag:
    def test_version(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        assert "actionsieve" in result.output
