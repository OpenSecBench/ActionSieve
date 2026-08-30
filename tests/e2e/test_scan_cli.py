import json
from pathlib import Path

import yaml
from click.testing import CliRunner

from actionsieve.cli import main

FIXTURES = Path(__file__).parent.parent / "fixtures" / "github"


class TestScanCommand:
    def test_scan_vulnerable_finds_issues(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["scan", str(FIXTURES / "vulnerable")])
        assert result.exit_code != 0
        data = json.loads(result.output)
        assert len(data["findings"]) > 0

    def test_scan_safe_clean(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["scan", str(FIXTURES / "safe")])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["findings"] == []

    def test_scan_json_format(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["scan", "--format", "json", str(FIXTURES / "vulnerable")])
        data = json.loads(result.output)
        assert "findings" in data

    def test_scan_yaml_format(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["scan", "--format", "yaml", str(FIXTURES / "vulnerable")])
        data = yaml.safe_load(result.output)
        assert "findings" in data

    def test_scan_sarif_format(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["scan", "--format", "sarif", str(FIXTURES / "vulnerable")])
        data = json.loads(result.output)
        assert data["version"] == "2.1.0"
        assert len(data["runs"][0]["results"]) > 0

    def test_scan_markdown_format(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main, ["scan", "--format", "markdown", str(FIXTURES / "vulnerable")]
        )
        assert result.exit_code != 0
        assert "# actionsieve Security Report" in result.output
        assert "expr-injection-run" in result.output

    def test_scan_markdown_output_file(self, tmp_path: Path) -> None:
        out = tmp_path / "report.md"
        runner = CliRunner()
        runner.invoke(
            main,
            ["scan", "--format", "markdown", "--output", str(out), str(FIXTURES / "vulnerable")],
        )
        assert out.exists()
        text = out.read_text()
        assert "# actionsieve Security Report" in text

    def test_scan_platform_github(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main, ["scan", "--platform", "github", str(FIXTURES / "vulnerable")]
        )
        data = json.loads(result.output)
        assert len(data["findings"]) > 0

    def test_scan_output_file(self, tmp_path: Path) -> None:
        out = tmp_path / "output.json"
        runner = CliRunner()
        runner.invoke(
            main,
            ["scan", "--output", str(out), str(FIXTURES / "vulnerable")],
        )
        assert out.exists()
        data = json.loads(out.read_text())
        assert len(data["findings"]) > 0

    def test_scan_with_profile(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["scan", "--profile", "hardened", str(FIXTURES / "vulnerable")],
        )
        data = json.loads(result.output)
        assert "findings" in data

    def test_scan_fail_on_info(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["scan", "--fail-on", "info", str(FIXTURES / "vulnerable")],
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
                str(FIXTURES / "vulnerable"),
            ],
        )
        data = json.loads(result.output)
        assert "findings" in data

    def test_scan_empty_dir_clean(self, tmp_path: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["scan", str(tmp_path)])
        assert result.exit_code == 0


class TestScanFindings:
    def test_expression_injection_detected(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["scan", "--platform", "github", str(FIXTURES / "vulnerable")],
        )
        data = json.loads(result.output)
        ids = [f["pattern_id"] for f in data["findings"]]
        assert "expr-injection-run" in ids

    def test_unpinned_refs_detected(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["scan", "--platform", "github", str(FIXTURES / "vulnerable")],
        )
        data = json.loads(result.output)
        ids = [f["pattern_id"] for f in data["findings"]]
        assert "mutable-action-ref" in ids

    def test_sarif_has_cwe(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["scan", "--format", "sarif", str(FIXTURES / "vulnerable")],
        )
        data = json.loads(result.output)
        results_with_cwe = [r for r in data["runs"][0]["results"] if "taxa" in r]
        assert len(results_with_cwe) > 0


class TestChainDetectionFindings:
    def test_fork_script_output_detected(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["scan", "--platform", "github", str(FIXTURES / "vulnerable")],
        )
        data = json.loads(result.output)
        ids = [f["pattern_id"] for f in data["findings"]]
        assert "fork-script-output-injection" in ids

    def test_fs_to_matrix_detected(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["scan", "--platform", "github", str(FIXTURES / "vulnerable")],
        )
        data = json.loads(result.output)
        ids = [f["pattern_id"] for f in data["findings"]]
        assert "fs-to-matrix-injection" in ids

    def test_safe_chain_not_detected(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["scan", "--platform", "github", str(FIXTURES / "safe")],
        )
        data = json.loads(result.output)
        chain_findings = [
            f
            for f in data["findings"]
            if f["pattern_id"] in ("fork-script-output-injection", "fs-to-matrix-injection")
        ]
        assert len(chain_findings) == 0


class TestHardeningFindings:
    def test_missing_permissions_detected(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["scan", "--platform", "github", str(FIXTURES / "vulnerable")],
        )
        data = json.loads(result.output)
        ids = [f["pattern_id"] for f in data["findings"]]
        assert "missing-permissions-block" in ids

    def test_checkout_persists_credentials_detected(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["scan", "--platform", "github", str(FIXTURES / "vulnerable")],
        )
        data = json.loads(result.output)
        ids = [f["pattern_id"] for f in data["findings"]]
        assert "checkout-persists-credentials" in ids

    def test_safe_fixtures_no_hardening_findings(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["scan", "--platform", "github", str(FIXTURES / "safe")],
        )
        data = json.loads(result.output)
        hardening = [
            f
            for f in data["findings"]
            if f["pattern_id"] in ("missing-permissions-block", "checkout-persists-credentials")
        ]
        assert len(hardening) == 0


class TestPipeToShellFindings:
    def test_pipe_to_shell_detected(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["scan", "--platform", "github", str(FIXTURES / "vulnerable")],
        )
        data = json.loads(result.output)
        ids = [f["pattern_id"] for f in data["findings"]]
        assert "pipe-to-shell" in ids

    def test_safe_download_not_flagged(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["scan", "--platform", "github", str(FIXTURES / "safe")],
        )
        data = json.loads(result.output)
        pipe_findings = [f for f in data["findings"] if f["pattern_id"] == "pipe-to-shell"]
        assert len(pipe_findings) == 0


class TestCloudCredentialFindings:
    def test_static_creds_detected(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["scan", "--platform", "github", str(FIXTURES / "vulnerable")],
        )
        data = json.loads(result.output)
        ids = [f["pattern_id"] for f in data["findings"]]
        assert "static-cloud-credentials" in ids

    def test_oidc_not_flagged(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["scan", "--platform", "github", str(FIXTURES / "safe")],
        )
        data = json.loads(result.output)
        cred_findings = [
            f for f in data["findings"] if f["pattern_id"] == "static-cloud-credentials"
        ]
        assert len(cred_findings) == 0


class TestDockerInDockerFindings:
    def test_docker_commands_detected(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["scan", "--platform", "github", str(FIXTURES / "vulnerable")],
        )
        data = json.loads(result.output)
        ids = [f["pattern_id"] for f in data["findings"]]
        assert "docker-in-docker" in ids

    def test_build_action_not_flagged(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["scan", "--platform", "github", str(FIXTURES / "safe")],
        )
        data = json.loads(result.output)
        dind_findings = [f for f in data["findings"] if f["pattern_id"] == "docker-in-docker"]
        assert len(dind_findings) == 0


class TestContainerImageFindings:
    def test_unpinned_container_detected(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["scan", "--platform", "github", str(FIXTURES / "vulnerable")],
        )
        data = json.loads(result.output)
        ids = [f["pattern_id"] for f in data["findings"]]
        assert "unpinned-container-image" in ids

    def test_pinned_container_not_flagged(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["scan", "--platform", "github", str(FIXTURES / "safe")],
        )
        data = json.loads(result.output)
        img_findings = [
            f for f in data["findings"] if f["pattern_id"] == "unpinned-container-image"
        ]
        assert len(img_findings) == 0


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
    - expr-injection
"""
        )
        return tmp_path

    def test_repo_profile_ignored_by_default(self, tmp_path: Path) -> None:
        repo = self._make_repo(tmp_path)
        runner = CliRunner()
        result = runner.invoke(main, ["scan", str(repo)])
        data = json.loads(result.output)
        ids = [f["pattern_id"] for f in data["findings"]]
        assert "expr-injection-run" in ids

    def test_repo_profile_loaded_with_flag(self, tmp_path: Path) -> None:
        repo = self._make_repo(tmp_path)
        runner = CliRunner()
        result = runner.invoke(main, ["scan", "--trust-repo-profile", str(repo)])
        data = json.loads(result.output)
        ids = [f["pattern_id"] for f in data["findings"]]
        assert "expr-injection-run" not in ids


class TestExplainCommand:
    def test_explain_known_pattern(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["explain", "expr-injection-run"])
        assert result.exit_code == 0
        assert "Expression injection" in result.output
        assert "Mitigations:" in result.output
        assert "CWE-78" in result.output

    def test_explain_unknown_pattern(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["explain", "nonexistent-pattern"])
        assert result.exit_code == 1
        assert "Unknown pattern" in result.output

    def test_explain_fuzzy_match(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["explain", "injection"])
        assert result.exit_code == 1
        assert "Did you mean:" in result.output
        assert "expr-injection-run" in result.output


class TestVersionFlag:
    def test_version(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        assert "actionsieve" in result.output
