import json
from pathlib import Path

from click.testing import CliRunner

from actionsieve.cli import main

FIXTURES = Path(__file__).parent.parent / "fixtures" / "jenkins"
SCRIPTED_VULN = FIXTURES / "vulnerable-scripted"
SCRIPTED_SAFE = FIXTURES / "safe-scripted"
SCRIPT_BLOCK = FIXTURES / "vulnerable-script-block"


class TestJenkinsScan:
    def test_scan_vulnerable_finds_issues(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main, ["scan", "--platform", "jenkins", str(FIXTURES / "vulnerable")]
        )
        assert result.exit_code != 0
        data = json.loads(result.output)
        assert len(data["findings"]) > 0

    def test_scan_safe_clean(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["scan", "--platform", "jenkins", str(FIXTURES / "safe")])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["findings"] == []

    def test_parameter_injection_detected(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main, ["scan", "--platform", "jenkins", str(FIXTURES / "vulnerable")]
        )
        data = json.loads(result.output)
        ids = [f["pattern_id"] for f in data["findings"]]
        assert "jenkins-parameter-injection" in ids

    def test_change_injection_detected(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main, ["scan", "--platform", "jenkins", str(FIXTURES / "vulnerable")]
        )
        data = json.loads(result.output)
        ids = [f["pattern_id"] for f in data["findings"]]
        assert "jenkins-change-injection" in ids

    def test_self_hosted_detected(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main, ["scan", "--platform", "jenkins", str(FIXTURES / "vulnerable")]
        )
        data = json.loads(result.output)
        ids = [f["pattern_id"] for f in data["findings"]]
        assert "self-hosted-runner-persistence" in ids

    def test_auto_detect_jenkins(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["scan", str(FIXTURES / "vulnerable")])
        data = json.loads(result.output)
        assert any(f["platform"] == "jenkins" for f in data["findings"])


class TestScriptedPipeline:
    def test_scripted_vuln_finds_issues(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["scan", "--platform", "jenkins", str(SCRIPTED_VULN)])
        assert result.exit_code != 0
        data = json.loads(result.output)
        assert len(data["findings"]) > 0

    def test_scripted_safe_no_injection(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["scan", "--platform", "jenkins", str(SCRIPTED_SAFE)])
        data = json.loads(result.output)
        injection_ids = [
            f["pattern_id"] for f in data["findings"] if "injection" in f["pattern_id"]
        ]
        assert injection_ids == []

    def test_scripted_parameter_injection(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["scan", "--platform", "jenkins", str(SCRIPTED_VULN)])
        data = json.loads(result.output)
        ids = [f["pattern_id"] for f in data["findings"]]
        assert "jenkins-parameter-injection" in ids

    def test_scripted_change_injection(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["scan", "--platform", "jenkins", str(SCRIPTED_VULN)])
        data = json.loads(result.output)
        ids = [f["pattern_id"] for f in data["findings"]]
        assert "jenkins-change-injection" in ids


class TestScriptBlock:
    def test_script_block_finds_injection(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["scan", "--platform", "jenkins", str(SCRIPT_BLOCK)])
        assert result.exit_code != 0
        data = json.loads(result.output)
        ids = [f["pattern_id"] for f in data["findings"]]
        assert "jenkins-change-injection" in ids
