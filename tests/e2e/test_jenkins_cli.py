import json
from pathlib import Path

from click.testing import CliRunner

from actionsieve.cli import main

FIXTURES = Path(__file__).parent.parent / "fixtures" / "jenkins"


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
