import json
from pathlib import Path

from click.testing import CliRunner

from actionsieve.cli import main

FIXTURES = Path(__file__).parent.parent / "fixtures" / "azure"


class TestAzureScan:
    def test_scan_vulnerable_finds_issues(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["scan", "--platform", "azure", str(FIXTURES / "vulnerable")])
        assert result.exit_code != 0
        data = json.loads(result.output)
        assert len(data["findings"]) > 0

    def test_scan_safe_clean(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["scan", "--platform", "azure", str(FIXTURES / "safe")])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["findings"] == []

    def test_variable_injection_detected(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["scan", "--platform", "azure", str(FIXTURES / "vulnerable")])
        data = json.loads(result.output)
        ids = [f["pattern_id"] for f in data["findings"]]
        assert "azure-variable-injection" in ids

    def test_auto_detect_azure(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["scan", str(FIXTURES / "vulnerable")])
        data = json.loads(result.output)
        assert any(f["platform"] == "azure" for f in data["findings"])

    def test_sarif_output_azure(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["scan", "--platform", "azure", "--format", "sarif", str(FIXTURES / "vulnerable")],
        )
        data = json.loads(result.output)
        assert data["version"] == "2.1.0"
        assert len(data["runs"][0]["results"]) > 0
