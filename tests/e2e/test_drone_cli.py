import json
from pathlib import Path

from click.testing import CliRunner

from actionsieve.cli import main

FIXTURES = Path(__file__).parent.parent / "fixtures" / "drone"
VULN = str(FIXTURES / "vulnerable")
SAFE = str(FIXTURES / "safe")


def _scan(args: list[str]) -> dict[str, object]:
    result = CliRunner().invoke(main, args)
    return json.loads(result.output)


class TestDroneScan:
    def test_scan_vulnerable_finds_issues(self) -> None:
        result = CliRunner().invoke(main, ["scan", "--platform", "drone", VULN])
        assert result.exit_code != 0
        data = json.loads(result.output)
        assert len(data["findings"]) > 0

    def test_scan_safe_clean(self) -> None:
        result = CliRunner().invoke(main, ["scan", "--platform", "drone", SAFE])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["findings"] == []

    def test_auto_detect_drone(self) -> None:
        data = _scan(["scan", VULN])
        assert any(f["platform"] == "drone" for f in data["findings"])

    def test_env_injection_detected(self) -> None:
        data = _scan(["scan", "--platform", "drone", VULN])
        ids = [f["pattern_id"] for f in data["findings"]]
        assert "drone-env-injection" in ids

    def test_mutable_plugin_detected(self) -> None:
        data = _scan(["scan", "--platform", "drone", VULN])
        ids = [f["pattern_id"] for f in data["findings"]]
        assert "mutable-action-ref" in ids

    def test_sarif_output(self) -> None:
        result = CliRunner().invoke(
            main,
            ["scan", "--platform", "drone", "--format", "sarif", VULN],
        )
        data = json.loads(result.output)
        assert data["version"] == "2.1.0"
        assert len(data["runs"][0]["results"]) > 0
