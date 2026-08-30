import json
from pathlib import Path

from click.testing import CliRunner

from actionsieve.cli import main

FIXTURES = Path(__file__).parent.parent / "fixtures" / "circleci"
VULN = str(FIXTURES / "vulnerable")
SAFE = str(FIXTURES / "safe")


def _scan(args: list[str]) -> dict[str, object]:
    result = CliRunner().invoke(main, args)
    return json.loads(result.output)


class TestCircleCIScan:
    def test_scan_vulnerable_finds_issues(self) -> None:
        result = CliRunner().invoke(main, ["scan", "--platform", "circleci", VULN])
        assert result.exit_code != 0
        data = json.loads(result.output)
        assert len(data["findings"]) > 0

    def test_scan_safe_clean(self) -> None:
        result = CliRunner().invoke(main, ["scan", "--platform", "circleci", SAFE])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["findings"] == []

    def test_auto_detect_circleci(self) -> None:
        data = _scan(["scan", VULN])
        assert any(f["platform"] == "circleci" for f in data["findings"])

    def test_mutable_orb_detected(self) -> None:
        data = _scan(["scan", "--platform", "circleci", VULN])
        ids = [f["pattern_id"] for f in data["findings"]]
        assert "mutable-action-ref" in ids

    def test_expression_injection_detected(self) -> None:
        data = _scan(["scan", "--platform", "circleci", VULN])
        ids = [f["pattern_id"] for f in data["findings"]]
        assert any("injection" in pid for pid in ids)

    def test_context_exposed_detected(self) -> None:
        data = _scan(["scan", "--platform", "circleci", VULN])
        ids = [f["pattern_id"] for f in data["findings"]]
        assert "circleci-context-exposed" in ids

    def test_dynamic_config_detected(self) -> None:
        dynamic = str(FIXTURES / "vulnerable-dynamic")
        data = _scan(["scan", "--platform", "circleci", dynamic])
        ids = [f["pattern_id"] for f in data["findings"]]
        assert "circleci-dynamic-config" in ids

    def test_sarif_output(self) -> None:
        result = CliRunner().invoke(
            main,
            ["scan", "--platform", "circleci", "--format", "sarif", VULN],
        )
        data = json.loads(result.output)
        assert data["version"] == "2.1.0"
        assert len(data["runs"][0]["results"]) > 0
