import json
from pathlib import Path

from click.testing import CliRunner

from actionsieve.cli import main

FIXTURES = Path(__file__).parent.parent / "fixtures" / "bitbucket"
VULN = str(FIXTURES / "vulnerable")
SAFE = str(FIXTURES / "safe")


def _scan(args: list[str]) -> dict[str, object]:
    result = CliRunner().invoke(main, args)
    return json.loads(result.output)


class TestBitbucketScan:
    def test_scan_vulnerable_finds_issues(self) -> None:
        result = CliRunner().invoke(main, ["scan", "--platform", "bitbucket", VULN])
        assert result.exit_code != 0
        data = json.loads(result.output)
        assert len(data["findings"]) > 0

    def test_scan_safe_clean(self) -> None:
        result = CliRunner().invoke(main, ["scan", "--platform", "bitbucket", SAFE])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["findings"] == []

    def test_auto_detect_bitbucket(self) -> None:
        data = _scan(["scan", VULN])
        assert any(f["platform"] == "bitbucket" for f in data["findings"])

    def test_mutable_pipe_detected(self) -> None:
        data = _scan(["scan", "--platform", "bitbucket", VULN])
        ids = [f["pattern_id"] for f in data["findings"]]
        assert "mutable-action-ref" in ids

    def test_env_injection_detected(self) -> None:
        data = _scan(["scan", "--platform", "bitbucket", VULN])
        ids = [f["pattern_id"] for f in data["findings"]]
        assert "bitbucket-env-injection" in ids

    def test_deployment_exposed_detected(self) -> None:
        data = _scan(["scan", "--platform", "bitbucket", VULN])
        ids = [f["pattern_id"] for f in data["findings"]]
        assert "bitbucket-deployment-exposed" in ids

    def test_sarif_output(self) -> None:
        result = CliRunner().invoke(
            main,
            ["scan", "--platform", "bitbucket", "--format", "sarif", VULN],
        )
        data = json.loads(result.output)
        assert data["version"] == "2.1.0"
        assert len(data["runs"][0]["results"]) > 0
