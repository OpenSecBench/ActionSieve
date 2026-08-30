import json
from pathlib import Path

from click.testing import CliRunner

from actionsieve.cli import main

FIXTURES = Path(__file__).parent.parent / "fixtures" / "codebuild"
VULN = str(FIXTURES / "vulnerable")
SAFE = str(FIXTURES / "safe")
VULN_IAM = str(FIXTURES / "vulnerable-iam")
SAFE_IAM = str(FIXTURES / "safe-iam")


def _scan(args: list[str]) -> dict[str, object]:
    result = CliRunner().invoke(main, args)
    return json.loads(result.output)


class TestCodeBuildScan:
    def test_scan_vulnerable_finds_issues(self) -> None:
        result = CliRunner().invoke(main, ["scan", "--platform", "codebuild", VULN])
        assert result.exit_code != 0
        data = json.loads(result.output)
        assert len(data["findings"]) > 0

    def test_scan_safe_clean(self) -> None:
        result = CliRunner().invoke(main, ["scan", "--platform", "codebuild", SAFE])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["findings"] == []

    def test_auto_detect_codebuild(self) -> None:
        data = _scan(["scan", VULN])
        assert any(f["platform"] == "codebuild" for f in data["findings"])

    def test_env_injection_detected(self) -> None:
        data = _scan(["scan", "--platform", "codebuild", VULN])
        ids = [f["pattern_id"] for f in data["findings"]]
        assert "codebuild-env-injection" in ids

    def test_sarif_output(self) -> None:
        result = CliRunner().invoke(
            main,
            ["scan", "--platform", "codebuild", "--format", "sarif", VULN],
        )
        data = json.loads(result.output)
        assert data["version"] == "2.1.0"
        assert len(data["runs"][0]["results"]) > 0


class TestCodeBuildIAMMisconfig:
    def test_plaintext_secrets_detected(self) -> None:
        data = _scan(["scan", "--platform", "codebuild", VULN_IAM])
        ids = [f["pattern_id"] for f in data["findings"]]
        assert "codebuild-plaintext-secrets" in ids

    def test_privileged_mode_detected(self) -> None:
        data = _scan(["scan", "--platform", "codebuild", VULN_IAM])
        ids = [f["pattern_id"] for f in data["findings"]]
        assert "codebuild-privileged-mode" in ids

    def test_exported_secrets_detected(self) -> None:
        data = _scan(["scan", "--platform", "codebuild", VULN_IAM])
        ids = [f["pattern_id"] for f in data["findings"]]
        assert "codebuild-exported-secrets" in ids

    def test_safe_iam_clean(self) -> None:
        data = _scan(["scan", "--platform", "codebuild", SAFE_IAM])
        iam_ids = [
            f["pattern_id"]
            for f in data["findings"]
            if f["pattern_id"].startswith("codebuild-")
            and f["pattern_id"] != "codebuild-env-injection"
        ]
        assert iam_ids == []
