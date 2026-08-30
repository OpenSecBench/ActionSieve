import json
from pathlib import Path

from click.testing import CliRunner

from actionsieve.cli import main

FIXTURES = Path(__file__).parent.parent / "fixtures" / "cloudbuild"
VULN = str(FIXTURES / "vulnerable")
SAFE = str(FIXTURES / "safe")
VULN_IAM = str(FIXTURES / "vulnerable-iam")
SAFE_IAM = str(FIXTURES / "safe-iam")


def _scan(args: list[str]) -> dict[str, object]:
    result = CliRunner().invoke(main, args)
    return json.loads(result.output)


class TestCloudBuildScan:
    def test_scan_vulnerable_finds_issues(self) -> None:
        result = CliRunner().invoke(main, ["scan", "--platform", "cloudbuild", VULN])
        assert result.exit_code != 0
        data = json.loads(result.output)
        assert len(data["findings"]) > 0

    def test_scan_safe_clean(self) -> None:
        result = CliRunner().invoke(main, ["scan", "--platform", "cloudbuild", SAFE])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["findings"] == []

    def test_auto_detect_cloudbuild(self) -> None:
        data = _scan(["scan", VULN])
        assert any(f["platform"] == "cloudbuild" for f in data["findings"])

    def test_substitution_injection_detected(self) -> None:
        data = _scan(["scan", "--platform", "cloudbuild", VULN])
        ids = [f["pattern_id"] for f in data["findings"]]
        assert "cloudbuild-substitution-injection" in ids

    def test_sarif_output(self) -> None:
        result = CliRunner().invoke(
            main,
            ["scan", "--platform", "cloudbuild", "--format", "sarif", VULN],
        )
        data = json.loads(result.output)
        assert data["version"] == "2.1.0"
        assert len(data["runs"][0]["results"]) > 0

    def test_mutable_image_ref_detected(self) -> None:
        data = _scan(["scan", "--platform", "cloudbuild", VULN])
        ids = [f["pattern_id"] for f in data["findings"]]
        assert "mutable-action-ref" in ids

    def test_static_credentials_detected(self) -> None:
        data = _scan(["scan", "--platform", "cloudbuild", VULN])
        ids = [f["pattern_id"] for f in data["findings"]]
        assert "static-cloud-credentials" in ids


class TestCloudBuildIAMMisconfig:
    def test_secret_in_env_detected(self) -> None:
        data = _scan(["scan", "--platform", "cloudbuild", VULN_IAM])
        ids = [f["pattern_id"] for f in data["findings"]]
        assert "cloudbuild-secret-in-env" in ids

    def test_default_service_account_detected(self) -> None:
        data = _scan(["scan", "--platform", "cloudbuild", VULN_IAM])
        ids = [f["pattern_id"] for f in data["findings"]]
        assert "cloudbuild-default-service-account" in ids

    def test_safe_iam_no_secret_in_env(self) -> None:
        data = _scan(["scan", "--platform", "cloudbuild", SAFE_IAM])
        ids = [f["pattern_id"] for f in data["findings"]]
        assert "cloudbuild-secret-in-env" not in ids

    def test_safe_iam_has_service_account(self) -> None:
        data = _scan(["scan", "--platform", "cloudbuild", SAFE_IAM])
        ids = [f["pattern_id"] for f in data["findings"]]
        assert "cloudbuild-default-service-account" not in ids
