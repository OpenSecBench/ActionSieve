from pathlib import Path

from actionsieve.engine import Finding, match
from actionsieve.matchers_cloud import _is_secret_key
from actionsieve.patterns import load_patterns
from actionsieve.providers.cloudbuild import CloudBuildProvider
from actionsieve.providers.codebuild import CodeBuildProvider

CODEBUILD_FIXTURES = Path(__file__).parent.parent / "fixtures" / "codebuild"
CLOUDBUILD_FIXTURES = Path(__file__).parent.parent / "fixtures" / "cloudbuild"


def _scan_codebuild(fixture: str) -> list[Finding]:
    provider = CodeBuildProvider()
    model = provider.parse(CODEBUILD_FIXTURES / fixture)
    patterns = load_patterns(platform="codebuild")
    return match(model, patterns)


def _scan_cloudbuild(fixture: str) -> list[Finding]:
    provider = CloudBuildProvider()
    model = provider.parse(CLOUDBUILD_FIXTURES / fixture)
    patterns = load_patterns(platform="cloudbuild")
    return match(model, patterns)


class TestIsSecretKey:
    def test_detects_password(self) -> None:
        assert _is_secret_key("DB_PASSWORD") is True

    def test_detects_token(self) -> None:
        assert _is_secret_key("API_TOKEN") is True

    def test_detects_secret(self) -> None:
        assert _is_secret_key("SIGNING_SECRET") is True

    def test_detects_api_key(self) -> None:
        assert _is_secret_key("MY_API_KEY") is True

    def test_rejects_normal_var(self) -> None:
        assert _is_secret_key("NODE_ENV") is False

    def test_rejects_build_type(self) -> None:
        assert _is_secret_key("BUILD_TYPE") is False

    def test_excludes_secret_arn(self) -> None:
        assert _is_secret_key("SECRET_ARN") is False

    def test_excludes_secret_name(self) -> None:
        assert _is_secret_key("SECRET_NAME") is False

    def test_excludes_token_url(self) -> None:
        assert _is_secret_key("TOKEN_URL") is False

    def test_case_insensitive(self) -> None:
        assert _is_secret_key("db_password") is True


class TestCodeBuildPlaintextSecrets:
    def test_detects_secrets_in_variables(self) -> None:
        findings = _scan_codebuild("vulnerable-iam/buildspec.yml")
        hits = [f for f in findings if f.pattern_id == "codebuild-plaintext-secrets"]
        assert len(hits) == 1
        evidence = " ".join(hits[0].evidence)
        assert "DB_PASSWORD" in evidence
        assert "API_TOKEN" in evidence

    def test_safe_parameter_store_not_flagged(self) -> None:
        findings = _scan_codebuild("safe-iam/buildspec.yml")
        hits = [f for f in findings if f.pattern_id == "codebuild-plaintext-secrets"]
        assert len(hits) == 0

    def test_non_secret_env_not_flagged(self) -> None:
        findings = _scan_codebuild("safe/buildspec.yml")
        hits = [f for f in findings if f.pattern_id == "codebuild-plaintext-secrets"]
        assert len(hits) == 0


class TestCodeBuildPrivilegedMode:
    def test_detects_privileged_mode(self) -> None:
        findings = _scan_codebuild("vulnerable-iam/buildspec.yml")
        hits = [f for f in findings if f.pattern_id == "codebuild-privileged-mode"]
        assert len(hits) == 1
        assert "privilegedMode" in " ".join(hits[0].evidence)

    def test_safe_no_privileged(self) -> None:
        findings = _scan_codebuild("safe-iam/buildspec.yml")
        hits = [f for f in findings if f.pattern_id == "codebuild-privileged-mode"]
        assert len(hits) == 0


class TestCodeBuildExportedSecrets:
    def test_detects_exported_secrets(self) -> None:
        findings = _scan_codebuild("vulnerable-iam/buildspec.yml")
        hits = [f for f in findings if f.pattern_id == "codebuild-exported-secrets"]
        assert len(hits) == 1
        evidence = " ".join(hits[0].evidence)
        assert "DEPLOY_KEY" in evidence
        assert "SIGNING_SECRET" in evidence

    def test_safe_non_secret_exports(self) -> None:
        findings = _scan_codebuild("safe-iam/buildspec.yml")
        hits = [f for f in findings if f.pattern_id == "codebuild-exported-secrets"]
        assert len(hits) == 0


class TestCloudBuildSecretInEnv:
    def test_detects_secrets_in_step_env(self) -> None:
        findings = _scan_cloudbuild("vulnerable-iam/cloudbuild.yaml")
        hits = [f for f in findings if f.pattern_id == "cloudbuild-secret-in-env"]
        assert len(hits) >= 1
        evidence = " ".join(hits[0].evidence)
        assert "DB_PASSWORD" in evidence or "API_TOKEN" in evidence

    def test_safe_secret_manager_not_flagged(self) -> None:
        findings = _scan_cloudbuild("safe-iam/cloudbuild.yaml")
        hits = [f for f in findings if f.pattern_id == "cloudbuild-secret-in-env"]
        assert len(hits) == 0


class TestCloudBuildDefaultServiceAccount:
    def test_detects_missing_service_account(self) -> None:
        findings = _scan_cloudbuild("vulnerable-iam/cloudbuild.yaml")
        hits = [f for f in findings if f.pattern_id == "cloudbuild-default-service-account"]
        assert len(hits) == 1
        assert "default" in " ".join(hits[0].evidence).lower()

    def test_safe_custom_service_account(self) -> None:
        findings = _scan_cloudbuild("safe-iam/cloudbuild.yaml")
        hits = [f for f in findings if f.pattern_id == "cloudbuild-default-service-account"]
        assert len(hits) == 0
