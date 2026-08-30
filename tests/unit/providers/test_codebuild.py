from pathlib import Path

import pytest

from actionsieve.providers import ParseError
from actionsieve.providers.codebuild import CodeBuildProvider


@pytest.fixture
def provider() -> CodeBuildProvider:
    return CodeBuildProvider()


def _write_config(tmp_path: Path, content: str) -> Path:
    p = tmp_path / "buildspec.yml"
    p.write_text(content)
    return p


class TestDetect:
    def test_detects_buildspec_yml(self, provider: CodeBuildProvider, tmp_path: Path) -> None:
        _write_config(tmp_path, "version: 0.2")
        assert provider.detect(tmp_path) is True

    def test_detects_buildspec_yaml(self, provider: CodeBuildProvider, tmp_path: Path) -> None:
        (tmp_path / "buildspec.yaml").write_text("version: 0.2")
        assert provider.detect(tmp_path) is True

    def test_rejects_non_codebuild(self, provider: CodeBuildProvider, tmp_path: Path) -> None:
        assert provider.detect(tmp_path) is False


class TestFindFiles:
    def test_finds_buildspec(self, provider: CodeBuildProvider, tmp_path: Path) -> None:
        _write_config(tmp_path, "version: 0.2")
        files = provider.find_files(tmp_path)
        assert len(files) == 1

    def test_empty_when_no_config(self, provider: CodeBuildProvider, tmp_path: Path) -> None:
        assert provider.find_files(tmp_path) == []


class TestParse:
    def test_simple_build(self, provider: CodeBuildProvider, tmp_path: Path) -> None:
        p = _write_config(
            tmp_path,
            """\
version: 0.2
phases:
  build:
    commands:
      - npm test
""",
        )
        wf = provider.parse(p)
        assert wf.platform == "codebuild"
        assert len(wf.jobs) == 1
        assert wf.jobs[0].steps[0].shell_command == "npm test"

    def test_multiple_phases(self, provider: CodeBuildProvider, tmp_path: Path) -> None:
        p = _write_config(
            tmp_path,
            """\
version: 0.2
phases:
  install:
    commands:
      - npm ci
  build:
    commands:
      - npm run build
  post_build:
    commands:
      - npm test
""",
        )
        wf = provider.parse(p)
        assert len(wf.jobs[0].steps) == 3
        assert wf.jobs[0].steps[0].name == "install"
        assert wf.jobs[0].steps[1].name == "build"
        assert wf.jobs[0].steps[2].name == "post_build"

    def test_finally_commands(self, provider: CodeBuildProvider, tmp_path: Path) -> None:
        p = _write_config(
            tmp_path,
            """\
version: 0.2
phases:
  build:
    commands:
      - npm test
    finally:
      - echo cleanup
""",
        )
        wf = provider.parse(p)
        assert len(wf.jobs[0].steps) == 2
        assert wf.jobs[0].steps[1].name == "build.finally"

    def test_rejects_invalid_yaml(self, provider: CodeBuildProvider, tmp_path: Path) -> None:
        p = _write_config(tmp_path, "{{invalid")
        with pytest.raises(ParseError):
            provider.parse(p)

    def test_rejects_non_mapping(self, provider: CodeBuildProvider, tmp_path: Path) -> None:
        p = _write_config(tmp_path, "- item")
        with pytest.raises(ParseError):
            provider.parse(p)


class TestEnv:
    def test_variables_parsed(self, provider: CodeBuildProvider, tmp_path: Path) -> None:
        p = _write_config(
            tmp_path,
            """\
version: 0.2
env:
  variables:
    NODE_ENV: production
phases:
  build:
    commands:
      - npm test
""",
        )
        wf = provider.parse(p)
        assert wf.jobs[0].env["NODE_ENV"] == "production"

    def test_secrets_manager_tracked(self, provider: CodeBuildProvider, tmp_path: Path) -> None:
        p = _write_config(
            tmp_path,
            """\
version: 0.2
env:
  secrets-manager:
    DEPLOY_KEY: prod/deploy-key:apiKey
phases:
  build:
    commands:
      - deploy.sh
""",
        )
        wf = provider.parse(p)
        assert "prod/deploy-key:apiKey" in wf.jobs[0].secrets_referenced

    def test_parameter_store_tracked(self, provider: CodeBuildProvider, tmp_path: Path) -> None:
        p = _write_config(
            tmp_path,
            """\
version: 0.2
env:
  parameter-store:
    DB_PASSWORD: /prod/db/password
phases:
  build:
    commands:
      - deploy.sh
""",
        )
        wf = provider.parse(p)
        assert "/prod/db/password" in wf.jobs[0].secrets_referenced


class TestExpressions:
    def test_tainted_webhook_head_ref(self, provider: CodeBuildProvider, tmp_path: Path) -> None:
        p = _write_config(
            tmp_path,
            """\
version: 0.2
phases:
  build:
    commands:
      - echo "$CODEBUILD_WEBHOOK_HEAD_REF"
""",
        )
        wf = provider.parse(p)
        tainted = [e for e in wf.jobs[0].steps[0].expressions if e.is_tainted]
        assert len(tainted) == 1
        assert tainted[0].context_path == "CODEBUILD_WEBHOOK_HEAD_REF"

    def test_tainted_source_version(self, provider: CodeBuildProvider, tmp_path: Path) -> None:
        p = _write_config(
            tmp_path,
            """\
version: 0.2
phases:
  build:
    commands:
      - echo "${CODEBUILD_SOURCE_VERSION}"
""",
        )
        wf = provider.parse(p)
        tainted = [e for e in wf.jobs[0].steps[0].expressions if e.is_tainted]
        assert len(tainted) == 1

    def test_colon_misparse_coerced(self, provider: CodeBuildProvider, tmp_path: Path) -> None:
        p = _write_config(
            tmp_path,
            """\
version: 0.2
phases:
  build:
    commands:
      - echo "Branch: $CODEBUILD_WEBHOOK_HEAD_REF"
""",
        )
        wf = provider.parse(p)
        assert len(wf.jobs[0].steps) == 1
        tainted = [e for e in wf.jobs[0].steps[0].expressions if e.is_tainted]
        assert len(tainted) == 1
        assert tainted[0].context_path == "CODEBUILD_WEBHOOK_HEAD_REF"

    def test_safe_command(self, provider: CodeBuildProvider, tmp_path: Path) -> None:
        p = _write_config(
            tmp_path,
            """\
version: 0.2
phases:
  build:
    commands:
      - npm test
""",
        )
        wf = provider.parse(p)
        assert wf.jobs[0].steps[0].expressions == []


class TestTriggers:
    def test_default_trigger(self, provider: CodeBuildProvider, tmp_path: Path) -> None:
        p = _write_config(
            tmp_path,
            """\
version: 0.2
phases:
  build:
    commands:
      - npm test
""",
        )
        wf = provider.parse(p)
        assert len(wf.triggers) == 1
        assert wf.triggers[0].event == "webhook"
        assert wf.triggers[0].is_fork_reachable is True


class TestRunner:
    def test_managed_runner(self, provider: CodeBuildProvider, tmp_path: Path) -> None:
        p = _write_config(
            tmp_path,
            """\
version: 0.2
phases:
  build:
    commands:
      - npm test
""",
        )
        wf = provider.parse(p)
        assert wf.jobs[0].runner.is_self_hosted is False


class TestBuildImage:
    def test_image_parsed(self, provider: CodeBuildProvider, tmp_path: Path) -> None:
        p = _write_config(
            tmp_path,
            """\
version: 0.2
env:
  image: aws/codebuild/standard:7.0
phases:
  build:
    commands:
      - npm test
""",
        )
        wf = provider.parse(p)
        assert wf.jobs[0].image == "aws/codebuild/standard:7.0"
