from pathlib import Path

import pytest

from actionsieve.providers import ParseError
from actionsieve.providers.cloudbuild import CloudBuildProvider


@pytest.fixture
def provider() -> CloudBuildProvider:
    return CloudBuildProvider()


def _write_config(tmp_path: Path, content: str) -> Path:
    p = tmp_path / "cloudbuild.yaml"
    p.write_text(content)
    return p


class TestDetect:
    def test_detects_cloudbuild_yaml(self, provider: CloudBuildProvider, tmp_path: Path) -> None:
        _write_config(tmp_path, "steps: []")
        assert provider.detect(tmp_path) is True

    def test_detects_cloudbuild_yml(self, provider: CloudBuildProvider, tmp_path: Path) -> None:
        (tmp_path / "cloudbuild.yml").write_text("steps: []")
        assert provider.detect(tmp_path) is True

    def test_rejects_non_cloudbuild(self, provider: CloudBuildProvider, tmp_path: Path) -> None:
        assert provider.detect(tmp_path) is False


class TestFindFiles:
    def test_finds_config(self, provider: CloudBuildProvider, tmp_path: Path) -> None:
        _write_config(tmp_path, "steps: []")
        files = provider.find_files(tmp_path)
        assert len(files) == 1

    def test_empty_when_no_config(self, provider: CloudBuildProvider, tmp_path: Path) -> None:
        assert provider.find_files(tmp_path) == []


class TestParse:
    def test_simple_args_step(self, provider: CloudBuildProvider, tmp_path: Path) -> None:
        p = _write_config(
            tmp_path,
            """\
steps:
  - name: 'gcr.io/cloud-builders/docker'
    args:
      - build
      - -t
      - app
      - .
""",
        )
        wf = provider.parse(p)
        assert wf.platform == "cloudbuild"
        assert len(wf.jobs) == 1
        assert "build" in wf.jobs[0].steps[0].shell_command

    def test_script_step(self, provider: CloudBuildProvider, tmp_path: Path) -> None:
        p = _write_config(
            tmp_path,
            """\
steps:
  - name: 'gcr.io/cloud-builders/gcloud'
    script: |
      echo hello
      make build
""",
        )
        wf = provider.parse(p)
        assert "make build" in wf.jobs[0].steps[0].shell_command

    def test_entrypoint_prepended(self, provider: CloudBuildProvider, tmp_path: Path) -> None:
        p = _write_config(
            tmp_path,
            """\
steps:
  - name: 'gcr.io/cloud-builders/gcloud'
    entrypoint: bash
    args:
      - -c
      - echo hello
""",
        )
        wf = provider.parse(p)
        assert wf.jobs[0].steps[0].shell_command.startswith("bash")

    def test_step_id_as_name(self, provider: CloudBuildProvider, tmp_path: Path) -> None:
        p = _write_config(
            tmp_path,
            """\
steps:
  - name: 'gcr.io/cloud-builders/docker'
    id: my-build
    args:
      - build
      - .
""",
        )
        wf = provider.parse(p)
        assert wf.jobs[0].steps[0].name == "my-build"

    def test_rejects_invalid_yaml(self, provider: CloudBuildProvider, tmp_path: Path) -> None:
        p = _write_config(tmp_path, "{{invalid")
        with pytest.raises(ParseError):
            provider.parse(p)

    def test_rejects_non_mapping(self, provider: CloudBuildProvider, tmp_path: Path) -> None:
        p = _write_config(tmp_path, "- item")
        with pytest.raises(ParseError):
            provider.parse(p)


class TestImageRefs:
    def test_first_party_gcr(self, provider: CloudBuildProvider, tmp_path: Path) -> None:
        p = _write_config(
            tmp_path,
            """\
steps:
  - name: 'gcr.io/cloud-builders/docker'
    args:
      - build
      - .
""",
        )
        wf = provider.parse(p)
        ref = wf.jobs[0].steps[0].action_ref
        assert ref is not None
        assert ref.is_first_party is True

    def test_third_party_image(self, provider: CloudBuildProvider, tmp_path: Path) -> None:
        p = _write_config(
            tmp_path,
            """\
steps:
  - name: 'myorg/custom-builder'
    args:
      - build
""",
        )
        wf = provider.parse(p)
        ref = wf.jobs[0].steps[0].action_ref
        assert ref is not None
        assert ref.is_first_party is False
        assert ref.owner == "myorg"

    def test_pinned_semver(self, provider: CloudBuildProvider, tmp_path: Path) -> None:
        p = _write_config(
            tmp_path,
            """\
steps:
  - name: 'gcr.io/cloud-builders/docker:1.0.0'
    args:
      - build
      - .
""",
        )
        wf = provider.parse(p)
        ref = wf.jobs[0].steps[0].action_ref
        assert ref is not None
        assert ref.is_pinned is True

    def test_unpinned_latest(self, provider: CloudBuildProvider, tmp_path: Path) -> None:
        p = _write_config(
            tmp_path,
            """\
steps:
  - name: 'gcr.io/cloud-builders/docker'
    args:
      - build
      - .
""",
        )
        wf = provider.parse(p)
        ref = wf.jobs[0].steps[0].action_ref
        assert ref is not None
        assert ref.is_pinned is False
        assert ref.ref == "latest"

    def test_digest_pinned(self, provider: CloudBuildProvider, tmp_path: Path) -> None:
        p = _write_config(
            tmp_path,
            """\
steps:
  - name: 'gcr.io/cloud-builders/docker@sha256:a1b2c3d4'
    args:
      - build
      - .
""",
        )
        wf = provider.parse(p)
        ref = wf.jobs[0].steps[0].action_ref
        assert ref is not None
        assert ref.is_pinned is True
        assert ref.ref_type == "sha"


class TestExpressions:
    def test_tainted_branch_name(self, provider: CloudBuildProvider, tmp_path: Path) -> None:
        p = _write_config(
            tmp_path,
            """\
steps:
  - name: 'gcr.io/cloud-builders/gcloud'
    entrypoint: bash
    args:
      - -c
      - echo "Deploying $BRANCH_NAME"
""",
        )
        wf = provider.parse(p)
        tainted = [e for e in wf.jobs[0].steps[0].expressions if e.is_tainted]
        assert len(tainted) == 1
        assert tainted[0].context_path == "BRANCH_NAME"

    def test_tainted_tag_name(self, provider: CloudBuildProvider, tmp_path: Path) -> None:
        p = _write_config(
            tmp_path,
            """\
steps:
  - name: 'gcr.io/cloud-builders/gcloud'
    script: |
      echo "Tag: ${TAG_NAME}"
""",
        )
        wf = provider.parse(p)
        tainted = [e for e in wf.jobs[0].steps[0].expressions if e.is_tainted]
        assert len(tainted) == 1
        assert tainted[0].context_path == "TAG_NAME"

    def test_safe_substitution(self, provider: CloudBuildProvider, tmp_path: Path) -> None:
        p = _write_config(
            tmp_path,
            """\
steps:
  - name: 'gcr.io/cloud-builders/docker'
    args:
      - build
      - -t
      - 'gcr.io/$PROJECT_ID/app:$COMMIT_SHA'
      - .
""",
        )
        wf = provider.parse(p)
        assert wf.jobs[0].steps[0].expressions == []


class TestSecrets:
    def test_secret_manager_tracked(self, provider: CloudBuildProvider, tmp_path: Path) -> None:
        p = _write_config(
            tmp_path,
            """\
steps:
  - name: 'gcr.io/cloud-builders/gcloud'
    args:
      - deploy
availableSecrets:
  secretManager:
    - versionName: projects/myproj/secrets/api-key/versions/latest
      env: API_KEY
""",
        )
        wf = provider.parse(p)
        assert any("api-key" in s for s in wf.jobs[0].secrets_referenced)


class TestStepEnv:
    def test_list_env_parsed(self, provider: CloudBuildProvider, tmp_path: Path) -> None:
        p = _write_config(
            tmp_path,
            """\
steps:
  - name: 'amazon/aws-cli'
    env:
      - 'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE'
      - 'AWS_SECRET_ACCESS_KEY=secret'
    args:
      - s3
      - sync
""",
        )
        wf = provider.parse(p)
        assert wf.jobs[0].steps[0].env["AWS_ACCESS_KEY_ID"] == "AKIAIOSFODNN7EXAMPLE"

    def test_empty_env_ok(self, provider: CloudBuildProvider, tmp_path: Path) -> None:
        p = _write_config(
            tmp_path,
            """\
steps:
  - name: 'gcr.io/cloud-builders/docker'
    args:
      - build
      - .
""",
        )
        wf = provider.parse(p)
        assert wf.jobs[0].steps[0].env == {}


class TestRunner:
    def test_default_managed(self, provider: CloudBuildProvider, tmp_path: Path) -> None:
        p = _write_config(
            tmp_path,
            """\
steps:
  - name: 'gcr.io/cloud-builders/docker'
    args:
      - build
      - .
""",
        )
        wf = provider.parse(p)
        assert wf.jobs[0].runner.is_self_hosted is False

    def test_private_pool_is_self_hosted(
        self, provider: CloudBuildProvider, tmp_path: Path
    ) -> None:
        p = _write_config(
            tmp_path,
            """\
steps:
  - name: 'gcr.io/cloud-builders/docker'
    args:
      - build
      - .
options:
  pool:
    name: projects/myproj/locations/us-central1/workerPools/my-pool
""",
        )
        wf = provider.parse(p)
        assert wf.jobs[0].runner.is_self_hosted is True
