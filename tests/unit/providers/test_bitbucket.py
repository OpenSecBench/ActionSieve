from pathlib import Path

import pytest

from actionsieve.providers import ParseError
from actionsieve.providers.bitbucket import BitbucketProvider


@pytest.fixture
def provider() -> BitbucketProvider:
    return BitbucketProvider()


def _write_config(tmp_path: Path, content: str) -> Path:
    p = tmp_path / "bitbucket-pipelines.yml"
    p.write_text(content)
    return p


class TestDetect:
    def test_detects_bitbucket_repo(self, provider: BitbucketProvider, tmp_path: Path) -> None:
        _write_config(tmp_path, "image: node:20\npipelines: {}")
        assert provider.detect(tmp_path) is True

    def test_rejects_non_bitbucket_repo(self, provider: BitbucketProvider, tmp_path: Path) -> None:
        assert provider.detect(tmp_path) is False


class TestFindFiles:
    def test_finds_config(self, provider: BitbucketProvider, tmp_path: Path) -> None:
        _write_config(tmp_path, "image: node:20")
        files = provider.find_files(tmp_path)
        assert len(files) == 1

    def test_empty_when_no_config(self, provider: BitbucketProvider, tmp_path: Path) -> None:
        assert provider.find_files(tmp_path) == []


class TestParse:
    def test_simple_pipeline(self, provider: BitbucketProvider, tmp_path: Path) -> None:
        p = _write_config(
            tmp_path,
            """\
image: node:20
pipelines:
  default:
    - step:
        name: Build
        script:
          - npm install
          - npm test
""",
        )
        wf = provider.parse(p)
        assert wf.platform == "bitbucket"
        assert len(wf.jobs) == 1
        job = wf.jobs[0]
        assert len(job.steps) == 2
        assert job.steps[0].shell_command == "npm install"
        assert job.steps[1].shell_command == "npm test"

    def test_branch_pipeline(self, provider: BitbucketProvider, tmp_path: Path) -> None:
        p = _write_config(
            tmp_path,
            """\
pipelines:
  branches:
    main:
      - step:
          script:
            - deploy.sh
""",
        )
        wf = provider.parse(p)
        assert len(wf.jobs) == 1
        events = {t.event for t in wf.triggers}
        assert "push" in events

    def test_pr_pipeline(self, provider: BitbucketProvider, tmp_path: Path) -> None:
        p = _write_config(
            tmp_path,
            """\
pipelines:
  pull-requests:
    '**':
      - step:
          script:
            - npm test
""",
        )
        wf = provider.parse(p)
        pr_triggers = [t for t in wf.triggers if t.event == "pull_request"]
        assert len(pr_triggers) == 1
        assert pr_triggers[0].is_fork_reachable is True
        assert pr_triggers[0].is_privileged is False

    def test_parallel_steps(self, provider: BitbucketProvider, tmp_path: Path) -> None:
        p = _write_config(
            tmp_path,
            """\
pipelines:
  default:
    - parallel:
        - step:
            script:
              - npm test
        - step:
            script:
              - npm run lint
""",
        )
        wf = provider.parse(p)
        assert len(wf.jobs) == 2

    def test_custom_pipeline(self, provider: BitbucketProvider, tmp_path: Path) -> None:
        p = _write_config(
            tmp_path,
            """\
pipelines:
  custom:
    deploy:
      - step:
          script:
            - deploy.sh
""",
        )
        wf = provider.parse(p)
        manual = [t for t in wf.triggers if t.event == "manual"]
        assert len(manual) == 1
        assert manual[0].is_privileged is True

    def test_rejects_invalid_yaml(self, provider: BitbucketProvider, tmp_path: Path) -> None:
        p = _write_config(tmp_path, "{{invalid")
        with pytest.raises(ParseError):
            provider.parse(p)

    def test_rejects_non_mapping(self, provider: BitbucketProvider, tmp_path: Path) -> None:
        p = _write_config(tmp_path, "- item1\n- item2")
        with pytest.raises(ParseError):
            provider.parse(p)


class TestSelfHosted:
    def test_self_hosted_runner(self, provider: BitbucketProvider, tmp_path: Path) -> None:
        p = _write_config(
            tmp_path,
            """\
pipelines:
  default:
    - step:
        runs-on:
          - self.hosted
          - linux
        script:
          - make
""",
        )
        wf = provider.parse(p)
        assert wf.jobs[0].runner.is_self_hosted is True
        assert "self.hosted" in wf.jobs[0].runner.labels

    def test_cloud_runner_default(self, provider: BitbucketProvider, tmp_path: Path) -> None:
        p = _write_config(
            tmp_path,
            """\
image: node:20
pipelines:
  default:
    - step:
        script:
          - npm test
""",
        )
        wf = provider.parse(p)
        assert wf.jobs[0].runner.is_self_hosted is False


class TestPipes:
    def test_pipe_as_component_ref(self, provider: BitbucketProvider, tmp_path: Path) -> None:
        p = _write_config(
            tmp_path,
            """\
pipelines:
  default:
    - step:
        script:
          - pipe: atlassian/aws-s3-deploy:1.2.3
            variables:
              REGION: us-east-1
""",
        )
        wf = provider.parse(p)
        pipe_steps = [s for s in wf.jobs[0].steps if s.type == "action"]
        assert len(pipe_steps) == 1
        ref = pipe_steps[0].action_ref
        assert ref is not None
        assert ref.owner == "atlassian"
        assert ref.is_first_party is True
        assert ref.is_pinned is True
        assert ref.ref == "1.2.3"

    def test_mutable_pipe_tag(self, provider: BitbucketProvider, tmp_path: Path) -> None:
        p = _write_config(
            tmp_path,
            """\
pipelines:
  default:
    - step:
        script:
          - pipe: myorg/deploy-pipe:1
""",
        )
        wf = provider.parse(p)
        pipe_steps = [s for s in wf.jobs[0].steps if s.type == "action"]
        ref = pipe_steps[0].action_ref
        assert ref is not None
        assert ref.is_pinned is False

    def test_docker_pipe(self, provider: BitbucketProvider, tmp_path: Path) -> None:
        p = _write_config(
            tmp_path,
            """\
pipelines:
  default:
    - step:
        script:
          - pipe: docker://myregistry/my-pipe:latest
""",
        )
        wf = provider.parse(p)
        pipe_steps = [s for s in wf.jobs[0].steps if s.type == "action"]
        ref = pipe_steps[0].action_ref
        assert ref is not None
        assert ref.is_pinned is False
        assert ref.owner == "myregistry"


class TestDeployment:
    def test_deployment_populates_secrets(
        self, provider: BitbucketProvider, tmp_path: Path
    ) -> None:
        p = _write_config(
            tmp_path,
            """\
pipelines:
  default:
    - step:
        deployment: production
        script:
          - deploy.sh
""",
        )
        wf = provider.parse(p)
        assert wf.jobs[0].secrets_referenced == ["deployment:production"]

    def test_no_deployment_empty_secrets(
        self, provider: BitbucketProvider, tmp_path: Path
    ) -> None:
        p = _write_config(
            tmp_path,
            """\
pipelines:
  default:
    - step:
        script:
          - npm test
""",
        )
        wf = provider.parse(p)
        assert wf.jobs[0].secrets_referenced == []

    def test_deployment_in_pr_pipeline(self, provider: BitbucketProvider, tmp_path: Path) -> None:
        p = _write_config(
            tmp_path,
            """\
pipelines:
  pull-requests:
    '**':
      - step:
          deployment: staging
          script:
            - deploy-preview.sh
""",
        )
        wf = provider.parse(p)
        assert wf.jobs[0].secrets_referenced == ["deployment:staging"]
        pr_triggers = [t for t in wf.triggers if t.event == "pull_request"]
        assert pr_triggers[0].is_fork_reachable is True


class TestExpressions:
    def test_tainted_branch_var(self, provider: BitbucketProvider, tmp_path: Path) -> None:
        p = _write_config(
            tmp_path,
            """\
pipelines:
  default:
    - step:
        script:
          - echo "$BITBUCKET_BRANCH"
""",
        )
        wf = provider.parse(p)
        step = wf.jobs[0].steps[0]
        tainted = [e for e in step.expressions if e.is_tainted]
        assert len(tainted) >= 1
        assert tainted[0].context_path == "BITBUCKET_BRANCH"

    def test_safe_command(self, provider: BitbucketProvider, tmp_path: Path) -> None:
        p = _write_config(
            tmp_path,
            """\
pipelines:
  default:
    - step:
        script:
          - npm test
""",
        )
        wf = provider.parse(p)
        step = wf.jobs[0].steps[0]
        assert step.expressions == []

    def test_after_script(self, provider: BitbucketProvider, tmp_path: Path) -> None:
        p = _write_config(
            tmp_path,
            """\
pipelines:
  default:
    - step:
        script:
          - npm test
        after-script:
          - echo "$BITBUCKET_BRANCH"
""",
        )
        wf = provider.parse(p)
        after = [s for s in wf.jobs[0].steps if s.name == "after-script"]
        assert len(after) == 1
        assert len(after[0].expressions) >= 1
