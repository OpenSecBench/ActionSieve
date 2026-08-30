from pathlib import Path

import pytest

from actionsieve.providers import ParseError
from actionsieve.providers.gitlab import GitLabProvider


@pytest.fixture
def provider() -> GitLabProvider:
    return GitLabProvider()


def _write_ci(tmp_path: Path, content: str) -> Path:
    ci_file = tmp_path / ".gitlab-ci.yml"
    ci_file.write_text(content)
    return ci_file


class TestDetect:
    def test_detects_gitlab_repo(self, provider: GitLabProvider, tmp_path: Path) -> None:
        (tmp_path / ".gitlab-ci.yml").write_text("stages: [build]")
        assert provider.detect(tmp_path) is True

    def test_rejects_non_gitlab_repo(self, provider: GitLabProvider, tmp_path: Path) -> None:
        assert provider.detect(tmp_path) is False


class TestFindFiles:
    def test_finds_ci_file(self, provider: GitLabProvider, tmp_path: Path) -> None:
        (tmp_path / ".gitlab-ci.yml").write_text("stages: [build]")
        files = provider.find_files(tmp_path)
        assert len(files) == 1
        assert files[0].name == ".gitlab-ci.yml"

    def test_empty_when_no_file(self, provider: GitLabProvider, tmp_path: Path) -> None:
        assert provider.find_files(tmp_path) == []


class TestParseBasic:
    def test_parses_simple_pipeline(self, provider: GitLabProvider, tmp_path: Path) -> None:
        ci = _write_ci(
            tmp_path,
            """\
stages:
  - build
  - test

build-job:
  stage: build
  script:
    - npm install
    - npm run build

test-job:
  stage: test
  needs: [build-job]
  script:
    - npm test
""",
        )
        wf = provider.parse(ci)
        assert wf.platform == "gitlab"
        assert len(wf.jobs) == 2

        build = next(j for j in wf.jobs if j.id == "build-job")
        assert len(build.steps) == 2
        assert build.steps[0].shell_command == "npm install"
        assert build.steps[1].shell_command == "npm run build"

        test = next(j for j in wf.jobs if j.id == "test-job")
        assert test.needs == ["build-job"]

    def test_skips_reserved_keys(self, provider: GitLabProvider, tmp_path: Path) -> None:
        ci = _write_ci(
            tmp_path,
            """\
stages:
  - build
variables:
  MY_VAR: hello
default:
  image: node:18
build:
  script:
    - echo hi
""",
        )
        wf = provider.parse(ci)
        assert len(wf.jobs) == 1
        assert wf.jobs[0].id == "build"

    def test_skips_hidden_jobs(self, provider: GitLabProvider, tmp_path: Path) -> None:
        ci = _write_ci(
            tmp_path,
            """\
.template:
  script:
    - echo template
real-job:
  script:
    - echo real
""",
        )
        wf = provider.parse(ci)
        assert len(wf.jobs) == 1
        assert wf.jobs[0].id == "real-job"


class TestParseVariables:
    def test_global_variables(self, provider: GitLabProvider, tmp_path: Path) -> None:
        ci = _write_ci(
            tmp_path,
            """\
variables:
  MY_VAR: hello
build:
  script:
    - echo $MY_VAR
""",
        )
        wf = provider.parse(ci)
        assert wf.env.get("MY_VAR") == "hello"

    def test_job_variables(self, provider: GitLabProvider, tmp_path: Path) -> None:
        ci = _write_ci(
            tmp_path,
            """\
build:
  variables:
    JOB_VAR: world
  script:
    - echo $JOB_VAR
""",
        )
        wf = provider.parse(ci)
        assert wf.jobs[0].env.get("JOB_VAR") == "world"

    def test_expanded_variable_syntax(self, provider: GitLabProvider, tmp_path: Path) -> None:
        ci = _write_ci(
            tmp_path,
            """\
variables:
  DB_URL:
    value: "postgres://localhost"
build:
  script:
    - echo $DB_URL
""",
        )
        wf = provider.parse(ci)
        assert wf.env.get("DB_URL") == "postgres://localhost"


class TestParseTriggers:
    def test_default_push_trigger(self, provider: GitLabProvider, tmp_path: Path) -> None:
        ci = _write_ci(
            tmp_path,
            """\
build:
  script:
    - echo hi
""",
        )
        wf = provider.parse(ci)
        assert len(wf.triggers) == 1
        assert wf.triggers[0].event == "push"

    def test_workflow_rules_triggers(self, provider: GitLabProvider, tmp_path: Path) -> None:
        ci = _write_ci(
            tmp_path,
            """\
workflow:
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
    - if: '$CI_PIPELINE_SOURCE == "push"'
build:
  script:
    - echo hi
""",
        )
        wf = provider.parse(ci)
        assert len(wf.triggers) == 2
        events = {t.event for t in wf.triggers}
        assert "merge_request" in events
        assert "push" in events

    def test_merge_request_is_fork_reachable(
        self, provider: GitLabProvider, tmp_path: Path
    ) -> None:
        ci = _write_ci(
            tmp_path,
            """\
workflow:
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
build:
  script:
    - echo hi
""",
        )
        wf = provider.parse(ci)
        assert wf.triggers[0].is_fork_reachable is True

    def test_push_is_privileged(self, provider: GitLabProvider, tmp_path: Path) -> None:
        ci = _write_ci(
            tmp_path,
            """\
workflow:
  rules:
    - if: '$CI_PIPELINE_SOURCE == "push"'
build:
  script:
    - echo hi
""",
        )
        wf = provider.parse(ci)
        assert wf.triggers[0].is_privileged is True

    def test_parent_pipeline_not_confused_with_pipeline(
        self, provider: GitLabProvider, tmp_path: Path
    ) -> None:
        ci = _write_ci(
            tmp_path,
            """\
workflow:
  rules:
    - if: '$CI_PIPELINE_SOURCE == "parent_pipeline"'
build:
  script:
    - echo hi
""",
        )
        wf = provider.parse(ci)
        assert wf.triggers[0].raw_event == "parent_pipeline"


class TestParseExpressions:
    def test_detects_tainted_variables(self, provider: GitLabProvider, tmp_path: Path) -> None:
        ci = _write_ci(
            tmp_path,
            """\
build:
  script:
    - echo $CI_COMMIT_MESSAGE
""",
        )
        wf = provider.parse(ci)
        step = wf.jobs[0].steps[0]
        tainted = [e for e in step.expressions if e.is_tainted]
        assert len(tainted) >= 1
        assert any("CI_COMMIT_MESSAGE" in e.context_path for e in tainted)

    def test_safe_variable_not_tainted(self, provider: GitLabProvider, tmp_path: Path) -> None:
        ci = _write_ci(
            tmp_path,
            """\
build:
  script:
    - echo $CI_PROJECT_DIR
""",
        )
        wf = provider.parse(ci)
        step = wf.jobs[0].steps[0]
        tainted = [e for e in step.expressions if e.is_tainted]
        assert len(tainted) == 0

    def test_braced_variable_syntax(self, provider: GitLabProvider, tmp_path: Path) -> None:
        ci = _write_ci(
            tmp_path,
            """\
build:
  script:
    - echo ${CI_MERGE_REQUEST_TITLE}
""",
        )
        wf = provider.parse(ci)
        step = wf.jobs[0].steps[0]
        tainted = [e for e in step.expressions if e.is_tainted]
        assert len(tainted) >= 1


class TestParseRunners:
    def test_default_runner(self, provider: GitLabProvider, tmp_path: Path) -> None:
        ci = _write_ci(
            tmp_path,
            """\
build:
  script:
    - echo hi
""",
        )
        wf = provider.parse(ci)
        assert wf.jobs[0].runner.is_self_hosted is False

    def test_tagged_runner_is_self_hosted(self, provider: GitLabProvider, tmp_path: Path) -> None:
        ci = _write_ci(
            tmp_path,
            """\
build:
  tags:
    - my-runner
    - linux
  script:
    - echo hi
""",
        )
        wf = provider.parse(ci)
        runner = wf.jobs[0].runner
        assert runner.is_self_hosted is True
        assert "my-runner" in runner.labels


class TestParseSecrets:
    def test_detects_secret_variables(self, provider: GitLabProvider, tmp_path: Path) -> None:
        ci = _write_ci(
            tmp_path,
            """\
deploy:
  script:
    - curl -H "Authorization: $SECRET_TOKEN" https://api.example.com
""",
        )
        wf = provider.parse(ci)
        assert "SECRET_TOKEN" in wf.jobs[0].secrets_referenced


class TestParseNeeds:
    def test_string_needs(self, provider: GitLabProvider, tmp_path: Path) -> None:
        ci = _write_ci(
            tmp_path,
            """\
build:
  script:
    - echo build
deploy:
  needs:
    - build
  script:
    - echo deploy
""",
        )
        wf = provider.parse(ci)
        deploy = next(j for j in wf.jobs if j.id == "deploy")
        assert deploy.needs == ["build"]

    def test_dict_needs(self, provider: GitLabProvider, tmp_path: Path) -> None:
        ci = _write_ci(
            tmp_path,
            """\
build:
  script:
    - echo build
deploy:
  needs:
    - job: build
      artifacts: true
  script:
    - echo deploy
""",
        )
        wf = provider.parse(ci)
        deploy = next(j for j in wf.jobs if j.id == "deploy")
        assert deploy.needs == ["build"]


class TestParseScriptBlocks:
    def test_before_and_after_script(self, provider: GitLabProvider, tmp_path: Path) -> None:
        ci = _write_ci(
            tmp_path,
            """\
build:
  before_script:
    - apt-get update
  script:
    - make build
  after_script:
    - make clean
""",
        )
        wf = provider.parse(ci)
        steps = wf.jobs[0].steps
        assert len(steps) == 3
        assert steps[0].shell_command == "apt-get update"
        assert steps[1].shell_command == "make build"
        assert steps[2].shell_command == "make clean"

    def test_default_before_script(self, provider: GitLabProvider, tmp_path: Path) -> None:
        ci = _write_ci(
            tmp_path,
            """\
default:
  before_script:
    - echo setup
build:
  script:
    - echo build
""",
        )
        wf = provider.parse(ci)
        steps = wf.jobs[0].steps
        assert len(steps) == 2
        assert steps[0].shell_command == "echo setup"

    def test_trigger_job(self, provider: GitLabProvider, tmp_path: Path) -> None:
        ci = _write_ci(
            tmp_path,
            """\
trigger-downstream:
  trigger:
    project: my-group/my-project
""",
        )
        wf = provider.parse(ci)
        assert len(wf.jobs) == 1
        assert wf.jobs[0].steps[0].type == "trigger"


class TestParseConditions:
    def test_job_rules(self, provider: GitLabProvider, tmp_path: Path) -> None:
        ci = _write_ci(
            tmp_path,
            """\
build:
  rules:
    - if: '$CI_PIPELINE_SOURCE == "push"'
  script:
    - echo hi
""",
        )
        wf = provider.parse(ci)
        assert len(wf.jobs[0].conditions) == 1
        assert "push" in wf.jobs[0].conditions[0]


class TestEdgeCases:
    def test_malformed_yaml(self, provider: GitLabProvider, tmp_path: Path) -> None:
        ci = _write_ci(tmp_path, "{{invalid")
        with pytest.raises(ParseError):
            provider.parse(ci)

    def test_non_mapping_yaml(self, provider: GitLabProvider, tmp_path: Path) -> None:
        ci = _write_ci(tmp_path, "- item1\n")
        with pytest.raises(ParseError, match="Expected mapping"):
            provider.parse(ci)

    def test_file_size_limit(self, provider: GitLabProvider, tmp_path: Path) -> None:
        ci = _write_ci(tmp_path, "x" * (1_048_577))
        with pytest.raises(ParseError, match="exceeds"):
            provider.parse(ci)

    def test_expression_syntax(self, provider: GitLabProvider) -> None:
        syntax = provider.expression_syntax()
        assert syntax.env_prefix == "$"
        assert "CI_" in syntax.context_roots
