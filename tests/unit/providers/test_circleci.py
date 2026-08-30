from pathlib import Path

import pytest

from actionsieve.providers import ParseError
from actionsieve.providers.circleci import CircleCIProvider


@pytest.fixture
def provider() -> CircleCIProvider:
    return CircleCIProvider()


def _write_config(tmp_path: Path, content: str) -> Path:
    d = tmp_path / ".circleci"
    d.mkdir()
    p = d / "config.yml"
    p.write_text(content)
    return p


class TestDetect:
    def test_detects_circleci_repo(self, provider: CircleCIProvider, tmp_path: Path) -> None:
        _write_config(tmp_path, "version: 2.1")
        assert provider.detect(tmp_path) is True

    def test_rejects_non_circleci_repo(self, provider: CircleCIProvider, tmp_path: Path) -> None:
        assert provider.detect(tmp_path) is False


class TestFindFiles:
    def test_finds_config(self, provider: CircleCIProvider, tmp_path: Path) -> None:
        _write_config(tmp_path, "version: 2.1")
        files = provider.find_files(tmp_path)
        assert len(files) == 1

    def test_empty_when_no_config(self, provider: CircleCIProvider, tmp_path: Path) -> None:
        assert provider.find_files(tmp_path) == []


class TestParse:
    def test_simple_job(self, provider: CircleCIProvider, tmp_path: Path) -> None:
        p = _write_config(
            tmp_path,
            """\
version: 2.1
jobs:
  build:
    docker:
      - image: cimg/node:20.10
    steps:
      - checkout
      - run: npm test
""",
        )
        wf = provider.parse(p)
        assert wf.platform == "circleci"
        assert len(wf.jobs) == 1
        job = wf.jobs[0]
        assert job.id == "build"
        assert len(job.steps) == 2
        assert job.steps[0].type == "action"
        assert job.steps[1].type == "shell"
        assert job.steps[1].shell_command == "npm test"

    def test_executor_ref(self, provider: CircleCIProvider, tmp_path: Path) -> None:
        p = _write_config(
            tmp_path,
            """\
version: 2.1
executors:
  node:
    docker:
      - image: cimg/node:18.19
jobs:
  test:
    executor: node
    steps:
      - checkout
""",
        )
        wf = provider.parse(p)
        assert wf.jobs[0].runner.raw == "cimg/node:18.19"

    def test_machine_executor(self, provider: CircleCIProvider, tmp_path: Path) -> None:
        p = _write_config(
            tmp_path,
            """\
version: 2.1
jobs:
  build:
    machine:
      image: ubuntu-2204:current
    steps:
      - run: make
""",
        )
        wf = provider.parse(p)
        assert wf.jobs[0].runner.raw == "ubuntu-2204:current"

    def test_self_hosted_resource_class(self, provider: CircleCIProvider, tmp_path: Path) -> None:
        p = _write_config(
            tmp_path,
            """\
version: 2.1
jobs:
  deploy:
    docker:
      - image: cimg/base:stable
    resource_class: myorg/production
    steps:
      - run: deploy.sh
""",
        )
        wf = provider.parse(p)
        assert wf.jobs[0].runner.is_self_hosted is True
        assert wf.jobs[0].runner.raw == "myorg/production"

    def test_managed_resource_class_not_self_hosted(
        self, provider: CircleCIProvider, tmp_path: Path
    ) -> None:
        p = _write_config(
            tmp_path,
            """\
version: 2.1
jobs:
  build:
    docker:
      - image: cimg/base:stable
    resource_class: large
    steps:
      - run: make
""",
        )
        wf = provider.parse(p)
        assert wf.jobs[0].runner.is_self_hosted is False

    def test_rejects_invalid_yaml(self, provider: CircleCIProvider, tmp_path: Path) -> None:
        p = _write_config(tmp_path, "{{invalid")
        with pytest.raises(ParseError):
            provider.parse(p)

    def test_rejects_non_mapping(self, provider: CircleCIProvider, tmp_path: Path) -> None:
        p = _write_config(tmp_path, "- item1\n- item2")
        with pytest.raises(ParseError):
            provider.parse(p)


class TestOrbs:
    def test_parses_orb_refs(self, provider: CircleCIProvider, tmp_path: Path) -> None:
        p = _write_config(
            tmp_path,
            """\
version: 2.1
orbs:
  slack: circleci/slack@4.12.5
  deploy: myorg/deploy@volatile
jobs:
  build:
    docker:
      - image: cimg/base:stable
    steps:
      - run: echo ok
""",
        )
        wf = provider.parse(p)
        job = wf.jobs[0]
        orb_steps = [s for s in job.steps if s.type == "action" and s.name.startswith("orb:")]
        assert len(orb_steps) == 2

        slack_ref = orb_steps[0].action_ref
        assert slack_ref is not None
        assert slack_ref.owner == "circleci"
        assert slack_ref.is_first_party is True
        assert slack_ref.is_pinned is True
        assert slack_ref.ref == "4.12.5"

        deploy_ref = orb_steps[1].action_ref
        assert deploy_ref is not None
        assert deploy_ref.is_pinned is False
        assert deploy_ref.ref == "volatile"


class TestExpressions:
    def test_pipeline_param_expression(self, provider: CircleCIProvider, tmp_path: Path) -> None:
        p = _write_config(
            tmp_path,
            """\
version: 2.1
jobs:
  build:
    docker:
      - image: cimg/base:stable
    steps:
      - run: echo '<< pipeline.git.branch >>'
""",
        )
        wf = provider.parse(p)
        step = wf.jobs[0].steps[0]
        assert len(step.expressions) == 1
        assert step.expressions[0].is_tainted is True
        assert step.expressions[0].context_path == "pipeline.git.branch"

    def test_env_var_expression(self, provider: CircleCIProvider, tmp_path: Path) -> None:
        p = _write_config(
            tmp_path,
            """\
version: 2.1
jobs:
  build:
    docker:
      - image: cimg/base:stable
    steps:
      - run: echo "$CIRCLE_BRANCH"
""",
        )
        wf = provider.parse(p)
        step = wf.jobs[0].steps[0]
        tainted = [e for e in step.expressions if e.is_tainted]
        assert len(tainted) >= 1

    def test_safe_command_no_tainted(self, provider: CircleCIProvider, tmp_path: Path) -> None:
        p = _write_config(
            tmp_path,
            """\
version: 2.1
jobs:
  build:
    docker:
      - image: cimg/base:stable
    steps:
      - run: npm test
""",
        )
        wf = provider.parse(p)
        step = wf.jobs[0].steps[0]
        assert step.expressions == []


class TestTriggers:
    def test_default_triggers(self, provider: CircleCIProvider, tmp_path: Path) -> None:
        p = _write_config(
            tmp_path,
            """\
version: 2.1
jobs:
  build:
    docker:
      - image: cimg/base:stable
    steps:
      - run: echo ok
""",
        )
        wf = provider.parse(p)
        events = {t.event for t in wf.triggers}
        assert "push" in events
        assert "pull_request" in events

    def test_schedule_trigger(self, provider: CircleCIProvider, tmp_path: Path) -> None:
        p = _write_config(
            tmp_path,
            """\
version: 2.1
jobs:
  nightly:
    docker:
      - image: cimg/base:stable
    steps:
      - run: echo ok
workflows:
  nightly:
    triggers:
      - schedule:
          cron: '0 0 * * *'
    jobs:
      - nightly
""",
        )
        wf = provider.parse(p)
        events = {t.event for t in wf.triggers}
        assert "schedule" in events


class TestContexts:
    def test_contexts_populate_secrets(self, provider: CircleCIProvider, tmp_path: Path) -> None:
        p = _write_config(
            tmp_path,
            """\
version: 2.1
jobs:
  deploy:
    docker:
      - image: cimg/base:stable
    steps:
      - run: deploy.sh
workflows:
  main:
    jobs:
      - deploy:
          context:
            - org-global
            - deploy-secrets
""",
        )
        wf = provider.parse(p)
        assert wf.jobs[0].secrets_referenced == ["org-global", "deploy-secrets"]

    def test_no_context_empty_secrets(self, provider: CircleCIProvider, tmp_path: Path) -> None:
        p = _write_config(
            tmp_path,
            """\
version: 2.1
jobs:
  build:
    docker:
      - image: cimg/base:stable
    steps:
      - run: npm test
workflows:
  main:
    jobs:
      - build
""",
        )
        wf = provider.parse(p)
        assert wf.jobs[0].secrets_referenced == []

    def test_string_context(self, provider: CircleCIProvider, tmp_path: Path) -> None:
        p = _write_config(
            tmp_path,
            """\
version: 2.1
jobs:
  deploy:
    docker:
      - image: cimg/base:stable
    steps:
      - run: deploy.sh
workflows:
  main:
    jobs:
      - deploy:
          context: org-global
""",
        )
        wf = provider.parse(p)
        assert wf.jobs[0].secrets_referenced == ["org-global"]


class TestDynamicConfig:
    def test_setup_true_detected(self, provider: CircleCIProvider, tmp_path: Path) -> None:
        p = _write_config(
            tmp_path,
            """\
version: 2.1
setup: true
jobs:
  generate:
    docker:
      - image: cimg/base:stable
    steps:
      - run: python gen.py
""",
        )
        wf = provider.parse(p)
        assert wf.raw.get("setup") is True

    def test_no_setup_flag(self, provider: CircleCIProvider, tmp_path: Path) -> None:
        p = _write_config(
            tmp_path,
            """\
version: 2.1
jobs:
  build:
    docker:
      - image: cimg/base:stable
    steps:
      - run: npm test
""",
        )
        wf = provider.parse(p)
        assert wf.raw.get("setup") is None


class TestOrbCommandStep:
    def test_orb_command_in_steps(self, provider: CircleCIProvider, tmp_path: Path) -> None:
        p = _write_config(
            tmp_path,
            """\
version: 2.1
orbs:
  slack: circleci/slack@4.12.5
jobs:
  notify:
    docker:
      - image: cimg/base:stable
    steps:
      - slack/notify:
          channel: deploys
""",
        )
        wf = provider.parse(p)
        job = wf.jobs[0]
        cmd_steps = [s for s in job.steps if s.name == "slack/notify"]
        assert len(cmd_steps) == 1
        assert cmd_steps[0].action_ref is not None
        assert cmd_steps[0].action_ref.owner == "slack"
