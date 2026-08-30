from pathlib import Path

import pytest

from actionsieve.providers import ParseError
from actionsieve.providers.drone import DroneProvider


@pytest.fixture
def provider() -> DroneProvider:
    return DroneProvider()


def _write_config(tmp_path: Path, content: str) -> Path:
    p = tmp_path / ".drone.yml"
    p.write_text(content)
    return p


class TestDetect:
    def test_detects_drone_repo(self, provider: DroneProvider, tmp_path: Path) -> None:
        _write_config(tmp_path, "steps: []")
        assert provider.detect(tmp_path) is True

    def test_rejects_non_drone_repo(self, provider: DroneProvider, tmp_path: Path) -> None:
        assert provider.detect(tmp_path) is False


class TestFindFiles:
    def test_finds_config(self, provider: DroneProvider, tmp_path: Path) -> None:
        _write_config(tmp_path, "steps: []")
        files = provider.find_files(tmp_path)
        assert len(files) == 1

    def test_empty_when_no_config(self, provider: DroneProvider, tmp_path: Path) -> None:
        assert provider.find_files(tmp_path) == []


class TestParse:
    def test_simple_command_step(self, provider: DroneProvider, tmp_path: Path) -> None:
        p = _write_config(
            tmp_path,
            """\
kind: pipeline
name: build
steps:
  - name: test
    image: node:20
    commands:
      - npm test
""",
        )
        wf = provider.parse(p)
        assert wf.platform == "drone"
        assert len(wf.jobs) == 1
        assert wf.jobs[0].steps[0].shell_command == "npm test"

    def test_multiple_commands(self, provider: DroneProvider, tmp_path: Path) -> None:
        p = _write_config(
            tmp_path,
            """\
kind: pipeline
name: build
steps:
  - name: test
    image: node:20
    commands:
      - npm ci
      - npm test
""",
        )
        wf = provider.parse(p)
        assert len(wf.jobs[0].steps) == 2
        assert wf.jobs[0].steps[0].shell_command == "npm ci"
        assert wf.jobs[0].steps[1].shell_command == "npm test"

    def test_plugin_step(self, provider: DroneProvider, tmp_path: Path) -> None:
        p = _write_config(
            tmp_path,
            """\
kind: pipeline
name: build
steps:
  - name: publish
    image: plugins/docker:20.17.0
    settings:
      repo: myorg/app
""",
        )
        wf = provider.parse(p)
        step = wf.jobs[0].steps[0]
        assert step.type == "action"
        assert step.action_ref is not None
        assert step.action_ref.name == "docker"
        assert step.action_ref.owner == "plugins"
        assert step.action_ref.is_first_party is True

    def test_multi_document(self, provider: DroneProvider, tmp_path: Path) -> None:
        p = _write_config(
            tmp_path,
            """\
kind: pipeline
name: build
steps:
  - name: test
    image: node:20
    commands:
      - npm test
---
kind: pipeline
name: deploy
steps:
  - name: deploy
    image: alpine
    commands:
      - deploy.sh
""",
        )
        wf = provider.parse(p)
        assert len(wf.jobs) == 2

    def test_skips_non_pipeline_docs(self, provider: DroneProvider, tmp_path: Path) -> None:
        p = _write_config(
            tmp_path,
            """\
kind: pipeline
name: build
steps:
  - name: test
    image: node:20
    commands:
      - npm test
---
kind: secret
name: my_secret
data: encrypted-value
""",
        )
        wf = provider.parse(p)
        assert len(wf.jobs) == 1

    def test_rejects_invalid_yaml(self, provider: DroneProvider, tmp_path: Path) -> None:
        p = _write_config(tmp_path, "{{invalid")
        with pytest.raises(ParseError):
            provider.parse(p)

    def test_pipeline_name(self, provider: DroneProvider, tmp_path: Path) -> None:
        p = _write_config(
            tmp_path,
            """\
kind: pipeline
name: my-build
steps:
  - name: test
    image: node:20
    commands:
      - npm test
""",
        )
        wf = provider.parse(p)
        assert wf.jobs[0].name == "my-build"

    def test_pipeline_env(self, provider: DroneProvider, tmp_path: Path) -> None:
        p = _write_config(
            tmp_path,
            """\
kind: pipeline
name: build
environment:
  NODE_ENV: production
steps:
  - name: test
    image: node:20
    commands:
      - npm test
""",
        )
        wf = provider.parse(p)
        assert wf.jobs[0].env["NODE_ENV"] == "production"

    def test_step_name_on_steps(self, provider: DroneProvider, tmp_path: Path) -> None:
        p = _write_config(
            tmp_path,
            """\
kind: pipeline
name: build
steps:
  - name: run tests
    image: node:20
    commands:
      - npm test
""",
        )
        wf = provider.parse(p)
        assert wf.jobs[0].steps[0].name == "run tests"


class TestRunner:
    def test_exec_type_is_self_hosted(self, provider: DroneProvider, tmp_path: Path) -> None:
        p = _write_config(
            tmp_path,
            """\
kind: pipeline
type: exec
name: build
steps:
  - name: test
    commands:
      - npm test
""",
        )
        wf = provider.parse(p)
        assert wf.jobs[0].runner.is_self_hosted is True

    def test_ssh_type_is_self_hosted(self, provider: DroneProvider, tmp_path: Path) -> None:
        p = _write_config(
            tmp_path,
            """\
kind: pipeline
type: ssh
name: build
steps:
  - name: test
    commands:
      - npm test
""",
        )
        wf = provider.parse(p)
        assert wf.jobs[0].runner.is_self_hosted is True

    def test_docker_type_default(self, provider: DroneProvider, tmp_path: Path) -> None:
        p = _write_config(
            tmp_path,
            """\
kind: pipeline
name: build
steps:
  - name: test
    image: node:20
    commands:
      - npm test
""",
        )
        wf = provider.parse(p)
        assert wf.jobs[0].runner.is_self_hosted is False

    def test_node_selector_is_self_hosted(self, provider: DroneProvider, tmp_path: Path) -> None:
        p = _write_config(
            tmp_path,
            """\
kind: pipeline
name: build
node:
  instance: runner-x86
steps:
  - name: test
    image: node:20
    commands:
      - npm test
""",
        )
        wf = provider.parse(p)
        assert wf.jobs[0].runner.is_self_hosted is True
        assert "instance=runner-x86" in wf.jobs[0].runner.labels


class TestPlugins:
    def test_unpinned_plugin(self, provider: DroneProvider, tmp_path: Path) -> None:
        p = _write_config(
            tmp_path,
            """\
kind: pipeline
name: build
steps:
  - name: publish
    image: plugins/docker
    settings:
      repo: myorg/app
""",
        )
        wf = provider.parse(p)
        ref = wf.jobs[0].steps[0].action_ref
        assert ref is not None
        assert ref.is_pinned is False
        assert ref.ref == "latest"

    def test_semver_pinned_plugin(self, provider: DroneProvider, tmp_path: Path) -> None:
        p = _write_config(
            tmp_path,
            """\
kind: pipeline
name: build
steps:
  - name: publish
    image: plugins/docker:20.17.0
    settings:
      repo: myorg/app
""",
        )
        wf = provider.parse(p)
        ref = wf.jobs[0].steps[0].action_ref
        assert ref is not None
        assert ref.is_pinned is True
        assert ref.ref == "20.17.0"

    def test_digest_pinned_plugin(self, provider: DroneProvider, tmp_path: Path) -> None:
        p = _write_config(
            tmp_path,
            """\
kind: pipeline
name: build
steps:
  - name: publish
    image: plugins/docker:20.17.0@sha256:a1b2c3d4e5f6
    settings:
      repo: myorg/app
""",
        )
        wf = provider.parse(p)
        ref = wf.jobs[0].steps[0].action_ref
        assert ref is not None
        assert ref.is_pinned is True
        assert ref.ref_type == "sha"

    def test_plugin_settings_as_inputs(self, provider: DroneProvider, tmp_path: Path) -> None:
        p = _write_config(
            tmp_path,
            """\
kind: pipeline
name: build
steps:
  - name: publish
    image: plugins/docker:20.17.0
    settings:
      repo: myorg/app
      tags: latest
""",
        )
        wf = provider.parse(p)
        step = wf.jobs[0].steps[0]
        assert step.inputs["repo"] == "myorg/app"

    def test_third_party_plugin(self, provider: DroneProvider, tmp_path: Path) -> None:
        p = _write_config(
            tmp_path,
            """\
kind: pipeline
name: build
steps:
  - name: notify
    image: myorg/slack:1.0.0
    settings:
      channel: builds
""",
        )
        wf = provider.parse(p)
        ref = wf.jobs[0].steps[0].action_ref
        assert ref is not None
        assert ref.is_first_party is False
        assert ref.owner == "myorg"


class TestExpressions:
    def test_tainted_branch_var(self, provider: DroneProvider, tmp_path: Path) -> None:
        p = _write_config(
            tmp_path,
            """\
kind: pipeline
name: build
steps:
  - name: test
    image: alpine
    commands:
      - echo "$DRONE_BRANCH"
""",
        )
        wf = provider.parse(p)
        tainted = [e for e in wf.jobs[0].steps[0].expressions if e.is_tainted]
        assert len(tainted) == 1
        assert tainted[0].context_path == "DRONE_BRANCH"

    def test_tainted_message_var(self, provider: DroneProvider, tmp_path: Path) -> None:
        p = _write_config(
            tmp_path,
            """\
kind: pipeline
name: build
steps:
  - name: test
    image: alpine
    commands:
      - echo "${DRONE_COMMIT_MESSAGE}"
""",
        )
        wf = provider.parse(p)
        tainted = [e for e in wf.jobs[0].steps[0].expressions if e.is_tainted]
        assert len(tainted) == 1

    def test_tainted_commit_author(self, provider: DroneProvider, tmp_path: Path) -> None:
        p = _write_config(
            tmp_path,
            """\
kind: pipeline
name: build
steps:
  - name: notify
    image: alpine
    commands:
      - echo $DRONE_COMMIT_AUTHOR
""",
        )
        wf = provider.parse(p)
        tainted = [e for e in wf.jobs[0].steps[0].expressions if e.is_tainted]
        assert len(tainted) == 1
        assert tainted[0].context_path == "DRONE_COMMIT_AUTHOR"

    def test_tainted_target_branch(self, provider: DroneProvider, tmp_path: Path) -> None:
        p = _write_config(
            tmp_path,
            """\
kind: pipeline
name: build
steps:
  - name: test
    image: alpine
    commands:
      - echo ${DRONE_TARGET_BRANCH}
""",
        )
        wf = provider.parse(p)
        tainted = [e for e in wf.jobs[0].steps[0].expressions if e.is_tainted]
        assert len(tainted) == 1
        assert tainted[0].context_path == "DRONE_TARGET_BRANCH"

    def test_safe_command(self, provider: DroneProvider, tmp_path: Path) -> None:
        p = _write_config(
            tmp_path,
            """\
kind: pipeline
name: build
steps:
  - name: test
    image: node:20
    commands:
      - npm test
""",
        )
        wf = provider.parse(p)
        assert wf.jobs[0].steps[0].expressions == []


class TestSecrets:
    def test_from_secret_tracked(self, provider: DroneProvider, tmp_path: Path) -> None:
        p = _write_config(
            tmp_path,
            """\
kind: pipeline
name: build
steps:
  - name: deploy
    image: alpine
    environment:
      SECRET_KEY:
        from_secret: my_secret
    commands:
      - deploy.sh
""",
        )
        wf = provider.parse(p)
        assert "my_secret" in wf.jobs[0].secrets_referenced


class TestTriggers:
    def test_default_triggers(self, provider: DroneProvider, tmp_path: Path) -> None:
        p = _write_config(
            tmp_path,
            """\
kind: pipeline
name: build
steps:
  - name: test
    image: node:20
    commands:
      - npm test
""",
        )
        wf = provider.parse(p)
        events = {t.event for t in wf.triggers}
        assert "push" in events

    def test_explicit_events(self, provider: DroneProvider, tmp_path: Path) -> None:
        p = _write_config(
            tmp_path,
            """\
kind: pipeline
name: build
trigger:
  event:
    - push
    - pull_request
steps:
  - name: test
    image: node:20
    commands:
      - npm test
""",
        )
        wf = provider.parse(p)
        events = {t.event for t in wf.triggers}
        assert events == {"push", "pull_request"}

    def test_pr_trigger_is_fork_reachable(self, provider: DroneProvider, tmp_path: Path) -> None:
        p = _write_config(
            tmp_path,
            """\
kind: pipeline
name: build
trigger:
  event:
    - pull_request
steps:
  - name: test
    image: node:20
    commands:
      - npm test
""",
        )
        wf = provider.parse(p)
        pr_trigger = [t for t in wf.triggers if t.event == "pull_request"]
        assert len(pr_trigger) == 1
        assert pr_trigger[0].is_fork_reachable is True

    def test_include_syntax(self, provider: DroneProvider, tmp_path: Path) -> None:
        p = _write_config(
            tmp_path,
            """\
kind: pipeline
name: build
trigger:
  event:
    include:
      - push
steps:
  - name: test
    image: node:20
    commands:
      - npm test
""",
        )
        wf = provider.parse(p)
        events = {t.event for t in wf.triggers}
        assert events == {"push"}
