from pathlib import Path

import pytest

from actionsieve.providers import ParseError
from actionsieve.providers.buildkite import BuildkiteProvider


@pytest.fixture
def provider() -> BuildkiteProvider:
    return BuildkiteProvider()


def _write_pipeline(tmp_path: Path, content: str) -> Path:
    d = tmp_path / ".buildkite"
    d.mkdir()
    p = d / "pipeline.yml"
    p.write_text(content)
    return p


class TestDetect:
    def test_detects_buildkite_repo(self, provider: BuildkiteProvider, tmp_path: Path) -> None:
        _write_pipeline(tmp_path, "steps: []")
        assert provider.detect(tmp_path) is True

    def test_rejects_non_buildkite_repo(self, provider: BuildkiteProvider, tmp_path: Path) -> None:
        assert provider.detect(tmp_path) is False


class TestFindFiles:
    def test_finds_pipeline(self, provider: BuildkiteProvider, tmp_path: Path) -> None:
        _write_pipeline(tmp_path, "steps: []")
        files = provider.find_files(tmp_path)
        assert len(files) == 1

    def test_empty_when_no_pipeline(self, provider: BuildkiteProvider, tmp_path: Path) -> None:
        assert provider.find_files(tmp_path) == []


class TestParse:
    def test_simple_command_step(self, provider: BuildkiteProvider, tmp_path: Path) -> None:
        p = _write_pipeline(
            tmp_path,
            """\
steps:
  - label: Build
    command: make build
""",
        )
        wf = provider.parse(p)
        assert wf.platform == "buildkite"
        assert len(wf.jobs) == 1
        assert wf.jobs[0].steps[0].shell_command == "make build"

    def test_multiple_commands(self, provider: BuildkiteProvider, tmp_path: Path) -> None:
        p = _write_pipeline(
            tmp_path,
            """\
steps:
  - command:
      - npm ci
      - npm test
""",
        )
        wf = provider.parse(p)
        assert len(wf.jobs[0].steps) == 2
        assert wf.jobs[0].steps[0].shell_command == "npm ci"
        assert wf.jobs[0].steps[1].shell_command == "npm test"

    def test_group_steps(self, provider: BuildkiteProvider, tmp_path: Path) -> None:
        p = _write_pipeline(
            tmp_path,
            """\
steps:
  - group: Tests
    steps:
      - command: npm test
      - command: npm run lint
""",
        )
        wf = provider.parse(p)
        assert len(wf.jobs) == 2

    def test_skips_wait_and_block(self, provider: BuildkiteProvider, tmp_path: Path) -> None:
        p = _write_pipeline(
            tmp_path,
            """\
steps:
  - command: make build
  - wait: ~
  - block: Approve
  - command: make deploy
""",
        )
        wf = provider.parse(p)
        assert len(wf.jobs) == 2

    def test_skips_trigger(self, provider: BuildkiteProvider, tmp_path: Path) -> None:
        p = _write_pipeline(
            tmp_path,
            """\
steps:
  - command: make build
  - trigger: deploy-pipeline
""",
        )
        wf = provider.parse(p)
        assert len(wf.jobs) == 1

    def test_label_as_name(self, provider: BuildkiteProvider, tmp_path: Path) -> None:
        p = _write_pipeline(
            tmp_path,
            """\
steps:
  - label: ":rocket: Deploy"
    command: deploy.sh
""",
        )
        wf = provider.parse(p)
        assert wf.jobs[0].name == ":rocket: Deploy"

    def test_rejects_invalid_yaml(self, provider: BuildkiteProvider, tmp_path: Path) -> None:
        p = _write_pipeline(tmp_path, "{{invalid")
        with pytest.raises(ParseError):
            provider.parse(p)

    def test_rejects_non_mapping(self, provider: BuildkiteProvider, tmp_path: Path) -> None:
        p = _write_pipeline(tmp_path, "- item1\n- item2")
        with pytest.raises(ParseError):
            provider.parse(p)

    def test_global_env(self, provider: BuildkiteProvider, tmp_path: Path) -> None:
        p = _write_pipeline(
            tmp_path,
            """\
env:
  NODE_ENV: production
steps:
  - command: npm test
""",
        )
        wf = provider.parse(p)
        assert wf.env == {"NODE_ENV": "production"}
        assert wf.jobs[0].env["NODE_ENV"] == "production"

    def test_step_env_overrides_global(self, provider: BuildkiteProvider, tmp_path: Path) -> None:
        p = _write_pipeline(
            tmp_path,
            """\
env:
  NODE_ENV: production
steps:
  - command: npm test
    env:
      NODE_ENV: test
""",
        )
        wf = provider.parse(p)
        assert wf.jobs[0].env["NODE_ENV"] == "test"


class TestAgents:
    def test_self_hosted_agents(self, provider: BuildkiteProvider, tmp_path: Path) -> None:
        p = _write_pipeline(
            tmp_path,
            """\
steps:
  - command: make
    agents:
      queue: deploy
      os: linux
""",
        )
        wf = provider.parse(p)
        assert wf.jobs[0].runner.is_self_hosted is True
        assert "queue=deploy" in wf.jobs[0].runner.labels

    def test_managed_default_queue(self, provider: BuildkiteProvider, tmp_path: Path) -> None:
        p = _write_pipeline(
            tmp_path,
            """\
steps:
  - command: make
    agents:
      queue: default
""",
        )
        wf = provider.parse(p)
        assert wf.jobs[0].runner.is_managed is True
        assert wf.jobs[0].runner.is_self_hosted is False

    def test_no_agents_default(self, provider: BuildkiteProvider, tmp_path: Path) -> None:
        p = _write_pipeline(
            tmp_path,
            """\
steps:
  - command: make
""",
        )
        wf = provider.parse(p)
        assert wf.jobs[0].runner.is_self_hosted is False


class TestPlugins:
    def test_plugin_as_component_ref(self, provider: BuildkiteProvider, tmp_path: Path) -> None:
        p = _write_pipeline(
            tmp_path,
            """\
steps:
  - command: make
    plugins:
      - docker#v5.0.0:
          image: node:20
""",
        )
        wf = provider.parse(p)
        plugin_steps = [s for s in wf.jobs[0].steps if s.type == "action"]
        assert len(plugin_steps) == 1
        ref = plugin_steps[0].action_ref
        assert ref is not None
        assert ref.name == "docker"
        assert ref.ref == "v5.0.0"
        assert ref.is_pinned is True

    def test_unpinned_plugin(self, provider: BuildkiteProvider, tmp_path: Path) -> None:
        p = _write_pipeline(
            tmp_path,
            """\
steps:
  - command: make
    plugins:
      - myorg/deploy#main:
          target: prod
""",
        )
        wf = provider.parse(p)
        plugin_steps = [s for s in wf.jobs[0].steps if s.type == "action"]
        ref = plugin_steps[0].action_ref
        assert ref is not None
        assert ref.is_pinned is False
        assert ref.ref == "main"

    def test_sha_pinned_plugin(self, provider: BuildkiteProvider, tmp_path: Path) -> None:
        p = _write_pipeline(
            tmp_path,
            """\
steps:
  - command: make
    plugins:
      - buildkite-plugins/docker#a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2:
          image: node:20
""",
        )
        wf = provider.parse(p)
        plugin_steps = [s for s in wf.jobs[0].steps if s.type == "action"]
        ref = plugin_steps[0].action_ref
        assert ref is not None
        assert ref.is_pinned is True
        assert ref.ref_type == "sha"
        assert ref.is_first_party is True

    def test_plugin_inputs(self, provider: BuildkiteProvider, tmp_path: Path) -> None:
        p = _write_pipeline(
            tmp_path,
            """\
steps:
  - command: make
    plugins:
      - docker#v5.0.0:
          image: node:20
          propagate-environment: true
""",
        )
        wf = provider.parse(p)
        plugin_steps = [s for s in wf.jobs[0].steps if s.type == "action"]
        assert plugin_steps[0].inputs["image"] == "node:20"


class TestExpressions:
    def test_tainted_branch_var(self, provider: BuildkiteProvider, tmp_path: Path) -> None:
        p = _write_pipeline(
            tmp_path,
            """\
steps:
  - command: echo "$BUILDKITE_BRANCH"
""",
        )
        wf = provider.parse(p)
        step = wf.jobs[0].steps[0]
        tainted = [e for e in step.expressions if e.is_tainted]
        assert len(tainted) == 1
        assert tainted[0].context_path == "BUILDKITE_BRANCH"

    def test_tainted_message_var(self, provider: BuildkiteProvider, tmp_path: Path) -> None:
        p = _write_pipeline(
            tmp_path,
            """\
steps:
  - command: echo "${BUILDKITE_MESSAGE}"
""",
        )
        wf = provider.parse(p)
        step = wf.jobs[0].steps[0]
        tainted = [e for e in step.expressions if e.is_tainted]
        assert len(tainted) == 1
        assert tainted[0].context_path == "BUILDKITE_MESSAGE"

    def test_safe_command(self, provider: BuildkiteProvider, tmp_path: Path) -> None:
        p = _write_pipeline(
            tmp_path,
            """\
steps:
  - command: npm test
""",
        )
        wf = provider.parse(p)
        assert wf.jobs[0].steps[0].expressions == []


class TestTriggers:
    def test_default_trigger(self, provider: BuildkiteProvider, tmp_path: Path) -> None:
        p = _write_pipeline(
            tmp_path,
            """\
steps:
  - command: make
""",
        )
        wf = provider.parse(p)
        assert any(t.event == "push" for t in wf.triggers)
        assert any(t.is_fork_reachable for t in wf.triggers)

    def test_pipeline_upload_adds_dynamic_trigger(
        self, provider: BuildkiteProvider, tmp_path: Path
    ) -> None:
        p = _write_pipeline(
            tmp_path,
            """\
steps:
  - command: buildkite-agent pipeline upload
""",
        )
        wf = provider.parse(p)
        dynamic = [t for t in wf.triggers if t.event == "dynamic"]
        assert len(dynamic) == 1
        assert dynamic[0].raw_event == "pipeline_upload"
