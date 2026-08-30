from pathlib import Path
from unittest.mock import patch

import pytest

from actionsieve.context import (
    ContextError,
    detect_ci_context,
    load_context_file,
    parse_changed_files,
    resolve_context,
)


class TestParseChangedFiles:
    def test_comma_separated(self) -> None:
        assert parse_changed_files("a.py,b.py,c.py") == ["a.py", "b.py", "c.py"]

    def test_strips_whitespace(self) -> None:
        assert parse_changed_files(" a.py , b.py ") == ["a.py", "b.py"]

    def test_empty_string(self) -> None:
        assert parse_changed_files("") == []

    def test_reads_from_file(self, tmp_path: Path) -> None:
        f = tmp_path / "files.txt"
        f.write_text("src/main.py\nDockerfile\n")
        assert parse_changed_files(str(f)) == ["src/main.py", "Dockerfile"]

    def test_reads_from_file_skips_blank_lines(self, tmp_path: Path) -> None:
        f = tmp_path / "files.txt"
        f.write_text("a.py\n\nb.py\n  \nc.py\n")
        assert parse_changed_files(str(f)) == ["a.py", "b.py", "c.py"]

    def test_single_file(self) -> None:
        assert parse_changed_files("Dockerfile") == ["Dockerfile"]


class TestLoadContextFile:
    def test_loads_all_fields(self, tmp_path: Path) -> None:
        f = tmp_path / "ctx.yaml"
        f.write_text(
            "trigger: pull_request\nactor: fork\nchanged_files:\n  - Dockerfile\n  - src/app.py\n"
        )
        ctx = load_context_file(f)
        assert ctx.trigger == "pull_request"
        assert ctx.actor == "fork"
        assert ctx.changed_files == ["Dockerfile", "src/app.py"]

    def test_partial_fields(self, tmp_path: Path) -> None:
        f = tmp_path / "ctx.yaml"
        f.write_text("trigger: push\n")
        ctx = load_context_file(f)
        assert ctx.trigger == "push"
        assert ctx.actor is None
        assert ctx.changed_files == []

    def test_rejects_non_mapping(self, tmp_path: Path) -> None:
        f = tmp_path / "ctx.yaml"
        f.write_text("- item1\n- item2\n")
        with pytest.raises(ContextError, match="YAML mapping"):
            load_context_file(f)


class TestDetectCIContext:
    def test_github_actions(self) -> None:
        env = {
            "GITHUB_ACTIONS": "true",
            "GITHUB_EVENT_NAME": "pull_request",
            "GITHUB_BASE_REF": "main",
            "GITHUB_HEAD_REF": "feature",
        }
        with patch.dict("os.environ", env, clear=True):
            ctx = detect_ci_context()
        assert ctx is not None
        assert ctx.trigger == "pull_request"

    def test_gitlab_ci(self) -> None:
        env = {
            "GITLAB_CI": "true",
            "CI_PIPELINE_SOURCE": "merge_request_event",
        }
        with patch.dict("os.environ", env, clear=True):
            ctx = detect_ci_context()
        assert ctx is not None
        assert ctx.trigger == "merge_request_event"

    def test_azure_pipelines(self) -> None:
        env = {
            "TF_BUILD": "True",
            "BUILD_REASON": "PullRequest",
        }
        with patch.dict("os.environ", env, clear=True):
            ctx = detect_ci_context()
        assert ctx is not None
        assert ctx.trigger == "PullRequest"

    def test_jenkins(self) -> None:
        env = {
            "JENKINS_URL": "http://jenkins.local",
            "CHANGE_TARGET": "main",
        }
        with patch.dict("os.environ", env, clear=True):
            ctx = detect_ci_context()
        assert ctx is not None
        assert ctx.trigger == "pull_request"

    def test_circleci(self) -> None:
        env = {
            "CIRCLECI": "true",
            "CIRCLE_PULL_REQUEST": "https://github.com/org/repo/pull/1",
        }
        with patch.dict("os.environ", env, clear=True):
            ctx = detect_ci_context()
        assert ctx is not None
        assert ctx.trigger == "pull_request"

    def test_bitbucket(self) -> None:
        env = {
            "BITBUCKET_BUILD_NUMBER": "42",
            "BITBUCKET_PR_ID": "7",
        }
        with patch.dict("os.environ", env, clear=True):
            ctx = detect_ci_context()
        assert ctx is not None
        assert ctx.trigger == "pull_request"

    def test_buildkite(self) -> None:
        env = {
            "BUILDKITE": "true",
            "BUILDKITE_PULL_REQUEST": "123",
        }
        with patch.dict("os.environ", env, clear=True):
            ctx = detect_ci_context()
        assert ctx is not None
        assert ctx.trigger == "pull_request"

    def test_buildkite_push(self) -> None:
        env = {
            "BUILDKITE": "true",
            "BUILDKITE_PULL_REQUEST": "false",
        }
        with patch.dict("os.environ", env, clear=True):
            ctx = detect_ci_context()
        assert ctx is not None
        assert ctx.trigger == "push"

    def test_drone(self) -> None:
        env = {
            "DRONE": "true",
            "DRONE_BUILD_EVENT": "pull_request",
            "DRONE_TARGET_BRANCH": "main",
        }
        with patch.dict("os.environ", env, clear=True):
            ctx = detect_ci_context()
        assert ctx is not None
        assert ctx.trigger == "pull_request"

    def test_no_ci_returns_none(self) -> None:
        with patch.dict("os.environ", {}, clear=True):
            ctx = detect_ci_context()
        assert ctx is None


class TestResolveContext:
    def test_explicit_flags_override_all(self) -> None:
        ctx = resolve_context(
            changed_files_raw="a.py,b.py",
            trigger="push",
            actor="collaborator",
        )
        assert ctx is not None
        assert ctx.changed_files == ["a.py", "b.py"]
        assert ctx.trigger == "push"
        assert ctx.actor == "collaborator"

    def test_context_file_provides_base(self, tmp_path: Path) -> None:
        f = tmp_path / "ctx.yaml"
        f.write_text("trigger: pull_request\nactor: fork\n")
        ctx = resolve_context(context_file=f)
        assert ctx is not None
        assert ctx.trigger == "pull_request"
        assert ctx.actor == "fork"

    def test_flags_override_context_file(self, tmp_path: Path) -> None:
        f = tmp_path / "ctx.yaml"
        f.write_text("trigger: pull_request\nactor: fork\n")
        ctx = resolve_context(context_file=f, trigger="push")
        assert ctx is not None
        assert ctx.trigger == "push"
        assert ctx.actor == "fork"

    def test_mode_static_returns_none(self) -> None:
        ctx = resolve_context(
            changed_files_raw="a.py",
            trigger="push",
            mode="static",
        )
        assert ctx is None

    def test_mode_pr_without_context_errors(self) -> None:
        with (
            patch.dict("os.environ", {}, clear=True),
            pytest.raises(ContextError, match="--mode pr requires"),
        ):
            resolve_context(mode="pr")

    def test_mode_pr_with_context_succeeds(self) -> None:
        ctx = resolve_context(
            changed_files_raw="Dockerfile",
            mode="pr",
        )
        assert ctx is not None
        assert ctx.changed_files == ["Dockerfile"]

    def test_no_context_no_mode_returns_none(self) -> None:
        with patch.dict("os.environ", {}, clear=True):
            ctx = resolve_context()
        assert ctx is None

    def test_auto_detect_used_as_base(self) -> None:
        env = {
            "GITHUB_ACTIONS": "true",
            "GITHUB_EVENT_NAME": "pull_request",
        }
        with patch.dict("os.environ", env, clear=True):
            ctx = resolve_context()
        assert ctx is not None
        assert ctx.trigger == "pull_request"

    def test_flags_override_auto_detect(self) -> None:
        env = {
            "GITHUB_ACTIONS": "true",
            "GITHUB_EVENT_NAME": "pull_request",
        }
        with patch.dict("os.environ", env, clear=True):
            ctx = resolve_context(trigger="push")
        assert ctx is not None
        assert ctx.trigger == "push"
