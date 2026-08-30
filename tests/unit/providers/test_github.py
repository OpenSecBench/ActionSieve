from pathlib import Path

import pytest

from actionsieve.providers import ParseError, auto_detect, get_provider
from actionsieve.providers.github import GitHubProvider

FIXTURES = Path(__file__).parent.parent.parent / "fixtures" / "github"
VULN = FIXTURES / "vulnerable" / ".github" / "workflows"
SAFE = FIXTURES / "safe" / ".github" / "workflows"


@pytest.fixture
def provider() -> GitHubProvider:
    return GitHubProvider()


class TestDetect:
    def test_detects_github_repo(self, provider: GitHubProvider, tmp_path: Path) -> None:
        (tmp_path / ".github" / "workflows").mkdir(parents=True)
        assert provider.detect(tmp_path) is True

    def test_rejects_non_github_repo(self, provider: GitHubProvider, tmp_path: Path) -> None:
        assert provider.detect(tmp_path) is False

    def test_auto_detect_finds_github(self, tmp_path: Path) -> None:
        (tmp_path / ".github" / "workflows").mkdir(parents=True)
        providers = auto_detect(tmp_path)
        assert len(providers) == 1
        assert providers[0].name == "github"

    def test_auto_detect_empty(self, tmp_path: Path) -> None:
        assert auto_detect(tmp_path) == []

    def test_get_provider_github(self) -> None:
        p = get_provider("github")
        assert p.name == "github"

    def test_get_provider_unknown(self) -> None:
        with pytest.raises(ValueError, match="Unknown provider"):
            get_provider("nonexistent")


class TestFindFiles:
    def test_finds_yml_files(self, provider: GitHubProvider, tmp_path: Path) -> None:
        wf_dir = tmp_path / ".github" / "workflows"
        wf_dir.mkdir(parents=True)
        (wf_dir / "ci.yml").write_text("on: push")
        (wf_dir / "deploy.yaml").write_text("on: push")
        (wf_dir / "notes.txt").write_text("not a workflow")

        files = provider.find_files(tmp_path)
        names = [f.name for f in files]
        assert "ci.yml" in names
        assert "deploy.yaml" in names
        assert "notes.txt" not in names

    def test_empty_when_no_dir(self, provider: GitHubProvider, tmp_path: Path) -> None:
        assert provider.find_files(tmp_path) == []


class TestParseExpressionInjection:
    def test_parses_vulnerable_workflow(self, provider: GitHubProvider) -> None:
        wf = provider.parse(VULN / "expression-injection.yml")
        assert wf.platform == "github"
        assert len(wf.triggers) == 1
        assert wf.triggers[0].event == "pull_request"
        assert wf.triggers[0].is_fork_reachable is True
        assert len(wf.jobs) == 1

        job = wf.jobs[0]
        assert job.id == "greet"
        assert job.runner.is_managed is True

        step = job.steps[0]
        assert step.type == "shell"
        assert step.shell_command is not None
        assert "github.event.pull_request.title" in step.shell_command

        tainted = [e for e in step.expressions if e.is_tainted]
        assert len(tainted) >= 1
        assert any("pull_request.title" in e.context_path for e in tainted)

    def test_safe_env_indirection(self, provider: GitHubProvider) -> None:
        wf = provider.parse(SAFE / "env-indirection.yml")
        step = wf.jobs[0].steps[0]

        shell_tainted = [e for e in step.expressions if e.is_tainted and e.is_in_shell]
        assert len(shell_tainted) == 0


class TestParsePwnRequest:
    def test_parses_privileged_trigger(self, provider: GitHubProvider) -> None:
        wf = provider.parse(VULN / "pwn-request.yml")
        trigger = wf.triggers[0]
        assert trigger.raw_event == "pull_request_target"
        assert trigger.event == "pull_request"
        assert trigger.is_privileged is True
        assert trigger.is_fork_reachable is True

    def test_permissions_parsed(self, provider: GitHubProvider) -> None:
        wf = provider.parse(VULN / "pwn-request.yml")
        assert wf.permissions is not None
        assert wf.permissions.contents == "write"

    def test_checkout_head_ref(self, provider: GitHubProvider) -> None:
        wf = provider.parse(VULN / "pwn-request.yml")
        checkout_step = wf.jobs[0].steps[0]
        assert checkout_step.type == "action"
        assert checkout_step.action_ref is not None
        assert checkout_step.action_ref.name == "checkout"
        assert "head.sha" in checkout_step.inputs.get("ref", "")

    def test_secrets_detected(self, provider: GitHubProvider) -> None:
        wf = provider.parse(VULN / "pwn-request.yml")
        job = wf.jobs[0]
        assert "DEPLOY_TOKEN" in job.secrets_referenced


class TestParseUnpinnedActions:
    def test_pinned_vs_unpinned(self, provider: GitHubProvider) -> None:
        wf = provider.parse(VULN / "unpinned-actions.yml")
        steps = wf.jobs[0].steps
        refs = [s.action_ref for s in steps if s.action_ref is not None]

        checkout = refs[0]
        assert checkout.owner == "actions"
        assert checkout.is_first_party is True
        assert checkout.ref_type == "tag"
        assert checkout.is_pinned is False

        branch_ref = refs[1]
        assert branch_ref.ref == "main"
        assert branch_ref.ref_type == "branch"
        assert branch_ref.is_pinned is False

    def test_pinned_sha_actions(self, provider: GitHubProvider) -> None:
        wf = provider.parse(SAFE / "pinned-actions.yml")
        steps = wf.jobs[0].steps
        refs = [s.action_ref for s in steps if s.action_ref is not None]
        assert all(r.is_pinned for r in refs)
        assert all(r.ref_type == "sha" for r in refs)


class TestParseSelfHosted:
    def test_self_hosted_runner(self, provider: GitHubProvider) -> None:
        wf = provider.parse(VULN / "self-hosted-secrets.yml")
        job = wf.jobs[0]
        assert job.runner.is_self_hosted is True
        assert job.runner.is_managed is False
        assert "AWS_SECRET_KEY" in job.secrets_referenced


class TestParseTriggers:
    def test_string_trigger(self, provider: GitHubProvider, tmp_path: Path) -> None:
        wf_file = tmp_path / "test.yml"
        wf_file.write_text(
            "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
        )
        wf = provider.parse(wf_file)
        assert len(wf.triggers) == 1
        assert wf.triggers[0].event == "push"

    def test_list_trigger(self, provider: GitHubProvider, tmp_path: Path) -> None:
        wf_file = tmp_path / "test.yml"
        wf_file.write_text(
            "on: [push, pull_request]\njobs:\n  a:\n"
            "    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
        )
        wf = provider.parse(wf_file)
        assert len(wf.triggers) == 2
        events = {t.event for t in wf.triggers}
        assert events == {"push", "pull_request"}

    def test_map_trigger_with_filters(self, provider: GitHubProvider, tmp_path: Path) -> None:
        content = """
on:
  push:
    branches: [main]
  pull_request:
    paths: [".github/**"]
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
"""
        wf_file = tmp_path / "test.yml"
        wf_file.write_text(content)
        wf = provider.parse(wf_file)
        assert len(wf.triggers) == 2
        push_trigger = next(t for t in wf.triggers if t.event == "push")
        assert push_trigger.filters.get("branches") == ["main"]


class TestParseEdgeCases:
    def test_malformed_yaml(self, provider: GitHubProvider, tmp_path: Path) -> None:
        wf_file = tmp_path / "bad.yml"
        wf_file.write_text("{{invalid yaml")
        with pytest.raises(ParseError):
            provider.parse(wf_file)

    def test_non_mapping_yaml(self, provider: GitHubProvider, tmp_path: Path) -> None:
        wf_file = tmp_path / "list.yml"
        wf_file.write_text("- item1\n- item2\n")
        with pytest.raises(ParseError, match="Expected mapping"):
            provider.parse(wf_file)

    def test_file_size_limit(self, provider: GitHubProvider, tmp_path: Path) -> None:
        wf_file = tmp_path / "huge.yml"
        wf_file.write_text("x" * (1_048_577))
        with pytest.raises(ParseError, match="exceeds"):
            provider.parse(wf_file)

    def test_empty_jobs(self, provider: GitHubProvider, tmp_path: Path) -> None:
        wf_file = tmp_path / "nojobs.yml"
        wf_file.write_text("on: push\n")
        wf = provider.parse(wf_file)
        assert wf.jobs == []

    def test_step_with_id(self, provider: GitHubProvider, tmp_path: Path) -> None:
        content = """
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - id: get-version
        run: echo "version=1.0" >> "$GITHUB_OUTPUT"
"""
        wf_file = tmp_path / "test.yml"
        wf_file.write_text(content)
        wf = provider.parse(wf_file)
        step = wf.jobs[0].steps[0]
        assert step.id == "get-version"
        assert "version" in step.outputs_written

    def test_job_conditions(self, provider: GitHubProvider, tmp_path: Path) -> None:
        content = """
on: push
jobs:
  deploy:
    if: github.ref == 'refs/heads/main'
    runs-on: ubuntu-latest
    steps:
      - run: echo deploy
"""
        wf_file = tmp_path / "test.yml"
        wf_file.write_text(content)
        wf = provider.parse(wf_file)
        assert len(wf.jobs[0].conditions) == 1

    def test_job_needs(self, provider: GitHubProvider, tmp_path: Path) -> None:
        content = """
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo build
  deploy:
    needs: build
    runs-on: ubuntu-latest
    steps:
      - run: echo deploy
"""
        wf_file = tmp_path / "test.yml"
        wf_file.write_text(content)
        wf = provider.parse(wf_file)
        deploy = next(j for j in wf.jobs if j.id == "deploy")
        assert deploy.needs == ["build"]


class TestExpressionSyntax:
    def test_github_syntax(self, provider: GitHubProvider) -> None:
        syntax = provider.expression_syntax()
        assert syntax.delimiters == ("${{", "}}")
        assert "github" in syntax.context_roots
        assert "github.event" in syntax.tainted_roots
        assert "env" in syntax.safe_indirection


class TestSearchQuery:
    def test_generates_query(self, provider: GitHubProvider) -> None:
        pattern = {
            "detection": {
                "grep_patterns": ["github.event.pull_request.title"],
            },
        }
        query = provider.search_query(pattern)
        assert query is not None
        assert "github.event.pull_request.title" in query
        assert "language:yaml" in query
        assert "path:.github/workflows" in query

    def test_no_query_without_grep(self, provider: GitHubProvider) -> None:
        pattern = {"detection": {"type": "structural"}}
        assert provider.search_query(pattern) is None
