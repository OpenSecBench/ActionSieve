from pathlib import Path

import pytest

from actionsieve.providers import ParseError
from actionsieve.providers.azure import AzureProvider


@pytest.fixture
def provider() -> AzureProvider:
    return AzureProvider()


def _write_pipeline(tmp_path: Path, content: str) -> Path:
    p = tmp_path / "azure-pipelines.yml"
    p.write_text(content)
    return p


class TestDetect:
    def test_detects_azure_repo(self, provider: AzureProvider, tmp_path: Path) -> None:
        (tmp_path / "azure-pipelines.yml").write_text("trigger: none")
        assert provider.detect(tmp_path) is True

    def test_detects_yaml_extension(self, provider: AzureProvider, tmp_path: Path) -> None:
        (tmp_path / "azure-pipelines.yaml").write_text("trigger: none")
        assert provider.detect(tmp_path) is True

    def test_rejects_non_azure_repo(self, provider: AzureProvider, tmp_path: Path) -> None:
        assert provider.detect(tmp_path) is False


class TestFindFiles:
    def test_finds_pipeline_file(self, provider: AzureProvider, tmp_path: Path) -> None:
        (tmp_path / "azure-pipelines.yml").write_text("trigger: none")
        files = provider.find_files(tmp_path)
        assert len(files) == 1

    def test_empty_when_no_file(self, provider: AzureProvider, tmp_path: Path) -> None:
        assert provider.find_files(tmp_path) == []


class TestParseSimple:
    def test_simple_steps_pipeline(self, provider: AzureProvider, tmp_path: Path) -> None:
        p = _write_pipeline(
            tmp_path,
            """\
trigger:
  - main

steps:
  - script: npm install
    displayName: Install
  - script: npm test
    displayName: Test
""",
        )
        wf = provider.parse(p)
        assert wf.platform == "azure"
        assert len(wf.jobs) == 1
        assert len(wf.jobs[0].steps) == 2
        assert wf.jobs[0].steps[0].shell_command == "npm install"
        assert wf.jobs[0].steps[0].name == "Install"

    def test_stages_pipeline(self, provider: AzureProvider, tmp_path: Path) -> None:
        p = _write_pipeline(
            tmp_path,
            """\
trigger:
  - main

stages:
  - stage: Build
    jobs:
      - job: BuildJob
        pool:
          vmImage: ubuntu-latest
        steps:
          - script: npm install
          - script: npm run build
""",
        )
        wf = provider.parse(p)
        assert len(wf.jobs) == 1
        assert wf.jobs[0].steps[0].shell_command == "npm install"

    def test_jobs_pipeline(self, provider: AzureProvider, tmp_path: Path) -> None:
        p = _write_pipeline(
            tmp_path,
            """\
trigger:
  - main

jobs:
  - job: Build
    pool:
      vmImage: ubuntu-latest
    steps:
      - script: echo build
  - job: Test
    dependsOn: Build
    pool:
      vmImage: ubuntu-latest
    steps:
      - script: echo test
""",
        )
        wf = provider.parse(p)
        assert len(wf.jobs) == 2
        test_job = next(j for j in wf.jobs if "Test" in j.id)
        assert test_job.needs == ["Build"]


class TestPoolParsing:
    def test_toplevel_pool_used_for_inline_steps(
        self, provider: AzureProvider, tmp_path: Path
    ) -> None:
        p = _write_pipeline(
            tmp_path,
            """\
pool:
  name: self-hosted

steps:
  - script: echo hello
""",
        )
        wf = provider.parse(p)
        runner = wf.jobs[0].runner
        assert runner.is_self_hosted is True
        assert "self-hosted" in runner.labels

    def test_toplevel_pool_string_form(self, provider: AzureProvider, tmp_path: Path) -> None:
        p = _write_pipeline(
            tmp_path,
            """\
pool: my-pool

steps:
  - script: echo hello
""",
        )
        wf = provider.parse(p)
        assert "my-pool" in wf.jobs[0].runner.labels

    def test_toplevel_pool_vmimage(self, provider: AzureProvider, tmp_path: Path) -> None:
        p = _write_pipeline(
            tmp_path,
            """\
pool:
  vmImage: ubuntu-latest

steps:
  - script: echo hello
""",
        )
        wf = provider.parse(p)
        runner = wf.jobs[0].runner
        assert runner.is_self_hosted is False
        assert runner.is_managed is True

    def test_no_pool_defaults(self, provider: AzureProvider, tmp_path: Path) -> None:
        p = _write_pipeline(
            tmp_path,
            """\
steps:
  - script: echo hello
""",
        )
        wf = provider.parse(p)
        assert "default" in wf.jobs[0].runner.labels


class TestParseTriggers:
    def test_branch_list_trigger(self, provider: AzureProvider, tmp_path: Path) -> None:
        p = _write_pipeline(
            tmp_path,
            """\
trigger:
  - main
  - develop
steps:
  - script: echo hi
""",
        )
        wf = provider.parse(p)
        push = next(t for t in wf.triggers if t.event == "push")
        assert push.is_privileged is True

    def test_pr_trigger(self, provider: AzureProvider, tmp_path: Path) -> None:
        p = _write_pipeline(
            tmp_path,
            """\
pr:
  - main
steps:
  - script: echo hi
""",
        )
        wf = provider.parse(p)
        pr = next(t for t in wf.triggers if t.event == "pr")
        assert pr.is_fork_reachable is True

    def test_trigger_none(self, provider: AzureProvider, tmp_path: Path) -> None:
        p = _write_pipeline(
            tmp_path,
            """\
trigger: none
pr: none
steps:
  - script: echo hi
""",
        )
        wf = provider.parse(p)
        events = {t.event for t in wf.triggers}
        assert "push" in events

    def test_schedule_trigger(self, provider: AzureProvider, tmp_path: Path) -> None:
        p = _write_pipeline(
            tmp_path,
            """\
schedules:
  - cron: "0 0 * * *"
    branches:
      include:
        - main
steps:
  - script: echo scheduled
""",
        )
        wf = provider.parse(p)
        sched = next((t for t in wf.triggers if t.event == "schedule"), None)
        assert sched is not None
        assert sched.is_privileged is True


class TestParseVariables:
    def test_dict_variables(self, provider: AzureProvider, tmp_path: Path) -> None:
        p = _write_pipeline(
            tmp_path,
            """\
variables:
  buildConfiguration: Release
steps:
  - script: echo $(buildConfiguration)
""",
        )
        wf = provider.parse(p)
        assert wf.env.get("buildConfiguration") == "Release"

    def test_list_variables(self, provider: AzureProvider, tmp_path: Path) -> None:
        p = _write_pipeline(
            tmp_path,
            """\
variables:
  - name: buildConfiguration
    value: Release
steps:
  - script: echo $(buildConfiguration)
""",
        )
        wf = provider.parse(p)
        assert wf.env.get("buildConfiguration") == "Release"


class TestParseExpressions:
    def test_macro_expression(self, provider: AzureProvider, tmp_path: Path) -> None:
        p = _write_pipeline(
            tmp_path,
            """\
steps:
  - script: echo $(Build.SourceBranchName)
""",
        )
        wf = provider.parse(p)
        step = wf.jobs[0].steps[0]
        tainted = [e for e in step.expressions if e.is_tainted]
        assert len(tainted) >= 1

    def test_safe_variable_not_tainted(self, provider: AzureProvider, tmp_path: Path) -> None:
        p = _write_pipeline(
            tmp_path,
            """\
steps:
  - script: echo $(Build.BuildId)
""",
        )
        wf = provider.parse(p)
        step = wf.jobs[0].steps[0]
        tainted = [e for e in step.expressions if e.is_tainted]
        assert len(tainted) == 0

    def test_template_expression(self, provider: AzureProvider, tmp_path: Path) -> None:
        p = _write_pipeline(
            tmp_path,
            """\
steps:
  - script: echo ${{ variables.myVar }}
""",
        )
        wf = provider.parse(p)
        step = wf.jobs[0].steps[0]
        template_exprs = [e for e in step.expressions if e.location == "template"]
        assert len(template_exprs) >= 1


class TestParseStepTypes:
    def test_bash_step(self, provider: AzureProvider, tmp_path: Path) -> None:
        p = _write_pipeline(
            tmp_path,
            """\
steps:
  - bash: echo "hello from bash"
""",
        )
        wf = provider.parse(p)
        assert wf.jobs[0].steps[0].shell_command == 'echo "hello from bash"'

    def test_powershell_step(self, provider: AzureProvider, tmp_path: Path) -> None:
        p = _write_pipeline(
            tmp_path,
            """\
steps:
  - powershell: Write-Host "hello"
""",
        )
        wf = provider.parse(p)
        assert wf.jobs[0].steps[0].type == "shell"

    def test_task_step(self, provider: AzureProvider, tmp_path: Path) -> None:
        p = _write_pipeline(
            tmp_path,
            """\
steps:
  - task: DotNetCoreCLI@2
    inputs:
      command: build
""",
        )
        wf = provider.parse(p)
        step = wf.jobs[0].steps[0]
        assert step.type == "action"
        assert step.action_ref is not None
        assert step.action_ref.name == "DotNetCoreCLI"
        assert step.action_ref.ref == "2"
        assert step.inputs.get("command") == "build"

    def test_checkout_step(self, provider: AzureProvider, tmp_path: Path) -> None:
        p = _write_pipeline(
            tmp_path,
            """\
steps:
  - checkout: self
""",
        )
        wf = provider.parse(p)
        step = wf.jobs[0].steps[0]
        assert step.type == "action"
        assert step.action_ref is not None
        assert step.action_ref.name == "checkout"


class TestParseDeployment:
    def test_deployment_job(self, provider: AzureProvider, tmp_path: Path) -> None:
        p = _write_pipeline(
            tmp_path,
            """\
stages:
  - stage: Deploy
    jobs:
      - deployment: DeployWeb
        pool:
          vmImage: ubuntu-latest
        steps:
          - script: echo deploying
""",
        )
        wf = provider.parse(p)
        assert len(wf.jobs) == 1
        assert wf.jobs[0].steps[0].shell_command == "echo deploying"


class TestJobId:
    def test_job_id_uses_identifier_not_display_name(
        self, provider: AzureProvider, tmp_path: Path
    ) -> None:
        p = _write_pipeline(
            tmp_path,
            """\
jobs:
  - job: BuildJob
    displayName: Build the project
    pool:
      vmImage: ubuntu-latest
    steps:
      - script: echo build
""",
        )
        wf = provider.parse(p)
        assert wf.jobs[0].id == "BuildJob"
        assert wf.jobs[0].name == "Build the project"

    def test_inline_job_entry_parses_steps(self, provider: AzureProvider, tmp_path: Path) -> None:
        p = _write_pipeline(
            tmp_path,
            """\
stages:
  - stage: Build
    jobs:
      - InlineJob:
          steps:
            - script: echo inline
""",
        )
        wf = provider.parse(p)
        assert len(wf.jobs) == 1
        assert wf.jobs[0].id == "InlineJob"
        assert len(wf.jobs[0].steps) == 1
        assert wf.jobs[0].steps[0].shell_command == "echo inline"


class TestEdgeCases:
    def test_malformed_yaml(self, provider: AzureProvider, tmp_path: Path) -> None:
        p = _write_pipeline(tmp_path, "{{invalid")
        with pytest.raises(ParseError):
            provider.parse(p)

    def test_non_mapping(self, provider: AzureProvider, tmp_path: Path) -> None:
        p = _write_pipeline(tmp_path, "- item1\n")
        with pytest.raises(ParseError, match="Expected mapping"):
            provider.parse(p)

    def test_file_size_limit(self, provider: AzureProvider, tmp_path: Path) -> None:
        p = _write_pipeline(tmp_path, "x" * (1_048_577))
        with pytest.raises(ParseError, match="exceeds"):
            provider.parse(p)

    def test_expression_syntax(self, provider: AzureProvider) -> None:
        syntax = provider.expression_syntax()
        assert syntax.delimiters == ("$(", ")")
        assert "Build" in syntax.context_roots

    def test_empty_pipeline(self, provider: AzureProvider, tmp_path: Path) -> None:
        p = _write_pipeline(tmp_path, "trigger: none\n")
        wf = provider.parse(p)
        assert wf.jobs == []
