from actionsieve.model import (
    ComponentRef,
    Expression,
    Job,
    Permissions,
    Step,
    Trigger,
    WorkflowModel,
    make_runner,
)


class TestMakeRunner:
    def test_managed_ubuntu(self) -> None:
        runner = make_runner("ubuntu-latest")
        assert runner.is_managed is True
        assert runner.is_self_hosted is False
        assert runner.labels == ["ubuntu-latest"]
        assert runner.raw == "ubuntu-latest"

    def test_managed_windows(self) -> None:
        runner = make_runner("windows-2022")
        assert runner.is_managed is True
        assert runner.is_self_hosted is False

    def test_managed_macos(self) -> None:
        runner = make_runner("macos-latest")
        assert runner.is_managed is True

    def test_self_hosted_string(self) -> None:
        runner = make_runner("self-hosted")
        assert runner.is_self_hosted is True
        assert runner.is_managed is False

    def test_self_hosted_list(self) -> None:
        runner = make_runner(["self-hosted", "linux", "x64"])
        assert runner.is_self_hosted is True
        assert runner.is_managed is False
        assert runner.labels == ["self-hosted", "linux", "x64"]

    def test_custom_label_not_managed(self) -> None:
        runner = make_runner("my-custom-runner")
        assert runner.is_managed is False
        assert runner.is_self_hosted is False

    def test_case_insensitive_self_hosted(self) -> None:
        runner = make_runner(["Self-Hosted", "Linux"])
        assert runner.is_self_hosted is True

    def test_self_hosted_overrides_managed(self) -> None:
        runner = make_runner(["self-hosted", "ubuntu-latest"])
        assert runner.is_self_hosted is True
        assert runner.is_managed is False


class TestTrigger:
    def test_privileged_trigger(self) -> None:
        trigger = Trigger(
            event="pull_request",
            raw_event="pull_request_target",
            is_privileged=True,
            is_fork_reachable=True,
        )
        assert trigger.is_privileged is True
        assert trigger.is_fork_reachable is True

    def test_safe_push_trigger(self) -> None:
        trigger = Trigger(event="push", raw_event="push")
        assert trigger.is_privileged is False
        assert trigger.is_fork_reachable is False

    def test_trigger_with_filters(self) -> None:
        trigger = Trigger(
            event="pull_request",
            raw_event="pull_request",
            filters={"paths": [".github/workflows/**"]},
            is_fork_reachable=True,
        )
        assert trigger.filters["paths"] == [".github/workflows/**"]


class TestPermissions:
    def test_explicit_permissions(self) -> None:
        perms = Permissions(
            contents="read",
            issues="write",
            raw={"contents": "read", "issues": "write"},
        )
        assert perms.contents == "read"
        assert perms.issues == "write"
        assert perms.pull_requests is None

    def test_empty_permissions(self) -> None:
        perms = Permissions()
        assert perms.contents is None
        assert perms.raw == {}


class TestStep:
    def test_shell_step(self) -> None:
        step = Step(
            index=0,
            type="shell",
            name="Run tests",
            shell_command="pytest",
        )
        assert step.type == "shell"
        assert step.action_ref is None
        assert step.inputs == {}

    def test_action_step(self) -> None:
        ref = ComponentRef(
            raw="actions/checkout@v4",
            owner="actions",
            name="checkout",
            ref="v4",
            ref_type="tag",
            is_pinned=False,
            is_first_party=True,
            line=10,
        )
        step = Step(
            index=0,
            type="action",
            action_ref=ref,
            inputs={"fetch-depth": "0"},
        )
        assert step.type == "action"
        assert step.action_ref is not None
        assert step.action_ref.owner == "actions"

    def test_step_with_expressions(self) -> None:
        expr = Expression(
            raw="${{ github.event.pull_request.title }}",
            context_path="github.event.pull_request.title",
            location="run",
            is_in_shell=True,
            is_tainted=True,
            line=15,
        )
        step = Step(
            index=0,
            type="shell",
            shell_command='echo "${{ github.event.pull_request.title }}"',
            expressions=[expr],
        )
        assert len(step.expressions) == 1
        assert step.expressions[0].is_tainted is True


class TestComponentRef:
    def test_pinned_sha(self) -> None:
        ref = ComponentRef(
            raw="actions/checkout@abc123def456",
            owner="actions",
            name="checkout",
            ref="abc123def456",
            ref_type="sha",
            is_pinned=True,
            is_first_party=True,
            line=5,
        )
        assert ref.is_pinned is True
        assert ref.resolved_sha is None

    def test_unpinned_tag(self) -> None:
        ref = ComponentRef(
            raw="some-org/action@v2",
            owner="some-org",
            name="action",
            ref="v2",
            ref_type="tag",
            is_pinned=False,
            is_first_party=False,
            line=12,
        )
        assert ref.is_pinned is False

    def test_resolved_sha(self) -> None:
        ref = ComponentRef(
            raw="some-org/action@v2",
            owner="some-org",
            name="action",
            ref="v2",
            ref_type="tag",
            is_pinned=False,
            is_first_party=False,
            line=12,
            resolved_sha="abc123",
        )
        assert ref.resolved_sha == "abc123"


class TestExpression:
    def test_tainted_expression(self) -> None:
        expr = Expression(
            raw="${{ github.event.pull_request.title }}",
            context_path="github.event.pull_request.title",
            location="run",
            is_in_shell=True,
            is_tainted=True,
            line=10,
        )
        assert expr.is_tainted is True
        assert expr.is_in_shell is True

    def test_safe_expression(self) -> None:
        expr = Expression(
            raw="${{ github.sha }}",
            context_path="github.sha",
            location="env",
            is_in_shell=False,
            is_tainted=False,
            line=5,
        )
        assert expr.is_tainted is False
        assert expr.is_in_shell is False


class TestJob:
    def test_job_with_needs(self) -> None:
        job = Job(
            id="deploy",
            runner=make_runner("ubuntu-latest"),
            needs=["build", "test"],
        )
        assert job.needs == ["build", "test"]
        assert job.steps == []
        assert job.secrets_referenced == []

    def test_job_with_outputs(self) -> None:
        job = Job(
            id="build",
            runner=make_runner("ubuntu-latest"),
            outputs={"version": "${{ steps.ver.outputs.version }}"},
        )
        assert "version" in job.outputs


class TestWorkflowModel:
    def test_minimal_workflow(self) -> None:
        wf = WorkflowModel(
            platform="github",
            file_path=".github/workflows/ci.yml",
            raw={"on": "push"},
        )
        assert wf.platform == "github"
        assert wf.triggers == []
        assert wf.jobs == []
        assert wf.permissions is None

    def test_full_workflow(self) -> None:
        trigger = Trigger(
            event="pull_request",
            raw_event="pull_request",
            is_fork_reachable=True,
        )
        perms = Permissions(contents="read", raw={"contents": "read"})
        step = Step(index=0, type="shell", shell_command="echo hello")
        job = Job(
            id="build",
            runner=make_runner("ubuntu-latest"),
            steps=[step],
        )
        wf = WorkflowModel(
            platform="github",
            file_path=".github/workflows/ci.yml",
            raw={"on": "pull_request"},
            triggers=[trigger],
            permissions=perms,
            env={"CI": "true"},
            jobs=[job],
        )
        assert len(wf.triggers) == 1
        assert len(wf.jobs) == 1
        assert wf.env["CI"] == "true"
        assert wf.jobs[0].steps[0].shell_command == "echo hello"
