from actionsieve.engine import Finding
from actionsieve.model import Job, Trigger, WorkflowModel, make_runner
from actionsieve.severity import apply_profile, compute_static, is_elevated, is_suppressed


def _finding(
    severity_base: str = "high",
    pattern_id: str = "test-pattern",
    tags: list[str] | None = None,
    job_id: str = "build",
    attacker_model: str = "fork_pr",
) -> Finding:
    return Finding(
        pattern_id=pattern_id,
        pattern_title="Test",
        file_path="test.yml",
        platform="github",
        line=1,
        job_id=job_id,
        step_index=0,
        severity_base=severity_base,
        attacker_model=attacker_model,
        impact="rce",
        tags=tags or [],
    )


def _model(
    triggers: list[Trigger] | None = None,
    jobs: list[Job] | None = None,
) -> WorkflowModel:
    return WorkflowModel(
        platform="github",
        file_path="test.yml",
        raw={},
        triggers=triggers or [],
        jobs=jobs or [Job(id="build", runner=make_runner("ubuntu-latest"))],
    )


class TestComputeStatic:
    def test_base_severity_unchanged_without_context(self) -> None:
        f = _finding(severity_base="high", attacker_model="contributor")
        m = _model()
        assert compute_static(f, m) == "high"

    def test_privileged_trigger_with_secrets_elevates(self) -> None:
        f = _finding(severity_base="high", attacker_model="contributor")
        m = _model(
            triggers=[Trigger(event="push", raw_event="push", is_privileged=True)],
            jobs=[
                Job(
                    id="build",
                    runner=make_runner("ubuntu-latest"),
                    secrets_referenced=["DEPLOY_KEY"],
                )
            ],
        )
        assert compute_static(f, m) == "critical"

    def test_self_hosted_with_fork_trigger_elevates(self) -> None:
        f = _finding(severity_base="medium")
        m = _model(
            triggers=[
                Trigger(event="push", raw_event="push", is_privileged=True),
                Trigger(
                    event="pull_request",
                    raw_event="pull_request",
                    is_fork_reachable=True,
                ),
            ],
            jobs=[Job(id="build", runner=make_runner(["self-hosted", "linux"]))],
        )
        assert compute_static(f, m) == "high"

    def test_self_hosted_without_fork_trigger_downgrades(self) -> None:
        f = _finding(severity_base="high")
        m = _model(
            triggers=[Trigger(event="push", raw_event="push", is_privileged=True)],
            jobs=[Job(id="build", runner=make_runner(["self-hosted", "linux"]))],
        )
        result = compute_static(f, m)
        assert result in ("low", "medium")

    def test_fork_pr_no_secrets_downgrades(self) -> None:
        f = _finding(severity_base="high")
        m = _model(
            triggers=[
                Trigger(
                    event="pull_request",
                    raw_event="pull_request",
                    is_fork_reachable=True,
                )
            ],
        )
        assert compute_static(f, m) == "medium"

    def test_severity_never_above_critical(self) -> None:
        f = _finding(severity_base="critical", attacker_model="contributor")
        m = _model(
            triggers=[Trigger(event="push", raw_event="push", is_privileged=True)],
            jobs=[
                Job(
                    id="build",
                    runner=make_runner(["self-hosted"]),
                    secrets_referenced=["KEY"],
                )
            ],
        )
        assert compute_static(f, m) == "critical"

    def test_severity_never_below_info(self) -> None:
        f = _finding(severity_base="info")
        m = _model(
            triggers=[
                Trigger(
                    event="pull_request",
                    raw_event="pull_request",
                    is_fork_reachable=True,
                )
            ],
        )
        assert compute_static(f, m) == "info"


class TestApplyProfile:
    def test_default_profile_unchanged(self) -> None:
        assert apply_profile("high", {}) == "high"

    def test_ephemeral_runners_downgrade(self) -> None:
        profile = {"runners": {"type": "ephemeral"}}
        assert apply_profile("high", profile) in ("medium", "high")

    def test_persistent_runners_upgrade(self) -> None:
        profile = {"runners": {"type": "persistent"}}
        result = apply_profile("medium", profile)
        assert result == "high"

    def test_restricted_network_downgrade(self) -> None:
        profile = {"runners": {"network": "restricted"}}
        result = apply_profile("high", profile)
        assert result == "medium"

    def test_disabled_forks_downgrade(self) -> None:
        profile = {"forks": {"policy": "disabled"}}
        result = apply_profile("high", profile)
        assert result == "medium"

    def test_oidc_secrets_downgrade(self) -> None:
        profile = {"secrets": {"backend": "oidc"}}
        result = apply_profile("high", profile)
        assert result == "medium"

    def test_auto_rotation_downgrade(self) -> None:
        profile = {"secrets": {"rotation": "automatic"}}
        result = apply_profile("high", profile)
        assert result == "medium"

    def test_hardened_profile_significant_downgrade(self) -> None:
        from actionsieve.profiles import BUILTIN_PROFILES

        hardened = BUILTIN_PROFILES["hardened"]
        result = apply_profile("high", hardened)
        assert result in ("info", "low", "medium")

    def test_severity_clamped_at_info(self) -> None:
        profile = {
            "runners": {"network": "restricted"},
            "forks": {"policy": "disabled"},
            "secrets": {"backend": "oidc", "rotation": "automatic"},
        }
        result = apply_profile("low", profile)
        assert result == "info"


class TestSuppression:
    def test_suppressed_by_tag(self) -> None:
        f = _finding(tags=["self-hosted", "persistence"])
        profile = {"suppress": ["self-hosted"]}
        assert is_suppressed(f, profile) is True

    def test_suppressed_by_pattern_id_prefix(self) -> None:
        f = _finding(pattern_id="self-hosted-runner-persistence")
        profile = {"suppress": ["self-hosted"]}
        assert is_suppressed(f, profile) is True

    def test_not_suppressed_when_no_match(self) -> None:
        f = _finding(tags=["injection"])
        profile = {"suppress": ["self-hosted"]}
        assert is_suppressed(f, profile) is False

    def test_not_suppressed_empty_profile(self) -> None:
        f = _finding()
        assert is_suppressed(f, {}) is False


class TestElevation:
    def test_elevated_by_tag(self) -> None:
        f = _finding(tags=["secret-exposure"])
        profile = {"elevate": ["secret-exposure"]}
        assert is_elevated(f, profile) is True

    def test_not_elevated_when_no_match(self) -> None:
        f = _finding(tags=["injection"])
        profile = {"elevate": ["secret-exposure"]}
        assert is_elevated(f, profile) is False
