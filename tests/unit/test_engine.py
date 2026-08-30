from pathlib import Path

from actionsieve.engine import Finding, match
from actionsieve.patterns import load_patterns
from actionsieve.providers.github import GitHubProvider

FIXTURES = Path(__file__).parent.parent / "fixtures" / "github"


def _scan(fixture: str, platform: str = "github") -> list[Finding]:
    provider = GitHubProvider()
    model = provider.parse(FIXTURES / fixture)
    patterns = load_patterns(platform=platform)
    return match(model, patterns)


class TestExpressionInjection:
    def test_detects_pr_title_in_run(self) -> None:
        findings = _scan("vulnerable/.github/workflows/expression-injection.yml")
        expr_findings = [f for f in findings if f.pattern_id == "expr-injection-run"]
        assert len(expr_findings) >= 1
        assert any("pull_request.title" in e for f in expr_findings for e in f.evidence)

    def test_safe_env_indirection_not_flagged(self) -> None:
        findings = _scan("safe/.github/workflows/env-indirection.yml")
        expr_findings = [f for f in findings if f.pattern_id == "expr-injection-run"]
        assert len(expr_findings) == 0

    def test_run_block_does_not_trigger_github_script(self) -> None:
        findings = _scan("vulnerable/.github/workflows/expression-injection.yml")
        script_findings = [f for f in findings if f.pattern_id == "expr-injection-github-script"]
        assert len(script_findings) == 0


class TestPwnRequest:
    def test_detects_prt_checkout_head(self) -> None:
        findings = _scan("vulnerable/.github/workflows/pwn-request.yml")
        prt_findings = [f for f in findings if f.pattern_id == "prt-checkout-head"]
        assert len(prt_findings) >= 1
        assert prt_findings[0].severity_base == "critical"

    def test_safe_base_checkout_not_flagged(self) -> None:
        findings = _scan("safe/.github/workflows/base-checkout.yml")
        prt_findings = [f for f in findings if f.pattern_id == "prt-checkout-head"]
        assert len(prt_findings) == 0


class TestSupplyChain:
    def test_detects_unpinned_third_party(self) -> None:
        findings = _scan("vulnerable/.github/workflows/unpinned-actions.yml")
        sc_findings = [f for f in findings if f.pattern_id == "mutable-action-ref"]
        assert len(sc_findings) >= 1
        unpinned_refs = [f for f in sc_findings if "unpinned" in " ".join(f.evidence)]
        assert len(unpinned_refs) >= 1

    def test_pinned_actions_not_flagged(self) -> None:
        findings = _scan("safe/.github/workflows/pinned-actions.yml")
        sc_findings = [f for f in findings if f.pattern_id == "mutable-action-ref"]
        assert len(sc_findings) == 0

    def test_detects_unpinned_reusable_workflow(self) -> None:
        findings = _scan("vulnerable/.github/workflows/reusable-workflow-unpinned.yml")
        sc_findings = [f for f in findings if f.pattern_id == "mutable-action-ref"]
        assert len(sc_findings) >= 1
        refs = [" ".join(f.evidence) for f in sc_findings]
        assert any("shared-workflows" in r for r in refs)


class TestTruncatedSha:
    def test_detects_truncated_sha(self) -> None:
        findings = _scan("vulnerable/.github/workflows/truncated-sha.yml")
        hits = [f for f in findings if f.pattern_id == "truncated-sha-pin"]
        assert len(hits) == 2
        evidence = " ".join(e for f in hits for e in f.evidence)
        assert "abc1234" in evidence
        assert "7-char hex" in evidence or "38-char hex" in evidence

    def test_full_sha_not_flagged(self) -> None:
        findings = _scan("safe/.github/workflows/pinned-actions.yml")
        hits = [f for f in findings if f.pattern_id == "truncated-sha-pin"]
        assert len(hits) == 0


class TestSelfHosted:
    def test_detects_self_hosted(self) -> None:
        findings = _scan("vulnerable/.github/workflows/self-hosted-secrets.yml")
        sh_findings = [f for f in findings if f.pattern_id == "self-hosted-runner-persistence"]
        assert len(sh_findings) >= 1

    def test_managed_runner_not_flagged(self) -> None:
        findings = _scan("safe/.github/workflows/minimal-permissions.yml")
        sh_findings = [f for f in findings if f.pattern_id == "self-hosted-runner-persistence"]
        assert len(sh_findings) == 0


class TestGithubScriptInjection:
    def test_detects_tainted_expr_in_script(self) -> None:
        findings = _scan("vulnerable/.github/workflows/github-script-injection.yml")
        script_findings = [f for f in findings if f.pattern_id == "expr-injection-github-script"]
        assert len(script_findings) >= 1

    def test_safe_env_indirection_not_flagged(self) -> None:
        findings = _scan("safe/.github/workflows/github-script-env.yml")
        script_findings = [f for f in findings if f.pattern_id == "expr-injection-github-script"]
        assert len(script_findings) == 0


class TestDispatchInjection:
    def test_detects_input_in_run(self) -> None:
        findings = _scan("vulnerable/.github/workflows/dispatch-injection.yml")
        dispatch_findings = [f for f in findings if f.pattern_id == "dispatch-input-injection"]
        assert len(dispatch_findings) >= 1

    def test_safe_env_indirection_not_flagged(self) -> None:
        findings = _scan("safe/.github/workflows/dispatch-safe.yml")
        dispatch_findings = [f for f in findings if f.pattern_id == "dispatch-input-injection"]
        assert len(dispatch_findings) == 0

    def test_choice_input_direct_not_flagged(self) -> None:
        findings = _scan("safe/.github/workflows/dispatch-choice-direct.yml")
        dispatch_findings = [f for f in findings if f.pattern_id == "dispatch-input-injection"]
        assert len(dispatch_findings) == 0

    def test_mixed_inputs_flags_string_only(self) -> None:
        findings = _scan("vulnerable/.github/workflows/dispatch-mixed-inputs.yml")
        dispatch_findings = [f for f in findings if f.pattern_id == "dispatch-input-injection"]
        assert len(dispatch_findings) >= 1
        evidence_text = " ".join(e for f in dispatch_findings for e in f.evidence)
        assert "inputs." in evidence_text


class TestOutputDelimiterInjection:
    def test_detects_hardcoded_delimiter(self) -> None:
        findings = _scan("vulnerable/.github/workflows/output-delimiter.yml")
        delim_findings = [f for f in findings if f.pattern_id == "output-delimiter-injection"]
        assert len(delim_findings) >= 1

    def test_random_delimiter_not_flagged(self) -> None:
        findings = _scan("safe/.github/workflows/output-random-delimiter.yml")
        delim_findings = [f for f in findings if f.pattern_id == "output-delimiter-injection"]
        assert len(delim_findings) == 0


class TestOidcFork:
    def test_detects_oidc_on_fork_reachable(self) -> None:
        findings = _scan("vulnerable/.github/workflows/oidc-fork.yml")
        oidc_findings = [f for f in findings if f.pattern_id == "oidc-token-fork"]
        assert len(oidc_findings) >= 1

    def test_push_only_not_flagged(self) -> None:
        findings = _scan("safe/.github/workflows/oidc-push-only.yml")
        oidc_findings = [f for f in findings if f.pattern_id == "oidc-token-fork"]
        assert len(oidc_findings) == 0


class TestCachePoisoning:
    def test_detects_restore_keys(self) -> None:
        findings = _scan("vulnerable/.github/workflows/cache-poisoning.yml")
        cache_findings = [f for f in findings if f.pattern_id == "actions-cache-poisoning"]
        assert len(cache_findings) >= 1

    def test_exact_key_not_flagged(self) -> None:
        findings = _scan("safe/.github/workflows/cache-exact-key.yml")
        cache_findings = [f for f in findings if f.pattern_id == "actions-cache-poisoning"]
        assert len(cache_findings) == 0


class TestWorkflowRunArtifacts:
    def test_detects_artifact_download(self) -> None:
        findings = _scan("vulnerable/.github/workflows/workflow-run-artifacts.yml")
        art_findings = [f for f in findings if f.pattern_id == "workflow-run-artifact-trust"]
        assert len(art_findings) >= 1

    def test_no_download_not_flagged(self) -> None:
        findings = _scan("safe/.github/workflows/workflow-run-no-artifacts.yml")
        art_findings = [f for f in findings if f.pattern_id == "workflow-run-artifact-trust"]
        assert len(art_findings) == 0


class TestArtifactSupplyChain:
    def test_detects_download_then_execute(self) -> None:
        findings = _scan("vulnerable/.github/workflows/workflow-run-artifacts.yml")
        chain_findings = [f for f in findings if f.pattern_id == "artifact-supply-chain"]
        assert len(chain_findings) >= 1

    def test_no_download_not_flagged(self) -> None:
        findings = _scan("safe/.github/workflows/workflow-run-no-artifacts.yml")
        chain_findings = [f for f in findings if f.pattern_id == "artifact-supply-chain"]
        assert len(chain_findings) == 0


class TestAdvisoryMatch:
    def test_detects_compromised_action(self) -> None:
        findings = _scan("vulnerable/.github/workflows/compromised-action.yml")
        adv_findings = [f for f in findings if f.pattern_id == "action-version-advisory"]
        assert len(adv_findings) >= 1
        assert adv_findings[0].severity_base == "critical"
        assert any("CVE-2025-30066" in e for e in adv_findings[0].evidence)

    def test_safe_action_not_flagged(self) -> None:
        findings = _scan("safe/.github/workflows/pinned-actions.yml")
        adv_findings = [f for f in findings if f.pattern_id == "action-version-advisory"]
        assert len(adv_findings) == 0


class TestMissingPermissions:
    def test_detects_missing_permissions(self) -> None:
        findings = _scan("vulnerable/.github/workflows/expression-injection.yml")
        perm_findings = [f for f in findings if f.pattern_id == "missing-permissions-block"]
        assert len(perm_findings) == 1
        assert perm_findings[0].severity_base == "info"

    def test_permissions_present_not_flagged(self) -> None:
        findings = _scan("safe/.github/workflows/minimal-permissions.yml")
        perm_findings = [f for f in findings if f.pattern_id == "missing-permissions-block"]
        assert len(perm_findings) == 0

    def test_workflow_level_permissions_sufficient(self) -> None:
        findings = _scan("vulnerable/.github/workflows/pwn-request.yml")
        perm_findings = [f for f in findings if f.pattern_id == "missing-permissions-block"]
        assert len(perm_findings) == 0


class TestCheckoutPersistsCredentials:
    def test_detects_default_persist(self) -> None:
        findings = _scan("vulnerable/.github/workflows/unpinned-actions.yml")
        cred_findings = [f for f in findings if f.pattern_id == "checkout-persists-credentials"]
        assert len(cred_findings) >= 1
        assert cred_findings[0].severity_base == "low"

    def test_persist_false_not_flagged(self) -> None:
        findings = _scan("safe/.github/workflows/minimal-permissions.yml")
        cred_findings = [f for f in findings if f.pattern_id == "checkout-persists-credentials"]
        assert len(cred_findings) == 0


class TestPipeToShell:
    def test_detects_curl_pipe_sh(self) -> None:
        findings = _scan("vulnerable/.github/workflows/pipe-to-shell.yml")
        pipe_findings = [f for f in findings if f.pattern_id == "pipe-to-shell"]
        assert len(pipe_findings) >= 2
        assert pipe_findings[0].severity_base == "medium"

    def test_safe_download_then_verify_not_flagged(self) -> None:
        findings = _scan("safe/.github/workflows/pipe-to-shell-safe.yml")
        pipe_findings = [f for f in findings if f.pattern_id == "pipe-to-shell"]
        assert len(pipe_findings) == 0


class TestStaticCloudCredentials:
    def test_detects_aws_keys_in_env(self) -> None:
        findings = _scan("vulnerable/.github/workflows/static-cloud-creds.yml")
        cred_findings = [f for f in findings if f.pattern_id == "static-cloud-credentials"]
        assert len(cred_findings) >= 1
        assert cred_findings[0].severity_base == "low"

    def test_oidc_auth_not_flagged(self) -> None:
        findings = _scan("safe/.github/workflows/oidc-cloud-auth.yml")
        cred_findings = [f for f in findings if f.pattern_id == "static-cloud-credentials"]
        assert len(cred_findings) == 0


class TestDockerInDocker:
    def test_detects_docker_commands(self) -> None:
        findings = _scan("vulnerable/.github/workflows/docker-in-docker.yml")
        dind_findings = [f for f in findings if f.pattern_id == "docker-in-docker"]
        assert len(dind_findings) >= 1
        assert dind_findings[0].severity_base == "medium"

    def test_build_action_not_flagged(self) -> None:
        findings = _scan("safe/.github/workflows/docker-build-action.yml")
        dind_findings = [f for f in findings if f.pattern_id == "docker-in-docker"]
        assert len(dind_findings) == 0


class TestDockerSocketConfig:
    def test_detects_docker_host_in_env(self) -> None:
        from actionsieve.providers.gitlab import GitLabProvider

        gitlab_fixtures = Path(__file__).parent.parent / "fixtures" / "gitlab"
        provider = GitLabProvider()
        model = provider.parse(gitlab_fixtures / "vulnerable-docker-socket" / ".gitlab-ci.yml")
        patterns = load_patterns(platform="gitlab")
        findings = match(model, patterns)
        socket_findings = [f for f in findings if f.pattern_id == "docker-socket-config"]
        assert len(socket_findings) >= 1
        evidence = " ".join(e for f in socket_findings for e in f.evidence)
        assert "DOCKER_HOST" in evidence

    def test_detects_dind_image(self) -> None:
        from actionsieve.providers.gitlab import GitLabProvider

        gitlab_fixtures = Path(__file__).parent.parent / "fixtures" / "gitlab"
        provider = GitLabProvider()
        model = provider.parse(gitlab_fixtures / "vulnerable-docker-socket" / ".gitlab-ci.yml")
        patterns = load_patterns(platform="gitlab")
        findings = match(model, patterns)
        dind_findings = [
            f
            for f in findings
            if f.pattern_id == "docker-socket-config" and "DinD" in " ".join(f.evidence)
        ]
        assert len(dind_findings) >= 1


class TestUnpinnedContainerImage:
    def test_detects_unpinned_tag(self) -> None:
        findings = _scan("vulnerable/.github/workflows/unpinned-container.yml")
        img_findings = [f for f in findings if f.pattern_id == "unpinned-container-image"]
        assert len(img_findings) == 1
        assert img_findings[0].severity_base == "low"
        assert "node:20" in img_findings[0].evidence[0]

    def test_pinned_digest_not_flagged(self) -> None:
        findings = _scan("safe/.github/workflows/pinned-container.yml")
        img_findings = [f for f in findings if f.pattern_id == "unpinned-container-image"]
        assert len(img_findings) == 0

    def test_no_container_not_flagged(self) -> None:
        findings = _scan("safe/.github/workflows/pinned-actions.yml")
        img_findings = [f for f in findings if f.pattern_id == "unpinned-container-image"]
        assert len(img_findings) == 0


class TestCompositeActionScanning:
    def test_detects_pipe_to_shell_in_composite(self) -> None:
        from actionsieve.scanner import _resolve_composite_actions

        provider = GitHubProvider()
        model = provider.parse(FIXTURES / "vulnerable/.github/workflows/composite-action.yml")
        _resolve_composite_actions(model, FIXTURES / "vulnerable")
        patterns = load_patterns(platform="github")
        findings = match(model, patterns)
        pipe_findings = [f for f in findings if f.pattern_id == "pipe-to-shell"]
        assert len(pipe_findings) >= 1

    def test_safe_composite_no_pipe_to_shell(self) -> None:
        from actionsieve.scanner import _resolve_composite_actions

        provider = GitHubProvider()
        model = provider.parse(FIXTURES / "safe/.github/workflows/composite-action-safe.yml")
        _resolve_composite_actions(model, FIXTURES / "safe")
        patterns = load_patterns(platform="github")
        findings = match(model, patterns)
        pipe_findings = [f for f in findings if f.pattern_id == "pipe-to-shell"]
        assert len(pipe_findings) == 0


class TestCompositeChainResolution:
    def test_detects_injection_through_nested_composite(self) -> None:
        from actionsieve.scanner import _resolve_composite_actions

        provider = GitHubProvider()
        model = provider.parse(FIXTURES / "vulnerable/.github/workflows/composite-chain.yml")
        _resolve_composite_actions(model, FIXTURES / "vulnerable")
        patterns = load_patterns(platform="github")
        findings = match(model, patterns)
        expr_findings = [f for f in findings if f.pattern_id == "expr-injection-run"]
        assert len(expr_findings) >= 1
        assert any("github.head_ref" in e for f in expr_findings for e in f.evidence)

    def test_nested_steps_appended_to_job(self) -> None:
        from actionsieve.scanner import _resolve_composite_actions

        provider = GitHubProvider()
        model = provider.parse(FIXTURES / "vulnerable/.github/workflows/composite-chain.yml")
        _resolve_composite_actions(model, FIXTURES / "vulnerable")
        job = model.jobs[0]
        shell_steps = [s for s in job.steps if s.type == "shell"]
        assert len(shell_steps) >= 1
        assert any("github.head_ref" in (s.shell_command or "") for s in shell_steps)

    def test_safe_chain_no_injection(self) -> None:
        from actionsieve.scanner import _resolve_composite_actions

        provider = GitHubProvider()
        model = provider.parse(FIXTURES / "safe/.github/workflows/composite-action-safe.yml")
        _resolve_composite_actions(model, FIXTURES / "safe")
        patterns = load_patterns(platform="github")
        findings = match(model, patterns)
        expr_findings = [f for f in findings if f.pattern_id == "expr-injection-run"]
        assert len(expr_findings) == 0


class TestCompositeOutputTaint:
    def test_detects_tainted_composite_output(self) -> None:
        from actionsieve.scanner import _resolve_composite_actions

        provider = GitHubProvider()
        model = provider.parse(
            FIXTURES / "vulnerable/.github/workflows/composite-output-injection.yml"
        )
        _resolve_composite_actions(model, FIXTURES / "vulnerable")
        patterns = load_patterns(platform="github")
        findings = match(model, patterns)
        composite_findings = [f for f in findings if f.pattern_id == "composite-output-injection"]
        assert len(composite_findings) >= 1
        assert composite_findings[0].severity_base == "high"

    def test_safe_composite_output_no_finding(self) -> None:
        from actionsieve.scanner import _resolve_composite_actions

        provider = GitHubProvider()
        model = provider.parse(FIXTURES / "safe/.github/workflows/composite-output-safe.yml")
        _resolve_composite_actions(model, FIXTURES / "safe")
        patterns = load_patterns(platform="github")
        findings = match(model, patterns)
        composite_findings = [f for f in findings if f.pattern_id == "composite-output-injection"]
        assert len(composite_findings) == 0

    def test_taint_propagated_to_caller_step(self) -> None:
        from actionsieve.scanner import _resolve_composite_actions

        provider = GitHubProvider()
        model = provider.parse(
            FIXTURES / "vulnerable/.github/workflows/composite-output-injection.yml"
        )
        _resolve_composite_actions(model, FIXTURES / "vulnerable")
        info_step = next(s for j in model.jobs for s in j.steps if s.id == "info")
        assert "pr_title" in info_step.outputs_written
        tainted = [e for e in info_step.expressions if e.is_tainted]
        assert len(tainted) >= 1
        assert tainted[0].context_path == "github.event.pull_request.title"


class TestForkCacheWrite:
    def test_detects_cache_in_fork_reachable(self) -> None:
        findings = _scan("vulnerable/.github/workflows/fork-cache-write.yml")
        cache_findings = [f for f in findings if f.pattern_id == "fork-pr-cache-write"]
        assert len(cache_findings) >= 1
        assert cache_findings[0].severity_base == "medium"

    def test_push_only_not_flagged(self) -> None:
        findings = _scan("safe/.github/workflows/cache-push-only.yml")
        cache_findings = [f for f in findings if f.pattern_id == "fork-pr-cache-write"]
        assert len(cache_findings) == 0

    def test_restore_only_not_flagged(self) -> None:
        findings = _scan("safe/.github/workflows/cache-restore-only.yml")
        cache_findings = [f for f in findings if f.pattern_id == "fork-pr-cache-write"]
        assert len(cache_findings) == 0


class TestDockerPluginPrivileged:
    def test_detects_privileged_plugin(self) -> None:
        from actionsieve.providers.buildkite import BuildkiteProvider

        provider = BuildkiteProvider()
        model = provider.parse(
            FIXTURES.parent / "buildkite" / "vulnerable" / ".buildkite" / "pipeline.yml"
        )
        patterns = load_patterns(platform="buildkite")
        findings = match(model, patterns)
        plugin_findings = [f for f in findings if f.pattern_id == "docker-plugin-privileged"]
        assert len(plugin_findings) >= 1
        assert any("privileged" in e for f in plugin_findings for e in f.evidence)

    def test_detects_socket_mount(self) -> None:
        from actionsieve.providers.buildkite import BuildkiteProvider

        provider = BuildkiteProvider()
        model = provider.parse(
            FIXTURES.parent / "buildkite" / "vulnerable" / ".buildkite" / "pipeline.yml"
        )
        patterns = load_patterns(platform="buildkite")
        findings = match(model, patterns)
        plugin_findings = [f for f in findings if f.pattern_id == "docker-plugin-privileged"]
        assert any("socket" in e for f in plugin_findings for e in f.evidence)


class TestDronePrivilegedStep:
    def test_detects_privileged_step(self) -> None:
        from actionsieve.providers.drone import DroneProvider

        provider = DroneProvider()
        model = provider.parse(FIXTURES.parent / "drone" / "vulnerable" / ".drone.yml")
        patterns = load_patterns(platform="drone")
        findings = match(model, patterns)
        priv = [f for f in findings if f.pattern_id == "docker-plugin-privileged"]
        assert len(priv) >= 1
        assert any("privileged" in e for f in priv for e in f.evidence)

    def test_detects_host_volume_socket(self) -> None:
        from actionsieve.providers.drone import DroneProvider

        provider = DroneProvider()
        model = provider.parse(FIXTURES.parent / "drone" / "vulnerable" / ".drone.yml")
        patterns = load_patterns(platform="drone")
        findings = match(model, patterns)
        priv = [f for f in findings if f.pattern_id == "docker-plugin-privileged"]
        assert any("socket" in e for f in priv for e in f.evidence)

    def test_safe_drone_no_privileged(self) -> None:
        from actionsieve.providers.drone import DroneProvider

        provider = DroneProvider()
        model = provider.parse(FIXTURES.parent / "drone" / "safe" / ".drone.yml")
        patterns = load_patterns(platform="drone")
        findings = match(model, patterns)
        priv = [f for f in findings if f.pattern_id == "docker-plugin-privileged"]
        assert len(priv) == 0


class TestIssueCommentForkCheckout:
    def test_detects_issue_comment_with_fork_checkout(self) -> None:
        findings = _scan("vulnerable/.github/workflows/issue-comment-checkout.yml")
        ic_findings = [f for f in findings if f.pattern_id == "issue-comment-fork-checkout"]
        assert len(ic_findings) == 1
        assert any("pull/" in e for e in ic_findings[0].evidence)
        assert any("id-token: write" in e for e in ic_findings[0].evidence)

    def test_safe_issue_comment_not_flagged(self) -> None:
        findings = _scan("safe/.github/workflows/issue-comment-safe.yml")
        ic_findings = [f for f in findings if f.pattern_id == "issue-comment-fork-checkout"]
        assert len(ic_findings) == 0


class TestStandaloneActionScanning:
    def test_detects_injection_in_unreferenced_action(self) -> None:
        from actionsieve.scanner import _parse_standalone_action

        model = _parse_standalone_action(
            FIXTURES / "vulnerable/.github/actions/standalone-vuln/action.yml", "github"
        )
        assert model is not None
        patterns = load_patterns(platform="github")
        findings = match(model, patterns)
        expr_findings = [f for f in findings if f.pattern_id == "expr-injection-run"]
        assert len(expr_findings) >= 1

    def test_standalone_no_permissions_finding(self) -> None:
        from actionsieve.scanner import _parse_standalone_action

        model = _parse_standalone_action(
            FIXTURES / "vulnerable/.github/actions/standalone-vuln/action.yml", "github"
        )
        assert model is not None
        patterns = load_patterns(platform="github")
        findings = match(model, patterns)
        perm_findings = [f for f in findings if f.pattern_id == "missing-permissions-block"]
        assert len(perm_findings) == 0

    def test_standalone_skips_non_composite(self) -> None:
        from actionsieve.scanner import _parse_standalone_action

        model = _parse_standalone_action(
            FIXTURES / "vulnerable/.github/workflows/expression-injection.yml", "github"
        )
        assert model is None

    def test_dedup_with_resolved_composites(self) -> None:
        from actionsieve.scanner import _resolve_composite_actions

        provider = GitHubProvider()
        model = provider.parse(FIXTURES / "vulnerable/.github/workflows/composite-chain.yml")
        resolved = _resolve_composite_actions(model, FIXTURES / "vulnerable")
        action_a_path = str((FIXTURES / "vulnerable/.github/actions/action-a").resolve())
        action_b_path = str((FIXTURES / "vulnerable/.github/actions/action-b").resolve())
        assert action_a_path in resolved
        assert action_b_path in resolved


class TestNoFalsePositivesOnSafe:
    def test_env_indirection(self) -> None:
        findings = _scan("safe/.github/workflows/env-indirection.yml")
        high_findings = [f for f in findings if f.severity_base in ("critical", "high")]
        assert len(high_findings) == 0

    def test_pinned_actions(self) -> None:
        findings = _scan("safe/.github/workflows/pinned-actions.yml")
        assert len(findings) == 0

    def test_minimal_permissions(self) -> None:
        findings = _scan("safe/.github/workflows/minimal-permissions.yml")
        high_findings = [f for f in findings if f.severity_base in ("critical", "high")]
        assert len(high_findings) == 0


class TestFindingFields:
    def test_finding_has_required_fields(self) -> None:
        findings = _scan("vulnerable/.github/workflows/expression-injection.yml")
        assert len(findings) > 0
        f = findings[0]
        assert f.pattern_id
        assert f.pattern_title
        assert f.file_path
        assert f.platform == "github"
        assert f.job_id
        assert f.severity_base in ("critical", "high", "medium", "low", "info")
        assert f.attacker_model
        assert f.impact

    def test_finding_has_evidence(self) -> None:
        findings = _scan("vulnerable/.github/workflows/expression-injection.yml")
        for f in findings:
            assert len(f.evidence) > 0
