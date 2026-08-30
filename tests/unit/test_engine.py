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


class TestSelfHosted:
    def test_detects_self_hosted(self) -> None:
        findings = _scan("vulnerable/.github/workflows/self-hosted-secrets.yml")
        sh_findings = [f for f in findings if f.pattern_id == "self-hosted-runner-persistence"]
        assert len(sh_findings) >= 1

    def test_managed_runner_not_flagged(self) -> None:
        findings = _scan("safe/.github/workflows/minimal-permissions.yml")
        sh_findings = [f for f in findings if f.pattern_id == "self-hosted-runner-persistence"]
        assert len(sh_findings) == 0


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
