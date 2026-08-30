from pathlib import Path

from actionsieve.chains import analyze
from actionsieve.engine import Finding, match
from actionsieve.patterns import load_patterns
from actionsieve.providers.github import GitHubProvider

FIXTURES = Path(__file__).parent.parent / "fixtures" / "github"


def _parse(fixture: str):
    provider = GitHubProvider()
    return provider.parse(FIXTURES / fixture)


def _scan(fixture: str) -> list[Finding]:
    model = _parse(fixture)
    patterns = load_patterns(platform="github")
    return match(model, patterns)


class TestChainAnalysis:
    def test_detects_output_flow(self) -> None:
        model = _parse("vulnerable/.github/workflows/fork-script-output.yml")
        analysis = analyze(model)
        assert len(analysis.flows) >= 1

    def test_tainted_flow_from_script(self) -> None:
        model = _parse("vulnerable/.github/workflows/fork-script-output.yml")
        analysis = analyze(model)
        tainted = [f for f in analysis.flows if f.is_tainted]
        assert len(tainted) >= 1
        assert tainted[0].sink_in_shell

    def test_safe_env_indirection_not_in_shell(self) -> None:
        model = _parse("safe/.github/workflows/script-output-env.yml")
        analysis = analyze(model)
        shell_flows = [f for f in analysis.flows if f.sink_in_shell]
        assert len(shell_flows) == 0

    def test_flow_has_taint_reasons(self) -> None:
        model = _parse("vulnerable/.github/workflows/fork-script-output.yml")
        analysis = analyze(model)
        tainted = [f for f in analysis.flows if f.is_tainted]
        assert len(tainted[0].taint_reasons) > 0

    def test_env_writes_detected(self) -> None:
        model = _parse("vulnerable/.github/workflows/output-delimiter.yml")
        analysis = analyze(model)
        assert len(analysis.github_env_writes) >= 0


class TestForkScriptOutputInjection:
    def test_detects_fork_script_output(self) -> None:
        findings = _scan("vulnerable/.github/workflows/fork-script-output.yml")
        chain_findings = [f for f in findings if f.pattern_id == "fork-script-output-injection"]
        assert len(chain_findings) >= 1

    def test_has_evidence(self) -> None:
        findings = _scan("vulnerable/.github/workflows/fork-script-output.yml")
        chain_findings = [f for f in findings if f.pattern_id == "fork-script-output-injection"]
        assert len(chain_findings[0].evidence) >= 3

    def test_safe_env_not_flagged(self) -> None:
        findings = _scan("safe/.github/workflows/script-output-env.yml")
        chain_findings = [f for f in findings if f.pattern_id == "fork-script-output-injection"]
        assert len(chain_findings) == 0


class TestNoFalsePositivesOnSafeChains:
    def test_script_output_env(self) -> None:
        findings = _scan("safe/.github/workflows/script-output-env.yml")
        cross_step = [f for f in findings if "injection" in f.pattern_id and "chain" in f.tags]
        assert len(cross_step) == 0
