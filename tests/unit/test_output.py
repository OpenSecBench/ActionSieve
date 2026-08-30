import json

import yaml

from actionsieve.engine import Finding
from actionsieve.output import render_json, render_sarif, render_yaml


def _sample_finding() -> Finding:
    return Finding(
        pattern_id="expr-injection-run",
        pattern_title="Expression injection in run block",
        file_path=".github/workflows/ci.yml",
        platform="github",
        line=12,
        job_id="build",
        step_index=0,
        severity_base="high",
        attacker_model="fork_pr",
        impact="rce",
        evidence=["Found '${{ github.event.pull_request.title }}' in run block"],
        tags=["injection", "shell"],
        cwe="CWE-78",
        mitigations=["Use env var indirection"],
    )


class TestJSON:
    def test_valid_json(self) -> None:
        text = render_json([_sample_finding()])
        data = json.loads(text)
        assert "findings" in data
        assert len(data["findings"]) == 1

    def test_finding_fields(self) -> None:
        text = render_json([_sample_finding()])
        data = json.loads(text)
        f = data["findings"][0]
        assert f["pattern_id"] == "expr-injection-run"
        assert f["severity_base"] == "high"
        assert f["line"] == 12
        assert f["cwe"] == "CWE-78"

    def test_empty_findings(self) -> None:
        text = render_json([])
        data = json.loads(text)
        assert data["findings"] == []


class TestYAML:
    def test_valid_yaml(self) -> None:
        text = render_yaml([_sample_finding()])
        data = yaml.safe_load(text)
        assert "findings" in data
        assert len(data["findings"]) == 1

    def test_finding_fields(self) -> None:
        text = render_yaml([_sample_finding()])
        data = yaml.safe_load(text)
        f = data["findings"][0]
        assert f["pattern_id"] == "expr-injection-run"
        assert f["platform"] == "github"


class TestSARIF:
    def test_valid_sarif(self) -> None:
        text = render_sarif([_sample_finding()])
        data = json.loads(text)
        assert data["version"] == "2.1.0"
        assert len(data["runs"]) == 1

    def test_sarif_rules(self) -> None:
        text = render_sarif([_sample_finding()])
        data = json.loads(text)
        rules = data["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 1
        assert rules[0]["id"] == "expr-injection-run"

    def test_sarif_results(self) -> None:
        text = render_sarif([_sample_finding()])
        data = json.loads(text)
        results = data["runs"][0]["results"]
        assert len(results) == 1
        assert results[0]["ruleId"] == "expr-injection-run"
        assert results[0]["level"] == "error"

    def test_sarif_location(self) -> None:
        text = render_sarif([_sample_finding()])
        data = json.loads(text)
        loc = data["runs"][0]["results"][0]["locations"][0]
        assert loc["physicalLocation"]["artifactLocation"]["uri"] == ".github/workflows/ci.yml"
        assert loc["physicalLocation"]["region"]["startLine"] == 12

    def test_sarif_cwe(self) -> None:
        text = render_sarif([_sample_finding()])
        data = json.loads(text)
        taxa = data["runs"][0]["results"][0]["taxa"]
        assert taxa[0]["id"] == "CWE-78"

    def test_sarif_dedup_rules(self) -> None:
        findings = [_sample_finding(), _sample_finding()]
        text = render_sarif(findings)
        data = json.loads(text)
        rules = data["runs"][0]["tool"]["driver"]["rules"]
        results = data["runs"][0]["results"]
        assert len(rules) == 1
        assert len(results) == 2

    def test_sarif_severity_mapping(self) -> None:
        for severity, expected in [
            ("critical", "error"),
            ("high", "error"),
            ("medium", "warning"),
            ("low", "note"),
            ("info", "note"),
        ]:
            f = _sample_finding()
            f.severity_base = severity
            text = render_sarif([f])
            data = json.loads(text)
            assert data["runs"][0]["results"][0]["level"] == expected

    def test_empty_findings(self) -> None:
        text = render_sarif([])
        data = json.loads(text)
        assert data["runs"][0]["results"] == []
