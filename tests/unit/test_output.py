import json

import yaml

from actionsieve.engine import Finding
from actionsieve.output import render_json, render_markdown, render_ocsf, render_sarif, render_yaml


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


class TestMarkdown:
    def test_header(self) -> None:
        text = render_markdown([_sample_finding()])
        assert text.startswith("# actionsieve Security Report")

    def test_summary_counts(self) -> None:
        text = render_markdown([_sample_finding()])
        assert "1 high" in text

    def test_finding_fields(self) -> None:
        text = render_markdown([_sample_finding()])
        assert "`expr-injection-run`" in text
        assert "`.github/workflows/ci.yml:12`" in text
        assert "fork_pr" in text
        assert "CWE-78" in text

    def test_evidence(self) -> None:
        text = render_markdown([_sample_finding()])
        assert "Found '${{ github.event.pull_request.title }}' in run block" in text

    def test_mitigations(self) -> None:
        text = render_markdown([_sample_finding()])
        assert "Use env var indirection" in text

    def test_empty_findings(self) -> None:
        text = render_markdown([])
        assert "No findings." in text
        assert "0" in text

    def test_severity_grouping(self) -> None:
        f1 = _sample_finding()
        f1.severity_base = "critical"
        f2 = _sample_finding()
        f2.severity_base = "low"
        f2.pattern_id = "other-pattern"
        f2.pattern_title = "Other pattern"
        text = render_markdown([f1, f2])
        crit_pos = text.index("## Critical")
        low_pos = text.index("## Low")
        assert crit_pos < low_pos

    def test_computed_severity_used(self) -> None:
        f = _sample_finding()
        f.severity_computed = "critical"
        text = render_markdown([f])
        assert "## Critical" in text
        assert "1 critical" in text

    def test_list_impact(self) -> None:
        f = _sample_finding()
        f.impact = ["rce", "secret_exfil"]
        text = render_markdown([f])
        assert "rce, secret_exfil" in text


class TestOCSF:
    def test_valid_json(self) -> None:
        text = render_ocsf([_sample_finding()])
        data = json.loads(text)
        assert "detection_findings" in data
        assert len(data["detection_findings"]) == 1

    def test_class_uid(self) -> None:
        text = render_ocsf([_sample_finding()])
        data = json.loads(text)
        event = data["detection_findings"][0]
        assert event["class_uid"] == 2004
        assert event["category_uid"] == 2
        assert event["type_uid"] == 200401
        assert event["activity_id"] == 1

    def test_severity_mapping(self) -> None:
        for severity, expected_id in [
            ("critical", 5),
            ("high", 4),
            ("medium", 3),
            ("low", 2),
            ("info", 1),
        ]:
            f = _sample_finding()
            f.severity_base = severity
            text = render_ocsf([f])
            data = json.loads(text)
            assert data["detection_findings"][0]["severity_id"] == expected_id

    def test_finding_info(self) -> None:
        text = render_ocsf([_sample_finding()])
        data = json.loads(text)
        info = data["detection_findings"][0]["finding_info"]
        assert info["title"] == "Expression injection in run block"
        assert "expr-injection-run" in info["uid"]
        assert info["analytic"]["uid"] == "expr-injection-run"
        assert info["analytic"]["type_id"] == 1

    def test_cwe_present(self) -> None:
        text = render_ocsf([_sample_finding()])
        data = json.loads(text)
        cwe = data["detection_findings"][0]["finding_info"]["cwe"]
        assert cwe["uid"] == "CWE-78"
        assert "78" in cwe["src_url"]

    def test_cwe_absent(self) -> None:
        f = _sample_finding()
        f.cwe = None
        text = render_ocsf([f])
        data = json.loads(text)
        assert "cwe" not in data["detection_findings"][0]["finding_info"]

    def test_metadata(self) -> None:
        text = render_ocsf([_sample_finding()])
        data = json.loads(text)
        meta = data["detection_findings"][0]["metadata"]
        assert meta["version"] == "1.4.0"
        assert meta["product"]["name"] == "actionsieve"

    def test_resources(self) -> None:
        text = render_ocsf([_sample_finding()])
        data = json.loads(text)
        resources = data["detection_findings"][0]["resources"]
        assert len(resources) == 1
        assert resources[0]["name"] == ".github/workflows/ci.yml"

    def test_empty_findings(self) -> None:
        text = render_ocsf([])
        data = json.loads(text)
        assert data["detection_findings"] == []

    def test_computed_severity_used(self) -> None:
        f = _sample_finding()
        f.severity_computed = "critical"
        text = render_ocsf([f])
        data = json.loads(text)
        event = data["detection_findings"][0]
        assert event["severity_id"] == 5
        assert event["severity"] == "critical"
