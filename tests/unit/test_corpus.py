"""Tests for corpus module — discovery, checking, table generation."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import yaml

if TYPE_CHECKING:
    import pytest

from actionsieve.corpus import (
    collect_coverage,
    discover_cases,
    generate_report,
    load_table_cases,
    run_case,
    update_expected,
)

GITHUB_FIXTURES = Path(__file__).parent.parent / "fixtures" / "github"
MINIMAL_PATTERNS = str(Path(__file__).parent.parent / "fixtures" / "minimal_patterns")


def _make_case(tmp_path: Path, case_name: str, expected: dict) -> Path:
    case_dir = tmp_path / "corpus" / "github" / "vulnerable" / case_name
    case_dir.mkdir(parents=True)
    (case_dir / ".actionsieve.repo.yaml").write_text(
        yaml.dump(expected, default_flow_style=False),
        encoding="utf-8",
    )
    return case_dir


class TestDiscoverCases:
    def test_finds_cases(self, tmp_path: Path) -> None:
        _make_case(tmp_path, "test-case", {"platform": "github"})
        cases = discover_cases(tmp_path / "corpus")
        assert len(cases) == 1
        assert cases[0][1]["platform"] == "github"

    def test_platform_filter(self, tmp_path: Path) -> None:
        _make_case(tmp_path, "test-case", {"platform": "github"})
        corpus = tmp_path / "corpus"
        gl = corpus / "gitlab" / "vulnerable" / "gl-case"
        gl.mkdir(parents=True)
        (gl / ".actionsieve.repo.yaml").write_text("platform: gitlab", encoding="utf-8")

        assert len(discover_cases(corpus, platform_filter="github")) == 1
        assert len(discover_cases(corpus, platform_filter="gitlab")) == 1
        assert len(discover_cases(corpus)) == 2

    def test_case_filter(self, tmp_path: Path) -> None:
        _make_case(tmp_path, "expr-injection", {"platform": "github"})
        _make_case(tmp_path, "supply-chain", {"platform": "github"})
        corpus = tmp_path / "corpus"

        assert len(discover_cases(corpus, case_filter="expr-*")) == 1
        assert len(discover_cases(corpus, case_filter="*chain")) == 1

    def test_empty_corpus(self, tmp_path: Path) -> None:
        assert discover_cases(tmp_path) == []


class TestRunCase:
    def test_pass_with_expected_findings(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ACTIONSIEVE_PATTERNS", MINIMAL_PATTERNS)
        vuln = GITHUB_FIXTURES / "vulnerable"
        expected = {
            "platform": "github",
            "expected_exit_code": 1,
            "expected_findings": [
                {"pattern_id": "test-expr-injection"},
            ],
        }
        result = run_case(vuln, expected, GITHUB_FIXTURES)
        assert result.findings_ok
        assert not result.missing_findings

    def test_fail_missing_finding(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ACTIONSIEVE_PATTERNS", MINIMAL_PATTERNS)
        safe = GITHUB_FIXTURES / "safe"
        expected = {
            "platform": "github",
            "expected_exit_code": 0,
            "expected_findings": [
                {"pattern_id": "nonexistent-pattern"},
            ],
        }
        result = run_case(safe, expected, GITHUB_FIXTURES)
        assert not result.findings_ok
        assert "nonexistent-pattern" in result.missing_findings[0]

    def test_pass_no_findings_expected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ACTIONSIEVE_PATTERNS", MINIMAL_PATTERNS)
        safe = GITHUB_FIXTURES / "safe"
        expected = {
            "platform": "github",
            "expected_exit_code": 0,
        }
        result = run_case(safe, expected, GITHUB_FIXTURES)
        assert result.passed
        assert result.exit_code_ok
        assert result.findings_ok

    def test_false_positive_detection(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ACTIONSIEVE_PATTERNS", MINIMAL_PATTERNS)
        vuln = GITHUB_FIXTURES / "vulnerable"
        expected = {
            "platform": "github",
            "expected_exit_code": 1,
        }
        result = run_case(vuln, expected, GITHUB_FIXTURES)
        assert not result.passed
        assert result.false_positives

    def test_exit_code_mismatch(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ACTIONSIEVE_PATTERNS", MINIMAL_PATTERNS)
        safe = GITHUB_FIXTURES / "safe"
        expected = {
            "platform": "github",
            "expected_exit_code": 1,
        }
        result = run_case(safe, expected, GITHUB_FIXTURES)
        assert not result.exit_code_ok
        assert result.actual_exit != 1


class TestUpdateExpected:
    def test_updates_yaml(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ACTIONSIEVE_PATTERNS", MINIMAL_PATTERNS)
        case_dir = tmp_path / "case"
        case_dir.mkdir()
        wf_dir = case_dir / ".github" / "workflows"
        wf_dir.mkdir(parents=True)
        (wf_dir / "ci.yml").write_text(
            "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - uses: actions/checkout@v4\n",
            encoding="utf-8",
        )
        expected: dict = {"platform": "github"}
        (case_dir / ".actionsieve.repo.yaml").write_text(yaml.dump(expected), encoding="utf-8")
        update_expected(case_dir, expected)

        updated = yaml.safe_load((case_dir / ".actionsieve.repo.yaml").read_text(encoding="utf-8"))
        assert "expected_exit_code" in updated
        assert "expected_findings" in updated


class TestCollectCoverage:
    def test_coverage_report(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ACTIONSIEVE_PATTERNS", MINIMAL_PATTERNS)
        corpus = tmp_path / "corpus"
        case_dir = corpus / "github" / "vulnerable" / "test"
        case_dir.mkdir(parents=True)
        (case_dir / ".actionsieve.repo.yaml").write_text(
            yaml.dump(
                {
                    "platform": "github",
                    "expected_findings": [{"pattern_id": "test-expr-injection"}],
                }
            ),
            encoding="utf-8",
        )

        cases = discover_cases(corpus)
        cov = collect_coverage(cases, corpus)
        assert "test-expr-injection" in cov
        assert len(cov["test-expr-injection"]["vulnerable"]) == 1


class TestTableGeneration:
    def test_load_table_cases(self, tmp_path: Path) -> None:
        corpus = tmp_path / "corpus"
        case_dir = corpus / "github" / "vulnerable" / "test-case"
        case_dir.mkdir(parents=True)
        (case_dir / ".actionsieve.repo.yaml").write_text(
            yaml.dump(
                {
                    "platform": "github",
                    "description": "Test case",
                    "expected_exit_code": 1,
                    "expected_findings": [{"pattern_id": "test-expr-injection"}],
                }
            ),
            encoding="utf-8",
        )

        cases = load_table_cases(corpus)
        assert len(cases) == 1
        assert cases[0]["platform"] == "github"
        assert cases[0]["name"] == "test-case"
        assert "test-expr-injection" in cases[0]["pattern_ids"]

    def test_generate_full_report(self, tmp_path: Path) -> None:
        corpus = tmp_path / "corpus"
        case_dir = corpus / "github" / "vulnerable" / "test"
        case_dir.mkdir(parents=True)
        (case_dir / ".actionsieve.repo.yaml").write_text(
            yaml.dump(
                {
                    "description": "Expr injection",
                    "expected_findings": [{"pattern_id": "test-expr-injection"}],
                }
            ),
            encoding="utf-8",
        )

        cases = load_table_cases(corpus)
        report = generate_report(cases)
        assert "# Corpus Index" in report
        assert "Platform Summary" in report
        assert "Pattern Coverage" in report
        assert "test-expr-injection" in report

    def test_generate_summary_only(self, tmp_path: Path) -> None:
        corpus = tmp_path / "corpus"
        case_dir = corpus / "github" / "vulnerable" / "test"
        case_dir.mkdir(parents=True)
        (case_dir / ".actionsieve.repo.yaml").write_text(
            yaml.dump({"expected_findings": []}),
            encoding="utf-8",
        )

        cases = load_table_cases(corpus)
        text = generate_report(cases, section="summary")
        assert "Platform Summary" in text
        assert "Pattern Coverage" not in text

    def test_platform_filter(self, tmp_path: Path) -> None:
        corpus = tmp_path / "corpus"
        for plat in ("github", "gitlab"):
            d = corpus / plat / "vulnerable" / "test"
            d.mkdir(parents=True)
            (d / ".actionsieve.repo.yaml").write_text(
                yaml.dump({"platform": plat, "expected_findings": []}),
                encoding="utf-8",
            )

        cases = load_table_cases(corpus)
        text = generate_report(cases, section="cases", platform_filter="github")
        assert "github" in text
        assert "gitlab" not in text
