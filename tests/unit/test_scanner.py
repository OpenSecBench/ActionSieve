from pathlib import Path

from actionsieve.scanner import (
    EXIT_CLEAN,
    EXIT_CRITICAL,
    EXIT_FINDINGS,
    scan,
)

FIXTURES = Path(__file__).parent.parent / "fixtures" / "github"


class TestScanVulnerable:
    def test_finds_expression_injection(self) -> None:
        result = scan(FIXTURES / "vulnerable", platform="github")
        ids = [f.pattern_id for f in result.findings]
        assert "expr-injection-run" in ids

    def test_finds_unpinned_refs(self) -> None:
        result = scan(FIXTURES / "vulnerable", platform="github")
        ids = [f.pattern_id for f in result.findings]
        assert "mutable-action-ref" in ids

    def test_findings_sorted_by_severity(self) -> None:
        result = scan(FIXTURES / "vulnerable", platform="github")
        severity_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        severities = [severity_order.get(f.severity_base, 0) for f in result.findings]
        assert severities == sorted(severities, reverse=True)


class TestScanSafe:
    def test_safe_fixtures_clean(self) -> None:
        result = scan(FIXTURES / "safe", platform="github")
        assert result.findings == []
        assert result.exit_code == EXIT_CLEAN


class TestScanExitCodes:
    def test_clean_exit(self) -> None:
        result = scan(FIXTURES / "safe", platform="github")
        assert result.exit_code == EXIT_CLEAN

    def test_findings_exit(self) -> None:
        result = scan(FIXTURES / "vulnerable", platform="github")
        assert result.exit_code in (EXIT_FINDINGS, EXIT_CRITICAL)

    def test_fail_on_info(self) -> None:
        result = scan(FIXTURES / "vulnerable", platform="github", fail_on="info")
        assert result.exit_code in (EXIT_FINDINGS, EXIT_CRITICAL)


class TestScanOutputFormats:
    def test_json_output(self) -> None:
        result = scan(FIXTURES / "vulnerable", platform="github", output_format="json")
        assert '"findings"' in result.output_text

    def test_yaml_output(self) -> None:
        result = scan(FIXTURES / "vulnerable", platform="github", output_format="yaml")
        assert "findings:" in result.output_text

    def test_sarif_output(self) -> None:
        result = scan(FIXTURES / "vulnerable", platform="github", output_format="sarif")
        assert '"version": "2.1.0"' in result.output_text


class TestScanSuppression:
    def test_show_suppressed_includes_suppressed(self) -> None:
        result = scan(
            FIXTURES / "vulnerable",
            platform="github",
            profile_name="hardened",
            show_suppressed=True,
        )
        all_count = len(result.findings) + len(result.suppressed)
        assert all_count > 0

    def test_suppressed_excluded_by_default(self) -> None:
        normal = scan(FIXTURES / "vulnerable", platform="github")
        hardened = scan(FIXTURES / "vulnerable", platform="github", profile_name="hardened")
        assert len(hardened.findings) <= len(normal.findings)


class TestScanNoProvider:
    def test_empty_dir_returns_clean(self, tmp_path: Path) -> None:
        result = scan(tmp_path)
        assert result.exit_code == EXIT_CLEAN
        assert result.findings == []


class TestScanOutputFile:
    def test_writes_to_file(self, tmp_path: Path) -> None:
        out = tmp_path / "results.json"
        scan(
            FIXTURES / "vulnerable",
            platform="github",
            output_file=out,
        )
        assert out.exists()
        assert '"findings"' in out.read_text()
