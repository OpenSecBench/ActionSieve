from pathlib import Path

from actionsieve.model import ComponentRef
from actionsieve.scanner import (
    EXIT_CLEAN,
    EXIT_CRITICAL,
    EXIT_FINDINGS,
    _coverage_notes,
    _local_action_path,
    _parse_composite_action,
    scan,
)

FIXTURES = Path(__file__).parent.parent / "fixtures" / "github"
MINIMAL_PATTERNS = Path(__file__).parent.parent / "fixtures" / "minimal_patterns"


class TestScanVulnerable:
    def test_findings_sorted_by_severity(self) -> None:
        result = scan(FIXTURES / "vulnerable", platform="github", patterns_path=MINIMAL_PATTERNS)
        assert len(result.findings) > 0
        severity_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        severities = [
            severity_order.get(f.severity_computed or f.severity_base, 0) for f in result.findings
        ]
        assert severities == sorted(severities, reverse=True)

    def test_severity_computed_set(self) -> None:
        result = scan(FIXTURES / "vulnerable", platform="github", patterns_path=MINIMAL_PATTERNS)
        assert len(result.findings) > 0
        for f in result.findings:
            assert f.severity_computed is not None


class TestScanSafe:
    def test_safe_fixtures_clean(self) -> None:
        result = scan(FIXTURES / "safe", platform="github", patterns_path=MINIMAL_PATTERNS)
        assert result.findings == []
        assert result.exit_code == EXIT_CLEAN


class TestScanExitCodes:
    def test_clean_exit(self) -> None:
        result = scan(FIXTURES / "safe", platform="github", patterns_path=MINIMAL_PATTERNS)
        assert result.exit_code == EXIT_CLEAN

    def test_findings_exit(self) -> None:
        result = scan(FIXTURES / "vulnerable", platform="github", patterns_path=MINIMAL_PATTERNS)
        assert result.exit_code in (EXIT_FINDINGS, EXIT_CRITICAL)

    def test_fail_on_info(self) -> None:
        result = scan(
            FIXTURES / "vulnerable",
            platform="github",
            patterns_path=MINIMAL_PATTERNS,
            fail_on="info",
        )
        assert result.exit_code in (EXIT_FINDINGS, EXIT_CRITICAL)


class TestScanOutputFormats:
    def test_json_output(self) -> None:
        result = scan(
            FIXTURES / "vulnerable",
            platform="github",
            output_format="json",
            patterns_path=MINIMAL_PATTERNS,
        )
        assert '"findings"' in result.output_text

    def test_yaml_output(self) -> None:
        result = scan(
            FIXTURES / "vulnerable",
            platform="github",
            output_format="yaml",
            patterns_path=MINIMAL_PATTERNS,
        )
        assert "findings:" in result.output_text

    def test_sarif_output(self) -> None:
        result = scan(
            FIXTURES / "vulnerable",
            platform="github",
            output_format="sarif",
            patterns_path=MINIMAL_PATTERNS,
        )
        assert '"version": "2.1.0"' in result.output_text


class TestScanSuppression:
    def test_show_suppressed_includes_suppressed(self) -> None:
        result = scan(
            FIXTURES / "vulnerable",
            platform="github",
            profile_name="hardened",
            show_suppressed=True,
            patterns_path=MINIMAL_PATTERNS,
        )
        all_count = len(result.findings) + len(result.suppressed)
        assert all_count > 0

    def test_suppressed_excluded_by_default(self) -> None:
        normal = scan(FIXTURES / "vulnerable", platform="github", patterns_path=MINIMAL_PATTERNS)
        hardened = scan(
            FIXTURES / "vulnerable",
            platform="github",
            profile_name="hardened",
            patterns_path=MINIMAL_PATTERNS,
        )
        assert len(normal.findings) > 0
        assert len(hardened.findings) <= len(normal.findings)

    def test_elevation_boosts_severity(self) -> None:
        result = scan(
            FIXTURES / "vulnerable",
            platform="github",
            profile_name="self-hosted",
            patterns_path=MINIMAL_PATTERNS,
        )
        elevated = [
            f
            for f in result.findings
            if f.severity_computed and f.severity_computed != f.severity_base
        ]
        assert len(elevated) > 0


class TestScanNoProvider:
    def test_empty_dir_returns_clean(self, tmp_path: Path) -> None:
        result = scan(tmp_path)
        assert result.exit_code == EXIT_CLEAN
        assert result.findings == []


class TestCoverageNotes:
    def test_no_files_warns(self) -> None:
        notes = _coverage_notes(0, 1)
        assert len(notes) == 1
        assert "No pipeline files found" in notes[0]

    def test_single_file_single_provider_warns(self) -> None:
        notes = _coverage_notes(1, 1)
        assert len(notes) == 1
        assert "coverage may be incomplete" in notes[0]

    def test_multiple_files_no_note(self) -> None:
        assert _coverage_notes(2, 1) == []

    def test_single_file_multiple_providers_no_note(self) -> None:
        assert _coverage_notes(1, 2) == []

    def test_notes_in_scan_result(self, tmp_path: Path) -> None:
        result = scan(tmp_path)
        assert "No pipeline files found" in result.notes[0]


def _make_ref(raw: str, owner: str | None = None, name: str = "") -> ComponentRef:
    return ComponentRef(
        raw=raw,
        owner=owner,
        name=name,
        ref="",
        ref_type="unknown",
        is_pinned=False,
        is_first_party=False,
        line=0,
    )


class TestLocalActionPathTraversal:
    def test_normal_local_ref(self) -> None:
        assert _local_action_path(_make_ref("./.github/actions/foo")) == ".github/actions/foo"

    def test_rejects_parent_traversal(self) -> None:
        assert _local_action_path(_make_ref("./../sibling/ci")) is None

    def test_rejects_deep_traversal(self) -> None:
        assert _local_action_path(_make_ref("./../../other/ci")) is None

    def test_rejects_mid_path_traversal(self) -> None:
        assert _local_action_path(_make_ref("./actions/../../escape")) is None

    def test_dot_owner_rejects_traversal(self) -> None:
        assert _local_action_path(_make_ref(".", owner=".", name="../escape")) is None

    def test_non_local_returns_none(self) -> None:
        assert _local_action_path(_make_ref("actions/checkout@v4", owner="actions")) is None


class TestCompositeActionBoundaryCheck:
    def test_traversal_blocked(self, tmp_path: Path) -> None:
        sibling = tmp_path / "sibling" / "ci"
        sibling.mkdir(parents=True)
        (sibling / "action.yml").write_text("name: evil\nruns:\n  using: composite\n  steps: []\n")
        repo = tmp_path / "repo"
        repo.mkdir()
        steps, _ = _parse_composite_action(repo, "../sibling/ci")
        assert steps == []

    def test_normal_composite_resolves(self, tmp_path: Path) -> None:
        action_dir = tmp_path / ".github" / "actions" / "foo"
        action_dir.mkdir(parents=True)
        (action_dir / "action.yml").write_text(
            "name: test\nruns:\n  using: composite\n  steps:\n"
            "  - name: hi\n    run: echo hi\n    shell: bash\n"
        )
        steps, _ = _parse_composite_action(tmp_path, ".github/actions/foo")
        assert len(steps) == 1


class TestScanOutputFile:
    def test_writes_to_file(self, tmp_path: Path) -> None:
        out = tmp_path / "results.json"
        scan(
            FIXTURES / "vulnerable",
            platform="github",
            output_file=out,
            patterns_path=MINIMAL_PATTERNS,
        )
        assert out.exists()
        assert '"findings"' in out.read_text()
