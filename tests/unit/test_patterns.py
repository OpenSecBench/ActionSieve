from pathlib import Path

import pytest

from actionsieve.patterns import PatternError, load_patterns

VALID_BASE = (
    "patterns:\n"
    "  - id: diff-test\n"
    "    title: Test\n"
    "    description: Test\n"
    "    platforms: all\n"
    "    attacker_model: any\n"
    "    impact: rce\n"
    "    severity_base: high\n"
    "    detection:\n"
    "      type: single_step\n"
)


class TestValidation:
    def test_reject_invalid_yaml(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.yml"
        bad.write_text("{{invalid")
        with pytest.raises(PatternError, match="Invalid YAML"):
            load_patterns(bad)

    def test_reject_missing_patterns_key(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.yml"
        bad.write_text("rules:\n  - id: test\n")
        with pytest.raises(PatternError, match="Missing 'patterns' key"):
            load_patterns(bad)

    def test_reject_duplicate_ids(self, tmp_path: Path) -> None:
        f1 = tmp_path / "a.yml"
        f2 = tmp_path / "b.yml"
        f1.write_text(
            "patterns:\n"
            "  - id: dupe-test\n"
            "    title: Test\n"
            "    description: Test\n"
            "    platforms: all\n"
            "    attacker_model: any\n"
            "    impact: rce\n"
            "    severity_base: high\n"
            "    detection:\n"
            "      type: single_step\n"
        )
        f2.write_text(
            "patterns:\n"
            "  - id: dupe-test\n"
            "    title: Test2\n"
            "    description: Test2\n"
            "    platforms: all\n"
            "    attacker_model: any\n"
            "    impact: rce\n"
            "    severity_base: high\n"
            "    detection:\n"
            "      type: single_step\n"
        )
        with pytest.raises(PatternError, match="Duplicate pattern ID"):
            load_patterns(tmp_path)

    def test_reject_invalid_schema(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.yml"
        bad.write_text("patterns:\n  - id: test\n    title: Test\n")
        with pytest.raises(PatternError, match="Schema validation failed"):
            load_patterns(bad)


class TestDiffScopeSchema:
    def test_diff_scope_always_valid(self, tmp_path: Path) -> None:
        f = tmp_path / "p.yml"
        f.write_text(VALID_BASE + "    diff_scope: always\n")
        patterns = load_patterns(f)
        assert patterns[0]["diff_scope"] == "always"

    def test_diff_scope_changeset_with_required_fields(self, tmp_path: Path) -> None:
        f = tmp_path / "p.yml"
        f.write_text(
            VALID_BASE
            + "    diff_scope: changeset\n"
            + "    diff_effect: suppress\n"
            + "    reachable_files:\n"
            + '      - "Dockerfile*"\n'
        )
        patterns = load_patterns(f)
        assert patterns[0]["diff_scope"] == "changeset"
        assert patterns[0]["diff_effect"] == "suppress"
        assert patterns[0]["reachable_files"] == ["Dockerfile*"]

    def test_diff_scope_changeset_elevate(self, tmp_path: Path) -> None:
        f = tmp_path / "p.yml"
        f.write_text(
            VALID_BASE
            + "    diff_scope: changeset\n"
            + "    diff_effect: elevate\n"
            + "    reachable_files:\n"
            + '      - ".github/workflows/*.yml"\n'
        )
        patterns = load_patterns(f)
        assert patterns[0]["diff_effect"] == "elevate"

    def test_diff_scope_changeset_missing_effect_rejected(self, tmp_path: Path) -> None:
        f = tmp_path / "p.yml"
        f.write_text(
            VALID_BASE
            + "    diff_scope: changeset\n"
            + "    reachable_files:\n"
            + '      - "Dockerfile*"\n'
        )
        with pytest.raises(PatternError, match="Schema validation failed"):
            load_patterns(f)

    def test_diff_scope_changeset_missing_reachable_rejected(self, tmp_path: Path) -> None:
        f = tmp_path / "p.yml"
        f.write_text(VALID_BASE + "    diff_scope: changeset\n" + "    diff_effect: suppress\n")
        with pytest.raises(PatternError, match="Schema validation failed"):
            load_patterns(f)

    def test_no_diff_scope_valid(self, tmp_path: Path) -> None:
        f = tmp_path / "p.yml"
        f.write_text(VALID_BASE)
        patterns = load_patterns(f)
        assert "diff_scope" not in patterns[0]

    def test_invalid_diff_scope_value_rejected(self, tmp_path: Path) -> None:
        f = tmp_path / "p.yml"
        f.write_text(VALID_BASE + "    diff_scope: invalid\n")
        with pytest.raises(PatternError, match="Schema validation failed"):
            load_patterns(f)


class TestNoPathError:
    def test_no_path_no_env_raises(self) -> None:
        import os

        env = os.environ.pop("ACTIONSIEVE_PATTERNS", None)
        try:
            with pytest.raises(PatternError, match="No patterns path"):
                load_patterns()
        finally:
            if env is not None:
                os.environ["ACTIONSIEVE_PATTERNS"] = env

    def test_nonexistent_path(self) -> None:
        with pytest.raises(PatternError, match="does not exist"):
            load_patterns(Path("/nonexistent/path"))
