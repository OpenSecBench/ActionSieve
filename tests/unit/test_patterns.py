from pathlib import Path

import pytest

from actionsieve.patterns import PatternError, load_patterns

PATTERNS_DIR = Path(__file__).parent.parent.parent / "patterns"


class TestLoadBuiltinPatterns:
    def test_loads_all_patterns(self) -> None:
        patterns = load_patterns()
        assert len(patterns) > 0

    def test_all_patterns_have_required_fields(self) -> None:
        for p in load_patterns():
            assert "id" in p, f"Pattern missing id: {p}"
            assert "title" in p, f"Pattern {p['id']} missing title"
            assert "platforms" in p, f"Pattern {p['id']} missing platforms"
            assert "severity_base" in p, f"Pattern {p['id']} missing severity_base"
            assert "detection" in p, f"Pattern {p['id']} missing detection"
            assert "attacker_model" in p, f"Pattern {p['id']} missing attacker_model"
            assert "impact" in p, f"Pattern {p['id']} missing impact"

    def test_all_ids_unique(self) -> None:
        patterns = load_patterns()
        ids = [p["id"] for p in patterns]
        assert len(ids) == len(set(ids))

    def test_all_ids_kebab_case(self) -> None:
        import re

        for p in load_patterns():
            assert re.match(r"^[a-z0-9][a-z0-9-]*$", p["id"]), f"Bad ID format: {p['id']}"

    def test_valid_severity_values(self) -> None:
        valid = {"critical", "high", "medium", "low", "info"}
        for p in load_patterns():
            assert p["severity_base"] in valid, f"Bad severity in {p['id']}: {p['severity_base']}"


class TestFilterByPlatform:
    def test_filter_github(self) -> None:
        github = load_patterns(platform="github")
        for p in github:
            platforms = p["platforms"]
            assert platforms == "all" or "github" in platforms

    def test_filter_removes_other_platforms(self) -> None:
        all_patterns = load_patterns()
        github = load_patterns(platform="github")
        assert len(github) <= len(all_patterns)

    def test_filter_nonexistent_platform(self) -> None:
        result = load_patterns(platform="nonexistent")
        all_platform = [p for p in load_patterns() if p.get("platforms") == "all"]
        assert len(result) == len(all_platform)


class TestLoadFromPath:
    def test_load_single_file(self) -> None:
        patterns = load_patterns(PATTERNS_DIR / "expression-injection.yml")
        assert len(patterns) > 0
        assert all("injection" in p["id"] or "script" in p["id"] for p in patterns)

    def test_load_directory(self) -> None:
        patterns = load_patterns(PATTERNS_DIR)
        assert len(patterns) > 0

    def test_nonexistent_path(self) -> None:
        with pytest.raises(PatternError, match="does not exist"):
            load_patterns(Path("/nonexistent/path"))


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
