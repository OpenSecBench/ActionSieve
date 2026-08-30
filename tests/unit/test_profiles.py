from pathlib import Path

import pytest

from actionsieve.profiles import BUILTIN_PROFILES, ProfileError, load_profile


class TestBuiltinPresets:
    def test_load_default(self) -> None:
        profile = load_profile()
        assert profile == {}

    def test_load_hosted_public(self) -> None:
        profile = load_profile("hosted-public")
        assert profile["runners"]["type"] == "ephemeral"
        assert profile["forks"]["policy"] == "open"

    def test_load_hosted_private(self) -> None:
        profile = load_profile("hosted-private")
        assert profile["forks"]["policy"] == "disabled"

    def test_load_self_hosted(self) -> None:
        profile = load_profile("self-hosted")
        assert profile["runners"]["type"] == "persistent"
        assert "self-hosted-runners" in profile.get("elevate", [])

    def test_load_hardened(self) -> None:
        profile = load_profile("hardened")
        assert profile["secrets"]["backend"] == "oidc"
        assert "self-hosted-runners" in profile.get("suppress", [])

    def test_all_presets_exist(self) -> None:
        expected = {"default", "hosted-public", "hosted-private", "self-hosted", "hardened"}
        assert set(BUILTIN_PROFILES.keys()) == expected

    def test_unknown_preset_raises(self) -> None:
        with pytest.raises(ProfileError, match="not found"):
            load_profile("nonexistent")


class TestLoadFromFile:
    def test_load_file(self, tmp_path: Path) -> None:
        profile_file = tmp_path / "profile.yml"
        profile_file.write_text(
            "profile:\n  runners:\n    type: ephemeral\n  forks:\n    policy: open\n"
        )
        profile = load_profile(str(profile_file))
        assert profile["runners"]["type"] == "ephemeral"

    def test_invalid_yaml(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.yml"
        bad.write_text("{{invalid")
        with pytest.raises(ProfileError, match="Invalid YAML"):
            load_profile(str(bad))

    def test_non_mapping(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.yml"
        bad.write_text("- item1\n")
        with pytest.raises(ProfileError, match="must be a mapping"):
            load_profile(str(bad))


class TestExtends:
    def test_extends_preset(self, tmp_path: Path) -> None:
        profile_file = tmp_path / "profile.yml"
        profile_file.write_text(
            "profile:\n"
            "  extends: self-hosted\n"
            "  runners:\n"
            "    isolation: container\n"
            "  secrets:\n"
            "    backend: vault\n"
        )
        profile = load_profile(str(profile_file))
        assert profile["runners"]["type"] == "persistent"
        assert profile["runners"]["isolation"] == "container"
        assert profile["secrets"]["backend"] == "vault"

    def test_extends_unknown_raises(self, tmp_path: Path) -> None:
        profile_file = tmp_path / "profile.yml"
        profile_file.write_text("profile:\n  extends: nonexistent\n")
        with pytest.raises(ProfileError, match="Unknown base profile"):
            load_profile(str(profile_file))


class TestAutoDiscovery:
    def test_repo_profile(self, tmp_path: Path) -> None:
        repo_profile = tmp_path / ".actionsieve.yml"
        repo_profile.write_text("profile:\n  forks:\n    policy: disabled\n")
        profile = load_profile(repo_path=tmp_path)
        assert profile["forks"]["policy"] == "disabled"

    def test_defaults_when_no_file(self, tmp_path: Path) -> None:
        profile = load_profile(repo_path=tmp_path)
        assert profile == {}
