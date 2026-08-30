import json
from pathlib import Path

import yaml
from click.testing import CliRunner

from actionsieve.cli import main

FIXTURES = Path(__file__).parent.parent / "fixtures" / "github"


class TestInventoryCommand:
    def test_inventory_json(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["inventory", str(FIXTURES / "vulnerable")])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "summary" in data
        assert "components" in data
        assert data["summary"]["total_refs"] > 0

    def test_inventory_yaml(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main, ["inventory", "--format", "yaml", str(FIXTURES / "vulnerable")]
        )
        assert result.exit_code == 0
        data = yaml.safe_load(result.output)
        assert "summary" in data
        assert "components" in data

    def test_inventory_cyclonedx(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main, ["inventory", "--format", "cyclonedx", str(FIXTURES / "vulnerable")]
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["bomFormat"] == "CycloneDX"
        assert data["specVersion"] == "1.5"
        assert len(data["components"]) > 0

    def test_inventory_output_file(self, tmp_path: Path) -> None:
        out = tmp_path / "bom.json"
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["inventory", "--output", str(out), str(FIXTURES / "vulnerable")],
        )
        assert result.exit_code == 0
        assert out.exists()
        data = json.loads(out.read_text())
        assert len(data["components"]) > 0

    def test_inventory_empty_dir(self, tmp_path: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["inventory", str(tmp_path)])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["summary"]["total_refs"] == 0

    def test_inventory_platform_filter(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["inventory", "--platform", "github", str(FIXTURES / "vulnerable")],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["summary"]["total_refs"] > 0


class TestInventoryCheck:
    def test_check_finds_advisory(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["inventory", "--check", str(FIXTURES / "vulnerable")],
        )
        assert result.exit_code == 3
        data = json.loads(result.output)
        assert data["summary"]["advisory_matches"] > 0

    def test_check_safe_no_advisory(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["inventory", "--check", str(FIXTURES / "safe")],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["summary"]["advisory_matches"] == 0


class TestInventoryTrust:
    def test_trust_scores_in_output(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["inventory", str(FIXTURES / "vulnerable")])
        data = json.loads(result.output)
        for comp in data["components"]:
            assert "trust_score" in comp

    def test_pinned_actions_higher_trust(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["inventory", str(FIXTURES / "safe")])
        data = json.loads(result.output)
        for comp in data["components"]:
            if comp["is_pinned"] and comp["is_first_party"]:
                assert comp["trust_score"] == "high"


class TestInventoryOnlineFlag:
    def test_online_offline_mutually_exclusive(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["inventory", "--online", "--offline", str(FIXTURES / "safe")],
        )
        assert result.exit_code != 0
        assert "mutually exclusive" in result.output

    def test_online_flag_in_help(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["inventory", "--help"])
        assert "--online" in result.output
        assert "--token" in result.output


class TestExcludeLocal:
    def test_exclude_local_removes_dot_refs(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main, ["inventory", "--exclude-local", str(FIXTURES / "vulnerable")]
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        for comp in data["components"]:
            assert not comp["ref"].startswith("./")

    def test_exclude_local_in_help(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["inventory", "--help"])
        assert "--exclude-local" in result.output
        assert "--repo" in result.output


class TestRepoMetadata:
    def test_repo_flag_in_output(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["inventory", "--repo", "github.com/org/repo", str(FIXTURES / "vulnerable")],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["summary"]["repo"] == "github.com/org/repo"

    def test_repo_in_cyclonedx_metadata(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "inventory",
                "--format",
                "cyclonedx",
                "--repo",
                "github.com/org/repo",
                str(FIXTURES / "vulnerable"),
            ],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["metadata"]["component"]["name"] == "github.com/org/repo"


class TestCycloneDxFormat:
    def test_purl_format(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["inventory", "--format", "cyclonedx", str(FIXTURES / "vulnerable")],
        )
        data = json.loads(result.output)
        for comp in data["components"]:
            assert comp["purl"].startswith("pkg:githubactions/")

    def test_cyclonedx_excludes_local_refs(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["inventory", "--format", "cyclonedx", str(FIXTURES / "vulnerable")],
        )
        data = json.loads(result.output)
        for comp in data["components"]:
            assert not comp["name"].startswith(".")

    def test_cyclonedx_has_timestamp(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["inventory", "--format", "cyclonedx", str(FIXTURES / "vulnerable")],
        )
        data = json.loads(result.output)
        assert "timestamp" in data["metadata"]

    def test_cyclonedx_has_platform_property(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["inventory", "--format", "cyclonedx", str(FIXTURES / "vulnerable")],
        )
        data = json.loads(result.output)
        comp = data["components"][0]
        prop_names = [p["name"] for p in comp["properties"]]
        assert "actionsieve:platform" in prop_names

    def test_actionsieve_properties(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["inventory", "--format", "cyclonedx", str(FIXTURES / "vulnerable")],
        )
        data = json.loads(result.output)
        comp = data["components"][0]
        prop_names = [p["name"] for p in comp["properties"]]
        assert "actionsieve:ref_type" in prop_names
        assert "actionsieve:is_pinned" in prop_names
