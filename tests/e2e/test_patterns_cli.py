import json
from pathlib import Path

import yaml
from click.testing import CliRunner

from actionsieve.cli import main

FIXTURES = Path(__file__).parent.parent / "fixtures" / "github"

CUSTOM_PATTERN = {
    "patterns": [
        {
            "id": "custom-test-pattern",
            "title": "Custom test pattern",
            "description": "Only matches this specific test string",
            "platforms": ["github"],
            "attacker_model": "fork_pr",
            "impact": "rce",
            "severity_base": "high",
            "detection": {
                "type": "single_step",
                "in_block": "run",
                "grep_patterns": ["${{ github.event.pull_request.title }}"],
            },
        }
    ]
}


class TestPatternsFlag:
    def test_custom_patterns_directory(self, tmp_path: Path) -> None:
        pat_dir = tmp_path / "patterns"
        pat_dir.mkdir()
        (pat_dir / "custom.yml").write_text(yaml.dump(CUSTOM_PATTERN))

        runner = CliRunner()
        result = runner.invoke(
            main,
            ["scan", "--patterns", str(pat_dir), str(FIXTURES / "vulnerable")],
        )

        data = json.loads(result.output)
        ids = {f["pattern_id"] for f in data["findings"]}
        assert "custom-test-pattern" in ids
        assert "mutable-action-ref" not in ids

    def test_custom_patterns_single_file(self, tmp_path: Path) -> None:
        pat_file = tmp_path / "custom.yml"
        pat_file.write_text(yaml.dump(CUSTOM_PATTERN))

        runner = CliRunner()
        result = runner.invoke(
            main,
            ["scan", "--patterns", str(pat_file), str(FIXTURES / "vulnerable")],
        )

        data = json.loads(result.output)
        ids = {f["pattern_id"] for f in data["findings"]}
        assert "custom-test-pattern" in ids

    def test_custom_patterns_no_match_clean(self, tmp_path: Path) -> None:
        no_match = {
            "patterns": [
                {
                    "id": "no-match-pattern",
                    "title": "Never matches",
                    "description": "Pattern that matches nothing",
                    "platforms": ["github"],
                    "attacker_model": "fork_pr",
                    "impact": "rce",
                    "severity_base": "high",
                    "detection": {
                        "type": "single_step",
                        "in_block": "run",
                        "grep_patterns": ["THIS_STRING_NEVER_APPEARS_ANYWHERE"],
                    },
                }
            ]
        }
        pat_file = tmp_path / "empty.yml"
        pat_file.write_text(yaml.dump(no_match))

        runner = CliRunner()
        result = runner.invoke(
            main,
            ["scan", "--patterns", str(pat_file), str(FIXTURES / "vulnerable")],
        )

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["findings"] == []
