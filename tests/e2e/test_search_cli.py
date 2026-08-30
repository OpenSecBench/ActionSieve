from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from actionsieve.cli import main
from actionsieve.search import SearchResult


class TestSearchCLI:
    def test_no_args_shows_error(self) -> None:
        result = CliRunner().invoke(main, ["search"])
        assert result.exit_code != 0
        assert "org/group name" in result.output or result.exit_code != 0

    def test_help(self) -> None:
        result = CliRunner().invoke(main, ["search", "--help"])
        assert result.exit_code == 0
        assert "--forge" in result.output
        assert "--token" in result.output
        assert "--pattern" in result.output

    @patch("actionsieve.search.search_org")
    @patch("actionsieve.search.get_backend")
    def test_org_search_output(self, mock_backend: MagicMock, mock_search: MagicMock) -> None:
        mock_backend.return_value = MagicMock(name="github")
        mock_search.return_value = iter(
            [
                SearchResult(
                    repo="org/repo1",
                    forge="github",
                    clone_url="https://github.com/org/repo1.git",
                    stars=42,
                    findings=[
                        {
                            "pattern_id": "expr-injection-run",
                            "severity": "high",
                        }
                    ],
                ),
            ]
        )
        result = CliRunner().invoke(main, ["search", "org"])
        assert result.exit_code == 0
        line = result.output.strip().split("\n")[0]
        data = json.loads(line)
        assert data["repo"] == "org/repo1"
        assert data["stars"] == 42
        assert len(data["findings"]) == 1

    @patch("actionsieve.search.search_pattern")
    @patch("actionsieve.search.get_backend")
    def test_pattern_search(self, mock_backend: MagicMock, mock_search: MagicMock) -> None:
        mock_backend.return_value = MagicMock(name="github")
        mock_search.return_value = iter([])
        result = CliRunner().invoke(main, ["search", "--pattern", "expr-injection-run"])
        assert result.exit_code == 0
        mock_search.assert_called_once()

    @patch("actionsieve.search.search_pattern")
    @patch("actionsieve.search.get_backend")
    def test_pattern_with_org(self, mock_backend: MagicMock, mock_search: MagicMock) -> None:
        mock_backend.return_value = MagicMock(name="github")
        mock_search.return_value = iter([])
        result = CliRunner().invoke(
            main,
            ["search", "myorg", "--pattern", "expr-injection-run"],
        )
        assert result.exit_code == 0
        call_args = mock_search.call_args
        assert call_args[1].get("org") == "myorg" or call_args[0][2] == "myorg"

    @patch("actionsieve.search.search_org")
    @patch("actionsieve.search.get_backend")
    def test_include_forks_flag(self, mock_backend: MagicMock, mock_search: MagicMock) -> None:
        mock_backend.return_value = MagicMock(name="github")
        mock_search.return_value = iter([])
        result = CliRunner().invoke(main, ["search", "org", "--include-forks"])
        assert result.exit_code == 0
        call_kwargs = mock_search.call_args[1]
        assert call_kwargs["skip_forks"] is False

    @patch("actionsieve.search.get_backend")
    def test_forge_gitlab(self, mock_backend: MagicMock) -> None:
        mock_backend.return_value = MagicMock(name="gitlab")
        mock_backend.return_value.list_repos.return_value = iter([])
        with patch("actionsieve.search.search_org") as mock_search:
            mock_search.return_value = iter([])
            result = CliRunner().invoke(main, ["search", "mygroup", "--forge", "gitlab"])
        assert result.exit_code == 0
        mock_backend.assert_called_once_with("gitlab", None)

    @patch("actionsieve.search.search_org")
    @patch("actionsieve.search.get_backend")
    def test_error_results_included(self, mock_backend: MagicMock, mock_search: MagicMock) -> None:
        mock_backend.return_value = MagicMock(name="github")
        mock_search.return_value = iter(
            [
                SearchResult(
                    repo="org/private",
                    forge="github",
                    clone_url="https://github.com/org/private.git",
                    stars=0,
                    error="Clone failed: permission denied",
                ),
            ]
        )
        result = CliRunner().invoke(main, ["search", "org"])
        line = result.output.strip().split("\n")[0]
        data = json.loads(line)
        assert data["error"] == "Clone failed: permission denied"

    @patch("actionsieve.search.search_org")
    @patch("actionsieve.search.get_backend")
    def test_multiple_results_streamed(
        self, mock_backend: MagicMock, mock_search: MagicMock
    ) -> None:
        mock_backend.return_value = MagicMock(name="github")
        mock_search.return_value = iter(
            [
                SearchResult(
                    repo="org/repo1",
                    forge="github",
                    clone_url="https://github.com/org/repo1.git",
                    stars=10,
                    findings=[{"pattern_id": "test"}],
                ),
                SearchResult(
                    repo="org/repo2",
                    forge="github",
                    clone_url="https://github.com/org/repo2.git",
                    stars=5,
                    findings=[{"pattern_id": "other"}],
                ),
            ]
        )
        result = CliRunner().invoke(main, ["search", "org"])
        lines = [line for line in result.output.strip().split("\n") if line.startswith("{")]
        assert len(lines) == 2
        assert json.loads(lines[0])["repo"] == "org/repo1"
        assert json.loads(lines[1])["repo"] == "org/repo2"
