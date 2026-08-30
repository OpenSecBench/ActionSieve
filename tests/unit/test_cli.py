from pathlib import Path

from click.testing import CliRunner

from actionsieve import __version__
from actionsieve.cli import main


class TestCLI:
    def test_version(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        assert __version__ in result.output

    def test_help(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "Multi-platform CI/CD pipeline security scanner" in result.output

    def test_scan_help(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["scan", "--help"])
        assert result.exit_code == 0
        assert "--platform" in result.output
        assert "--format" in result.output
        assert "--changed-since" in result.output
        assert "--changed-files" in result.output
        assert "--trigger" in result.output
        assert "--actor" in result.output
        assert "--context" in result.output
        assert "--mode" in result.output
        assert "--profile" in result.output
        assert "--fail-on" in result.output

    def test_inventory_help(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["inventory", "--help"])
        assert result.exit_code == 0
        assert "--check" in result.output
        assert "--platform" in result.output

    def test_scan_accepts_path(self, tmp_path: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["scan", str(tmp_path)])
        assert result.exit_code == 0

    def test_inventory_accepts_path(self, tmp_path: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["inventory", str(tmp_path)])
        assert result.exit_code == 0
