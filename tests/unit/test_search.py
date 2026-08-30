from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from actionsieve.search import (
    GitHubBackend,
    GitLabBackend,
    RepoInfo,
    SearchError,
    SearchHit,
    SearchResult,
    _clone_and_scan,
    _finding_dict,
    _parse_github_hit,
    _parse_github_repo,
    _parse_gitlab_project,
    _RateLimiter,
    _resolve_token,
    get_backend,
    search_org,
    search_pattern,
)


class TestRepoInfo:
    def test_defaults(self) -> None:
        info = RepoInfo(
            owner="org",
            name="repo",
            full_name="org/repo",
            default_branch="main",
            clone_url="https://example.com/repo.git",
        )
        assert info.stars == 0
        assert info.is_fork is False


class TestRateLimiter:
    def test_first_call_no_delay(self) -> None:
        rl = _RateLimiter(1.0)
        rl.wait()
        assert rl._last > 0

    def test_respects_interval(self) -> None:
        rl = _RateLimiter(0.01)
        rl.wait()
        first = rl._last
        rl.wait()
        assert rl._last >= first + 0.01


class TestParseGithubRepo:
    def test_valid_repo(self) -> None:
        data = {
            "owner": {"login": "myorg"},
            "name": "myrepo",
            "full_name": "myorg/myrepo",
            "default_branch": "main",
            "clone_url": "https://github.com/myorg/myrepo.git",
            "stargazers_count": 42,
            "fork": False,
        }
        info = _parse_github_repo(data, "fallback")
        assert info is not None
        assert info.owner == "myorg"
        assert info.name == "myrepo"
        assert info.stars == 42

    def test_fallback_org(self) -> None:
        data = {
            "name": "myrepo",
            "full_name": "fallback/myrepo",
            "default_branch": "main",
            "clone_url": "https://github.com/fallback/myrepo.git",
        }
        info = _parse_github_repo(data, "fallback")
        assert info is not None
        assert info.owner == "fallback"

    def test_non_dict_returns_none(self) -> None:
        assert _parse_github_repo("not a dict", "org") is None

    def test_fork_detected(self) -> None:
        data = {
            "owner": {"login": "org"},
            "name": "repo",
            "full_name": "org/repo",
            "default_branch": "main",
            "clone_url": "https://github.com/org/repo.git",
            "fork": True,
        }
        info = _parse_github_repo(data, "org")
        assert info is not None
        assert info.is_fork is True


class TestParseGithubHit:
    def test_valid_hit(self) -> None:
        item = {
            "path": ".github/workflows/ci.yml",
            "repository": {
                "owner": {"login": "org"},
                "name": "repo",
                "full_name": "org/repo",
                "default_branch": "main",
                "clone_url": "https://github.com/org/repo.git",
            },
        }
        hit = _parse_github_hit(item)
        assert hit is not None
        assert hit.file_path == ".github/workflows/ci.yml"
        assert hit.repo.full_name == "org/repo"

    def test_non_dict_returns_none(self) -> None:
        assert _parse_github_hit("bad") is None

    def test_missing_repository(self) -> None:
        assert _parse_github_hit({"path": "test"}) is None


class TestParseGitlabProject:
    def test_valid_project(self) -> None:
        data = {
            "namespace": {"full_path": "mygroup"},
            "path": "myproject",
            "path_with_namespace": "mygroup/myproject",
            "default_branch": "main",
            "http_url_to_repo": "https://gitlab.com/mygroup/myproject.git",
            "star_count": 10,
        }
        info = _parse_gitlab_project(data, "fallback")
        assert info is not None
        assert info.owner == "mygroup"
        assert info.name == "myproject"
        assert info.stars == 10

    def test_non_dict_returns_none(self) -> None:
        assert _parse_gitlab_project("bad", "grp") is None

    def test_forked_project(self) -> None:
        data = {
            "namespace": {"full_path": "grp"},
            "path": "proj",
            "path_with_namespace": "grp/proj",
            "default_branch": "main",
            "http_url_to_repo": "https://gitlab.com/grp/proj.git",
            "forked_from_project": {"id": 123},
        }
        info = _parse_gitlab_project(data, "grp")
        assert info is not None
        assert info.is_fork is True


class TestResolveToken:
    def test_explicit_wins(self) -> None:
        assert _resolve_token("github", "my-token") == "my-token"

    def test_actionsieve_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ACTIONSIEVE_GITHUB_TOKEN", "as-token")
        assert _resolve_token("github", None) == "as-token"

    def test_platform_env_fallback(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("GITHUB_TOKEN", "gh-token")
        assert _resolve_token("github", None) == "gh-token"

    def test_actionsieve_takes_precedence(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ACTIONSIEVE_GITHUB_TOKEN", "as-token")
        monkeypatch.setenv("GITHUB_TOKEN", "gh-token")
        assert _resolve_token("github", None) == "as-token"

    def test_no_token(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("ACTIONSIEVE_GITHUB_TOKEN", raising=False)
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)
        assert _resolve_token("github", None) is None


class TestGetBackend:
    def test_github(self) -> None:
        backend = get_backend("github", "token")
        assert backend.name == "github"

    def test_gitlab(self) -> None:
        backend = get_backend("gitlab", "token")
        assert backend.name == "gitlab"

    def test_unknown_raises(self) -> None:
        with pytest.raises(SearchError, match="Unknown forge"):
            get_backend("bitbucket")


class TestGitHubBackend:
    def test_search_code_requires_token(self) -> None:
        backend = GitHubBackend(token=None)
        with pytest.raises(SearchError, match="requires authentication"):
            list(backend.search_code("test query"))

    @patch("actionsieve.search._api_get")
    def test_list_repos_pagination(self, mock_get: MagicMock) -> None:
        page1 = [
            {
                "owner": {"login": "org"},
                "name": f"repo-{i}",
                "full_name": f"org/repo-{i}",
                "default_branch": "main",
                "clone_url": f"https://github.com/org/repo-{i}.git",
                "stargazers_count": i,
            }
            for i in range(100)
        ]
        page2 = [
            {
                "owner": {"login": "org"},
                "name": "repo-100",
                "full_name": "org/repo-100",
                "default_branch": "main",
                "clone_url": "https://github.com/org/repo-100.git",
                "stargazers_count": 100,
            }
        ]
        mock_get.side_effect = [page1, page2]
        backend = GitHubBackend(token="tok")
        repos = list(backend.list_repos("org"))
        assert len(repos) == 101
        assert mock_get.call_count == 2

    @patch("actionsieve.search._api_get")
    def test_list_repos_empty(self, mock_get: MagicMock) -> None:
        mock_get.return_value = []
        backend = GitHubBackend(token="tok")
        repos = list(backend.list_repos("org"))
        assert repos == []

    @patch("actionsieve.search._api_get")
    def test_search_code_dedup_pages(self, mock_get: MagicMock) -> None:
        mock_get.return_value = {
            "total_count": 1,
            "items": [
                {
                    "path": ".github/workflows/ci.yml",
                    "repository": {
                        "owner": {"login": "org"},
                        "name": "repo",
                        "full_name": "org/repo",
                        "default_branch": "main",
                        "clone_url": "https://github.com/org/repo.git",
                    },
                }
            ],
        }
        backend = GitHubBackend(token="tok")
        hits = list(backend.search_code("test query"))
        assert len(hits) == 1
        assert hits[0].repo.full_name == "org/repo"

    @patch("actionsieve.search._api_get")
    def test_search_code_org_scoped(self, mock_get: MagicMock) -> None:
        mock_get.return_value = {"total_count": 0, "items": []}
        backend = GitHubBackend(token="tok")
        list(backend.search_code("test", org="myorg"))
        called_url = mock_get.call_args[0][0]
        assert "org%3Amyorg" in called_url


class TestGitLabBackend:
    @patch("actionsieve.search._api_get")
    def test_list_repos(self, mock_get: MagicMock) -> None:
        mock_get.return_value = [
            {
                "namespace": {"full_path": "mygroup"},
                "path": "myproject",
                "path_with_namespace": "mygroup/myproject",
                "default_branch": "main",
                "http_url_to_repo": "https://gitlab.com/mygroup/myproject.git",
                "star_count": 5,
            }
        ]
        backend = GitLabBackend(token="tok")
        repos = list(backend.list_repos("mygroup"))
        assert len(repos) == 1
        assert repos[0].full_name == "mygroup/myproject"

    @patch("actionsieve.search._api_get")
    def test_search_code_with_cache(self, mock_get: MagicMock) -> None:
        blob_response = [
            {"project_id": 42, "filename": ".gitlab-ci.yml"},
            {"project_id": 42, "filename": "other.yml"},
        ]
        project_response = {
            "namespace": {"full_path": "grp"},
            "path": "proj",
            "path_with_namespace": "grp/proj",
            "default_branch": "main",
            "http_url_to_repo": "https://gitlab.com/grp/proj.git",
            "star_count": 3,
        }
        mock_get.side_effect = [blob_response, project_response]
        backend = GitLabBackend(token="tok")
        hits = list(backend.search_code("CI_MERGE_REQUEST_TITLE"))
        assert len(hits) == 1
        assert mock_get.call_count == 2


class TestFindingDict:
    def test_converts_finding(self) -> None:
        from actionsieve.engine import Finding

        f = Finding(
            pattern_id="test-pattern",
            pattern_title="Test Pattern",
            file_path=".github/workflows/ci.yml",
            platform="github",
            line=10,
            job_id="build",
            step_index=0,
            severity_base="high",
            attacker_model="fork_pr",
            impact="rce",
            severity_computed="critical",
        )
        d = _finding_dict(f)
        assert d["pattern_id"] == "test-pattern"
        assert d["severity"] == "critical"
        assert d["severity_base"] == "high"

    def test_fallback_severity(self) -> None:
        from actionsieve.engine import Finding

        f = Finding(
            pattern_id="test",
            pattern_title="Test",
            file_path="ci.yml",
            platform="github",
            line=1,
            job_id="build",
            step_index=0,
            severity_base="medium",
            attacker_model="contributor",
            impact="info_disclosure",
        )
        d = _finding_dict(f)
        assert d["severity"] == "medium"


class TestCloneAndScan:
    @patch("actionsieve.scanner.scan")
    @patch("subprocess.run")
    def test_clone_failure(self, mock_run: MagicMock, mock_scan: MagicMock) -> None:
        import subprocess

        mock_run.side_effect = subprocess.CalledProcessError(128, "git clone")
        repo = RepoInfo(
            owner="org",
            name="repo",
            full_name="org/repo",
            default_branch="main",
            clone_url="https://github.com/org/repo.git",
        )
        result = _clone_and_scan(repo, "github")
        assert result.error is not None
        assert "Clone failed" in result.error
        mock_scan.assert_not_called()

    @patch("actionsieve.scanner.scan")
    @patch("subprocess.run")
    def test_scan_error(self, mock_run: MagicMock, mock_scan: MagicMock) -> None:
        mock_run.return_value = MagicMock(returncode=0)
        mock_scan.side_effect = RuntimeError("parse error")
        repo = RepoInfo(
            owner="org",
            name="repo",
            full_name="org/repo",
            default_branch="main",
            clone_url="https://github.com/org/repo.git",
        )
        result = _clone_and_scan(repo, "github")
        assert result.error is not None
        assert "Scan error" in result.error

    @patch("actionsieve.scanner.scan")
    @patch("subprocess.run")
    def test_successful_scan(self, mock_run: MagicMock, mock_scan: MagicMock) -> None:
        from actionsieve.engine import Finding
        from actionsieve.scanner import ScanResult

        mock_run.return_value = MagicMock(returncode=0)
        finding = Finding(
            pattern_id="test-pattern",
            pattern_title="Test",
            file_path="ci.yml",
            platform="github",
            line=1,
            job_id="build",
            step_index=0,
            severity_base="high",
            attacker_model="fork_pr",
            impact="rce",
        )
        mock_scan.return_value = ScanResult(
            findings=[finding],
            suppressed=[],
            exit_code=1,
            output_text="",
        )
        repo = RepoInfo(
            owner="org",
            name="repo",
            full_name="org/repo",
            default_branch="main",
            clone_url="https://github.com/org/repo.git",
        )
        result = _clone_and_scan(repo, "github")
        assert result.error is None
        assert len(result.findings) == 1
        assert result.findings[0]["pattern_id"] == "test-pattern"

    @patch("actionsieve.scanner.scan")
    @patch("subprocess.run")
    def test_filter_pattern(self, mock_run: MagicMock, mock_scan: MagicMock) -> None:
        from actionsieve.engine import Finding
        from actionsieve.scanner import ScanResult

        mock_run.return_value = MagicMock(returncode=0)
        findings = [
            Finding(
                pattern_id="target",
                pattern_title="Target",
                file_path="ci.yml",
                platform="github",
                line=1,
                job_id="build",
                step_index=0,
                severity_base="high",
                attacker_model="fork_pr",
                impact="rce",
            ),
            Finding(
                pattern_id="other",
                pattern_title="Other",
                file_path="ci.yml",
                platform="github",
                line=5,
                job_id="build",
                step_index=1,
                severity_base="medium",
                attacker_model="contributor",
                impact="info_disclosure",
            ),
        ]
        mock_scan.return_value = ScanResult(
            findings=findings,
            suppressed=[],
            exit_code=1,
            output_text="",
        )
        repo = RepoInfo(
            owner="org",
            name="repo",
            full_name="org/repo",
            default_branch="main",
            clone_url="https://github.com/org/repo.git",
        )
        result = _clone_and_scan(repo, "github", filter_pattern="target")
        assert len(result.findings) == 1
        assert result.findings[0]["pattern_id"] == "target"


class TestSearchOrg:
    @patch("actionsieve.search._clone_and_scan")
    def test_skips_forks(self, mock_scan: MagicMock) -> None:
        mock_backend = MagicMock()
        mock_backend.name = "github"
        repos = [
            RepoInfo(
                owner="org",
                name="repo1",
                full_name="org/repo1",
                default_branch="main",
                clone_url="https://github.com/org/repo1.git",
                is_fork=False,
            ),
            RepoInfo(
                owner="org",
                name="fork-repo",
                full_name="org/fork-repo",
                default_branch="main",
                clone_url="https://github.com/org/fork-repo.git",
                is_fork=True,
            ),
        ]
        mock_backend.list_repos.return_value = iter(repos)
        mock_scan.return_value = SearchResult(
            repo="org/repo1",
            forge="github",
            clone_url="https://github.com/org/repo1.git",
            stars=0,
            findings=[{"pattern_id": "test"}],
        )
        results = list(search_org(mock_backend, "org"))
        assert len(results) == 1
        mock_scan.assert_called_once()

    @patch("actionsieve.search._clone_and_scan")
    def test_includes_forks_when_requested(self, mock_scan: MagicMock) -> None:
        mock_backend = MagicMock()
        mock_backend.name = "github"
        repos = [
            RepoInfo(
                owner="org",
                name="repo1",
                full_name="org/repo1",
                default_branch="main",
                clone_url="https://github.com/org/repo1.git",
                is_fork=True,
            ),
        ]
        mock_backend.list_repos.return_value = iter(repos)
        mock_scan.return_value = SearchResult(
            repo="org/repo1",
            forge="github",
            clone_url="https://github.com/org/repo1.git",
            stars=0,
            findings=[{"pattern_id": "test"}],
        )
        results = list(search_org(mock_backend, "org", skip_forks=False))
        assert len(results) == 1

    @patch("actionsieve.search._clone_and_scan")
    def test_skips_clean_repos(self, mock_scan: MagicMock) -> None:
        mock_backend = MagicMock()
        mock_backend.name = "github"
        repos = [
            RepoInfo(
                owner="org",
                name="clean",
                full_name="org/clean",
                default_branch="main",
                clone_url="https://github.com/org/clean.git",
            ),
        ]
        mock_backend.list_repos.return_value = iter(repos)
        mock_scan.return_value = SearchResult(
            repo="org/clean",
            forge="github",
            clone_url="https://github.com/org/clean.git",
            stars=0,
            findings=[],
        )
        results = list(search_org(mock_backend, "org"))
        assert len(results) == 0


class TestSearchPattern:
    @patch("actionsieve.search._clone_and_scan")
    @patch("actionsieve.providers.get_provider")
    @patch("actionsieve.patterns.load_patterns")
    def test_deduplicates_repos(
        self,
        mock_load: MagicMock,
        mock_provider: MagicMock,
        mock_scan: MagicMock,
    ) -> None:
        mock_load.return_value = [{"id": "test-pattern", "detection": {}}]
        provider = MagicMock()
        provider.search_query.return_value = '"test" language:yaml'
        mock_provider.return_value = provider

        repo = RepoInfo(
            owner="org",
            name="repo",
            full_name="org/repo",
            default_branch="main",
            clone_url="https://github.com/org/repo.git",
        )
        mock_backend = MagicMock()
        mock_backend.name = "github"
        mock_backend.search_code.return_value = iter(
            [
                SearchHit(repo=repo, file_path="ci.yml"),
                SearchHit(repo=repo, file_path="ci2.yml"),
            ]
        )

        mock_scan.return_value = SearchResult(
            repo="org/repo",
            forge="github",
            clone_url="https://github.com/org/repo.git",
            stars=0,
            findings=[{"pattern_id": "test-pattern"}],
        )

        results = list(search_pattern(mock_backend, "test-pattern"))
        assert len(results) == 1
        mock_scan.assert_called_once()

    @patch("actionsieve.providers.get_provider")
    @patch("actionsieve.patterns.load_patterns")
    def test_pattern_not_found(
        self,
        mock_load: MagicMock,
        mock_provider: MagicMock,
    ) -> None:
        mock_load.return_value = [{"id": "other-pattern"}]
        mock_provider.return_value = MagicMock()
        mock_backend = MagicMock()
        mock_backend.name = "github"
        with pytest.raises(SearchError, match="Pattern not found"):
            list(search_pattern(mock_backend, "nonexistent"))

    @patch("actionsieve.providers.get_provider")
    @patch("actionsieve.patterns.load_patterns")
    def test_no_grep_patterns(
        self,
        mock_load: MagicMock,
        mock_provider: MagicMock,
    ) -> None:
        mock_load.return_value = [{"id": "test-pattern", "detection": {}}]
        provider = MagicMock()
        provider.search_query.return_value = None
        mock_provider.return_value = provider
        mock_backend = MagicMock()
        mock_backend.name = "github"
        with pytest.raises(SearchError, match="no searchable"):
            list(search_pattern(mock_backend, "test-pattern"))
