"""Forge-wide code search — query forge APIs, clone candidates, scan locally."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from collections.abc import Iterator

    from actionsieve.engine import Finding


class SearchError(Exception):
    pass


@dataclass
class RepoInfo:
    owner: str
    name: str
    full_name: str
    default_branch: str
    clone_url: str
    stars: int = 0
    is_fork: bool = False


@dataclass
class SearchHit:
    repo: RepoInfo
    file_path: str


@dataclass
class SearchResult:
    repo: str
    forge: str
    clone_url: str
    stars: int
    findings: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None


class ForgeBackend(Protocol):
    name: str

    def list_repos(self, org: str) -> Iterator[RepoInfo]: ...

    def search_code(self, query: str, org: str | None = None) -> Iterator[SearchHit]: ...


class _RateLimiter:
    def __init__(self, min_interval: float) -> None:
        self._min_interval = min_interval
        self._last = 0.0

    def wait(self) -> None:
        now = time.monotonic()
        gap = self._min_interval - (now - self._last)
        if gap > 0:
            time.sleep(gap)
        self._last = time.monotonic()


def _api_get(url: str, headers: dict[str, str]) -> Any:
    req = urllib.request.Request(url)  # noqa: S310
    for k, v in headers.items():
        req.add_header(k, v)
    with urllib.request.urlopen(req) as resp:  # noqa: S310
        return json.loads(resp.read())


class GitHubBackend:
    name = "github"

    def __init__(self, token: str | None = None) -> None:
        self._token = token
        self._rate = _RateLimiter(2.0 if token else 60.0)
        self._headers: dict[str, str] = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if token:
            self._headers["Authorization"] = f"Bearer {token}"

    def list_repos(self, org: str) -> Iterator[RepoInfo]:
        page = 1
        while True:
            encoded = urllib.parse.quote(org, safe="")
            url = (
                f"https://api.github.com/orgs/{encoded}/repos?per_page=100&page={page}&sort=pushed"
            )
            data = self._get(url)
            if not isinstance(data, list) or not data:
                break
            for repo in data:
                info = _parse_github_repo(repo, org)
                if info:
                    yield info
            if len(data) < 100:
                break
            page += 1

    def search_code(self, query: str, org: str | None = None) -> Iterator[SearchHit]:
        if not self._token:
            raise SearchError(
                "GitHub code search requires authentication (--token or GITHUB_TOKEN)"
            )
        full_query = f"org:{org} {query}" if org else query
        page = 1
        while True:
            encoded = urllib.parse.quote(full_query, safe="")
            url = f"https://api.github.com/search/code?q={encoded}&per_page=100&page={page}"
            data = self._get(url)
            if not isinstance(data, dict):
                break
            items = data.get("items")
            if not isinstance(items, list) or not items:
                break
            for item in items:
                hit = _parse_github_hit(item)
                if hit:
                    yield hit
            total = data.get("total_count", 0)
            if not isinstance(total, int):
                break
            if page * 100 >= total or page >= 10:
                break
            page += 1

    def _get(self, url: str) -> Any:
        self._rate.wait()
        try:
            return _api_get(url, self._headers)
        except urllib.error.HTTPError as e:
            if e.code == 403:
                retry = e.headers.get("Retry-After")
                if retry:
                    time.sleep(min(float(retry), 120))
                    return self._get(url)
            if e.code in (404, 422):
                return None
            raise SearchError(f"GitHub API {e.code}: {url}") from e
        except urllib.error.URLError as e:
            raise SearchError(f"Network error: {e.reason}") from e


def _parse_github_repo(data: Any, fallback_org: str) -> RepoInfo | None:
    if not isinstance(data, dict):
        return None
    owner = data.get("owner", {})
    login = owner.get("login", fallback_org) if isinstance(owner, dict) else fallback_org
    return RepoInfo(
        owner=login,
        name=data.get("name", ""),
        full_name=data.get("full_name", ""),
        default_branch=data.get("default_branch", "main"),
        clone_url=data.get("clone_url", ""),
        stars=data.get("stargazers_count", 0),
        is_fork=bool(data.get("fork")),
    )


def _parse_github_hit(item: Any) -> SearchHit | None:
    if not isinstance(item, dict):
        return None
    repo = _parse_github_repo(item.get("repository"), "")
    if not repo:
        return None
    return SearchHit(repo=repo, file_path=item.get("path", ""))


class GitLabBackend:
    name = "gitlab"

    def __init__(self, token: str | None = None, base_url: str = "https://gitlab.com") -> None:
        self._token = token
        self._base = base_url.rstrip("/")
        self._rate = _RateLimiter(0.2)
        self._headers: dict[str, str] = {}
        if token:
            self._headers["PRIVATE-TOKEN"] = token
        self._project_cache: dict[int, RepoInfo | None] = {}

    def list_repos(self, group: str) -> Iterator[RepoInfo]:
        page = 1
        encoded = urllib.parse.quote(group, safe="")
        while True:
            url = (
                f"{self._base}/api/v4/groups/{encoded}/projects"
                f"?per_page=100&page={page}&include_subgroups=true"
                f"&order_by=last_activity_at"
            )
            data = self._get(url)
            if not isinstance(data, list) or not data:
                break
            for proj in data:
                info = _parse_gitlab_project(proj, group)
                if info:
                    yield info
            if len(data) < 100:
                break
            page += 1

    def search_code(self, query: str, org: str | None = None) -> Iterator[SearchHit]:
        if org:
            encoded = urllib.parse.quote(org, safe="")
            base = f"{self._base}/api/v4/groups/{encoded}/search"
        else:
            base = f"{self._base}/api/v4/search"
        page = 1
        seen: set[str] = set()
        while True:
            encoded_q = urllib.parse.quote(query, safe="")
            url = f"{base}?scope=blobs&search={encoded_q}&per_page=20&page={page}"
            data = self._get(url)
            if not isinstance(data, list) or not data:
                break
            for blob in data:
                if not isinstance(blob, dict):
                    continue
                proj_id = blob.get("project_id")
                if not isinstance(proj_id, int):
                    continue
                repo = self._resolve_project(proj_id)
                if not repo or repo.full_name in seen:
                    continue
                seen.add(repo.full_name)
                yield SearchHit(repo=repo, file_path=blob.get("filename", ""))
            if len(data) < 20:
                break
            page += 1
            if page > 100:
                break

    def _resolve_project(self, project_id: int) -> RepoInfo | None:
        if project_id in self._project_cache:
            return self._project_cache[project_id]
        url = f"{self._base}/api/v4/projects/{project_id}"
        data = self._get(url)
        info = _parse_gitlab_project(data, "") if isinstance(data, dict) else None
        self._project_cache[project_id] = info
        return info

    def _get(self, url: str) -> Any:
        self._rate.wait()
        try:
            return _api_get(url, self._headers)
        except urllib.error.HTTPError as e:
            if e.code == 429:
                retry = e.headers.get("Retry-After")
                if retry:
                    time.sleep(min(float(retry), 120))
                    return self._get(url)
            if e.code in (404, 422):
                return None
            raise SearchError(f"GitLab API {e.code}: {url}") from e
        except urllib.error.URLError as e:
            raise SearchError(f"Network error: {e.reason}") from e


def _parse_gitlab_project(data: Any, fallback_group: str) -> RepoInfo | None:
    if not isinstance(data, dict):
        return None
    ns = data.get("namespace", {})
    owner = ns.get("full_path", fallback_group) if isinstance(ns, dict) else fallback_group
    return RepoInfo(
        owner=owner,
        name=data.get("path", ""),
        full_name=data.get("path_with_namespace", ""),
        default_branch=data.get("default_branch", "main"),
        clone_url=data.get("http_url_to_repo", ""),
        stars=data.get("star_count", 0),
        is_fork=bool(data.get("forked_from_project")),
    )


def get_backend(forge: str, token: str | None = None) -> ForgeBackend:
    resolved = _resolve_token(forge, token)
    if forge == "github":
        return GitHubBackend(resolved)
    if forge == "gitlab":
        return GitLabBackend(resolved)
    msg = f"Unknown forge: {forge}"
    raise SearchError(msg)


def _resolve_token(forge: str, explicit: str | None) -> str | None:
    if explicit:
        return explicit
    upper = forge.upper()
    return os.environ.get(f"ACTIONSIEVE_{upper}_TOKEN") or os.environ.get(f"{upper}_TOKEN")


def search_org(
    backend: ForgeBackend,
    org: str,
    *,
    patterns_path: Path | None = None,
    profile_name: str | None = None,
    skip_forks: bool = True,
) -> Iterator[SearchResult]:
    for repo in backend.list_repos(org):
        if skip_forks and repo.is_fork:
            continue
        result = _clone_and_scan(
            repo,
            backend.name,
            patterns_path=patterns_path,
            profile_name=profile_name,
        )
        if result.findings or result.error:
            yield result


def search_pattern(
    backend: ForgeBackend,
    pattern_id: str,
    org: str | None = None,
    *,
    patterns_path: Path | None = None,
    profile_name: str | None = None,
) -> Iterator[SearchResult]:
    from actionsieve.patterns import load_patterns
    from actionsieve.providers import get_provider

    platform = _FORGE_PLATFORM.get(backend.name, backend.name)
    provider = get_provider(platform)
    patterns = load_patterns(patterns_path, platform=platform)

    target = next((p for p in patterns if p.get("id") == pattern_id), None)
    if target is None:
        raise SearchError(f"Pattern not found for platform {platform}: {pattern_id}")

    query = provider.search_query(target)
    if query is None:
        raise SearchError(f"Pattern {pattern_id} has no searchable grep_patterns")

    seen: set[str] = set()
    for hit in backend.search_code(query, org):
        if hit.repo.full_name in seen:
            continue
        seen.add(hit.repo.full_name)
        result = _clone_and_scan(
            hit.repo,
            backend.name,
            patterns_path=patterns_path,
            profile_name=profile_name,
            filter_pattern=pattern_id,
        )
        if result.findings or result.error:
            yield result


_FORGE_PLATFORM: dict[str, str] = {"github": "github", "gitlab": "gitlab"}


def _clone_and_scan(
    repo: RepoInfo,
    forge: str,
    *,
    patterns_path: Path | None = None,
    profile_name: str | None = None,
    filter_pattern: str | None = None,
) -> SearchResult:
    from actionsieve.scanner import scan

    with tempfile.TemporaryDirectory(prefix="actionsieve-") as tmp:
        clone_dir = Path(tmp) / repo.name
        try:
            subprocess.run(  # noqa: S603
                [  # noqa: S607
                    "git",
                    "clone",
                    "--depth",
                    "1",
                    "--single-branch",
                    repo.clone_url,
                    str(clone_dir),
                ],
                capture_output=True,
                text=True,
                check=True,
                timeout=120,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            return SearchResult(
                repo=repo.full_name,
                forge=forge,
                clone_url=repo.clone_url,
                stars=repo.stars,
                error=f"Clone failed: {e}",
            )

        try:
            result = scan(
                repo_path=clone_dir,
                patterns_path=patterns_path,
                profile_name=profile_name,
            )
        except Exception as e:
            return SearchResult(
                repo=repo.full_name,
                forge=forge,
                clone_url=repo.clone_url,
                stars=repo.stars,
                error=f"Scan error: {e}",
            )

        findings = [_finding_dict(f) for f in result.findings]
        if filter_pattern:
            findings = [f for f in findings if f["pattern_id"] == filter_pattern]

    return SearchResult(
        repo=repo.full_name,
        forge=forge,
        clone_url=repo.clone_url,
        stars=repo.stars,
        findings=findings,
    )


def _finding_dict(f: Finding) -> dict[str, Any]:
    return {
        "pattern_id": f.pattern_id,
        "title": f.pattern_title,
        "file": f.file_path,
        "platform": f.platform,
        "line": f.line,
        "job": f.job_id,
        "severity": f.severity_computed or f.severity_base,
        "severity_base": f.severity_base,
        "attacker_model": f.attacker_model,
        "impact": f.impact,
    }
