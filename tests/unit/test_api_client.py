from __future__ import annotations

import time
from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch

import pytest

if TYPE_CHECKING:
    from pathlib import Path

from actionsieve.api_client import (
    APIError,
    APIResponse,
    DiskCache,
    GitHubAPI,
    GitLabAPI,
    RateLimiter,
    resolve_token,
)


class TestRateLimiter:
    def test_first_call_no_wait(self) -> None:
        rl = RateLimiter(1.0)
        start = time.monotonic()
        rl.wait()
        assert time.monotonic() - start < 0.1

    def test_second_call_waits(self) -> None:
        rl = RateLimiter(0.1)
        rl.wait()
        start = time.monotonic()
        rl.wait()
        assert time.monotonic() - start >= 0.05


class TestResolveToken:
    def test_explicit_wins(self) -> None:
        assert resolve_token("github", "my-token") == "my-token"

    def test_actionsieve_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ACTIONSIEVE_GITHUB_TOKEN", "as-token")
        assert resolve_token("github") == "as-token"

    def test_forge_env_fallback(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("ACTIONSIEVE_GITHUB_TOKEN", raising=False)
        monkeypatch.setenv("GITHUB_TOKEN", "gh-token")
        assert resolve_token("github") == "gh-token"

    def test_none_when_missing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("ACTIONSIEVE_GITHUB_TOKEN", raising=False)
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)
        assert resolve_token("github") is None


class TestDiskCache:
    def test_put_and_get(self, tmp_path: Path) -> None:
        cache = DiskCache(tmp_path)
        cache.put("test/key.json", {"hello": "world"}, etag='"abc"')
        entry = cache.get("test/key.json", ttl=3600)
        assert entry is not None
        assert entry.data == {"hello": "world"}
        assert entry.etag == '"abc"'

    def test_fresh_check(self, tmp_path: Path) -> None:
        cache = DiskCache(tmp_path)
        cache.put("k", "val")
        entry = cache.get("k", ttl=3600)
        assert entry is not None
        assert cache.is_fresh(entry, 3600) is True
        assert cache.is_fresh(entry, 0) is False

    def test_missing_key_returns_none(self, tmp_path: Path) -> None:
        cache = DiskCache(tmp_path)
        assert cache.get("nonexistent", ttl=3600) is None

    def test_corrupt_file_returns_none(self, tmp_path: Path) -> None:
        cache = DiskCache(tmp_path)
        path = tmp_path / "bad.json"
        path.write_text("not json", encoding="utf-8")
        assert cache.get("bad.json", ttl=3600) is None

    def test_xdg_cache_home(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
        cache = DiskCache()
        cache.put("xdg_test", "data")
        assert (tmp_path / "actionsieve" / "xdg_test").exists()

    def test_long_key_truncated(self, tmp_path: Path) -> None:
        cache = DiskCache(tmp_path)
        long_key = "a" * 300
        cache.put(long_key, "data")
        entry = cache.get(long_key, ttl=3600)
        assert entry is not None
        assert entry.data == "data"


def _mock_response(
    data: object, etag: str | None = None, remaining: int | None = None
) -> MagicMock:
    return MagicMock(return_value=APIResponse(data=data, etag=etag, rate_remaining=remaining))


class TestGitHubAPI:
    @patch("actionsieve.api_client._make_request")
    def test_get_returns_data(self, mock_req: MagicMock) -> None:
        mock_req.return_value = APIResponse(data={"id": 1}, etag=None, rate_remaining=4999)
        api = GitHubAPI(token="tok")
        result = api.get("/repos/owner/repo")
        assert result == {"id": 1}
        assert api.rate_remaining == 4999

    @patch("actionsieve.api_client._make_request")
    def test_get_with_cache(self, mock_req: MagicMock, tmp_path: Path) -> None:
        mock_req.return_value = APIResponse(
            data=[{"name": "v1"}], etag='"etag1"', rate_remaining=100
        )
        cache = DiskCache(tmp_path)
        api = GitHubAPI(token="tok", cache=cache)
        result = api.get("/repos/o/r/tags", cache_key="github/tags/o/r.json", cache_ttl=3600)
        assert result == [{"name": "v1"}]
        assert mock_req.call_count == 1

        result2 = api.get("/repos/o/r/tags", cache_key="github/tags/o/r.json", cache_ttl=3600)
        assert result2 == [{"name": "v1"}]
        assert mock_req.call_count == 1

    @patch("actionsieve.api_client._make_request")
    def test_get_pages(self, mock_req: MagicMock) -> None:
        mock_req.side_effect = [
            APIResponse(data=[{"id": i} for i in range(100)], etag=None, rate_remaining=100),
            APIResponse(data=[{"id": 100}], etag=None, rate_remaining=99),
        ]
        api = GitHubAPI(token="tok")
        pages = list(api.get_pages("/repos/o/r/tags"))
        assert len(pages) == 2
        assert len(pages[0]) == 100
        assert len(pages[1]) == 1

    @patch("actionsieve.api_client._make_request")
    def test_get_pages_stops_on_empty(self, mock_req: MagicMock) -> None:
        mock_req.return_value = APIResponse(data=[], etag=None, rate_remaining=100)
        api = GitHubAPI(token="tok")
        pages = list(api.get_pages("/repos/o/r/tags"))
        assert pages == []

    @patch("actionsieve.api_client._make_request")
    def test_get_pages_respects_max(self, mock_req: MagicMock) -> None:
        mock_req.return_value = APIResponse(
            data=[{"id": i} for i in range(100)], etag=None, rate_remaining=100
        )
        api = GitHubAPI(token="tok")
        pages = list(api.get_pages("/repos/o/r/tags", max_pages=2))
        assert len(pages) == 2

    @patch("actionsieve.api_client._make_request")
    def test_404_returns_none(self, mock_req: MagicMock) -> None:
        import urllib.error

        mock_req.side_effect = urllib.error.HTTPError(
            "url",
            404,
            "Not Found",
            {},
            None,  # type: ignore[arg-type]
        )
        api = GitHubAPI(token="tok")
        assert api.get("/repos/o/r") is None

    @patch("actionsieve.api_client._make_request")
    def test_500_raises_api_error(self, mock_req: MagicMock) -> None:
        import urllib.error

        mock_req.side_effect = urllib.error.HTTPError(
            "url",
            500,
            "Server Error",
            {},
            None,  # type: ignore[arg-type]
        )
        api = GitHubAPI(token="tok")
        with pytest.raises(APIError, match="500"):
            api.get("/repos/o/r")

    def test_no_token_uses_slow_rate(self) -> None:
        api = GitHubAPI()
        assert api._rate._min_interval == 60.0

    def test_token_uses_fast_rate(self) -> None:
        api = GitHubAPI(token="tok")
        assert api._rate._min_interval == 2.0


class TestGitLabAPI:
    @patch("actionsieve.api_client._make_request")
    def test_get_returns_data(self, mock_req: MagicMock) -> None:
        mock_req.return_value = APIResponse(data={"id": 1}, etag=None, rate_remaining=None)
        api = GitLabAPI(token="tok")
        result = api.get("/api/v4/projects/1")
        assert result == {"id": 1}

    @patch("actionsieve.api_client._make_request")
    def test_get_pages(self, mock_req: MagicMock) -> None:
        mock_req.side_effect = [
            APIResponse(data=[{"id": 1}], etag=None, rate_remaining=None),
        ]
        api = GitLabAPI(token="tok")
        pages = list(api.get_pages("/api/v4/groups/g/projects"))
        assert len(pages) == 1

    @patch("actionsieve.api_client._make_request")
    def test_429_retries(self, mock_req: MagicMock) -> None:
        import urllib.error
        from http.client import HTTPMessage
        from io import BytesIO

        headers = HTTPMessage()
        headers["Retry-After"] = "0"
        mock_req.side_effect = [
            urllib.error.HTTPError("url", 429, "Rate limited", headers, BytesIO()),
            APIResponse(data={"ok": True}, etag=None, rate_remaining=None),
        ]
        api = GitLabAPI(token="tok")
        result = api.get("/api/v4/test")
        assert result == {"ok": True}

    def test_custom_base_url(self) -> None:
        api = GitLabAPI(base_url="https://gitlab.example.com/")
        assert api._base == "https://gitlab.example.com"
