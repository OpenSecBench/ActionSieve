"""Shared HTTP client, rate limiting, disk cache for forge APIs."""

from __future__ import annotations

import hashlib
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Iterator


class APIError(Exception):
    pass


class RateLimiter:
    def __init__(self, min_interval: float) -> None:
        self._min_interval = min_interval
        self._last = 0.0

    def wait(self) -> None:
        now = time.monotonic()
        gap = self._min_interval - (now - self._last)
        if gap > 0:
            time.sleep(gap)
        self._last = time.monotonic()


@dataclass
class CacheEntry:
    data: Any
    etag: str | None
    ts: float


class DiskCache:
    def __init__(self, base_dir: Path | None = None) -> None:
        if base_dir is None:
            xdg = os.environ.get("XDG_CACHE_HOME")
            root = Path(xdg) if xdg else Path.home() / ".cache"
            base_dir = root / "actionsieve"
        self._base = base_dir

    def get(self, key: str, ttl: float) -> CacheEntry | None:
        path = self._path(key)
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, ValueError):
            return None
        ts = raw.get("ts", 0.0)
        if time.time() - ts > ttl:
            return CacheEntry(data=raw.get("data"), etag=raw.get("etag"), ts=ts)
        return CacheEntry(data=raw.get("data"), etag=raw.get("etag"), ts=ts)

    def is_fresh(self, entry: CacheEntry, ttl: float) -> bool:
        return time.time() - entry.ts <= ttl

    def put(self, key: str, data: Any, etag: str | None = None) -> None:
        path = self._path(key)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                json.dumps({"data": data, "etag": etag, "ts": time.time()}),
                encoding="utf-8",
            )
        except OSError:
            pass

    def _path(self, key: str) -> Path:
        safe = key.replace("\\", "/")
        if len(safe) > 200:
            digest = hashlib.sha256(safe.encode()).hexdigest()[:16]
            safe = safe[:100] + "_" + digest
        return self._base / safe


@dataclass
class APIResponse:
    data: Any
    etag: str | None = None
    rate_remaining: int | None = None


def resolve_token(forge: str, explicit: str | None = None) -> str | None:
    if explicit:
        return explicit
    upper = forge.upper()
    return os.environ.get(f"ACTIONSIEVE_{upper}_TOKEN") or os.environ.get(f"{upper}_TOKEN")


def _make_request(
    url: str,
    headers: dict[str, str],
    etag: str | None = None,
) -> APIResponse | None:
    req = urllib.request.Request(url)  # noqa: S310
    for k, v in headers.items():
        req.add_header(k, v)
    if etag:
        req.add_header("If-None-Match", etag)
    try:
        with urllib.request.urlopen(req) as resp:  # noqa: S310
            data = json.loads(resp.read())
            resp_etag = resp.headers.get("ETag")
            remaining = resp.headers.get("X-RateLimit-Remaining")
            return APIResponse(
                data=data,
                etag=resp_etag,
                rate_remaining=int(remaining) if remaining else None,
            )
    except urllib.error.HTTPError as e:
        if e.code == 304:
            return None
        raise


class GitHubAPI:
    BASE = "https://api.github.com"

    def __init__(
        self,
        token: str | None = None,
        cache: DiskCache | None = None,
    ) -> None:
        self._token = token
        self._rate = RateLimiter(2.0 if token else 60.0)
        self._cache = cache
        self._remaining: int | None = None
        self._headers: dict[str, str] = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if token:
            self._headers["Authorization"] = f"Bearer {token}"

    @property
    def rate_remaining(self) -> int | None:
        return self._remaining

    def get(
        self,
        path: str,
        *,
        cache_key: str | None = None,
        cache_ttl: float = 0,
    ) -> Any:
        if cache_key and self._cache and cache_ttl > 0:
            entry = self._cache.get(cache_key, cache_ttl)
            if entry and self._cache.is_fresh(entry, cache_ttl):
                return entry.data

            etag = entry.etag if entry else None
            resp = self._request(self.BASE + path, etag=etag)
            if resp is None and entry:
                self._cache.put(cache_key, entry.data, entry.etag)
                return entry.data
            if resp:
                self._cache.put(cache_key, resp.data, resp.etag)
                return resp.data
            return None

        resp = self._request(self.BASE + path)
        return resp.data if resp else None

    def get_pages(
        self,
        path: str,
        *,
        per_page: int = 100,
        max_pages: int = 10,
    ) -> Iterator[list[Any]]:
        sep = "&" if "?" in path else "?"
        for page in range(1, max_pages + 1):
            url = f"{self.BASE}{path}{sep}per_page={per_page}&page={page}"
            resp = self._request(url)
            if resp is None:
                break
            data = resp.data
            if not isinstance(data, list) or not data:
                break
            yield data
            if len(data) < per_page:
                break

    def _request(self, url: str, etag: str | None = None) -> APIResponse | None:
        self._rate.wait()
        try:
            resp = _make_request(url, self._headers, etag=etag)
            if resp and resp.rate_remaining is not None:
                self._remaining = resp.rate_remaining
            return resp
        except urllib.error.HTTPError as e:
            if e.code == 403:
                retry = e.headers.get("Retry-After")
                if retry:
                    time.sleep(min(float(retry), 120))
                    return self._request(url, etag=etag)
            if e.code in (404, 422):
                return None
            raise APIError(f"GitHub API {e.code}: {url}") from e
        except urllib.error.URLError as e:
            raise APIError(f"Network error: {e.reason}") from e


class GitLabAPI:
    def __init__(
        self,
        token: str | None = None,
        base_url: str = "https://gitlab.com",
        cache: DiskCache | None = None,
    ) -> None:
        self._token = token
        self._base = base_url.rstrip("/")
        self._rate = RateLimiter(0.2)
        self._cache = cache
        self._remaining: int | None = None
        self._headers: dict[str, str] = {}
        if token:
            self._headers["PRIVATE-TOKEN"] = token

    @property
    def rate_remaining(self) -> int | None:
        return self._remaining

    def get(
        self,
        path: str,
        *,
        cache_key: str | None = None,
        cache_ttl: float = 0,
    ) -> Any:
        if cache_key and self._cache and cache_ttl > 0:
            entry = self._cache.get(cache_key, cache_ttl)
            if entry and self._cache.is_fresh(entry, cache_ttl):
                return entry.data

            etag = entry.etag if entry else None
            resp = self._request(self._base + path, etag=etag)
            if resp is None and entry:
                self._cache.put(cache_key, entry.data, entry.etag)
                return entry.data
            if resp:
                self._cache.put(cache_key, resp.data, resp.etag)
                return resp.data
            return None

        resp = self._request(self._base + path)
        return resp.data if resp else None

    def get_pages(
        self,
        path: str,
        *,
        per_page: int = 100,
        max_pages: int = 10,
    ) -> Iterator[list[Any]]:
        sep = "&" if "?" in path else "?"
        for page in range(1, max_pages + 1):
            url = f"{self._base}{path}{sep}per_page={per_page}&page={page}"
            resp = self._request(url)
            if resp is None:
                break
            data = resp.data
            if not isinstance(data, list) or not data:
                break
            yield data
            if len(data) < per_page:
                break

    def _request(self, url: str, etag: str | None = None) -> APIResponse | None:
        self._rate.wait()
        try:
            resp = _make_request(url, self._headers, etag=etag)
            if resp and resp.rate_remaining is not None:
                self._remaining = resp.rate_remaining
            return resp
        except urllib.error.HTTPError as e:
            if e.code == 429:
                retry = e.headers.get("Retry-After")
                if retry:
                    time.sleep(min(float(retry), 120))
                    return self._request(url, etag=etag)
            if e.code in (404, 422):
                return None
            raise APIError(f"GitLab API {e.code}: {url}") from e
        except urllib.error.URLError as e:
            raise APIError(f"Network error: {e.reason}") from e
