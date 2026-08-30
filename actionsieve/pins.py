"""SHA pin verification — online checks for pinned action references."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from actionsieve.api_client import GitHubAPI
    from actionsieve.inventory import Component


@dataclass
class TagInfo:
    name: str
    sha: str


@dataclass
class PinResult:
    component_key: str
    ref: str
    status: str
    detail: str = ""
    current_sha: str | None = None
    latest_tag: str | None = None
    latest_sha: str | None = None


_SEMVER_RE = re.compile(r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?$")


def _parse_semver(tag: str) -> tuple[int, int, int] | None:
    m = _SEMVER_RE.match(tag)
    if not m:
        return None
    return (
        int(m.group(1)),
        int(m.group(2) or 0),
        int(m.group(3) or 0),
    )


def _fetch_tags(api: GitHubAPI, owner: str, repo: str) -> list[TagInfo]:
    cache_key = f"github/tags/{owner}/{repo}.json"
    data = api.get(
        f"/repos/{owner}/{repo}/tags?per_page=100",
        cache_key=cache_key,
        cache_ttl=86400,
    )
    if not isinstance(data, list):
        return []
    tags: list[TagInfo] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        name = item.get("name", "")
        commit = item.get("commit", {})
        sha = commit.get("sha", "") if isinstance(commit, dict) else ""
        if name and sha:
            tags.append(TagInfo(name=name, sha=sha))
    return tags


def _sha_exists(api: GitHubAPI, owner: str, repo: str, sha: str) -> bool:
    result = api.get(f"/repos/{owner}/{repo}/commits/{sha}")
    return result is not None


def _find_tag_for_sha(sha: str, tags: list[TagInfo]) -> TagInfo | None:
    for tag in tags:
        if tag.sha == sha:
            return tag
    return None


def _find_latest_in_major(current: tuple[int, int, int], tags: list[TagInfo]) -> TagInfo | None:
    major = current[0]
    best: tuple[int, int, int] | None = None
    best_tag: TagInfo | None = None
    for tag in tags:
        ver = _parse_semver(tag.name)
        if ver is None or ver[0] != major:
            continue
        if ver <= current:
            continue
        if best is None or ver > best:
            best = ver
            best_tag = tag
    return best_tag


def verify_pins(
    components: list[Component],
    api: GitHubAPI,
) -> list[PinResult]:
    pinned = [c for c in components if c.is_pinned and c.owner and c.platform == "github"]
    if not pinned:
        return []

    by_repo: dict[str, list[Component]] = {}
    for comp in pinned:
        repo_key = f"{comp.owner}/{comp.name}"
        by_repo.setdefault(repo_key, []).append(comp)

    results: list[PinResult] = []
    for repo_key, comps in by_repo.items():
        owner, repo = repo_key.split("/", 1)
        tags = _fetch_tags(api, owner, repo)

        for comp in comps:
            result = _check_pin(api, owner, repo, comp, tags)
            if result:
                results.append(result)

    return results


def _check_pin(
    api: GitHubAPI,
    owner: str,
    repo: str,
    comp: Component,
    tags: list[TagInfo],
) -> PinResult | None:
    sha = comp.ref
    comp_key = f"{comp.owner}/{comp.name}@{sha[:12]}"

    matched_tag = _find_tag_for_sha(sha, tags)

    if matched_tag is None:
        if not _sha_exists(api, owner, repo, sha):
            return PinResult(
                component_key=comp_key,
                ref=comp.raw,
                status="wrong_repo",
                detail=f"SHA {sha[:12]} not found in {owner}/{repo}",
            )
        return PinResult(
            component_key=comp_key,
            ref=comp.raw,
            status="untagged",
            detail=f"SHA {sha[:12]} exists but matches no tag",
        )

    ver = _parse_semver(matched_tag.name)
    if ver is None:
        return None

    latest = _find_latest_in_major(ver, tags)
    if latest and latest.sha != sha:
        return PinResult(
            component_key=comp_key,
            ref=comp.raw,
            status="outdated",
            detail=f"Pinned to {matched_tag.name}, latest is {latest.name}",
            current_sha=sha,
            latest_tag=latest.name,
            latest_sha=latest.sha,
        )

    return None


_PIN_SEVERITY: dict[str, str] = {
    "wrong_repo": "medium",
    "outdated": "info",
    "untagged": "info",
}


def pins_to_findings(
    results: list[PinResult],
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for r in results:
        findings.append(
            {
                "pattern_id": f"pin-{r.status.replace('_', '-')}",
                "title": f"SHA pin verification: {r.status}",
                "detail": r.detail,
                "ref": r.ref,
                "severity": _PIN_SEVERITY.get(r.status, "info"),
                "latest_tag": r.latest_tag,
                "latest_sha": r.latest_sha,
            }
        )
    return findings
