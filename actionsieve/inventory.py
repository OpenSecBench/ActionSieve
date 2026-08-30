"""Component inventory — bill of materials for CI/CD external dependencies."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pathlib import Path

    from actionsieve.model import WorkflowModel


@dataclass
class ComponentLocation:
    file: str
    job: str
    step: int
    line: int


@dataclass
class Component:
    raw: str
    owner: str | None
    name: str
    ref: str
    ref_type: str
    is_pinned: bool
    is_first_party: bool
    resolved_sha: str | None
    platform: str
    locations: list[ComponentLocation] = field(default_factory=list)
    trust_score: str | None = None
    risk_factors: list[str] = field(default_factory=list)
    advisory_ids: list[str] = field(default_factory=list)

    @property
    def key(self) -> str:
        if self.owner:
            return f"{self.owner}/{self.name}"
        return self.name

    @property
    def is_local(self) -> bool:
        return self.owner == "." or self.raw.startswith("./") or self.raw.startswith(".\\")


@dataclass
class Inventory:
    components: list[Component]
    total_refs: int
    pinned_count: int
    unpinned_count: int
    first_party_count: int
    third_party_count: int
    advisory_matches: int = 0
    repo: str | None = None

    def to_dict(self) -> dict[str, Any]:
        summary: dict[str, Any] = {
            "total_refs": self.total_refs,
            "unique_components": len(self.components),
            "pinned": self.pinned_count,
            "unpinned": self.unpinned_count,
            "first_party": self.first_party_count,
            "third_party": self.third_party_count,
            "advisory_matches": self.advisory_matches,
        }
        if self.repo:
            summary["repo"] = self.repo
        return {
            "summary": summary,
            "components": [_component_dict(c) for c in self.components],
        }


def _component_dict(comp: Component) -> dict[str, Any]:
    d: dict[str, Any] = {
        "ref": comp.raw,
        "platform": comp.platform,
        "owner": comp.owner,
        "name": comp.name,
        "version": comp.ref,
        "ref_type": comp.ref_type,
        "is_pinned": comp.is_pinned,
        "is_first_party": comp.is_first_party,
        "locations": [
            {"file": loc.file, "job": loc.job, "step": loc.step, "line": loc.line}
            for loc in comp.locations
        ],
    }
    if comp.resolved_sha:
        d["resolved_sha"] = comp.resolved_sha
    if comp.trust_score:
        d["trust_score"] = comp.trust_score
    if comp.risk_factors:
        d["risk_factors"] = comp.risk_factors
    if comp.advisory_ids:
        d["advisory_ids"] = comp.advisory_ids
    return d


def collect(models: list[WorkflowModel]) -> Inventory:
    by_key: dict[str, Component] = {}
    total = 0

    for model in models:
        for job in model.jobs:
            for step in job.steps:
                ref = step.action_ref
                if ref is None:
                    continue

                total += 1
                base_key = f"{ref.owner}/{ref.name}" if ref.owner else ref.name
                key = f"{base_key}@{ref.ref}"
                loc = ComponentLocation(
                    file=model.file_path,
                    job=job.id,
                    step=step.index,
                    line=ref.line,
                )

                if key in by_key:
                    by_key[key].locations.append(loc)
                else:
                    by_key[key] = Component(
                        raw=ref.raw,
                        owner=ref.owner,
                        name=ref.name,
                        ref=ref.ref,
                        ref_type=ref.ref_type,
                        is_pinned=ref.is_pinned,
                        is_first_party=ref.is_first_party,
                        resolved_sha=ref.resolved_sha,
                        platform=model.platform,
                        locations=[loc],
                    )

    components = sorted(by_key.values(), key=lambda c: c.key)
    pinned = sum(1 for c in components if c.is_pinned)
    first_party = sum(1 for c in components if c.is_first_party)

    return Inventory(
        components=components,
        total_refs=total,
        pinned_count=pinned,
        unpinned_count=len(components) - pinned,
        first_party_count=first_party,
        third_party_count=len(components) - first_party,
    )


def run_inventory(
    repo_path: Path,
    platform: str | None = None,
    check: bool = False,
    offline: bool = False,
    online: bool = False,
    token: str | None = None,
    exclude_local: bool = False,
    repo: str | None = None,
) -> Inventory:
    from actionsieve.providers import ParseError, auto_detect, get_provider

    providers = [get_provider(platform)] if platform else auto_detect(repo_path)
    models: list[WorkflowModel] = []

    for provider in providers:
        for file_path in provider.find_files(repo_path):
            try:
                model = provider.parse(file_path)
            except ParseError:
                continue
            models.append(model)

    inv = collect(models)

    if exclude_local:
        inv = _filter_local(inv)

    if check:
        from actionsieve.advisories import check_advisories

        inv = check_advisories(inv)

    if online:
        _verify_online(inv, token)

    from actionsieve.trust import score_components

    score_components(inv)

    inv.repo = repo or _detect_repo(repo_path)

    return inv


def _filter_local(inv: Inventory) -> Inventory:
    filtered = [c for c in inv.components if not c.is_local]
    pinned = sum(1 for c in filtered if c.is_pinned)
    first_party = sum(1 for c in filtered if c.is_first_party)
    return Inventory(
        components=filtered,
        total_refs=inv.total_refs,
        pinned_count=pinned,
        unpinned_count=len(filtered) - pinned,
        first_party_count=first_party,
        third_party_count=len(filtered) - first_party,
    )


def _detect_repo(repo_path: Path) -> str | None:
    import subprocess

    try:
        result = subprocess.run(  # noqa: S603
            ["git", "remote", "get-url", "origin"],  # noqa: S607
            capture_output=True,
            text=True,
            cwd=repo_path,
            check=False,
        )
    except FileNotFoundError:
        return None
    if result.returncode != 0:
        return None
    url = result.stdout.strip()
    return _normalize_git_url(url) if url else None


def _normalize_git_url(url: str) -> str:
    import re

    url = re.sub(r"\.git$", "", url)
    m = re.match(r"git@([^:]+):(.+)", url)
    if m:
        return f"https://{m.group(1)}/{m.group(2)}"
    return url


def _verify_online(inv: Inventory, token: str | None) -> None:
    from actionsieve.api_client import DiskCache, GitHubAPI, resolve_token
    from actionsieve.pins import verify_pins

    resolved = resolve_token("github", token)
    api = GitHubAPI(token=resolved, cache=DiskCache())
    results = verify_pins(inv.components, api)

    status_map = {r.component_key: r for r in results}
    for comp in inv.components:
        key = f"{comp.owner}/{comp.name}@{comp.ref[:12]}"
        pin_result = status_map.get(key)
        if pin_result:
            comp.risk_factors.append(f"pin:{pin_result.status} — {pin_result.detail}")
