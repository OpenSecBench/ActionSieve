"""Advisory database — known-compromised component detection."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml

if TYPE_CHECKING:
    from actionsieve.inventory import Component, Inventory

DEFAULT_DB = Path(__file__).parent.parent / "patterns" / "advisories"


@dataclass
class Advisory:
    action: str
    cve: str
    severity: str
    description: str
    date_disclosed: str
    compromised_versions: list[dict[str, str]] = field(default_factory=list)
    references: list[str] = field(default_factory=list)

    @property
    def owner(self) -> str | None:
        parts = self.action.split("/")
        return parts[0] if len(parts) == 2 else None

    @property
    def name(self) -> str:
        parts = self.action.split("/")
        return parts[1] if len(parts) == 2 else self.action


def load_advisories(db_path: Path | None = None) -> list[Advisory]:
    path = db_path or DEFAULT_DB
    advisories: list[Advisory] = []

    if path.is_file():
        advisories.extend(_load_file(path))
    elif path.is_dir():
        for f in sorted(path.glob("*.yml")):
            advisories.extend(_load_file(f))

    return advisories


def _load_file(path: Path) -> list[Advisory]:
    text = path.read_text()
    data: dict[str, Any] = yaml.safe_load(text) or {}
    raw_list: list[dict[str, Any]] = data.get("advisories", [])

    return [
        Advisory(
            action=entry["action"],
            cve=entry.get("cve", ""),
            severity=entry.get("severity", "high"),
            description=entry.get("description", ""),
            date_disclosed=entry.get("date_disclosed", ""),
            compromised_versions=entry.get("compromised_versions", []),
            references=entry.get("references", []),
        )
        for entry in raw_list
    ]


def check_advisories(
    inv: Inventory,
    db_path: Path | None = None,
) -> Inventory:
    advisories = load_advisories(db_path)
    by_key = _index_advisories(advisories)
    matches = 0

    for comp in inv.components:
        key = comp.key.lower()
        if key in by_key:
            for adv in by_key[key]:
                if _is_affected(comp, adv):
                    comp.advisory_ids.append(adv.cve)
                    if "advisory_match" not in comp.risk_factors:
                        comp.risk_factors.append("advisory_match")
                    matches += 1

    inv.advisory_matches = matches
    return inv


def _index_advisories(advisories: list[Advisory]) -> dict[str, list[Advisory]]:
    by_key: dict[str, list[Advisory]] = {}
    for adv in advisories:
        key = adv.action.lower()
        by_key.setdefault(key, []).append(adv)
    return by_key


def match_ref(
    owner: str | None, name: str, ref: str, advisories: list[Advisory]
) -> Advisory | None:
    key = f"{owner}/{name}".lower() if owner else name.lower()
    for adv in advisories:
        if adv.action.lower() != key:
            continue
        for ver in adv.compromised_versions:
            if ver.get("sha_malicious") and ref == ver["sha_malicious"]:
                return adv
            if ver.get("ref") and ref == ver["ref"]:
                return adv
        if not adv.compromised_versions:
            return adv
    return None


def _is_affected(comp: Component, adv: Advisory) -> bool:
    for ver in adv.compromised_versions:
        if ver.get("sha_malicious") and comp.ref == ver["sha_malicious"]:
            return True
        if ver.get("ref") and comp.ref == ver["ref"]:
            return True
    return not adv.compromised_versions
