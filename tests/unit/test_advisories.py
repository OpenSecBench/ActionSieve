from pathlib import Path

import yaml

from actionsieve.advisories import Advisory, check_advisories, load_advisories, match_ref
from actionsieve.inventory import Component, ComponentLocation, Inventory


def _write_db(tmp_path: Path) -> Path:
    db = tmp_path / "advisories"
    db.mkdir()
    (db / "test.yml").write_text(
        yaml.dump(
            {
                "advisories": [
                    {
                        "action": "evil/action",
                        "cve": "CVE-2099-0001",
                        "severity": "critical",
                        "description": "Test advisory",
                        "date_disclosed": "2099-01-01",
                        "compromised_versions": [
                            {"ref": "v1", "sha_malicious": "abc123"},
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    return db


def _make_component(owner: str, name: str, ref: str) -> Component:
    return Component(
        raw=f"{owner}/{name}@{ref}",
        owner=owner,
        name=name,
        ref=ref,
        ref_type="tag",
        is_pinned=False,
        is_first_party=False,
        resolved_sha=None,
        platform="github",
        locations=[ComponentLocation(file="ci.yml", job="build", step=0, line=5)],
    )


def _make_inventory(components: list[Component]) -> Inventory:
    return Inventory(
        components=components,
        total_refs=len(components),
        pinned_count=0,
        unpinned_count=len(components),
        first_party_count=0,
        third_party_count=len(components),
    )


class TestLoadAdvisories:
    def test_loads_from_path(self, tmp_path: Path) -> None:
        db = _write_db(tmp_path)
        advisories = load_advisories(db)
        assert len(advisories) == 1
        assert advisories[0].cve == "CVE-2099-0001"

    def test_no_path_returns_empty(self) -> None:
        import os

        env = os.environ.pop("ACTIONSIEVE_PATTERNS", None)
        try:
            advisories = load_advisories()
            assert advisories == []
        finally:
            if env is not None:
                os.environ["ACTIONSIEVE_PATTERNS"] = env

    def test_advisory_fields(self, tmp_path: Path) -> None:
        db = _write_db(tmp_path)
        adv = load_advisories(db)[0]
        assert adv.action == "evil/action"
        assert adv.owner == "evil"
        assert adv.name == "action"
        assert adv.severity == "critical"


class TestCheckAdvisories:
    def test_matches_compromised_ref(self, tmp_path: Path) -> None:
        db = _write_db(tmp_path)
        comp = _make_component("evil", "action", "v1")
        inv = check_advisories(_make_inventory([comp]), db_path=db)
        assert inv.advisory_matches > 0
        assert "CVE-2099-0001" in comp.advisory_ids

    def test_matches_by_malicious_sha(self, tmp_path: Path) -> None:
        db = _write_db(tmp_path)
        comp = _make_component("evil", "action", "abc123")
        inv = check_advisories(_make_inventory([comp]), db_path=db)
        assert inv.advisory_matches > 0

    def test_no_match_for_safe_action(self, tmp_path: Path) -> None:
        db = _write_db(tmp_path)
        comp = _make_component("safe", "action", "v1")
        inv = check_advisories(_make_inventory([comp]), db_path=db)
        assert inv.advisory_matches == 0

    def test_case_insensitive_match(self, tmp_path: Path) -> None:
        db = _write_db(tmp_path)
        comp = _make_component("Evil", "Action", "v1")
        inv = check_advisories(_make_inventory([comp]), db_path=db)
        assert inv.advisory_matches > 0


class TestMatchRef:
    def test_match_by_ref(self) -> None:
        adv = Advisory(
            action="evil/action",
            cve="CVE-2099-0001",
            severity="critical",
            description="",
            date_disclosed="",
            compromised_versions=[{"ref": "v1"}],
        )
        result = match_ref("evil", "action", "v1", [adv])
        assert result is not None
        assert result.cve == "CVE-2099-0001"

    def test_no_match_different_ref(self) -> None:
        adv = Advisory(
            action="evil/action",
            cve="CVE-2099-0001",
            severity="critical",
            description="",
            date_disclosed="",
            compromised_versions=[{"ref": "v1"}],
        )
        assert match_ref("evil", "action", "v2", [adv]) is None

    def test_match_no_versions_matches_any(self) -> None:
        adv = Advisory(
            action="evil/action",
            cve="CVE-2099-0001",
            severity="critical",
            description="",
            date_disclosed="",
        )
        result = match_ref("evil", "action", "v999", [adv])
        assert result is not None
