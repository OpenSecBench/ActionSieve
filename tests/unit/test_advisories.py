from pathlib import Path

from actionsieve.advisories import check_advisories, load_advisories
from actionsieve.inventory import Component, ComponentLocation, Inventory

DB_PATH = Path(__file__).parent.parent.parent / "patterns" / "advisories"


class TestLoadAdvisories:
    def test_loads_builtin_db(self) -> None:
        advisories = load_advisories()
        assert len(advisories) > 0

    def test_advisory_fields(self) -> None:
        advisories = load_advisories()
        for adv in advisories:
            assert adv.action
            assert adv.severity in ("critical", "high", "medium", "low", "info")

    def test_tj_actions_present(self) -> None:
        advisories = load_advisories()
        names = [a.action for a in advisories]
        assert "tj-actions/changed-files" in names

    def test_owner_and_name(self) -> None:
        advisories = load_advisories()
        tj = next(a for a in advisories if a.action == "tj-actions/changed-files")
        assert tj.owner == "tj-actions"
        assert tj.name == "changed-files"

    def test_loads_from_path(self) -> None:
        advisories = load_advisories(DB_PATH)
        assert len(advisories) > 0


class TestCheckAdvisories:
    def _make_inventory(self, components: list[Component]) -> Inventory:
        return Inventory(
            components=components,
            total_refs=len(components),
            pinned_count=0,
            unpinned_count=len(components),
            first_party_count=0,
            third_party_count=len(components),
        )

    def test_matches_compromised_ref(self) -> None:
        comp = Component(
            raw="tj-actions/changed-files@v35",
            owner="tj-actions",
            name="changed-files",
            ref="v35",
            ref_type="tag",
            is_pinned=False,
            is_first_party=False,
            resolved_sha=None,
            platform="github",
            locations=[ComponentLocation(file="ci.yml", job="build", step=0, line=5)],
        )
        inv = check_advisories(self._make_inventory([comp]))
        assert inv.advisory_matches > 0
        assert len(comp.advisory_ids) > 0
        assert "CVE-2025-30066" in comp.advisory_ids

    def test_no_match_for_safe_action(self) -> None:
        comp = Component(
            raw="actions/checkout@v4",
            owner="actions",
            name="checkout",
            ref="v4",
            ref_type="tag",
            is_pinned=False,
            is_first_party=True,
            resolved_sha=None,
            platform="github",
            locations=[ComponentLocation(file="ci.yml", job="build", step=0, line=5)],
        )
        inv = check_advisories(self._make_inventory([comp]))
        assert inv.advisory_matches == 0
        assert len(comp.advisory_ids) == 0

    def test_matches_by_malicious_sha(self) -> None:
        comp = Component(
            raw="tj-actions/changed-files@0e58ed8671d6b60d0890c21b07f8835ace038e67",
            owner="tj-actions",
            name="changed-files",
            ref="0e58ed8671d6b60d0890c21b07f8835ace038e67",
            ref_type="sha",
            is_pinned=True,
            is_first_party=False,
            resolved_sha=None,
            platform="github",
            locations=[ComponentLocation(file="ci.yml", job="build", step=0, line=5)],
        )
        inv = check_advisories(self._make_inventory([comp]))
        assert inv.advisory_matches > 0

    def test_case_insensitive_match(self) -> None:
        comp = Component(
            raw="TJ-Actions/Changed-Files@v35",
            owner="TJ-Actions",
            name="Changed-Files",
            ref="v35",
            ref_type="tag",
            is_pinned=False,
            is_first_party=False,
            resolved_sha=None,
            platform="github",
            locations=[ComponentLocation(file="ci.yml", job="build", step=0, line=5)],
        )
        inv = check_advisories(self._make_inventory([comp]))
        assert inv.advisory_matches > 0
