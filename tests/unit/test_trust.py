from actionsieve.inventory import Component, ComponentLocation, Inventory
from actionsieve.trust import score_components


def _make_comp(**kwargs: object) -> Component:
    defaults = {
        "raw": "owner/name@ref",
        "owner": "owner",
        "name": "name",
        "ref": "ref",
        "ref_type": "tag",
        "is_pinned": False,
        "is_first_party": False,
        "resolved_sha": None,
        "platform": "github",
        "locations": [ComponentLocation(file="ci.yml", job="build", step=0, line=1)],
    }
    defaults.update(kwargs)
    return Component(**defaults)  # type: ignore[arg-type]


def _make_inv(components: list[Component]) -> Inventory:
    return Inventory(
        components=components,
        total_refs=len(components),
        pinned_count=sum(1 for c in components if c.is_pinned),
        unpinned_count=sum(1 for c in components if not c.is_pinned),
        first_party_count=sum(1 for c in components if c.is_first_party),
        third_party_count=sum(1 for c in components if not c.is_first_party),
    )


class TestTrustScoring:
    def test_pinned_first_party_is_high(self) -> None:
        comp = _make_comp(is_pinned=True, is_first_party=True, ref_type="sha")
        inv = _make_inv([comp])
        score_components(inv)
        assert comp.trust_score == "high"

    def test_unpinned_first_party_is_medium(self) -> None:
        comp = _make_comp(is_pinned=False, is_first_party=True)
        inv = _make_inv([comp])
        score_components(inv)
        assert comp.trust_score == "medium"

    def test_pinned_third_party_is_medium(self) -> None:
        comp = _make_comp(is_pinned=True, is_first_party=False, ref_type="sha")
        inv = _make_inv([comp])
        score_components(inv)
        assert comp.trust_score == "medium"

    def test_unpinned_third_party_is_low(self) -> None:
        comp = _make_comp(is_pinned=False, is_first_party=False)
        inv = _make_inv([comp])
        score_components(inv)
        assert comp.trust_score == "low"

    def test_branch_ref_is_critical(self) -> None:
        comp = _make_comp(ref_type="branch", is_pinned=False, is_first_party=False)
        inv = _make_inv([comp])
        score_components(inv)
        assert comp.trust_score == "critical"

    def test_advisory_match_is_critical(self) -> None:
        comp = _make_comp(advisory_ids=["CVE-2025-30066"])
        comp.advisory_ids = ["CVE-2025-30066"]
        inv = _make_inv([comp])
        score_components(inv)
        assert comp.trust_score == "critical"


class TestRiskFactors:
    def test_unpinned_flagged(self) -> None:
        comp = _make_comp(is_pinned=False)
        inv = _make_inv([comp])
        score_components(inv)
        assert "unpinned_mutable_ref" in comp.risk_factors

    def test_third_party_flagged(self) -> None:
        comp = _make_comp(is_first_party=False)
        inv = _make_inv([comp])
        score_components(inv)
        assert "third_party" in comp.risk_factors

    def test_branch_ref_flagged(self) -> None:
        comp = _make_comp(ref_type="branch", is_pinned=False)
        inv = _make_inv([comp])
        score_components(inv)
        assert "branch_ref" in comp.risk_factors

    def test_pinned_first_party_no_risk_factors(self) -> None:
        comp = _make_comp(is_pinned=True, is_first_party=True, ref_type="sha")
        inv = _make_inv([comp])
        score_components(inv)
        assert comp.risk_factors == []
