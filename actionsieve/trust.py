"""Trust scoring — risk assessment for external CI/CD components."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from actionsieve.inventory import Component, Inventory


def score_components(inv: Inventory) -> None:
    for comp in inv.components:
        comp.trust_score = _compute_score(comp)
        computed = _compute_risks(comp)
        computed_set = set(computed)
        comp.risk_factors = computed + [r for r in comp.risk_factors if r not in computed_set]


def _compute_score(comp: Component) -> str:
    if comp.advisory_ids:
        return "critical"

    if comp.is_first_party and comp.is_pinned:
        return "high"

    if comp.is_first_party:
        return "medium"

    if comp.is_pinned:
        return "medium"

    if comp.ref_type == "branch":
        return "critical"

    return "low"


def _compute_risks(comp: Component) -> list[str]:
    risks: list[str] = []

    if not comp.is_pinned:
        risks.append("unpinned_mutable_ref")

    if comp.ref_type == "branch":
        risks.append("branch_ref")

    if not comp.is_first_party:
        risks.append("third_party")

    if comp.advisory_ids:
        risks.append("advisory_match")

    return risks
