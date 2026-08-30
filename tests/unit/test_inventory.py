from pathlib import Path

from actionsieve.inventory import Inventory, _normalize_git_url, collect, run_inventory
from actionsieve.providers.github import GitHubProvider

FIXTURES = Path(__file__).parent.parent / "fixtures" / "github"


def _parse_fixture(fixture: str) -> list:
    provider = GitHubProvider()
    return [provider.parse(FIXTURES / fixture)]


class TestCollect:
    def test_extracts_components(self) -> None:
        models = _parse_fixture("vulnerable/.github/workflows/unpinned-actions.yml")
        inv = collect(models)
        assert inv.total_refs > 0
        assert len(inv.components) > 0

    def test_pinned_vs_unpinned(self) -> None:
        models = _parse_fixture("safe/.github/workflows/pinned-actions.yml")
        inv = collect(models)
        assert inv.pinned_count == len(inv.components)
        assert inv.unpinned_count == 0

    def test_unpinned_counted(self) -> None:
        models = _parse_fixture("vulnerable/.github/workflows/unpinned-actions.yml")
        inv = collect(models)
        assert inv.unpinned_count > 0

    def test_first_party_detected(self) -> None:
        models = _parse_fixture("safe/.github/workflows/pinned-actions.yml")
        inv = collect(models)
        first_party = [c for c in inv.components if c.is_first_party]
        assert len(first_party) > 0

    def test_location_tracking(self) -> None:
        models = _parse_fixture("vulnerable/.github/workflows/unpinned-actions.yml")
        inv = collect(models)
        for comp in inv.components:
            assert len(comp.locations) > 0
            for loc in comp.locations:
                assert loc.file
                assert loc.job

    def test_components_sorted_by_key(self) -> None:
        models = _parse_fixture("vulnerable/.github/workflows/unpinned-actions.yml")
        inv = collect(models)
        keys = [c.key for c in inv.components]
        assert keys == sorted(keys)

    def test_aggregates_across_files(self) -> None:
        provider = GitHubProvider()
        models = [
            provider.parse(FIXTURES / "vulnerable/.github/workflows/unpinned-actions.yml"),
            provider.parse(FIXTURES / "vulnerable/.github/workflows/dispatch-injection.yml"),
        ]
        inv = collect(models)
        checkout = [c for c in inv.components if c.name == "checkout"]
        assert len(checkout) == 1
        assert len(checkout[0].locations) >= 2


class TestInventoryDict:
    def test_to_dict_has_summary(self) -> None:
        models = _parse_fixture("vulnerable/.github/workflows/unpinned-actions.yml")
        inv = collect(models)
        d = inv.to_dict()
        assert "summary" in d
        assert "components" in d
        assert d["summary"]["total_refs"] == inv.total_refs

    def test_component_dict_fields(self) -> None:
        models = _parse_fixture("vulnerable/.github/workflows/unpinned-actions.yml")
        inv = collect(models)
        d = inv.to_dict()
        comp = d["components"][0]
        assert "ref" in comp
        assert "owner" in comp
        assert "name" in comp
        assert "ref_type" in comp
        assert "locations" in comp


class TestIsLocal:
    def test_dot_owner_is_local(self) -> None:
        models = _parse_fixture("vulnerable/.github/workflows/composite-action.yml")
        inv = collect(models)
        local = [c for c in inv.components if c.is_local]
        assert len(local) >= 1

    def test_third_party_not_local(self) -> None:
        models = _parse_fixture("vulnerable/.github/workflows/unpinned-actions.yml")
        inv = collect(models)
        for comp in inv.components:
            assert not comp.is_local


class TestFilterLocal:
    def test_exclude_local_removes_local(self) -> None:
        inv = run_inventory(FIXTURES / "vulnerable", platform="github", exclude_local=True)
        for comp in inv.components:
            assert not comp.is_local

    def test_exclude_local_preserves_total_refs(self) -> None:
        inv_all = run_inventory(FIXTURES / "vulnerable", platform="github")
        inv_filtered = run_inventory(
            FIXTURES / "vulnerable", platform="github", exclude_local=True
        )
        assert inv_filtered.total_refs == inv_all.total_refs
        assert len(inv_filtered.components) < len(inv_all.components)


class TestRepoDetection:
    def test_repo_flag_sets_repo(self) -> None:
        inv = run_inventory(FIXTURES / "vulnerable", platform="github", repo="github.com/org/repo")
        assert inv.repo == "github.com/org/repo"

    def test_normalize_ssh_url(self) -> None:
        assert _normalize_git_url("git@github.com:org/repo.git") == "https://github.com/org/repo"

    def test_normalize_https_url(self) -> None:
        assert (
            _normalize_git_url("https://github.com/org/repo.git") == "https://github.com/org/repo"
        )

    def test_normalize_plain_url(self) -> None:
        assert _normalize_git_url("https://github.com/org/repo") == "https://github.com/org/repo"


class TestRunInventory:
    def test_scans_repo(self) -> None:
        inv = run_inventory(FIXTURES / "vulnerable", platform="github")
        assert isinstance(inv, Inventory)
        assert inv.total_refs > 0

    def test_with_check(self) -> None:
        inv = run_inventory(FIXTURES / "vulnerable", platform="github", check=True)
        assert isinstance(inv, Inventory)
        assert inv.advisory_matches > 0

    def test_trust_scores_assigned(self) -> None:
        inv = run_inventory(FIXTURES / "vulnerable", platform="github")
        for comp in inv.components:
            assert comp.trust_score is not None
