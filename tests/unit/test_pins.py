from __future__ import annotations

from unittest.mock import MagicMock, patch

from actionsieve.api_client import APIResponse, RateLimiter
from actionsieve.inventory import Component, ComponentLocation
from actionsieve.pins import (
    PinResult,
    TagInfo,
    _find_latest_in_major,
    _find_tag_for_sha,
    _parse_semver,
    pins_to_findings,
    verify_pins,
)


def _make_component(
    owner: str = "some-org",
    name: str = "some-action",
    ref: str = "a" * 40,
    ref_type: str = "sha",
    is_pinned: bool = True,
    is_first_party: bool = False,
    platform: str = "github",
) -> Component:
    return Component(
        raw=f"{owner}/{name}@{ref}",
        owner=owner,
        name=name,
        ref=ref,
        ref_type=ref_type,
        is_pinned=is_pinned,
        is_first_party=is_first_party,
        resolved_sha=None,
        platform=platform,
        locations=[ComponentLocation(file="ci.yml", job="build", step=0, line=10)],
    )


class TestParseSemver:
    def test_full_version(self) -> None:
        assert _parse_semver("v1.2.3") == (1, 2, 3)

    def test_no_v_prefix(self) -> None:
        assert _parse_semver("2.0.1") == (2, 0, 1)

    def test_major_only(self) -> None:
        assert _parse_semver("v3") == (3, 0, 0)

    def test_major_minor(self) -> None:
        assert _parse_semver("v1.5") == (1, 5, 0)

    def test_non_semver(self) -> None:
        assert _parse_semver("main") is None

    def test_sha_not_semver(self) -> None:
        assert _parse_semver("abc1234") is None


class TestFindTagForSha:
    def test_found(self) -> None:
        tags = [TagInfo("v1.0.0", "aaa"), TagInfo("v2.0.0", "bbb")]
        assert _find_tag_for_sha("bbb", tags) == TagInfo("v2.0.0", "bbb")

    def test_not_found(self) -> None:
        tags = [TagInfo("v1.0.0", "aaa")]
        assert _find_tag_for_sha("zzz", tags) is None

    def test_empty_tags(self) -> None:
        assert _find_tag_for_sha("aaa", []) is None


class TestFindLatestInMajor:
    def test_finds_newer(self) -> None:
        tags = [
            TagInfo("v1.0.0", "a1"),
            TagInfo("v1.1.0", "a2"),
            TagInfo("v1.2.0", "a3"),
            TagInfo("v2.0.0", "b1"),
        ]
        result = _find_latest_in_major((1, 0, 0), tags)
        assert result is not None
        assert result.name == "v1.2.0"

    def test_no_newer(self) -> None:
        tags = [TagInfo("v1.0.0", "a1"), TagInfo("v1.1.0", "a2")]
        assert _find_latest_in_major((1, 1, 0), tags) is None

    def test_ignores_other_major(self) -> None:
        tags = [TagInfo("v2.0.0", "b1")]
        assert _find_latest_in_major((1, 0, 0), tags) is None

    def test_non_semver_tags_skipped(self) -> None:
        tags = [TagInfo("latest", "c1"), TagInfo("v1.1.0", "a2")]
        result = _find_latest_in_major((1, 0, 0), tags)
        assert result is not None
        assert result.name == "v1.1.0"


@patch.object(RateLimiter, "wait", new=lambda self: None)
class TestVerifyPins:
    @patch("actionsieve.api_client._make_request")
    def test_wrong_repo_sha(self, mock_req: MagicMock) -> None:
        import urllib.error

        sha = "a" * 40
        tags_resp = APIResponse(data=[], etag=None, rate_remaining=100)
        mock_req.side_effect = [
            tags_resp,
            urllib.error.HTTPError("url", 404, "Not Found", {}, None),  # type: ignore[arg-type]
        ]

        from actionsieve.api_client import GitHubAPI

        api = GitHubAPI(token="tok")
        comp = _make_component(ref=sha)
        results = verify_pins([comp], api)
        assert len(results) == 1
        assert results[0].status == "wrong_repo"

    @patch("actionsieve.api_client._make_request")
    def test_outdated_pin(self, mock_req: MagicMock) -> None:
        sha_old = "a" * 40
        sha_new = "b" * 40
        tags_resp = APIResponse(
            data=[
                {"name": "v1.0.0", "commit": {"sha": sha_old}},
                {"name": "v1.1.0", "commit": {"sha": sha_new}},
            ],
            etag=None,
            rate_remaining=100,
        )
        mock_req.return_value = tags_resp

        from actionsieve.api_client import GitHubAPI

        api = GitHubAPI(token="tok")
        comp = _make_component(ref=sha_old)
        results = verify_pins([comp], api)
        assert len(results) == 1
        assert results[0].status == "outdated"
        assert results[0].latest_tag == "v1.1.0"

    @patch("actionsieve.api_client._make_request")
    def test_up_to_date_returns_nothing(self, mock_req: MagicMock) -> None:
        sha = "a" * 40
        tags_resp = APIResponse(
            data=[{"name": "v1.0.0", "commit": {"sha": sha}}],
            etag=None,
            rate_remaining=100,
        )
        mock_req.return_value = tags_resp

        from actionsieve.api_client import GitHubAPI

        api = GitHubAPI(token="tok")
        comp = _make_component(ref=sha)
        results = verify_pins([comp], api)
        assert len(results) == 0

    @patch("actionsieve.api_client._make_request")
    def test_untagged_sha(self, mock_req: MagicMock) -> None:
        sha = "a" * 40
        tags_resp = APIResponse(data=[], etag=None, rate_remaining=100)
        commit_resp = APIResponse(data={"sha": sha}, etag=None, rate_remaining=99)
        mock_req.side_effect = [tags_resp, commit_resp]

        from actionsieve.api_client import GitHubAPI

        api = GitHubAPI(token="tok")
        comp = _make_component(ref=sha)
        results = verify_pins([comp], api)
        assert len(results) == 1
        assert results[0].status == "untagged"

    def test_skips_non_github(self) -> None:
        from actionsieve.api_client import GitHubAPI

        api = GitHubAPI(token="tok")
        comp = _make_component(platform="gitlab")
        results = verify_pins([comp], api)
        assert len(results) == 0

    def test_skips_unpinned(self) -> None:
        from actionsieve.api_client import GitHubAPI

        api = GitHubAPI(token="tok")
        comp = _make_component(ref="v1", ref_type="tag", is_pinned=False)
        results = verify_pins([comp], api)
        assert len(results) == 0

    @patch("actionsieve.api_client._make_request")
    def test_batches_by_repo(self, mock_req: MagicMock) -> None:
        sha1 = "a" * 40
        sha2 = "b" * 40
        tags_resp = APIResponse(
            data=[
                {"name": "v1.0.0", "commit": {"sha": sha1}},
                {"name": "v1.1.0", "commit": {"sha": sha2}},
            ],
            etag=None,
            rate_remaining=100,
        )
        mock_req.return_value = tags_resp

        from actionsieve.api_client import GitHubAPI

        api = GitHubAPI(token="tok")
        comp1 = _make_component(ref=sha1)
        comp2 = _make_component(ref=sha2)
        verify_pins([comp1, comp2], api)
        assert mock_req.call_count == 1


class TestPinsToFindings:
    def test_converts_results(self) -> None:
        results = [
            PinResult(
                component_key="org/action@aaa",
                ref="org/action@" + "a" * 40,
                status="outdated",
                detail="Pinned to v1.0.0, latest is v1.1.0",
                latest_tag="v1.1.0",
                latest_sha="b" * 40,
            ),
        ]
        findings = pins_to_findings(results)
        assert len(findings) == 1
        assert findings[0]["pattern_id"] == "pin-outdated"
        assert findings[0]["severity"] == "info"
        assert findings[0]["latest_tag"] == "v1.1.0"

    def test_wrong_repo_severity(self) -> None:
        results = [
            PinResult(
                component_key="org/action@aaa",
                ref="org/action@" + "a" * 40,
                status="wrong_repo",
                detail="SHA not found",
            ),
        ]
        findings = pins_to_findings(results)
        assert findings[0]["severity"] == "medium"
