import os

import pytest

_CI_ENV_VARS = [
    "GITHUB_ACTIONS",
    "GITHUB_EVENT_NAME",
    "GITHUB_BASE_REF",
    "GITHUB_HEAD_REF",
    "GITLAB_CI",
    "TF_BUILD",
    "JENKINS_URL",
    "CIRCLECI",
    "BITBUCKET_BUILD_NUMBER",
    "BUILDKITE",
    "DRONE",
]


@pytest.fixture
def clean_ci_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in _CI_ENV_VARS:
        if var in os.environ:
            monkeypatch.delenv(var)
