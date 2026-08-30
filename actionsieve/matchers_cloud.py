"""Cloud-native CI IAM/secret misconfig matchers (CodeBuild, Cloud Build)."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from actionsieve.engine import Finding
    from actionsieve.matchers import MakeFinding
    from actionsieve.model import WorkflowModel

_SECRET_KEY_FRAGMENTS = (
    "PASSWORD",
    "SECRET",
    "TOKEN",
    "API_KEY",
    "APIKEY",
    "PRIVATE_KEY",
    "CREDENTIAL",
    "AUTH_KEY",
    "PASSPHRASE",
    "SIGNING_KEY",
)

_SAFE_KEY_FRAGMENTS = (
    "SECRET_ARN",
    "SECRET_NAME",
    "SECRET_ID",
    "TOKEN_URL",
    "TOKEN_ENDPOINT",
    "TOKEN_TYPE",
)


def _is_secret_key(key: str) -> bool:
    upper = key.upper()
    if any(safe in upper for safe in _SAFE_KEY_FRAGMENTS):
        return False
    return any(frag in upper for frag in _SECRET_KEY_FRAGMENTS)


def match_codebuild_plaintext_secrets(
    model: WorkflowModel, pattern: dict[str, Any], make_finding: MakeFinding
) -> list[Finding]:
    if model.platform != "codebuild":
        return []

    findings: list[Finding] = []
    for job in model.jobs:
        secret_keys = [k for k in job.env if _is_secret_key(k)]
        if secret_keys:
            findings.append(
                make_finding(
                    pattern=pattern,
                    model=model,
                    job=job,
                    step=None,
                    evidence=[
                        "Plaintext secrets in env.variables: " + ", ".join(secret_keys),
                        "Use env.parameter-store or env.secrets-manager instead",
                    ],
                    line=0,
                )
            )
    return findings


def match_codebuild_privileged_mode(
    model: WorkflowModel, pattern: dict[str, Any], make_finding: MakeFinding
) -> list[Finding]:
    if model.platform != "codebuild":
        return []

    env_section = model.raw.get("env", {})
    if not isinstance(env_section, dict):
        return []

    if not env_section.get("privilegedMode"):
        return []

    if not model.jobs:
        return []

    return [
        make_finding(
            pattern=pattern,
            model=model,
            job=model.jobs[0],
            step=None,
            evidence=["env.privilegedMode: true — container has root-level host access"],
            line=0,
        )
    ]


def match_codebuild_exported_secrets(
    model: WorkflowModel, pattern: dict[str, Any], make_finding: MakeFinding
) -> list[Finding]:
    if model.platform != "codebuild":
        return []

    env_section = model.raw.get("env", {})
    if not isinstance(env_section, dict):
        return []

    exported = env_section.get("exported-variables", [])
    if not isinstance(exported, list):
        return []

    secret_keys: set[str] = set()
    for store in ("parameter-store", "secrets-manager"):
        refs = env_section.get(store, {})
        if isinstance(refs, dict):
            secret_keys.update(str(k) for k in refs)

    leaked = [v for v in exported if str(v) in secret_keys]
    if not leaked or not model.jobs:
        return []

    return [
        make_finding(
            pattern=pattern,
            model=model,
            job=model.jobs[0],
            step=None,
            evidence=[
                "Exported variables include secrets: " + ", ".join(str(v) for v in leaked),
                "Secrets will be passed as plaintext to downstream CodePipeline stages",
            ],
            line=0,
        )
    ]


def match_cloudbuild_secret_in_env(
    model: WorkflowModel, pattern: dict[str, Any], make_finding: MakeFinding
) -> list[Finding]:
    if model.platform != "cloudbuild":
        return []

    findings: list[Finding] = []
    for job in model.jobs:
        for step in job.steps:
            secret_keys = [k for k in step.env if _is_secret_key(k)]
            if secret_keys:
                findings.append(
                    make_finding(
                        pattern=pattern,
                        model=model,
                        job=job,
                        step=step,
                        evidence=[
                            "Secret-like env vars in step: " + ", ".join(secret_keys),
                            "Use availableSecrets.secretManager instead",
                        ],
                        line=0,
                    )
                )
    return findings


def match_cloudbuild_default_sa(
    model: WorkflowModel, pattern: dict[str, Any], make_finding: MakeFinding
) -> list[Finding]:
    if model.platform != "cloudbuild":
        return []

    if model.raw.get("serviceAccount"):
        return []

    if not model.jobs:
        return []

    return [
        make_finding(
            pattern=pattern,
            model=model,
            job=model.jobs[0],
            step=None,
            evidence=[
                "No serviceAccount specified — build uses default Cloud Build SA",
                "Default SA typically has Editor role (overprivileged)",
            ],
            line=0,
        )
    ]
