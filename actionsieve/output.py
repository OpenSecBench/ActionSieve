"""Result formatting — JSON, YAML, SARIF, Markdown, and CycloneDX output."""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml
from jinja2 import Environment, FileSystemLoader

if TYPE_CHECKING:
    from actionsieve.engine import Finding
    from actionsieve.inventory import Inventory

_TEMPLATE_DIR = Path(__file__).parent / "templates"

SEVERITY_ORDER_LIST = ["critical", "high", "medium", "low", "info"]


def render(
    findings: list[Finding],
    fmt: str,
    output_file: Path | None = None,
    *,
    notes: list[str] | None = None,
) -> str:
    if fmt == "json":
        text = render_json(findings, notes=notes)
    elif fmt == "yaml":
        text = render_yaml(findings, notes=notes)
    elif fmt == "sarif":
        text = render_sarif(findings, notes=notes)
    elif fmt == "markdown":
        text = render_markdown(findings, notes=notes)
    elif fmt == "ocsf":
        text = render_ocsf(findings, notes=notes)
    else:
        msg = f"Unknown format: {fmt}"
        raise ValueError(msg)

    if output_file:
        output_file.write_text(text, encoding="utf-8")

    return text


def render_json(findings: list[Finding], *, notes: list[str] | None = None) -> str:
    result: dict[str, Any] = {"findings": [_finding_dict(f) for f in findings]}
    if notes:
        result["notes"] = notes
    return json.dumps(result, indent=2)


def render_yaml(findings: list[Finding], *, notes: list[str] | None = None) -> str:
    result: dict[str, Any] = {"findings": [_finding_dict(f) for f in findings]}
    if notes:
        result["notes"] = notes
    return yaml.dump(result, default_flow_style=False, sort_keys=False)


def render_sarif(findings: list[Finding], *, notes: list[str] | None = None) -> str:
    rules: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    seen_rules: set[str] = set()

    for f in findings:
        if f.pattern_id not in seen_rules:
            rules.append(
                {
                    "id": f.pattern_id,
                    "name": f.pattern_title,
                    "shortDescription": {"text": f.pattern_title},
                    "defaultConfiguration": {
                        "level": _sarif_level(f.severity_base),
                    },
                    "properties": {
                        "tags": f.tags,
                    },
                }
            )
            seen_rules.add(f.pattern_id)

        effective_severity = f.severity_computed or f.severity_base
        result: dict[str, Any] = {
            "ruleId": f.pattern_id,
            "level": _sarif_level(effective_severity),
            "message": {"text": "; ".join(f.evidence)},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.file_path},
                        "region": {"startLine": max(f.line, 1)},
                    },
                },
            ],
        }
        if f.cwe:
            result["taxa"] = [{"id": f.cwe, "toolComponent": {"name": "CWE"}}]
        results.append(result)

    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": "actionsieve",
                "informationUri": "https://github.com/OpenSecBench/ActionSieve",
                "rules": rules,
            },
        },
        "results": results,
    }

    if notes:
        run["invocations"] = [
            {
                "executionSuccessful": True,
                "toolExecutionNotifications": [
                    {"level": "note", "message": {"text": n}} for n in notes
                ],
            }
        ]

    sarif: dict[str, Any] = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [run],
    }

    return json.dumps(sarif, indent=2)


def render_markdown(findings: list[Finding], *, notes: list[str] | None = None) -> str:
    grouped: list[tuple[str, list[Finding]]] = []
    by_severity: dict[str, list[Finding]] = {}
    for f in findings:
        sev = f.severity_computed or f.severity_base
        by_severity.setdefault(sev, []).append(f)
    for sev in SEVERITY_ORDER_LIST:
        if sev in by_severity:
            grouped.append((sev, by_severity[sev]))

    counts = [f"{len(g)} {s}" for s, g in grouped]
    summary = ", ".join(counts) if counts else "none"

    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=False,  # noqa: S701 — Markdown output, not HTML
        keep_trailing_newline=True,
    )
    template = env.get_template("report.md.j2")
    return template.render(
        scan_date=datetime.now(UTC).date().isoformat(),
        total=len(findings),
        summary=summary,
        findings=findings,
        grouped=grouped,
        notes=notes or [],
    )


def render_ocsf(findings: list[Finding], *, notes: list[str] | None = None) -> str:
    now = datetime.now(UTC).isoformat()
    metadata: dict[str, Any] = {
        "version": "1.4.0",
        "product": {"name": "actionsieve", "vendor_name": "actionsieve"},
    }
    events = [_ocsf_event(f, now, metadata) for f in findings]
    result: dict[str, Any] = {"detection_findings": events}
    if notes:
        result["notes"] = notes
    return json.dumps(result, indent=2)


def _ocsf_event(f: Finding, ts: str, metadata: dict[str, Any]) -> dict[str, Any]:
    severity = f.severity_computed or f.severity_base
    event: dict[str, Any] = {
        "class_uid": 2004,
        "category_uid": 2,
        "activity_id": 1,
        "type_uid": 200401,
        "severity_id": _ocsf_severity(severity),
        "severity": severity,
        "status_id": 1,
        "time": ts,
        "message": f"{f.pattern_title} in {f.file_path}",
        "metadata": metadata,
        "finding_info": {
            "uid": f"{f.pattern_id}:{f.file_path}:{f.job_id}:{f.step_index or 0}",
            "title": f.pattern_title,
            "desc": "; ".join(f.evidence),
            "analytic": {
                "uid": f.pattern_id,
                "name": f.pattern_title,
                "type_id": 1,
                "type": "Rule",
            },
            "types": f.tags,
            "data_sources": [f.file_path],
        },
        "resources": [{"name": f.file_path, "uid": f.file_path, "type": "CI/CD Pipeline"}],
    }
    if f.cwe:
        event["finding_info"]["cwe"] = {
            "uid": f.cwe,
            "src_url": f"https://cwe.mitre.org/data/definitions/{f.cwe.split('-')[-1]}.html",
        }
    return event


_OCSF_SEVERITY = {"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}


def _ocsf_severity(severity: str) -> int:
    return _OCSF_SEVERITY.get(severity, 0)


def _finding_dict(f: Finding) -> dict[str, Any]:
    d = asdict(f)
    return {k: v for k, v in d.items() if v is not None and v != [] and v != {}}


def render_inventory(
    inv: Inventory,
    fmt: str,
    output_file: Path | None = None,
) -> str:
    if fmt == "json":
        text = json.dumps(inv.to_dict(), indent=2)
    elif fmt == "yaml":
        text = yaml.dump(inv.to_dict(), default_flow_style=False, sort_keys=False)
    elif fmt == "cyclonedx":
        text = _render_cyclonedx(inv)
    else:
        msg = f"Unknown inventory format: {fmt}"
        raise ValueError(msg)

    if output_file:
        output_file.write_text(text, encoding="utf-8")

    return text


def _render_cyclonedx(inv: Inventory) -> str:
    components: list[dict[str, Any]] = []

    for comp in inv.components:
        if comp.is_local:
            continue
        purl = _make_purl(comp)
        cdx_comp: dict[str, Any] = {
            "type": "library",
            "name": comp.key,
            "version": comp.ref,
            "purl": purl,
            "properties": [
                {"name": "actionsieve:ref_type", "value": comp.ref_type},
                {"name": "actionsieve:is_pinned", "value": str(comp.is_pinned).lower()},
                {"name": "actionsieve:is_first_party", "value": str(comp.is_first_party).lower()},
                {"name": "actionsieve:platform", "value": comp.platform},
            ],
        }
        if comp.trust_score:
            cdx_comp["properties"].append(
                {"name": "actionsieve:trust_score", "value": comp.trust_score}
            )
        if comp.advisory_ids:
            cdx_comp["properties"].append(
                {"name": "actionsieve:advisories", "value": ",".join(comp.advisory_ids)}
            )
        components.append(cdx_comp)

    metadata: dict[str, Any] = {
        "timestamp": datetime.now(UTC).isoformat(),
        "tools": [{"name": "actionsieve"}],
    }
    if inv.repo:
        metadata["component"] = {
            "type": "application",
            "name": inv.repo,
        }

    bom: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": metadata,
        "components": components,
    }

    return json.dumps(bom, indent=2)


_PURL_NAMESPACE = {
    "github": "githubactions",
    "gitlab": "gitlabci",
    "azure": "azurepipelines",
    "jenkins": "jenkins",
    "circleci": "circleci",
    "bitbucket": "bitbucket",
    "buildkite": "buildkite",
    "drone": "drone",
    "codebuild": "codebuild",
    "cloudbuild": "cloudbuild",
}


def _make_purl(comp: Any) -> str:
    ns = _PURL_NAMESPACE.get(comp.platform, "cicd")
    if comp.owner and comp.owner != ".":
        return f"pkg:{ns}/{comp.owner}/{comp.name}@{comp.ref}"
    return f"pkg:{ns}/{comp.name}@{comp.ref}"


def _sarif_level(severity: str) -> str:
    mapping = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "note",
    }
    return mapping.get(severity, "warning")
