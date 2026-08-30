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
) -> str:
    if fmt == "json":
        text = render_json(findings)
    elif fmt == "yaml":
        text = render_yaml(findings)
    elif fmt == "sarif":
        text = render_sarif(findings)
    elif fmt == "markdown":
        text = render_markdown(findings)
    else:
        msg = f"Unknown format: {fmt}"
        raise ValueError(msg)

    if output_file:
        output_file.write_text(text, encoding="utf-8")

    return text


def render_json(findings: list[Finding]) -> str:
    return json.dumps(
        {"findings": [_finding_dict(f) for f in findings]},
        indent=2,
    )


def render_yaml(findings: list[Finding]) -> str:
    return yaml.dump(
        {"findings": [_finding_dict(f) for f in findings]},
        default_flow_style=False,
        sort_keys=False,
    )


def render_sarif(findings: list[Finding]) -> str:
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

    sarif: dict[str, Any] = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "actionsieve",
                        "informationUri": "https://github.com/OpenSecBench/actionsieve",
                        "rules": rules,
                    },
                },
                "results": results,
            },
        ],
    }

    return json.dumps(sarif, indent=2)


def render_markdown(findings: list[Finding]) -> str:
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
    )


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

    bom: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "tools": [{"name": "actionsieve"}],
        },
        "components": components,
    }

    return json.dumps(bom, indent=2)


def _make_purl(comp: Any) -> str:
    if comp.owner:
        return f"pkg:githubactions/{comp.owner}/{comp.name}@{comp.ref}"
    return f"pkg:githubactions/{comp.name}@{comp.ref}"


def _sarif_level(severity: str) -> str:
    mapping = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "note",
    }
    return mapping.get(severity, "warning")
