"""Result formatting — JSON, YAML, and SARIF output."""

from __future__ import annotations

import json
from dataclasses import asdict
from typing import TYPE_CHECKING, Any

import yaml

if TYPE_CHECKING:
    from pathlib import Path

    from actionsieve.engine import Finding


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

        result: dict[str, Any] = {
            "ruleId": f.pattern_id,
            "level": _sarif_level(f.severity_base),
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


def _finding_dict(f: Finding) -> dict[str, Any]:
    d = asdict(f)
    return {k: v for k, v in d.items() if v is not None and v != [] and v != {}}


def _sarif_level(severity: str) -> str:
    mapping = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "note",
    }
    return mapping.get(severity, "warning")
