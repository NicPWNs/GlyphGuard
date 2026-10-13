"""SARIF 2.1.0 output, the format GitHub code scanning and most security dashboards read."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from glyphguard.catalog import Severity, Technique, techniques
from glyphguard.findings import Finding

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFORMATION_URI = "https://github.com/NicPWNs/GlyphGuard"
CATALOG_URI = "https://github.com/NicPWNs/GlyphGuard/blob/main/src/glyphguard/catalog.toml"

# GitHub code scanning buckets security-severity: >= 9 critical, >= 7 high, >= 4 medium,
# otherwise low.
SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "1.0",
}
LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


@dataclass(frozen=True, slots=True)
class Located:
    """A finding with its file and 1-based line/column range (end column exclusive)."""

    path: str | None
    finding: Finding
    start_line: int
    start_column: int
    end_line: int
    end_column: int


def _rule(technique: Technique) -> dict[str, Any]:
    references = "".join(f"\n- <{url}>" for url in technique.references)
    cwes = ", ".join(technique.cwe)
    markdown = f"**{technique.title}** ({technique.id})\n\n{technique.summary}\n"
    if cwes:
        markdown += f"\nRelated weaknesses: {cwes}\n"
    if references:
        markdown += f"\nReferences:{references}\n"
    tags = ["security", "unicode", technique.family.lower()]
    tags += [f"external/cwe/{cwe.lower()}" for cwe in technique.cwe]
    return {
        "id": technique.id,
        "name": "".join(part.capitalize() for part in technique.slug.split("-")),
        "shortDescription": {"text": technique.title},
        "fullDescription": {"text": technique.summary},
        "helpUri": technique.references[0] if technique.references else CATALOG_URI,
        "help": {"text": technique.summary, "markdown": markdown},
        "defaultConfiguration": {"level": LEVEL[technique.severity]},
        "properties": {
            "tags": tags,
            "precision": "high",
            "security-severity": SECURITY_SEVERITY[technique.severity],
        },
    }


def _result(item: Located, rule_index: dict[str, int]) -> dict[str, Any]:
    f = item.finding
    result: dict[str, Any] = {
        "ruleId": f.technique_id,
        "ruleIndex": rule_index[f.technique_id],
        "level": LEVEL[f.severity],
        "message": {"text": f"{f.technique.title}: {f.message}"},
        "properties": {
            "severity": str(f.severity),
            "security-severity": SECURITY_SEVERITY[f.severity],
            "codepoints": [f"U+{cp:04X}" for cp in f.codepoints[:64]],
        },
    }
    if f.payload is not None:
        result["properties"]["payload"] = f.payload.to_dict()
    if item.path is not None:
        result["locations"] = [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": item.path.replace("\\", "/"),
                        "uriBaseId": "%SRCROOT%",
                    },
                    "region": {
                        "startLine": item.start_line,
                        "startColumn": item.start_column,
                        "endLine": item.end_line,
                        "endColumn": item.end_column,
                    },
                }
            }
        ]
    return result


def to_sarif(results: list[Located], *, version: str) -> dict[str, Any]:
    """A SARIF 2.1.0 log for ``results``, with every catalog technique as a rule."""
    catalog = list(techniques().values())
    rule_index = {technique.id: i for i, technique in enumerate(catalog)}
    return {
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "GlyphGuard",
                        "version": version,
                        "semanticVersion": version,
                        "informationUri": INFORMATION_URI,
                        "rules": [_rule(technique) for technique in catalog],
                    }
                },
                "columnKind": "unicodeCodePoints",
                "results": [_result(item, rule_index) for item in results],
            }
        ],
    }
