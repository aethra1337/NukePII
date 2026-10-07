"""SARIF 2.1.0 export for NukePII scan reports (stdlib only).

Converts a :class:`DataStreamer` scan report dict (as returned by
``scan_file``) into a minimal SARIF log so results can be consumed by
GitHub Code Scanning, VS Code SARIF Viewer, etc.

Only file/line-level locations are emitted — NukePII reports carry
line numbers (``preview[].line``) but not columns, so ``startColumn``
defaults to 1.
"""

from __future__ import annotations

from typing import Any

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
TOOL_NAME = "NukePII"
TOOL_URI = "https://github.com/anomalyco/opencode"


def _rule_index(breakdown: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rules = []
    for row in breakdown:
        pii_type = str(row.get("type", "PII"))
        rules.append(
            {
                "id": f"nukepii/{pii_type}",
                "name": pii_type,
                "shortDescription": {"text": f"PII detected: {pii_type}"},
                "fullDescription": {
                    "text": f"NukePII detector {pii_type} "
                    f"(compliance: {','.join(row.get('compliance', [])) or 'n/a'})."
                },
                "properties": {
                    "compliance": row.get("compliance", []),
                    "count": row.get("count", 0),
                },
            }
        )
    return rules


def report_to_sarif(report: dict[str, Any]) -> dict[str, Any]:
    """Convert a NukePII scan report dict to a SARIF log dict."""
    breakdown: list[dict[str, Any]] = list(report.get("breakdown", []))
    rules = _rule_index(breakdown)
    rule_ids = [r["id"] for r in rules]

    results: list[dict[str, Any]] = []
    # Preview rows carry the offending line numbers; attribute each line
    # to every detected type proportional to nothing — one result per
    # (line, type) would explode, so emit one result per preview line
    # tagged with all rule ids found in the file.
    for row in report.get("preview", []):
        line = int(row.get("line", 1) or 1)
        for rid in rule_ids:
            results.append(
                {
                    "ruleId": rid,
                    "level": "warning",
                    "message": {
                        "text": f"Possible PII ({rid}) in "
                        f"{report.get('filename', '?')}:{line} "
                        f"[risk {report.get('risk_score', 0)}/100 "
                        f"{report.get('risk_label', '')}]"
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": str(report.get("filename", "input")),
                                    "uriBaseId": "SRCROOT",
                                },
                                "region": {"startLine": line, "startColumn": 1},
                            }
                        }
                    ],
                }
            )
    # No preview lines but detections exist (e.g. truncated preview):
    # emit a single file-level result per rule so nothing is lost.
    if not results:
        for rid in rule_ids:
            results.append(
                {
                    "ruleId": rid,
                    "level": "warning",
                    "message": {"text": f"Possible PII ({rid}) in {report.get('filename', '?')}"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": str(report.get("filename", "input")),
                                    "uriBaseId": "SRCROOT",
                                },
                            }
                        }
                    ],
                }
            )

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": str(report.get("engine", "")),
                        "informationUri": TOOL_URI,
                        "rules": rules,
                    }
                },
                "artifactLocations": [{"uri": str(report.get("filename", "input"))}],
                "results": results,
                "properties": {
                    "riskScore": report.get("risk_score", 0),
                    "riskLabel": report.get("risk_label", ""),
                    "totalDetections": report.get("total_detections", 0),
                    "region": report.get("region", "ALL"),
                },
            }
        ],
    }


__all__ = ["SARIF_SCHEMA", "SARIF_VERSION", "report_to_sarif"]
