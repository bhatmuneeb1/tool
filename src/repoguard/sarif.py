"""SARIF 2.1.0 serialization for RepoGuard findings."""

from __future__ import annotations

from typing import Iterable

from .scanner import Finding

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"

LEVEL_MAP = {"low": "note", "medium": "warning", "high": "error"}


def to_sarif(findings: Iterable[Finding]) -> dict[str, object]:
    items = list(findings)
    rules: dict[str, dict[str, object]] = {}
    results: list[dict[str, object]] = []

    for finding in items:
        rules.setdefault(
            finding.rule_id,
            {
                "id": finding.rule_id,
                "name": finding.rule_id,
                "shortDescription": {"text": finding.message},
                "defaultConfiguration": {"level": LEVEL_MAP[finding.severity]},
                "properties": {"security-severity": finding.severity},
            },
        )
        results.append(
            {
                "ruleId": finding.rule_id,
                "level": LEVEL_MAP[finding.severity],
                "message": {"text": finding.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.path},
                            "region": {"startLine": finding.line},
                        }
                    }
                ],
                "properties": {"severity": finding.severity},
            }
        )

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "RepoGuard",
                        "informationUri": "https://github.com/bhatmuneeb1/tool",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
