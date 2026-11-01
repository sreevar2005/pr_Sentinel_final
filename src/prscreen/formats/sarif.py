"""SARIF 2.1.0, the format GitHub code scanning (and most security dashboards) import."""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import quote

from prscreen import __version__
from prscreen.engine import ScanResult
from prscreen.models import Finding, Rule, Severity
from prscreen.sanitize import visible

_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_LEVEL = {Severity.HIGH: "error", Severity.MEDIUM: "warning", Severity.LOW: "note"}
# GitHub maps security-severity >= 7.0 to "high", >= 4.0 to "medium", otherwise "low".
_SECURITY_SEVERITY = {Severity.HIGH: "8.0", Severity.MEDIUM: "5.5", Severity.LOW: "3.0"}


def render(result: ScanResult) -> str:
    rule_index = {rule.id: i for i, rule in enumerate(result.rules)}
    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": "prscreen",
                "version": __version__,
                "rules": [_rule(rule) for rule in result.rules],
            }
        },
        "results": [_result(f, rule_index) for f in result.findings],
        "invocations": [
            {
                "executionSuccessful": result.complete,
                "toolExecutionNotifications": [
                    {"level": "error", "message": {"text": visible(error)}} for error in result.errors
                ],
            }
        ],
    }
    return json.dumps({"$schema": _SCHEMA, "version": "2.1.0", "runs": [run]}, indent=2) + "\n"


def _rule(rule: Rule) -> dict[str, Any]:
    return {
        "id": rule.id,
        "name": rule.title,
        "shortDescription": {"text": rule.title},
        "fullDescription": {"text": rule.rationale},
        "help": {"text": f"{rule.rationale}\n\nCould be harmless if: {rule.benign}"},
        "defaultConfiguration": {"level": _LEVEL[rule.severity]},
        "properties": {
            "tags": ["security", rule.category.value],
            "security-severity": _SECURITY_SEVERITY[rule.severity],
            "precision": {3: "high", 2: "medium", 1: "low"}[rule.confidence],
        },
    }


def _result(f: Finding, rule_index: dict[str, int]) -> dict[str, Any]:
    location: dict[str, Any] = {"artifactLocation": {"uri": quote(f.path), "uriBaseId": "%SRCROOT%"}}
    if f.line:
        location["region"] = {"startLine": f.line, "snippet": {"text": visible(f.evidence)}}
    text = " ".join(part for part in (f.rule.title + ".", visible(f.detail)) if part)
    return {
        "ruleId": f.rule.id,
        "ruleIndex": rule_index[f.rule.id],
        "level": _LEVEL[f.severity],
        "message": {"text": text},
        "locations": [{"physicalLocation": location}],
        "partialFingerprints": {"prscreen/v1": f.fingerprint},
        "properties": {"confidence": f.confidence.label},
    }
