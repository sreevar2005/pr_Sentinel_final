"""prscreen's own JSON, for scripts and the evaluation harness."""

from __future__ import annotations

import json
from typing import Any

from prscreen import __version__
from prscreen.engine import ScanResult
from prscreen.models import Finding
from prscreen.sanitize import visible

SCHEMA_VERSION = 1


def render(result: ScanResult) -> str:
    doc: dict[str, Any] = {
        "tool": "prscreen",
        "version": __version__,
        "schema_version": SCHEMA_VERSION,
        "complete": result.complete,
        "files_scanned": result.files_scanned,
        "findings": [_finding(f) for f in result.findings],
        "skipped": [{"path": visible(path), "reason": reason} for path, reason in result.skipped],
        "capped": [
            {"rule_id": rule_id, "path": visible(path), "dropped": n}
            for (rule_id, path), n in result.capped.items()
        ],
        "errors": [visible(error) for error in result.errors],
    }
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"


def _finding(f: Finding) -> dict[str, Any]:
    return {
        "rule_id": f.rule.id,
        "title": f.rule.title,
        "category": f.rule.category.value,
        "severity": f.severity.label,
        "confidence": f.confidence.label,
        "path": visible(f.path),
        "line": f.line,
        "evidence": visible(f.evidence),
        "detail": visible(f.detail),
        "fingerprint": f.fingerprint,
    }
