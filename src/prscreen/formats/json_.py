"""prscreen's own JSON, for scripts and the evaluation harness."""

from __future__ import annotations

import json
from typing import Any

from prscreen import __version__, formats
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
        "findings": [_finding(f, formats.ai_note(result, f)) for f in result.findings],
        "skipped": [{"path": visible(path), "reason": reason} for path, reason in result.skipped],
        "capped": [
            {"rule_id": rule_id, "path": visible(path), "dropped": n}
            for (rule_id, path), n in result.capped.items()
        ],
        "errors": [visible(error) for error in result.errors],
        "ai": _ai(result),
    }
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"


def _finding(f: Finding, note: str | None) -> dict[str, Any]:
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
        "ai_note": visible(note) if note else None,
    }


def _ai(result: ScanResult) -> dict[str, Any] | None:
    ai = result.ai
    if ai is None:
        return None
    return {
        "provider": ai.provider,
        "model": ai.model,
        "status": visible(ai.status),
        "notes": len(ai.notes),
        "questions": ai.questions,
        "rejected": [visible(reason) for reason in ai.rejected],
        "truncated": ai.truncated,
    }
