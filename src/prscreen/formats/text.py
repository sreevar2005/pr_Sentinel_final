"""Plain text for terminals and logs."""

from __future__ import annotations

import textwrap

from prscreen import formats
from prscreen.engine import ScanResult
from prscreen.sanitize import visible

_WIDTH = 100
_INDENT = " " * 6


def render(result: ScanResult) -> str:
    out = [f"prscreen: {formats.summary_line(result)}", ""]
    for f in result.findings:
        location = visible(f.path) + (f":{f.line}" if f.line else "")
        out.append(f"{f.severity.label.upper():<6} {f.rule.id}  {location}  {f.rule.title}")
        out.append(f"{_INDENT}evidence:   {visible(f.evidence, formats.EVIDENCE_DISPLAY_CHARS)}")
        if f.detail:
            out.extend(_wrap("detail", visible(f.detail)))
        out.extend(_wrap("why", f.rule.rationale))
        out.extend(_wrap("benign if", f.rule.benign))
        if note := formats.ai_note(result, f):
            out.extend(_wrap("ai note", f"{visible(note)} (AI-generated, unverified)"))
        out.append(f"{_INDENT}confidence: {f.confidence.label}")
        out.append("")
    out.extend(_notes(result))
    if result.findings:
        out.append("These are signals for a human reviewer, not verdicts.")
    return "\n".join(out).rstrip() + "\n"


def _wrap(label: str, body: str) -> list[str]:
    head = f"{_INDENT}{label + ':':<12}"
    return textwrap.wrap(
        body, _WIDTH, initial_indent=head, subsequent_indent=" " * len(head), break_on_hyphens=False
    ) or [head]


def _notes(result: ScanResult) -> list[str]:
    notes = [f"skipped {visible(path)}: {reason}" for path, reason in result.skipped]
    notes += [
        f"capped {rule_id} in {visible(path)}: {n} more findings not shown"
        for (rule_id, path), n in result.capped.items()
    ]
    notes += [f"ERROR {visible(error)} (results are incomplete)" for error in result.errors]
    if status := formats.ai_status(result):
        notes.append(visible(status))
        if result.ai is not None:
            notes += [f"  rejected {visible(reason)}" for reason in result.ai.rejected]
    return [*notes, ""] if notes else []
