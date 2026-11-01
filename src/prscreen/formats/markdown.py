"""GitHub-flavoured Markdown for job summaries and, later, PR comments.

PR text is either escaped (outside code) or put in a code fence longer than any backtick run it
contains, so it cannot add links, images, HTML or ``@mentions`` that notify people.
"""

from __future__ import annotations

import re

from prscreen import formats
from prscreen.engine import ScanResult
from prscreen.models import Finding, Severity
from prscreen.sanitize import visible

# GitHub rejects comments over 65,536 characters; detail sections stop well before that.
MAX_DETAILED = 50

_ICON = {Severity.HIGH: "🔴", Severity.MEDIUM: "🟠", Severity.LOW: "🟡"}
_MD_SPECIAL = re.compile(r"([\\`*_{}\[\]()#+\-.!|~])")


def escape(text: str) -> str:
    text = _MD_SPECIAL.sub(r"\\\1", visible(text))
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("@", "&#64;")


def code_block(text: str) -> str:
    text = visible(text, formats.EVIDENCE_DISPLAY_CHARS)
    longest = max((len(run) for run in re.findall(r"`+", text)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"{fence}text\n{text}\n{fence}"


def render(result: ScanResult) -> str:
    out = [
        "## prscreen report",
        "",
        f"**{formats.summary_line(result)}** Advisory only: each item is evidence for a human "
        "reviewer to judge, not a verdict about the change or its author.",
        "",
    ]
    if result.findings:
        out += ["| Severity | Rule | Location | Finding |", "| --- | --- | --- | --- |"]
        out += [_row(f) for f in result.findings]
        out.append("")
        for f in result.findings[:MAX_DETAILED]:
            out += _details(f)
        hidden = len(result.findings) - MAX_DETAILED
        if hidden > 0:
            out += [f"_{hidden} more findings are listed in the table only._", ""]
    out += _notes(result)
    return "\n".join(out).rstrip() + "\n"


def _location(f: Finding) -> str:
    return escape(f.path) + (f":{f.line}" if f.line else "")


def _row(f: Finding) -> str:
    return (
        f"| {_ICON[f.severity]} {f.severity.label} | {f.rule.id} | {_location(f)} | {escape(f.rule.title)} |"
    )


def _details(f: Finding) -> list[str]:
    lines = [
        f"### {_ICON[f.severity]} {f.rule.id} · {escape(f.rule.title)}",
        "",
        f"`{f.severity.label}` severity · `{f.confidence.label}` confidence · {_location(f)}",
        "",
        code_block(f.evidence),
        "",
    ]
    if f.detail:
        lines += [escape(f.detail), ""]
    lines += [f"**Why it matters:** {escape(f.rule.rationale)}", ""]
    lines += [f"**Could be harmless if:** {escape(f.rule.benign)}", ""]
    return lines


def _notes(result: ScanResult) -> list[str]:
    notes = [f"- Skipped {escape(path)}: {escape(reason)}" for path, reason in result.skipped]
    notes += [
        f"- {rule_id} in {escape(path)}: {n} more findings not shown"
        for (rule_id, path), n in result.capped.items()
    ]
    notes += [f"- ⚠️ {escape(error)}. **Results are incomplete.**" for error in result.errors]
    return ["### Notes", "", *notes, ""] if notes else []
