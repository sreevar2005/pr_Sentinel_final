"""Optional AI review on top of the rules. Off unless asked for; prscreen is complete without it.

The one invariant: **the AI can add, never remove.** :func:`review` returns a new result whose
first findings are exactly the rule findings it was given, in the same order, followed by any
validated AI questions. Notes attach to findings by key and never replace their text. If the
model fails, refuses, times out or replies with anything invalid, the rule result comes back
unchanged with the problem recorded in :class:`AIReport`.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace

from prscreen.ai.prompt import OUTPUT_SCHEMA, build_prompt
from prscreen.ai.providers import Provider, ProviderError
from prscreen.ai.validate import InvalidReply, parse_reply, validate
from prscreen.diff import Diff
from prscreen.engine import ScanResult
from prscreen.models import Category, Confidence, Finding, Rule, Severity

AI_QUESTION = Rule(
    id="AI001",
    title="Question from the AI reviewer",
    category=Category.AI_REVIEW,
    severity=Severity.LOW,
    confidence=Confidence.LOW,
    rationale=(
        "Only with --ai. A language model read the diff and asked about this added line. The line and "
        "quote were checked against the diff; the reasoning was not. Treat it as a prompt to look, "
        "never as evidence on its own."
    ),
    benign=(
        "Models raise plausible-sounding concerns about ordinary code; many questions have simple answers."
    ),
)

NoteKey = tuple[str, str, int | None]


def note_key(finding: Finding) -> NoteKey:
    return (finding.rule.id, finding.path, finding.line)


@dataclass
class AIReport:
    provider: str
    model: str
    status: str
    """"ok", or why the AI output was not used ("failed: ...", "invalid reply: ...")."""
    notes: dict[NoteKey, str] = field(default_factory=dict)
    questions: int = 0
    rejected: list[str] = field(default_factory=list)
    truncated: bool = False

    @property
    def ok(self) -> bool:
        return self.status == "ok"


def review(result: ScanResult, diff: Diff, provider: Provider, title: str = "", body: str = "") -> ScanResult:
    rule_findings = list(result.findings)
    prompt = build_prompt(diff, rule_findings, title, body)
    report = AIReport(provider=provider.name, model=provider.model, status="ok", truncated=prompt.truncated)
    try:
        data = parse_reply(provider.complete(prompt.system, prompt.user, OUTPUT_SCHEMA))
    except ProviderError as exc:
        report.status = f"failed: {exc}"
        return replace(result, ai=report)
    except InvalidReply as exc:
        report.status = f"invalid reply: {exc}"
        return replace(result, ai=report)

    checked = validate(data, diff, prompt.finding_ids)
    report.rejected = checked.rejected
    report.notes = {note_key(prompt.finding_ids[fid]): text for fid, text in checked.notes.items()}
    questions = [
        AI_QUESTION.finding(q.path, q.line, q.line_text, f"AI question: {q.question}")
        for q in checked.questions
    ]
    report.questions = len(questions)
    rules = result.rules if not questions else [*result.rules, AI_QUESTION]
    return replace(result, findings=[*rule_findings, *questions], rules=rules, ai=report)


__all__ = ["AI_QUESTION", "AIReport", "Provider", "ProviderError", "note_key", "review"]
