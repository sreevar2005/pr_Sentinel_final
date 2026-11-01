"""Checks every claim the model makes before any of it reaches a reviewer.

The model's reply is treated as untrusted as the diff itself, because a prompt injection in the
diff can steer it. A reply can only *add* text, never change rule findings, and only text that
passes every check below is kept:

* the reply must match the schema exactly (no extra keys such as "remove_findings");
* notes must refer to a finding that exists, at most one note per finding;
* questions must name a file in the diff and an added line, and quote that line;
* nothing may dismiss a finding or declare the change safe (the verdict filter);
* lengths and counts are capped.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from prscreen.ai.prompt import MAX_NOTE_CHARS, MAX_QUESTION_CHARS, MAX_QUESTIONS
from prscreen.diff import ChangeKind, Diff
from prscreen.models import Finding
from prscreen.sanitize import visible

# Wording that turns a note or question into a verdict. The AI explains; the reviewer decides.
_VERDICT_RE = re.compile(
    r"(?i)\b(?:safe to (?:merge|ship|approve)|(?:is|looks|seems|appears)\s+(?:completely\s+|perfectly\s+)?"
    r"(?:safe|fine|harmless|benign)|false\s+positive|can\s+(?:safely\s+)?be\s+ignored|(?:no|not\s+an?)\s+"
    r"(?:real\s+)?(?:security\s+)?(?:issues?|risks?|problems?|concerns?)|lgtm|approve[ds]?|dismiss)\b"
)
_MIN_QUOTE_CHARS = 6


@dataclass
class Question:
    path: str
    line: int
    line_text: str
    question: str


@dataclass
class Validated:
    notes: dict[str, str] = field(default_factory=dict)
    questions: list[Question] = field(default_factory=list)
    rejected: list[str] = field(default_factory=list)


class InvalidReply(ValueError):
    pass


def _norm(text: str) -> str:
    return " ".join(text.split())


def parse_reply(raw: str) -> dict[str, Any]:
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise InvalidReply(f"reply is not JSON ({exc.msg})") from exc
    if not isinstance(data, dict) or set(data) != {"notes", "questions"}:
        raise InvalidReply("reply must be an object with exactly 'notes' and 'questions'")
    if not isinstance(data["notes"], list) or not isinstance(data["questions"], list):
        raise InvalidReply("'notes' and 'questions' must be lists")
    return data


def validate(data: dict[str, Any], diff: Diff, finding_ids: dict[str, Finding]) -> Validated:
    out = Validated()
    for item in data["notes"]:
        if not (isinstance(item, dict) and set(item) == {"finding", "note"}):
            out.rejected.append("note: malformed")
            continue
        fid, note = item["finding"], item["note"]
        if not isinstance(fid, str) or not isinstance(note, str) or not note.strip():
            out.rejected.append("note: malformed")
        elif fid not in finding_ids:
            out.rejected.append(f"note: refers to unknown finding {visible(fid, 20)!r}")
        elif fid in out.notes:
            out.rejected.append(f"note: second note for {fid}")
        elif _VERDICT_RE.search(note):
            out.rejected.append(f"note on {fid}: dismisses the finding or gives a verdict")
        else:
            out.notes[fid] = visible(_norm(note), MAX_NOTE_CHARS)

    added = {
        (change.path, line.number): line.text
        for change in diff.files
        if change.kind is not ChangeKind.DELETED and not change.binary
        for line in change.added
    }
    paths = {change.path for change in diff.files}
    for item in data["questions"]:
        reason = _question_problem(item, paths, added)
        if reason:
            out.rejected.append(f"question: {reason}")
            continue
        if len(out.questions) == MAX_QUESTIONS:
            out.rejected.append(f"question: over the limit of {MAX_QUESTIONS}")
            continue
        out.questions.append(
            Question(
                path=item["path"],
                line=item["line"],
                line_text=added[(item["path"], item["line"])],
                question=visible(_norm(item["question"]), MAX_QUESTION_CHARS),
            )
        )
    return out


def _question_problem(item: Any, paths: set[str], added: dict[tuple[str, int], str]) -> str | None:
    if not (isinstance(item, dict) and set(item) == {"path", "line", "quote", "question"}):
        return "malformed"
    path, line, quote, question = item["path"], item["line"], item["quote"], item["question"]
    if not (isinstance(path, str) and isinstance(quote, str) and isinstance(question, str)):
        return "malformed"
    if not isinstance(line, int) or isinstance(line, bool):
        return "malformed"
    if path not in paths:
        return f"file {visible(path, 80)!r} is not in the diff"
    if (path, line) not in added:
        return f"{visible(path, 80)}:{line} is not an added line"
    norm_quote = _norm(quote)
    if len(norm_quote) < _MIN_QUOTE_CHARS or norm_quote not in _norm(added[(path, line)]):
        return f"quote does not match {visible(path, 80)}:{line}"
    if not question.strip():
        return "empty question"
    if _VERDICT_RE.search(question):
        return "gives a verdict instead of asking"
    return None
