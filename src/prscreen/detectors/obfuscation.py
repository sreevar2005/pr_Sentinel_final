"""Code that reads differently to a human reviewer than to the machine."""

from __future__ import annotations

from collections.abc import Iterator

from prscreen.detectors import LineDetector
from prscreen.diff import DiffLine, FileChange
from prscreen.models import Category, Confidence, Finding, Rule, Severity

# Embedding, override and isolate controls: the characters used by "Trojan Source"
# (CVE-2021-42574). LRM/RLM/ALM are left out: they are common in real right-to-left text and
# cannot reorder code on their own.
_BIDI_CONTROLS = {
    "\u202a": "LRE",
    "\u202b": "RLE",
    "\u202c": "PDF",
    "\u202d": "LRO",
    "\u202e": "RLO",
    "\u2066": "LRI",
    "\u2067": "RLI",
    "\u2068": "FSI",
    "\u2069": "PDI",
}
# Prose and translation files: a control character there misleads readers, not compilers.
_TEXT_SUFFIXES = (".md", ".rst", ".txt", ".po", ".pot", ".xlf", ".xliff", ".strings", ".resx")

BIDI_CONTROL = Rule(
    id="OBF001",
    title="Hidden bidirectional control character",
    category=Category.OBFUSCATION,
    severity=Severity.HIGH,
    confidence=Confidence.HIGH,
    rationale=(
        "Invisible Unicode controls change the order in which text is displayed, so code can look "
        "different in review from how the compiler or interpreter reads it ('Trojan Source', "
        "CVE-2021-42574). A comment can appear to close early, or a string can appear to hold "
        "code that actually runs."
    ),
    benign=(
        "Right-to-left text (Arabic, Hebrew, Persian) in strings, comments or translation files "
        "sometimes needs these characters. That is fine when they sit inside readable text and "
        "not around code tokens."
    ),
)


class BidiControlDetector(LineDetector):
    name = "bidi-control"
    rules = (BIDI_CONTROL,)

    def check_line(self, change: FileChange, line: DiffLine) -> Iterator[Finding]:
        hits = [(col, ch) for col, ch in enumerate(line.text, start=1) if ch in _BIDI_CONTROLS]
        if not hits:
            return
        names = ", ".join(f"U+{ord(ch):04X} {_BIDI_CONTROLS[ch]} at column {col}" for col, ch in hits[:5])
        if len(hits) > 5:
            names += f" and {len(hits) - 5} more"
        prose = change.path.lower().endswith(_TEXT_SUFFIXES)
        yield BIDI_CONTROL.finding(
            change.path,
            line.number,
            line.text,
            f"Contains {names}.",
            severity=Severity.MEDIUM if prose else None,
            confidence=Confidence.MEDIUM if prose else None,
        )
