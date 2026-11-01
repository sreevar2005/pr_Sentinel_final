"""Output formats. Every formatter escapes PR-controlled text for its own target."""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable

from prscreen.engine import ScanResult
from prscreen.models import Severity

EVIDENCE_DISPLAY_CHARS = 200


def summary_line(result: ScanResult) -> str:
    total = len(result.findings)
    if total == 0:
        return f"No findings in {_files(result.files_scanned)}."
    counts = Counter(f.severity for f in result.findings)
    parts = [f"{counts[s]} {s.label}" for s in sorted(Severity, reverse=True) if counts[s]]
    noun = "finding" if total == 1 else "findings"
    return f"{total} {noun} ({', '.join(parts)}) in {_files(result.files_scanned)}."


def _files(n: int) -> str:
    return "1 file" if n == 1 else f"{n} files"


def render(result: ScanResult, fmt: str) -> str:
    return FORMATS[fmt](result)


def _registry() -> dict[str, Callable[[ScanResult], str]]:
    from prscreen.formats import github, json_, markdown, sarif, text

    return {
        "text": text.render,
        "markdown": markdown.render,
        "github": github.render,
        "sarif": sarif.render,
        "json": json_.render,
    }


FORMATS = _registry()
