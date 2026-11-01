"""GitHub Actions workflow commands that show findings as annotations on the PR's changed lines.

The runner reads any stdout line starting with ``::`` as a command, so PR text in a command must
never be able to start a new line or end the property list early. Values are escaped the way
the runner expects (``%``, CR and LF in data; also ``:`` and ``,`` in properties), after
:func:`prscreen.sanitize.visible` has already removed every control character.

GitHub shows at most 10 error and 10 warning annotations per step, so findings are emitted
most severe first. The Markdown job summary carries the full list.
"""

from __future__ import annotations

from prscreen import formats
from prscreen.engine import ScanResult
from prscreen.models import Severity
from prscreen.sanitize import visible

_LEVEL = {Severity.HIGH: "error", Severity.MEDIUM: "warning", Severity.LOW: "notice"}


def escape_data(text: str) -> str:
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def escape_property(text: str) -> str:
    return escape_data(text).replace(":", "%3A").replace(",", "%2C")


def render(result: ScanResult, min_severity: Severity | None = Severity.LOW) -> str:
    """Annotations for findings at ``min_severity`` or above (``None``: no annotations at all)."""
    out = []
    shown = [f for f in result.findings if min_severity is not None and f.severity >= min_severity]
    for f in shown:
        props = [f"file={escape_property(visible(f.path))}"]
        if f.line:
            props.append(f"line={f.line}")
        props.append(f"title={escape_property(f'{f.rule.id} {f.rule.title}')}")
        message = f"{f.detail} Evidence: {visible(f.evidence, formats.EVIDENCE_DISPLAY_CHARS)}".strip()
        message += f" ({f.confidence.label} confidence; advisory, verify before acting)"
        out.append(f"::{_LEVEL[f.severity]} {','.join(props)}::{escape_data(visible(message))}")
    for error in result.errors:
        out.append(f"::error title=prscreen incomplete::{escape_data(visible(error))}")
    summary = formats.summary_line(result)
    hidden = len(result.findings) - len(shown)
    if hidden:
        summary += (
            f" {hidden} lower-severity {'finding is' if hidden == 1 else 'findings are'} in the job summary."
        )
    out.append(f"::notice title=prscreen::{escape_data(summary)}")
    return "\n".join(out) + "\n"
