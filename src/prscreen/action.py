"""The GitHub Action entry point (``prscreen github-action``), run by action.yml.

Inputs arrive only as environment variables that action.yml sets from its inputs, so no value is
ever pasted into a shell script. The step:

* diffs base...head in the checked-out workspace with :func:`prscreen.gitdiff.git_diff` (no
  repository-controlled diff programs run, and no PR code is executed or imported);
* prints annotations for findings at or above ``PRSCREEN_ANNOTATE``;
* appends the full Markdown report to ``$GITHUB_STEP_SUMMARY``;
* optionally writes SARIF to ``PRSCREEN_SARIF``;
* sets the outputs ``findings``, ``high``, ``medium``, ``low`` and ``sarif-file``.

It needs only a read-only token and no secrets, so it also works on pull requests from forks.
Findings never fail the step. It fails (exit 1) only when the scan itself is incomplete, and
with exit 2 when it cannot run at all, for example on a shallow clone.
"""

from __future__ import annotations

import sys
from collections.abc import Mapping
from pathlib import Path
from typing import TextIO

from prscreen.diff import DiffParseError, parse_diff
from prscreen.engine import scan
from prscreen.formats import github, markdown, sarif
from prscreen.gitdiff import GitError, git_diff
from prscreen.models import Severity

# GitHub rejects step summaries over 1 MiB; leave room for other steps' summaries.
MAX_SUMMARY_BYTES = 512 * 1024
_ANNOTATE_LEVELS = {"low": Severity.LOW, "medium": Severity.MEDIUM, "high": Severity.HIGH, "none": None}


class ActionError(Exception):
    pass


def run(env: Mapping[str, str], out: TextIO = sys.stdout) -> int:
    try:
        return _run(env, out)
    except ActionError as exc:
        out.write(f"::error title=prscreen::{github.escape_data(str(exc))}\n")
        return 2


def _run(env: Mapping[str, str], out: TextIO) -> int:
    base, head = env.get("PRSCREEN_BASE", "").strip(), env.get("PRSCREEN_HEAD", "").strip()
    if not base or not head:
        raise ActionError(
            "No base or head commit. Run on pull_request events, or set the 'base' and 'head' inputs."
        )
    annotate = env.get("PRSCREEN_ANNOTATE", "medium").strip().lower() or "medium"
    if annotate not in _ANNOTATE_LEVELS:
        raise ActionError(f"'annotate' must be one of low, medium, high or none, not {annotate!r}.")
    sarif_path = env.get("PRSCREEN_SARIF", "").strip()
    if "\n" in sarif_path or "\r" in sarif_path:
        raise ActionError("'sarif-file' must be a single path.")
    workspace = Path(env.get("GITHUB_WORKSPACE") or ".")

    try:
        raw = git_diff(f"{base}...{head}", workspace)
    except GitError as exc:
        raise ActionError(
            f"git diff failed: {exc}. Check out with 'fetch-depth: 0' so both commits are available."
        ) from exc
    try:
        result = scan(parse_diff(raw.decode("utf-8", errors="replace")))
    except DiffParseError as exc:
        raise ActionError(f"could not parse the diff: {exc}") from exc

    out.write(github.render(result, _ANNOTATE_LEVELS[annotate]))
    if summary_file := env.get("GITHUB_STEP_SUMMARY"):
        report = markdown.render(result)
        if len(report.encode()) > MAX_SUMMARY_BYTES:
            report = report.encode()[:MAX_SUMMARY_BYTES].decode(errors="ignore")
            report += (
                "\n\n_Report truncated to fit GitHub's step summary limit; see the annotations or SARIF._\n"
            )
        with open(summary_file, "a", encoding="utf-8", newline="\n") as handle:
            handle.write(report)
    if sarif_path:
        (workspace / sarif_path).parent.mkdir(parents=True, exist_ok=True)
        (workspace / sarif_path).write_text(sarif.render(result), encoding="utf-8", newline="\n")

    counts = {s: sum(1 for f in result.findings if f.severity is s) for s in Severity}
    if output_file := env.get("GITHUB_OUTPUT"):
        with open(output_file, "a", encoding="utf-8", newline="\n") as handle:
            handle.write(f"findings={len(result.findings)}\n")
            handle.write(
                f"high={counts[Severity.HIGH]}\nmedium={counts[Severity.MEDIUM]}\nlow={counts[Severity.LOW]}\n"
            )
            handle.write(f"sarif-file={sarif_path}\n")
    return 0 if result.complete else 1
