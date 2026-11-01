"""Get a diff from a local git repository without running anything the repository controls.

``git diff`` can run programs named in configuration: external diff drivers and textconv
filters, which a repository's ``.gitattributes`` can select. Both are disabled explicitly.
Prefixes, colour and path quoting are pinned so user configuration cannot change the output
the parser expects.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

_REV = r"[A-Za-z0-9_./~^@{}][A-Za-z0-9_./~^@{}\-]*"
_RANGE_RE = re.compile(rf"{_REV}(?:\.\.\.?{_REV})?")
TIMEOUT_SECONDS = 120


class GitError(RuntimeError):
    pass


def git_diff(rev_range: str, repo: Path = Path()) -> bytes:
    """Return ``git diff <rev_range>`` as raw bytes, e.g. for ``origin/main...HEAD``."""
    if not _RANGE_RE.fullmatch(rev_range):
        raise GitError(f"not a revision or range: {rev_range!r}")
    cmd = [
        "git",
        "-c", "core.quotePath=true",
        "-c", "diff.noprefix=false",
        "diff",
        "--no-color",
        "--no-ext-diff",
        "--no-textconv",
        "--no-relative",
        "--src-prefix=a/",
        "--dst-prefix=b/",
        "--find-renames",
        rev_range,
        "--",
    ]  # fmt: skip
    try:
        proc = subprocess.run(cmd, cwd=repo, capture_output=True, timeout=TIMEOUT_SECONDS, check=False)
    except FileNotFoundError as exc:
        raise GitError("git is not installed or not on PATH") from exc
    except subprocess.TimeoutExpired as exc:
        raise GitError(f"git diff took longer than {TIMEOUT_SECONDS}s") from exc
    if proc.returncode != 0:
        raise GitError(proc.stderr.decode("utf-8", errors="replace").strip() or "git diff failed")
    return proc.stdout
