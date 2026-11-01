"""Command line interface.

Exit codes: 0 scan finished (whether or not anything was found; findings are advisory and never
fail a build), 1 scan finished but a detector crashed so results are incomplete, 2 bad input or
usage.
"""

from __future__ import annotations

import argparse
import os
import secrets
import sys
from pathlib import Path
from typing import BinaryIO

from prscreen import __version__
from prscreen.detectors import all_rules
from prscreen.diff import DiffParseError, parse_diff
from prscreen.engine import scan
from prscreen.formats import FORMATS, render
from prscreen.gitdiff import GitError, git_diff
from prscreen.sanitize import visible

MAX_DIFF_BYTES = 50 * 1024 * 1024
EXIT_OK, EXIT_INCOMPLETE, EXIT_USAGE = 0, 1, 2


class UsageError(Exception):
    pass


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    args = _parser().parse_args(argv)
    try:
        code: int = args.handler(args)
    except UsageError as exc:
        print(f"prscreen: error: {visible(str(exc))}", file=sys.stderr)
        return EXIT_USAGE
    return code


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="prscreen",
        description="Screen a pull request diff for suspicious or risky changes. Advisory only.",
    )
    parser.add_argument("--version", action="version", version=f"prscreen {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    scan_cmd = commands.add_parser("scan", help="scan a diff and report findings")
    source = scan_cmd.add_mutually_exclusive_group()
    source.add_argument("--diff", metavar="PATH", help="unified diff file, or - for stdin (the default)")
    source.add_argument("--git", metavar="RANGE", help="diff a local git range, e.g. origin/main...HEAD")
    scan_cmd.add_argument("--repo", metavar="DIR", default=".", help="repository for --git (default: .)")
    scan_cmd.add_argument("--format", choices=sorted(FORMATS), default="text", help="output format")
    scan_cmd.add_argument("--output", metavar="PATH", help="write the report here instead of stdout")
    scan_cmd.set_defaults(handler=_scan)

    explain = commands.add_parser("explain", help="describe a rule, or list all rules")
    explain.add_argument("rule_id", nargs="?", help="rule ID such as OBF001")
    explain.set_defaults(handler=_explain)
    return parser


def _scan(args: argparse.Namespace) -> int:
    raw = _read_input(args)
    try:
        diff = parse_diff(raw.decode("utf-8", errors="replace"))
    except DiffParseError as exc:
        raise UsageError(f"could not parse diff: {exc}") from exc
    result = scan(diff)
    report = render(result, args.format)

    if args.output:
        Path(args.output).write_text(report, encoding="utf-8", newline="\n")
    else:
        _write_stdout(report, args.format)
    for error in result.errors:
        print(f"prscreen: {visible(error)}", file=sys.stderr)
    return EXIT_OK if result.complete else EXIT_INCOMPLETE


def _read_input(args: argparse.Namespace) -> bytes:
    if args.git:
        try:
            raw = git_diff(args.git, Path(args.repo))
        except GitError as exc:
            raise UsageError(str(exc)) from exc
    elif args.diff and args.diff != "-":
        try:
            with open(args.diff, "rb") as handle:
                raw = _read_limited(handle)
        except OSError as exc:
            raise UsageError(f"cannot read {args.diff}: {exc.strerror}") from exc
    else:
        if sys.stdin.isatty():
            raise UsageError("no input: pass --diff PATH, --git RANGE, or pipe a diff on stdin")
        raw = _read_limited(sys.stdin.buffer)
    if len(raw) > MAX_DIFF_BYTES:
        raise UsageError(f"diff is larger than {MAX_DIFF_BYTES // (1024 * 1024)} MB")
    return raw


def _read_limited(handle: BinaryIO) -> bytes:
    return handle.read(MAX_DIFF_BYTES + 1)


def _write_stdout(report: str, fmt: str) -> None:
    # In a GitHub Actions log, a printed line starting with "::" is executed as a workflow
    # command. Evidence comes from the PR, so human-readable reports are wrapped in
    # stop-commands with an unguessable token. The "github" format is made of commands on
    # purpose and escapes its own values instead.
    if os.environ.get("GITHUB_ACTIONS") == "true" and fmt in ("text", "markdown"):
        token = secrets.token_hex(16)
        report = f"::stop-commands::{token}\n{report}::{token}::\n"
    sys.stdout.write(report)


def _explain(args: argparse.Namespace) -> int:
    rules = all_rules()
    if not args.rule_id:
        for rule in rules:
            print(f"{rule.id}  {rule.severity.label:<6}  {rule.category.value:<16}  {rule.title}")
        return EXIT_OK
    wanted = args.rule_id.upper()
    match = next((r for r in rules if r.id == wanted), None)
    if match is None:
        raise UsageError(f"unknown rule {args.rule_id!r}; run 'prscreen explain' to list rules")
    print(f"{match.id}: {match.title}")
    print(
        f"category: {match.category.value}   default severity: {match.severity.label}   "
        f"default confidence: {match.confidence.label}"
    )
    print(f"\nWhy it matters:\n  {match.rationale}\n\nCould be harmless if:\n  {match.benign}")
    return EXIT_OK
