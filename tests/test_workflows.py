"""Security invariants for this repository's own workflows and action.

A screening tool with a weak pipeline would be a poor example, so these are enforced in tests
rather than left to review.
"""

import re
from pathlib import Path

import pytest

from prscreen.diff import parse_diff
from prscreen.engine import scan
from prscreen.models import Severity

ROOT = Path(__file__).parent.parent
WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
ACTION = ROOT / "action.yml"
ALL = [*WORKFLOWS, ACTION]
SHA_PIN = re.compile(r"^[\w.-]+/[\w.-]+(?:/[\w./-]+)?@[0-9a-f]{40}$")


def _run_blocks(text: str) -> list[str]:
    """The script text of every run: step, including multi-line blocks."""
    blocks: list[str] = []
    lines = text.splitlines()
    for i, line in enumerate(lines):
        match = re.match(r"^(\s*)(?:-\s+)?run:\s*(.*)$", line)
        if not match:
            continue
        indent, inline = len(match[1]), match[2]
        if inline not in ("|", ">", "|-", ">-"):
            blocks.append(inline)
            continue
        body = []
        for follow in lines[i + 1 :]:
            if follow.strip() and len(follow) - len(follow.lstrip()) <= indent:
                break
            body.append(follow)
        blocks.append("\n".join(body))
    return blocks


def test_there_are_workflows_to_check():
    assert {p.name for p in WORKFLOWS} >= {"ci.yml", "prscreen.yml"}


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_workflows_have_read_only_permissions_and_no_privileged_triggers(path):
    text = path.read_text(encoding="utf-8")
    assert re.search(r"(?m)^permissions:\n  contents: read$", text)
    assert "write" not in re.sub(r"(?m)^\s*#.*$", "", text).split("jobs:", 1)[0]
    assert ": write" not in text
    assert "pull_request_target" not in text and "workflow_run" not in text


@pytest.mark.parametrize("path", ALL, ids=lambda p: p.name)
def test_actions_are_pinned_to_commits(path):
    for target in re.findall(r"(?m)^\s*(?:-\s+)?uses:\s*([^\s#]+)", path.read_text(encoding="utf-8")):
        assert target == "./" or SHA_PIN.match(target), f"{path.name}: {target} is not pinned to a commit"


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_checkouts_do_not_persist_the_token(path):
    text = path.read_text(encoding="utf-8")
    assert text.count("actions/checkout@") == text.count("persist-credentials: false")


@pytest.mark.parametrize("path", ALL, ids=lambda p: p.name)
def test_no_expressions_inside_scripts(path):
    for block in _run_blocks(path.read_text(encoding="utf-8")):
        assert "${{" not in block, f"{path.name}: pass values to run: through env instead:\n{block}"


def test_action_runs_python_isolated_from_the_workspace():
    text = ACTION.read_text(encoding="utf-8")
    assert 'python3 -I "$GITHUB_ACTION_PATH/run.py" github-action' in text
    assert "pip install" not in text


def test_prscreen_finds_nothing_serious_in_its_own_pipeline():
    parts = []
    for path in ALL:
        lines = path.read_text(encoding="utf-8").splitlines()
        rel = path.relative_to(ROOT).as_posix()
        parts.append(
            f"--- /dev/null\n+++ b/{rel}\n@@ -0,0 +1,{len(lines)} @@\n" + "".join(f"+{x}\n" for x in lines)
        )
    serious = [f for f in scan(parse_diff("".join(parts))).findings if f.severity >= Severity.MEDIUM]
    assert serious == []
