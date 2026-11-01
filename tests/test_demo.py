"""The demo repository's pull requests must keep showing what they claim to show."""

import importlib.util
import io
import sys
from contextlib import redirect_stdout
from pathlib import Path

import pytest

from prscreen.models import Severity

ROOT = Path(__file__).parent.parent
_spec = importlib.util.spec_from_file_location("prscreen_demo", ROOT / "scripts" / "demo.py")
assert _spec and _spec.loader
demo = importlib.util.module_from_spec(_spec)
sys.modules["prscreen_demo"] = demo
_spec.loader.exec_module(demo)


@pytest.fixture(scope="module")
def results(tmp_path_factory):
    repo = tmp_path_factory.mktemp("demo") / "repo"
    demo.build(repo, "sreevar2005/pr_Sentinel_final@main")
    return demo.scan_branches(repo)


@pytest.mark.parametrize("scenario", demo.SCENARIOS, ids=lambda s: s.branch)
def test_each_demo_pr_shows_what_it_claims(results, scenario):
    loud = {f.rule.id for f in results[scenario.branch].findings if f.severity >= Severity.MEDIUM}
    if scenario.expect:
        assert scenario.expect <= loud
    else:
        assert loud == set(), "the clean demo PR must stay quiet"


def test_demo_covers_every_rule_category(results):
    categories = {
        f.rule.category.value
        for result in results.values()
        for f in result.findings
        if f.severity >= Severity.MEDIUM
    }
    assert categories >= {
        "secrets",
        "execution",
        "ci",
        "network",
        "obfuscation",
        "security-config",
        "dependencies",
    }


def test_demo_build_refuses_a_non_empty_folder(tmp_path):
    (tmp_path / "x").write_text("keep me")
    with pytest.raises(SystemExit):
        demo.build(tmp_path, "a/b@c")
    assert (tmp_path / "x").read_text() == "keep me"


def test_docs_demo_md_is_up_to_date():
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        assert demo.main(["report"]) == 0
    assert (ROOT / "docs" / "demo.md").read_text(encoding="utf-8") == buffer.getvalue(), (
        "regenerate: uv run python scripts/demo.py report > docs/demo.md"
    )
