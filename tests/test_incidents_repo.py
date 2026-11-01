"""The prscreen-incidents repository: every branch must keep showing the incident it recreates."""

import importlib.util
import sys
from pathlib import Path

import pytest

from prscreen.gitdiff import list_branches
from prscreen.gui.samples import SAMPLES

ROOT = Path(__file__).parent.parent
_spec = importlib.util.spec_from_file_location(
    "prscreen_incidents_repo", ROOT / "scripts" / "incidents_repo.py"
)
assert _spec and _spec.loader
incidents = importlib.util.module_from_spec(_spec)
sys.modules["prscreen_incidents_repo"] = incidents
_spec.loader.exec_module(incidents)


@pytest.fixture(scope="module")
def repo(tmp_path_factory):
    path = tmp_path_factory.mktemp("incidents") / "repo"
    incidents.build(path, incidents.DEFAULT_ACTION)
    return path


def test_every_branch_shows_its_incident(repo):
    assert incidents.check(incidents.scan_branches(repo)) == []


def test_every_incident_branch_is_a_documented_case_with_sources():
    ids = {sample["id"] for sample in SAMPLES}
    for branch in incidents.BRANCHES:
        if branch.incident is None:
            assert branch.name.startswith("control/")
            continue
        assert branch.incident in ids
        assert branch.name == f"incident/{branch.incident}"
        assert incidents.INCIDENTS[branch.incident]["sources"]


def test_commit_messages_and_readme_carry_the_sources(repo):
    readme = (repo / "README.md").read_text(encoding="utf-8")
    for branch in incidents.BRANCHES:
        assert f"`{branch.name}`" in readme
        if branch.incident:
            for source in incidents.INCIDENTS[branch.incident]["sources"]:
                assert source["url"] in readme
                assert source["url"] in incidents._commit_message(branch)


def test_branch_listing_puts_local_branches_first(repo):
    branches = list_branches(repo)
    assert branches[0] == "control/ordinary-change"
    assert "main" in branches and "incident/codecov-2021" in branches


def test_the_repo_workflow_pins_prscreen_to_a_commit():
    workflow = incidents.base_files(incidents.DEFAULT_ACTION)[".github/workflows/prscreen.yml"]
    assert "uses: sreevar2005/pr_Sentinel_final@" in workflow
    assert len(incidents.DEFAULT_ACTION.split("@")[1]) == 40
