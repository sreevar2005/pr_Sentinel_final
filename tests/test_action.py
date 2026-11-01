import io
import json
import subprocess
import sys
from pathlib import Path

import pytest

from prscreen.action import run

ROOT = Path(__file__).parent.parent


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, text=True).stdout.strip()


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.email", "t@example.invalid")
    _git(repo, "config", "user.name", "t")
    (repo / "app.py").write_text("x = 1\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "base")
    (repo / "app.py").write_text("x = 1\nrequests.get(url, verify=False)\n")
    (repo / "setup.cfg").write_text("[metadata]\nname = demo\n")
    (repo / ".github").mkdir()
    (repo / ".github" / "CODEOWNERS").write_text("* @someone\n")
    (repo / "notes.md").write_text("see the CI config\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "change")
    return repo


def _env(repo: Path, tmp_path: Path, **extra: str) -> dict[str, str]:
    env = {
        "PRSCREEN_BASE": _git(repo, "rev-parse", "HEAD~1"),
        "PRSCREEN_HEAD": _git(repo, "rev-parse", "HEAD"),
        "PRSCREEN_ANNOTATE": "medium",
        "PRSCREEN_SARIF": "",
        "GITHUB_WORKSPACE": str(repo),
        "GITHUB_STEP_SUMMARY": str(tmp_path / "summary.md"),
        "GITHUB_OUTPUT": str(tmp_path / "output.txt"),
    }
    env.update(extra)
    return env


def test_annotations_summary_and_outputs(repo, tmp_path):
    out = io.StringIO()
    assert run(_env(repo, tmp_path), out) == 0
    lines = out.getvalue().splitlines()
    assert lines[0].startswith("::warning file=.github/CODEOWNERS,title=PATH002 ")
    assert lines[1].startswith("::warning file=app.py,line=2,title=CFG001 ")
    assert lines[-1] == "::notice title=prscreen::2 findings (2 medium) in 4 files."
    summary = (tmp_path / "summary.md").read_text(encoding="utf-8")
    assert summary.startswith("## prscreen report") and "CFG001" in summary
    outputs = dict(line.split("=", 1) for line in (tmp_path / "output.txt").read_text().splitlines())
    assert outputs == {"findings": "2", "high": "0", "medium": "2", "low": "0", "sarif-file": ""}


def test_low_findings_are_summarised_not_annotated(repo, tmp_path):
    (repo / "requirements.txt").write_text("flask==3.0\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "dep")
    env = _env(repo, tmp_path, PRSCREEN_BASE=_git(repo, "rev-parse", "HEAD~2"))
    out = io.StringIO()
    run(env, out)
    assert "DEP001" not in out.getvalue()
    assert "1 lower-severity finding is in the job summary." in out.getvalue()
    assert "DEP001" in (tmp_path / "summary.md").read_text(encoding="utf-8")


def test_annotate_none_prints_only_the_summary_notice(repo, tmp_path):
    out = io.StringIO()
    assert run(_env(repo, tmp_path, PRSCREEN_ANNOTATE="none"), out) == 0
    assert out.getvalue().splitlines() == [
        "::notice title=prscreen::2 findings (2 medium) in 4 files. "
        "2 lower-severity findings are in the job summary."
    ]


def test_sarif_is_written_creating_folders(repo, tmp_path):
    assert run(_env(repo, tmp_path, PRSCREEN_SARIF="out/prscreen.sarif"), io.StringIO()) == 0
    doc = json.loads((repo / "out" / "prscreen.sarif").read_text(encoding="utf-8"))
    assert {r["ruleId"] for r in doc["runs"][0]["results"]} == {"CFG001", "PATH002"}


@pytest.mark.parametrize(
    ("override", "message"),
    [
        ({"PRSCREEN_BASE": ""}, "Run on pull_request events"),
        ({"PRSCREEN_ANNOTATE": "loud"}, "must be one of"),
        ({"PRSCREEN_BASE": "$(touch pwned)"}, "not a revision or range"),
        ({"PRSCREEN_BASE": "0" * 40}, "fetch-depth: 0"),
        ({"PRSCREEN_SARIF": "a\nb"}, "single path"),
    ],
)
def test_bad_inputs_fail_with_an_error_annotation(repo, tmp_path, override, message):
    out = io.StringIO()
    assert run(_env(repo, tmp_path, **override), out) == 2
    assert out.getvalue().startswith("::error title=prscreen::")
    assert message in out.getvalue()
    assert not (repo / "pwned").exists()


def test_launcher_ignores_modules_planted_in_the_scanned_repository(tmp_path):
    # A PR could add a prscreen/ package to its repository. The action runs from the workspace,
    # so run.py must import its own copy, not the planted one.
    planted = tmp_path / "workspace" / "prscreen"
    planted.mkdir(parents=True)
    marker = tmp_path / "hijacked"
    (planted / "__init__.py").write_text(f"open({str(marker)!r}, 'w').close()\n")
    (planted / "cli.py").write_text(f"open({str(marker)!r}, 'w').close()\n")
    proc = subprocess.run(
        [sys.executable, "-I", str(ROOT / "run.py"), "explain", "OBF001"],
        cwd=planted.parent,
        capture_output=True,
        text=True,
        env={"PYTHONPATH": str(planted.parent), "SYSTEMROOT": "C:\\Windows", "PATH": ""},
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert "OBF001: Hidden bidirectional control character" in proc.stdout
    assert not marker.exists()
