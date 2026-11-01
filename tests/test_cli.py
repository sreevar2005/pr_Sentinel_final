import io
import json
import subprocess
import sys
from pathlib import Path

import pytest

from prscreen.cli import main

RLO = "\u202e"
DIFF = f"--- a/x.py\n+++ b/x.py\n@@ -0,0 +1 @@\n+a = 1{RLO}\n"


@pytest.fixture
def diff_file(tmp_path: Path) -> Path:
    path = tmp_path / "pr.diff"
    path.write_bytes(DIFF.encode())
    return path


def test_scan_file_text(diff_file, capsys, monkeypatch):
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    assert main(["scan", "--diff", str(diff_file)]) == 0
    out = capsys.readouterr().out
    assert out.startswith("prscreen: 1 finding (1 high) in 1 file.")


def test_scan_stdin_json(capsys, monkeypatch):
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(DIFF.encode())))
    assert main(["scan", "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["findings"][0]["line"] == 1


def test_scan_to_output_file(diff_file, tmp_path, capsys):
    out = tmp_path / "report.sarif"
    assert main(["scan", "--diff", str(diff_file), "--format", "sarif", "--output", str(out)]) == 0
    assert json.loads(out.read_text(encoding="utf-8"))["version"] == "2.1.0"
    assert capsys.readouterr().out == ""


def test_human_output_is_wrapped_in_stop_commands_on_actions(diff_file, capsys, monkeypatch):
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    main(["scan", "--diff", str(diff_file)])
    lines = capsys.readouterr().out.splitlines()
    token = lines[0].removeprefix("::stop-commands::")
    assert len(token) == 32
    assert lines[-1] == f"::{token}::"


def test_github_format_is_not_wrapped(diff_file, capsys, monkeypatch):
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    main(["scan", "--diff", str(diff_file), "--format", "github"])
    assert capsys.readouterr().out.startswith("::error file=x.py,line=1,")


def test_bad_inputs_exit_2(tmp_path, capsys):
    bad = tmp_path / "bad.diff"
    bad.write_text("@@ -1 +1 @@\n+x\n")
    assert main(["scan", "--diff", str(bad)]) == 2
    assert main(["scan", "--diff", str(tmp_path / "missing.diff")]) == 2
    assert main(["scan", "--git=--output=/tmp/x"]) == 2  # option injection into git
    err = capsys.readouterr().err
    assert "could not parse diff" in err
    assert "cannot read" in err
    assert "not a revision or range" in err


def test_explain(capsys):
    assert main(["explain"]) == 0
    assert "OBF001" in capsys.readouterr().out
    assert main(["explain", "obf001"]) == 0
    assert "Trojan Source" in capsys.readouterr().out
    assert main(["explain", "NOPE1"]) == 2


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)


def test_scan_git_range_ignores_repo_controlled_diff_programs(tmp_path, capsys):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.email", "t@example.invalid")
    _git(repo, "config", "user.name", "t")
    # If git ran either of these, the diff would fail: the commands do not exist.
    _git(repo, "config", "diff.evil.textconv", "prscreen-test-no-such-textconv")
    _git(repo, "config", "diff.external", "prscreen-test-no-such-external")
    (repo / ".gitattributes").write_text("*.py diff=evil\n")
    (repo / "a.py").write_text("x = 1\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "base")
    (repo / "a.py").write_text(f"x = 1\ny = 2{RLO}\n", encoding="utf-8")
    _git(repo, "commit", "-qam", "change")

    assert main(["scan", "--git", "HEAD~1...HEAD", "--repo", str(repo), "--format", "json"]) == 0
    (finding,) = json.loads(capsys.readouterr().out)["findings"]
    assert (finding["path"], finding["line"]) == ("a.py", 2)


def test_docs_rules_md_is_up_to_date(capsys):
    assert main(["explain", "--markdown"]) == 0
    expected = capsys.readouterr().out
    docs = Path(__file__).parent.parent / "docs" / "rules.md"
    assert docs.read_text(encoding="utf-8") == expected, (
        "regenerate: prscreen explain --markdown > docs/rules.md"
    )
