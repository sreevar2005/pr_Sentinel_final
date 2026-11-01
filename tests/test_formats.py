import json

import pytest

from prscreen.detectors.obfuscation import BIDI_CONTROL
from prscreen.engine import ScanResult
from prscreen.formats import FORMATS, render, summary_line
from prscreen.formats.markdown import code_block, escape
from prscreen.models import Severity


def _result(*findings, **kwargs) -> ScanResult:
    return ScanResult(findings=list(findings), rules=[BIDI_CONTROL], files_scanned=3, **kwargs)


HOSTILE = BIDI_CONTROL.finding(
    "src/@octocat <img src=x>,a:b.py",
    7,
    "x = 1\u202e ``` \x1b[2J\n::set-env name=X::1 [link](http://evil.example) %0A",
    "Contains U+202E.",
)


def test_summary_line():
    assert summary_line(_result()) == "No findings in 3 files."
    medium = BIDI_CONTROL.finding("a.md", 1, "x", severity=Severity.MEDIUM)
    assert summary_line(_result(HOSTILE, medium)) == "2 findings (1 high, 1 medium) in 3 files."


@pytest.mark.parametrize("fmt", sorted(FORMATS))
def test_no_format_leaks_raw_control_characters(fmt):
    out = render(_result(HOSTILE, errors=["detector 'x' failed: \x1b]0;pwn\x07"]), fmt)
    for raw in ("\u202e", "\x1b", "\x07"):
        assert raw not in out
    # Only the format's own line structure: the evidence's newline must not start a new line.
    assert not any(line.startswith("::set-env") for line in out.splitlines())


def test_text_report():
    out = render(_result(HOSTILE, capped={("OBF001", "a.py"): 4}), "text")
    assert "HIGH   OBF001  src/@octocat <img src=x>,a:b.py:7  Hidden bidirectional control character" in out
    assert "\\u202e" in out
    assert "capped OBF001 in a.py: 4 more findings not shown" in out
    assert out.rstrip().endswith("not verdicts.")


def test_markdown_escapes_mentions_html_and_links():
    out = render(_result(HOSTILE), "markdown")
    assert "@octocat" not in out
    assert "<img" not in out
    assert "&#64;octocat &lt;img src=x&gt;" in out
    assert "````text" in out  # fence longer than the ``` inside the evidence
    assert "| 🔴 high | OBF001 |" in out


def test_markdown_helpers():
    assert escape("[a](b) *c* @d") == "\\[a\\]\\(b\\) \\*c\\* &#64;d"
    assert code_block("a ```` b").startswith("`````text\n")


def test_markdown_lists_incomplete_results():
    out = render(_result(errors=["detector 'x' failed: boom"]), "markdown")
    assert "**Results are incomplete.**" in out


def test_github_annotations_escape_properties_and_data():
    out = render(_result(HOSTILE), "github")
    first = out.splitlines()[0]
    assert first.startswith("::error file=src/@octocat <img src=x>%2Ca%3Ab.py,line=7,title=OBF001 ")
    assert "%250A" in first  # a literal "%0A" in the evidence stays text
    assert "\\u000a::set-env" in first
    assert out.splitlines()[-1] == "::notice title=prscreen::1 finding (1 high) in 3 files."


def test_sarif_structure():
    doc = json.loads(render(_result(HOSTILE), "sarif"))
    run = doc["runs"][0]
    assert doc["version"] == "2.1.0"
    assert run["tool"]["driver"]["rules"][0]["properties"]["security-severity"] == "8.0"
    (res,) = run["results"]
    loc = res["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "src/%40octocat%20%3Cimg%20src%3Dx%3E%2Ca%3Ab.py"
    assert loc["region"]["startLine"] == 7
    assert res["partialFingerprints"]["prscreen/v1"] == HOSTILE.fingerprint
    assert run["invocations"][0]["executionSuccessful"] is True


def test_json_structure():
    doc = json.loads(render(_result(HOSTILE, skipped=[("x.png", "binary file")]), "json"))
    assert doc["complete"] is True
    assert doc["findings"][0]["rule_id"] == "OBF001"
    assert doc["findings"][0]["severity"] == "high"
    assert doc["skipped"] == [{"path": "x.png", "reason": "binary file"}]
