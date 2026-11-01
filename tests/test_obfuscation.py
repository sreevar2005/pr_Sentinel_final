from prscreen.detectors.obfuscation import BidiControlDetector
from prscreen.diff import parse_diff
from prscreen.models import Confidence, Severity

RLO, LRI, PDI, RLM = "\u202e", "\u2066", "\u2069", "\u200f"


def _diff(path: str, *added: str) -> str:
    body = "".join(f"+{line}\n" for line in added)
    return f"diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n@@ -0,0 +1,{len(added)} @@\n{body}"


def _scan(text: str):
    return list(BidiControlDetector().scan(parse_diff(text)))


def test_trojan_source_line_in_code_is_high():
    line = f'if access_level != "user{RLO} {LRI}// Check if admin{PDI} {LRI}":'
    (finding,) = _scan(_diff("auth.py", "ok = 1", line))
    assert finding.rule.id == "OBF001"
    assert finding.line == 2
    assert (finding.severity, finding.confidence) == (Severity.HIGH, Confidence.HIGH)
    assert "U+202E RLO at column 25" in finding.detail


def test_prose_files_are_medium():
    (finding,) = _scan(_diff("docs/README.md", f"Hello {RLO}world"))
    assert (finding.severity, finding.confidence) == (Severity.MEDIUM, Confidence.MEDIUM)


def test_right_to_left_marks_alone_are_not_flagged():
    assert _scan(_diff("i18n.py", f"label = 'שלום{RLM}'")) == []


def test_removed_lines_and_deleted_files_are_ignored():
    removed = f"--- a/x.py\n+++ b/x.py\n@@ -1 +1 @@\n-bad{RLO}\n+good\n"
    deleted = (
        "diff --git a/y.py b/y.py\ndeleted file mode 100644\n"
        f"--- a/y.py\n+++ /dev/null\n@@ -1 +0,0 @@\n-{RLO}\n"
    )
    assert _scan(removed) == []
    assert _scan(deleted) == []


def test_many_controls_on_one_line_are_summarised():
    (finding,) = _scan(_diff("a.js", RLO * 8))
    assert "and 3 more" in finding.detail
