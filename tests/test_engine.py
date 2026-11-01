from collections.abc import Iterator

from prscreen.detectors import Detector
from prscreen.diff import Diff, FileChange, parse_diff
from prscreen.engine import MAX_FINDINGS_PER_RULE_PER_FILE, scan
from prscreen.models import Category, Confidence, Finding, Rule, Severity


def _rule(rule_id: str, severity: Severity = Severity.LOW) -> Rule:
    return Rule(rule_id, "test rule", Category.EXECUTION, severity, Confidence.MEDIUM, "why", "benign")


class _Emit(Detector):
    name = "emit"
    rules = (_rule("T001"), _rule("T002", Severity.HIGH))

    def __init__(self, findings: list[Finding]) -> None:
        self._findings = findings

    def scan(self, diff: Diff) -> Iterator[Finding]:
        yield from self._findings


class _Crash(Detector):
    name = "crash"
    rules = ()

    def scan(self, diff: Diff) -> Iterator[Finding]:
        raise RuntimeError("boom")
        yield  # pragma: no cover


def test_duplicates_are_removed_and_results_sorted():
    low, high = _Emit.rules
    findings = [low.finding("b.py", 3, "x"), low.finding("b.py", 3, "x"), high.finding("a.py", 9, "y")]
    result = scan(Diff([FileChange("a.py"), FileChange("b.py")]), [_Emit(findings)])
    assert [(f.rule.id, f.path) for f in result.findings] == [("T002", "a.py"), ("T001", "b.py")]
    assert result.files_scanned == 2
    assert [r.id for r in result.rules] == ["T001", "T002"]


def test_per_file_cap_counts_dropped_findings():
    rule = _Emit.rules[0]
    findings = [rule.finding("a.py", n, f"line {n}") for n in range(1, MAX_FINDINGS_PER_RULE_PER_FILE + 6)]
    result = scan(Diff(), [_Emit(findings)])
    assert len(result.findings) == MAX_FINDINGS_PER_RULE_PER_FILE
    assert result.capped == {("T001", "a.py"): 5}


def test_crashing_detector_does_not_hide_other_findings():
    rule = _Emit.rules[0]
    result = scan(Diff(), [_Crash(), _Emit([rule.finding("a.py", 1, "x")])])
    assert len(result.findings) == 1
    assert not result.complete
    assert result.errors == ["detector 'crash' failed: RuntimeError: boom"]


def test_binary_files_are_reported_as_skipped():
    diff = parse_diff("diff --git a/x.png b/x.png\nBinary files a/x.png and b/x.png differ\n")
    assert scan(diff).skipped == [("x.png", "binary file")]


def test_long_evidence_is_truncated_and_fingerprint_ignores_whitespace():
    rule = _Emit.rules[0]
    long = rule.finding("a.py", 1, "x" * 1000)
    assert len(long.evidence) == 301
    assert rule.finding("a.py", 1, "a  b").fingerprint == rule.finding("a.py", 7, " a b ").fingerprint
    assert rule.finding("a.py", 1, "a b").fingerprint != rule.finding("c.py", 1, "a b").fingerprint
