"""Measure the rules against a corpus: labeled cases for recall and precision, real PRs for noise.

Corpus layout::

    corpus/cases/*.toml     labeled cases (risky changes and harmless look-alikes)
    corpus/real/prs.toml    manifest of real merged pull requests, diffs stored next to it

A labeled case lists the findings it ``expect``s (each one missing is a false negative) and the
findings it ``allow``s (accurate but beside the point, such as "CI config changed"). Any other
finding is a false positive. Real PRs are not labeled; they are assumed benign and every finding
on them is reported, so a reader can judge the noise for themselves.

Case files never contain live-looking credentials: ``{{GITHUB_TOKEN}}`` and similar placeholders
are filled with generated fakes at load time.
"""

from __future__ import annotations

import json
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from prscreen.detectors import all_rules
from prscreen.diff import parse_diff
from prscreen.engine import scan
from prscreen.formats.markdown import escape
from prscreen.models import Finding, Severity
from prscreen.sanitize import visible

PLACEHOLDERS = {
    "{{AWS_KEY}}": "AKIA" + "Z7Q3" * 4,
    "{{GITHUB_TOKEN}}": "ghp_" + "aB3dE6gH9k" * 4,
    "{{STRIPE_KEY}}": "sk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dc",
    "{{SLACK_TOKEN}}": "xox" + "b-" + "1234567890-" + "AbCdEfGhIjKl",
    "{{PRIVATE_KEY}}": "-----BEGIN " + "RSA PRIVATE KEY-----",
    # Invisible and look-alike characters, so case files stay plain ASCII.
    "{{RLO}}": chr(0x202E),
    "{{LRI}}": chr(0x2066),
    "{{PDI}}": chr(0x2069),
    "{{RLM}}": chr(0x200F),
    "{{ZWJ}}": chr(0x200D),
    "{{ZWSP}}": chr(0x200B),
    "{{HANGUL_FILLER}}": chr(0x3164),
    "{{CYRILLIC_A}}": chr(0x430),
    "{{CYRILLIC_O}}": chr(0x43E),
}


class CorpusError(ValueError):
    pass


@dataclass(frozen=True)
class Expectation:
    rule_id: str
    path: str
    line: int | None

    @classmethod
    def parse(cls, text: str) -> Expectation:
        try:
            rule_id, location = text.split(" ", 1)
        except ValueError as exc:
            raise CorpusError(f"expected 'RULE path[:line]', got {text!r}") from exc
        path, _, line = location.rpartition(":")
        if path and line.isdigit():
            return cls(rule_id, path, int(line))
        return cls(rule_id, location, None)

    def matches(self, finding: Finding) -> bool:
        return (
            finding.rule.id == self.rule_id
            and finding.path == self.path
            and (self.line is None or finding.line == self.line)
        )

    def __str__(self) -> str:
        return f"{self.rule_id} {self.path}" + (f":{self.line}" if self.line else "")


@dataclass
class CaseResult:
    case_id: str
    kind: str
    title: str
    source: str
    missed: list[Expectation]
    unexpected: list[Finding]
    true_positives: list[Finding]
    known_limitation: str | None = None
    """Set for attacks the rules are known not to catch. They count in recall but not in ``passed``."""
    known_noise: list[Finding] = field(default_factory=list)
    """False positives that are documented and accepted. Still counted as false positives."""

    @property
    def passed(self) -> bool:
        return not self.missed and not self.unexpected

    @property
    def gate_ok(self) -> bool:
        """Whether the case behaves as labeled. Documented misses and noise do not fail the gate."""
        new_noise = [f for f in self.unexpected if f not in self.known_noise]
        return not new_noise and (not self.missed or self.known_limitation is not None)


@dataclass
class RealPR:
    repo: str
    number: int
    title: str
    url: str
    license: str
    findings: list[Finding]
    lines_changed: int


@dataclass
class EvalReport:
    cases: list[CaseResult] = field(default_factory=list)
    real: list[RealPR] = field(default_factory=list)

    @property
    def tp(self) -> int:
        return sum(len(c.true_positives) for c in self.cases)

    @property
    def fn(self) -> int:
        return sum(len(c.missed) for c in self.cases)

    @property
    def fp(self) -> int:
        return sum(len(c.unexpected) for c in self.cases)

    @property
    def passed(self) -> bool:
        """The regression gate: every case behaves as labeled, apart from documented limitations."""
        return all(c.gate_ok for c in self.cases)

    def per_rule(self) -> dict[str, RuleStats]:
        table = {rule.id: RuleStats(rule.title) for rule in all_rules()}
        for case in self.cases:
            for f in case.true_positives:
                table[f.rule.id].tp += 1
            for e in case.missed:
                table.setdefault(e.rule_id, RuleStats("unknown rule")).fn += 1
            for f in case.unexpected:
                table[f.rule.id].fp += 1
        for pr in self.real:
            for rule_id in {f.rule.id for f in pr.findings}:
                table[rule_id].real_prs += 1
            for f in pr.findings:
                if f.severity >= Severity.MEDIUM:
                    table[f.rule.id].real_medium_plus += 1
        return table


@dataclass
class RuleStats:
    title: str
    tp: int = 0
    fn: int = 0
    fp: int = 0
    real_prs: int = 0
    """Real PRs on which the rule fired at any severity."""
    real_medium_plus: int = 0
    """Medium-or-higher findings from this rule on real PRs: the noise a reviewer would see."""


def load_case(path: Path) -> dict[str, Any]:
    raw = path.read_text(encoding="utf-8")
    for placeholder, value in PLACEHOLDERS.items():
        raw = raw.replace(placeholder, value)
    try:
        case = tomllib.loads(raw)
    except tomllib.TOMLDecodeError as exc:
        raise CorpusError(f"{path.name}: {exc}") from exc
    if case.get("kind") not in ("risky", "benign"):
        raise CorpusError(f"{path.name}: kind must be 'risky' or 'benign'")
    if case["kind"] == "risky" and not case.get("expect"):
        raise CorpusError(f"{path.name}: a risky case must expect at least one finding")
    if case["kind"] == "benign" and case.get("expect"):
        raise CorpusError(f"{path.name}: a benign case cannot expect findings; use allow")
    return case


def build_diff(files: list[dict[str, Any]]) -> str:
    """Turn the compact ``[[file]]`` form of a case into a unified diff."""
    out: list[str] = []
    for spec in files:
        path, status = spec["path"], spec.get("status", "modified")
        added, removed = spec.get("added", []), spec.get("removed", [])
        start = spec.get("start", 1)
        out.append(f"diff --git a/{path} b/{path}")
        if status == "added":
            out.append(f"new file mode {spec.get('mode', '100644')}")
        elif status == "deleted":
            out.append("deleted file mode 100644")
        if spec.get("binary"):
            old = "/dev/null" if status == "added" else f"a/{path}"
            out.append(f"Binary files {old} and b/{path} differ")
            continue
        out.append("--- /dev/null" if status == "added" else f"--- a/{path}")
        out.append("+++ /dev/null" if status == "deleted" else f"+++ b/{path}")
        old_start = 0 if status == "added" else start
        new_start = 0 if status == "deleted" else start
        out.append(f"@@ -{old_start},{len(removed)} +{new_start},{len(added)} @@")
        out += [f"-{line}" for line in removed]
        out += [f"+{line}" for line in added]
    return "\n".join(out) + "\n"


def evaluate_case(case_id: str, case: dict[str, Any]) -> CaseResult:
    diff_text = case.get("diff") or build_diff(case.get("file", []))
    findings = scan(parse_diff(diff_text)).findings
    expect = [Expectation.parse(e) for e in case.get("expect", [])]
    allow = [Expectation.parse(e) for e in case.get("allow", [])]
    missed = [e for e in expect if not any(e.matches(f) for f in findings)]
    true_positives = [f for f in findings if any(e.matches(f) for e in expect)]
    unexpected = [f for f in findings if f not in true_positives and not any(a.matches(f) for a in allow)]
    noise = [Expectation.parse(e) for e in case.get("known_noise", [])]
    return CaseResult(
        known_noise=[f for f in unexpected if any(n.matches(f) for n in noise)],
        case_id=case_id,
        kind=case["kind"],
        title=case.get("title", case_id),
        source=case.get("source", "synthetic"),
        missed=missed,
        unexpected=unexpected,
        true_positives=true_positives,
        known_limitation=case.get("known_limitation"),
    )


def evaluate(corpus: Path) -> EvalReport:
    if not corpus.is_dir():
        raise CorpusError(f"corpus directory not found: {corpus}")
    report = EvalReport()
    for path in sorted((corpus / "cases").glob("*.toml")):
        report.cases.append(evaluate_case(path.stem, load_case(path)))
    manifest = corpus / "real" / "prs.toml"
    if manifest.exists():
        for pr in tomllib.loads(manifest.read_text(encoding="utf-8")).get("pr", []):
            diff_text = (manifest.parent / pr["file"]).read_bytes().decode("utf-8", errors="replace")
            diff = parse_diff(diff_text)
            report.real.append(
                RealPR(
                    repo=pr["repo"],
                    number=pr["number"],
                    title=pr["title"],
                    url=pr["url"],
                    license=pr["license"],
                    findings=scan(diff).findings,
                    lines_changed=sum(len(c.added) + len(c.removed) for c in diff.files),
                )
            )
    return report


# --- reports --------------------------------------------------------------------------------


def _pct(num: int, den: int) -> str:
    return f"{num} / {den} ({100 * num / den:.1f}%)" if den else "n/a"


def _summary(report: EvalReport) -> list[tuple[str, str]]:
    risky = [c for c in report.cases if c.kind == "risky"]
    benign = [c for c in report.cases if c.kind == "benign"]
    real_findings = [f for pr in report.real for f in pr.findings]
    loud = sum(1 for pr in report.real if any(f.severity >= Severity.MEDIUM for f in pr.findings))
    low = sum(1 for f in real_findings if f.severity is Severity.LOW)
    rows = [
        ("Labeled cases", f"{len(report.cases)} ({len(risky)} risky, {len(benign)} harmless look-alikes)"),
        ("Expected findings caught (recall)", _pct(report.tp, report.tp + report.fn)),
        ("Findings that were expected (precision on labeled cases)", _pct(report.tp, report.tp + report.fp)),
        (
            "Harmless look-alikes with no false alarm",
            _pct(sum(1 for c in benign if not c.unexpected), len(benign)),
        ),
        ("Documented misses (known limitations)", str(sum(1 for c in risky if c.known_limitation))),
    ]
    if report.real:
        repos = len({pr.repo for pr in report.real})
        lines = sum(pr.lines_changed for pr in report.real)
        rows += [
            ("Real merged PRs scanned", f"{len(report.real)} from {repos} projects, {lines:,} changed lines"),
            ("Real PRs with a medium or high finding", _pct(loud, len(report.real))),
            ("Low findings per real PR", f"{low / len(report.real):.2f} ({low} in total)"),
        ]
    return rows


def render_text(report: EvalReport) -> str:
    out = ["prscreen eval", ""]
    width = max(len(label) for label, _ in _summary(report))
    out += [f"  {label:<{width}}  {value}" for label, value in _summary(report)]
    out.append("")
    for case in report.cases:
        if case.passed:
            continue
        tag = "LIMITATION" if case.known_limitation else ("NOISE" if case.gate_ok else "FAIL")
        out.append(f"{tag:<10} {case.case_id}: {visible(case.title)}")
        out += [f"           missed   {e}" for e in case.missed]
        out += [
            f"           extra    {f.rule.id} {visible(f.path)}" + (f":{f.line}" if f.line else "")
            for f in case.unexpected
        ]
    out.append("")
    out.append("gate: PASS" if report.passed else "gate: FAIL (a case no longer behaves as labeled)")
    return "\n".join(out) + "\n"


def render_json(report: EvalReport) -> str:
    doc = {
        "summary": dict(_summary(report)),
        "tp": report.tp,
        "fn": report.fn,
        "fp": report.fp,
        "gate_passed": report.passed,
        "rules": {rule_id: vars(stats) for rule_id, stats in report.per_rule().items()},
        "cases": [
            {
                "id": c.case_id,
                "kind": c.kind,
                "passed": c.passed,
                "known_limitation": c.known_limitation,
                "missed": [str(e) for e in c.missed],
                "unexpected": [f"{f.rule.id} {visible(f.path)}:{f.line or ''}" for f in c.unexpected],
            }
            for c in report.cases
        ],
    }
    return json.dumps(doc, indent=2) + "\n"


def _link(pr: RealPR) -> str:
    label = f"{escape(pr.repo)}#{pr.number}"
    return f"[{label}]({pr.url})" if pr.url.startswith("https://github.com/") else label


def render_markdown(report: EvalReport) -> str:
    out = [
        "# Evaluation",
        "",
        "Generated by `prscreen eval --format markdown > docs/evaluation.md` from [corpus/](../corpus).",
        "A test fails if this file is out of date, so the numbers always match the current rules.",
        "",
        "## Summary",
        "",
        "| Measure | Result |",
        "| --- | --- |",
    ]
    out += [f"| {label} | {value} |" for label, value in _summary(report)]
    out += [
        "",
        "## How to read these numbers",
        "",
        "- **The labeled cases were written by the same person as the rules.** They show that each",
        "  rule does what it claims and they stop regressions, but they are not an independent",
        "  benchmark; real-world recall will be lower.",
        "- **Recall counts expected findings, not cases.** The documented misses below are",
        "  included, so the number is not inflated by leaving hard cases out.",
        "- **The real PRs measure noise, not detection.** They are the most recently merged PRs of",
        "  well-maintained projects, chosen by a fixed rule in",
        "  [scripts/fetch_real_prs.py](../scripts/fetch_real_prs.py) before results were seen, and",
        "  assumed benign. None of them is known to be malicious.",
        '- **Low findings are informational** ("CI config changed", "new dependency"). The figure',
        "  that matters for reviewer fatigue is the share of real PRs with a medium or high finding.",
        "",
        "## Per rule",
        "",
        "Caught, missed and false alarms come from the labeled cases; the last two columns from real PRs.",
        "",
        "| Rule | Title | Caught | Missed | False alarms | Real PRs it fired on | Real medium+ findings |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for rule_id, s in sorted(report.per_rule().items()):
        out.append(
            f"| {rule_id} | {escape(s.title)} | {s.tp} | {s.fn} | {s.fp} "
            f"| {s.real_prs} | {s.real_medium_plus} |"
        )
    limits = [c for c in report.cases if c.known_limitation]
    if limits:
        out += ["", "## Known limitations", "", "Attacks in the corpus that the rules do not catch:", ""]
        out += [
            f"- **{escape(c.title)}** ({escape(c.source)}). {escape(c.known_limitation or '')}"
            for c in limits
        ]
    noisy = [c for c in report.cases if c.known_noise]
    if noisy:
        out += ["", "## Known false positives", ""]
        for c in noisy:
            for f in c.known_noise:
                loc = escape(f.path) + (f":{f.line}" if f.line else "")
                out.append(f"- {f.rule.id} at {loc} in *{escape(c.title)}* ({f.severity.label} severity).")
    out += ["", "## Labeled cases", "", "| Case | Kind | Source | Result |", "| --- | --- | --- | --- |"]
    for c in report.cases:
        if c.passed:
            result = f"✅ {len(c.true_positives)} expected" if c.kind == "risky" else "✅ quiet"
        elif c.known_limitation:
            result = "⚠️ known limitation"
        elif c.gate_ok:
            result = f"⚠️ {len(c.unexpected)} known false positive"
        else:
            result = "❌ " + ", ".join(
                [f"missed {e}" for e in c.missed] + [f"extra {f.rule.id}" for f in c.unexpected]
            )
        out.append(f"| {escape(c.title)} | {c.kind} | {escape(c.source)} | {escape(result)} |")
    if report.real:
        out += [
            "",
            "## Real pull requests",
            "",
            "| PR | License | Lines changed | High | Medium | Low | Rules |",
            "| --- | --- | ---: | ---: | ---: | ---: | --- |",
        ]
        for pr in report.real:
            counts = {s: sum(1 for f in pr.findings if f.severity is s) for s in Severity}
            rules = ", ".join(sorted({f.rule.id for f in pr.findings})) or "none"
            out.append(
                f"| {_link(pr)} | {escape(pr.license)} | {pr.lines_changed:,} | {counts[Severity.HIGH]} "
                f"| {counts[Severity.MEDIUM]} | {counts[Severity.LOW]} | {rules} |"
            )
    return "\n".join(out) + "\n"
