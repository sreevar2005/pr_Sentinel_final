"""Runs detectors over a parsed diff and collects the results."""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, field, replace

from prscreen.detectors import MAX_SCAN_LINE_CHARS, Detector, all_rules, default_detectors
from prscreen.detectors.secrets import redact
from prscreen.diff import Diff
from prscreen.models import Finding, Rule

# A PR padded with thousands of copies of one pattern should not bury everything else in noise.
MAX_FINDINGS_PER_RULE_PER_FILE = 20


@dataclass
class ScanResult:
    findings: list[Finding]
    rules: list[Rule]
    files_scanned: int
    skipped: list[tuple[str, str]] = field(default_factory=list)
    """(path, reason) for files whose content could not be scanned."""
    capped: dict[tuple[str, str], int] = field(default_factory=dict)
    """(rule id, path) -> findings dropped by the per-file cap."""
    errors: list[str] = field(default_factory=list)
    """Detectors that crashed. Their findings are missing, so the result is incomplete."""

    @property
    def complete(self) -> bool:
        return not self.errors


def scan(diff: Diff, detectors: Sequence[Detector] | None = None) -> ScanResult:
    detectors = default_detectors() if detectors is None else list(detectors)
    findings: list[Finding] = []
    seen: set[tuple[str, str, int | None, str]] = set()
    per_file: Counter[tuple[str, str]] = Counter()
    capped: Counter[tuple[str, str]] = Counter()
    errors: list[str] = []

    for detector in detectors:
        try:
            for finding in detector.scan(diff):
                finding = replace(finding, evidence=redact(finding.evidence))
                key = (finding.rule.id, finding.path, finding.line, finding.evidence)
                if key in seen:
                    continue
                seen.add(key)
                bucket = (finding.rule.id, finding.path)
                per_file[bucket] += 1
                if per_file[bucket] > MAX_FINDINGS_PER_RULE_PER_FILE:
                    capped[bucket] += 1
                    continue
                findings.append(finding)
        except Exception as exc:  # noqa: BLE001 - one broken detector must not hide the others' findings
            errors.append(f"detector {detector.name!r} failed: {type(exc).__name__}: {exc}")

    findings = _drop_superseded(findings)
    findings.sort(key=lambda f: (-f.severity, -f.confidence, f.path, f.line or 0, f.rule.id))
    return ScanResult(
        findings=findings,
        rules=all_rules(detectors),
        files_scanned=len(diff.files),
        skipped=_skipped(diff),
        capped=dict(capped),
        errors=errors,
    )


def _drop_superseded(findings: list[Finding]) -> list[Finding]:
    """Drop findings that a more specific rule already reports on the same line."""
    covered = {(f.path, f.line, sup) for f in findings if f.line is not None for sup in f.rule.supersedes}
    return [f for f in findings if (f.path, f.line, f.rule.id) not in covered]


def _skipped(diff: Diff) -> list[tuple[str, str]]:
    skipped = [(change.path, "binary file") for change in diff.files if change.binary]
    for change in diff.files:
        long = [line.number for line in change.added if len(line.text) > MAX_SCAN_LINE_CHARS]
        if long:
            where = ", ".join(map(str, long[:5])) + (" and more" if len(long) > 5 else "")
            skipped.append((change.path, f"line {where} scanned only to {MAX_SCAN_LINE_CHARS:,} characters"))
    return skipped
