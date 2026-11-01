"""Core data types shared by the diff parser, the detectors and the output formats."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import IntEnum, StrEnum

# Evidence is one diff line; anything longer than this is cut so a minified 2 MB line
# cannot bloat reports or comments.
MAX_EVIDENCE_CHARS = 300


class Severity(IntEnum):
    """How much harm the change could do if the finding is real."""

    LOW = 1
    MEDIUM = 2
    HIGH = 3

    @property
    def label(self) -> str:
        return self.name.lower()


class Confidence(IntEnum):
    """How likely it is that the matched pattern means what the rule says."""

    LOW = 1
    MEDIUM = 2
    HIGH = 3

    @property
    def label(self) -> str:
        return self.name.lower()


class Category(StrEnum):
    SECRETS = "secrets"
    EXECUTION = "execution"
    CI = "ci"
    NETWORK = "network"
    OBFUSCATION = "obfuscation"
    DEPENDENCIES = "dependencies"
    SECURITY_CONFIG = "security-config"
    SENSITIVE_PATHS = "sensitive-paths"
    AI_REVIEW = "ai-review"


@dataclass(frozen=True)
class Rule:
    """A single check. The text fields are shown to reviewers next to every finding."""

    id: str
    title: str
    category: Category
    severity: Severity
    confidence: Confidence
    rationale: str
    """Why the pattern may be risky."""
    benign: str
    """Common harmless reasons for the same pattern, so a finding never reads as an accusation."""
    supersedes: tuple[str, ...] = ()
    """Rule IDs that add nothing when this rule fires on the same line (shown once, not twice)."""

    def finding(
        self,
        path: str,
        line: int | None,
        evidence: str,
        detail: str = "",
        *,
        severity: Severity | None = None,
        confidence: Confidence | None = None,
    ) -> Finding:
        evidence = evidence.strip()
        if len(evidence) > MAX_EVIDENCE_CHARS:
            evidence = evidence[:MAX_EVIDENCE_CHARS] + "…"
        return Finding(
            rule=self,
            path=path,
            line=line,
            evidence=evidence,
            detail=detail,
            severity=severity or self.severity,
            confidence=confidence or self.confidence,
        )


@dataclass(frozen=True)
class Finding:
    """One piece of evidence in the diff.

    ``line`` is a line number in the new version of the file, or ``None`` for findings about
    the file as a whole (for example a deleted file or a mode change). ``evidence`` is raw
    text from the pull request and must go through :mod:`prscreen.sanitize` before display.
    """

    rule: Rule
    path: str
    line: int | None
    evidence: str
    detail: str
    severity: Severity
    confidence: Confidence

    @property
    def fingerprint(self) -> str:
        """Stable ID that survives the line moving, so later stages can track a finding across pushes."""
        normalized = " ".join(self.evidence.split())
        material = f"{self.rule.id}\0{self.path}\0{normalized}".encode("utf-8", "surrogatepass")
        return hashlib.sha256(material).hexdigest()[:16]
