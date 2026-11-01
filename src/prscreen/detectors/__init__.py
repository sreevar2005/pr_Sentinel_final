"""Detector interface and the registry of built-in detectors."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable, Iterator
from typing import ClassVar

from prscreen.diff import ChangeKind, Diff, DiffLine, FileChange
from prscreen.models import Finding, Rule


class Detector(ABC):
    """Looks at a whole diff. Use this when a check needs more than one line, or several files."""

    name: ClassVar[str]
    rules: ClassVar[tuple[Rule, ...]]

    @abstractmethod
    def scan(self, diff: Diff) -> Iterator[Finding]: ...


class LineDetector(Detector):
    """Runs :meth:`check_line` on every added line of every text file that is not deleted."""

    def scan(self, diff: Diff) -> Iterator[Finding]:
        for change in diff.files:
            if change.binary or change.kind is ChangeKind.DELETED or not self.applies_to(change.path):
                continue
            for line in change.added:
                yield from self.check_line(change, line)

    def applies_to(self, path: str) -> bool:
        return True

    @abstractmethod
    def check_line(self, change: FileChange, line: DiffLine) -> Iterable[Finding]: ...


def default_detectors() -> list[Detector]:
    from prscreen.detectors.obfuscation import BidiControlDetector

    return [BidiControlDetector()]


def all_rules(detectors: Iterable[Detector] | None = None) -> list[Rule]:
    rules: list[Rule] = []
    for detector in default_detectors() if detectors is None else detectors:
        rules.extend(detector.rules)
    return sorted(rules, key=lambda rule: rule.id)
