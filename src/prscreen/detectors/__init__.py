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
    from prscreen.detectors.ci import WorkflowDetector
    from prscreen.detectors.config import RemovedCheckDetector, SecurityConfigDetector
    from prscreen.detectors.dependencies import DependencyDetector
    from prscreen.detectors.execution import ExecutionDetector, InstallHookDetector
    from prscreen.detectors.network import DataCollectionDetector, NetworkDetector
    from prscreen.detectors.obfuscation import (
        BidiControlDetector,
        BinaryFileDetector,
        EncodedPayloadDetector,
        LookalikeDetector,
    )
    from prscreen.detectors.paths import SensitivePathDetector
    from prscreen.detectors.secrets import SecretFileDetector, SecretsDetector

    return [
        SecretsDetector(),
        SecretFileDetector(),
        ExecutionDetector(),
        InstallHookDetector(),
        WorkflowDetector(),
        NetworkDetector(),
        DataCollectionDetector(),
        BidiControlDetector(),
        LookalikeDetector(),
        EncodedPayloadDetector(),
        BinaryFileDetector(),
        SecurityConfigDetector(),
        RemovedCheckDetector(),
        DependencyDetector(),
        SensitivePathDetector(),
    ]


def all_rules(detectors: Iterable[Detector] | None = None) -> list[Rule]:
    rules: dict[str, Rule] = {}
    for detector in default_detectors() if detectors is None else detectors:
        for rule in detector.rules:
            rules[rule.id] = rule
    return sorted(rules.values(), key=lambda rule: rule.id)
