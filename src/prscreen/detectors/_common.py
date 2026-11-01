"""Shared helpers for detectors: what kind of file a path is, and table-driven regex rules."""

from __future__ import annotations

import math
import re
from collections import Counter
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import ClassVar

from prscreen.detectors import LineDetector
from prscreen.diff import DiffLine, FileChange
from prscreen.models import Confidence, Finding, Rule, Severity

CODE_SUFFIXES = frozenset(
    ".py .pyw .pyi .js .mjs .cjs .jsx .ts .mts .cts .tsx .vue .svelte .go .rb .php .java .kt .kts "
    ".scala .groovy .gradle .cs .vb .fs .c .cc .cpp .cxx .h .hh .hpp .rs .swift .m .mm .dart .ex .exs "
    ".erl .lua .pl .pm .r .jl .sh .bash .zsh .fish .ps1 .psm1 .psd1 .bat .cmd .vbs .tf .hcl".split()
)
CONFIG_SUFFIXES = frozenset(".yml .yaml .json .jsonc .toml .ini .cfg .conf .properties .xml .env".split())
DOC_SUFFIXES = frozenset(".md .markdown .rst .txt .adoc .asciidoc .org .tex .rtf".split())
CODE_BASENAMES = frozenset(
    "dockerfile containerfile makefile gnumakefile jenkinsfile rakefile gemfile vagrantfile "
    "justfile procfile .bashrc .zshrc .profile".split()
)
LOCKFILES = frozenset(
    "package-lock.json npm-shrinkwrap.json yarn.lock pnpm-lock.yaml bun.lock poetry.lock uv.lock "
    "pipfile.lock pdm.lock cargo.lock go.sum gemfile.lock composer.lock packages.lock.json "
    "gradle.lockfile flake.lock".split()
)
_VENDOR_PARTS = frozenset(
    "node_modules vendor third_party third-party dist build .yarn bower_components".split()
)
_TEST_PARTS = frozenset(
    "test tests __tests__ spec specs testdata test_data fixtures __fixtures__ e2e".split()
)
_TEST_NAME_RE = re.compile(r"(^test_|_test\.|\.test\.|\.spec\.|_spec\.|^conftest\.py$)")
_COMMENT_PREFIXES = ("#", "//", "/*", "*", "<!--", "rem ", "REM ")


def basename(path: str) -> str:
    return path.rsplit("/", 1)[-1]


def suffix(path: str) -> str:
    name = basename(path).lower()
    return name[name.rfind(".") :] if "." in name[1:] else ""


def parts(path: str) -> list[str]:
    return path.lower().split("/")


def is_code(path: str) -> bool:
    name = basename(path).lower()
    return suffix(path) in CODE_SUFFIXES or name in CODE_BASENAMES or name.startswith("dockerfile")


def is_config(path: str) -> bool:
    return suffix(path) in CONFIG_SUFFIXES and not is_lockfile(path)


def is_doc(path: str) -> bool:
    return suffix(path) in DOC_SUFFIXES or basename(path).lower() in ("license", "notice", "authors")


def is_lockfile(path: str) -> bool:
    return basename(path).lower() in LOCKFILES


def is_vendored(path: str) -> bool:
    name = basename(path).lower()
    return (
        any(part in _VENDOR_PARTS for part in parts(path)[:-1])
        or ".min." in name
        or name.endswith((".map", ".bundle.js", ".chunk.js"))
    )


def is_test(path: str) -> bool:
    return any(part in _TEST_PARTS for part in parts(path)[:-1]) or bool(
        _TEST_NAME_RE.search(basename(path).lower())
    )


def is_workflow(path: str) -> bool:
    lower = path.lower()
    return (lower.startswith(".github/workflows/") and lower.endswith((".yml", ".yaml"))) or basename(
        lower
    ) in ("action.yml", "action.yaml")


def is_source(path: str) -> bool:
    """Hand-written code that runs: the main target for most rules."""
    return is_code(path) and not is_vendored(path)


def is_runnable(path: str) -> bool:
    """Anything a machine executes or loads, including CI and config files."""
    return (is_code(path) or is_config(path) or is_workflow(path)) and not is_vendored(path)


def anywhere(path: str) -> bool:
    return True


def is_comment(text: str) -> bool:
    stripped = text.lstrip()
    return stripped.startswith(_COMMENT_PREFIXES) and not stripped.startswith("#!")


def entropy(text: str) -> float:
    """Shannon entropy in bits per character."""
    if not text:
        return 0.0
    counts = Counter(text)
    return -sum(n / len(text) * math.log2(n / len(text)) for n in counts.values())


def lower(confidence: Confidence) -> Confidence:
    return Confidence(max(Confidence.LOW, confidence - 1))


@dataclass(frozen=True)
class Pattern:
    """One regex check. ``where`` picks the files it applies to."""

    rule: Rule
    regex: re.Pattern[str]
    detail: str
    where: Callable[[str], bool] = is_source
    skip_comments: bool = True
    severity: Severity | None = None
    confidence: Confidence | None = None


class PatternDetector(LineDetector):
    """Runs a table of :class:`Pattern` over added lines. One finding per rule per line.

    Matches in test files drop one step in severity and confidence: tests are full of
    deliberately bad input.
    """

    patterns: ClassVar[tuple[Pattern, ...]]

    def __init_subclass__(cls, **kwargs: object) -> None:
        super().__init_subclass__(**kwargs)
        if "patterns" in cls.__dict__ and "rules" not in cls.__dict__:
            cls.rules = tuple(dict.fromkeys(p.rule for p in cls.patterns))

    def check_line(self, change: FileChange, line: DiffLine) -> Iterator[Finding]:
        fired: set[str] = set()
        comment = is_comment(line.text)
        for pattern in self.patterns:
            if pattern.rule.id in fired or not pattern.where(change.path):
                continue
            if pattern.skip_comments and comment:
                continue
            if pattern.regex.search(line.text) is None:
                continue
            fired.add(pattern.rule.id)
            severity = pattern.severity or pattern.rule.severity
            confidence = pattern.confidence or pattern.rule.confidence
            if is_test(change.path):
                severity, confidence = Severity(max(Severity.LOW, severity - 1)), lower(confidence)
            yield pattern.rule.finding(
                change.path,
                line.number,
                line.text,
                pattern.detail,
                severity=severity,
                confidence=confidence,
            )
