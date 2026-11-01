"""Files whose change deserves attention no matter what the change is."""

from __future__ import annotations

import re
from collections.abc import Iterator

from prscreen.detectors import Detector
from prscreen.detectors._common import basename, is_source, is_test, is_workflow
from prscreen.diff import ChangeKind, Diff, FileChange
from prscreen.models import Category, Confidence, Finding, Rule, Severity

CI_CONFIG = Rule(
    id="PATH001",
    title="CI or automation configuration changed",
    category=Category.SENSITIVE_PATHS,
    severity=Severity.LOW,
    confidence=Confidence.HIGH,
    rationale=(
        "Pipelines hold deployment credentials and decide which checks run. A change here can "
        "affect every future build, and deleting a workflow silently stops a check."
    ),
    benign="Routine maintenance: version bumps, new test matrix entries, caching tweaks.",
)
REVIEW_RULES = Rule(
    id="PATH002",
    title="Code ownership or review rules changed",
    category=Category.SENSITIVE_PATHS,
    severity=Severity.MEDIUM,
    confidence=Confidence.HIGH,
    rationale=(
        "CODEOWNERS and repository settings decide who must approve changes. Editing them in the "
        "same PR as other changes can remove the reviewer who would have objected."
    ),
    benign="Team changes and new directories need ownership updates.",
)
AUTO_RUN_CONFIG = Rule(
    id="PATH003",
    title="Config that runs commands on developer machines",
    category=Category.SENSITIVE_PATHS,
    severity=Severity.LOW,
    confidence=Confidence.MEDIUM,
    rationale=(
        "Editor tasks, dev containers, git hooks, direnv files, test bootstrap files and git "
        "filters run automatically when someone opens, builds or tests the project, often without "
        "an obvious prompt."
    ),
    benign="Teams share these deliberately to standardise their setup.",
)
SECURITY_CODE = Rule(
    id="PATH004",
    title="Security-sensitive code changed",
    category=Category.SENSITIVE_PATHS,
    severity=Severity.LOW,
    confidence=Confidence.LOW,
    rationale=(
        "The file name suggests authentication, authorization, sessions or cryptography. Bugs here "
        "have outsized impact, so the change deserves a reviewer who knows that area."
    ),
    benign="Ordinary changes to these files are common; this only routes attention.",
)

_CI_PATHS = re.compile(
    r"^(?:\.github/(?:workflows|actions)/|\.circleci/|\.buildkite/|\.gitlab/ci/)"
    r"|(?:^|/)(?:\.gitlab-ci\.ya?ml|jenkinsfile|azure-pipelines\.ya?ml|\.travis\.yml|bitbucket-pipelines\.yml"
    r"|cloudbuild\.ya?ml|\.drone\.yml|action\.ya?ml)$"
    r"|^\.github/(?:dependabot\.yml|renovate\.json5?)$|^renovate\.json5?$"
)
_REVIEW_PATHS = re.compile(r"^(?:\.github/|docs/)?codeowners$|^\.github/settings\.ya?ml$|^\.github/rulesets/")
_AUTO_RUN_PATHS = re.compile(
    r"^\.vscode/(?:tasks|settings|launch)\.json$|^\.devcontainer/|^\.idea/(?:runConfigurations|workspace\.xml)"
    r"|(?:^|/)(?:\.envrc|\.gitattributes|\.gitmodules|\.pre-commit-config\.yaml|\.lefthook\.ya?ml|lefthook\.ya?ml"
    r"|conftest\.py|\.npmrc|\.yarnrc(?:\.yml)?|\.mise\.toml|\.tool-versions)$|^\.husky/|^\.githooks/"
)
_SECURITY_NAME = re.compile(
    r"(?:^|[/_\-.])(?:auth[nz]?|authenticat\w*|authoriz\w*|login|logout|sessions?|passwords?|passwd|"
    r"oauth2?|saml|sso|jwt|tokens?|crypto|cryptography|permissions?|acl|rbac|"
    r"policy|policies|security|secrets?|csrf|signature|signing|verify)(?:[/_\-.]|$)"
)


class SensitivePathDetector(Detector):
    name = "sensitive-paths"
    rules = (CI_CONFIG, REVIEW_RULES, AUTO_RUN_CONFIG, SECURITY_CODE)

    def scan(self, diff: Diff) -> Iterator[Finding]:
        for change in diff.files:
            path = change.path.lower()
            if _CI_PATHS.search(path) or is_workflow(path):
                deleted = change.kind is ChangeKind.DELETED
                yield self._finding(
                    CI_CONFIG, change,
                    "Deletes CI configuration; whatever it checked no longer runs." if deleted else None,
                    severity=Severity.MEDIUM if deleted else None,
                )  # fmt: skip
            elif _REVIEW_PATHS.search(path):
                yield self._finding(REVIEW_RULES, change)
            elif _AUTO_RUN_PATHS.search(path):
                yield self._finding(AUTO_RUN_CONFIG, change)
            elif is_source(path) and not is_test(path) and _SECURITY_NAME.search(path):
                yield self._finding(SECURITY_CODE, change)

    @staticmethod
    def _finding(
        rule: Rule, change: FileChange, detail: str | None = None, severity: Severity | None = None
    ) -> Finding:
        verb = {"added": "Adds", "deleted": "Deletes", "renamed": "Renames"}.get(change.kind.value, "Changes")
        return rule.finding(
            change.path,
            None,
            basename(change.path),
            detail or f"{verb} {change.path} (+{len(change.added)}/-{len(change.removed)} lines).",
            severity=severity,
        )
