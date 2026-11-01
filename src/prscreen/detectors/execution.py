"""Code that runs other code: shells, eval, unsafe deserialization and install-time hooks."""

from __future__ import annotations

import re
from collections.abc import Iterator

from prscreen.detectors import LineDetector
from prscreen.detectors._common import (
    Pattern,
    PatternDetector,
    basename,
    is_comment,
    is_doc,
    is_runnable,
    is_source,
    is_vendored,
    suffix,
)
from prscreen.diff import ChangeKind, Diff, DiffLine, FileChange
from prscreen.models import Category, Confidence, Finding, Rule, Severity

PIPE_TO_SHELL = Rule(
    id="EXE001",
    title="Downloaded script piped straight into a shell",
    category=Category.EXECUTION,
    severity=Severity.HIGH,
    confidence=Confidence.HIGH,
    rationale=(
        "Whatever the server returns at that moment runs immediately with the current user's "
        "rights, with no review and no integrity check. If the host or the connection is "
        "compromised, so is every machine or CI runner that runs this line."
    ),
    benign=(
        "Official installers (rustup, Homebrew, nvm) are distributed this way. Prefer a pinned "
        "version and a checksum, especially in CI."
    ),
    supersedes=("NET003",),
)
DYNAMIC_EVAL = Rule(
    id="EXE002",
    title="Dynamic code evaluation",
    category=Category.EXECUTION,
    severity=Severity.MEDIUM,
    confidence=Confidence.MEDIUM,
    rationale=(
        "eval, exec and new Function run a string as code. If any part of that string can be "
        "influenced from outside, it becomes remote code execution; it is also a common way to hide "
        "what code really does."
    ),
    benign="Templating engines, REPLs, plugin loaders and build tools use it deliberately.",
)
SHELL_COMMAND = Rule(
    id="EXE003",
    title="Shell command execution",
    category=Category.EXECUTION,
    severity=Severity.MEDIUM,
    confidence=Confidence.MEDIUM,
    rationale=(
        "Running a command through a shell interprets quotes, semicolons and $(...) in its "
        "arguments. Any outside input in the command string allows command injection."
    ),
    benign=(
        "Build scripts and developer tooling often run fixed commands. It is safe when the command "
        "is a constant or the arguments are passed as a list without a shell."
    ),
)
UNSAFE_DESERIALIZATION = Rule(
    id="EXE004",
    title="Unsafe deserialization",
    category=Category.EXECUTION,
    severity=Severity.MEDIUM,
    confidence=Confidence.MEDIUM,
    rationale=(
        "pickle, marshal, unsafe YAML loaders, Java ObjectInputStream and PHP unserialize can run "
        "code while decoding. Loading data from an untrusted source with them is remote code "
        "execution."
    ),
    benign="Loading files the application wrote itself, such as a local cache or a trained model.",
)
INSTALL_HOOK = Rule(
    id="EXE005",
    title="Install-time script",
    category=Category.EXECUTION,
    severity=Severity.MEDIUM,
    confidence=Confidence.MEDIUM,
    rationale=(
        "Package managers run install hooks automatically on every machine that installs the "
        "project, including CI. They are the most common way malicious packages run code."
    ),
    benign=(
        "Native extensions compile on install, and tools like husky set up git hooks in prepare. "
        "Check what the script actually runs."
    ),
)
STARTUP_FILE = Rule(
    id="EXE006",
    title="Python startup file (.pth) with code",
    category=Category.EXECUTION,
    severity=Severity.HIGH,
    confidence=Confidence.MEDIUM,
    rationale=(
        "Lines starting with 'import' in a .pth file in site-packages run every time Python "
        "starts, for every program. Malware uses this to persist."
    ),
    benign="A few packages (coverage tools, editable installs) ship .pth hooks on purpose.",
)

_SHELLS = r"(?:sudo\s+(?:-\S+\s+)*)?(?:ba|z|da|k|fi)?sh\b"
_INTERPRETERS = r"(?:sudo\s+(?:-\S+\s+)*)?(?:python[0-9.]*|perl|ruby|node|php)\b"
_PIPE_TO_SHELL_RE = re.compile(
    rf"\b(?:curl|wget)\b[^|;&\n]{{0,500}}\|\s*(?:{_SHELLS}|{_INTERPRETERS})"
    rf"|\b(?:ba|z)?sh\s+(?:-c\s+)?[\"']?(?:<\(|\$\()\s*(?:curl|wget)\b"
    r"|(?i:\b(?:iex|invoke-expression)\b.{0,300}\b(?:downloadstring|iwr|irm|invoke-webrequest|invoke-restmethod)\b)"
    r"|(?i:\b(?:downloadstring|iwr|irm|invoke-webrequest|invoke-restmethod)\b.{0,300}\|\s*(?:iex|invoke-expression)\b)"
)


def _python(path: str) -> bool:
    return is_source(path) and suffix(path) in (".py", ".pyw", ".pth")


def _javascript(path: str) -> bool:
    return is_source(path) and suffix(path) in (".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx")


def _not_doc(path: str) -> bool:
    return is_runnable(path) or (not is_doc(path) and "." not in basename(path))


class ExecutionDetector(PatternDetector):
    name = "execution"
    patterns = (
        Pattern(PIPE_TO_SHELL, _PIPE_TO_SHELL_RE, "Runs a remote script without saving or verifying it.",
                where=_not_doc),
        Pattern(PIPE_TO_SHELL, _PIPE_TO_SHELL_RE, "Documentation tells readers to run a remote script.",
                where=is_doc, skip_comments=False, severity=Severity.LOW, confidence=Confidence.MEDIUM),
        # exec() is Python's eval for statements; in JavaScript a bare exec() is child_process.
        Pattern(DYNAMIC_EVAL, re.compile(r"(?<![\w.$])eval\s*\((?!\s*\))"), "Evaluates a string as code."),
        Pattern(DYNAMIC_EVAL, re.compile(r"(?<![\w.$])exec\s*\((?!\s*\))"), "Executes a string as code.",
                where=_python),
        Pattern(DYNAMIC_EVAL, re.compile(r"\bnew\s+Function\s*\(|\bset(?:Timeout|Interval)\s*\(\s*[\"'`]"),
                "Builds a function from a string."),
        Pattern(SHELL_COMMAND, re.compile(r"(?<![\w.$])exec(?:Sync)?\s*\(\s*[`'\"]"),
                "Runs a command string through a shell (child_process.exec).", where=_javascript),
        Pattern(SHELL_COMMAND, re.compile(
            r"\bsubprocess\.\w+\s*\(.{0,300}\bshell\s*=\s*True"
            r"|\bos\.(?:system|popen)\s*\("
            r"|\bRuntime\.getRuntime\(\)\.exec\s*\("
            r"|\bexec\.Command(?:Context)?\((?:ctx,\s*)?\"(?:/bin/)?(?:ba)?sh\",\s*\"-c\""
            r"|(?<![\w.>$])(?:shell_exec|passthru|proc_open|popen)\s*\("
        ), "Runs a command through a shell."),
        Pattern(SHELL_COMMAND, re.compile(
            r"""(?:require\s*\(\s*|from\s+|import\s*\(\s*)["'](?:node:)?child_process["']"""
            r"|\b(?:execSync|spawnSync)\s*\(|\bchild_process\.exec\s*\("
        ), "Imports or calls Node's child_process.", severity=Severity.LOW),
        Pattern(UNSAFE_DESERIALIZATION, re.compile(
            r"\b(?:c?[Pp]ickle|dill|marshal|shelve)\.loads?\s*\("
            r"|\byaml\.load(?:_all)?\s*\((?![^)]{0,300}Loader\s*=\s*(?:yaml\.)?C?SafeLoader)"
            r"|\byaml\.(?:unsafe_load|full_load)(?:_all)?\s*\("
            r"|\bjsonpickle\.decode\s*\(|\bnew\s+ObjectInputStream\b|\bBinaryFormatter\b"
            r"|(?<![\w.>$])unserialize\s*\(|\bMarshal\.load\b"
            r"|\btorch\.load\s*\((?![^)]{0,300}weights_only\s*=\s*True)"
        ), "Decodes data with a format that can run code."),
    )  # fmt: skip


_NPM_HOOK_RE = re.compile(r'"((?:pre|post)?install|prepare|prepublish)"\s*:\s*"([^"]*)"')
_COMPOSER_HOOK_RE = re.compile(r'"(post-(?:install|update|autoload-dump)-cmd|pre-install-cmd)"\s*:')
_SUSPICIOUS_HOOK_RE = re.compile(
    r"(?i)\b(?:curl|wget|https?://|node\s+-e|eval|base64|powershell|iex|nc\s|bash\s+-c|sh\s+-c)\b|\|\s*(?:ba)?sh\b"
)
_SETUP_CMDCLASS_RE = re.compile(
    r"\bcmdclass\s*=|class\s+\w+\s*\(\s*(?:install|develop|egg_info|build_py|build_ext)\s*\)"
)
_SETUP_NETWORK_RE = re.compile(
    r"\b(?:urllib|requests|httpx|socket|http\.client|urlopen|subprocess|os\.system)\b"
)


class InstallHookDetector(LineDetector):
    name = "install-hooks"
    rules = (INSTALL_HOOK, STARTUP_FILE)

    def scan(self, diff: Diff) -> Iterator[Finding]:
        yield from super().scan(diff)
        for change in diff.files:
            if basename(change.path) == "build.rs" and change.kind is ChangeKind.ADDED:
                yield INSTALL_HOOK.finding(
                    change.path, None, change.path,
                    "Adds a Cargo build script, which runs on every build of the crate.",
                    severity=Severity.LOW,
                )  # fmt: skip

    def check_line(self, change: FileChange, line: DiffLine) -> Iterator[Finding]:
        name = basename(change.path).lower()
        text = line.text
        if name == "package.json" and (match := _NPM_HOOK_RE.search(text)):
            hook, command = match[1], match[2]
            suspicious = bool(_SUSPICIOUS_HOOK_RE.search(command))
            if hook == "prepare" and not suspicious:
                return  # husky and friends: build steps that only run in a checkout
            yield INSTALL_HOOK.finding(
                change.path, line.number, text,
                f"npm runs the '{hook}' script automatically on install"
                + (" and it downloads or decodes something." if suspicious else "."),
                severity=Severity.HIGH if suspicious else None,
                confidence=Confidence.HIGH if suspicious else None,
            )  # fmt: skip
        elif name == "composer.json" and _COMPOSER_HOOK_RE.search(text):
            yield INSTALL_HOOK.finding(change.path, line.number, text, "Composer runs this on install.")
        elif name == "setup.py" and not is_comment(text):
            importing = text.lstrip().startswith(("import ", "from "))  # importing alone does nothing
            if _SETUP_NETWORK_RE.search(text) and not importing:
                yield INSTALL_HOOK.finding(
                    change.path, line.number, text,
                    "setup.py runs during install; this line makes network calls or runs commands.",
                    severity=Severity.HIGH,
                )  # fmt: skip
            elif _SETUP_CMDCLASS_RE.search(text):
                yield INSTALL_HOOK.finding(change.path, line.number, text, "Overrides an install step.")
        elif name.endswith(".pth") and text.lstrip().startswith("import ") and not is_vendored(change.path):
            yield STARTUP_FILE.finding(change.path, line.number, text, "Runs on every Python start-up.")
