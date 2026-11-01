"""Credentials committed to the repository.

Secret values are never shown: evidence keeps the first few characters and replaces the rest.
:func:`redact` is also applied by the engine to every other detector's evidence, so a line that
trips, say, a network rule cannot leak a token either.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator

from prscreen.detectors import Detector, LineDetector
from prscreen.detectors._common import basename, entropy, is_test, is_vendored
from prscreen.diff import ChangeKind, Diff, DiffLine, FileChange
from prscreen.models import Category, Confidence, Finding, Rule, Severity

_BENIGN_EXAMPLE = (
    "Documentation and tests sometimes contain revoked or fake keys. Even then, a real-looking key "
    "in history gets reported by scanners and copied by readers, so confirm it is not live."
)

PRIVATE_KEY = Rule(
    id="SEC001",
    title="Private key committed",
    category=Category.SECRETS,
    severity=Severity.HIGH,
    confidence=Confidence.HIGH,
    rationale=(
        "A private key in the repository lets anyone who can read it impersonate its owner: sign in "
        "to servers, decrypt traffic or sign releases. Deleting it later does not remove it from git "
        "history; the key has to be revoked."
    ),
    benign=_BENIGN_EXAMPLE,
)
KNOWN_TOKEN = Rule(
    id="SEC002",
    title="Access token with a known format",
    category=Category.SECRETS,
    severity=Severity.HIGH,
    confidence=Confidence.HIGH,
    rationale=(
        "The value matches the published format of a cloud or SaaS credential. Leaked tokens are "
        "harvested from public repositories within minutes and used to run up bills or steal data."
    ),
    benign=_BENIGN_EXAMPLE,
)
HARDCODED_CREDENTIAL = Rule(
    id="SEC003",
    title="Hardcoded password or secret",
    category=Category.SECRETS,
    severity=Severity.MEDIUM,
    confidence=Confidence.MEDIUM,
    rationale=(
        "A variable named like a credential is set to a literal, random-looking value. Secrets in "
        "source code end up in every clone, fork, log and backup of the repository."
    ),
    benign=(
        "Local development defaults, test fixtures and example configuration often use dummy "
        "values. Check that this one is not used in a deployed environment."
    ),
)
URL_CREDENTIAL = Rule(
    id="SEC004",
    title="Password embedded in a URL",
    category=Category.SECRETS,
    severity=Severity.MEDIUM,
    confidence=Confidence.MEDIUM,
    rationale=(
        "A URL of the form scheme://user:password@host carries the password in plain text, and URLs "
        "are routinely written to logs, error messages and browser history."
    ),
    benign="Connection strings for local databases in development or test setups are common.",
)
SECRET_FILE = Rule(
    id="SEC005",
    title="File that usually holds secrets",
    category=Category.SECRETS,
    severity=Severity.MEDIUM,
    confidence=Confidence.MEDIUM,
    rationale=(
        "Files such as .env, private key files, keystores and Terraform state usually contain "
        "credentials and are normally kept out of version control."
    ),
    benign=(
        "Sample files with dummy values, public certificates (.pem can be either) and test "
        "keystores are sometimes committed on purpose."
    ),
)

_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN (?:(?:RSA|DSA|EC|OPENSSH|PGP|ENCRYPTED) )?PRIVATE KEY(?: BLOCK)?-----"
)
_TOKENS: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (name, re.compile(pattern))
    for name, pattern in (
        ("AWS access key ID", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        ("GitHub token", r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b"),
        ("GitHub fine-grained token", r"\bgithub_pat_[A-Za-z0-9_]{60,255}\b"),
        ("GitLab token", r"\bglpat-[A-Za-z0-9_\-]{20,}"),
        ("Slack token", r"\bxox[abposr]-[A-Za-z0-9-]{10,}"),
        ("Slack webhook URL", r"hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+"),
        ("Stripe live key", r"\b[sr]k_live_[0-9a-zA-Z]{20,}"),
        ("Google API key", r"\bAIza[0-9A-Za-z_\-]{35}"),
        ("Anthropic API key", r"\bsk-ant-[A-Za-z0-9_\-]{20,}"),
        ("OpenAI API key", r"\bsk-[A-Za-z0-9_\-]{0,40}T3BlbkFJ[A-Za-z0-9_\-]{20,}"),
        ("npm token", r"\bnpm_[A-Za-z0-9]{36}\b"),
        ("PyPI token", r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}"),
        ("SendGrid key", r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b"),
    )
)
_CREDENTIAL_NAME = r"[\w.-]{0,40}(?:password|passwd|secret|api[_-]?key|access[_-]?key|auth[_-]?token|access[_-]?token|private[_-]?key|client[_-]?secret)[\w.-]{0,40}"  # noqa: E501
_ASSIGNMENT_RE = re.compile(
    rf"""(?i)\b({_CREDENTIAL_NAME})["']?\s*(?::=|=>|[:=])\s*[bru]?["']([^"'\s]{{8,200}})["']"""
)
# Keys that describe a credential rather than hold one: PASSWORD_FIELD = "password_input".
_DESCRIPTIVE_KEY_RE = re.compile(
    r"(?i)(name|field|label|url|uri|path|file|dir|env|var|header|type|id|prompt|policy|length|regex|"
    r"pattern|format|hint|placeholder|param|key_name|class|selector|column|attr)s?$"
)
_PLACEHOLDER_RE = re.compile(
    r"(?i)(example|sample|changeme|change_me|your[_-]|dummy|fake|placeholder|redacted|xxxx|\*\*\*|"
    r"<[^>]*>|\$\{|\{\{|%\(|^\$|test|secret_here|todo|replace)"
)
_WORDS_ONLY_RE = re.compile(r"^[a-z]+(?:[_\-.][a-z]+)*$")
_URL_CREDENTIAL_RE = re.compile(
    r"\b[a-zA-Z][a-zA-Z0-9+.\-]{0,20}://[^/\s:@\"'<>]{1,100}:([^/\s@\"'<>]{1,200})@[^/\s\"'<>]{1,200}"
)
_URL_PLACEHOLDERS = frozenset("password pass pwd secret xxx changeme passwd pw p".split())

_ENV_FILE_RE = re.compile(r"^\.env(?:\.[\w-]+)?$")
_ENV_SAMPLE_SUFFIXES = (".example", ".sample", ".template", ".dist", ".defaults", ".tmpl", ".schema")
_SECRET_NAMES = frozenset(
    "id_rsa id_dsa id_ecdsa id_ed25519 .htpasswd .pgpass .netrc _netrc .git-credentials "
    "credentials.json terraform.tfstate terraform.tfstate.backup kubeconfig secrets.yml "
    "secrets.yaml".split()
)
_SECRET_SUFFIXES = (".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", ".ppk", ".tfstate")


def _mask(value: str) -> str:
    return value[:4] + "…[redacted]"


def redact(text: str) -> str:
    """Replace every recognisable secret value in ``text`` with a short masked prefix."""
    for _, pattern in _TOKENS:
        text = pattern.sub(lambda m: _mask(m[0]), text)
    text = _ASSIGNMENT_RE.sub(
        lambda m: m[0].replace(m[2], _mask(m[2])) if _is_secret_value(m) else m[0], text
    )
    return _URL_CREDENTIAL_RE.sub(
        lambda m: (
            m[0].replace(":" + m[1] + "@", ":" + _mask(m[1]) + "@")
            if m[1].lower() not in _URL_PLACEHOLDERS
            else m[0]
        ),
        text,
    )


def _is_secret_value(match: re.Match[str]) -> bool:
    key, value = match[1], match[2]
    if _DESCRIPTIVE_KEY_RE.search(key) or _PLACEHOLDER_RE.search(value) or _WORDS_ONLY_RE.match(value):
        return False
    if len(set(value)) < 4:
        return False
    return entropy(value) >= 3.0


class SecretsDetector(LineDetector):
    name = "secrets"
    rules = (PRIVATE_KEY, KNOWN_TOKEN, HARDCODED_CREDENTIAL, URL_CREDENTIAL)

    def check_line(self, change: FileChange, line: DiffLine) -> Iterable[Finding]:
        text, path = line.text, change.path
        evidence = redact(text)
        if _PRIVATE_KEY_RE.search(text):
            yield PRIVATE_KEY.finding(path, line.number, evidence, "Starts a PEM private key block.")
        for name, pattern in _TOKENS:
            if pattern.search(text):
                yield KNOWN_TOKEN.finding(path, line.number, evidence, f"Looks like a {name}.")
                break
        else:
            yield from self._generic(change, line, evidence)

    def _generic(self, change: FileChange, line: DiffLine, evidence: str) -> Iterator[Finding]:
        if is_vendored(change.path):
            return
        test = is_test(change.path)
        for match in _ASSIGNMENT_RE.finditer(line.text):
            if _is_secret_value(match):
                yield HARDCODED_CREDENTIAL.finding(
                    change.path,
                    line.number,
                    evidence,
                    f"'{match[1]}' is set to a random-looking literal ({len(match[2])} characters).",
                    severity=Severity.LOW if test else None,
                    confidence=Confidence.LOW if test else None,
                )
                break
        for match in _URL_CREDENTIAL_RE.finditer(line.text):
            if match[1].lower() not in _URL_PLACEHOLDERS and not match[1].startswith(("$", "{", "%")):
                yield URL_CREDENTIAL.finding(
                    change.path,
                    line.number,
                    evidence,
                    "The URL contains a user name and password.",
                    confidence=Confidence.LOW if test else None,
                )
                break


class SecretFileDetector(Detector):
    name = "secret-files"
    rules = (SECRET_FILE,)

    def scan(self, diff: Diff) -> Iterator[Finding]:
        for change in diff.files:
            if change.kind is ChangeKind.DELETED:
                continue
            name = basename(change.path).lower()
            env_file = bool(_ENV_FILE_RE.match(name)) and not name.endswith(_ENV_SAMPLE_SUFFIXES)
            if env_file or name in _SECRET_NAMES or name.endswith(_SECRET_SUFFIXES):
                verb = "Adds" if change.kind is ChangeKind.ADDED else "Changes"
                yield SECRET_FILE.finding(
                    change.path,
                    None,
                    change.path,
                    f"{verb} a file named like a credential store.",
                    confidence=Confidence.LOW if is_test(change.path) else None,
                )
