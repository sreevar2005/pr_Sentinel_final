"""Security settings switched off, opened up or removed."""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterator

from prscreen.detectors import Detector
from prscreen.detectors._common import (
    Pattern,
    PatternDetector,
    is_comment,
    is_runnable,
    is_source,
    is_test,
    is_vendored,
)
from prscreen.diff import ChangeKind, Diff
from prscreen.models import Category, Confidence, Finding, Rule, Severity

TLS_DISABLED = Rule(
    id="CFG001",
    title="TLS certificate verification disabled",
    category=Category.SECURITY_CONFIG,
    severity=Severity.MEDIUM,
    confidence=Confidence.HIGH,
    rationale=(
        "Without certificate checks, anyone on the network path can impersonate the server and read "
        "or change the traffic, including credentials sent over it."
    ),
    benign="Talking to a local service with a self-signed certificate in development or tests.",
)
PERMISSIVE_CORS = Rule(
    id="CFG002",
    title="Cross-origin access allowed from any site",
    category=Category.SECURITY_CONFIG,
    severity=Severity.LOW,
    confidence=Confidence.MEDIUM,
    rationale=(
        "A wildcard CORS policy lets any website's scripts call this API from a visitor's browser. "
        "Combined with cookies or credentials it exposes user data to other sites."
    ),
    benign="Public, read-only APIs and CDNs serve '*' on purpose.",
)
PROTECTION_DISABLED = Rule(
    id="CFG003",
    title="Framework protection turned off",
    category=Category.SECURITY_CONFIG,
    severity=Severity.MEDIUM,
    confidence=Confidence.MEDIUM,
    rationale=(
        "Debug mode, disabled CSRF protection and insecure cookies remove defences the framework "
        "provides by default. Debug pages in particular can leak secrets or allow code execution."
    ),
    benign="Local development settings, tests, and API endpoints that use token auth instead of cookies.",
)
WORLD_WRITABLE = Rule(
    id="CFG004",
    title="World-writable file permissions",
    category=Category.SECURITY_CONFIG,
    severity=Severity.MEDIUM,
    confidence=Confidence.HIGH,
    rationale=(
        "Files anyone on the machine can modify (777, 666, o+w) let any local user or compromised "
        "service replace code or configuration that later runs with more privileges."
    ),
    benign="Throw-away containers and scratch directories, though narrower permissions still work.",
)
CHECK_REMOVED = Rule(
    id="CFG005",
    title="Authentication or authorization check removed",
    category=Category.SECURITY_CONFIG,
    severity=Severity.MEDIUM,
    confidence=Confidence.MEDIUM,
    rationale=(
        "A line that enforced login, permissions, CSRF or signature checks was deleted and not added "
        "back elsewhere in the same file. Removing a check is easy to miss in review because the "
        "remaining code still looks complete."
    ),
    benign="The check moved to middleware, a base class or another file, or the endpoint was retired.",
)

_TLS_RE = re.compile(
    r"\bverify\s*=\s*False\b|\brejectUnauthorized\s*:\s*false\b|NODE_TLS_REJECT_UNAUTHORIZED[\"']?\s*[=:]\s*[\"']?0"
    r"|\bInsecureSkipVerify\s*:\s*true\b|\bssl\._create_unverified_context\b|\bCERT_NONE\b"
    r"|\bcheck_hostname\s*=\s*False\b|\bcurl\b.{0,300}\s(?:-k|--insecure)\b|\bwget\b.{0,300}--no-check-certificate"
    r"|\bstrict-ssl\s*[=:]\s*false\b|\bsslverify\s*[=:]\s*(?:false|0)\b|--trusted-host\b"
    r"|-SkipCertificateCheck\b|\bServerCertificateValidationCallback\b.{0,300}=>\s*true"
    r"|\bVERIFY_NONE\b|\bsetHostnameVerifier\s*\(.{0,300}ALLOW_ALL|\bTrustAllCerts\b|\bInsecureRequestWarning\b"
)
_CORS_RE = re.compile(
    r"Access-Control-Allow-Origin[\"']?\s*[:,]\s*[\"']\*|\bCORS_(?:ORIGIN_ALLOW_ALL|ALLOW_ALL_ORIGINS)\s*=\s*True"
    r"|\ballow_origins\s*=\s*\[\s*[\"']\*[\"']|\borigin\s*:\s*[\"']\*[\"']|\bAllowAnyOrigin\s*\(\s*\)"
    r"|\bcors\s*\(\s*\)"
)
_PROTECTION_RE = re.compile(
    r"^\s*DEBUG\s*=\s*True\b|\.run\s*\(.{0,300}\bdebug\s*=\s*True|@csrf_exempt\b|\bWTF_CSRF_ENABLED\s*=\s*False"
    r"|\.csrf\s*\(\s*\)\s*\.\s*disable\s*\(|\bcsrf\s*\(\s*(?:AbstractHttpConfigurer::)?disable\s*\)"
    r"|\b(?:SESSION|CSRF)_COOKIE_SECURE\s*=\s*False|\bSESSION_COOKIE_HTTPONLY\s*=\s*False"
    r"|\bhttpOnly\s*:\s*false\b|\bprotect_from_forgery\s+with:\s*:null_session|\bskip_forgery_protection\b"
    r"|\bSECURE_SSL_REDIRECT\s*=\s*False|\bALLOWED_HOSTS\s*=\s*\[\s*[\"']\*[\"']"
)
_WORLD_WRITABLE_RE = re.compile(
    r"\bchmod\s+(?:-\w+\s+)*(?:0?777|0?666|[ugoa]*o[ugoa]*\+[rx]*w|a\+[rx]*w)\b"
    r"|\b(?:os\.)?chmod\s*\([^)]{0,300},\s*0o?777\b|\bumask\s*\(\s*0+\s*\)|\bumask\s+0+\b"
)
_CHECK_RE = re.compile(
    r"@(?:login_required|permission_required|user_passes_test|staff_member_required|csrf_protect|"
    r"requires_auth|auth_required|jwt_required|fresh_jwt_required|roles_required|admin_required|"
    r"PreAuthorize|Secured|RolesAllowed|UseGuards|Authorized?)\b"
    r"|\[Authorize\b|\bverify_signature\b|\bcheck_permissions?\s*\(|\bhas_perm(?:s)?\s*\("
    r"|\bis_authenticated\b|\bauthenticate(?:User|Request|Token)?\s*\(|\bverify(?:Token|Jwt|JWT|Signature)\s*\("
    r"|\bjwt\.verify\s*\(|\brequire(?:Auth|Login|Admin|Role)\s*\(|\bensureAuthenticated\b"
    r"|\bpermission_classes\s*=|\bauthentication_classes\s*=|\bUse(?:Authentication|Authorization)\s*\("
    r"|\bhelmet\s*\(|\bcsrf(?:Protection)?\s*\(|\bhmac\.compare_digest\s*\("
)


class SecurityConfigDetector(PatternDetector):
    name = "security-config"
    patterns = (
        Pattern(TLS_DISABLED, _TLS_RE, "Turns off certificate verification.", where=is_runnable),
        Pattern(PERMISSIVE_CORS, _CORS_RE, "Allows requests from every origin.", where=is_runnable),
        Pattern(PROTECTION_DISABLED, _PROTECTION_RE, "Disables a default protection.", where=is_runnable),
        Pattern(WORLD_WRITABLE, _WORLD_WRITABLE_RE, "Makes files writable by everyone.", where=is_runnable),
    )


class RemovedCheckDetector(Detector):
    name = "removed-checks"
    rules = (CHECK_REMOVED,)

    def scan(self, diff: Diff) -> Iterator[Finding]:
        for change in diff.files:
            if change.binary or change.kind is ChangeKind.DELETED or not is_source(change.path):
                continue
            if is_vendored(change.path):
                continue
            added = Counter(m[0] for line in change.added for m in _CHECK_RE.finditer(line.text))
            for line in change.removed:
                if is_comment(line.text):
                    continue
                for match in _CHECK_RE.finditer(line.text):
                    if added[match[0]] > 0:
                        added[match[0]] -= 1  # the same check re-added: moved, not removed
                        continue
                    yield CHECK_REMOVED.finding(
                        change.path, None, line.text,
                        f"Removed '{match[0]}' (old line {line.number}) without adding it back.",
                        confidence=Confidence.LOW if is_test(change.path) else None,
                    )  # fmt: skip
                    break
