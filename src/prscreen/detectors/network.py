"""New network destinations and code that gathers data worth stealing."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterator

from prscreen.detectors import Detector
from prscreen.detectors._common import (
    Pattern,
    PatternDetector,
    is_comment,
    is_doc,
    is_lockfile,
    is_runnable,
    is_source,
    is_test,
    is_vendored,
)
from prscreen.diff import ChangeKind, Diff, DiffLine, FileChange
from prscreen.models import Category, Confidence, Finding, Rule, Severity

HARDCODED_IP = Rule(
    id="NET001",
    title="Hardcoded public IP address",
    category=Category.NETWORK,
    severity=Severity.MEDIUM,
    confidence=Confidence.MEDIUM,
    rationale=(
        "Connecting to a raw public IP skips DNS, certificates tied to a name and most allow-lists, "
        "and the address says nothing about who owns it. Malware uses this for command-and-control."
    ),
    benign="Public DNS resolvers, well-known service IPs, or test infrastructure.",
)
EXFIL_ENDPOINT = Rule(
    id="NET002",
    title="Data-drop, paste or tunnelling service",
    category=Category.NETWORK,
    severity=Severity.HIGH,
    confidence=Confidence.MEDIUM,
    rationale=(
        "Request catchers, paste sites, chat webhooks and tunnels accept data from anyone without an "
        "account. They are favourite destinations for stolen tokens and environment dumps."
    ),
    benign=(
        "Developers use them while debugging webhooks, and bots post to Discord or Telegram on "
        "purpose. Check what data is sent."
    ),
)
NEW_ENDPOINT = Rule(
    id="NET003",
    title="New outbound network destination",
    category=Category.NETWORK,
    severity=Severity.LOW,
    confidence=Confidence.LOW,
    rationale=(
        "The change makes the code talk to a host it may not have talked to before. Reviewers should "
        "know where data goes, especially when something is sent rather than fetched."
    ),
    benign="Most new URLs are ordinary APIs, documentation links or CDNs.",
)
ENV_HARVEST = Rule(
    id="NET004",
    title="Collects every environment variable",
    category=Category.NETWORK,
    severity=Severity.MEDIUM,
    confidence=Confidence.MEDIUM,
    rationale=(
        "Environment variables hold API keys and CI tokens. Serialising all of them at once is "
        "rarely needed by application code and is the first step of most credential-stealing "
        "packages."
    ),
    benign="Debug output and diagnostics tools sometimes dump the environment locally.",
)
CREDENTIAL_FILES = Rule(
    id="NET005",
    title="Reads files where credentials are stored",
    category=Category.NETWORK,
    severity=Severity.MEDIUM,
    confidence=Confidence.MEDIUM,
    rationale=(
        "SSH keys, cloud credential files, package-registry tokens, browser password stores and "
        "crypto wallets are what info-stealing code looks for."
    ),
    benign="Deployment and developer tools legitimately read their own configuration files.",
)

_URL_RE = re.compile(r"\b(?:https?|wss?|ftp)://([A-Za-z0-9.\-]+|\[[0-9A-Fa-f:]+\])(?::\d+)?")
_IP_RE = re.compile(r"(?:(?<=://)|(?<=[\"'@=]))((?:\d{1,3}\.){3}\d{1,3})(?=[:/\"'\s]|$)")
_EXFIL_RE = re.compile(
    r"(?i)(?<![\w-])(?:[\w-]+\.)*(?:webhook\.site|requestbin\.(?:com|net)|pipedream\.net|"
    r"(?:[\w-]+\.)?m\.pipedream\.net|beeceptor\.com|requestcatcher\.com|hookbin\.com|"
    r"pastebin\.com|paste\.ee|hastebin\.com|ghostbin\.\w+|rentry\.co|transfer\.sh|file\.io|"
    r"0x0\.st|temp\.sh|bashupload\.com|ngrok(?:-free)?\.(?:io|app|dev)|serveo\.net|loca\.lt|"
    r"localtunnel\.me|trycloudflare\.com|interact\.sh|oast\.(?:fun|live|me|online|pro|site)|"
    r"burpcollaborator\.net|canarytokens\.com|dnslog\.cn|ceye\.io)\b"
    r"|discord(?:app)?\.com/api/webhooks/|api\.telegram\.org/bot"
)
_SENDS_DATA_RE = re.compile(
    r"\b(?:requests|httpx|session|client|axios|http|got|superagent)\.(?:post|put|patch)\s*\("
    r"|\bfetch\s*\([^)]*method\s*:\s*[\"'](?:POST|PUT)|\bsendBeacon\s*\(|\bnew\s+WebSocket\s*\("
    r"|\burlopen\s*\([^)]*data\s*=|\bcurl\b.*\s(?:-d|--data(?:-\w+)?|-F|--form|-T|--upload-file)\b"
    r"|\bInvoke-(?:WebRequest|RestMethod)\b.*-Method\s+Post"
)
_ALLOWED_HOSTS = (
    "localhost", "example.com", "example.org", "example.net", "github.com", "githubusercontent.com",
    "github.io", "githubassets.com", "gitlab.com", "python.org", "pypi.org", "pythonhosted.org",
    "npmjs.org", "npmjs.com", "yarnpkg.com", "w3.org", "json-schema.org", "schemastore.org",
    "apache.org", "opensource.org", "mozilla.org", "creativecommons.org", "gnu.org", "readthedocs.io",
    "readthedocs.org", "shields.io", "wikipedia.org", "microsoft.com", "docker.com", "docker.io",
    "golang.org", "go.dev", "rust-lang.org", "crates.io", "rubygems.org", "packagist.org",
    "mvnrepository.com", "maven.org", "nodejs.org", "ietf.org", "rfc-editor.org", "semver.org",
    "xmlsoap.org", "openxmlformats.org", "purl.org", "schema.org",
)  # fmt: skip
_TEST_HOSTS = (".test", ".example", ".invalid", ".localhost", ".local", ".internal")


def _allowed(host: str) -> bool:
    host = host.lower().rstrip(".")
    return host.endswith(_TEST_HOSTS) or any(host == h or host.endswith("." + h) for h in _ALLOWED_HOSTS)


def _public_ip(text: str) -> str | None:
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return None
    return text if address.is_global else None


def _code_or_ci(path: str) -> bool:
    return is_runnable(path) and not is_lockfile(path)


class NetworkDetector(Detector):
    """One finding per destination per file, so a URL repeated 50 times is one item to review."""

    name = "network"
    rules = (HARDCODED_IP, EXFIL_ENDPOINT, NEW_ENDPOINT)

    def scan(self, diff: Diff) -> Iterator[Finding]:
        for change in diff.files:
            if change.binary or change.kind is ChangeKind.DELETED or is_vendored(change.path):
                continue
            yield from self._file(change)

    def _file(self, change: FileChange) -> Iterator[Finding]:
        path = change.path
        doc, code, test = is_doc(path), _code_or_ci(path), is_test(path)
        seen: set[tuple[str, str]] = set()
        new_hosts: dict[str, DiffLine] = {}
        for line in change.added:
            text = line.text
            match = _EXFIL_RE.search(text)
            if match and ("exfil", match[0].lower()) not in seen and not is_lockfile(path):
                seen.add(("exfil", match[0].lower()))
                yield EXFIL_ENDPOINT.finding(
                    path, line.number, text, f"Refers to {match[0]}.",
                    severity=Severity.LOW if doc else (Severity.MEDIUM if test else None),
                    confidence=Confidence.LOW if doc or test else None,
                )  # fmt: skip
            if not code or is_comment(text):
                continue
            for ip in filter(None, map(_public_ip, (m[1] for m in _IP_RE.finditer(text)))):
                if ("ip", ip) not in seen:
                    seen.add(("ip", ip))
                    yield HARDCODED_IP.finding(
                        path, line.number, text, f"Connects to {ip} directly.",
                        confidence=Confidence.LOW if test else None,
                    )  # fmt: skip
            if test:
                continue
            for match in _URL_RE.finditer(text):
                host = match[1].lower()
                if "." not in host or _allowed(host) or _public_ip(host) or _EXFIL_RE.search(host):
                    continue
                # Keep the line that sends data if there is one: it is the one worth reading.
                if host not in new_hosts or (
                    _SENDS_DATA_RE.search(text) and not _SENDS_DATA_RE.search(new_hosts[host].text)
                ):
                    new_hosts[host] = line
        for host, line in new_hosts.items():
            sends = bool(_SENDS_DATA_RE.search(line.text))
            yield NEW_ENDPOINT.finding(
                path, line.number, line.text,
                f"Sends data to {host}." if sends else f"Talks to {host}.",
                severity=Severity.MEDIUM if sends else None,
                confidence=Confidence.MEDIUM if sends else None,
            )  # fmt: skip


class DataCollectionDetector(PatternDetector):
    name = "data-collection"
    patterns = (
        Pattern(ENV_HARVEST, re.compile(
            r"\b(?:json\.dumps|str|repr|base64\.\w+encode)\s*\(\s*(?:dict\s*\(\s*)?os\.environ\b"
            r"|\bJSON\.stringify\s*\(\s*process\.env\s*[,)]|\bObject\.entries\s*\(\s*process\.env\s*\)"
            r"|\bprintenv\s*(?:\||>|$)|(?<![\w-])env\s*\|\s*(?:curl|nc|base64|gzip)\b"
            r"|\bEnvironment\.GetEnvironmentVariables\s*\(\s*\)|\bos\.Environ\s*\(\s*\)"
            r"|\bENV\.to_h\b|\bgetenv\s*\(\s*\)"
        ), "Serialises the whole environment.", where=is_runnable),
        Pattern(CREDENTIAL_FILES, re.compile(
            r"(?:~|\$HOME|homedir\(\)|expanduser\([^)]*)[^\"'\n]{0,20}/?\.(?:ssh|aws|azure|kube|docker|gnupg)\b"
            r"|\.ssh/id_\w+|\.aws/credentials|\.docker/config\.json|\.kube/config|\.config/gcloud"
            r"|\.git-credentials|(?<![\w.])\.netrc\b|(?<![\w.])\.pypirc\b|/etc/shadow\b"
            r"|Login Data|Local State|\bCookies\.sqlite\b|logins\.json|key4\.db|wallet\.dat"
            r"|Exodus|Electrum|MetaMask|Library/Keychains"
        ), "Refers to a file that stores credentials.", where=is_source),
    )  # fmt: skip
