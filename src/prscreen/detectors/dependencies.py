"""Changes to what the project installs and where it installs it from."""

from __future__ import annotations

import re
from collections.abc import Iterator
from urllib.parse import urlsplit

from prscreen.detectors import Detector
from prscreen.detectors._common import basename, is_comment, is_lockfile, is_vendored
from prscreen.diff import ChangeKind, Diff, DiffLine, FileChange
from prscreen.models import Category, Confidence, Finding, Rule, Severity

NEW_DEPENDENCY = Rule(
    id="DEP001",
    title="New dependency",
    category=Category.DEPENDENCIES,
    severity=Severity.LOW,
    confidence=Confidence.HIGH,
    rationale=(
        "Every new package is code from a new author that runs in the project, often with install "
        "scripts. Worth a quick check of who publishes it, how widely it is used and whether it is "
        "really needed."
    ),
    benign="Most new dependencies are ordinary and well known.",
)
TYPOSQUAT = Rule(
    id="DEP002",
    title="Package name one typo away from a popular package",
    category=Category.DEPENDENCIES,
    severity=Severity.MEDIUM,
    confidence=Confidence.MEDIUM,
    rationale=(
        "Attackers publish packages whose names differ from popular ones by a single character "
        "(crossenv for cross-env, reqeusts for requests) and wait for someone to mistype."
    ),
    benign="Some legitimate packages have similar names; check the publisher and download counts.",
)
NON_REGISTRY_SOURCE = Rule(
    id="DEP003",
    title="Dependency source outside the default registry",
    category=Category.DEPENDENCIES,
    severity=Severity.MEDIUM,
    confidence=Confidence.HIGH,
    rationale=(
        "Installing from a git URL, a tarball, a local path or an extra package index bypasses the "
        "registry's ownership and version history. An extra index also enables dependency "
        "confusion: a public package with an internal name wins the version race."
    ),
    benign="Private registries, forks with an unreleased fix, and monorepo workspaces.",
)
LOCKFILE_ONLY = Rule(
    id="DEP004",
    title="Lockfile changed without its manifest",
    category=Category.DEPENDENCIES,
    severity=Severity.LOW,
    confidence=Confidence.MEDIUM,
    rationale=(
        "Lockfiles are long, generated and rarely read, so they are a convenient place to swap a "
        "package version or download URL without any visible change to the declared dependencies."
    ),
    benign="Automated updates (Dependabot, Renovate, npm audit fix) legitimately touch only the lockfile.",
)
LOCKFILE_SOURCE = Rule(
    id="DEP005",
    title="Lockfile resolves a package from an unusual host",
    category=Category.DEPENDENCIES,
    severity=Severity.MEDIUM,
    confidence=Confidence.HIGH,
    rationale=(
        "The lockfile says to download a package from a host other than the public registry. "
        "Editing resolved URLs is a known way to slip a different tarball past review."
    ),
    benign="A company mirror or private registry configured for the project.",
)

_DEFAULT_REGISTRY_HOSTS = frozenset({
    "registry.npmjs.org", "registry.yarnpkg.com", "npm.pkg.github.com", "pypi.org",
    "files.pythonhosted.org", "proxy.golang.org", "sum.golang.org", "crates.io", "static.crates.io",
    "index.crates.io", "rubygems.org", "repo.packagist.org", "codeload.github.com",
})  # fmt: skip

# Short lists of the most downloaded packages, enough to catch the classic one-typo squats.
POPULAR_PYPI = frozenset(
    """
requests urllib3 numpy pandas boto3 botocore setuptools six python-dateutil pyyaml certifi idna
charset-normalizer typing-extensions cryptography wheel packaging attrs jinja2 markupsafe click flask
django fastapi pydantic sqlalchemy pytest scipy matplotlib pillow protobuf grpcio awscli s3transfer
jmespath rsa pyasn1 psutil pytz tzdata werkzeug colorama tqdm beautifulsoup4 lxml scikit-learn
tensorflow torch keras openai anthropic httpx aiohttp redis psycopg2 psycopg2-binary pymongo celery
gunicorn uvicorn selenium paramiko pyjwt oauthlib docker kubernetes pyopenssl toml tomli filelock
virtualenv platformdirs regex simplejson ujson orjson rich black ruff mypy coverage isort flake8
pylint poetry transformers langchain websocket-client websockets bcrypt passlib pycryptodome nltk
opencv-python xgboost streamlit playwright sentry-sdk pyparsing decorator pygments babel
""".split()
)
POPULAR_NPM = frozenset(
    """
lodash react react-dom express axios chalk commander debug moment request async uuid vue webpack
typescript eslint prettier jest mocha chai next nuxt jquery underscore bluebird yargs inquirer dotenv
cross-env rimraf mkdirp glob minimist semver colors body-parser cors mongoose mongodb mysql mysql2 pg
redis socket.io ws jsonwebtoken bcrypt bcryptjs passport nodemon ts-node rxjs redux react-redux
react-router react-router-dom styled-components tailwindcss postcss autoprefixer sass vite rollup
esbuild electron puppeteer cheerio node-fetch got superagent form-data qs classnames prop-types
date-fns dayjs zod yup graphql sequelize typeorm prisma knex winston morgan helmet multer sharp
event-stream ua-parser-js coa rc nanoid immer svelte angular core-js tslib babel-loader eslint-plugin-react
""".split()
)

_NPM_DEP_RE = re.compile(
    r'^\s*"(@?[A-Za-z0-9][\w.\-]*(?:/[\w.\-]+)?)"\s*:\s*"((?:[\^~<>=*]|\d|npm:|git|github:|gitlab:|bitbucket:'
    r'|https?:|file:|link:|workspace:|latest|next)[^"]*)"'
)
_NPM_NON_DEP_KEYS = frozenset({"version", "node", "npm", "yarn", "pnpm", "engines", "packageManager"})
_REQ_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._\-]*)\s*(?:\[[^\]]*\])?\s*(?:[<>=!~;@ ]|$)")
_TOML_ARRAY_DEP_RE = re.compile(
    r'^\s*"([A-Za-z0-9][A-Za-z0-9._\-]*)\s*(?:\[[^\]]*\])?\s*(?:[<>=!~;@ ][^"]*)?"\s*,?\s*$'
)
_TOML_TABLE_DEP_RE = re.compile(r'^\s*([A-Za-z0-9][A-Za-z0-9._\-]*)\s*=\s*(?:"[\^~<>=*]?\d|"\*"|\{)')
_TOML_NON_DEP_KEYS = frozenset(
    "version python name edition rust-version requires-python line-length target-version "
    "python_version build-backend".split()
)
_GO_DEP_RE = re.compile(r"^\s*(?:require\s+)?([a-z0-9.\-]+\.[a-z]{2,}(?:/[\w.\-~]+)+)\s+v\d")
_GEM_RE = re.compile(r"""^\s*gem\s+["']([\w.\-]+)["']""")

_SOURCE_PATTERNS: tuple[tuple[re.Pattern[str], str, Severity], ...] = (
    (re.compile(r"--extra-index-url\b|\bextra[-_]index[-_]url\s*="), "Adds an extra package index.",
     Severity.HIGH),
    (re.compile(r"--index-url\b|(?<![\w-])index[-_]url\s*=|^\s*\[\[tool\.(?:uv\.index|poetry\.source|pdm\.source)\]\]"),
     "Changes the package index.", Severity.MEDIUM),
    (re.compile(r"""\bgit\+(?:https?|ssh|git|file)://|["']\s*:\s*["'](?:git(?:\+\w+)?://|git@|github:|gitlab:|bitbucket:)"""
                r"""|\s@\s*(?:https?|git\+|file):"""), "Installs straight from a git repository or URL.",
     Severity.MEDIUM),
    (re.compile(r"""https?://[^\s"']+\.(?:tgz|tar\.gz|zip|whl)\b|["']\s*:\s*["']file:"""),
     "Installs from a tarball or local path.", Severity.MEDIUM),
    (re.compile(r"^\s*(?:@[\w-]+:)?registry\s*=|\bnpmRegistryServer\s*:|^\s*replace\s+\S+.*=>"),
     "Redirects where packages come from.", Severity.MEDIUM),
    (re.compile(r"""^\s*source\s+["'](?!https://rubygems\.org)|\bgem\s+.*\b(?:git|github|path)\s*:"""),
     "Uses a gem source other than rubygems.org.", Severity.MEDIUM),
)  # fmt: skip

_LOCK_URL_RE = re.compile(
    r"""(?:"resolved"\s*:\s*"|^\s*resolved\s+"|\btarball\s*:\s*|\burl\s*=\s*"|\bregistry\s*=\s*"|\bsource\s*=\s*")"""
    r"""((?:https?|git\+\w+|git)://[^"\s,}]+)"""
)
_MANIFEST_FOR_LOCK = {
    "package-lock.json": ("package.json",),
    "npm-shrinkwrap.json": ("package.json",),
    "yarn.lock": ("package.json",),
    "pnpm-lock.yaml": ("package.json",),
    "bun.lock": ("package.json",),
    "poetry.lock": ("pyproject.toml",),
    "uv.lock": ("pyproject.toml",),
    "pdm.lock": ("pyproject.toml",),
    "pipfile.lock": ("pipfile",),
    "cargo.lock": ("cargo.toml",),
    "go.sum": ("go.mod",),
    "gemfile.lock": ("gemfile", "gems.rb"),
    "composer.lock": ("composer.json",),
}


def _ecosystem(path: str) -> str | None:
    name = basename(path).lower()
    if name in ("package.json", "composer.json"):
        return "npm" if name == "package.json" else "composer"
    if (name.startswith("requirements") and name.endswith((".txt", ".in"))) or name in ("constraints.txt",):
        return "requirements"
    if name in ("pyproject.toml", "pipfile"):
        return "pyproject"
    if name == "cargo.toml":
        return "cargo"
    if name == "go.mod":
        return "go"
    if name in ("gemfile", "gems.rb"):
        return "gem"
    return None


def _dependency_name(ecosystem: str, text: str) -> str | None:
    if is_comment(text) or text.lstrip().startswith("-"):
        return None
    match: re.Match[str] | None
    if ecosystem in ("npm", "composer"):
        match = _NPM_DEP_RE.match(text)
        return match[1] if match and match[1] not in _NPM_NON_DEP_KEYS and match[1] != "php" else None
    if ecosystem == "requirements":
        match = _REQ_RE.match(text)
        return match[1] if match else None
    if ecosystem in ("pyproject", "cargo"):
        match = _TOML_ARRAY_DEP_RE.match(text) if ecosystem == "pyproject" else None
        if match:
            return match[1]
        match = _TOML_TABLE_DEP_RE.match(text)
        return match[1] if match and match[1].lower() not in _TOML_NON_DEP_KEYS else None
    if ecosystem == "go":
        match = _GO_DEP_RE.match(text)
        return match[1] if match else None
    match = _GEM_RE.match(text)
    return match[1] if match else None


def _normalize(name: str, ecosystem: str) -> str:
    name = name.lower()
    return re.sub(r"[-_.]+", "-", name) if ecosystem in ("requirements", "pyproject") else name


def _distance_at_most_one(a: str, b: str) -> bool:
    """True when ``a`` and ``b`` differ by one insertion, deletion, substitution or swap."""
    if a == b or abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        diffs = [i for i in range(len(a)) if a[i] != b[i]]
        if len(diffs) == 1:
            return True
        return (
            len(diffs) == 2
            and diffs[1] == diffs[0] + 1
            and a[diffs[0]] == b[diffs[1]]
            and a[diffs[1]] == b[diffs[0]]
        )
    short, long = (a, b) if len(a) < len(b) else (b, a)
    return any(long[:i] + long[i + 1 :] == short for i in range(len(long)))


def lookalike_of(name: str, ecosystem: str) -> str | None:
    popular = POPULAR_NPM if ecosystem in ("npm", "composer") else POPULAR_PYPI
    normalized = _normalize(name, ecosystem)
    if ecosystem in ("go", "gem", "cargo") or len(normalized) < 5 or normalized in popular:
        return None
    return next((p for p in sorted(popular) if len(p) >= 5 and _distance_at_most_one(normalized, p)), None)


class DependencyDetector(Detector):
    name = "dependencies"
    rules = (NEW_DEPENDENCY, TYPOSQUAT, NON_REGISTRY_SOURCE, LOCKFILE_ONLY, LOCKFILE_SOURCE)

    def scan(self, diff: Diff) -> Iterator[Finding]:
        changed = {change.path.lower() for change in diff.files}
        for change in diff.files:
            if change.binary or change.kind is ChangeKind.DELETED or is_vendored(change.path):
                continue
            if is_lockfile(change.path):
                yield from self._lockfile(change, changed)
                continue
            for line in change.added:
                yield from self._sources(change, line)
            if ecosystem := _ecosystem(change.path):
                yield from self._manifest(change, ecosystem)

    def _sources(self, change: FileChange, line: DiffLine) -> Iterator[Finding]:
        name = basename(change.path).lower()
        relevant = _ecosystem(change.path) or name in (
            ".npmrc",
            ".yarnrc",
            ".yarnrc.yml",
            "pip.conf",
            "pip.ini",
            "uv.toml",
        )
        if not relevant or is_comment(line.text):
            return
        for pattern, detail, severity in _SOURCE_PATTERNS:
            if pattern.search(line.text):
                yield NON_REGISTRY_SOURCE.finding(
                    change.path, line.number, line.text, detail, severity=severity
                )
                return

    def _manifest(self, change: FileChange, ecosystem: str) -> Iterator[Finding]:
        before = {
            _normalize(n, ecosystem)
            for line in change.removed
            if (n := _dependency_name(ecosystem, line.text))
        }
        for line in change.added:
            dep = _dependency_name(ecosystem, line.text)
            if dep is None or _normalize(dep, ecosystem) in before:
                continue  # a version bump, not a new package
            yield NEW_DEPENDENCY.finding(change.path, line.number, line.text, f"Adds '{dep}'.")
            if popular := lookalike_of(dep, ecosystem):
                yield TYPOSQUAT.finding(
                    change.path, line.number, line.text,
                    f"'{dep}' is one character away from the popular package '{popular}'.",
                )  # fmt: skip

    def _lockfile(self, change: FileChange, changed: set[str]) -> Iterator[Finding]:
        lock = basename(change.path).lower()
        folder = change.path.lower()[: -len(lock)]
        if change.kind is ChangeKind.MODIFIED and not any(
            folder + manifest in changed for manifest in _MANIFEST_FOR_LOCK.get(lock, ())
        ):
            yield LOCKFILE_ONLY.finding(
                change.path, None, change.path,
                f"{len(change.added)} lines added and {len(change.removed)} removed, no manifest change.",
            )  # fmt: skip
        hosts: set[str] = set()
        for line in change.added:
            for match in _LOCK_URL_RE.finditer(line.text):
                url = match[1]
                host = (urlsplit(url.replace("git+", "", 1)).hostname or "").lower()
                if url.startswith("git") or host not in _DEFAULT_REGISTRY_HOSTS:
                    if host in hosts:
                        continue
                    hosts.add(host)
                    yield LOCKFILE_SOURCE.finding(
                        change.path, line.number, line.text, f"Downloads from {host or url}."
                    )
