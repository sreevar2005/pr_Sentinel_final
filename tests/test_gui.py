"""The local GUI: what it shows, and who can reach it."""

import http.client
import json
import re
import subprocess
import threading
from pathlib import Path

import pytest

from prscreen.gui.samples import SAMPLES
from prscreen.gui.server import MAX_BODY_BYTES, TOKEN_HEADER, GuiServer

STATIC = Path(__file__).parent.parent / "src" / "prscreen" / "gui" / "static"


@pytest.fixture(scope="module")
def server():
    srv = GuiServer(port=0, token="test-token")
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield srv
    srv.shutdown()
    srv.server_close()


def request(server, method, path, body=None, token="test-token", host=None, headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", server.port, timeout=30)
    all_headers = {"Host": host or f"127.0.0.1:{server.port}", **(headers or {})}
    if token is not None:
        all_headers[TOKEN_HEADER] = token
    payload = json.dumps(body).encode() if isinstance(body, dict) else body
    if payload is not None:
        all_headers["Content-Type"] = "application/json"
    conn.request(method, path, body=payload, headers=all_headers)
    response = conn.getresponse()
    data = response.read()
    conn.close()
    return response, data


def scan(server, **body):
    response, data = request(server, "POST", "/api/scan", body)
    return response.status, json.loads(data)


def test_page_and_assets_are_served_with_a_strict_policy(server):
    for path, kind in (("/", "text/html"), ("/app.js", "text/javascript"), ("/app.css", "text/css")):
        response, data = request(server, "GET", path, token=None)
        assert response.status == 200 and data
        assert response.getheader("Content-Type").startswith(kind)
        csp = response.getheader("Content-Security-Policy")
        assert "script-src 'self'" in csp and "unsafe-inline" not in csp.split("style-src")[0]
        assert response.getheader("X-Content-Type-Options") == "nosniff"


@pytest.mark.parametrize("token", [None, "", "wrong-token"])
def test_api_needs_this_runs_token(server, token):
    response, _ = request(server, "GET", "/api/rules", token=token)
    assert response.status == 403
    response, _ = request(server, "POST", "/api/scan", {"mode": "diff", "diff": "x"}, token=token)
    assert response.status == 403


def test_other_hosts_are_refused(server):
    # A DNS-rebinding page would reach us under its own host name.
    response, _ = request(server, "GET", "/api/rules", host=f"evil.example:{server.port}")
    assert response.status == 421
    response, _ = request(server, "GET", "/", host="evil.example", token=None)
    assert response.status == 421


def test_cross_origin_preflight_is_never_approved(server):
    response, _ = request(
        server, "OPTIONS", "/api/scan", token=None, headers={"Origin": "https://evil.example"}
    )
    assert response.status == 403
    assert response.getheader("Access-Control-Allow-Origin") is None


def test_server_listens_on_loopback_only(server):
    assert server.server_address[0] == "127.0.0.1"


def test_rules_endpoint(server):
    response, data = request(server, "GET", "/api/rules")
    rules = json.loads(data)["rules"]
    assert response.status == 200
    assert {"OBF001", "CFG001", "AI001"} <= {r["id"] for r in rules}
    assert all(r["rationale"] and r["benign"] for r in rules)


def test_every_example_triggers_the_rules_it_claims(server):
    response, data = request(server, "GET", "/api/samples")
    samples = json.loads(data)["samples"]
    assert response.status == 200 and len(samples) == len(SAMPLES)
    for sample in samples:
        status, body = scan(server, mode="diff", diff=sample["diff"])
        assert status == 200, sample["title"]
        found = {f["rule_id"] for f in body["result"]["findings"]}
        if sample["expect"]:
            assert set(sample["expect"]) <= found, sample["title"]
        else:
            assert found == set(), f"{sample['title']} should stay quiet"


def test_every_example_is_a_real_case_with_sources():
    assert any(not s["expect"] for s in SAMPLES), "keep one real pull request that stays quiet"
    for sample in SAMPLES:
        assert re.fullmatch(r"(19|20)\d\d", sample["year"]), sample["title"]
        assert sample["summary"] and sample["recreation"], sample["title"]
        assert sample["sources"], f"{sample['title']} needs at least one source"
        for source in sample["sources"]:
            assert source["name"] and source["url"].startswith("https://"), source


def test_scan_returns_findings_markdown_and_respects_min_severity(server):
    diff = "--- a/requirements.txt\n+++ b/requirements.txt\n@@ -0,0 +1,2 @@\n+flask==3.0\n+reqeusts==2.0\n"
    status, body = scan(server, mode="diff", diff=diff, min_severity="medium")
    assert status == 200
    assert [f["rule_id"] for f in body["result"]["findings"]] == ["DEP002"]
    assert body["markdown"].startswith("## prscreen report")


def test_scan_from_a_git_repository(server, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    for args in (
        ["init", "-q", "-b", "main"],
        ["config", "user.email", "t@example.invalid"],
        ["config", "user.name", "t"],
    ):
        subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)
    (repo / "a.py").write_text("x = 1\n")
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-qm", "base"], cwd=repo, check=True)
    (repo / "a.py").write_text("x = 1\nrequests.get(u, verify=False)\n")
    subprocess.run(["git", "commit", "-qam", "change"], cwd=repo, check=True)
    status, body = scan(server, mode="git", repo=str(repo), range="HEAD~1...HEAD")
    assert status == 200
    assert [f["rule_id"] for f in body["result"]["findings"]] == ["CFG001"]


@pytest.mark.parametrize(
    ("body", "message"),
    [
        ({"mode": "diff", "diff": "   "}, "Paste a diff first"),
        ({"mode": "nope"}, "mode must be"),
        ({"mode": "diff", "diff": "@@ -1 +1 @@\n+x\n"}, "does not look like a unified diff"),
        ({"mode": "git", "repo": "Z:/definitely/missing", "range": "main...HEAD"}, "Folder not found"),
        ({"mode": "git", "repo": ".", "range": "--output=/tmp/x"}, "not a revision or range"),
    ],
)
def test_bad_requests_get_a_readable_error(server, body, message):
    status, reply = scan(server, **body)
    assert status == 400 and message in reply["error"]


def test_non_json_and_oversized_bodies(server):
    response, _ = request(server, "POST", "/api/scan", b"not json")
    assert response.status == 400
    conn = http.client.HTTPConnection("127.0.0.1", server.port, timeout=10)
    conn.putrequest("POST", "/api/scan", skip_host=True)
    conn.putheader("Host", f"127.0.0.1:{server.port}")
    conn.putheader(TOKEN_HEADER, "test-token")
    conn.putheader("Content-Length", str(MAX_BODY_BYTES + 1))
    conn.endheaders()
    assert conn.getresponse().status == 413
    conn.close()


def test_hostile_text_comes_back_as_data(server):
    diff = '--- a/x.html\n+++ b/x.html\n@@ -0,0 +1 @@\n+<img src=x onerror="alert(1)"> @octocat\n'
    status, body = scan(server, mode="diff", diff=diff)
    assert status == 200
    assert isinstance(body["result"]["findings"], list)


def test_page_script_never_inserts_html():
    # Findings contain text from the pull request; the page must only ever set it as text.
    script = (STATIC / "app.js").read_text(encoding="utf-8")
    for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"):
        assert sink not in script, sink
    html = (STATIC / "index.html").read_text(encoding="utf-8")
    assert not re.search(r"<script(?![^>]*\bsrc=)", html), "no inline scripts"
    assert "http://" not in html.replace("http://127.0.0.1", "") and "https://" not in html


def test_code_is_shown_without_ligatures():
    # Fonts such as Cascadia Code draw "!=" as one symbol; a reviewer must see the real characters.
    assert "font-variant-ligatures: none" in (STATIC / "app.css").read_text(encoding="utf-8")


def test_branches_endpoint_lists_branches_and_picks_main(server, tmp_path):
    repo = tmp_path / "branches"
    repo.mkdir()
    for args in (
        ["init", "-q", "-b", "main"],
        ["config", "user.email", "t@example.invalid"],
        ["config", "user.name", "t"],
    ):
        subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)
    (repo / "a.txt").write_text("a\n")
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-qm", "base"], cwd=repo, check=True)
    subprocess.run(["git", "branch", "incident/demo"], cwd=repo, check=True)
    response, data = request(server, "POST", "/api/branches", {"repo": str(repo)})
    body = json.loads(data)
    assert response.status == 200
    assert body == {"branches": ["incident/demo", "main"], "base": "main"}


@pytest.mark.parametrize(
    ("repo", "message"),
    [("", "Enter the repository folder"), ("Z:/definitely/missing", "Folder not found")],
)
def test_branches_endpoint_errors(server, repo, message):
    response, data = request(server, "POST", "/api/branches", {"repo": repo})
    assert response.status == 400 and message in json.loads(data)["error"]


def test_branches_endpoint_rejects_a_folder_that_is_not_a_repository(server, tmp_path):
    response, data = request(server, "POST", "/api/branches", {"repo": str(tmp_path)})
    assert response.status == 400 and "Not a git repository" in json.loads(data)["error"]
