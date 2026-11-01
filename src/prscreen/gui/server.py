"""The local GUI server. Standard library only, like the rest of prscreen.

The page shows text taken from pull requests, so it is built as carefully as the other outputs:

* **Local only.** The server binds to 127.0.0.1 and rejects requests whose ``Host`` header is not
  this server, which stops DNS-rebinding attacks from other websites.
* **A token per run.** The API answers only requests that carry this run's random token in the
  ``X-Prscreen-Token`` header. A web page on another site cannot send that header to us without a
  CORS preflight, which this server never approves, so it cannot drive scans on your machine.
* **Text, never markup.** The page script inserts PR content with ``textContent`` only, and a
  strict Content-Security-Policy allows no inline or third-party scripts.
* **Bounded input.** Request bodies are capped at the same 20 MB as the CLI.
"""

from __future__ import annotations

import json
import secrets
import threading
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from pathlib import Path
from typing import Any

from prscreen import __version__
from prscreen.detectors import all_rules
from prscreen.diff import DiffParseError, parse_diff
from prscreen.engine import scan
from prscreen.formats import json_, markdown
from prscreen.gitdiff import GitError, git_diff, list_branches
from prscreen.gui.samples import SAMPLES
from prscreen.models import Severity

MAX_BODY_BYTES = 20 * 1024 * 1024
TOKEN_HEADER = "X-Prscreen-Token"  # noqa: S105 - a header name, not a secret
_STATIC = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/app.css": ("app.css", "text/css; charset=utf-8"),
}
_SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
        "img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}


class ApiError(Exception):
    def __init__(self, status: HTTPStatus, message: str) -> None:
        super().__init__(message)
        self.status = status


def rules_payload() -> list[dict[str, str]]:
    from prscreen.ai import AI_QUESTION

    return [
        {
            "id": r.id,
            "title": r.title,
            "category": r.category.value,
            "severity": r.severity.label,
            "confidence": r.confidence.label,
            "rationale": r.rationale,
            "benign": r.benign,
        }
        for r in [*all_rules(), AI_QUESTION]
    ]


def run_scan(request: dict[str, Any]) -> dict[str, Any]:
    mode = request.get("mode")
    if mode == "diff":
        text = request.get("diff")
        if not isinstance(text, str) or not text.strip():
            raise ApiError(HTTPStatus.BAD_REQUEST, "Paste a diff first.")
    elif mode == "git":
        repo, rev_range = request.get("repo"), request.get("range")
        if not isinstance(repo, str) or not isinstance(rev_range, str) or not rev_range.strip():
            raise ApiError(
                HTTPStatus.BAD_REQUEST, "Give a repository folder and a range such as main...HEAD."
            )
        if not Path(repo).expanduser().is_dir():
            raise ApiError(HTTPStatus.BAD_REQUEST, f"Folder not found: {repo}")
        try:
            text = git_diff(rev_range.strip(), Path(repo).expanduser()).decode("utf-8", errors="replace")
        except GitError as exc:
            raise ApiError(HTTPStatus.BAD_REQUEST, f"git diff failed: {exc}") from exc
    else:
        raise ApiError(HTTPStatus.BAD_REQUEST, "mode must be 'diff' or 'git'")
    try:
        result = scan(parse_diff(text))
    except DiffParseError as exc:
        raise ApiError(HTTPStatus.BAD_REQUEST, f"That does not look like a unified diff: {exc}") from exc
    level = request.get("min_severity", "low")
    floor = Severity[level.upper()] if level in ("low", "medium", "high") else Severity.LOW
    result.findings = [f for f in result.findings if f.severity >= floor]
    return {"result": json.loads(json_.render(result)), "markdown": markdown.render(result)}


def run_branches(request: dict[str, Any]) -> dict[str, Any]:
    repo = request.get("repo")
    if not isinstance(repo, str) or not repo.strip():
        raise ApiError(HTTPStatus.BAD_REQUEST, "Enter the repository folder first.")
    folder = Path(repo.strip()).expanduser()
    if not folder.is_dir():
        raise ApiError(HTTPStatus.BAD_REQUEST, f"Folder not found: {repo}")
    try:
        branches = list_branches(folder)
    except GitError as exc:
        raise ApiError(HTTPStatus.BAD_REQUEST, f"Not a git repository: {exc}") from exc
    if not branches:
        raise ApiError(HTTPStatus.BAD_REQUEST, "This repository has no branches yet.")
    base = next((b for b in ("main", "master", "origin/main", "origin/master") if b in branches), branches[0])
    return {"branches": branches, "base": base}


class Handler(BaseHTTPRequestHandler):
    server: GuiServer
    server_version = f"prscreen-gui/{__version__}"

    def log_message(self, format: str, *args: Any) -> None:
        pass  # keep the terminal quiet; the page shows errors

    def _host_ok(self) -> bool:
        return self.headers.get("Host", "") in self.server.allowed_hosts

    def _send(self, status: HTTPStatus, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for name, value in _SECURITY_HEADERS.items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: HTTPStatus, payload: Any) -> None:
        self._send(
            status, json.dumps(payload, ensure_ascii=False).encode(), "application/json; charset=utf-8"
        )

    def _check_api(self) -> None:
        if not secrets.compare_digest(self.headers.get(TOKEN_HEADER, ""), self.server.token):
            raise ApiError(
                HTTPStatus.FORBIDDEN, "Missing or wrong token. Open the link printed by prscreen gui."
            )

    def do_GET(self) -> None:
        if not self._host_ok():
            self._send(HTTPStatus.MISDIRECTED_REQUEST, b"Unknown host", "text/plain")
            return
        path = self.path.split("?", 1)[0]
        if path in _STATIC:
            name, content_type = _STATIC[path]
            body = resources.files("prscreen.gui").joinpath("static", name).read_bytes()
            self._send(HTTPStatus.OK, body, content_type)
            return
        try:
            self._check_api()
            if path == "/api/rules":
                self._json(HTTPStatus.OK, {"version": __version__, "rules": rules_payload()})
            elif path == "/api/samples":
                self._json(HTTPStatus.OK, {"samples": SAMPLES})
            else:
                raise ApiError(HTTPStatus.NOT_FOUND, "Not found")
        except ApiError as exc:
            self._json(exc.status, {"error": str(exc)})

    def do_POST(self) -> None:
        if not self._host_ok():
            self._send(HTTPStatus.MISDIRECTED_REQUEST, b"Unknown host", "text/plain")
            return
        try:
            self._check_api()
            if self.path not in ("/api/scan", "/api/branches"):
                raise ApiError(HTTPStatus.NOT_FOUND, "Not found")
            length = int(self.headers.get("Content-Length") or 0)
            if length > MAX_BODY_BYTES:
                raise ApiError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "The diff is larger than 20 MB.")
            try:
                request = json.loads(self.rfile.read(length) or b"{}")
            except json.JSONDecodeError as exc:
                raise ApiError(HTTPStatus.BAD_REQUEST, "Request body is not JSON.") from exc
            if not isinstance(request, dict):
                raise ApiError(HTTPStatus.BAD_REQUEST, "Request body must be a JSON object.")
            handler = run_scan if self.path == "/api/scan" else run_branches
            self._json(HTTPStatus.OK, handler(request))
        except ApiError as exc:
            self._json(exc.status, {"error": str(exc)})

    def do_OPTIONS(self) -> None:
        # Never approve a cross-origin preflight: other sites must not reach the API.
        self._send(HTTPStatus.FORBIDDEN, b"", "text/plain")


class GuiServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, port: int = 0, token: str | None = None) -> None:
        super().__init__(("127.0.0.1", port), Handler)
        self.token = token or secrets.token_urlsafe(24)
        self.port = self.server_address[1]
        self.allowed_hosts = {f"127.0.0.1:{self.port}", f"localhost:{self.port}"}

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/?token={self.token}"


def serve(port: int = 8765, open_browser: bool = True) -> int:
    try:
        server = GuiServer(port)
    except OSError as exc:
        print(f"prscreen gui: cannot listen on port {port} ({exc.strerror}); try --port 0")
        return 2
    print(f"prscreen GUI running at {server.url}", flush=True)
    print("Only this computer can reach it. Press Ctrl+C to stop.", flush=True)
    if open_browser:
        threading.Timer(0.5, webbrowser.open, args=(server.url,)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        server.server_close()
    return 0
