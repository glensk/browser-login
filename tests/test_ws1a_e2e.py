"""WS1a end-to-end: a candidate-sentinel login through the REAL broker runner
(its own headless Chromium, nothing stubbed) against a local fixture site.

Regression for review round 2 / N2: the logged-out half of the proof opened a
second ``sync_playwright()`` inside the runner's own, which raises inside the
running event loop — every candidate login failed as ``login_failed``.

The runner launches a disposable headless Chromium (not browser.py's shared
one) and closes it again; skipped when Playwright's Chromium is not installed.
"""
# pylint: disable=duplicate-code

from __future__ import annotations

# pylint: disable=missing-function-docstring,missing-class-docstring
# pylint: disable=import-error,wrong-import-position
import http.server
import json
import sys
import threading
from collections.abc import Sequence
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from broker import daemon, limiter, vault  # noqa: E402

USER = "alice"
PASSWORD = "pw-E2e-Candidate-1"
SESSION = "sess-e2e-candidate"


def _chromium_installed() -> bool:
    try:
        from playwright.sync_api import (  # pylint: disable=import-outside-toplevel
            sync_playwright,
        )

        with sync_playwright() as pw:
            return Path(pw.chromium.executable_path).exists()
    except Exception:  # pylint: disable=broad-exception-caught
        return False


class _App(http.server.BaseHTTPRequestHandler):
    """/home shows #welcome only with the session cookie, else -> /login."""

    def log_message(self, *args: Any) -> None:
        return

    def _send(
        self, code: int, body: str = "", headers: Sequence[tuple[str, str]] = ()
    ) -> None:
        self.send_response(code)
        for k, v in headers:
            self.send_header(k, v)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self) -> None:  # noqa: N802
        logged = f"session={SESSION}" in (self.headers.get("Cookie") or "")
        if self.path.startswith("/home"):
            if not logged:
                self._send(302, headers=[("Location", "/login")])
                return
            self._send(200, "<html><body><div id=welcome>hi</div></body></html>")
            return
        self._send(
            200,
            "<html><head><title>Login</title></head><body>"
            "<form method=post action=/login>"
            "<input type=text name=user><input type=password name=pw>"
            "<button type=submit>Go</button></form></body></html>",
        )

    def do_POST(self) -> None:  # noqa: N802
        n = int(self.headers.get("Content-Length") or 0)
        q = parse_qs(self.rfile.read(n).decode())
        if q.get("user") == [USER] and q.get("pw") == [PASSWORD]:
            cookie = f"session={SESSION}; Path=/; Max-Age=3600; HttpOnly"
            self._send(302, headers=[("Set-Cookie", cookie), ("Location", "/home")])
        else:
            self._send(302, headers=[("Location", "/login?err=1")])


@pytest.mark.launches_chrome
@pytest.mark.skipif(not _chromium_installed(), reason="Playwright Chromium missing")
def test_candidate_login_through_the_real_runner(tmp_path: Path) -> None:
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _App)
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    origin = f"http://127.0.0.1:{port}"
    item = {
        "id": "id-local",
        "name": "Local",
        "login": {"username": USER, "password": PASSWORD},
        "fields": [
            {"name": "agent_site", "value": "local"},
            {"name": "agent_fill_origins", "value": origin},
            {"name": "agent_check_url", "value": origin + "/home"},
            {"name": "agent_login_url", "value": origin + "/login"},
        ],
    }
    fixture = tmp_path / "items.json"
    fixture.write_text(json.dumps([item]))
    home = tmp_path / "home"
    lim = limiter.Limiter(home / "limiter.json", 0, 100, 100)
    brk = daemon.Broker(
        vault.FixtureVault(fixture, dev=True),
        lim,
        home,
        runner=daemon.PlaywrightRunner(home, dev=True),
    )
    try:
        resp = brk._login_request(  # pylint: disable=protected-access
            "local", {"candidate_sentinel": "#welcome"}
        )
    finally:
        httpd.shutdown()
    assert resp.get("ok"), resp
    assert resp["candidate_verified"] is True and resp["bundle"]["via"] == "login"
    attempts = json.loads((home / "limiter.json").read_text())["sites"]["local"]
    assert attempts["attempts"][-1][1] == "candidate"
    assert not list((home / "tmp").iterdir())  # the throwaway profile is gone
