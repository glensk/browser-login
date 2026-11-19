"""tp#1900 B4: `open` on a real disposable Chromium keeps a URL's #fragment.

`open` creates its tab on the owner marker (`about:blank#owned-…`) and then
navigates it; a fragment URL (a pairing code, an OAuth token) must arrive
untouched and the navigation must verifiably leave the marker. One open per
case against a local `http.server` that answers instantly (never the shared
browser: free port, temp profile, temp cache dir).
"""

from __future__ import annotations

# pylint: disable=protected-access,import-error,wrong-import-position
# pylint: disable=redefined-outer-name
import http.server
import json
import re
import sys
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from chromium_page import REPO, disposable_chromium, load_script
from pw_bound import bound_test, chrome_mark

sys.path.insert(0, str(REPO))

browser = load_script("bin/browser.py", "openfragchromium_browser")

CDP_START_S = 60  # the disposable Chromium's DevTools port answers (load-tolerant)
EVAL_BUDGET_S = 20.0
CHROME = chrome_mark()

# Deliberately no history.replaceState: the real hub's /pair rewrites its own
# hash on mount, which would hide the fragment this test reads back.
PAIR_HTML = b"<!doctype html><title>pair</title><p>pair</p>"


@pytest.fixture(autouse=True)
def _playwright_bound(request: pytest.FixtureRequest) -> Iterator[None]:
    """The main-thread bound of every `launches_chrome` test here."""
    yield from bound_test(request, 180)


class _Handler(http.server.BaseHTTPRequestHandler):
    """`/pair` → a static page; anything else → 404."""

    def do_GET(self) -> None:  # pylint: disable=invalid-name
        """Answer instantly."""
        ok = self.path.split("?")[0] == "/pair"
        self.send_response(200 if ok else 404)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(PAIR_HTML) if ok else 0))
        self.end_headers()
        if ok:
            self.wfile.write(PAIR_HTML)

    def log_message(self, *args: Any) -> None:  # pylint: disable=arguments-differ
        """Quiet."""


@pytest.fixture
def chromium_and_server(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[tuple[int, int]]:
    """A throwaway headless Chromium on a free port plus a local server;
    yields (cdp port, server port). Both are stopped in a `finally`."""
    files = {
        "CACHE_DIR": "",
        "LIFECYCLE_FILE": ".browser-lifecycle.json",
        "CLIENTS_DIR": "clients",
        "REGISTRY_GATE": "clients/.registry.lock",
        "INTERACTION_LOCK": "interaction.lock",
        "MAINTENANCE_FILE": "maintenance.json",
        "MAINTENANCE_LOCK": ".maintenance.lock",
    }
    for name, rel in files.items():
        monkeypatch.setattr(browser, name, tmp_path / rel if rel else tmp_path)
    monkeypatch.setenv("CLAUDE_BROWSER_CACHE_DIR", str(tmp_path))
    monkeypatch.delenv("CLAUDE_BROWSER_LEASE_HELD", raising=False)
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        with disposable_chromium(
            tmp_path / "profile", CDP_START_S, browser.INSTANCE_PORTS.values()
        ) as (port, _version):
            yield port, int(httpd.server_address[1])
    finally:
        httpd.shutdown()
        httpd.server_close()


def _open_and_read_hash(port: int, url: str, capsys: pytest.CaptureFixture[str]) -> str:
    """`cmd_open(url)` → exit 0; return `location.hash` read with `eval -T`."""
    rc = browser.cmd_open(port, url, new=True)
    out = capsys.readouterr().out
    found = re.search(r"^target=(\S+)$", out, re.MULTILINE)
    assert found, out
    tid = found.group(1)
    try:
        assert rc == 0
        rc = browser._eval_target_raw(port, tid, "location.hash", EVAL_BUDGET_S)
        assert rc == 0
        return str(json.loads(capsys.readouterr().out.strip()))
    finally:
        browser._cdp_close_target(port, tid)


@pytest.mark.launches_chrome
@CHROME
@pytest.mark.parametrize(
    ("suffix", "want"),
    [("", ""), ("#code-123", "#code-123")],
    ids=["plain", "fragment"],
)
def test_open_keeps_fragment(
    chromium_and_server: tuple[int, int],
    capsys: pytest.CaptureFixture[str],
    suffix: str,
    want: str,
) -> None:
    """`open` on `/pair` and `/pair#code-123` exits 0 and the page sees the
    fragment exactly as requested (none for the plain URL)."""
    port, srv = chromium_and_server
    got = _open_and_read_hash(port, f"http://127.0.0.1:{srv}/pair{suffix}", capsys)
    assert got == want
