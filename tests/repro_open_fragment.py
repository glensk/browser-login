#!/usr/bin/env python3
"""tp#1900 B1: does `open -N` fail to navigate a fresh tab to a URL with a #fragment?

Runs `browser.py`'s own `_open_create_target` + `_await_target_load` against a
DISPOSABLE headless Chromium (free port, temp profile, temp
``CLAUDE_BROWSER_CACHE_DIR``; never the shared 9222/9223 browser) and a local
``http.server`` whose ``/pair`` writes ``location.hash`` into the title.

Two orders, each on its own fresh browser + server so the first contact with
the origin is separated from the fragment:

- ``plain-first``: ``/pair`` then ``/pair#code-123``
- ``fragment-first``: ``/pair#code-123`` then ``/pair``

Each order ends with one H2 probe: a marker tab created by hand, the
``Page.navigate`` to the fragment URL sent only AFTER ``/json/list`` shows the
marker committed. One run per case, no loops.

Per case it records the raw ``Page.navigate`` reply (``loaderId``,
``errorText``), the listed URL over time, what ``_await_target_load`` returned,
whether ``Runtime.evaluate`` answers (and ``location.hash`` / title), and the
server's request log. The evidence is written as JSON to ``--out``.

Usage: uv run python tests/repro_open_fragment.py -o /tmp/evidence.json

The attended H3 run (only with Albert's go-ahead; still a disposable browser):
``-u https://decide.dom42.space/pair -u 'https://decide.dom42.space/pair#bogus'``
— the hub's PairView posts ``/api/pair`` only on the form's submit, so loading
``/pair#<bogus>`` sends no pairing request. Not a pytest file (no ``test_``
prefix): it launches Chromium twice and takes about a minute.
"""

from __future__ import annotations

# pylint: disable=protected-access,import-error,wrong-import-position
import argparse
import http.server
import json
import os
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from chromium_page import (  # noqa: E402
    chromium_executable,
    disposable_chromium,
    load_script,
)

PAIR_HTML = b"""<!doctype html><html><head><title>pending</title></head>
<body><p id=p>pair</p>
<script>document.title = 'hash=' + location.hash;</script>
</body></html>"""

FRAGMENT = "#code-123"
# Generous: the host may be loaded; a reply at all is what B1 asks.
EVAL_BUDGET_S = 20.0


class _Server:
    """A local `/pair` server on a free port that logs every request."""

    def __init__(self) -> None:
        self.log: list[dict[str, Any]] = []
        log = self.log
        t0 = time.monotonic()

        class Handler(http.server.BaseHTTPRequestHandler):
            """`/pair` → the hash-to-title page; anything else → 404."""

            def do_GET(self) -> None:  # pylint: disable=invalid-name
                """Serve `/pair`, log the request path (fragments never reach it)."""
                log.append({"t": round(time.monotonic() - t0, 3), "path": self.path})
                if self.path.split("?")[0] == "/pair":
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html")
                    self.send_header("Content-Length", str(len(PAIR_HTML)))
                    self.end_headers()
                    self.wfile.write(PAIR_HTML)
                else:
                    self.send_response(404)
                    self.send_header("Content-Length", "0")
                    self.end_headers()

            def log_message(self, *args: Any) -> None:  # pylint: disable=arguments-differ
                """Quiet: the request log is kept in `log`."""

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = int(self.httpd.server_address[1])
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def stop(self) -> None:
        """Shut the server down."""
        self.httpd.shutdown()
        self.httpd.server_close()


class _Poller:
    """Polls `/json/list` every 0.1 s and records URL changes of one target."""

    def __init__(self, browser: Any, port: int) -> None:
        self.browser = browser
        self.port = port
        self.tid: str | None = None
        self.seen: list[dict[str, Any]] = []
        self.t0 = time.monotonic()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        last: object = None
        while not self._stop.is_set():
            listing = self.browser._cdp_get(self.port, "/json/list", timeout=1.0)
            tid = self.tid
            if tid and isinstance(listing, list):
                url = next(
                    (
                        t.get("url")
                        for t in listing
                        if isinstance(t, dict) and t.get("id") == tid
                    ),
                    "<not listed>",
                )
                if url != last:
                    self.seen.append(
                        {"t": round(time.monotonic() - self.t0, 3), "url": url}
                    )
                    last = url
            self._stop.wait(0.1)

    def stop(self) -> None:
        """Stop polling."""
        self._stop.set()
        self._thread.join(timeout=3)


def _page_ws(browser: Any, port: int, tid: str) -> str | None:
    listing = browser._cdp_get(port, "/json/list")
    for t in listing if isinstance(listing, list) else []:
        if isinstance(t, dict) and t.get("id") == tid:
            ws = t.get("webSocketDebuggerUrl")
            return ws if isinstance(ws, str) else None
    return None


def _evaluate(browser: Any, port: int, tid: str) -> dict[str, Any]:
    ws = _page_ws(browser, port, tid)
    if not ws:
        return {"status": "no websocket"}
    t = time.monotonic()
    res = browser._cdp_ws_call(
        ws,
        "Runtime.evaluate",
        {
            "expression": "JSON.stringify([location.href, location.hash, document.title])",
            "returnByValue": True,
        },
        EVAL_BUDGET_S,
    )
    out: dict[str, Any] = {
        "status": res.status,
        "error": res.error,
        "ms": round((time.monotonic() - t) * 1000),
    }
    value = ((res.result or {}).get("result") or {}).get("value")
    if isinstance(value, str):
        href, hsh, title = json.loads(value)
        out.update(href=href, hash=hsh, title=title)
    return out


def _case_open(browser: Any, port: int, ws_url: str, url: str) -> dict[str, Any]:
    """`open -N`'s create + navigate + load wait, instrumented."""
    navs: list[dict[str, Any]] = []
    real_call = browser._cdp_ws_call

    def spy(ws: str, method: str, params: Any = None, budget_s: float = 5.0) -> Any:
        t = time.monotonic()
        res = real_call(ws, method, params, budget_s)
        if method == "Page.navigate":
            navs.append(
                {
                    "params": params,
                    "status": res.status,
                    "error": res.error,
                    "reply": res.result,
                    "ms": round((time.monotonic() - t) * 1000),
                }
            )
        return res

    poller = _Poller(browser, port)
    real_create = browser._cdp_create_background_target

    def create_spy(ws: str, marker_url: str, budget_s: float = 5.0) -> Any:
        tid = real_create(ws, marker_url, budget_s)
        poller.tid = tid
        poller.seen.append(
            {"t": round(time.monotonic() - poller.t0, 3), "created_on": marker_url}
        )
        return tid

    browser._cdp_ws_call = spy
    browser._cdp_create_background_target = create_spy
    t0 = time.monotonic()
    try:
        tid, why, _info = browser._open_create_target(port, ws_url, url)
        t_nav = time.monotonic() - t0
        info = browser._await_target_load(port, tid) if tid else {}
        t_load = time.monotonic() - t0
    finally:
        browser._cdp_ws_call = real_call
        browser._cdp_create_background_target = real_create
    time.sleep(1.0)  # let the poller see a late commit
    poller.stop()
    ev = _evaluate(browser, port, tid) if tid else {}
    if tid:
        browser._cdp_close_target(port, tid, ws_url=ws_url)
    return {
        "url": url,
        "tid8": (tid or "")[:8],
        "why": why,
        "create_navigate_s": round(t_nav, 3),
        "total_with_await_s": round(t_load, 3),
        "await_returned_url": info.get("url"),
        "page_navigate": navs,
        "listed_url_timeline": poller.seen,
        "evaluate": ev,
    }


def _case_late_navigate(
    browser: Any, port: int, ws_url: str, url: str
) -> dict[str, Any]:
    """H2: create on a marker, wait until `/json/list` shows it, then navigate."""
    marker_url = browser._owned_marker_url(browser._new_owned_marker())
    tid = browser._cdp_create_background_target(ws_url, marker_url, 15.0)
    if not tid:
        return {"url": url, "why": "create failed"}
    poller = _Poller(browser, port)
    poller.tid = tid
    deadline = time.monotonic() + 10
    listed = None
    while time.monotonic() < deadline:
        ws = _page_ws(browser, port, tid)
        listing = browser._cdp_get(port, "/json/list")
        listed = next(
            (
                t.get("url")
                for t in (listing if isinstance(listing, list) else [])
                if isinstance(t, dict) and t.get("id") == tid
            ),
            None,
        )
        if ws and listed == marker_url:
            break
        time.sleep(0.1)
    time.sleep(0.5)  # well after the marker committed
    ws = _page_ws(browser, port, tid) or ""
    t = time.monotonic()
    res = browser._cdp_ws_call(ws, "Page.navigate", {"url": url}, 10.0)
    nav = {
        "status": res.status,
        "error": res.error,
        "reply": res.result,
        "ms": round((time.monotonic() - t) * 1000),
    }
    info = browser._await_target_load(port, tid)
    time.sleep(1.0)
    poller.stop()
    ev = _evaluate(browser, port, tid)
    browser._cdp_close_target(port, tid, ws_url=ws_url)
    return {
        "url": url,
        "tid8": tid[:8],
        "marker_listed_before_navigate": listed == marker_url,
        "page_navigate": [nav],
        "await_returned_url": info.get("url"),
        "listed_url_timeline": poller.seen,
        "evaluate": ev,
    }


def _run_order(
    browser: Any, order: list[str], tmp: Path, urls: list[str] | None = None
) -> dict[str, Any]:
    """One fresh browser + one fresh server; the cases of `order` in sequence.

    With `urls` (the attended H3 run): those URLs in sequence instead, no
    local `/pair` cases and no H2 probe."""
    server = _Server()
    try:
        with disposable_chromium(
            tmp / "profile", 60, browser.INSTANCE_PORTS.values()
        ) as (port, version):
            ws_url = version["webSocketDebuggerUrl"]
            base = f"http://127.0.0.1:{server.port}/pair"
            if urls:
                cases = [_case_open(browser, port, ws_url, u) for u in urls]
            else:
                cases = [_case_open(browser, port, ws_url, base + s) for s in order]
                cases.append(
                    _case_late_navigate(browser, port, ws_url, base + FRAGMENT)
                )
            return {
                "browser": version.get("Browser"),
                "mode": browser._browser_mode(port),
                "cases": cases,
                "server_log": server.log,
            }
    finally:
        server.stop()


def main() -> int:
    """Run both orders; write the evidence JSON; print a one-line summary per case."""
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    ap.add_argument("-o", "--out", required=True, help="evidence JSON path")
    ap.add_argument(
        "-u",
        "--url",
        action="append",
        default=[],
        help="instead of the local cases: open this URL (repeatable, in order) "
        "on one fresh disposable browser — the attended H3 run",
    )
    args = ap.parse_args()
    root = Path(tempfile.mkdtemp(prefix="tp1900-b1-"))
    os.environ["CLAUDE_BROWSER_CACHE_DIR"] = str(root / "cache")
    os.environ.pop("CLAUDE_BROWSER_LEASE_HELD", None)
    (root / "cache").mkdir()
    browser = load_script("bin/browser.py", "tp1900_browser")
    if not chromium_executable():
        print("no Playwright Chromium", file=sys.stderr)
        return 2
    evidence = (
        {"urls": _run_order(browser, [], root / "u", args.url)}
        if args.url
        else {
            "plain-first": _run_order(browser, ["", FRAGMENT], root / "a"),
            "fragment-first": _run_order(browser, [FRAGMENT, ""], root / "b"),
        }
    )
    Path(args.out).write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    for order, run in evidence.items():
        for case in run["cases"]:
            nav = (case.get("page_navigate") or [{}])[0]
            reply = nav.get("reply") or {}
            if not nav:
                sent = "no-navigate"
            elif nav.get("status") != "ok":
                sent = "navigate-" + str(nav.get("status"))
            else:
                sent = "loaderId=" + ("yes" if reply.get("loaderId") else "NO")
            print(
                order,
                case["url"].rsplit("/", 1)[-1],
                sent,
                "why=" + repr(case.get("why") or ""),
                "errorText=" + repr(reply.get("errorText")),
                "await=" + repr(case.get("await_returned_url")),
                "eval=" + repr(case.get("evaluate", {}).get("hash")),
                case.get("evaluate", {}).get("title"),
            )
    return 0


if __name__ == "__main__":
    sys.exit(main())
