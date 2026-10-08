"""One wedged tab must not hang `open`/`eval`/`doctor` (tp#693).

Playwright's ``connect_over_cdp`` attaches to every page target and waits until
each answers its initialisation commands; a tab whose renderer answers no CDP
command stalled the attach for Playwright's 180 s launch default. Pinned here:

* the REAL `_connect` (in a subprocess) gives up after
  ``CLAUDE_BROWSER_CONNECT_TIMEOUT_S`` and names the hung tab, origin only;
* `_probe_targets` classifies responsive / silent / event-spamming / stalled
  handshake / stalled close targets under one budget, caps its threads, and
  reports a failed ``/json/list`` as indeterminate;
* `close-hung` closes only the tab that failed three probes, skips one that
  recovered, and closes nothing when the prompt is declined;
* `status -p` marks only the silent tab;
* `eval -t` exits 1 at its deadline even while the attach is stuck;
* `_cdp_browser_close` gives up within its 5 s budget on a silent browser;
* `doctor` reports a wedged tab or a stalled attach as ❌, closes its probe
  tab by id, and still re-reads the desktop afterwards.

No real browser: a fake CDP endpoint (stdlib HTTP for ``/json/*``, a
``websockets`` server for the browser and page sockets, raw sockets for the
stalled-handshake / stalled-close cases) runs on ephemeral 127.0.0.1 ports, and
every coordination file lives under ``tmp_path``.

Run: uv run pytest -q tests/test_connect_hang.py     (from the repo root)
"""

from __future__ import annotations

# Tests reach into browser.py's private helpers on purpose (it is a script, not
# a package, so there is no public API).
# pylint: disable=protected-access,missing-function-docstring,import-error
# pylint: disable=redefined-outer-name,unused-argument,too-many-instance-attributes
# pylint: disable=missing-class-docstring,too-few-public-methods
# One module on purpose: every test here shares the FakeCdp endpoint above.
# pylint: disable=too-many-lines
import base64
import hashlib
import importlib.util
import json
import os
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from websockets.datastructures import Headers
from websockets.exceptions import ConnectionClosed
from websockets.http11 import Response
from websockets.sync.server import serve

_BROWSER_PY = Path(__file__).resolve().parent.parent / "bin" / "browser.py"


def _load_browser_module():
    """Import bin/browser.py as a module (it has no module-level playwright import)."""
    spec = importlib.util.spec_from_file_location("browser_hang_test", _BROWSER_PY)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["browser_hang_test"] = mod
    spec.loader.exec_module(mod)
    return mod


browser = _load_browser_module()

HUNG_URL = "https://albertha.cloudflareaccess.com/cdn-cgi/access/login?tok=LEAKTOKEN"
HUNG_TITLE = "Sign in ・ Cloudflare Access"


# --- the fake CDP endpoint ---------------------------------------------------


@dataclass
class FakeTarget:
    """One page target. ``mode``: ok | silent | spam | recover | raw-handshake |
    raw-close. ``recover`` stays silent for its first ``recover_after`` sockets."""

    tid: str
    url: str
    title: str
    mode: str = "ok"
    recover_after: int = 0
    connections: int = 0
    # What an answered ``Runtime.evaluate`` returns as ``result.value`` (and,
    # when set, the exception it throws instead); every command it received.
    eval_value: object = 1
    eval_exception: str | None = None
    received: list = field(default_factory=list)


def _ws_accept(key: str) -> str:
    magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
    return base64.b64encode(hashlib.sha1((key + magic).encode()).digest()).decode()


def _read_frame(conn: socket.socket) -> bytes:
    """One masked client frame's payload (enough for a single CDP command)."""

    def need(n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = conn.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("peer closed")
            buf += chunk
        return buf

    _b0, b1 = need(2)
    length = b1 & 0x7F
    if length == 126:
        length = int.from_bytes(need(2), "big")
    elif length == 127:
        length = int.from_bytes(need(8), "big")
    mask = need(4) if b1 & 0x80 else b"\0\0\0\0"
    data = need(length)
    return bytes(b ^ mask[i % 4] for i, b in enumerate(data))


def _text_frame(payload: bytes) -> bytes:
    if len(payload) < 126:
        return bytes([0x81, len(payload)]) + payload
    return bytes([0x81, 126]) + len(payload).to_bytes(2, "big") + payload


class FakeCdp:
    """HTTP ``/json/*`` + a websockets server + a raw-socket stall server."""

    def __init__(self) -> None:
        self.targets: dict[str, FakeTarget] = {}
        self.browser_mode = "ok"  # or "silent"
        self.list_fail = False
        # Runs on every /json and /json/list read, before the listing is built.
        self.list_hook = None
        self.list_reads = 0
        self.create_fail = False  # Target.createTarget answers with a CDP error
        self.created: list[str] = []
        self.browser_log: list[dict] = []
        self.closed: list[str] = []
        self._stop = threading.Event()
        self._sockets: list[socket.socket] = []
        self._lock = threading.Lock()
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_a) -> None:  # silence the stdlib logger
                return

            def do_GET(self) -> None:  # noqa: N802
                path = self.path.rstrip("/")
                if path == "/json/version":
                    # HEADLESS, like the real shared browser: a fake that looks
                    # headed makes every CLI's preflight "revert" it — i.e.
                    # launch a real Chrome on the fake's port (it leaked).
                    body: object = {
                        "Browser": "HeadlessChrome/151.0.0.0",
                        "Protocol-Version": "1.3",
                        "User-Agent": "Mozilla/5.0 HeadlessChrome/151.0.0.0",
                        "webSocketDebuggerUrl": f"{fake.ws_base}/devtools/browser/b",
                    }
                elif path in ("/json", "/json/list"):
                    with fake._lock:
                        fake.list_reads += 1
                    if fake.list_hook is not None:
                        fake.list_hook(fake)
                    if fake.list_fail:
                        self.send_error(500)
                        return
                    body = [fake.listing(t) for t in list(fake.targets.values())]
                else:
                    self.send_error(404)
                    return
                data = json.dumps(body).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.http = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.http.server_address[1]
        threading.Thread(target=self.http.serve_forever, daemon=True).start()
        self.ws = serve(
            self._ws_handler,
            "127.0.0.1",
            0,
            process_request=self._ws_process_request,
            compression=None,
            ping_interval=None,
        )
        self.ws_base = f"ws://127.0.0.1:{self.ws.socket.getsockname()[1]}"
        threading.Thread(target=self.ws.serve_forever, daemon=True).start()
        self.raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.raw.bind(("127.0.0.1", 0))
        self.raw.listen(64)
        self.raw_base = f"ws://127.0.0.1:{self.raw.getsockname()[1]}"
        threading.Thread(target=self._raw_accept, daemon=True).start()

    # -- target bookkeeping --
    def add(self, tid: str, url: str, title: str = "", mode: str = "ok", **kw):
        self.targets[tid] = FakeTarget(tid, url, title, mode, **kw)
        return self.targets[tid]

    def listing(self, t: FakeTarget) -> dict:
        base = self.raw_base if t.mode.startswith("raw-") else self.ws_base
        return {
            "id": t.tid,
            "type": "page",
            "url": t.url,
            "title": t.title,
            "webSocketDebuggerUrl": f"{base}/devtools/page/{t.tid}",
        }

    def close(self) -> None:
        self._stop.set()
        self.http.shutdown()
        self.ws.shutdown()
        with self._lock:
            for s in [self.raw, *self._sockets]:
                try:
                    s.close()
                except OSError:
                    pass

    # -- websockets server --
    def _ws_process_request(self, _conn, request):
        parts = request.path.strip("/").split("/")
        if parts[:2] == ["devtools", "page"] and parts[2] not in self.targets:
            return Response(404, "Not Found", Headers(), b"No such target id")
        return None

    def _ws_handler(self, conn) -> None:
        parts = conn.request.path.strip("/").split("/")
        if parts[:2] == ["devtools", "browser"]:
            self._browser_session(conn)
            return
        target = self.targets[parts[2]]
        with self._lock:
            target.connections += 1
            nth = target.connections
        mode = target.mode
        if mode == "recover":
            mode = "silent" if nth <= target.recover_after else "ok"
        try:
            if mode == "spam":
                threading.Thread(target=self._spam, args=(conn,), daemon=True).start()
            for raw in conn:
                msg = json.loads(raw)
                target.received.append(msg)
                if mode == "ok":
                    conn.send(
                        json.dumps({"id": msg["id"], "result": self._eval(target)})
                    )
        except ConnectionClosed:
            pass

    @staticmethod
    def _eval(target: FakeTarget) -> dict:
        if target.eval_exception is not None:
            return {
                "result": {"type": "object", "subtype": "error"},
                "exceptionDetails": {
                    "text": "Uncaught",
                    "exception": {"description": target.eval_exception},
                },
            }
        if target.eval_value is None:
            return {"result": {"type": "undefined"}}
        return {"result": {"type": "object", "value": target.eval_value}}

    def _spam(self, conn) -> None:
        try:
            while not self._stop.is_set():
                conn.send(json.dumps({"method": "Page.frameStartedNavigating"}))
                time.sleep(0.01)
        except ConnectionClosed:
            pass

    def _browser_session(self, conn) -> None:
        """Enough of the browser endpoint for Playwright to START attaching."""
        try:
            for raw in conn:
                msg = json.loads(raw)
                self.browser_log.append(msg)
                if self.browser_mode == "silent" or "sessionId" in msg:
                    continue  # page sessions never answer: the attach stalls
                method, params = msg.get("method"), msg.get("params") or {}
                result: dict = {}
                if method == "Browser.getVersion":
                    result = {
                        "protocolVersion": "1.3",
                        "product": "Chrome/151.0.0.0",
                        "revision": "@0",
                        "userAgent": "Mozilla/5.0 Chrome/151.0.0.0",
                        "jsVersion": "15.1",
                    }
                elif method == "Target.getTargetInfo":
                    result = {
                        "targetInfo": {
                            "targetId": "browser",
                            "type": "browser",
                            "title": "",
                            "url": "",
                            "attached": True,
                            "canAccessOpener": False,
                        }
                    }
                elif method == "Target.closeTarget":
                    tid = str(params.get("targetId"))
                    self.closed.append(tid)
                    self.targets.pop(tid, None)
                    result = {"success": True}
                elif method == "Target.createTarget":
                    if self.create_fail:
                        conn.send(
                            json.dumps(
                                {
                                    "id": msg["id"],
                                    "error": {"code": -32000, "message": "nope"},
                                }
                            )
                        )
                        continue
                    with self._lock:
                        tid = f"NEW{len(self.created):05d}"
                        self.created.append(tid)
                    self.add(tid, str(params.get("url") or "about:blank"))
                    result = {"targetId": tid}
                conn.send(json.dumps({"id": msg["id"], "result": result}))
                if method == "Target.setAutoAttach":
                    for n, t in enumerate(list(self.targets.values())):
                        conn.send(json.dumps(self._attached_event(t, n)))
        except ConnectionClosed:
            pass

    @staticmethod
    def _attached_event(t: FakeTarget, n: int) -> dict:
        return {
            "method": "Target.attachedToTarget",
            "params": {
                "sessionId": f"S{n}",
                "targetInfo": {
                    "targetId": t.tid,
                    "type": "page",
                    "title": t.title,
                    "url": t.url,
                    "attached": True,
                    "canAccessOpener": False,
                    "browserContextId": "CTX",
                },
                "waitingForDebugger": True,
            },
        }

    # -- raw stall server (handshake never completes / close never answered) --
    def _raw_accept(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self.raw.accept()
            except OSError:
                return
            with self._lock:
                self._sockets.append(conn)
            threading.Thread(
                target=self._raw_session, args=(conn,), daemon=True
            ).start()

    def _raw_session(self, conn: socket.socket) -> None:
        try:
            head = b""
            while b"\r\n\r\n" not in head:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                head += chunk
            lines = head.decode("latin-1").split("\r\n")
            tid = lines[0].split()[1].rstrip("/").split("/")[-1]
            target = self.targets.get(tid)
            if target is None or target.mode == "raw-handshake":
                self._stop.wait()  # never answer the upgrade
                return
            key = next(
                ln.split(":", 1)[1].strip()
                for ln in lines
                if ln.lower().startswith("sec-websocket-key:")
            )
            conn.sendall(
                (
                    "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                    "Connection: Upgrade\r\n"
                    f"Sec-WebSocket-Accept: {_ws_accept(key)}\r\n\r\n"
                ).encode()
            )
            msg = json.loads(_read_frame(conn))
            conn.sendall(
                _text_frame(json.dumps({"id": msg["id"], "result": {}}).encode())
            )
            while not self._stop.is_set():  # swallow the close frame, never reply
                if not conn.recv(4096):
                    return
        except (OSError, ConnectionError, ValueError):
            return


@pytest.fixture
def fake():
    srv = FakeCdp()
    yield srv
    srv.close()


@pytest.fixture
def cache(tmp_path, monkeypatch):
    """Point every coordination file browser.py writes at tmp_path."""
    monkeypatch.delenv("CLAUDE_BROWSER_LEASE_HELD", raising=False)
    monkeypatch.setattr(browser, "CACHE_DIR", tmp_path)
    monkeypatch.setattr(browser, "CLIENTS_DIR", tmp_path / "clients")
    monkeypatch.setattr(browser, "REGISTRY_GATE", tmp_path / "clients" / ".lock")
    monkeypatch.setattr(browser, "INTERACTION_LOCK", tmp_path / "interaction.lock")
    monkeypatch.setattr(browser, "LIFECYCLE_FILE", tmp_path / "lifecycle.json")
    return tmp_path


def _run_cli(fake: FakeCdp, tmp_path: Path, *argv: str, env: dict, deadline: float):
    full_env = {
        **os.environ,
        "CLAUDE_BROWSER_CACHE_DIR": str(tmp_path),
        **env,
    }
    full_env.pop("CLAUDE_BROWSER_LEASE_HELD", None)
    t0 = time.monotonic()
    proc = subprocess.run(
        [sys.executable, str(_BROWSER_PY), "--cdp-port", str(fake.port), *argv],
        capture_output=True,
        text=True,
        env=full_env,
        timeout=deadline,
        check=False,
    )
    return proc, time.monotonic() - t0


# --- the real _connect -------------------------------------------------------


def test_real_connect_times_out_and_names_the_hung_tab_origin_only(fake, tmp_path):
    fake.add("AAAA0001", "https://example.com/", "Example", mode="ok")
    fake.add("EEE09E93FFFF", HUNG_URL, HUNG_TITLE, mode="silent")
    proc, took = _run_cli(
        fake,
        tmp_path,
        "open",
        "https://example.com",
        env={"CLAUDE_BROWSER_CONNECT_TIMEOUT_S": "2"},
        deadline=60,
    )
    # 2 s attach + the 6 s probe budget + interpreter/driver start-up slack.
    assert proc.returncode == 1, proc.stderr
    assert took < 2 + browser.PROBE_BUDGET_S + 12, took
    err = proc.stderr
    assert "within 2s" in err
    assert "https://albertha.cloudflareaccess.com" in err
    assert "[id EEE09E93]" in err
    assert "close-hung" in err
    assert "LEAKTOKEN" not in err and "/cdn-cgi" not in err
    assert "example.com" not in err  # the responsive tab is not named


def test_eval_watchdog_exits_at_its_deadline_while_the_attach_is_stuck(
    fake, tmp_path, cache
):
    fake.add("EEE09E93FFFF", HUNG_URL, HUNG_TITLE, mode="silent")
    proc, took = _run_cli(
        fake,
        tmp_path,
        "eval",
        "-t",
        "2",
        "1+1",
        env={"CLAUDE_BROWSER_CONNECT_TIMEOUT_S": "60"},
        deadline=40,
    )
    assert proc.returncode == 1
    assert "no result after 2s" in proc.stderr
    assert took < 2 + 10, took
    # os._exit skips atexit, but the registration's flock died with the process:
    # the listing reaps the file instead of reporting a live client.
    assert list((cache / "clients").glob("*.json")), "eval never registered"
    assert browser._registry_live_clients() == []
    assert not list((cache / "clients").glob("*.json"))


def test_eval_rejects_a_non_positive_timeout(tmp_path):
    proc = subprocess.run(
        [sys.executable, str(_BROWSER_PY), "eval", "-t", "0", "1"],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert proc.returncode == 2
    assert "must be > 0" in proc.stderr


def test_connect_timeout_env_parsing():
    parse = browser._connect_timeout_s
    assert parse(None) == 30.0
    assert parse("7.5") == 7.5
    for bad in ("0", "-3", "abc", "nan", ""):
        assert parse(bad) == 30.0, bad


# --- _probe_targets ----------------------------------------------------------


def test_probe_classifies_each_target_within_one_budget(fake):
    fake.add("OK000001", "https://ok.example/", "ok", mode="ok")
    fake.add("SILENT01", "https://silent.example/", "silent", mode="silent")
    fake.add("SPAM0001", "https://spam.example/", "spam", mode="spam")
    fake.add("HSHAKE01", "https://handshake.example/", "hs", mode="raw-handshake")
    fake.add("CLOSE001", "https://close.example/", "close", mode="raw-close")
    budget = 1.5
    t0 = time.monotonic()
    report = browser._probe_targets(fake.port, budget_s=budget)
    took = time.monotonic() - t0
    got = {t.target_id: t.outcome for t in report.targets}
    assert report.indeterminate is None
    assert got == {
        "OK000001": "responsive",
        "SILENT01": "unresponsive",
        "SPAM0001": "unresponsive",  # events never extend the deadline
        "HSHAKE01": "indeterminate",  # the socket never opened: cannot tell
        "CLOSE001": "responsive",  # replied; an unanswered close is not a hang
    }
    assert took < budget + 1.5, took


def test_probe_caps_threads_at_32_and_marks_the_rest_indeterminate(fake):
    for n in range(33):
        fake.add(f"T{n:07d}", f"https://t{n}.example/", str(n), mode="ok")
    report = browser._probe_targets(fake.port, budget_s=3.0)
    outcomes = [t.outcome for t in report.targets]
    assert outcomes.count("responsive") == 32
    assert outcomes.count("indeterminate") == 1
    assert "not probed" in report.with_outcome("indeterminate")[0].detail


def test_probe_is_indeterminate_when_the_target_list_fails(fake):
    fake.add("OK000001", "https://ok.example/", "ok")
    fake.list_fail = True
    report = browser._probe_targets(fake.port, budget_s=1.0)
    assert report.indeterminate
    assert report.targets == []


def test_probe_sends_only_runtime_evaluate_one(fake, monkeypatch):
    sent: list[tuple[str, dict | None]] = []
    real = browser._cdp_ws_call

    def spy(ws_url, method, params=None, budget_s=5.0):
        sent.append((method, params))
        return real(ws_url, method, params, budget_s)

    monkeypatch.setattr(browser, "_cdp_ws_call", spy)
    fake.add("OK000001", "https://ok.example/", "ok")
    fake.add("SILENT01", "https://silent.example/", "silent", mode="silent")
    browser._probe_targets(fake.port, budget_s=1.0)
    assert sent and all(m == ("Runtime.evaluate", {"expression": "1"}) for m in sent)


# --- close-hung --------------------------------------------------------------


def test_close_hung_yes_closes_only_the_silent_tab(fake, cache, monkeypatch, capsys):
    monkeypatch.setattr(browser, "PROBE_BUDGET_S", 1.0)
    fake.add("OK000001", "https://ok.example/", "ok")
    fake.add("SILENT01", HUNG_URL, HUNG_TITLE, mode="silent")
    rc = browser.cmd_close_hung(fake.port, assume_yes=True)
    out = capsys.readouterr().out
    assert rc == 0
    assert fake.closed == ["SILENT01"]
    assert "closed:" in out and "LEAKTOKEN" not in out


def test_close_hung_skips_a_tab_that_recovers_before_the_final_probe(
    fake, cache, monkeypatch, capsys
):
    monkeypatch.setattr(browser, "PROBE_BUDGET_S", 1.0)
    fake.add("RECOVER1", "https://flaky.example/", "flaky", "recover", recover_after=2)
    rc = browser.cmd_close_hung(fake.port, assume_yes=True)
    assert rc == 0
    assert not fake.closed
    assert "skipped (recovered)" in capsys.readouterr().out


class _TtyStdin:
    @staticmethod
    def isatty() -> bool:
        return True


def test_close_hung_declined_confirmation_closes_nothing(
    fake, cache, monkeypatch, capsys
):
    monkeypatch.setattr(browser, "PROBE_BUDGET_S", 1.0)
    monkeypatch.setattr(sys, "stdin", _TtyStdin())
    monkeypatch.setattr("builtins.input", lambda _prompt: "n")
    fake.add("SILENT01", HUNG_URL, HUNG_TITLE, mode="silent")
    rc = browser.cmd_close_hung(fake.port, assume_yes=False)
    assert rc == 1
    assert not fake.closed
    assert "Nothing closed" in capsys.readouterr().out


def test_close_hung_without_tty_and_without_yes_closes_nothing(
    fake, cache, monkeypatch
):
    monkeypatch.setattr(browser, "PROBE_BUDGET_S", 1.0)
    monkeypatch.setattr(sys, "stdin", type("S", (), {"isatty": lambda self: False})())
    fake.add("SILENT01", HUNG_URL, HUNG_TITLE, mode="silent")
    assert browser.cmd_close_hung(fake.port) == 1
    assert not fake.closed


# --- status -p ---------------------------------------------------------------


def test_status_probe_marks_only_the_silent_tab(fake, cache, monkeypatch, capsys):
    monkeypatch.setattr(browser, "PROBE_BUDGET_S", 1.0)
    monkeypatch.setattr(browser, "_lifecycle_problems", lambda _port: [])
    fake.add("OK000001", "https://ok.example/", "Fine")
    fake.add("SILENT01", HUNG_URL, HUNG_TITLE, mode="silent")
    rc = browser.cmd_status(fake.port, probe=True)
    out = capsys.readouterr().out
    assert rc == 0
    lines = {ln for ln in out.splitlines() if "→" in ln}
    fine = next(ln for ln in lines if "ok.example" in ln)
    hung = next(ln for ln in lines if "cloudflareaccess" in ln)
    assert "unresponsive" not in fine and "indeterminate" not in fine
    assert hung.endswith("⚠ unresponsive")
    assert "LEAKTOKEN" not in out


def test_status_probe_exits_1_when_the_list_is_unreadable(
    fake, cache, monkeypatch, capsys
):
    monkeypatch.setattr(browser, "_lifecycle_problems", lambda _port: [])
    fake.add("OK000001", "https://ok.example/", "Fine")
    fake.list_fail = True
    assert browser.cmd_status(fake.port, probe=True) == 1
    assert "probe indeterminate" in capsys.readouterr().out


# --- _cdp_browser_close ------------------------------------------------------


def test_browser_close_gives_up_within_its_budget_on_a_silent_browser(fake):
    fake.browser_mode = "silent"
    t0 = time.monotonic()
    assert browser._cdp_browser_close(fake.port) is False
    assert time.monotonic() - t0 < 5 + 1.5
    assert any(m.get("method") == "Browser.close" for m in fake.browser_log)


def test_browser_close_counts_a_reply_as_sent(fake):
    assert browser._cdp_browser_close(fake.port, budget_s=2.0) is True


# --- doctor ------------------------------------------------------------------


class _Windows:
    """`_window_snapshot` stand-in (no Quartz, no osascript); counts calls."""

    def __init__(self) -> None:
        self.calls = 0

    def __call__(self):
        self.calls += 1
        return {"frontmost": "iTerm2", "owners": ["iTerm2"]}


def _doctor_world(monkeypatch, cache) -> _Windows:
    monkeypatch.setattr(browser, "_lifecycle_problems", lambda _port: [])
    monkeypatch.setattr(browser, "_unknown_cdp_clients", lambda _port: [])
    windows = _Windows()
    monkeypatch.setattr(browser, "_window_snapshot", windows)
    monkeypatch.setattr(browser, "PROBE_BUDGET_S", 1.0)
    return windows


def test_doctor_names_a_wedged_tab_and_skips_the_playwright_probe(
    fake, cache, monkeypatch, capsys
):
    windows = _doctor_world(monkeypatch, cache)

    def no_connect(*_a, **_k):
        raise AssertionError("the Playwright probe must be skipped")

    monkeypatch.setattr(browser, "_connect", no_connect)
    fake.add("SILENT01", HUNG_URL, HUNG_TITLE, mode="silent")
    rc = browser.cmd_doctor(fake.port)
    out = capsys.readouterr().out
    assert rc == 1
    assert "❌ tab responsiveness" in out and "close-hung" in out
    assert windows.calls == 2  # windows-after still ran
    assert "LEAKTOKEN" not in out


class _FakeSession:
    def __init__(self, fake: FakeCdp) -> None:
        self.fake = fake

    def send(self, method, params=None):
        assert method == "Target.createTarget"
        self.fake.add("PROBE0001", browser.DOCTOR_PROBE_URL, "doctor-probe")
        return {"targetId": "PROBE0001"}


class _FakeBrowser:
    def __init__(self, fake: FakeCdp) -> None:
        self.fake = fake

    def new_browser_cdp_session(self):
        return _FakeSession(self.fake)

    def close(self) -> None:
        return


class _FakePw:
    def stop(self) -> None:
        return


def test_doctor_stalled_reattach_is_a_fail_line_and_the_probe_tab_is_closed_by_id(
    fake, cache, monkeypatch, capsys
):
    windows = _doctor_world(monkeypatch, cache)
    calls = []

    def connect(port, purpose=""):
        calls.append(port)
        if len(calls) == 1:
            return _FakePw(), _FakeBrowser(fake)
        raise browser.BrowserAttachTimeout("attach timed out\n   - some tab")

    monkeypatch.setattr(browser, "_connect", connect)
    fake.add("OK000001", "https://ok.example/", "Fine")
    rc = browser.cmd_doctor(fake.port)
    out = capsys.readouterr().out
    assert rc == 1
    assert len(calls) == 2
    assert "❌ attach: attach timed out" in out
    assert fake.closed == ["PROBE0001"]  # closed by id, over raw CDP
    assert windows.calls == 2


# --- open -N / eval -T / close (tp#786) ----------------------------------------
# A caller owns its tab by CDP target id: `open -N` creates it over raw CDP and
# prints the id, `eval -T` evaluates in exactly that target, `close -i` closes
# exactly that id — under the lease, re-checked right before the close, never
# the last page, inside one deadline.


def _hold_lease(cache: Path) -> int:
    import fcntl  # pylint: disable=import-outside-toplevel

    fd = os.open(str(cache / "interaction.lock"), os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX)
    return fd


def _lease_is_held(cache: Path) -> bool:
    import fcntl  # pylint: disable=import-outside-toplevel

    fd = os.open(str(cache / "interaction.lock"), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        return True
    finally:
        os.close(fd)
    return False


def test_close_id_leaves_same_url_foreign_tab_open(fake, cache, capsys):
    url = "https://app.smartsheet.com/sheets/X?tok=LEAKTOKEN"
    fake.add("FOREIGN1", url, "Sheet")
    fake.add("OURS0001", url, "Sheet")
    rc = browser.cmd_close(fake.port, None, ["OURS0001"])
    out = capsys.readouterr().out
    assert rc == 0
    assert fake.closed == ["OURS0001"]
    assert "FOREIGN1" in fake.targets
    assert "✓ closed:" in out and "[id OURS0001]" in out
    assert "LEAKTOKEN" not in out and "/sheets/" not in out


def test_close_id_missing_is_gone_and_rc0(fake, cache, capsys):
    fake.add("OTHER001", "https://ok.example/", "ok")
    assert browser.cmd_close(fake.port, None, ["NOPE0001"]) == 0
    assert "- gone: [id NOPE0001]" in capsys.readouterr().out
    assert not fake.closed


def test_close_url_mode_skips_tab_that_navigated_between_list_and_close(
    fake, cache, capsys
):
    fake.add("LITTER01", "https://app.example.com/login?next=x", "Login")
    fake.add("OTHER001", "https://ok.example/", "ok")

    def navigate_after_first_listing(f: FakeCdp) -> None:
        if f.list_reads >= 2:
            f.targets["LITTER01"].url = "https://app.example.com/home"

    fake.list_hook = navigate_after_first_listing
    rc = browser.cmd_close(fake.port, ["https://app.example.com/login"], None)
    assert rc == 0
    assert not fake.closed
    assert "skipped (changed)" in capsys.readouterr().out


def test_close_url_mode_matches_exact_base_url_only(fake, cache, capsys):
    fake.add("LITTER01", "https://app.example.com/login/?next=a#f", "Login")
    fake.add("LITTER02", "https://app.example.com/login?next=b", "Login")
    fake.add("KEEP0001", "https://app.example.com/login/other", "Other")
    rc = browser.cmd_close(fake.port, ["https://app.example.com/login"], None)
    assert rc == 0
    assert sorted(fake.closed) == ["LITTER01", "LITTER02"]
    assert "KEEP0001" in fake.targets
    assert "next=" not in capsys.readouterr().out


def test_close_url_mode_dry_run_closes_nothing(fake, cache, capsys):
    fake.add("LITTER01", "https://app.example.com/login?next=a", "Login")
    fake.add("OTHER001", "https://ok.example/", "ok")
    rc = browser.cmd_close(
        fake.port, ["https://app.example.com/login"], None, dry_run=True
    )
    out = capsys.readouterr().out
    assert rc == 0 and not fake.closed
    assert "would close:" in out and "[id LITTER01]" in out


def test_close_url_mode_refuses_non_http_url(fake, cache, capsys):
    fake.add("BLANK001", "about:blank")
    assert browser.cmd_close(fake.port, ["chrome://settings"], None) == 1
    assert not fake.closed
    assert "refusing" in capsys.readouterr().err


def test_close_creates_keepalive_when_list_changes_to_last_tab(fake, cache):
    fake.add("OURS0001", "https://ok.example/a", "ours")
    fake.add("OTHER001", "https://ok.example/b", "other")

    def drop_other_after_first_listing(f: FakeCdp) -> None:
        if f.list_reads >= 2:
            f.targets.pop("OTHER001", None)

    fake.list_hook = drop_other_after_first_listing
    rc = browser.cmd_close(fake.port, None, ["OURS0001"])
    assert rc == 0
    methods = [m.get("method") for m in fake.browser_log]
    assert "Target.createTarget" in methods
    assert methods.index("Target.createTarget") < methods.index("Target.closeTarget")
    assert fake.closed == ["OURS0001"]
    assert [t.url for t in fake.targets.values()] == ["about:blank"]


def test_close_keepalive_failure_keeps_tab_rc1(fake, cache, capsys):
    fake.add("OURS0001", "https://ok.example/a", "ours")
    fake.create_fail = True
    rc = browser.cmd_close(fake.port, None, ["OURS0001"])
    assert rc == 1
    assert not fake.closed and "OURS0001" in fake.targets
    assert "keep-alive" in capsys.readouterr().err


def test_close_lease_timeout_closes_nothing(fake, cache):
    fake.add("OURS0001", "https://ok.example/a", "ours")
    fake.add("OTHER001", "https://ok.example/b", "other")
    fd = _hold_lease(cache)
    try:
        t0 = time.monotonic()
        with pytest.raises(SystemExit) as exc:
            browser.cmd_close(fake.port, None, ["OURS0001"], wait_s=0.5)
        assert time.monotonic() - t0 < 3
    finally:
        os.close(fd)
    assert "holds the lease" in str(exc.value.code)
    assert not fake.closed
    assert browser._registry_live_clients() == []  # released in the finally


def test_close_deadline_bounds_silent_browser(fake, cache, capsys):
    fake.browser_mode = "silent"
    fake.add("OURS0001", "https://ok.example/a", "ours")
    fake.add("OTHER001", "https://ok.example/b", "other")
    t0 = time.monotonic()
    rc = browser.cmd_close(fake.port, None, ["OURS0001"], deadline_s=1.0)
    took = time.monotonic() - t0
    assert rc == 1
    assert took < 2.5, took
    assert "❌ failed" in capsys.readouterr().err


def test_close_works_while_another_tab_is_silent(fake, cache):
    fake.add("SILENT01", HUNG_URL, HUNG_TITLE, mode="silent")
    fake.add("OURS0001", "https://ok.example/a", "ours")
    t0 = time.monotonic()
    assert browser.cmd_close(fake.port, None, ["OURS0001"]) == 0
    assert time.monotonic() - t0 < 3
    assert fake.closed == ["OURS0001"]


def test_close_unreadable_list_closes_nothing(fake, cache, capsys):
    fake.add("OURS0001", "https://ok.example/a", "ours")
    fake.add("OTHER001", "https://ok.example/b", "other")
    fake.list_fail = True
    assert browser.cmd_close(fake.port, None, ["OURS0001"]) == 1
    assert not fake.closed
    assert "closed nothing" in capsys.readouterr().err


def test_close_unreadable_relist_closes_nothing(fake, cache, capsys):
    fake.add("OURS0001", "https://ok.example/a", "ours")
    fake.add("OTHER001", "https://ok.example/b", "other")

    def fail_after_first_listing(f: FakeCdp) -> None:
        f.list_fail = f.list_reads >= 2

    fake.list_hook = fail_after_first_listing
    assert browser.cmd_close(fake.port, None, ["OURS0001"]) == 1
    assert not fake.closed
    assert "tab list unreadable" in capsys.readouterr().err


def test_close_registers_and_releases(fake, cache):
    fake.add("OURS0001", "https://ok.example/a", "ours")
    fake.add("OTHER001", "https://ok.example/b", "other")
    seen: list[tuple[int, bool]] = []

    def snapshot(f: FakeCdp) -> None:
        seen.append((len(browser._registry_live_clients()), _lease_is_held(cache)))

    fake.list_hook = snapshot
    assert browser.cmd_close(fake.port, None, ["OURS0001"]) == 0
    assert seen and all(s == (1, True) for s in seen), seen
    assert browser._registry_live_clients() == []
    assert not _lease_is_held(cache)


def test_close_browser_down_is_rc0(cache, capsys):
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        dead = s.getsockname()[1]
    assert browser.cmd_close(dead, None, ["OURS0001"]) == 0
    assert "down" in capsys.readouterr().out


def test_open_new_twice_gives_distinct_targets(fake, cache, capsys):
    fake.add("EXIST001", "https://ok.example/", "ok")
    url = "https://app.example.com/sheets/X"
    rcs: list[int] = []
    threads = [
        threading.Thread(
            target=lambda: rcs.append(browser.cmd_open(fake.port, url, new=True))
        )
        for _ in range(2)
    ]
    for th in threads:
        th.start()
    for th in threads:
        th.join(timeout=20)
    out = capsys.readouterr().out
    ids = [ln.split("=", 1)[1] for ln in out.splitlines() if ln.startswith("target=")]
    assert rcs == [0, 0]
    assert len(ids) == 2 and len(set(ids)) == 2
    assert set(ids) == set(fake.created)
    creates = [m for m in fake.browser_log if m.get("method") == "Target.createTarget"]
    assert all(m["params"] == {"url": url, "background": True} for m in creates)
    assert "EXIST001" in fake.targets  # never reused, never navigated


def test_open_new_create_failure_rc1(fake, cache, capsys):
    fake.add("EXIST001", "https://ok.example/", "ok")
    fake.create_fail = True
    assert browser.cmd_open(fake.port, "https://x.example/", new=True) == 1
    assert "target=" not in capsys.readouterr().out


def test_eval_target_hits_named_target(fake, cache, capsys):
    fake.add("TAB00001", "https://a.example/", "a").eval_value = "from-A"
    fake.add("TAB00002", "https://b.example/", "b").eval_value = {"k": "from-B"}
    rc = browser.cmd_eval(
        fake.port, "location.host", None, timeout_s=5, target="TAB00002"
    )
    out = capsys.readouterr().out
    assert rc == 0
    assert json.loads(out) == {"k": "from-B"}
    sent = fake.targets["TAB00002"].received
    assert [m["method"] for m in sent] == ["Runtime.evaluate"]
    assert sent[0]["params"] == {
        "expression": "(location.host)",
        "awaitPromise": True,
        "returnByValue": True,
    }
    assert not fake.targets["TAB00001"].received
    rc = browser.cmd_eval(fake.port, "1", None, timeout_s=5, target="UNKNOWN1")
    assert rc == 1
    assert "no tab with target id [id UNKNOWN1]" in capsys.readouterr().err


def test_eval_target_undefined_prints_null_and_exception_is_rc1(fake, cache, capsys):
    tab = fake.add("TAB00001", "https://a.example/", "a")
    tab.eval_value = None
    assert (
        browser.cmd_eval(fake.port, "void 0", None, timeout_s=5, target="TAB00001") == 0
    )
    assert capsys.readouterr().out.strip() == "null"
    tab.eval_exception = "ReferenceError: nope is not defined\n    at <anonymous>:1:1"
    assert (
        browser.cmd_eval(fake.port, "nope", None, timeout_s=5, target="TAB00001") == 1
    )
    err = capsys.readouterr().err
    assert "ReferenceError: nope is not defined" in err and "<anonymous>" not in err


def test_eval_target_times_out_on_silent_tab(fake, cache, monkeypatch, capsys):
    # The raw budget expires first; the watchdog (here: never) is the backstop.
    monkeypatch.setattr(browser, "_eval_watchdog_fire", lambda _t: None)
    fake.add("SILENT01", HUNG_URL, HUNG_TITLE, mode="silent")
    t0 = time.monotonic()
    assert browser.cmd_eval(fake.port, "1", None, timeout_s=1, target="SILENT01") == 1
    assert time.monotonic() - t0 < 2.5
    assert "no result after 1s" in capsys.readouterr().err


def test_cli_open_new_then_close_id(fake, tmp_path):
    fake.add("EXIST001", "https://ok.example/", "ok")
    proc, _took = _run_cli(
        fake, tmp_path, "open", "-N", "https://example.org/", env={}, deadline=60
    )
    assert proc.returncode == 0, proc.stderr
    ids = [ln[7:] for ln in proc.stdout.splitlines() if ln.startswith("target=")]
    assert len(ids) == 1 and ids[0] in fake.targets
    proc, _took = _run_cli(fake, tmp_path, "close", "-i", ids[0], env={}, deadline=60)
    assert proc.returncode == 0, proc.stderr
    assert "✓ closed:" in proc.stdout
    assert fake.closed == ids
    assert "EXIST001" in fake.targets


def test_cli_close_rejects_ids_and_urls_together(tmp_path):
    proc = subprocess.run(
        [sys.executable, str(_BROWSER_PY), "close", "https://a.example/", "-i", "T1"],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert proc.returncode == 2
    assert "not both" in proc.stderr
