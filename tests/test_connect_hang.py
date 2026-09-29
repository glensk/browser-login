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
from dataclasses import dataclass
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
                    body: object = {
                        "Browser": "Chrome/151.0.0.0",
                        "Protocol-Version": "1.3",
                        "User-Agent": "Mozilla/5.0 Chrome/151.0.0.0",
                        "webSocketDebuggerUrl": f"{fake.ws_base}/devtools/browser/b",
                    }
                elif path in ("/json", "/json/list"):
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
                if mode == "ok":
                    conn.send(
                        json.dumps(
                            {"id": msg["id"], "result": {"result": {"value": 1}}}
                        )
                    )
        except ConnectionClosed:
            pass

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
