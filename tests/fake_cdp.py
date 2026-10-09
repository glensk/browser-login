"""A fake Chrome DevTools Protocol (CDP) endpoint for tests — no real browser.

Stdlib HTTP for ``/json/*``, a ``websockets`` server for the browser and page
sockets, and raw sockets for the stalled-handshake / stalled-close cases, all
on ephemeral 127.0.0.1 ports. Shared by test_connect_hang.py (tp#693) and
test_login_timeout.py (tp#843).
"""

from __future__ import annotations

# pylint: disable=missing-function-docstring,too-many-instance-attributes
# pylint: disable=missing-class-docstring,too-few-public-methods
import base64
import hashlib
import json
import socket
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from websockets.datastructures import Headers
from websockets.exceptions import ConnectionClosed
from websockets.http11 import Response
from websockets.sync.server import serve


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
    # CDP target type (page | iframe | service_worker …) and the target that
    # opened it (``openerId`` in ``Target.getTargets``; tp#845 popups).
    type: str = "page"
    opener: str | None = None


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
        self.create_stall = False  # Target.createTarget is never answered
        # Target.createTarget creates the target but its reply never arrives.
        self.create_lose_reply = False
        self.get_targets_fail = False  # Target.getTargets answers with an error
        self.create_params: list[dict] = []
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
            "type": t.type,
            "url": t.url,
            "title": t.title,
            "webSocketDebuggerUrl": f"{base}/devtools/page/{t.tid}",
        }

    @staticmethod
    def info(t: FakeTarget) -> dict:
        """One ``Target.getTargets`` entry."""
        out = {
            "targetId": t.tid,
            "type": t.type,
            "title": t.title,
            "url": t.url,
            "attached": False,
            "canAccessOpener": False,
            "browserContextId": "CTX",
        }
        if t.opener:
            out["openerId"] = t.opener
        return out

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
                elif method in self.TARGET_CALLS:
                    outcome, result = self._target_call(str(method), params)
                    if outcome == "none":
                        continue  # no reply at all
                    if outcome == "error":
                        conn.send(
                            json.dumps(
                                {
                                    "id": msg["id"],
                                    "error": {"code": -32000, "message": "nope"},
                                }
                            )
                        )
                        continue
                conn.send(json.dumps({"id": msg["id"], "result": result}))
                if method == "Target.setAutoAttach":
                    for n, t in enumerate(list(self.targets.values())):
                        conn.send(json.dumps(self._attached_event(t, n)))
        except ConnectionClosed:
            pass

    TARGET_CALLS = ("Target.closeTarget", "Target.getTargets", "Target.createTarget")

    def _target_call(self, method: str, params: dict) -> tuple[str, dict]:
        """``("ok", result)``, ``("error", {})`` or ``("none", {})`` (no reply)."""
        if method == "Target.closeTarget":
            tid = str(params.get("targetId"))
            self.closed.append(tid)
            self.targets.pop(tid, None)
            return "ok", {"success": True}
        if method == "Target.getTargets":
            if self.get_targets_fail:
                return "error", {}
            return "ok", {"targetInfos": [self.info(t) for t in self.targets.values()]}
        return self._create_target(params)

    def _create_target(self, params: dict) -> tuple[str, dict]:
        """``Target.createTarget`` (see `_target_call`)."""
        self.create_params.append(dict(params))
        if self.create_stall:
            return "none", {}  # no reply, no target
        if self.create_fail:
            return "error", {}
        with self._lock:
            tid = f"NEW{len(self.created):05d}"
            self.created.append(tid)
        self.add(tid, str(params.get("url") or "about:blank"))
        if self.create_lose_reply:
            return "none", {}  # the target exists, the reply never comes
        return "ok", {"targetId": tid}

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
