#!/usr/bin/env python3
"""Remote view of ONE owned headless tab: screencast frames out, input in.

Guided login, design "B" (PLAN_focus-free-browser.md, Phase 3). The shared
browser runs headless; when a human must log in, this relay attaches to exactly
one target of the CDP endpoint, streams ``Page.startScreencast`` frames to a
single loopback web page and forwards the human's input back:

* mouse and wheel  -> ``Input.dispatchMouseEvent`` (coordinates scaled from the
  canvas to the target's CSS viewport, taken from each frame's metadata)
* non-text keys    -> ``Input.dispatchKeyEvent`` (Tab, Enter, Backspace, arrows,
  Escape, modifiers, shortcuts) — NEVER with ``nativeVirtualKeyCode``: on macOS
  that field makes headless Chrome build a native key event, which stalled CfT
  153 for tens of seconds per key in the spike (the stock DevTools screencast
  sends it, which is why the stock frontend is unusable here)
* text             -> a focused hidden textarea; ``beforeinput`` insertText,
  ``paste`` and ``compositionend`` -> ``Input.insertText``;
  ``compositionstart/update`` -> ``Input.imeSetComposition``

Ownership: by default (``-u URL``) the relay CREATES the target itself
(``Target.createTarget``, background) and closes it on exit, so it can never
show a tab it does not own. Attaching to an existing id needs ``-t ID`` PLUS
``-A``: the caller proves ownership (e.g. an id it got from
``browser.py open -N``).

Only an allowlist of CDP methods ever leaves the relay (exactly the methods it
sends), Target.* only for the owned target id. The relay's own HTTP/WebSocket
endpoint lives on ``127.0.0.1:<random port>`` behind a random 32-byte path
token, rejects a wrong Host (DNS rebinding), a foreign Origin, a wrong token and
a second concurrent viewer. The token is one-shot: the first page load binds it
to that browser tab with an HttpOnly SameSite=Strict session cookie (required
for the WebSocket); after the viewer disconnects the tab has 10 s to reconnect,
then the token is burned (404) and the relay exits.

Spike status: popups (``window.open``/OAuth) are only REPORTED (a new target
whose openerId is the owned id, or ``opener=unknown`` when a page target without
openerId appears while the human is typing into ours); following them is the job
of the real target supervisor.

TODO(Phase 3 integration) — what this spike deliberately leaves out:
  * register the relay as a long-lived CDP client via ``browser.py register-exec``
    (it holds a browser-level CDP websocket; unregistered it would trip the
    "unregistered CDP peers" check of the maintenance transaction);
  * hold the interaction lease for the relay's whole lifetime;
  * require the maintenance owner token (refuse to start without it), write the
    owned target id(s) into the maintenance record, exit when its heartbeat is
    stale so the watchdog can close the owned targets;
  * target supervisor: follow owned popups, switch the viewer, handle popup
    close + opener redirect;
  * viewport sizing to the viewer window; JS dialogs and unsupported surfaces
    (WebAuthn, permission and client-cert prompts) -> named-reason exit to
    fallback A.
"""

from __future__ import annotations

import argparse
import asyncio
import hmac
import http.cookies
import json
import math
import secrets
import sys
import time
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# websockets is imported lazily (in the functions that need it) so `-h` and the
# unit tests of the pure helpers run on any Python; `main()` re-execs under the
# repo's .venv (pyvenv_bootstrap) once the arguments are parsed.
# pylint: disable=import-outside-toplevel
# Single-file tool that embeds its viewer page (HTML+JS) on purpose.
# pylint: disable=too-many-lines

SCRIPT = Path(__file__).resolve()
REPO_ROOT = SCRIPT.parent.parent
VIEWER_MODULES = ("websockets",)
EXIT_MISSING_DEP = 3

# Methods the relay may send to the CDP endpoint, whoever asked for them.
ALLOWED_METHODS = frozenset(
    {
        "Page.enable",
        "Inspector.enable",
        "Emulation.setFocusEmulationEnabled",
        "Page.startScreencast",
        "Page.stopScreencast",
        "Page.screencastFrameAck",
        "Input.dispatchMouseEvent",
        "Input.dispatchKeyEvent",
        "Input.insertText",
        "Input.imeSetComposition",
        "Target.setDiscoverTargets",
        "Target.createTarget",
        "Target.attachToTarget",
        "Target.closeTarget",
    }
)
# Target.* calls that name a target must name the owned one.
_TARGET_SCOPED = frozenset({"Target.attachToTarget", "Target.closeTarget"})

MOD_ALT, MOD_CTRL, MOD_META, MOD_SHIFT = 1, 2, 4, 8

# key -> (default code, windowsVirtualKeyCode) for keys that never produce text
# through the textarea path.
NAMED_KEYS: dict[str, tuple[str, int]] = {
    "Backspace": ("Backspace", 8),
    "Tab": ("Tab", 9),
    "Enter": ("Enter", 13),
    "Shift": ("ShiftLeft", 16),
    "Control": ("ControlLeft", 17),
    "Alt": ("AltLeft", 18),
    "Pause": ("Pause", 19),
    "CapsLock": ("CapsLock", 20),
    "Escape": ("Escape", 27),
    "PageUp": ("PageUp", 33),
    "PageDown": ("PageDown", 34),
    "End": ("End", 35),
    "Home": ("Home", 36),
    "ArrowLeft": ("ArrowLeft", 37),
    "ArrowUp": ("ArrowUp", 38),
    "ArrowRight": ("ArrowRight", 39),
    "ArrowDown": ("ArrowDown", 40),
    "Insert": ("Insert", 45),
    "Delete": ("Delete", 46),
    "Meta": ("MetaLeft", 91),
    **{f"F{i}": (f"F{i}", 111 + i) for i in range(1, 13)},
}

# Shortcuts headless Chrome only honours with an explicit editing command (macOS
# has no native key bindings in headless mode).
_MAC_COMMANDS: dict[tuple[str, int], list[str]] = {
    ("a", MOD_META): ["selectAll"],
    ("z", MOD_META): ["undo"],
    ("z", MOD_META | MOD_SHIFT): ["redo"],
    ("Backspace", MOD_ALT): ["deleteWordBackward"],
    ("Backspace", MOD_META): ["deleteToBeginningOfLine"],
}
# Clipboard shortcuts are never forwarded: paste arrives as text through the
# textarea's paste event, and copying OUT of the login tab is not offered.
_BLOCKED_SHORTCUTS = frozenset({"c", "v", "x"})

MAX_TEXT = 4096
MAX_COORD = 100_000.0
MOUSE_TYPES = frozenset({"mousePressed", "mouseReleased", "mouseMoved"})
MOUSE_BUTTONS = frozenset({"none", "left", "middle", "right", "back", "forward"})
RECONNECT_GRACE_S = 10.0
MAX_POPUPS = 20
# A page target without openerId that appears within this many seconds of the
# human's last input is reported as a possible popup (opener=unknown).
POPUP_FOCUS_WINDOW_S = 3.0


def osc8(url: str, text: str | None = None) -> str:
    """OSC 8 hyperlink (invisible where unsupported)."""
    return f"\x1b]8;;{url}\x1b\\{text or url}\x1b]8;;\x1b\\"


def method_allowed(method: str, params: dict[str, Any], owned_id: str) -> bool:
    """Final gate for every CDP command the relay sends."""
    if method not in ALLOWED_METHODS:
        return False
    if method == "Target.createTarget":
        return not owned_id  # only the one target the relay creates for itself
    if method in _TARGET_SCOPED:
        return bool(owned_id) and params.get("targetId") == owned_id
    return True


def ownership_error(
    url: str | None, target_id: str | None, assume_owned: bool
) -> str | None:
    """Why the requested target is not provably owned, or None when it is."""
    if url and target_id:
        return "use either -u/--url or -t/--target-id, not both"
    if url:
        if not url.startswith(("https://", "http://")):
            return "-u/--url must be an http(s) URL"
        return None
    if target_id:
        if not assume_owned:
            return (
                "-t/--target-id attaches to an EXISTING tab; pass -A/--assume-owned only "
                "when the caller owns it (e.g. an id from `browser.py open -N`), "
                "or use -u URL to let the relay create its own tab"
            )
        return None
    return "pass -u/--url URL (the relay creates and owns the tab) or -t ID -A"


def _cookie(headers: dict[str, str], name: str) -> str:
    raw = {k.lower(): v for k, v in headers.items()}.get("cookie", "")
    jar: http.cookies.SimpleCookie = http.cookies.SimpleCookie()
    try:
        jar.load(raw)
    except http.cookies.CookieError:
        return ""
    morsel = jar.get(name)
    return morsel.value if morsel is not None else ""


@dataclass
class ViewerAuth:
    """One-shot viewer credential: path token + session cookie bound on first load.

    ``fresh``  -> the first page GET binds a random session cookie (``bound``);
    ``bound``  -> page reloads and the WebSocket need that cookie;
    after the first viewer disconnects, the same tab has ``RECONNECT_GRACE_S``
    to reconnect, after which the token is burned for good.
    """

    port: int
    session: str = ""
    connected: bool = False
    burn_at: float | None = None

    @property
    def cookie_name(self) -> str:
        """Per-port cookie name (cookies are not isolated by port)."""
        return f"lv_{self.port}"

    def burned(self, now: float) -> bool:
        """True once the reconnect grace after the last disconnect has run out."""
        return self.burn_at is not None and now >= self.burn_at and not self.connected

    def _cookie_ok(self, headers: dict[str, str]) -> bool:
        given = _cookie(headers, self.cookie_name)
        return bool(self.session) and hmac.compare_digest(
            given.encode(), self.session.encode()
        )

    def page(self, headers: dict[str, str], now: float) -> tuple[int, str | None]:
        """HTTP status for a page GET, plus a Set-Cookie value on the binding load."""
        if self.burned(now):
            return 404, None
        if not self.session:
            self.session = secrets.token_urlsafe(32)
            return 200, self.session
        return (200, None) if self._cookie_ok(headers) else (404, None)

    def websocket(self, headers: dict[str, str], now: float) -> int:
        """HTTP status for a WebSocket upgrade (0 = accept)."""
        if self.burned(now):
            return 404
        if not self._cookie_ok(headers):
            return 403
        return 409 if self.connected else 0

    def on_connect(self) -> None:
        """A viewer socket was accepted: cancel any pending burn."""
        self.connected = True
        self.burn_at = None

    def on_disconnect(self, now: float) -> None:
        """The viewer left: start the reconnect grace."""
        self.connected = False
        self.burn_at = now + RECONNECT_GRACE_S


def token_ok(path: str, token: str) -> tuple[bool, str]:
    """Split ``/<token>/<rest>``; constant-time token check. Returns (ok, rest)."""
    parts = path.split("?", 1)[0].lstrip("/").split("/", 1)
    given = parts[0]
    rest = parts[1] if len(parts) > 1 else ""
    return hmac.compare_digest(given.encode(), token.encode()), rest


def origin_ok(headers: dict[str, str], port: int, websocket: bool) -> bool:
    """Host must be our own loopback authority; a WS Origin must be our origin.

    A top-level navigation carries no Origin, so for plain GETs an Origin is only
    checked when present; ``Sec-Fetch-Site`` (when present) must not be
    cross-site.
    """
    own = f"127.0.0.1:{port}"
    h = {k.lower(): v for k, v in headers.items()}
    if h.get("host") != own:
        return False
    origin = h.get("origin")
    if websocket:
        return origin == f"http://{own}"
    if origin is not None and origin != f"http://{own}":
        return False
    return h.get("sec-fetch-site", "none") in ("none", "same-origin")


def _num(v: Any, lo: float = -MAX_COORD, hi: float = MAX_COORD) -> float | None:
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return None
    try:
        f = float(v)
    except OverflowError:
        return None
    if not math.isfinite(f):
        return None
    return min(max(f, lo), hi)


def _mods(v: Any) -> int:
    return v & 15 if isinstance(v, int) and not isinstance(v, bool) else 0


def key_event_params(
    kind: str, key: str, code: str, modifiers: int
) -> dict[str, Any] | None:
    """CDP Input.dispatchKeyEvent params for a non-text key, or None to drop it."""
    if (
        kind not in ("down", "up")
        or not isinstance(key, str)
        or not isinstance(code, str)
    ):
        return None
    modifiers = _mods(modifiers)
    if key in NAMED_KEYS:
        default_code, vk = NAMED_KEYS[key]
    elif (
        len(key) == 1
        and key.isascii()
        and key.isalnum()
        and modifiers & (MOD_CTRL | MOD_META)
    ):
        if key.lower() in _BLOCKED_SHORTCUTS:
            return None
        default_code = f"Key{key.upper()}" if key.isalpha() else f"Digit{key}"
        vk = ord(key.upper())
    else:
        return None  # printable text goes through Input.insertText
    if not code or len(code) > 32:
        code = default_code
    params: dict[str, Any] = {
        "type": "keyUp" if kind == "up" else "rawKeyDown",
        "key": key,
        "code": code,
        "windowsVirtualKeyCode": vk,
        "modifiers": modifiers,
    }
    if kind == "down" and key == "Enter" and not modifiers & (MOD_CTRL | MOD_META):
        # keyDown + text "\r" makes Blink fire keypress -> implicit form submit.
        params.update(type="keyDown", text="\r", unmodifiedText="\r")
    cmd_key = key.lower() if len(key) == 1 else key
    commands = (
        _MAC_COMMANDS.get((cmd_key, modifiers)) if sys.platform == "darwin" else None
    )
    if kind == "down" and commands:
        params["commands"] = commands
    return params


Cmd = tuple[str, dict[str, Any]]


def _tr_mouse(msg: dict[str, Any]) -> Cmd | None:
    x, y = _num(msg.get("x"), 0), _num(msg.get("y"), 0)
    typ, button = msg.get("type"), msg.get("button", "none")
    if not isinstance(typ, str) or not isinstance(button, str):
        return None
    if x is None or y is None or typ not in MOUSE_TYPES or button not in MOUSE_BUTTONS:
        return None
    clicks = msg.get("clickCount", 0)
    return "Input.dispatchMouseEvent", {
        "type": typ,
        "x": x,
        "y": y,
        "button": button,
        "buttons": _mods(msg.get("buttons", 0)) if msg.get("buttons") else 0,
        "clickCount": clicks if isinstance(clicks, int) and 0 <= clicks <= 3 else 0,
        "modifiers": _mods(msg.get("modifiers")),
    }


def _tr_wheel(msg: dict[str, Any]) -> Cmd | None:
    x, y = _num(msg.get("x"), 0), _num(msg.get("y"), 0)
    dx = _num(msg.get("deltaX", 0), -10_000, 10_000)
    dy = _num(msg.get("deltaY", 0), -10_000, 10_000)
    if x is None or y is None or dx is None or dy is None:
        return None
    return "Input.dispatchMouseEvent", {
        "type": "mouseWheel",
        "x": x,
        "y": y,
        "deltaX": dx,
        "deltaY": dy,
        "modifiers": _mods(msg.get("modifiers")),
    }


def _tr_key(msg: dict[str, Any]) -> Cmd | None:
    p = key_event_params(
        str(msg.get("kind")),
        msg.get("key", ""),
        msg.get("code", ""),
        msg.get("modifiers", 0),
    )
    return ("Input.dispatchKeyEvent", p) if p else None


def _tr_text(msg: dict[str, Any]) -> Cmd | None:
    text = msg.get("text")
    if not isinstance(text, str) or not text or len(text) > MAX_TEXT:
        return None
    return "Input.insertText", {"text": text}


def _tr_ime(msg: dict[str, Any]) -> Cmd | None:
    text = msg.get("text")
    s, e = msg.get("selStart", 0), msg.get("selEnd", 0)
    if not isinstance(text, str) or len(text) > MAX_TEXT:
        return None
    if not (isinstance(s, int) and isinstance(e, int) and 0 <= s <= e <= len(text)):
        s = e = len(text)
    return "Input.imeSetComposition", {
        "text": text,
        "selectionStart": s,
        "selectionEnd": e,
    }


def _tr_ack(msg: dict[str, Any]) -> Cmd | None:
    sid = msg.get("sessionId")
    if isinstance(sid, int) and not isinstance(sid, bool):
        return "Page.screencastFrameAck", {"sessionId": sid}
    return None


_TRANSLATORS = {
    "mouse": _tr_mouse,
    "wheel": _tr_wheel,
    "key": _tr_key,
    "text": _tr_text,
    "ime": _tr_ime,
    "ack": _tr_ack,
}


def translate(msg: Any) -> Cmd | None:
    """Viewer message -> (CDP method, params), or None to drop it.

    The viewer never sends raw CDP: it sends small typed messages, and only
    these translators can turn one into a CDP call.
    """
    if not isinstance(msg, dict):
        return None
    t = msg.get("t")
    if not isinstance(t, str):  # unhashable or odd keys never reach a lookup
        return None
    tr = _TRANSLATORS.get(t)
    return tr(msg) if tr else None


_BAD_INPUT = (TypeError, ValueError, OverflowError, RecursionError)


def parse_message(raw: Any) -> dict[str, Any] | None:
    """Viewer frame -> dict, or None for anything malformed (never raises)."""
    try:
        msg = json.loads(raw)
    except _BAD_INPUT:
        return None
    return msg if isinstance(msg, dict) else None


def safe_translate(msg: Any) -> Cmd | None:
    """``translate`` that turns any malformed input into None instead of raising."""
    try:
        return translate(msg)
    except _BAD_INPUT:
        return None


@dataclass
class Relay:  # pylint: disable=too-many-instance-attributes
    """One CDP attachment to the owned target plus at most one viewer socket."""

    cdp_http: str
    target_id: str  # "" until the relay has created its own target
    token: str
    quality: int
    idle_timeout: float
    url: str | None = None
    port: int = 0
    auth: ViewerAuth = field(default_factory=lambda: ViewerAuth(0))
    created: bool = False
    session_id: str = ""
    viewer: Any = None
    last_input: float = 0.0
    last_viewer: float = field(default_factory=time.monotonic)
    popups: list[str] = field(default_factory=list)
    exit_reason: str = ""
    exit_code: int = 0
    done: asyncio.Event = field(default_factory=asyncio.Event)
    _cdp: Any = None
    _next_id: int = 0
    _pending: dict[int, asyncio.Future[Any]] = field(default_factory=dict)

    def finish(self, reason: str, code: int = 0) -> None:
        """Record the first exit reason and stop the relay."""
        if not self.done.is_set():
            self.exit_reason, self.exit_code = reason, code
            self.done.set()

    async def call(self, method: str, session: bool = True, **params: Any) -> Any:
        """Send one gated CDP command and await its result."""
        if not method_allowed(method, params, self.target_id):
            raise PermissionError(f"CDP method not allowed: {method}")
        self._next_id += 1
        mid = self._next_id
        msg: dict[str, Any] = {"id": mid, "method": method, "params": params}
        if session:
            msg["sessionId"] = self.session_id
        fut: asyncio.Future[Any] = asyncio.get_running_loop().create_future()
        self._pending[mid] = fut
        try:
            await self._cdp.send(json.dumps(msg))
            return await asyncio.wait_for(fut, 10)
        except asyncio.TimeoutError as e:
            raise asyncio.TimeoutError(f"{method}: no answer within 10 s") from e
        finally:
            self._pending.pop(mid, None)  # also drops timed-out futures

    async def attach(self) -> None:
        """Connect to the browser endpoint; create (-u) or adopt (-t -A) the target."""
        from websockets.asyncio.client import connect

        info = await asyncio.to_thread(_http_json, f"{self.cdp_http}/json/version")
        if not self.url:
            targets = await asyncio.to_thread(_http_json, f"{self.cdp_http}/json/list")
            if not any(
                t.get("id") == self.target_id and t.get("type") == "page"
                for t in targets
            ):
                raise LookupError(f"no page target {self.target_id} on {self.cdp_http}")
        # origin=None: the shared browser runs without --remote-allow-origins,
        # so Chrome rejects (403) any CDP WebSocket that sends an Origin.
        self._cdp = await connect(
            info["webSocketDebuggerUrl"], max_size=None, origin=None
        )
        asyncio.create_task(self._cdp_reader())
        await self.call("Target.setDiscoverTargets", session=False, discover=True)
        if self.url:
            res = await self.call(
                "Target.createTarget", session=False, url=self.url, background=True
            )
            self.target_id, self.created = res["targetId"], True
        res = await self.call(
            "Target.attachToTarget",
            session=False,
            targetId=self.target_id,
            flatten=True,
        )
        self.session_id = res["sessionId"]
        await self.call("Page.enable")
        await self.call("Inspector.enable")
        # A background-created tab is "hidden" and renders no frames (Page.startScreencast
        # then never answers). Focus emulation makes it visible to THIS session only —
        # no window is shown or raised.
        await self.call("Emulation.setFocusEmulationEnabled", enabled=True)

    async def close(self) -> None:
        """Close the target the relay created (never an adopted one), then CDP."""
        if self.created and self.target_id and self._cdp is not None:
            try:
                await self.call(
                    "Target.closeTarget", session=False, targetId=self.target_id
                )
            except Exception:  # pylint: disable=broad-exception-caught
                pass
        if self._cdp is not None:
            await self._cdp.close()

    async def _cdp_reader(self) -> None:
        try:
            async for raw in self._cdp:
                await self._on_cdp(json.loads(raw))
        except Exception as e:  # pylint: disable=broad-exception-caught
            self.finish(f"CDP connection lost: {type(e).__name__}", 1)
        finally:
            self.finish("CDP connection closed", 1)

    async def _on_cdp(self, msg: dict[str, Any]) -> None:
        if "id" in msg:
            fut = self._pending.get(msg["id"])
            if fut and not fut.done():
                if "error" in msg:
                    fut.set_exception(
                        RuntimeError(msg["error"].get("message", "CDP error"))
                    )
                else:
                    fut.set_result(msg.get("result", {}))
            return
        method, params = msg.get("method", ""), msg.get("params", {})
        own_session = bool(self.session_id) and msg.get("sessionId") == self.session_id
        if method == "Page.screencastFrame" and own_session:
            if self.viewer is not None:
                frame = {
                    "t": "frame",
                    "data": params["data"],
                    "meta": params["metadata"],
                    "sid": params["sessionId"],
                    "rt": time.time() * 1000,
                }
                await self._to_viewer(frame)
        elif method == "Target.targetCreated":
            await self._maybe_popup(params.get("targetInfo", {}))
        elif (
            method == "Target.targetDestroyed"
            and params.get("targetId") == self.target_id
        ):
            await self._end("the login tab was closed")
        elif (
            method == "Target.detachedFromTarget"
            and params.get("sessionId") == self.session_id
        ):
            await self._end("the relay was detached from the login tab")
        elif method == "Inspector.targetCrashed" and own_session:
            await self._end("the login tab crashed")

    async def _maybe_popup(self, ti: dict[str, Any]) -> None:
        tid = ti.get("targetId", "")
        if not tid or tid == self.target_id or ti.get("type") != "page":
            return
        opener = ti.get("openerId")
        if opener == self.target_id:
            label = "opener=owned"
        elif (
            not opener
            and self.viewer is not None
            and time.monotonic() - self.last_input < POPUP_FOCUS_WINDOW_S
        ):
            label = "opener=unknown"
        else:
            return
        if len(self.popups) >= MAX_POPUPS:
            return
        self.popups.append(tid)
        note = f"popup target {tid} ({label})"
        print(f"ℹ️  {note} — not followed in this spike", file=sys.stderr)
        await self._to_viewer(
            {"t": "info", "text": note, "popup": tid, "opener": label}
        )

    async def _end(self, reason: str) -> None:
        await self._to_viewer({"t": "info", "text": reason, "end": True})
        self.finish(reason, 1)

    async def _to_viewer(self, obj: dict[str, Any]) -> None:
        if self.viewer is not None:
            try:
                await self.viewer.send(json.dumps(obj))
            except Exception:  # pylint: disable=broad-exception-caught
                pass

    # ---- viewer side -------------------------------------------------------------

    def process_request(self, connection: Any, request: Any) -> Any:
        """websockets hook: auth every request; serve the page; gate the upgrade."""
        headers = dict(request.headers.raw_items())
        ok, rest = token_ok(request.path, self.token)
        is_ws = request.headers.get("Upgrade", "").lower() == "websocket"
        if not ok:
            return connection.respond(404, "not found\n")
        if not origin_ok(headers, self.port, websocket=is_ws):
            return connection.respond(403, "forbidden\n")
        now = time.monotonic()
        if is_ws and rest == "ws":
            status = self.auth.websocket(headers, now)
            return connection.respond(status, "refused\n") if status else None
        if not is_ws and rest == "":
            status, session = self.auth.page(headers, now)
            if status != 200:
                return connection.respond(404, "not found\n")
            cookie = None
            if session:
                cookie = (
                    f"{self.auth.cookie_name}={session}; Path=/{self.token}/; "
                    "HttpOnly; SameSite=Strict"
                )
            return _html_response(self.port, cookie)
        return connection.respond(404, "not found\n")

    async def _start_screencast(self, msg: dict[str, Any]) -> None:
        w = int(_num(msg.get("w"), 200, 4096) or 1280)
        h = int(_num(msg.get("h"), 200, 4096) or 800)
        await self.call(
            "Page.startScreencast",
            format="jpeg",
            quality=self.quality,
            maxWidth=w,
            maxHeight=h,
            everyNthFrame=1,
        )

    async def _handle_message(self, raw: Any) -> None:
        """One viewer frame -> at most one allowlisted CDP call; never raises on input."""
        msg = parse_message(raw)
        if msg is None:
            return
        try:
            if msg.get("t") == "hello":
                await self._start_screencast(msg)
                return
            cmd = safe_translate(msg)
            if cmd is None:
                return
            if cmd[0] != "Page.screencastFrameAck":
                self.last_input = time.monotonic()
            await self.call(cmd[0], **cmd[1])
        except (RuntimeError, PermissionError, asyncio.TimeoutError) as e:
            print(f"❌ viewer command failed: {e}", file=sys.stderr)

    async def handle_viewer(self, ws: Any) -> None:
        """One viewer socket: start the screencast, relay its input until it leaves."""
        from websockets.exceptions import ConnectionClosed

        if self.auth.connected or self.viewer is not None:
            await ws.close(1008, "busy")
            return
        self.auth.on_connect()
        self.viewer = ws
        print("✅ viewer connected", file=sys.stderr)
        try:
            async for raw in ws:
                await self._handle_message(raw)
        except ConnectionClosed as e:
            print(
                f"ℹ️  viewer connection dropped (code {e.rcvd.code if e.rcvd else 'none'})",
                file=sys.stderr,
            )
        finally:
            # Stop frames BEFORE freeing the slot, so a reconnecting viewer can
            # never race a stopScreencast that is still in flight.
            try:
                await self.call("Page.stopScreencast")
            except Exception:  # pylint: disable=broad-exception-caught
                pass
            self.viewer = None
            self.last_viewer = time.monotonic()
            self.auth.on_disconnect(self.last_viewer)
            print(
                f"ℹ️  viewer disconnected — the same tab may reconnect within "
                f"{RECONNECT_GRACE_S:.0f}s, then the token is burned",
                file=sys.stderr,
            )

    async def lifecycle_watch(self) -> None:
        """Exit once the token is burned, or after ``idle_timeout`` s with no viewer."""
        while not self.done.is_set():
            await asyncio.sleep(0.5)
            now = time.monotonic()
            if self.viewer is not None:
                self.last_viewer = now
            elif self.auth.burned(now):
                self.finish("viewer left and did not reconnect; token burned")
            elif now - self.last_viewer > self.idle_timeout:
                self.finish(f"no viewer connected for {self.idle_timeout:.0f}s", 1)


def _http_json(url: str) -> Any:
    with urllib.request.urlopen(url, timeout=5) as r:  # noqa: S310 (loopback CDP only)
        return json.loads(r.read())


def _html_response(port: int, set_cookie: str | None) -> Any:
    from websockets.datastructures import (
        Headers,
    )
    from websockets.http11 import Response

    nonce = secrets.token_urlsafe(16)
    body = VIEWER_HTML.replace("__NONCE__", nonce).encode()
    csp = (
        f"default-src 'none'; script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'; "
        f"img-src data:; connect-src ws://127.0.0.1:{port}; frame-ancestors 'none'; "
        "base-uri 'none'; form-action 'none'"
    )
    return Response(
        200,
        "OK",
        Headers(
            [
                ("Content-Type", "text/html; charset=utf-8"),
                ("Content-Length", str(len(body))),
                ("Content-Security-Policy", csp),
                ("Referrer-Policy", "no-referrer"),
                ("Cache-Control", "no-store"),
                ("X-Content-Type-Options", "nosniff"),
                *([("Set-Cookie", set_cookie)] if set_cookie else []),
            ]
        ),
        body,
    )


VIEWER_HTML = r"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Guided login</title>
<style nonce="__NONCE__">
html,body{margin:0;height:100%;background:#202124;color:#e8eaed;font:13px system-ui,sans-serif;overflow:hidden}
#bar{height:26px;line-height:26px;padding:0 10px;background:#303134}
#wrap{position:absolute;top:26px;left:0;right:0;bottom:0;display:flex;align-items:center;justify-content:center}
canvas{background:#fff;cursor:default;max-width:100%;max-height:100%}
#ime{position:fixed;left:0;bottom:0;width:2px;height:2px;opacity:0;border:0;padding:0;resize:none}
</style></head><body>
<div id="bar">Guided login — click into the page and type; paste works. <span id="st"></span></div>
<div id="wrap"><canvas id="c" width="800" height="600" aria-label="remote login tab"></canvas></div>
<textarea id="ime" autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false"></textarea>
<script nonce="__NONCE__">
"use strict";
const cv = document.getElementById("c"), ctx = cv.getContext("2d"), ta = document.getElementById("ime");
const st = document.getElementById("st");
const ws = new WebSocket("ws://" + location.host + location.pathname + "ws");
let meta = null, composing = false, ended = false;
window.__viewerStats = {frames: 0, lat: [], relayLat: [], info: []};
const send = o => { if (ws.readyState === 1) ws.send(JSON.stringify(o)); };
const mods = e => (e.altKey ? 1 : 0) | (e.ctrlKey ? 2 : 0) | (e.metaKey ? 4 : 0) | (e.shiftKey ? 8 : 0);
ws.onopen = () => { st.textContent = "connected";
  send({t: "hello", w: Math.round(innerWidth * devicePixelRatio), h: Math.round((innerHeight - 26) * devicePixelRatio)}); };
ws.onclose = () => { if (!ended) st.textContent = "disconnected — reload within 10 s to reconnect"; };
ws.onmessage = ev => {
  const m = JSON.parse(ev.data);
  if (m.t === "info") { window.__viewerStats.info.push(m); st.textContent = m.text; if (m.end) ended = true; return; }
  if (m.t !== "frame") return;
  const now = Date.now(), img = new Image();
  img.onload = () => {
    if (cv.width !== img.naturalWidth || cv.height !== img.naturalHeight) { cv.width = img.naturalWidth; cv.height = img.naturalHeight; }
    ctx.drawImage(img, 0, 0); meta = m.meta;
    const s = window.__viewerStats; s.frames++; s.lastDraw = Date.now();
    if (s.lat.length < 500) { s.lat.push(Date.now() - m.meta.timestamp * 1000); s.relayLat.push(m.rt - m.meta.timestamp * 1000); }
    send({t: "ack", sessionId: m.sid});
  };
  img.src = "data:image/jpeg;base64," + m.data;
};
function pt(e) {
  const r = cv.getBoundingClientRect();
  const w = meta ? meta.deviceWidth : cv.width, h = meta ? meta.deviceHeight : cv.height;
  return {x: (e.clientX - r.left) * w / r.width, y: (e.clientY - r.top) * h / r.height};
}
const BTN = ["left", "middle", "right", "back", "forward"];
cv.addEventListener("mousedown", e => { e.preventDefault(); ta.focus();
  send(Object.assign({t: "mouse", type: "mousePressed", button: BTN[e.button] || "none", buttons: e.buttons, clickCount: e.detail, modifiers: mods(e)}, pt(e))); });
cv.addEventListener("mouseup", e => { e.preventDefault(); ta.focus();
  send(Object.assign({t: "mouse", type: "mouseReleased", button: BTN[e.button] || "none", buttons: e.buttons, clickCount: e.detail, modifiers: mods(e)}, pt(e))); });
let moveQueued = null;
cv.addEventListener("mousemove", e => { const first = !moveQueued;
  moveQueued = Object.assign({t: "mouse", type: "mouseMoved", button: "none", buttons: e.buttons, modifiers: mods(e)}, pt(e));
  if (first) requestAnimationFrame(() => { send(moveQueued); moveQueued = null; }); });
cv.addEventListener("contextmenu", e => e.preventDefault());
cv.addEventListener("wheel", e => { e.preventDefault();
  const k = e.deltaMode === 1 ? 40 : e.deltaMode === 2 ? 800 : 1;
  send(Object.assign({t: "wheel", deltaX: e.deltaX * k, deltaY: e.deltaY * k, modifiers: mods(e)}, pt(e))); }, {passive: false});
// keys: named keys and Ctrl/Meta shortcuts go as key events; printable text via beforeinput
const NAMED = new Set(["Backspace","Tab","Enter","Shift","Control","Alt","Pause","CapsLock","Escape","PageUp","PageDown","End","Home",
  "ArrowLeft","ArrowUp","ArrowRight","ArrowDown","Insert","Delete","Meta","F1","F2","F3","F4","F5","F6","F7","F8","F9","F10","F11","F12"]);
const CLIP = new Set(["c", "v", "x"]);
function keyMsg(e, kind) {
  if (e.isComposing || composing || e.key === "Process" || e.key === "Dead" || e.keyCode === 229) return null;
  if (NAMED.has(e.key)) return {t: "key", kind, key: e.key, code: e.code, modifiers: mods(e)};
  if ((e.ctrlKey || e.metaKey) && e.key.length === 1 && !CLIP.has(e.key.toLowerCase()))
    return {t: "key", kind, key: e.key, code: e.code, modifiers: mods(e)};
  return null;
}
ta.addEventListener("keydown", e => { const m = keyMsg(e, "down"); if (m) { e.preventDefault(); send(m); } });
ta.addEventListener("keyup", e => { const m = keyMsg(e, "up"); if (m) { e.preventDefault(); send(m); } });
ta.addEventListener("beforeinput", e => {
  if (e.inputType === "insertText" && !e.isComposing && e.data) { e.preventDefault(); send({t: "text", text: e.data}); }
  else if (e.inputType === "insertLineBreak" || e.inputType === "insertParagraph") { e.preventDefault(); }
  else if (e.inputType === "insertFromPaste") { e.preventDefault(); }
});
ta.addEventListener("paste", e => { e.preventDefault();
  const t = (e.clipboardData || window.clipboardData).getData("text/plain"); if (t) send({t: "text", text: t}); });
ta.addEventListener("compositionstart", () => { composing = true; });
ta.addEventListener("compositionupdate", e => { send({t: "ime", text: e.data || "", selStart: (e.data || "").length, selEnd: (e.data || "").length}); });
ta.addEventListener("compositionend", e => { composing = false; if (e.data) send({t: "text", text: e.data}); else send({t: "ime", text: ""}); ta.value = ""; });
ta.addEventListener("input", () => { if (!composing) ta.value = ""; });
ta.focus();
</script></body></html>"""


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="login_viewer.py",
        description=(
            "Loopback remote view of ONE owned headless tab: screencast out, "
            "mouse/keys/text/paste/IME in, via an allowlisted CDP relay. By default "
            "the relay creates the tab itself (-u URL) and closes it on exit."
        ),
        epilog=(
            "The viewer URL carries a one-shot credential (path token; the first page\n"
            "load binds it to that browser tab). It is printed exactly once; with -j\n"
            "the JSON line contains it in clear — treat that line as a secret.\n\n"
            "examples:\n"
            "  login_viewer.py -c http://127.0.0.1:9333 -u https://example.org/login\n"
            "  login_viewer.py -c http://127.0.0.1:9333 -u https://example.org/login -j -i 120\n"
            "  login_viewer.py -c http://127.0.0.1:9333 -t 1A2B... -A  # `browser.py open -N` id"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "-c",
        "--cdp",
        default="http://127.0.0.1:9222",
        help="CDP HTTP endpoint (127.0.0.1 only)",
    )
    p.add_argument(
        "-u", "--url", help="create a background tab on URL and own it (default mode)"
    )
    p.add_argument(
        "-t", "--target-id", help="attach to an EXISTING page target (needs -A)"
    )
    p.add_argument(
        "-A",
        "--assume-owned",
        action="store_true",
        help="the caller proves it owns -t ID (e.g. an id from `browser.py open -N`)",
    )
    p.add_argument(
        "-p", "--port", type=int, default=0, help="viewer port (default: random)"
    )
    p.add_argument(
        "-q", "--quality", type=int, default=70, help="JPEG quality 1-100 (default 70)"
    )
    p.add_argument(
        "-i",
        "--idle-timeout",
        type=float,
        default=300.0,
        help="exit after N s with NO viewer connected (default 300)",
    )
    p.add_argument(
        "-j",
        "--json",
        action="store_true",
        help="print {url, port, target} as one JSON line (url = one-shot credential)",
    )
    a = p.parse_args(argv)
    err = ownership_error(a.url, a.target_id, a.assume_owned)
    if err:
        p.exit(2, f"❌ {err}\n")
    if not a.cdp.startswith("http://127.0.0.1:"):
        p.exit(
            2,
            "❌ --cdp must be http://127.0.0.1:<port> (CDP is loopback-only, never localhost)\n",
        )
    a.cdp = a.cdp.rstrip("/")
    a.quality = min(max(a.quality, 1), 100)
    return a


async def _amain(a: argparse.Namespace) -> int:
    from websockets.asyncio.server import serve

    relay = Relay(
        a.cdp,
        a.target_id or "",
        secrets.token_urlsafe(32),
        a.quality,
        a.idle_timeout,
        url=a.url,
    )
    try:
        await relay.attach()
    except (OSError, LookupError, RuntimeError, KeyError, asyncio.TimeoutError) as e:
        print(f"❌ cannot open/attach the login tab on {a.cdp}: {e}", file=sys.stderr)
        await relay.close()
        return 1
    try:
        async with serve(
            relay.handle_viewer,
            "127.0.0.1",
            a.port,
            process_request=relay.process_request,
            max_size=1 << 20,
        ) as server:
            relay.port = server.sockets[0].getsockname()[1]
            relay.auth = ViewerAuth(relay.port)
            url = f"http://127.0.0.1:{relay.port}/{relay.token}/"
            if a.json:
                print(
                    json.dumps(
                        {"url": url, "port": relay.port, "target": relay.target_id}
                    ),
                    flush=True,
                )
            else:
                link = osc8(url, f"open viewer (127.0.0.1:{relay.port})")
                print(
                    f"✅ guided-login viewer for target {relay.target_id}: {link}",
                    flush=True,
                )
            del url
            watcher = asyncio.create_task(relay.lifecycle_watch())
            await relay.done.wait()
            watcher.cancel()
    finally:
        await relay.close()
    mark = "✅" if relay.exit_code == 0 else "❌"
    print(f"{mark} viewer relay ended: {relay.exit_reason}", file=sys.stderr)
    return relay.exit_code


def bootstrap_venv() -> None:
    """Run under the repo's .venv (pyvenv_bootstrap; creates/repairs it, re-execs).

    Called from `main()` after argument parsing, so `-h` and argument errors
    work on a bare interpreter.
    """
    sys.path.insert(0, str(REPO_ROOT))
    from pyvenv_bootstrap import ensure_venv

    try:
        ensure_venv(__file__, requires=VIEWER_MODULES)
    except SystemExit as exc:
        if exc.code in (0, None):
            raise
        print(
            f"❌ no usable venv with websockets; run: uv sync --project {REPO_ROOT}",
            file=sys.stderr,
        )
        raise SystemExit(EXIT_MISSING_DEP) from exc


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    a = _parse_args(argv)  # -h needs no venv
    bootstrap_venv()  # may re-exec under <repo>/.venv
    try:
        return asyncio.run(_amain(a))
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
