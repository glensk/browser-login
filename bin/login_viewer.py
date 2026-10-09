#!/usr/bin/env python3
"""Remote view of ONE owned headless tab: screencast frames out, input in.

Guided login, design "B" (plans-done/PLAN_focus-free-browser_DONE.md, Phase 3). The shared
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

Guided-login integration (``browser.py assisted-login``, the maintenance
transaction): the relay runs as a REGISTERED long-lived client (``register-exec``)
under the transaction's owner token; ``-M FILE`` makes it refuse to start without
that token and end as soon as the maintenance record is gone or its owner died
(the watchdog then closes the owned targets), or once the owner marked the login
``succeeded`` (the view then says ``✅ Logged in to SITE — you can close this
tab``); the record is polled every 0.5 s. Whatever ends the relay (SIGTERM from
the transaction included), a connected view gets one final ``end`` line first,
so it never just says "disconnected". ``-E`` prints one JSON event per line on
stdout for the transaction:

* ``{"ev": "owned", "target", "opener"}`` — the TARGET SUPERVISOR followed a new
  target whose ``openerId`` is an owned one (an OAuth popup): it is owned now and
  shown in the viewer; ``{"ev": "released", "target"}`` — an owned target closed
  (the viewer returns to its opener). A target without an owned opener is never
  selected; ``{"ev": "popup_unowned", "target"}`` (plus a stderr line) when one
  appears right after the human's input — usually browser.py's own background
  ``logged-in`` probe tab. It is NOT shown in the view.
* ``{"ev": "viewer", "connected"}`` — the human's view (dis)connected.
* ``{"ev": "surface", "reason"}`` — something the view cannot do: a WebAuthn /
  passkey prompt (``navigator.credentials.get/create`` hook, conditional
  mediation excluded), a permission request (notifications, geolocation,
  camera/microphone, screen capture), an external-app link (navigation to a
  non-web scheme), or "Use a window instead" pressed in the viewer. The relay
  then exits ``5`` and the transaction offers the window (fallback A).
  Client-certificate prompts are not exposed by CDP in headless Chrome (it
  silently sends no certificate); the site's error page shows in the view and
  the button is the way out.
* ``{"ev": "end", "reason", "code"}`` — the relay's last line.

JS dialogs (alert/confirm/prompt/beforeunload) are answered in the viewer. The
owned target's viewport follows the viewer window (``Emulation.
setDeviceMetricsOverride``, session-scoped: it ends with the relay's session).
"""

from __future__ import annotations

import argparse
import asyncio
import hmac
import http.cookies
import json
import math
import os
import secrets
import signal
import sys
import time
import urllib.request
from collections.abc import Collection, Sequence
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
# The guided login's owner token (browser.py exports it to its children).
MAINTENANCE_ENV = "CLAUDE_BROWSER_MAINTENANCE"

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
        "Emulation.setDeviceMetricsOverride",
        "Page.handleJavaScriptDialog",
        "Runtime.enable",
        "Runtime.addBinding",
        "Runtime.evaluate",
        "Page.addScriptToEvaluateOnNewDocument",
    }
)
# Target.* calls that name a target must name an owned one.
_TARGET_SCOPED = frozenset({"Target.attachToTarget", "Target.closeTarget"})
# Calls that carry relay-internal code/names: only the exact strings the relay
# registered (the WebAuthn/permission hook and its binding name) pass.
_INTERNAL_PARAM = {
    "Runtime.evaluate": "expression",
    "Runtime.addBinding": "name",
    "Page.addScriptToEvaluateOnNewDocument": "source",
}
EXIT_FALLBACK = 5
# Browser-level events the target supervisor acts on.
_SUPERVISOR_EVENTS = frozenset(
    {"Target.targetCreated", "Target.targetDestroyed", "Target.detachedFromTarget"}
)

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
# How often (-M) the relay re-reads the guided login's maintenance record.
MAINT_POLL_S = 0.5
# The record state browser.py writes once the login succeeded.
MAINT_SUCCEEDED = "succeeded"


def osc8(url: str, text: str | None = None) -> str:
    """OSC 8 hyperlink (invisible where unsupported)."""
    return f"\x1b]8;;{url}\x1b\\{text or url}\x1b]8;;\x1b\\"


def method_allowed(
    method: str,
    params: dict[str, Any],
    owned: str | Collection[str],
    internal: Collection[str] = (),
) -> bool:
    """Final gate for every CDP command the relay sends.

    `owned` = the owned target id(s); `internal` = the relay's own hook source
    and binding name (the only values ``Runtime.evaluate``/``addBinding`` and
    ``Page.addScriptToEvaluateOnNewDocument`` may carry).
    """
    ids = {owned} if isinstance(owned, str) else set(owned)
    ids.discard("")
    if method not in ALLOWED_METHODS:
        return False
    if method == "Target.createTarget":
        return not ids  # only the one target the relay creates for itself
    if method in _TARGET_SCOPED:
        return params.get("targetId") in ids
    key = _INTERNAL_PARAM.get(method)
    if key is not None:
        value = params.get(key)
        return isinstance(value, str) and value in internal
    return True


# Schemes a login tab may navigate to; anything else asks the OS for an app.
_WEB_SCHEMES = frozenset({"http", "https", "about", "data", "blob", "javascript"})


def external_scheme(url: Any) -> str | None:
    """The non-web scheme `url` navigates to (an external-app prompt), or None."""
    if not isinstance(url, str) or ":" not in url:
        return None
    scheme = url.split(":", 1)[0].lower()
    if not scheme or scheme in _WEB_SCHEMES or scheme.startswith("chrome"):
        return None
    return scheme


def popup_decision(
    ti: dict[str, Any], owned: Collection[str], recent_input: bool
) -> str:
    """``follow`` (opener owned), ``report`` (no opener, right after input) or
    ``ignore`` for a new target — never selects a target without an owned opener."""
    tid = ti.get("targetId")
    if not isinstance(tid, str) or not tid or tid in owned:
        return "ignore"
    if ti.get("type") != "page":
        return "ignore"
    opener = ti.get("openerId")
    if isinstance(opener, str) and opener in owned:
        return "follow"
    if not opener and recent_input:
        return "report"
    return "ignore"


def view_after_close(
    closed: str, current: str, owned: Sequence[str], openers: dict[str, str]
) -> str | None:
    """What the viewer shows after owned target `closed` went away (None = end).

    Not the shown one → unchanged. The shown one → its opener (or the opener's
    opener …) if still owned, else the most recent owned target left.
    """
    left = [t for t in owned if t != closed]
    if not left:
        return None
    if closed != current:
        return current
    opener = openers.get(closed)
    seen: set[str] = set()
    while opener is not None and opener not in left and opener not in seen:
        seen.add(opener)
        opener = openers.get(opener)
    return opener if opener in left else left[-1]


_SURFACES = {
    "webauthn": "a passkey / security-key (WebAuthn) prompt",
    "permission": "a permission request",
    "external": "a link that opens an external app",
    "requested": "you asked for a visible window",
}


def surface_reason(kind: str, detail: str = "") -> str:
    """The named reason a surface ends the remote view."""
    base = _SURFACES.get(kind, "an unsupported prompt")
    return f"{base} ({detail})" if detail and kind != "requested" else base


def hook_source(binding: str) -> str:
    """The init script that reports unsupported surfaces through `binding`.

    It removes the binding from the page's global object first (pages cannot
    call it by name), then wraps the APIs whose UI a headless tab cannot show.
    Conditional mediation (passkey autofill, called by many login pages on
    load) is NOT reported — only a modal WebAuthn ceremony is.
    """
    name = json.dumps(binding)
    return (
        "(() => { const sig = globalThis[" + name + "];"
        " try { delete globalThis[" + name + "]; } catch (e) {}"
        " if (typeof sig !== 'function') return;"
        " const send = (k, d) => { try { sig(JSON.stringify({k: k, d: d}));"
        " } catch (e) {} };"
        " const wrap = (o, n, k, test) => { try { const f = o && o[n];"
        " if (typeof f !== 'function') return;"
        " o[n] = function (...a) { if (!test || test(a)) send(k, n);"
        " return f.apply(this, a); }; } catch (e) {} };"
        " const c = navigator.credentials;"
        " wrap(c, 'get', 'webauthn', a => !!(a[0] && a[0].publicKey)"
        " && a[0].mediation !== 'conditional');"
        " wrap(c, 'create', 'webauthn', a => !!(a[0] && a[0].publicKey));"
        " if (globalThis.Notification)"
        " wrap(Notification, 'requestPermission', 'permission');"
        " wrap(navigator.geolocation, 'getCurrentPosition', 'permission');"
        " wrap(navigator.geolocation, 'watchPosition', 'permission');"
        " wrap(navigator.mediaDevices, 'getUserMedia', 'permission');"
        " wrap(navigator.mediaDevices, 'getDisplayMedia', 'permission');"
        " })();"
    )


def _record_error(path: Path, nonce: str) -> tuple[dict[str, Any], str | None]:
    """(the record, why the relay may not run under it — None when it may)."""
    try:
        rec = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}, (
            f"no maintenance record at {path} (start it via browser.py assisted-login)"
        )
    if not isinstance(rec, dict) or not rec.get("owner_nonce"):
        return {}, f"invalid maintenance record at {path}"
    if not nonce or not hmac.compare_digest(str(rec["owner_nonce"]), nonce):
        return rec, "not the guided login's owner ($CLAUDE_BROWSER_MAINTENANCE)"
    return rec, None


def maintenance_error(path: Path, nonce: str) -> str | None:
    """Why the relay may not run under maintenance record `path`, or None."""
    return _record_error(path, nonce)[1]


def maintenance_poll(path: Path, nonce: str) -> tuple[str, str]:
    """One look at the guided login's record: ``("gone", "")`` (gone, another
    owner's, or its owner pid died), ``("succeeded", SITE)`` (the owner marked
    the login done) or ``("live", "")``."""
    rec, err = _record_error(path, nonce)
    if err is not None:
        return "gone", ""
    try:
        os.kill(int(rec["pid"]), 0)
    except ProcessLookupError:
        return "gone", ""
    except (OSError, KeyError, ValueError, TypeError):
        pass  # EPERM / unreadable: never end a live session on a hiccup
    if rec.get("state") == MAINT_SUCCEEDED:
        return MAINT_SUCCEEDED, str(rec.get("site") or "")
    return "live", ""


def owner_alive(path: Path, nonce: str) -> bool:
    """The record still carries `nonce` and its owner pid exists."""
    return maintenance_poll(path, nonce)[0] != "gone"


def success_text(site: str) -> str:
    """The view's last line after a successful guided login."""
    return f"✅ Logged in to {site or 'the site'} — you can close this tab"


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
    """One CDP connection, the owned target(s) and at most one viewer socket.

    ``target_id``/``session_id`` name the target the viewer SHOWS right now;
    ``owned`` lists every owned target (the login tab first, then the popups
    the target supervisor followed), ``sessions`` their flat CDP sessions.
    """

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
    end_sent: bool = False  # the view got its final ``end`` line
    done: asyncio.Event = field(default_factory=asyncio.Event)
    events: bool = False
    maint_file: Path | None = None
    maint_nonce: str = ""
    owned: list[str] = field(default_factory=list)
    openers: dict[str, str] = field(default_factory=dict)
    sessions: dict[str, str] = field(default_factory=dict)
    dims: tuple[int, int, int, int] | None = None  # css w, h; device w, h
    dialogs: dict[str, dict[str, Any]] = field(default_factory=dict)
    binding: str = field(default_factory=lambda: "__lv" + secrets.token_hex(8))
    _cdp: Any = None
    _next_id: int = 0
    _pending: dict[int, asyncio.Future[Any]] = field(default_factory=dict)
    _tasks: set[asyncio.Task[None]] = field(default_factory=set)

    @property
    def hook(self) -> str:
        """This relay's surface hook (init script)."""
        return hook_source(self.binding)

    @property
    def internal(self) -> frozenset[str]:
        """The relay-internal strings the gate lets through."""
        return frozenset({self.hook, self.binding})

    def emit(self, **obj: Any) -> None:
        """One JSON event line on stdout (``-E``); a closed pipe ends the relay."""
        if not self.events:
            return
        try:
            print(json.dumps(obj), flush=True)
        except (BrokenPipeError, OSError):
            self.finish("the guided login stopped listening", 1)

    def finish(self, reason: str, code: int = 0) -> None:
        """Record the first exit reason and stop the relay."""
        if not self.done.is_set():
            self.exit_reason, self.exit_code = reason, code
            self.done.set()

    async def call(self, method: str, session: bool | str = True, **params: Any) -> Any:
        """Send one gated CDP command and await its result.

        ``session=True`` → the shown target's session, a str → that session,
        False → the browser target.
        """
        if not method_allowed(method, params, self.owned, self.internal):
            raise PermissionError(f"CDP method not allowed: {method}")
        self._next_id += 1
        mid = self._next_id
        msg: dict[str, Any] = {"id": mid, "method": method, "params": params}
        if session is True:
            msg["sessionId"] = self.session_id
        elif session:
            msg["sessionId"] = session
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
        self.owned.append(self.target_id)
        self.session_id = await self._adopt(self.target_id)

    async def _adopt(self, tid: str) -> str:
        """Attach to owned `tid`; install the surface hook; make it render."""
        res = await self.call(
            "Target.attachToTarget", session=False, targetId=tid, flatten=True
        )
        sid = str(res["sessionId"])
        self.sessions[tid] = sid
        await self.call("Page.enable", session=sid)
        await self.call("Inspector.enable", session=sid)
        await self.call("Runtime.enable", session=sid)
        await self.call("Runtime.addBinding", session=sid, name=self.binding)
        await self.call(
            "Page.addScriptToEvaluateOnNewDocument", session=sid, source=self.hook
        )
        try:  # the document that is already loaded gets the hook too
            await self.call("Runtime.evaluate", session=sid, expression=self.hook)
        except (RuntimeError, asyncio.TimeoutError):
            pass
        # A background-created tab is "hidden" and renders no frames (Page.startScreencast
        # then never answers). Focus emulation makes it visible to THIS session only —
        # no window is shown or raised.
        await self.call("Emulation.setFocusEmulationEnabled", session=sid, enabled=True)
        await self._apply_viewport(sid)
        return sid

    async def _apply_viewport(self, sid: str) -> None:
        """Size target `sid`'s viewport to the viewer's canvas (CSS pixels)."""
        if self.dims is None:
            return
        cw, ch = self.dims[0], self.dims[1]
        await self.call(
            "Emulation.setDeviceMetricsOverride",
            session=sid,
            width=cw,
            height=ch,
            deviceScaleFactor=0,
            mobile=False,
        )

    async def _start_screencast(self) -> None:
        if self.dims is None:
            return
        await self.call(
            "Page.startScreencast",
            format="jpeg",
            quality=self.quality,
            maxWidth=self.dims[2],
            maxHeight=self.dims[3],
            everyNthFrame=1,
        )

    async def show(self, tid: str) -> None:
        """Switch the viewer to owned target `tid` (stops the old screencast)."""
        if tid == self.target_id or tid not in self.sessions:
            return
        if self.viewer is not None:
            try:
                await self.call("Page.stopScreencast")
            except (RuntimeError, asyncio.TimeoutError):
                pass
        self.target_id, self.session_id = tid, self.sessions[tid]
        if self.viewer is not None:
            try:
                await self._apply_viewport(self.session_id)
                await self._start_screencast()
            except (RuntimeError, asyncio.TimeoutError) as e:
                print(f"❌ cannot show target {tid}: {e}", file=sys.stderr)
            pending = self.dialogs.get(self.session_id)
            if pending:
                await self._to_viewer({"t": "dialog", **pending})

    async def close(self) -> None:
        """Close the targets the relay created (never adopted ones), then CDP."""
        if self.created and self._cdp is not None:
            for tid in list(self.owned):
                try:
                    await self.call("Target.closeTarget", session=False, targetId=tid)
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

    def _tid_of(self, sid: Any) -> str | None:
        return next((t for t, s in self.sessions.items() if s == sid), None)

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
        sid = msg.get("sessionId")
        ours = sid is not None and self._tid_of(sid) is not None
        if method == "Page.screencastFrame" and ours and sid == self.session_id:
            if self.viewer is not None:
                frame = {
                    "t": "frame",
                    "data": params["data"],
                    "meta": params["metadata"],
                    "sid": params["sessionId"],
                    "rt": time.time() * 1000,
                }
                await self._to_viewer(frame)
        elif method in _SUPERVISOR_EVENTS or ours:
            # Handlers send CDP commands and await their answers, which only
            # THIS reader can deliver: run them as tasks, never inline.
            task = asyncio.create_task(self._on_event(method, params, sid, ours))
            self._tasks.add(task)
            task.add_done_callback(self._tasks.discard)

    async def _on_event(
        self, method: str, params: dict[str, Any], sid: Any, ours: bool
    ) -> None:
        """Target supervisor and owned-session events (runs as its own task)."""
        try:
            if method == "Target.targetCreated":
                await self._maybe_popup(params.get("targetInfo", {}))
            elif method == "Target.targetDestroyed":
                await self._owned_gone(str(params.get("targetId", "")))
            elif method == "Target.detachedFromTarget":
                await self._detached(params.get("sessionId"))
            elif ours:
                await self._on_session_event(method, params, str(sid))
        except Exception as e:  # pylint: disable=broad-exception-caught
            print(f"❌ relay event {method} failed: {e}", file=sys.stderr)

    async def _on_session_event(
        self, method: str, params: dict[str, Any], sid: str
    ) -> None:
        """Events of an owned target's session: crash, surfaces, dialogs."""
        if method == "Inspector.targetCrashed" and sid == self.session_id:
            await self._end("the login tab crashed")
        elif method == "Runtime.bindingCalled" and params.get("name") == self.binding:
            try:
                data = json.loads(str(params.get("payload", "")))
            except ValueError:
                data = {}
            kind = str(data.get("k", "")) if isinstance(data, dict) else ""
            detail = str(data.get("d", ""))[:40] if isinstance(data, dict) else ""
            if kind in ("webauthn", "permission"):
                await self.surface(kind, detail)
        elif method == "Page.frameRequestedNavigation":
            scheme = external_scheme(params.get("url"))
            if scheme:
                await self.surface("external", f"{scheme}:")
        elif method == "Page.javascriptDialogOpening":
            info = {
                "type": str(params.get("type", "alert"))[:20],
                "message": str(params.get("message", ""))[:500],
                "prompt": str(params.get("defaultPrompt", ""))[:200],
            }
            self.dialogs[sid] = info
            tid = self._tid_of(sid)
            if tid and tid != self.target_id:
                await self.show(tid)
            else:
                await self._to_viewer({"t": "dialog", **info})
        elif method == "Page.javascriptDialogClosed":
            self.dialogs.pop(sid, None)
            if sid == self.session_id:
                await self._to_viewer({"t": "dialog-closed"})

    async def surface(self, kind: str, detail: str = "") -> None:
        """End the remote view: this login needs a real window (exit 5)."""
        if self.done.is_set():
            return
        reason = surface_reason(kind, detail)
        print(f"⚠ {reason} — the remote view cannot do this", file=sys.stderr)
        self.emit(ev="surface", reason=reason)
        await self._to_viewer(
            {
                "t": "info",
                "text": f"{reason}: switch to the terminal to continue",
                "end": True,
            }
        )
        self.finish(reason, EXIT_FALLBACK)

    async def _maybe_popup(self, ti: dict[str, Any]) -> None:
        recent = (
            self.viewer is not None
            and time.monotonic() - self.last_input < POPUP_FOCUS_WINDOW_S
        )
        action = popup_decision(ti, self.owned, recent)
        tid = str(ti.get("targetId", ""))
        if action == "ignore":
            return
        if action == "report":
            # Terminal + transaction only: in practice browser.py's own
            # background `logged-in` probe tab, nothing the human must see.
            print(
                f"ℹ️  popup target {tid} (opener=unknown) — not owned, not shown",
                file=sys.stderr,
            )
            self.emit(ev="popup_unowned", target=tid)
            return
        # Only followed popups count: probe tabs must not use up the cap.
        if len(self.popups) >= MAX_POPUPS:
            return
        self.popups.append(tid)
        opener = str(ti.get("openerId", ""))
        self.owned.append(tid)
        self.openers[tid] = opener
        self.emit(ev="owned", target=tid, opener=opener)
        try:
            await self._adopt(tid)
        except (RuntimeError, PermissionError, KeyError, asyncio.TimeoutError) as e:
            print(f"❌ cannot attach to the popup {tid}: {e}", file=sys.stderr)
            return
        await self.show(tid)
        await self._to_viewer({"t": "info", "text": "showing a popup of the login tab"})

    async def _owned_gone(self, tid: str) -> None:
        if tid not in self.owned:
            return
        nxt = view_after_close(tid, self.target_id, self.owned, self.openers)
        self.owned.remove(tid)
        sid = self.sessions.pop(tid, None)
        if sid is not None:
            self.dialogs.pop(sid, None)
        self.emit(ev="released", target=tid)
        if nxt is None:
            await self._end("the login tab was closed")
        elif tid == self.target_id:
            self.target_id = ""  # force the switch
            await self.show(nxt)
            await self._to_viewer({"t": "info", "text": "back to the login tab"})

    async def _detached(self, sid: Any) -> None:
        """A session went away: a closing popup (fine) or the relay was cut off."""
        tid = self._tid_of(sid)
        if tid is None:
            return
        await asyncio.sleep(0.5)  # targetDestroyed follows a closing tab
        if tid not in self.owned:
            return
        try:
            targets = await asyncio.to_thread(_http_json, f"{self.cdp_http}/json/list")
        except (OSError, ValueError):
            targets = []
        if any(t.get("id") == tid for t in targets):
            await self._end("the relay was detached from the login tab")
        else:
            await self._owned_gone(tid)

    async def _end(self, reason: str) -> None:
        await self._to_viewer({"t": "info", "text": reason, "end": True})
        self.finish(reason, 1)

    async def _to_viewer(self, obj: dict[str, Any]) -> None:
        if self.viewer is not None:
            if obj.get("end"):
                self.end_sent = True
            try:
                await self.viewer.send(json.dumps(obj))
            except Exception:  # pylint: disable=broad-exception-caught
                pass

    async def final_word(self) -> None:
        """Tell a connected view why it ends (once; the page keeps that text)."""
        if not self.end_sent:
            text = f"{self.exit_reason} — see the terminal"
            await self._to_viewer({"t": "info", "text": text, "end": True})

    async def poll_maintenance(self) -> None:
        """``-M``: end with the guided login — gone/dead owner, or succeeded."""
        if self.maint_file is None:
            return
        state, site = await asyncio.to_thread(
            maintenance_poll, self.maint_file, self.maint_nonce
        )
        if state == "gone":
            self.finish("the guided login ended")
        elif state == MAINT_SUCCEEDED:
            text = success_text(site)
            await self._to_viewer({"t": "info", "text": text, "end": True})
            self.finish(f"logged in to {site}")

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

    async def _set_dims(self, msg: dict[str, Any], restart: bool) -> None:
        """Viewer canvas size → target viewport + screencast size."""
        w = int(_num(msg.get("w"), 200, 4096) or 1280)
        h = int(_num(msg.get("h"), 200, 4096) or 800)
        cw = int(_num(msg.get("cw"), 200, 4096) or w)
        ch = int(_num(msg.get("ch"), 200, 4096) or h)
        self.dims = (cw, ch, w, h)
        if restart:
            try:
                await self.call("Page.stopScreencast")
            except (RuntimeError, asyncio.TimeoutError):
                pass
        await self._apply_viewport(self.session_id)
        await self._start_screencast()
        pending = self.dialogs.get(self.session_id)
        if pending:
            await self._to_viewer({"t": "dialog", **pending})

    async def _answer_dialog(self, msg: dict[str, Any]) -> None:
        if self.session_id not in self.dialogs:
            return
        text = msg.get("text", "")
        await self.call(
            "Page.handleJavaScriptDialog",
            accept=msg.get("accept") is True,
            promptText=text[:MAX_TEXT] if isinstance(text, str) else "",
        )

    async def _handle_message(self, raw: Any) -> None:
        """One viewer frame -> at most one allowlisted CDP call; never raises on input."""
        msg = parse_message(raw)
        if msg is None:
            return
        try:
            kind = msg.get("t")
            if kind in ("hello", "resize"):
                await self._set_dims(msg, restart=kind == "resize")
                return
            if kind == "dialog":
                await self._answer_dialog(msg)
                return
            if kind == "fallback":
                await self.surface("requested")
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
        self.emit(ev="viewer", connected=True)
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
            self.emit(ev="viewer", connected=False)
            print(
                f"ℹ️  viewer disconnected — the same tab may reconnect within "
                f"{RECONNECT_GRACE_S:.0f}s, then the token is burned",
                file=sys.stderr,
            )

    async def lifecycle_watch(self) -> None:
        """Exit once the token is burned, after ``idle_timeout`` s with no viewer,
        or (``-M``, every MAINT_POLL_S) once the guided login's record is gone,
        its owner died, or the owner marked the login succeeded."""
        while not self.done.is_set():
            await asyncio.sleep(MAINT_POLL_S)
            await self.poll_maintenance()
            if self.done.is_set():
                continue
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
#fb{float:right;margin-top:3px;font:12px system-ui,sans-serif}
#dlg{display:none;position:absolute;top:34px;left:50%;transform:translateX(-50%);z-index:2;background:#303134;border:1px solid #888;padding:12px;max-width:80%}
#dlg p{white-space:pre-wrap;margin:0 0 8px}
</style></head><body>
<div id="bar">Guided login — click into the page and type; paste works. <span id="st"></span><button id="fb" type="button">Use a window instead</button></div>
<div id="dlg"><p id="dmsg"></p><input id="dval" type="text"><button id="dok" type="button">OK</button> <button id="dno" type="button">Cancel</button></div>
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
const dims = () => ({w: Math.round(innerWidth * devicePixelRatio), h: Math.round((innerHeight - 26) * devicePixelRatio),
  cw: Math.round(innerWidth), ch: Math.round(innerHeight - 26)});
ws.onopen = () => { st.textContent = "connected"; send(Object.assign({t: "hello"}, dims())); };
let rz = null;
addEventListener("resize", () => { clearTimeout(rz); rz = setTimeout(() => send(Object.assign({t: "resize"}, dims())), 250); });
const dlg = document.getElementById("dlg"), dmsg = document.getElementById("dmsg"), dval = document.getElementById("dval");
function answer(accept) { send({t: "dialog", accept, text: dval.value}); dlg.style.display = "none"; ta.focus(); }
document.getElementById("dok").addEventListener("click", () => answer(true));
document.getElementById("dno").addEventListener("click", () => answer(false));
document.getElementById("fb").addEventListener("click", () => send({t: "fallback"}));
ws.onclose = () => { if (!ended) st.textContent = "disconnected — reload within 10 s to reconnect; if the login already finished, check the terminal"; };
ws.onmessage = ev => {
  const m = JSON.parse(ev.data);
  if (m.t === "info") { window.__viewerStats.info.push(m); if (!ended) st.textContent = m.text; if (m.end) ended = true; return; }
  if (m.t === "dialog") { dmsg.textContent = m.type + ": " + m.message; dval.value = m.prompt || "";
    dval.style.display = m.type === "prompt" ? "" : "none"; dlg.style.display = "block"; return; }
  if (m.t === "dialog-closed") { dlg.style.display = "none"; return; }
  if (m.t !== "frame") return;
  const now = Date.now(), img = new Image();
  img.onload = () => {
    if (cv.width !== img.naturalWidth || cv.height !== img.naturalHeight) { cv.width = img.naturalWidth; cv.height = img.naturalHeight; }
    ctx.drawImage(img, 0, 0); meta = m.meta; window.__viewerStats.meta = m.meta;
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
            "  login_viewer.py -c http://127.0.0.1:9333 -t 1A2B... -A  # `open -N` id\n\n"
            "exit codes: 0 ended normally, 1 error/idle timeout, 2 refused,\n"
            "  5 this login needs a real window (a surface the view cannot show)"
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
    p.add_argument(
        "-E",
        "--events",
        action="store_true",
        help="then one JSON event per line on stdout (owned/released/viewer/"
        "surface/end) — for browser.py assisted-login",
    )
    p.add_argument(
        "-M",
        "--maintenance",
        type=Path,
        default=None,
        help="the guided login's maintenance record: refuse without its owner "
        "token ($CLAUDE_BROWSER_MAINTENANCE), exit once it is gone",
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
        events=a.events,
        maint_file=a.maintenance,
        maint_nonce=os.environ.get(MAINTENANCE_ENV, ""),
    )
    _stop_on_signals(relay)
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
            await relay.final_word()  # before the server closes the socket
    finally:
        await relay.close()
    mark = "✅" if relay.exit_code == 0 else "❌"
    print(f"{mark} viewer relay ended: {relay.exit_reason}", file=sys.stderr)
    relay.emit(ev="end", reason=relay.exit_reason, code=relay.exit_code)
    return relay.exit_code


def _stop_on_signals(relay: Relay) -> None:
    """SIGTERM (the transaction's `_stop_viewer`, forwarded by register-exec)
    and SIGINT end the relay through `finish`, so a connected view still gets
    its final line instead of a bare "disconnected"."""
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(
                sig, relay.finish, "the guided login stopped the view", 128 + sig
            )
        except (NotImplementedError, RuntimeError, ValueError):
            pass  # not the main thread / no signal support: default handling


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
    if a.maintenance is not None:
        err = maintenance_error(a.maintenance, os.environ.get(MAINTENANCE_ENV, ""))
        if err:
            print(f"❌ {err}", file=sys.stderr)
            return 2
    bootstrap_venv()  # may re-exec under <repo>/.venv
    try:
        return asyncio.run(_amain(a))
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
