"""Unit tests for bin/login_viewer.py's pure gatekeeping and key mapping.

Pinned here:

* only the allowlisted CDP methods ever leave the relay, Target.* only for the
  owned target id;
* the relay's HTTP/WS endpoint rejects a wrong token, a foreign Host (DNS
  rebinding), a foreign or missing WebSocket Origin and a cross-site fetch;
* non-text keys map to CDP key events WITHOUT ``nativeVirtualKeyCode`` (on macOS
  that field stalls headless Chrome), clipboard shortcuts are never forwarded,
  and viewer messages are validated before they become CDP calls.

Run: python3 -m pytest tests/ -q     (from the repo root)
"""

from __future__ import annotations

# The allowlist pin repeats the module's set on purpose (duplicate-code).
# pylint: disable=missing-function-docstring,import-error,duplicate-code
import asyncio
import importlib.util
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

import pytest

_VIEWER_PY = Path(__file__).resolve().parent.parent / "bin" / "login_viewer.py"


def _load():
    spec = importlib.util.spec_from_file_location("login_viewer_under_test", _VIEWER_PY)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["login_viewer_under_test"] = mod
    spec.loader.exec_module(mod)
    return mod


lv = _load()
OWNED = "OWNED0000"
PORT = 45678


@pytest.mark.parametrize(
    "method",
    [
        "Input.dispatchMouseEvent",
        "Input.dispatchKeyEvent",
        "Input.insertText",
        "Input.imeSetComposition",
        "Page.startScreencast",
        "Page.stopScreencast",
        "Page.screencastFrameAck",
        "Inspector.enable",
        "Page.enable",
        "Target.setDiscoverTargets",
    ],
)
def test_allowlisted_methods_pass(method):
    assert lv.method_allowed(method, {}, OWNED)


@pytest.mark.parametrize(
    "method",
    [
        "Runtime.evaluate",
        "Network.getCookies",
        "Storage.getCookies",
        "Page.navigate",
        "Target.createTarget",
        "Target.activateTarget",
        "Page.getLayoutMetrics",
        "Target.exposeDevToolsProtocol",
        "Browser.close",
        "Input.dispatchDragEvent",
        "",
    ],
)
def test_other_methods_are_refused(method):
    assert not lv.method_allowed(method, {"targetId": OWNED}, OWNED)


def test_target_methods_only_for_owned_id():
    assert lv.method_allowed("Target.attachToTarget", {"targetId": OWNED}, OWNED)
    assert not lv.method_allowed("Target.attachToTarget", {"targetId": "OTHER"}, OWNED)
    assert lv.method_allowed("Target.closeTarget", {"targetId": OWNED}, OWNED)
    assert not lv.method_allowed("Target.closeTarget", {"targetId": "OTHER"}, OWNED)
    assert not lv.method_allowed("Target.closeTarget", {}, "")
    assert lv.method_allowed("Target.setDiscoverTargets", {"discover": True}, OWNED)


def test_create_target_only_before_the_relay_owns_one():
    assert lv.method_allowed("Target.createTarget", {"url": "https://x"}, "")
    assert not lv.method_allowed("Target.createTarget", {"url": "https://x"}, OWNED)


def test_allowlist_is_exactly_what_the_relay_sends():
    assert lv.ALLOWED_METHODS == {
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
        # Phase 3: viewport, dialogs, the surface hook (gated, see below).
        "Emulation.setDeviceMetricsOverride",
        "Page.handleJavaScriptDialog",
        "Runtime.enable",
        "Runtime.addBinding",
        "Runtime.evaluate",
        "Page.addScriptToEvaluateOnNewDocument",
    }


def test_internal_calls_carry_only_the_relays_own_strings():
    hook = lv.hook_source("__lvX")
    internal = {hook, "__lvX"}
    assert lv.method_allowed("Runtime.evaluate", {"expression": hook}, OWNED, internal)
    assert not lv.method_allowed(
        "Runtime.evaluate", {"expression": "document.cookie"}, OWNED, internal
    )
    assert not lv.method_allowed("Runtime.evaluate", {"expression": hook}, OWNED)
    assert lv.method_allowed("Runtime.addBinding", {"name": "__lvX"}, OWNED, internal)
    assert not lv.method_allowed("Runtime.addBinding", {"name": "x"}, OWNED, internal)
    assert lv.method_allowed(
        "Page.addScriptToEvaluateOnNewDocument", {"source": hook}, OWNED, internal
    )
    assert not lv.method_allowed(
        "Page.addScriptToEvaluateOnNewDocument", {"source": "evil()"}, OWNED, internal
    )


def test_target_calls_accept_every_owned_id_and_no_other():
    owned = ["ROOT", "POPUP"]
    for tid in owned:
        assert lv.method_allowed("Target.attachToTarget", {"targetId": tid}, owned)
    assert not lv.method_allowed("Target.attachToTarget", {"targetId": "X"}, owned)
    assert not lv.method_allowed("Target.createTarget", {"url": "https://x"}, owned)


@pytest.mark.parametrize(
    ("info", "owned", "recent", "want"),
    [
        ({"targetId": "P", "type": "page", "openerId": "R"}, ["R"], False, "follow"),
        (
            {"targetId": "P", "type": "page", "openerId": "Q"},
            ["R", "Q"],
            False,
            "follow",
        ),
        ({"targetId": "P", "type": "page", "openerId": "Z"}, ["R"], True, "ignore"),
        ({"targetId": "P", "type": "page"}, ["R"], True, "report"),
        ({"targetId": "P", "type": "page"}, ["R"], False, "ignore"),
        ({"targetId": "P", "type": "iframe", "openerId": "R"}, ["R"], False, "ignore"),
        ({"targetId": "R", "type": "page", "openerId": "R"}, ["R"], False, "ignore"),
        ({"type": "page", "openerId": "R"}, ["R"], False, "ignore"),
    ],
)
def test_popup_decision(info, owned, recent, want):
    assert lv.popup_decision(info, owned, recent) == want


def test_view_after_close():
    openers = {"P1": "R", "P2": "P1"}
    owned = ["R", "P1", "P2"]
    assert lv.view_after_close("P2", "P2", owned, openers) == "P1"  # back to opener
    assert lv.view_after_close("P1", "P2", owned, openers) == "P2"  # not shown
    assert lv.view_after_close("P2", "P2", ["R", "P2"], openers) == "R"  # opener gone
    assert lv.view_after_close("R", "R", ["R"], {}) is None  # the login tab: end
    assert lv.view_after_close("R", "R", ["R", "P1"], openers) == "P1"


@pytest.mark.parametrize(
    ("url", "want"),
    [
        ("zoommtg://join?x=1", "zoommtg"),
        ("msteams:/l/meetup", "msteams"),
        ("https://example.org/", None),
        ("about:blank", None),
        ("data:text/html,x", None),
        ("javascript:void(0)", None),
        ("chrome-error://chromewebdata/", None),
        ("", None),
        (None, None),
    ],
)
def test_external_scheme(url, want):
    assert lv.external_scheme(url) == want


def test_surface_reasons_are_named():
    assert "passkey" in lv.surface_reason("webauthn", "get")
    assert "permission" in lv.surface_reason("permission", "getUserMedia")
    assert "external app" in lv.surface_reason("external", "zoommtg:")
    assert lv.surface_reason("requested") == "you asked for a visible window"


def test_hook_ignores_conditional_mediation_and_hides_the_binding():
    src = lv.hook_source("__lvABC")
    assert "mediation !== 'conditional'" in src
    assert 'delete globalThis["__lvABC"]' in src


def test_maintenance_gate(tmp_path):
    rec = tmp_path / "maintenance.json"
    assert "no maintenance record" in (lv.maintenance_error(rec, "n") or "")
    rec.write_text('{"owner_nonce": "abc", "pid": 1}', encoding="utf-8")
    assert "owner" in (lv.maintenance_error(rec, "zzz") or "")
    assert "owner" in (lv.maintenance_error(rec, "") or "")
    assert lv.maintenance_error(rec, "abc") is None
    rec.write_text('{"owner_nonce": "abc", "pid": 999999999}', encoding="utf-8")
    assert not lv.owner_alive(rec, "abc")  # owner pid gone → the relay ends


def test_main_refuses_without_the_owner_token(tmp_path, monkeypatch, capsys):
    rec = tmp_path / "maintenance.json"
    rec.write_text('{"owner_nonce": "abc", "pid": 1}', encoding="utf-8")
    monkeypatch.delenv("CLAUDE_BROWSER_MAINTENANCE", raising=False)
    argv = ["-c", "http://127.0.0.1:9", "-t", "T", "-A", "-M", str(rec)]
    assert lv.main(argv) == 2
    assert "owner" in capsys.readouterr().err


def test_token_check():
    tok = "a" * 43
    assert lv.token_ok(f"/{tok}/", tok) == (True, "")
    assert lv.token_ok(f"/{tok}/ws", tok) == (True, "ws")
    assert lv.token_ok(f"/{tok}/ws?x=1", tok) == (True, "ws")
    assert not lv.token_ok("/" + "b" * 43 + "/", tok)[0]
    assert not lv.token_ok("/", tok)[0]
    assert not lv.token_ok(f"/{tok[:-1]}/", tok)[0]


def test_origin_check_http():
    own = {"Host": f"127.0.0.1:{PORT}"}
    assert lv.origin_ok(own, PORT, websocket=False)
    assert lv.origin_ok({**own, "Sec-Fetch-Site": "none"}, PORT, websocket=False)
    assert lv.origin_ok(
        {**own, "Origin": f"http://127.0.0.1:{PORT}"}, PORT, websocket=False
    )
    assert not lv.origin_ok({"Host": f"localhost:{PORT}"}, PORT, websocket=False)
    assert not lv.origin_ok({"Host": "evil.example"}, PORT, websocket=False)
    assert not lv.origin_ok(
        {**own, "Origin": "http://evil.example"}, PORT, websocket=False
    )
    assert not lv.origin_ok(
        {**own, "Sec-Fetch-Site": "cross-site"}, PORT, websocket=False
    )


def test_origin_check_websocket():
    own = {"Host": f"127.0.0.1:{PORT}"}
    assert lv.origin_ok(
        {**own, "Origin": f"http://127.0.0.1:{PORT}"}, PORT, websocket=True
    )
    assert not lv.origin_ok(own, PORT, websocket=True)  # missing Origin
    assert not lv.origin_ok(
        {**own, "Origin": f"http://localhost:{PORT}"}, PORT, websocket=True
    )
    assert not lv.origin_ok({**own, "Origin": "null"}, PORT, websocket=True)
    assert not lv.origin_ok(
        {**own, "Origin": "http://127.0.0.1:1"}, PORT, websocket=True
    )


@pytest.mark.parametrize(
    ("key", "vk"),
    [
        ("Tab", 9),
        ("Backspace", 8),
        ("Escape", 27),
        ("ArrowLeft", 37),
        ("Delete", 46),
        ("F5", 116),
    ],
)
def test_named_keys(key, vk):
    down = lv.key_event_params("down", key, "", 0)
    up = lv.key_event_params("up", key, "", 0)
    assert down["type"] == "rawKeyDown" and up["type"] == "keyUp"
    assert down["windowsVirtualKeyCode"] == vk
    assert "nativeVirtualKeyCode" not in down and "nativeVirtualKeyCode" not in up
    assert "text" not in down


def test_enter_carries_text_for_implicit_submit():
    down = lv.key_event_params("down", "Enter", "Enter", 0)
    assert down["type"] == "keyDown" and down["text"] == "\r"
    assert "text" not in lv.key_event_params("down", "Enter", "Enter", lv.MOD_META)


def test_printable_text_is_not_a_key_event():
    assert lv.key_event_params("down", "a", "KeyA", 0) is None
    assert lv.key_event_params("down", "ä", "", 0) is None
    assert lv.key_event_params("down", "a", "KeyA", lv.MOD_SHIFT) is None


def test_shortcuts_and_clipboard_block():
    sel = lv.key_event_params("down", "a", "KeyA", lv.MOD_META)
    assert sel["windowsVirtualKeyCode"] == 65 and sel["code"] == "KeyA"
    if sys.platform == "darwin":
        assert sel["commands"] == ["selectAll"]
    for k in ("v", "c", "x", "V"):
        assert lv.key_event_params("down", k, "", lv.MOD_META) is None
        assert lv.key_event_params("down", k, "", lv.MOD_CTRL) is None


def test_bogus_code_is_replaced():
    p = lv.key_event_params("down", "Tab", "X" * 100, 0)
    assert p["code"] == "Tab"


def test_translate_mouse_and_wheel():
    m, p = lv.translate(
        {
            "t": "mouse",
            "type": "mousePressed",
            "x": 10.5,
            "y": 20,
            "button": "left",
            "clickCount": 1,
        }
    )
    assert m == "Input.dispatchMouseEvent" and p["x"] == 10.5 and p["clickCount"] == 1
    assert lv.translate({"t": "mouse", "type": "mouseDragged", "x": 1, "y": 1}) is None
    assert (
        lv.translate({"t": "mouse", "type": "mouseMoved", "x": float("nan"), "y": 1})
        is None
    )
    assert lv.translate({"t": "mouse", "type": "mouseMoved", "x": "1", "y": 1}) is None
    m, p = lv.translate({"t": "wheel", "x": 1, "y": 2, "deltaY": 1e9})
    assert p["type"] == "mouseWheel" and p["deltaY"] == 10_000


def test_translate_text_ime_ack():
    assert lv.translate({"t": "text", "text": "P@ss wörd€"}) == (
        "Input.insertText",
        {"text": "P@ss wörd€"},
    )
    assert lv.translate({"t": "text", "text": ""}) is None
    assert lv.translate({"t": "text", "text": "x" * (lv.MAX_TEXT + 1)}) is None
    m, p = lv.translate({"t": "ime", "text": "にほ", "selStart": 9, "selEnd": 1})
    assert (
        m == "Input.imeSetComposition" and p["selectionStart"] == p["selectionEnd"] == 2
    )
    assert lv.translate({"t": "ack", "sessionId": 3}) == (
        "Page.screencastFrameAck",
        {"sessionId": 3},
    )
    assert lv.translate({"t": "ack", "sessionId": True}) is None


def test_translate_rejects_raw_cdp():
    assert (
        lv.translate({"method": "Runtime.evaluate", "params": {"expression": "1"}})
        is None
    )
    assert lv.translate({"t": "cdp", "method": "Page.navigate"}) is None
    assert lv.translate(["t", "text"]) is None


def test_every_translation_passes_the_gate():
    samples = [
        {"t": "mouse", "type": "mouseMoved", "x": 1, "y": 1},
        {"t": "wheel", "x": 1, "y": 1, "deltaY": 5},
        {"t": "key", "kind": "down", "key": "Tab", "code": "Tab", "modifiers": 0},
        {"t": "text", "text": "x"},
        {"t": "ime", "text": "x"},
        {"t": "ack", "sessionId": 1},
    ]
    for s in samples:
        method, params = lv.translate(s)
        assert lv.method_allowed(method, params, OWNED), s


def _args(argv):
    return lv._parse_args(argv)  # pylint: disable=protected-access


def test_cli_rejects_non_loopback_cdp(capsys):
    with pytest.raises(SystemExit):
        _args(["-c", "http://localhost:9222", "-u", "https://x.org/"])
    assert "❌" in capsys.readouterr().err
    a = _args(["-c", "http://127.0.0.1:9333/", "-u", "https://x.org/"])
    assert a.cdp == "http://127.0.0.1:9333"


# --- 1: ownership ----------------------------------------------------------------


def test_target_id_without_assume_owned_is_refused(capsys):
    with pytest.raises(SystemExit) as exc:
        _args(["-c", "http://127.0.0.1:9333", "-t", "SOMETAB"])
    assert exc.value.code == 2
    err = capsys.readouterr().err
    assert err.startswith("❌") and "-A/--assume-owned" in err


def test_target_id_with_assume_owned_and_url_mode_pass():
    a = _args(["-c", "http://127.0.0.1:9333", "-t", "SOMETAB", "-A"])
    assert a.target_id == "SOMETAB" and a.assume_owned and a.url is None
    a = _args(["-c", "http://127.0.0.1:9333", "-u", "https://x.org/login"])
    assert a.url == "https://x.org/login" and a.target_id is None


@pytest.mark.parametrize(
    "argv",
    [
        [],
        ["-u", "https://x.org/", "-t", "T", "-A"],
        ["-u", "javascript:alert(1)"],
        ["-u", "file:///etc/passwd"],
        ["-A"],
    ],
)
def test_ownership_refusals(argv):
    with pytest.raises(SystemExit):
        _args(["-c", "http://127.0.0.1:9333", *argv])


# --- 3: one-shot token -------------------------------------------------------------


def _cookie_hdr(auth, value):
    return {"Cookie": f"{auth.cookie_name}={value}"}


def test_first_load_binds_cookie_other_clients_get_404():
    auth = lv.ViewerAuth(PORT)
    status, session = auth.page({}, 0.0)
    assert status == 200 and session
    assert auth.page({}, 1.0) == (404, None)  # second client without the cookie
    assert auth.page(_cookie_hdr(auth, "forged"), 1.0) == (404, None)
    assert auth.page(_cookie_hdr(auth, session), 1.0) == (200, None)  # same tab reload


def test_websocket_needs_the_bound_cookie():
    auth = lv.ViewerAuth(PORT)
    assert auth.websocket({}, 0.0) == 403  # nothing bound yet
    _, session = auth.page({}, 0.0)
    assert auth.websocket({}, 0.0) == 403
    assert auth.websocket(_cookie_hdr(auth, "x" * 43), 0.0) == 403
    assert auth.websocket(_cookie_hdr(auth, session), 0.0) == 0
    auth.on_connect()
    assert auth.websocket(_cookie_hdr(auth, session), 0.0) == 409


def test_token_burns_after_disconnect_grace():
    auth = lv.ViewerAuth(PORT)
    _, session = auth.page({}, 0.0)
    hdr = _cookie_hdr(auth, session)
    auth.on_connect()
    auth.on_disconnect(100.0)
    grace = lv.RECONNECT_GRACE_S
    assert not auth.burned(100.0 + grace - 0.1)
    assert auth.websocket(hdr, 100.0 + grace - 0.1) == 0  # same tab may reconnect
    assert auth.burned(100.0 + grace)
    assert auth.websocket(hdr, 100.0 + grace) == 404
    assert auth.page(hdr, 100.0 + grace) == (404, None)


def test_reconnect_within_grace_cancels_the_burn():
    auth = lv.ViewerAuth(PORT)
    _, session = auth.page({}, 0.0)
    auth.on_connect()
    auth.on_disconnect(10.0)
    auth.on_connect()
    assert not auth.burned(10.0 + 3 * lv.RECONNECT_GRACE_S)
    auth.on_disconnect(50.0)
    assert auth.burned(50.0 + lv.RECONNECT_GRACE_S)
    assert (
        auth.websocket(_cookie_hdr(auth, session), 50.0 + lv.RECONNECT_GRACE_S) == 404
    )


def test_malformed_cookie_header_is_just_unauthenticated():
    auth = lv.ViewerAuth(PORT)
    auth.page({}, 0.0)
    assert auth.websocket({"Cookie": '\x00;;="=;'}, 0.0) == 403


# --- 4: robust parsing -------------------------------------------------------------


@pytest.mark.parametrize(
    "raw",
    [
        "not json",
        "[" * 100_000 + "]" * 100_000,  # RecursionError inside json
        '"just a string"',
        "[1, 2]",
        b"\xff\xfe",
        None,
        12,
    ],
)
def test_parse_message_never_raises(raw):
    assert lv.parse_message(raw) is None


@pytest.mark.parametrize(
    "msg",
    [
        {"t": ["unhashable"]},
        {"t": {"a": 1}},
        {"t": "mouse", "type": ["mousePressed"], "x": 1, "y": 1},
        {"t": "mouse", "type": "mousePressed", "button": {"x": 1}, "x": 1, "y": 1},
        {"t": "mouse", "type": "mouseMoved", "x": 10**400, "y": 1},
        {"t": "wheel", "x": 1, "y": 1, "deltaY": -(10**400)},
        {"t": "key", "kind": "down", "key": ["Tab"], "code": "Tab"},
        {"t": "key", "kind": ["down"], "key": "Tab", "code": {}},
        {"t": "text", "text": ["x"]},
        {"t": "ime", "text": {"x": 1}},
        {"t": "ack", "sessionId": 10**400},
    ],
)
def test_translate_rejects_hostile_shapes_without_raising(msg):
    result = lv.safe_translate(msg)
    if result is not None:  # a huge int ack id is harmless; it must still pass the gate
        assert lv.method_allowed(result[0], result[1], OWNED)
    assert lv.translate({"t": ["unhashable"]}) is None


# --- the end of a guided login in the view -------------------------------------------


class _FakeViewer:
    """A connected viewer socket: records what the relay sends it."""

    def __init__(self) -> None:
        self.sent: list[dict] = []

    async def send(self, data: str) -> None:
        self.sent.append(json.loads(data))


def _relay(**over) -> Any:
    return lv.Relay("http://127.0.0.1:9", "R", "tok", 60, 300.0, **over)


def _record(path: Path, **over) -> None:
    rec = {"owner_nonce": "abc", "pid": os.getpid(), "site": "notion"}
    rec.update(over)
    # Atomic, like the real record: the relay polls it from a worker thread,
    # and a read between write_text's truncate and write sees no record.
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(rec), encoding="utf-8")
    os.replace(tmp, path)


def test_maintenance_poll(tmp_path):
    rec = tmp_path / "maintenance.json"
    assert lv.maintenance_poll(rec, "abc") == ("gone", "")  # no record
    _record(rec, state="active")
    assert lv.maintenance_poll(rec, "abc") == ("live", "")
    assert lv.owner_alive(rec, "abc")
    assert lv.maintenance_poll(rec, "zzz") == ("gone", "")  # another owner's
    _record(rec, state="succeeded")
    assert lv.maintenance_poll(rec, "abc") == ("succeeded", "notion")
    _record(rec, state="succeeded", pid=999999999)
    assert lv.maintenance_poll(rec, "abc") == ("gone", "")  # owner died first


def test_unowned_popup_is_not_shown_in_the_view(capsys):
    """A page target without an opener right after input (in practice
    browser.py's own `logged-in` probe tab): stderr + an event, never the view."""

    async def run() -> list[dict]:
        relay = _relay(events=True, owned=["R"])
        relay.viewer = _FakeViewer()
        relay.last_input = time.monotonic()
        await relay._maybe_popup({"targetId": "P", "type": "page"})
        assert "P" not in relay.owned
        return list(relay.viewer.sent)

    assert not asyncio.run(run())
    out, err = capsys.readouterr()
    assert json.loads(out) == {"ev": "popup_unowned", "target": "P"}
    assert "popup target P (opener=unknown)" in err


def test_success_record_ends_the_view_with_a_final_line(tmp_path, monkeypatch):
    rec = tmp_path / "maintenance.json"
    _record(rec, state="active")
    monkeypatch.setattr(lv, "MAINT_POLL_S", 0.01)

    async def run() -> Any:
        relay = _relay(maint_file=rec, maint_nonce="abc")
        relay.viewer = _FakeViewer()
        watch = asyncio.create_task(relay.lifecycle_watch())
        await asyncio.sleep(0.1)
        assert not relay.done.is_set()  # active: the view stays
        _record(rec, state="succeeded")
        await asyncio.wait_for(watch, 5)
        await relay.final_word()  # already said: no second end line
        return relay

    relay = asyncio.run(run())
    assert relay.done.is_set() and relay.exit_code == 0
    assert relay.viewer.sent == [
        {
            "t": "info",
            "text": "✅ Logged in to notion — you can close this tab",
            "end": True,
        }
    ]


def test_record_gone_ends_the_relay(tmp_path, monkeypatch):
    rec = tmp_path / "maintenance.json"
    _record(rec, state="active")
    monkeypatch.setattr(lv, "MAINT_POLL_S", 0.01)

    async def run() -> Any:
        relay = _relay(maint_file=rec, maint_nonce="abc")
        watch = asyncio.create_task(relay.lifecycle_watch())
        rec.unlink()
        await asyncio.wait_for(watch, 5)
        return relay

    assert asyncio.run(run()).exit_reason == "the guided login ended"


def test_any_other_end_tells_a_connected_view_once():
    async def run() -> Any:
        relay = _relay()
        relay.viewer = _FakeViewer()
        relay.finish("CDP connection lost: OSError", 1)
        await relay.final_word()
        await relay.final_word()
        idle = _relay()
        idle.finish("token burned")
        await idle.final_word()  # no viewer: nothing to tell, no error
        return relay

    relay = asyncio.run(run())
    assert relay.viewer.sent == [
        {
            "t": "info",
            "text": "CDP connection lost: OSError — see the terminal",
            "end": True,
        }
    ]


def test_a_surface_end_is_not_repeated():
    async def run() -> Any:
        relay = _relay()
        relay.viewer = _FakeViewer()
        await relay.surface("requested")
        await relay.final_word()
        return relay

    relay = asyncio.run(run())
    assert len(relay.viewer.sent) == 1 and relay.viewer.sent[0]["end"] is True


def test_viewer_page_keeps_the_final_text_and_explains_a_disconnect():
    html = lv.VIEWER_HTML
    assert "if (!ended) st.textContent = m.text" in html
    assert (
        "disconnected — reload within 10 s to reconnect; if the login already "
        "finished, check the terminal"
    ) in html
