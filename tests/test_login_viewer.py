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
import importlib.util
import sys
from pathlib import Path

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
    }


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
