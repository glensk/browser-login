"""Login page that also carries a REGISTER form (WeLib ``/account``, 2026-10-08).

WeLib shows a Register form (``reg_email``, ``nickname``, ``reg_password`` —
the password input turned into ``type=password`` by a script) BEFORE the Log
in form (``input#email``, ``input#password autocomplete=current-password``,
posting to ``/account/``). The generic recipe took the first visible password
field — the registration one — and its username next to it (``nickname``).
The layout is reproduced here; no real site is contacted.

Hermetic by default (descriptor dicts, as ``FIELD_DESCRIBE_JS`` returns them).
The real-browser test (`-m browser`, opt-in via LOGIN_BROKER_E2E=1) logs into
a local WeLib-like fixture site with a throwaway headless Chromium through the
broker daemon and asserts nothing was ever typed into the register form.

Run: uv run --no-sync pytest tests/test_register_form.py
"""

from __future__ import annotations

# pylint: disable=protected-access,import-outside-toplevel,too-few-public-methods
# pylint: disable=missing-function-docstring,missing-class-docstring,import-error
# pylint: disable=redefined-outer-name,wrong-import-position
import contextlib
import http.server
import json
import os
import shutil
import socket
import sys
import tempfile
import threading
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from broker import daemon, limiter, login_form, vault  # noqa: E402

EMAIL = "alice@example.com"
PASSWORD = "pw-W3libTest!"  # fixture value, never a real one
SESSION = "sess-welib-0123"

# ---------------------------------------------------------------------------
# A. the pure rules on descriptors (what FIELD_DESCRIBE_JS returns)
# ---------------------------------------------------------------------------


def _desc(**kw: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "type": "password",
        "name": "password",
        "id": "password",
        "autocomplete": "",
        "form": True,
        "form_action": "/login",
        "form_id": "",
        "form_class": "",
        "form_name": "",
        "form_passwords": 1,
        "form_confirm": False,
    }
    base.update(kw)
    return base


# WeLib as served: register password first (no autocomplete), login second.
WELIB_REGISTER_PW = _desc(
    name="reg_password", id="reg_password", form_action="/account/"
)
WELIB_LOGIN_PW = _desc(autocomplete="current-password", form_action="/account/")


@pytest.mark.parametrize(
    "desc",
    [
        WELIB_REGISTER_PW,
        _desc(autocomplete="new-password"),
        _desc(name="signupPassword", id="signupPassword"),
        _desc(name="registerPassword", id=""),
        _desc(name="new_password", id=""),
        _desc(form_action="/account/register"),
        _desc(form_id="signup-form", form_action="/account/"),
        _desc(form_class="registration form", form_action="/account/"),
        _desc(form_name="regForm", form_action="/account/"),
        _desc(form_passwords=2),
        _desc(form_confirm=True),
    ],
)
def test_registration_field_like(desc):
    assert login_form.registration_field_like(desc)


@pytest.mark.parametrize(
    "desc",
    [
        WELIB_LOGIN_PW,
        _desc(),
        _desc(form=False, form_action="", form_passwords=0),
        _desc(name="pass", id="i0116"),  # Microsoft-style ids
        _desc(form_action="/login?next=/register"),  # names the login too
        _desc(form_class="login-or-signup"),
        _desc(name="renewal_password"),  # "new" inside a word is no token
        _desc(form_action="/regional/login"),
        _desc(form_action="/newsletter"),
    ],
)
def test_login_field_not_registration(desc):
    assert not login_form.registration_field_like(desc)


def test_current_password_wins_even_after_registration():
    assert login_form.pick_login_password([WELIB_REGISTER_PW, WELIB_LOGIN_PW]) == 1


def test_current_password_wins_over_an_untagged_first_field():
    assert login_form.pick_login_password([_desc(), WELIB_LOGIN_PW]) == 1


def test_untagged_login_after_registration_is_picked():
    login = _desc(form_action="/account/")
    assert login_form.pick_login_password([WELIB_REGISTER_PW, login]) == 1


def test_single_untagged_password_unchanged():
    assert login_form.pick_login_password([_desc()]) == 0


def test_only_registration_fields_pick_nothing():
    assert login_form.pick_login_password([WELIB_REGISTER_PW]) is None
    assert login_form.pick_login_password([]) is None


def test_username_skips_registration_email():
    reg_email = _desc(type="email", name="reg_email", id="reg_email", form_passwords=1)
    login_email = _desc(type="email", name="email", id="email", form_action="/account/")
    assert login_form.pick_login_username([reg_email, login_email]) == 1
    assert login_form.pick_login_username([reg_email]) is None


# ---------------------------------------------------------------------------
# B. real headless Chromium against a WeLib-like fixture site
# ---------------------------------------------------------------------------

# Every input event in the register form is reported to /typed (field name
# only), so the test can prove the broker never typed there.
_REGISTER_FORM = (
    "<h2>Register</h2>"
    "<form id=register method=post action=/account/>"
    "<input type=email name=reg_email id=reg_email placeholder=Email>"
    "<input type=text name=nickname id=nickname placeholder=Nickname>"
    "<input type=text name=reg_password id=reg_password autocomplete=off>"
    "<button type=submit>Register</button></form>"
)


def _login_form(current_password: bool) -> str:
    auto = " autocomplete=current-password" if current_password else ""
    return (
        "<h2>Log in</h2>"
        "<form id=login method=post action=/account/>"
        "<input type=email name=email id=email>"
        f"<input type=password name=password id=password{auto}>"
        "<button type=submit>Log in</button></form>"
    )


_SCRIPT = (
    "<script>"
    "document.getElementById('reg_password').type = 'password';"
    "for (const i of document.querySelectorAll('#register input')) {"
    "  i.addEventListener('input', () => fetch('/typed', {method: 'POST',"
    "    body: i.name, keepalive: true}));"
    "}"
    "</script>"
)


class _WelibApp(http.server.BaseHTTPRequestHandler):
    current_password = True
    typed: list[str] = []  # register-form input names that received input
    logins: list[bool] = []  # one entry per login-form POST: valid?
    registrations: int = 0  # register-form POSTs

    def log_message(self, *args):
        return

    def _send(self, code, body="", headers=()):
        self.send_response(code)
        for k, v in headers:
            self.send_header(k, v)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body.encode())

    def _body(self) -> str:
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n).decode()

    def do_GET(self):  # noqa: N802
        cls = type(self)
        if self.path.startswith("/account"):
            if f"session={SESSION}" in (self.headers.get("Cookie") or ""):
                self._send(200, "<html><body><h1 id=welcome>Library</h1></body></html>")
                return
            self._send(
                200,
                "<html><head><title>Account</title></head><body>"
                + _REGISTER_FORM
                + _login_form(cls.current_password)
                + _SCRIPT
                + "</body></html>",
            )
            return
        self._send(404, "nope")

    def do_POST(self):  # noqa: N802
        cls = type(self)
        body = self._body()
        if self.path == "/typed":
            cls.typed.append(body)
            self._send(204)
            return
        if self.path.startswith("/account"):
            q = parse_qs(body)
            if {"reg_email", "nickname", "reg_password"} & set(q):
                cls.registrations += 1
                self._send(200, "<html><body>registered?</body></html>")
                return
            ok = q.get("email") == [EMAIL] and q.get("password") == [PASSWORD]
            cls.logins.append(ok)
            if ok:
                cookie = f"session={SESSION}; Path=/; Max-Age=3600; HttpOnly"
                self._send(
                    302, headers=[("Location", "/account"), ("Set-Cookie", cookie)]
                )
            else:
                self._send(302, headers=[("Location", "/account?err=1")])
            return
        self._send(404, "nope")


@contextlib.contextmanager
def _server(current_password: bool):
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _WelibApp)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    _WelibApp.current_password = current_password
    _WelibApp.typed, _WelibApp.logins, _WelibApp.registrations = [], [], 0
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}"
    finally:
        srv.shutdown()
        srv.server_close()


def _ask(path: str, obj: dict[str, Any]) -> dict[str, Any]:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(120)
        s.connect(path)
        s.sendall(json.dumps(obj).encode() + b"\n")
        chunks: list[bytes] = []
        while not chunks or not chunks[-1].endswith(b"\n"):
            chunk = s.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
    reply: dict[str, Any] = json.loads(b"".join(chunks))
    return reply


@pytest.mark.browser
@pytest.mark.skipif(
    os.environ.get("LOGIN_BROKER_E2E") != "1", reason="set LOGIN_BROKER_E2E=1"
)
@pytest.mark.parametrize(
    "current_password", [True, False], ids=["current-password", "untagged"]
)
def test_e2e_login_form_beside_register_form(tmp_path, current_password):
    sockdir = Path(tempfile.mkdtemp(prefix="lb-"))  # AF_UNIX path length cap
    try:
        with _server(current_password) as origin:
            item = {
                "id": "id-welibx",
                "name": "WelibLike",
                "login": {"username": EMAIL, "password": PASSWORD},
                "fields": [
                    {"name": k, "value": v, "type": 0}
                    for k, v in {
                        "agent_site": "weliblike",
                        "agent_fill_origins": origin,
                        "agent_check_url": origin + "/account",
                        "agent_logged_in_selector": "#welcome",
                    }.items()
                ],
            }
            fixture = tmp_path / "items.json"
            fixture.write_text(json.dumps([item]))
            home = tmp_path / "home"
            brk = daemon.Broker(
                vault.FixtureVault(fixture, dev=True),
                limiter.Limiter(home / "limiter.json", 0, 100, 100),
                home,
                runner=daemon.PlaywrightRunner(home, dev=True),
            )
            path = str(sockdir / "b.sock")
            srv = daemon.make_server(path, brk, os.getuid())
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            try:
                result = _ask(path, {"op": "login", "site": "weliblike"})
            finally:
                srv.shutdown()
                srv.server_close()
    finally:
        shutil.rmtree(sockdir, ignore_errors=True)
    assert result["ok"], result
    assert result["bundle"]["via"] == "login"
    assert [(c["name"], c["value"]) for c in result["bundle"]["cookies"]] == [
        ("session", SESSION)
    ]
    assert _WelibApp.logins == [True]  # one login-form submit, valid
    assert _WelibApp.registrations == 0
    assert not _WelibApp.typed  # nothing ever typed into the register form
    flat = json.dumps(result)
    assert PASSWORD not in flat
