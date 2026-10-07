"""Generic second-factor detection (Infomaniak OTP step, 2026-10-07).

Infomaniak's OTP step carries an input the strong ``OTP_SELECTOR`` misses
(``<input type=tel name=number pattern=[0-9]* maxlength=6 placeholder=000000
autocomplete=off>`` under an ``<h3>`` "OTP connection code") and keeps an idle
reCAPTCHA in a ``<div hidden>`` on every login step, which the challenge check
used to read as a captcha (``needs_human``). Both shapes are reproduced here
from the site's login bundle — no real site is contacted.

Hermetic by default (descriptor dicts, fake pages). The real-browser test
(`-m browser`, opt-in via LOGIN_BROKER_E2E=1) logs into a local Infomaniak-like
fixture site with a throwaway headless Chromium through the broker daemon.

Run: uv run --no-sync pytest tests/test_infomaniak_otp.py
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

import pyotp
import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from broker import daemon, limiter, otp_detect, recipes, vault  # noqa: E402

SEED = "JBSWY3DPEHPK3PXP"  # the RFC/pyotp documentation seed, never a real one
EMAIL = "alice@example.com"
PASSWORD = "pw-Inf0maniakTest!"
SESSION = "sess-infomaniak-0123"

# ---------------------------------------------------------------------------
# A. otp_field_like on descriptors (what _OTP_DESCRIBE_JS returns)
# ---------------------------------------------------------------------------


def _desc(**kw: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "type": "text",
        "name": "",
        "id": "",
        "autocomplete": "",
        "inputmode": "",
        "pattern": "",
        "maxlength": -1,
        "placeholder": "",
        "aria_label": "",
        "title": "",
        "labels": "",
        "context": "",
        "username": False,
    }
    base.update(kw)
    return base


INFOMANIAK = _desc(
    type="tel",
    name="number",
    id="mat-input-2",
    autocomplete="off",
    pattern="[0-9]*",
    maxlength=6,
    placeholder="000000",
    context="OTP connection code\nVALIDATE",
)


@pytest.mark.parametrize(
    "desc",
    [
        INFOMANIAK,
        {**INFOMANIAK, "context": ""},  # shape alone: numeric, 6, "000000"
        {**INFOMANIAK, "context": "Code de connexion OTP"},
        _desc(autocomplete="one-time-code"),
        _desc(name="totp", maxlength=6),
        _desc(name="mfaToken"),
        _desc(aria_label="Authentication code", inputmode="numeric", maxlength=6),
        _desc(inputmode="numeric", maxlength=6, labels="Code"),
        _desc(type="number", placeholder="123 456"),
        _desc(
            context="Enter the 6-digit code from the app on your phone",
            inputmode="numeric",
            maxlength=6,
        ),
    ],
)
def test_otp_field_like_accepts(desc):
    assert otp_detect.otp_field_like(desc)


@pytest.mark.parametrize(
    "desc",
    [
        {**INFOMANIAK, "username": True},
        {**INFOMANIAK, "type": "password"},
        {**INFOMANIAK, "type": "email"},
        # Infomaniak's other methods: TOTP never goes into SMS / backup codes
        {**INFOMANIAK, "context": "Code sent by SMS"},
        _desc(
            type="tel",
            pattern="[0-9]*",
            maxlength=8,
            placeholder="00000000",
            context="Backup code",
        ),
        _desc(
            context="Enter the code we sent to your e-mail",
            inputmode="numeric",
            maxlength=6,
        ),
        _desc(name="zip", inputmode="numeric", maxlength=6, labels="Postal code"),
        _desc(name="promo", maxlength=6, labels="Promo code"),
        _desc(type="tel", name="phone", placeholder="+41 79 123 45 67"),
        _desc(name="q", labels="Search"),
        _desc(name="user", context="Log in"),
        _desc(inputmode="numeric", maxlength=6),  # numeric, but nothing says code
        _desc(autocomplete="username", inputmode="numeric", maxlength=6, labels="Code"),
    ],
)
def test_otp_field_like_rejects(desc):
    assert not otp_detect.otp_field_like(desc)


# ---------------------------------------------------------------------------
# B. a hidden captcha widget is no challenge; a shown one still is
# ---------------------------------------------------------------------------


class _Iframe:
    def __init__(self, visible: bool) -> None:
        self._visible = visible

    def is_visible(self) -> bool:
        return self._visible


class _Frame:
    def __init__(self, url: str, *, visible: bool = True, main: bool = False):
        self.url = url
        self.parent_frame = None if main else object()
        self._el = _Iframe(visible)

    def frame_element(self) -> _Iframe:
        return self._el


class _CaptchaPage:
    url = "https://login.example.ch/"

    def __init__(self, frames: list[_Frame], shown_srcs: list[str]) -> None:
        self.frames = frames
        self._srcs = shown_srcs

    def title(self) -> str:
        return "Infomaniak"

    def eval_on_selector_all(self, _sel: str, js: str) -> list[str]:
        assert js == recipes._SHOWN_IFRAME_SRCS_JS  # visibility filtered in-page
        return self._srcs

    def evaluate(self, _js: str) -> str:
        return "OTP Application OTP connection code VALIDATE"


ANCHOR = "https://www.google.com/recaptcha/api2/anchor?k=x"


def test_hidden_recaptcha_is_not_a_challenge():
    page = _CaptchaPage(
        [_Frame("https://login.example.ch/", main=True), _Frame(ANCHOR, visible=False)],
        [],
    )
    assert recipes.challenge_reason(page) is None


def test_shown_recaptcha_is_a_challenge():
    page = _CaptchaPage([_Frame(ANCHOR, visible=True)], [ANCHOR])
    assert recipes.challenge_reason(page) == "captcha"


def test_uninspectable_frame_counts_as_shown():
    class _Broken(_Frame):
        def frame_element(self):
            raise RuntimeError("detached")

    page = _CaptchaPage([_Broken(ANCHOR)], [])
    assert recipes.challenge_reason(page) == "captcha"


# ---------------------------------------------------------------------------
# C. real headless Chromium against an Infomaniak-like fixture site
# ---------------------------------------------------------------------------

# Angular Material nesting of Infomaniak's <number-input> (label in an <h3>
# beside it, not a <label>), a VALIDATE button, and the idle reCAPTCHA host.
_HIDDEN_CAPTCHA = (
    "<div class=recaptcha hidden><app-recaptcha><re-captcha>"
    "<iframe src='/recaptcha/api2/anchor?k=test'></iframe>"
    "</re-captcha></app-recaptcha></div>"
)
_OTP_PAGE = (
    "<html><head><title>Infomaniak</title></head><body>"
    "<h2>OTP Application</h2>"
    "<p>Enter the unique connection code below generated via your OTP app</p>"
    "<form><div class=otp><div class='flex flex-column'><h3>OTP connection code</h3>"
    "<div class=block-input-button><number-input><div class=number-box>"
    "<mat-form-field><div class=wrapper><div class=flex><div class=infix>"
    "<input id=mat-input-2 autocomplete=off name=number pattern='[0-9]*' type=tel"
    " class=number-box__input maxlength=6 minlength=1 placeholder=000000>"
    "</div></div></div></mat-form-field></div></number-input>"
    "<button type=button id=validate>VALIDATE</button></div></div></div>"
    + _HIDDEN_CAPTCHA
    + "</form><a href='#'>Choose another method</a>"
    "<script>"
    "const i = document.getElementById('mat-input-2');"
    "async function go() {"
    "  const r = await fetch('/api/otp', {method: 'POST', body: i.value});"
    "  if (r.ok) location.href = (await r.json()).next;"
    "}"
    "i.addEventListener('keyup', e => { if (e.key === 'Enter') go(); });"
    "document.getElementById('validate').addEventListener('click', go);"
    "</script></body></html>"
)


class _InfomaniakApp(http.server.BaseHTTPRequestHandler):
    """Login origin: e-mail → password → OTP (SPA-style, no form action);
    the site origin's /account needs the session cookie."""

    login_origin = ""
    site_origin = ""
    otp_posts: list[bool] = []  # one entry per OTP submit: was the code valid?

    def log_message(self, *args):
        return

    def _send(self, code, body="", headers=(), ctype="text/html"):
        self.send_response(code)
        for k, v in headers:
            self.send_header(k, v)
        self.send_header("Content-Type", ctype)
        self.end_headers()
        self.wfile.write(body.encode())

    def _body(self) -> str:
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n).decode()

    def do_GET(self):  # noqa: N802
        cls = type(self)
        if self.path.startswith("/account"):
            if f"session={SESSION}" in (self.headers.get("Cookie") or ""):
                self._send(200, "<html><body><h1 id=welcome>Manager</h1></body></html>")
            else:
                self._send(302, headers=[("Location", cls.login_origin + "/login")])
            return
        if self.path.startswith("/recaptcha/"):
            self._send(200, "<html><body>captcha widget</body></html>")
            return
        if self.path.startswith("/login/otp"):
            self._send(200, _OTP_PAGE)
            return
        if self.path.startswith("/login/password"):
            self._send(
                200,
                "<html><body><form method=post action=/login/password>"
                f"<input type=email name=email value='{EMAIL}' readonly>"
                "<input type=password name=password>"
                "<button type=submit>Continue</button>"
                + _HIDDEN_CAPTCHA
                + "</form></body></html>",
            )
            return
        if self.path.startswith("/login"):
            self._send(
                200,
                "<html><body><form method=post action=/login>"
                "<input type=email name=email autocomplete=email>"
                "<button type=submit>Next</button>"
                + _HIDDEN_CAPTCHA
                + "</form></body></html>",
            )
            return
        self._send(404, "nope")

    def do_POST(self):  # noqa: N802
        from urllib.parse import parse_qs

        cls = type(self)
        if self.path.startswith("/api/otp"):
            ok = pyotp.TOTP(SEED).verify(self._body().strip(), valid_window=1)
            cls.otp_posts.append(ok)
            if not ok:
                self._send(400, "{}", ctype="application/json")
                return
            cookie = f"session={SESSION}; Path=/; Max-Age=3600; HttpOnly"
            self._send(
                200,
                json.dumps({"next": cls.site_origin + "/account"}),
                headers=[("Set-Cookie", cookie)],
                ctype="application/json",
            )
            return
        q = parse_qs(self._body())
        if self.path.startswith("/login/password"):
            ok = q.get("email") == [EMAIL] and q.get("password") == [PASSWORD]
            loc = "/login/otp" if ok else "/login/password?err=1"
            self._send(302, headers=[("Location", loc)])
            return
        if self.path.startswith("/login"):
            ok = q.get("email") == [EMAIL]
            self._send(
                302, headers=[("Location", "/login/password" if ok else "/login")]
            )
            return
        self._send(404, "nope")


@contextlib.contextmanager
def _servers():
    srvs = [
        http.server.ThreadingHTTPServer(("127.0.0.1", 0), _InfomaniakApp)
        for _ in range(2)
    ]
    for srv in srvs:
        threading.Thread(target=srv.serve_forever, daemon=True).start()
    login, site = (f"http://127.0.0.1:{s.server_address[1]}" for s in srvs)
    _InfomaniakApp.login_origin, _InfomaniakApp.site_origin = login, site
    _InfomaniakApp.otp_posts = []
    try:
        yield login, site
    finally:
        for srv in srvs:
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
def test_e2e_infomaniak_like_otp_step(tmp_path):
    sockdir = Path(tempfile.mkdtemp(prefix="lb-"))  # AF_UNIX path length cap
    try:
        with _servers() as (login, site):
            item = {
                "id": "id-infomaniaklike",
                "name": "InfomaniakLike",
                "login": {"username": EMAIL, "password": PASSWORD, "totp": SEED},
                "fields": [
                    {"name": k, "value": v, "type": 0}
                    for k, v in {
                        "agent_site": "infomaniaklike",
                        "agent_fill_origins": login,
                        "agent_check_url": site + "/account",
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
                result = _ask(path, {"op": "login", "site": "infomaniaklike"})
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
    assert _InfomaniakApp.otp_posts == [True]  # one submit, with a valid code
    flat = json.dumps(result)
    assert PASSWORD not in flat and SEED not in flat
