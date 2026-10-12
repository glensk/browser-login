"""WS2-calibre: generic submit safety, remember-me, Access gate, session age.

Live evidence (2026-10-08): Calibre-Web Automated v4.0.8 puts ``<button
type=submit name=forgot value=forgot>`` BEFORE its Login button. The
pre-tp#835 broker pressed Enter in the password field, which fired ``forgot``:
CWA reset the admin password twice and mailed it. The fixes tested here hold
for every site, not only CWA:

* the submit fails CLOSED: when the form's submit buttons cannot be read,
  nothing is submitted (no Enter "fallback"), before the submit marker;
* a POST tripwire aborts, inside the browser, any request to a fill origin
  that names a secondary action (forgot, reset, register, resend …): phase
  ``submit``, code ``secondary_action_blocked``, attempt ``not_submitted``;
* the submit marker is set right before the click on the identified login
  button, never before (CWA's order: forgot first);
* a "remember me" box is ticked before the password is typed;
* a Cloudflare Access login instead of the site (off-LAN) is phase
  ``precheck``, code ``access_gated`` — nothing reserved, typed or submitted,
  never ❌ for agents;
* ``agent_max_session_days``: a session older than that since its last proven
  fresh login is renewed with a fresh login while it still works.

The broker tests drive the REAL runner (its own disposable headless Chromium,
never browser.py's shared one) against a local CWA-like fixture; skipped when
Playwright's Chromium is missing. Secrets are generated at run time.
"""
# pylint: disable=too-many-lines,duplicate-code

from __future__ import annotations

# pylint: disable=protected-access,missing-function-docstring,missing-class-docstring
# pylint: disable=import-error,wrong-import-position,too-few-public-methods
import contextlib
import functools
import http.server
import importlib.util
import json
import secrets
import sys
import threading
import time
import urllib.parse
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

_PW = secrets.token_hex(4)  # random fixture password, never a real one
_ACTION_WORD_PW = "for" + "got"  # a password that equals an action word

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

import agent_login_state as als  # noqa: E402
from broker import (  # noqa: E402
    daemon,
    limiter,
    login_form,
    onboarding,
    origins,
    phases,
    recipes,
    vault,
)


def _load(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


browser = _load("browser_ws2_calibre_test", REPO / "bin" / "browser.py")
al = _load("agent_login_ws2_calibre_test", REPO / "agent-login.py")

USER = "agent"
PASSWORD = secrets.token_urlsafe(18)  # generated: never a literal secret
SITE = "calfix"
SENTINEL = "#top_tasks"
ACCESS_URL = (
    "https://team.cloudflareaccess.com/cdn-cgi/access/login/calibre.example"
    "?redirect_url=%2Fme"
)


def _chromium_installed() -> bool:
    try:
        from playwright.sync_api import (  # pylint: disable=import-outside-toplevel
            sync_playwright,
        )

        with sync_playwright() as pw:
            return Path(pw.chromium.executable_path).exists()
    except Exception:  # pylint: disable=broad-exception-caught
        return False


CHROME = pytest.mark.skipif(
    not _chromium_installed(), reason="Playwright Chromium missing"
)


# ---------------------------------------------------------------------------
# A. pure rules
# ---------------------------------------------------------------------------

CWA_FORM = "application/x-www-form-urlencoded"


def _form(**kv: str) -> str:
    return urllib.parse.urlencode(kv)


def test_a_cwa_forgot_post_is_secondary() -> None:
    body = _form(next="/", csrf_token="t", username=USER, password=_PW, forgot="forgot")
    hit = login_form.secondary_post(
        "https://calibre.example/login", body, CWA_FORM, protect={"password"}
    )
    assert hit == "field forgot"
    # with the form's own button names it is named as that button
    hit = login_form.secondary_post(
        "https://calibre.example/login",
        body,
        CWA_FORM,
        button_pairs={("forgot", "forgot")},
    )
    assert hit == "button forgot"


@pytest.mark.parametrize(
    "body",
    [
        _form(
            next="/",
            csrf_token="t",
            username=USER,
            password=_PW,
            remember_me="on",
            submit="",
        ),
        # GitHub's login carries a hidden `allow_signup`: no action of its own
        _form(login=USER, password=_PW, commit="Sign in", allow_signup=""),
        # Keycloak
        _form(username=USER, password=_PW, rememberMe="on", credentialId=""),
        # a password that happens to be an action word is never read
        _form(username=USER, password=_ACTION_WORD_PW),
        # an action key that says "no"
        _form(username=USER, password=_PW, signup="false", forgotPassword="0"),
    ],
)
def test_a_login_post_is_not_secondary(body: str) -> None:
    assert (
        login_form.secondary_post(
            "https://site.example/login", body, CWA_FORM, protect={"password"}
        )
        is None
    )


@pytest.mark.parametrize(
    ("url", "body", "ctype"),
    [
        ("https://s.example/login", _form(forgot_password=_PW), CWA_FORM),
        ("https://s.example/login", _form(action="reset"), CWA_FORM),
        ("https://s.example/login", _form(submit="Register"), CWA_FORM),
        (
            "https://s.example/login",
            json.dumps({"intent": "resend-code"}),
            "application/json",
        ),
        (
            "https://s.example/api",
            json.dumps({"signUp": True, "user": {"email": "a"}}),
            "application/json",
        ),
        ("https://s.example/account/forgot-password", _form(email="a"), CWA_FORM),
        (
            "https://s.example/login",
            '--b\r\nContent-Disposition: form-data; name="resend"\r\n\r\n1\r\n--b--',
            "multipart/form-data; boundary=b",
        ),
    ],
)
def test_secondary_actions_are_recognised(url: str, body: str, ctype: str) -> None:
    assert login_form.secondary_post(url, body, ctype) is not None


def test_a_get_query_is_judged_without_its_path() -> None:
    # a GET form's submit: the query is the body, the URL path is not judged
    assert login_form.secondary_post("", "next=%2Fme", CWA_FORM) is None
    assert login_form.secondary_post("", "op=forgot&u=a", CWA_FORM) == "op=forgot"


@pytest.mark.parametrize(
    "desc",
    [
        {"name": "op", "value": "forgot", "text": "Continue"},
        {"name": "", "text": "Continue", "formaction": "/account/forgot-password"},
    ],
)
def test_a_button_value_or_formaction_makes_it_secondary(desc: dict[str, Any]) -> None:
    assert login_form.secondary_button_like(desc)
    login = {"name": "submit", "text": "Login", "visible": True}
    assert login_form.pick_submit_button([{**desc, "visible": True}, login]) == 1


def test_a_hit_names_no_value() -> None:
    secret = secrets.token_hex(8)
    hit = login_form.secondary_post(
        "https://s.example/x", _form(reset=secret), CWA_FORM
    )
    assert hit == "field reset" and secret not in hit


@pytest.mark.parametrize(
    "desc",
    [
        {"name": "remember_me", "id": "", "aria": "", "label": ""},
        {"name": "", "id": "rememberMe", "aria": "", "label": ""},
        {"name": "stay", "id": "", "aria": "", "label": "Angemeldet bleiben"},
        {"name": "x", "id": "", "aria": "", "label": "Rester connecté"},
        {"name": "x", "id": "", "aria": "Keep me signed in", "label": ""},
    ],
)
def test_remember_me_like(desc: dict[str, Any]) -> None:
    assert login_form.remember_me_like(desc)
    assert login_form.pick_remember_me([{**desc, "visible": True}]) == 0


@pytest.mark.parametrize(
    "desc",
    [
        {"name": "remember_device", "label": "Remember this device"},
        {"name": "trust", "label": "Remember this browser for 30 days"},
        {"name": "rememberUsername", "label": ""},
        {"name": "x", "label": "Remember my choice"},
        {"name": "x", "label": "Remember me on this computer"},
    ],
)
def test_remember_device_or_choice_is_never_ticked(desc: dict[str, Any]) -> None:
    # a trusted device skips the second factor: another policy, not a session
    assert not login_form.remember_me_like(desc)


def test_remember_me_skips_other_boxes() -> None:
    boxes = [
        {"name": "newsletter", "label": "Send me news", "visible": True},
        {"name": "terms", "label": "I accept", "visible": True},
        {"name": "remember_me", "visible": True, "disabled": True},
        {"name": "remember_me", "visible": False, "label_visible": False},
    ]
    assert login_form.pick_remember_me(boxes) is None
    boxes.append({"name": "remember", "visible": False, "label_visible": True})
    assert login_form.pick_remember_me(boxes) == 4


@pytest.mark.parametrize(
    ("url", "gated"),
    [
        (ACCESS_URL, True),
        ("https://albertha.cloudflareaccess.com/", True),
        ("http://team.cloudflareaccess.com/", False),
        ("https://cloudflareaccess.com/", False),
        ("https://evilcloudflareaccess.com/", False),
        ("https://team.cloudflareaccess.com.evil.example/", False),
        ("https://calibre.example/?u=x.cloudflareaccess.com", False),
        ("https://calibre.example/cdn-cgi/access/login/calibre.example", True),
        ("https://calibre.example/cdn-cgi/l/email-protection", False),
        ("chrome-error://chromewebdata/", False),
    ],
)
def test_access_gated(url: str, gated: bool) -> None:
    assert origins.access_gated(url) is gated


def _cwa_item(**fields: str) -> dict[str, Any]:
    base = {
        "agent_site": SITE,
        "agent_fill_origins": "https://calibre.example",
        "agent_login_url": "https://calibre.example/login",
        "agent_check_url": "https://calibre.example/me",
        "agent_logged_in_selector": SENTINEL,
        "agent_cookie_names": "session,remember_token",
    }
    base.update(fields)
    return {
        "id": "id-cal",
        "name": "calibre",
        "login": {"username": USER, "password": PASSWORD},
        "fields": [{"name": k, "value": v} for k, v in base.items()],
    }


def test_vault_max_session_days() -> None:
    item = vault.site_item_from_json(
        _cwa_item(agent_fresh_login="true", agent_max_session_days="28")
    )
    assert item.refused is None and item.max_session_days == 28
    assert item.public()["max_session_days"] == 28
    plain = vault.site_item_from_json(_cwa_item())
    assert plain.max_session_days is None and plain.public()["max_session_days"] is None


@pytest.mark.parametrize("raw", ["0", "366", "abc", "28.5", "-1", "²"])
def test_vault_refuses_a_bad_max_session_days(raw: str) -> None:
    item = vault.site_item_from_json(
        _cwa_item(agent_fresh_login="true", agent_max_session_days=raw)
    )
    assert item.refused and "agent_max_session_days" in item.refused


def test_vault_max_session_days_needs_fresh_login() -> None:
    item = vault.site_item_from_json(_cwa_item(agent_max_session_days="28"))
    assert item.refused == "agent_max_session_days needs agent_fresh_login true"


def test_new_codes_have_fixed_text() -> None:
    for code in ("access_gated", "submit_unidentified", "secondary_action_blocked"):
        assert code in phases.CODE_TEXT
    assert phases.phase_for_error("access_gated") == "precheck"
    assert "off-LAN" in phases.text("precheck", "access_gated")


def test_a_tripwire_abort_is_not_submitted() -> None:
    attempt = recipes.AttemptController()
    attempt.entered()
    attempt.mark_submitted()
    sent = recipes.SecondaryActionBlocked("x", never_sent=True)
    assert daemon._error_outcome(attempt, sent) == "not_submitted"
    leaked = recipes.SecondaryActionBlocked("x", never_sent=False)
    assert daemon._error_outcome(attempt, leaked) == "unknown"
    assert sent.phase == "submit" and sent.code == "secondary_action_blocked"


class _BadHandle:
    def get_properties(self) -> dict[str, Any]:
        raise RuntimeError("detached")


def test_unreadable_buttons_read_as_none() -> None:
    field_ = SimpleNamespace(evaluate_handle=lambda _js: _BadHandle())
    assert login_form.form_submit_buttons(field_) is None
    assert login_form.read_submit_buttons(field_) is None
    broken = SimpleNamespace(evaluate=lambda _js: {"name": "submit"})  # keys missing
    assert login_form.describe_buttons([broken]) is None

    def boom(_js: str) -> Any:
        raise RuntimeError("gone")

    assert login_form.describe_buttons([SimpleNamespace(evaluate=boom)]) is None
    assert login_form.describe_buttons([]) == []


def _button_desc(**kw: Any) -> dict[str, Any]:
    base = {"name": "", "id": "", "cls": "", "text": "", "aria": ""}
    return {**base, "disabled": False, "visible": True, **kw}


class _FakeButton:
    def __init__(self, desc: dict[str, Any] | None) -> None:
        self.desc = desc
        self.clicked = False

    def evaluate(self, _js: str) -> Any:
        if self.desc is None:
            raise RuntimeError("detached")
        return self.desc

    def click(self, **_kw: Any) -> None:
        self.clicked = True


def test_keycloak_fallback_never_clicks_a_secondary_button() -> None:
    forgot = _FakeButton(_button_desc(name="forgot", text="Forgot Password?"))
    unreadable = _FakeButton(None)
    login = _FakeButton(_button_desc(text="Sign In"))
    page = SimpleNamespace(
        query_selector=lambda _sel: None,
        query_selector_all=lambda _sel: [forgot, unreadable, login],
    )
    attempt = recipes.AttemptController()
    assert recipes.click_keycloak_submit(page, attempt)
    assert login.clicked and not forgot.clicked and not unreadable.clicked
    assert attempt.submitted
    page.query_selector_all = lambda _sel: [forgot]
    attempt = recipes.AttemptController()
    assert not recipes.click_keycloak_submit(page, attempt)
    assert not attempt.submitted and not forgot.clicked


def test_smartsheet_without_its_button_submits_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    field_ = SimpleNamespace(press=_no_broker)
    page = SimpleNamespace(
        url="https://app.smartsheet.com/b/login", goto=lambda *a, **k: None
    )
    monkeypatch.setattr(recipes, "_wait_visible", lambda *_a: None)
    monkeypatch.setattr(recipes, "_smartsheet_password_field", lambda *_a, **_k: field_)
    monkeypatch.setattr(recipes, "_fill_password", lambda *_a, **_k: field_)
    monkeypatch.setattr(recipes, "_guard", lambda *_a, **_k: None)
    monkeypatch.setattr(recipes, "_visible", lambda *_a: None)
    monkeypatch.setattr(recipes, "_field_value", lambda _f: PASSWORD)
    item = vault.site_item_from_json(
        {
            "id": "id-ss",
            "name": "smartsheet",
            "login": {"username": USER, "password": PASSWORD},
            "fields": [
                {"name": "agent_site", "value": "smartsheet"},
                {"name": "agent_fill_origins", "value": "https://app.smartsheet.com"},
            ],
        }
    )
    attempt = recipes.AttemptController()
    secret = vault.Secret(USER, PASSWORD)
    with pytest.raises(recipes.SubmitUnidentified) as err:
        recipes.smartsheet_login(page, item, secret, attempt=attempt)
    assert not attempt.submitted and err.value.unsent and not err.value.submitted


class _OtpField:
    """An OTP input whose form's buttons cannot be read; `on_fill` models a
    page that submits itself once the code is complete."""

    def __init__(self, page: Any, *, self_submit: bool) -> None:
        self.page = page
        self.self_submit = self_submit
        self.gone = False

    def fill(self, _code: str) -> None:
        if self.self_submit:  # GitHub: 6 digits typed → the form posts itself
            self.page.url = "https://auth.example/sessions/two-factor/done"
            self.gone = True

    def is_visible(self) -> bool:
        return not self.gone

    def evaluate_handle(self, _js: str) -> Any:
        return _BadHandle()

    def press(self, _key: str) -> None:
        raise AssertionError("never Enter on a page that submitted itself")


def _otp_run(
    monkeypatch: pytest.MonkeyPatch, *, self_submit: bool
) -> tuple[recipes.AttemptController, Any]:
    import base64  # pylint: disable=import-outside-toplevel
    import os  # pylint: disable=import-outside-toplevel

    page = SimpleNamespace(
        url="https://auth.example/otp", wait_for_timeout=lambda _ms: None
    )
    otp = _OtpField(page, self_submit=self_submit)
    monkeypatch.setattr(recipes, "_otp_field", lambda _page: otp)
    monkeypatch.setattr(recipes, "_select_authenticator", lambda *_a: None)
    monkeypatch.setattr(recipes, "_guard", lambda *_a, **_k: None)
    seed = base64.b32encode(os.urandom(20)).decode()
    secret = vault.Secret(USER, PASSWORD, seed)
    attempt = recipes.AttemptController()
    try:
        recipes._fill_otp(
            page, otp, secret, ["https://auth.example"], dev=False, attempt=attempt
        )
    except recipes.RecipeError as exc:
        return attempt, exc
    return attempt, None


def test_an_otp_with_unreadable_buttons_is_post_submit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attempt, err = _otp_run(monkeypatch, self_submit=False)
    assert isinstance(err, recipes.SubmitUnidentified)
    assert err.submitted and not attempt.submitted  # the password went first


def test_a_self_submitting_otp_page_is_marked_not_failed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """GitHub-like: the page posts the code itself. No Enter, no
    SubmitUnidentified — the submit is marked, the settle loop decides."""
    attempt, err = _otp_run(monkeypatch, self_submit=True)
    assert err is None and attempt.submitted


def test_a_blocked_secondary_action_quarantines(
    tmp_path: Path,
) -> None:
    browser._result_begin("login", SITE, str(tmp_path / "r.json"))
    reply = {
        "ok": False,
        "error": "secondary_action_blocked",
        "detail": "a submit named a secondary form action (button forgot)",
        "phase": "submit",
        "submitted": False,
    }
    assert browser._broker_refused(SITE, reply) == 2
    assert als.quarantined(SITE) is not None  # no daily repeat of a misread form
    browser._result_begin("login", "", None)


# ---------------------------------------------------------------------------
# B. the CWA-like fixture site
# ---------------------------------------------------------------------------

_LOGIN_HTML = """<!doctype html><html><head><title>Calibre-Web | Login</title></head>
<body><div class="cwa-login"><h2>Login</h2>
<form method="POST" role="form" action="/login"{target}>
  <input type="hidden" name="next" value="/">
  <input type="hidden" name="csrf_token" value="{csrf}">
  <div class="form-group"><label for="username">Username</label>
    <input type="text" class="form-control" id="username" name="username"></div>
  <div class="form-group"><label for="password">Password</label>
    <input type="password" class="form-control" id="password" name="password">
    <button type="button" class="password-toggle" aria-label="Show password">o</button>
  </div>
  <div class="checkbox"><label><input type="checkbox" name="remember_me"{checked}>
    Remember Me</label></div>
  <button type="submit" name="forgot" value="forgot" class="cwa-link-button">
    Forgot Password?</button>
  <button type="submit" name="submit" class="cwa-btn cwa-btn-primary">Login</button>
</form>{flash}</div></body></html>"""

_NAV = '<nav id="main-nav"><a id="top_tasks" href="/tasks">Tasks</a></nav>'
_PAGE = "<!doctype html><html><body>{nav}<div id=books>library</div></body></html>"
_ACCESS_HTML = """<!doctype html><html><body><h1>Sign in to calibre.example</h1>
<form><input type=email name=email placeholder="you@example.com">
<button type=submit>Send me a code</button></form></body></html>"""


@dataclass
class _Cwa:  # pylint: disable=too-many-instance-attributes
    """Server-side state of one fixture Calibre-Web Automated."""

    remember_default: bool = False
    access_gate: bool = False
    block_status: int = 0  # e.g. 403: an Access block page / IP gate
    form_target: str = ""  # e.g. "_blank": the form posts into a popup
    posts: list[dict[str, str]] = field(default_factory=list)
    resets: int = 0
    logins: int = 0
    sessions: set[str] = field(default_factory=set)
    csrf: dict[str, str] = field(default_factory=dict)


class _Server(http.server.ThreadingHTTPServer):
    app: _Cwa


class _Handler(http.server.BaseHTTPRequestHandler):
    server: _Server

    def log_message(self, *args: Any) -> None:
        return

    def _cookies(self) -> dict[str, str]:
        out: dict[str, str] = {}
        for part in (self.headers.get("Cookie") or "").split(";"):
            name, _, value = part.strip().partition("=")
            if name:
                out[name] = value
        return out

    def _send(self, code: int, body: str, cookies: list[str] | None = None) -> None:
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        for ck in cookies or []:
            self.send_header("Set-Cookie", ck)
        self.end_headers()
        self.wfile.write(data)

    def _redirect(self, where: str, cookies: list[str] | None = None) -> None:
        self.send_response(302)
        self.send_header("Location", where)
        self.send_header("Content-Length", "0")
        for ck in cookies or []:
            self.send_header("Set-Cookie", ck)
        self.end_headers()

    def _logged_in(self) -> bool:
        return self._cookies().get("session") in self.server.app.sessions

    def _login_page(self, flash: str = "") -> None:
        app = self.server.app
        pre = secrets.token_hex(8)
        app.csrf[pre] = secrets.token_hex(12)
        page = (
            _LOGIN_HTML.replace("{csrf}", app.csrf[pre])
            .replace("{checked}", " checked" if app.remember_default else "")
            .replace(
                "{target}", f' target="{app.form_target}"' if app.form_target else ""
            )
            .replace("{flash}", f"<div class=flash>{flash}</div>" if flash else "")
        )
        self._send(200, page, [f"pre={pre}; Path=/; HttpOnly"])

    def do_GET(self) -> None:  # noqa: N802
        app = self.server.app
        path = self.path.split("?", 1)[0]
        if app.access_gate:
            self._redirect(ACCESS_URL)
            return
        if app.block_status:
            self._send(
                app.block_status, "<h1>Forbidden</h1><form><input name=q></form>"
            )
            return
        if path == "/login":
            self._login_page()
        elif path == "/me":
            if self._logged_in():
                self._send(200, _PAGE.replace("{nav}", _NAV))
            else:
                self._redirect("/login?next=%2Fme")
        else:  # anonymous browsing: the library without the user's nav
            self._send(200, _PAGE.replace("{nav}", _NAV if self._logged_in() else ""))

    def do_POST(self) -> None:  # noqa: N802
        app = self.server.app
        n = int(self.headers.get("Content-Length") or 0)
        body = dict(
            urllib.parse.parse_qsl(self.rfile.read(n).decode(), keep_blank_values=True)
        )
        app.posts.append(body)
        pre = self._cookies().get("pre", "")
        if self.path != "/login" or body.get("csrf_token") != app.csrf.get(pre):
            self._send(400, "The CSRF token is missing.")
            return
        if body.get("forgot") == "forgot":  # CWA: resets the password, mails it
            app.resets += 1
            self._send(200, "New Password was sent to your email address")
            return
        if (
            "submit" in body
            and body.get("username") == USER
            and body.get("password") == PASSWORD
        ):
            app.logins += 1
            token = secrets.token_hex(16)
            app.sessions.add(token)
            cookies = [f"session={token}; Path=/; HttpOnly"]
            if body.get("remember_me") == "on":
                cookies.append(
                    f"remember_token={secrets.token_hex(16)}; Path=/; HttpOnly; "
                    "Max-Age=31536000"
                )
            self._redirect("/", cookies)
            return
        self._login_page("Wrong Username or Password")


@pytest.fixture(name="cwa")
def _cwa() -> Iterator[tuple[_Cwa, str]]:
    httpd = _Server(("127.0.0.1", 0), _Handler)
    httpd.app = _Cwa()
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        yield httpd.app, f"http://127.0.0.1:{httpd.server_address[1]}"
    finally:
        httpd.shutdown()
        httpd.server_close()


class _CountingVault:
    def __init__(self, inner: vault.FixtureVault) -> None:
        self._inner = inner
        self.secret_calls = 0

    def items(self) -> list[vault.SiteItem]:
        return self._inner.items()

    def secret(self, site: str) -> vault.Secret:
        self.secret_calls += 1
        return self._inner.secret(site)


@dataclass
class _Rig:
    brk: daemon.Broker
    vault: _CountingVault
    home: Path

    def login(self) -> dict[str, Any]:
        return self.brk._login_request(SITE, {})

    def attempts(self) -> list[Any]:
        path = self.home / "limiter.json"
        if not path.exists():
            return []
        entry = json.loads(path.read_text()).get("sites", {}).get(SITE) or {}
        return list(entry.get("attempts") or [])


def _rig(tmp_path: Path, origin: str, *, fresh: bool = True) -> _Rig:
    fields = {
        "agent_site": SITE,
        "agent_fill_origins": origin,
        "agent_login_url": origin + "/login",
        "agent_check_url": origin + "/me",
        "agent_logged_in_selector": SENTINEL,
        "agent_cookie_names": "session,remember_token",
    }
    if fresh:
        fields["agent_fresh_login"] = "true"
        fields["agent_max_session_days"] = "28"
    item = {
        "id": "id-calfix",
        "name": "CWA fixture",
        "login": {"username": USER, "password": PASSWORD},
        "fields": [{"name": k, "value": v} for k, v in fields.items()],
    }
    fixture = tmp_path / "items.json"
    fixture.write_text(json.dumps([item]))
    home = tmp_path / "home"
    counting = _CountingVault(vault.FixtureVault(fixture, dev=True))
    brk = daemon.Broker(
        counting,  # type: ignore[arg-type]
        limiter.Limiter(home / "limiter.json", 0, 100, 100),
        home,
        runner=daemon.PlaywrightRunner(home, dev=True),
    )
    return _Rig(brk, counting, home)


@pytest.fixture(name="fast")
def _fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(daemon, "PROFILE_PROOF_WAIT_S", 2.5)
    monkeypatch.setattr(
        daemon,
        "recipe_for",
        lambda site: functools.partial(recipes.generic_login, settle_s=4.0),
    )


@pytest.fixture(name="marks")
def _marks(monkeypatch: pytest.MonkeyPatch, cwa: tuple[_Cwa, str]) -> list[int]:
    """How many POSTs the server had seen each time the submit marker was set."""
    app, _origin = cwa
    seen: list[int] = []
    real = daemon._LimiterAttempt.mark_submitted

    def mark(self: Any) -> None:
        seen.append(len(app.posts))
        real(self)

    monkeypatch.setattr(daemon._LimiterAttempt, "mark_submitted", mark)
    return seen


# ---------------------------------------------------------------------------
# C. the broker against the fixture (real headless Chromium)
# ---------------------------------------------------------------------------


@pytest.mark.launches_chrome
@CHROME
@pytest.mark.usefixtures("fast")
def test_cwa_login_clicks_login_with_remember_me_never_forgot(
    tmp_path: Path, cwa: tuple[_Cwa, str], marks: list[int]
) -> None:
    app, origin = cwa
    rig = _rig(tmp_path, origin)
    resp = rig.login()
    assert resp.get("ok"), resp
    assert resp["fresh_auth"] is True and resp["bundle"]["via"] == "login"
    assert len(app.posts) == 1 and app.logins == 1 and app.resets == 0
    post = app.posts[0]
    assert "submit" in post and "forgot" not in post
    assert post["remember_me"] == "on"  # ticked: the fixture renders it unticked
    names = sorted(c["name"] for c in resp["bundle"]["cookies"])
    assert names == ["remember_token", "session"]
    # the marker came once, right before the click: nothing was posted before it
    assert marks == [0]
    assert rig.attempts()[-1][1] == "ok"
    assert PASSWORD not in json.dumps(resp)


@pytest.mark.launches_chrome
@CHROME
@pytest.mark.usefixtures("fast")
@pytest.mark.parametrize("broken", ["SUBMIT_BUTTONS_JS", "BUTTON_DESCRIBE_JS"])
def test_unreadable_buttons_submit_nothing(
    tmp_path: Path,
    cwa: tuple[_Cwa, str],
    marks: list[int],
    monkeypatch: pytest.MonkeyPatch,
    broken: str,
) -> None:
    app, origin = cwa
    monkeypatch.setattr(login_form, broken, "e => { throw new Error('unreadable'); }")
    rig = _rig(tmp_path, origin)
    resp = rig.login()
    assert not resp.get("ok")
    assert resp["error"] == "submit_unidentified" and resp["phase"] == "recipe"
    assert resp["submitted"] is False
    assert app.posts == [] and marks == []  # no request, no marker
    assert rig.attempts()[-1][1] == "failed"  # not_submitted: no cooldown


@pytest.mark.launches_chrome
@CHROME
@pytest.mark.usefixtures("fast")
@pytest.mark.parametrize(
    ("known", "target"),
    [(True, ""), (False, ""), (True, "_blank")],
    ids=["button-name", "action-word", "popup"],
)
def test_tripwire_aborts_a_forgot_post(  # pylint: disable=too-many-arguments,too-many-positional-arguments
    tmp_path: Path,
    cwa: tuple[_Cwa, str],
    marks: list[int],
    monkeypatch: pytest.MonkeyPatch,
    known: bool,
    target: str,
) -> None:
    """The pre-tp#835 broker, reproduced: Enter in the password field fires
    CWA's default (first) submit button, `forgot`. The tripwire aborts the
    POST in the browser — the server never sees it, nothing is reset. A form
    that posts into a popup (target=_blank) is caught too (context scope)."""
    app, origin = cwa
    app.form_target = target
    monkeypatch.setattr(recipes, "pick_submit_button", lambda _descs: None)
    if not known:  # without the form's button names: the word alone trips
        monkeypatch.setattr(recipes, "secondary_pairs", lambda _descs: set())
    rig = _rig(tmp_path, origin)
    resp = rig.login()
    assert not resp.get("ok")
    assert resp["error"] == "secondary_action_blocked" and resp["phase"] == "submit"
    assert resp["submitted"] is False  # the password never left the browser
    assert app.posts == [] and app.resets == 0
    assert marks == [0]  # the (wrong) Enter was marked, then aborted
    assert rig.attempts()[-1][1] == "failed"  # not_submitted
    want = "button forgot" if known else "field forgot"
    assert want in resp["detail"]


@pytest.mark.launches_chrome
@CHROME
@pytest.mark.usefixtures("fast")
@pytest.mark.parametrize("fresh", [True, False], ids=["fresh-login", "profile"])
def test_an_access_redirect_is_gated_without_a_submit(
    tmp_path: Path,
    cwa: tuple[_Cwa, str],
    monkeypatch: pytest.MonkeyPatch,
    fresh: bool,
) -> None:
    app, origin = cwa
    app.access_gate = True
    real = daemon.PlaywrightRunner._launch

    def launch(self: Any, pw: Any, profile: Path, item: Any = None) -> Any:
        ctx = real(self, pw, profile, item)
        ctx.route(
            "https://team.cloudflareaccess.com/**",
            lambda route: route.fulfill(
                status=200, content_type="text/html", body=_ACCESS_HTML
            ),
        )
        return ctx

    monkeypatch.setattr(daemon.PlaywrightRunner, "_launch", launch)
    rig = _rig(tmp_path, origin, fresh=fresh)
    resp = rig.login()
    assert not resp.get("ok")
    assert resp["error"] == "access_gated" and resp["phase"] == "precheck"
    assert resp["submitted"] is False
    assert rig.vault.secret_calls == 0  # nothing reserved, no secret read
    assert rig.attempts() == []
    assert app.posts == []


@pytest.mark.launches_chrome
@CHROME
@pytest.mark.usefixtures("fast")
@pytest.mark.parametrize("fresh", [True, False], ids=["fresh-login", "profile"])
def test_a_blocked_login_page_is_never_typed_into(
    tmp_path: Path, cwa: tuple[_Cwa, str], fresh: bool
) -> None:
    app, origin = cwa
    app.block_status = 403
    rig = _rig(tmp_path, origin, fresh=fresh)
    resp = rig.login()
    assert not resp.get("ok")
    assert resp["error"] == "login_blocked" and resp["phase"] == "precheck"
    assert resp["submitted"] is False
    assert rig.vault.secret_calls == 0 and rig.attempts() == []
    assert app.posts == []


@pytest.mark.launches_chrome
@CHROME
def test_a_hidden_styled_remember_box_is_ticked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from playwright.sync_api import (  # pylint: disable=import-outside-toplevel
        sync_playwright,
    )

    monkeypatch.setattr(recipes, "_guard", lambda *a, **k: None)
    html = """<html><body><form action="/login">
      <input name=username><input type=password name=password>
      <input type=checkbox id=news name=newsletter><label for=news>News</label>
      <input type=checkbox id=stay name=stay style="display:none">
      <label for=stay class=switch>Angemeldet bleiben</label>
      <button type=submit>Anmelden</button></form></body></html>"""
    with sync_playwright() as pw:
        chrome = pw.chromium.launch(headless=True)
        try:
            page = chrome.new_page()
            page.set_content(html)
            pw_field = page.query_selector("input[type=password]")
            assert recipes._tick_remember_me(page, pw_field, [], dev=False)
            assert page.eval_on_selector("#stay", "b => b.checked")
            assert not page.eval_on_selector("#news", "b => b.checked")
        finally:
            chrome.close()


# ---------------------------------------------------------------------------
# D. browser.py: the Access gate and the session age (no Chrome, no broker)
# ---------------------------------------------------------------------------


@pytest.fixture(name="result")
def _result(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    path = tmp_path / "result.json"
    monkeypatch.setattr(browser, "LOGIN_LOG_DIR", tmp_path / "login-log")
    monkeypatch.setattr(browser, "SESSION_AGE_DIR", tmp_path / "session-age")
    browser._result_begin("login", SITE, str(path))
    browser._LOGIN_OPTS.update(scheduled=False, candidate=None, refresh_only=False)
    browser._SESSION_DUE.clear()
    yield path
    browser._result_begin("login", "", None)
    browser._LOGIN_OPTS.update(scheduled=False, candidate=None, refresh_only=False)
    browser._SESSION_DUE.clear()


ENTRY = {
    "site": SITE,
    "check_url": "https://calibre.example/me",
    "login_url": "https://calibre.example/login",
    "fill_origins": ["https://calibre.example"],
    "logged_in_selector": SENTINEL,
    "cookie_hosts": ["calibre.example"],
    "fresh_login": True,
    "max_session_days": 28,
}


@pytest.mark.parametrize("sentinel", [SENTINEL, None], ids=["strict", "legacy"])
def test_probe_on_an_access_page_is_gated(sentinel: str | None) -> None:
    # The legacy proof alone would call this page logged in: off the fill
    # origins, no password field.
    page = SimpleNamespace(url=ACCESS_URL)
    entry = {**ENTRY, "logged_in_selector": sentinel}
    assert browser._broker_probe(page, entry) == browser.PROOF_GATED


def test_check_entry_records_access_gated(
    monkeypatch: pytest.MonkeyPatch, result: Path
) -> None:
    page = SimpleNamespace(url=ACCESS_URL)
    monkeypatch.setattr(
        browser,
        "_with_prepared_background_page",
        lambda _port, _url, _prep, verify: verify(page),
    )
    assert browser._broker_check_entry(9222, SITE, ENTRY) == 2
    browser._result_write(2)
    rec = json.loads(result.read_text())
    assert rec["phase"] == "precheck" and rec["code"] == "access_gated"


def _no_broker(*_a: Any, **_k: Any) -> Any:
    raise AssertionError("the broker must not be asked")


def test_login_stops_at_the_access_gate(
    monkeypatch: pytest.MonkeyPatch, result: Path
) -> None:
    def probe(_port: int, _site: str) -> int:
        browser._result_fail("precheck", "access_gated", "Cloudflare Access")
        return 2

    monkeypatch.setattr(browser, "_broker_logged_in", probe)
    monkeypatch.setattr(browser, "_broker_request", _no_broker)
    monkeypatch.setattr(browser, "_broker_login_gated", _no_broker)
    assert browser._broker_login(9222, SITE) == 2
    browser._result_write(2)
    assert json.loads(result.read_text())["code"] == "access_gated"


def _age_state(**fields: float) -> Path:
    """Write the site's session-age record; returns its path."""
    browser.SESSION_AGE_DIR.mkdir(parents=True, exist_ok=True)
    path = Path(browser.SESSION_AGE_DIR) / f"{SITE}.json"
    path.write_text(json.dumps(fields))
    return path


DAY = 86400.0


@pytest.mark.parametrize(
    ("state", "due", "age"),
    [
        ({"fresh_auth_at": time.time() - 29 * DAY}, True, 29),
        ({"fresh_auth_at": time.time() - 1 * DAY}, False, 1),
        # no fresh login of ours on record: counted from the first sighting
        ({"first_seen_at": time.time() - 30 * DAY}, True, 30),
        ({"first_seen_at": time.time() - 2 * DAY}, False, 2),
        # a fresh login wins over the first sighting
        (
            {"first_seen_at": time.time() - 90 * DAY, "fresh_auth_at": time.time()},
            False,
            0,
        ),
    ],
    ids=["29d", "1d", "seen-30d", "seen-2d", "fresh-wins"],
)
def test_session_age(
    result: Path, state: dict[str, float], due: bool, age: int
) -> None:
    _age_state(**state)
    browser._broker_note_session_age(SITE, ENTRY)
    assert browser._SESSION_DUE[SITE] is due
    assert browser._RESULT["renew_due"] is due
    assert round(browser._RESULT["session_age_d"]) == age
    del result


def test_no_record_starts_the_clock_never_a_submit(result: Path) -> None:
    browser._broker_note_session_age(SITE, ENTRY)
    assert browser._SESSION_DUE[SITE] is False
    rec = json.loads((browser.SESSION_AGE_DIR / f"{SITE}.json").read_text())
    assert time.time() - rec["first_seen_at"] < 60
    del result


def test_an_unreadable_or_unwritable_record_is_never_due(
    monkeypatch: pytest.MonkeyPatch, result: Path
) -> None:
    _age_state().write_text("{torn")
    browser._broker_note_session_age(SITE, ENTRY)
    assert browser._SESSION_DUE[SITE] is False
    assert browser._RESULT["session_age_d"] is None
    (browser.SESSION_AGE_DIR / f"{SITE}.json").unlink()
    monkeypatch.setattr(browser, "_session_age_write", lambda *_a, **_k: False)
    browser._broker_note_session_age(SITE, ENTRY)  # nothing on record, no write
    assert browser._SESSION_DUE[SITE] is False
    del result


def test_no_max_session_days_no_age(result: Path) -> None:
    browser._broker_note_session_age(SITE, {**ENTRY, "max_session_days": None})
    assert SITE not in browser._SESSION_DUE and "renew_due" not in browser._RESULT
    del result


class _Ctx:
    def cookies(self) -> list:
        return []

    def add_cookies(self, _cookies: list) -> None:
        pass


class _Browser:
    contexts = [_Ctx()]

    def close(self) -> None:
        pass


class _Pw:
    def stop(self) -> None:
        pass


def _logged_in_env(
    monkeypatch: pytest.MonkeyPatch, answers: list[int]
) -> list[tuple[str, dict]]:
    """The shared browser's check answers `answers` in turn (a VALID one notes
    the session age); the broker answers a fresh login. Returns the requests."""
    sent: list[tuple[str, dict]] = []

    def logged_in(_port: int, site: str) -> int:
        rc = answers.pop(0)
        if rc == 0:
            browser._result_set(phase="ok", code="ok")
            browser._broker_note_session_age(site, ENTRY)
        else:
            browser._result_fail("client-proof", "logged_out")
        return rc

    def request(op: str, **kw: Any) -> dict:
        sent.append((op, kw))
        return {"ok": True, "bundle": {"cookies": []}, "fresh_auth": True}

    monkeypatch.setattr(browser, "_broker_logged_in", logged_in)
    monkeypatch.setattr(browser, "_broker_entry_or_rc", lambda _s: (ENTRY, 0))
    monkeypatch.setattr(browser, "_connect", lambda _p: (_Pw(), _Browser()))
    monkeypatch.setattr(
        browser, "_interaction_lease", lambda _w: contextlib.nullcontext()
    )
    monkeypatch.setattr(browser, "_broker_request", request)
    monkeypatch.setattr(browser, "_broker_write_storage", lambda _p, _b, _o=None: 0)

    def check(_port: int, site: str, entry: dict, **_kw: Any) -> int:
        browser._broker_note_session_age(site, entry)  # as on a VALID proof
        return 0

    monkeypatch.setattr(browser, "_broker_check_entry", check)
    return sent


def test_an_old_session_is_renewed_with_a_fresh_login(
    monkeypatch: pytest.MonkeyPatch, result: Path
) -> None:
    state = _age_state(fresh_auth_at=time.time() - 29 * DAY)
    sent = _logged_in_env(monkeypatch, [0])
    assert browser._broker_login(9222, SITE) == 0
    assert sent == [("login", {"site": SITE})]  # a broker login, though logged in
    browser._result_write(0)
    rec = json.loads(result.read_text())
    assert rec["renewal"] == "renewed" and rec["fresh_auth"] is True
    assert rec["renew_due"] is False  # the verify saw the new record
    # the fresh login is on record: the next check is not due
    assert time.time() - json.loads(state.read_text())["fresh_auth_at"] < 60
    browser._broker_note_session_age(SITE, ENTRY)
    assert browser._SESSION_DUE[SITE] is False


def test_a_young_session_is_left_alone(
    monkeypatch: pytest.MonkeyPatch, result: Path
) -> None:
    _age_state(fresh_auth_at=time.time() - 2 * DAY)
    sent = _logged_in_env(monkeypatch, [0])
    assert browser._broker_login(9222, SITE) == 0
    assert not sent
    del result


def test_a_failed_renewal_keeps_the_working_session(
    monkeypatch: pytest.MonkeyPatch, result: Path
) -> None:
    _age_state(fresh_auth_at=time.time() - 29 * DAY)
    _logged_in_env(monkeypatch, [0, 0])
    refusal = {
        "ok": False,
        "error": "login_failed",
        "detail": "still on the login page after submitting the password",
        "phase": "submit",
        "submitted": True,
    }
    monkeypatch.setattr(browser, "_broker_request", lambda _op, **_kw: refusal)
    assert browser._broker_login(9222, SITE) == 0  # still logged in
    browser._result_write(0)
    rec = json.loads(result.read_text())
    assert rec["renewal"] == "failed" and rec["renewal_phase"] == "submit"
    assert als.quarantined(SITE) is not None  # a post-submit failure stays visible


def test_a_failed_injection_neither_renews_the_age_nor_retries(
    monkeypatch: pytest.MonkeyPatch, result: Path
) -> None:
    """The broker logged in fresh, but the session never reached the shared
    browser: the age stays (the shared session was not renewed), and the
    recorded attempt holds the next renewal off — no daily submit loop."""
    old = time.time() - 29 * DAY
    state = _age_state(fresh_auth_at=old)
    _logged_in_env(monkeypatch, [0, 0])
    monkeypatch.setattr(browser, "_broker_check_entry", lambda *_a, **_k: 2)
    assert browser._broker_login(9222, SITE) == 0  # the old session works
    rec = json.loads(state.read_text())
    assert rec["fresh_auth_at"] == old  # not advanced: nothing was injected
    assert time.time() - rec["renewal_attempt_at"] < 60
    browser._broker_note_session_age(SITE, ENTRY)
    assert browser._SESSION_DUE[SITE] is False  # held off for 20 h
    _age_state(fresh_auth_at=old, renewal_attempt_at=time.time() - 21 * 3600)
    browser._broker_note_session_age(SITE, ENTRY)
    assert browser._SESSION_DUE[SITE] is True  # the next daily check retries
    del result


def test_no_renewal_when_its_attempt_cannot_be_recorded(
    monkeypatch: pytest.MonkeyPatch, result: Path
) -> None:
    _age_state(fresh_auth_at=time.time() - 29 * DAY)
    sent = _logged_in_env(monkeypatch, [0])
    monkeypatch.setattr(browser, "_session_age_store", lambda *_a, **_k: False)
    monkeypatch.setattr(browser, "_broker_keep_fresh", lambda _p, _s: True)
    assert browser._broker_login(9222, SITE) == 0
    assert not sent  # never a submit without the record that holds off a retry
    del result


class _Req:
    def __init__(
        self, method: str, url: str, body: bytes = b"", *, nav: bool = False
    ) -> None:
        self.method = method
        self.url = url
        self.post_data_buffer = body
        self.headers = {"content-type": CWA_FORM}
        self.nav = nav
        self.redirected_from: _Req | None = None

    def is_navigation_request(self) -> bool:
        return self.nav


class _Route:
    def __init__(self, req: _Req, *, abort_fails: bool = False) -> None:
        self.request = req
        self.abort_fails = abort_fails
        self.aborted = self.continued = False

    def abort(self, _code: str) -> None:
        if self.abort_fails:
            raise RuntimeError("route already handled")
        self.aborted = True

    def continue_(self) -> None:
        self.continued = True


def _armed_trip() -> recipes.SubmitTripwire:
    ctx = SimpleNamespace(service_workers=[])
    trip = recipes.SubmitTripwire(
        SimpleNamespace(context=ctx), ["https://calibre.example"], dev=False
    )
    trip.protect.add("username")  # the login form's field: FORGOT carries it
    trip.arm()
    return trip


FORGOT = _Req("POST", "https://calibre.example/login", b"username=a&forgot=forgot")


def test_never_sent_needs_a_proven_abort() -> None:
    trip = _armed_trip()
    trip._seen(FORGOT)
    route = _Route(FORGOT, abort_fails=True)
    trip._handle(route)
    assert trip.tripped == "field forgot" and not trip.never_sent
    trip = _armed_trip()
    trip._seen(FORGOT)
    trip._handle(_Route(FORGOT))
    assert trip.never_sent


@pytest.mark.parametrize(
    "leak",
    [
        _Req("GET", "https://tracker.example/p?u=x"),  # any query, any origin
        _Req("OPTIONS", "https://calibre.example/api", b"x"),
        _Req("POST", "https://other.example/collect", b"x"),
    ],
)
def test_any_other_carrier_voids_never_sent(leak: _Req) -> None:
    trip = _armed_trip()
    trip._seen(leak)
    trip._seen(FORGOT)
    trip._handle(_Route(FORGOT))
    assert trip.tripped and not trip.never_sent


def test_a_fill_origin_service_worker_voids_never_sent() -> None:
    worker = SimpleNamespace(url="https://calibre.example/sw.js")
    ctx = SimpleNamespace(service_workers=[worker])
    trip = recipes.SubmitTripwire(
        SimpleNamespace(context=ctx), ["https://calibre.example"], dev=False
    )
    trip.protect.add("username")
    trip.arm()
    trip._seen(FORGOT)
    trip._handle(_Route(FORGOT))
    assert trip.tripped and not trip.never_sent


def test_a_get_form_is_screened_by_query_and_first_path() -> None:
    trip = _armed_trip()
    get_forgot = _Req("GET", "https://calibre.example/forgot?u=a", nav=True)
    route = _Route(get_forgot)
    trip._handle(route)
    assert route.aborted and trip.tripped == "path forgot"
    hop = _Req("GET", "https://calibre.example/register?next=%2F", nav=True)
    hop.redirected_from = get_forgot  # a redirect hop: its path is not judged
    route = _Route(hop)
    _armed_trip()._handle(route)
    assert route.continued
    asset = _Req("GET", "https://calibre.example/reset.css?v=2")  # not a navigation
    route = _Route(asset)
    _armed_trip()._handle(route)
    assert route.continued


def test_keycloak_never_clicks_a_hidden_fallback() -> None:
    hidden = _FakeButton(_button_desc(text="Sign In", visible=False))
    page = SimpleNamespace(
        query_selector=lambda _sel: None, query_selector_all=lambda _sel: [hidden]
    )
    assert not recipes.click_keycloak_submit(page, recipes.AttemptController())
    assert not hidden.clicked


def test_keycloak_guards_its_button_on_the_broker_path() -> None:
    class _FramedButton(_FakeButton):
        def owner_frame(self) -> Any:  # a cross-origin iframe's button
            return SimpleNamespace(url="https://evil.example/")

        def get_attribute(self, _name: str) -> None:
            return None

    login = _FramedButton(_button_desc(text="Sign In"))
    page = SimpleNamespace(
        url="https://auth.cscs.ch/login",
        query_selector=lambda sel: login if sel == "#kc-login" else None,
    )
    attempt = recipes.AttemptController()
    with pytest.raises(recipes.OriginViolation):
        recipes.click_keycloak_submit(
            page, attempt, allowed=["https://auth.cscs.ch"], dev=False
        )
    assert not attempt.submitted and not login.clicked


@pytest.mark.parametrize(
    ("url", "on"),
    [
        ("https://auth.cscs.ch/realms/cscs/login", True),
        ("https://auth.cscs.ch.evil.example/x", False),
        ("https://evil.example/?next=auth.cscs.ch", False),
        ("http://auth.cscs.ch/", False),
    ],
)
def test_cscs_auth_is_an_exact_origin(url: str, on: bool) -> None:
    assert browser._on_cscs_auth(url) is on


def test_direct_keycloak_login_without_a_button_submits_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(browser, "_click_keycloak_submit", lambda _page: False)
    page = SimpleNamespace(fill=lambda *_a: None)
    creds = SimpleNamespace(user=USER, password=PASSWORD, otp=lambda: "123456")
    assert browser._submit_keycloak_login(page, creds) is False


def test_a_failed_renewal_of_a_dead_session_fails(
    monkeypatch: pytest.MonkeyPatch, result: Path
) -> None:
    _age_state(fresh_auth_at=time.time() - 29 * DAY)
    _logged_in_env(monkeypatch, [0, 2])
    monkeypatch.setattr(
        browser,
        "_broker_request",
        lambda _op, **_kw: {"ok": False, "error": "rate_limited", "phase": "limiter"},
    )
    assert browser._broker_login(9222, SITE) == 2
    browser._result_write(2)
    assert json.loads(result.read_text())["phase"] == "limiter"


# ---------------------------------------------------------------------------
# E. agent-login: unreachable is no ❌, a due session is renewed
# ---------------------------------------------------------------------------


def _row(**kw: Any) -> dict:
    return {
        "site": SITE,
        "name": SITE,
        "status": "ready",
        "flow": "one-page",
        "stage": "usable",
        # promoted for the listed configuration (WS3 digest)
        "config": "c" * 64,
        "promoted_config": "c" * 64,
        "promoted_config_v": onboarding.CONFIG_V,
        **kw,
    }


def test_an_access_gated_check_is_unreachable_not_failed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        al, "probe", lambda _s: (2, {"phase": "precheck", "code": "access_gated"})
    )
    monkeypatch.setattr(al, "run_browser", _no_broker)  # never a login
    ok, how, res = al.ensure_logged_in(SITE)
    assert ok is None and how == al.UNREACHABLE_HOW
    assert res is not None and res["code"] == "access_gated"
    al.record_check(SITE, ok, how, res)
    state, _why = al.row_state(_row(), al.last_checks())
    assert state == "unreachable"
    data = {"rows": [_row()], "broker_ok": True, "secrets": []}
    summary = al.agent_summary(data, al.last_checks())
    assert f"❓ {SITE} (`{SITE}`): unreachable off-LAN (Cloudflare Access)" in summary
    assert f"❌ {SITE}" not in summary


def _run(rc: int, rec: dict) -> Any:
    return al.BrowserRun(rc, False, "", 0.0, rec)


def test_renew_step_logs_in_once(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, ...]] = []

    def run(*args: str, **_kw: Any) -> Any:
        calls.append(args)
        return _run(0, {"phase": "ok", "code": "ok", "renewal": "renewed"})

    monkeypatch.setattr(al, "run_browser", run)
    ok, how, _res = al.renew_step(SITE, _row(), {"renew_due": True}, "logged in")
    assert ok is True and "renewed" in how
    assert calls == [("login", SITE, "-s")]


def test_renew_step_respects_the_gates(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(al, "run_browser", _no_broker)
    ok, how, _res = al.renew_step(
        SITE, _row(stage="pending"), {"renew_due": True}, "logged in"
    )
    assert ok is True and "renewal due — pending" in how
    ok, how, _res = al.renew_step(SITE, _row(), {"renew_due": False}, "logged in")
    assert ok is True and how == "logged in"


def test_renew_step_reports_a_failed_renewal(monkeypatch: pytest.MonkeyPatch) -> None:
    rec = {
        "phase": "ok",
        "code": "ok",
        "renewal": "failed",
        "renewal_phase": "submit",
        "renewal_code": "login_failed",
    }
    monkeypatch.setattr(al, "run_browser", lambda *_a, **_k: _run(0, rec))
    ok, how, _res = al.renew_step(SITE, _row(), {"renew_due": True}, "logged in")
    assert ok is True and "session renewal FAILED" in how
    monkeypatch.setattr(
        al,
        "run_browser",
        lambda *_a, **_k: _run(2, {"phase": "client-proof", "code": "logged_out"}),
    )
    ok, how, _res = al.renew_step(SITE, _row(), {"renew_due": True}, "logged in")
    assert ok is False and how.startswith("NOT logged in")


def test_check_all_renews_a_due_session(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(al, "wait_for_network", lambda: True)
    monkeypatch.setattr(al, "ensure_browser_up", lambda: True)
    monkeypatch.setattr(al, "_browser", lambda *a, **_k: 0)  # reap-owned
    monkeypatch.setattr(
        al, "overview", lambda: {"broker_ok": True, "broker": "ok", "rows": [_row()]}
    )
    monkeypatch.setattr(
        al,
        "ensure_logged_in",
        lambda _s, gate=None: (True, "logged in", {"renew_due": True, "phase": "ok"}),
    )
    calls: list[tuple[str, ...]] = []

    def run(*args: str, **_kw: Any) -> Any:
        calls.append(args)
        return _run(0, {"phase": "ok", "code": "ok", "renewal": "renewed"})

    monkeypatch.setattr(al, "run_browser", run)
    assert al.check_all() == 0
    assert calls == [("login", SITE, "-s")]
    assert "renewed" in als.checks()[SITE]["how"]


def test_only_one_concurrent_renewal_claim_wins(result: Path) -> None:
    _age_state(fresh_auth_at=time.time() - 29 * DAY)
    results: list[bool] = []
    barrier = threading.Barrier(4)

    def claim() -> None:
        barrier.wait()
        results.append(browser._session_renewal_claim(SITE))

    threads = [threading.Thread(target=claim) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(results) == [False, False, False, True]
    del result


@pytest.mark.parametrize("label", ["Delete account", "Log out", "Unsubscribe"])
def test_destructive_buttons_are_never_the_login(label: str) -> None:
    desc = _button_desc(text=label)
    assert login_form.secondary_button_like(desc)
    assert login_form.pick_submit_button([desc]) == -1  # nothing to press


def test_a_fresh_login_with_a_preflight_is_prechecked_too() -> None:
    """CSCS has its own preflight; a fresh_login item still gets the status
    and Access precheck before anything is reserved."""
    page = SimpleNamespace(url="about:blank")

    def goto(url: str, **_kw: Any) -> Any:
        page.url = url
        return SimpleNamespace(status=403)

    page.goto = goto
    item = SimpleNamespace(site="cscs", login_url="https://portal.cscs.ch/profile/")
    with pytest.raises(recipes.LoginBlocked):
        daemon.PlaywrightRunner._access_precheck(page, item, None)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# F. overseer review (M1, M2, S3, S4 and the nice-to-haves)
# ---------------------------------------------------------------------------


def _bdesc(name: str, value: str, text: str) -> dict[str, Any]:
    return _button_desc(name=name, post_value=value, text=text)


def test_m1_rails_commit_name_is_shared_so_never_a_button_pair() -> None:
    descs = [
        _bdesc("commit", "Sign in", "Sign in"),
        _bdesc("commit", "Cancel", "Cancel"),
    ]
    pairs = login_form.secondary_pairs(descs)
    assert pairs == set()  # the login button uses `commit` too
    body = _form(login=USER, password=_PW, commit="Sign in")
    assert login_form.secondary_post("", body, CWA_FORM, button_pairs=pairs) is None


def test_m1_auth0_action_default_never_trips() -> None:
    descs = [
        _bdesc("action", "default", "Continue"),
        _bdesc("action", "passkey", "Use a passkey"),
    ]
    pairs = login_form.secondary_pairs(descs)
    assert pairs == set()
    body = _form(state="s", username=USER, password=_PW, action="default")
    hit = login_form.secondary_post(
        "", body, CWA_FORM, protect={"password"}, button_pairs=pairs
    )
    assert hit is None


def test_m1_a_pair_matches_name_and_value_only() -> None:
    pairs = login_form.secondary_pairs(
        [_bdesc("forgot", "forgot", "Forgot Password?"), _bdesc("submit", "", "Login")]
    )
    assert pairs == {("forgot", "forgot")}
    assert login_form.secondary_hit("", [("forgot", "forgot")], button_pairs=pairs)
    # same name, other value: not that button (an action word still trips)
    hit = login_form.secondary_hit(
        "", [("Forgot", "x")], button_pairs={("forgot", "y")}
    )
    assert hit == "field Forgot"
    assert (
        login_form.secondary_hit("", [("op", "x")], button_pairs={("op", "y")}) is None
    )


def test_m1_a_step_replaces_the_last_steps_pairs() -> None:
    trip = _armed_trip()
    trip.step([_bdesc("next", "1", "Forgot e-mail?")])
    assert trip.button_pairs == {("next", "1")}
    trip.step([_bdesc("next", "1", "Sign in")])  # page 2 reuses the name
    assert trip.button_pairs == set()


def _spa_trip() -> recipes.SubmitTripwire:
    trip = _armed_trip()
    trip.protect.update({"identity", "secret"})
    return trip


def _json_req(url: str, obj: Any, *, nav: bool = False) -> _Req:
    req = _Req("POST", url, json.dumps(obj).encode(), nav=nav)
    req.headers = {"content-type": "application/json"}
    return req


def test_m2_app_traffic_after_an_xhr_login_never_trips() -> None:
    trip = _spa_trip()
    route = _Route(_json_req("https://calibre.example/api/tokens", {"identity": USER}))
    trip._handle(route)
    assert route.continued and trip.proof["login_sent"]
    after = [
        _json_req("https://calibre.example/api/push/register", {"a": 1}),
        _json_req("https://calibre.example/api/x", {"e": {"recovery": "1"}}),
        # even a form navigation after the login is the app's business
        _Req("POST", "https://calibre.example/account/recovery", b"t=1", nav=True),
    ]
    for req in after:
        route = _Route(req)
        trip._handle(route)
        assert route.continued and not trip.tripped


def test_m2_only_shielded_requests_or_form_navigations_are_screened() -> None:
    trip = _spa_trip()
    xhr = _Req("POST", "https://calibre.example/api/register", b"a=1")  # no shield
    route = _Route(xhr)
    trip._handle(route)
    assert route.continued and not trip.tripped
    nav = _Req("POST", "https://calibre.example/register", b"a=1", nav=True)
    route = _Route(nav)
    trip._handle(route)  # a form navigation before the login: screened
    assert route.aborted and trip.tripped == "path register"


def test_never_sent_tracks_request_identity() -> None:
    trip = _armed_trip()
    other = _Req("POST", "https://calibre.example/x", b"a=1")
    trip._seen(other)  # left the browser, never aborted
    trip._handle(_Route(FORGOT))  # aborted — but `other` was not this one
    assert trip.tripped and not trip.never_sent


def test_a_get_with_authorization_is_a_carrier() -> None:
    basic = _Req("GET", "https://komga.example/api/v1/users/me")
    basic.headers = {"authorization": "Basic <runtime>"}
    assert recipes.SubmitTripwire._carrier(basic)
    plain = _Req("GET", "https://komga.example/app.js")
    plain.headers = {}
    assert not recipes.SubmitTripwire._carrier(plain)


def test_a_tripped_tripwire_keeps_screening() -> None:
    calls: list[str] = []
    ctx = SimpleNamespace(
        service_workers=[],
        on=lambda *_a: calls.append("on"),
        route=lambda *_a: calls.append("route"),
        unroute=lambda *_a: calls.append("unroute"),
        remove_listener=lambda *_a: calls.append("off"),
    )
    page = SimpleNamespace(context=ctx)
    trip = recipes.SubmitTripwire(page, ["https://calibre.example"], dev=False)
    with pytest.raises(recipes.SecondaryActionBlocked):
        with trip:
            trip.tripped = "field forgot"
            trip.check()
    assert calls == ["on", "route"]  # left in place until the context closes
    with recipes.SubmitTripwire(page, ["https://calibre.example"], dev=False):
        pass
    assert calls[-2:] == ["unroute", "off"]


@pytest.mark.parametrize(
    "label", ["Don't remember me", "Do not remember me", "Nicht angemeldet bleiben"]
)
def test_a_negated_remember_me_is_never_ticked(label: str) -> None:
    assert not login_form.remember_me_like({"name": "x", "label": label})


def test_resend_is_secondary_and_verify_is_clicked() -> None:
    resend = _button_desc(text="Resend code")
    verify = _button_desc(text="Verify")
    assert login_form.secondary_button_like(resend)
    assert login_form.pick_submit_button([resend, verify]) == 1


class _BlockedResp:
    def __init__(self, status: int, headers: dict[str, str]) -> None:
        self.status = status
        self.headers = headers


def test_s4_a_cloudflare_challenge_403_needs_a_human(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(recipes, "challenge_reason", lambda _p: None)
    page = SimpleNamespace(url="https://calibre.example/login")
    challenge = _BlockedResp(403, {"cf-mitigated": "challenge"})
    with pytest.raises(recipes.NeedsHuman) as err:
        recipes.raise_if_blocked(page, challenge)
    assert err.value.phase == "precheck" and not err.value.submitted
    monkeypatch.setattr(recipes, "challenge_reason", lambda _p: "captcha")
    with pytest.raises(recipes.NeedsHuman):  # "Just a moment" interstitial
        recipes.raise_if_blocked(page, _BlockedResp(403, {}))
    monkeypatch.setattr(recipes, "challenge_reason", lambda _p: None)
    with pytest.raises(recipes.LoginBlocked):
        recipes.raise_if_blocked(page, _BlockedResp(403, {}))
    recipes.raise_if_blocked(page, _BlockedResp(200, {}))  # not blocked


def test_a_fresh_login_never_reports_renew_due(
    monkeypatch: pytest.MonkeyPatch, result: Path
) -> None:
    """Logged out with an old record: the login is fresh, so the result says
    renew_due false although the verify judged the old record."""
    _age_state(fresh_auth_at=time.time() - 40 * DAY)
    sent = _logged_in_env(monkeypatch, [2])
    assert browser._broker_login(9222, SITE) == 0
    assert sent == [("login", {"site": SITE})]
    browser._result_write(0)
    rec = json.loads(result.read_text())
    assert rec["fresh_auth"] is True and rec["renew_due"] is False


@pytest.mark.launches_chrome
@CHROME
def test_an_otp_form_with_a_resend_default_clicks_verify(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from playwright.sync_api import (  # pylint: disable=import-outside-toplevel
        sync_playwright,
    )

    html = """<html><body>
<form method=post action="/otp" onsubmit="event.preventDefault();
    document.title = 'submitted:' + (event.submitter ? event.submitter.name : '')">
  <input name=otp autocomplete=one-time-code>
  <button type=submit name=resend value=1>Resend code</button>
  <button type=submit name=verify value=1>Verify</button>
</form></body></html>"""
    monkeypatch.setattr(recipes, "_guard", lambda *a, **k: None)
    monkeypatch.setattr(
        recipes, "_click_on_fill_origin", lambda _p, el, _a, dev: el.click()
    )
    monkeypatch.setattr(recipes, "_frame_url", lambda _h: "https://auth.example/otp")
    with sync_playwright() as pw:
        chrome = pw.chromium.launch(headless=True)
        try:
            page = chrome.new_page()
            page.set_content(html)
            field_ = page.query_selector("input[name=otp]")
            assert field_ is not None
            field_.fill("123456")

            monkeypatch.setattr(recipes, "_guarded_button", lambda *_a, **_k: "")
            recipes._submit_password(page, field_, [], dev=False)
            page.wait_for_timeout(200)
            assert page.title() == "submitted:verify"
        finally:
            chrome.close()


def test_an_attempt_time_rounded_up_still_holds_off(result: Path) -> None:
    """`renewal_attempt_at` is rounded to ms and can lie a hair in the
    future: it must still count as a recent attempt (found by the
    concurrency test: two claims won)."""
    _age_state(
        fresh_auth_at=time.time() - 29 * DAY, renewal_attempt_at=time.time() + 0.0005
    )
    assert browser._session_renewal_claim(SITE) is False
    browser._broker_note_session_age(SITE, ENTRY)
    assert browser._SESSION_DUE[SITE] is False
    del result
