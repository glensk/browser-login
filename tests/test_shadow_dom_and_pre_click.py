"""Shadow-DOM login forms (Home Assistant) and ``agent_pre_click`` (Jellyfin).

Home Assistant (``ha.dom42.space``, 2026-10-08): ``ha-auth-flow`` renders its
username and password inputs each inside a web component's OPEN shadow root.
Playwright's CSS engine pierces open shadow roots, so the password field was
found — but ``USERNAME_JS`` searched ``pw.form || document`` with
``querySelectorAll``, which never enters a shadow root, so the username stayed
empty. It now falls back to every input of the password's frame, open shadow
roots included (inputs of ANOTHER form skipped).

Jellyfin (``jellyfin.dom42.space``): the login page first shows a user picker;
the manual form (``#txtManualName`` / ``#txtManualPassword``) appears only
after a click on ``.btnManual``. The item field ``agent_pre_click`` names that
element; the generic recipe clicks it once, on a fill origin, before looking
for login fields.

Hermetic by default (vault parsing, a fake page). The real-browser tests
(`-m browser`, opt-in via LOGIN_BROKER_E2E=1) run a throwaway headless
Chromium against local fixture sites; no real site is contacted.

Run: uv run --no-sync pytest tests/test_shadow_dom_and_pre_click.py
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
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from broker import daemon, limiter, login_form, recipes, vault  # noqa: E402

USER = "alice"
PASSWORD = "pw-Sh4dowTest!"  # fixture value, never a real one
SESSION = "sess-shadow-0123"
ORIGIN = "https://ha.example"

E2E = pytest.mark.skipif(
    os.environ.get("LOGIN_BROKER_E2E") != "1", reason="set LOGIN_BROKER_E2E=1"
)

# ---------------------------------------------------------------------------
# A. agent_pre_click parsing (vault.py)
# ---------------------------------------------------------------------------


def _item(**fields: str) -> dict[str, Any]:
    base = {"agent_fill_origins": ORIGIN, "agent_check_url": ORIGIN + "/"}
    base.update(fields)
    return {
        "id": "id-x",
        "name": "Jellyfin",
        "fields": [{"name": k, "value": v, "type": 0} for k, v in base.items()],
    }


def test_pre_click_parsed():
    it = vault.site_item_from_json(_item(agent_pre_click="  .btnManual "))
    assert it.refused is None
    assert it.pre_click == ".btnManual"
    assert it.public()["pre_click"] == ".btnManual"


def test_pre_click_absent_is_none():
    it = vault.site_item_from_json(_item())
    assert it.refused is None
    assert it.pre_click is None
    assert it.public()["pre_click"] is None


@pytest.mark.parametrize("raw", [".a\n.b", ".a\r.b", "x" * 513])
def test_bad_pre_click_refuses_the_item(raw):
    it = vault.site_item_from_json(_item(agent_pre_click=raw))
    assert it.refused is not None
    assert "agent_pre_click" in it.refused


# ---------------------------------------------------------------------------
# B. _pre_click on a fake page
# ---------------------------------------------------------------------------


class _Frame:
    def __init__(self, url: str) -> None:
        self.url = url


class _Button:
    """Visible until clicked: the click opens the form, like Jellyfin's."""

    def __init__(self, frame_url: str) -> None:
        self.frame_url = frame_url
        self.clicks = 0

    def is_visible(self) -> bool:
        return self.clicks == 0

    def owner_frame(self) -> _Frame:
        return _Frame(self.frame_url)

    def click(self) -> None:
        self.clicks += 1


class _Page:
    def __init__(self, url: str, button: _Button | None) -> None:
        self.url = url
        self.button = button
        self.waits = 0

    def query_selector_all(self, selector: str) -> list[Any]:
        return [self.button] if selector == ".btnManual" and self.button else []

    def wait_for_timeout(self, _ms: float) -> None:
        self.waits += 1


@pytest.fixture
def no_password(monkeypatch):
    monkeypatch.setattr(recipes, "_check_challenge", lambda *a, **k: None)
    monkeypatch.setattr(recipes, "_login_password", lambda page: None)
    monkeypatch.setattr(recipes, "_login_username", lambda page: None)


@pytest.mark.usefixtures("no_password")
def test_pre_click_clicks_once_on_a_fill_origin():
    button = _Button(ORIGIN + "/web/")
    page = _Page(ORIGIN + "/web/", button)
    assert recipes._pre_click(page, ".btnManual", [ORIGIN], dev=False)
    assert button.clicks == 1


@pytest.mark.usefixtures("no_password")
def test_pre_click_refused_off_the_fill_origins():
    button = _Button("https://evil.example/")
    page = _Page("https://evil.example/", button)
    with pytest.raises(recipes.OriginViolation):
        recipes._pre_click(page, ".btnManual", [ORIGIN], dev=False)
    assert button.clicks == 0


@pytest.mark.usefixtures("no_password")
def test_pre_click_refused_in_a_foreign_frame():
    button = _Button("https://evil.example/frame")
    page = _Page(ORIGIN + "/web/", button)
    with pytest.raises(recipes.OriginViolation):
        recipes._pre_click(page, ".btnManual", [ORIGIN], dev=False)
    assert button.clicks == 0


def test_pre_click_skipped_when_the_password_shows_first(monkeypatch):
    monkeypatch.setattr(recipes, "_check_challenge", lambda *a, **k: None)
    monkeypatch.setattr(recipes, "_login_password", lambda page: object())
    page = _Page(ORIGIN + "/web/", None)
    assert not recipes._pre_click(page, ".btnManual", [ORIGIN], dev=False)
    assert page.waits == 0


# ---------------------------------------------------------------------------
# C. USERNAME_JS in a real headless Chromium (no broker)
# ---------------------------------------------------------------------------

# A web component holding ONE input in its open shadow root (HA's
# ha-textfield / mwc-textfield), and ha-auth-flow with a <form> in its own
# shadow root around two of them — so neither input is associated with a form.
_COMPONENTS = """
<script>
class HaTextfield extends HTMLElement {
  connectedCallback() {
    if (this.shadowRoot) return;
    const root = this.attachShadow({mode: 'open'});
    const i = document.createElement('input');
    for (const a of ['type', 'name', 'autocomplete']) {
      if (this.hasAttribute(a)) i.setAttribute(a, this.getAttribute(a));
    }
    root.appendChild(i);
  }
  get value() { return this.shadowRoot.querySelector('input').value; }
}
customElements.define('ha-textfield', HaTextfield);
class HaAuthFlow extends HTMLElement {
  connectedCallback() {
    if (this.shadowRoot) return;
    const root = this.attachShadow({mode: 'open'});
    const tag = this.hasAttribute('tagged') ? ' autocomplete="username"' : '';
    root.innerHTML = '<form>'
      + '<ha-textfield name="username"' + tag + '></ha-textfield>'
      + '<ha-textfield name="password" type="password"'
      + ' autocomplete="current-password"></ha-textfield>'
      + '<button type="button" id="next">Log in</button></form>';
    root.addEventListener('keydown', ev => {
      if (ev.key !== 'Enter') return;
      const [u, p] = root.querySelectorAll('ha-textfield');
      fetch('/auth/login_flow', {method: 'POST',
        body: JSON.stringify({username: u.value, password: p.value})})
        .then(r => { if (r.ok) location.href = '/lovelace'; });
    });
  }
}
customElements.define('ha-auth-flow', HaAuthFlow);
</script>
"""


def _ha_page(tagged: bool) -> str:
    attr = " tagged" if tagged else ""
    return (
        "<html><head><title>Home Assistant</title>"
        + _COMPONENTS
        + "</head><body><ha-authorize>"
        + f"<ha-auth-flow{attr}></ha-auth-flow>"
        + "</ha-authorize></body></html>"
    )


@contextlib.contextmanager
def _page() -> Iterator[Any]:
    from playwright.sync_api import sync_playwright

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        try:
            yield browser.new_page()
        finally:
            browser.close()


def _username_for_password(page: Any) -> dict[str, Any] | None:
    pw_field = recipes._login_password(page)
    assert pw_field is not None
    handle = pw_field.evaluate_handle(login_form.USERNAME_JS)
    el = handle.as_element() if handle is not None else None
    if el is None:
        return None
    desc: dict[str, Any] = el.evaluate(
        "e => ({name: e.getAttribute('name') || '', id: e.id || ''})"
    )
    return desc


@pytest.mark.browser
@E2E
@pytest.mark.parametrize("tagged", [True, False], ids=["autocomplete", "untagged"])
def test_username_found_inside_shadow_roots(tagged):
    with _page() as page:
        page.set_content(_ha_page(tagged))
        assert _username_for_password(page) == {"name": "username", "id": ""}


@pytest.mark.browser
@E2E
def test_shadow_fallback_skips_inputs_of_another_form():
    # A register form in one shadow root, a form-less password in another:
    # the shadow fallback must not hand back the register form's e-mail.
    html = (
        "<html><body><div id=reg></div><div id=login></div><script>"
        "const shadow = id => document.getElementById(id)"
        "  .attachShadow({mode: 'open'});"
        "shadow('reg').innerHTML = '<form><input type=email name=reg_email></form>';"
        "shadow('login').innerHTML = '<input type=password name=password>';"
        "</script></body></html>"
    )
    with _page() as page:
        page.set_content(html)
        assert _username_for_password(page) is None


@pytest.mark.browser
@E2E
def test_light_dom_same_form_rule_unchanged():
    html = (
        "<html><body>"
        "<form id=register><input type=email name=reg_email>"
        "<input type=password name=reg_password autocomplete=new-password></form>"
        "<form id=login><input type=email name=email id=email>"
        "<input type=password name=password autocomplete=current-password></form>"
        "</body></html>"
    )
    with _page() as page:
        page.set_content(html)
        assert _username_for_password(page) == {"name": "email", "id": "email"}


# ---------------------------------------------------------------------------
# D. end to end through the broker daemon: HA-like and Jellyfin-like sites
# ---------------------------------------------------------------------------


class _App(http.server.BaseHTTPRequestHandler):
    tagged = True
    picker = True
    logins: list[bool] = []

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

    def _logged_in(self) -> bool:
        return f"session={SESSION}" in (self.headers.get("Cookie") or "")

    def _ok(self) -> list[tuple[str, str]]:
        return [("Set-Cookie", f"session={SESSION}; Path=/; Max-Age=3600; HttpOnly")]

    def do_GET(self):  # noqa: N802
        cls = type(self)
        if self.path.startswith(("/lovelace", "/web/home")):
            if self._logged_in():
                self._send(200, "<html><body><h1 id=welcome>Home</h1></body></html>")
            else:
                self._send(200, "<html><body>please log in</body></html>")
        elif self.path.startswith("/auth/authorize"):
            self._send(200, _ha_page(cls.tagged))
        elif self.path.startswith("/web/index"):
            self._send(200, _jellyfin_page(cls.picker))
        else:
            self._send(404, "nope")

    def do_POST(self):  # noqa: N802
        cls = type(self)
        body = self._body()
        if self.path == "/auth/login_flow":
            data = json.loads(body or "{}")
            ok = data == {"username": USER, "password": PASSWORD}
            cls.logins.append(ok)
            self._send(200 if ok else 400, "{}", self._ok() if ok else ())
        elif self.path == "/Users/AuthenticateByName":
            q = parse_qs(body)
            ok = q.get("Username") == [USER] and q.get("Pw") == [PASSWORD]
            cls.logins.append(ok)
            headers = [("Location", "/web/home" if ok else "/web/index.html")]
            self._send(302, "", headers + (self._ok() if ok else []))
        else:
            self._send(404, "nope")


def _jellyfin_page(picker: bool) -> str:
    """Jellyfin's login: a user picker (shown by script, like the SPA) whose
    `.btnManual` reveals the hidden manual form; without a picker the manual
    form shows at once."""
    form_style = "display:none" if picker else ""
    script = (
        "<script>"
        "const picker = document.getElementById('picker');"
        "const form = document.getElementById('manualLoginForm');"
        "setTimeout(() => { picker.style.display = 'block'; }, 300);"
        "document.querySelector('.btnManual').addEventListener('click', () => {"
        "  picker.style.display = 'none'; form.style.display = 'block'; });"
        "</script>"
        if picker
        else ""
    )
    return (
        "<html><head><title>Jellyfin</title></head><body>"
        "<div id=picker style='display:none'><div class=card>alice</div>"
        "<button type=button class='raised btnManual'>Manual Login</button></div>"
        f"<form id=manualLoginForm style='{form_style}' method=post "
        "action=/Users/AuthenticateByName>"
        "<input id=txtManualName name=Username type=text>"
        "<input id=txtManualPassword name=Pw type=password>"
        "<button type=submit>Sign In</button></form>" + script + "</body></html>"
    )


@contextlib.contextmanager
def _server() -> Iterator[str]:
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _App)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    _App.logins = []
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


def _broker_login(tmp_path: Path, site: str, fields: dict[str, str]) -> dict[str, Any]:
    item = {
        "id": f"id-{site}",
        "name": site,
        "login": {"username": USER, "password": PASSWORD},
        "fields": [
            {"name": k, "value": v, "type": 0}
            for k, v in {"agent_site": site, **fields}.items()
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
    sockdir = Path(tempfile.mkdtemp(prefix="lb-"))  # AF_UNIX path length cap
    try:
        path = str(sockdir / "b.sock")
        srv = daemon.make_server(path, brk, os.getuid())
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            return _ask(path, {"op": "login", "site": site})
        finally:
            srv.shutdown()
            srv.server_close()
    finally:
        shutil.rmtree(sockdir, ignore_errors=True)


def _assert_logged_in(result: dict[str, Any]) -> None:
    assert result["ok"], result
    assert result["bundle"]["via"] == "login"
    assert [(c["name"], c["value"]) for c in result["bundle"]["cookies"]] == [
        ("session", SESSION)
    ]
    assert _App.logins == [True]  # one submit, with the username filled
    assert PASSWORD not in json.dumps(result)


@pytest.mark.browser
@E2E
@pytest.mark.parametrize("tagged", [True, False], ids=["autocomplete", "untagged"])
def test_e2e_home_assistant_shadow_dom_login(tmp_path, tagged):
    _App.tagged = tagged
    with _server() as origin:
        result = _broker_login(
            tmp_path,
            "halike",
            {
                "agent_fill_origins": origin,
                "agent_check_url": origin + "/lovelace",
                "agent_login_url": origin + "/auth/authorize",
                "agent_logged_in_selector": "#welcome",
            },
        )
    _assert_logged_in(result)


@pytest.mark.browser
@E2E
@pytest.mark.parametrize("picker", [True, False], ids=["picker", "no-picker"])
def test_e2e_jellyfin_pre_click_reveals_the_manual_form(tmp_path, picker):
    _App.picker = picker
    with _server() as origin:
        result = _broker_login(
            tmp_path,
            "jellylike",
            {
                "agent_fill_origins": origin,
                "agent_check_url": origin + "/web/home",
                "agent_login_url": origin + "/web/index.html",
                "agent_logged_in_selector": "#welcome",
                "agent_pre_click": ".btnManual",
            },
        )
    _assert_logged_in(result)
