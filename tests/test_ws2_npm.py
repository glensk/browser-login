"""WS2-npm: storage-token SPA logins (Nginx Proxy Manager 2.x) end to end.

Live evidence (2026-10-10): the broker's NPM login SUCCEEDED server-side
(``POST /api/tokens`` 200, ``GET /api/users/me`` 200), but its persistent
profile served the SPA's ``index.html`` of the PREVIOUS build from its
heuristic HTTP cache (no Cache-Control, an old Last-Modified). That build's
lazy Dashboard chunk no longer existed; the server's SPA fallback answered it
with HTML, the import failed and the page stayed blank — reported as "still on
the login page after submitting the password" and quarantined.

The fixture app below behaves like NPM: the login form POSTs ``/api/tokens``,
stores ``[{token, expires}]`` under localStorage ``authentications`` and
reloads; the dashboard (a lazy chunk) asks ``/api/users/me`` with the bearer and
renders a HIDDEN navbar ``a[href='/nginx/proxy']`` first, the visible card
``a.card-link[href='/nginx/proxy']`` a moment later; a 401 clears the token and
shows the login form. Missing assets get the SPA fallback HTML, like NPM.

The broker tests drive the REAL runner (its own disposable headless Chromium,
never browser.py's shared one); skipped when Playwright's Chromium is missing.
"""
# pylint: disable=duplicate-code,too-many-lines

from __future__ import annotations

# pylint: disable=protected-access,missing-function-docstring,missing-class-docstring
# pylint: disable=import-error,wrong-import-position,too-few-public-methods
import contextlib
import functools
import http.server
import importlib.util
import json
import os
import secrets
import sys
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import formatdate
from pathlib import Path
from typing import Any

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from broker import daemon, limiter, page_state, phases, recipes, vault  # noqa: E402

USER = "admin@example.com"
PASSWORD = "pw-Npm-Fixture-1"
SENTINEL = "a.card-link[href='/nginx/proxy']"
TOKEN_KEY = "authentications"
# An old Last-Modified and no Cache-Control: Chrome caches the page
# heuristically for days, like NPM's index.html.
OLD_LAST_MODIFIED = formatdate(1_700_000_000, usegmt=True)


def _load(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


browser = _load("browser_ws2_npm_test", REPO / "bin" / "browser.py")


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
# The NPM-like fixture app
# ---------------------------------------------------------------------------

_HTML = """<!doctype html><html><head><title>NPM fixture</title>
<script type=module src="/assets/main-{build}.js"></script></head>
<body><div id=root></div></body></html>"""

_MAIN_JS = """const KEY = 'authentications';
const root = document.getElementById('root');
const token = () => {
  try { const l = JSON.parse(localStorage.getItem(KEY) || '[]');
        return l.length ? l[l.length - 1].token : null; }
  catch (e) { return null; }
};
function loginForm(msg) {
  root.innerHTML = '<form id=login><input type=email name=identity autocomplete=email>'
    + '<input type=password name=secret autocomplete=current-password>'
    + '<button type=submit>Sign in</button>'
    + (msg ? '<div class=error>' + msg + '</div>' : '') + '</form>';
  document.getElementById('login').addEventListener('submit', async ev => {
    ev.preventDefault();
    const f = ev.target;
    const r = await fetch('/api/tokens', {method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({identity: f.identity.value, secret: f.secret.value})});
    if (!r.ok) { loginForm('Invalid email or password'); return; }
    const b = await r.json();
    localStorage.setItem(KEY, JSON.stringify([{token: b.token, expires: b.expires}]));
    {after_login}
  });
}
async function boot() {
  const t = token();
  if (!t) { loginForm(''); return; }
  const r = await fetch('/api/users/me?expand=permissions',
                        {headers: {Authorization: 'Bearer ' + t}});
  if (r.status === 401) { localStorage.removeItem(KEY); location.reload(); return; }
  root.innerHTML = '<nav><a class=nav-link href="/nginx/proxy" style="display:none">'
    + 'Proxy Hosts</a></nav>';
  try { (await import('/assets/dash-{build}.js')).render(root); }
  catch (e) { root.innerHTML = ''; }
}
boot();
"""

_DASH_JS = """export function render(root) {
  setTimeout(() => {
    const a = document.createElement('a');
    a.className = 'card-link'; a.href = '/nginx/proxy'; a.textContent = 'Proxy Hosts';
    root.appendChild(a);
  }, 700);
}
"""


@dataclass
class _NpmApp:  # pylint: disable=too-many-instance-attributes
    """Server-side state of one fixture NPM."""

    build: str = "a"
    login_ttl_s: float = 24 * 3600
    blank: bool = False  # the dashboard chunk is missing: blank forever
    # After the token is stored: reload the page, or (NPM 2.16 itself) render
    # the dashboard in place — a reload would revalidate a stale index.html.
    reload_after_login: bool = True
    refuse_refresh: bool = False
    refresh_status: int | None = None  # e.g. 403: a WAF in front of the API
    refresh_delay_s: float = 0.0  # a hanging refresh endpoint
    tokens: dict[str, float] = field(default_factory=dict)
    logins: int = 0
    refreshes: int = 0

    def issue(self, ttl_s: float) -> dict[str, str]:
        token = secrets.token_hex(16)
        exp = time.time() + ttl_s
        self.tokens[token] = exp
        iso = datetime.fromtimestamp(exp, tz=timezone.utc).isoformat()
        return {"token": token, "expires": iso.replace("+00:00", "Z")}

    def valid(self, auth: str | None) -> str | None:
        token = (auth or "").removeprefix("Bearer ")
        exp = self.tokens.get(token)
        return token if exp is not None and exp > time.time() else None


class _Server(http.server.ThreadingHTTPServer):
    app: _NpmApp


class _Handler(http.server.BaseHTTPRequestHandler):
    server: _Server

    def log_message(self, *args: Any) -> None:
        return

    def _send(
        self, code: int, body: str, ctype: str, *, cacheable: bool = False
    ) -> None:
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        if cacheable:
            self.send_header("Last-Modified", OLD_LAST_MODIFIED)
        else:
            self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _json(self, code: int, obj: object) -> None:
        self._send(code, json.dumps(obj), "application/json")

    def do_GET(self) -> None:  # noqa: N802
        app = self.server.app
        path = self.path.split("?", 1)[0]
        auth = self.headers.get("Authorization")
        if path == "/api/users/me":
            if app.valid(auth):
                self._json(200, {"id": 1})
            else:
                self._json(401, {"error": {"message": "Unauthorized"}})
            return
        if path == "/api/tokens":
            if app.refresh_delay_s:
                time.sleep(app.refresh_delay_s)
            if app.refresh_status:
                self._json(app.refresh_status, {"error": {"message": "blocked"}})
                return
            if app.valid(auth) and not app.refuse_refresh:
                app.refreshes += 1
                self._json(200, app.issue(24 * 3600))
            else:
                self._json(401, {"error": {"message": "Unauthorized"}})
            return
        js = "application/javascript"
        if path == "/sw.js":
            self._send(200, "self.addEventListener('fetch', () => {});", js)
        elif path == f"/assets/main-{app.build}.js":
            after = "location.reload();" if app.reload_after_login else "boot();"
            main = _MAIN_JS.replace("{build}", app.build).replace(
                "{after_login}", after
            )
            self._send(200, main, js, cacheable=True)
        elif path == f"/assets/dash-{app.build}.js" and not app.blank:
            self._send(200, _DASH_JS, js, cacheable=True)
        else:  # the SPA fallback, for missing assets too (like NPM)
            page = _HTML.replace("{build}", app.build)
            self._send(200, page, "text/html", cacheable=True)

    def do_POST(self) -> None:  # noqa: N802
        app = self.server.app
        n = int(self.headers.get("Content-Length") or 0)
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
        except ValueError:
            body = {}
        if self.path == "/api/tokens" and body == {
            "identity": USER,
            "secret": PASSWORD,
        }:
            app.logins += 1
            self._json(200, app.issue(app.login_ttl_s))
            return
        self._json(400, {"error": {"message": "Invalid email or password"}})


@pytest.fixture(name="npm")
def _npm() -> Iterator[tuple[_NpmApp, str]]:
    httpd = _Server(("127.0.0.1", 0), _Handler)
    httpd.app = _NpmApp()
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        yield httpd.app, f"http://127.0.0.1:{httpd.server_address[1]}"
    finally:
        httpd.shutdown()
        httpd.server_close()


# ---------------------------------------------------------------------------
# Broker plumbing
# ---------------------------------------------------------------------------


class _CountingVault:
    """The fixture vault, counting secret reads (a reuse must need none)."""

    def __init__(self, inner: vault.FixtureVault) -> None:
        self._inner = inner
        self.secret_calls = 0

    def items(self) -> list[vault.SiteItem]:
        return self._inner.items()

    def secret(self, site: str) -> vault.Secret:
        self.secret_calls += 1
        return self._inner.secret(site)


def _item_json(origin: str, password: str = PASSWORD, **extra: str) -> dict[str, Any]:
    fields = {
        "agent_site": "npmfix",
        "agent_fill_origins": origin,
        "agent_check_url": origin + "/",
        "agent_login_url": origin + "/",
        "agent_logged_in_selector": SENTINEL,
        "agent_storage_keys": json.dumps({origin: [TOKEN_KEY]}),
        "agent_session_refresh": "npm-jwt",
        **extra,
    }
    return {
        "id": "id-npmfix",
        "name": "NPM fixture",
        "login": {"username": USER, "password": password},
        "fields": [{"name": k, "value": v} for k, v in fields.items()],
    }


@dataclass
class _Rig:
    brk: daemon.Broker
    lim: limiter.Limiter
    vault: _CountingVault
    home: Path

    def login(self) -> dict[str, Any]:
        return self.brk._login_request("npmfix", {})

    def limiter_bytes(self) -> bytes:
        path = self.home / "limiter.json"
        return path.read_bytes() if path.exists() else b""


def _rig(tmp_path: Path, origin: str, password: str = PASSWORD) -> _Rig:
    fixture = tmp_path / "items.json"
    fixture.write_text(json.dumps([_item_json(origin, password)]))
    home = tmp_path / "home"
    lim = limiter.Limiter(home / "limiter.json", 0, 100, 100)
    counting = _CountingVault(vault.FixtureVault(fixture, dev=True))
    brk = daemon.Broker(
        counting,  # type: ignore[arg-type]
        lim,
        home,
        runner=daemon.PlaywrightRunner(home, dev=True),
    )
    return _Rig(brk, lim, counting, home)


@pytest.fixture(name="fast")
def _fast(monkeypatch: pytest.MonkeyPatch) -> None:
    """Shorter waits: the logged-out profile proof and the settle loop."""
    monkeypatch.setattr(daemon, "PROFILE_PROOF_WAIT_S", 2.5)
    monkeypatch.setattr(
        daemon,
        "recipe_for",
        lambda site: functools.partial(recipes.generic_login, settle_s=4.0),
    )


def _token_in(bundle: dict[str, Any], origin: str) -> dict[str, Any]:
    raw = bundle["storage"][origin][TOKEN_KEY]
    entries = json.loads(raw)
    assert isinstance(entries, list) and entries
    last: dict[str, Any] = entries[-1]
    return last


def _cooldown(lim: limiter.Limiter, site: str = "npmfix") -> None:
    now = time.time()
    grant = lim.reserve_site(site, now)
    assert isinstance(grant, limiter.AttemptGrant)
    lim.mark_submitted(grant)
    lim.finish(grant, "unknown", now)
    assert lim.peek([site], time.time()) is not None


# ---------------------------------------------------------------------------
# The broker against the fixture NPM (real headless Chromium)
# ---------------------------------------------------------------------------


@pytest.mark.launches_chrome
@CHROME
@pytest.mark.usefixtures("fast")
def test_submit_then_reload_is_a_valid_login(
    tmp_path: Path, npm: tuple[_NpmApp, str]
) -> None:
    app, origin = npm
    rig = _rig(tmp_path, origin)
    resp = rig.login()
    assert resp.get("ok"), resp
    assert resp["fresh_auth"] is True and resp["bundle"]["via"] == "login"
    assert app.valid("Bearer " + _token_in(resp["bundle"], origin)["token"])
    assert resp["bundle"]["storage_keys"] == {origin: [TOKEN_KEY]}
    assert app.logins == 1
    entry = json.loads(rig.limiter_bytes())["sites"]["npmfix"]
    assert entry["attempts"][-1][1] == "ok"


@pytest.mark.launches_chrome
@CHROME
@pytest.mark.usefixtures("fast")
def test_a_stale_cached_build_does_not_blank_the_login(
    tmp_path: Path, npm: tuple[_NpmApp, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The root cause: build "a" is cached in the broker profile (one visit,
    logged out), the server moves to build "b"; the cached index.html asks for
    the gone ``dash-a.js``. Without the cache clear at launch the dashboard
    stays blank after a successful submit; with it the login is valid."""
    app, origin = npm
    app.reload_after_login = False  # like NPM 2.16: no reload revalidates it
    rig = _rig(tmp_path, origin)
    # One visit with build "a": the profile caches index.html + main-a.js.
    with monkeypatch.context() as m:
        m.setattr(rig.vault, "secret", _no_secret)
        assert not rig.login().get("ok")  # logged out: needs the secret
    app.build = "b"
    with monkeypatch.context() as m:  # the bug, reproduced: no cache clear
        m.setattr(daemon, "clear_http_cache", lambda _ctx: None)
        broken = rig.login()
    assert not broken.get("ok") and app.logins == 1  # the server said yes
    assert broken["phase"] == "broker-proof" and broken["submitted"] is True
    assert "still on the login page" not in broken["detail"]
    # the report names the server-side cause too
    assert "served HTML for 1 script(s)" in broken["detail"]
    assert broken["diag"]["script_as_html"] == ["dash-a.js"]  # file names only
    # The same stale profile, a fresh limiter (the failure left a cooldown).
    rig.brk.limiter = limiter.Limiter(tmp_path / "limiter2.json", 0, 100, 100)
    resp = rig.login()
    assert resp.get("ok"), resp
    # the token the "failed" login stored is reused: no second submit
    assert resp["bundle"]["via"] == "profile" and app.logins == 1


def _no_secret(_site: str) -> vault.Secret:
    raise vault.VaultError("no secret in this step")


@pytest.mark.launches_chrome
@CHROME
@pytest.mark.usefixtures("fast")
def test_profile_reuse_during_cooldown_needs_no_secret(
    tmp_path: Path, npm: tuple[_NpmApp, str]
) -> None:
    app, origin = npm
    rig = _rig(tmp_path, origin)
    assert rig.login().get("ok")
    _cooldown(rig.lim)
    before, calls = rig.limiter_bytes(), rig.vault.secret_calls
    resp = rig.login()
    assert resp.get("ok"), resp
    assert resp["bundle"]["via"] == "profile" and resp["fresh_auth"] is False
    assert resp["bundle"]["session_refresh"] == recipes.REFRESH_FRESH
    assert rig.vault.secret_calls == calls and rig.limiter_bytes() == before
    assert app.logins == 1 and app.refreshes == 0


@pytest.mark.launches_chrome
@CHROME
@pytest.mark.usefixtures("fast")
def test_a_token_near_expiry_is_refreshed_before_export(
    tmp_path: Path, npm: tuple[_NpmApp, str]
) -> None:
    app, origin = npm
    app.login_ttl_s = 2 * 3600  # the stored token has < 12 h left
    rig = _rig(tmp_path, origin)
    assert rig.login().get("ok")
    old = set(app.tokens)
    resp = rig.login()
    assert resp.get("ok"), resp
    assert resp["bundle"]["via"] == "profile"
    assert resp["bundle"]["session_refresh"] == recipes.REFRESH_DONE
    token = _token_in(resp["bundle"], origin)
    assert token["token"] not in old and app.valid("Bearer " + token["token"])
    left = datetime.fromisoformat(token["expires"].replace("Z", "+00:00"))
    assert left.timestamp() - time.time() > 20 * 3600
    assert app.refreshes == 1 and app.logins == 1


@pytest.mark.launches_chrome
@CHROME
@pytest.mark.usefixtures("fast")
def test_a_rejected_refresh_falls_back_to_a_login(
    tmp_path: Path, npm: tuple[_NpmApp, str]
) -> None:
    app, origin = npm
    app.login_ttl_s = 2 * 3600
    rig = _rig(tmp_path, origin)
    assert rig.login().get("ok")
    app.refuse_refresh = True  # /api/users/me still 200, /api/tokens 401
    resp = rig.login()
    assert resp.get("ok"), resp
    assert resp["bundle"]["via"] == "login" and resp["fresh_auth"] is True
    assert app.logins == 2 and app.refreshes == 0


@pytest.mark.launches_chrome
@CHROME
@pytest.mark.usefixtures("fast")
def test_a_wrong_password_is_invalid(tmp_path: Path, npm: tuple[_NpmApp, str]) -> None:
    app, origin = npm
    rig = _rig(tmp_path, origin, password=secrets.token_hex(6))  # random wrong password
    resp = rig.login()
    assert not resp.get("ok")
    assert resp["phase"] == "submit" and resp["submitted"] is True
    assert "still on the login page" in resp["detail"]
    assert app.logins == 0


@pytest.mark.launches_chrome
@CHROME
@pytest.mark.usefixtures("fast")
def test_a_page_that_stays_blank_is_indeterminate(
    tmp_path: Path, npm: tuple[_NpmApp, str]
) -> None:
    app, origin = npm
    app.blank = True
    rig = _rig(tmp_path, origin)
    resp = rig.login()
    assert not resp.get("ok") and app.logins == 1
    assert resp["phase"] == "broker-proof" and resp["submitted"] is True
    assert "could not decide" in resp["detail"]
    entry = json.loads(rig.limiter_bytes())["sites"]["npmfix"]
    assert entry["attempts"][-1][1] == "unknown"  # marker + indeterminate


# ---------------------------------------------------------------------------
# Proof primitives on a real page
# ---------------------------------------------------------------------------


@contextlib.contextmanager
def _page() -> Iterator[Any]:
    from playwright.sync_api import (  # pylint: disable=import-outside-toplevel
        sync_playwright,
    )

    with sync_playwright() as pw:
        b = pw.chromium.launch(headless=True)
        try:
            yield b.new_page()
        finally:
            b.close()


_HIDDEN_FIRST = (
    "<nav><a href='/nginx/proxy' style='display:none'>x</a></nav><div id=r></div>"
    "<script>setTimeout(() => { const a = document.createElement('a');"
    " a.href = '/nginx/proxy'; a.className = 'card-link'; a.textContent = 'Proxy';"
    " document.getElementById('r').appendChild(a); }, 1200);</script>"
)


@pytest.mark.launches_chrome
@CHROME
def test_a_hidden_first_match_passes_by_polling(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _page() as page:
        page.set_content(_HIDDEN_FIRST)
        with pytest.raises(Exception):  # the old wait: first match only
            page.wait_for_selector(
                "a[href='/nginx/proxy']", state="visible", timeout=1500
            )
        page.set_content(_HIDDEN_FIRST)
        assert page_state.poll_sentinel(page, "a[href='/nginx/proxy']", 5.0)
        page.set_content(_HIDDEN_FIRST)
        monkeypatch.setattr(browser, "BROKER_SENTINEL_WAIT_S", 5.0)
        assert browser._broker_wait_sentinel(page, "a[href='/nginx/proxy']")


@pytest.mark.launches_chrome
@CHROME
def test_blank_and_login_pages_are_told_apart(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(browser, "BROKER_SENTINEL_WAIT_S", 0.6)
    entry = {
        "site": "x",
        "check_url": "https://x.example/",
        "logged_in_selector": "#me",
    }
    item = vault.site_item_from_json(
        {
            "name": "x",
            "fields": [
                {"name": "agent_fill_origins", "value": "https://x.example"},
                {"name": "agent_check_url", "value": "https://x.example/"},
                {"name": "agent_logged_in_selector", "value": "#me"},
            ],
        }
    )
    with _page() as page:
        page.route(
            "**/*",
            lambda route: route.fulfill(body=_ROUTED[0], content_type="text/html"),
        )
        cases = [
            ("<div id=root></div>", recipes.INDETERMINATE),
            ("<form><input type=password></form>", recipes.INVALID),
            ("<p>Access denied</p>", recipes.INVALID),
            ("<div id=me>me</div>", recipes.VALID),
            (_shadow("<form><input type=password></form>"), recipes.INVALID),
            (_shadow("<p>Welcome</p>"), recipes.INVALID),
            (_shadow("<p hidden>Welcome</p>"), recipes.INDETERMINATE),
        ]
        for body, want in cases:
            _ROUTED[0] = f"<html><body>{body}</body></html>"
            page.goto("https://x.example/")
            assert recipes.sentinel_proof(page, item, wait_s=0.6) == want, body
            browser._BG_STATUS[id(page)] = 200
            try:
                assert browser._broker_probe(page, entry) == want, body
            finally:
                browser._BG_STATUS.pop(id(page), None)


_ROUTED = [""]


def _shadow(inner: str) -> str:
    """A surface entirely inside an open shadow root (Home Assistant's
    `ha-authorize` login): rendered, never "blank"."""
    return (
        "<x-app></x-app><script>customElements.define('x-app', class extends"
        " HTMLElement { connectedCallback() { this.attachShadow({mode: 'open'})"
        f".innerHTML = '{inner}'; }} }});</script>"
    )


@pytest.mark.launches_chrome
@CHROME
def test_the_probe_tab_bypasses_a_stale_cache(npm: tuple[_NpmApp, str]) -> None:
    """Client side: a tab with `_broker_bypass_cache` loads the server's
    current build — and refreshes the cache for the other tabs."""
    app, origin = npm
    from playwright.sync_api import (  # pylint: disable=import-outside-toplevel
        sync_playwright,
    )

    with sync_playwright() as pw:
        ctx = pw.chromium.launch_persistent_context(
            str(Path(_tmpdir()) / "profile"), headless=True
        )
        try:
            page = ctx.pages[0] if ctx.pages else ctx.new_page()
            page.goto(origin + "/")
            page.wait_for_selector("input[type=password]")
            app.build = "b"
            stale = ctx.new_page()
            stale.goto(origin + "/")
            assert "main-a.js" in stale.content()  # from the heuristic cache
            fresh = ctx.new_page()
            browser._broker_bypass_cache(fresh)
            fresh.goto(origin + "/")
            assert "main-b.js" in fresh.content()
            healed = ctx.new_page()
            healed.goto(origin + "/")
            assert "main-b.js" in healed.content()
        finally:
            browser._BG_NOCACHE.clear()
            ctx.close()


def _tmpdir() -> str:
    import tempfile  # pylint: disable=import-outside-toplevel

    return tempfile.mkdtemp(prefix="ws2-npm-")


# ---------------------------------------------------------------------------
# Session refresh selection and vault field
# ---------------------------------------------------------------------------


def _item(site: str, **fields: str) -> vault.SiteItem:
    base = {"agent_site": site, "agent_fill_origins": "https://n.example"}
    return vault.site_item_from_json(
        {
            "name": site,
            "fields": [
                {"name": k, "value": v}
                for k, v in {
                    **base,
                    "agent_logged_in_selector": "#me",
                    **fields,
                }.items()
            ],
        }
    )


def test_refresher_choice_by_site_and_field() -> None:
    assert recipes.session_refresh_name(_item("npm-nixos")) == "npm-jwt"
    assert recipes.session_refresh_name(_item("npm-raspi")) == "npm-jwt"
    assert recipes.session_refresh_name(_item("jellyfin")) is None
    on = _item("npm-other", agent_session_refresh="npm-jwt")
    assert recipes.session_refresh_name(on) == "npm-jwt"
    assert on.public()["session_refresh"] == "npm-jwt"
    off = _item("npm-nixos", agent_session_refresh="none")
    assert recipes.session_refresh_name(off) is None
    bad = _item("npm-nixos", agent_session_refresh="evil")
    assert bad.refused and "agent_session_refresh" in bad.refused
    assert recipes.refresh_session(object(), _item("jellyfin")) == recipes.REFRESH_NONE


class _EvalPage:
    def __init__(self, url: str, answer: object) -> None:
        self.url = url
        self.answer = answer
        self.calls = 0

    def evaluate(self, _js: str, _arg: object = None) -> object:
        self.calls += 1
        if isinstance(self.answer, Exception):
            raise self.answer
        return self.answer


def test_npm_refresh_runs_only_on_its_storage_origin() -> None:
    item = _item(
        "npm-nixos",
        agent_storage_keys=json.dumps({"https://n.example": [TOKEN_KEY]}),
    )
    elsewhere = _EvalPage("https://evil.example/", {"state": "refreshed"})
    assert recipes.npm_jwt_refresh(elsewhere, item) == recipes.REFRESH_FAILED
    assert elsewhere.calls == 0
    home = _EvalPage("https://n.example/", {"state": "refreshed", "left_s": 86000})
    assert recipes.npm_jwt_refresh(home, item) == recipes.REFRESH_DONE
    odd = _EvalPage("https://n.example/", {"state": "<script>"})
    assert recipes.npm_jwt_refresh(odd, item) == recipes.REFRESH_FAILED
    boom = _EvalPage("https://n.example/", RuntimeError("context destroyed"))
    assert recipes.npm_jwt_refresh(boom, item) == recipes.REFRESH_FAILED
    no_key = _item("npm-nixos")  # no storage key configured
    assert recipes.npm_jwt_refresh(home, no_key) == recipes.REFRESH_FAILED


# ---------------------------------------------------------------------------
# Client: bundle completeness and storage-inject count
# ---------------------------------------------------------------------------

ORIGIN = "https://nginx-nix.example"


def test_bundle_gap_rules() -> None:
    entry = {"storage_origins": [ORIGIN]}
    full = {
        "storage": {ORIGIN: {TOKEN_KEY: "[]"}},
        "storage_keys": {ORIGIN: [TOKEN_KEY]},
    }
    assert browser._broker_bundle_gap(full, entry) == ([], 0, 1)
    lacking = {"storage": {}, "storage_keys": {ORIGIN: [TOKEN_KEY]}}
    assert browser._broker_bundle_gap(lacking, entry) == ([ORIGIN], 0, 1)
    # the deployed broker lists only storage_origins: one key per origin
    assert browser._broker_bundle_gap({"storage": {}}, entry) == ([ORIGIN], 0, 1)
    some = {"storage": {ORIGIN: {"x": "1"}}}
    assert browser._broker_bundle_gap(some, entry) == ([], 0, 1)
    # some of an origin's keys: partial (inject what is there), not empty
    named = {"storage_keys": {ORIGIN: [TOKEN_KEY, "other"]}}
    partial = {"storage": {ORIGIN: {TOKEN_KEY: "x"}}}
    assert browser._broker_bundle_gap(partial, named) == ([], 1, 2)
    # a bundle can add requirements, never drop the item's
    item_keys = {"storage_keys": {ORIGIN: [TOKEN_KEY]}}
    empty_decl: dict[str, Any] = {"storage": {}, "storage_keys": {}}
    assert browser._broker_bundle_gap(empty_decl, item_keys) == ([ORIGIN], 0, 1)
    # a malformed declaration empties its origin (fails closed)
    malformed: dict[str, Any] = {"storage": {}, "storage_keys": {ORIGIN: None}}
    assert browser._broker_bundle_gap(malformed, {}) == ([ORIGIN], 0, 1)
    assert browser._broker_bundle_gap({"storage": {}}, {}) == ([], 0, 0)


def test_expected_key_count_uses_the_write_filter() -> None:
    bundle = {
        "storage": {
            ORIGIN: {TOKEN_KEY: "[]", "b": "1"},
            "http://127.0.0.1:9": {"c": "1"},  # never written: not https
            ORIGIN + "/path": {"d": "1"},  # not an exact origin
            "https://x.example": "not a dict",
        }
    }
    assert browser._broker_bundle_keys(bundle) == 2


class _FakeBrowser:
    contexts: list[Any] = []

    def close(self) -> None:
        return None


class _FakePw:
    def stop(self) -> None:
        return None


@pytest.fixture(name="inject")
def _inject(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    seen: dict[str, Any] = {"cookies": 0, "storage": 0, "reply": {}}
    monkeypatch.setattr(browser, "_connect", lambda _port: (_FakePw(), _FakeBrowser()))
    monkeypatch.setattr(
        browser, "_interaction_lease", lambda _why: contextlib.nullcontext()
    )
    monkeypatch.setattr(browser, "_broker_request", lambda *_a, **_k: seen["reply"])

    def cookies(_browser: Any, _bundle: dict[str, Any]) -> int:
        seen["cookies"] += 1
        return 1

    def drop(_port: int, _bundle: dict[str, Any]) -> int:
        seen["dropped"] = seen.get("dropped", 0) + 1
        return 1

    monkeypatch.setattr(browser, "_broker_replace_cookies", cookies)
    monkeypatch.setattr(browser, "_broker_drop_cookies", drop)
    browser._RESULT.clear()
    return seen


def test_a_partial_bundle_injects_what_is_there(
    inject: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    inject["reply"] = {
        "ok": True,
        "bundle": {
            "storage": {ORIGIN: {TOKEN_KEY: "[]"}},
            "storage_keys": {ORIGIN: [TOKEN_KEY, "other"]},
        },
    }
    monkeypatch.setattr(browser, "_broker_write_storage", _writes(1))
    rc, _bundle, _c, keys = browser._broker_fetch_inject(9222, "npm-nixos", {}, {})
    assert rc is None and keys == 1 and inject["cookies"] == 1
    assert browser._RESULT["warning"] == "partial_bundle"
    assert "phase" not in browser._RESULT


def test_an_incomplete_bundle_touches_nothing(inject: dict[str, Any]) -> None:
    inject["reply"] = {
        "ok": True,
        "fresh_auth": False,
        "bundle": {"storage": {}, "storage_keys": {ORIGIN: [TOKEN_KEY]}},
    }
    rc, _bundle, _c, _k = browser._broker_fetch_inject(9222, "npm-nixos", {}, {})
    assert rc == 2 and inject["cookies"] == 0
    assert browser._RESULT["phase"] == "bundle-export"
    assert browser._RESULT["code"] == "incomplete_bundle"
    assert "incomplete_bundle" in phases.CODE_TEXT


def test_a_short_storage_write_is_storage_inject(
    inject: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    inject["reply"] = {
        "ok": True,
        "bundle": {
            "storage": {ORIGIN: {TOKEN_KEY: "[]"}},
            "storage_keys": {ORIGIN: [TOKEN_KEY]},
        },
    }
    monkeypatch.setattr(browser, "_broker_write_storage", _writes(0))
    rc, _bundle, _c, keys = browser._broker_fetch_inject(9222, "npm-nixos", {}, {})
    assert rc == 2 and keys == 0 and inject["cookies"] == 1
    assert browser._RESULT["phase"] == "storage-inject"
    assert inject["dropped"] == 1  # no half session: the cookies went again
    assert browser._RESULT["rollback"] == "complete"
    inject["reply"]["bundle"]["session_refresh"] = recipes.REFRESH_FAILED
    monkeypatch.setattr(browser, "_broker_write_storage", _writes(1))
    browser._RESULT.clear()
    rc, _bundle, _c, keys = browser._broker_fetch_inject(9222, "npm-nixos", {}, {})
    assert rc is None and keys == 1 and "phase" not in browser._RESULT
    assert browser._RESULT["session_refresh"] == recipes.REFRESH_FAILED


def _writes(n: int) -> Any:
    def write(_port: int, bundle: dict[str, Any], origins: Any = None) -> int:
        if n and origins is not None:
            origins.extend(bundle.get("storage") or {})
        return n

    return write


def test_a_failed_rollback_keeps_the_storage_failure(
    inject: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    inject["reply"] = {
        "ok": True,
        "bundle": {
            "storage": {ORIGIN: {TOKEN_KEY: "[]"}, ORIGIN + ":8443": {"k": "v"}},
        },
    }
    monkeypatch.setattr(browser, "_broker_write_storage", _writes(1))

    def boom(_port: int, _bundle: dict[str, Any]) -> int:
        raise RuntimeError("browser gone")

    dropped: list[list[str]] = []

    def drop_storage(_port: int, _bundle: dict[str, Any], origins: list[str]) -> bool:
        dropped.append(list(origins))
        return True

    monkeypatch.setattr(browser, "_broker_drop_cookies", boom)
    monkeypatch.setattr(browser, "_broker_drop_storage", drop_storage)
    rc, _bundle, _c, keys = browser._broker_fetch_inject(9222, "npm-nixos", {}, {})
    assert rc == 2 and keys == 1
    assert browser._RESULT["phase"] == "storage-inject"
    assert browser._RESULT["rollback"] == "partial"
    assert dropped and dropped[0]  # the written origin's keys were removed again


def test_a_half_failed_origin_is_rolled_back_too(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The origin whose write FAILED may still have taken a key (one setItem,
    then a redirect): it is listed for the rollback like the written ones."""
    second = ORIGIN.replace("nginx-nix", "nginx")
    bundle = {"storage": {ORIGIN: {TOKEN_KEY: "[]"}, second: {TOKEN_KEY: "[]"}}}
    answers = iter([True, False])
    monkeypatch.setattr(
        browser, "_with_prepared_background_page", lambda *_a: next(answers)
    )
    touched: list[str] = []
    assert browser._broker_write_storage(9222, bundle, touched) == 1
    assert touched == [ORIGIN, second]


@pytest.mark.launches_chrome
@CHROME
@pytest.mark.usefixtures("fast")
def test_refresh_only_renews_and_never_logs_in(
    tmp_path: Path, npm: tuple[_NpmApp, str]
) -> None:
    """``refresh_only`` (the proactive refresh's broker half): a valid profile
    is re-exported with its token renewed; a profile that is not reusable
    answers ``refresh_unavailable`` — no secret, no limiter write."""
    app, origin = npm
    app.login_ttl_s = 2 * 3600
    rig = _rig(tmp_path, origin)
    assert rig.login().get("ok")
    before, calls = rig.limiter_bytes(), rig.vault.secret_calls
    resp = rig.brk._login_request("npmfix", {"refresh_only": True})
    assert resp.get("ok"), resp
    assert resp["bundle"]["via"] == "profile" and resp["fresh_auth"] is False
    assert resp["bundle"]["session_refresh"] == recipes.REFRESH_DONE
    app.blank = True  # an undecidable profile proof: still never a login
    resp = rig.brk._login_request("npmfix", {"refresh_only": True})
    assert not resp.get("ok") and resp["error"] == "refresh_unavailable", resp
    assert resp["submitted"] is False
    app.blank = False
    app.tokens.clear()  # every token revoked: the SPA falls back to its login form
    resp = rig.brk._login_request("npmfix", {"refresh_only": True})
    assert not resp.get("ok") and resp["error"] == "refresh_unavailable"
    assert resp["phase"] == "profile-proof" and resp["submitted"] is False
    assert rig.vault.secret_calls == calls and rig.limiter_bytes() == before
    assert app.logins == 1
    assert "refresh_unavailable" in phases.CODE_TEXT
    both = {"refresh_only": True, "candidate_sentinel": "#x"}
    assert rig.brk._login_request("npmfix", both)["error"] == "bad_request"


# ---------------------------------------------------------------------------
# Review round 1: the refresher on a real page (bounded, 401 vs 403, fields)
# ---------------------------------------------------------------------------


@contextlib.contextmanager
def _npm_page(app: _NpmApp, origin: str, ttl_s: float) -> Iterator[tuple[Any, str]]:
    """A plain headless page on the fixture origin holding a valid stored
    token with `ttl_s` left (plus an extra field the refresher must keep)."""
    issued = app.issue(ttl_s)
    entry = {**issued, "note": "keep"}
    with _page() as page:
        page.goto(origin + "/")
        page.evaluate(
            "([k, v]) => localStorage.setItem(k, JSON.stringify([v]))",
            [TOKEN_KEY, entry],
        )
        yield page, issued["token"]


def _stored(page: Any) -> list[dict[str, Any]] | None:
    raw = page.evaluate("k => localStorage.getItem(k)", TOKEN_KEY)
    return None if raw is None else json.loads(raw)


def _fixture_item(origin: str) -> vault.SiteItem:
    return vault.site_item_from_json(_item_json(origin), dev=True)


@pytest.mark.launches_chrome
@CHROME
def test_refresh_keeps_fields_and_only_a_401_drops_the_token(
    npm: tuple[_NpmApp, str],
) -> None:
    app, origin = npm
    item = _fixture_item(origin)
    with _npm_page(app, origin, 2 * 3600) as (page, token):
        app.refresh_status = 403  # a WAF / Cloudflare Access: says nothing
        assert recipes.npm_jwt_refresh(page, item, dev=True) == recipes.REFRESH_FAILED
        stored = _stored(page)
        assert stored and stored[-1]["token"] == token
        app.refresh_status = None
        assert recipes.npm_jwt_refresh(page, item, dev=True) == recipes.REFRESH_DONE
        stored = _stored(page)
        assert stored and stored[-1]["token"] != token and stored[-1]["note"] == "keep"
        assert app.valid("Bearer " + stored[-1]["token"])
        left = recipes.session_left_s(page, "npm-jwt")
        assert left is not None and left > 20 * 3600
        app.refuse_refresh = True  # the server answers 401
    with _npm_page(app, origin, 2 * 3600) as (page, _token):
        assert recipes.npm_jwt_refresh(page, item, dev=True) == recipes.REFRESH_REJECTED
        assert _stored(page) is None


@pytest.mark.launches_chrome
@CHROME
def test_a_hanging_refresh_is_bounded(
    npm: tuple[_NpmApp, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    app, origin = npm
    item = _fixture_item(origin)
    app.refresh_delay_s = 4.0
    with _npm_page(app, origin, 2 * 3600) as (page, token):
        monkeypatch.setattr(recipes, "REFRESH_FETCH_S", 1)
        t0 = time.monotonic()
        assert recipes.npm_jwt_refresh(page, item, dev=True) == recipes.REFRESH_FAILED
        assert time.monotonic() - t0 < 3.0  # the fetch was aborted
        monkeypatch.setattr(recipes, "REFRESH_FETCH_S", 10)
        monkeypatch.setattr(recipes, "REFRESH_TOTAL_S", 1)
        t0 = time.monotonic()
        assert recipes.npm_jwt_refresh(page, item, dev=True) == recipes.REFRESH_FAILED
        assert time.monotonic() - t0 < 3.0  # the whole script gave up
        stored = _stored(page)
        assert stored and stored[-1]["token"] == token  # untouched


@pytest.mark.launches_chrome
@CHROME
def test_the_client_proof_reads_the_token_expiry(npm: tuple[_NpmApp, str]) -> None:
    app, origin = npm
    entry = {
        "site": "npmfix",
        "check_url": origin + "/",
        "logged_in_selector": SENTINEL,
        "session_refresh": "npm-jwt",
        "storage_origins": [origin],
    }
    with _npm_page(app, origin, 2 * 3600) as (page, _token):
        page.goto(origin + "/")  # the SPA boots with the stored token
        browser._BG_STATUS[id(page)] = 200
        try:
            assert browser._broker_probe(page, entry) == browser.PROOF_VALID
        finally:
            browser._BG_STATUS.pop(id(page), None)
    left = browser._SESSION_LEFT.pop("npmfix")
    assert left is not None and 3600 < left <= 2 * 3600
    assert browser._RESULT["session_left_s"] == left


# ---------------------------------------------------------------------------
# Review round 1: the client keeps the session fresh (M2), hermetic
# ---------------------------------------------------------------------------

NPM_ENTRY = {
    "site": "npm-nixos",
    "check_url": ORIGIN + "/",
    "logged_in_selector": SENTINEL,
    "session_refresh": "npm-jwt",
    "storage_origins": [ORIGIN],
}


@pytest.fixture(name="keep_fresh")
def _keep_fresh(monkeypatch: pytest.MonkeyPatch) -> Iterator[dict[str, Any]]:
    """`_broker_login` with every browser/broker step faked: `state["left"]`
    is what the free check reads, `state["logged_in"]` its answer,
    `state["refresh"]` the broker's answer to refresh_only."""
    state: dict[str, Any] = {
        "left": 2 * 3600,
        "logged_in": True,
        "refresh": "ok",
        "requests": [],
    }

    def logged_in(_port: int, site: str) -> int:
        browser._SESSION_LEFT[site] = state["left"]
        return 0 if state["logged_in"] else 2

    def fetch(
        _port: int, site: str, opts: dict[str, Any], _entry: Any = None, **kw: Any
    ) -> tuple[int | None, dict, int, int]:
        state["requests"].append((dict(opts), kw.get("refresh", False)))
        if opts.get("refresh_only") and state["refresh"] != "ok":
            browser._BROKER_REFUSALS[site] = (state["refresh"], "")
            return 2, {}, 0, 0
        return None, {}, 0, 1

    monkeypatch.setattr(browser, "_broker_logged_in", logged_in)
    monkeypatch.setattr(browser, "_broker_entry_or_rc", lambda _site: (NPM_ENTRY, 0))
    monkeypatch.setattr(browser, "_broker_fetch_inject", fetch)
    monkeypatch.setattr(browser, "_broker_check_entry", lambda *_a, **_k: 0)
    monkeypatch.setattr(browser, "_broker_gate", lambda _site: None)
    monkeypatch.setattr(browser, "_broker_after_login", lambda _port, _site: 0)
    monkeypatch.setattr(browser, "_record_login_event", lambda *_a: None)
    browser._RESULT.clear()
    browser._LOGIN_OPTS.update(scheduled=False, candidate=None, refresh_only=False)
    yield state
    browser._LOGIN_OPTS.update(refresh_only=False)


def test_a_due_token_is_renewed_without_a_login(keep_fresh: dict[str, Any]) -> None:
    assert browser._broker_login(9222, "npm-nixos") == 0
    assert keep_fresh["requests"] == [({"refresh_only": True}, True)]
    assert browser._RESULT["refresh"] == "refreshed"


@pytest.mark.parametrize("left", [20 * 3600, None])
def test_no_refresh_when_not_due_or_unknown(
    keep_fresh: dict[str, Any], left: int | None
) -> None:
    keep_fresh["left"] = left
    assert browser._broker_login(9222, "npm-nixos") == 0
    assert not keep_fresh["requests"] and "refresh" not in browser._RESULT


def test_an_expired_token_still_shown_logged_in_is_renewed(
    keep_fresh: dict[str, Any],
) -> None:
    keep_fresh["left"] = -120
    assert browser._broker_login(9222, "npm-nixos") == 0
    assert keep_fresh["requests"] == [({"refresh_only": True}, True)]


def test_refresh_unavailable_falls_back_to_the_normal_login(
    keep_fresh: dict[str, Any],
) -> None:
    keep_fresh["refresh"] = "refresh_unavailable"
    assert browser._broker_login(9222, "npm-nixos") == 0
    # the refresh, then ONE normal (gated) broker login
    assert keep_fresh["requests"] == [({"refresh_only": True}, True), ({}, False)]


def test_refresh_only_never_logs_in(keep_fresh: dict[str, Any]) -> None:
    browser._LOGIN_OPTS.update(refresh_only=True)
    keep_fresh["refresh"] = "refresh_unavailable"
    assert browser._broker_login(9222, "npm-nixos") == 0  # still logged in
    assert keep_fresh["requests"] == [({"refresh_only": True}, True)]
    assert browser._RESULT["refresh"] == "unavailable"
    keep_fresh["requests"].clear()
    keep_fresh["logged_in"] = False
    assert browser._broker_login(9222, "npm-nixos") == 2
    assert not keep_fresh["requests"]  # not logged in: nothing at all
    assert browser._RESULT["phase"] == "client-proof"


def test_a_refresh_deadline_never_quarantines() -> None:
    assert browser._STEP_PHASE["broker:refresh"] == "profile-proof"
    assert not _phases_post_submit("profile-proof")


def _phases_post_submit(phase: str) -> bool:
    return phases.post_submit(phase, None)


# ---------------------------------------------------------------------------
# Review round 1: agent-login -c renews refreshable sites, pending ones too
# ---------------------------------------------------------------------------

al = _load("agent_login_ws2_npm_test", REPO / "agent-login.py")


def _refresh_run(
    monkeypatch: pytest.MonkeyPatch, refresh: str = "refreshed", rc: int = 0
) -> list[tuple[str, ...]]:
    calls: list[tuple[str, ...]] = []

    def run(*args: str, **_kw: Any) -> Any:
        calls.append(args)
        return al.BrowserRun(rc, False, "", 0.0, {"phase": "ok", "refresh": refresh})

    monkeypatch.setattr(al, "run_browser", run)
    return calls


def test_refresh_step_only_when_due(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _refresh_run(monkeypatch)
    assert al.refresh_step("npm-nixos", {"session_left_s": 20 * 3600}, "x") == "x"
    assert al.refresh_step("npm-nixos", {}, "x") == "x"
    assert not calls
    how = al.refresh_step("npm-nixos", {"session_left_s": 3600}, "logged in")
    assert how == "logged in (token renewed)"
    assert calls == [("login", "npm-nixos", "-F")]
    _refresh_run(monkeypatch, refresh="unavailable")
    how = al.refresh_step("npm-nixos", {"session_left_s": 3600}, "logged in")
    assert "NOT renewed: unavailable" in how


def test_check_all_renews_a_pending_site(monkeypatch: pytest.MonkeyPatch) -> None:
    row = {
        "site": "npm-nixos",
        "name": "npm-nixos",
        "status": "extra",
        "flow": "one-page",
        "stage": "pending",
        "sentinel": True,
        "session_refresh": "npm-jwt",
    }
    assert al.schedule_gate(row)[0] == "pending"  # no scheduled LOGIN
    monkeypatch.setattr(al, "wait_for_network", lambda: True)
    monkeypatch.setattr(al, "ensure_browser_up", lambda: True)
    monkeypatch.setattr(al, "_browser", lambda *a, **_k: 0)
    monkeypatch.setattr(
        al, "overview", lambda: {"broker_ok": True, "broker": "ok", "rows": [row]}
    )
    calls: list[tuple[str, ...]] = []

    def run(*args: str, **_kw: Any) -> Any:
        calls.append(args)
        rec: dict[str, Any] = {"phase": "ok", "code": "ok", "proof_v": 1}
        if args[0] == "logged-in":
            rec["session_left_s"] = 1800
        else:
            rec["refresh"] = "refreshed"
        return al.BrowserRun(0, False, "", 0.0, rec)

    monkeypatch.setattr(al, "run_browser", run)
    assert al.check_all() == 0
    assert [c[:3] for c in calls] == [
        ("logged-in", "npm-nixos"),
        ("login", "npm-nixos", "-F"),
    ]
    assert "token renewed" in als_checks()["npm-nixos"]["how"]


def als_checks() -> dict[str, dict]:
    import agent_login_state  # pylint: disable=import-outside-toplevel

    return agent_login_state.checks()


# ---------------------------------------------------------------------------
# Review round 1: service workers, closed shadow roots, early INVALID
# ---------------------------------------------------------------------------


@pytest.mark.launches_chrome
@CHROME
def test_launch_clears_the_items_service_workers(
    npm: tuple[_NpmApp, str], tmp_path: Path
) -> None:
    _app, origin = npm
    from playwright.sync_api import (  # pylint: disable=import-outside-toplevel
        sync_playwright,
    )

    count = "() => navigator.serviceWorker.getRegistrations().then(r => r.length)"
    with sync_playwright() as pw:
        ctx = pw.chromium.launch_persistent_context(str(tmp_path / "p"), headless=True)
        try:
            page = ctx.pages[0]
            page.goto(origin + "/")
            page.evaluate("() => navigator.serviceWorker.register('/sw.js')")
            page.wait_for_function(
                "async () => (await navigator.serviceWorker"
                ".getRegistrations()).length > 0"
            )
        finally:
            ctx.close()
        ctx = pw.chromium.launch_persistent_context(str(tmp_path / "p"), headless=True)
        try:
            page = ctx.pages[0]
            page.goto(origin + "/")
            assert page.evaluate(count) == 1  # it survived the restart
            assert daemon.clear_origin_workers(ctx, [origin]) is True
            page.goto(origin + "/")
            assert page.evaluate(count) == 0
        finally:
            ctx.close()
    item = _fixture_item(origin)
    assert origin in daemon.item_origins(item)


@pytest.mark.launches_chrome
@CHROME
def test_closed_shadow_root_is_rendered_and_idp_is_invalid_at_once() -> None:
    closed = (
        "<x-c></x-c><script>customElements.define('x-c', class extends HTMLElement"
        " { connectedCallback() { this.attachShadow({mode: 'closed'}).innerHTML ="
        " '<p>Sign in</p>'; } });</script>"
    )
    item = vault.site_item_from_json(
        {
            "name": "x",
            "fields": [
                {"name": "agent_fill_origins", "value": "https://idp.example"},
                {"name": "agent_check_url", "value": "https://x.example/"},
                {"name": "agent_logged_in_selector", "value": "#me"},
            ],
        }
    )
    with _page() as page:
        page.route(
            "**/*",
            lambda route: route.fulfill(body=_ROUTED[0], content_type="text/html"),
        )
        _ROUTED[0] = f"<html><body>{closed}</body></html>"
        page.goto("https://x.example/")
        assert not page_state.page_blank(page)
        assert recipes.sentinel_proof(page, item, wait_s=0.6) == recipes.INVALID
        # a logged-out redirect to the IdP's login form: INVALID without waiting
        _ROUTED[0] = "<html><body><form><input type=password></form></body></html>"
        page.goto("https://idp.example/login")
        t0 = time.monotonic()
        assert recipes.sentinel_proof(page, item, wait_s=8.0) == recipes.INVALID
        assert time.monotonic() - t0 < 2.0


# ---------------------------------------------------------------------------
# The reviewer's open question: does NPM's own SPA renew its token in a
# short-lived tab? Opt-in (WS2_NPM_LIVE_URL=https://nginx-nix.dom42.space):
# the REAL NPM frontend (its static files, fetched anonymously) with every
# /api call except the anonymous health check answered locally.
# Answer (2026-10-10, NPM 2.16.0): NO — its refresh timer
# (AuthContext: setInterval 5 min, not immediate) never fires in a probe tab
# of a few seconds, so the client-side refresh (`_broker_keep_fresh`,
# `agent-login.py -c` → `login -F`) is what keeps the token alive.
# ---------------------------------------------------------------------------


@pytest.mark.launches_chrome
@CHROME
@pytest.mark.skipif(
    not os.environ.get("WS2_NPM_LIVE_URL"), reason="opt-in: WS2_NPM_LIVE_URL"
)
def test_live_npm_spa_does_not_renew_its_token_in_a_short_tab() -> None:
    base = os.environ["WS2_NPM_LIVE_URL"].rstrip("/")
    refreshes: list[str] = []
    user = {
        "id": 1,
        "name": "Fixture",
        "nickname": "f",
        "email": USER,
        "avatar": "",
        "roles": ["admin"],
        "permissions": {
            "visibility": "all",
            "proxyHosts": "manage",
            "redirectionHosts": "manage",
            "deadHosts": "manage",
            "streams": "manage",
            "accessLists": "manage",
            "certificates": "manage",
        },
    }

    def api(route: Any) -> None:
        url = route.request.url
        path = url.split(base, 1)[-1].split("?", 1)[0]
        if path in ("/api/", "/api"):
            route.continue_()
        elif path == "/api/tokens" and route.request.method == "GET":
            refreshes.append(url)
            route.fulfill(json={"token": "t2", "expires": "2099-01-01T00:00:00Z"})
        elif path.startswith("/api/users/me"):
            route.fulfill(json=user)
        elif path.startswith("/api/reports/hosts"):
            route.fulfill(json={"proxy": 1, "redirection": 0, "stream": 0, "dead": 0})
        else:
            route.fulfill(json=[])

    with _page() as page:
        expires = datetime.fromtimestamp(time.time() + 7200, tz=timezone.utc)
        stored = json.dumps([{"token": "t1", "expires": expires.isoformat()}])
        page.add_init_script(
            f"localStorage.setItem('{TOKEN_KEY}', {json.dumps(stored)})"
        )
        page.route(base + "/api/**", api)
        page.goto(base + "/")
        assert page_state.poll_sentinel(page, SENTINEL, 15.0)  # the dashboard
        page.wait_for_timeout(10_000)
        assert not refreshes  # no renewal within a short tab
        # control: a renewal WOULD have been seen
        page.evaluate("() => fetch('/api/tokens').then(r => r.status)")
    assert len(refreshes) == 1
