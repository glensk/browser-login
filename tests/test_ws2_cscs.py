"""WS2-cscs: the CSCS login is proven by the SERVER, exported on /profile/.

Live evidence (2026-10-09): the broker's CSCS login reported `ok`, but the
bundle carried 1 cookie and 0 storage keys and the portal sent the injected
session to Keycloak. Root cause: the proof accepted ANY 40-hex value in
localStorage — also an expired Waldur token — so the broker reused a dead
profile; the export then looked for the token on `/`, where the portal's
boot-redirect.js sends a session it thinks expired to the IdP first, found
nothing and silently exported no storage key.

The fixture portal below behaves like HomePort + Keycloak, served through
Playwright routes (``ctx.route``) inside throwaway headless Chromium contexts
— no real site is contacted, never the shared browser: the app keeps its DRF
token under ``waldur/auth/token`` (+ ``token_expires_at``, ``method``), asks
``/api/users/me/`` with it, removes a rejected token and goes to Keycloak;
``/`` runs a boot-redirect that treats an expired recorded expiry as no
session; Keycloak shows ``#username``/``#password``/``#rememberMe`` or — with
``silent_sso`` — returns to the portal at once. Tokens and passwords are
generated per test.
"""

from __future__ import annotations

# pylint: disable=protected-access,missing-function-docstring,missing-class-docstring
# pylint: disable=import-error,wrong-import-position,too-few-public-methods
# pylint: disable=too-many-lines,redefined-outer-name,too-many-instance-attributes
# pylint: disable=duplicate-code
import contextlib
import importlib.util
import json
import secrets
import sys
import time
import urllib.parse
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest
import requests

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

import agent_login_jobs as jobs  # noqa: E402
from broker import daemon, limiter, phases, recipes, vault  # noqa: E402

PORTAL = "https://portal.cscs.ch"
AUTH = "https://auth.cscs.ch"
KC_AUTH = AUTH + "/auth/realms/cscs/protocol/openid-connect/auth?client_id=portal"
KC_POST = AUTH + "/auth/realms/cscs/login-actions/authenticate"
TOKEN_KEY = recipes.CSCS_TOKEN_KEY
EXPIRES_KEY = recipes.CSCS_EXPIRES_KEY


def _load(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


browser = _load("browser_ws2_cscs_test", REPO / "bin" / "browser.py")


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


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# The fixture portal (HomePort + Keycloak, routed)
# ---------------------------------------------------------------------------

_BOOT_JS = """(() => {
  if (location.pathname !== '/' && location.pathname !== '/login/') return;
  const tok = localStorage.getItem('waldur/auth/token');
  const exp = Date.parse(localStorage.getItem('waldur/auth/token_expires_at') || '');
  const live = !!tok && (isNaN(exp) || Date.now() < exp + 60000);
  if (!live) location.replace('__KC__');
})();"""

_APP_JS = """(async () => {
  const away = () => setTimeout(() => location.replace('__KC__'), 300);
  const tok = localStorage.getItem('waldur/auth/token');
  if (!tok) { away(); return; }
  const r = await fetch('/api/users/me/', {headers: {Authorization: '__SCHEME__ ' + tok}});
  if (r.status === 401) { localStorage.removeItem('waldur/auth/token'); away(); return; }
  if (r.status !== 200) {  // an API outage: an error page, no redirect
    document.getElementById('app').textContent = 'error ' + r.status; return;
  }
  const b = await r.json();
  if (b.token_expires_at) localStorage.setItem('waldur/auth/token_expires_at',
                                               b.token_expires_at);
  document.getElementById('app').textContent = 'portal ' + b.username;
})();"""

_KC_FORM = """<html><body><form id=kc-form-login method=post action="__POST__">
<input id=username name=username type=text autocomplete=username>
<input id=password name=password type=password autocomplete=current-password>
<input id=rememberMe name=rememberMe type=checkbox>
<input id=kc-login name=login type=submit value="Sign In">
</form>__MSG__</body></html>"""


@dataclass
class Portal:
    """Server-side state of the fixture portal + IdP."""

    username: str = "cscs-fixture-user"
    password: str = field(default_factory=lambda: "pw-" + secrets.token_urlsafe(12))
    ttl_s: float = 3600.0
    tokens: dict[str, float] = field(default_factory=dict)
    me_status: int | None = None  # e.g. 503: the API is down
    config_status: int = 200
    oidc: bool = False  # OIDC_ACCESS_TOKEN_ENABLED: the API wants Bearer
    silent_sso: bool = False  # Keycloak's own session: no form
    logins: int = 0
    remember_me: list[bool] = field(default_factory=list)
    me_calls: int = 0

    def issue(self) -> str:
        token = secrets.token_hex(20)
        self.tokens[token] = time.time() + self.ttl_s
        return token

    def live(self, token: str) -> bool:
        exp = self.tokens.get(token)
        return exp is not None and exp > time.time()

    def revoke_all(self) -> None:
        self.tokens.clear()

    # --- routes -----------------------------------------------------------

    def handle(self, route: Any) -> None:
        req = route.request
        url = urllib.parse.urlsplit(req.url)
        origin = f"{url.scheme}://{url.netloc}"
        if origin == AUTH:
            self._auth(route, req, url)
        elif url.path.startswith("/api/"):
            self._api(route, req, url.path)
        elif url.path.startswith("/oauth_login_completed/"):
            token = self.issue()
            script = (
                f"localStorage.setItem('{TOKEN_KEY}', '{token}');"
                "localStorage.setItem('waldur/auth/method', 'keycloak');"
                "location.replace('/profile/');"
            )
            _html(route, f"<html><body><script>{script}</script></body></html>")
        else:
            boot = _BOOT_JS.replace("__KC__", KC_AUTH)
            scheme = "Bearer" if self.oidc else "Token"  # the app's own rule
            app = _APP_JS.replace("__KC__", KC_AUTH).replace("__SCHEME__", scheme)
            _html(
                route,
                f"<html><head><script>{boot}</script></head><body>"
                f"<div id=app>loading</div><script>{app}</script></body></html>",
            )

    def _auth(self, route: Any, req: Any, url: Any) -> None:
        done = PORTAL + "/oauth_login_completed/?state=s"
        if req.method == "POST" and url.path.endswith("/authenticate"):
            form = urllib.parse.parse_qs(req.post_data or "")
            self.remember_me.append(form.get("rememberMe") == ["on"])
            if form.get("username") == [self.username] and form.get("password") == [
                self.password
            ]:
                self.logins += 1
                _html(route, f"<script>location.replace('{done}')</script>")
                return
            _html(route, _KC_FORM.replace("__POST__", KC_POST).replace("__MSG__", "x"))
            return
        if self.silent_sso:  # Keycloak's own session: back without a form
            _html(
                route,
                f"<script>setTimeout(() => location.replace('{done}'), 2500)</script>",
            )
            return
        _html(route, _KC_FORM.replace("__POST__", KC_POST).replace("__MSG__", ""))

    def _api(self, route: Any, req: Any, path: str) -> None:
        if path == "/api/configuration/":
            if self.config_status != 200:
                route.fulfill(status=self.config_status, body="")
                return
            _json(route, 200, {"WALDUR_CORE": {"OIDC_ACCESS_TOKEN_ENABLED": self.oidc}})
            return
        if path == "/api/users/me/":
            self.me_calls += 1
            if self.me_status:
                route.fulfill(status=self.me_status, body="unavailable")
                return
            scheme, _, token = (req.headers.get("authorization") or "").partition(" ")
            want = "Bearer" if self.oidc else "Token"
            if scheme == want and self.live(token):
                self.tokens[token] = time.time() + self.ttl_s  # sliding expiry
                _json(
                    route,
                    200,
                    {
                        "uuid": "u-1",
                        "username": self.username,
                        "email": "fixture@example.org",
                        "token_expires_at": _iso(self.tokens[token]),
                    },
                )
                return
            _json(route, 401, {"detail": "Invalid token."})
            return
        _json(route, 404, {})


def _html(route: Any, body: str) -> None:
    route.fulfill(
        status=200,
        body=body,
        content_type="text/html",
        headers={"Cache-Control": "no-store"},
    )


def _json(route: Any, status: int, obj: object) -> None:
    route.fulfill(status=status, body=json.dumps(obj), content_type="application/json")


def _route(ctx: Any, app: Portal) -> None:
    ctx.route(PORTAL + "/**", app.handle)
    ctx.route(AUTH + "/**", app.handle)


@pytest.fixture
def portal() -> Portal:
    return Portal()


@contextlib.contextmanager
def _page(app: Portal) -> Iterator[Any]:
    """A fresh routed page (own context, own storage) in a throwaway Chromium."""
    from playwright.sync_api import (  # pylint: disable=import-outside-toplevel
        sync_playwright,
    )

    with sync_playwright() as pw:
        chrome = pw.chromium.launch(headless=True)
        try:
            ctx = chrome.new_context(viewport={"width": 1280, "height": 720})
            _route(ctx, app)
            yield ctx.new_page()
        finally:
            chrome.close()


def _seed(page: Any, token: str | None, expires: str | None = None) -> None:
    """Put a token (and expiry) into the portal's storage, then open /profile/."""
    page.goto(PORTAL + "/robots.txt")  # the origin, before the app runs
    kv = {TOKEN_KEY: token, EXPIRES_KEY: expires}
    page.evaluate(
        "kv => { for (const [k, v] of Object.entries(kv)) {"
        " if (v === null) localStorage.removeItem(k); else localStorage.setItem(k, v);"
        " } }",
        kv,
    )
    page.goto(PORTAL + "/profile/", wait_until="domcontentloaded")


# ---------------------------------------------------------------------------
# A. the proof asks the server (real headless Chromium)
# ---------------------------------------------------------------------------


@pytest.mark.launches_chrome
@CHROME
def test_a_stale_token_is_invalid(portal: Portal) -> None:
    """The root cause: a 40-hex token the server no longer knows."""
    with _page(portal) as page:
        _seed(page, secrets.token_hex(20))
        assert recipes.cscs_token_proof(page, wait_s=8) == recipes.INVALID


@pytest.mark.launches_chrome
@CHROME
def test_a_valid_token_is_valid_and_never_leaves_the_page(portal: Portal) -> None:
    token = portal.issue()
    with _page(portal) as page:
        _seed(page, token)
        assert recipes.cscs_token_proof(page, wait_s=8) == recipes.VALID
        got = recipes.cscs_token_state(page)
        assert got["state"] == recipes.VALID and got["key"] == TOKEN_KEY
        assert token not in json.dumps(got)


@pytest.mark.launches_chrome
@CHROME
def test_no_token_on_the_portal_is_invalid(portal: Portal) -> None:
    with _page(portal) as page:
        _seed(page, None)
        assert recipes.cscs_token_proof(page, wait_s=8) == recipes.INVALID


@pytest.mark.launches_chrome
@CHROME
@pytest.mark.parametrize("status", [503, 500])
def test_an_api_error_is_indeterminate(portal: Portal, status: int) -> None:
    token = portal.issue()
    portal.me_status = status
    with _page(portal) as page:
        _seed(page, token)
        assert recipes.cscs_token_proof(page, wait_s=8) == recipes.INDETERMINATE


@pytest.mark.launches_chrome
@CHROME
def test_bearer_only_when_the_portal_enables_oidc_tokens(portal: Portal) -> None:
    token = portal.issue()
    portal.oidc = True
    with _page(portal) as page:
        _seed(page, token)
        assert recipes.cscs_token_state(page)["state"] == recipes.VALID
        page.evaluate("() => localStorage.setItem('waldur/auth/method', 'local')")
        # a local login always sends `Token` (the app's rule): rejected here
        assert recipes.cscs_token_state(page)["state"] == recipes.INVALID
        page.evaluate("() => localStorage.setItem('waldur/auth/method', 'keycloak')")
        portal.config_status = 500  # the scheme is unknown: a 401 decides nothing
        assert recipes.cscs_token_state(page)["state"] == recipes.INDETERMINATE


@pytest.mark.launches_chrome
@CHROME
def test_a_valid_token_under_another_key_proves_nothing(portal: Portal) -> None:
    """Without `waldur/auth/token`, 40-hex values elsewhere are only
    candidates; one the server accepts is `wrong_key` — undecided, never a
    reusable session (the app reads only its key), so no proof-valid /
    export-impossible loop (debate C2)."""
    good = portal.issue()
    with _page(portal) as page:
        _seed(page, None)
        page.evaluate(
            "([a, b]) => { localStorage.setItem('other/a', a);"
            " localStorage.setItem('other/b', b); }",
            [secrets.token_hex(20), good],
        )
        assert recipes.cscs_token_state(page)["state"] == "wrong_key"
        assert recipes.cscs_token_proof(page, wait_s=8) == recipes.INDETERMINATE
        with pytest.raises(recipes.BundleExportError, match="not under"):
            recipes.cscs_export_storage(page)


@pytest.mark.launches_chrome
@CHROME
def test_export_reads_the_validated_tuple(portal: Portal) -> None:
    token = portal.issue()
    with _page(portal) as page:
        _seed(page, token, _iso(time.time() + 3000))
        page.evaluate("() => localStorage.setItem('waldur/auth/method', 'keycloak')")
        page.evaluate("() => localStorage.setItem('unrelated', 'x')")
        values = recipes.cscs_export_storage(page)
        assert set(values) == {TOKEN_KEY, EXPIRES_KEY, "waldur/auth/method"}
        assert values[TOKEN_KEY] == token
        portal.revoke_all()
        with pytest.raises(recipes.BundleExportError, match="rejected"):
            recipes.cscs_export_storage(page)


# ---------------------------------------------------------------------------
# B. the broker end to end (its own disposable Chromium, routed)
# ---------------------------------------------------------------------------


class _CountingVault:
    def __init__(self, inner: vault.FixtureVault) -> None:
        self._inner = inner
        self.secret_calls = 0

    def items(self) -> list[vault.SiteItem]:
        return self._inner.items()

    def secret(self, site: str) -> vault.Secret:
        self.secret_calls += 1
        return self._inner.secret(site)


class _RoutedRunner(daemon.PlaywrightRunner):
    """The real runner; its contexts are routed to the fixture portal."""

    app: Portal

    def _launch(
        self, pw: Any, profile: Path, item: vault.SiteItem | None = None
    ) -> Any:
        ctx = super()._launch(pw, profile, item)
        _route(ctx, self.app)
        return ctx


@dataclass
class _Rig:
    brk: daemon.Broker
    vault: _CountingVault
    home: Path
    app: Portal
    runner: _RoutedRunner

    def login(self) -> dict[str, Any]:
        return self.brk._login_request("cscs", {})

    def limiter_bytes(self) -> bytes:
        path = self.home / "limiter.json"
        return path.read_bytes() if path.exists() else b""

    def last_outcome(self) -> str:
        entry = json.loads(self.limiter_bytes())["sites"]["cscs"]
        return str(entry["attempts"][-1][1])


def _rig(tmp_path: Path, app: Portal) -> _Rig:
    fields = {
        "agent_site": "cscs",
        "agent_fill_origins": AUTH,
        "agent_cookie_hosts": "portal.cscs.ch",
        "agent_login_url": PORTAL + "/profile/",
    }
    item = {
        "id": "id-cscs",
        "name": "CSCS fixture",
        "login": {"username": app.username, "password": app.password},
        "fields": [{"name": k, "value": v} for k, v in fields.items()],
    }
    fixture = tmp_path / "items.json"
    fixture.write_text(json.dumps([item]))
    home = tmp_path / "home"
    counting = _CountingVault(vault.FixtureVault(fixture, dev=True))
    runner = _RoutedRunner(home, dev=True)
    runner.app = app
    brk = daemon.Broker(
        counting,  # type: ignore[arg-type]
        limiter.Limiter(home / "limiter.json", 0, 100, 100),
        home,
        runner=runner,
    )
    return _Rig(brk, counting, home, app, runner)


def _cooldown(rig: _Rig) -> None:
    now = time.time()
    grant = rig.brk.limiter.reserve_site("cscs", now)
    assert isinstance(grant, limiter.AttemptGrant)
    rig.brk.limiter.mark_submitted(grant)
    rig.brk.limiter.finish(grant, "unknown", now)
    assert rig.brk.limiter.peek(["cscs"], time.time()) is not None


@pytest.mark.launches_chrome
@CHROME
def test_a_fresh_login_exports_the_validated_token(
    tmp_path: Path, portal: Portal
) -> None:
    rig = _rig(tmp_path, portal)
    resp = rig.login()
    assert resp.get("ok"), resp
    assert resp["proof"] == "strict"  # the server proof, no DOM sentinel
    assert resp["fresh_auth"] is True and resp["bundle"]["via"] == "login"
    storage = resp["bundle"]["storage"][PORTAL]
    assert portal.live(storage[TOKEN_KEY]) and EXPIRES_KEY in storage
    assert resp["bundle"]["storage_keys"][PORTAL] == list(storage)
    assert portal.logins == 1 and rig.last_outcome() == "ok"
    assert portal.remember_me == [True]  # the IdP session survives restarts


@pytest.mark.launches_chrome
@CHROME
def test_a_stale_profile_logs_in_again(tmp_path: Path, portal: Portal) -> None:
    """The live failure: the profile's token died server-side. The old proof
    reused it (and exported nothing); now it is a normal login."""
    rig = _rig(tmp_path, portal)
    assert rig.login().get("ok")
    portal.revoke_all()
    resp = rig.login()
    assert resp.get("ok"), resp
    assert resp["bundle"]["via"] == "login" and portal.logins == 2
    assert portal.live(resp["bundle"]["storage"][PORTAL][TOKEN_KEY])


@pytest.mark.launches_chrome
@CHROME
def test_a_validated_reuse_in_a_cooldown_needs_no_secret(
    tmp_path: Path, portal: Portal
) -> None:
    rig = _rig(tmp_path, portal)
    assert rig.login().get("ok")
    _cooldown(rig)
    before, calls = rig.limiter_bytes(), rig.vault.secret_calls
    resp = rig.login()
    assert resp.get("ok"), resp
    assert resp["bundle"]["via"] == "profile" and resp["fresh_auth"] is False
    assert resp["bundle"]["session_refresh"] == recipes.REFRESH_DONE
    assert rig.vault.secret_calls == calls and rig.limiter_bytes() == before
    assert portal.logins == 1


@pytest.mark.launches_chrome
@CHROME
def test_an_api_outage_on_reuse_never_reads_the_secret(
    tmp_path: Path, portal: Portal
) -> None:
    rig = _rig(tmp_path, portal)
    assert rig.login().get("ok")
    portal.me_status = 503
    before, calls = rig.limiter_bytes(), rig.vault.secret_calls
    resp = rig.login()
    assert not resp.get("ok")
    assert resp["phase"] == "profile-proof" and resp["submitted"] is False
    assert rig.vault.secret_calls == calls and rig.limiter_bytes() == before


@pytest.mark.launches_chrome
@CHROME
def test_a_stale_expiry_is_refreshed_before_export(
    tmp_path: Path, portal: Portal
) -> None:
    """The token still works but its recorded expiry has passed: exported as
    is, boot-redirect.js would send the session to Keycloak on `/`. The reuse
    writes back the expiry the server reports (its sliding renewal)."""
    rig = _rig(tmp_path, portal)
    assert rig.login().get("ok")
    from playwright.sync_api import (  # pylint: disable=import-outside-toplevel
        sync_playwright,
    )

    with sync_playwright() as pw:  # age the profile's recorded expiry
        ctx = rig.runner._launch(pw, rig.runner.profile_dir("cscs"))
        try:
            page = ctx.new_page()
            page.goto(PORTAL + "/robots.txt")
            page.evaluate(
                "([k, v]) => localStorage.setItem(k, v)",
                [EXPIRES_KEY, _iso(time.time() - 7200)],
            )
        finally:
            ctx.close()
    resp = rig.login()
    assert resp.get("ok"), resp
    assert resp["bundle"]["via"] == "profile"
    exported = resp["bundle"]["storage"][PORTAL][EXPIRES_KEY]
    left = datetime.fromisoformat(exported).timestamp() - time.time()
    assert left > 3000


@pytest.mark.launches_chrome
@CHROME
def test_a_silent_sso_types_nothing(tmp_path: Path, portal: Portal) -> None:
    rig = _rig(tmp_path, portal)
    assert rig.login().get("ok")
    portal.revoke_all()
    portal.silent_sso = True  # Keycloak still knows the browser
    before, calls = rig.limiter_bytes(), rig.vault.secret_calls
    resp = rig.login()
    assert resp.get("ok"), resp
    assert resp["bundle"]["via"] == "sso" and resp["fresh_auth"] is False
    assert portal.logins == 1 and portal.live(
        resp["bundle"]["storage"][PORTAL][TOKEN_KEY]
    )
    # the preflight ran BEFORE any reservation: limiter and vault untouched
    assert rig.limiter_bytes() == before and rig.vault.secret_calls == calls


def _streak(rig: _Rig) -> tuple[int, Any]:
    entry = json.loads(rig.limiter_bytes())["sites"]["cscs"]
    return int(entry.get("consecutive", 0)), entry.get("cooldown_until")


def _revoke_before_export(
    monkeypatch: pytest.MonkeyPatch, app: Portal
) -> Callable[..., Any]:
    """The token dies between the proof and the export (the export's own
    server check must catch it)."""
    real = daemon.PlaywrightRunner._cscs_portal_storage

    def revoked(self: Any, ctx: Any, item: Any) -> dict[str, str]:
        app.revoke_all()
        return real(self, ctx, item)

    monkeypatch.setattr(daemon.PlaywrightRunner, "_cscs_portal_storage", revoked)
    return real


@pytest.mark.launches_chrome
@CHROME
def test_an_export_without_a_valid_token_is_bundle_export(
    tmp_path: Path, portal: Portal, monkeypatch: pytest.MonkeyPatch
) -> None:
    rig = _rig(tmp_path, portal)
    audits: list[tuple[str, str]] = []
    real_audit = rig.brk.audit

    def audit(op: str, site: Any, result: str, *a: Any, **k: Any) -> None:
        audits.append((op, result))
        real_audit(op, site, result, *a, **k)

    monkeypatch.setattr(rig.brk, "audit", audit)
    _revoke_before_export(monkeypatch, portal)
    resp = rig.brk.handle({"op": "login", "site": "cscs"}, uid=0)
    assert not resp.get("ok")
    assert resp["error"] == "bundle_export" and resp["phase"] == "bundle-export"
    assert ("login", "bundle_export") in audits and ("login", "ok") not in audits
    # the password was right (proven): the streak clears, nothing to quarantine
    assert rig.last_outcome() == "ok"
    assert not phases.post_submit(resp["phase"], resp["submitted"])
    assert "bundle_export" in phases.CODE_TEXT


@pytest.mark.launches_chrome
@CHROME
def test_a_silent_sso_with_a_failed_export_keeps_the_streak(
    tmp_path: Path, portal: Portal, monkeypatch: pytest.MonkeyPatch
) -> None:
    rig = _rig(tmp_path, portal)
    assert rig.login().get("ok")
    portal.revoke_all()
    portal.silent_sso = True
    _revoke_before_export(monkeypatch, portal)
    before, calls = rig.limiter_bytes(), rig.vault.secret_calls
    resp = rig.login()
    assert resp["error"] == "bundle_export" and resp["submitted"] is False
    assert rig.limiter_bytes() == before and rig.vault.secret_calls == calls
    assert _streak(rig) == (0, None)


# ---------------------------------------------------------------------------
# C. the client (bin/browser.py) against the same portal
# ---------------------------------------------------------------------------

CSCS_ENTRY = {
    "site": "cscs",
    "check_url": PORTAL + "/profile/",
    "storage_origins": [PORTAL],
}


@contextlib.contextmanager
def _client(app: Portal, monkeypatch: pytest.MonkeyPatch) -> Iterator[list[str]]:
    """`_with_prepared_background_page` on a routed throwaway context (the
    shared browser stays untouched); yields the URLs it loaded."""
    from playwright.sync_api import (  # pylint: disable=import-outside-toplevel
        sync_playwright,
    )

    loaded: list[str] = []
    with sync_playwright() as pw:
        chrome = pw.chromium.launch(headless=True)
        try:
            ctx = chrome.new_context()
            _route(ctx, app)

            def run(_port: int, url: str, prepare: Any, fn: Any) -> Any:
                page = ctx.new_page()
                try:
                    if prepare is not None:
                        prepare(page)
                    loaded.append(url)
                    resp = page.goto(url, wait_until="domcontentloaded")
                    browser._BG_STATUS[id(page)] = getattr(resp, "status", None)
                    return fn(page)
                finally:
                    browser._BG_STATUS.pop(id(page), None)
                    page.close()

            monkeypatch.setattr(browser, "_with_prepared_background_page", run)
            yield loaded
        finally:
            chrome.close()


def _bundle(app: Portal, *, expires: str | None = None) -> dict[str, Any]:
    kv = {TOKEN_KEY: app.issue(), "waldur/auth/method": "keycloak"}
    if expires:
        kv[EXPIRES_KEY] = expires
    return {"storage": {PORTAL: kv}, "storage_keys": {PORTAL: list(kv)}}


@pytest.mark.launches_chrome
@CHROME
def test_the_client_injects_on_profile_reads_back_and_proves(
    portal: Portal, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    bundle = _bundle(portal, expires=_iso(time.time() - 7200))  # app rewrites it
    with _client(portal, monkeypatch) as loaded:
        browser._RESULT.clear()
        assert browser._broker_check_entry(0, "cscs", CSCS_ENTRY) == 2  # empty
        assert browser._broker_write_storage(0, bundle) == 3
        assert loaded[-1] == PORTAL + "/profile/"  # never `/`
        assert browser._broker_check_entry(0, "cscs", CSCS_ENTRY) == 0
        assert browser._RESULT["proof_v"] == browser.PROOF_V
    out = capsys.readouterr()
    assert bundle["storage"][PORTAL][TOKEN_KEY] not in out.out + out.err
    assert "weaker proof" not in out.err


@pytest.mark.launches_chrome
@CHROME
def test_the_client_probe_rejects_a_stale_injected_token(
    portal: Portal, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = _bundle(portal)
    portal.revoke_all()
    with _client(portal, monkeypatch):
        browser._broker_write_storage(0, bundle)
        assert browser._broker_check_entry(0, "cscs", CSCS_ENTRY) == 2
        assert browser._RESULT["code"] == "logged_out"


def _fake_requests(app: Portal) -> Callable[..., Any]:
    """`requests.get` answered by the fixture portal's state (no network)."""

    class _Resp:
        def __init__(self, status: int, obj: object) -> None:
            self.status_code = status
            self._obj = obj

        def json(self) -> object:
            return self._obj

    def get(url: str, headers: dict[str, str] | None = None, **_k: Any) -> _Resp:
        if url == browser.PORTAL_API_CONFIG:
            return _Resp(200, {"WALDUR_CORE": {"OIDC_ACCESS_TOKEN_ENABLED": app.oidc}})
        assert url == browser.PORTAL_API_ME
        scheme, _, token = (headers or {}).get("Authorization", "").partition(" ")
        if scheme == ("Bearer" if app.oidc else "Token") and app.live(token):
            return _Resp(200, {"uuid": "u-1", "username": app.username, "email": "e"})
        return _Resp(401, {"detail": "Invalid token."})

    return get


@pytest.mark.launches_chrome
@CHROME
def test_cmd_token_caches_only_a_validated_token(
    portal: Portal, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cache = tmp_path / "portal_token"
    monkeypatch.setattr(browser, "CSCS_TOKEN_CACHE", cache)
    monkeypatch.setattr(requests, "get", _fake_requests(portal))
    token = portal.issue()
    with _page(portal) as page:
        _seed(page, token)
        browser._RESULT.clear()
        assert browser._token_in_page(page) == 0
        assert cache.read_text() == token and cache.stat().st_mode & 0o777 == 0o600
        assert browser._RESULT["proof_v"] == browser.PROOF_V
        cache.unlink()
        portal.revoke_all()
        _seed(page, token)
        assert browser._token_in_page(page) == 2  # rejected: needs a login
        assert not cache.exists()


@pytest.mark.launches_chrome
@CHROME
def test_token_candidates_prefer_the_app_key(portal: Portal) -> None:
    main, other = portal.issue(), secrets.token_hex(20)
    with _page(portal) as page:
        _seed(page, main)
        page.evaluate("v => localStorage.setItem('zz/other', v)", other)
        tokens, method = browser._token_candidates(page.context, page)
        assert tokens == [main] and method is None
        page.evaluate("() => localStorage.removeItem('waldur/auth/token')")
        tokens, _method = browser._token_candidates(page.context, page)
        assert tokens == [other]


# ---------------------------------------------------------------------------
# D. hermetic units
# ---------------------------------------------------------------------------


@pytest.fixture(name="inject")
def _inject(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    seen: dict[str, Any] = {"cookies": 0, "reply": {}}

    class _Pw:
        def stop(self) -> None:
            return None

    class _Browser:
        contexts: list[Any] = []

        def close(self) -> None:
            return None

    monkeypatch.setattr(browser, "_connect", lambda _port: (_Pw(), _Browser()))
    monkeypatch.setattr(
        browser, "_interaction_lease", lambda _why: contextlib.nullcontext()
    )
    monkeypatch.setattr(browser, "_broker_request", lambda *_a, **_k: seen["reply"])

    def cookies(_browser: Any, _bundle: dict[str, Any]) -> int:
        seen["cookies"] += 1
        return 1

    monkeypatch.setattr(browser, "_broker_replace_cookies", cookies)
    monkeypatch.setattr(
        browser, "_broker_write_storage", lambda *_a: pytest.fail("storage touched")
    )
    browser._RESULT.clear()
    return seen


@pytest.mark.parametrize(
    "storage",
    [
        {},
        {PORTAL: {}},
        {PORTAL: {EXPIRES_KEY: "2026-01-01T00:00:00Z"}},
        {PORTAL: {TOKEN_KEY: "  "}},
    ],
)
def test_the_client_never_touches_cookies_without_the_token(
    inject: dict[str, Any], storage: dict[str, Any]
) -> None:
    inject["reply"] = {
        "ok": True,
        "fresh_auth": True,
        "bundle": {"cookies": [{"name": "c"}], "storage": storage},
    }
    rc, _bundle, n_cookies, _keys = browser._broker_fetch_inject(9222, "cscs", {}, {})
    assert rc == 2 and n_cookies == 0 and inject["cookies"] == 0
    assert browser._RESULT["phase"] == "bundle-export"
    assert browser._RESULT["code"] == "incomplete_bundle"


class _RewritingSpa:
    """A portal tab whose app rewrites the expiry right after the injection."""

    def __init__(self) -> None:
        self.url = "about:blank"
        self.storage: dict[str, str] = {}
        self.scripts: list[str] = []

    def add_init_script(self, script: str) -> None:
        self.scripts.append(script)

    def goto(self, url: str, **_kw: Any) -> None:
        self.url = url
        for script in self.scripts:
            kv = json.loads(script.split("const kv = ", 1)[1].split(";", 1)[0])
            self.storage.update(kv)
        self.storage[EXPIRES_KEY] = "rewritten by the app"

    def evaluate(self, js: str, arg: Any = None) -> bool:
        assert js == browser._BROKER_STORAGE_CHECK_JS
        assert EXPIRES_KEY not in arg  # volatile: never checked
        # The init script read every value back before the app ran; after
        # load only presence counts.
        return bool(self.scripts) and all(self.storage.get(k) for k in arg)


def test_the_storage_write_ignores_the_volatile_expiry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    page = _RewritingSpa()
    urls: list[str] = []

    def run(_port: int, url: str, prepare: Any, fn: Any) -> Any:
        urls.append(url)
        prepare(page)
        page.goto(url)
        return fn(page)

    monkeypatch.setattr(browser, "_with_prepared_background_page", run)
    monkeypatch.setattr(browser, "_broker_bypass_cache", lambda _p: None)
    kv = {TOKEN_KEY: secrets.token_hex(20), EXPIRES_KEY: "old"}
    assert browser._broker_write_storage(9222, {"storage": {PORTAL: kv}}) == 2
    assert urls == [PORTAL + "/profile/"]


class _NoFormPage:
    """Neither the Keycloak form nor the portal: somewhere else entirely."""

    url = "https://elsewhere.example/"
    frames: list[Any] = []

    def query_selector_all(self, _sel: str) -> list[Any]:
        return []

    def wait_for_timeout(self, _ms: float) -> None:
        return None

    def title(self) -> str:
        return ""

    def evaluate(self, *_a: Any) -> Any:
        return ""

    def eval_on_selector_all(self, *_a: Any) -> list[Any]:
        return []


def test_no_form_and_no_portal_is_a_pre_submit_failure() -> None:
    with pytest.raises(recipes.LoginFailed, match="form not found") as err:
        recipes._cscs_form_or_portal(_NoFormPage(), 0.5)
    assert err.value.submitted is False


def test_an_export_without_a_token_is_bundle_export() -> None:
    class _Empty:
        def evaluate(self, *_a: Any) -> dict[str, str]:
            return {"state": "none"}

        def wait_for_timeout(self, _ms: float) -> None:
            return None

    with pytest.raises(recipes.BundleExportError) as err:
        recipes.cscs_export_storage(_Empty())
    assert err.value.code == "bundle_export" and err.value.phase == "bundle-export"


def test_cscs_is_a_strict_proof_without_a_sentinel() -> None:
    raw = {
        "id": "x",
        "name": "CSCS",
        "login": {"username": "u", "password": "p" * 8},
        "fields": [{"name": "agent_fill_origins", "value": AUTH}],
    }
    raw["name"] = "cscs"
    item = vault.site_item_from_json(raw)
    assert item.site == "cscs" and not item.logged_in_selector
    assert item.has_proof and recipes.strict_proof(item)
    assert item.public()["strict_proof"] is True
    assert item.public()["sentinel"] is False
    assert item.public()["session_refresh"] == "waldur-token"


def test_agent_login_counts_the_server_proof() -> None:
    al = _load("agent_login_ws2_cscs_test", REPO / "agent-login.py")
    assert al.has_sentinel({"site": "cscs", "strict_proof": True, "sentinel": False})
    # an older broker (no strict_proof) still runs the 40-hex shape proof
    assert not al.has_sentinel({"site": "cscs", "sentinel": False})
    assert not al.has_sentinel({"site": "x", "sentinel": False})
    assert not al.has_sentinel({"site": "x", "strict_proof": False})


def test_the_timeouts_nest() -> None:
    """broker run < client socket < browser.py login deadline < runner, and
    a login only starts with enough of the run left."""
    assert daemon.MIN_LOGIN_LEFT_S < daemon.RUN_DEADLINE_S
    assert daemon.RUN_DEADLINE_S + 20 <= browser.BROKER_TIMEOUT_S
    assert browser.BROKER_TIMEOUT_S + 120 <= browser.LOGIN_TIMEOUT_DEFAULT_S
    assert jobs.LOGIN_TIMEOUT_DEFAULT_S == browser.LOGIN_TIMEOUT_DEFAULT_S
    assert jobs.browser_timeout("login") > browser.LOGIN_TIMEOUT_DEFAULT_S
    assert 188 < daemon.RUN_DEADLINE_S  # the measured fresh CSCS login


def test_a_login_is_not_started_late(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner = daemon.PlaywrightRunner(tmp_path)

    class _Page:
        url = "about:blank"

    class _Ctx:
        pages = [_Page()]

    called: list[int] = []

    def get_secret() -> vault.Secret:
        called.append(1)
        raise AssertionError("no secret this late")

    item = vault.site_item_from_json(
        {
            "id": "x",
            "name": "cscs",
            "login": {"username": "u", "password": "p" * 8},
            "fields": [{"name": "agent_fill_origins", "value": AUTH}],
        }
    )
    monkeypatch.setattr(runner, "_profile_proof", lambda _p, _i: recipes.INVALID)
    ran: list[str] = []

    def slow_preflight(*_a: Any, **_k: Any) -> str:
        ran.append("preflight")
        time.sleep(0.3)  # the Keycloak form wait eats into the run
        return recipes.INVALID

    monkeypatch.setitem(daemon.PREFLIGHTS, "cscs", slow_preflight)
    # enough left BEFORE the preflight, too little after it (debate R2-C4)
    deadline = time.monotonic() + daemon.MIN_LOGIN_LEFT_S + 0.2
    with pytest.raises(recipes.LoginFailed) as err:
        runner.run_in_context(_Ctx(), item, get_secret, deadline=deadline)
    assert err.value.code == "timeout" and not called and ran == ["preflight"]


def test_the_watchdog_kills_only_the_run_profile(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    profile = tmp_path / "profiles" / "cscs"
    listing = (
        f"  101 /x/Chromium --user-data-dir={profile} --headless\n"
        f"  102 /x/Chromium --user-data-dir={profile}-other\n"
        "  103 /bin/zsh\n"
    )

    class _Done:
        stdout = listing

    monkeypatch.setattr(daemon.subprocess, "run", lambda *_a, **_k: _Done())
    assert daemon.chrome_pids(profile) == [101]
    killed: list[int] = []
    monkeypatch.setattr(daemon.os, "kill", lambda pid, _sig: killed.append(pid))
    starts = {101: "Sat Oct 10 10:00:00 2026"}
    monkeypatch.setattr(daemon, "proc_start", starts.get)
    with daemon.RunWatchdog(profile, 0.1) as dog:
        dog.arm()
        time.sleep(0.4)
    assert dog.fired.is_set() and killed == [101]
    with daemon.RunWatchdog(profile, 0.1) as reused:
        reused.arm()
        starts[101] = "Sat Oct 10 11:00:00 2026"  # pid 101 is another process now
        time.sleep(0.4)
    assert reused.fired.is_set() and killed == [101]  # never the reused pid
    with daemon.RunWatchdog(profile, 5) as quiet:
        pass
    assert not quiet.fired.is_set() and killed == [101]
    err = daemon.deadline_error(
        recipes.LoginFailed("x", submitted=True, phase="submit")
    )
    assert err.code == "timeout" and err.submitted and err.phase == "submit"


@pytest.mark.launches_chrome
@CHROME
def test_chrome_pids_finds_a_real_persistent_context(tmp_path: Path) -> None:
    from playwright.sync_api import (  # pylint: disable=import-outside-toplevel
        sync_playwright,
    )

    profile = tmp_path / "profile"
    with sync_playwright() as pw:
        ctx = pw.chromium.launch_persistent_context(str(profile), headless=True)
        try:
            assert daemon.chrome_pids(profile)
        finally:
            ctx.close()


class _StatePage:
    """A portal page whose in-page check answers `state`; records budgets."""

    url = PORTAL + "/profile/"

    def __init__(self, state: str) -> None:
        self.state = state
        self.budgets: list[int] = []

    def evaluate(self, _js: str, arg: Any = None) -> dict[str, Any]:
        self.budgets.append(int(arg[2]))
        return {"state": self.state}

    def wait_for_timeout(self, _ms: float) -> None:
        return None


@pytest.mark.parametrize("state", ["storage_error", "wrong_key"])
def test_unreadable_storage_or_a_foreign_key_is_undecided(state: str) -> None:
    """Debate C3: storage that cannot be read is not "no token"."""
    assert (
        recipes.cscs_token_proof(_StatePage(state), wait_s=2) == recipes.INDETERMINATE
    )


def test_each_check_gets_only_the_budget_left() -> None:
    """Debate C5: the in-page check never runs longer than the proof's wait."""
    page = _StatePage("none")
    assert recipes.cscs_token_proof(page, wait_s=3) == recipes.INVALID
    limit = int((3 + recipes.CSCS_MIN_CHECK_S) * 1000)
    assert page.budgets and all(b <= limit for b in page.budgets)
    assert recipes.cscs_token_state(_StatePage("none"), budget_s=999) == {
        "state": "none"
    }


def test_a_rejected_bundle_never_touches_cookies(
    inject: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Debate C9: the client asks the API about the bundled token first."""
    inject["reply"] = {
        "ok": True,
        "bundle": {"storage": {PORTAL: {TOKEN_KEY: secrets.token_hex(20)}}},
    }
    monkeypatch.setattr(browser, "_portal_auth_scheme", lambda _m, *_a: ["Token"])
    monkeypatch.setattr(
        browser, "_validate_portal_token", lambda _t, _s, *_a: ("invalid", None, "")
    )
    rc, _bundle, n_cookies, _keys = browser._broker_fetch_inject(9222, "cscs", {}, {})
    assert rc == 2 and n_cookies == 0 and inject["cookies"] == 0
    assert browser._RESULT["code"] == "bundle_rejected"
    assert "bundle_rejected" in phases.CODE_TEXT
    # undecided (network): the proof after the injection decides
    monkeypatch.setattr(
        browser,
        "_validate_portal_token",
        lambda _t, _s, *_a: ("indeterminate", None, ""),
    )
    monkeypatch.setattr(browser, "_broker_write_storage", lambda *_a: 1)
    rc, _bundle, n_cookies, _keys = browser._broker_fetch_inject(9222, "cscs", {}, {})
    assert rc is None and inject["cookies"] == 1


def test_a_success_after_the_deadline_is_a_timeout_with_the_auth_proven(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Debate C6: a result the client may no longer wait for never leaves;
    the proven login still counts, the profile keeps the session."""
    runner = daemon.PlaywrightRunner(tmp_path)

    class _Ctx:
        def close(self) -> None:
            return None

    monkeypatch.setattr(daemon, "RUN_DEADLINE_S", 0.05)
    monkeypatch.setattr(daemon, "chrome_pids", lambda _p: [])
    monkeypatch.setattr(runner, "_launch", lambda *_a, **_k: _Ctx())

    def slow(*_a: Any, **_k: Any) -> dict[str, Any]:
        time.sleep(0.4)
        return {"site": "cscs"}

    monkeypatch.setattr(runner, "run_in_context", slow)
    item = vault.site_item_from_json(
        {
            "id": "x",
            "name": "cscs",
            "login": {"username": "u", "password": "p" * 8},
            "fields": [{"name": "agent_fill_origins", "value": AUTH}],
        }
    )
    with pytest.raises(daemon.DeadlineError) as err:
        runner(item, lambda: pytest.fail("no secret"))
    assert err.value.code == "timeout" and err.value.auth_proven


@pytest.mark.parametrize(
    "said, rolled_back",
    [("invalid", True), ("indeterminate", False), (None, False)],
)
def test_a_dead_injected_session_is_removed_again(
    monkeypatch: pytest.MonkeyPatch, said: str | None, rolled_back: bool
) -> None:
    """Debate C9 + review: only the site's API saying `invalid` undoes the
    injection; an undecided answer or a generic "logged out" (a missing
    sentinel, a 4xx — a slow SPA) leaves it alone."""
    bundle = {"storage": {PORTAL: {TOKEN_KEY: "t"}}, "cookies": []}
    monkeypatch.setattr(browser, "_broker_already", lambda *_a: None)
    monkeypatch.setattr(browser, "_broker_gate", lambda _s: None)
    monkeypatch.setattr(browser, "_broker_entry_or_rc", lambda _s: (CSCS_ENTRY, 0))
    monkeypatch.setattr(
        browser, "_broker_fetch_inject", lambda *_a, **_k: (None, bundle, 0, 1)
    )

    def check(*_a: Any, **_k: Any) -> int:
        browser._RESULT["code"] = (
            "indeterminate" if said == "indeterminate" else "logged_out"
        )
        if said is not None:
            browser._RESULT["server_proof"] = said
        return 2

    undone: list[Any] = []

    def undo(_port: int, site: str, got: dict[str, Any]) -> str:
        undone.append((site, got))
        return "complete"

    monkeypatch.setattr(browser, "_broker_check_entry", check)
    monkeypatch.setattr(browser, "_broker_undo_injection", undo)
    monkeypatch.setitem(browser._LOGIN_OPTS, "candidate", None)
    browser._RESULT.clear()
    assert browser._broker_login(9222, "cscs") == 2
    assert bool(undone) is rolled_back
    if rolled_back:
        assert undone == [("cscs", bundle)]
        assert browser._RESULT["rollback"] == "complete"
    # a candidate check never undoes (its sentinel may be wrong, not the session)
    undone.clear()
    monkeypatch.setitem(browser._LOGIN_OPTS, "candidate", "#maybe")
    assert browser._broker_login(9222, "cscs") == 2
    assert not undone


@pytest.mark.launches_chrome
@CHROME
def test_the_undo_removes_only_values_that_are_still_the_bundle(
    portal: Portal, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Debate R2-C1: compare-and-swap — a session another login installed
    meanwhile (different values) survives the undo of a rejected bundle."""
    monkeypatch.setattr(
        browser, "_interaction_lease", lambda _why, **_k: contextlib.nullcontext()
    )
    stale = _bundle(portal)
    newer = portal.issue()
    with _client(portal, monkeypatch):
        assert browser._broker_write_storage(0, stale) == 2
        assert browser._broker_undo_injection(0, "cscs", stale) == "complete"
        assert browser._broker_check_entry(0, "cscs", CSCS_ENTRY) == 2  # gone
        browser._broker_write_storage(0, stale)
        mine = {"storage": {PORTAL: {TOKEN_KEY: newer}}}
        browser._broker_write_storage(0, mine)  # a concurrent, newer login
        assert browser._broker_undo_injection(0, "cscs", stale) == "complete"
        assert browser._broker_check_entry(0, "cscs", CSCS_ENTRY) == 0  # kept


class _NeverFires:
    """A watchdog whose thread never got to run (the boundary race)."""

    def __init__(self, *_a: Any) -> None:
        import threading  # pylint: disable=import-outside-toplevel

        self.fired = threading.Event()

    def __enter__(self) -> _NeverFires:
        return self

    def __exit__(self, *_a: Any) -> None:
        return None

    def arm(self) -> None:
        return None


def test_the_deadline_itself_decides_not_only_the_watchdog(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Debate R2-C2: a run that ends after its deadline before the watchdog
    thread fired is still a timeout; a request already past it never starts
    a browser."""
    runner = daemon.PlaywrightRunner(tmp_path)

    class _Ctx:
        def close(self) -> None:
            return None

    launched: list[int] = []

    def launch(*_a: Any, **_k: Any) -> _Ctx:
        launched.append(1)
        return _Ctx()

    monkeypatch.setattr(daemon, "RunWatchdog", _NeverFires)
    monkeypatch.setattr(runner, "_launch", launch)
    item = vault.site_item_from_json(
        {
            "id": "x",
            "name": "cscs",
            "login": {"username": "u", "password": "p" * 8},
            "fields": [{"name": "agent_fill_origins", "value": AUTH}],
        }
    )

    class _Gate:
        deadline = 0.0

        def __call__(self) -> vault.Secret:
            raise AssertionError("no secret")

    gate = _Gate()
    gate.deadline = time.monotonic() + 3.0  # room for Playwright's start

    def finish_late(*_a: Any, **_k: Any) -> dict[str, Any]:
        time.sleep(max(0.0, gate.deadline - time.monotonic()) + 0.1)
        return {"site": "x"}

    monkeypatch.setattr(runner, "run_in_context", finish_late)
    with pytest.raises(daemon.DeadlineError):
        runner(item, gate)
    assert launched == [1]
    gone = _Gate()
    gone.deadline = time.monotonic() - 1
    with pytest.raises(daemon.DeadlineError):
        runner(item, gone)
    assert launched == [1]  # never launched


def test_the_run_deadline_counts_from_the_request(tmp_path: Path) -> None:
    """Debate R2-C3: the vault item read happens INSIDE the deadline."""
    seen: list[float] = []

    def runner(_item: Any, gate: Any) -> dict[str, Any]:
        seen.append(gate.deadline)
        return {"site": "cscs", "cookies": [], "storage": {}}

    class _SlowVault:
        def items(self) -> list[vault.SiteItem]:
            time.sleep(0.3)  # a cold Bitwarden read
            return [
                vault.site_item_from_json(
                    {
                        "id": "x",
                        "name": "cscs",
                        "login": {"username": "u", "password": "p" * 8},
                        "fields": [{"name": "agent_fill_origins", "value": AUTH}],
                    }
                )
            ]

        def secret(self, _site: str) -> vault.Secret:
            raise AssertionError("no secret")

    brk = daemon.Broker(
        _SlowVault(),  # type: ignore[arg-type]
        limiter.Limiter(tmp_path / "limiter.json", 0, 100, 100),
        tmp_path,
        runner=runner,
    )
    before = time.monotonic()
    brk._login_request("cscs", {})
    assert seen and seen[0] <= before + daemon.RUN_DEADLINE_S + 0.05
    assert seen[0] >= before + daemon.RUN_DEADLINE_S - 0.05


# ---------------------------------------------------------------------------
# E. overseer review (2026-10-10)
# ---------------------------------------------------------------------------


def _cscs_item(**fields: str) -> vault.SiteItem:
    return vault.site_item_from_json(
        {
            "id": "x",
            "name": "cscs",
            "login": {"username": "u", "password": "p" * 8},
            "fields": [
                {"name": k, "value": v}
                for k, v in {"agent_fill_origins": AUTH, **fields}.items()
            ],
        }
    )


def test_no_password_with_too_little_left_whatever_the_path(tmp_path: Path) -> None:
    """S1: the gate itself refuses (fresh_login asks it before any proof)."""
    lim = limiter.Limiter(tmp_path / "limiter.json", 0, 100, 100)

    class _NoVault:
        def secret(self, _site: str) -> vault.Secret:
            raise AssertionError("no secret")

    brk = daemon.Broker(
        _NoVault(),  # type: ignore[arg-type]
        lim,
        tmp_path,
        runner=lambda *_a: {},
    )
    gate = daemon._SecretGate(
        brk, _cscs_item(agent_fresh_login="true"), scheduled=False
    )
    gate.deadline = time.monotonic() + daemon.MIN_LOGIN_LEFT_S - 1
    with pytest.raises(daemon._TooLate) as err:
        gate()
    assert err.value.code == "timeout" and gate.grant is None
    assert not (tmp_path / "limiter.json").exists()  # nothing reserved
    gate.deadline = time.monotonic() + daemon.MIN_LOGIN_LEFT_S + 60
    with pytest.raises(AssertionError, match="no secret"):
        gate()  # enough left: reserves, then reads the secret
    assert gate.grant is not None


@pytest.mark.parametrize("trouble", ["lease", "busy"])
def test_an_unavailable_lease_never_escapes_the_undo(
    monkeypatch: pytest.MonkeyPatch, trouble: str
) -> None:
    """S2: `_interaction_lease` and a client registration end the process
    with SystemExit; the undo answers `partial` instead, the login exits 2."""
    waits: list[float] = []

    @contextlib.contextmanager
    def lease(_why: str, wait_s: float = 30.0) -> Iterator[str]:
        waits.append(wait_s)
        if trouble == "lease":
            raise SystemExit(1)
        yield "nonce"

    def connect(_port: int) -> Any:
        raise SystemExit(75)

    monkeypatch.setattr(browser, "_interaction_lease", lease)
    monkeypatch.setattr(browser, "_connect", connect)
    bundle = {"cookies": [{"name": "c", "domain": "portal.cscs.ch", "value": "v"}]}
    assert browser._broker_undo_injection(0, "cscs", bundle) == "partial"
    assert waits == [browser.UNDO_LEASE_WAIT_S] and browser.UNDO_LEASE_WAIT_S <= 5
    monkeypatch.setattr(browser, "_broker_already", lambda *_a: None)
    monkeypatch.setattr(browser, "_broker_gate", lambda _s: None)
    monkeypatch.setattr(browser, "_broker_entry_or_rc", lambda _s: (CSCS_ENTRY, 0))
    monkeypatch.setattr(
        browser, "_broker_fetch_inject", lambda *_a, **_k: (None, bundle, 1, 0)
    )

    def check(*_a: Any, **_k: Any) -> int:
        browser._RESULT.update(code="logged_out", server_proof="invalid")
        return 2

    monkeypatch.setattr(browser, "_broker_check_entry", check)
    monkeypatch.setitem(browser._LOGIN_OPTS, "candidate", None)
    browser._RESULT.clear()
    assert browser._broker_login(9222, "cscs") == 2
    assert browser._RESULT["rollback"] == "partial"


def test_chrome_pids_parses_argv_robustly(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    profile = tmp_path / "pro file" / "cscs"  # a space in the path
    exe = "/x/chromium-1/chrome-mac/Chromium.app/Contents/MacOS/Chromium"
    helper = (
        "/x/Chromium.app/Contents/Frameworks/Chromium Helper (Renderer).app"
        "/Contents/MacOS/Chromium Helper (Renderer)"
    )
    listing = "\n".join(
        [
            f"  101 {exe} --headless --user-data-dir={profile} --remote-debugging-pipe",
            f"  102 {helper} --type=renderer --user-data-dir={profile}",
            f"  103 {exe} --user-data-dir={profile}-other --headless",
            f"  104 /usr/bin/grep --user-data-dir={profile}",
            f"  105 {exe} --user-data-dir={profile} x",
            "  106 /bin/zsh",
        ]
    )
    seen: list[list[str]] = []

    class _Done:
        stdout = listing

    def run(argv: list[str], **_k: Any) -> _Done:
        seen.append(argv)
        return _Done()

    monkeypatch.setattr(daemon.subprocess, "run", run)
    assert daemon.chrome_pids(profile) == [101, 102]
    assert seen[0][0] == "/bin/ps"  # pinned


def test_the_watchdog_kills_late_helpers_but_not_older_processes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    profile = tmp_path / "profiles" / "cscs"
    monkeypatch.setattr(daemon, "chrome_pids", lambda _p: [201, 202])
    killed: list[int] = []
    monkeypatch.setattr(daemon.os, "kill", lambda pid, _sig: killed.append(pid))
    now = time.time()
    began = {201: now + 5, 202: now - 3600}  # a later helper / an older process
    monkeypatch.setattr(daemon, "start_epoch", began.get)
    monkeypatch.setattr(daemon, "proc_start", lambda _pid: None)
    with daemon.RunWatchdog(profile, 0.1) as dog:  # arm() never saw them
        time.sleep(0.4)
    assert dog.fired.is_set() and killed == [201]
    stopping = daemon.RunWatchdog(profile, 5)
    stopping._stop.set()
    stopping._run()  # the run already ended: nothing killed
    assert killed == [201]


def test_start_epoch_reads_ps_lstart(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(daemon, "proc_start", lambda _pid: "Sat Oct 10 21:00:05 2026")
    assert (
        daemon.start_epoch(1)
        == datetime(2026, 10, 10, 21, 0, 5, tzinfo=timezone.utc).timestamp()
    )
    monkeypatch.setattr(daemon, "proc_start", lambda _pid: "garbage")
    assert daemon.start_epoch(1) is None


def test_deadline_error_keeps_unsent() -> None:
    err = daemon.deadline_error(recipes.LoginFailed("x", unsent=True, phase="recipe"))
    assert err.unsent and err.code == "timeout"


@pytest.mark.parametrize(
    "exc",
    [
        recipes.NeedsHuman("captcha", submitted=True),
        recipes.OriginViolation("left the fill origins"),
    ],
)
def test_past_the_deadline_some_errors_stay_themselves(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, exc: Exception
) -> None:
    runner = daemon.PlaywrightRunner(tmp_path)

    class _Ctx:
        def close(self) -> None:
            return None

    monkeypatch.setattr(daemon, "RunWatchdog", _NeverFires)
    monkeypatch.setattr(runner, "_launch", lambda *_a, **_k: _Ctx())

    class _Gate:
        deadline = 0.0

        def __call__(self) -> vault.Secret:
            raise AssertionError("no secret")

    gate = _Gate()
    gate.deadline = time.monotonic() + 3.0

    def fail_late(*_a: Any, **_k: Any) -> dict[str, Any]:
        time.sleep(max(0.0, gate.deadline - time.monotonic()) + 0.1)
        raise exc

    monkeypatch.setattr(runner, "run_in_context", fail_late)
    with pytest.raises(type(exc)) as err:
        runner(_cscs_item(), gate)
    assert err.value is exc


def test_the_sso_export_honours_a_rejected_refresh(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    runner = daemon.PlaywrightRunner(tmp_path)
    monkeypatch.setitem(daemon.PREFLIGHTS, "cscs", lambda *_a, **_k: recipes.VALID)
    monkeypatch.setattr(runner, "_profile_proof", lambda _p, _i: recipes.VALID)
    monkeypatch.setattr(runner, "_export", lambda *_a, **_k: pytest.fail("exported"))
    monkeypatch.setattr(
        daemon, "refresh_session", lambda *_a, **_k: recipes.REFRESH_REJECTED
    )
    got = runner._before_secret(
        object(), object(), _cscs_item(), lambda: pytest.fail("secret"), None
    )
    assert got is None  # not reusable: the normal login takes over


def test_the_token_capture_has_one_overall_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A network stall ends as exit 1 well inside LOGGED_IN_TIMEOUT_S."""
    assert browser.TOKEN_CAPTURE_BUDGET_S <= browser.LOGGED_IN_TIMEOUT_S / 2
    assert browser.BUNDLE_CHECK_BUDGET_S <= 10
    monkeypatch.setattr(browser, "TOKEN_CAPTURE_BUDGET_S", 0.0)
    monkeypatch.setattr(
        browser, "_token_candidates", lambda *_a: ([secrets.token_hex(20)], "keycloak")
    )
    monkeypatch.setattr(requests, "get", lambda *_a, **_k: pytest.fail("no time left"))
    assert browser._capture_and_cache_token(None, None) == 1
    assert browser._api_timeout(time.monotonic() + 3) == pytest.approx(3, abs=0.2)
    assert browser._api_timeout(time.monotonic() + 100) == browser.PORTAL_API_TIMEOUT_S


def test_the_client_names_the_new_broker_errors() -> None:
    for code in ("timeout", "bundle_export", "bundle_rejected"):
        assert browser.BROKER_ERRORS[code]
        assert code in phases.CODE_TEXT


def test_the_idp_session_never_leaves_with_a_cscs_bundle() -> None:
    """The live cscs item lists `agent_cookie_hosts = cscs.ch` (broker
    snapshot 2026-10-10): Keycloak's host-only cookies on auth.cscs.ch —
    also the long-lived ones "Remember me" sets — stay in the broker."""
    from broker import bundle  # pylint: disable=import-outside-toplevel

    spec = bundle.SiteBundleSpec(cookie_hosts=["cscs.ch"])
    for name in ("KEYCLOAK_IDENTITY", "KEYCLOAK_SESSION", "KEYCLOAK_REMEMBER_ME"):
        assert not bundle.cookie_in_scope("auth.cscs.ch", name, spec)
        assert not browser._broker_cookie_in_scope(
            "auth.cscs.ch", name, ["cscs.ch"], None
        )
    assert bundle.cookie_in_scope("portal.cscs.ch", "csrftoken", spec)


@pytest.mark.launches_chrome
@CHROME
def test_the_undo_beats_a_dead_token_redirect(
    portal: Portal, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Review: the compare-and-swap runs at document start, before the app
    can send a dead session to Keycloak; the result is `complete`."""
    monkeypatch.setattr(
        browser, "_interaction_lease", lambda _why, **_k: contextlib.nullcontext()
    )
    dead = _bundle(portal)
    portal.revoke_all()
    with _client(portal, monkeypatch) as loaded:
        browser._broker_write_storage(0, dead)
        assert browser._broker_undo_injection(0, "cscs", dead) == "complete"
        assert loaded[-1] == PORTAL + "/profile/"
