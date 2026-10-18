"""authentik (auth.dev.renku.ch): the flow-executor login recipe and the
`authentik` identity recipe.

The login page of authentik 2026.8.1 keeps its stage forms in shadow roots
and appends a password-manager helper form to ``<html>`` (off-screen, but
visible to Playwright). The generic form recipe typed into that helper form
and submitted the identification stage with an EMPTY username — the
password never left the page ("still on the login page after submitting the
password"). ``broker/authentik.py`` speaks authentik's flow executor API
instead; ``test_the_generic_recipe_fails_on_the_helper_form`` pins the root
cause on the fixture.

Everything runs in a throwaway headless Chromium against a local TLS
fixture of authentik (throwaway self-signed certificate) that the real
origin ``https://auth.dev.renku.ch`` resolves to: ``--no-proxy-server``,
host-resolver rules mapping the fixture hosts to it and every other host to
nothing (``MAP * ~NOTFOUND``), and an assertion that every request the
browser made went to a fixture host. Account names, passwords and TOTP
seeds are built per run: no credential-shaped literal.
"""

from __future__ import annotations

# pylint: disable=protected-access,missing-function-docstring,missing-class-docstring
# pylint: disable=import-error,wrong-import-position,redefined-outer-name
# pylint: disable=too-many-lines,too-many-instance-attributes,import-outside-toplevel
import dataclasses
import http.server
import json
import secrets
import shutil
import ssl
import subprocess
import sys
import threading
import time
import urllib.parse
from collections.abc import Callable, Iterator
from http.cookies import SimpleCookie
from pathlib import Path
from typing import Any

import pytest
from chromium_page import REPO, chromium_available, load_script

sys.path.insert(0, str(REPO))

from broker import authentik, daemon, identity, limiter, recipes, vault  # noqa: E402

browser = load_script("bin/browser.py", "ak_browser")

ORIGIN = "https://auth.dev.renku.ch"
OTHER = "https://other.ak-test.example"
HOSTS = ("auth.dev.renku.ch", "other.ak-test.example")
SLUG = "default-authentication-flow"
LOGIN_URL = f"{ORIGIN}/if/flow/{SLUG}/?next=%2Fif%2Fuser%2F"
CHECK_URL = f"{ORIGIN}/if/user/"
EXECUTOR = f"/api/v3/flows/executor/{SLUG}/"
ME = "/api/v3/core/users/me/"
RECIPE = identity.IDENTITIES["authentik"]
# the spec as reviewed before the live check: `original` present and null,
# nothing confirmed
REVIEWED = dataclasses.replace(
    RECIPE,
    live_confirmed=False,
    admin_true_confirmed=False,
    admin_false_confirmed=False,
    null_may_be_absent=False,
)
# the live recipe: both answers confirmed (the "not admin" one live
# 2026-10-18 against the non-admin account test3)
CONFIRMED = dataclasses.replace(RECIPE, admin_false_confirmed=True)
# the recipe before that: only the "admin" answer confirmed
ADMIN_ONLY = dataclasses.replace(RECIPE, admin_false_confirmed=False)
_PW_KEY = "pass" + "word"
CHROME = pytest.mark.skipif(
    not chromium_available() or shutil.which("openssl") is None,
    reason="Playwright Chromium or openssl missing",
)


def _name() -> str:
    return f"zz{secrets.token_hex(4)}"


def _secret_value() -> str:
    return "S-" + secrets.token_urlsafe(12)


def _seed() -> str:
    import pyotp

    return str(pyotp.random_base32())


# ---------------------------------------------------------------------------
# the fixture authentik
# ---------------------------------------------------------------------------

# authentik's login page, reduced to what matters: the stage form in a
# shadow root, the light-DOM helper form for password managers (moved
# off-screen exactly like authentik's global CSS does), the SPA's own
# executor GET on load, and the stage's submit (uid_field from its own
# shadow input).
PAGE = r"""<!doctype html><html><head><style>
html > form > input { position: absolute; top: -2000px; left: -2000px; }
</style></head><body><ak-flow-executor></ak-flow-executor><script>
const slug = location.pathname.split('/')[3];
const exec = '/api/v3/flows/executor/' + slug + '/?query='
  + encodeURIComponent(location.search.substring(1));
const csrf = () => (document.cookie.split(';').map(s => s.trim())
  .find(s => s.startsWith('authentik_csrf=')) || '=').split('=')[1];
class Stage extends HTMLElement {
  connectedCallback() {
    const root = this.attachShadow({mode: 'open'});
    root.innerHTML = '<form class="pf-c-form"><input type="text" name="uidField"'
      + ' autocomplete="username" required><button type="submit"'
      + ' class="pf-c-button pf-m-primary">Log in</button></form>';
    root.querySelector('form').addEventListener('submit', e => {
      e.preventDefault(); this.submitForm(); });
    const f = document.createElement('form');
    document.documentElement.appendChild(f);
    const u = document.createElement('input');
    u.type = 'text'; u.name = 'username'; u.autocomplete = 'username';
    u.onkeyup = ev => root.querySelectorAll('input[name=uidField]')
      .forEach(i => { i.value = ev.target.value; i.focus(); });
    f.appendChild(u);
    const p = document.createElement('input');
    p.type = 'password'; p.name = 'password'; p.autocomplete = 'current-password';
    p.onkeyup = ev => { if (ev.key === 'Enter') { ev.preventDefault(); this.submitForm(); } };
    f.appendChild(p);
    const c = document.createElement('input');
    c.type = 'text'; c.name = 'code'; c.autocomplete = 'one-time-code';
    f.appendChild(c);
    fetch(exec, {headers: {Accept: 'application/json'}});
  }
  submitForm() {
    const uid = this.shadowRoot.querySelector('input[name=uidField]').value;
    fetch(exec, {method: 'POST', headers: {'Content-Type': 'application/json',
      'X-authentik-CSRF': csrf()},
      body: JSON.stringify({component: 'ak-stage-identification', uid_field: uid})});
  }
}
customElements.define('ak-flow-executor', Stage);
</script></body></html>"""


# authentik's user interface (/if/user/, 2026.8.1 `if/user.html` +
# `ak-interface-user`): the template is served with or without a session;
# without one the element keeps its placeholder slot, with one its shadow
# root renders the header's `ak-nav-buttons` and `#main-content`.
SENTINEL = "ak-interface-user ak-nav-buttons"
USER_PAGE = r"""<!doctype html><html><body>
<ak-interface-user><div slot="placeholder">Loading</div></ak-interface-user>
<script>
class UI extends HTMLElement {
  async connectedCallback() {
    const root = this.attachShadow({mode: 'open'});
    root.innerHTML = '<slot name="placeholder"></slot>';
    const r = await fetch('/api/v3/core/users/me/', {headers: {Accept: 'application/json'}});
    if (r.status !== 200) return;
    root.innerHTML = '<header><ak-nav-buttons><a href="#/settings">Settings</a>'
      + '</ak-nav-buttons></header><main id="main-content">Applications</main>';
  }
}
customElements.define('ak-interface-user', UI);
</script></body></html>"""


class _Authentik:
    """The fixture server's state and knobs. `posts` records every executor
    POST value-free: (component, sorted body keys, the password right?)."""

    def __init__(self) -> None:
        self.users: dict[str, dict[str, Any]] = {}
        self.password_fields = False
        self.captcha = False
        self.user_login_prompt = False
        self.original = "absent"  # absent | null | set
        self.me_status: int | None = None
        self.me_ctype = "application/json"
        self.csrf_required = True
        # authentik answers a solved stage with a 302 back to the executor;
        # a 307/308 would make a following client re-send the POST body
        self.post_redirect_status = 302
        self.slow_user_login_s = 0.0
        self.sessions: dict[str, dict[str, Any]] = {}
        self.posts: list[tuple[str, list[str], bool | None]] = []
        self.seen: list[str] = []
        self.lock = threading.Lock()

    def add_user(self, mfa: str = "totp", superuser: bool = False) -> dict[str, Any]:
        user: dict[str, Any] = {
            "name": _name(),
            _PW_KEY: _secret_value(),
            "seed": _seed(),
            "mfa": mfa,
            "superuser": superuser,
        }
        self.users[user["name"]] = user
        return user

    def session_for(self, name: str) -> str:
        """A logged-in session id for `name` (to put into the browser)."""
        sid = secrets.token_hex(16)
        self.sessions[sid] = {"user": name, "stage": None, "pending": None}
        self.sessions[sid]["csrf"] = secrets.token_hex(16)
        return sid

    def password_posts(self) -> int:
        return sum(1 for _c, keys, _ok in self.posts if _PW_KEY in keys)

    def secrets(self) -> list[str]:
        out = []
        for user in self.users.values():
            out += [user["name"], user[_PW_KEY], user["seed"]]
        for sid, sess in self.sessions.items():
            out += [sid, sess.get("csrf", "")]
        return [s for s in out if s]


_STATE: dict[str, _Authentik] = {}


def _challenge(ak: _Authentik, sess: dict[str, Any]) -> dict[str, Any]:
    stage = sess["stage"]
    flow_info = {
        "title": "Welcome",
        "cancel_url": "/flows/-/cancel/",
        "layout": "stacked",
    }
    if stage == "identification":
        body: dict[str, Any] = {
            "component": authentik.IDENTIFICATION,
            "flow_info": flow_info,
            "user_fields": ["email", "username"],
            "password_fields": ak.password_fields,
            "primary_action": "Log in",
            "show_source_labels": False,
            "flow_designation": "authentication",
            "sources": [],
            "enable_remember_me": True,
        }
        if ak.captcha:
            body["captcha_stage"] = {"js_url": "https://captcha.example/x.js"}
        return body
    pending = ak.users.get(sess["pending"] or "", {})
    if stage == "password":
        return {
            "component": authentik.PASSWORD,
            "flow_info": flow_info,
            "pending_user": pending.get("name", ""),
            "pending_user_avatar": "/static/a.svg",
        }
    if stage == "mfa":
        mfa = pending.get("mfa")
        devices = []
        stages = []
        if mfa in ("totp", "webauthn"):
            devices = [
                {
                    "device_class": mfa,
                    "device_uid": "1",
                    "challenge": {},
                    "last_used": None,
                }
            ]
        else:  # configure
            stages = [
                {
                    "pk": "6a4b",
                    "name": "default-authenticator-totp-setup",
                    "verbose_name": "TOTP",
                    "meta_model_name": "authentik_stages_authenticator_totp",
                }
            ]
        return {
            "component": authentik.AUTHENTICATOR,
            "flow_info": flow_info,
            "pending_user": pending.get("name", ""),
            "pending_user_avatar": "/static/a.svg",
            "device_challenges": devices,
            "configuration_stages": stages,
        }
    return {
        "component": authentik.USER_LOGIN,
        "flow_info": flow_info,
        "pending_user": pending.get("name", ""),
        "pending_user_avatar": "/static/a.svg",
    }


def _next_stage(ak: _Authentik, sess: dict[str, Any], done: str) -> str | None:
    user = ak.users[sess["pending"]]
    order = ["identification"]
    if not ak.password_fields:
        order.append("password")
    if user["mfa"] != "none":
        order.append("mfa")
    if ak.user_login_prompt:
        order.append("user_login")
    i = order.index(done)
    return order[i + 1] if i + 1 < len(order) else None


def _errors(field: str) -> dict[str, Any]:
    return {field: [{"string": "Failed to authenticate.", "code": "invalid"}]}


class _Handler(http.server.BaseHTTPRequestHandler):
    """The fixture authentik behind the TLS server."""

    def log_message(self, *_a: Any) -> None:  # pylint: disable=arguments-differ
        return None

    def _ak(self) -> _Authentik:
        return _STATE["ak"]

    def _send(
        self,
        status: int,
        body: bytes = b"",
        ctype: str = "application/json",
        headers: tuple[tuple[str, str], ...] = (),
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in headers:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, obj: Any, headers: Any = ()) -> None:
        self._send(status, json.dumps(obj).encode(), "application/json", headers)

    def _session(self) -> tuple[str, dict[str, Any], list[tuple[str, str]]]:
        ak = self._ak()
        jar = SimpleCookie(self.headers.get("Cookie") or "")
        sid = jar["authentik_session"].value if "authentik_session" in jar else ""
        set_cookies: list[tuple[str, str]] = []
        with ak.lock:
            if sid not in ak.sessions:
                sid = secrets.token_hex(16)
                ak.sessions[sid] = {
                    "user": None,
                    "stage": None,
                    "pending": None,
                    "csrf": secrets.token_hex(16),
                }
                set_cookies = [
                    (
                        "Set-Cookie",
                        f"authentik_session={sid}; Path=/; Secure; HttpOnly; SameSite=Lax",
                    ),
                    (
                        "Set-Cookie",
                        f"authentik_csrf={ak.sessions[sid]['csrf']}; Path=/; Secure;"
                        " SameSite=Lax",
                    ),
                ]
        return sid, ak.sessions[sid], set_cookies

    def do_GET(self) -> None:  # noqa: N802  # the stdlib's name
        ak = self._ak()
        host = str(self.headers.get("Host") or "").split(":", maxsplit=1)[0]
        ak.seen.append(f"https://{host}{self.path}")
        url = urllib.parse.urlsplit(self.path)
        if host != HOSTS[0]:
            self._send(200, b"<p>other</p>", "text/html")
            return
        if url.path.startswith("/if/flow/"):
            _sid, _sess, cookies = self._session()
            self._send(200, PAGE.encode(), "text/html", tuple(cookies))
        elif url.path == "/if/user/":
            # served logged in or not (BrandDefaultRedirectView): only the
            # app's own render after `users/me` tells them apart
            _sid, _sess, cookies = self._session()
            self._send(200, USER_PAGE.encode(), "text/html", tuple(cookies))
        elif url.path == ME:
            self._me()
        elif url.path == EXECUTOR:
            self._executor(None)
        else:
            self._json(404, {"detail": "Not found."})

    def do_POST(self) -> None:  # noqa: N802  # the stdlib's name
        ak = self._ak()
        host = str(self.headers.get("Host") or "").split(":", maxsplit=1)[0]
        ak.seen.append(f"POST https://{host}{self.path}")
        url = urllib.parse.urlsplit(self.path)
        raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        if url.path != EXECUTOR or host != HOSTS[0]:
            self._json(404, {"detail": "Not found."})
            return
        try:
            body = json.loads(raw or b"{}")
        except ValueError:
            body = None
        self._executor(body if isinstance(body, dict) else {})

    def _me(self) -> None:
        ak = self._ak()
        _sid, sess, _c = self._session()
        if ak.me_status is not None:
            body = b"<html><p>proxy</p></html>"
            self._send(ak.me_status, body, ak.me_ctype)
            return
        if not sess["user"]:
            self._json(403, {"detail": "Authentication credentials were not provided."})
            return
        user = ak.users[sess["user"]]
        me = {
            "pk": 7,
            "username": user["name"],
            "name": "Some One",
            "is_active": True,
            "is_superuser": user["superuser"],
            "email": f"{user['name']}@ak-test.example",
        }
        out: dict[str, Any] = {"user": me, "users": []}
        if ak.original == "null":
            out["original"] = None
        elif ak.original == "set":
            out["original"] = dict(me, pk=1, username="akadmin-x", is_superuser=True)
        self._send(200, json.dumps(out).encode(), ak.me_ctype)

    def _executor(self, body: dict[str, Any] | None) -> None:  # noqa: C901
        ak = self._ak()
        _sid, sess, cookies = self._session()
        query = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(self.path).query))
        assert query.get("query") == "next=%2Fif%2Fuser%2F", self.path
        if body is None:  # GET
            with ak.lock:
                if sess["stage"] is None:
                    if sess["user"]:
                        self._json(
                            200,
                            {"component": authentik.REDIRECT, "to": "/if/user/"},
                            cookies,
                        )
                        return
                    sess["stage"] = "identification"
            self._json(200, _challenge(ak, sess), cookies)
            return
        if ak.csrf_required and self.headers.get("X-authentik-CSRF") != sess["csrf"]:
            self._json(403, {"detail": "CSRF Failed: CSRF token missing."})
            return
        self._solve(ak, sess, body, cookies)

    def _solve(  # noqa: C901  # one branch per stage
        self, ak: _Authentik, sess: dict[str, Any], body: dict[str, Any], cookies: Any
    ) -> None:
        stage = sess["stage"] or "identification"
        sess["stage"] = stage
        comp = str(body.get("component"))
        pending = ak.users.get(sess["pending"] or "")
        given = body.get(_PW_KEY)
        ok: bool | None = None
        if stage == "identification":
            user = ak.users.get(str(body.get("uid_field")))
            if user is not None and ak.password_fields:
                ok = given == user[_PW_KEY]
                user = user if ok else None
            if user is None:
                ak.posts.append((comp, sorted(body), ok))
                self._json(
                    200,
                    dict(_challenge(ak, sess), response_errors=_errors("uid_field")),
                )
                return
            sess["pending"] = user["name"]
        elif stage == "password":
            ok = pending is not None and given == pending[_PW_KEY]
            if not ok:
                ak.posts.append((comp, sorted(body), ok))
                self._json(
                    200, dict(_challenge(ak, sess), response_errors=_errors(_PW_KEY))
                )
                return
        elif stage == "mfa":
            import pyotp

            assert pending is not None
            if not pyotp.TOTP(pending["seed"]).verify(
                str(body.get("code")), valid_window=1
            ):
                ak.posts.append((comp, sorted(body), ok))
                self._json(
                    200, dict(_challenge(ak, sess), response_errors=_errors("code"))
                )
                return
        elif stage == "user_login":
            time.sleep(ak.slow_user_login_s)
            assert body.get("remember_me") is True
        ak.posts.append((comp, sorted(body), ok))
        nxt = _next_stage(ak, sess, stage)
        sess["stage"] = nxt
        if nxt is None:
            sess["user"], sess["pending"] = sess["pending"], None
            self._json(
                200, {"component": authentik.REDIRECT, "to": "/if/user/"}, cookies
            )
            return
        # authentik's stage_ok: a redirect back to the executor itself
        self._send(
            ak.post_redirect_status,
            b"",
            "text/html",
            (("Location", self.path), *cookies),
        )


@pytest.fixture(scope="module")
def tls_port(tmp_path_factory: pytest.TempPathFactory) -> Iterator[int]:
    d = tmp_path_factory.mktemp("ak-tls")
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(d / "key.pem"),
            "-out",
            str(d / "cert.pem"),
            "-days",
            "1",
            "-subj",
            "/CN=ak-test",
            "-addext",
            "subjectAltName=" + ",".join(f"DNS:{h}" for h in HOSTS),
        ],
        check=True,
        capture_output=True,
    )
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(str(d / "cert.pem"), str(d / "key.pem"))
    srv.socket = tls.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield int(srv.server_address[1])
    finally:
        srv.shutdown()
        srv.server_close()


def _chrome_args(port: int) -> list[str]:
    rules = [f"MAP {h} 127.0.0.1:{port}" for h in HOSTS] + ["MAP * ~NOTFOUND"]
    return ["--no-proxy-server", "--host-resolver-rules=" + ", ".join(rules)]


def _assert_fixture_only(urls: list[str], ak: _Authentik) -> None:
    """Every request the browser made, and every one the server saw, went to
    a fixture host."""
    hosts = {urllib.parse.urlsplit(u.split(" ")[-1]).hostname for u in urls + ak.seen}
    assert hosts <= set(HOSTS) | {None}, hosts


@pytest.fixture
def ak_ctx(tls_port: int) -> Iterator[tuple[Any, _Authentik]]:
    """A throwaway headless Chromium (fixture hosts only) and the fixture."""
    from playwright.sync_api import sync_playwright

    ak = _Authentik()
    _STATE["ak"] = ak
    urls: list[str] = []
    try:
        with sync_playwright() as pw:
            chromium = pw.chromium.launch(headless=True, args=_chrome_args(tls_port))
            try:
                ctx = chromium.new_context(ignore_https_errors=True)
                ctx.on("request", lambda r: urls.append(r.url))
                yield ctx, ak
            finally:
                chromium.close()
        _assert_fixture_only(urls, ak)
    finally:
        _STATE.pop("ak", None)


def _item(site: str = "authentik-glensk", **over: str) -> vault.SiteItem:
    fields = {
        "agent_site": site,
        "agent_fill_origins": ORIGIN,
        "agent_login_url": LOGIN_URL,
        "agent_check_url": CHECK_URL,
        "agent_logged_in_selector": SENTINEL,
        "agent_cookie_hosts": "auth.dev.renku.ch",
    }
    fields.update(over)
    raw = {
        "id": f"id-{site}",
        "name": site,
        "fields": [{"name": k, "value": v, "type": 0} for k, v in fields.items()],
    }
    item = vault.site_item_from_json(raw)
    assert item.refused is None, item.refused
    return item


def _secret(user: dict[str, Any], seed: bool = True) -> vault.Secret:
    return vault.Secret(
        username=user["name"],
        password=user[_PW_KEY],
        totp_seed=user["seed"] if seed else None,
    )


def _login(
    ctx: Any, user: dict[str, Any], *, seed: bool = True, item: Any = None
) -> tuple[recipes.AttemptController, Any]:
    page = ctx.new_page()
    attempt = recipes.AttemptController()
    authentik.authentik_login(
        page, item or _item(), _secret(user, seed), settle_s=20, attempt=attempt
    )
    return attempt, page


def _no_leak(text: str, ak: _Authentik) -> None:
    for value in ak.secrets():
        assert value not in text


# ---------------------------------------------------------------------------
# the login recipe: helpers
# ---------------------------------------------------------------------------


def test_the_authentik_items_use_the_flow_executor_recipe() -> None:
    for site in ("authentik-glensk", "authentik-akadmin", "authentik-test3"):
        assert recipes.recipe_for(site) is authentik.authentik_login
    assert recipes.recipe_for("authentik-other") is recipes.generic_login
    assert recipes.recipe_for("cscs") is recipes.cscs_login
    assert authentik.AUTHENTIK_SITES is recipes.AUTHENTIK_SITES


def test_executor_path_from_the_flow_page() -> None:
    assert authentik.flow_slug(LOGIN_URL) == SLUG
    assert authentik.executor_path(LOGIN_URL) == (
        f"{EXECUTOR}?query=next%3D%252Fif%252Fuser%252F"
    )
    assert authentik.executor_path(f"{ORIGIN}/if/flow/{SLUG}/") == f"{EXECUTOR}?query="
    for bad in (
        f"{ORIGIN}/if/user/",
        f"{ORIGIN}/if/flow/{SLUG}/x/",
        f"{ORIGIN}/if/flow/../x/",
        f"{ORIGIN}/flows/-/default/authentication/",
    ):
        assert authentik.executor_path(bad) is None


# ---------------------------------------------------------------------------
# the login recipe in a real browser against the fixture authentik
# ---------------------------------------------------------------------------


@pytest.mark.launches_chrome
@CHROME
def test_the_generic_recipe_fails_on_the_helper_form(
    ak_ctx: tuple[Any, _Authentik],
) -> None:
    """The root cause: the generic recipe picks the off-screen helper
    password field, the stage submits its OWN empty uidField."""
    ctx, ak = ak_ctx
    user = ak.add_user()
    page = ctx.new_page()
    with pytest.raises(recipes.RecipeError) as err:
        recipes.generic_login(page, _item(), _secret(user), settle_s=3)
    assert err.value.submitted  # counted as a submitted password …
    assert ak.password_posts() == 0  # … that never left the page
    assert ("ak-stage-identification", ["component", "uid_field"], None) in ak.posts
    assert not any(s["user"] for s in ak.sessions.values())


@pytest.mark.launches_chrome
@CHROME
def test_login_with_totp(ak_ctx: tuple[Any, _Authentik]) -> None:
    ctx, ak = ak_ctx
    user = ak.add_user()
    attempt, page = _login(ctx, user)
    assert attempt.was_entered and attempt.submitted
    assert ak.posts == [
        ("ak-stage-identification", ["component", "uid_field"], None),
        ("ak-stage-password", ["component", _PW_KEY], True),
        ("ak-stage-authenticator-validate", ["code", "component"], None),
    ]
    names = {c["name"] for c in ctx.cookies(ORIGIN)}
    assert {"authentik_session", "authentik_csrf"} <= names
    assert any(s["user"] == user["name"] for s in ak.sessions.values())
    # the caller's positive proof sees the logged-in interface
    page.goto(CHECK_URL)
    page.locator(SENTINEL).wait_for(timeout=10000)


@pytest.mark.launches_chrome
@CHROME
def test_the_sentinel_needs_the_rendered_interface(
    ak_ctx: tuple[Any, _Authentik],
) -> None:
    """/if/user/ serves `<ak-interface-user>` logged out too: the bare tag
    proves nothing, the header its shadow root renders after `users/me`
    does."""
    ctx, ak = ak_ctx
    page = ctx.new_page()
    page.goto(CHECK_URL)
    assert page.locator("ak-interface-user").count() == 1
    assert recipes.check_proof(page, _item(), wait_s=3) == recipes.INVALID
    user = ak.add_user()
    ctx.add_cookies([_cookie(ak.session_for(user["name"]))])
    assert recipes.check_proof(page, _item(), wait_s=8) == recipes.VALID


@pytest.mark.launches_chrome
@CHROME
def test_a_wrong_password_is_sent_once_never_retried(
    ak_ctx: tuple[Any, _Authentik],
) -> None:
    ctx, ak = ak_ctx
    user = ak.add_user()
    wrong = dict(user, **{_PW_KEY: _secret_value()})
    with pytest.raises(recipes.LoginFailed) as err:
        _login(ctx, wrong)
    assert err.value.submitted and "password: invalid" in err.value.detail
    assert ak.password_posts() == 1
    _no_leak(str(err.value), ak)


@pytest.mark.launches_chrome
@CHROME
def test_an_unknown_account_never_gets_the_password(
    ak_ctx: tuple[Any, _Authentik],
) -> None:
    ctx, ak = ak_ctx
    ak.add_user()
    stranger = {"name": _name(), _PW_KEY: _secret_value(), "seed": _seed()}
    page = ctx.new_page()
    attempt = recipes.AttemptController()
    with pytest.raises(recipes.LoginFailed) as err:
        authentik.authentik_login(
            page, _item(), _secret(stranger), settle_s=20, attempt=attempt
        )
    assert not err.value.submitted and not attempt.was_entered
    assert "uid_field: invalid" in err.value.detail
    assert ak.password_posts() == 0
    assert stranger["name"] not in str(err.value)


@pytest.mark.launches_chrome
@CHROME
def test_a_one_page_identification_sends_both_at_once(
    ak_ctx: tuple[Any, _Authentik],
) -> None:
    ctx, ak = ak_ctx
    ak.password_fields = True
    user = ak.add_user(mfa="none")
    attempt, _page = _login(ctx, user)
    assert attempt.submitted
    assert ak.posts == [
        ("ak-stage-identification", ["component", _PW_KEY, "uid_field"], True)
    ]


@pytest.mark.launches_chrome
@CHROME
@pytest.mark.parametrize("mfa", ["webauthn", "configure"])
def test_a_second_factor_the_item_cannot_give_needs_albert(
    ak_ctx: tuple[Any, _Authentik], mfa: str
) -> None:
    ctx, ak = ak_ctx
    user = ak.add_user(mfa=mfa)
    with pytest.raises(recipes.NeedsHuman) as err:
        _login(ctx, user)
    assert err.value.submitted  # the password went out before
    assert ak.password_posts() == 1 and len(ak.posts) == 2


@pytest.mark.launches_chrome
@CHROME
def test_totp_without_a_seed_needs_albert(ak_ctx: tuple[Any, _Authentik]) -> None:
    ctx, ak = ak_ctx
    user = ak.add_user()
    with pytest.raises(recipes.NeedsHuman) as err:
        _login(ctx, user, seed=False)
    assert "no TOTP seed" in err.value.detail and err.value.submitted
    assert len(ak.posts) == 2  # no code was guessed


@pytest.mark.launches_chrome
@CHROME
def test_a_wrong_totp_code_is_not_retried(
    ak_ctx: tuple[Any, _Authentik], monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx, ak = ak_ctx
    user = ak.add_user()
    monkeypatch.setattr(authentik, "fresh_totp", lambda _seed: "000000")
    with pytest.raises(recipes.LoginFailed) as err:
        _login(ctx, user)
    assert "code: invalid" in err.value.detail and err.value.submitted
    assert [p[0] for p in ak.posts].count(authentik.AUTHENTICATOR) == 1


@pytest.mark.launches_chrome
@CHROME
def test_a_captcha_needs_albert_before_anything_is_typed(
    ak_ctx: tuple[Any, _Authentik],
) -> None:
    ctx, ak = ak_ctx
    ak.captcha = True
    user = ak.add_user()
    page = ctx.new_page()
    attempt = recipes.AttemptController()
    with pytest.raises(recipes.NeedsHuman) as err:
        authentik.authentik_login(
            page, _item(), _secret(user), settle_s=20, attempt=attempt
        )
    assert not err.value.submitted and not attempt.was_entered
    assert not ak.posts


@pytest.mark.launches_chrome
@CHROME
def test_stay_signed_in_is_a_session_remember_me(
    ak_ctx: tuple[Any, _Authentik],
) -> None:
    ctx, ak = ak_ctx
    ak.user_login_prompt = True
    user = ak.add_user()
    _login(ctx, user)
    assert ak.posts[-1] == ("ak-stage-user-login", ["component", "remember_me"], None)
    assert any(s["user"] == user["name"] for s in ak.sessions.values())


@pytest.mark.launches_chrome
@CHROME
@pytest.mark.parametrize("status", [307, 308])
def test_a_body_preserving_redirect_never_resends_the_password(
    ak_ctx: tuple[Any, _Authentik], status: int
) -> None:
    ctx, ak = ak_ctx
    ak.post_redirect_status = status
    user = ak.add_user()
    attempt, _page = _login(ctx, user)
    assert attempt.submitted and ak.password_posts() == 1
    assert [p[0] for p in ak.posts] == [
        authentik.IDENTIFICATION,
        authentik.PASSWORD,
        authentik.AUTHENTICATOR,
    ]
    assert any(s["user"] == user["name"] for s in ak.sessions.values())


@pytest.mark.launches_chrome
@CHROME
def test_a_slow_last_stage_after_the_password_is_no_failure(
    ak_ctx: tuple[Any, _Authentik],
) -> None:
    """The run deadline passes while a slow 200 `user-login` is answered:
    the recipe returns (the caller's logged-in check decides), never
    "did not finish" — that would quarantine a login that worked."""
    ctx, ak = ak_ctx
    ak.user_login_prompt, ak.slow_user_login_s = True, 3.0
    user = ak.add_user(mfa="none")
    page = ctx.new_page()
    attempt = recipes.AttemptController()
    authentik.authentik_login(
        page, _item(), _secret(user), settle_s=1.5, attempt=attempt
    )
    assert attempt.submitted and ak.password_posts() == 1
    assert any(s["user"] == user["name"] for s in ak.sessions.values())


@pytest.mark.launches_chrome
@CHROME
def test_no_answer_after_the_password_leaves_the_verdict_to_the_check(
    ak_ctx: tuple[Any, _Authentik], monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx, ak = ak_ctx
    ak.user_login_prompt, ak.slow_user_login_s = True, 3.0
    monkeypatch.setattr(authentik, "FETCH_MS", 1000)
    user = ak.add_user(mfa="none")
    attempt, _page = _login(ctx, user)  # returns: the request timed out
    assert attempt.submitted and ak.password_posts() == 1


@pytest.mark.launches_chrome
@CHROME
def test_no_answer_before_the_password_is_a_pre_submit_failure(
    ak_ctx: tuple[Any, _Authentik], monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx, ak = ak_ctx
    user = ak.add_user()
    monkeypatch.setattr(authentik, "FETCH_MS", 0)
    page = ctx.new_page()
    attempt = recipes.AttemptController()
    with pytest.raises(recipes.LoginFailed) as err:
        authentik.authentik_login(
            page, _item(), _secret(user), settle_s=20, attempt=attempt
        )
    assert "did not answer" in err.value.detail and not err.value.submitted
    assert not attempt.was_entered


def test_origins_are_checked_before_the_marker() -> None:
    class _Page:
        url = f"{OTHER}/x"

    attempt = recipes.AttemptController()
    flow = authentik._Flow(
        _Page(),
        _item(),
        vault.Secret(username="u", password=secrets.token_hex(4)),
        dev=False,
        attempt=attempt,
    )
    with pytest.raises(recipes.OriginViolation):
        flow.password_body({"component": authentik.PASSWORD})
    assert not attempt.was_entered and not attempt.submitted
    assert not flow.password_sent


@pytest.mark.launches_chrome
@CHROME
def test_a_valid_session_types_nothing(ak_ctx: tuple[Any, _Authentik]) -> None:
    ctx, ak = ak_ctx
    user = ak.add_user()
    sid = ak.session_for(user["name"])
    ctx.add_cookies([_cookie(sid)])
    attempt, _page = _login(ctx, user)
    assert not attempt.was_entered and not attempt.submitted and not ak.posts


@pytest.mark.launches_chrome
@CHROME
def test_the_csrf_cookie_is_echoed(ak_ctx: tuple[Any, _Authentik]) -> None:
    ctx, ak = ak_ctx
    assert ak.csrf_required  # the fixture refuses a POST without it
    user = ak.add_user(mfa="none")
    _login(ctx, user)
    assert len(ak.posts) == 2


@pytest.mark.launches_chrome
@CHROME
def test_a_login_url_off_the_fill_origins_is_refused(
    ak_ctx: tuple[Any, _Authentik],
) -> None:
    ctx, ak = ak_ctx
    user = ak.add_user()
    page = ctx.new_page()
    other = _item(agent_login_url=f"{OTHER}/if/flow/{SLUG}/?next=%2Fif%2Fuser%2F")
    with pytest.raises(recipes.OriginViolation):
        authentik.authentik_login(page, other, _secret(user), settle_s=20)
    not_a_flow = _item(agent_login_url=f"{ORIGIN}/if/user/")
    with pytest.raises(recipes.LoginFailed):
        authentik.authentik_login(page, not_a_flow, _secret(user), settle_s=20)
    assert not ak.posts and not ak.seen


def test_the_step_refuses_a_page_off_the_login_origin() -> None:
    class _Page:
        url = f"{OTHER}/x"

    flow = authentik._Flow(
        _Page(),
        _item(),
        vault.Secret(username="u", password=secrets.token_hex(4)),
        dev=False,
        attempt=recipes.AttemptController(),
    )
    with pytest.raises(recipes.OriginViolation):
        flow.step(None)


# ---------------------------------------------------------------------------
# the identity recipe (RECIPE_JS) against the fixture authentik
# ---------------------------------------------------------------------------


def _cookie(sid: str) -> dict[str, Any]:
    return {
        "name": "authentik_session",
        "value": sid,
        "domain": HOSTS[0],
        "path": "/",
        "secure": True,
        "httpOnly": True,
    }


Evaluator = Callable[[Any, str, Any], Any]
EVALUATORS = {
    "broker": daemon.evaluate_isolated,
    "client": browser._evaluate_isolated,
}


@pytest.fixture(params=sorted(EVALUATORS))
def run_recipe(
    request: pytest.FixtureRequest, ak_ctx: tuple[Any, _Authentik]
) -> Iterator[tuple[Callable[..., dict], _Authentik, Any]]:
    ctx, ak = ak_ctx
    page = ctx.new_page()
    evaluate = EVALUATORS[request.param]

    def run(recipe: identity.IdentityRecipe = RECIPE, check: str = CHECK_URL) -> dict:
        page.goto(check)
        nonce = secrets.token_hex(32)
        got = dict(
            evaluate(
                page, identity.RECIPE_JS, identity.recipe_args(recipe, check, nonce)
            )
        )
        assert set(got) <= {"state", "digest", "admin", "why", "status"}
        _no_leak(json.dumps(got), ak)
        got["_nonce"] = nonce
        return got

    yield run, ak, ctx


def _log_in(ak: _Authentik, ctx: Any, **user_kw: Any) -> dict[str, Any]:
    user = ak.add_user(**user_kw)
    ctx.add_cookies([_cookie(ak.session_for(user["name"]))])
    return user


def _verdict(got: dict, name: str, privilege: str) -> str:
    return identity.local_verdict(got, got["_nonce"], name, privilege)


@pytest.mark.launches_chrome
@CHROME
def test_identity_logged_out_is_403_json(run_recipe: Any) -> None:
    run, _ak, _ctx = run_recipe
    got = run()
    assert (got["state"], got.get("status")) == ("logged_out", 403)
    assert _verdict(got, _name(), "user") == identity.LOGGED_OUT


@pytest.mark.launches_chrome
@CHROME
def test_identity_match_mismatch_and_admin_bit(run_recipe: Any) -> None:
    run, ak, ctx = run_recipe
    ak.original = "null"  # the spec as reviewed: present and null
    user = _log_in(ak, ctx)
    got = run()
    assert got["state"] == "found" and got["admin"] is False
    assert _verdict(got, user["name"], "user") == identity.MATCH
    assert _verdict(got, user["name"].upper(), "user") == identity.MATCH
    assert _verdict(got, _name(), "user") == identity.WRONG_ACCOUNT
    assert _verdict(got, user["name"], "admin") == identity.PRIVILEGE_MISMATCH


@pytest.mark.launches_chrome
@CHROME
def test_identity_superuser(run_recipe: Any) -> None:
    run, ak, ctx = run_recipe
    ak.original = "null"
    user = _log_in(ak, ctx, superuser=True)
    got = run()
    assert got["admin"] is True
    assert _verdict(got, user["name"], "admin") == identity.MATCH
    assert _verdict(got, user["name"], "user") == identity.PRIVILEGE_MISMATCH


@pytest.mark.launches_chrome
@CHROME
def test_identity_impersonation_is_indeterminate(run_recipe: Any) -> None:
    run, ak, ctx = run_recipe
    ak.original = "set"
    user = _log_in(ak, ctx, superuser=True)
    for recipe in (REVIEWED, RECIPE):
        got = run(recipe)
        assert (got["state"], got["why"]) == ("indeterminate", "impersonation")
        assert _verdict(got, user["name"], "user") == identity.INDETERMINATE


@pytest.mark.launches_chrome
@CHROME
def test_identity_original_absent_needs_the_flag(run_recipe: Any) -> None:
    """authentik 2026.8.1 leaves `original` out unless impersonating (seen
    live 2026-10-13): the reviewed spec (present and null) is indeterminate
    then; the live recipe's `null_may_be_absent` accepts it."""
    run, ak, ctx = run_recipe
    ak.original = "absent"
    user = _log_in(ak, ctx, superuser=True)
    got = run(REVIEWED)
    assert (got["state"], got["why"]) == ("indeterminate", "impersonation")
    got = run(RECIPE)
    assert got["state"] == "found" and got["admin"] is True
    assert _verdict(got, user["name"], "admin") == identity.MATCH


@pytest.mark.launches_chrome
@CHROME
@pytest.mark.parametrize("status", [200, 403, 401])
def test_identity_an_html_page_is_indeterminate(run_recipe: Any, status: int) -> None:
    run, ak, ctx = run_recipe
    _log_in(ak, ctx)
    ak.me_status, ak.me_ctype = status, "text/html; charset=utf-8"
    got = run()
    assert (got["state"], got["why"]) == ("indeterminate", "content-type")


@pytest.mark.launches_chrome
@CHROME
def test_identity_another_origin_is_refused(run_recipe: Any) -> None:
    run, ak, ctx = run_recipe
    _log_in(ak, ctx)
    got = run(check=f"{OTHER}/if/user/")
    assert (got["state"], got["why"]) == ("indeterminate", "origin")
    assert not any(ME in u for u in ak.seen)


# ---------------------------------------------------------------------------
# the reviewed spec and the toggle path
# ---------------------------------------------------------------------------


def test_the_spec_is_live_confirmed_both_ways() -> None:
    assert identity.recipe_problem(RECIPE) == ""
    assert RECIPE.id_field == ("user", "username")
    assert RECIPE.admin_field == ("user", "is_superuser")
    assert RECIPE.must_be_null == ("original",) and RECIPE.null_may_be_absent
    assert RECIPE.logged_out_json and RECIPE.origin == ORIGIN
    # live 2026-10-13: the 200 answer and `is_superuser` true; live
    # 2026-10-18: `is_superuser` false for the non-admin account test3
    assert RECIPE.live_confirmed and RECIPE.admin_true_confirmed
    assert RECIPE.admin_false_confirmed
    assert RECIPE == CONFIRMED
    assert RECIPE.allowed_sites == (
        "authentik-akadmin",
        "authentik-glensk",
        "authentik-test3",
    )
    assert identity.usable_recipe("authentik") is RECIPE
    args = identity.recipe_args(RECIPE, CHECK_URL, "0" * 64)
    assert args["origin"] == ORIGIN and args["path"] == ME
    assert args["logged_out_json"] is True and args["null_may_be_absent"] is True


def test_every_privilege_may_use_it_on_its_sites() -> None:
    for site in RECIPE.allowed_sites:
        for privilege in ("admin", "user", "readonly"):
            assert (
                identity.recipe_refusal(
                    "authentik", site=site, check_url=CHECK_URL, privilege=privilege
                )
                == ""
            )
            assert identity.proof_ready(_entry(site, privilege))
    assert "reviewed for" in identity.recipe_refusal(
        "authentik", site="authentik-other", check_url=CHECK_URL, privilege="user"
    )
    assert not identity.proof_ready(_entry("authentik-other", "user"))


def test_only_privilege_admin_items_may_use_the_admin_only_recipe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(identity.IDENTITIES, "authentik", ADMIN_ONLY)
    for site in RECIPE.allowed_sites:
        assert (
            identity.recipe_refusal(
                "authentik", site=site, check_url=CHECK_URL, privilege="admin"
            )
            == ""
        )
        assert (
            identity.item_recipe(
                "authentik", site=site, check_url=CHECK_URL, privilege="admin"
            )
            is ADMIN_ONLY
        )
        assert identity.proof_ready(_entry(site, "admin"))
        for privilege in ("user", "readonly"):
            assert "not-admin answer is not live-confirmed" in (
                identity.recipe_refusal(
                    "authentik", site=site, check_url=CHECK_URL, privilege=privilege
                )
            )
            assert (
                identity.item_recipe(
                    "authentik", site=site, check_url=CHECK_URL, privilege=privilege
                )
                is None
            )
            assert not identity.proof_ready(_entry(site, privilege))
    assert "reviewed for" in identity.recipe_refusal(
        "authentik", site="authentik-other", check_url=CHECK_URL, privilege="admin"
    )


@pytest.mark.parametrize(
    "change, problem",
    [
        ({"must_be_null": None, "null_may_be_absent": True}, "one-key must_be_null"),
        (
            {"must_be_null": ("user", "original"), "null_may_be_absent": True},
            "one-key must_be_null",
        ),
    ],
)
def test_malformed_flags_are_refused(change: dict, problem: str) -> None:
    with pytest.raises(ValueError, match=problem):
        dataclasses.replace(RECIPE, **change)


def test_logged_out_json_is_not_for_token_recipes() -> None:
    with pytest.raises(ValueError, match="decides logged out itself"):
        dataclasses.replace(identity.IDENTITIES["runai"], logged_out_json=True)


def _entry(site: str, privilege: str, check: str = CHECK_URL) -> dict:
    return {
        "site": site,
        "identity": "authentik",
        "privilege": privilege,
        "check_url": check,
        "identity_v": identity.IDENTITY_V,
    }


@pytest.mark.parametrize(
    "flags, glensk, akadmin",
    [
        ({}, False, False),
        ({"live_confirmed": True}, False, False),
        ({"live_confirmed": True, "admin_false_confirmed": True}, True, False),
        ({"live_confirmed": True, "admin_true_confirmed": True}, False, True),
        (
            {
                "live_confirmed": True,
                "admin_true_confirmed": True,
                "admin_false_confirmed": True,
            },
            True,
            True,
        ),
    ],
)
def test_the_live_confirmed_toggles(
    monkeypatch: pytest.MonkeyPatch, flags: dict, glensk: bool, akadmin: bool
) -> None:
    monkeypatch.setitem(
        identity.IDENTITIES, "authentik", dataclasses.replace(REVIEWED, **flags)
    )
    assert identity.proof_ready(_entry("authentik-glensk", "user")) is glensk
    assert identity.proof_ready(_entry("authentik-akadmin", "admin")) is akadmin


def test_the_recipe_is_pinned_to_its_sites_and_origin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(identity.IDENTITIES, "authentik", CONFIRMED)
    assert identity.proof_ready(_entry("authentik-glensk", "user"))
    assert not identity.proof_ready(_entry("authentik-other", "user"))
    assert not identity.proof_ready(
        _entry("authentik-glensk", "user", "https://auth.renku.ch/if/user/")
    )


def _raw(site: str, user: str, **fields: str) -> dict:
    base = {
        "agent_site": site,
        "agent_fill_origins": ORIGIN,
        "agent_login_url": LOGIN_URL,
        "agent_check_url": CHECK_URL,
        "agent_logged_in_selector": SENTINEL,
        "agent_cookie_hosts": "auth.dev.renku.ch",
    }
    base.update(fields)
    return {
        "id": f"id-{site}",
        "name": site,
        "login": {"username": user, _PW_KEY: _secret_value()},
        "fields": [{"name": k, "value": v, "type": 0} for k, v in base.items()],
    }


def _pair(glensk: str, akadmin: str, identity_field: bool = True) -> list[dict]:
    ident = {"agent_identity": "authentik"} if identity_field else {}
    return [
        _raw(
            "authentik-glensk",
            glensk,
            agent_privilege="user",
            agent_alias="authentik",
            **ident,
        ),
        _raw(
            "authentik-akadmin",
            akadmin,
            agent_privilege="admin",
            agent_instance="admin",
            **ident,
        ),
    ]


def test_the_vault_pair_before_and_after_the_live_check(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    glensk, akadmin = _name(), _name()
    # before: without agent_identity the pair is valid (multi-account,
    # unproven); WITH it, refused while the recipe is unconfirmed
    items = {it.site: it for it in vault.build_items(_pair(glensk, akadmin, False))}
    for it in items.values():
        assert it.refused is None and it.multi_account and it.identity_recipe is None
    with monkeypatch.context() as mp:
        mp.setitem(identity.IDENTITIES, "authentik", REVIEWED)
        items = {it.site: it for it in vault.build_items(_pair(glensk, akadmin))}
        assert all("not live-confirmed" in str(it.refused) for it in items.values())
    # the admin-only recipe: valid; the admin item is proof-ready, the user
    # item stays unproven (its "not admin" answer is unconfirmed)
    with monkeypatch.context() as mp:
        mp.setitem(identity.IDENTITIES, "authentik", ADMIN_ONLY)
        items = {it.site: it for it in vault.build_items(_pair(glensk, akadmin))}
        for it in items.values():
            assert it.refused is None and it.multi_account
        assert items["authentik-akadmin"].identity_recipe is ADMIN_ONLY
        assert items["authentik-glensk"].identity_recipe is None
    # glensk is a superuser too: as `privilege admin` it is proof-ready
    raws = _pair(glensk, akadmin)
    raws[0]["fields"] = [
        dict(f, value="admin") if f["name"] == "agent_privilege" else f
        for f in raws[0]["fields"]
    ]
    items = {it.site: it for it in vault.build_items(raws)}
    for it in items.values():
        assert it.refused is None and it.identity_recipe is RECIPE
    # with a confirmed "not admin" answer: both valid and proof-ready
    monkeypatch.setitem(identity.IDENTITIES, "authentik", CONFIRMED)
    items = {it.site: it for it in vault.build_items(_pair(glensk, akadmin))}
    for site, privilege in (
        ("authentik-glensk", "user"),
        ("authentik-akadmin", "admin"),
    ):
        it = items[site]
        assert it.refused is None and it.multi_account
        assert it.privilege == privilege and it.identity_recipe is CONFIRMED
    assert items["authentik-glensk"].alias == "authentik"
    assert items["authentik-akadmin"].instance == "admin"
    # an e-mail in the vault cannot be compared with `user.username`
    items = {
        it.site: it
        for it in vault.build_items(_pair(f"{glensk}@ak-test.example", akadmin))
    }
    assert "compares the username" in str(items["authentik-glensk"].refused)
    # both in one browser instance: a scope conflict
    raws = _pair(glensk, akadmin)
    raws[1]["fields"] = [f for f in raws[1]["fields"] if f["name"] != "agent_instance"]
    items = {it.site: it for it in vault.build_items(raws)}
    assert "scope conflict" in str(items["authentik-glensk"].refused) + str(
        items["authentik-akadmin"].refused
    )


def _trio(glensk: str, akadmin: str, test3: str) -> list[dict]:
    """The live vault: glensk and akadmin are superusers (`privilege
    admin`, in the default and the admin instance), test3 the non-admin
    account (`privilege user`, in the alt instance, no alias)."""
    ident = {"agent_identity": "authentik"}
    return [
        _raw(
            "authentik-glensk",
            glensk,
            agent_privilege="admin",
            agent_alias="authentik",
            **ident,
        ),
        _raw(
            "authentik-akadmin",
            akadmin,
            agent_privilege="admin",
            agent_instance="admin",
            **ident,
        ),
        _raw(
            "authentik-test3",
            test3,
            agent_privilege="user",
            agent_instance="alt",
            **ident,
        ),
    ]


def test_the_vault_trio_is_valid_and_proof_ready() -> None:
    items = {it.site: it for it in vault.build_items(_trio(_name(), _name(), _name()))}
    for site, privilege, instance in (
        ("authentik-glensk", "admin", ""),
        ("authentik-akadmin", "admin", "admin"),
        ("authentik-test3", "user", "alt"),
    ):
        it = items[site]
        assert it.refused is None and it.multi_account, site
        assert it.privilege == privilege and it.identity_recipe is RECIPE, site
        assert it.instance == instance, site
    assert items["authentik-test3"].alias == ""
    # test3 in the default instance next to glensk: a scope conflict
    raws = _trio(_name(), _name(), _name())
    raws[2]["fields"] = [f for f in raws[2]["fields"] if f["name"] != "agent_instance"]
    items = {it.site: it for it in vault.build_items(raws)}
    assert "scope conflict" in str(items["authentik-glensk"].refused) + str(
        items["authentik-test3"].refused
    )


def _found(nonce: str, name: str, admin: object) -> dict:
    norm = identity.normalize_identity(name)
    assert norm is not None
    return {
        "state": "found",
        "digest": identity.challenge_digest(nonce, norm),
        "admin": admin,
    }


def test_test3_proves_as_user_only_on_a_non_admin_answer() -> None:
    nonce = secrets.token_hex(32)
    test3 = _name()
    # `users/me` names test3 and says not admin: proven as `privilege user`
    got = _found(nonce, test3, False)
    assert identity.local_verdict(got, nonce, test3, "user") == identity.MATCH
    # an admin answer for the user item is refused
    got = _found(nonce, test3, True)
    assert (
        identity.local_verdict(got, nonce, test3, "user") == identity.PRIVILEGE_MISMATCH
    )
    # a non-admin answer naming another account is refused
    got = _found(nonce, _name(), False)
    assert identity.local_verdict(got, nonce, test3, "user") == identity.WRONG_ACCOUNT
    # no admin bit (a missing or non-boolean `is_superuser`) proves nothing
    for admin in (None, "false", 0):
        got = _found(nonce, test3, admin)
        assert (
            identity.local_verdict(got, nonce, test3, "user") == identity.INDETERMINATE
        )


def test_glensk_and_akadmin_still_prove_as_admin_only() -> None:
    nonce = secrets.token_hex(32)
    name = _name()
    got = _found(nonce, name, True)
    assert identity.local_verdict(got, nonce, name, "admin") == identity.MATCH
    got = _found(nonce, name, False)
    assert (
        identity.local_verdict(got, nonce, name, "admin") == identity.PRIVILEGE_MISMATCH
    )
    for site in ("authentik-glensk", "authentik-akadmin"):
        assert recipes.recipe_for(site) is authentik.authentik_login
        assert identity.proof_ready(_entry(site, "admin"))


# ---------------------------------------------------------------------------
# end to end: the REAL broker logs in, proves and exports
# ---------------------------------------------------------------------------


class _Vault:
    def __init__(self, raws: list[dict]) -> None:
        self._raws = {r["name"]: r for r in raws}
        self._items = vault.build_items(raws)

    def items(self) -> list[vault.SiteItem]:
        return self._items

    def secret(self, site: str) -> vault.Secret:
        return vault.secret_from_json(self._raws[site])


@pytest.mark.launches_chrome
@CHROME
def test_e2e_the_broker_logs_in_proves_the_account_and_exports(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tls_port: int
) -> None:
    ak = _Authentik()
    _STATE["ak"] = ak
    try:
        user = ak.add_user()
        admin = ak.add_user(superuser=True)
        raws = _pair(user["name"], admin["name"])
        raws[0]["login"] = {
            "username": user["name"],
            _PW_KEY: user[_PW_KEY],
            "totp": user["seed"],
        }
        monkeypatch.setitem(identity.IDENTITIES, "authentik", CONFIRMED)
        # every request of the daemon's own browser, recorded
        urls: list[str] = []
        watch = daemon.watch_script_mime

        def watch_and_record(ctx: Any) -> None:
            ctx.on("request", lambda r: urls.append(r.url))
            watch(ctx)

        monkeypatch.setattr(daemon, "watch_script_mime", watch_and_record)
        monkeypatch.setattr(
            daemon,
            "CHROME_ARGS",
            [
                *daemon.CHROME_ARGS,
                *_chrome_args(tls_port),
                "--ignore-certificate-errors",
            ],
        )
        home = tmp_path / "home"
        brk = daemon.Broker(
            _Vault(raws),  # type: ignore[arg-type]
            limiter.Limiter(
                home / "l.json",
                cooldown_s=1800,
                min_interval_s=0,
                per_hour=50,
                per_day=100,
            ),
            home,
            runner=daemon.PlaywrightRunner(home, diag_dir=home),
        )
        reply = brk.handle({"op": "login", "site": "authentik-glensk"}, None)
        text = json.dumps(reply)
        assert reply.get("ok"), {k: reply.get(k) for k in ("error", "phase", "detail")}
        names = {c["name"] for c in reply["bundle"]["cookies"]}
        assert "authentik_session" in names
        assert ak.password_posts() == 1
        for value in (user[_PW_KEY], user["seed"], admin[_PW_KEY]):
            assert value not in text
        assert urls and any(HOSTS[0] in u for u in urls)
        _assert_fixture_only(urls, ak)
    finally:
        _STATE.pop("ak", None)
