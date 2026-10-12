"""WS5 S4c: the reviewed `keycloak-admin` identity recipe (oidc-silent-pkce).

The Keycloak admin console (custos-admin, realm master) keeps its tokens in
page memory. The recipe obtains its own in a CDP isolated world: a silent
OIDC authorization-code request with PKCE (``prompt=none``, the console's
public client, its own random state and verifier), the code exchange, the
ID token's claims (``preferred_username``; ``azp``, ``aud``, the exact
issuer and ``exp`` pinned) and the admin bit from ``GET /admin/realms`` with
the access token as bearer. Only the "admin" answer is live-confirmed
(2026-10-12): a ``privilege user`` item stays unproven.

The recipe runs in a throwaway headless Chromium against a routed fixture
Keycloak (no network), through BOTH isolated-world evaluators, and end to
end through the REAL broker behind its socket. Account names, codes and
tokens are built per run: no credential-shaped literal.

Playwright does not route the request that FOLLOWS a fulfilled redirect (it
goes to the network): Chromium maps the fixture hosts to a local TLS server
(throwaway self-signed certificate) that answers those, and every other host
to nothing (``MAP * ~NOTFOUND``) — no test request ever leaves the machine.
"""

from __future__ import annotations

# pylint: disable=protected-access,missing-function-docstring,missing-class-docstring
# pylint: disable=import-error,wrong-import-position,redefined-outer-name
# pylint: disable=too-many-lines,too-many-instance-attributes
import base64
import contextlib
import dataclasses
import hashlib
import http.server
import json
import os
import secrets
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from chromium_page import REPO, chromium_available, load_script

sys.path.insert(0, str(REPO))

from broker import daemon, identity, limiter, vault  # noqa: E402

browser = load_script("bin/browser.py", "ws5kc_browser")

RECIPE = identity.IDENTITIES["keycloak-admin"]
# the recipe once a non-admin's 403 is seen live
CONFIRMED_FALSE = dataclasses.replace(RECIPE, admin_false_confirmed=True)
ORIGIN = "https://custos.datascience.ch"
CHECK = f"{ORIGIN}/admin/master/console/"
OTHER = "https://other.ws5kc.example"
RA_ORIGIN = "https://sdsc.run.ai"
ISS = f"{ORIGIN}/realms/master"
AUTH_PATH = "/realms/master/protocol/openid-connect/auth"
TOKEN_PATH = "/realms/master/protocol/openid-connect/token"
REDIRECT_PATH = "/admin/master/console/"
PROBE_PATH = "/admin/realms/master/users/count"
CLIENT = "security-admin-console"
_LOGIN_KEY = "pass" + "word"
_DROP = object()
CHROME = pytest.mark.skipif(
    not chromium_available() or shutil.which("openssl") is None,
    reason="Playwright Chromium or openssl missing",
)


def _user() -> str:
    """A fresh e-mail-shaped account name (never a literal in this file)."""
    return f"zz-{secrets.token_hex(5)}@ws5kc.example"


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _jwt(claims: Any) -> str:
    """A JWT-shaped string built at run time (random signature: the recipe
    never checks it — the token comes straight from the server)."""
    head = _b64url(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
    body = _b64url(json.dumps(claims).encode())
    return f"{head}.{body}.{_b64url(secrets.token_bytes(64))}"


def _id_claims(name: str, **over: Any) -> dict:
    now = int(time.time())
    claims = {
        "exp": now + 300,
        "iat": now,
        "iss": ISS,
        "aud": CLIENT,
        "sub": secrets.token_hex(8),
        "typ": "ID",
        "azp": CLIENT,
        "sid": secrets.token_hex(8),
        "preferred_username": name,
        "email": name,
    }
    claims.update(over)
    return {k: v for k, v in claims.items() if v is not _DROP}


def _access_claims() -> dict:
    """The lightweight access token: no account name at all."""
    now = int(time.time())
    return {
        "exp": now + 300,
        "iat": now,
        "jti": secrets.token_hex(8),
        "iss": ISS,
        "typ": "Bearer",
        "azp": CLIENT,
        "sid": secrets.token_hex(8),
        "scope": "openid email profile",
    }


@pytest.fixture
def confirmed_false(monkeypatch: pytest.MonkeyPatch) -> None:
    """`IDENTITIES["keycloak-admin"]` with its 403 side confirmed."""
    monkeypatch.setitem(identity.IDENTITIES, "keycloak-admin", CONFIRMED_FALSE)


# ---------------------------------------------------------------------------
# the reviewed spec
# ---------------------------------------------------------------------------


def test_the_keycloak_recipe_is_reviewed() -> None:
    assert identity.usable_recipe("keycloak-admin") is RECIPE
    assert RECIPE.auth == "oidc-silent-pkce" and RECIPE.forms == ("email",)
    assert RECIPE.live_confirmed and RECIPE.admin_true_confirmed
    assert not RECIPE.admin_false_confirmed
    assert RECIPE.allowed_sites == ("custos-admin",) and RECIPE.origin == ORIGIN
    assert RECIPE.admin_field is None and not RECIPE.identity_storage_keys
    assert not RECIPE.token_body and not RECIPE.admin_probe_error_shape
    args = identity.recipe_args(RECIPE, CHECK, "0" * 64)
    assert args["origin"] == ORIGIN and args["path"] == TOKEN_PATH
    assert args["auth"] == "oidc-silent-pkce"
    assert args["client_id"] == CLIENT and args["audience"] == CLIENT
    assert args["auth_path"] == AUTH_PATH
    assert args["redirect_path"] == REDIRECT_PATH
    assert args["token_field"] == ["id_token"]
    assert args["bearer_field"] == ["access_token"]
    assert args["claim_pins"] == [["azp", CLIENT], ["typ", "ID"]]
    assert args["exp_leeway_s"] == 30 and args["admin_probe_true_integer"]
    assert args["issuer"] == ISS == RECIPE.issuer
    assert args["admin_probe"] == PROBE_PATH
    assert (args["admin_probe_true"], args["admin_probe_false"]) == ([200], [403])
    assert args["id_field"] == ["preferred_username"]
    assert not args["token_body"]
    # the pinned origin wins over a check URL elsewhere (the page check fails)
    assert identity.recipe_args(RECIPE, f"{OTHER}/x", "0" * 64)["origin"] == ORIGIN
    # its issuer and origin are one host: the item's own
    assert identity.recipe_hosts(_entry()) == {"custos.datascience.ch"}
    assert not identity.foreign_storage_keys(_entry())


def test_the_other_recipes_carry_no_oidc_fields() -> None:
    for name in ("gitlab", "audiobookshelf", "navidrome", "runai"):
        recipe = identity.IDENTITIES[name]
        assert recipe.admin_false_confirmed, name
        args = identity.recipe_args(recipe, f"{OTHER}/x", "0" * 64)
        assert not args["client_id"] and not args["auth_path"], name
        assert not args["redirect_path"] and not args["audience"], name
        assert args["bearer_field"] is None, name
        assert args["exp_leeway_s"] == 0, name
        assert args["admin_probe_true_integer"] is False, name


@pytest.mark.parametrize(
    ("change", "problem"),
    [
        ({"client_id": ""}, "plain client_id"),
        ({"client_id": "a b"}, "plain client_id"),
        ({"auth_path": ""}, "auth_path"),
        ({"auth_path": "realms/master/x"}, "auth_path"),
        ({"auth_path": f"{AUTH_PATH}?prompt=login"}, "auth_path takes no query"),
        ({"auth_path": "//evil.example/x"}, "auth_path"),
        ({"redirect_path": ""}, "redirect_path"),
        ({"redirect_path": "/admin/master/console/#x"}, "redirect_path"),
        ({"redirect_path": "/admin/?x=1"}, "redirect_path takes no query"),
        ({"issuer": "https://other.ws5kc.example/realms/master"}, "on its origin"),
        ({"issuer": f"{ISS}?x=1"}, "needs an issuer"),
        ({"issuer": "http://custos.datascience.ch/realms/master"}, "needs an issuer"),
        (
            {"auth_path": "/realms/sdsc/protocol/openid-connect/auth"},
            "under the issuer's path",
        ),
        (
            {"path": "/realms/master-x/protocol/openid-connect/token"},
            "under the issuer's path",
        ),
        ({"audience": ""}, "audience pin"),
        ({"audience": "a b"}, "audience pin"),
        ({"bearer_field": None}, "bearer_field"),
        ({"bearer_field": ("access token",)}, "bad field path"),
        ({"token_field": None}, "token_field"),
        ({"token_body": (("grant_type", "x"),)}, "takes no token_body"),
        ({"admin_field": ("isAdmin",)}, "admin bit from admin_probe"),
        ({"admin_probe": ""}, "admin_probe"),
        ({"admin_probe_true": (403,)}, "disjoint"),
        ({"allowed_sites": ()}, "allowed_sites and an origin"),
        ({"origin": ""}, "allowed_sites and an origin"),
        ({"path": f"{TOKEN_PATH}?x=1"}, "one fixed path"),
        ({"base_segments": ("x",)}, "one fixed path"),
        ({"exp_leeway_s": 61}, "exp_leeway_s"),
        ({"exp_leeway_s": -1}, "exp_leeway_s"),
        ({"exp_leeway_s": True}, "exp_leeway_s"),
        ({"exp_leeway_s": 1.5}, "exp_leeway_s"),
        ({"admin_probe_true_integer": 1}, "admin_probe_true_integer"),
    ],
)
def test_a_malformed_oidc_spec_is_refused(change: dict, problem: str) -> None:
    with pytest.raises(ValueError, match="identity recipe") as err:
        dataclasses.replace(RECIPE, **change)
    assert problem in str(err.value)


def test_oidc_fields_need_the_oidc_auth() -> None:
    gl = identity.IDENTITIES["gitlab"]
    runai = identity.IDENTITIES["runai"]
    for change in (
        {"client_id": CLIENT},
        {"auth_path": AUTH_PATH},
        {"redirect_path": REDIRECT_PATH},
        {"audience": CLIENT},
        {"bearer_field": ("access_token",)},
    ):
        for base in (gl, runai):
            with pytest.raises(ValueError, match="oidc fields need auth"):
                dataclasses.replace(base, **change)
    for change in (
        {"issuer": ISS},
        {"exp_leeway_s": 30},
        {"admin_probe_true_integer": True},
    ):
        with pytest.raises(ValueError, match="token fields need auth token-endpoint"):
            dataclasses.replace(gl, **change)


# ---------------------------------------------------------------------------
# who may use it: the site, the origin, and only the confirmed admin side
# ---------------------------------------------------------------------------


def _entry(site: str = "custos-admin", privilege: str = "admin", **over: Any) -> dict:
    entry = {
        "site": site,
        "identity": "keycloak-admin",
        "privilege": privilege,
        "check_url": CHECK,
        "identity_v": 1,
        "refused": False,
    }
    entry.update(over)
    return entry


def test_only_the_admin_item_may_use_it() -> None:
    assert (
        identity.recipe_refusal(
            "keycloak-admin", site="custos-admin", check_url=CHECK, privilege="admin"
        )
        == ""
    )
    assert identity.proof_ready(_entry())
    assert identity.entry_recipe(_entry()) is RECIPE
    # the 403 side is unconfirmed: user / readonly items stay unproven
    for privilege in ("user", "readonly"):
        assert not identity.proof_ready(_entry(privilege=privilege)), privilege
        assert identity.entry_recipe(_entry(privilege=privilege)) is None
        assert "not-admin answer is not live-confirmed" in identity.recipe_refusal(
            "keycloak-admin", site="custos-admin", check_url=CHECK, privilege=privilege
        )
    refusals = {
        "site": _entry("custos-x"),
        "runai site": _entry("runai-admin"),
        "origin": _entry(check_url=f"{OTHER}/admin/master/console/"),
        "port": _entry(check_url=f"{ORIGIN}:8443/admin/master/console/"),
        "http": _entry(check_url="http://custos.datascience.ch/admin/"),
    }
    for why, entry in refusals.items():
        assert not identity.proof_ready(entry), why
        assert identity.entry_recipe(entry) is None, why


@pytest.mark.usefixtures("confirmed_false")
def test_a_confirmed_403_side_admits_the_user_item() -> None:
    assert identity.proof_ready(_entry(privilege="user"))
    assert identity.entry_recipe(_entry(privilege="readonly")) is CONFIRMED_FALSE
    assert identity.proof_ready(_entry())


def _custos_raw(user: str | None = None, **fields: str) -> dict:
    base = {
        "agent_site": "custos-admin",
        "agent_fill_origins": ORIGIN,
        "agent_check_url": CHECK,
        "agent_logged_in_selector": "#me",
        "agent_cookie_scopes": json.dumps(
            [{"host": "custos.datascience.ch", "path": "/realms/master/"}]
        ),
        "agent_identity": "keycloak-admin",
        "agent_privilege": "admin",
        "agent_instance": "alt",
    }
    base.update({f"agent_{k}": v for k, v in fields.items()})
    return _item_raw("custos-admin", user, base)


def _runai_raw(site: str, user: str, **fields: str) -> dict:
    base = {
        "agent_site": site,
        "agent_fill_origins": ORIGIN,
        "agent_check_url": f"{RA_ORIGIN}/workloads",
        "agent_logged_in_selector": "#me",
        "agent_cookie_scopes": json.dumps(
            [
                {"host": "sdsc.run.ai", "path": "/"},
                {"host": "custos.datascience.ch", "path": "/realms/sdsc/"},
                {"host": "app1.run.ai", "path": "/auth/realms/sdsc/"},
            ]
        ),
        "agent_identity": "runai",
        "agent_privilege": "user",
    }
    base.update({f"agent_{k}": v for k, v in fields.items()})
    return _item_raw(site, user, base)


def _item_raw(site: str, user: str | None, fields: dict) -> dict:
    return {
        "id": f"id-{site}",
        "name": site,
        "login": {
            "username": user if user is not None else _user(),
            _LOGIN_KEY: secrets.token_urlsafe(18),
        },
        "fields": [{"name": k, "value": v} for k, v in fields.items() if v is not None],
    }


def _trio(custos: str, test3: str, admin: str, **custos_fields: str) -> list[dict]:
    return [
        _custos_raw(custos, **custos_fields),
        _runai_raw("runai-test3", test3),
        _runai_raw("runai-admin", admin, privilege="admin", instance="admin"),
    ]


def _items(raws: list[dict]) -> dict[str, vault.SiteItem]:
    return {it.site: it for it in vault.build_items(raws)}


def test_the_vault_admits_custos_admin_next_to_runai() -> None:
    items = _items(_trio(_user(), _user(), _user()))
    custos = items["custos-admin"]
    assert not custos.refused, custos.refused
    assert custos.multi_account and custos.identity_recipe is RECIPE
    assert identity.proof_ready(custos.public())
    for site in ("runai-test3", "runai-admin"):
        assert not items[site].refused, items[site].refused
        assert items[site].multi_account


def test_the_vault_keeps_a_user_item_unproven() -> None:
    custos = _items(_trio(_user(), _user(), _user(), privilege="user"))["custos-admin"]
    assert not custos.refused, custos.refused
    assert custos.multi_account and custos.identity_recipe is None
    assert not identity.proof_ready(custos.public())


@pytest.mark.parametrize(
    ("user", "fields", "problem"),
    [
        ("plainname", {}, "the vault holds an username"),
        (None, {"check_url": f"{OTHER}/admin/"}, "runs on https://custos"),
        (None, {"site": "custos-x"}, "reviewed for custos-admin only"),
    ],
)
def test_the_vault_refuses_what_the_recipe_does_not_cover(
    user: str | None, fields: dict, problem: str
) -> None:
    raw = _custos_raw(user, **fields)
    it = vault.build_items([raw])[0]
    assert it.refused and problem in it.refused


# ---------------------------------------------------------------------------
# RECIPE_JS against a routed fixture Keycloak, both evaluators
# ---------------------------------------------------------------------------


def _s256(verifier: str) -> str:
    return _b64url(hashlib.sha256(verifier.encode("ascii")).digest())


class _Keycloak:
    """The fixture realm: the authorization endpoint (an SSO session for
    `name`, or none → login_required), the token endpoint (checks the code,
    the client, the redirect URI and the PKCE verifier) and the admin probe.
    Knobs override each answer; `seen` records every request URL."""

    def __init__(self) -> None:
        self.name: str | None = None
        self.id_over: dict = {}
        self.auth_redirect: Callable[[dict], str] | None = None
        self.auth_status = 302
        self.iss_param: Any = ISS
        self.token_status: int | None = None
        self.token_ctype = "application/json"
        self.token_body: Any = None
        self.probe_status = 200
        self.probe_ctype = "application/json;charset=UTF-8"
        self.probe_body: str | None = None
        self.codes: dict[str, dict] = {}
        self.auths: list[dict] = []
        self.posts: list[dict] = []
        self.probes: list[bool] = []
        self.seen: list[str] = []
        self.followups: list[str] = []
        self.id_token = ""
        self.access_token = ""
        self.refresh_token = ""

    def handle(self, route: Any) -> None:
        req = route.request
        self.seen.append(req.url)
        url = urllib.parse.urlsplit(req.url)
        origin = f"{url.scheme}://{url.netloc}"
        if req.resource_type == "document" or (
            origin == ORIGIN and url.path == REDIRECT_PATH
        ):
            route.fulfill(status=200, content_type="text/html", body="<p id=me>K</p>")
        elif origin != ORIGIN:
            route.fulfill(status=200, content_type="text/html", body="<p>x</p>")
        elif url.path == AUTH_PATH:
            self._auth(route, url)
        elif url.path == TOKEN_PATH:
            self._token(route, req)
        elif url.path == PROBE_PATH:
            self._probe(route, req)
        else:
            route.fulfill(status=404, content_type="application/json", body="{}")

    def _auth(self, route: Any, url: Any) -> None:
        q = dict(urllib.parse.parse_qsl(url.query))
        self.auths.append(q)
        if self.auth_status != 302:
            route.fulfill(status=self.auth_status, content_type="text/html", body="x")
            return
        back: dict[str, str] = {"state": q.get("state", "")}
        if self.name is None:
            back["error"] = "login_required"
        else:
            back["session_state"] = secrets.token_hex(8)
            if self.iss_param is not None:
                back["iss"] = self.iss_param
            code = ".".join(secrets.token_hex(8) for _ in range(3))
            self.codes[code] = q
            back["code"] = code
        location = (
            self.auth_redirect(back)
            if self.auth_redirect
            else f"{q.get('redirect_uri')}?{urllib.parse.urlencode(back)}"
        )
        route.fulfill(status=302, headers={"Location": location})

    def _token(self, route: Any, req: Any) -> None:
        form = dict(urllib.parse.parse_qsl(req.post_data or ""))
        self.posts.append(
            {
                "method": req.method,
                "ctype": req.headers.get("content-type"),
                "form": form,
            }
        )
        auth = self.codes.pop(form.get("code", ""), None)
        valid = (
            req.method == "POST"
            and auth is not None
            and form.get("grant_type") == "authorization_code"
            and form.get("client_id") == auth.get("client_id") == CLIENT
            and form.get("redirect_uri") == auth.get("redirect_uri") == CHECK
            and auth.get("code_challenge_method") == "S256"
            and _s256(form.get("code_verifier", "")) == auth.get("code_challenge")
        )
        status = self.token_status or (200 if valid else 400)
        if status != 200:
            route.fulfill(
                status=status,
                content_type="application/json",
                body=json.dumps({"error": "invalid_grant"}),
            )
            return
        body = self.token_body
        if body is None:
            assert self.name is not None
            over = {"nonce": (auth or {}).get("nonce", _DROP), **self.id_over}
            self.id_token = _jwt(_id_claims(self.name, **over))
            self.access_token = _jwt(_access_claims())
            self.refresh_token = _jwt({"typ": "Refresh"})
            body = {
                "access_token": self.access_token,
                "expires_in": 300,
                "refresh_expires_in": 1800,
                "refresh_token": self.refresh_token,
                "token_type": "Bearer",
                "id_token": self.id_token,
                "not-before-policy": 0,
                "session_state": secrets.token_hex(8),
                "scope": "openid email profile",
            }
        route.fulfill(status=200, content_type=self.token_ctype, body=json.dumps(body))

    def _probe(self, route: Any, req: Any) -> None:
        bearer = req.headers.get("authorization") == f"Bearer {self.access_token}"
        self.probes.append(bearer)
        status = self.probe_status if bearer and self.access_token else 401
        body = self.probe_body
        if body is None:
            body = (
                json.dumps(secrets.randbelow(500))
                if "json" in self.probe_ctype
                else "<html>app</html>"
            )
        route.fulfill(status=status, content_type=self.probe_ctype, body=body)

    def secrets(self) -> list[str]:
        out = [self.id_token, self.access_token, self.refresh_token]
        out += [p for t in out if t for p in t.split(".")]
        out += list(self.codes)
        for post in self.posts:
            out += [post["form"].get("code", ""), post["form"].get("code_verifier", "")]
        for q in self.auths:
            out += [q.get(k, "") for k in ("state", "nonce", "code_challenge")]
        return [s for s in out if s]


# The `_Keycloak` the local TLS server records the redirect follow-ups for.
_FOLLOWUP: dict[str, _Keycloak] = {}


class _FollowupHandler(http.server.BaseHTTPRequestHandler):
    """Answers what the browser sends AFTER a fulfilled redirect: the
    redirect target (the console page, 200 HTML), recorded in `seen`."""

    def do_GET(self) -> None:  # noqa: N802  # the stdlib's name
        host = str(self.headers.get("Host") or "").split(":", maxsplit=1)[0]
        api = _FOLLOWUP.get("api")
        if api is not None:
            api.seen.append(f"https://{host}{self.path}")
            api.followups.append(f"https://{host}{self.path}")
        body = b"<p id=me>K</p>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_a: Any) -> None:  # pylint: disable=arguments-differ
        return None


@pytest.fixture(scope="module")
def followup_port(tmp_path_factory: pytest.TempPathFactory) -> Iterator[int]:
    """The local TLS server (throwaway self-signed certificate) the fixture
    hosts map to."""
    d = tmp_path_factory.mktemp("kc-tls")
    hosts = [urllib.parse.urlsplit(o).hostname for o in (ORIGIN, OTHER)]
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
            "/CN=ws5kc",
            "-addext",
            "subjectAltName=" + ",".join(f"DNS:{h}" for h in hosts),
        ],
        check=True,
        capture_output=True,
    )
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _FollowupHandler)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(str(d / "cert.pem"), str(d / "key.pem"))
    srv.socket = tls.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield int(srv.server_address[1])
    finally:
        srv.shutdown()
        srv.server_close()


@contextlib.contextmanager
def _kc_context(api: _Keycloak, port: int) -> Iterator[Any]:
    """A throwaway headless Chromium whose context routes every request to
    `api`; the fixture hosts resolve to the local follow-up server, every
    other host to nothing."""
    from playwright.sync_api import (  # pylint: disable=import-outside-toplevel
        sync_playwright,
    )

    hosts = [urllib.parse.urlsplit(o).hostname for o in (ORIGIN, OTHER)]
    rules = [f"MAP {h} 127.0.0.1:{port}" for h in hosts] + ["MAP * ~NOTFOUND"]
    _FOLLOWUP["api"] = api
    try:
        with sync_playwright() as pw:
            chromium = pw.chromium.launch(
                headless=True,
                args=["--no-proxy-server", "--host-resolver-rules=" + ", ".join(rules)],
            )
            try:
                ctx = chromium.new_context(ignore_https_errors=True)
                ctx.route("**/*", api.handle)
                yield ctx
            finally:
                chromium.close()
        # nothing the route did not answer went anywhere but the fixture hosts
        strays = [
            u for u in api.followups if urllib.parse.urlsplit(u).hostname not in hosts
        ]
        assert not strays, strays
    finally:
        _FOLLOWUP.pop("api", None)


Evaluator = Callable[[Any, str, Any], Any]
EVALUATORS = {
    "broker": daemon.evaluate_isolated,
    "client": browser._evaluate_isolated,
}


@pytest.fixture(params=sorted(EVALUATORS))
def kc(
    request: pytest.FixtureRequest, followup_port: int
) -> Iterator[tuple[Any, _Keycloak, Evaluator]]:
    api = _Keycloak()
    with _kc_context(api, followup_port) as ctx:
        page = ctx.new_page()
        page.goto(CHECK)
        yield page, api, EVALUATORS[request.param]


def _run(page: Any, run: Evaluator, check: str = CHECK) -> dict:
    nonce = secrets.token_hex(32)
    got = dict(
        run(page, identity.RECIPE_JS, identity.recipe_args(RECIPE, check, nonce))
    )
    got["_nonce"] = nonce
    return got


def _verdict(got: dict, name: str, privilege: str) -> str:
    return identity.local_verdict(got, got["_nonce"], name, privilege)


def _no_leak(got: dict, api: _Keycloak, *names: str) -> None:
    text = json.dumps(got)
    for secret in (*api.secrets(), *names):
        assert secret not in text and secret.lower() not in text
    assert set(got) <= {"state", "digest", "admin", "why", "status", "_nonce"}


@pytest.mark.launches_chrome
@CHROME
def test_match_and_mismatch(kc: tuple[Any, _Keycloak, Evaluator]) -> None:
    page, api, run = kc
    me = _user()
    api.name = f" {me.upper()} "
    got = _run(page, run)
    assert got["state"] == "found" and got["admin"] is True
    assert _verdict(got, me, "admin") == identity.MATCH
    assert _verdict(got, _user(), "admin") == identity.WRONG_ACCOUNT
    assert _verdict(got, me, "user") == identity.PRIVILEGE_MISMATCH
    # ONE silent authorization request, ONE code exchange, ONE probe
    assert len(api.auths) == 1 and len(api.posts) == 1 and api.probes == [True]
    q = api.auths[0]
    assert {k: q[k] for k in q if k not in ("state", "nonce", "code_challenge")} == {
        "client_id": CLIENT,
        "redirect_uri": CHECK,
        "response_type": "code",
        "response_mode": "query",
        "scope": "openid",
        "prompt": "none",
        "code_challenge_method": "S256",
    }
    assert len(q["state"]) >= 22 and len(q["code_challenge"]) == 43
    assert len(q["nonce"]) >= 22 and q["nonce"] != q["state"]
    post = api.posts[0]
    assert post["method"] == "POST"
    assert post["ctype"].startswith("application/x-www-form-urlencoded")
    assert set(post["form"]) == {
        "grant_type",
        "code",
        "client_id",
        "redirect_uri",
        "code_verifier",
    }
    assert len(post["form"]["code_verifier"]) == 43
    assert not api.codes  # the code was spent by the recipe, once
    # the redirect was followed to the console URL (the local server: the
    # fetch never runs that page) with our state and the code
    (landed,) = api.followups
    back = urllib.parse.urlsplit(landed)
    assert f"https://{back.netloc}{back.path}" == CHECK
    params = urllib.parse.parse_qs(back.query)
    assert params["state"] == [q["state"]]
    assert params["code"] == [post["form"]["code"]]
    _no_leak(got, api, me)
    # a second run: a fresh state and verifier
    _run(page, run)
    assert api.auths[1]["state"] != q["state"]
    assert api.auths[1]["code_challenge"] != q["code_challenge"]
    assert api.auths[1]["nonce"] != q["nonce"]


@pytest.mark.launches_chrome
@CHROME
def test_no_session_is_logged_out(kc: tuple[Any, _Keycloak, Evaluator]) -> None:
    page, api, run = kc
    got = _run(page, run)
    assert (got["state"], got["why"]) == ("logged_out", "error")
    assert _verdict(got, _user(), "admin") == identity.LOGGED_OUT
    assert len(api.auths) == 1 and not api.posts and not api.probes
    # only login_required is logged out: any other error (a server fault, a
    # pending required action) is indeterminate — never a password login
    for error in (
        "interaction_required",
        "invalid_request",
        "unauthorized_client",
        "server_error",
        "temporarily_unavailable",
        "consent_required",
        "LOGIN_REQUIRED",
        "",
    ):
        api.auth_redirect = lambda back, e=error: (
            f"{CHECK}?" + urllib.parse.urlencode({**back, "error": e})
        )
        got = _run(page, run)
        assert (got["state"], got["why"]) == ("indeterminate", "error"), error
    # two error parameters are no logged-out either
    api.auth_redirect = lambda back: (
        f"{CHECK}?" + urllib.parse.urlencode(back) + "&error=login_required"
    )
    assert (_run(page, run)["state"], len(api.posts)) == ("indeterminate", 0)
    assert not api.posts and not api.probes


@pytest.mark.launches_chrome
@CHROME
def test_pinned_id_token_claims(kc: tuple[Any, _Keycloak, Evaluator]) -> None:
    page, api, run = kc
    me = _user()
    api.name = me
    bad: dict[str, dict[str, Any]] = {
        "azp other": {"azp": "another-client"},
        "azp missing": {"azp": _DROP},
        "aud other": {"aud": "another-client"},
        "aud list without": {"aud": ["account", "another-client"]},
        "aud missing": {"aud": _DROP},
        "aud not a string": {"aud": 7},
        "iss other realm": {"iss": f"{ORIGIN}/realms/sdsc"},
        "iss suffix trick": {"iss": f"{ISS}-evil"},
        "iss http": {"iss": "http://custos.datascience.ch/realms/master"},
        "iss trailing slash": {"iss": f"{ISS}/"},
        "iss another host": {"iss": "https://other.ws5kc.example/realms/master"},
        "iss missing": {"iss": _DROP},
        "typ other": {"typ": "Bearer"},
        "typ missing": {"typ": _DROP},
        "nonce other": {"nonce": "x" * 22},
        "nonce missing": {"nonce": _DROP},
        "nonce not a string": {"nonce": 7},
    }
    for case, over in bad.items():
        api.id_over = over
        before = len(api.probes)
        got = _run(page, run)
        assert (got["state"], got["why"]) == ("indeterminate", "claim"), case
        assert len(api.probes) == before, case  # nothing more was sent
        _no_leak(got, api, me)
    for case, exp in {
        "expired past the leeway": int(time.time()) - 40,
        "missing": _DROP,
        "a string": str(int(time.time()) + 300),
    }.items():
        api.id_over = {"exp": exp}
        got = _run(page, run)
        assert (got["state"], got["why"]) == ("indeterminate", "expired"), case
    # 30 s of leeway (the master realm's tokens live 60 s): clock skew
    api.id_over = {"exp": int(time.time()) - 5}
    assert _verdict(_run(page, run), me, "admin") == identity.MATCH
    # an aud list holding the client is fine
    api.id_over = {"aud": ["account", CLIENT]}
    assert _verdict(_run(page, run), me, "admin") == identity.MATCH
    api.id_over = {"preferred_username": _DROP}
    assert _run(page, run)["why"] == "identity"


@pytest.mark.launches_chrome
@CHROME
def test_the_redirect_is_checked(kc: tuple[Any, _Keycloak, Evaluator]) -> None:
    page, api, run = kc
    api.name = _user()

    def back_with(**over: Any) -> Callable[[dict], str]:
        def make(back: dict) -> str:
            params = {**back, **over}
            return f"{CHECK}?" + urllib.parse.urlencode(
                {k: v for k, v in params.items() if v is not _DROP}, doseq=True
            )

        return make

    cases: dict[str, tuple[Callable[[dict], str], str]] = {
        "another state": (back_with(state="x" * 22), "state"),
        "no state": (back_with(state=_DROP), "state"),
        "two states": (
            lambda b: f"{CHECK}?state={b['state']}&" + "state=x&code=y",
            "state",
        ),
        "an error of another state": (
            back_with(state="x" * 22, error="login_required"),
            "state",
        ),
        "no code": (back_with(code=_DROP), "code"),
        "two codes": (
            lambda b: f"{CHECK}?" + urllib.parse.urlencode(b) + "&code=z",
            "code",
        ),
        "a strange code": (back_with(code="a b<c"), "code"),
        "another iss": (back_with(iss=f"{ORIGIN}/realms/sdsc"), "claim"),
        # RFC 9207: the issuer is checked before an error is believed
        "an error from another iss": (
            back_with(iss=f"{ORIGIN}/realms/sdsc", error="login_required"),
            "claim",
        ),
        "another path": (
            lambda b: f"{ORIGIN}/admin/sdsc/console/?" + urllib.parse.urlencode(b),
            "redirect",
        ),
    }
    for case, (make, why) in cases.items():
        api.auth_redirect = make
        got = _run(page, run)
        assert (got["state"], got.get("why")) == ("indeterminate", why), case
        assert not api.posts, case  # the code never reached the token endpoint
        _no_leak(got, api)
    # Keycloak's own error page (no redirect at all): the auth path itself
    api.auth_redirect, api.auth_status = None, 200
    got = _run(page, run)
    assert (got["state"], got["why"]) == ("indeterminate", "redirect")
    # no `iss` parameter at all is fine (older Keycloak)
    api.auth_status, api.iss_param = 302, None
    assert _run(page, run)["state"] == "found"


@pytest.mark.launches_chrome
@CHROME
def test_a_redirect_off_the_origin_is_never_followed(
    kc: tuple[Any, _Keycloak, Evaluator],
) -> None:
    page, api, run = kc
    api.name = _user()
    api.auth_redirect = lambda back: (
        f"{OTHER}{REDIRECT_PATH}?" + urllib.parse.urlencode(back)
    )
    got = _run(page, run)
    assert (got["state"], got["why"]) == ("indeterminate", "network")
    assert not api.posts and not api.probes
    # the code never travelled to the other origin (mode same-origin: the
    # browser refuses the cross-origin hop before sending it)
    assert len(api.auths) == 1
    assert not [u for u in api.seen if u.startswith(OTHER)]
    assert not api.followups
    _no_leak(got, api)


@pytest.mark.launches_chrome
@CHROME
def test_the_token_endpoint_answers(kc: tuple[Any, _Keycloak, Evaluator]) -> None:
    page, api, run = kc
    me = _user()
    api.name = me
    for status in (400, 401, 403, 500):
        api.token_status = status
        got = _run(page, run)
        assert (got["state"], got["why"], got["status"]) == (
            "indeterminate",
            "status",
            status,
        ), status
        assert not api.probes
    api.token_status = None
    api.token_ctype = "text/html"
    assert _run(page, run)["why"] == "content-type"
    api.token_ctype = "application/json"
    good_id = _jwt(_id_claims(me))
    good_access = _jwt(_access_claims())
    shapes = {
        "no id token": ({"access_token": good_access}, "token"),
        "no access token": ({"id_token": good_id}, "token"),
        "id token not a string": (
            {"id_token": 7, "access_token": good_access},
            "token",
        ),
        "a bearer with a space": (
            {"id_token": good_id, "access_token": "a b"},
            "token",
        ),
        "id token not a jwt": (
            {"id_token": secrets.token_hex(20), "access_token": good_access},
            "token",
        ),
        "an array": ([good_id], "schema"),
    }
    for case, (body, why) in shapes.items():
        api.token_body = body
        got = _run(page, run)
        assert (got["state"], got["why"]) == ("indeterminate", why), case
        assert not api.probes, case


@pytest.mark.launches_chrome
@CHROME
def test_the_admin_probe(kc: tuple[Any, _Keycloak, Evaluator]) -> None:
    page, api, run = kc
    me = _user()
    api.name = me
    # 200 JSON, one integer (live, the admin account): admin
    got = _run(page, run)
    assert got["admin"] is True and api.probes == [True]
    assert _verdict(got, me, "admin") == identity.MATCH
    api.probe_body = "0"
    assert _run(page, run)["admin"] is True
    # a 200 JSON that is not one non-negative integer: no bit
    for body in (
        "[]",
        json.dumps([{"realm": "master"}]),
        "{}",
        "-1",
        "1.5",
        '"7"',
        "null",
        "true",
        "",
        "7" + " " * (64 * 1024),
        "<html>app</html>",
    ):
        api.probe_body = body
        got = _run(page, run)
        assert got["state"] == "found" and got["admin"] is None, body[:20]
        assert _verdict(got, me, "admin") == identity.INDETERMINATE
    # 403 JSON (expected for a non-admin, unconfirmed): not admin
    api.probe_status, api.probe_ctype = 403, "application/json"
    api.probe_body = json.dumps({"error": "HTTP 403 Forbidden"})
    got = _run(page, run)
    assert got["state"] == "found" and got["admin"] is False
    assert _verdict(got, me, "admin") == identity.PRIVILEGE_MISMATCH
    # a 403 in plain text, HTML 200 / 403, other statuses: no bit
    api.probe_ctype, api.probe_body = "text/plain", "Forbidden"
    assert _run(page, run)["admin"] is None
    api.probe_body = json.dumps({"error": "HTTP 403 Forbidden"})
    assert _run(page, run)["admin"] is None
    api.probe_ctype, api.probe_body = "text/html", "<html>app</html>"
    for status in (200, 403):
        api.probe_status = status
        got = _run(page, run)
        assert got["state"] == "found" and got["admin"] is None, status
        assert _verdict(got, me, "admin") == identity.INDETERMINATE
    api.probe_ctype, api.probe_body = "application/json", None
    for status in (401, 404, 500):
        api.probe_status = status
        assert _run(page, run)["admin"] is None, status
    # the probe's bearer is the ACCESS token, never the ID token
    assert all(api.probes)


@pytest.mark.launches_chrome
@CHROME
def test_page_scripts_cannot_hook_the_recipe(
    kc: tuple[Any, _Keycloak, Evaluator],
) -> None:
    """The app's world replaces crypto, Response.json, JSON and atob: the
    main world is fooled, the isolated recipe is not."""
    page, api, run = kc
    real, fake = _user(), _user()
    api.name = real
    api.id_over = {"exp": int(time.time()) - 60}  # an EXPIRED ID token
    # the main world's crypto is the page's: its nonce is predictable
    zero = _b64url(bytes(16))
    forged = _jwt(_id_claims(fake, nonce=zero))
    page.evaluate(
        """([forged, fakeClaims]) => {
          crypto.getRandomValues = (arr) => arr;  // all zero: guessable
          Response.prototype.json = async function () {
            return {id_token: forged, access_token: 'x'}; };
          const parse = JSON.parse;
          JSON.parse = (s) => {
            const v = parse(s); if (v && v.exp) v.exp = 4102444800; return v; };
          window.atob = () => JSON.stringify(fakeClaims);
        }""",
        [forged, _id_claims(fake, nonce=zero)],
    )
    nonce = secrets.token_hex(32)
    args = identity.recipe_args(RECIPE, CHECK, nonce)
    hooked = page.evaluate(identity.RECIPE_JS, args)
    norm = identity.normalize_identity(fake)
    assert norm is not None
    assert hooked["state"] == "found"  # fooled …
    assert hooked["digest"] == identity.challenge_digest(nonce, norm)
    assert api.auths[-1]["state"] == zero  # … with a zero state and nonce
    assert api.auths[-1]["nonce"] == zero
    got = _run(page, run)  # … the isolated world is not: the server's token
    assert (got["state"], got["why"]) == ("indeterminate", "expired")
    assert zero not in (api.auths[-1]["state"], api.auths[-1]["nonce"])
    api.id_over = {}
    got = _run(page, run)
    assert _verdict(got, real, "admin") == identity.MATCH
    assert _verdict(got, fake, "admin") == identity.WRONG_ACCOUNT
    # a replaced fetch (no real redirect) gives the main world nothing
    page.evaluate(
        """() => { window.fetch = async () => new Response('{}',
          {status: 200, headers: {'content-type': 'application/json'}}); }"""
    )
    assert page.evaluate(identity.RECIPE_JS, args)["state"] != "found"
    got = _run(page, run)
    assert _verdict(got, real, "admin") == identity.MATCH
    _no_leak(got, api, real, fake)


@pytest.mark.launches_chrome
@CHROME
def test_a_page_on_another_origin_is_refused(
    kc: tuple[Any, _Keycloak, Evaluator],
) -> None:
    page, api, run = kc
    api.name = _user()
    page.goto(f"{OTHER}/admin/master/console/")
    for check in (CHECK, f"{OTHER}/admin/master/console/"):
        got = _run(page, run, check)
        assert (got["state"], got["why"]) == ("indeterminate", "origin")
    assert not api.auths and not api.posts  # nothing was sent


# ---------------------------------------------------------------------------
# end to end: the client proof through the REAL broker
# ---------------------------------------------------------------------------


class _Vault:
    def __init__(self, items: list[vault.SiteItem]) -> None:
        self._items = items

    def items(self) -> list[vault.SiteItem]:
        return self._items

    def secret(self, site: str) -> vault.Secret:
        raise AssertionError(f"no login may reach the vault ({site})")


class _NoRunner:
    def __call__(self, item: Any, get_secret: Any) -> dict[str, Any]:
        raise AssertionError("the runner must not be reached")


class FakeBroker:
    """The real broker (`daemon.Broker`) behind its real socket server."""

    def __init__(self, raws: list[dict], home: Path) -> None:
        self.items = vault.build_items(raws)
        lim = limiter.Limiter(
            home / "l.json", cooldown_s=1800, min_interval_s=0, per_hour=50, per_day=100
        )
        self.broker = daemon.Broker(
            _Vault(self.items),  # type: ignore[arg-type]
            lim,
            home / "home",
            runner=_NoRunner(),
        )
        self.ops: list[str] = []
        self.secrets: list[str] = []
        real = self.broker.handle

        def handle(req: Any, uid: Any = None, pid: Any = None) -> dict:
            if isinstance(req, dict):
                self.ops.append(str(req.get("op")))
                self.secrets += [
                    str(req[k]) for k in ("challenge_id", "digest") if req.get(k)
                ]
            reply = real(req, uid, pid)
            self.secrets += [
                str(reply[k]) for k in ("challenge_id", "nonce") if reply.get(k)
            ]
            return reply

        self.broker.handle = handle  # type: ignore[method-assign]
        self.dir = tempfile.mkdtemp(prefix="ws5kc-")
        self.path = os.path.join(self.dir, "b.sock")
        self.server = daemon.BrokerServer(self.path, self.broker, os.getuid())
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        shutil.rmtree(self.dir, ignore_errors=True)


@pytest.fixture
def result_file(tmp_path: Path) -> Iterator[Path]:
    path = tmp_path / "result.json"
    browser._result_begin("logged-in", "", str(path))
    browser._LOGIN_OPTS.update(scheduled=False, candidate=None, refresh_only=False)
    browser._BROKER_SITES_CACHE.clear()
    yield path
    browser._result_begin("logged-in", "", None)
    browser._BROKER_SITES_CACHE.clear()


@pytest.fixture
def e2e(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, followup_port: int
) -> Iterator[tuple[Callable[[list[dict]], FakeBroker], _Keycloak, list]]:
    made: list[FakeBroker] = []
    cleared: list = []
    api = _Keycloak()

    def make(raws: list[dict]) -> FakeBroker:
        fake = FakeBroker(raws, tmp_path)
        monkeypatch.setenv("LOGIN_BROKER_SOCKET", fake.path)
        browser._BROKER_SITES_CACHE.clear()
        made.append(fake)
        return fake

    with _kc_context(api, followup_port) as ctx:
        try:
            page = ctx.new_page()

            def probe_tab(_port: int, url: str, _prepare: Any, fn: Any) -> Any:
                resp = page.goto(url)
                browser._BG_STATUS[id(page)] = getattr(resp, "status", None)
                try:
                    return fn(page)
                finally:
                    browser._BG_STATUS.pop(id(page), None)

            def clear(
                _port: int, site: str, _entry: dict, _names: Any, *, why: str
            ) -> int:
                cleared.append((site, why))
                return 3

            def clear_storage(_port: int, site: str, plan: Any) -> int:
                cleared.append((site, "storage", dict(plan)))
                return sum(len(keys) for keys in plan.values())

            monkeypatch.setattr(browser, "_with_prepared_background_page", probe_tab)
            monkeypatch.setattr(browser, "_broker_note_session_age", lambda *_a: None)
            monkeypatch.setattr(browser, "_broker_clear_cookies", clear)
            monkeypatch.setattr(browser, "_broker_clear_foreign_storage", clear_storage)
            monkeypatch.setattr(browser, "INSTANCE", "alt")
            yield make, api, cleared
        finally:
            for fake in made:
                fake.close()


def _record(path: Path, rc: int) -> dict:
    browser._result_write(rc)
    rec: dict = json.loads(path.read_text())
    return rec


def _leak_free(
    names: list[str], capsys: pytest.CaptureFixture[str], *paths: Path
) -> None:
    out = capsys.readouterr()
    texts = [out.out, out.err]
    texts += [p.read_text(encoding="utf-8") for p in paths if p.exists()]
    journal = os.environ.get("CLAUDE_BROWSER_JOURNAL_FILE")
    if journal and Path(journal).exists():
        texts.append(Path(journal).read_text(encoding="utf-8"))
    for name in names:
        for text in texts:
            assert name not in text and name.upper() not in text


@pytest.mark.launches_chrome
@CHROME
def test_e2e_custos_admin_is_proven_once_and_nothing_leaks(
    e2e: Any, result_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    make, api, cleared = e2e
    custos, test3, admin = _user(), _user(), _user()
    fake = make(_trio(custos, test3, admin))
    api.name = custos
    assert browser._broker_logged_in(9225, "custos-admin") == 0
    rec = _record(result_file, 0)
    assert rec["identity"] == "match" and rec["multi_account"] is True
    assert fake.ops == ["sites", "identity_challenge", "identity_answer"]
    # the recipe ran ONCE in this check: one authorization request, one
    # code exchange, one probe
    assert len(api.auths) == 1 and len(api.posts) == 1 and api.probes == [True]
    assert not cleared
    _leak_free(
        [custos, test3, admin, *api.secrets(), *fake.secrets], capsys, result_file
    )


@pytest.mark.launches_chrome
@CHROME
def test_e2e_another_account_is_wrong_account_and_cleared(
    e2e: Any, result_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    make, api, cleared = e2e
    custos, other = _user(), _user()
    make(_trio(custos, _user(), _user()))
    api.name = other
    assert browser._broker_logged_in(9225, "custos-admin") == 2
    rec = _record(result_file, 2)
    assert rec["code"] == "wrong_account" and rec["phase"] == "client-proof"
    # its cookies only: the recipe keeps nothing in storage
    assert cleared == [("custos-admin", "clear-foreign")]
    assert len(api.auths) == 1 and len(api.posts) == 1
    _leak_free([custos, other, *api.secrets()], capsys, result_file)


@pytest.mark.launches_chrome
@CHROME
def test_e2e_a_user_item_stays_unproven_without_asking_the_site(
    e2e: Any, result_file: Path
) -> None:
    make, api, cleared = e2e
    custos = _user()
    fake = make(_trio(custos, _user(), _user(), privilege="user"))
    api.name = custos
    assert browser._broker_logged_in(9225, "custos-admin") == 2
    rec = _record(result_file, 2)
    assert rec["code"] == "identity_unproven"
    assert not api.auths and not api.posts and not api.probes
    assert "identity_challenge" not in fake.ops and not cleared
