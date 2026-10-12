"""WS5 S4c (tp#931): the reviewed `runai` identity recipe (token-endpoint).

Run:ai's SPA keeps its bearer in page memory and renews it with its own
same-origin ``POST /api/v1/token`` (the HttpOnly refresh cookie authenticates
it). The recipe sends that POST itself in a CDP isolated world, reads the
returned JWT's claims (``preferred_username``; ``azp``, the issuer path and
``exp`` pinned) and takes the admin bit from a fixed GET with the token as
bearer (200 admin, 403 not, anything else none). Both answers are
live-confirmed (2026-10-12), so an ``agent_privilege admin`` item may use it;
the rule that keeps an admin item unproven while a recipe's "admin" answer is
unconfirmed runs on an explicit ``admin_true_confirmed=False`` variant (the
``unconfirmed`` fixture).

The recipe runs in a throwaway headless Chromium against a routed fixture
Run:ai (no network), through BOTH isolated-world evaluators, and end to end
through the REAL broker behind its socket. Account names, tokens and
signatures are built per run: no credential-shaped literal.
"""

from __future__ import annotations

# pylint: disable=protected-access,missing-function-docstring,missing-class-docstring
# pylint: disable=import-error,wrong-import-position,redefined-outer-name
# pylint: disable=too-many-lines,too-many-instance-attributes
import base64
import dataclasses
import json
import os
import secrets
import shutil
import sys
import tempfile
import threading
import time
import urllib.parse
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from chromium_page import REPO, chromium_available, load_script, routed_context

sys.path.insert(0, str(REPO))

from broker import daemon, identity, limiter, vault  # noqa: E402

browser = load_script("bin/browser.py", "ws5runai_browser")

RECIPE = identity.IDENTITIES["runai"]
# the recipe as it was before its admin answer was seen live: the
# unconfirmed-admin rule stays covered on it
UNCONFIRMED = dataclasses.replace(RECIPE, admin_true_confirmed=False)
ORIGIN = "https://sdsc.run.ai"
CHECK = f"{ORIGIN}/workloads"
KC_ORIGIN = "https://custos.datascience.ch"
OTHER = "https://other.ws5r.example"
TOKEN_PATH = "/api/v1/token"
PROBE_PATH = "/api/v1/authorization/access-rules"
BODY = {"grantType": "refresh_token", "clientID": "runai-admin-ui"}
ISS = "https://app1.run.ai/auth/realms/sdsc"
_LOGIN_KEY = "pass" + "word"
CHROME = pytest.mark.skipif(
    not chromium_available(), reason="Playwright Chromium missing"
)


def _user() -> str:
    """A fresh e-mail-shaped account name (never a literal in this file)."""
    return f"zz-{secrets.token_hex(5)}@ws5r.example"


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _jwt(claims: Any) -> str:
    """A JWT-shaped string built at run time (random signature: the recipe
    never checks it — the token comes straight from the server)."""
    head = _b64url(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
    body = _b64url(json.dumps(claims).encode())
    return f"{head}.{body}.{_b64url(secrets.token_bytes(64))}"


def _claims(name: str, **over: Any) -> dict:
    claims = {
        "iss": ISS,
        "azp": "runai-admin-ui",
        "aud": ["runai-dummy", "runai"],
        "exp": int(time.time()) + 300,
        "iat": int(time.time()),
        "preferred_username": name,
        "email": name,
        "sub": name,
    }
    claims.update(over)
    return {k: v for k, v in claims.items() if v is not _DROP}


_DROP = object()


@pytest.fixture
def unconfirmed(monkeypatch: pytest.MonkeyPatch) -> None:
    """`IDENTITIES["runai"]` swapped for the unconfirmed-admin variant."""
    monkeypatch.setitem(identity.IDENTITIES, "runai", UNCONFIRMED)


# ---------------------------------------------------------------------------
# the reviewed spec
# ---------------------------------------------------------------------------


def test_the_runai_recipe_is_reviewed() -> None:
    assert identity.usable_recipe("runai") is RECIPE
    assert RECIPE.live_confirmed and RECIPE.admin_true_confirmed
    assert RECIPE.auth == "token-endpoint" and RECIPE.forms == ("email",)
    assert RECIPE.allowed_sites == ("runai-admin", "runai-test3")
    assert RECIPE.origin == ORIGIN and RECIPE.admin_field is None
    assert RECIPE.identity_storage_keys == ("logged-in-user-email",)
    args = identity.recipe_args(RECIPE, CHECK, "0" * 64)
    assert args["origin"] == ORIGIN and args["path"] == TOKEN_PATH
    assert args["token_body"] == BODY and args["token_field"] == ["accessToken"]
    assert args["claim_pins"] == [["azp", "runai-admin-ui"]]
    assert args["issuer"] == ISS == RECIPE.issuer
    assert args["admin_probe"] == f"{PROBE_PATH}?subjectType=user"
    assert (args["admin_probe_true"], args["admin_probe_false"]) == ([200], [403])
    assert args["admin_probe_error_shape"] == ["code", "message"]
    assert args["probe_body_max"] == 64 * 1024
    assert args["id_field"] == ["preferred_username"]
    # the pinned origin wins over a check URL elsewhere (the page check fails)
    assert identity.recipe_args(RECIPE, f"{OTHER}/x", "0" * 64)["origin"] == ORIGIN


def test_the_other_recipes_send_no_token_fields() -> None:
    for name in ("gitlab", "audiobookshelf", "navidrome"):
        args = identity.recipe_args(identity.IDENTITIES[name], f"{OTHER}/x", "0" * 64)
        assert args["origin"] == OTHER
        assert not args["token_body"] and args["token_field"] is None
        assert args["claim_pins"] == [] and not args["admin_probe"]
        assert not args["admin_probe_error_shape"]
        assert identity.IDENTITIES[name].admin_true_confirmed
        assert not identity.IDENTITIES[name].allowed_sites


@pytest.mark.parametrize(
    ("change", "problem"),
    [
        ({"token_body": ()}, "token_body"),
        ({"token_body": (("grant type", "x"),)}, "token_body"),
        ({"token_body": (("grantType", "a b"),)}, "token_body"),
        ({"token_field": None}, "token_field"),
        ({"token_field": ("access token",)}, "token_field"),
        ({"claim_pins": (("a-z", "x"),)}, "bad claim_pins"),
        ({"claim_pins": (("azp", ""),)}, "bad claim_pins"),
        ({"issuer": ""}, "needs an issuer"),
        ({"issuer": "/auth/realms/sdsc"}, "needs an issuer"),
        ({"issuer": "http://app1.run.ai/auth/realms/sdsc"}, "needs an issuer"),
        ({"issuer": f"{ISS}?x=1"}, "needs an issuer"),
        ({"issuer": f"{ISS}#x"}, "needs an issuer"),
        ({"issuer": "https://app1.run.ai"}, "needs an issuer"),
        ({"admin_field": ("isAdmin",)}, "admin bit from admin_probe"),
        ({"admin_probe": ""}, "admin_probe"),
        ({"admin_probe": "api/v1/x"}, "admin_probe"),
        ({"admin_probe": "//evil.example/x"}, "admin_probe"),
        ({"admin_probe": "/api/v1/x#y"}, "admin_probe"),
        ({"admin_probe_true": (200,), "admin_probe_false": (200,)}, "disjoint"),
        ({"admin_probe_true": ()}, "disjoint"),
        ({"admin_probe_true": (True,)}, "disjoint"),
        ({"admin_probe_false": (99,)}, "disjoint"),
        ({"admin_probe_error_shape": ("code",)}, "admin_probe_error_shape"),
        ({"admin_probe_error_shape": ("code", "code")}, "admin_probe_error_shape"),
        ({"admin_probe_error_shape": ("code", "a b")}, "admin_probe_error_shape"),
        ({"admin_probe_error_shape": ("a", "b", "c")}, "admin_probe_error_shape"),
        ({"base_segments": ("x",)}, "one fixed path"),
        ({"path": "/api/v1/token?x=1"}, "one fixed path"),
        ({"allowed_sites": ()}, "allowed_sites and an origin"),
        ({"origin": ""}, "allowed_sites and an origin"),
        ({"origin": f"{ORIGIN}/"}, "exact https origin"),
        ({"origin": "http://sdsc.run.ai"}, "exact https origin"),
        ({"origin": f"{ORIGIN}:443"}, "exact https origin"),
        ({"allowed_sites": ("Bad Site",)}, "bad allowed_sites"),
        ({"identity_storage_keys": ("",)}, "bad identity_storage_keys"),
        ({"path_claim": "uid", "claim_field": ("id",)}, "path_claim needs jwt"),
    ],
)
def test_a_malformed_token_spec_is_refused(change: dict, problem: str) -> None:
    with pytest.raises(ValueError, match="identity recipe") as err:
        dataclasses.replace(RECIPE, **change)
    assert problem in str(err.value)


def test_token_fields_need_the_token_auth() -> None:
    gl = identity.IDENTITIES["gitlab"]
    for change in (
        {"admin_probe": "/x"},
        {"token_body": (("a", "b"),)},
        {"token_field": ("t",)},
        {"claim_pins": (("azp", "x"),)},
        {"issuer": ISS},
        {"admin_probe_error_shape": ("code", "message")},
    ):
        with pytest.raises(ValueError, match="token fields need auth token-endpoint"):
            dataclasses.replace(gl, **change)


# ---------------------------------------------------------------------------
# who may use it: sites, origin, privilege — one rule on both sides
# ---------------------------------------------------------------------------


def _entry(site: str = "runai-test3", privilege: str = "user", **over: Any) -> dict:
    entry = {
        "site": site,
        "identity": "runai",
        "privilege": privilege,
        "check_url": CHECK,
        "identity_v": 1,
        "refused": False,
    }
    entry.update(over)
    return entry


def test_recipe_refusal_and_proof_ready() -> None:
    assert (
        identity.recipe_refusal(
            "runai", site="runai-test3", check_url=CHECK, privilege="user"
        )
        == ""
    )
    assert identity.proof_ready(_entry())
    assert identity.proof_ready(_entry("runai-admin", "readonly"))
    # the admin answer is live-confirmed: an admin item may use the recipe
    assert (
        identity.recipe_refusal(
            "runai", site="runai-admin", check_url=CHECK, privilege="admin"
        )
        == ""
    )
    assert identity.proof_ready(_entry("runai-admin", "admin"))
    assert identity.entry_recipe(_entry("runai-admin", "admin")) is RECIPE
    refusals = {
        "site": _entry("runai-x"),
        "origin": _entry(check_url=f"{OTHER}/workloads"),
        "port": _entry(check_url=f"{ORIGIN}:8443/workloads"),
        "http": _entry(check_url="http://sdsc.run.ai/workloads"),
    }
    for why, entry in refusals.items():
        assert not identity.proof_ready(entry), why
        assert identity.entry_recipe(entry) is None, why
    # a login URL stands in for a missing check URL (where the check looks)
    assert identity.proof_ready(_entry(check_url="", login_url=f"{ORIGIN}/login"))


@pytest.mark.usefixtures("unconfirmed")
def test_an_unconfirmed_admin_answer_refuses_the_admin_item() -> None:
    admin = _entry("runai-admin", "admin")
    assert not identity.proof_ready(admin)
    assert identity.entry_recipe(admin) is None
    assert "admin answer is not live-confirmed" in identity.recipe_refusal(
        "runai", site="runai-admin", check_url=CHECK, privilege="admin"
    )
    # its "not admin" side is confirmed: user / readonly items may use it
    assert identity.proof_ready(_entry())
    assert identity.proof_ready(_entry("runai-admin", "readonly"))
    assert identity.entry_recipe(_entry()) is UNCONFIRMED


def _raw(site: str, user: str | None = None, **fields: str) -> dict:
    base = {
        "agent_site": site,
        "agent_fill_origins": KC_ORIGIN,
        "agent_check_url": CHECK,
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
    return {
        "id": f"id-{site}",
        "name": site,
        "login": {
            "username": user if user is not None else _user(),
            _LOGIN_KEY: secrets.token_urlsafe(18),
        },
        "fields": [{"name": k, "value": v} for k, v in base.items() if v is not None],
    }


def _items(*raws: dict) -> dict[str, vault.SiteItem]:
    return {it.site: it for it in vault.build_items(list(raws))}


def _members() -> dict[str, vault.SiteItem]:
    return _items(
        _raw("runai-test3"), _raw("runai-admin", privilege="admin", instance="admin")
    )


def test_the_vault_admits_both_members() -> None:
    items = _members()
    test3 = items["runai-test3"]
    assert not test3.refused, test3.refused
    assert test3.identity_recipe is RECIPE and test3.multi_account
    assert identity.proof_ready(test3.public())
    # the admin member: its "admin" answer is live-confirmed
    admin = items["runai-admin"]
    assert not admin.refused and admin.multi_account
    assert admin.identity_recipe is RECIPE
    assert identity.proof_ready(admin.public())


@pytest.mark.usefixtures("unconfirmed")
def test_the_vault_keeps_an_unconfirmed_admin_member_unproven() -> None:
    items = _members()
    test3 = items["runai-test3"]
    assert not test3.refused, test3.refused
    assert test3.identity_recipe is UNCONFIRMED and test3.multi_account
    assert identity.proof_ready(test3.public())
    # the admin member: valid, but unproven while the admin answer is
    # unconfirmed (no recipe for it anywhere: identity_unproven)
    admin = items["runai-admin"]
    assert not admin.refused and admin.multi_account
    assert admin.identity_recipe is None
    assert not identity.proof_ready(admin.public())


@pytest.mark.parametrize(
    ("site", "user", "fields", "problem"),
    [
        ("runai-test3", "plainname", {}, "the vault holds an username"),
        ("runai-x", None, {}, "reviewed for runai-admin, runai-test3 only"),
        (
            "runai-test3",
            None,
            {"check_url": f"{OTHER}/w"},
            "runs on https://sdsc.run.ai only",
        ),
        (
            "runai-test3",
            None,
            {"storage_keys": json.dumps({ORIGIN: ["logged-in-user-email"]})},
            "identity-source key",
        ),
        (
            "runai-test3",
            None,
            {"storage_keys": json.dumps({KC_ORIGIN: ["x", "logged-in-user-email"]})},
            "identity-source key",
        ),
    ],
)
def test_the_vault_refuses_what_the_recipe_does_not_cover(
    site: str, user: str | None, fields: dict, problem: str
) -> None:
    it = _items(_raw(site, user, **fields))[site]
    assert it.refused and problem in it.refused


def test_other_storage_keys_are_fine() -> None:
    it = _items(_raw("runai-test3", storage_keys=json.dumps({ORIGIN: ["theme"]})))[
        "runai-test3"
    ]
    assert not it.refused


# ---------------------------------------------------------------------------
# the broker's gates (an admin item that slipped past the vault)
# ---------------------------------------------------------------------------


class _Vault:
    def __init__(self, items: list[vault.SiteItem]) -> None:
        self._items = items

    def items(self) -> list[vault.SiteItem]:
        return self._items

    def secret(self, site: str) -> vault.Secret:
        raise AssertionError(f"no login may reach the vault ({site})")


class _NoRunner:
    calls = 0

    def __call__(self, item: Any, get_secret: Any) -> dict[str, Any]:
        raise AssertionError("the runner must not be reached")


def _broker(tmp_path: Path, items: list[vault.SiteItem]) -> Any:
    lim = limiter.Limiter(
        tmp_path / "l.json", cooldown_s=1800, min_interval_s=0, per_hour=50, per_day=100
    )
    return daemon.Broker(
        _Vault(items),  # type: ignore[arg-type]
        lim,
        tmp_path / "home",
        runner=_NoRunner(),
        clock=lambda: 1000.0,
    )


@pytest.mark.usefixtures("unconfirmed")
def test_the_broker_refuses_an_unconfirmed_admin_item(tmp_path: Path) -> None:
    good = _items(_raw("runai-admin", instance="admin"))["runai-admin"]
    assert not good.refused
    admin = vault.replace(good, privilege="admin")  # past the vault's check
    brk = _broker(tmp_path, [admin])
    resp = brk.handle({"op": "login", "site": "runai-admin"}, 501)
    assert resp["error"] == "identity_unproven" and resp["phase"] == "precheck"
    chal = brk.handle(
        {"op": "identity_challenge", "site": "runai-admin", "instance": "admin"},
        501,
        4242,
    )
    assert chal["error"] == "identity_unproven"

    class _Page:  # the broker's own proof never runs the recipe for it
        context = property(lambda _s: pytest.fail("evaluated"))

    assert (
        daemon.PlaywrightRunner._identity_verdict(_Page(), admin, admin.account_name)
        == identity.INDETERMINATE
    )


@pytest.mark.usefixtures("unconfirmed")
def test_the_client_refuses_an_unconfirmed_admin_item(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        browser, "_broker_request", lambda *_a, **_k: pytest.fail("asked the broker")
    )
    for entry in (_entry("runai-admin", "admin"), _entry("runai-x")):
        assert (
            browser._client_identity_proof(object(), entry["site"], entry, CHECK)
            == "identity_unproven"
        )


# ---------------------------------------------------------------------------
# RECIPE_JS against a routed fixture Run:ai, both evaluators
# ---------------------------------------------------------------------------


class _RunAi:
    """The fixture server: the token endpoint (`token_status`, the JWT of
    `claims`, or `token_body` verbatim) and the admin probe
    (`probe_status`, `probe_ctype`, `probe_redirect`); `sw` is the body of
    /sw.js when a test installs a service worker."""

    def __init__(self) -> None:
        self.claims: dict | None = None
        self.token = ""
        self.token_status = 200
        self.token_ctype = "application/json; charset=utf-8"
        self.token_body: Any = None
        self.token_redirect: str | None = None
        self.probe_status = 403
        self.probe_redirect: str | None = None
        self.probe_ctype = "application/json"
        self.probe_body: str | None = None  # None: by content type
        self.sw = ""
        self.posts: list[tuple[str, Any, str | None]] = []
        self.probes: list[tuple[str, bool]] = []

    def mint(self, name: str, **over: Any) -> str:
        self.claims = _claims(name, **over)
        self.token = _jwt(self.claims)
        return self.token

    def handle(self, route: Any) -> None:
        req = route.request
        url = urllib.parse.urlsplit(req.url)
        if req.resource_type == "document":
            route.fulfill(status=200, content_type="text/html", body="<p id=me>R</p>")
            return
        if url.path == "/sw.js" and self.sw:
            route.fulfill(status=200, content_type="text/javascript", body=self.sw)
            return
        if url.path == TOKEN_PATH:
            self._token(route, req)
        elif url.path == PROBE_PATH:
            bearer = req.headers.get("authorization") == f"Bearer {self.token}"
            self.probes.append((url.query, bearer))
            if self.probe_redirect:
                route.fulfill(status=302, headers={"Location": self.probe_redirect})
                return
            status = self.probe_status if bearer else 401
            body = self.probe_body
            if body is None:
                body = "[]" if "json" in self.probe_ctype else "<html>app</html>"
            route.fulfill(status=status, content_type=self.probe_ctype, body=body)
        else:
            route.fulfill(status=404, content_type="application/json", body="{}")

    def _token(self, route: Any, req: Any) -> None:
        try:
            sent = json.loads(req.post_data or "null")
        except ValueError:
            sent = None
        self.posts.append((req.method, sent, req.headers.get("content-type")))
        if self.token_redirect:
            route.fulfill(status=302, headers={"Location": self.token_redirect})
            return
        if req.method != "POST" or sent != BODY:
            route.fulfill(status=400, content_type="application/json", body="{}")
            return
        if self.token_status != 200 or self.claims is None and self.token_body is None:
            status = self.token_status if self.token_status != 200 else 401
            route.fulfill(status=status, content_type="application/json", body="{}")
            return
        body = self.token_body
        if body is None:
            body = {"accessToken": self.token, "idToken": _jwt({"sub": "x"})}
        route.fulfill(status=200, content_type=self.token_ctype, body=json.dumps(body))


Evaluator = Callable[[Any, str, Any], Any]
EVALUATORS = {
    "broker": daemon.evaluate_isolated,
    "client": browser._evaluate_isolated,
}


@pytest.fixture(params=sorted(EVALUATORS))
def ra(request: pytest.FixtureRequest) -> Iterator[tuple[Any, _RunAi, Evaluator]]:
    api = _RunAi()
    with routed_context(api.handle) as ctx:
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


def _no_leak(got: dict, api: _RunAi, *names: str) -> None:
    text = json.dumps(got)
    for secret in (api.token, *names, *(api.token.split(".") if api.token else [])):
        assert secret not in text and secret.lower() not in text
    assert set(got) <= {"state", "digest", "admin", "why", "status", "_nonce"}


@pytest.mark.launches_chrome
@CHROME
def test_match_and_mismatch(ra: tuple[Any, _RunAi, Evaluator]) -> None:
    page, api, run = ra
    me = _user()
    api.mint(f" {me.upper()} ")
    got = _run(page, run)
    assert got["state"] == "found" and got["admin"] is False
    assert _verdict(got, me, "user") == identity.MATCH
    assert _verdict(got, _user(), "user") == identity.WRONG_ACCOUNT
    assert _verdict(got, me, "admin") == identity.PRIVILEGE_MISMATCH
    # ONE refresh POST with the fixed JSON body, ONE probe with the token
    assert api.posts == [("POST", BODY, "application/json")]
    assert api.probes == [("subjectType=user", True)]
    _no_leak(got, api, me)


@pytest.mark.launches_chrome
@CHROME
def test_the_admin_probe(ra: tuple[Any, _RunAi, Evaluator]) -> None:
    page, api, run = ra
    me = _user()
    api.mint(me)
    api.probe_status = 200
    got = _run(page, run)
    assert got["admin"] is True
    assert _verdict(got, me, "admin") == identity.MATCH
    assert _verdict(got, me, "user") == identity.PRIVILEGE_MISMATCH
    for status in (500, 404, 401):
        api.probe_status = status
        got = _run(page, run)
        assert got["state"] == "found" and got["admin"] is None, status
        assert _verdict(got, me, "user") == identity.INDETERMINATE
    # the bit only from a JSON answer: an HTML 200 or 403 (an SPA fallback,
    # a WAF page) is no bit at all
    api.probe_ctype = "text/html; charset=utf-8"
    for status in (200, 403):
        api.probe_status = status
        got = _run(page, run)
        assert got["state"] == "found" and got["admin"] is None, status
        assert _verdict(got, me, "user") == identity.INDETERMINATE
        assert _verdict(got, me, "admin") == identity.INDETERMINATE
    api.probe_ctype = "application/json; charset=utf-8"
    assert _run(page, run)["admin"] is False  # 403 JSON: not admin
    api.probe_status, api.probe_redirect = 200, f"{OTHER}/x"
    got = _run(page, run)
    assert got["state"] == "found" and got["admin"] is None
    # an identity mismatch is still a mismatch without an admin bit
    assert _verdict(got, _user(), "user") == identity.WRONG_ACCOUNT


def _error_object(**over: Any) -> str:
    body: dict[str, Any] = {"code": 403, "message": "permission denied"}
    body.update(over)
    return json.dumps({k: v for k, v in body.items() if v is not _DROP})


@pytest.mark.launches_chrome
@CHROME
def test_the_admin_probe_text_plain_403(ra: tuple[Any, _RunAi, Evaluator]) -> None:
    """Live 2026-10-12 (runai-test3): Run:ai answers the non-admin's probe
    403 `text/plain; charset=utf-8` with its JSON error object. That body is
    the "not admin" answer whatever the content type; anything else in a
    non-JSON 403 (HTML, a JSON of another shape, an oversized body) is no
    bit, and a 200 still needs a JSON content type."""
    page, api, run = ra
    me = _user()
    api.mint(me)
    api.probe_status, api.probe_ctype = 403, "text/plain; charset=utf-8"
    api.probe_body = _error_object()
    got = _run(page, run)
    assert got["state"] == "found" and got["admin"] is False
    assert _verdict(got, me, "user") == identity.MATCH
    assert _verdict(got, me, "admin") == identity.PRIVILEGE_MISMATCH
    _no_leak(got, api, me)
    # no content type at all: the error object still decides
    api.probe_ctype = ""
    assert _run(page, run)["admin"] is False
    api.probe_ctype = "text/plain; charset=utf-8"
    for body in (
        "<html><body>403 Forbidden</body></html>",
        _error_object(message=_DROP),
        _error_object(code=_DROP),
        _error_object(extra="x"),
        _error_object(code="403"),
        _error_object(message=7),
        json.dumps([403, "permission denied"]),
        "null",
        "",
        _error_object(message="x" * (64 * 1024)),
    ):
        api.probe_body = body
        got = _run(page, run)
        assert got["state"] == "found" and got["admin"] is None, body[:40]
        assert _verdict(got, me, "user") == identity.INDETERMINATE
    # a 200 needs a JSON content type, even with a JSON body …
    api.probe_status, api.probe_body = 200, "[]"
    got = _run(page, run)
    assert got["state"] == "found" and got["admin"] is None
    assert _verdict(got, me, "admin") == identity.INDETERMINATE
    # … and a JSON body under its JSON content type
    api.probe_ctype, api.probe_body = "application/json", "<html>app</html>"
    assert _run(page, run)["admin"] is None
    api.probe_body = "[]"
    assert _run(page, run)["admin"] is True
    # a 401 with the error object is no bit (only the false statuses count)
    api.probe_status, api.probe_ctype = 401, "text/plain"
    api.probe_body = _error_object(code=401)
    assert _run(page, run)["admin"] is None


@pytest.mark.launches_chrome
@CHROME
def test_the_confirmed_admin_item_matches(ra: tuple[Any, _RunAi, Evaluator]) -> None:
    """Live 2026-10-12 (the admin account): its own token gets 200
    `application/json; charset=UTF-8` on the probe. With the confirmed recipe
    the admin item resolves to it and passes as `match`."""
    page, api, run = ra
    entry = _entry("runai-admin", "admin")
    recipe = identity.entry_recipe(entry)
    assert recipe is RECIPE and recipe.admin_true_confirmed
    me = _user()
    api.mint(me)
    api.probe_status, api.probe_ctype = 200, "application/json; charset=UTF-8"
    api.probe_body = json.dumps({"accessRules": [], "totalRecords": 0})
    nonce = secrets.token_hex(32)
    got = dict(
        run(page, identity.RECIPE_JS, identity.recipe_args(recipe, CHECK, nonce))
    )
    assert got["state"] == "found" and got["admin"] is True
    assert identity.local_verdict(got, nonce, me, "admin") == identity.MATCH
    assert identity.local_verdict(got, nonce, _user(), "admin") == (
        identity.WRONG_ACCOUNT
    )
    assert api.probes == [("subjectType=user", True)]
    _no_leak(got, api, me)


@pytest.mark.launches_chrome
@CHROME
def test_pinned_claims(ra: tuple[Any, _RunAi, Evaluator]) -> None:
    page, api, run = ra
    me = _user()
    bad: dict[str, dict[str, Any]] = {
        "azp other": {"azp": "another-client"},
        "azp missing": {"azp": _DROP},
        "iss other realm": {"iss": "https://app1.run.ai/auth/realms/master"},
        "iss suffix trick": {"iss": "https://app1.run.ai/auth/realms/sdsc-evil"},
        "iss http": {"iss": "http://app1.run.ai/auth/realms/sdsc"},
        "iss query": {"iss": f"{ISS}?x=1"},
        "iss not a string": {"iss": 7},
        "iss missing": {"iss": _DROP},
        "iss not a url": {"iss": "/auth/realms/sdsc"},
        "iss another host": {"iss": "https://other.run.ai/auth/realms/sdsc"},
        "iss a tenant path": {"iss": "https://app1.run.ai/x/auth/realms/sdsc"},
        "iss trailing slash": {"iss": f"{ISS}/"},
        "iss upper case": {"iss": ISS.upper()},
    }
    for case, over in bad.items():
        api.mint(me, **over)
        before = len(api.probes)
        got = _run(page, run)
        assert (got["state"], got["why"]) == ("indeterminate", "claim"), case
        assert len(api.probes) == before, case  # nothing more was sent
        _no_leak(got, api, me)
    for case, exp in {
        "expired": int(time.time()) - 5,
        "missing": _DROP,
        "a string": str(int(time.time()) + 300),
        "null": None,
    }.items():
        api.mint(me, exp=exp)
        got = _run(page, run)
        assert (got["state"], got["why"]) == ("indeterminate", "expired"), case
    api.mint(me)  # the exact issuer
    assert _run(page, run)["state"] == "found"


@pytest.mark.launches_chrome
@CHROME
def test_the_token_endpoint_answers(ra: tuple[Any, _RunAi, Evaluator]) -> None:
    page, api, run = ra
    me = _user()
    api.mint(me)
    api.token_status = 401
    got = _run(page, run)
    assert (got["state"], got["status"]) == ("logged_out", 401)
    assert not api.probes  # logged out: no probe
    api.token_status = 403
    assert _run(page, run)["state"] == "logged_out"
    api.token_status = 500
    got = _run(page, run)
    assert (got["state"], got["why"], got["status"]) == ("indeterminate", "status", 500)
    api.token_status, api.token_ctype = 200, "text/html"
    assert _run(page, run)["why"] == "content-type"
    api.token_ctype = "application/json"
    shapes = {
        "no access token": ({"idToken": api.token}, "token"),
        "token not a string": ({"accessToken": 7}, "token"),
        "empty token": ({"accessToken": ""}, "token"),
        "not a jwt": ({"accessToken": secrets.token_hex(20)}, "token"),
        "payload an array": ({"accessToken": _jwt([me])}, "token"),
        "an array": ([api.token], "schema"),
        "no name": (
            {"accessToken": _jwt(_claims(me, preferred_username=_DROP))},
            "identity",
        ),
        "a non-ASCII name": (
            {"accessToken": _jwt(_claims("zz-é@ws5r.example"))},
            "identity",
        ),
        "inherited name": (
            {
                "accessToken": _jwt(
                    _claims(
                        me,
                        preferred_username=_DROP,
                        __proto__={"preferred_username": me},
                    )
                )
            },
            "identity",
        ),
    }
    for case, (body, why) in shapes.items():
        api.token_body = body
        before = len(api.probes)
        got = _run(page, run)
        assert (got["state"], got["why"]) == ("indeterminate", why), case
        assert len(api.probes) == before, case
    api.token_body, api.token_redirect = None, f"{OTHER}/login"
    assert _run(page, run)["why"] == "redirect"


@pytest.mark.launches_chrome
@CHROME
def test_page_scripts_cannot_hook_the_recipe(ra: tuple[Any, _RunAi, Evaluator]) -> None:
    """The app's world replaces fetch, JSON, atob, Date and the hash: the
    main world is fooled, the isolated recipe is not."""
    page, api, run = ra
    real, fake = _user(), _user()
    api.mint(real, exp=int(time.time()) - 60)  # an EXPIRED token from the server
    forged = _jwt(_claims(fake))
    page.evaluate(
        """([forged, fakeClaims]) => {
          Response.prototype.json = async function () { return {accessToken: forged}; };
          const parse = JSON.parse;
          JSON.parse = (s) => {
            const v = parse(s); if (v && v.exp) v.exp = 4102444800; return v; };
          window.atob = () => JSON.stringify(fakeClaims);
          Date.now = () => 0;
          crypto.subtle.digest = async () => new ArrayBuffer(32);
        }""",
        [forged, _claims(fake)],
    )
    args = identity.recipe_args(RECIPE, CHECK, secrets.token_hex(32))
    hooked = page.evaluate(identity.RECIPE_JS, args)
    assert hooked["state"] == "found" and hooked["digest"] == "0" * 64  # fooled …
    # … and a replaced fetch answers whatever the app wants there
    page.evaluate(
        """t => { window.fetch = async () => new Response(
          JSON.stringify({accessToken: t}),
          {status: 200, headers: {'content-type': 'application/json'}}); }""",
        forged,
    )
    assert page.evaluate(identity.RECIPE_JS, args)["state"] != "found"
    got = _run(page, run)  # … the isolated world is not: the server's token
    assert (got["state"], got["why"]) == ("indeterminate", "expired")
    api.mint(real)
    got = _run(page, run)
    assert _verdict(got, real, "user") == identity.MATCH
    assert _verdict(got, fake, "user") == identity.WRONG_ACCOUNT
    _no_leak(got, api, real, fake)


@pytest.mark.launches_chrome
@CHROME
def test_a_page_on_another_origin_is_refused(ra: tuple[Any, _RunAi, Evaluator]) -> None:
    page, api, run = ra
    api.mint(_user())
    page.goto(f"{OTHER}/workloads")
    for check in (CHECK, f"{OTHER}/workloads"):  # the pinned origin either way
        got = _run(page, run, check)
        assert (got["state"], got["why"]) == ("indeterminate", "origin")
    assert not api.posts  # nothing was sent


# ---------------------------------------------------------------------------
# end to end: the client proof through the REAL broker
# ---------------------------------------------------------------------------


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
        self.dir = tempfile.mkdtemp(prefix="ws5r-")
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
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[tuple[Callable[[list[dict]], FakeBroker], _RunAi, list]]:
    from playwright.sync_api import (  # pylint: disable=import-outside-toplevel
        sync_playwright,
    )

    made: list[FakeBroker] = []
    cleared: list = []
    api = _RunAi()

    def make(raws: list[dict]) -> FakeBroker:
        fake = FakeBroker(raws, tmp_path)
        monkeypatch.setenv("LOGIN_BROKER_SOCKET", fake.path)
        browser._BROKER_SITES_CACHE.clear()
        made.append(fake)
        return fake

    with sync_playwright() as pw:
        chromium = pw.chromium.launch(headless=True)
        try:
            ctx = chromium.new_context()
            ctx.route("**/*", api.handle)
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

            monkeypatch.setattr(browser, "_with_prepared_background_page", probe_tab)
            monkeypatch.setattr(browser, "_broker_note_session_age", lambda *_a: None)

            def clear_storage(_port: int, site: str, plan: Any) -> int:
                cleared.append((site, "storage", dict(plan)))
                return sum(len(keys) for keys in plan.values())

            monkeypatch.setattr(browser, "_broker_clear_cookies", clear)
            monkeypatch.setattr(browser, "_broker_clear_foreign_storage", clear_storage)
            yield make, api, cleared
        finally:
            chromium.close()
            for fake in made:
                fake.close()


def _record(path: Path, rc: int) -> dict:
    browser._result_write(rc)
    rec: dict = json.loads(path.read_text())
    return rec


def _pair(test3: str, admin: str) -> list[dict]:
    return [
        _raw("runai-test3", test3),
        _raw("runai-admin", admin, privilege="admin", instance="admin"),
    ]


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
def test_e2e_the_user_member_is_proven_once_and_nothing_leaks(
    e2e: Any, result_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    make, api, _cleared = e2e
    test3, admin = _user(), _user()
    fake = make(_pair(test3, admin))
    token = api.mint(test3)
    assert browser._broker_logged_in(9222, "runai-test3") == 0
    rec = _record(result_file, 0)
    assert rec["identity"] == "match" and rec["multi_account"] is True
    assert fake.ops == ["sites", "identity_challenge", "identity_answer"]
    # the recipe ran ONCE in this check: one refresh, one probe
    assert len(api.posts) == 1 and len(api.probes) == 1
    claims = json.dumps(api.claims)
    _leak_free(
        [test3, admin, token, *token.split("."), claims, *fake.secrets],
        capsys,
        result_file,
    )


@pytest.mark.launches_chrome
@CHROME
def test_e2e_another_account_is_wrong_account_and_cleared(
    e2e: Any, result_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    make, api, cleared = e2e
    test3, admin, other = _user(), _user(), _user()
    make(_pair(test3, admin))
    api.mint(other)
    assert browser._broker_logged_in(9222, "runai-test3") == 2
    rec = _record(result_file, 2)
    assert rec["code"] == "wrong_account" and rec["phase"] == "client-proof"
    # cookies, and the page's own account claim on the recipe's origin
    assert cleared == [
        ("runai-test3", "clear-foreign"),
        ("runai-test3", "storage", {ORIGIN: ["logged-in-user-email"]}),
    ]
    _leak_free([test3, admin, other, api.token], capsys, result_file)


@pytest.mark.launches_chrome
@CHROME
def test_e2e_the_admin_member_is_proven(
    e2e: Any,
    result_file: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    make, api, _cleared = e2e
    test3, admin = _user(), _user()
    fake = make(_pair(test3, admin))
    token = api.mint(admin)
    api.probe_status, api.probe_ctype = 200, "application/json; charset=UTF-8"
    monkeypatch.setattr(browser, "INSTANCE", "admin")
    assert browser._broker_logged_in(9224, "runai-admin") == 0
    rec = _record(result_file, 0)
    assert rec["identity"] == "match" and rec["multi_account"] is True
    assert fake.ops == ["sites", "identity_challenge", "identity_answer"]
    assert len(api.posts) == 1 and len(api.probes) == 1
    _leak_free(
        [test3, admin, token, *token.split("."), *fake.secrets], capsys, result_file
    )


@pytest.mark.launches_chrome
@CHROME
@pytest.mark.usefixtures("unconfirmed")
def test_e2e_an_unconfirmed_admin_member_stays_unproven(
    e2e: Any, result_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    make, api, _cleared = e2e
    test3, admin = _user(), _user()
    make(_pair(test3, admin))
    api.mint(admin)
    api.probe_status = 200
    monkeypatch.setattr(browser, "INSTANCE", "admin")
    assert browser._broker_logged_in(9224, "runai-admin") == 2
    rec = _record(result_file, 2)
    assert rec["code"] == "identity_unproven"
    assert not api.posts  # never asked the site


@pytest.mark.launches_chrome
@CHROME
def test_broker_reuse_needs_the_same_server_proof(
    ra: tuple[Any, _RunAi, Evaluator],
) -> None:
    """The broker's own profile reuse runs the same recipe: its account →
    export; logged out → log in; another account → reset + ONE login; a
    missing artifact (no token in the answer) → stop, nothing reserved."""
    page, api, _run_unused = ra
    me = _user()
    item = _items(_raw("runai-test3", me))["runai-test3"]
    runner = daemon.PlaywrightRunner(REPO, dev=True)
    api.mint(me)
    assert runner._identity_reuse(page, item) == "ok"
    api.mint(_user())
    assert runner._identity_reuse(page, item) == "reset"
    api.token_status = 401
    assert runner._identity_reuse(page, item) == "login"
    api.token_status, api.token_body = 200, {"idToken": api.token}
    with pytest.raises(daemon.IdentityMismatch) as err:
        runner._identity_reuse(page, item)
    assert err.value.code == "identity_indeterminate"
    assert len(api.posts) == 4  # one refresh per proof


@pytest.mark.launches_chrome
@CHROME
def test_e2e_a_missing_artifact_never_starts_a_login(
    e2e: Any, result_file: Path
) -> None:
    make, api, cleared = e2e
    test3, admin = _user(), _user()
    fake = make(_pair(test3, admin))
    api.mint(test3)
    api.token_body = {"idToken": api.token}  # 200, but no access token
    assert browser._broker_already(9222, "runai-test3") == 2
    rec = _record(result_file, 2)
    assert rec["code"] == "identity_indeterminate" and rec["identity_why"] == "token"
    assert "login" not in fake.ops and not cleared
    assert len(api.posts) == 1


def test_the_foreign_clear_takes_the_page_claim_key() -> None:
    """A token-endpoint recipe has no session in storage, but the page's own
    account claim would show the foreign e-mail: it goes, on the recipe's
    origin only."""
    assert identity.foreign_storage_keys(_entry()) == {ORIGIN: ["logged-in-user-email"]}
    assert not identity.foreign_storage_keys(_entry(check_url=f"{OTHER}/w"))
    assert not identity.foreign_storage_keys(_entry(identity="gitlab"))


# A service worker of the Run:ai origin that answers the token endpoint with
# a token of ANOTHER account (FORGED is replaced per test).
_SW = """
self.addEventListener('install', e => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(clients.claim()));
self.addEventListener('fetch', e => {
  if (new URL(e.request.url).pathname === '/api/v1/token')
    e.respondWith(new Response(JSON.stringify({accessToken: FORGED}),
      {status: 200, headers: {'content-type': 'application/json'}}));
});
"""


@pytest.mark.launches_chrome
@CHROME
def test_a_service_worker_never_answers_the_token_endpoint(
    ra: tuple[Any, _RunAi, Evaluator],
) -> None:
    """The recipe's world bypasses the origin's service worker: a worker
    that answers /api/v1/token with another account's token fools the main
    world, never the recipe."""
    page, api, run = ra
    real, fake = _user(), _user()
    api.mint(real)
    api.sw = _SW.replace("FORGED", json.dumps(_jwt(_claims(fake))))
    page.goto(f"{ORIGIN}/elsewhere")
    page.evaluate(
        "async () => { await navigator.serviceWorker.register('/sw.js');"
        " await navigator.serviceWorker.ready; }"
    )
    page.goto(CHECK)
    assert page.evaluate("() => !!navigator.serviceWorker.controller")
    nonce = secrets.token_hex(32)
    hooked = page.evaluate(
        identity.RECIPE_JS, identity.recipe_args(RECIPE, CHECK, nonce)
    )
    assert hooked["state"] == "found"  # the worker answered the main world …
    # (the forged account's digest; the server refuses the forged bearer on
    # the admin probe, so there is no admin bit)
    norm = identity.normalize_identity(fake)
    assert norm is not None
    assert hooked["digest"] == identity.challenge_digest(nonce, norm)
    assert hooked["admin"] is None
    posts = len(api.posts)
    got = _run(page, run)  # … the recipe's world went to the server
    assert _verdict(got, real, "user") == identity.MATCH
    assert _verdict(got, fake, "user") == identity.WRONG_ACCOUNT
    assert len(api.posts) == posts + 1
