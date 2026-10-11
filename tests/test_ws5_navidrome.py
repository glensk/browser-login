"""WS5 (tp#909): the reviewed `navidrome` identity recipe and the spec
validation of identity recipes (broker/identity.py).

Navidrome keeps its session in localStorage `token` (a JWT whose `uid` claim
names the user); ``GET /api/user/<uid>`` with ``x-nd-authorization: Bearer
<token>`` answers the user record. The recipe runs in a throwaway headless
Chromium against a routed fixture Navidrome (no network), through BOTH
isolated-world evaluators — the broker's (``daemon.evaluate_isolated``) and
the client's (``browser._evaluate_isolated``) — which must agree. Account
names and tokens are generated per run: no credential-shaped literal.
"""

from __future__ import annotations

# pylint: disable=protected-access,missing-function-docstring,missing-class-docstring
# pylint: disable=import-error,wrong-import-position,redefined-outer-name
import base64
import dataclasses
import json
import secrets
import sys
import urllib.parse
from collections.abc import Callable, Iterator
from typing import Any

import pytest
from chromium_page import REPO, chromium_available, load_script, routed_context

sys.path.insert(0, str(REPO))

from broker import daemon, identity  # noqa: E402

browser = load_script("bin/browser.py", "ws5nd_browser")

ND = "https://music.ws5nd.example"
CHECK = f"{ND}/app/#/album/recentlyAdded"
OTHER = "https://other.ws5nd.example"
HEADER = "x-nd-" + "authorization"


def _user() -> str:
    return f"zz-{secrets.token_hex(5)}"


def _uid() -> str:
    return secrets.token_hex(11)


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _jwt(claims: Any) -> str:
    """A JWT-shaped string built at run time: header, payload, a random
    signature (the recipe never checks it; the fixture server compares the
    whole token)."""
    head = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body = _b64url(json.dumps(claims).encode())
    return f"{head}.{body}.{_b64url(secrets.token_bytes(32))}"


# ---------------------------------------------------------------------------
# the reviewed spec
# ---------------------------------------------------------------------------


def test_navidrome_recipe_is_reviewed_and_usable() -> None:
    recipe = identity.IDENTITIES["navidrome"]
    assert identity.usable_recipe("navidrome") is recipe
    assert recipe.live_confirmed and recipe.forms == ("username",)
    assert recipe.auth == "jwt-local-storage" and recipe.token_key == "token"
    assert (recipe.auth_header, recipe.auth_scheme) == (HEADER, "Bearer ")
    assert (recipe.path, recipe.path_claim, recipe.claim_field) == (
        "/api/user/",
        "uid",
        ("id",),
    )
    assert recipe.id_field == ("userName",) and recipe.admin_field == ("isAdmin",)
    # the API lives at the origin root, whatever the app's path
    args = identity.recipe_args(recipe, CHECK, "0" * 64)
    assert args["origin"] == ND and args["path"] == "/api/user/"
    assert args["auth_header"] == HEADER and args["claim_field"] == ["id"]


def test_existing_recipes_send_what_they_sent() -> None:
    """gitlab / audiobookshelf: the new arguments change nothing they send."""
    gl = identity.recipe_args(identity.IDENTITIES["gitlab"], f"{ND}/x", "0" * 64)
    assert gl["auth"] == "cookie" and gl["path"] == "/api/v4/user"
    assert gl["path_claim"] == "" and gl["claim_field"] is None
    abs_ = identity.IDENTITIES["audiobookshelf"]
    args = identity.recipe_args(abs_, f"{ND}/audiobookshelf/x", "0" * 64)
    assert args["auth"] == "bearer-local-storage"
    assert (args["auth_header"], args["auth_scheme"]) == ("Authorization", "Bearer ")
    assert args["path"] == "/audiobookshelf/api/me" and args["path_claim"] == ""


_ND_SPEC = identity.IDENTITIES["navidrome"]


@pytest.mark.parametrize(
    ("change", "problem"),
    [
        ({"name": "Bad Name"}, "bad name"),
        ({"auth": "basic"}, "bad auth"),
        ({"path": "api/user/"}, "absolute path"),
        ({"path": "//evil.example/"}, "absolute path"),
        ({"path": "/api/user/#x"}, "bad path"),
        ({"id_field": ()}, "no identity field"),
        ({"id_field": ("user name",)}, "bad field path"),
        ({"claim_field": ("__proto__ x",)}, "bad field path"),
        ({"token_key": ""}, "needs token_key"),
        ({"auth_header": "Cookie"}, "bad auth_header"),
        ({"auth_header": "Accept"}, "bad auth_header"),
        ({"auth_header": "Sec-Fetch-Site"}, "bad auth_header"),
        ({"auth_header": "Access-Control-Request-Headers"}, "bad auth_header"),
        ({"auth_header": "access-control-request-x"}, "bad auth_header"),
        ({"auth_header": "x nd"}, "bad auth_header"),
        ({"auth_scheme": "Bearer"}, "bad auth_scheme"),
        ({"auth_scheme": "Bearer\n"}, "bad auth_scheme"),
        ({"path_claim": "", "claim_field": None}, "jwt-local-storage needs path_claim"),
        ({"path_claim": ""}, "bad path_claim"),
        ({"path_claim": "u-id"}, "bad path_claim"),
        ({"claim_field": None}, "needs claim_field"),
        ({"path": "/api/user"}, "ending in '/'"),
        ({"path": "/api/user?x=/"}, "ending in '/'"),
        ({"base_segments": ("music",)}, "no base_segments"),
        ({"auth": "bearer-local-storage"}, "path_claim needs jwt-local-storage"),
    ],
)
def test_a_malformed_spec_is_refused(change: dict, problem: str) -> None:
    with pytest.raises(ValueError, match="identity recipe") as err:
        dataclasses.replace(_ND_SPEC, **change)
    assert problem in str(err.value)


def test_a_claim_needs_a_jwt_recipe_and_a_cookie_recipe_needs_no_header() -> None:
    gl = identity.IDENTITIES["gitlab"]
    with pytest.raises(ValueError, match="path_claim needs jwt-local-storage"):
        dataclasses.replace(gl, path_claim="uid", claim_field=("id",))
    # a cookie recipe's (unused) header is not validated: nothing is sent in it
    assert dataclasses.replace(gl, auth_header="Cookie").auth == "cookie"


# ---------------------------------------------------------------------------
# foreign_storage_keys: what a wrong_account check clears besides cookies
# ---------------------------------------------------------------------------


def _entry(identity_name: str, **extra: Any) -> dict:
    base = {
        "site": "nd-albert",
        "identity": identity_name,
        "check_url": CHECK,
        "fill_origins": [ND],
        "storage_keys": {ND: ["token", "userId", "subsonic-token"]},
    }
    base.update(extra)
    return base


def test_foreign_storage_keys_of_a_storage_token_item() -> None:
    assert identity.foreign_storage_keys(_entry("navidrome")) == {
        ND: ["subsonic-token", "token", "userId"]
    }
    sso = "https://sso.ws5nd.example"
    abs_entry = _entry(
        "audiobookshelf",
        check_url=f"{ND}/audiobookshelf/library",
        fill_origins=[ND, f"{ND}:443", OTHER, sso],
        storage_keys={
            ND: ["user"],
            sso: ["sso-session"],
            "https://idp.ws5nd.example": ["idp"],
        },
    )
    # check + fill origins only (default port folded); the recipe's token
    # key on the CHECK origin only (a fill origin may be a shared SSO
    # provider: only its declared keys); a fill origin with no declared key
    # is left alone (OTHER); never a storage origin that is neither (idp)
    assert identity.foreign_storage_keys(abs_entry) == {
        ND: ["token", "user"],
        sso: ["sso-session"],
    }
    # the check origin keeps the token key even with nothing declared
    bare = _entry("navidrome", storage_keys={})
    assert identity.foreign_storage_keys(bare) == {ND: ["token"]}


@pytest.mark.parametrize(
    "entry",
    [
        _entry("gitlab"),  # a cookie session: nothing in storage
        _entry("dsm"),  # not usable
        _entry("runai"),  # unknown
        _entry(
            "navidrome", check_url="http://music.ws5nd.example/app/", fill_origins=[]
        ),
    ],
)
def test_foreign_storage_keys_is_empty_otherwise(entry: dict) -> None:
    assert not identity.foreign_storage_keys(entry)


# ---------------------------------------------------------------------------
# RECIPE_JS against a routed fixture Navidrome, both evaluators
# ---------------------------------------------------------------------------


CHROME = pytest.mark.skipif(
    not chromium_available(), reason="Playwright Chromium missing"
)


class _Navidrome:
    """The fixture server: `users` by id, the one valid `token`; overrides
    for the record (`record`), the status and the content type."""

    def __init__(self) -> None:
        self.users: dict[str, dict] = {}
        self.token = ""
        self.record: dict | None = None
        self.status: int | None = None
        self.ctype = "application/json"
        self.seen: list[tuple[str, str | None, str | None]] = []

    def handle(self, route: Any) -> None:
        req = route.request
        url = urllib.parse.urlsplit(req.url)
        if req.resource_type == "document":
            route.fulfill(status=200, content_type="text/html", body="<div id=app>")
            return
        self.seen.append(
            (url.path, req.headers.get(HEADER), req.headers.get("authorization"))
        )
        if not url.path.startswith("/api/user/"):
            route.fulfill(status=404, content_type="application/json", body="{}")
            return
        if req.headers.get(HEADER) != f"Bearer {self.token}" or not self.token:
            route.fulfill(
                status=401,
                content_type="application/json",
                body=json.dumps({"error": "Authentication required"}),
            )
            return
        if self.status is not None:
            route.fulfill(status=self.status, content_type=self.ctype, body="{}")
            return
        record = self.record or self.users.get(url.path.rsplit("/", 1)[1])
        if record is None:
            route.fulfill(status=404, content_type="application/json", body="{}")
            return
        route.fulfill(status=200, content_type=self.ctype, body=json.dumps(record))

    def add(self, name: str, admin: Any = False) -> str:
        uid = _uid()
        self.users[uid] = {
            "id": uid,
            "userName": name,
            "name": "Someone",
            "email": "",
            "isAdmin": admin,
            "lastLoginAt": "2026-10-11T00:00:00Z",
            "libraries": [],
        }
        return uid

    def login(self, page: Any, uid: Any, claims: dict | None = None) -> str:
        """The app's session: a JWT with `uid` in localStorage `token`."""
        payload = {"exp": 4102444800, "iat": 1760000000, "iss": "ND", "sub": "x"}
        if uid is not None:
            payload["uid"] = uid
        payload.update(claims or {})
        self.token = _jwt(payload)
        page.evaluate("t => localStorage.setItem('token', t)", self.token)
        return self.token


Evaluator = Callable[[Any, str, Any], Any]
EVALUATORS = {
    "broker": daemon.evaluate_isolated,
    "client": browser._evaluate_isolated,
}


@pytest.fixture(params=sorted(EVALUATORS))
def nd(request: pytest.FixtureRequest) -> Iterator[tuple[Any, _Navidrome, Evaluator]]:
    api = _Navidrome()
    with routed_context(api.handle) as ctx:
        page = ctx.new_page()
        page.goto(CHECK)
        yield page, api, EVALUATORS[request.param]


def _run(page: Any, run: Evaluator, check: str = CHECK) -> dict:
    nonce = secrets.token_hex(32)
    args = identity.recipe_args(identity.IDENTITIES["navidrome"], check, nonce)
    got = dict(run(page, identity.RECIPE_JS, args))
    got["_nonce"] = nonce
    return got


def _verdict(got: dict, name: str, privilege: str) -> str:
    return identity.local_verdict(got, got["_nonce"], name, privilege)


@pytest.mark.launches_chrome
@CHROME
def test_match_and_mismatch(nd: tuple[Any, _Navidrome, Evaluator]) -> None:
    page, api, run = nd
    me = _user()
    uid = api.add(f" {me.upper()} ")
    api.login(page, uid)
    got = _run(page, run)
    assert got["state"] == "found" and got["admin"] is False
    assert _verdict(got, me, "user") == identity.MATCH
    assert _verdict(got, _user(), "user") == identity.WRONG_ACCOUNT
    assert _verdict(got, me, "admin") == identity.PRIVILEGE_MISMATCH
    # the API at the origin root, the token in Navidrome's header, no
    # Authorization header, and never the name or the token in the answer
    assert api.seen[-1] == (f"/api/user/{uid}", f"Bearer {api.token}", None)
    assert me not in json.dumps(got) and api.token not in json.dumps(got)


@pytest.mark.launches_chrome
@CHROME
def test_admin_bit(nd: tuple[Any, _Navidrome, Evaluator]) -> None:
    page, api, run = nd
    root = _user()
    api.login(page, api.add(root, admin=True))
    got = _run(page, run)
    assert got["admin"] is True
    assert _verdict(got, root, "admin") == identity.MATCH
    assert _verdict(got, root, "user") == identity.PRIVILEGE_MISMATCH
    for weird in ("true", 1, None):  # any other type: no admin bit
        api.login(page, api.add(root, admin=weird))
        got = _run(page, run)
        assert got["state"] == "found" and got["admin"] is None
        assert _verdict(got, root, "user") == identity.INDETERMINATE


@pytest.mark.launches_chrome
@CHROME
def test_another_users_record_is_indeterminate(
    nd: tuple[Any, _Navidrome, Evaluator],
) -> None:
    """An admin token can read any user: the record must be the token's own."""
    page, api, run = nd
    me, other = _user(), _user()
    mine = api.add(me, admin=True)
    theirs = api.add(other)
    api.login(page, mine)
    api.record = api.users[theirs]  # the server answers another user's record
    got = _run(page, run)
    assert (got["state"], got["why"]) == ("indeterminate", "claim")
    api.record = {k: v for k, v in api.users[mine].items() if k != "id"}  # no id
    assert _run(page, run)["why"] == "claim"


@pytest.mark.launches_chrome
@CHROME
def test_missing_and_garbage_tokens(nd: tuple[Any, _Navidrome, Evaluator]) -> None:
    page, api, run = nd
    got = _run(page, run)  # no token at all
    assert (got["state"], got["why"]) == ("logged_out", "no token")
    uid = api.add(_user())
    garbage = {
        "not a jwt": secrets.token_hex(20),
        "two parts": f"{_b64url(b'{}')}.{_b64url(secrets.token_bytes(8))}",
        "payload not json": ".".join(
            _b64url(x) for x in (b"{}", b"\xff\xfe not json", b"sig")
        ),
        "payload an array": _jwt([uid]),
        "bad base64": f"{_b64url(b'{}')}.a.{_b64url(b'sig')}",
        "spaces": f"{_b64url(b'{}')}.{_b64url(b'{}')} .x",
    }
    for case, token in garbage.items():
        page.evaluate("t => localStorage.setItem('token', t)", token)
        before = len(api.seen)
        got = _run(page, run)
        assert (got["state"], got["why"]) == ("indeterminate", "token"), case
        assert len(api.seen) == before, case  # nothing was sent
    bad_claims = (None, "", "..", "../../api/admin", "a/b", "a%2Fb", "a?b", "a#b")
    for claim in (*bad_claims, "x" * 129, 42, [uid]):
        api.login(page, claim)
        before = len(api.seen)
        got = _run(page, run)
        assert (got["state"], got["why"]) == ("indeterminate", "claim"), claim
        assert len(api.seen) == before, claim
    # a uid claim inherited from the prototype is not the token's own
    api.login(page, None, {"__proto__": {"uid": uid}})
    assert _run(page, run)["why"] == "claim"


@pytest.mark.launches_chrome
@CHROME
def test_401_and_non_json(nd: tuple[Any, _Navidrome, Evaluator]) -> None:
    page, api, run = nd
    uid = api.add(_user())
    api.login(page, uid)
    api.token = secrets.token_hex(8)  # the server no longer accepts it
    got = _run(page, run)
    assert (got["state"], got["status"]) == ("logged_out", 401)
    api.login(page, uid)
    api.status = 403
    assert _run(page, run)["state"] == "logged_out"
    api.status = 500
    assert _run(page, run)["state"] == "indeterminate"
    api.status, api.ctype = None, "text/html"
    got = _run(page, run)
    assert (got["state"], got["why"]) == ("indeterminate", "content-type")


@pytest.mark.launches_chrome
@CHROME
def test_page_scripts_cannot_hook_the_recipe(
    nd: tuple[Any, _Navidrome, Evaluator],
) -> None:
    """The app's world replaces fetch, Response.json, JSON.parse, atob and the
    hash: the main world is fooled, the isolated recipe is not."""
    page, api, run = nd
    real, fake = _user(), _user()
    uid = api.add(real)
    api.login(page, uid)
    page.evaluate(
        """([n, uid]) => {
          const rec = {id: uid, userName: n, isAdmin: true};
          Response.prototype.json = async function () { return rec; };
          const parse = JSON.parse;
          JSON.parse = (s) => { const v = parse(s); if (v && v.uid) v.uid = uid; return v; };
          window.atob = () => JSON.stringify({uid: uid});
          crypto.subtle.digest = async () => new ArrayBuffer(32);
        }""",
        [fake, uid],
    )
    args = identity.recipe_args(
        identity.IDENTITIES["navidrome"], CHECK, secrets.token_hex(32)
    )
    hooked = page.evaluate(identity.RECIPE_JS, args)
    assert hooked["digest"] == "0" * 64  # the main world is hooked …
    # … and a replaced fetch answers whatever the app wants there
    page.evaluate(
        """rec => { window.fetch = async () => new Response(JSON.stringify(rec),
          {status: 200, headers: {'content-type': 'application/json'}}); }""",
        {"id": uid, "userName": fake, "isAdmin": True},
    )
    assert page.evaluate(identity.RECIPE_JS, args)["state"] != "found"
    got = _run(page, run)  # … the isolated world is not
    assert got["admin"] is False
    assert _verdict(got, real, "user") == identity.MATCH
    assert _verdict(got, fake, "user") == identity.WRONG_ACCOUNT


@pytest.mark.launches_chrome
@CHROME
def test_a_page_on_another_origin_is_refused(
    nd: tuple[Any, _Navidrome, Evaluator],
) -> None:
    page, api, run = nd
    api.login(page, api.add(_user()))
    page.goto(f"{OTHER}/app/")
    got = _run(page, run)
    assert (got["state"], got["why"]) == ("indeterminate", "origin")
