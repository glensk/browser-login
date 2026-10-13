"""WS5: the reviewed `dsm` identity recipe (syno-token, DSM 7).

The recipe obtains the SynoToken from DSM itself (``SYNO.API.Auth`` method
``token``, the session cookie) in a CDP isolated world — never the page's
``window.SYNO`` global —, reads ``data.username`` of ``SYNO.Core.NormalUser``
with that token, and takes the admin bit from ``SYNO.Core.User`` ``list``
in DSM's API envelope (success true = admin, error 105 = not admin, anything
else no bit). Only the token request's error 106/107/119 is logged out; once
it succeeded, any error is indeterminate. Both the "not admin" and the
"admin" answer are live-confirmed (2026-10-13): readonly, user and admin
items are all proof-ready.

The recipe runs in a throwaway headless Chromium against a routed fixture
DSM (no network), through BOTH isolated-world evaluators. Account names and
tokens are built per run: no credential-shaped literal.
"""

from __future__ import annotations

# pylint: disable=protected-access,missing-function-docstring,missing-class-docstring
# pylint: disable=import-error,wrong-import-position,redefined-outer-name
# pylint: disable=too-many-instance-attributes
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

from broker import daemon, identity, vault  # noqa: E402

browser = load_script("bin/browser.py", "ws5dsm_browser")

RECIPE = identity.IDENTITIES["dsm"]
ORIGIN = "https://synology.dom42.space"
CHECK = f"{ORIGIN}/"
OTHER = "https://other.ws5dsm.example"
ENTRY = "/webapi/entry.cgi"
TOKEN_API = "SYNO.API.Auth"
USER_API = "SYNO.Core.NormalUser"
PROBE_API = "SYNO.Core.User"
_LOGIN_KEY = "pass" + "word"
CHROME = pytest.mark.skipif(
    not chromium_available(), reason="Playwright Chromium missing"
)


def _user() -> str:
    """A fresh account name (never a literal in this file)."""
    return f"zz{secrets.token_hex(5)}"


# ---------------------------------------------------------------------------
# the reviewed spec
# ---------------------------------------------------------------------------


def test_the_dsm_recipe_is_reviewed() -> None:
    assert identity.usable_recipe("dsm") is RECIPE
    assert RECIPE.live_confirmed and RECIPE.auth == "syno-token"
    assert RECIPE.admin_false_confirmed and RECIPE.admin_true_confirmed
    assert RECIPE.allowed_sites == ("dsm-albert", "dsm-readonly")
    assert RECIPE.origin == ORIGIN and RECIPE.admin_field is None
    assert RECIPE.forms == ("username",)
    assert RECIPE.logged_out_codes == (106, 107, 119)
    assert RECIPE.admin_probe_false_codes == (105,)
    args = identity.recipe_args(RECIPE, CHECK, "0" * 64)
    assert args["origin"] == ORIGIN
    assert args["path"] == f"{ENTRY}?api={USER_API}&method=get&version=1"
    assert args["syno_token_path"] == f"{ENTRY}?api={TOKEN_API}&method=token&version=6"
    assert args["syno_token_field"] == ["data", "synotoken"]
    assert args["admin_probe"] == (
        f"{ENTRY}?api={PROBE_API}&method=list&version=1&limit=1"
    )
    assert args["admin_probe_false_codes"] == [105]
    assert args["id_field"] == ["data", "username"]
    assert args["ok_field"] == ["success"]
    assert args["error_code_field"] == ["error", "code"]
    # no JWT machinery
    assert not args["token_body"] and args["token_field"] is None
    assert not args["issuer"] and not args["admin_probe_error_shape"]
    # the pinned origin wins over a check URL elsewhere (the page check fails)
    assert identity.recipe_args(RECIPE, f"{OTHER}/x", "0" * 64)["origin"] == ORIGIN
    # a SynoToken session lives in cookies: nothing in localStorage to clear
    assert not identity.foreign_storage_keys(
        {"identity": "dsm", "site": "dsm-readonly", "check_url": CHECK}
    )


def test_the_other_recipes_send_no_syno_fields() -> None:
    for name, recipe in identity.IDENTITIES.items():
        if name == "dsm":
            continue
        args = identity.recipe_args(recipe, f"{OTHER}/x", "0" * 64)
        assert not args["syno_token_path"] and args["syno_token_field"] is None
        assert not args["admin_probe_false_codes"]


@pytest.mark.parametrize(
    ("change", "problem"),
    [
        ({"syno_token_path": ""}, "syno_token_path"),
        ({"syno_token_path": "webapi/x"}, "syno_token_path"),
        ({"syno_token_path": "//evil.example/x"}, "syno_token_path"),
        ({"syno_token_path": "/webapi/x#y"}, "syno_token_path"),
        ({"syno_token_field": None}, "syno_token_field"),
        ({"syno_token_field": ("data", "a b")}, "bad field path"),
        ({"ok_field": None}, "ok_field and error_code_field"),
        ({"error_code_field": None}, "ok_field and error_code_field"),
        ({"logged_out_codes": ()}, "logged_out_codes"),
        ({"logged_out_codes": (True,)}, "logged_out_codes"),
        ({"admin_field": ("data", "is_admin")}, "admin bit from admin_probe"),
        ({"admin_probe": ""}, "admin_probe"),
        ({"admin_probe": "//evil.example/x"}, "admin_probe"),
        ({"admin_probe_false_codes": ()}, "admin_probe_false_codes"),
        ({"admin_probe_false_codes": ("105",)}, "admin_probe_false_codes"),
        ({"admin_probe_false_codes": (105, 119)}, "admin_probe_false_codes"),
        ({"base_segments": ("x",)}, "no base_segments"),
        ({"allowed_sites": ()}, "allowed_sites and an origin"),
        ({"origin": ""}, "allowed_sites and an origin"),
        ({"origin": f"{ORIGIN}/"}, "exact https origin"),
        ({"issuer": "https://synology.dom42.space/x"}, "token fields need"),
        ({"token_field": ("t",)}, "token fields need"),
        ({"admin_probe_error_shape": ("code", "message")}, "token fields need"),
        ({"client_id": "x"}, "oidc fields need"),
    ],
)
def test_a_malformed_syno_spec_is_refused(change: dict, problem: str) -> None:
    with pytest.raises(ValueError, match="identity recipe") as err:
        dataclasses.replace(RECIPE, **change)
    assert problem in str(err.value)


def test_syno_fields_need_the_syno_auth() -> None:
    gl = identity.IDENTITIES["gitlab"]
    for change in (
        {"syno_token_path": "/x"},
        {"syno_token_field": ("data", "t")},
        {"admin_probe_false_codes": (105,)},
    ):
        with pytest.raises(ValueError, match="syno fields need auth syno-token"):
            dataclasses.replace(gl, **change)
    with pytest.raises(ValueError, match="token fields need"):
        dataclasses.replace(gl, admin_probe="/x")


# ---------------------------------------------------------------------------
# who may use it: sites, origin, privilege
# ---------------------------------------------------------------------------


def _entry(
    site: str = "dsm-readonly", privilege: str = "readonly", **over: Any
) -> dict:
    entry = {
        "site": site,
        "identity": "dsm",
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
            "dsm", site="dsm-readonly", check_url=CHECK, privilege="readonly"
        )
        == ""
    )
    assert identity.proof_ready(_entry())
    assert identity.entry_recipe(_entry()) is RECIPE
    # a user item of either site: the "not admin" answer is confirmed
    assert identity.proof_ready(_entry("dsm-albert", "user"))
    # the admin answer is live-confirmed too: the admin item is proof-ready
    assert (
        identity.recipe_refusal(
            "dsm", site="dsm-albert", check_url=CHECK, privilege="admin"
        )
        == ""
    )
    assert identity.proof_ready(_entry("dsm-albert", "admin"))
    assert identity.entry_recipe(_entry("dsm-albert", "admin")) is RECIPE
    refusals = [
        ("dsm-x", CHECK, "reviewed for dsm-albert, dsm-readonly only"),
        ("dsm-readonly", f"{OTHER}/", f"runs on {ORIGIN} only"),
        ("dsm-readonly", f"{ORIGIN}:5001/", f"runs on {ORIGIN} only"),
        ("dsm-readonly", "http://synology.dom42.space/", f"runs on {ORIGIN} only"),
    ]
    for site, check, text in refusals:
        entry = _entry(site, check_url=check)
        assert not identity.proof_ready(entry), check
        assert identity.entry_recipe(entry) is None, check
        assert text in identity.recipe_refusal(
            "dsm", site=site, check_url=check, privilege="readonly"
        ), check


def _raw(site: str, user: str | None = None, **fields: str) -> dict:
    base = {
        "agent_site": site,
        "agent_fill_origins": ORIGIN,
        "agent_check_url": CHECK,
        "agent_logged_in_selector": "#me",
        "agent_cookie_hosts": "synology.dom42.space",
        "agent_identity": "dsm",
        "agent_privilege": "readonly",
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


def test_the_vault_admits_readonly_and_admin() -> None:
    items = _items(
        _raw("dsm-readonly"),
        _raw("dsm-albert", privilege="admin", instance="admin"),
    )
    ro = items["dsm-readonly"]
    assert not ro.refused, ro.refused
    assert ro.identity_recipe is RECIPE and ro.multi_account
    assert identity.proof_ready(ro.public())
    admin = items["dsm-albert"]
    assert not admin.refused, admin.refused
    assert admin.multi_account and admin.identity_recipe is RECIPE
    assert identity.proof_ready(admin.public())


@pytest.mark.parametrize(
    ("site", "user", "fields", "problem"),
    [
        ("dsm-readonly", "zz@ws5dsm.example", {}, "the vault holds an email"),
        ("dsm-x", None, {}, "reviewed for dsm-albert, dsm-readonly only"),
        ("dsm-readonly", None, {"check_url": f"{OTHER}/"}, f"runs on {ORIGIN} only"),
    ],
)
def test_the_vault_refuses_what_the_recipe_does_not_cover(
    site: str, user: str | None, fields: dict, problem: str
) -> None:
    it = _items(_raw(site, user, **fields))[site]
    assert it.refused and problem in it.refused


# ---------------------------------------------------------------------------
# RECIPE_JS against a routed fixture DSM, both evaluators
# ---------------------------------------------------------------------------


class _Dsm:
    """The fixture DSM: `token` is the session's SynoToken (None = logged
    out with `token_code`); the identity call needs it in X-SYNO-TOKEN
    (else error 119, as live); the admin probe answers by `admin`. Every
    answer can be overridden (`*_status`, `*_ctype`, `*_body`,
    `*_redirect`)."""

    def __init__(self) -> None:
        self.name = _user()
        self.token: str | None = secrets.token_urlsafe(24)
        self.token_code = 119
        self.token_status = 200
        self.token_ctype = "application/json; charset=utf-8"
        self.token_body: str | None = None
        self.token_redirect: str | None = None
        self.user_status = 200
        self.user_body: str | None = None
        self.admin = False
        self.probe_status = 200
        self.probe_ctype = "application/json; charset=utf-8"
        self.probe_body: str | None = None
        self.probe_redirect: str | None = None
        self.seen: list[tuple[str, str | None]] = []

    def handle(self, route: Any) -> None:
        req = route.request
        url = urllib.parse.urlsplit(req.url)
        if req.resource_type == "document":
            route.fulfill(status=200, content_type="text/html", body="<p id=me>D</p>")
            return
        if url.path != ENTRY:
            route.fulfill(status=404, content_type="text/html", body="")
            return
        api = urllib.parse.parse_qs(url.query).get("api", [""])[0]
        sent = req.headers.get("x-syno-token")
        self.seen.append((api, sent))
        authed = self.token is not None and sent == self.token
        if api == TOKEN_API:
            self._token(route)
        elif api == USER_API:
            env: dict = (
                {"success": True, "data": {"username": self.name, "email": ""}}
                if authed
                else {"success": False, "error": {"code": 119}}
            )
            body = self.user_body if self.user_body is not None else json.dumps(env)
            route.fulfill(
                status=self.user_status, content_type="application/json", body=body
            )
        elif api == PROBE_API:
            if self.probe_redirect:
                route.fulfill(status=302, headers={"Location": self.probe_redirect})
                return
            if not authed:
                env = {"success": False, "error": {"code": 119}}
            elif self.admin:
                env = {"success": True, "data": {"total": 3, "users": [{}]}}
            else:
                env = {"success": False, "error": {"code": 105}}
            body = self.probe_body if self.probe_body is not None else json.dumps(env)
            route.fulfill(
                status=self.probe_status, content_type=self.probe_ctype, body=body
            )
        else:
            route.fulfill(status=200, content_type="application/json", body="{}")

    def _token(self, route: Any) -> None:
        if self.token_redirect:
            route.fulfill(status=302, headers={"Location": self.token_redirect})
            return
        if self.token is None:
            env: dict = {"success": False, "error": {"code": self.token_code}}
        else:
            env = {
                "success": True,
                "data": {"is_portal_port": False, "synotoken": self.token},
            }
        body = self.token_body if self.token_body is not None else json.dumps(env)
        route.fulfill(
            status=self.token_status, content_type=self.token_ctype, body=body
        )


Evaluator = Callable[[Any, str, Any], Any]
EVALUATORS = {
    "broker": daemon.evaluate_isolated,
    "client": browser._evaluate_isolated,
}


@pytest.fixture(params=sorted(EVALUATORS))
def ds(request: pytest.FixtureRequest) -> Iterator[tuple[Any, _Dsm, Evaluator]]:
    api = _Dsm()
    with routed_context(api.handle) as ctx:
        yield _check_page(ctx), api, EVALUATORS[request.param]


def _check_page(ctx: Any) -> Any:
    """A fresh page of the context, on the DSM check URL."""
    page = ctx.new_page()
    page.goto(CHECK)
    return page


def _run(page: Any, run: Evaluator, check: str = CHECK) -> dict:
    nonce = secrets.token_hex(32)
    got = dict(
        run(page, identity.RECIPE_JS, identity.recipe_args(RECIPE, check, nonce))
    )
    got["_nonce"] = nonce
    return got


def _verdict(got: dict, name: str, privilege: str) -> str:
    return identity.local_verdict(got, got["_nonce"], name, privilege)


def _no_leak(got: dict, api: _Dsm) -> None:
    text = json.dumps(got)
    for value in (api.token or "", api.name):
        assert not value or value not in text
    assert set(got) <= {"state", "digest", "admin", "why", "status", "_nonce"}


@pytest.mark.launches_chrome
@CHROME
def test_js_readonly_match_with_the_servers_token(
    ds: tuple[Any, _Dsm, Evaluator],
) -> None:
    page, api, run = ds
    # the page's own global is never read: a fake token there changes nothing
    page.evaluate(
        "t => { window.SYNO = {SDS: {Session: {SynoToken: t}}}; }",
        secrets.token_urlsafe(24),
    )
    got = _run(page, run)
    assert got["state"] == "found" and got["admin"] is False
    _no_leak(got, api)
    assert _verdict(got, api.name, "readonly") == identity.MATCH
    assert _verdict(got, _user(), "readonly") == identity.WRONG_ACCOUNT
    assert _verdict(got, api.name, "admin") == identity.PRIVILEGE_MISMATCH
    assert [a for a, _ in api.seen] == [TOKEN_API, USER_API, PROBE_API]
    # the token request carries none; the two API calls the server's
    assert api.seen[0][1] is None
    assert api.seen[1][1] == api.token and api.seen[2][1] == api.token


@pytest.mark.launches_chrome
@CHROME
def test_js_admin_bit_from_the_envelope(ds: tuple[Any, _Dsm, Evaluator]) -> None:
    page, api, run = ds
    api.admin = True
    got = _run(page, run)
    assert got["state"] == "found" and got["admin"] is True
    _no_leak(got, api)
    assert _verdict(got, api.name, "admin") == identity.MATCH
    assert _verdict(got, api.name, "readonly") == identity.PRIVILEGE_MISMATCH
    # ... and the admin ITEM may use the recipe: its answer is confirmed
    assert (
        identity.item_recipe(
            "dsm", site="dsm-albert", check_url=CHECK, privilege="admin"
        )
        is RECIPE
    )


@pytest.mark.launches_chrome
@CHROME
@pytest.mark.parametrize("code", [106, 107, 119])
def test_js_logged_out_only_from_the_token_request(
    ds: tuple[Any, _Dsm, Evaluator], code: int
) -> None:
    page, api, run = ds
    api.token, api.token_code = None, code
    got = _run(page, run)
    assert got["state"] == "logged_out"
    assert [a for a, _ in api.seen] == [TOKEN_API]  # nothing else was asked
    assert _verdict(got, api.name, "readonly") == identity.LOGGED_OUT


@pytest.mark.launches_chrome
@CHROME
def test_js_other_token_answers_are_indeterminate(
    ds: tuple[Any, _Dsm, Evaluator],
) -> None:
    page, api, run = ds
    api.token, api.token_code = None, 105
    assert _run(page, run)["state"] == "indeterminate"
    api.token = secrets.token_urlsafe(24)
    cases: list[dict[str, Any]] = [
        {"token_status": 500},
        {"token_status": 403},
        {"token_ctype": "text/html"},
        {"token_body": "not json"},
        {"token_body": json.dumps(["a"])},
        {"token_body": json.dumps({"success": True, "data": {}})},
        {"token_body": json.dumps({"success": True, "data": {"synotoken": 7}})},
        {"token_body": json.dumps({"success": True, "data": {"synotoken": "a b"}})},
        {"token_body": json.dumps({"success": "true", "error": {"code": 119}})},
        {"token_redirect": f"{ORIGIN}/login"},
        {"token_redirect": f"{OTHER}/x"},
    ]
    for case in cases:
        fresh = _Dsm()
        fresh.token = api.token
        vars(api).update({**vars(fresh), **case})
        got = _run(page, run)
        assert got["state"] == "indeterminate", case
        assert USER_API not in [a for a, _ in api.seen], case


@pytest.mark.launches_chrome
@CHROME
def test_js_identity_errors_after_a_token_are_indeterminate(
    ds: tuple[Any, _Dsm, Evaluator],
) -> None:
    page, api, run = ds
    for code in (106, 107, 119, 105):
        api.user_body = json.dumps({"success": False, "error": {"code": code}})
        got = _run(page, run)
        assert got["state"] == "indeterminate" and got["why"] == "api", code
    api.user_body = None
    for status in (401, 403, 500):
        api.user_status = status
        got = _run(page, run)
        assert got["state"] == "indeterminate", status
    api.user_status = 200
    api.user_body = json.dumps({"success": True, "data": {"username": 7}})
    assert _run(page, run)["state"] == "indeterminate"


@pytest.mark.launches_chrome
@CHROME
def test_js_other_probe_answers_are_no_bit(ds: tuple[Any, _Dsm, Evaluator]) -> None:
    page, api, run = ds
    cases: list[dict[str, Any]] = [
        {"probe_body": json.dumps({"success": False, "error": {"code": 102}})},
        {"probe_body": json.dumps({"success": False, "error": {"code": 119}})},
        {"probe_body": json.dumps({"success": False, "error": {"code": "105"}})},
        {"probe_body": json.dumps({"success": False})},
        {"probe_body": json.dumps({"success": "yes"})},
        {"probe_body": "<html>DSM</html>", "probe_ctype": "text/html"},
        {"probe_ctype": "text/plain"},
        {"probe_status": 403},
        {"probe_status": 500},
        {"probe_body": json.dumps({"success": True, "pad": "x" * 70000})},
        {"probe_redirect": f"{ORIGIN}/login"},
    ]
    for case in cases:
        for key, value in (
            ("probe_body", None),
            ("probe_status", 200),
            ("probe_ctype", "application/json; charset=utf-8"),
            ("probe_redirect", None),
        ):
            setattr(api, key, value)
        for key, value in case.items():
            setattr(api, key, value)
        got = _run(page, run)
        assert got["state"] == "found" and got["admin"] is None, case
        assert _verdict(got, api.name, "readonly") == identity.INDETERMINATE, case


@pytest.mark.launches_chrome
@CHROME
def test_js_refuses_another_origin(ds: tuple[Any, _Dsm, Evaluator]) -> None:
    page, api, run = ds
    page.goto(f"{OTHER}/")
    got = _run(page, run)
    assert got["state"] == "indeterminate" and got["why"] == "origin"
    assert not api.seen
