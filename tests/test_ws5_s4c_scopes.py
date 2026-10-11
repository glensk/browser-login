"""WS5 S4c (tp#931): cookie scopes with a path (Keycloak realms).

``identity.CookieScope`` is the ONE implementation of a cookie scope: the
conflict matrix (domain relations x RFC 6265 path intervals), the vault field
``agent_cookie_scopes`` and its validation, the versioned ``sites`` / bundle
views (``scope_v``) with old/new reader compatibility, and every cookie
operation — the broker's export, fresh-login wipe and WS5 reset, the client's
replace, rollback, logout and foreign clear — each touching only the cookies
inside the item's paths, a sibling realm's cookies untouched.

Hermetic: fake cookie jars, no browser, no broker socket; usernames are
generated per run.
"""

from __future__ import annotations

# pylint: disable=protected-access,missing-function-docstring,missing-class-docstring
# pylint: disable=import-error,wrong-import-position,redefined-outer-name
import contextlib
import json
import secrets
import sys
from typing import Any

import pytest
from chromium_page import REPO, load_script

sys.path.insert(0, str(REPO))

from broker import bundle, daemon, identity, vault  # noqa: E402

browser = load_script("bin/browser.py", "ws5s4c_browser")

KC = "custos.datascience.ch"
RUNAI = "sdsc.run.ai"
APP1 = "app1.run.ai"  # Run:ai's own Keycloak: EVERY tenant's realm lives there
SDSC = "/realms/sdsc/"
MASTER = "/realms/master/"
APP1_SDSC = "/auth/realms/sdsc/"
APP1_TENANT = "/auth/realms/acme/"  # another Run:ai tenant
KC_ORIGIN = f"https://{KC}"
RUNAI_CHECK = f"https://{RUNAI}/workloads"
KC_CHECK = f"https://{KC}/admin/master/console/"
S = identity.CookieScope
KC_NAMES = ("AUTH_SESSION_ID", "KC_RESTART", "KEYCLOAK_SESSION")


def _user() -> str:
    return f"zz-{secrets.token_hex(5)}@ws5s4c.example"


def _scopes(*pairs: tuple[str, str]) -> str:
    return json.dumps([{"host": h, "path": p} for h, p in pairs])


def _raw(site: str, **fields: str) -> dict:
    """A Bitwarden-shaped login item; `fields` without the agent_ prefix."""
    base = {"agent_site": site, "agent_logged_in_selector": "#me"}
    base.update({f"agent_{k}": v for k, v in fields.items()})
    return {
        "id": f"id-{site}",
        "name": site,
        "login": {"username": _user(), "pass" + "word": secrets.token_urlsafe(12)},
        "fields": [{"name": k, "value": v} for k, v in base.items()],
    }


RUNAI_SCOPES = ((RUNAI, "/"), (KC, SDSC), (APP1, APP1_SDSC))


def _runai_raw(site: str = "runai-test3", **extra: str) -> dict:
    fields = {
        "fill_origins": KC_ORIGIN,
        "check_url": RUNAI_CHECK,
        "cookie_scopes": _scopes(*RUNAI_SCOPES),
    }
    fields.update(extra)
    return _raw(site, **fields)


def _custos_raw(**extra: str) -> dict:
    fields = {
        "fill_origins": KC_ORIGIN,
        "check_url": KC_CHECK,
        "cookie_scopes": _scopes((KC, MASTER)),
    }
    fields.update(extra)
    return _raw("custos-admin", **fields)


def _items(*raws: dict) -> dict[str, vault.SiteItem]:
    return {it.site: it for it in vault.build_items(list(raws))}


def _ck(domain: str, path: str, name: str, value: str = "v") -> dict:
    return {"domain": domain, "path": path, "name": name, "value": value}


def _realm(host: str, path: str) -> set[tuple[str, str, str]]:
    return {(host, path, n) for n in KC_NAMES}


MASTER_COOKIES = _realm(KC, MASTER)
SDSC_COOKIES = _realm(KC, SDSC)
APP1_COOKIES = _realm(APP1, APP1_SDSC)
TENANT_COOKIES = _realm(APP1, APP1_TENANT)
RUNAI_COOKIES = {(RUNAI, "/api/v1/token", "refresh-token"), (RUNAI, "/", "ui")}
# cookies on an ANCESTOR path of a scope path (sent into the realm)
ANCESTOR_COOKIES = {
    (KC, "/", "kc-root"),
    (KC, "/realms/", "kc-realms"),
    (APP1, "/", "app1-root"),
    (APP1, "/auth/", "app1-auth"),
}
PARENT = (".datascience.ch", "/", "parent")
UNRELATED = ("gitlab.datascience.ch", "/", "_gitlab_session")
# what a shared-browser delete of the Run:ai item must leave
SIBLINGS_KEPT = MASTER_COOKIES | TENANT_COOKIES | {PARENT, UNRELATED}


def _jar() -> list[dict]:
    """The A0 inventory's shape: Keycloak's session cookies per realm path
    (custos: sdsc and master; app1.run.ai: sdsc and another tenant), cookies
    on ancestor paths, Run:ai's refresh cookie, a parent-domain cookie and
    an unrelated subdomain of that parent."""
    out = [
        _ck(host, path, name, f"{name}-{host}{path}")
        for host, path, name in sorted(
            MASTER_COOKIES | SDSC_COOKIES | APP1_COOKIES | TENANT_COOKIES
        )
    ]
    out += [_ck(*key) for key in sorted(ANCESTOR_COOKIES | RUNAI_COOKIES)]
    out += [_ck(*PARENT), _ck(*UNRELATED)]
    return out


def _left(jar: list[dict]) -> set[tuple[str, str, str]]:
    return {(c["domain"], c["path"], c["name"]) for c in jar}


class _Jar:
    """Playwright's cookie API on a list: `cookies`, `clear_cookies` (exact
    name + domain + path, as Playwright), `add_cookies`."""

    def __init__(self, cookies: list[dict]) -> None:
        self.jar = [dict(c) for c in cookies]
        self.added: list[dict] = []
        self.pages: list[Any] = []

    def cookies(self) -> list[dict]:
        return [dict(c) for c in self.jar]

    def clear_cookies(self, *, name: Any = None, domain: Any = None, path: Any = None):
        assert name and domain and path  # never a wildcard clear
        self.jar = [
            c
            for c in self.jar
            if not (c["name"] == name and c["domain"] == domain and c["path"] == path)
        ]

    def add_cookies(self, cookies: list[dict]) -> None:
        self.added += [dict(c) for c in cookies]
        self.jar += [dict(c) for c in cookies]


class _Browser:
    def __init__(self, ctx: _Jar) -> None:
        self.contexts = [ctx]

    def close(self) -> None:
        pass


class _Pw:
    def stop(self) -> None:
        pass


# ---------------------------------------------------------------------------
# CookieScope: the conflict matrix and the per-cookie rules
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("a", "b", "overlap"),
    [
        ((KC, "/"), (KC, SDSC), True),  # "/" covers every path
        ((KC, SDSC), (KC, "/realms/sdsc"), True),  # the exact path without its /
        ((KC, SDSC), (KC, MASTER), False),  # sibling realms
        ((KC, "/realms/sd"), (KC, SDSC), False),  # a prefix, not a path segment
        ((KC, SDSC), (KC, "/realms/sdscx/"), False),
        ((KC, SDSC), (KC, "/realms/sdsc/account"), True),  # nested
        (("datascience.ch", "/"), (KC, SDSC), True),  # a parent domain at /
        (("datascience.ch", MASTER), (KC, SDSC), False),  # parent, sibling path
        (("datascience.ch", SDSC), (KC, SDSC), True),  # parent, same path
        ((f"x.{KC}", SDSC), (KC, "/realms/sdsc"), True),  # a subdomain
        ((f"evil{KC}", SDSC), (KC, SDSC), False),  # not a subdomain
        (("gitlab.datascience.ch", "/"), (KC, "/"), False),  # siblings under a parent
        (("a.example", "/"), ("b.example", "/"), False),
    ],
)
def test_the_conflict_matrix(
    a: tuple[str, str], b: tuple[str, str], overlap: bool
) -> None:
    assert S(*a).overlaps(S(*b)) is overlap
    assert S(*b).overlaps(S(*a)) is overlap  # symmetric
    assert identity.scopes_overlap([S(*a)], [S(*b)]) is overlap


def test_the_scope_path_is_canonical() -> None:
    assert S(KC, SDSC) == S(KC, "/realms/sdsc") == S(f".{KC.upper()}", "/realms/sdsc//")
    assert S(KC, "").path == "/" and S(KC).path == "/"
    assert S(KC, SDSC).view() == {"host": KC, "path": "/realms/sdsc"}


@pytest.mark.parametrize(
    ("domain", "path", "held"),
    [
        (KC, SDSC, True),
        (KC, "/realms/sdsc", True),
        (KC, "/realms/sdsc/protocol/openid-connect", True),
        (f".{KC}", SDSC, True),  # a domain cookie of the host itself
        (f"x.{KC}", SDSC, True),  # a subdomain
        (KC, MASTER, False),  # the sibling realm
        (KC, "/", False),  # a root cookie is not the realm's
        (KC, "/realms/sdscx/", False),
        (".datascience.ch", SDSC, False),  # never a parent domain
        ("", SDSC, False),
    ],
)
def test_holds_is_the_export_and_clear_rule(domain: str, path: str, held: bool) -> None:
    assert S(KC, SDSC).holds(domain, path) is held


@pytest.mark.parametrize(
    ("domain", "path", "reached"),
    [
        (KC, SDSC, True),
        (".datascience.ch", "/", True),  # a parent root cookie is SENT there
        (".datascience.ch", SDSC, True),
        (".datascience.ch", MASTER, False),
        (KC, "/", True),  # a root cookie of the host reaches the realm
        (KC, MASTER, False),
        (f"x.{KC}", "/realms/sdsc/x", True),
        ("gitlab.datascience.ch", "/", False),
    ],
)
def test_reaches_is_the_fresh_login_rule(domain: str, path: str, reached: bool) -> None:
    assert S(KC, SDSC).reaches(domain, path) is reached


def test_a_host_only_scope_decides_as_the_host_lists_did() -> None:
    """Path '/': every path, as before — even a malformed cookie path."""
    scope = S(KC)
    for path in ("/", SDSC, MASTER, "", "weird"):
        assert scope.holds(KC, path) and scope.reaches(KC, path)
        assert scope.holds(f"a.{KC}", path)
        assert not scope.holds(".datascience.ch", path)
        assert scope.reaches(".datascience.ch", path)


def _old_cookie_in_scope(
    domain: str, name: str, hosts: list[str], names: list[str] | None
) -> bool:
    """bundle.cookie_in_scope before S4c, verbatim."""
    d = domain.strip().lstrip(".").lower()
    if not d:
        return False
    norm = [h.strip().lstrip(".").lower() for h in hosts if h.strip()]
    if not any(d == h or d.endswith("." + h) for h in norm):
        return False
    if bundle.is_idp_host(d) and d not in norm:
        return False
    return names is None or name in names


def test_host_only_specs_export_exactly_what_they_did() -> None:
    domains = [KC, f".{KC}", "datascience.ch", "x.y.example", "y.example", ""]
    domains += ["accounts.google.com", "sso.example", "keycloak.y.example"]
    host_sets = [[KC], ["datascience.ch"], ["y.example", "sso.example"], ["google.com"]]
    for hosts in host_sets:
        for names in (None, ["sid"]):
            spec = bundle.SiteBundleSpec(cookie_hosts=hosts, cookie_names=names)
            for d in domains:
                for n in ("sid", "other"):
                    for path in ("/", SDSC):
                        want = _old_cookie_in_scope(d, n, hosts, names)
                        assert bundle.cookie_in_scope(d, n, spec, path) is want
                        assert (
                            browser._broker_cookie_in_scope(
                                d, n, hosts, names, path=path
                            )
                            is want
                        )


def test_broker_and_client_agree_on_path_scopes() -> None:
    scopes = (S(RUNAI), S(KC, SDSC), S("sso.example", "/realms/x"))
    hosts = [RUNAI, KC, "sso.example"]
    spec = bundle.SiteBundleSpec(cookie_hosts=hosts, cookie_scopes=scopes)
    for c in [
        *_jar(),
        _ck("sso.example", "/realms/x/", "idp"),
        _ck("sso.example", "/", "r"),
    ]:
        for names in (None, ["KC_RESTART"]):
            spec_n = bundle.SiteBundleSpec(
                cookie_hosts=hosts, cookie_names=names, cookie_scopes=scopes
            )
            assert bundle.cookie_in_scope(
                c["domain"], c["name"], spec_n, c["path"]
            ) == browser._broker_cookie_in_scope(
                c["domain"], c["name"], hosts, names, path=c["path"], scopes=scopes
            ), c
    # an IdP-labelled host only when named exactly (sso.example is named)
    assert bundle.cookie_in_scope("sso.example", "idp", spec, "/realms/x/")
    assert not bundle.cookie_in_scope("sso.example", "r", spec, "/")


# ---------------------------------------------------------------------------
# the vault field and its validation
# ---------------------------------------------------------------------------


def test_a_realm_scope_item_and_its_views() -> None:
    it = _items(_runai_raw())["runai-test3"]
    assert not it.refused, it.refused
    # what an old reader sees: the hosts, host-wide
    assert it.cookie_hosts == [RUNAI, KC, APP1]
    assert it.scopes == tuple(S(*pair) for pair in RUNAI_SCOPES)
    view = it.public()
    assert view["scope_v"] == identity.SCOPE_V == 1
    assert view["cookie_scopes"] == [
        {"host": RUNAI, "path": "/"},
        {"host": KC, "path": "/realms/sdsc"},
        {"host": APP1, "path": "/auth/realms/sdsc"},
    ]
    assert identity.entry_cookie_scopes(view) == it.scopes
    assert it.bundle_spec.scopes == it.scopes


def test_a_host_only_item_lists_its_hosts_at_root() -> None:
    it = _items(
        _raw("solo", fill_origins="https://solo.example", cookie_hosts="solo.example")
    )["solo"]
    view = it.public()
    assert view["cookie_scopes"] == [{"host": "solo.example", "path": "/"}]


def test_both_fields_must_name_the_same_hosts() -> None:
    same = _runai_raw(cookie_hosts=f"{KC}, {APP1}, {RUNAI}")
    assert not _items(same)["runai-test3"].refused
    other = _runai_raw(cookie_hosts=KC)
    reason = _items(other)["runai-test3"].refused or ""
    assert "agent_cookie_scopes and agent_cookie_hosts name different hosts" in reason


@pytest.mark.parametrize(
    ("value", "problem"),
    [
        ("not json", "not JSON"),
        ("{}", "non-empty JSON list"),
        ("[]", "non-empty JSON list"),
        (json.dumps([{"host": f"h{i}.example"} for i in range(17)]), "at most 16"),
        (json.dumps(["custos.datascience.ch"]), "each scope is an object"),
        (json.dumps([{"path": "/"}]), "exactly the keys"),
        (json.dumps([{"host": KC, "path": "/", "secure": True}]), "exactly the keys"),
        (json.dumps([{"host": f"https://{KC}"}]), "bad host"),
        (json.dumps([{"host": f"{KC}:443"}]), "bad host"),
        (json.dumps([{"host": f"{KC}/realms"}]), "bad host"),
        (json.dumps([{"host": ""}]), "bad host"),
        (json.dumps([{"host": "a b.example"}]), "bad host"),
        (json.dumps([{"host": 7}]), "bad host"),
        (json.dumps([{"host": KC, "path": "realms/sdsc"}]), "bad path"),
        (json.dumps([{"host": KC, "path": "/realms/sdsc?x"}]), "bad path"),
        (json.dumps([{"host": KC, "path": "/realms/sdsc#x"}]), "bad path"),
        (json.dumps([{"host": KC, "path": "/realms/a b"}]), "bad path"),
        (json.dumps([{"host": KC, "path": "/realms;x"}]), "bad path"),
        (json.dumps([{"host": KC, "path": "/realms//sdsc"}]), "no //"),
        (json.dumps([{"host": KC, "path": "/realms/../admin"}]), "no //"),
        (json.dumps([{"host": KC, "path": "/realms/./x"}]), "no //"),
        (json.dumps([{"host": KC, "path": "/" + "a" * 256}]), "bad path"),
        (json.dumps([{"host": KC, "path": "/réalms"}]), "bad path"),
        (json.dumps([{"host": KC, "path": 3}]), "bad path"),
        (json.dumps([{"host": KC, "path": "/realms/%2e%2e/admin"}]), "no %"),
        (json.dumps([{"host": KC, "path": "/realms/%2E/x"}]), "no %"),
        (json.dumps([{"host": KC, "path": "/realms/sd%73c/"}]), "no %"),
    ],
)
def test_malformed_scopes_are_refused(value: str, problem: str) -> None:
    it = _items(_runai_raw(cookie_scopes=value))["runai-test3"]
    assert it.refused and it.refused.startswith("bad agent_cookie_scopes: ")
    assert problem in it.refused


def test_duplicates_fold_and_a_bare_host_means_root() -> None:
    value = json.dumps(
        [{"host": RUNAI}, {"host": RUNAI, "path": "/"}, {"host": KC, "path": SDSC}]
    )
    it = _items(_runai_raw(cookie_scopes=value))["runai-test3"]
    assert it.scopes == (S(RUNAI), S(KC, SDSC))


def test_a_refused_item_keeps_its_scope_hosts_host_wide() -> None:
    """Refused before its scope was parsed (a malformed field): its hosts
    still take part in the conflicts, at path '/' (over-inclusive)."""
    bad = _custos_raw(cookie_scopes='[{"host": "' + KC + '", "path": 1}]')
    other = _raw(
        "realm-x",
        fill_origins="https://login.ws5s4c.example",
        check_url=f"https://{KC}/realms/x/account",
        cookie_scopes=_scopes((KC, "/realms/x/")),
        privilege="user",
    )
    items = _items(bad, other)
    assert items["custos-admin"].refused
    assert items["custos-admin"].cookie_hosts == [KC]
    assert items["realm-x"].multi_account  # the refused item's host-wide scope


# ---------------------------------------------------------------------------
# conflicts: multi-account and the in-instance rule, one implementation
# ---------------------------------------------------------------------------


def _realm_item(site: str, realm: str, fill: str, **extra: str) -> dict:
    return _raw(
        site,
        fill_origins=fill,
        check_url=f"https://{KC}{realm}account",
        cookie_scopes=_scopes((KC, realm)),
        **extra,
    )


def test_sibling_realms_with_their_own_fill_origins_do_not_conflict() -> None:
    a = _realm_item("realm-a", "/realms/a/", "https://a.ws5s4c.example")
    b = _realm_item("realm-b", "/realms/b/", "https://b.ws5s4c.example")
    items = _items(a, b)
    assert not items["realm-a"].refused and not items["realm-b"].refused
    assert not items["realm-a"].multi_account and not items["realm-b"].multi_account
    sites = [it.public() for it in items.values()]
    assert identity.scope_conflicts(sites) == {}


def test_a_shared_fill_origin_stays_a_conflict() -> None:
    """O11: origin state (the login form, localStorage) cannot be split by
    path — two realms typed into on one origin conflict, and inside one
    instance the later site id is refused."""
    a = _realm_item("realm-a", "/realms/a/", KC_ORIGIN, privilege="user")
    b = _realm_item("realm-b", "/realms/b/", KC_ORIGIN, privilege="user")
    items = _items(a, b)
    assert items["realm-a"].multi_account and items["realm-b"].multi_account
    assert not items["realm-a"].refused
    assert "scope conflict in instance default" in (items["realm-b"].refused or "")
    apart = _items(
        a,
        _realm_item(
            "realm-b", "/realms/b/", KC_ORIGIN, privilege="user", instance="alt"
        ),
    )
    assert not apart["realm-b"].refused and apart["realm-b"].multi_account


def test_a_storage_origin_stays_a_conflict() -> None:
    keys = json.dumps({"https://kc.ws5s4c.example": ["k"]})
    a = _realm_item(
        "realm-a", "/realms/a/", "https://a.ws5s4c.example", storage_keys=keys
    )
    b = _raw(
        "other",
        fill_origins="https://b.ws5s4c.example",
        check_url="https://kc.ws5s4c.example/x",
        cookie_scopes=_scopes(("kc.ws5s4c.example", "/realms/b/")),
    )
    sites = [it.public() for it in _items(a, b).values()]
    assert identity.scope_conflicts(sites) == {
        "other": ("realm-a",),
        "realm-a": ("other",),
    }


def test_custos_admin_still_conflicts_with_the_runai_items() -> None:
    """The realistic S4c migration: custos-admin on /realms/master/, the
    Run:ai items on /realms/sdsc/ — their cookie scopes no longer overlap,
    but all three type into https://custos.datascience.ch (fill origin), so
    they still conflict: custos-admin goes to `alt`."""
    runai = _runai_raw(privilege="user")
    custos = _custos_raw(privilege="admin")
    cookies_only = [
        {**it.public(), "fill_origins": [], "storage_origins": []}
        for it in _items(runai, custos).values()
    ]
    assert identity.scope_conflicts(cookies_only) == {}  # the paths alone: apart
    items = _items(runai, custos)
    assert items["custos-admin"].multi_account and items["runai-test3"].multi_account
    assert "scope conflict in instance default" in (items["runai-test3"].refused or "")
    moved = _items(runai, _custos_raw(privilege="admin", instance="alt"))
    assert not moved["custos-admin"].refused and not moved["runai-test3"].refused


def test_mixed_versions_read_host_wide() -> None:
    """Old client / new broker: without `scope_v` the client reads the
    hosts (host-wide) — more conflicts, never fewer. New client / old
    broker: no `cookie_scopes` at all → the hosts. A malformed or
    inconsistent versioned field → the hosts too."""
    a = _realm_item("realm-a", "/realms/a/", "https://a.ws5s4c.example")
    b = _realm_item("realm-b", "/realms/b/", "https://b.ws5s4c.example")
    new = [it.public() for it in _items(a, b).values()]
    assert identity.scope_conflicts(new) == {}
    old_reader = [{k: v for k, v in e.items() if k != "scope_v"} for e in new]
    old_broker = [
        {k: v for k, v in e.items() if k not in ("scope_v", "cookie_scopes")}
        for e in new
    ]
    for view in (old_reader, old_broker):
        assert identity.scope_conflicts(view) == {
            "realm-a": ("realm-b",),
            "realm-b": ("realm-a",),
        }
        assert identity.entry_cookie_scopes(view[0]) == (S(KC),)
    for bad in (
        "nope",
        [{"host": KC, "path": "rel"}],
        [{"host": "elsewhere.example", "path": "/realms/a"}],  # not its cookie host
        [],
    ):
        broken = [dict(new[0], cookie_scopes=bad), new[1]]
        assert identity.entry_cookie_scopes(broken[0]) == (S(KC),)
        assert identity.scope_conflicts(broken)
    assert identity.entry_cookie_scopes(dict(new[0], scope_v=True)) == (S(KC),)


def test_a_new_client_reads_an_old_bundle_host_wide() -> None:
    old = {"cookie_hosts": [KC]}
    assert browser._cookie_scopes_of(old) == (S(KC),)
    new = {"cookie_hosts": [KC], "cookie_scopes": [S(KC, SDSC).view()], "scope_v": 1}
    assert browser._cookie_scopes_of(new) == (S(KC, SDSC),)


# ---------------------------------------------------------------------------
# every cookie operation: exact export and injection, deletes in the paths
# and their ancestors (shared browser), host-wide in the broker's own profile
# ---------------------------------------------------------------------------


@pytest.fixture
def runai() -> vault.SiteItem:
    return _items(_runai_raw(privilege="user", identity=""))["runai-test3"]


def test_broker_export_takes_only_the_realms_cookies(runai: vault.SiteItem) -> None:
    """Exact: the realm's cookies only — never an ancestor path, a sibling
    realm, another tenant on app1.run.ai, or a parent domain."""
    runner = daemon.PlaywrightRunner(REPO, dev=True)
    out = runner.export_bundle(_Jar(_jar()), runai, "profile")
    assert _left(out["cookies"]) == SDSC_COOKIES | APP1_COOKIES | RUNAI_COOKIES
    assert out["scope_v"] == 1
    assert out["cookie_scopes"] == [S(*pair).view() for pair in RUNAI_SCOPES]
    assert out["cookie_hosts"] == [RUNAI, KC, APP1]


def test_broker_fresh_login_wipe_is_host_wide(runai: vault.SiteItem) -> None:
    """The broker's profile is the item's own: its wipe takes every cookie
    on the scope and fill hosts, every path, and what reaches them from a
    parent domain — only unrelated hosts stay."""
    assert daemon.fresh_login_scopes(runai) == [S(RUNAI), S(KC), S(APP1)]
    ctx = _Jar(_jar())
    gone = daemon.PlaywrightRunner(REPO, dev=True).clear_site_cookies(ctx, runai)
    assert _left(ctx.jar) == {UNRELATED}
    assert gone == len(_jar()) - 1


def test_a_host_only_fresh_login_wipe_is_unchanged() -> None:
    it = _items(_raw("solo", fill_origins=KC_ORIGIN, cookie_hosts=RUNAI))["solo"]
    assert daemon.fresh_login_scopes(it) == [S(RUNAI), S(KC)]
    ctx = _Jar(_jar())
    daemon.PlaywrightRunner(REPO, dev=True).clear_site_cookies(ctx, it)
    assert _left(ctx.jar) == TENANT_COOKIES | APP1_COOKIES | {
        ("app1.run.ai", "/", "app1-root"),
        ("app1.run.ai", "/auth/", "app1-auth"),
        UNRELATED,
    }


class _Session:
    def __init__(self, sent: list) -> None:
        self.sent = sent

    def send(self, method: str, params: dict | None = None) -> dict:
        self.sent.append((method, params))
        return {}

    def detach(self) -> None:
        pass


class _ResetCtx(_Jar):
    def __init__(self, cookies: list[dict]) -> None:
        super().__init__(cookies)
        self.sent: list = []

    def new_cdp_session(self, _page: Any) -> _Session:
        return _Session(self.sent)

    def new_page(self) -> Any:
        return _Page()


class _Page:
    def __init__(self) -> None:
        self.urls: list[str] = []
        self.closed = False

    def goto(self, url: str) -> None:
        self.urls.append(url)

    def close(self) -> None:
        self.closed = True


def test_the_ws5_reset_is_host_wide_in_the_brokers_profile(
    runai: vault.SiteItem,
) -> None:
    ctx, page = _ResetCtx(_jar()), _Page()
    fresh = daemon.PlaywrightRunner(REPO, dev=True).reset_site_profile(ctx, page, runai)
    assert page.urls == ["about:blank"] and page.closed and fresh is not page
    assert _left(ctx.jar) == {UNRELATED}
    cleared = [p["origin"] for m, p in ctx.sent if m == "Storage.clearDataForOrigin"]
    assert cleared == [KC_ORIGIN, f"https://{RUNAI}"]  # every origin, as before


def _bundle(item: vault.SiteItem, cookies: list[dict]) -> dict:
    out = daemon.PlaywrightRunner(REPO, dev=True).export_bundle(
        _Jar(cookies), item, "login"
    )
    return out


def test_client_replace_touches_only_the_realms_cookies(runai: vault.SiteItem) -> None:
    fresh = [
        _ck(KC, SDSC, "KEYCLOAK_SESSION", "new"),
        _ck(RUNAI, "/api/v1/token", "refresh-token", "new"),
    ]
    bundle_ = _bundle(runai, fresh)
    # defence in depth: a bundle cookie outside the scope's paths is dropped,
    # an ancestor-path one too (injection is exact)
    bundle_["cookies"].append(_ck(KC, MASTER, "KEYCLOAK_SESSION", "planted"))
    bundle_["cookies"].append(_ck(KC, "/", "kc-root", "planted"))
    ctx = _Jar(_jar())
    assert browser._broker_replace_cookies(_Browser(ctx), bundle_) == 2
    left = {(c["domain"], c["path"], c["name"]): c["value"] for c in ctx.jar}
    for key in MASTER_COOKIES | TENANT_COOKIES:
        assert left[key] == f"{key[2]}-{key[0]}{key[1]}"  # untouched
    assert left[(KC, SDSC, "KEYCLOAK_SESSION")] == "new"
    assert (KC, SDSC, "AUTH_SESSION_ID") not in left  # the old realm session went
    assert not set(left) & ANCESTOR_COOKIES  # the delete took the ancestors
    assert PARENT in left and UNRELATED in left  # never a parent domain


def test_client_replace_with_an_old_bundle_is_host_wide(runai: vault.SiteItem) -> None:
    """New client, pre-S4c broker: no `scope_v` → the hosts, as before."""
    bundle_ = _bundle(runai, [_ck(KC, SDSC, "KEYCLOAK_SESSION", "new")])
    for key in ("scope_v", "cookie_scopes"):
        bundle_.pop(key)
    ctx = _Jar(_jar())
    browser._broker_replace_cookies(_Browser(ctx), bundle_)
    assert not _left(ctx.jar) & (MASTER_COOKIES | TENANT_COOKIES)  # fail closed


@pytest.fixture
def connected(monkeypatch: pytest.MonkeyPatch) -> tuple[_Jar, list[str]]:
    ctx = _Jar(_jar())
    leases: list[str] = []

    @contextlib.contextmanager
    def lease(purpose: str) -> Any:
        leases.append(purpose)
        yield "owner"

    monkeypatch.setattr(browser, "_connect", lambda _port: (_Pw(), _Browser(ctx)))
    monkeypatch.setattr(browser, "_interaction_lease", lease)
    return ctx, leases


# what a delete of the Run:ai item takes: its realms, Run:ai, the ancestors
DELETED = SDSC_COOKIES | APP1_COOKIES | RUNAI_COOKIES | ANCESTOR_COOKIES


def test_client_rollback_drops_the_realms_and_ancestor_cookies(
    runai: vault.SiteItem, connected: tuple[_Jar, list[str]]
) -> None:
    ctx, _leases = connected
    bundle_ = _bundle(runai, [])
    assert browser._broker_rollback(9222, bundle_, 1, []) == "complete"
    assert _left(ctx.jar) == SIBLINGS_KEPT


def test_logout_deletes_the_realms_and_ancestor_cookies(
    runai: vault.SiteItem,
    connected: tuple[_Jar, list[str]],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    ctx, leases = connected
    entry = runai.public()
    monkeypatch.setattr(browser, "_broker_site", lambda _s: entry)
    monkeypatch.setattr(browser, "_instance_gate", lambda *_a: None)
    monkeypatch.setattr(
        browser, "_broker_request", lambda op, **_k: {"ok": True, "removed": True}
    )
    assert browser.cmd_broker_logout(9222, "runai-test3") == 0
    assert f"deleted {len(DELETED)} runai-test3 cookie(s)" in capsys.readouterr().out
    assert leases == ["logout runai-test3"]
    left = _left(ctx.jar)
    assert left == SIBLINGS_KEPT
    assert not left & ANCESTOR_COOKIES  # `/` and `/realms/`, `/` and `/auth/`
    assert MASTER_COOKIES <= left and TENANT_COOKIES <= left  # sibling realms
    assert PARENT in left  # never a parent domain


def test_the_foreign_clear_deletes_the_realms_and_ancestor_cookies(
    runai: vault.SiteItem, connected: tuple[_Jar, list[str]]
) -> None:
    ctx, leases = connected
    entry = runai.public()
    msg = browser._broker_clear_foreign(9222, "runai-test3", entry)
    assert f"foreign session cleared ({len(DELETED)} cookie(s)" in msg
    assert leases == ["clear-foreign runai-test3"]
    left = _left(ctx.jar)
    assert left == SIBLINGS_KEPT
    assert not left & ANCESTOR_COOKIES
    assert MASTER_COOKIES <= left and PARENT in left


def test_the_foreign_clear_of_an_old_entry_is_host_wide(
    runai: vault.SiteItem, connected: tuple[_Jar, list[str]]
) -> None:
    ctx, _leases = connected
    entry = {k: v for k, v in runai.public().items() if k != "scope_v"}
    browser._broker_clear_foreign(9222, "runai-test3", entry)
    assert not _left(ctx.jar) & (MASTER_COOKIES | TENANT_COOKIES)


@pytest.mark.parametrize(
    ("domain", "path", "deleted"),
    [
        (KC, "/", True),
        (KC, "/realms/", True),
        (KC, "/realms", True),
        (f"x.{KC}", "/", True),  # a subdomain's ancestor-path cookie
        (KC, SDSC, True),
        (KC, MASTER, False),  # sibling path
        (KC, "/realms/sd", False),  # not a segment boundary
        (KC, "/admin/", False),  # not an ancestor
        (".datascience.ch", "/", False),  # parent domain
        (APP1, "/auth/", True),
        (APP1, APP1_TENANT, False),
    ],
)
def test_the_delete_rule(domain: str, path: str, deleted: bool) -> None:
    scopes = (S(KC, SDSC), S(APP1, APP1_SDSC))
    assert identity.scopes_clear(scopes, domain, path) is deleted
    held = identity.scopes_hold(scopes, domain, path)
    assert held is (deleted and path in (SDSC, APP1_SDSC))  # export stays exact
