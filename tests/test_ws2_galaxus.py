"""WS2-galaxus: the broker never submits a Galaxus password again.

* galaxus.ch comes from Albert's Safari session (``SAFARI_SITES["galaxus"]``):
  the session cookies travel, every bot-management cookie stays behind, and the
  shared Chromium's OWN Akamai cookies are dropped (``drop_bot_cookies``).
* ``BOT_COOKIE_DENY`` covers Akamai's ``bm_*`` family.
* ``agent-login.py -g galaxus|galaxus-de`` is a guided login in the shown window.
* the never-submit guard (``agent_no_submit`` / ``vault.NO_SUBMIT_SITES``)
  refuses ``get_secret`` before the limiter or the vault is touched.
* the IdP's own answer to a password is an allowlisted reason code.

Hermetic: synthetic cookie jars with runtime-generated dummy values, stub
runners/vaults, no Chrome, no broker socket.
"""

from __future__ import annotations

# pylint: disable=protected-access,missing-function-docstring,missing-class-docstring
# pylint: disable=import-error,wrong-import-position,too-few-public-methods
# pylint: disable=redefined-outer-name,unused-argument
import contextlib
import json
import secrets
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "tests"))

# browser.py and agent-login.py as test_safari_cookies loaded them (one copy).
from test_safari_cookies import _Ctx, al, browser, encode  # noqa: E402
from test_ws1a_broker import _Vault  # noqa: E402

import agent_login_safari  # noqa: E402
from broker import daemon, idp_reasons, limiter, phases, recipes, vault  # noqa: E402
from broker import safari_cookies as sc  # noqa: E402

# every safari.py feature a recipe can need (WS1b S2)
ALL_FEATURES = sorted(
    frozenset().union(*(r.features() for r in agent_login_safari.RECIPES.values()))
)

FUTURE = time.time() + 86400 * 200
# Runtime-generated dummy values: never a real cookie or password.
VALUES = {
    k: secrets.token_urlsafe(18) for k in ("at", "atinfo", "ident", "dev", "abck")
}
PASSWORD = secrets.token_urlsafe(16)

KEEP = {
    ".at",
    ".atinfo",
    ".AspNetCore.Identity.Application",
    "DeviceCookie_1",
    "Tenant",
}
BOT = {"_abck", "bm_s", "bm_so", "bm_lso", "ak_bmsc", "bm_sz"}


def _galaxus_jar() -> list[dict]:
    return [
        {
            "domain": "www.galaxus.ch",
            "name": ".at",
            "value": VALUES["at"],
            "http_only": True,
        },
        {"domain": "www.galaxus.ch", "name": ".atinfo", "value": VALUES["atinfo"]},
        {"domain": ".galaxus.ch", "name": "_abck", "value": VALUES["abck"]},
        {"domain": ".galaxus.ch", "name": "bm_s", "value": "x"},
        {"domain": ".galaxus.ch", "name": "bm_so", "value": "x"},
        {"domain": ".galaxus.ch", "name": "bm_lso", "value": "x"},
        {"domain": ".galaxus.ch", "name": "ak_bmsc", "value": "x"},
        {
            "domain": "id.digitecgalaxus.ch",
            "name": ".AspNetCore.Identity.Application",
            "value": VALUES["ident"],
            "secure": True,
            "http_only": True,
        },
        {
            "domain": "id.digitecgalaxus.ch",
            "name": "DeviceCookie_1",
            "value": VALUES["dev"],
        },
        {"domain": "id.digitecgalaxus.ch", "name": "Tenant", "value": "x"},
        {"domain": ".digitecgalaxus.ch", "name": "bm_sz", "value": "x"},
        # not galaxus.ch: another shop, a look-alike, an expired one
        {"domain": ".digitec.ch", "name": ".at", "value": "other"},
        {"domain": "evilgalaxus.ch", "name": ".at", "value": "evil"},
        {"domain": "www.galaxus.ch", "name": "old", "expires": time.time() - 10},
    ]


@pytest.fixture
def jar(tmp_path: Path, monkeypatch) -> Path:
    path = tmp_path / "Cookies.binarycookies"
    path.write_bytes(encode(_galaxus_jar()))
    monkeypatch.setenv("SAFARI_COOKIES", str(path))
    return path


# ---------------------------------------------------------------------------
# Safari import
# ---------------------------------------------------------------------------


def test_bm_family_is_denied_generically() -> None:
    rules = sc.SAFARI_SITES["anibis"]
    for name in ("bm_s", "bm_so", "bm_lso", "bm_sz", "bm_mi", "bm_sv"):
        assert sc.denied(name, rules), name
    for name in ("bmx", "abm_s", ".at", "DeviceCookie_1"):
        assert not sc.denied(name, rules), name


def test_galaxus_site_rules() -> None:
    rules = sc.SAFARI_SITES["galaxus"]
    assert rules.domains == ("galaxus.ch", "digitecgalaxus.ch")
    assert rules.session_cookies == (".at",)
    assert rules.drop_bot_cookies and not rules.broker_fallback
    # every other site keeps them; galaxus-de shares the wall (WS1b)
    assert [s for s, r in sc.SAFARI_SITES.items() if r.drop_bot_cookies] == [
        "galaxus",
        "galaxus-de",
    ]


def test_galaxus_import_picks_session_not_bot_cookies(jar) -> None:
    picked = sc.site_cookies(sc.read_binarycookies(), "galaxus")
    assert {c.name for c in picked} == KEEP
    assert all(not c.domain.endswith("digitec.ch") for c in picked)
    assert "evilgalaxus.ch" not in {c.domain for c in picked}


def test_replaced_on_import() -> None:
    # galaxus: Chromium's own Akamai cookies go too
    for name in BOT | {".at", "anything"}:
        assert sc.replaced_on_import(".galaxus.ch", name, "galaxus"), name
    assert sc.replaced_on_import("id.digitecgalaxus.ch", "_abck", "galaxus")
    assert not sc.replaced_on_import(".digitec.ch", "_abck", "galaxus")
    # anibis: Chromium's own bot cookies stay
    assert not sc.replaced_on_import("anibis.ch", "cf_clearance", "anibis")
    assert sc.replaced_on_import("anibis.ch", "session", "anibis")
    # nothing outside the site, nothing denied is ever imported
    assert not sc.importable(".galaxus.ch", "bm_lso", "galaxus")
    assert sc.importable("www.galaxus.ch", ".atinfo", "galaxus")


@pytest.fixture
def chromium(monkeypatch):
    ctx = _Ctx(
        [
            {"domain": ".galaxus.ch", "name": "_abck", "path": "/"},
            {"domain": ".galaxus.ch", "name": "bm_s", "path": "/"},
            {"domain": ".galaxus.ch", "name": "ak_bmsc", "path": "/"},
            {"domain": "www.galaxus.ch", "name": ".at", "path": "/"},
            {"domain": "id.digitecgalaxus.ch", "name": "bm_sz", "path": "/"},
            {"domain": ".digitec.ch", "name": "_abck", "path": "/"},
            {"domain": "anibis.ch", "name": "cf_clearance", "path": "/"},
        ]
    )
    leases: list[str] = []

    @contextlib.contextmanager
    def lease(purpose: str):
        leases.append(purpose)
        yield "owner"

    browser_obj = SimpleNamespace(contexts=[ctx], close=lambda: None)
    monkeypatch.setattr(
        browser,
        "_connect",
        lambda port: (SimpleNamespace(stop=lambda: None), browser_obj),
    )
    monkeypatch.setattr(browser, "_interaction_lease", lease)
    monkeypatch.setattr(browser, "_record_login_event", lambda *a: None)
    monkeypatch.setattr(browser, "_broker_site", {"galaxus": {"site": "galaxus"}}.get)
    return ctx, leases


def test_import_drops_chromiums_bot_cookies(jar, chromium, monkeypatch, capsys) -> None:
    ctx, leases = chromium
    monkeypatch.setattr(browser, "_broker_check_entry", lambda *a: 0)
    assert browser.cmd_import_safari(9222, "galaxus") == 0
    assert leases == ["import-safari galaxus"]
    assert sorted(ctx.cleared) == sorted(
        [
            (".galaxus.ch", "_abck"),
            (".galaxus.ch", "bm_s"),
            (".galaxus.ch", "ak_bmsc"),
            ("www.galaxus.ch", ".at"),
            ("id.digitecgalaxus.ch", "bm_sz"),
        ]
    )  # digitec.ch and anibis untouched
    assert {c["name"] for c in ctx.added} == KEEP
    out = capsys.readouterr()
    for value in VALUES.values():
        assert value not in out.out + out.err


def test_login_galaxus_is_check_only(jar, chromium, monkeypatch, capsys) -> None:
    """M1: `browser.py login galaxus` never imports (and never reaches the
    broker): needs Albert, code manual_import, Chromium untouched."""
    ctx, leases = chromium
    monkeypatch.setattr(browser, "_broker_check_entry", lambda *a: 2)
    monkeypatch.setattr(browser, "_broker_login", pytest.fail)
    monkeypatch.setattr(browser, "_safari_inject", pytest.fail)
    browser._result_begin("login", "galaxus", None)
    assert browser._safari_login(9222, "galaxus") == browser.NEEDS_ALBERT_RC
    assert browser._RESULT["code"] == "manual_import"
    assert browser._RESULT["phase"] == "safari-source"
    assert "agent-login.py -t galaxus" in capsys.readouterr().err
    assert not ctx.cleared and not ctx.added and not leases
    # already logged in: still fine, nothing imported
    monkeypatch.setattr(browser, "_broker_check_entry", lambda *a: 0)
    assert browser._safari_login(9222, "galaxus") == 0


def test_import_safari_writes_a_result_record(jar, chromium, monkeypatch, tmp_path):
    monkeypatch.setattr(browser, "_broker_check_entry", lambda *a: 2)
    out = tmp_path / "r.json"
    assert browser.cmd_import_safari(9222, "galaxus", result_file=str(out)) == 2
    rec = json.loads(out.read_text())
    assert (rec["cmd"], rec["phase"], rec["code"]) == (
        "import-safari",
        "client-proof",
        "logged_out",
    )
    monkeypatch.setattr(
        sys, "argv", ["browser.py", "import-safari", "galaxus", "-R", str(out)]
    )
    assert browser.parse_args().result_file == str(out)


def _logged_out_jar(site: str) -> list[dict]:
    """Safari holds cookies of `site` but none of its session cookies."""
    domain = sc.SAFARI_SITES[site].domains[0]
    return [
        {"domain": f".{domain}", "name": "_ga", "value": "x"},
        {"domain": f".{domain}", "name": "consent", "value": "x"},
    ]


@pytest.mark.parametrize("site", sorted(sc.SAFARI_SITES))
def test_logged_out_safari_never_wipes_chromium(
    site: str, tmp_path: Path, monkeypatch
) -> None:
    """M1: for EVERY Safari site, a Safari set without a session cookie
    changes nothing in the shared browser (import, login, the replace itself)."""
    path = tmp_path / "Cookies.binarycookies"
    path.write_bytes(encode(_logged_out_jar(site)))
    monkeypatch.setenv("SAFARI_COOKIES", str(path))
    domain = sc.SAFARI_SITES[site].domains[0]
    ctx = _Ctx([{"domain": f".{domain}", "name": "good-session", "path": "/"}])
    browser_obj = SimpleNamespace(contexts=[ctx], close=lambda: None)
    monkeypatch.setattr(
        browser,
        "_connect",
        lambda port: (SimpleNamespace(stop=lambda: None), browser_obj),
    )
    monkeypatch.setattr(browser, "_interaction_lease", contextlib.nullcontext)
    monkeypatch.setattr(browser, "_broker_site", lambda s: {"site": s})
    monkeypatch.setattr(browser, "_broker_check_entry", lambda *a: 2)
    monkeypatch.setattr(browser, "_broker_login", lambda *a: 2)
    assert browser.cmd_import_safari(9222, site) == 2
    browser._result_begin("login", site, None)
    assert browser._safari_login(9222, site) in (2, browser.NEEDS_ALBERT_RC)
    cookies = sc.site_cookies(sc.read_binarycookies(), site)
    assert cookies and not sc.has_session(site, cookies)
    with pytest.raises(ValueError):
        browser._safari_replace_cookies(browser_obj, site, cookies)
    assert not ctx.cleared and not ctx.added


# ---------------------------------------------------------------------------
# agent-login.py: -g, -t, overview
# ---------------------------------------------------------------------------


def test_g_galaxus_de_goes_to_the_window(monkeypatch) -> None:
    calls: list[list[str]] = []

    def browser_call(*argv: str, **_kw: Any) -> int:
        calls.append(list(argv))
        return 0

    monkeypatch.setattr(al, "_browser", browser_call)
    monkeypatch.setattr(al, "broker_state", pytest.fail)  # static set decides
    assert al.manual_login("galaxus-de") == 0
    assert calls[-1] == [
        "assisted-login",
        "galaxus-de",
        "-u",
        "https://www.galaxus.de/de/orders",
        "-a",
    ]
    assert al.manual_login("galaxus", force=True) == 0
    assert calls[-1] == [
        "assisted-login",
        "galaxus",
        "-u",
        "https://www.galaxus.ch/de/orders",
        "-a",
        "-f",
    ]
    # the marketplace sites keep the remote view (no -a)
    monkeypatch.setattr(al, "broker_state", lambda **_k: ("running, Bitwarden ok", []))
    assert al.manual_login("anibis") == 0
    assert "-a" not in calls[-1]


def test_g_generic_no_submit_site(monkeypatch, capsys) -> None:
    calls: list[list[str]] = []

    def browser_call(*argv: str, **_kw: Any) -> int:
        calls.append(list(argv))
        return 0

    monkeypatch.setattr(al, "_browser", browser_call)
    sites = [{"site": "shopx", "no_submit": True}, {"site": "plain"}]
    monkeypatch.setattr(
        al, "broker_state", lambda **_k: ("running, Bitwarden ok", sites)
    )
    assert al.manual_login("shopx") == 0
    assert calls[-1] == ["assisted-login", "shopx", "-a"]  # its item's login URL
    assert al.manual_login("plain") == 2
    assert "no guided login known" in capsys.readouterr().out


def test_t_galaxus_de_imports_explicitly(monkeypatch) -> None:
    """WS1b: galaxus-de is a Safari site now: -t imports by hand, never a
    `browser.py login` (the broker never submits there)."""
    calls: list[tuple] = []

    def run(*argv: str, **_kw: Any) -> Any:
        calls.append(argv)
        return al.BrowserRun(2, False, "", 0.0, {"phase": "safari-source"})

    monkeypatch.setattr(al, "run_browser", run)
    monkeypatch.setattr(al, "probe", lambda site, quiet=True: (2, None))
    monkeypatch.setattr(al, "record_check", lambda *a, **k: None)
    assert al.run_test("galaxus-de") == 2
    assert calls[0] == ("import-safari", "galaxus-de")
    assert not any(c[0] == "login" for c in calls)
    assert not al._no_submit_assisted("galaxus")  # Safari import, not assisted
    assert not al._no_submit_assisted("galaxus-de")


def test_overview_galaxus_rows(monkeypatch) -> None:
    sites = [
        {"site": "galaxus", "fill_origins": ["https://id.digitecgalaxus.ch"]},
        {"site": "galaxus-de", "fill_origins": ["https://id.galaxus.eu"]},
        {"site": "shopx", "no_submit": True, "sentinel": True},
        {"site": "plain", "sentinel": True},
    ]
    monkeypatch.setattr(
        al, "broker_state", lambda **_k: ("running, Bitwarden ok", sites)
    )
    monkeypatch.setattr(al, "safari_state", lambda s: {})
    rows = {r["site"]: r for r in al.overview()["rows"]}
    assert rows["galaxus"]["status"] == "safari"
    # WS1b: galaxus-de is a Safari target (an agent logs Safari in: -L)
    assert rows["galaxus-de"]["status"] == "safari"
    assert rows["shopx"]["status"] == "assisted"
    assert "never submits" in rows["shopx"]["detail"]
    assert rows["plain"]["status"] == "extra"
    # a no-submit row is checked by -c, never logged in by it
    checks = {"galaxus-de": {"state": "failed", "at": time.time()}}
    text = al.agent_summary({"rows": [rows["galaxus-de"]], "broker_ok": True}, checks)
    # without the safari.py features its recipe needs: the old wording
    assert "Albert logs in in Safari" in text  # no Safari session readable
    assert "./agent-login.py -t galaxus-de" in al.safari_fix("galaxus-de")
    # with them (WS1b S2): an agent's Safari login
    monkeypatch.setenv("AGENT_LOGIN_SAFARI_FEATURES", ",".join(ALL_FEATURES))
    text = al.agent_summary({"rows": [rows["galaxus-de"]], "broker_ok": True}, checks)
    assert (
        "an agent renews it: ./agent-login.py -L galaxus-de (Albert's Safari)" in text
    )
    assert "./agent-login.py -L galaxus-de" in al.safari_fix("galaxus-de")
    # a custom no-submit site's failure mail names -g too
    assert "./agent-login.py -g shopx" in al.safari_fix("shopx")
    assert "-t plain and read" in al.safari_fix("plain")


def test_t_galaxus_imports_explicitly(monkeypatch) -> None:
    """M1: -t for a manual-import site runs `browser.py import-safari`, never
    `browser.py login` (which refuses it)."""
    calls: list[tuple] = []

    def run(*argv: str, **kw: Any) -> Any:
        calls.append((argv, kw.get("timeout_s")))
        return al.BrowserRun(0, False, "", 0.0, {"phase": "ok", "code": "ok"})

    monkeypatch.setattr(al, "run_browser", run)
    monkeypatch.setattr(al, "probe", lambda site, quiet=True: (0, None))
    monkeypatch.setattr(al, "record_check", lambda *a, **k: None)
    assert al.run_test("galaxus") == 0
    assert calls[0][0] == ("import-safari", "galaxus")
    assert calls[0][1] == al.browser_timeout("import-safari")
    calls.clear()
    assert al.run_test("anibis") == 0  # an unattended Safari site: `login`
    assert calls[0][0] == ("login", "anibis")


def test_agents_md_says_check_only_for_galaxus(monkeypatch) -> None:
    row = {
        "site": "galaxus",
        "name": "Galaxus",
        "status": "safari",
        "flow": al.SAFARI_FLOW,
        "safari": True,
        "safari_expires": "2099-01-01",
    }
    ok = {"galaxus": {"state": "ok", "at": time.time(), "at_text": "now"}}
    bad = {"galaxus": {"state": "failed", "at": time.time(), "at_text": "now"}}
    # no Safari session readable (or an expired one): Albert logs in in Safari
    for stale in ({**row, "safari": False}, {**row, "safari_expires": "2000-01-01"}):
        text = al.agent_summary({"rows": [stale], "broker_ok": True}, ok)
        assert "- ❌ Galaxus: Safari session missing, expired or unreadable" in text
        assert "-L galaxus" not in text
    # no new safari.py features, but Safari holds a live session: -L imports
    # it (SF2) — the plain `-t` wording is gone for a routed site
    text = al.agent_summary({"rows": [row], "broker_ok": True}, ok)
    assert (
        "- ✅ Galaxus (`galaxus`): Albert's Safari session; the daily run only "
        "checks it — when it lapses — an agent imports Albert's existing Safari "
        "session: ./agent-login.py -L galaxus" in text
    )
    text = al.agent_summary({"rows": [row], "broker_ok": True}, bad)
    assert (
        "- ❌ Galaxus: not logged in — an agent imports Albert's existing "
        "Safari session: ./agent-login.py -L galaxus — never ask Albert" in text
    )
    # with them (WS1b S2): an agent's Safari login
    monkeypatch.setenv("AGENT_LOGIN_SAFARI_FEATURES", ",".join(ALL_FEATURES))
    text = al.agent_summary({"rows": [row], "broker_ok": True}, ok)
    assert (
        "- ✅ Galaxus (`galaxus`): Albert's Safari session; the daily run only "
        "checks it — when it lapses — an agent renews it: ./agent-login.py -L "
        "galaxus (Albert's Safari)" in text
    )
    bad = {"galaxus": {"state": "failed", "at": time.time(), "at_text": "now"}}
    text = al.agent_summary({"rows": [row], "broker_ok": True}, bad)
    assert (
        "- ❌ Galaxus: not logged in — an agent renews it: ./agent-login.py -L "
        "galaxus (Albert's Safari) — never ask Albert" in text
    )


def test_daily_check_only_checks_galaxus_safari(monkeypatch) -> None:
    """galaxus: import_unattended=False -> the daily run probes, never imports."""
    assert not sc.SAFARI_SITES["galaxus"].import_unattended
    assert sc.SAFARI_SITES["anibis"].import_unattended
    row = {"site": "galaxus", "status": "safari", "flow": al.SAFARI_FLOW}
    gate = al.check_only_gate(row)
    assert gate is not None
    code, why = gate
    assert code == "manual_import" and "-t galaxus" in why
    assert al.check_only_gate({**row, "site": "anibis"}) is None
    monkeypatch.setattr(al, "probe", lambda site: (2, None))
    monkeypatch.setattr(al, "run_browser", pytest.fail)  # no `browser.py login`
    ok, how, res = al.ensure_logged_in("galaxus", gate=(code, why))
    assert ok is False and "by hand" in how
    assert res is not None and res["code"] == "manual_import"
    assert "manual_import" in phases.CODE_TEXT


def test_check_all_never_logs_a_no_submit_site_in(monkeypatch) -> None:
    monkeypatch.setattr(al, "wait_for_network", lambda: True)
    monkeypatch.setattr(al, "ensure_browser_up", lambda: True)
    monkeypatch.setattr(al, "_browser", lambda *a, **_k: 0)
    row = {"site": "galaxus-de", "name": "galaxus-de", "status": "assisted"}
    monkeypatch.setattr(
        al, "overview", lambda: {"broker": "ok", "broker_ok": True, "rows": [row]}
    )
    seen: list[str] = []
    monkeypatch.setattr(al, "ensure_logged_in", pytest.fail)

    def check(site: str) -> tuple[bool, str]:
        seen.append(site)
        return True, "logged in"

    monkeypatch.setattr(al, "assisted_check", check)
    assert al.check_all() == 0
    assert seen == ["galaxus-de"]


# ---------------------------------------------------------------------------
# the never-submit guard (broker)
# ---------------------------------------------------------------------------


def _raw(site: str, **fields: str) -> dict[str, Any]:
    base = {
        "agent_site": site,
        "agent_fill_origins": "https://login.shop.example",
        "agent_check_url": "https://www.shop.example/account",
        "agent_logged_in_selector": "#me",
        "agent_cookie_hosts": "shop.example",
    }
    return {
        "id": f"id-{site}",
        "name": site,
        "login": {"username": "someone@example.org", "password": PASSWORD},
        "fields": [{"name": k, "value": v} for k, v in {**base, **fields}.items()],
    }


@pytest.mark.parametrize(
    "site, field, want",
    [
        ("shop", "", False),
        ("shop", "true", True),
        ("shop", "false", False),
        ("galaxus", "", True),  # built in
        ("galaxus-de", "false", True),  # the vault cannot lift it
    ],
)
def test_no_submit_field(site: str, field: str, want: bool) -> None:
    extra = {"agent_no_submit": field} if field else {}
    item = vault.site_item_from_json(_raw(site, **extra))
    assert item.refused is None and item.no_submit is want
    assert item.public()["no_submit"] is want


@pytest.mark.parametrize(
    "origin",
    [
        "https://id.digitecgalaxus.ch",
        "https://id.galaxus.eu",
        "https://login.galaxus.de",
        "https://www.digitec.ch",
    ],
)
def test_no_submit_by_fill_origin_whatever_the_name(origin: str) -> None:
    """A renamed / duplicate item ("digitec.ch galaxus.ch" -> its own slug) that
    would type on a Digitec Galaxus host is no-submit too."""
    raw = _raw("shop", agent_fill_origins=origin, agent_no_submit="false")
    raw["fields"] = [f for f in raw["fields"] if f["name"] != "agent_site"]
    raw["name"] = "digitec.ch galaxus.ch"
    item = vault.site_item_from_json(raw)
    assert item.refused is None and item.site not in vault.NO_SUBMIT_SITES
    assert item.no_submit and item.public()["no_submit"]


def test_no_submit_origin_match_is_exact() -> None:
    for origin in ("https://notgalaxus.ch", "https://galaxus.ch.evil.example"):
        assert not vault.no_submit_by_origin([origin]), origin


NOSUB = "no-submit login item"
MALFORMED = "malformed URI"


@pytest.mark.parametrize(
    "fields, uris, why",
    [
        ({}, [], None),  # an ordinary secret
        ({}, ["https://www.example.org"], None),
        ({}, ["https://notgalaxus.ch"], None),  # a label boundary, not a substring
        ({}, [r"^https://.*\.example\.org"], None),  # a Bitwarden regex, harmless
        ({"agent_site": "galaxus"}, [], NOSUB),
        ({"agent_no_submit": "true"}, [], NOSUB),
        ({"agent_no_submit": "maybe"}, [], NOSUB),  # malformed: fail closed
        ({"agent_fill_origins": "https://id.galaxus.eu"}, [], NOSUB),
        ({}, ["id.digitecgalaxus.ch/login"], NOSUB),  # a bare login URI
        ({}, ["https://ID.Galaxus.EU./x"], NOSUB),  # case + trailing DNS dot
        ({"agent_fill_origins": "id.galaxus.eu"}, [], NOSUB),  # malformed, named
        ({}, [r"^https://.*\.galaxus\.ch"], NOSUB),  # Bitwarden regex URI
        ({}, [r"^https://(www\.)?galaxus\.fr/.*"], NOSUB),  # a country shop
        ({}, ["https://[a-z]+.galaxus.it/"], NOSUB),  # brackets, but named
        ({}, ["https://[broken/"], MALFORMED),  # unparsable: fail closed
        ({}, [r"https://[a-z]+\.example\.org"], MALFORMED),  # regex with brackets
        ({"agent_fill_origins": "example.org"}, [], MALFORMED),
    ],
)
def test_secret_ops_never_expose_a_no_submit_login(
    fields: dict, uris: list, why: str | None
) -> None:
    """A copy of a no-submit login in the secrets collection (or that collection
    configured equal to agent-logins) is refused by `secret` / `secret-run`;
    an URI that cannot be read is refused as malformed (fail closed)."""
    raw = {
        "id": "id-x",
        "name": "some secret",
        "login": {
            "username": "u",
            "password": PASSWORD,
            "uris": [{"uri": u} for u in uris],
        },
        "fields": [{"name": k, "value": v} for k, v in fields.items()],
    }
    item, values = vault.secret_item_from_json(raw, 1)
    if why:
        assert values is None and why in (item.refused or ""), item.refused
    else:
        assert item.refused is None and values is not None


def _fixture_vault(tmp_path: Path, *items: dict) -> vault.FixtureVault:
    path = tmp_path / "vault.json"
    path.write_text(json.dumps(list(items)))
    return vault.FixtureVault(path, dev=True)


def test_fresh_read_refuses_a_no_submit_login_secret(tmp_path: Path) -> None:
    """S3: `secret()` re-judges the FRESH item: an item flagged no-submit after
    the site list was cached never yields a login secret (and the removed
    `fingerprint` op, tp#965, reads nothing)."""
    fv = _fixture_vault(tmp_path, _raw("shop", agent_no_submit="true"))
    with pytest.raises(vault.VaultError, match="no-submit"):
        fv.secret("shop")
    assert not hasattr(fv, "fingerprint_secret")
    # a stale cached item (not no-submit) still cannot reach the password
    stale = vault.site_item_from_json(_raw("shop"))
    assert not stale.no_submit
    brk = daemon.Broker(
        fv,
        limiter.Limiter(
            tmp_path / "l.json",
            cooldown_s=1800,
            min_interval_s=0,
            per_hour=5,
            per_day=9,
        ),
        tmp_path / "home",
        runner=_Runner(recipes.INVALID),
        clock=lambda: 10.0,
    )
    gate = daemon._SecretGate(brk, stale, scheduled=False)
    with pytest.raises(vault.VaultError, match="no-submit"):
        gate()
    resp = brk.handle({"op": "fingerprint", "site": "shop"})
    assert resp["ok"] is False and resp["error"] == "removed"
    assert "password_check" not in resp
    plain = _fixture_vault(tmp_path, _raw("shop"))
    assert plain.secret("shop").password == PASSWORD


def test_bad_no_submit_value_is_refused() -> None:
    item = vault.site_item_from_json(_raw("shop", agent_no_submit="maybe"))
    assert item.refused and "agent_no_submit" in item.refused


class _Runner:
    """Shaped like PlaywrightRunner.run_in_context (profile proof first)."""

    def __init__(self, proof: str) -> None:
        self.proof = proof
        self.last_diag: dict[str, Any] = {}
        self.cleared = False
        self.typed = False

    def __call__(self, item: vault.SiteItem, get_secret: Any) -> dict[str, Any]:
        if item.fresh_login:
            get_secret()
            self.cleared = True
        elif self.proof == recipes.VALID:
            return {"via": "profile", "cookies": [{"n": 1}]}
        else:
            get_secret()
        self.typed = True
        return {"via": "login", "cookies": [{"n": 1}]}


def _broker(tmp_path: Path, runner: Any, item: vault.SiteItem) -> daemon.Broker:
    lim = limiter.Limiter(
        tmp_path / "limiter.json",
        cooldown_s=1800,
        min_interval_s=0,
        per_hour=50,
        per_day=100,
    )
    return daemon.Broker(
        _Vault([item]),  # type: ignore[arg-type]
        lim,
        tmp_path / "home",
        runner=runner,
        clock=lambda: 10.0,
    )


@pytest.mark.parametrize("extra", [{}, {"agent_fresh_login": "true"}])
def test_guard_refuses_before_any_secret_read(tmp_path: Path, extra: dict) -> None:
    item = vault.site_item_from_json(_raw("galaxus-de", **extra))
    runner = _Runner(recipes.INVALID)
    brk = _broker(tmp_path, runner, item)
    resp = brk._do_login("galaxus-de")
    assert resp["error"] == "submit_disabled" and resp["phase"] == "vault"
    assert resp["submitted"] is False
    assert brk.vault.secret_calls == 0  # type: ignore[attr-defined]
    assert not runner.typed and not runner.cleared
    assert not (tmp_path / "limiter.json").exists()  # nothing reserved
    assert phases.phase_for_error("submit_disabled") == "vault"
    assert not phases.post_submit(resp["phase"], resp["submitted"])


@pytest.mark.parametrize(
    "kwargs, fields, error",
    [
        ({"scheduled": True}, {}, "submit_disabled"),  # the daily check's -s
        # `login -x CSS`: an item without a sentinel, the candidate path
        ({"candidate": "#cand"}, {"agent_logged_in_selector": ""}, "submit_disabled"),
        ({"refresh_only": True}, {}, "refresh_unavailable"),  # never a password
    ],
)
def test_guard_holds_on_every_login_path(
    tmp_path: Path, kwargs: dict, fields: dict, error: str
) -> None:
    item = vault.site_item_from_json(_raw("galaxus", **fields))
    runner = _Runner(recipes.INVALID)
    brk = _broker(tmp_path, runner, item)
    resp = brk._do_login("galaxus", **kwargs)
    assert resp["error"] == error and resp["submitted"] is False
    assert brk.vault.secret_calls == 0  # type: ignore[attr-defined]
    assert not runner.typed


def test_guard_still_exports_a_reusable_profile(tmp_path: Path) -> None:
    item = vault.site_item_from_json(_raw("shop", agent_no_submit="true"))
    brk = _broker(tmp_path, _Runner(recipes.VALID), item)
    resp = brk._do_login("shop")
    assert resp["ok"] and resp["bundle"]["via"] == "profile"
    assert brk.vault.secret_calls == 0  # type: ignore[attr-defined]


def test_client_maps_submit_disabled_to_needs_albert(monkeypatch, capsys) -> None:
    monkeypatch.setattr(browser._als, "quarantine", pytest.fail)
    monkeypatch.setattr(browser, "_result_fail", lambda *a, **k: None)
    resp = {
        "ok": False,
        "error": "submit_disabled",
        "detail": "",
        "phase": "vault",
        "submitted": False,
    }
    assert browser._broker_refused("galaxus-de", resp) == browser.NEEDS_ALBERT_RC
    assert "never submits a password" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# IdP reason codes
# ---------------------------------------------------------------------------

URL = "https://id.digitecgalaxus.ch/api/v1/login/_actions/submit-password?x=1"


@pytest.mark.parametrize(
    "method, url, status, body, want",
    [
        ("POST", URL, 200, {"error": "InvalidCredentials"}, "idp_invalid_credentials"),
        ("post", URL, 200, {"error": "Unknown"}, "idp_unknown"),
        ("POST", URL, 200, {"error": "CaptchaRequired"}, "captcha_required"),
        ("POST", URL, 200, {"error": "UserDoesNotExist"}, None),  # not allowlisted
        ("POST", URL, 200, {"success": {"nextStep": "x"}}, None),
        ("POST", URL, 403, {"error": "Unknown"}, None),  # an edge refusal
        ("GET", URL, 200, {"error": "Unknown"}, None),
        ("POST", "https://x.example/other", 200, {"error": "Unknown"}, None),
        # the same path on a host that is not the IdP's, or over http
        (
            "POST",
            "https://x.example/api/v1/login/_actions/submit-password",
            200,
            {"error": "Unknown"},
            None,
        ),
        ("POST", URL.replace("https:", "http:"), 200, {"error": "Unknown"}, None),
        (
            "POST",
            URL.replace("id.digitecgalaxus.ch", "id.galaxus.eu"),
            200,
            {"error": "Unknown"},
            "idp_unknown",
        ),
        ("POST", URL, 200, ["Unknown"], None),
        ("POST", URL, 200, {"error": 7}, None),
    ],
)
def test_classifier(method: str, url: str, status: int, body: Any, want: Any) -> None:
    assert idp_reasons.classify(method, url, status, json.dumps(body)) == want


def test_classifier_rejects_garbage_and_huge_bodies() -> None:
    assert idp_reasons.classify("POST", URL, 200, b"<html>") is None
    huge = json.dumps({"error": "Unknown", "pad": "x" * idp_reasons.MAX_BODY})
    assert idp_reasons.classify("POST", URL, 200, huge) is None
    assert idp_reasons.CODES <= set(phases.CODE_TEXT)
    assert idp_reasons.CODES <= set(browser.BROKER_ERRORS)


class _Resp:
    def __init__(self, error: str | None, *, broken: bool, length: int | None) -> None:
        self.status = 200
        self.error = error
        self.broken = broken
        self.headers = {} if length is None else {"content-length": str(length)}

    def body(self) -> bytes:
        if self.broken:
            raise RuntimeError("No resource with given identifier found")
        return json.dumps({"error": self.error} if self.error else {}).encode()


class _Req:
    """A finished request (`requestfinished`) and its response."""

    def __init__(
        self,
        error: str | None,
        *,
        broken: bool = False,
        length: int | None = None,
        method: str = "POST",
        url: str = "",
    ) -> None:
        self.method = method
        self.url = url or URL
        self.resp = _Resp(error, broken=broken, length=length)

    def response(self) -> _Resp:
        return self.resp


class _EventCtx:
    def __init__(self) -> None:
        self.handlers: list[Any] = []

    def on(self, event: str, fn: Any) -> None:
        assert event == "requestfinished"
        self.handlers.append(fn)


def test_watcher_keeps_only_password_answers_and_last_readable_decides() -> None:
    ctx = _EventCtx()
    kept = daemon.watch_idp_responses(ctx)
    try:
        for req in (
            _Req("Unknown", method="GET"),
            _Req(
                "Unknown", url="https://x.example/api/v1/login/_actions/submit-password"
            ),
            _Req("InvalidCredentials"),
            _Req("Unknown"),
            _Req(None, broken=True),
            _Req("CaptchaRequired", length=idp_reasons.MAX_BODY + 1),
        ):
            ctx.handlers[0](req)
        assert len(kept) == 4  # the GET and the foreign host are not kept
        # the oversized one is never fetched, the broken one skipped
        assert daemon.idp_reason(ctx) == "idp_unknown"
        ctx.handlers[0](_Req(None))  # a later success answer decides: no reason
        assert daemon.idp_reason(ctx) is None
    finally:
        daemon._IDP_RESPONSES.pop(id(ctx), None)


def test_recipe_failure_carries_the_idp_reason(tmp_path: Path, monkeypatch) -> None:
    runner = daemon.PlaywrightRunner(tmp_path, dev=False)

    def recipe(_page, _item, _secret, *, dev, attempt):
        del dev
        attempt.mark_submitted()
        raise recipes.LoginFailed("still on the password page", phase="submit")

    def record(_page, item, _secret):
        runner.last_diag[item.site] = {"title": "Sign in"}

    monkeypatch.setattr(runner, "_profile_proof", lambda _p, _i: recipes.INVALID)
    monkeypatch.setattr(runner, "_record_failure", record)
    monkeypatch.setattr(daemon, "recipe_for", lambda _site: recipe)
    ctx = SimpleNamespace(pages=[object()])
    daemon._IDP_RESPONSES[id(ctx)] = [_Req("Unknown")]
    secret = vault.Secret(username="a@b.ch", password=PASSWORD)
    item: Any = SimpleNamespace(site="galaxus-x", fresh_login=False)
    try:
        with pytest.raises(recipes.LoginFailed) as err:
            runner.run_in_context(ctx, item, lambda: secret)
    finally:
        daemon._IDP_RESPONSES.pop(id(ctx), None)
    assert err.value.code == "idp_unknown" and err.value.phase == "submit"
    assert runner.last_diag["galaxus-x"]["idp_reason"] == "idp_unknown"
    assert PASSWORD not in json.dumps(runner.last_diag)
