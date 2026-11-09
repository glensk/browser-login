"""tp#1644 B2: the Safari route table (`agent-login.py -L SITE -s`).

Every listed login is classified exactly once (route / ⛔ reason / not built
yet); the ⛔ cell, legend, `-j` field and agents.md line; `-s` refusals; the
`in_safari` proof through the real Safari Machine (safari.py is a scripted
fake); `-O`; the in-Safari identity read; the Cloudflare Access stop; the
import rule. Hermetic: no network, no real Safari / Chrome / broker, the
state dir is a per-test temp dir (conftest). The node-backed test documents
what page JS in Safari's MAIN world can do to the identity read.
"""

from __future__ import annotations

# pylint: disable=missing-function-docstring,import-error,wrong-import-position
# pylint: disable=protected-access,redefined-outer-name,unused-argument
# One file for the whole route table (B2, B6, B8): pylint: disable=too-many-lines
import contextlib
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
import time
import urllib.parse
from pathlib import Path
from typing import Any

import pytest

sys.path[:0] = [
    str(Path(__file__).resolve().parent.parent),
    str(Path(__file__).resolve().parent),
]

import test_ws1b_safari as w  # noqa: E402
from ws3_fixtures import load_script  # noqa: E402

import agent_login_safari as alsafari  # noqa: E402
from broker import identity, vault  # noqa: E402

al = load_script("agent_login_tp1644_test", "agent-login.py")


# ---------------------------------------------------------------------------
# Every listed login is classified exactly once
# ---------------------------------------------------------------------------

# The broker `sites` listing as of 2026-11-04 (fields the classification
# reads; no names, URLs or usernames). A new broker item fails
# `test_every_listed_login_is_classified_exactly_once` until it is added
# here AND to `EXPECTED`. `cloudflare` is listed twice (one refused).
# A labelled broker route (tp#1644 B13) also needs the fill fields its
# recipe reads (`broker_recipe`).
LISTED_FILL: dict[str, dict[str, Any]] = {
    "zoho-desk": {
        "safari_fill": True,
        "fill_only": False,
        "fill_origins": ["https://accounts.zoho.eu"],
        "check_url": "https://desk.zoho.eu/agent",
        "login_url": "https://desk.zoho.eu/agent",
    },
}
LISTING: list[dict[str, Any]] = [
    {
        "site": s,
        "privilege": p,
        "identity": i,
        "refused": False,
        **LISTED_FILL.get(s, {}),
    }
    for s, p, i in (
        ("google-kindle", None, None),
        ("anibis", None, None),
        ("abs-albert", "user", "audiobookshelf"),
        ("abs-root", "admin", "audiobookshelf"),
        ("aurral", None, None),
        ("authentik-akadmin", "admin", "authentik"),
        ("authentik-glensk", "admin", "authentik"),
        ("authentik-test3", "user", None),
        ("calibre", None, None),
        ("cloudflare", None, None),
        ("cscs", None, None),
        ("galaxus", None, None),
        ("gitlab-ethz", None, None),
        ("myfritz", None, None),
        ("galaxus-de", None, None),
        ("github", None, None),
        ("gitlab-sdsc-admin", "admin", "gitlab"),
        ("gitlab-sdsc-glensk", "user", "gitlab"),
        ("gitlab-com", None, None),
        ("homeassistant", None, None),
        ("syncthing-nixos", None, None),
        ("immich", None, None),
        ("infomaniak", None, None),
        ("jellyfin", None, None),
        ("kavita-admin", None, None),
        ("custos-admin", "admin", "keycloak-admin"),
        ("kleinanzeigen", None, None),
        ("komga", None, None),
        ("mullvad", None, None),
        ("navidrome-root", "admin", "navidrome"),
        ("navidrome-albert", "user", "navidrome"),
        ("npm-nixos", None, None),
        ("npm-raspi", None, None),
        ("portainer-ds218", None, None),
        ("qbittorrent", None, None),
        ("ricardo", None, None),
        ("runai-admin", "admin", "runai"),
        ("runai-test3", "user", "runai"),
        ("smartsheet", None, None),
        ("stirling", None, None),
        ("eduid", None, None),
        ("dsm-albert", "admin", "dsm"),
        ("dsm-readonly", "readonly", "dsm"),
        ("tutti", None, None),
        ("welib", None, None),
        ("zoho-desk", None, None),
    )
] + [
    {"site": "cloudflare", "refused": True, "reason": "x"},
    # fill-only items are not logins: no row, no classification
    {"site": "fill-example", "fill_only": True},
]

ROUTE = "route"
NOT_BUILT = "not built yet"
_ADMIN = "⛔ admin_account"
# site → its ONE class: the route, a ⛔ reason code, or not built yet
EXPECTED: dict[str, str] = {
    **dict.fromkeys(
        (
            "notion",
            # tp#1644 B8: the Safari-cookie sites
            "anibis",
            "galaxus",
            "galaxus-de",
            "kleinanzeigen",
            "ricardo",
            "tutti",
            # tp#1644 B6: the built-in sites
            "openai",
            "slack",
            # tp#1644 B13: the broker SaaS route with probe labels
            "zoho-desk",
        ),
        ROUTE,
    ),
    "google-kindle": "⛔ albert_only",
    "authentik-test3": "⛔ account_unproven",
    "mullvad": "⛔ not_opted_in",
    "cloudflare": "⛔ refused",
    "myfritz": "⛔ on_demand",
    **dict.fromkeys(
        (
            "abs-root",
            "authentik-akadmin",
            "authentik-glensk",
            "custos-admin",
            "dsm-albert",
            "gitlab-sdsc-admin",
            "navidrome-root",
            "runai-admin",
        ),
        _ADMIN,
    ),
    **dict.fromkeys(
        (
            "abs-albert",
            "anthropic",
            "anthropic-private",
            "aurral",
            "calibre",
            "console",
            "console-private",
            "cscs",
            "dsm-readonly",
            "eduid",
            "github",
            "gitlab-com",
            "gitlab-ethz",
            "gitlab-sdsc-glensk",
            "homeassistant",
            "immich",
            "infomaniak",
            "jellyfin",
            "kavita-admin",
            "komga",
            "navidrome-albert",
            "npm-nixos",
            "npm-raspi",
            "portainer-ds218",
            "qbittorrent",
            "runai-test3",
            "smartsheet",
            "stirling",
            "switch",
            "syncthing-nixos",
            "welib",
        ),
        NOT_BUILT,
    ),
}


def _class(cols: Any) -> str:
    if cols.safari:
        assert not cols.safari_why
        return ROUTE
    return f"⛔ {cols.safari_why}" if cols.safari_why else NOT_BUILT


@pytest.fixture
def listed(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    """The overview's rows over `LISTING` (no broker, no Safari jar)."""
    monkeypatch.setattr(
        al, "broker_state", lambda **_k: ("running, Bitwarden readable", LISTING)
    )
    monkeypatch.setattr(al, "safari_state", lambda _s: {})
    # a labelled broker route reads its row from the `sites` snapshot (B13)
    _snapshot(monkeypatch, LISTING)
    rows: list[dict[str, Any]] = al.overview()["rows"]
    return rows


def test_every_listed_login_is_classified_exactly_once(
    listed: list[dict[str, Any]],
) -> None:
    sites = [str(r["site"]) for r in listed]
    assert len(sites) == len(set(sites)), "a login listed twice"
    assert set(sites) == set(EXPECTED), "classify the new / gone login in EXPECTED"
    got = {r["site"]: _class(al.login_columns(r["site"], r)) for r in listed}
    assert got == EXPECTED


def test_the_tables_name_only_listed_logins_and_never_overlap(
    listed: list[dict[str, Any]],
) -> None:
    sites = {str(r["site"]) for r in listed}
    assert not set(al.SAFARI_ROUTES) & set(al.SAFARI_INFEASIBLE)
    assert set(al.SAFARI_ROUTES) <= sites
    assert set(al.SAFARI_INFEASIBLE) <= sites
    assert set(al.SAFARI_INFEASIBLE.values()) <= set(al.SAFARI_INFEASIBLE_TEXT)
    assert "admin_account" in al.SAFARI_INFEASIBLE_TEXT
    for route in al.SAFARI_ROUTES.values():
        assert route.proof in al.SAFARI_PROOFS
        assert route.landing.startswith("https://")


def test_no_admin_row_has_a_route(listed: list[dict[str, Any]]) -> None:
    admins = [r["site"] for r in listed if r.get("privilege") == "admin"]
    assert admins  # the listing has admin rows
    assert not set(admins) & set(al.SAFARI_ROUTES)
    for site in admins:
        row = next(r for r in listed if r["site"] == site)
        assert al.login_columns(site, row).safari_why == "admin_account"


def test_the_admin_rule_is_derived_from_the_listing_snapshot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert al.safari_why("abs-root") == ""  # no snapshot yet
    _snapshot(monkeypatch, [{"site": "abs-root", "privilege": "admin"}])
    assert al.safari_why("abs-root") == "admin_account"
    assert al.safari_why("abs-root", {"privilege": "user"}) == ""
    # a route wins over the derived rule
    monkeypatch.setitem(
        al.SAFARI_ROUTES, "abs-root", al.SafariRoute("https://x.example/", "in_safari")
    )
    assert al.safari_why("abs-root") == ""


def _snapshot(monkeypatch: pytest.MonkeyPatch, sites: list[dict[str, Any]]) -> None:
    path = al._state_path("sites.json")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"at": 0, "health": "x", "sites": sites}), "utf-8")


# ---------------------------------------------------------------------------
# The ⛔ cell, legend, -j and agents.md
# ---------------------------------------------------------------------------


def _rows() -> list[dict[str, Any]]:
    return [
        {"site": "notion", "name": "Notion", "status": "assisted"},
        {"site": "google-kindle", "name": "google-kindle", "status": "extra"},
        {
            "site": "abs-root",
            "name": "abs-root",
            "status": "extra",
            "privilege": "admin",
        },
        # a login without a route yet (openai is routed since tp#1644 B6)
        {"site": "github", "name": "github", "status": "extra"},
    ]


def test_the_overview_shows_the_blocked_cell_and_its_legend(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(al, "USE", False)
    monkeypatch.setattr(al, "last_checks", dict)
    monkeypatch.setattr(al, "_row_flags", lambda _r: "")
    monkeypatch.setattr(al, "row_state", lambda _r, _c: ("ok", "WHY"))
    al.print_overview({"rows": _rows(), "broker_ok": True, "broker": "running"})
    lines = capsys.readouterr().out.splitlines()
    head = next(i for i, x in enumerate(lines) if "agent_fill_origins" in x)
    assert lines[head + 1].strip() == al.LOGIN_COLUMNS_LEGEND
    assert "⛔ = Albert's (reason: -L SITE -s -n, -j login_columns.safari_why)" in (
        al.LOGIN_COLUMNS_LEGEND
    )
    cells = {
        name: next(x for x in lines[head + 2 :] if f" {name} " in x)
        .split(name, 1)[1]
        .split()[0]
        for name in ("Notion", "google-kindle", "abs-root", "github")
    }
    assert cells == {
        "Notion": "✅",
        "google-kindle": "⛔",
        "abs-root": "⛔",
        "github": "❌",
    }


def test_json_rows_carry_safari_why() -> None:
    rows = {r["site"]: r["login_columns"] for r in al.with_login_columns(_rows())}
    assert rows["notion"]["safari_why"] == ""
    kindle = rows["google-kindle"]
    assert (kindle["safari"], kindle["safari_why"]) == (False, "albert_only")
    assert rows["abs-root"]["safari_why"] == "admin_account"
    assert rows["github"]["safari_why"] == ""


def test_agents_md_lists_the_blocked_sites_in_one_line() -> None:
    line = al.safari_infeasible_sentence(_rows())
    assert line.startswith("Safari logins that stay Albert's (⛔, never try them): ")
    for site, code in {**al.SAFARI_INFEASIBLE, "abs-root": "admin_account"}.items():
        assert f"{site} ({code})" in line
    assert "github" not in line and "notion" not in line
    text = al.agent_summary({"rows": _rows(), "broker_ok": True, "broker": "x"}, {})
    assert line in text and text.count("never try them") == 1


# ---------------------------------------------------------------------------
# -s / -s -n on a ⛔ site: exit 2 with its code, nothing called
# ---------------------------------------------------------------------------

_BLOCKED = sorted({**al.SAFARI_INFEASIBLE, "abs-root": "admin_account"}.items())


def _nothing(*_a: Any, **_k: Any) -> Any:
    pytest.fail("a ⛔ site called something")


@pytest.mark.parametrize("dry_run", [False, True])
@pytest.mark.parametrize(("site", "code"), _BLOCKED)
def test_a_blocked_site_exits_2_naming_its_code(
    site: str,
    code: str,
    dry_run: bool,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _snapshot(monkeypatch, [{"site": "abs-root", "privilege": "admin"}])
    monkeypatch.setattr(alsafari, "scheduled", lambda: False)
    monkeypatch.setattr(al, "resolve_site", lambda s: s)
    for mod, name in (
        (alsafari, "interactive_gate"),
        (alsafari, "safari_py_bin"),
        (alsafari, "run_safari_py"),
        (alsafari, "Machine"),
        (al, "run_browser"),
        (al, "broker_request"),
        (al, "_import_run"),
        (al, "safari_login_lock"),
    ):
        monkeypatch.setattr(mod, name, _nothing)
    for prove_only in (False, True):
        assert (
            al.safari_target_action(site, "", dry_run=dry_run, prove_only=prove_only)
            == 2
        )
        out = capsys.readouterr().out
        assert f"no_safari_route ({code})" in out
        assert al.SAFARI_INFEASIBLE_TEXT[code] in out


# ---------------------------------------------------------------------------
# The in_safari proof through the real Machine
# ---------------------------------------------------------------------------

SITE = "shop-tp1644"
SHOP = alsafari.Recipe(
    SITE,
    ("shop.example.org", "id.example.org"),
    "shop.example.org",
    w.SHOP.steps,
    start_url="https://shop.example.org/orders",
    sentinel="#account",
    broker=False,
    import_after=False,
)
LANDING = "https://shop.example.org/orders"
SENTINEL = ("https://shop.example.org/orders", w._page(sentinel=True))
FILLS = ("--login", "--otp", "--click")


class Safari(w.FakeSafari):
    """safari.py: the scripted login window, `--status`, the landing open,
    and the identity read's two evals (by the marker of the file's body)."""

    def __init__(self, recipe: alsafari.Recipe, script: list) -> None:
        super().__init__(recipe, script)
        self.answer: dict[str, Any] = {}
        self.evals: list[tuple[str, int, str]] = []  # (marker, file mode, argv)

    def __call__(self, args: list[str]) -> alsafari.Reply:
        if args[0] == "--status":
            self.calls.append(list(args))
            return alsafari.Reply(0, {"ok": True, "javascript": True})
        if args[0] == "--open" and "--new-window" not in args:
            self.calls.append(list(args))  # the landing page
            return alsafari.Reply(0, {"ok": True})
        if args[0] == "--eval":
            path = Path(args[1])
            body = path.read_text(encoding="utf-8")
            mode = stat.S_IMODE(os.stat(path).st_mode)
            for marker in ("identity-start", "identity-read"):
                if f"// agent-login:{marker}" in body:
                    self.calls.append(list(args))
                    self.evals.append((marker, mode, json.dumps(args)))
                    res = {"ok": True} if marker == "identity-start" else self.answer
                    return alsafari.Reply(0, {"ok": True, "result": json.dumps(res)})
        return super().__call__(args)

    def ops(self, *names: str) -> list[list[str]]:
        return [c for c in self.calls if c[0] in names]

    def landing_opens(self) -> list[list[str]]:
        return [c for c in self.ops("--open") if "--new-window" not in c]


@pytest.fixture
def run(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """A `-L SITE -s` run of the test recipe: st["safari"] is the fake."""
    st: dict[str, Any] = {
        "safari": None,
        "imports": [],
        "mail": [],
        "broker": [],
        "records": [],
    }
    monkeypatch.setitem(alsafari.RECIPES, SITE, SHOP)
    monkeypatch.setitem(al.SAFARI_ROUTES, SITE, al.SafariRoute(LANDING, "in_safari"))
    monkeypatch.setattr(alsafari, "scheduled", lambda: False)
    monkeypatch.setattr(alsafari, "interactive_gate", lambda *_a: None)
    monkeypatch.setattr(alsafari, "safari_py_bin", lambda: "safari-fake")
    monkeypatch.setattr(alsafari, "run_safari_py", lambda _b: st["safari"])
    monkeypatch.setattr(alsafari, "features", lambda _c: w.ALL_FEATURES)
    monkeypatch.setattr(alsafari, "load_overrides", dict)
    monkeypatch.setattr(alsafari, "POLL_S", 0)
    monkeypatch.setattr(alsafari.time, "sleep", lambda _s: None)
    monkeypatch.setattr(al, "resolve_site", lambda s: s)
    monkeypatch.setattr(al, "record_check", lambda *a, **_k: st["records"].append(a))
    monkeypatch.setattr(al, "_free_check", lambda _s: (2, {"code": "logged_out"}))
    monkeypatch.setattr(
        al,
        "_import_run",
        lambda s, agent: st["imports"].append(s) or al.BrowserRun(0, False, "", 0, {}),
    )
    monkeypatch.setattr(al, "_mail_code_dry_run", st["mail"].append)
    monkeypatch.setattr(al, "IDENTITY_READ_POLL_S", 0)

    def broker(op: str, **kw: Any) -> dict[str, Any]:
        st["broker"].append(op)
        if op == "identity_challenge":
            return {
                "ok": True,
                "nonce": st["nonce"],
                "challenge_id": "c1",
                "identity": "gitlab",
                "privilege": "user",
            }
        return {"ok": True, "result": st["verdict"]}

    monkeypatch.setattr(al, "broker_request", broker)
    return st


def _go(st: dict[str, Any], script: list, **kw: Any) -> int:
    st["safari"] = Safari(SHOP, script)
    rc: int = al.safari_target_action(SITE, "", **kw)
    return rc


def test_a_live_session_opens_the_landing_page_with_zero_fills(
    run: dict[str, Any],
) -> None:
    assert _go(run, [SENTINEL]) == 0
    fake = run["safari"]
    assert not fake.ops(*FILLS)
    assert fake.landing_opens() == [["--open", LANDING, "--wait", "20"]]
    assert not run["broker"] and not run["imports"]


def test_a_login_form_runs_the_recipe_steps_then_opens(run: dict[str, Any]) -> None:
    assert _go(run, w.TWO_STEP) == 0
    fake = run["safari"]
    assert [c[0] for c in fake.ops("--login")] == ["--login", "--login"]
    assert fake.landing_opens() == [["--open", LANDING, "--wait", "20"]]
    # the login window's open comes before any step, the landing page last
    assert fake.ops("--open")[0][:3] == ["--open", SHOP.start_url, "--new-window"]
    assert fake.calls[-1][0] == "--open"


def test_prove_only_on_a_login_form_is_safari_logged_out(
    run: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    assert _go(run, w.TWO_STEP, prove_only=True) == 2
    assert "safari_logged_out" in capsys.readouterr().out
    fake = run["safari"]
    assert not fake.ops(*FILLS) and not fake.landing_opens()
    assert not run["mail"] and not run["broker"] and not run["imports"]
    assert fake.ops("--close")  # the login window is closed


def test_prove_only_with_a_live_session_still_opens(run: dict[str, Any]) -> None:
    assert _go(run, [SENTINEL], prove_only=True) == 0
    assert run["safari"].landing_opens()


def test_the_dry_run_of_an_in_safari_route_calls_nothing(
    run: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    for prove_only, want in (
        (
            False,
            "prove Safari's session in a new window, else log Safari in, then open",
        ),
        (True, "prove Safari's session in a new window (no login), then open"),
    ):
        assert _go(run, [SENTINEL], dry_run=True, prove_only=prove_only) == 0
        text = capsys.readouterr().out
        assert f"-s would {want}" in text
        assert "no cookie rules" in text
        assert set(c[0] for c in run["safari"].calls) <= {"--status"}
    assert not run["mail"]  # no mail_code step


@pytest.mark.parametrize(
    "url",
    [
        "https://x.cloudflareaccess.com/cdn-cgi/access/login",
        "https://cloudflareaccess.com/",
    ],
)
def test_a_cloudflare_access_tab_is_alberts(
    url: str, run: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    assert _go(run, [(url, w._page(user=True))]) == 4
    out = capsys.readouterr().out
    assert run["records"][-1][3]["code"] == "needs_albert_access"
    assert "Cloudflare Access" in out
    assert "safari_tab_moved" not in out
    assert not run["safari"].ops(*FILLS) and not run["safari"].landing_opens()


@pytest.mark.parametrize("import_after", [False, True])
def test_the_import_runs_only_with_import_after(
    import_after: bool, run: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    recipe = alsafari.Recipe(**{**SHOP.__dict__, "import_after": import_after})
    monkeypatch.setitem(alsafari.RECIPES, SITE, recipe)
    run["safari"] = Safari(recipe, w.TWO_STEP)
    assert al.safari_target_action(SITE, "") == 0
    assert run["imports"] == ([SITE] if import_after else [])


# ---------------------------------------------------------------------------
# tp#1644 B8: the Safari-cookie routes (the real recipes)
# ---------------------------------------------------------------------------

# site → (landing, the listing's logged_in_selector, IdP host, import_after);
# the listing values as of 2026-11-04 (sites.json, `check_url` /
# `logged_in_selector`)
SC: dict[str, tuple[str, str, str, bool]] = {
    "anibis": (
        "https://www.anibis.ch/fr/myads/active",
        'input[data-testid="myads-searchbox"]',
        "auth.anibis.ch",
        True,
    ),
    "tutti": (
        "https://www.tutti.ch/de/myads/active",
        'input[data-testid="myads-searchbox"]',
        "auth.tutti.ch",
        True,
    ),
    "kleinanzeigen": (
        "https://www.kleinanzeigen.de/m-meine-anzeigen.html",
        "a#user-logout",
        "login.kleinanzeigen.de",
        True,
    ),
    "ricardo": (
        "https://www.ricardo.ch/de/my-ricardo/saved/articles/",
        'button[title="Nachrichten"]',
        "login.ricardo.ch",
        False,
    ),
    "galaxus": (
        "https://www.galaxus.ch/de/orders",
        '[data-testid="customer-account-button"]',
        "id.digitecgalaxus.ch",
        True,
    ),
    "galaxus-de": (
        "https://www.galaxus.de/de/orders",
        '[data-testid="customer-account-button"]',
        "id.galaxus.eu",
        True,
    ),
}
ITEM = "Shop Item"  # the listing's vault item name (fake)


def test_the_safari_cookie_routes_prove_in_safari_from_their_landing_page() -> None:
    for site, (landing, sentinel, idp, imports) in SC.items():
        recipe = alsafari.RECIPES[site]
        assert al.SAFARI_ROUTES[site] == al.SafariRoute(landing, "in_safari")
        assert recipe.start_url == landing and recipe.sentinel == sentinel
        assert recipe.import_after is imports and recipe.broker
        assert not recipe.identity
        assert urllib.parse.urlsplit(landing).hostname == recipe.sentinel_host
        assert al.safari_target_url(site, "") == landing
        assert {s.host for s in recipe.steps} == {idp}
        assert {s.kind for s in recipe.steps} == {"login", "user"}
        assert al.login_columns(site).safari


@pytest.fixture
def sc(run: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """`run` for the real SC recipes: the listing row (vault item, broker
    rules) from a fake `broker_state`, Safari's jar unreadable (no flush
    wait)."""

    def listing(**_k: Any) -> tuple[str, list[dict[str, Any]]]:
        rows = [
            {
                "site": site,
                "name": ITEM,
                # the recipe's own start page and sentinel win
                "login_url": "https://wrong.example.org/",
                "logged_in_selector": "#wrong",
                "no_submit": site in ("galaxus", "galaxus-de"),
            }
            for site in SC
        ]
        return "running, Bitwarden readable", rows

    monkeypatch.setattr(al, "broker_state", listing)
    monkeypatch.setattr(al, "_safari_jar", lambda _s: ([], "test"))
    return run


def _go_sc(st: dict[str, Any], site: str, script: list, **kw: Any) -> int:
    st["safari"] = Safari(alsafari.RECIPES[site], script)
    rc: int = al.safari_target_action(site, "", **kw)
    return rc


def _landed(site: str) -> tuple[str, dict]:
    return (SC[site][0], w._page(sentinel=True))


def _one_page(site: str) -> list:
    idp = SC[site][2]
    page = w._page(
        user=True, password=True, steps=[[True, False], [False, True], [False, False]]
    )
    return [(f"https://{idp}/login", page), _landed(site)]


def _two_page(site: str) -> list:
    idp = SC[site][2]
    return [
        (
            f"https://{idp}/login",
            w._page(user=True, steps=[[False, False], [True, False], [False, False]]),
        ),
        (
            f"https://{idp}/password",
            w._page(
                password=True, steps=[[False, False], [False, True], [True, False]]
            ),
        ),
        _landed(site),
    ]


def _value(call: list[str], opt: str) -> str:
    return call[call.index(opt) + 1]


@pytest.mark.parametrize("site", sorted(SC))
def test_sc_a_live_session_opens_the_landing_page_with_zero_fills(
    site: str, sc: dict[str, Any]
) -> None:
    assert _go_sc(sc, site, [_landed(site)]) == 0
    fake = sc["safari"]
    assert not fake.ops(*FILLS)
    # the proof window opens on the landing page, the landing tab last
    assert fake.ops("--open")[0][:3] == ["--open", SC[site][0], "--new-window"]
    assert fake.landing_opens() == [["--open", SC[site][0], "--wait", "20"]]
    assert not sc["broker"]


@pytest.mark.parametrize("site", sorted(SC))
def test_sc_prove_only_on_a_login_form_is_safari_logged_out(
    site: str, sc: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    assert _go_sc(sc, site, _one_page(site), prove_only=True) == 2
    assert "safari_logged_out" in capsys.readouterr().out
    fake = sc["safari"]
    assert not fake.ops(*FILLS) and not fake.landing_opens()
    assert not sc["broker"] and not sc["imports"] and not sc["mail"]


@pytest.mark.parametrize("shape", ["one_page", "two_page"])
@pytest.mark.parametrize("site", sorted(SC))
def test_sc_a_login_form_fills_through_safari_py_on_the_idp_host(
    site: str, shape: str, sc: dict[str, Any]
) -> None:
    script = _one_page(site) if shape == "one_page" else _two_page(site)
    assert _go_sc(sc, site, script) == 0
    fake = sc["safari"]
    fills = fake.ops(*FILLS)
    assert fills and all(c[0] == "--login" for c in fills)
    steps = alsafari.RECIPES[site].steps
    want = (
        [steps[0].submit] if shape == "one_page" else [steps[1].submit, steps[2].submit]
    )
    assert len(fills) == len(want)
    for call, submit in zip(fills, want, strict=True):
        assert call[1] == ITEM
        assert _value(call, "--expect-host") == SC[site][2]  # the IdP, every time
        assert _value(call, "--submit") == submit
    assert fake.landing_opens() == [["--open", SC[site][0], "--wait", "20"]]
    assert not sc["broker"]  # no broker op: safari.py fills (safari_fill)


@pytest.mark.parametrize("prove_only", [False, True])
@pytest.mark.parametrize("site", ["anibis", "tutti"])
def test_sc_an_auth0_captcha_is_alberts_and_nothing_is_submitted(
    site: str, prove_only: bool, sc: dict[str, Any]
) -> None:
    page = w._page(
        captcha=True, user=True, steps=[[False, False], [True, False], [False, False]]
    )
    script = [(f"https://{SC[site][2]}/u/login/identifier", page)]
    assert _go_sc(sc, site, script, prove_only=prove_only) == 4
    assert sc["records"][-1][3]["code"] == "needs_albert_captcha"
    fake = sc["safari"]
    assert not fake.ops(*FILLS) and not fake.landing_opens()
    assert not sc["imports"]
    assert al.als.quarantined(site) is None  # nothing typed: no quarantine


@pytest.mark.parametrize("site", ["galaxus", "galaxus-de"])
def test_galaxus_no_submit_stays_the_brokers_rule_only(
    site: str, sc: dict[str, Any]
) -> None:
    # Safari submits although the listing row says no_submit: that rule is
    # the broker's headless login's, never read on the Safari path
    assert _go_sc(sc, site, _one_page(site)) == 0
    (fill,) = sc["safari"].ops("--login")
    assert _value(fill, "--submit") == "Weiter"
    assert not sc["broker"]  # no broker op, no headless login
    # the broker's headless rule is untouched
    assert {"galaxus", "galaxus-de"} <= vault.NO_SUBMIT_SITES
    assert vault.no_submit_by_origin([f"https://{SC[site][2]}"])


@pytest.mark.parametrize("live", [True, False])
def test_ricardo_never_imports(live: bool, sc: dict[str, Any]) -> None:
    script = [_landed("ricardo")] if live else _two_page("ricardo")
    assert _go_sc(sc, "ricardo", script) == 0
    assert not sc["imports"]
    assert sc["safari"].landing_opens()


@pytest.mark.parametrize("site", sorted(set(SC) - {"ricardo"}))
def test_the_other_sc_sites_import_when_chromium_is_logged_out(
    site: str, sc: dict[str, Any]
) -> None:
    assert _go_sc(sc, site, [_landed(site)]) == 0
    assert sc["imports"] == [site]


# ---------------------------------------------------------------------------
# tp#1644 B6: the built-in routes (slack, openai; the real recipes)
# ---------------------------------------------------------------------------

# site → (landing, the login page the Google click is on, the sentinel page)
BI: dict[str, tuple[str, str, str]] = {
    "slack": (
        "https://swiss-data-science.slack.com/",
        "https://swiss-data-science.slack.com/",
        "https://app.slack.com/client/T1/C1",
    ),
    "openai": (
        "https://chatgpt.com/",
        "https://auth.openai.com/log-in",
        "https://chatgpt.com/",
    ),
}
GOOGLE = "accounts.google.com"
ACCOUNT = "albert@example.org"  # the override file's Google account (fake)


def test_slack_labels_match_the_live_sign_in_page() -> None:
    """B7 L2 read (2026-11-04): Slack's sign-in page labels its buttons
    "Google" and "Sign in with email"; safari.py matches labels exactly, so
    the old "Sign In With Google" / "Sign In With Email" ended
    `recipe_stuck` before anything was sent."""
    steps = alsafari.RECIPES["slack"].steps
    assert (steps[0].kind, steps[0].trigger) == ("click", "Google")
    assert steps[0].optional
    mail = next(s for s in steps if s.kind == "mail_code")
    assert mail.trigger == "Sign in with email"
    # the logged-in client (app.slack.com) carries data-qa "channel-sidebar"
    assert alsafari.RECIPES["slack"].sentinel == '[data-qa="channel-sidebar"]'


def test_the_builtin_routes_use_the_throwaway_proof() -> None:
    for site, (landing, _login, _done) in BI.items():
        assert al.SAFARI_ROUTES[site] == al.SafariRoute(landing, "builtin")
        assert al.safari_target_url(site, "") == landing
        assert al.login_columns(site).safari
        recipe = alsafari.RECIPES[site]
        assert recipe.identity == site and not recipe.broker and recipe.import_after
    assert al.has_mail_code(alsafari.RECIPES["slack"])
    assert not al.has_mail_code(alsafari.RECIPES["openai"])
    assert al.MAIL_CODE_ENV["slack"] == {"SDSC_EMAIL_NO_AUTO_AUTH": "1"}
    assert al.als.mail_code_file("slack") == "slack-mail-code.json"
    # the headless -M set stays notion's
    assert "slack" not in al.MAIL_CODE_SITES


@pytest.fixture
def bi(run: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """`run` for a built-in route: Safari's jar (`held`), the `-P` proof's
    verdict (`proof`), the override file (`over`); no flush wait, no
    himalaya."""
    run.update(held=True, proof=(0, "match"), over={"account": ACCOUNT}, proofs=[])

    def run_browser(*args: Any, **_k: Any) -> Any:
        run["proofs"].append(args)
        rc, said = run["proof"]
        return al.BrowserRun(rc, False, "", 0.0, {"safari": said, "code": said})

    monkeypatch.setattr(al, "_safari_jar", lambda _s: ([], None))
    monkeypatch.setattr(
        al.safari_cookies, "has_session", lambda _s, _c: bool(run["held"])
    )
    monkeypatch.setattr(al, "run_browser", run_browser)
    monkeypatch.setattr(al, "site_session", lambda _s: contextlib.nullcontext())
    monkeypatch.setattr(al, "_wait_flush", lambda _s, _b: True)
    monkeypatch.setattr(
        alsafari, "load_overrides", lambda: {s: dict(run["over"]) for s in BI}
    )
    monkeypatch.setattr(al.shutil, "which", lambda _n: None)
    return run


def _go_bi(st: dict[str, Any], site: str, script: list, **kw: Any) -> int:
    st["safari"] = Safari(alsafari.RECIPES[site], script)
    rc: int = al.safari_target_action(site, "", **kw)
    return rc


def _google_login(site: str) -> list:
    """The login page's Google button, the chooser, the consent, the
    logged-in page (`steps`: one [when, unless] per recipe step)."""
    _landing, login, done = BI[site]
    n = len(alsafari.RECIPES[site].steps)

    def on(i: int) -> list[list[bool]]:
        return [[j == i, False] for j in range(n)]

    return [
        (login, w._page(steps=on(0))),
        (f"https://{GOOGLE}/o/oauth2/chooser", w._page(steps=on(1))),
        (f"https://{GOOGLE}/signin/oauth/consent", w._page(steps=on(2))),
        (done, w._page(sentinel=True)),
    ]


@pytest.mark.parametrize("site", sorted(BI))
def test_bi_a_proven_session_only_opens_the_landing_page(
    site: str, bi: dict[str, Any]
) -> None:
    assert _go_bi(bi, site, [_google_login(site)[-1]]) == 0
    assert bi["proofs"][0][:3] == ("import-safari", site, "-P")
    fake = bi["safari"]
    # no Machine window, no step: safari.py's status, then the landing page
    assert [c[0] for c in fake.calls] == ["--status", "--open"]
    assert fake.landing_opens() == [["--open", BI[site][0], "--wait", "20"]]
    assert not (al.als.state_dir() / al.als.mail_code_file(site)).exists()


@pytest.mark.parametrize("held", [True, False])
@pytest.mark.parametrize("site", sorted(BI))
def test_bi_logged_out_runs_the_google_steps_then_opens(
    site: str, held: bool, bi: dict[str, Any]
) -> None:
    bi["held"] = held
    bi["proof"] = (2, "logged_out")
    assert _go_bi(bi, site, _google_login(site)) == 0
    assert len(bi["proofs"]) == (1 if held else 0)  # no session: no proof run
    fake = bi["safari"]
    clicks = fake.ops("--click")
    assert [c[1] for c in clicks] == [
        alsafari.RECIPES[site].steps[0].trigger,
        ACCOUNT,
        "Continue",
    ]
    assert [_value(c, "--expect-host") for c in clicks] == [
        urllib.parse.urlsplit(BI[site][1]).hostname,
        GOOGLE,
        GOOGLE,
    ]
    assert not fake.ops("--login", "--otp")  # no password, no TOTP
    assert fake.landing_opens() == [["--open", BI[site][0], "--wait", "20"]]
    assert bi["imports"] == [site]  # the shared Chromium was logged out
    # Google's way in: no code mail, no cooldown stamp
    assert not (al.als.state_dir() / al.als.mail_code_file(site)).exists()


@pytest.mark.parametrize("held", [True, False])
@pytest.mark.parametrize("site", sorted(BI))
def test_bi_prove_only_and_logged_out_is_exit_2_without_steps(
    site: str, held: bool, bi: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    bi["held"] = held
    bi["proof"] = (2, "logged_out")
    assert _go_bi(bi, site, _google_login(site), prove_only=True) == 2
    assert "safari_logged_out" in capsys.readouterr().out
    fake = bi["safari"]
    assert [c[0] for c in fake.calls] == ["--status"]  # no window, no step
    assert not bi["imports"] and not bi["mail"]
    assert not (al.als.state_dir() / al.als.mail_code_file(site)).exists()


@pytest.mark.parametrize("site", sorted(BI))
def test_bi_the_google_chooser_picks_only_the_expected_account(
    site: str, bi: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    bi["proof"] = (2, "logged_out")
    assert _go_bi(bi, site, _google_login(site)) == 0
    on_google = [
        c
        for c in bi["safari"].ops("--click")
        if _value(c, "--expect-host") == GOOGLE and c[1] != "Continue"
    ]
    # exactly one pick on Google: the configured account, its row only
    (pick,) = on_google
    assert pick[:4] == ["--click", ACCOUNT, "--row", ACCOUNT]
    # no account configured: the chooser is never clicked
    capsys.readouterr()
    bi["over"] = {}
    assert _go_bi(bi, site, _google_login(site)) == 2
    assert bi["records"][-1][3]["code"] == "identity_unconfigured"
    assert [c[1] for c in bi["safari"].ops("--click")] == [
        alsafari.RECIPES[site].steps[0].trigger
    ]
    assert not bi["safari"].landing_opens()


@pytest.mark.parametrize(
    ("flag", "code"),
    [("push", "needs_albert_push"), ("hardware_key", "needs_albert_hardware_key")],
)
@pytest.mark.parametrize("site", sorted(BI))
def test_bi_a_google_push_or_passkey_page_is_alberts(
    site: str, flag: str, code: str, bi: dict[str, Any]
) -> None:
    bi["proof"] = (2, "logged_out")
    login = _google_login(site)
    script = [login[0], (f"https://{GOOGLE}/signin/challenge", w._page(**{flag: True}))]
    assert _go_bi(bi, site, script) == 4
    assert bi["records"][-1][3]["code"] == code
    fake = bi["safari"]
    assert len(fake.ops("--click")) == 1  # the Google button only
    assert not fake.landing_opens() and not bi["imports"]


class _MailDrive:  # pylint: disable=too-few-public-methods
    """`_drive_safari` of slack's mail-code fallback: records the cooldown
    seen at the trigger (after the hook), the env and the no-trigger mode."""

    def __init__(self) -> None:
        self.log: list[tuple[str, Any]] = []

    def __call__(self, site: str, _recipe: Any, **kw: Any) -> alsafari.Outcome:
        self.log.append(("env", kw.get("env")))
        if kw.get("no_trigger"):
            self.log.append(("no_trigger", kw["no_trigger"]))
            return alsafari.Outcome(2, kw["no_trigger"])
        stop = kw["before_trigger"]()
        if stop:
            return alsafari.Outcome(2, stop)
        self.log.append(("click", al.als.mail_code_cooldown_left(site, time.time())))
        return alsafari.Outcome(0, "ok", credential=True, steps=["mail_code"])


def test_slack_mail_code_fallback_stamps_before_the_trigger(
    bi: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    drive = _MailDrive()
    monkeypatch.setattr(al, "_drive_safari", drive)
    bi["proof"] = (2, "logged_out")
    assert _go_bi(bi, "slack", []) == 0
    assert [k for k, _v in drive.log] == ["env", "click"]
    assert drive.log[0][1] == {"SDSC_EMAIL_NO_AUTO_AUTH": "1"}
    # stamped first: the trigger already sees a full cooldown
    assert drive.log[1][1] == pytest.approx(al.als.MAIL_CODE_COOLDOWN_S, abs=5)
    assert (al.als.state_dir() / "slack-mail-code.json").is_file()
    assert not (al.als.state_dir() / "notion-mail-code.json").exists()


def test_slack_inside_the_cooldown_runs_without_a_code_mail(
    bi: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    drive = _MailDrive()
    monkeypatch.setattr(al, "_drive_safari", drive)
    bi["proof"] = (2, "logged_out")
    assert al.als.mail_code_stamp("slack", time.time())
    path = al.als.state_dir() / "slack-mail-code.json"
    before = path.read_bytes()
    assert _go_bi(bi, "slack", []) == 2
    assert ("no_trigger", "cooldown") in drive.log
    assert not any(k == "click" for k, _v in drive.log)
    assert path.read_bytes() == before  # never re-stamped
    assert al.als.quarantined("slack") is None


# ---------------------------------------------------------------------------
# The in-Safari identity read
# ---------------------------------------------------------------------------


@pytest.fixture
def ident(run: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """`run` for a multi-account row: a listing `identity` (gitlab)."""
    _snapshot(
        monkeypatch,
        [
            {
                "site": SITE,
                "identity": "gitlab",
                "privilege": "user",
                "check_url": "https://shop.example.org/-/profile",
            }
        ],
    )
    monkeypatch.setattr(
        al.identity, "item_recipe", lambda *_a, **_k: identity.IDENTITIES["gitlab"]
    )
    run["nonce"] = secrets.token_hex(32)
    run["answer"] = {"state": "found", "digest": secrets.token_hex(32), "admin": False}
    return run


def _go_ident(st: dict[str, Any], script: list, verdict: str) -> int:
    st["verdict"] = verdict
    st["safari"] = Safari(SHOP, script)
    st["safari"].answer = st["answer"]
    rc: int = al.safari_target_action(SITE, "")
    return rc


def test_identity_mismatch_is_wrong_account_with_zero_fills(
    ident: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    assert _go_ident(ident, [SENTINEL], "mismatch") == 2
    assert "wrong_account" in capsys.readouterr().out
    fake = ident["safari"]
    assert not fake.ops(*FILLS) and not fake.landing_opens()
    assert ident["broker"] == ["identity_challenge", "identity_answer"]


def test_identity_match_opens_the_landing_page(ident: dict[str, Any]) -> None:
    assert _go_ident(ident, [SENTINEL], "match") == 0
    fake = ident["safari"]
    assert not fake.ops(*FILLS) and fake.landing_opens()


@pytest.mark.parametrize(
    ("answer", "verdict"),
    [({"state": "logged_out"}, "match"), ({"state": "found", "digest": "x"}, "match")],
)
def test_an_unproven_identity_is_indeterminate(
    answer: dict, verdict: str, ident: dict[str, Any]
) -> None:
    ident["answer"] = answer
    assert _go_ident(ident, [SENTINEL], verdict) == 2
    assert ident["broker"] == ["identity_challenge"]  # never answered
    assert not ident["safari"].landing_opens()


def test_the_identity_js_goes_through_a_private_file_never_argv(
    ident: dict[str, Any],
) -> None:
    assert _go_ident(ident, [SENTINEL], "match") == 0
    evals = ident["safari"].evals
    assert [e[0] for e in evals] == ["identity-start", "identity-read"]
    for _marker, mode, argv in evals:
        assert mode == 0o600
        assert ident["nonce"] not in argv and "RECIPE" not in argv
        assert "async" not in argv and "agent-login:" not in argv
    # the files are gone after the run
    for call in ident["safari"].ops("--eval"):
        assert not Path(call[1]).exists()


# ---------------------------------------------------------------------------
# What page JS can do to the identity read (Safari: MAIN world)
# ---------------------------------------------------------------------------

_NODE = shutil.which("node")
# The hostile page's hooks, installed BEFORE the agent's evals (they share
# the page's globals: `do JavaScript` has no isolated world). Mode "fetch":
# it answers the recipe's own request with a name of its choice. Mode
# "park": it learns the nonce from a hooked RegExp.test, computes the digest
# itself and pins the parked answer slot with a setter that drops the
# recipe's write.
_PAGE = r"""(async () => {
  globalThis.window = globalThis;
  globalThis.location = {origin: __P_ORIGIN__};
  const seen = {};
  const realTest = RegExp.prototype.test;
  RegExp.prototype.test = function (s) {
    if (typeof s === 'string' && /^[0-9a-f]{64}$/.exec(s)) seen.nonce = s;
    return realTest.call(this, s);
  };
  if (__P_MODE__ === 'fetch') {
    globalThis.fetch = async (href) => {
      const r = new Response(JSON.stringify({username: __P_FORGED__, is_admin: false}),
        {status: 200, headers: {'content-type': 'application/json'}});
      Object.defineProperty(r, 'url', {value: href});
      return r;
    };
  } else {
    globalThis.fetch = async () => { throw new TypeError('offline'); };
  }
  (0, eval)(__P_START__);
  seen.parked = Object.keys(window).filter(k => k.startsWith('__agentLoginIdentity_'));
  if (__P_MODE__ === 'park') {
    const data = new Uint8Array([...Buffer.from(seen.nonce, 'hex'), ...Buffer.from(__P_FORGED__)]);
    const d = Buffer.from(await crypto.subtle.digest('SHA-256', data)).toString('hex');
    const fake = {state: 'found', digest: d, admin: false};
    Object.defineProperty(window, seen.parked[0],
      {configurable: true, enumerable: true, get: () => fake, set: () => {}});
  }
  let read;
  for (let i = 0; i < 200; i++) {
    read = JSON.parse((0, eval)(__P_READ__));
    if (!read.pending) break;
    await new Promise(r => setTimeout(r, 5));
  }
  console.log(JSON.stringify({seen, read}));
})();
"""


@pytest.mark.skipif(_NODE is None, reason="node not installed")
@pytest.mark.parametrize("mode", ["fetch", "park"])
def test_page_js_can_forge_the_identity_answer(mode: str, tmp_path: Path) -> None:
    """DOCUMENTS a weakness (reported to the overseer, not fixed in B2):
    in Safari's MAIN world the page sees the nonce and can make the read
    return sha256(nonce || a name of its choice) — a `match` whenever the
    page knows the item's username. Flip this test when the read is moved
    out of the page's reach."""
    assert _NODE is not None
    nonce = secrets.token_hex(32)
    forged = "someone-" + secrets.token_hex(4)
    key = f"__agentLoginIdentity_{secrets.token_hex(8)}"
    recipe = identity.IDENTITIES["gitlab"]
    args = identity.recipe_args(recipe, "https://gitlab.example.org/-/profile", nonce)
    values = {
        "__P_ORIGIN__": "https://gitlab.example.org",
        "__P_MODE__": mode,
        "__P_FORGED__": forged,
        "__P_START__": alsafari.identity_start_js(identity.RECIPE_JS, args, key),
        "__P_READ__": alsafari.identity_read_js(key),
    }
    script = _PAGE
    for name, value in values.items():
        script = script.replace(name, json.dumps(value))
    page = tmp_path / "page.js"
    page.write_text(script, encoding="utf-8")
    out = subprocess.run(
        [_NODE, str(page)], capture_output=True, text=True, check=True, timeout=60
    ).stdout
    got = json.loads(out)
    assert got["seen"]["parked"] == [key]  # the slot is enumerable
    assert got["seen"]["nonce"] == nonce  # the page sees the nonce
    assert got["read"]["state"] == "found"
    assert got["read"]["digest"] == identity.challenge_digest(nonce, forged)


# ---------------------------------------------------------------------------
# tp#1644 B10: broker-built Safari routes (listing row + probe labels)
# ---------------------------------------------------------------------------

BSITE = "selfhost-tp1644"
BLANDING = "https://app.example.org/home"
BROW: dict[str, Any] = {
    "site": BSITE,
    "name": "Selfhost",
    "safari_fill": True,
    "refused": False,
    "fill_only": False,
    "fill_origins": ["https://id.example.org"],
    "check_url": BLANDING,
    "login_url": "https://app.example.org/login",
    "logged_in_selector": "#me",
    "privilege": None,
    "identity": None,
}
TWO_LABELS = alsafari.BrokerLabels(
    "two_step", pass_submit="Sign in", user_submit="Next", otp_submit="Verify"
)


def test_a_listing_row_and_labels_build_the_recipe() -> None:
    recipe = alsafari.broker_recipe(BROW, TWO_LABELS)
    assert recipe is not None
    assert recipe.hosts == ("id.example.org", "app.example.org")
    assert recipe.start_url == BLANDING
    assert recipe.sentinel_host == "app.example.org"
    assert recipe.broker and not recipe.import_after and not recipe.identity
    assert recipe.sentinel == ""  # the listing's logged_in_selector (_safari_plan)
    assert [(s.kind, s.host, s.submit, s.after) for s in recipe.steps] == [
        ("user", "id.example.org", "Next", ""),
        ("login", "id.example.org", "Sign in", "user"),
        ("otp", "id.example.org", "Verify", "login"),
    ]
    one = alsafari.broker_recipe(
        {**BROW, "identity": "gitlab"},
        alsafari.BrokerLabels("one_page", pass_submit="Log in"),
    )
    assert one is not None and one.identity == BSITE
    assert [(s.kind, s.when) for s in one.steps] == [("login", alsafari.ONE_PAGE_FORM)]


@pytest.mark.parametrize(
    "change",
    [
        {"safari_fill": False},
        {"refused": True},
        {"fill_only": True},
        {"check_url": "http://app.example.org/"},
        {"fill_origins": ["not a url"]},
        {"pre_click": "#show-login"},  # no label for it: never a guess
    ],
)
def test_a_row_the_labels_do_not_fit_builds_no_recipe(change: dict) -> None:
    assert alsafari.broker_recipe({**BROW, **change}, TWO_LABELS) is None


def test_labels_naming_a_foreign_idp_build_no_recipe() -> None:
    labels = alsafari.BrokerLabels("one_page", pass_submit="x", idp="evil.example")
    assert alsafari.broker_recipe(BROW, labels) is None
    assert alsafari.broker_recipe(BROW, alsafari.BrokerLabels("x", "y")) is None


def test_pre_click_is_a_click_step_before_the_form() -> None:
    labels = alsafari.BrokerLabels(
        "one_page", pass_submit="Sign in", pre_click_label="Manual login"
    )
    recipe = alsafari.broker_recipe({**BROW, "pre_click": "#manual"}, labels)
    assert recipe is not None
    click = recipe.steps[0]
    assert (click.kind, click.trigger, click.when) == (
        "click",
        "Manual login",
        "#manual",
    )
    assert click.unless == 'input[type="password"]' and click.optional
    assert [s.kind for s in recipe.steps] == ["click", "login"]


def test_b10_ships_no_labels_no_stops_and_no_identity_route() -> None:
    # tp#1644 B13: zoho-desk's probe labels are the only ones so far
    assert set(alsafari.BROKER_SAFARI_LABELS) == B13_LABELLED
    # tp#1644 B12: the SaaS sites' own stops only, none for B10's sites
    assert set(alsafari.BROKER_SAFARI_STOPS) == set(B12_STOPS)
    assert al.SAFARI_IDENTITY_READ_SAFE is False
    for site in ("aurral", "jellyfin", "dsm-readonly", "welib", "abs-albert"):
        assert site in al.SAFARI_ROUTES
        assert al.safari_recipe(site) is None and not al.safari_routed(site)
    assert "dsm-albert" not in al.SAFARI_ROUTES


@pytest.fixture
def broker_run(run: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """`run` for a broker-built route: labels, listing row, route entry."""
    monkeypatch.setitem(alsafari.BROKER_SAFARI_LABELS, BSITE, TWO_LABELS)
    monkeypatch.setitem(al.SAFARI_ROUTES, BSITE, al.SafariRoute(BLANDING, "in_safari"))
    _snapshot(monkeypatch, [BROW])
    monkeypatch.setattr(al, "broker_state", lambda **_k: ("ok", [BROW]))
    monkeypatch.setattr(
        al, "record_safari_fail", lambda *a: run["safari_fails"].append(a)
    )
    every = w.ALL_FEATURES | frozenset(alsafari.STEP_FEATURES.values())
    monkeypatch.setattr(alsafari, "features", lambda _c: every)
    run["safari_fails"] = []
    return run


def _go_broker(st: dict[str, Any], script: list, **kw: Any) -> int:
    recipe = al.safari_recipe(BSITE)
    assert recipe is not None
    st["safari"] = Safari(recipe, script)
    rc: int = al.safari_target_action(BSITE, "", **kw)
    return rc


B_LOGIN = "https://id.example.org/login"
B_SENTINEL = (BLANDING, w._page(sentinel=True))


def test_no_labels_is_no_route(
    broker_run: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert al.safari_routed(BSITE) and al.login_columns(BSITE, BROW).safari
    monkeypatch.delitem(alsafari.BROKER_SAFARI_LABELS, BSITE)
    assert not al.safari_routed(BSITE)
    cols = al.login_columns(BSITE, BROW)
    assert not cols.safari and not cols.safari_why  # ❌, not ⛔
    assert al.safari_target_action(BSITE, "") == 2
    assert "no_safari_route" in capsys.readouterr().out


def test_a_broker_route_with_a_live_session_opens_with_zero_fills(
    broker_run: dict[str, Any],
) -> None:
    assert _go_broker(broker_run, [B_SENTINEL]) == 0
    fake = broker_run["safari"]
    assert not fake.ops(*FILLS) and not broker_run["imports"]
    assert fake.landing_opens() == [["--open", BLANDING, "--wait", "20"]]


def test_totp_runs_only_after_the_password_step(broker_run: dict[str, Any]) -> None:
    # a code field before the password step: the otp step never runs
    early = [
        (
            B_LOGIN,
            w._page(code=True, steps=[[False, False], [False, False], [True, False]]),
        )
    ]
    assert _go_broker(broker_run, early) == 2
    assert not broker_run["safari"].ops(*FILLS)
    flow = [
        (
            B_LOGIN,
            w._page(user=True, steps=[[True, False], [False, False], [True, False]]),
        ),
        (
            B_LOGIN,
            w._page(password=True, steps=[[False, True], [True, False], [True, False]]),
        ),
        (
            B_LOGIN,
            w._page(code=True, steps=[[False, False], [False, False], [True, False]]),
        ),
        B_SENTINEL,
    ]
    assert _go_broker(broker_run, flow) == 0
    fills = broker_run["safari"].ops(*FILLS)
    assert [c[0] for c in fills] == ["--login", "--login", "--otp"]
    assert "--user-only" in fills[0] and "--no-user" in fills[1]
    assert fills[2][:2] == ["--otp", "Selfhost"]


def test_an_access_interstitial_is_alberts_and_not_a_chromium_failure(
    broker_run: dict[str, Any],
) -> None:
    url = "https://x.cloudflareaccess.com/cdn-cgi/access/login"
    assert _go_broker(broker_run, [(url, w._page(user=True))]) == 4
    assert not broker_run["safari"].ops(*FILLS)
    assert not broker_run["records"]  # checks.json (the Chromium row) untouched
    assert broker_run["safari_fails"][-1][3]["code"] == "needs_albert_access"


def test_a_failed_broker_login_quarantines_but_keeps_the_chromium_row(
    broker_run: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    quarantined: list[str] = []
    monkeypatch.setattr(al.als, "quarantine", lambda s, *_a: quarantined.append(s))
    stuck = [
        (
            B_LOGIN,
            w._page(user=True, steps=[[True, False], [False, False], [False, False]]),
        )
    ]
    assert _go_broker(broker_run, stuck) == 2  # the user step, then stuck
    assert quarantined == [BSITE]
    assert not broker_run["records"]
    assert broker_run["safari_fails"][-1][1] is False


def test_record_safari_fail_writes_its_own_file() -> None:
    al.record_safari_fail(BSITE, False, "stopped", {"phase": "fill", "code": "x"})
    data = al.als.read(al.SAFARI_FAILS_FILE)
    assert data["sites"][BSITE]["code"] == "x"
    assert data["sites"][BSITE]["state"] == "failed"
    assert BSITE not in al.als.checks()


def _old_fail(site: str) -> None:
    """A stale failure entry of `site` in safari-checks.json."""

    def put(data: dict[str, Any]) -> None:
        data.setdefault("sites", {})[site] = {"state": "failed", "code": "x"}

    al.als.update(al.SAFARI_FAILS_FILE, put)


def _fails() -> dict[str, Any]:
    sites: dict[str, Any] = al.als.read(al.SAFARI_FAILS_FILE).get("sites", {})
    return sites


@pytest.mark.parametrize("prove_only", [False, True], ids=["-s", "-O"])
def test_a_passed_broker_proof_clears_its_old_failure(
    broker_run: dict[str, Any], prove_only: bool
) -> None:
    # tp#1644 canary follow-up: zoho-desk's 16:44 recipe_stuck outlived the
    # passing canary — a passed -s / -O proof drops the site's entry only
    _old_fail(BSITE)
    _old_fail("other-site")
    assert _go_broker(broker_run, [B_SENTINEL], prove_only=prove_only) == 0
    assert set(_fails()) == {"other-site"}
    assert not broker_run["records"]  # checks.json (the Chromium row) untouched


def test_a_failed_broker_proof_keeps_its_failure(broker_run: dict[str, Any]) -> None:
    _old_fail(BSITE)
    url = "https://x.cloudflareaccess.com/cdn-cgi/access/login"
    assert _go_broker(broker_run, [(url, w._page(user=True))]) == 4
    assert BSITE in _fails()


def test_clearing_leaves_hand_written_routes_and_absent_entries_alone(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    hand = next(iter(alsafari.RECIPES))
    assert not al.broker_built_route(hand)
    _old_fail(hand)
    al.clear_safari_fail(hand)
    assert hand in _fails()
    # a broker route without an entry: the file is not rewritten
    monkeypatch.setitem(alsafari.BROKER_SAFARI_LABELS, BSITE, TWO_LABELS)
    assert al.broker_built_route(BSITE)
    writes: list[str] = []
    monkeypatch.setattr(al.als, "update", lambda name, _fn: writes.append(name))
    al.clear_safari_fail(BSITE)
    assert not writes


def test_a_listing_identity_row_is_no_route_until_the_read_is_isolated(
    broker_run: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    row = {**BROW, "identity": "gitlab", "privilege": "user"}
    _snapshot(monkeypatch, [row])
    assert al.safari_recipe(BSITE) is None and not al.safari_routed(BSITE)
    monkeypatch.setattr(al, "SAFARI_IDENTITY_READ_SAFE", True)
    recipe = al.safari_recipe(BSITE)
    assert recipe is not None and recipe.identity == BSITE


def test_a_multi_account_broker_route_mismatch_is_wrong_account(
    broker_run: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    row = {**BROW, "identity": "gitlab", "privilege": "user"}
    _snapshot(monkeypatch, [row])
    monkeypatch.setattr(al, "broker_state", lambda **_k: ("ok", [row]))
    monkeypatch.setattr(al, "SAFARI_IDENTITY_READ_SAFE", True)
    monkeypatch.setattr(
        al.identity, "item_recipe", lambda *_a, **_k: identity.IDENTITIES["gitlab"]
    )
    broker_run["nonce"] = secrets.token_hex(32)
    broker_run["verdict"] = "mismatch"
    recipe = al.safari_recipe(BSITE)
    assert recipe is not None
    broker_run["safari"] = Safari(recipe, [B_SENTINEL])
    broker_run["safari"].answer = {
        "state": "found",
        "digest": secrets.token_hex(32),
        "admin": False,
    }
    assert al.safari_target_action(BSITE, "") == 2
    assert "wrong_account" in capsys.readouterr().out
    assert not broker_run["safari"].ops(*FILLS)
    assert not broker_run["safari"].landing_opens()


def test_the_dsm_pair_routes_only_the_held_account(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ro, adm = "dsm-readonly", "dsm-albert"
    admin_row = {"privilege": "admin"}
    # undecided (B11 step 0 pending): no group reason, the admin rule only
    assert al.safari_why(ro, {}) == "" and not al.safari_routed(ro)
    assert al.safari_why(adm, admin_row) == "admin_account"
    labels = alsafari.BrokerLabels("one_page", pass_submit="Sign in")
    monkeypatch.setitem(alsafari.BROKER_SAFARI_LABELS, ro, labels)
    dsm = {
        **BROW,
        "site": ro,
        "fill_origins": ["https://synology.dom42.space"],
        "check_url": "https://synology.dom42.space/",
        "login_url": "https://synology.dom42.space/",
    }
    _snapshot(monkeypatch, [dsm])
    monkeypatch.setitem(al.SAFARI_HELD, "dsm", ro)
    assert al.safari_routed(ro) and al.safari_why(ro, {}) == ""
    assert not al.safari_routed(adm)
    assert al.safari_why(adm, {}) == "second_account"
    assert al.safari_why(adm, admin_row) == "admin_account"  # the admin rule wins
    monkeypatch.setitem(al.SAFARI_HELD, "dsm", adm)
    assert not al.safari_routed(ro) and al.safari_why(ro, {}) == "second_account"
    monkeypatch.setitem(al.SAFARI_HELD, "dsm", "")
    assert not al.safari_routed(ro)
    assert al.safari_why(ro, {}) == "not_held" == al.safari_why(adm, {})
    assert al.login_columns(ro, dsm).safari_why == "not_held"


def test_a_site_stop_ends_the_run_only_after_its_step() -> None:
    stop = alsafari.SiteStop("needs_albert_push", r"OneAuth", after="login")
    recipe = alsafari.Recipe(**{**w.SHOP.__dict__, "stops": (stop,)})
    hit = [True]
    before = w._page(steps=[[False, False], [False, False]], stops=hit)
    fake = w.FakeSafari(recipe, [("https://id.example.org/login", before)])
    out = w._machine(fake).run()
    assert out.code == "recipe_stuck"  # not before the password step
    pages = [
        (
            "https://id.example.org/pw",
            w._page(password=True, steps=[[False, True], [True, False]], stops=[False]),
        ),
        (
            "https://id.example.org/push",
            w._page(steps=[[False, False], [False, False]], stops=hit),
        ),
    ]
    fake = w.FakeSafari(recipe, pages)
    out = w._machine(fake).run()
    assert (out.code, out.rc) == ("needs_albert_push", alsafari.NEEDS_ALBERT_RC)
    assert alsafari.parse_page(json.dumps({**before, "steps": []}), 0, 1) is not None
    no_stops = {k: v for k, v in before.items() if k != "stops"}
    assert alsafari.parse_page(json.dumps({**no_stops, "steps": []}), 0, 1) is None
    assert alsafari.parse_page(json.dumps({**no_stops, "steps": []}), 0) is not None
    js = alsafari.detector_js(recipe, "#account")
    params = json.loads(js.split("const P = ", 1)[1].split(";\n", 1)[0])
    assert params["stops"] == ["OneAuth"]


# ---------------------------------------------------------------------------
# tp#1644 B12: the SaaS broker routes and their own Albert stops
# ---------------------------------------------------------------------------

B12_LANDINGS = {
    "github": "https://github.com/settings/profile",
    "gitlab-com": "https://gitlab.com/-/user_settings/profile",
    "gitlab-ethz": "https://gitlab.ethz.ch/-/user_settings/profile",
    "gitlab-sdsc-glensk": "https://gitlab.datascience.ch/-/user_settings/profile",
    "infomaniak": "https://manager.infomaniak.com",
    "zoho-desk": "https://desk.zoho.eu/agent",
    "smartsheet": "https://app.smartsheet.com/b/home",
}
B12_IDP = {
    "github": "github.com",
    "infomaniak": "login.infomaniak.com",
    "zoho-desk": "accounts.zoho.eu",
    "smartsheet": "app.smartsheet.com",
}
# site → its stops as (code, after, page)
B12_STOPS = {
    "zoho-desk": [
        ("needs_albert_push", "login", "any"),
        ("needs_albert_hardware_key", "user", "any"),
    ],
    "github": [
        ("needs_albert_push", "login", "fieldless"),
        ("needs_albert_hardware_key", "login", "fieldless"),
    ],
    "infomaniak": [
        ("needs_albert_sms", "login", "code"),
        ("needs_albert_push", "login", "fieldless"),
    ],
    "smartsheet": [("email_code_unwired", "", "code")],
}

# The normal login pages' text (synthetic, after the live wording): no stop
# regex of the site matches any of them.
LOGIN_TEXT = {
    "zoho-desk": [
        "Sign in\nto access Desk\nEmail address or mobile number\nNext\n"
        "Sign in using passkey\nSign in using\nGoogle",
        "Enter password\nForgot password?\nSign in\nSign in using OneAuth",
        "TOTP\nEnter the TOTP from your authenticator app\nVerify\nSign in another way",
        "Trust this browser?\nIf you trust this browser, you will not be asked "
        "for a verification code again.\nTrust\nNot now",
        "Review your account details\nRemind me later\nConfirm",
        # B13: Zoho's own strings (sign-in page, 2026-11-09)
        "Sign in\nto access Zoho Desk\nEmail address or mobile number\nNext\n"
        "Use passkey to sign in\nSign in another way",
        "Verify your identity\nVerify via Passkey\nTry another way",
        "Sign in another way\nOffline TOTP verification\nOpen OneAuth, tap Sign "
        "in another way, and enter it here to verify your sign-in.\nScan QR "
        "verification\nOpen OneAuth and tap Sign in another way. Tap Scan QR "
        "instead to open code scanner. Scan the below code to verify sign-in.",
        "Trust this browser?\nDon't trust browsers on public or shared "
        "devices.\nTrust\nNot now",
    ],
    "github": [
        "Sign in to GitHub\nUsername or email address\nPassword\n"
        "Forgot password?\nSign in\nSign in with a passkey\nNew to GitHub?",
        "Two-factor authentication\nAuthentication code\nVerify\nOpen your "
        "two-factor authenticator (TOTP) app or browser extension to view your "
        "authentication code.\nHaving problems?\nUse GitHub Mobile\n"
        "Use your passkey\nUse a recovery code",
        "Sign in faster with passkeys\nAdd a passkey\nAsk me later",
    ],
    "infomaniak": [
        "Log in\nEmail address\nPassword\nForgot your password?\nLog in\n"
        "Create an account",
        "Two-step verification\nEnter the 6-digit code from your "
        "authentication app\nReceive a code by SMS instead\nValidate",
        "Welcome to the Manager\nDownload the Infomaniak app for iOS and Android",
    ],
    "smartsheet": [
        "Log in\nEmail\nContinue\nOr\nLog in with Google\nLog in with Microsoft",
        "Enter your password\nForgot password?\nLog in\nEmail me a login link",
    ],
}
# site → (stop index, the challenge page's text) — each matches its stop only
CHALLENGE_TEXT = {
    "zoho-desk": [
        (
            0,
            "Sign in to access Desk\nWe have sent a push notification to your "
            "OneAuth app on iPhone. Approve it to sign in.",
        ),
        (0, "Open OneAuth and approve the sign-in request"),
        # B13: Zoho's own push / OneAuth-biometric wait strings
        (
            0,
            "Verify push notification\nAccept the push notification in OneAuth to sign in",
        ),
        (0, "Accept the push notification you received on OneAuth to verify."),
        (
            0,
            "A push notification has been sent to your OneAuth devices. "
            "Approve it to verify",
        ),
        (0, "Verify Touch ID\nUse Touch ID in OneAuth to sign in to your account"),
        (1, "Sign in with passkey\nWaiting for your passkey ..."),
        (1, "Use your passkey to sign in. Follow the browser instructions."),
    ],
    "github": [
        (
            0,
            "GitHub Mobile\nWe sent you a sign-in request on your GitHub Mobile "
            "app. Enter the digits shown below to verify your identity.\n42",
        ),
        (1, "Passkey\nWhen you are ready to authenticate, press the button below."),
        (1, "Security key\nWaiting for input from browser interaction..."),
    ],
    "infomaniak": [
        (0, "Two-step verification\nA code has been sent by SMS to +41 79 *** ** 12"),
        (0, "Un code vous a été envoyé par SMS\nCode\nValider"),
        (
            1,
            "Confirm the connection on the Infomaniak app\nA notification has "
            "been sent to your device",
        ),
        (1, "Validez la connexion depuis l'application Infomaniak"),
    ],
    "smartsheet": [
        (0, "Check your email\nWe sent a 6-digit code to albert@example.org"),
        (0, "Enter the code we emailed to you\nContinue"),
    ],
}


def _hits(site: str, text: str) -> list[bool]:
    """The detector's `stops` answer for `text` (Python's `re` stands in for
    the page's JS RegExp, case-insensitive)."""
    return [
        re.search(stop.text, text, re.IGNORECASE) is not None
        for stop in alsafari.BROKER_SAFARI_STOPS[site]
    ]


def test_b12_routes_are_listed_and_unbuilt_without_labels() -> None:
    for site, landing in B12_LANDINGS.items():
        assert al.SAFARI_ROUTES[site] == al.SafariRoute(landing, "in_safari")
        if site in B13_LABELLED:
            continue
        assert al.safari_recipe(site) is None and not al.safari_routed(site)
        assert site not in alsafari.BROKER_SAFARI_LABELS
        assert EXPECTED[site] == NOT_BUILT


def test_b12_stops_name_their_code_step_and_page() -> None:
    got = {
        site: [(s.code, s.after, s.page) for s in stops]
        for site, stops in alsafari.BROKER_SAFARI_STOPS.items()
    }
    assert got == B12_STOPS
    for stops in alsafari.BROKER_SAFARI_STOPS.values():
        for stop in stops:
            want = 2 if stop.code == "email_code_unwired" else alsafari.NEEDS_ALBERT_RC
            assert alsafari.stop_rc(stop.code) == want
            assert stop.code in al.phases.CODE_TEXT or stop.code in al.SAFARI_CODE_TEXT


@pytest.mark.parametrize("site", sorted(LOGIN_TEXT))
def test_b12_no_stop_matches_a_normal_login_page(site: str) -> None:
    for text in LOGIN_TEXT[site]:
        assert not any(_hits(site, text)), text


@pytest.mark.parametrize("site", sorted(CHALLENGE_TEXT))
def test_b12_each_challenge_page_matches_its_own_stop_only(site: str) -> None:
    n = len(alsafari.BROKER_SAFARI_STOPS[site])
    for index, text in CHALLENGE_TEXT[site]:
        assert _hits(site, text) == [i == index for i in range(n)], text


_JS_TEST = r"""const fs = require("fs");
const cases = JSON.parse(fs.readFileSync(0, "utf8"));
process.stdout.write(JSON.stringify(cases.map(
  ([re, text]) => new RegExp(re, "i").test(text))));
"""


@pytest.mark.skipif(_NODE is None, reason="node not installed")
def test_b12_the_page_js_regexp_agrees_with_python(tmp_path: Path) -> None:
    cases: list[tuple[str, str]] = []
    want: list[bool] = []
    for site, stops in alsafari.BROKER_SAFARI_STOPS.items():
        texts = LOGIN_TEXT[site] + [t for _i, t in CHALLENGE_TEXT[site]]
        for text in texts:
            for stop, hit in zip(stops, _hits(site, text)):
                cases.append((stop.text, text))
                want.append(hit)
    script = tmp_path / "re.js"
    script.write_text(_JS_TEST, encoding="utf-8")
    assert _NODE is not None
    done = subprocess.run(
        [_NODE, str(script)],
        input=json.dumps(cases),
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )
    assert json.loads(done.stdout) == want
    assert any(want) and not all(want)


B12_LABELS = alsafari.BrokerLabels(
    "two_step", pass_submit="Sign in", user_submit="Next", otp_submit="Verify"
)


class _Clock:
    """A fake monotonic clock: every sleep moves it on."""

    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


def _timed(
    fake: w.FakeSafari, plan: alsafari.Plan | None = None, **kw: Any
) -> alsafari.Machine:
    """`w._machine` on a fake clock (an Albert wait runs out at once)."""
    clock = _Clock()
    kw.setdefault("notify", lambda _line: None)
    return alsafari.Machine(
        fake.recipe, plan or w._plan(), fake, sleep=clock.sleep, clock=clock, **kw
    )


def _b12_recipe(site: str) -> alsafari.Recipe:
    row = {
        **BROW,
        "site": site,
        "fill_origins": [f"https://{B12_IDP[site]}"],
        "check_url": B12_LANDINGS[site],
        "login_url": B12_LANDINGS[site],
    }
    recipe = alsafari.broker_recipe(row, B12_LABELS, alsafari.BROKER_SAFARI_STOPS[site])
    assert recipe is not None
    return recipe


# (user, login, otp) step conditions per page
_USER_PAGE = [[True, False], [False, False], [False, False]]
_PASS_PAGE = [[False, True], [True, False], [False, False]]
_CODE_PAGE = [[False, False], [False, False], [True, False]]
_NO_STEP = [[False, False], [False, False], [False, False]]


def _shape(page: str) -> dict[str, Any]:
    """Page flags of a challenge page of shape `page`."""
    if page == "code":
        return {"code": True, "steps": _CODE_PAGE}
    if page == "any":  # Zoho: the concealed password field counts visible
        return {"password": True, "steps": _NO_STEP}
    return {"steps": _NO_STEP}


def _challenges() -> list[tuple[str, int, str]]:
    return [
        (site, index, text)
        for site, items in CHALLENGE_TEXT.items()
        for index, text in items
    ]


def _run_b12(site: str, pages: list[tuple[str, str, dict[str, Any]]]) -> Any:
    """Run `site`'s recipe over (path, page text, flags) pages."""
    idp = B12_IDP[site]
    script = [
        (f"https://{idp}{path}", w._page(**flags, stops=_hits(site, text)))
        for path, text, flags in pages
    ]
    fake = w.FakeSafari(_b12_recipe(site), script)
    return fake, _timed(fake).run()  # a waiting stop runs out on a fake clock


def _before(after: str) -> list[tuple[str, str, dict[str, Any]]]:
    """The pages that run the steps up to and including `after`."""
    user = ("/login", "Sign in", {"user": True, "steps": _USER_PAGE})
    password = ("/pw", "Password", {"password": True, "steps": _PASS_PAGE})
    return {"": [], "user": [user], "login": [user, password]}[after]


@pytest.mark.parametrize(("site", "index", "text"), _challenges())
def test_b12_a_stop_fires_on_its_page_after_its_step(
    site: str, index: int, text: str
) -> None:
    stop = alsafari.BROKER_SAFARI_STOPS[site][index]
    pages = [*_before(stop.after), ("/challenge", text, _shape(stop.page))]
    fake, out = _run_b12(site, pages)
    assert (out.code, out.rc) == (stop.code, alsafari.stop_rc(stop.code))
    kinds = [c[0] for c in fake.calls if c[0] in FILLS]
    assert kinds == ["--login"] * len(_before(stop.after))  # never the TOTP


@pytest.mark.parametrize(("site", "index", "text"), _challenges())
def test_b12_a_stop_never_fires_before_its_step_or_on_another_page(
    site: str, index: int, text: str
) -> None:
    stop = alsafari.BROKER_SAFARI_STOPS[site][index]
    if stop.after:  # the challenge text before its step ran
        _fake, out = _run_b12(site, [("/challenge", text, _shape(stop.page))])
        assert out.code != stop.code
    if stop.page != "any":  # the text on a page of the other shape
        other = _shape("fieldless" if stop.page == "code" else "code")
        pages = [*_before(stop.after), ("/challenge", text, other)]
        _fake, out = _run_b12(site, pages)
        assert out.code != stop.code


def test_b12_the_identity_row_stays_unrouted(monkeypatch: pytest.MonkeyPatch) -> None:
    site = "gitlab-sdsc-glensk"
    row = {
        **BROW,
        "site": site,
        "identity": "gitlab",
        "privilege": "user",
        "fill_origins": ["https://gitlab.datascience.ch"],
        "check_url": B12_LANDINGS[site],
        "login_url": "https://gitlab.datascience.ch/users/sign_in",
    }
    _snapshot(monkeypatch, [row])
    labels = alsafari.BrokerLabels(
        "one_page", pass_submit="Sign in", otp_submit="Verify"
    )
    monkeypatch.setitem(alsafari.BROKER_SAFARI_LABELS, site, labels)
    assert al.safari_recipe(site) is None and not al.safari_routed(site)
    assert al.safari_why(site, row) == ""  # ❌ not built, never ⛔
    monkeypatch.setattr(al, "SAFARI_IDENTITY_READ_SAFE", True)
    recipe = al.safari_recipe(site)
    assert recipe is not None and recipe.identity == site and al.safari_routed(site)


def test_b12_labels_route_a_saas_site_with_its_stops(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    site = "zoho-desk"
    row = {
        **BROW,
        "site": site,
        "fill_origins": ["https://accounts.zoho.eu"],
        "check_url": B12_LANDINGS[site],
        "login_url": B12_LANDINGS[site],
    }
    _snapshot(monkeypatch, [row])
    monkeypatch.delitem(alsafari.BROKER_SAFARI_LABELS, site)
    assert not al.safari_routed(site)  # no labels: no route
    monkeypatch.setitem(alsafari.BROKER_SAFARI_LABELS, site, B12_LABELS)
    recipe = al.safari_recipe(site)
    assert recipe is not None and al.safari_routed(site)
    assert recipe.stops == alsafari.BROKER_SAFARI_STOPS[site]
    assert recipe.hosts == ("accounts.zoho.eu", "desk.zoho.eu")
    assert recipe.start_url == B12_LANDINGS[site] and not recipe.import_after


FIELD_LABELS = alsafari.BrokerLabels(
    "two_step",
    pass_submit="Sign in",
    user_submit="Next",
    otp_submit="Verify",
    user_field="#login_id",
    pass_field="#password",
    otp_field="#mfa_totp",
    post_clicks=(("Not now", "#trust-browser"), ("Remind me later", "#review")),
)


def test_b12_field_selectors_and_post_login_clicks_build_steps() -> None:
    recipe = alsafari.broker_recipe(BROW, FIELD_LABELS)
    assert recipe is not None
    got = [(s.kind, s.fields, s.trigger, s.when, s.after) for s in recipe.steps]
    assert got == [
        ("user", (("--user-field", "#login_id"),), "", alsafari._USER_FIELD, ""),
        ("login", (("--pass-field", "#password"),), "", alsafari._PASSWORD, "user"),
        ("otp", (("--otp-field", "#mfa_totp"),), "", alsafari._OTP_FIELD, "login"),
        ("click", (), "Not now", "#trust-browser", "login"),
        ("click", (), "Remind me later", "#review", "login"),
    ]
    assert all(s.optional for s in recipe.steps[3:])
    one = alsafari.broker_recipe(
        BROW,
        alsafari.BrokerLabels(
            "one_page", pass_submit="Log in", user_field="#u", pass_field="#p"
        ),
    )
    assert one is not None
    assert one.steps[0].fields == (("--user-field", "#u"), ("--pass-field", "#p"))
    for bad in (("", "#x"), ("Not now", "")):
        labels = alsafari.BrokerLabels("one_page", "Log in", post_clicks=(bad,))
        assert alsafari.broker_recipe(BROW, labels) is None


def test_b12_the_fills_pass_their_field_selectors_to_safari_py() -> None:
    recipe = alsafari.broker_recipe(BROW, FIELD_LABELS)
    assert recipe is not None
    five = [[False, False]] * 5
    pages = [
        (
            "https://id.example.org/login",
            w._page(user=True, steps=_USER_PAGE + five[:2]),
        ),
        (
            "https://id.example.org/pw",
            w._page(password=True, steps=_PASS_PAGE + five[:2]),
        ),
        ("https://id.example.org/mfa", w._page(code=True, steps=_CODE_PAGE + five[:2])),
        (
            "https://id.example.org/trust",
            w._page(steps=[*five[:3], [True, False], [False, False]]),
        ),
        ("https://app.example.org/home", w._page(sentinel=True)),
    ]
    fake = w.FakeSafari(recipe, pages)
    out = w._machine(fake, w._plan(start_url=BLANDING, item="Selfhost")).run()
    assert out.ok, out.code
    calls = [c for c in fake.calls if c[0] in FILLS]
    assert [c[0] for c in calls] == ["--login", "--login", "--otp", "--click"]
    assert calls[0][-1] == "--user-field=#login_id" and "--user-only" in calls[0]
    assert calls[1][-1] == "--pass-field=#password" and "--no-user" in calls[1]
    assert calls[2][-1] == "--otp-field=#mfa_totp"
    assert calls[3][:2] == ["--click", "Not now"]


# ---------------------------------------------------------------------------
# tp#1644 B13: zoho-desk's labels (sign-in page markup, 2026-11-09)
# ---------------------------------------------------------------------------

B13_LABELLED = {"zoho-desk"}
ZOHO_ROW: dict[str, Any] = {
    **BROW,
    "site": "zoho-desk",
    "name": "Zoho",
    **LISTED_FILL["zoho-desk"],
    "logged_in_selector": '[data-selector-id="avatarStatus"]',
}
ZOHO_ID = "https://accounts.zoho.eu/signin"
NO_HIT = [False, False]  # neither Zoho stop's text
_TRUST_PAGE = [[False, False], [False, False], [True, False]]


def _zoho_recipe(monkeypatch: pytest.MonkeyPatch) -> alsafari.Recipe:
    _snapshot(monkeypatch, [ZOHO_ROW])
    recipe: alsafari.Recipe | None = al.safari_recipe("zoho-desk")
    assert recipe is not None and al.safari_routed("zoho-desk")
    return recipe


def test_b13_zoho_fills_the_password_only_on_the_password_step(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recipe = _zoho_recipe(monkeypatch)
    zp = alsafari.ZOHO_PASSWORD
    got = [(s.kind, s.when, s.unless, s.after, s.fields) for s in recipe.steps]
    assert got == [
        ("user", "#login_id", zp, "", (("--user-field", "#login_id"),)),
        ("login", zp, "", "user", (("--pass-field", "#password"),)),
        ("click", ".trustbrowser_ui .trustbtn", "", "user", ()),
    ]
    assert recipe.albert_wait == alsafari.AlbertWait(
        "user", 90.0, "needs_albert_hardware_key", "Touch ID / OneAuth approval"
    )
    assert all(s.wait_s == 90.0 for s in recipe.stops)
    assert [s.submit for s in recipe.steps[:2]] == ["Next", "Sign in"]
    assert recipe.steps[2].trigger == "Trust" and recipe.steps[2].optional
    assert ".zeroheight" in zp and 'input[type="password"]' in zp
    assert recipe.stops == alsafari.BROKER_SAFARI_STOPS["zoho-desk"]
    assert recipe.hosts == ("accounts.zoho.eu", "desk.zoho.eu")
    assert recipe.sentinel_host == "desk.zoho.eu" and not recipe.import_after


def test_b13_zoho_login_runs_user_password_trust_then_lands(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recipe = _zoho_recipe(monkeypatch)
    # (user, login, trust) step conditions; the identifier page shows the
    # concealed password field (the detector's `password` flag is true)
    pages = [
        (ZOHO_ID, w._page(user=True, password=True, steps=_USER_PAGE, stops=NO_HIT)),
        (ZOHO_ID, w._page(password=True, steps=_PASS_PAGE, stops=NO_HIT)),
        (ZOHO_ID, w._page(steps=_TRUST_PAGE, stops=NO_HIT)),
        ("https://desk.zoho.eu/agent", w._page(sentinel=True, stops=NO_HIT)),
    ]
    fake = w.FakeSafari(recipe, pages)
    out = w._machine(fake, w._plan(start_url=ZOHO_ROW["check_url"], item="Zoho")).run()
    assert out.ok, out.code
    calls = [c for c in fake.calls if c[0] in FILLS]
    assert [c[0] for c in calls] == ["--login", "--login", "--click"]
    assert "--user-only" in calls[0] and calls[0][-1] == "--user-field=#login_id"
    assert "--no-user" in calls[1] and calls[1][-1] == "--pass-field=#password"
    assert calls[2][:4] == ["--click", "Trust", "--row", "Trust"]


class _Albert(w.FakeSafari):
    """Albert acts in Safari: after `holds[i]` page reads of script entry i
    the page moves on by itself (no step of the run)."""

    def __init__(
        self, recipe: alsafari.Recipe, script: list, holds: dict[int, int]
    ) -> None:
        super().__init__(recipe, script)
        self.holds = holds
        self.reads = 0

    def __call__(self, args: list[str]) -> alsafari.Reply:
        reply = super().__call__(args)
        if args[0] == "--eval" and self.pos in self.holds:
            self.reads += 1
            if self.reads >= self.holds[self.pos]:
                self.reads, self.pos = 0, self.pos + 1
        return reply


ZOHO_USER = (ZOHO_ID, w._page(user=True, password=True, steps=_USER_PAGE, stops=NO_HIT))
# after the e-mail: a loader under Safari's own Touch ID sheet — the page
# keeps the concealed field, no step, no wording
ZOHO_LOADER = (ZOHO_ID, w._page(password=True, steps=_NO_STEP, stops=NO_HIT))
ZOHO_TRUST = (ZOHO_ID, w._page(steps=_TRUST_PAGE, stops=NO_HIT))
ZOHO_LANDED = ("https://desk.zoho.eu/agent", w._page(sentinel=True, stops=NO_HIT))
TRUST_LINE = '▶ zoho-desk: clicked Trust on "Trust this browser?"'


def _zoho_plan() -> alsafari.Plan:
    return w._plan(start_url=ZOHO_ROW["check_url"], item="Zoho")


def test_b13_zoho_passkey_first_waits_for_albert_then_trusts_and_lands(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recipe = _zoho_recipe(monkeypatch)
    pages = [ZOHO_USER, ZOHO_LOADER, ZOHO_TRUST, ZOHO_LANDED]
    fake = _Albert(recipe, pages, {1: 8})  # Albert touches after 8 reads
    lines: list[str] = []
    m = _timed(fake, _zoho_plan(), notify=lines.append)
    out = m.run()
    assert out.ok, out.code
    calls = [c for c in fake.calls if c[0] in FILLS]
    assert [c[0] for c in calls] == ["--login", "--click"]  # never the password
    assert "--user-only" in calls[0] and calls[1][:2] == ["--click", "Trust"]
    assert len(lines) == 2 and "90 s" in lines[0] and "Touch ID" in lines[0]
    assert lines[1] == TRUST_LINE
    assert m.clock() < 90 and fake.calls[-1][0] == "--close"


def test_b13_zoho_wait_runs_out_needs_albert_with_the_window_open(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recipe = _zoho_recipe(monkeypatch)
    fake = w.FakeSafari(recipe, [ZOHO_USER, ZOHO_LOADER])
    m = _timed(fake, _zoho_plan())
    out = m.run()
    assert (out.rc, out.code) == (4, "needs_albert_hardware_key")
    assert out.window_open and not out.credential  # the e-mail alone: no quarantine
    assert not [c for c in fake.calls if c[0] == "--close"]
    calls = [c for c in fake.calls if c[0] in FILLS]
    assert len(calls) == 1 and "--user-only" in calls[0]  # nothing typed meanwhile
    assert 90 <= m.clock() < 90 + 2 * alsafari.POLL_S


def test_b13_a_run_out_wait_records_without_quarantine(
    run: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    del run
    quarantined: list[str] = []
    fails: list[tuple] = []
    monkeypatch.setattr(al.als, "quarantine", lambda s, *_a: quarantined.append(s))
    monkeypatch.setattr(al, "record_safari_fail", lambda *a: fails.append(a))
    out = alsafari.Outcome(4, "needs_albert_hardware_key", window_open=True)
    out.steps = ["user"]
    assert al._safari_fail("zoho-desk", out, "stopped") == 4
    assert not quarantined and fails[-1][3]["code"] == "needs_albert_hardware_key"
    assert "stays open" in capsys.readouterr().out


def test_b13_zoho_push_waits_for_the_approval_then_trusts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recipe = _zoho_recipe(monkeypatch)
    pw = (ZOHO_ID, w._page(password=True, steps=_PASS_PAGE, stops=NO_HIT))
    push = (ZOHO_ID, w._page(password=True, steps=_NO_STEP, stops=[True, False]))
    pages = [ZOHO_USER, pw, push, ZOHO_TRUST, ZOHO_LANDED]
    fake = _Albert(recipe, pages, {2: 5})
    lines: list[str] = []
    out = _timed(fake, _zoho_plan(), notify=lines.append).run()
    assert out.ok, out.code
    calls = [c for c in fake.calls if c[0] in FILLS]
    assert [c[0] for c in calls] == ["--login", "--login", "--click"]
    assert len(lines) == 2 and "push approval" in lines[0]
    assert lines[1] == TRUST_LINE
    # never approved: the push stop's code, a credential run (password sent)
    fake = w.FakeSafari(recipe, [ZOHO_USER, pw, push])
    out = _timed(fake, _zoho_plan()).run()
    assert (out.rc, out.code) == (4, "needs_albert_push")
    assert out.window_open and out.credential


def test_a_recipe_without_albert_wait_stays_stuck(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recipe = _zoho_recipe(monkeypatch)
    plain = alsafari.Recipe(**{**recipe.__dict__, "albert_wait": None, "stops": ()})
    fake = w.FakeSafari(plain, [ZOHO_USER, ZOHO_LOADER])
    lines: list[str] = []
    out = _timed(fake, _zoho_plan(), notify=lines.append).run()
    assert (out.rc, out.code) == (2, "recipe_stuck") and not lines
    assert not out.window_open and fake.calls[-1][0] == "--close"


def test_prove_only_never_waits_for_albert(monkeypatch: pytest.MonkeyPatch) -> None:
    recipe = _zoho_recipe(monkeypatch)
    push = (ZOHO_ID, w._page(password=True, steps=_NO_STEP, stops=[True, True]))
    fake = w.FakeSafari(recipe, [ZOHO_LOADER])
    lines: list[str] = []
    out = _timed(fake, _zoho_plan(), notify=lines.append, proof_only=True).run()
    assert out.code == "recipe_stuck" and not lines
    # a stop page whose step never ran stays no stop; none waits in prove-only
    fake = w.FakeSafari(recipe, [push])
    out = _timed(fake, _zoho_plan(), notify=lines.append, proof_only=True).run()
    assert not lines and not out.window_open


def test_b13_only_zoho_desk_answers_a_trust_prompt_with_trust() -> None:
    # the never-trust-a-device rule (docs/AGENTS_REFERENCE.md) and its one
    # exception, Albert's decision of 2026-11-09
    trusting = {
        site
        for site, labels in alsafari.BROKER_SAFARI_LABELS.items()
        for label, _when in labels.post_clicks
        if label.strip().lower() in {"trust", "trust browser", "trust this browser"}
    }
    assert trusting == {"zoho-desk"}


# tp#1644 canary follow-up: the Trust click says one ▶ line (TRUST_LINE), a
# run whose prompt never showed (or whose click safari.py refused) says nothing.


def test_the_trust_click_says_one_line_only_when_it_clicked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recipe = _zoho_recipe(monkeypatch)
    pw = (ZOHO_ID, w._page(password=True, steps=_PASS_PAGE, stops=NO_HIT))
    lines: list[str] = []
    fake = w.FakeSafari(recipe, [ZOHO_USER, pw, ZOHO_TRUST, ZOHO_LANDED])
    out = _timed(fake, _zoho_plan(), notify=lines.append).run()
    assert out.ok, out.code
    assert lines == [TRUST_LINE]
    # no "Trust this browser?" prompt: no click, no line
    lines.clear()
    fake = w.FakeSafari(recipe, [ZOHO_USER, pw, ZOHO_LANDED])
    out = _timed(fake, _zoho_plan(), notify=lines.append).run()
    assert out.ok, out.code
    assert not [c for c in fake.calls if c[0] == "--click"] and not lines


def test_a_refused_trust_click_says_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    recipe = _zoho_recipe(monkeypatch)
    pw = (ZOHO_ID, w._page(password=True, steps=_PASS_PAGE, stops=NO_HIT))
    refused = alsafari.Reply(2, {"ok": False, "error": "no such button"}, "")
    fake = w.FakeSafari(
        recipe, [ZOHO_USER, pw, ZOHO_TRUST, ZOHO_LANDED], fail={"--click": refused}
    )
    lines: list[str] = []
    _timed(fake, _zoho_plan(), notify=lines.append).run()  # the page stays put
    assert [c[0] for c in fake.calls if c[0] == "--click"] == ["--click"]
    assert not [line for line in lines if line.startswith("▶")]


def test_only_post_clicks_carry_a_prompt_line(monkeypatch: pytest.MonkeyPatch) -> None:
    recipe = _zoho_recipe(monkeypatch)
    assert [s.prompt for s in recipe.steps] == ["", "", '"Trust this browser?"']
    labels = alsafari.BrokerLabels(
        "one_page", "Log in", post_clicks=(("Not now", "#other"),)
    )
    other = alsafari.broker_recipe(BROW, labels)
    assert other is not None and other.steps[-1].prompt == "a post-login prompt"


# ---------------------------------------------------------------------------
# tp#1644 canary follow-up: a failed safari.py call names its step + exit code
# ---------------------------------------------------------------------------

LEAK = "no visible field #login_id (safari.py message)"


def test_a_refused_user_step_names_op_user_and_its_exit_code(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    recipe = _zoho_recipe(monkeypatch)
    fail = {"--login": alsafari.Reply(2, {"ok": False, "error": LEAK}, LEAK)}
    fake = w.FakeSafari(recipe, [ZOHO_USER], fail=fail)
    out = _timed(fake, _zoho_plan()).run()
    assert (out.rc, out.code) == (2, "recipe_stuck") and not out.stuck
    assert (out.failed_op, out.safari_rc) == ("user", 2)
    fails: list[tuple] = []
    monkeypatch.setattr(al, "record_safari_fail", lambda *a: fails.append(a))
    monkeypatch.setattr(al.als, "quarantine", lambda *_a: None)
    assert al._safari_fail("zoho-desk", out, "stopped") == 2
    assert fails[-1][3]["detail"] == "op: user, safari_rc: 2"
    got = capsys.readouterr()
    assert got.err.splitlines() == ["   safari.py --user exited 2"]
    assert LEAK not in got.out + got.err + json.dumps(fails)


def test_a_failed_tabs_read_names_op_tabs(monkeypatch: pytest.MonkeyPatch) -> None:
    recipe = _zoho_recipe(monkeypatch)
    fail = {"--tabs": alsafari.Reply(1, {"ok": False, "error": LEAK}, LEAK)}
    out = _timed(w.FakeSafari(recipe, [ZOHO_USER], fail=fail), _zoho_plan()).run()
    assert (out.rc, out.code) == (2, "recipe_stuck")
    assert (out.failed_op, out.safari_rc) == ("tabs", 1)


def test_a_failed_open_names_op_open(monkeypatch: pytest.MonkeyPatch) -> None:
    recipe = _zoho_recipe(monkeypatch)
    fail = {"--open": alsafari.Reply(1, {"ok": False}, LEAK)}
    out = _timed(w.FakeSafari(recipe, [ZOHO_USER], fail=fail), _zoho_plan()).run()
    assert (out.code, out.failed_op, out.safari_rc) == ("recipe_stuck", "open", 1)


def test_max_polls_is_its_own_stuck_reason(monkeypatch: pytest.MonkeyPatch) -> None:
    recipe = _zoho_recipe(monkeypatch)
    monkeypatch.setattr(alsafari, "MAX_POLLS", 1)  # the user step, then the end
    out = _timed(w.FakeSafari(recipe, [ZOHO_USER, ZOHO_LOADER]), _zoho_plan()).run()
    assert (out.rc, out.code) == (2, "recipe_stuck")
    assert (out.stuck, out.stuck_host) == ("max_polls", "accounts.zoho.eu")
    assert "max_polls" in alsafari.STUCK_REASONS and not out.failed_op


def test_a_stuck_reason_and_a_failed_op_share_the_detail() -> None:
    out = alsafari.Outcome(2, "recipe_stuck", stuck="code_field")
    assert al._safari_detail("code_field", out) == "code_field"
    out.failed_op, out.safari_rc = "eval", 1
    assert al._safari_detail("code_field", out) == "code_field; op: eval, safari_rc: 1"
    assert al._safari_detail("", out) == "op: eval, safari_rc: 1"


def test_a_blocked_safari_lock_says_it_waits(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with al.safari_login_lock(0) as first:
        assert first
        with al.safari_login_lock(0.6) as second:
            assert not second
    assert capsys.readouterr().err.splitlines() == [
        "   waiting for another Safari login run (lock) up to 1 s"
    ]
