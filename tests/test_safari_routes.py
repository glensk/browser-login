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
LISTING: list[dict[str, Any]] = [
    {"site": s, "privilege": p, "identity": i, "refused": False}
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
            "zoho-desk",
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
