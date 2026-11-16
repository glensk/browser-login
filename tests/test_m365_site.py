"""tp#2144: the built-in site `m365` (EPFL Microsoft 365 / Teams).

Registry and aliases, the Safari import rule (only Entra's cookies travel),
the agent-login route and recipe, the override key, the tri-state check and
the account proof's enum mapping (fake pages; the identity JS in node when
installed). Hermetic: no network, no real Chrome / Safari.
"""

from __future__ import annotations

# pylint: disable=missing-function-docstring,import-error,wrong-import-position
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

sys.path[:0] = [
    str(Path(__file__).resolve().parent.parent),
    str(Path(__file__).resolve().parent),
]

from ws3_fixtures import load_script  # noqa: E402

import agent_login_safari as alsafari  # noqa: E402
from broker import identity  # noqa: E402
from broker import safari_cookies as sc  # noqa: E402

browser = load_script("browser_m365_test", "bin/browser.py")
al = load_script("agent_login_m365_test", "agent-login.py")

ALIASES = (
    "office365",
    "teams.cloud.microsoft",
    "m365",
    "sharepoint",
    "teams",
    "epfl-m365",
    "microsoft",
)
USER, TENANT = "0000aaaa-1111", "0000bbbb-2222"  # fake ids (never Albert's)


@pytest.mark.parametrize("name", ALIASES)
def test_every_alias_resolves_to_m365(name: str) -> None:
    assert browser._resolve_site(name).name == "m365"
    assert browser._static_site_name(name.upper()) == "m365"
    assert name in identity.STATIC_SITE_NAMES


def test_aliases_collide_with_no_other_site() -> None:
    seen: list[str] = []
    for site in browser._sites():
        seen += [site.name, *site.aliases]
    assert len(seen) == len(set(seen))
    # a broker item that merely starts with "microsoft" stays a broker item
    assert browser._static_site_name("microsoft-cmt") is None


def test_guided_login_tables() -> None:
    assert browser.GUIDED_START_URLS["m365"] == "https://teams.cloud.microsoft/"
    assert "m365" in browser.GUIDED_BUILTIN_WINDOW
    assert browser.BUILTIN_EXPECTED_KEYS["m365"] == (
        "expected_tenant_id",
        "expected_user_id",
    )
    assert browser.BUILTIN_PROVERS["m365"] is browser._m365_identity


def _cookie(domain: str, name: str) -> sc.Cookie:
    return sc.Cookie(domain, name, "v", "/", 4e9, True, True)


def test_safari_rule_imports_only_entra_cookies() -> None:
    rule = sc.SAFARI_BUILTIN["m365"]
    assert rule.domains == ("microsoftonline.com",)
    assert not rule.import_unattended
    assert sc.is_session_cookie("ESTSAUTHPERSISTENT", "m365")
    assert not sc.is_session_cookie("ESTSAUTH", "m365")
    assert sc.importable(".login.microsoftonline.com", "ESTSAUTHPERSISTENT", "m365")
    for domain, name in (
        ("teams.cloud.microsoft", "authtoken"),
        ("epflch.sharepoint.com", "FedAuth"),
        (".microsoft.com", "MUID"),
        ("login.microsoftonline.com.evil.example", "ESTSAUTHPERSISTENT"),
    ):
        assert not sc.importable(domain, name, "m365"), (domain, name)
    assert sc.has_session(
        "m365", [_cookie("login.microsoftonline.com", "ESTSAUTHPERSISTENT")]
    )
    assert not sc.has_session("m365", [_cookie("login.microsoftonline.com", "x")])


def test_agent_login_route_and_recipe() -> None:
    assert al.SAFARI_ROUTES["m365"] == al.SafariRoute(
        "https://teams.cloud.microsoft/", "builtin"
    )
    assert al.safari_routed("m365")
    assert "m365" in al.TRISTATE_SITES and "m365" in al.ASSISTED_SITES
    assert "m365" in al.VIEWER_SITES
    assert al.MATRIX_META["m365"][1] == "user"
    assert "m365" not in al.kal.KEEPALIVE_SITES
    recipe = alsafari.RECIPES["m365"]
    assert not recipe.steps and not recipe.broker and recipe.import_after
    assert recipe.identity == "m365"
    assert recipe.sentinel == browser.M365_SENTINEL
    assert recipe.sentinel_host == "teams.cloud.microsoft"
    for stop in recipe.stops:
        assert alsafari.stop_rc(stop.code) == alsafari.NEEDS_ALBERT_RC
        assert stop.code in al.phases.CODE_TEXT or stop.code in al.SAFARI_CODE_TEXT
        assert stop.wait_s > 0 and stop.page == "any" and stop.after == ""


@pytest.mark.parametrize(
    ("text", "code"),
    [
        ("Approve sign in request\nOpen your Authenticator app", "needs_albert_push"),
        ("Microsoft\nPick an account\nalbert@example.org", "needs_albert_login"),
        ("Microsoft\nSign in\nEmail, phone, or Skype", "needs_albert_login"),
        ("Enter password\nForgot my password", "needs_albert_login"),
        ("Chat\nTeams\nCalendar\nSigned in as someone", None),
    ],
)
def test_recipe_stops_match_their_pages(text: str, code: str | None) -> None:
    hits = [
        stop.code
        for stop in alsafari.RECIPES["m365"].stops
        if _js_regex_hits(stop.text, text)
    ]
    assert (hits[0] if hits else None) == code


def _js_regex_hits(pattern: str, text: str) -> bool:
    import re  # pylint: disable=import-outside-toplevel

    return re.search(pattern, text, re.IGNORECASE) is not None


def test_override_key_is_accepted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "overrides.json"
    path.write_text(
        json.dumps({"m365": {"expected_tenant_id": TENANT, "expected_user_id": USER}}),
        encoding="utf-8",
    )
    os.chmod(path, 0o600)
    monkeypatch.setenv("AGENT_LOGIN_SAFARI_OVERRIDES", str(path))
    assert "expected_tenant_id" in alsafari.OVERRIDE_STR_KEYS
    assert browser._builtin_expected("m365") == (
        {"expected_tenant_id": TENANT, "expected_user_id": USER},
        "",
    )


class TeamsPage:
    """A fake page: its URL, whether the avatar / a sign-in form shows, and
    what the identity JS answers."""

    def __init__(
        self, url: str, *, avatar: bool = False, signin: bool = False, ident: Any = None
    ) -> None:
        self.url = url
        self.avatar = avatar
        self.signin = signin
        self.ident = ident
        self.evals: list[Any] = []

    def goto(self, _url: str, **_kw: Any) -> None:
        if self.url == "raise":
            raise browser.PlaywrightErrorForTests("net::ERR_TIMED_OUT")

    def wait_for_timeout(self, _ms: float) -> None:
        return None

    def wait_for_load_state(self, *_a: Any, **_kw: Any) -> None:
        return None

    def query_selector_all(self, sel: str) -> list[Any]:
        if sel == browser.M365_SENTINEL and self.avatar:
            return [type("El", (), {"is_visible": lambda _s: True})()]
        return []

    def evaluate(self, js: str, *args: Any) -> Any:
        if js == browser.M365_SIGNIN_JS:
            return self.signin
        if js == browser.M365_IDENTITY_JS:
            self.evals.append(args[0])
            return self.ident
        return None


@pytest.fixture(autouse=True)
def _fast_boot(monkeypatch: pytest.MonkeyPatch) -> None:
    from playwright.sync_api import Error  # pylint: disable=import-outside-toplevel

    monkeypatch.setattr(browser, "M365_BOOT_WAIT_S", 0.0, raising=True)
    monkeypatch.setattr(browser, "PlaywrightErrorForTests", Error, raising=False)


@pytest.mark.parametrize(
    ("page", "state"),
    [
        (TeamsPage("https://teams.cloud.microsoft/v2/", avatar=True), "valid"),
        # the avatar counts on Teams only
        (
            TeamsPage("https://login.microsoftonline.com/x", avatar=True),
            "indeterminate",
        ),
        (
            TeamsPage("https://login.microsoftonline.com/common/oauth2", signin=True),
            "invalid",
        ),
        # a sign-in-looking page elsewhere is not "logged out"
        (TeamsPage("https://teams.cloud.microsoft/", signin=True), "indeterminate"),
        (TeamsPage("https://teams.cloud.microsoft/"), "indeterminate"),
        (TeamsPage("raise"), "indeterminate"),
    ],
)
def test_m365_state(page: TeamsPage, state: str) -> None:
    assert browser._m365_state(page) == state


@pytest.mark.parametrize("ident", ["match", "mismatch", "indeterminate", "logged_out"])
def test_m365_identity_passes_the_enum_through(ident: str) -> None:
    page = TeamsPage("https://teams.cloud.microsoft/", avatar=True, ident=ident)
    want = {"expected_user_id": USER, "expected_tenant_id": TENANT}
    assert browser._m365_identity(page, want) == ident
    assert page.evals == [{"user": USER, "tenant": TENANT}]


@pytest.mark.parametrize("ident", ["eyJ0eXAiOi.token", None, 42])
def test_m365_identity_never_passes_anything_else(ident: Any) -> None:
    page = TeamsPage("https://teams.cloud.microsoft/", avatar=True, ident=ident)
    want = {"expected_user_id": USER, "expected_tenant_id": TENANT}
    assert browser._m365_identity(page, want) == "indeterminate"


def test_m365_identity_logged_out_and_unknown_skip_the_js() -> None:
    want = {"expected_user_id": USER, "expected_tenant_id": TENANT}
    out = TeamsPage("https://login.microsoftonline.com/common", signin=True)
    assert browser._m365_identity(out, want) == "logged_out"
    slow = TeamsPage("https://teams.cloud.microsoft/")
    assert browser._m365_identity(slow, want) == "indeterminate"
    assert not out.evals and not slow.evals


_NODE = shutil.which("node")
_NODE_HARNESS = r"""
const [js, host, keys, want] = JSON.parse(require("fs").readFileSync(0, "utf8"));
globalThis.location = { hostname: host };
globalThis.localStorage = { length: keys.length, key: (i) => keys[i],
  getItem: () => { throw new Error("a value was read"); } };
process.stdout.write(JSON.stringify(eval("(" + js + ")")(want)));
"""


@pytest.mark.skipif(_NODE is None, reason="node not installed")
@pytest.mark.parametrize(
    ("host", "keys", "verdict"),
    [
        (
            "teams.cloud.microsoft",
            [f"msal.2|{USER}.{TENANT}|login.windows.net|accesstoken|c|{TENANT}|s"],
            "match",
        ),
        (
            "teams.cloud.microsoft",
            [f"msal.2|{USER.upper()}.{TENANT.upper()}|login.windows.net|idtoken|c"],
            "match",
        ),
        (
            "teams.cloud.microsoft",
            ["msal.2|cccc-1.dddd-2|login.windows.net|accesstoken|c|dddd-2|s"],
            "mismatch",
        ),
        ("teams.cloud.microsoft", ["msal.version", "other|x|y"], "indeterminate"),
        ("teams.cloud.microsoft", [], "indeterminate"),
        ("login.microsoftonline.com", [], "logged_out"),
    ],
)
def test_identity_js_reads_key_names_only(
    host: str, keys: list[str], verdict: str
) -> None:
    payload = json.dumps(
        [browser.M365_IDENTITY_JS, host, keys, {"user": USER, "tenant": TENANT}]
    )
    run = subprocess.run(
        [str(_NODE), "-e", _NODE_HARNESS],
        input=payload,
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )
    assert json.loads(run.stdout) == verdict
