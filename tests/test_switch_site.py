#!/usr/bin/env python3
"""Unit tests for the Switch Cloud Portal site (cloud.switch.ch, edu-ID SSO).

The interesting part is the VERDICT: the portal answers an anonymous ``GET /``
with 200 **at** ``/`` and renders the edu-ID sign-in page there (verified
2026-09-14), so "the tab is on cloud.switch.ch" proves nothing — only the
absence of the ``/auth/openid_connect_eduid_ch`` sign-in form does. Everything
else is ``unknown``, which the caller treats as "not logged in" (fail closed):
`logged-in switch` is polled by a monitoring check that reads exit 2 as red.

Run: python3 -m pytest tests/ -q     (from the repo root)
"""

from __future__ import annotations

# Tests reach into browser.py's private helpers on purpose (it is a script, not
# a package, so there is no public API), and build throwaway stub classes.
# pylint: disable=protected-access,import-outside-toplevel,too-few-public-methods
# pylint: disable=missing-function-docstring,missing-class-docstring,import-error
# pylint: disable=unused-argument
import importlib.util
import sys
from pathlib import Path

import pytest

_BROWSER_PY = Path(__file__).resolve().parent.parent / "bin" / "browser.py"


def _load_browser_module():
    """Import bin/browser.py as a module (it has no module-level playwright import)."""
    spec = importlib.util.spec_from_file_location("browser_under_test", _BROWSER_PY)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["browser_under_test"] = mod
    spec.loader.exec_module(mod)
    return mod


browser = _load_browser_module()


# --- the pure verdict ------------------------------------------------------


@pytest.mark.parametrize(
    "url,has_form,expected",
    [
        # The sign-in page itself — by path, and by form on the bare root.
        ("https://cloud.switch.ch/auth/login", False, "login"),
        ("https://cloud.switch.ch/", True, "login"),
        # Portal surfaces with no sign-in form = a live session.
        ("https://cloud.switch.ch/", False, "logged-in"),
        ("https://cloud.switch.ch/projects", False, "logged-in"),
        ("https://cloud.switch.ch", False, "logged-in"),
        # Mid-flight OIDC callback: still under /auth/, decide nothing yet.
        (
            "https://cloud.switch.ch/auth/openid_connect_eduid_ch/callback?code=x",
            False,
            "unknown",
        ),
        # Off-origin / no page / error page / empty — never a verdict.
        ("https://login.eduid.ch/idp/profile/SAML2/Redirect/SSO", False, "unknown"),
        ("about:blank", False, "unknown"),
        ("chrome-error://chromewebdata/", False, "unknown"),
        ("", False, "unknown"),
        # Prefix trap: a host that merely STARTS with the origin is off-origin.
        ("https://cloud.switch.ch.evil.example/", False, "unknown"),
    ],
)
def test_switch_verdict(url: str, has_form: bool, expected: str) -> None:
    assert browser._switch_verdict(url, has_form) == expected


# --- "cannot read the DOM" is never "no form" ------------------------------


class _Page:
    """Minimal stand-in for a Playwright page: query_selector only."""

    def __init__(self, result: object = None, raises: bool = False) -> None:
        self._result = result
        self._raises = raises

    def query_selector(self, _selector: str) -> object:
        if self._raises:
            raise RuntimeError("target closed")
        return self._result


def test_has_sign_in_form_none_when_query_raises() -> None:
    assert browser._switch_has_sign_in_form(_Page(raises=True)) is None


def test_has_sign_in_form_false_when_absent() -> None:
    assert browser._switch_has_sign_in_form(_Page(None)) is False


def test_has_sign_in_form_true_when_present() -> None:
    assert browser._switch_has_sign_in_form(_Page(object())) is True


# --- registry --------------------------------------------------------------


def test_site_resolves_by_name_and_aliases() -> None:
    site = browser._resolve_site("switch")
    assert site.name == "switch"
    for alias in ("switch-cloud", "cloud.switch.ch", "scp"):
        assert browser._resolve_site(alias) is not None
        assert browser._resolve_site(alias).name == "switch"


def test_site_has_no_stored_credentials() -> None:
    site = browser._resolve_site("switch")
    assert site.store_creds is None and site.forget_creds is None


def test_site_wires_the_switch_commands() -> None:
    site = browser._resolve_site("switch")
    assert site.login is browser.cmd_switch_login
    assert site.logged_in is browser.cmd_switch_logged_in


def test_sso_is_an_automated_mode() -> None:
    assert "sso" not in browser.ASSISTED_MODES


def test_blurb_names_the_identity_provider() -> None:
    assert "edu-ID" in browser._resolve_site("switch").blurb


# --- tp#1957: SWITCHengines AdminUI (engines.admin.switch.ch) --------------

ENGINES = "https://engines.admin.switch.ch"


@pytest.mark.parametrize(
    "url,has_form,has_sentinel,expected",
    [
        # Anonymous: every page answers 302 to /auth/login, which has the form.
        (ENGINES + "/auth/login", True, False, "login"),
        (ENGINES + "/auth/login", False, False, "login"),
        # Signed in: no form AND the signed-in navbar sentinel.
        (ENGINES + "/costcenters/1096", False, True, "logged-in"),
        (ENGINES + "/", False, True, "logged-in"),
        # The OIDC callback lands on the parent AdminUI (.admin.switch.ch
        # session cookie, same navbar): it proves the session as well.
        ("https://admin.switch.ch/", False, True, "logged-in"),
        ("https://admin.switch.ch/", False, False, "unknown"),
        ("https://admin.switch.ch.evil.example/", False, True, "unknown"),
        # No form but no sentinel either (an error page, a half-rendered page):
        # never a session.
        (ENGINES + "/costcenters/", False, False, "unknown"),
        # The cloud portal's session is not the engines one, and vice versa.
        ("https://cloud.switch.ch/projects", False, True, "unknown"),
        (
            ENGINES + "/auth/openid_connect_eduid_ch/callback?code=x",
            False,
            True,
            "unknown",
        ),
        ("https://login.eduid.ch/idp/profile/oidc/authorize", False, False, "unknown"),
        (ENGINES + ".evil.example/", False, True, "unknown"),
    ],
)
def test_engines_verdict(
    url: str, has_form: bool, has_sentinel: bool, expected: str
) -> None:
    got = browser._switch_verdict(
        url, has_form, browser.SWITCH_ENGINES_PORTAL, has_sentinel
    )
    assert got == expected


def test_cloud_portal_verdict_ignores_the_sentinel_flag() -> None:
    """cloud.switch.ch has no positive sentinel: form absence alone decides."""
    assert browser._switch_verdict(
        "https://cloud.switch.ch/", False, has_sentinel=False
    ) == ("logged-in")


class _DomPage:
    """A page at `url` whose DOM holds exactly the selectors in `present`."""

    def __init__(self, url: str, present: set[str], raises: bool = False) -> None:
        self.url = url
        self._present = present
        self._raises = raises

    def query_selector(self, selector: str) -> object:
        if self._raises:
            raise RuntimeError("target closed")
        return object() if selector in self._present else None


def test_engines_page_verdict_needs_the_sentinel() -> None:
    portal = browser.SWITCH_ENGINES_PORTAL
    signed_in = _DomPage(ENGINES + "/costcenters/", {browser.SWITCH_ENGINES_SENTINEL})
    assert browser._switch_page_verdict(signed_in, portal) == "logged-in"
    bare = _DomPage(ENGINES + "/costcenters/", set())
    assert browser._switch_page_verdict(bare, portal) == "unknown"
    anon = _DomPage(ENGINES + "/auth/login", {browser.SWITCH_SIGN_IN_FORM_SELECTOR})
    assert browser._switch_page_verdict(anon, portal) == "login"


def test_engines_page_verdict_fails_closed_on_an_unreadable_dom() -> None:
    page = _DomPage(ENGINES + "/costcenters/", set(), raises=True)
    assert (
        browser._switch_page_verdict(page, browser.SWITCH_ENGINES_PORTAL) == "unknown"
    )


def test_engines_site_resolves_by_name_and_aliases() -> None:
    for name in (
        "switch-engines",
        "engines",
        "engines.admin.switch.ch",
        "switchengines",
    ):
        assert browser._resolve_site(name).name == "switch-engines"


def test_engines_site_wires_the_shared_switch_flow() -> None:
    site = browser._resolve_site("switch-engines")
    assert site.login is browser.cmd_switch_engines_login
    assert site.logged_in is browser.cmd_switch_engines_logged_in
    assert site.store_creds is None and site.forget_creds is None
    assert "edu-ID" in site.blurb


def test_engines_is_a_guided_window_site() -> None:
    assert "switch-engines" in browser.GUIDED_BUILTIN_WINDOW
    assert browser.GUIDED_START_URLS["switch-engines"] == ENGINES + "/auth/login"


def test_engines_logged_in_reports_its_own_portal(monkeypatch, capsys) -> None:
    seen: list[object] = []

    def probe(port, portal=None):
        seen.append(portal)
        return ("login", ENGINES + "/auth/login")

    monkeypatch.setattr(browser, "_switch_probe", probe)
    assert browser.cmd_switch_engines_logged_in(9222) == 2
    assert seen == [browser.SWITCH_ENGINES_PORTAL]
    assert "Not logged into SWITCHengines AdminUI (engines.admin.switch.ch)." in (
        capsys.readouterr().err
    )
