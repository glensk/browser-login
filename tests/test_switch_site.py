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
