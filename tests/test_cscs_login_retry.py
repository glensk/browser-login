#!/usr/bin/env python3
"""Regression guard for the CSCS login retry on a stale Keycloak auth session.

The bug (2026-09-03): `browser.py cscs-login` submitted a Keycloak login page
whose `session_code` had gone stale, Keycloak bounced the flow to
`/api-auth/keycloak/complete/?error=temporarily_unavailable&
error_description=authentication_expired`, and cscs-login reported "wrong
username/password/OTP" — nothing was wrong with the credentials. A fresh
navigation starts a new authorization request and succeeds, so that one case
now earns exactly one retry, with a freshly generated TOTP code.

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

_EXPIRED_URL = (
    "https://portal.cscs.ch/api-auth/keycloak/complete/"
    "?error=temporarily_unavailable&error_description=authentication_expired"
    "&iss=https%3A%2F%2Fauth.cscs.ch%2Fauth%2Frealms%2Fcscs"
)


class _Page:
    """Minimal stand-in for a Playwright page (url + inner_text only)."""

    def __init__(self, url: str, body: str = "") -> None:
        self.url = url
        self._body = body

    def inner_text(self, _selector: str, timeout: int = 0) -> str:
        return self._body


def _needs_playwright():
    return pytest.mark.skipif(
        importlib.util.find_spec("playwright") is None,
        reason="playwright not installed in this interpreter",
    )


def test_expired_callback_url_is_retryable():
    # The exact URL the browser was parked on after the 2026-09-03 failure.
    assert browser._keycloak_flow_expired(_Page(_EXPIRED_URL)) is True


def test_url_fast_path_needs_no_playwright():
    # The URL check must run before the playwright import, so a stub page with
    # no inner_text at all still classifies correctly.
    class _UrlOnly:
        url = _EXPIRED_URL

    assert browser._keycloak_flow_expired(_UrlOnly()) is True


@_needs_playwright()
def test_timed_out_login_page_is_retryable():
    page = _Page(
        "https://auth.cscs.ch/auth/realms/cscs/login-actions/authenticate",
        "Your login attempt timed out. Login will start from the beginning.",
    )
    assert browser._keycloak_flow_expired(page) is True


@_needs_playwright()
def test_plain_login_page_is_not_retryable():
    # A wrong password must NOT be retried — it would burn a try toward lockout.
    page = _Page(
        "https://auth.cscs.ch/auth/realms/cscs/login-actions/authenticate",
        "Invalid username or password.",
    )
    assert browser._keycloak_flow_expired(page) is False


def test_creds_are_reresolved_per_attempt(monkeypatch, capsys):
    # A TOTP code lives ~30s, so the retry must fetch a *fresh* one, and the
    # "which source" banner must be printed only on the first attempt.
    codes = iter(["111111", "222222"])
    monkeypatch.setattr(
        browser, "_keychain_creds", lambda: ("aglensk", "pw", next(codes))
    )

    first, mode_first = browser._cscs_creds(announce=True)
    second, mode_second = browser._cscs_creds(announce=False)

    assert (mode_first, mode_second) == ("keychain", "keychain")
    assert first is not None and second is not None
    assert first[2] == "111111"
    assert second[2] == "222222"
    out = capsys.readouterr().out
    assert out.count("macOS keychain") == 1


def test_creds_fall_back_to_1password(monkeypatch):
    monkeypatch.setattr(browser, "_keychain_creds", lambda: None)
    monkeypatch.setattr(
        browser, "_op_creds", lambda item, account: ("aglensk", "pw", "333333")
    )
    creds, mode = browser._cscs_creds(announce=False)
    assert mode == "1password"
    assert creds == ("aglensk", "pw", "333333")
