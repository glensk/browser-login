#!/usr/bin/env python3
"""Keychain / 1Password credential access and the CSCS Keycloak login (browser.py).

Nothing here touches a real keychain, `op`, network or browser: `subprocess.run`
is replaced by a recorder, and pages are tiny stand-ins. What is pinned down:
secrets never reach argv or stdout on the READ path, every subprocess has a
timeout, a failing tool degrades to ``None``/``False`` (never a crash, never a
false success), and the Keycloak form flow fills the OTP exactly once.

Run: python3 -m pytest tests/ -q     (from the repo root)
"""

from __future__ import annotations

# Tests reach into browser.py's private helpers on purpose (it is a script, not
# a package, so there is no public API), and build throwaway stub classes.
# pylint: disable=protected-access,import-outside-toplevel,too-few-public-methods
# pylint: disable=missing-function-docstring,missing-class-docstring,import-error
# pylint: disable=unused-argument
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pyotp
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

SEED = "JBSWY3DPEHPK3PXP"


class _Res:
    def __init__(self, returncode: int = 0, stdout: str = "", stderr: str = ""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class _Run:
    """Records every subprocess.run call; answers from a queue or a callable."""

    def __init__(self, *answers):
        self.calls: list[tuple[list[str], dict]] = []
        self._answers = list(answers)

    def __call__(self, argv, **kwargs):
        self.calls.append((list(argv), kwargs))
        ans = self._answers.pop(0) if len(self._answers) > 1 else self._answers[0]
        if isinstance(ans, BaseException):
            raise ans
        return ans


@pytest.fixture
def run(monkeypatch):
    def install(*answers):
        rec = _Run(*answers)
        monkeypatch.setattr(browser.subprocess, "run", rec)
        return rec

    monkeypatch.setattr(browser, "_kc_account", lambda: "tester")
    return install


# --- keychain ------------------------------------------------------------------


def test_keychain_get_reads_with_timeout_and_strips_only_newline(run):
    rec = run(_Res(0, "  pw with spaces  \n"))
    assert browser._keychain_get("svc") == "  pw with spaces  "
    argv, kwargs = rec.calls[0]
    assert argv[:2] == ["security", "find-generic-password"]
    assert argv[argv.index("-a") + 1] == "tester"
    assert argv[argv.index("-s") + 1] == "svc"
    assert kwargs["timeout"] and kwargs["capture_output"]


@pytest.mark.parametrize(
    "answer",
    [
        _Res(44, "", "The specified item could not be found in the keychain."),
        _Res(0, "\n"),
        OSError("no security binary"),
        subprocess.TimeoutExpired("security", 15),
    ],
)
def test_keychain_get_failure_is_none(run, answer):
    run(answer)
    assert browser._keychain_get("svc") is None


def test_keychain_set_reports_the_return_code(run):
    rec = run(_Res(0))
    assert browser._keychain_set("svc", "v") is True
    assert rec.calls[0][1]["timeout"]
    run(_Res(1))
    assert browser._keychain_set("svc", "v") is False
    run(OSError("gone"))
    assert browser._keychain_set("svc", "v") is False


def test_keychain_creds_generates_the_code_locally(monkeypatch):
    items = {
        browser.KEYCHAIN_SVC_USER: "user",
        browser.KEYCHAIN_SVC_PASS: "pw",
        browser.KEYCHAIN_SVC_TOTP: SEED,
    }
    monkeypatch.setattr(browser, "_keychain_get", items.get)
    creds = browser._keychain_creds()
    assert creds is not None and creds[:2] == ("user", "pw")
    assert pyotp.TOTP(SEED).verify(creds[2], valid_window=1)

    items[browser.KEYCHAIN_SVC_TOTP] = "not base32 !!"
    assert browser._keychain_creds() is None
    del items[browser.KEYCHAIN_SVC_PASS]
    assert browser._keychain_creds() is None


# --- TOTP ------------------------------------------------------------------------


def test_totp_now_accepts_seed_and_uri_forms():
    want = pyotp.TOTP(SEED).now()
    assert browser._totp_now(SEED) == want
    assert browser._totp_now(" jbsw y3dp ehpk 3pxp ") == want
    assert browser._totp_now(f"otpauth://totp/CSCS:u?secret={SEED}&issuer=CSCS") == want


@pytest.mark.parametrize(
    "bad",
    ["not base32 !!", "otpauth://totp/x?issuer=CSCS", "otpauth://totp/x?secret=!!!!"],
)
def test_totp_now_rejects_malformed_input(bad):
    assert browser._totp_now(bad) is None


def test_totp_now_changes_on_the_period_boundary(monkeypatch):
    # The code is a function of floor(t / 30): the last second of a window and
    # the first second of the next produce different codes.
    import datetime as _dt

    import pyotp.totp

    def frozen(epoch: float):
        class _Frozen(_dt.datetime):
            @classmethod
            def now(cls, tz=None):
                return _dt.datetime.fromtimestamp(epoch, tz)

        monkeypatch.setattr(pyotp.totp.datetime, "datetime", _Frozen)

    frozen(59.0)
    before = browser._totp_now(SEED)
    frozen(60.0)
    after = browser._totp_now(SEED)
    monkeypatch.undo()
    assert before == pyotp.TOTP(SEED).at(59)
    assert after == pyotp.TOTP(SEED).at(60)
    assert before != after


# --- 1Password -------------------------------------------------------------------


def test_op_creds_parses_fields_and_live_otp(run):
    fields = [
        {"label": "username", "value": "user"},
        {"label": "password", "value": "pw"},
    ]
    rec = run(_Res(0, json.dumps(fields)), _Res(0, "123456\n"))
    assert browser._op_creds("CSCS", "acct") == ("user", "pw", "123456")
    assert all(kwargs["timeout"] for _, kwargs in rec.calls)
    assert rec.calls[1][0][-1] == "--otp"


@pytest.mark.parametrize(
    "creds_out, otp_out",
    [
        (_Res(1, "", "not signed in"), _Res(0, "123456")),
        (_Res(0, "{not json"), _Res(0, "123456")),
        (_Res(0, json.dumps([{"label": "username", "value": "u"}])), _Res(0, "1")),
        (_Res(0, json.dumps([{"label": "password", "value": "p"}])), _Res(1)),
    ],
)
def test_op_creds_failure_is_none(run, creds_out, otp_out):
    run(creds_out, otp_out)
    assert browser._op_creds("CSCS", "acct") is None


def test_op_totp_uri_finds_the_seed_uri(run):
    uri = f"otpauth://totp/CSCS?secret={SEED}"
    run(_Res(0, json.dumps([{"type": "OTP", "totp": "123456", "value": uri}])))
    assert browser._op_totp_uri("CSCS", "acct") == uri
    run(_Res(0, json.dumps({"type": "OTP", "totp": uri})))
    assert browser._op_totp_uri("CSCS", "acct") == uri


@pytest.mark.parametrize(
    "answer",
    [
        _Res(0, json.dumps([{"totp": "123456"}])),  # live code only, no seed
        _Res(0, "garbage"),
        _Res(1, ""),
        subprocess.TimeoutExpired("op", 60),
    ],
)
def test_op_totp_uri_without_seed_is_none(run, answer):
    run(answer)
    assert browser._op_totp_uri("CSCS", "acct") is None


# --- cscs-store-creds ------------------------------------------------------------


def _store_creds_env(monkeypatch, seed: str):
    stored: dict[str, str] = {}
    monkeypatch.setattr(browser.shutil, "which", lambda name: "/usr/bin/op")
    monkeypatch.setattr(browser, "_op_creds", lambda item, acct: ("user", "pw", "1"))
    monkeypatch.setattr(browser, "_op_totp_uri", lambda item, acct: seed)
    monkeypatch.setattr(
        browser, "_keychain_set", lambda svc, v: stored.__setitem__(svc, v) or True
    )
    return stored


def test_store_creds_writes_all_three_without_printing_secrets(monkeypatch, capsys):
    stored = _store_creds_env(monkeypatch, SEED)
    assert browser.cmd_cscs_store_creds() == 0
    assert stored == {
        browser.KEYCHAIN_SVC_USER: "user",
        browser.KEYCHAIN_SVC_PASS: "pw",
        browser.KEYCHAIN_SVC_TOTP: SEED,
    }
    out = capsys.readouterr()
    assert SEED not in out.out + out.err and "pw\n" not in out.out


def test_store_creds_refuses_a_seed_that_makes_no_code(monkeypatch):
    stored = _store_creds_env(monkeypatch, "not base32 !!")
    assert browser.cmd_cscs_store_creds() == 1
    assert not stored


# --- Keycloak form ---------------------------------------------------------------


class _El:
    def __init__(self, log: list, name: str):
        self._log, self._name = log, name

    def click(self):
        self._log.append(("click", self._name))

    def fill(self, value):
        self._log.append(("fill", self._name, value))


class _KcPage:
    """Keycloak: user/pass → OTP step → portal after the second submit."""

    def __init__(self, reach_portal: bool = True):
        self.url = "https://auth.cscs.ch/auth/realms/cscs/login-actions/authenticate"
        self.log: list = []
        self.submits = 0
        self._reach = reach_portal

    def fill(self, sel, value):
        self.log.append(("fill", sel, value))

    def query_selector(self, sel):
        if sel == "#kc-login":
            return self
        if sel == "#otp" and self.submits >= 1:
            return _El(self.log, sel)
        return None

    def click(self):
        self.submits += 1
        if self.submits >= 2 and self._reach:
            self.url = "https://portal.cscs.ch/profile/"

    def wait_for_timeout(self, _ms):
        pass


def test_submit_keycloak_login_fills_otp_once_and_lands_on_portal():
    page = _KcPage()
    assert browser._submit_keycloak_login(page, ("user", "pw", "654321")) is True
    assert ("fill", "#username", "user") in page.log
    assert ("fill", "#password", "pw") in page.log
    assert page.log.count(("fill", "#otp", "654321")) == 1
    assert page.submits == 2


def test_submit_keycloak_login_that_never_reaches_portal_is_false():
    page = _KcPage(reach_portal=False)
    assert browser._submit_keycloak_login(page, ("user", "pw", "654321")) is False
    assert page.log.count(("fill", "#otp", "654321")) == 1


def test_click_keycloak_submit_is_a_noop_without_a_button():
    class _Blank:
        def query_selector(self, sel):
            return None

    browser._click_keycloak_submit(_Blank())  # must not raise


@pytest.mark.parametrize(
    "url, on_portal",
    [
        ("https://portal.cscs.ch/profile/", True),
        ("https://auth.cscs.ch/auth/realms/cscs/protocol/openid-connect/auth", False),
        ("https://portal.cscs.ch/api-auth/keycloak/complete/?state=x", False),
        ("https://portal.cscs.ch/oauth_login_completed/", False),
        ("https://portal.cscs.ch/profile/?code=abc", False),
        ("https://example.com/portal.cscs.ch", True),
    ],
)
def test_on_portal(url, on_portal):
    class _P:
        pass

    p = _P()
    p.url = url
    assert browser._on_portal(p) is on_portal


# --- DRF token scan ----------------------------------------------------------------

HEX = "0123456789abcdef0123456789abcdef01234567"


class _Ctx:
    def __init__(self, cookies):
        self._cookies = cookies

    def cookies(self, urls=None):
        return list(self._cookies)


class _TokPage:
    def __init__(self, token=None, exc=None):
        self._token, self._exc = token, exc

    def evaluate(self, _js):
        if self._exc:
            raise self._exc
        return self._token


def test_scan_token_prefers_local_storage():
    assert browser._scan_token(_Ctx([]), _TokPage(HEX)) == HEX


def test_scan_token_falls_back_to_portal_cookie():
    ctx = _Ctx([{"name": "token", "domain": "portal.cscs.ch", "value": HEX}])
    assert browser._scan_token(ctx, _TokPage(None)) == HEX


def test_scan_token_survives_a_navigation_mid_scan():
    from playwright.sync_api import Error as PlaywrightError

    page = _TokPage(exc=PlaywrightError("Execution context was destroyed"))
    assert browser._scan_token(_Ctx([]), page) is None


class _ScopedCtx:
    """Like a Playwright context: ``cookies(urls)`` filters by URL, ``cookies()``
    returns EVERY site's cookies."""

    def __init__(self, cookies):
        self._cookies = cookies
        self.asked: list = []

    def cookies(self, urls=None):
        self.asked.append(urls)
        if urls is None:
            return list(self._cookies)
        urls = [urls] if isinstance(urls, str) else urls
        return [c for c in self._cookies if any(c["domain"] in u for u in urls)]


def test_scan_token_ignores_other_sites_cookies():
    # Regression: the cookie fallback scanned ctx.cookies() — every site's
    # cookies in the shared profile — so a 40-hex session cookie from another
    # site was cached as the CSCS token and sent to portal.cscs.ch.
    other = "fedcba9876543210fedcba9876543210fedcba98"
    ctx = _ScopedCtx([{"name": "sid", "domain": "slack.com", "value": other}])
    assert browser._scan_token(ctx, _TokPage(None)) is None
    assert None not in ctx.asked


class _Resp:
    status_code = 200
    text = ""

    @staticmethod
    def json():
        return {"username": "user", "email": "u@x.ch"}


@pytest.fixture
def token_env(tmp_path, monkeypatch):
    import os

    import requests

    cache = tmp_path / "cscs-api" / "portal_token"
    monkeypatch.setattr(browser, "CSCS_TOKEN_CACHE", cache)
    monkeypatch.setattr(browser, "_scan_token", lambda ctx, page: HEX)
    monkeypatch.setattr(requests, "get", lambda *a, **k: _Resp())
    old = os.umask(0o022)
    yield cache
    os.umask(old)


def test_token_cache_is_never_readable_by_others(token_env, monkeypatch):
    # Regression: write_text() created the file 0644 and only a later chmod()
    # tightened it, leaving a window where any local user could read the token.
    # With the after-the-fact chmod neutralised, the file must still be 0600.
    import pathlib

    monkeypatch.setattr(pathlib.Path, "chmod", lambda self, mode: None)
    assert browser._capture_and_cache_token(None, None) == 0
    assert token_env.read_text() == HEX
    assert token_env.stat().st_mode & 0o777 == 0o600


def test_token_cache_tightens_a_preexisting_loose_file(token_env):
    token_env.parent.mkdir(parents=True)
    token_env.write_text("old-token-that-is-longer-than-the-new-one" * 2)
    token_env.chmod(0o644)
    assert browser._capture_and_cache_token(None, None) == 0
    assert token_env.read_text() == HEX
    assert token_env.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize(
    "answer, ok",
    [
        (_Res(0), True),
        (_Res(44, "", "The specified item could not be found in the keychain."), True),
        (_Res(51, "", "User interaction is not allowed."), False),
        (OSError("no security binary"), False),
    ],
)
def test_keychain_delete_reports_real_failures(run, answer, ok):
    # Regression: the return code was ignored, so a locked keychain (51) was
    # reported as "deleted" and the secret silently stayed stored.
    run(answer)
    assert browser._keychain_delete("svc") is ok


@pytest.mark.parametrize(
    "cmd", ["cmd_cscs_forget_creds", "cmd_biopolwifi_forget_creds"]
)
def test_forget_creds_fails_loud_when_an_item_survives(monkeypatch, capsys, cmd):
    # Regression: forget-creds printed "✓ Removed" and exited 0 even when the
    # secrets were still in the keychain.
    monkeypatch.setattr(browser, "_keychain_delete", lambda svc: "pass" not in svc)
    assert getattr(browser, cmd)() == 1
    out = capsys.readouterr()
    assert "✓" not in out.out and "password" in out.err


@pytest.mark.parametrize(
    "cmd", ["cmd_cscs_forget_creds", "cmd_biopolwifi_forget_creds"]
)
def test_forget_creds_succeeds_when_all_items_are_gone(monkeypatch, capsys, cmd):
    deleted: list[str] = []
    monkeypatch.setattr(
        browser, "_keychain_delete", lambda svc: not deleted.append(svc)
    )
    assert getattr(browser, cmd)() == 0
    assert len(deleted) == (3 if "cscs" in cmd else 2)
    assert "✓ Removed" in capsys.readouterr().out


@pytest.mark.parametrize(
    "bad",
    [
        f"otpauth://hotp/CSCS?secret={SEED}&counter=1",  # AttributeError: no .now()
        f"otpauth://totp/CSCS?secret={SEED}&period=0",  # ZeroDivisionError
        "   ",  # empty key: pyotp happily makes a code from b""
    ],
)
def test_totp_now_rejects_unusable_secrets_without_crashing(bad):
    # Regression: these crashed cscs-store-creds with a traceback, or (blank
    # seed in the keychain) produced a code that is guaranteed wrong and burns a
    # Keycloak attempt toward the account lockout.
    assert browser._totp_now(bad) is None
