"""The CSCS Keycloak OTP step gets a code produced at fill time (tp#491 D2).

The code used to be generated before the password submit and typed up to ~20 s
later. Now ``CscsCreds.otp()`` runs only once the OTP field is shown, the page
is re-checked afterwards, and ``_fresh_totp`` waits out the last seconds of a
step. Pages are stand-ins, the clock is mocked, ``op`` is a recorded stub.

Run: python3 -m pytest tests/test_keycloak_otp.py -q     (from the repo root)
"""

from __future__ import annotations

# pylint: disable=protected-access,import-outside-toplevel,too-few-public-methods
# pylint: disable=missing-function-docstring,missing-class-docstring,import-error
import importlib.util
import sys
from pathlib import Path

import pyotp
import pytest

_BROWSER_PY = Path(__file__).resolve().parent.parent / "bin" / "browser.py"


def _load_browser_module():
    spec = importlib.util.spec_from_file_location("browser_keycloak_otp", _BROWSER_PY)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["browser_keycloak_otp"] = mod
    spec.loader.exec_module(mod)
    return mod


browser = _load_browser_module()

SEED = "JBSWY3DPEHPK3PXP"
KEYCLOAK = "https://auth.cscs.ch/auth/realms/cscs/login-actions/authenticate"
PORTAL = "https://portal.cscs.ch/profile/"


class _Field:
    def __init__(self, page: _Page):
        self._page = page

    def fill(self, value):
        if self._page.fill_raises:
            from playwright.sync_api import Error as PlaywrightError

            raise PlaywrightError("Element is not attached DUMMY-DETAIL")
        self._page.log.append(("fill-otp", value))


class _Button:
    def __init__(self, page: _Page):
        self._page = page

    def click(self):
        page = self._page
        page.submits += 1
        page.log.append(("submit", page.submits))
        if page.submits == 1 and page.direct_to_portal:
            page.url = PORTAL
        elif page.submits >= 2:
            page.url = PORTAL


class _Page:
    """Keycloak: user/pass submit → OTP field (or the portal) → portal."""

    def __init__(self, *, direct_to_portal: bool = False):
        self.url = KEYCLOAK
        self.log: list = []
        self.submits = 0
        self.direct_to_portal = direct_to_portal
        self.field_gone = False
        self.fill_raises = False

    def fill(self, sel, value):
        self.log.append(("fill", sel, value))

    def query_selector(self, sel):
        if sel == "#kc-login":
            return _Button(self)
        if sel == "#otp" and self.submits >= 1 and not self.field_gone:
            return _Field(self)
        return None

    def wait_for_timeout(self, _ms):
        self.log.append("wait")


def _provider(page: _Page, code: str | None = "654321", side_effect=None):
    def otp():
        page.log.append("otp()")
        if side_effect:
            side_effect(page)
        return code

    return otp


def test_otp_is_produced_only_after_the_otp_field_appears():
    page = _Page()
    creds = browser.CscsCreds("user", "pw", _provider(page))
    assert browser._submit_keycloak_login(page, creds) is True
    steps = [e for e in page.log if e != "wait"]
    assert steps == [
        ("fill", "#username", "user"),
        ("fill", "#password", "pw"),
        ("submit", 1),
        "otp()",
        ("fill-otp", "654321"),
        ("submit", 2),
    ]


def test_otp_is_never_produced_when_the_portal_is_reached_directly():
    page = _Page(direct_to_portal=True)
    creds = browser.CscsCreds("user", "pw", _provider(page))
    assert browser._submit_keycloak_login(page, creds) is True
    assert "otp()" not in page.log


def test_no_code_means_no_fill_and_no_otp_submit(capsys):
    page = _Page()
    creds = browser.CscsCreds("user", "pw", _provider(page, code=None))
    assert browser._submit_keycloak_login(page, creds) is False
    assert not any(e[0] == "fill-otp" for e in page.log if isinstance(e, tuple))
    assert page.submits == 1
    assert "Could not produce a TOTP code" in capsys.readouterr().out


def _navigate_away(page: _Page):
    page.url = "https://example.org/elsewhere"


def _detach_field(page: _Page):
    page.field_gone = True


@pytest.mark.parametrize("side_effect", [_navigate_away, _detach_field])
def test_page_changing_while_the_code_is_produced_gets_no_code(side_effect):
    page = _Page()
    creds = browser.CscsCreds("user", "pw", _provider(page, side_effect=side_effect))
    assert browser._submit_keycloak_login(page, creds) is False
    assert not any(e[0] == "fill-otp" for e in page.log if isinstance(e, tuple))
    assert page.submits == 1


def test_playwright_error_while_filling_is_false_without_detail(capsys):
    page = _Page()
    page.fill_raises = True
    creds = browser.CscsCreds("user", "pw", _provider(page))
    assert browser._submit_keycloak_login(page, creds) is False
    assert page.submits == 1
    out = capsys.readouterr()
    assert "DUMMY-DETAIL" not in out.out + out.err
    assert "654321" not in out.out + out.err


# --- _fresh_totp -------------------------------------------------------------------


class _Clock:
    def __init__(self, start: float):
        self.now = start
        self.slept: list[float] = []

    def time(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.now += seconds


def _fresh(seed: str, clock: _Clock):
    return browser._fresh_totp(seed, clock=clock.time, sleep=clock.sleep)


STEP0 = 30 * 57_000_000  # an arbitrary step start


def test_mid_step_code_needs_no_wait():
    clock = _Clock(STEP0 + 10)
    assert _fresh(SEED, clock) == pyotp.TOTP(SEED).at(STEP0 + 10)
    assert not clock.slept


def test_late_code_waits_into_the_next_step():
    clock = _Clock(STEP0 + 26)
    code = _fresh(SEED, clock)
    assert clock.slept == [pytest.approx(4.05)]
    assert code == pyotp.TOTP(SEED).at(STEP0 + 30)
    assert code != pyotp.TOTP(SEED).at(STEP0 + 26)


def test_exactly_five_seconds_left_does_not_wait():
    clock = _Clock(STEP0 + 25)
    assert _fresh(SEED, clock) == pyotp.TOTP(SEED).at(STEP0 + 25)
    assert not clock.slept


def test_fractional_time_just_past_the_threshold_waits():
    clock = _Clock(STEP0 + 25.5)
    code = _fresh(SEED, clock)
    assert clock.slept == [pytest.approx(4.55)]
    assert code == pyotp.TOTP(SEED).at(STEP0 + 30)


def test_otpauth_uri_period_is_honoured():
    uri = f"otpauth://totp/CSCS:u?secret={SEED}&issuer=CSCS&period=60"
    base = 60 * 28_000_000
    totp60 = pyotp.TOTP(SEED, interval=60)
    clock = _Clock(base + 50)  # 10 s left of a 60 s step: fine
    assert _fresh(uri, clock) == totp60.at(base + 50)
    assert not clock.slept
    clock = _Clock(base + 56)  # 4 s left: wait for the next 60 s step
    assert _fresh(uri, clock) == totp60.at(base + 60)
    assert clock.slept == [pytest.approx(4.05)]


@pytest.mark.parametrize(
    "bad",
    [
        "not base32 !!",
        "otpauth://totp/x?issuer=CSCS",
        f"otpauth://hotp/CSCS?secret={SEED}&counter=1",
        f"otpauth://totp/CSCS?secret={SEED}&period=0",
        "",
    ],
)
def test_malformed_seed_is_none(bad):
    clock = _Clock(STEP0 + 26)
    assert _fresh(bad, clock) is None
    assert not clock.slept


# --- _op_otp -----------------------------------------------------------------------


class _Res:
    def __init__(self, returncode: int = 0, stdout: str = ""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = ""


@pytest.mark.parametrize(
    "answer, want",
    [
        (_Res(0, "123456\n"), "123456"),
        (_Res(1, ""), None),
        (_Res(0, "  \n"), None),
        (OSError("no op"), None),
    ],
)
def test_op_otp_runs_the_otp_call_with_a_short_timeout(monkeypatch, answer, want):
    calls: list = []

    def fake_run(argv, **kwargs):
        calls.append((argv, kwargs))
        if isinstance(answer, Exception):
            raise answer
        return answer

    monkeypatch.setattr(browser.subprocess, "run", fake_run)
    assert browser._op_otp("CSCS", "acct") == want
    argv, kwargs = calls[0]
    assert argv[0] == "op" and argv[-1] == "--otp"
    assert kwargs["timeout"] == 20
