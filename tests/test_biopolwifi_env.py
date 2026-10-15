"""`login biopolwifi` reads its portal credentials from the env, never the keychain.

No browser and no keychain: the page is a stub, `_keychain_get` and
`subprocess.run` raise if anything reaches them, and the values are dummies.

Run: python3 -m pytest tests/test_biopolwifi_env.py -q     (from the repo root)
"""

from __future__ import annotations

# pylint: disable=protected-access,missing-function-docstring,missing-class-docstring
# pylint: disable=import-error,too-few-public-methods,duplicate-code
import contextlib
import importlib.util
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

_BROWSER_PY = Path(__file__).resolve().parent.parent / "bin" / "browser.py"


def _load_browser_module():
    spec = importlib.util.spec_from_file_location("browser_biopol_env", _BROWSER_PY)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["browser_biopol_env"] = mod
    spec.loader.exec_module(mod)
    return mod


browser = _load_browser_module()
DUMMY_PW = "dummy-portal-pw"  # not a real secret


def _boom(*_a: Any, **_k: Any) -> Any:
    raise AssertionError("the biopolwifi flow must not touch the keychain")


@pytest.fixture(autouse=True)
def _no_keychain(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(browser, "_keychain_get", _boom)
    monkeypatch.setattr(browser, "_keychain_set_all", _boom)
    monkeypatch.setattr(browser, "_keychain_delete", _boom)
    monkeypatch.setattr(subprocess, "run", _boom)
    monkeypatch.setattr(
        browser, "_interaction_lease", lambda *a, **k: contextlib.nullcontext()
    )
    monkeypatch.setattr(browser, "_record_login_event", lambda *a: None)


class FakePage:
    """The Cloudpath login form: logged out until the form is submitted."""

    url = "https://cloudpath.edificom.cloud/management-portal/x"

    def __init__(self) -> None:
        self.filled: dict[str, str] = {}
        self.clicked: list[str] = []

    def goto(self, *_a: Any, **_k: Any) -> None:
        return None

    def wait_for_timeout(self, _ms: int) -> None:
        return None

    def wait_for_selector(self, *_a: Any, **_k: Any) -> None:
        return None

    def evaluate(self, _js: str) -> bool:
        return bool(self.clicked)

    def fill(self, selector: str, value: str) -> None:
        self.filled[selector] = value

    def click(self, selector: str) -> None:
        self.clicked.append(selector)


def _set_env(monkeypatch: pytest.MonkeyPatch, email: str | None, pw: str | None):
    for name, value in (("BIOPOLWIFI_EMAIL", email), ("BIOPOLWIFI_PASSWORD", pw)):
        if value is None:
            monkeypatch.delenv(name, raising=False)
        else:
            monkeypatch.setenv(name, value)


def test_login_fills_the_form_from_the_env(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _set_env(monkeypatch, "e@example.org", DUMMY_PW)
    page = FakePage()
    assert browser._biopolwifi_login_owned(page) == 0
    assert page.filled == {
        'input[placeholder="Email Address"]': "e@example.org",
        'input[placeholder="Password"]': DUMMY_PW,
    }
    assert DUMMY_PW not in capsys.readouterr().out


@pytest.mark.parametrize(
    ("email", "pw", "missing"),
    [
        pytest.param(None, None, "BIOPOLWIFI_EMAIL and BIOPOLWIFI_PASSWORD", id="both"),
        pytest.param("e@example.org", None, "BIOPOLWIFI_PASSWORD not set", id="pw"),
        pytest.param(None, DUMMY_PW, "BIOPOLWIFI_EMAIL not set", id="email"),
    ],
)
def test_login_without_env_fails_naming_the_rerun_line(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    email: str | None,
    pw: str | None,
    missing: str,
) -> None:
    _set_env(monkeypatch, email, pw)
    page = FakePage()
    assert browser._biopolwifi_login_owned(page) == 1
    assert not page.filled
    assert not page.clicked
    err = capsys.readouterr().err
    assert missing in err
    assert "env-profile-run.py biopol-wifi -- browser.py login biopolwifi" in err
    assert DUMMY_PW not in err


@pytest.mark.parametrize("verb", ["cmd_store_creds", "cmd_forget_creds"])
def test_store_and_forget_creds_are_retired(
    capsys: pytest.CaptureFixture[str], verb: str
) -> None:
    assert getattr(browser, verb)("biopolwifi") == 1
    err = capsys.readouterr().err
    assert "no credentials in the macOS keychain" in err
    assert "env-profile-run.py biopol-wifi" in err


class StatePage:
    """A fresh tab that settles on one portal state ('in' / 'form' / 'other')."""

    def __init__(self, state: str) -> None:
        self.state = state

    def goto(self, *_a: Any, **_k: Any) -> None:
        return None

    def wait_for_timeout(self, _ms: int) -> None:
        return None

    def evaluate(self, _js: str) -> str:
        return self.state


@pytest.mark.parametrize(
    ("state", "rc", "says"),
    [
        pytest.param("in", 0, "✓ Logged into", id="sentinel"),
        pytest.param("form", 2, "sessionStorage", id="per-tab-login-form"),
        pytest.param("other", 2, "neither the logged-in sentinel", id="unexpected"),
    ],
)
def test_logged_in_answers_from_a_fresh_tab_and_says_why(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    state: str,
    rc: int,
    says: str,
) -> None:
    """tp#1059: the portal's session lives in the signing-in tab only, so a
    fresh tab after `login` shows the form — exit 2, and the reason is named."""
    monkeypatch.setattr(
        browser, "_logged_in_page_check", lambda _port, check: check(StatePage(state))
    )
    assert browser.cmd_biopolwifi_logged_in(9222) == rc
    out = capsys.readouterr()
    assert says in (out.out + out.err)
