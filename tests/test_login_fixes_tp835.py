"""Broker logins that failed on 2026-10-08 (tp#835), one root cause each.

* Galaxus (``id.digitecgalaxus.ch`` / ``id.galaxus.eu``) and Zoho
  (``accounts.zoho.eu``): the identifier step pre-renders the step-2 password
  field, hidden from humans without ``display: none`` (Galaxus: the input says
  ``aria-hidden=true`` inside an ``opacity: 0; height: 0`` wrapper; Zoho: a
  ``height: 0; overflow: hidden`` container). The broker took it for a
  one-page form. ``FIELD_DESCRIBE_JS`` now reports ``concealed`` and the field
  pickers skip such inputs.
* Calibre-Web Automated: the login form's FIRST submit button is
  ``name=forgot`` ("Forgot Password?"), so Enter in the password field fired
  it. ``_submit_password`` clicks the login button instead.
* Jellyfin: ``agent_pre_click`` (``.btnManual``) clicked at first sight did
  nothing — the SPA attached its handler later. ``_pre_click`` re-clicks.
* Kavita: the sentinel ``app-side-nav`` is an inline custom element around a
  fixed-position child, so its own box is 0x0. ``sentinel_shown`` accepts a
  visible descendant.
* gitlab.ethz.ch (Anubis): a fixed ``Chrome/141`` User-Agent on engine 148
  earned proof-of-work difficulty 7; the broker now uses the engine's version.

Hermetic by default. The real-browser tests (`-m browser`, opt-in via
LOGIN_BROKER_E2E=1) use a throwaway headless Chromium on local HTML; no real
site is contacted.

Run: uv run --no-sync pytest tests/test_login_fixes_tp835.py
"""

from __future__ import annotations

# pylint: disable=protected-access,import-outside-toplevel,too-few-public-methods
# pylint: disable=missing-function-docstring,missing-class-docstring,import-error
# pylint: disable=redefined-outer-name,wrong-import-position
import contextlib
import os
import plistlib
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from broker import daemon, login_form, recipes  # noqa: E402

ORIGIN = "https://login.example"
E2E = pytest.mark.skipif(
    os.environ.get("LOGIN_BROKER_E2E") != "1", reason="set LOGIN_BROKER_E2E=1"
)


def _desc(**kw: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "type": "password",
        "name": "password",
        "id": "",
        "autocomplete": "",
        "form": True,
        "form_action": "",
        "form_id": "",
        "form_class": "",
        "form_name": "",
        "form_passwords": 1,
        "form_confirm": False,
        "concealed": False,
    }
    base.update(kw)
    return base


# ---------------------------------------------------------------------------
# A. concealed fields never count (pure)
# ---------------------------------------------------------------------------


def test_concealed_current_password_is_skipped():
    # Galaxus step 1: the only password input is a concealed
    # autocomplete=current-password decoy -> no login password on this page.
    decoy = _desc(autocomplete="current-password", concealed=True)
    assert login_form.pick_login_password([decoy]) is None


def test_shown_password_after_a_concealed_one_is_picked():
    decoy = _desc(autocomplete="current-password", concealed=True)
    real = _desc(name="pw")
    assert login_form.pick_login_password([decoy, real]) == 1


def test_unflagged_descriptors_keep_the_old_rules():
    desc = _desc()
    del desc["concealed"]
    assert login_form.pick_login_password([desc]) == 0
    assert login_form.pick_login_username([_desc(type="email", name="email")]) == 0


def test_concealed_username_is_skipped():
    hidden = _desc(type="email", name="email", concealed=True)
    shown = _desc(type="text", name="login")
    assert login_form.pick_login_username([hidden]) is None
    assert login_form.pick_login_username([hidden, shown]) == 1


# ---------------------------------------------------------------------------
# B. which submit button the password goes to (pure)
# ---------------------------------------------------------------------------


def _button(**kw: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "name": "",
        "id": "",
        "cls": "",
        "text": "",
        "aria": "",
        "disabled": False,
        "visible": True,
    }
    base.update(kw)
    return base


CWA_FORGOT = _button(name="forgot", cls="cwa-link-button", text="Forgot Password?")
CWA_LOGIN = _button(name="submit", cls="cwa-btn cwa-btn-primary", text="Login")


def test_calibre_web_forgot_default_button_is_bypassed():
    assert login_form.secondary_button_like(CWA_FORGOT)
    assert not login_form.secondary_button_like(CWA_LOGIN)
    assert login_form.pick_submit_button([CWA_FORGOT, CWA_LOGIN]) == 1


@pytest.mark.parametrize(
    "buttons",
    [
        [],  # no form / no buttons: Enter, as before
        [CWA_LOGIN, CWA_FORGOT],  # the default button logs in
        [_button(text="Anmelden"), _button(text="Passwort vergessen?")],
        [_button(text="Weiter", cls="btn btn-back show-mobile")],  # class noise
        [_button(text="Sign in", name="register-or-login")],  # names the login too
    ],
)
def test_enter_stays_when_the_default_button_logs_in(buttons):
    assert login_form.pick_submit_button(buttons) is None


@pytest.mark.parametrize(
    "default",
    [
        _button(aria="Show password"),
        _button(aria="Passwort anzeigen"),
        _button(cls="password-toggle"),
        _button(text="Use a passkey"),
        _button(text="Create account"),
        _button(text="Cancel"),
    ],
)
def test_secondary_default_buttons(default):
    assert login_form.pick_submit_button([default, CWA_LOGIN]) == 1


def test_hidden_or_disabled_login_buttons_are_not_clicked():
    hidden = _button(text="Login", visible=False)
    disabled = _button(text="Login", disabled=True)
    assert login_form.pick_submit_button([CWA_FORGOT, hidden, disabled]) == -1


# ---------------------------------------------------------------------------
# C. agent_pre_click re-clicks a button whose handler came late (fake page)
# ---------------------------------------------------------------------------


class _Frame:
    def __init__(self, url: str) -> None:
        self.url = url


class _LateButton:
    """Visible until clicked `needed` times (the handler attaches late)."""

    def __init__(self, needed: int) -> None:
        self.needed = needed
        self.clicks = 0

    def is_visible(self) -> bool:
        return self.clicks < self.needed

    def owner_frame(self) -> _Frame:
        return _Frame(ORIGIN + "/web/")

    def click(self) -> None:
        self.clicks += 1


class _Page:
    def __init__(self, button: _LateButton) -> None:
        self.url = ORIGIN + "/web/"
        self.button = button

    def query_selector_all(self, selector: str) -> list[Any]:
        return [self.button] if selector == ".btnManual" else []

    def wait_for_timeout(self, _ms: float) -> None:
        return


@pytest.fixture
def no_fields(monkeypatch):
    monkeypatch.setattr(recipes, "_check_challenge", lambda *a, **k: None)
    monkeypatch.setattr(recipes, "_login_password", lambda page: None)
    monkeypatch.setattr(recipes, "_login_username", lambda page: None)
    monkeypatch.setattr(recipes, "PRE_CLICK_RETRY_S", 0.0)


@pytest.mark.usefixtures("no_fields")
@pytest.mark.parametrize("needed", [1, 2, 3])
def test_pre_click_repeats_until_the_element_goes(needed):
    button = _LateButton(needed)
    assert recipes._pre_click(_Page(button), ".btnManual", [ORIGIN], dev=False)
    assert button.clicks == needed


def test_pre_click_stops_once_a_login_field_shows(monkeypatch):
    monkeypatch.setattr(recipes, "_check_challenge", lambda *a, **k: None)
    monkeypatch.setattr(recipes, "PRE_CLICK_RETRY_S", 0.0)
    button = _LateButton(needed=99)
    shown: dict[str, Any] = {"field": None}
    monkeypatch.setattr(recipes, "_login_password", lambda page: shown["field"])
    monkeypatch.setattr(recipes, "_login_username", lambda page: None)
    real_click = button.click

    def click() -> None:
        real_click()
        shown["field"] = object()  # the form opens; the button stays visible

    button.click = click  # type: ignore[method-assign]
    assert recipes._pre_click(_Page(button), ".btnManual", [ORIGIN], dev=False)
    assert button.clicks == 1


# ---------------------------------------------------------------------------
# D. the broker's User-Agent carries the engine's version
# ---------------------------------------------------------------------------


def _fake_app(tmp_path: Path, version: str | None) -> str:
    contents = tmp_path / "Chromium.app" / "Contents"
    (contents / "MacOS").mkdir(parents=True)
    if version is not None:
        with (contents / "Info.plist").open("wb") as fh:
            plistlib.dump({"CFBundleShortVersionString": version}, fh)
    return str(contents / "MacOS" / "Chromium")


class _Pw:
    def __init__(self, executable: str) -> None:
        self.chromium = type("C", (), {"executable_path": executable})()


def test_user_agent_follows_the_engine(tmp_path, monkeypatch):
    monkeypatch.delenv("LOGIN_BROKER_USER_AGENT", raising=False)
    exe = _fake_app(tmp_path, "148.0.7778.96")
    ua = daemon.broker_user_agent(_Pw(exe))
    assert "Chrome/148.0.0.0 Safari/537.36" in ua
    assert "Headless" not in ua


@pytest.mark.parametrize("version", [None, "", "abc"])
def test_user_agent_falls_back(tmp_path, monkeypatch, version):
    monkeypatch.delenv("LOGIN_BROKER_USER_AGENT", raising=False)
    exe = _fake_app(tmp_path, version)
    assert daemon.broker_user_agent(_Pw(exe)) == daemon.FALLBACK_CHROME_UA


def test_user_agent_env_override(tmp_path, monkeypatch):
    monkeypatch.setenv("LOGIN_BROKER_USER_AGENT", "Custom/1.0")
    exe = _fake_app(tmp_path, "148.0.1.2")
    assert daemon.broker_user_agent(_Pw(exe)) == "Custom/1.0"


# ---------------------------------------------------------------------------
# E. the same rules in a real headless Chromium (local HTML only)
# ---------------------------------------------------------------------------


@contextlib.contextmanager
def _page() -> Iterator[Any]:
    from playwright.sync_api import sync_playwright

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        try:
            yield browser.new_page(viewport={"width": 1280, "height": 720})
        finally:
            browser.close()


def _concealed(page: Any, selector: str) -> bool:
    return bool(page.eval_on_selector(selector, login_form.CONCEALED_JS))


_CONCEALED_HTML = """<html><body>
<form id=galaxus>
  <input id=g_email type=text autocomplete="username webauthn">
  <div style="opacity:0;height:0"><input id=g_pw type=password
    autocomplete=current-password aria-hidden=true tabindex=-1></div>
</form>
<form id=zoho>
  <input id=z_login type=text>
  <div style="height:0;overflow:hidden"><div style="height:44px">
    <input id=z_pw type=password></div></div>
</form>
<form id=plain><input id=p_user type=text><input id=p_pw type=password></form>
<div style="height:40px;overflow:auto"><div style="height:400px"></div>
  <input id=scrolled type=password></div>
<div style="height:0;overflow:hidden">
  <input id=escapes type=password style="position:absolute;top:300px"></div>
<div style="height:0;overflow:hidden;position:relative">
  <input id=clipped_abs type=password style="position:absolute;top:300px"></div>
<div id=host></div>
<script>
  const root = document.getElementById('host').attachShadow({mode: 'open'});
  root.innerHTML = '<div style="height:0;overflow:hidden"><input id=s_pw type=password></div>';
</script>
</body></html>"""


@pytest.mark.browser
@E2E
def test_concealed_rule_in_chromium():
    with _page() as page:
        page.set_content(_CONCEALED_HTML)
        assert _concealed(page, "#g_pw")  # aria-hidden + opacity 0 (Galaxus)
        assert _concealed(page, "#z_pw")  # zero-height overflow:hidden (Zoho)
        assert _concealed(page, "#clipped_abs")  # clipped by its containing block
        assert _concealed(page, "#host >> #s_pw")  # across a shadow root
        for shown in ("#g_email", "#z_login", "#p_user", "#p_pw"):
            assert not _concealed(page, shown), shown
        assert not _concealed(page, "#scrolled")  # scrollable: a human can reach it
        assert not _concealed(page, "#escapes")  # abs box escapes a static clip


@pytest.mark.browser
@E2E
def test_identifier_first_with_decoy_password_in_chromium():
    with _page() as page:
        page.set_content(_CONCEALED_HTML.replace("<form id=zoho>", "<form hidden>"))
        page.eval_on_selector("#plain", "f => f.remove()")
        for sel in ("#scrolled", "#escapes", "#clipped_abs", "#host"):
            page.eval_on_selector(sel, "e => e.remove()")
        user, pw_field = recipes._wait_login_fields(page, 2.0)
        assert pw_field is None
        assert user is not None and user.get_attribute("id") == "g_email"


@pytest.mark.browser
@E2E
def test_inline_custom_element_sentinel_in_chromium():
    html = (
        "<html><body><app-side-nav><div class=side-nav "
        "style='position:fixed;left:0;top:0;width:200px;height:400px'>"
        "</div></app-side-nav>"
        "<app-gone><div style='position:fixed;visibility:hidden;width:9px;"
        "height:9px'></div></app-gone></body></html>"
    )
    with _page() as page:
        page.set_content(html)
        assert not page.is_visible("app-side-nav")  # the Playwright view
        assert recipes.sentinel_shown(page, "app-side-nav")
        assert not recipes.sentinel_shown(page, "app-gone")
        assert not recipes.sentinel_shown(page, "app-missing")


_CWA_HTML = """<html><body>
<form method=post action="/login" id=login onsubmit="event.preventDefault();
    document.title = 'submitted:' + (event.submitter ? event.submitter.name : '')">
  <input id=username name=username autocomplete=username>
  <input id=password name=password type=password autocomplete=current-password>
  <label><input type=checkbox name=remember_me checked> Remember Me</label>
  <button type=submit name=forgot value=forgot class=cwa-link-button>Forgot Password?</button>
  <button type=submit name=submit class="cwa-btn cwa-btn-primary">Login</button>
</form></body></html>"""


@pytest.mark.browser
@E2E
@pytest.mark.parametrize("swap", [False, True], ids=["forgot-first", "login-first"])
def test_password_submit_uses_the_login_button_in_chromium(monkeypatch, swap):
    html = _CWA_HTML
    if swap:  # login button first: Enter, as always
        forgot = "<button type=submit name=forgot value=forgot class=cwa-link-button>"
        forgot += "Forgot Password?</button>"
        login = '<button type=submit name=submit class="cwa-btn cwa-btn-primary">'
        login += "Login</button>"
        html = html.replace(forgot + "\n  " + login, login + forgot)
    monkeypatch.setattr(recipes, "_guard", lambda *a, **k: None)
    monkeypatch.setattr(
        recipes, "_click_on_fill_origin", lambda p, el, a, dev: el.click()
    )
    monkeypatch.setattr(recipes, "_frame_url", lambda handle: ORIGIN + "/login")
    with _page() as page:
        page.set_content(html)
        pw_field = recipes._login_password(page)
        assert pw_field is not None
        pw_field.fill("fixture-not-a-secret")
        recipes._submit_password(page, pw_field, [ORIGIN], dev=False)
        page.wait_for_timeout(200)
        assert page.title() == "submitted:submit"
