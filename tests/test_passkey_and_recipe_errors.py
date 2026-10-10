"""Broker logins still failing after the tp#835 round-1 fixes (2026-10-08).

* Zoho (``accounts.zoho.eu``): after the e-mail lookup the page asks for the
  account's passkey (``/signin/v2/primary/<id>/passkey/self``, then
  ``navigator.credentials.get({publicKey})``). The broker's headless Chromium
  has no authenticator, so the promise never settled and "Next" stayed a
  disabled spinner. Every broker context now gets ``NO_PASSKEY_JS``, which
  refuses WebAuthn requests like a human's "Cancel"; Zoho then shows its
  password field (verified against the live page, e-mail step only).
* The same run ended as "unexpected error during login" with no screenshot:
  ``_submit_identifier``'s fallback clicked the disabled spinner and
  Playwright's click waited 30 s. The fallback now skips a disabled button and
  bounds the click, and the daemon reports any non-recipe exception of a
  recipe as a recorded ``LoginFailed`` naming the exception class and frame.

Hermetic by default. The real-browser tests (`-m browser`, opt-in via
LOGIN_BROKER_E2E=1) use a throwaway headless Chromium on routed local HTML;
no real site is contacted.

Run: uv run --no-sync pytest tests/test_passkey_and_recipe_errors.py
"""

from __future__ import annotations

# pylint: disable=protected-access,import-outside-toplevel,too-few-public-methods
# pylint: disable=missing-function-docstring,missing-class-docstring,import-error
# pylint: disable=wrong-import-position
import contextlib
import os
import sys
import time
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from broker import daemon, recipes, vault  # noqa: E402

ORIGIN = "https://login.example"
FIXTURE_PASSWORD = "fixture-not-a-secret"
E2E = pytest.mark.skipif(
    os.environ.get("LOGIN_BROKER_E2E") != "1", reason="set LOGIN_BROKER_E2E=1"
)


# ---------------------------------------------------------------------------
# A. where an unexpected exception happened (pure)
# ---------------------------------------------------------------------------


class _ExplodingField:
    def press(self, _key: str) -> None:
        raise RuntimeError("page text that must not be reported")


def _raised(fn: Any) -> BaseException:
    try:
        fn()
    except Exception as exc:  # pylint: disable=broad-exception-caught
        return exc
    raise AssertionError("did not raise")


def test_exception_site_names_the_innermost_broker_frame():
    page = SimpleNamespace(url=ORIGIN + "/")
    exc = _raised(
        lambda: recipes._submit_identifier(page, _ExplodingField(), [ORIGIN], dev=False)
    )
    site = daemon.exception_site(exc)
    assert site.startswith("RuntimeError in _submit_identifier (recipes.py:")
    assert "page text" not in site


def test_exception_site_outside_the_broker_and_without_traceback():
    def local_step() -> None:
        raise ValueError("x")

    assert daemon.exception_site(_raised(local_step)).startswith(
        "ValueError in local_step (test_passkey_and_recipe_errors.py:"
    )
    assert daemon.exception_site(KeyError("k")) == "KeyError"


# ---------------------------------------------------------------------------
# B. the daemon turns a non-recipe exception into a recorded LoginFailed
# ---------------------------------------------------------------------------


class PlaywrightTimeout(Exception):
    """Stands in for playwright's TimeoutError."""


def test_unexpected_recipe_exception_is_a_recorded_login_failure(tmp_path, monkeypatch):
    runner = daemon.PlaywrightRunner(tmp_path, dev=False)
    recorded: list[str] = []

    def recipe(_page, _item, _secret, *, dev, attempt):
        del dev, attempt
        raise PlaywrightTimeout("ElementHandle.click: Timeout 30000ms exceeded")

    monkeypatch.setattr(runner, "_profile_proof", lambda _page, _item: recipes.INVALID)
    monkeypatch.setattr(
        runner, "_record_failure", lambda _p, item, _s: recorded.append(item.site)
    )
    monkeypatch.setattr(daemon, "recipe_for", lambda _site: recipe)
    ctx = SimpleNamespace(pages=[object()])
    item: Any = SimpleNamespace(site="zoho-desk", fresh_login=False)
    secret = vault.Secret(username="a@b.ch", password=FIXTURE_PASSWORD)
    with pytest.raises(recipes.LoginFailed) as err:
        runner.run_in_context(ctx, item, lambda: secret)
    assert err.value.submitted  # unknown -> the limiter never retries it
    assert err.value.detail.startswith(
        "unexpected error in the login recipe: PlaywrightTimeout in recipe ("
    )
    assert "30000ms" not in err.value.detail
    assert recorded == ["zoho-desk"]


def test_recipe_errors_pass_through_unchanged(tmp_path, monkeypatch):
    runner = daemon.PlaywrightRunner(tmp_path, dev=False)

    def recipe(_page, _item, _secret, *, dev, attempt):
        del dev, attempt
        raise recipes.NeedsHuman("captcha")

    monkeypatch.setattr(runner, "_profile_proof", lambda _page, _item: recipes.INVALID)
    monkeypatch.setattr(runner, "_record_failure", lambda *_a: None)
    monkeypatch.setattr(daemon, "recipe_for", lambda _site: recipe)
    secret = vault.Secret(username="a@b.ch", password=FIXTURE_PASSWORD)
    with pytest.raises(recipes.NeedsHuman):
        item: Any = SimpleNamespace(site="x", fresh_login=False)
        runner.run_in_context(SimpleNamespace(pages=[object()]), item, lambda: secret)


# ---------------------------------------------------------------------------
# C. every broker context refuses passkey prompts
# ---------------------------------------------------------------------------


class _Ctx:
    def __init__(self) -> None:
        self.scripts: list[str] = []

    def add_init_script(self, script: str) -> None:
        self.scripts.append(script)


class _Chromium:
    def __init__(self, fail_channel: bool) -> None:
        self.fail_channel = fail_channel
        self.ctx = _Ctx()

    def launch_persistent_context(self, **kwargs: Any) -> _Ctx:
        if self.fail_channel and "channel" in kwargs:
            raise RuntimeError("no chromium channel")
        return self.ctx


@pytest.mark.parametrize("fail_channel", [False, True])
def test_launch_installs_the_passkey_guard(tmp_path, monkeypatch, fail_channel):
    monkeypatch.setattr(daemon, "broker_user_agent", lambda _pw: "UA")
    pw = SimpleNamespace(chromium=_Chromium(fail_channel))
    runner = daemon.PlaywrightRunner(tmp_path, dev=True)
    ctx = runner._launch(pw, tmp_path / "profile")
    assert ctx.scripts == [recipes.NO_PASSKEY_JS]


# ---------------------------------------------------------------------------
# D. the identifier step's fallback click (fakes)
# ---------------------------------------------------------------------------


class _Button:
    def __init__(self, *, enabled: bool, click_error: bool = False) -> None:
        self.enabled = enabled
        self.click_error = click_error
        self.clicks: list[Any] = []

    def is_enabled(self) -> bool:
        return self.enabled

    def get_attribute(self, _name: str) -> None:
        return None

    def click(self, **kwargs: Any) -> None:
        self.clicks.append(kwargs.get("timeout"))
        if self.click_error:
            raise PlaywrightTimeout("Timeout 5000ms exceeded")


class _UserField:
    def __init__(self, button: _Button) -> None:
        self.button = button

    def press(self, _key: str) -> None:
        pass

    def is_visible(self) -> bool:
        return True

    def evaluate_handle(self, _js: str) -> Any:
        return SimpleNamespace(as_element=lambda: self.button)


@pytest.fixture
def quiet_identifier(monkeypatch):
    monkeypatch.setattr(recipes, "SUBMIT_CHANGE_S", 0.0)
    monkeypatch.setattr(recipes, "_guard", lambda *a, **k: None)
    monkeypatch.setattr(recipes, "_frame_url", lambda _h: ORIGIN + "/")
    monkeypatch.setattr(recipes, "_login_password", lambda _page: None)


_PAGE = SimpleNamespace(url=ORIGIN + "/signin", wait_for_timeout=lambda _ms: None)


@pytest.mark.usefixtures("quiet_identifier")
def test_a_disabled_submit_button_is_not_clicked():
    button = _Button(enabled=False)
    recipes._submit_identifier(_PAGE, _UserField(button), [ORIGIN], dev=False)
    assert not button.clicks


@pytest.mark.usefixtures("quiet_identifier")
def test_the_fallback_click_is_bounded_and_never_raises():
    button = _Button(enabled=True, click_error=True)
    recipes._submit_identifier(_PAGE, _UserField(button), [ORIGIN], dev=False)
    assert button.clicks == [recipes.FALLBACK_CLICK_TIMEOUT_S * 1000]


# ---------------------------------------------------------------------------
# E. the same in a real headless Chromium (routed local HTML only)
# ---------------------------------------------------------------------------


# What the broker's Chromium does on the live Zoho page: a WebAuthn request
# that never settles (no authenticator, no UI). Chromium's own answer offline
# depends on the build and the RP ID (a local fixture origin is often refused
# at once), so the fixture pins the live behaviour; NO_PASSKEY_JS, installed
# after it, sits in front of it like in front of the real one.
_SILENT_AUTHENTICATOR_JS = """(() => {
  const C = window.CredentialsContainer;
  if (!C) return;
  C.prototype.get = C.prototype.create = () => new Promise(() => {});
})();"""


@contextlib.contextmanager
def _routed_page(html: str, *, guard: bool) -> Iterator[Any]:
    """A page on https://login.example/ (a secure context, so WebAuthn exists)
    serving `html`, whose WebAuthn requests never settle; `guard` installs
    ``NO_PASSKEY_JS`` like the broker."""
    from playwright.sync_api import sync_playwright

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        try:
            ctx = browser.new_context(viewport={"width": 1280, "height": 720})
            ctx.add_init_script(_SILENT_AUTHENTICATOR_JS)
            if guard:
                ctx.add_init_script(recipes.NO_PASSKEY_JS)
            ctx.route(
                ORIGIN + "/**",
                lambda route: route.fulfill(body=html, content_type="text/html"),
            )
            page = ctx.new_page()
            page.goto(ORIGIN + "/signin")
            yield page
        finally:
            browser.close()


_REQUEST_JS = """async kind => {
  const publicKey = kind === 'get'
    ? {challenge: new Uint8Array(32), timeout: 600000}
    : {challenge: new Uint8Array(32), rp: {name: 'x'},
       user: {id: new Uint8Array(8), name: 'u', displayName: 'u'},
       pubKeyCredParams: [{type: 'public-key', alg: -7}], timeout: 600000};
  try { await navigator.credentials[kind]({publicKey}); return 'resolved'; }
  catch (e) { return e.name; }
}"""


@pytest.mark.browser
@E2E
@pytest.mark.parametrize("kind", ["get", "create"])
def test_passkey_requests_are_refused_at_once_in_chromium(kind):
    with _routed_page("<html><body></body></html>", guard=True) as page:
        start = time.monotonic()
        assert page.evaluate(_REQUEST_JS, kind) == "NotAllowedError"
        assert time.monotonic() - start < 2.0


# Zoho's sign-in as of 2026-10-08, reduced: one form, the password pre-rendered
# in a zero-height container, "Next" turns into a disabled spinner while the
# lookup runs, then the passkey prompt; only its failure reveals the password.
_ZOHO_HTML = """<html><body>
<form id=login novalidate>
  <input id=login_id name=LOGIN_ID type=text autocomplete="webauthn username email">
  <div id=pwbox style="height:0;overflow:hidden"><div style="height:44px">
    <input id=password name=PASSWORD type=password autocomplete=off></div></div>
  <button id=nextbtn class="btn blue">Next</button>
</form>
<script>
  const form = document.getElementById('login');
  const next = document.getElementById('nextbtn');
  form.addEventListener('submit', ev => {
    ev.preventDefault();
    if (next.textContent === 'Sign in') { document.title = 'signed-in'; return; }
    next.disabled = true;
    next.className = 'btn blue changeloadbtn';
    setTimeout(() => {
      navigator.credentials.get({publicKey: {challenge: new Uint8Array(32),
                                             timeout: 600000}})
        .catch(() => {
          document.getElementById('login_id').style.display = 'none';
          document.getElementById('pwbox').style.height = 'auto';
          next.disabled = false;
          next.className = 'btn blue';
          next.textContent = 'Sign in';
        });
    }, 200);
  });
</script>
</body></html>"""


@pytest.fixture
def fast_steps(monkeypatch):
    monkeypatch.setattr(recipes, "SUBMIT_CHANGE_S", 1.0)
    monkeypatch.setattr(recipes, "STEP_TIMEOUT_S", 4.0)
    monkeypatch.setattr(recipes, "_guard", lambda *a, **k: None)
    monkeypatch.setattr(recipes, "_frame_url", lambda _h: ORIGIN + "/signin")
    monkeypatch.setattr(
        recipes, "_click_on_fill_origin", lambda p, el, a, dev: el.click()
    )


@pytest.mark.browser
@E2E
@pytest.mark.usefixtures("fast_steps")
@pytest.mark.parametrize("guard", [True, False], ids=["guarded", "unguarded"])
def test_passkey_first_identifier_step_in_chromium(guard):
    with _routed_page(_ZOHO_HTML, guard=guard) as page:
        user, pw_field = recipes._wait_login_fields(page, 2.0)
        assert pw_field is None and user is not None  # the decoy is concealed
        user.fill("user@example.org")
        recipes._submit_identifier(page, user, [ORIGIN], dev=False)
        pw_field = recipes._password_after_identifier(page, [ORIGIN], dev=False)
        if guard:
            assert pw_field is not None
            assert pw_field.get_attribute("id") == "password"
        else:  # the live failure: "Next" spins, no password field ever
            assert pw_field is None
            assert page.eval_on_selector("#nextbtn", "b => b.disabled")


# "Next" stays a disabled spinner for good (the unguarded Zoho page).
_SPINNER_HTML = """<html><body>
<form id=login novalidate>
  <input id=login_id name=LOGIN_ID type=text>
  <button id=nextbtn>Next</button>
</form>
<script>
  document.getElementById('login').addEventListener('submit', ev => {
    ev.preventDefault();
    document.getElementById('nextbtn').disabled = true;
  });
</script>
</body></html>"""


@pytest.mark.browser
@E2E
@pytest.mark.usefixtures("fast_steps")
def test_a_spinning_submit_button_neither_hangs_nor_raises_in_chromium():
    with _routed_page(_SPINNER_HTML, guard=False) as page:
        user = page.query_selector("#login_id")
        user.fill("user@example.org")
        start = time.monotonic()
        recipes._submit_identifier(page, user, [ORIGIN], dev=False)
        assert time.monotonic() - start < 3.0
        assert recipes._password_after_identifier(page, [ORIGIN], dev=False) is None
