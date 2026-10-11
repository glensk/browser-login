"""Invisible reCAPTCHA is no challenge; a challenge a human must answer is.

Live evidence (2026-10-08..10, MyFRITZ, sso.myfritz.net = Keycloak): between
password and OTP the site shows an intermediate page (form
``#kc-recaptcha-form``, its theme's ``recaptcha-page.js``) whose INVISIBLE
reCAPTCHA calls ``grecaptcha.execute()`` on load and submits the form itself
after 2-4 s. The broker's settle loop looked for a challenge every 500 ms
before the OTP field, and any shown iframe with "recaptcha" in its URL was a
captcha: a false ``needs_human`` on every login but one (which won the race).
The failure screenshot, taken after the error, showed the NEXT page.

Now (``page_state.challenge_detail`` / ``recipes.ChallengeWatch``): an
invisible anchor (``size=invisible``, the ``.grecaptcha-badge``) is passive;
a checkbox, a shown challenge popup (``bframe``), hCaptcha/Turnstile widgets
and a "Just a moment" interstitial count; after the submit a challenge must
stay ``CHALLENGE_GRACE_S`` on one document (every navigation starts over)
before it is ``needs_human``; nothing is ever clicked; where it was seen is
snapshotted at detection time.

The fixture pages run in a disposable headless Chromium (never browser.py's
shared one); skipped when Playwright's Chromium is missing. Every credential
is generated at run time.
"""

from __future__ import annotations

# pylint: disable=missing-function-docstring,missing-class-docstring
# pylint: disable=import-error,wrong-import-position,protected-access
# pylint: disable=too-few-public-methods,invalid-name,too-many-instance-attributes
import base64
import contextlib
import http.server
import os
import secrets
import sys
import threading
import time
import urllib.parse
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from broker import daemon, page_state, recipes, vault  # noqa: E402

ANCHOR_INVISIBLE = (
    "/recaptcha/api2/anchor?ar=1&k=fixturekey&co=x&hl=de&v=x&size=invisible&cb=x"
)
ANCHOR_CHECKBOX = "/recaptcha/api2/anchor?ar=1&k=fixturekey&co=x&hl=de&v=x&size=normal"
BFRAME = "/recaptcha/api2/bframe?hl=de&v=x&k=fixturekey"

# Provider DOM shapes, taken from the providers' own scripts on 2026-10-11:
# - reCAPTCHA (www.gstatic.com/recaptcha/releases/nY0xPItgwtlvjEjk2TqdwOQz/
#   recaptcha__en.js): the invisible widget is 256x60 in a
#   ``div.grecaptcha-badge``; the challenge popup's container is parked with
#   ``top: -10000px`` and a ``visibility 0s linear 0.3s, opacity 0.3s linear``
#   transition until a challenge is shown. MyFRITZ's own recaptcha-loaded.js
#   waits for ``iframe[src^='https://www.google.com/recaptcha/api2/bframe']``.
# - hCaptcha (js.hcaptcha.com/1/api.js): ``hcaptcha.html#frame=checkbox-
#   invisible`` (invisible), ``#frame=checkbox&id=..&host=..`` (checkbox),
#   ``#frame=challenge&id=..&host=..`` (challenge popup).
# - Turnstile (challenges.cloudflare.com/turnstile/v0/api.js): the token goes
#   into a hidden ``input[name=cf-turnstile-response]``.
_BADGE = (
    "<div class=grecaptcha-badge data-style=bottomright style='width:256px;"
    "height:60px;position:fixed;bottom:14px;right:-186px'>"
    "<div class=grecaptcha-logo><iframe title=reCAPTCHA width=256 height=60"
    f" src='{ANCHOR_INVISIBLE}'></iframe></div></div>"
)
_CHALLENGE_POPUP = (
    "<div id=popup style='visibility: hidden; position: absolute; width: 100%;"
    " top: -10000px; left: 0px; right: 0px; transition: visibility 0s linear"
    " 0.3s, opacity 0.3s linear; opacity: 0;'><iframe title='recaptcha"
    f" challenge expires in two minutes' width=400 height=580 src='{BFRAME}'>"
    "</iframe></div>"
)
# Challenge documents (interstitial pages, widget frames) report any click;
# the login and OTP pages do not (the broker clicks their submit buttons).
_CLICK_SPY = (
    "<script>addEventListener('click', () =>"
    " fetch('/clicked', {method: 'POST'}), true);</script>"
)
# recaptcha-page.js of sso.myfritz.net, reduced: the invisible widget runs and
# the form submits itself ("auto"), or Google decides to show its challenge
# popup and the page waits for a human ("escalate").
_INTERSTITIAL_JS = {
    "auto": "setTimeout(() => document.getElementById('kc-recaptcha-form')"
    ".submit(), 3000);",
    "escalate": "setTimeout(() => { const p = document.getElementById('popup');"
    " p.style.visibility = 'visible'; p.style.top = '10px';"
    " p.style.opacity = '1'; }, 1000);",
}


class _App(http.server.BaseHTTPRequestHandler):
    """Keycloak-like login: password page → (interstitial) → OTP → /home.

    Class attributes are set per test by ``_serve``."""

    username = ""
    password = ""
    seed = ""
    interstitial = "auto"  # auto | escalate | none | cloudflare
    badge_everywhere = False
    title_name = ""  # the captcha page's title greets the user (redaction)
    home_widget = False  # a checkbox reCAPTCHA on the logged-in page too
    clicks: list[str] = []
    visits: list[str] = []
    otp_posts: list[bool] = []

    def log_message(self, *args: Any) -> None:
        return

    def _send(
        self, code: int, body: str = "", headers: tuple[tuple[str, str], ...] = ()
    ) -> None:
        self.send_response(code)
        for key, value in headers:
            self.send_header(key, value)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(body.encode())

    def _page(self, title: str, body: str, *, spy: bool = False) -> None:
        badge = _BADGE if type(self).badge_everywhere else ""
        self._send(
            200,
            f"<!doctype html><html><head><title>{title}</title></head><body>"
            f"{body}{badge}{_CLICK_SPY if spy else ''}</body></html>",
        )

    def _form(self) -> dict[str, list[str]]:
        size = int(self.headers.get("Content-Length") or 0)
        return urllib.parse.parse_qs(self.rfile.read(size).decode())

    def do_GET(self) -> None:  # noqa: N802
        cls = type(self)
        path = urllib.parse.urlsplit(self.path).path
        cls.visits.append(path)
        if path.startswith("/recaptcha/"):
            self._send(
                200,
                "<html><body><div style='width:300px;height:70px'>widget</div>"
                + _CLICK_SPY
                + "</body></html>",
            )
        elif path == "/login":
            self._page(
                "Sign in",
                "<form method=post action=/login>"
                "<input name=username autocomplete=username>"
                "<input type=password name=password>"
                "<button type=submit>Sign in</button></form>",
            )
        elif path == "/captcha":
            js = _INTERSTITIAL_JS[cls.interstitial]
            self._page(
                f"Welcome {cls.title_name}" if cls.title_name else "Sign in",
                "<form id=kc-recaptcha-form method=post action=/captcha>"
                "<input type=hidden name=step value=captcha></form>"
                + _BADGE
                + _CHALLENGE_POPUP
                + f"<script>{js}</script>",
                spy=True,
            )
        elif path == "/moment":
            self._page("Just a moment...", "<p>Checking your browser</p>", spy=True)
        elif path == "/otp":
            self._page(
                "One-time code",
                "<form method=post action=/otp>"
                "<input id=otp name=otp autocomplete=one-time-code>"
                "<button type=submit>Verify</button></form>",
            )
        elif path == "/home":
            if "session=1" in (self.headers.get("Cookie") or ""):
                widget = (
                    f"<iframe width=304 height=78 src='{ANCHOR_CHECKBOX}'></iframe>"
                    if cls.home_widget
                    else ""
                )
                self._page("Devices", f"<h1 id=welcome>Devices</h1>{widget}")
            else:
                self._send(302, headers=(("Location", "/login"),))
        else:
            self._send(404, "nope")

    def do_POST(self) -> None:  # noqa: N802
        import pyotp  # pylint: disable=import-outside-toplevel

        cls = type(self)
        path = urllib.parse.urlsplit(self.path).path
        form = self._form()
        if path == "/clicked":
            cls.clicks.append(path)
            self._send(204)
        elif path == "/login":
            ok = form.get("username") == [cls.username] and form.get("password") == [
                cls.password
            ]
            nxt = {
                "auto": "/captcha?session_code=x",
                "escalate": "/captcha?session_code=x",
                "none": "/otp",
                "cloudflare": "/moment",
            }[cls.interstitial]
            self._send(302, headers=(("Location", nxt if ok else "/login"),))
        elif path == "/captcha":
            self._send(302, headers=(("Location", "/otp"),))
        elif path == "/otp":
            ok = pyotp.TOTP(cls.seed).verify(
                (form.get("otp") or [""])[0], valid_window=1
            )
            cls.otp_posts.append(ok)
            headers = (("Location", "/home" if ok else "/otp"),)
            if ok:
                headers += (("Set-Cookie", "session=1; Path=/"),)
            self._send(302, headers=headers)
        else:
            self._send(404, "nope")


def _chromium_installed() -> bool:
    try:
        from playwright.sync_api import (  # pylint: disable=import-outside-toplevel
            sync_playwright,
        )

        with sync_playwright() as pw:
            return Path(pw.chromium.executable_path).exists()
    except Exception:  # pylint: disable=broad-exception-caught
        return False


CHROME = pytest.mark.skipif(
    not _chromium_installed(), reason="Playwright Chromium missing"
)


def _secret() -> vault.Secret:
    """Fake credentials, generated at run time."""
    return vault.Secret(
        username="user-" + secrets.token_hex(4),
        password=secrets.token_urlsafe(18),
        totp_seed=base64.b32encode(os.urandom(20)).decode(),
    )


@contextlib.contextmanager
def _serve(secret: vault.Secret, **config: Any) -> Iterator[tuple[str, Any]]:
    """(origin, handler class) of a fresh fixture server; the class records
    clicks, visits and OTP posts."""
    handler: Any = type("App", (_App,), {})
    handler.username = secret.username
    handler.password = secret.password
    handler.seed = secret.totp_seed or ""
    handler.clicks, handler.visits, handler.otp_posts = [], [], []
    for key, value in config.items():
        setattr(handler, key, value)
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{srv.server_port}", handler
    finally:
        srv.shutdown()
        srv.server_close()


@contextlib.contextmanager
def _page() -> Iterator[Any]:
    from playwright.sync_api import (  # pylint: disable=import-outside-toplevel
        sync_playwright,
    )

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        try:
            yield browser.new_page()
        finally:
            browser.close()


def _item(origin: str, login_path: str = "/login") -> vault.SiteItem:
    fields = {
        "agent_site": "captchafix",
        "agent_fill_origins": origin,
        "agent_login_url": origin + login_path,
        "agent_check_url": origin + "/home",
        "agent_logged_in_selector": "#welcome",
    }
    item = vault.site_item_from_json(
        {
            "name": "captcha fixture",
            "fields": [{"name": k, "value": v} for k, v in fields.items()],
        },
        dev=True,  # the fixture serves http on 127.0.0.1
    )
    assert not item.refused, item.refused
    return item


# ---------------------------------------------------------------------------
# A. classification by frame URL (no browser)
# ---------------------------------------------------------------------------

G = "https://www.google.com"
H = "https://newassets.hcaptcha.com/captcha/v1/abc/static/hcaptcha.html"


@pytest.mark.parametrize(
    ("url", "kind"),
    [
        (G + ANCHOR_INVISIBLE, "recaptcha-invisible"),
        ("https://www.recaptcha.net" + ANCHOR_INVISIBLE, "recaptcha-invisible"),
        (G + "/recaptcha/enterprise/anchor?k=x&size=invisible", "recaptcha-invisible"),
        (G + ANCHOR_CHECKBOX, "recaptcha-checkbox"),
        (G + "/recaptcha/api2/anchor?k=x", "recaptcha-checkbox"),
        (G + BFRAME, "recaptcha-challenge"),
        (G + "/recaptcha/api2/aframe", "recaptcha-helper"),
        (H + "#frame=checkbox-invisible", "hcaptcha-invisible"),  # api.js verbatim
        (H + "#frame=checkbox-invisible&id=x", "hcaptcha-invisible"),
        (H + "#frame=checkbox&size=invisible", "hcaptcha-invisible"),
        (H + "#frame=checkbox&id=x", "hcaptcha-checkbox"),
        (H + "#frame=challenge&id=x", "hcaptcha-challenge"),
        (H + "#frame=something-new", "captcha-other"),
        (
            "https://challenges.cloudflare.com/cdn-cgi/challenge-platform/h/b/"
            "turnstile/if/ov2/av0/rcv0/0/x/light/normal",
            "turnstile",
        ),
        (G + "/recaptcha/api2/fallback?k=x", "captcha-other"),
        ("https://sso.example.net/realms/r/login-actions/authenticate", None),
        ("", None),
    ],
)
def test_challenge_kind(url: str, kind: str | None) -> None:
    assert page_state.challenge_kind(url) == kind
    if kind is not None:
        passive = kind in page_state.PASSIVE_CHALLENGE_KINDS
        assert passive == kind.endswith(("-invisible", "-helper"))


class _FakePage:
    """Answers challenge_detail / challenge_snapshot / _document_key."""

    def __init__(self) -> None:
        self.url = "https://sso.example.net/realms/r/login-actions/authenticate?x=1"
        self.srcs: list[str] = []
        self.doc = 1.0
        self.body = ""
        self.broken = False  # frames cannot be inspected (mid-navigation)
        self.turnstile_token = False
        self.waits: list[float] = []
        self.on_wait: Any = None

    @property
    def frames(self) -> list[Any]:
        if self.broken:
            raise RuntimeError("Execution context was destroyed")
        return []

    def title(self) -> str:
        return "Sign in"

    def eval_on_selector_all(self, _sel: str, _js: str) -> list[str]:
        return list(self.srcs)

    def evaluate(self, js: str) -> Any:
        if "timeOrigin" in js:
            return self.doc
        if "cf-turnstile-response" in js:
            return self.turnstile_token
        return self.body

    def wait_for_timeout(self, ms: float) -> None:
        self.waits.append(ms)
        if self.on_wait:
            self.on_wait(self)


TURNSTILE = (
    "https://challenges.cloudflare.com/cdn-cgi/challenge-platform/h/b/"
    "turnstile/if/ov2/av0/rcv0/0/x/light/normal"
)


class _Clock:
    def __init__(self) -> None:
        self.now = 100.0

    def __call__(self) -> float:
        return self.now


def test_watch_grace_and_reset_on_navigation() -> None:
    page, clock = _FakePage(), _Clock()
    watch = recipes.ChallengeWatch(grace_s=8.0, clock=clock)
    page.srcs = [G + ANCHOR_INVISIBLE]  # passive: never pending
    watch.check(page)
    assert not watch.pending
    page.srcs = [G + ANCHOR_INVISIBLE, G + BFRAME]  # the popup shows
    watch.check(page)
    assert watch.pending
    clock.now += 7.9
    watch.check(page)  # still inside the grace
    page.doc = 2.0  # a navigation (same URL, new document): starts over
    clock.now += 0.2
    watch.check(page)
    clock.now += 7.9
    watch.check(page)
    page.srcs = []  # gone: starts over too
    watch.check(page)
    assert not watch.pending
    watch.final(page)  # nothing showing now: no error
    page.srcs = [G + BFRAME]
    watch.check(page)
    clock.now += 8.0
    with pytest.raises(recipes.NeedsHuman) as err:
        watch.check(page)
    assert err.value.submitted
    assert err.value.challenge == {
        "url": "https://sso.example.net/realms/r/login-actions/authenticate",
        "frame": "recaptcha-challenge",
        "title": "Sign in",
    }
    assert "?" not in err.value.detail and "recaptcha-challenge" in err.value.detail


def test_watch_block_page_needs_no_grace() -> None:
    page = _FakePage()
    page.body = "Zu viele Anmeldeversuche"
    with pytest.raises(recipes.NeedsHuman) as err:
        recipes.ChallengeWatch(grace_s=60.0).check(page)
    assert "blocked" in err.value.detail


def test_watch_final_looks_again_at_the_deadline() -> None:
    page = _FakePage()
    page.srcs = [G + ANCHOR_CHECKBOX]
    watch = recipes.ChallengeWatch(grace_s=60.0)
    watch.check(page)
    page.srcs = []  # gone by the deadline: the cached sighting does not count
    watch.final(page)
    page.srcs = [G + ANCHOR_CHECKBOX]
    watch = recipes.ChallengeWatch(grace_s=60.0)
    watch.check(page)
    with pytest.raises(recipes.NeedsHuman) as err:
        watch.final(page)  # still up: needs a human, whatever is left of the grace
    assert err.value.challenge and err.value.challenge["frame"] == "recaptcha-checkbox"


def test_watch_uninspectable_page_is_pending_but_never_a_challenge() -> None:
    page, clock = _FakePage(), _Clock()
    watch = recipes.ChallengeWatch(grace_s=8.0, clock=clock)
    page.srcs = [G + BFRAME]
    watch.check(page)
    page.broken = True  # mid-navigation: nothing is acted on, nothing reset
    clock.now += 5.0
    watch.check(page)
    assert watch.pending
    page.broken = False
    clock.now += 3.0
    with pytest.raises(recipes.NeedsHuman):  # the grace kept running
        watch.check(page)
    fresh = recipes.ChallengeWatch(grace_s=0.0)
    page.broken = True
    fresh.check(page)  # unknown alone never raises
    fresh.final(page)
    assert fresh.pending
    assert page_state.challenge_reason(page) is None


def test_a_solved_turnstile_is_no_challenge() -> None:
    page = _FakePage()
    page.srcs = [TURNSTILE]
    assert page_state.challenge_detail(page) == {
        "reason": "captcha",
        "kind": "turnstile",
    }
    page.turnstile_token = True
    assert page_state.challenge_detail(page) is None


def test_pre_submit_processing_challenge_gets_a_bounded_wait(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(recipes, "CHALLENGE_GRACE_S", 0.3)
    page = _FakePage()
    page.srcs = [TURNSTILE]

    def solve(p: _FakePage) -> None:
        if len(p.waits) >= 2:
            p.turnstile_token = True

    page.on_wait = solve
    recipes._check_challenge(page, submitted=False)  # passed by itself: no error
    assert len(page.waits) == 2
    page.turnstile_token, page.on_wait = False, None
    with pytest.raises(recipes.NeedsHuman) as err:
        recipes._check_challenge(page, submitted=False)
    assert not err.value.submitted and "turnstile" in err.value.detail
    page.srcs, page.waits = [G + ANCHOR_CHECKBOX], []
    with pytest.raises(recipes.NeedsHuman):  # a confirmed one: at once
        recipes._check_challenge(page, submitted=False)
    assert not page.waits
    page.srcs, page.broken = [], True

    def recover(p: _FakePage) -> None:
        p.broken = False  # inspectable again, nothing showing

    page.on_wait = recover
    recipes._check_challenge(page, submitted=False)  # definite "none": go on
    assert len(page.waits) == 1
    page.broken, page.on_wait = True, None
    with pytest.raises(recipes.LoginFailed) as failed:  # never a definite answer
        recipes._check_challenge(page, submitted=False)
    assert not failed.value.submitted
    assert not isinstance(failed.value, recipes.NeedsHuman)


def test_watch_another_kind_on_the_same_document_starts_over() -> None:
    page, clock = _FakePage(), _Clock()
    watch = recipes.ChallengeWatch(grace_s=8.0, clock=clock)
    page.srcs = [TURNSTILE]
    watch.check(page)
    clock.now += 7.0
    page.srcs = [G + BFRAME]  # Turnstile gone, a reCAPTCHA popup instead
    watch.check(page)
    assert watch.snapshot and watch.snapshot["frame"] == "recaptcha-challenge"
    clock.now += 7.0
    watch.check(page)  # 7 s of THIS one: still inside its grace
    clock.now += 1.0
    with pytest.raises(recipes.NeedsHuman) as err:
        watch.check(page)
    assert err.value.challenge and err.value.challenge["frame"] == "recaptcha-challenge"


def test_otp_fill_holds_when_a_challenge_came_up_during_the_code_wait(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``fresh_totp`` may wait up to ~5 s for the next step; a challenge that
    shows meanwhile stops the fill before anything is selected or typed."""
    monkeypatch.setattr(recipes, "fresh_totp", lambda _seed: "0" * 6)
    page = _FakePage()
    page.srcs = [G + ANCHOR_CHECKBOX]
    held = recipes._fill_otp(
        page, None, _secret(), [], dev=True, watch=recipes.ChallengeWatch()
    )
    assert held is False  # the fake page has no field: a fill would raise


# ---------------------------------------------------------------------------
# B. real headless Chromium against the fixture site
# ---------------------------------------------------------------------------


@pytest.mark.launches_chrome
@CHROME
def test_persistent_invisible_badge_is_no_challenge() -> None:
    secret = _secret()
    with _serve(secret, interstitial="none", badge_everywhere=True) as (
        origin,
        handler,
    ):
        with _page() as page:
            page.goto(origin + "/otp")
            assert page.locator(".grecaptcha-badge iframe").is_visible()
            assert page_state.challenge_detail(page) is None
            assert page_state.challenge_reason(page) is None
            recipes.generic_login(page, _item(origin), secret, dev=True)
            assert page.url == origin + "/home"
    assert handler.otp_posts == [True] and not handler.clicks


@pytest.mark.launches_chrome
@CHROME
def test_auto_submitting_invisible_recaptcha_reaches_the_otp_step() -> None:
    secret = _secret()
    with _serve(secret, interstitial="auto") as (origin, handler), _page() as page:
        recipes.generic_login(page, _item(origin), secret, dev=True)
        assert page.url == origin + "/home"
    assert "/captcha" in handler.visits  # the interstitial really ran
    assert handler.otp_posts == [True]
    assert not handler.clicks


@pytest.mark.launches_chrome
@CHROME
def test_invisible_recaptcha_escalating_to_a_challenge_needs_a_human(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(recipes, "CHALLENGE_GRACE_S", 3.0)
    secret = _secret()
    with _serve(secret, interstitial="escalate") as (origin, handler), _page() as page:
        start = time.monotonic()
        with pytest.raises(recipes.NeedsHuman) as err:
            recipes.generic_login(page, _item(origin), secret, dev=True)
        elapsed = time.monotonic() - start
    # popup at ~1 s after the interstitial loads, then the full grace
    assert elapsed >= 3.0 + 1.0
    assert err.value.submitted
    assert err.value.challenge == {
        "url": origin + "/captcha",
        "frame": "recaptcha-challenge",
        "title": "Sign in",
    }
    assert f"recaptcha-challenge on {origin}/captcha)" in err.value.detail
    assert not handler.clicks and not handler.otp_posts


@pytest.mark.launches_chrome
@CHROME
def test_failure_report_names_the_page_the_challenge_was_seen_on(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The page moves on before the failure report runs (MyFRITZ: the
    screenshot showed the OTP page): ``challenge_at_detection`` still names
    the interstitial; the username in its title is masked."""
    monkeypatch.setattr(recipes, "CHALLENGE_GRACE_S", 2.0)
    secret = _secret()
    with (
        _serve(secret, interstitial="escalate", title_name=secret.username) as (
            origin,
            _handler,
        ),
        _page() as page,
    ):
        item = _item(origin)
        with pytest.raises(recipes.NeedsHuman) as err:
            recipes.generic_login(page, item, secret, dev=True)
        page.goto(origin + "/otp")  # the page went on by itself
        runner = daemon.PlaywrightRunner(tmp_path, dev=True, diag_dir=tmp_path)
        runner._record_failure(page, item, secret)
        runner._note_challenge(item, err.value, secret)
    diag = runner.last_diag["captchafix"]
    assert diag["url"] == origin + "/otp"
    assert diag["challenge_at_detection"] == {
        "url": origin + "/captcha",
        "frame": "recaptcha-challenge",
        "title": "Welcome ***",
    }
    assert secret.username not in str(diag) and secret.password not in str(diag)


@pytest.mark.launches_chrome
@CHROME
def test_cloudflare_interstitial_still_needs_a_human(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(recipes, "CHALLENGE_GRACE_S", 2.0)
    secret = _secret()
    with (
        _serve(secret, interstitial="cloudflare") as (origin, handler),
        _page() as page,
    ):
        # on the login page: after the bounded wait, nothing typed
        with pytest.raises(recipes.NeedsHuman) as err:
            recipes.generic_login(page, _item(origin, "/moment"), secret, dev=True)
        assert not err.value.submitted
        assert err.value.challenge and err.value.challenge["frame"] == "interstitial"
        # after the password: once it stayed the grace
        with pytest.raises(recipes.NeedsHuman) as err:
            recipes.generic_login(page, _item(origin), secret, dev=True)
        assert err.value.submitted
        assert err.value.challenge == {
            "url": origin + "/moment",
            "frame": "interstitial",
            "title": "Just a moment...",
        }
        assert not handler.clicks


@pytest.mark.launches_chrome
@CHROME
@pytest.mark.parametrize(
    "style",
    [
        "visibility:visible;position:absolute;top:-10000px;left:0",  # off screen
        "visibility:visible;position:absolute;top:10px;left:0;opacity:0",  # clear
    ],
)
def test_a_parked_challenge_popup_is_not_shown(style: str) -> None:
    """Google parks the bframe off screen / transparent; Playwright's
    is_visible calls both visible. Shown = on screen and not transparent."""
    secret = _secret()
    with _serve(secret) as (origin, _handler), _page() as page:
        page.goto(origin + "/otp")
        page.evaluate(
            """([style, src]) => {
              const d = document.createElement('div');
              d.setAttribute('style', style);
              d.innerHTML = '<iframe width=400 height=580 src="' + src + '"></iframe>';
              document.body.appendChild(d);
            }""",
            [style, origin + BFRAME],
        )
        page.wait_for_load_state("load")
        assert page.locator("iframe").is_visible()  # Playwright alone: shown
        assert page_state.challenge_detail(page) is None
        page.evaluate(
            "() => { const d = document.querySelector('iframe').parentElement;"
            " d.style.top = '10px'; d.style.opacity = '1'; }"
        )
        assert page_state.challenge_detail(page) == {
            "reason": "captcha",
            "kind": "recaptcha-challenge",
        }


@pytest.mark.launches_chrome
@CHROME
def test_a_widget_on_the_logged_in_page_does_not_hold_up_the_login(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The sentinel is looked at before any challenge escalation: a checkbox
    reCAPTCHA (a contact form, say) next to it never turns a login into
    ``needs_human``; the positive proof decides afterwards."""
    monkeypatch.setattr(recipes, "CHALLENGE_GRACE_S", 1.0)
    secret = _secret()
    with (
        _serve(secret, interstitial="none", home_widget=True) as (origin, handler),
        _page() as page,
    ):
        recipes.generic_login(page, _item(origin), secret, dev=True)
        assert page.url == origin + "/home"
        assert page_state.challenge_detail(page) == {
            "reason": "captcha",
            "kind": "recaptcha-checkbox",
        }
    assert handler.otp_posts == [True] and not handler.clicks


# Runtime DOM of the providers' public demo pages, captured 2026-10-11 in a
# throwaway headless Chromium (anonymous; nothing clicked or submitted):
# google.com/recaptcha/api2/demo?invisible=true, google.com/recaptcha/api2/demo,
# accounts.hcaptcha.com/demo. Query/fragment values are replaced by "x" except
# the ones that classify (size, frame); container styles are verbatim.
_GOOGLE = "https://www.google.com/recaptcha/api2/"
_HC = (
    "https://newassets.hcaptcha.com/captcha/v1/"
    "e97a50d7ecb685043e82c9d7a6034c5c544521c1/static/hcaptcha.html"
)
_HC_TAIL = (
    "&id=x&host=x&sentry=x&reportapi=x&recaptchacompat=x&custom=x&hl=x&tplinks=x"
    "&andint=x&pstissuer=x&sitekey=x&theme=x&origin=x&clientOptions=x"
)
_ANCHOR_Q = "ar=x&k=x&co=x&hl=x&v=x&size={size}&sa=x&anchor-ms=x&execute-ms=x&cb=x"
_BFRAME_SRC = _GOOGLE + "bframe?hl=x&v=x&k=x&bft=x&ca=x"
CAPTURED = {
    "recaptcha-v2-invisible": (
        "<div style='width: 256px; height: 60px; display: block; transition: right"
        " 0.3s; position: fixed; bottom: 14px; right: -186px; box-shadow: gray 0px"
        " 0px 5px; border-radius: 2px; overflow: hidden;' class=grecaptcha-badge>"
        "<div class=grecaptcha-logo><iframe width=256 height=60 src='"
        + _GOOGLE
        + "anchor?"
        + _ANCHOR_Q.format(size="invisible")
        + "'></iframe></div></div>"
        "<div style='visibility: hidden; position: absolute; width: 100%; top:"
        " -10000px; left: 0px; right: 0px; transition: visibility linear 0.3s,"
        " opacity 0.3s linear; opacity: 0;'><div><iframe width=1278 height=150"
        f" src='{_BFRAME_SRC}'></iframe></div></div>",
        None,
    ),
    "recaptcha-v2-checkbox": (
        "<div style='width: 304px; height: 78px;'><div><iframe width=304 height=78"
        " src='" + _GOOGLE + "anchor?" + _ANCHOR_Q.format(size="normal") + "'>"
        "</iframe></div></div>"
        "<div style='background-color: rgb(255, 255, 255); border: 1px solid"
        " rgb(204, 204, 204); box-shadow: rgba(0, 0, 0, 0.2) 2px 2px 3px; position:"
        " absolute; transition: visibility linear 0.3s, opacity 0.3s linear;"
        " opacity: 0; visibility: hidden; z-index: 2000000000; left: 0px; top:"
        " -10000px;'><div><iframe width=300 height=150"
        f" src='{_BFRAME_SRC}'></iframe></div></div>",
        "recaptcha-checkbox",
    ),
    "hcaptcha-checkbox": (
        "<div><iframe width=302 height=76 src='"
        + _HC
        + "#frame=checkbox"
        + _HC_TAIL
        + "'></iframe></div>"
        "<div style='background-color: rgb(255, 255, 255); border: 1px solid"
        " rgb(215, 215, 215); box-shadow: rgba(0, 0, 0, 0.1) 0px 0px 4px;"
        " border-radius: 4px; left: auto; top: -10000px; z-index: -2147483648;"
        " position: absolute; pointer-events: auto; transition: opacity 0.15s"
        " ease-out; opacity: 0; visibility: hidden;'><div><iframe width=300"
        " height=150 src='" + _HC + "#frame=challenge" + _HC_TAIL + "'></iframe>"
        "</div></div>",
        "hcaptcha-checkbox",
    ),
}


@pytest.mark.launches_chrome
@CHROME
@pytest.mark.parametrize("name", sorted(CAPTURED))
def test_captured_provider_dom(name: str) -> None:
    """The captured demo DOM, served offline (Playwright routes the provider
    hosts to a stub; no network): invisible = no challenge, the parked
    popups are not shown, the checkboxes are."""
    body, expected = CAPTURED[name]
    with _page() as page:
        for pattern in (
            "https://www.google.com/**",
            "https://newassets.hcaptcha.com/**",
        ):
            page.route(
                pattern,
                lambda route: route.fulfill(
                    status=200, content_type="text/html", body="<p>widget</p>"
                ),
            )
        page.route(
            "https://captured.example/**",
            lambda route: route.fulfill(
                status=200,
                content_type="text/html",
                body=f"<!doctype html><html><body>{body}</body></html>",
            ),
        )
        page.goto("https://captured.example/")
        page.wait_for_load_state("load")
        detail = page_state.challenge_detail(page)
        assert (detail or {}).get("kind") == expected, detail
