"""Login recipes: where and how the broker types a site's secret.

A recipe decides where a secret is typed, so every fill and every submit is
preceded by ``_guard``: the page's CURRENT origin and the form's effective
action must both be one of the item's ``agent_fill_origins`` (exact scheme +
host + port). A redirect to a look-alike host between two fills is caught
because the check runs again right before each one.

Exceptions carry ``submitted``: whether a secret had already been submitted
when the recipe gave up. The daemon maps a failure after submission to the
limiter's ``unknown`` outcome (never retried automatically).
"""

from __future__ import annotations

import re
import time
import urllib.parse
from collections.abc import Callable
from typing import Any

from broker.origins import form_action_allowed, origin_allowed
from broker.vault import Secret, SiteItem

PASSWORD_SELECTOR = "input[type=password]"
OTP_SELECTOR = "input[autocomplete=one-time-code], input[name*=otp i], #otp"
CHALLENGE_SRC_RE = re.compile(
    r"recaptcha|hcaptcha|turnstile|challenges\.cloudflare", re.IGNORECASE
)
CHALLENGE_TITLES = ("nur einen moment", "just a moment")
STEP_TIMEOUT_S = 20.0
SETTLE_TIMEOUT_S = 30.0

CSCS_AUTH_ORIGIN = "https://auth.cscs.ch"
CSCS_PORTAL_ORIGIN = "https://portal.cscs.ch"
CSCS_LOGIN_URL = CSCS_PORTAL_ORIGIN + "/profile/"

# Effective action of the form around an input: the default submit button's
# `formaction` overrides the form's `action`. `null` = no form.
_FORM_ACTION_JS = """e => {
  const f = e.form;
  if (!f) return {form: false, action: null};
  const b = f.querySelector('button[type=submit], input[type=submit], button:not([type])');
  return {form: true, action: (b && b.getAttribute('formaction')) || f.getAttribute('action')};
}"""

# Username field for a password input: an autocomplete=username input in the
# same form (or document), else the nearest preceding visible text/email input.
_USERNAME_JS = """pw => {
  const scope = pw.form || document;
  const vis = el => !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length);
  const inputs = Array.from(scope.querySelectorAll('input'));
  const tagged = inputs.find(i => (i.getAttribute('autocomplete') || '').split(/\\s+/)
      .includes('username') && vis(i));
  if (tagged) return tagged;
  let best = null;
  for (const i of inputs) {
    if (i === pw) break;
    const t = (i.getAttribute('type') || 'text').toLowerCase();
    if ((t === 'text' || t === 'email') && vis(i)) best = i;
  }
  return best;
}"""


class RecipeError(Exception):
    """A recipe gave up. ``detail`` never contains a secret."""

    code = "login_failed"

    def __init__(self, detail: str, *, submitted: bool = False) -> None:
        super().__init__(detail)
        self.detail = detail
        self.submitted = submitted


class LoginFailed(RecipeError):
    """The login did not reach a logged-in state."""


class OriginViolation(RecipeError):
    """The page or form left the item's fill origins before a fill or submit."""

    code = "origin_violation"


class NeedsHuman(RecipeError):
    """A captcha / bot challenge or a missing second factor."""

    code = "needs_human"


def parse_totp(seed_or_uri: str) -> Any:
    """A usable ``pyotp.TOTP`` from a base32 seed or an ``otpauth://`` URI, or None.

    None for an empty, malformed or non-TOTP seed (``otpauth://hotp/``,
    ``period=0``) — probed by generating one code, so every returned object
    can produce codes.
    """
    import binascii  # pylint: disable=import-outside-toplevel

    import pyotp  # pylint: disable=import-outside-toplevel

    s = seed_or_uri.strip()
    if not s:  # pyotp turns an empty key into a (necessarily wrong) code
        return None
    try:
        if s.lower().startswith("otpauth://"):
            otp = pyotp.parse_uri(s)
        else:
            otp = pyotp.TOTP(s.replace(" ", "").upper())
        if not isinstance(otp, pyotp.TOTP) or otp.interval <= 0:
            return None
        otp.now()
    except (ValueError, ArithmeticError, binascii.Error):
        return None
    return otp


def fresh_totp(
    seed_or_uri: str,
    *,
    clock: Callable[[], float] = time.time,
    sleep: Callable[[float], None] = time.sleep,
) -> str | None:
    """A TOTP code with time left to be used, or None for a bad seed.

    A code in the last ``min(5, interval / 3)`` seconds of its step could expire
    between the fill and the server's check, so then wait for the next step and
    return ITS code. The clock is sampled once per decision.
    """
    otp = parse_totp(seed_or_uri)
    if otp is None:
        return None
    interval = otp.interval
    now = clock()
    remaining = interval - (now % interval)
    if remaining < min(5, interval / 3):
        sleep(remaining + 0.05)
        now = clock()
    return str(otp.at(now))


def challenge_reason(page: Any) -> str | None:
    """``"captcha"`` when a captcha / bot-challenge is on the page, else None."""
    try:
        title = (page.title() or "").strip().lower()
    except Exception:  # pylint: disable=broad-exception-caught
        title = ""
    if any(title.startswith(t) for t in CHALLENGE_TITLES):
        return "captcha"
    try:
        frames = [f.url for f in page.frames]
        srcs = page.eval_on_selector_all(
            "iframe", "els => els.map(e => e.getAttribute('src') || '')"
        )
    except Exception:  # pylint: disable=broad-exception-caught
        return None
    if any(CHALLENGE_SRC_RE.search(str(u or "")) for u in [*frames, *srcs]):
        return "captcha"
    return None


def _guard(page: Any, field_handle: Any, allowed: list[str], *, dev: bool) -> None:
    """Raise OriginViolation unless the top page, the field's OWN frame and the
    form action (resolved against that frame's URL) are all on a fill origin.

    Checking only the top page would let a cross-origin iframe on an allowed
    page receive the secret. A field whose frame cannot be determined, or a
    frame without a real origin (``about:blank``, ``srcdoc``), fails closed.
    """
    if not origin_allowed(page.url, allowed, dev=dev):
        raise OriginViolation("page is not on a fill origin")
    try:
        frame = field_handle.owner_frame()
        frame_url = frame.url if frame is not None else ""
    except Exception:  # pylint: disable=broad-exception-caught
        frame_url = ""
    if not origin_allowed(frame_url, allowed, dev=dev):
        raise OriginViolation("the field's frame is not on a fill origin")
    info = field_handle.evaluate(_FORM_ACTION_JS)
    action = info.get("action") if isinstance(info, dict) else None
    if not form_action_allowed(frame_url, action, allowed, dev=dev):
        raise OriginViolation("form action is not on a fill origin")


def _visible(page: Any, selector: str) -> Any:
    """The first visible element matching `selector`, or None."""
    try:
        for el in page.query_selector_all(selector):
            if el.is_visible():
                return el
    except Exception:  # pylint: disable=broad-exception-caught
        return None
    return None


def _on_login_path(url: str, item: SiteItem) -> bool:
    """True while `url` is the login URL's path on a fill origin."""
    try:
        cur = urllib.parse.urlsplit(url)
        login = urllib.parse.urlsplit(item.login_url)
    except ValueError:
        return True
    # dev=True only widens which URLs are RECOGNISED as the login page (a dev
    # item may list http://127.0.0.1); erring here means "not logged in".
    on_fill = origin_allowed(url, item.fill_origins, dev=True)
    return on_fill and cur.path.rstrip("/") == login.path.rstrip("/")


def logged_in(page: Any, item: SiteItem, *, wait_s: float = 8.0) -> bool:
    """Generic success test: the sentinel is visible, or (no sentinel) the
    password field is gone and the page left the login path."""
    if item.logged_in_selector:
        try:
            page.wait_for_selector(
                item.logged_in_selector, state="visible", timeout=wait_s * 1000
            )
            return True
        except Exception:  # pylint: disable=broad-exception-caught
            return False
    if _visible(page, PASSWORD_SELECTOR) is not None:
        return False
    return not _on_login_path(page.url, item)


def _check_challenge(page: Any, *, submitted: bool) -> None:
    reason = challenge_reason(page)
    if reason:
        raise NeedsHuman(reason, submitted=submitted)


def _wait_visible(page: Any, selector: str, timeout_s: float) -> Any:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        el = _visible(page, selector)
        if el is not None:
            return el
        page.wait_for_timeout(250)
    return None


def _fill_otp(
    page: Any, otp_field: Any, secret: Secret, allowed: list[str], *, dev: bool
) -> None:
    if not secret.totp_seed:
        raise NeedsHuman("otp required but the item has no TOTP seed", submitted=True)
    code = fresh_totp(secret.totp_seed)
    if not code:
        raise LoginFailed("could not produce a TOTP code", submitted=True)
    otp_field = _visible(page, OTP_SELECTOR)  # re-query: the wait may have taken s
    if otp_field is None:
        raise LoginFailed("the OTP field disappeared", submitted=True)
    try:
        _guard(page, otp_field, allowed, dev=dev)
    except OriginViolation as exc:
        exc.submitted = True
        raise
    otp_field.fill(code)
    _guard(page, otp_field, allowed, dev=dev)
    otp_field.press("Enter")


def generic_login(
    page: Any,
    item: SiteItem,
    secret: Secret,
    *,
    dev: bool = False,
    settle_s: float = SETTLE_TIMEOUT_S,
) -> None:
    """Ordinary username/password(/TOTP) form login; returns on success, raises else."""
    allowed = list(item.fill_origins)
    page.goto(item.login_url, wait_until="domcontentloaded")
    _check_challenge(page, submitted=False)
    pw_field = _wait_visible(page, PASSWORD_SELECTOR, STEP_TIMEOUT_S)
    if pw_field is None:
        _check_challenge(page, submitted=False)
        raise LoginFailed("no visible password field on the login page")
    user_handle = pw_field.evaluate_handle(_USERNAME_JS)
    user_field = user_handle.as_element() if user_handle is not None else None
    if user_field is not None and secret.username:
        _guard(page, user_field, allowed, dev=dev)
        user_field.fill(secret.username)
    _guard(page, pw_field, allowed, dev=dev)
    pw_field.fill(secret.password)
    _guard(page, pw_field, allowed, dev=dev)
    pw_field.press("Enter")

    otp_done = False
    deadline = time.monotonic() + settle_s
    while time.monotonic() < deadline:
        page.wait_for_timeout(500)
        _check_challenge(page, submitted=True)
        otp_field = None if otp_done else _visible(page, OTP_SELECTOR)
        if otp_field is not None:
            _fill_otp(page, otp_field, secret, allowed, dev=dev)
            otp_done = True
            continue
        if logged_in(page, item, wait_s=0.5):
            return
    raise LoginFailed("login did not reach a logged-in state", submitted=True)


def cscs_on_portal(url: str) -> bool:
    """Exact-host port of browser.py's ``_on_portal``: the settled portal app."""
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        return False
    if parts.scheme != "https" or (parts.hostname or "") != "portal.cscs.ch":
        return False
    if parts.port not in (None, 443):
        return False
    path_q = parts.path + "?" + parts.query
    return not any(
        m in path_q for m in ("/api-auth/", "/oauth_login_completed/", "code=")
    )


def click_keycloak_submit(page: Any) -> None:
    for sel in (
        "#kc-login",
        "input[name=login]",
        "button[type=submit]",
        "input[type=submit]",
    ):
        el = page.query_selector(sel)
        if el:
            el.click()
            return


def cscs_login(
    page: Any,
    item: SiteItem,
    secret: Secret,
    *,
    dev: bool = False,
    settle_s: float = SETTLE_TIMEOUT_S,
) -> None:
    """CSCS Keycloak login (port of ``browser.py cmd_cscs_login``) with exact hosts.

    Secrets are typed only on ``https://auth.cscs.ch`` (and only if the item
    lists it); success is the settled ``https://portal.cscs.ch`` app.
    """
    allowed = [o for o in item.fill_origins if o == CSCS_AUTH_ORIGIN]
    if dev:
        allowed = list(item.fill_origins)
    if not allowed:
        raise OriginViolation("the cscs item does not list https://auth.cscs.ch")
    page.goto(item.login_url or CSCS_LOGIN_URL, wait_until="domcontentloaded")
    page.wait_for_timeout(1500)
    if cscs_on_portal(page.url):
        return
    _check_challenge(page, submitted=False)
    user = _wait_visible(page, "#username", STEP_TIMEOUT_S)
    pw_field = _visible(page, "#password")
    if user is None or pw_field is None:
        raise LoginFailed("Keycloak login form not found")
    _guard(page, user, allowed, dev=dev)
    user.fill(secret.username)
    _guard(page, pw_field, allowed, dev=dev)
    pw_field.fill(secret.password)
    _guard(page, pw_field, allowed, dev=dev)
    click_keycloak_submit(page)

    otp_done = False
    deadline = time.monotonic() + settle_s
    while time.monotonic() < deadline:
        page.wait_for_timeout(500)
        if cscs_on_portal(page.url):
            return
        _check_challenge(page, submitted=True)
        if not otp_done:
            otp_field = _visible(page, OTP_SELECTOR)
            if otp_field is not None:
                _fill_otp(page, otp_field, secret, allowed, dev=dev)
                otp_done = True
    raise LoginFailed("login did not reach the CSCS portal", submitted=True)


Recipe = Callable[..., None]


def recipe_for(site: str) -> Recipe:
    """The recipe for a site id (recipes are code: changing one needs sudo)."""
    return cscs_login if site == "cscs" else generic_login
