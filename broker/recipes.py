"""Login recipes: where and how the broker types a site's secret.

A recipe decides where a secret is typed, so every fill and every submit is
preceded by ``_guard``: the page's CURRENT origin and the form's effective
action must both be one of the item's ``agent_fill_origins`` (exact scheme +
host + port). A redirect to a look-alike host between two fills is caught
because the check runs again right before each one.

Success needs POSITIVE proof (``check_logged_in``): on the site's check page
(``agent_check_url`` or a built-in default from ``DEFAULT_CHECK_URLS``) either
the item's sentinel is visible, or the page ended OFF every fill origin with
no visible password field. "The password field went away" alone proves
nothing — page 2 of an identifier-first (Auth0) login has none either.

Exceptions carry ``submitted``: whether a secret had already been submitted
when the recipe gave up. The daemon maps a failure after submission to the
limiter's ``unknown`` outcome (never retried automatically).
"""

from __future__ import annotations

import re
import time
import urllib.parse
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from broker.origins import form_action_allowed, origin_allowed, url_origin

if TYPE_CHECKING:  # annotations only: vault imports DEFAULT_CHECK_URLS from here
    from broker.vault import Secret, SiteItem

PASSWORD_SELECTOR = "input[type=password]"
# Username / e-mail field of an identifier-first page (Auth0: type=email
# name=username autocomplete=email).
USERNAME_SELECTOR = (
    "input[type=email], input[autocomplete~=username], input[autocomplete~=email], "
    "input[name=username], input[name=email], input[name=identifier], input#username"
)
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
SUBMIT_CHANGE_S = 3.0

# Built-in check URLs: a page that needs the login and, when logged out,
# redirects to the site's login page on a fill origin (each verified with an
# unauthenticated headless load, 2026-10-02). An item's `agent_check_url`
# overrides. Toppreise has none: its account pages show the login form INLINE
# on www.toppreise.ch, so such an item needs `agent_logged_in_selector`.
DEFAULT_CHECK_URLS = {
    "kleinanzeigen": "https://www.kleinanzeigen.de/m-meine-anzeigen.html",
    "anibis": "https://www.anibis.ch/fr/user/searches",
    "ricardo": "https://www.ricardo.ch/de/my-ricardo/saved/articles/",
    "tutti": "https://www.tutti.ch/de/myads/active",
    "cscs": CSCS_LOGIN_URL,
}

# Effective action of the form around an input: the default submit button's
# `formaction` overrides the form's `action`. `null` = no form.
_FORM_ACTION_JS = """e => {
  const f = e.form;
  if (!f) return {form: false, action: null};
  const b = f.querySelector('button[type=submit], input[type=submit], button:not([type])');
  return {form: true, action: (b && b.getAttribute('formaction')) || f.getAttribute('action')};
}"""

# The visible submit button of the form around an input (first in DOM order).
_SUBMIT_BUTTON_JS = """e => {
  const scope = e.form || document;
  const vis = el => !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length);
  return Array.from(scope.querySelectorAll(
      'button[type=submit], input[type=submit], button:not([type])')).find(vis) || null;
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


def interstitial_title(page: Any) -> bool:
    """True on a bot-check interstitial ("Just a moment…")."""
    try:
        title = (page.title() or "").strip().lower()
    except Exception:  # pylint: disable=broad-exception-caught
        title = ""
    return any(title.startswith(t) for t in CHALLENGE_TITLES)


# Fraud-protection pages: retrying makes them worse, so they mean "needs a human".
BLOCKED_TEXT_RE = re.compile(
    r"IP-Bereich vor\u00fcbergehend gesperrt|IP-Bereich gesperrt|temporarily blocked"
    r"|too many (?:login )?attempts|zu viele (?:Anmelde)?versuche"
    r"|trop de tentatives|Zugriff vor\u00fcbergehend gesperrt",
    re.IGNORECASE,
)


def challenge_reason(page: Any) -> str | None:
    """``"captcha"`` when a captcha / bot-challenge is on the page, else None."""
    if interstitial_title(page):
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
    try:
        text = str(
            page.evaluate("() => (document.body?.innerText || '').slice(0, 4000)")
        )
    except Exception:  # pylint: disable=broad-exception-caught
        return None
    if BLOCKED_TEXT_RE.search(text):
        return (
            "the site blocked this IP range / too many attempts — stop and retry later"
        )
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


def off_fill_origins(url: str, fill_origins: list[str], *, dev: bool) -> bool:
    """True iff `url` is a real http(s) page (http only for the dev loopback)
    whose origin is NOT one of `fill_origins` — the "left the login" half of
    the positive check. ``chrome-error://``, ``about:blank`` and unparsable
    URLs are False."""
    origin = url_origin(url, dev=dev)
    return origin is not None and origin not in fill_origins


def check_page_url(item: SiteItem) -> str:
    """Where the positive check looks: the check URL, else (sentinel-only
    items) the login URL."""
    return item.check_url or item.login_url


def logged_in(
    page: Any, item: SiteItem, *, wait_s: float = 8.0, dev: bool = False
) -> bool:
    """Positive success test on the CURRENT page (the check page).

    True iff the item's sentinel is visible, or — the item has a check URL —
    the page is off every fill origin, shows no bot challenge and no visible
    password field. No check URL and no sentinel: never logged in. Only the
    interstitial TITLE counts as a challenge here — a logged-in account page
    may well embed a reCAPTCHA iframe.
    """
    if item.logged_in_selector:
        try:
            page.wait_for_selector(
                item.logged_in_selector, state="visible", timeout=wait_s * 1000
            )
            return True
        except Exception:  # pylint: disable=broad-exception-caught
            pass
    if not item.check_url:
        return False
    if not off_fill_origins(page.url, list(item.fill_origins), dev=dev):
        return False
    if interstitial_title(page):
        return False
    return _visible(page, PASSWORD_SELECTOR) is None


def check_logged_in(
    page: Any, item: SiteItem, *, dev: bool = False, wait_s: float = 8.0
) -> bool:
    """Navigate to the check page and decide (see ``logged_in``).

    CSCS keeps its own rule: the settled ``https://portal.cscs.ch`` app. An
    HTTP error status on the check page is never a login.
    """
    url = check_page_url(item)
    if not url:
        return False
    resp = page.goto(url, wait_until="domcontentloaded")
    try:
        page.wait_for_load_state("load", timeout=10_000)
    except Exception:  # pylint: disable=broad-exception-caught
        pass
    page.wait_for_timeout(1500 if item.site == "cscs" else 1000)
    if item.site == "cscs":
        return cscs_on_portal(page.url)
    status = getattr(resp, "status", None) if resp is not None else None
    if isinstance(status, int) and status >= 400:
        return False
    return logged_in(page, item, wait_s=wait_s, dev=dev)


# A freshly shown password page may still re-render (and clear inputs) while its
# JS hydrates; give it this long before typing, then verify the value stuck.
HYDRATE_S = 1.5


def _fill_password(
    page: Any, pw_field: Any, secret: Secret, allowed: list[str], *, dev: bool
) -> Any:
    """Type the password and make sure the field KEEPS it; returns the field used.

    One retry types it key by key into the (re-located) visible password field;
    a field that still drops the value fails BEFORE anything is submitted.
    """
    page.wait_for_timeout(HYDRATE_S * 1000)
    _check_challenge(page, submitted=False)
    pw_field = _visible(page, PASSWORD_SELECTOR) or pw_field
    _guard(page, pw_field, allowed, dev=dev)
    pw_field.fill(secret.password)
    page.wait_for_timeout(500)
    if _field_value(pw_field) == secret.password:
        return pw_field
    pw_field = _visible(page, PASSWORD_SELECTOR) or pw_field
    _guard(page, pw_field, allowed, dev=dev)
    pw_field.fill("")
    pw_field.press_sequentially(secret.password, delay=60)
    page.wait_for_timeout(500)
    if _field_value(pw_field) != secret.password:
        raise LoginFailed("the password field did not keep the typed value")
    return pw_field


def _field_value(field: Any) -> str | None:
    try:
        return str(field.input_value())
    except Exception:  # pylint: disable=broad-exception-caught
        return None


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


# Keycloak lists several OTP credentials as radios; labels are not secrets.
_SELECT_OTP_JS = """(label) => {
  const rs = [...document.querySelectorAll('input[name=selectedCredentialId]')];
  if (rs.length < 2) return 'single';
  const text = r => {
    const l = document.querySelector('label[for="' + r.id + '"]');
    return ((l && l.innerText) || (r.closest('label,div') || {}).innerText || '').trim();
  };
  if (!label) return 'ambiguous:' + rs.map(text).join('|');
  const r = rs.find(x => text(x).toLowerCase().includes(label.toLowerCase()));
  if (!r) return 'nomatch:' + rs.map(text).join('|');
  const l = document.querySelector('label[for="' + r.id + '"]');
  if (l) l.click();
  r.checked = true;
  r.dispatchEvent(new Event('change', {bubbles: true}));
  return 'selected:' + text(r);
}"""


def _select_authenticator(page: Any, otp_label: str | None) -> None:
    """Pick the item's authenticator when the account offers several."""
    result = str(page.evaluate(_SELECT_OTP_JS, otp_label or ""))
    if result.startswith("ambiguous:"):
        raise NeedsHuman(
            "the account has several authenticators ("
            + result.split(":", 1)[1]
            + "); set agent_otp_label on the item",
            submitted=True,
        )
    if result.startswith("nomatch:"):
        raise LoginFailed(
            f"authenticator {otp_label!r} not offered ({result.split(':', 1)[1]})",
            submitted=True,
        )


def _fill_otp(  # pylint: disable=too-many-arguments
    page: Any,
    otp_field: Any,
    secret: Secret,
    allowed: list[str],
    *,
    dev: bool,
    otp_label: str | None = None,
) -> None:
    if not secret.totp_seed:
        raise NeedsHuman("otp required but the item has no TOTP seed", submitted=True)
    code = fresh_totp(secret.totp_seed)
    if not code:
        raise LoginFailed("could not produce a TOTP code", submitted=True)
    otp_field = _visible(page, OTP_SELECTOR)  # re-query: the wait may have taken s
    if otp_field is None:
        raise LoginFailed("the OTP field disappeared", submitted=True)
    _select_authenticator(page, otp_label)
    try:
        _guard(page, otp_field, allowed, dev=dev)
    except OriginViolation as exc:
        exc.submitted = True
        raise
    otp_field.fill(code)
    _guard(page, otp_field, allowed, dev=dev)
    otp_field.press("Enter")


def _wait_login_fields(page: Any, timeout_s: float) -> tuple[Any, Any]:
    """(visible username field, visible password field) once either shows up.

    Visibility is what counts: Auth0's identifier page carries a HIDDEN
    password input. Both None after `timeout_s`.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        pw_field = _visible(page, PASSWORD_SELECTOR)
        user_field = _visible(page, USERNAME_SELECTOR)
        if pw_field is not None or user_field is not None:
            return user_field, pw_field
        if time.monotonic() >= deadline:
            return None, None
        _check_challenge(page, submitted=False)
        page.wait_for_timeout(250)


def _wait_password(page: Any, timeout_s: float) -> Any:
    """The visible password field of step 2, or None; bot checks abort early."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        el = _visible(page, PASSWORD_SELECTOR)
        if el is not None:
            return el
        _check_challenge(page, submitted=False)
        page.wait_for_timeout(250)
    return None


def _still_there(field: Any) -> bool:
    try:
        return bool(field.is_visible())
    except Exception:  # pylint: disable=broad-exception-caught
        return False  # detached: the page moved on


def _submit_identifier(
    page: Any, user_field: Any, allowed: list[str], *, dev: bool
) -> None:
    """Submit the username step: Enter in the field; if neither the URL nor the
    DOM changes within ``SUBMIT_CHANGE_S``, click the form's visible submit
    button (re-guarded: the button's own ``formaction`` must stay on a fill
    origin too)."""
    before = page.url
    user_field.press("Enter")
    deadline = time.monotonic() + SUBMIT_CHANGE_S
    while time.monotonic() < deadline:
        page.wait_for_timeout(250)
        if (
            page.url != before
            or not _still_there(user_field)
            or _visible(page, PASSWORD_SELECTOR) is not None
        ):
            return
    handle = user_field.evaluate_handle(_SUBMIT_BUTTON_JS)
    button = handle.as_element() if handle is not None else None
    if button is None:
        return
    _guard(page, user_field, allowed, dev=dev)
    try:
        frame = button.owner_frame()
        frame_url = frame.url if frame is not None else ""
    except Exception:  # pylint: disable=broad-exception-caught
        frame_url = ""
    own_action = button.get_attribute("formaction")
    if own_action and not form_action_allowed(frame_url, own_action, allowed, dev=dev):
        raise OriginViolation("submit button posts off the fill origins")
    button.click()


def _needs_fill(field: Any, username: str) -> bool:
    """False when the field already holds `username` or is read-only (Auth0's
    password page echoes the identifier typed on page 1 read-only)."""
    try:
        value = str(field.input_value() or "").strip()
        editable = bool(field.is_editable())
    except Exception:  # pylint: disable=broad-exception-caught
        return True
    if value and value.casefold() == username.strip().casefold():
        return False
    return editable


def generic_login(
    page: Any,
    item: SiteItem,
    secret: Secret,
    *,
    dev: bool = False,
    settle_s: float = SETTLE_TIMEOUT_S,
) -> None:
    """Username/password(/TOTP) form login, one-page or identifier-first.

    Starts at the login URL (= the check URL when the item sets no
    ``agent_login_url``: an Auth0 login needs the ``state`` the site creates).
    Returns once the page left the login (sentinel visible / off the fill
    origins) or `settle_s` passed; the caller then runs the POSITIVE check
    ``check_logged_in`` — this function's return alone proves nothing.
    """
    allowed = list(item.fill_origins)
    page.goto(item.login_url, wait_until="domcontentloaded")
    _check_challenge(page, submitted=False)
    user_field, pw_field = _wait_login_fields(page, STEP_TIMEOUT_S)
    if user_field is None and pw_field is None:
        _check_challenge(page, submitted=False)
        raise LoginFailed("no visible username or password field on the login page")
    if pw_field is None:  # identifier-first: username page, then password page
        _guard(page, user_field, allowed, dev=dev)
        user_field.fill(secret.username)
        _guard(page, user_field, allowed, dev=dev)
        _submit_identifier(page, user_field, allowed, dev=dev)
        pw_field = _wait_password(page, STEP_TIMEOUT_S)
        if pw_field is None:
            _check_challenge(page, submitted=False)
            raise LoginFailed("no visible password field after the username step")
    user_handle = pw_field.evaluate_handle(_USERNAME_JS)
    user_field = user_handle.as_element() if user_handle is not None else None
    if user_field is not None and secret.username:
        if _needs_fill(user_field, secret.username):
            _guard(page, user_field, allowed, dev=dev)
            user_field.fill(secret.username)
    pw_field = _fill_password(page, pw_field, secret, allowed, dev=dev)
    _guard(page, pw_field, allowed, dev=dev)
    pw_field.press("Enter")

    otp_done = False
    deadline = time.monotonic() + settle_s
    while time.monotonic() < deadline:
        page.wait_for_timeout(500)
        _check_challenge(page, submitted=True)
        otp_field = None if otp_done else _visible(page, OTP_SELECTOR)
        if otp_field is not None:
            _fill_otp(
                page, otp_field, secret, allowed, dev=dev, otp_label=item.otp_label
            )
            otp_done = True
            continue
        if _left_login(page, item, dev=dev):
            return
    # Still on the login after the password: wrong password, an e-mail code, a
    # captcha... Fail HERE so the failure report shows this page.
    raise LoginFailed(
        "still on the login page after submitting the password", submitted=True
    )


def _left_login(page: Any, item: SiteItem, *, dev: bool) -> bool:
    """Cheap "the login is over" signal for the settle loop (NOT the proof)."""
    if item.logged_in_selector and _visible(page, item.logged_in_selector):
        return True
    return off_fill_origins(page.url, list(item.fill_origins), dev=dev) and (
        _visible(page, PASSWORD_SELECTOR) is None
    )


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
    # Same protected entry as the generic recipe: wait for the page to settle,
    # verify the field KEPT the password, retry key by key, fail before submit.
    pw_field = _fill_password(page, pw_field, secret, allowed, dev=dev)
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
                _fill_otp(
                    page, otp_field, secret, allowed, dev=dev, otp_label=item.otp_label
                )
                otp_done = True
    raise LoginFailed("login did not reach the CSCS portal", submitted=True)


Recipe = Callable[..., None]


def recipe_for(site: str) -> Recipe:
    """The recipe for a site id (recipes are code: changing one needs sudo)."""
    return cscs_login if site == "cscs" else generic_login


# What a failure report lists: visible message-like elements and buttons.
_DIAG_JS = """() => {
  const vis = e => !!(e.offsetWidth || e.offsetHeight || e.getClientRects().length);
  const txt = e => (e.innerText || e.value || e.getAttribute('aria-label') || '')
    .replace(/\\s+/g, ' ').trim();
  const pick = (sel, n, len) => [...document.querySelectorAll(sel)].filter(vis)
    .map(txt).filter(Boolean).map(t => t.slice(0, len)).slice(0, n);
  const inputs = [...document.querySelectorAll('input')].filter(vis)
    .map(i => (i.type || 'text') + (i.name ? ':' + i.name : '')).slice(0, 10);
  return {
    messages: pick('[role=alert], [aria-live], .error, [class*=error i], [class*=alert i],'
      + ' [id*=error i], .ulp-input-error-message, .ulp-validator-error', 5, 200),
    buttons: pick('button, input[type=submit]', 6, 40),
    inputs: inputs,
    frames: [...document.querySelectorAll('iframe')].map(f => {
      try { return new URL(f.src).host; } catch (e) { return ''; } }).filter(Boolean)
      .slice(0, 6),
  };
}"""


def _redact(text: str, secret: Secret) -> str:
    """Mask the username and password wherever a page echoes them."""
    for value in (secret.password, secret.username):
        if value:
            text = text.replace(value, "***")
    return text


def diagnose(page: Any, secret: Secret) -> dict[str, Any]:
    """Secret-free picture of the page a login stopped on.

    URL without query/fragment, title, visible inputs (type:name only, never
    values), message-like texts and buttons (username/password masked), iframe
    hosts, and whether a bot challenge is showing.
    """
    parts = urllib.parse.urlsplit(page.url)
    raw = page.evaluate(_DIAG_JS)
    raw = raw if isinstance(raw, dict) else {}
    return {
        "url": f"{parts.scheme}://{parts.netloc}{parts.path}",
        "title": _redact(str(page.title() or "")[:120], secret),
        "inputs": [str(x) for x in raw.get("inputs", [])],
        "messages": [_redact(str(x), secret) for x in raw.get("messages", [])],
        "buttons": [_redact(str(x), secret) for x in raw.get("buttons", [])],
        "frames": [str(x) for x in raw.get("frames", [])],
        "challenge": challenge_reason(page) or "",
    }
