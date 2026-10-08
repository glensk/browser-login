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

from broker.login_form import (
    BUTTON_DESCRIBE_JS,
    FORM_ACTION_JS,
    SUBMIT_BUTTON_JS,
    USERNAME_JS,
    form_submit_buttons,
    pick_login_password,
    pick_login_username,
    pick_submit_button,
    pick_visible,
)
from broker.origins import form_action_allowed, origin_allowed, origin_hint, url_origin
from broker.otp_detect import OTP_CANDIDATE_SELECTOR, OTP_DESCRIBE_JS, otp_field_like
from broker.page_state import (  # browser.py imports interstitial_title from here
    challenge_reason,
    interstitial_title,
    sentinel_shown,
    trust_prompt_button,
)

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
STEP_TIMEOUT_S = 20.0
# Identifier-first logins that offer a passkey (SWITCH edu-ID, verified
# 2026-10-07) show "Use password" / "Use a passkey" buttons instead of the
# password field after the e-mail step. The password choice is clicked once,
# after this grace, while no password field is visible; a passkey / WebAuthn
# option never is.
PASSWORD_CHOICE_GRACE_S = 2.0
PASSWORD_CHOICE_RE = re.compile(
    r"^\s*(?:"
    r"(?:(?:use|with|sign\s+in\s+with|log\s+in\s+with)\s+(?:a\s+|the\s+|your\s+)?)?"
    r"password"
    r"|(?:mit\s+)?passwort(?:\s+(?:verwenden|benutzen|anmelden))?"
    r"|(?:utiliser\s+(?:le\s+|un\s+|votre\s+)?|avec\s+(?:le\s+|un\s+)?)?mot\s+de\s+passe"
    r")\s*$",
    re.IGNORECASE,
)
PASSKEY_RE = re.compile(
    r"passkey|webauthn|security\s*key|fido|cl[eé]\s+d.acc[eè]s|sicherheitsschl",
    re.IGNORECASE,
)
# The broker never answers a passkey prompt, and its headless Chromium has no
# authenticator, so `navigator.credentials.get({publicKey})` never settles:
# Zoho (accounts.zoho.eu, verified 2026-10-08) calls it right after the e-mail
# lookup for an account whose primary sign-in is a passkey, and its "Next"
# button spins forever. Installed in every broker page before the page's own
# scripts, this rejects each WebAuthn request at once with the
# NotAllowedError a human's "Cancel" gives; Zoho then shows its password field.
NO_PASSKEY_JS = """(() => {
  const C = window.CredentialsContainer;
  if (!C) return;
  const deny = () => Promise.reject(new DOMException(
      'The operation either timed out or was not allowed.', 'NotAllowedError'));
  for (const name of ['get', 'create']) {
    const orig = C.prototype[name];
    if (typeof orig !== 'function') continue;
    C.prototype[name] = function (options) {
      return options && options.publicKey ? deny() : orig.call(this, options);
    };
  }
})();"""
SETTLE_TIMEOUT_S = 30.0
# agent_pre_click: re-click while the element stays and no login field shows.
PRE_CLICK_RETRY_S = 3.0

CSCS_AUTH_ORIGIN = "https://auth.cscs.ch"
CSCS_PORTAL_ORIGIN = "https://portal.cscs.ch"
CSCS_LOGIN_URL = CSCS_PORTAL_ORIGIN + "/profile/"
SMARTSHEET_ORIGIN = "https://app.smartsheet.com"
SUBMIT_CHANGE_S = 3.0
# Bound on the identifier step's fallback click (Playwright's default is 30 s).
FALLBACK_CLICK_TIMEOUT_S = 5.0

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
    "smartsheet": SMARTSHEET_ORIGIN + "/b/home",
}

# Built-in logged-in sentinels, for sites whose check page stays ON the fill
# origin when logged in (so "left the fill origins" can never prove a login).
# An item's `agent_logged_in_selector` overrides. Smartsheet: the home
# desktop and the left rail's "Home" label, rendered only for a signed-in user
# (its data-testid attributes are missing in some sessions, verified 2026-10-06).
DEFAULT_LOGGED_IN_SELECTORS = {
    "smartsheet": "#desktopHome, #home-label",
}


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


def _frame_url(handle: Any) -> str:
    """URL of the frame `handle` lives in; "" when it cannot be determined."""
    try:
        frame = handle.owner_frame()
        return frame.url if frame is not None else ""
    except Exception:  # pylint: disable=broad-exception-caught
        return ""


def _guard(page: Any, field_handle: Any, allowed: list[str], *, dev: bool) -> None:
    """Raise OriginViolation unless the top page, the field's OWN frame and the
    form action (resolved against that frame's URL) are all on a fill origin.

    Checking only the top page would let a cross-origin iframe on an allowed
    page receive the secret. A field whose frame cannot be determined, or a
    frame without a real origin (``about:blank``, ``srcdoc``), fails closed.
    """
    if not origin_allowed(page.url, allowed, dev=dev):
        raise OriginViolation("page is not on a fill origin")
    frame_url = _frame_url(field_handle)
    if not origin_allowed(frame_url, allowed, dev=dev):
        raise OriginViolation(
            "the field's frame is not on a fill origin "
            f"(frame: {origin_hint(frame_url, dev=dev)})"
        )
    info = field_handle.evaluate(FORM_ACTION_JS)
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


def _login_password(page: Any) -> Any:
    """The visible LOGIN password field (never a registration one), or None."""
    return pick_visible(page, PASSWORD_SELECTOR, pick_login_password)


def _login_username(page: Any) -> Any:
    """The first visible username field outside a registration form, or None."""
    return pick_visible(page, USERNAME_SELECTOR, pick_login_username)


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
        if sentinel_shown(page, item.logged_in_selector):
            return True
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
    if item.site == "cscs":
        return cscs_portal_ready(page, wait_s=max(wait_s, 8.0))
    page.wait_for_timeout(1000)
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
    pw_field = _login_password(page) or pw_field
    _guard(page, pw_field, allowed, dev=dev)
    pw_field.fill(secret.password)
    page.wait_for_timeout(500)
    if _field_value(pw_field) == secret.password:
        return pw_field
    pw_field = _login_password(page) or pw_field
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


def _otp_field(page: Any) -> Any:
    """The visible TOTP input, or None.

    ``OTP_SELECTOR`` first; then — only while no password field is visible —
    the first visible, editable ``OTP_CANDIDATE_SELECTOR`` input that
    ``otp_field_like`` accepts (never a username field)."""
    el = _visible(page, OTP_SELECTOR)
    if el is not None:
        return el
    if _visible(page, PASSWORD_SELECTOR) is not None:
        return None
    try:
        for cand in page.query_selector_all(OTP_CANDIDATE_SELECTOR):
            if not cand.is_visible() or not cand.is_editable():
                continue
            desc = cand.evaluate(OTP_DESCRIBE_JS, USERNAME_SELECTOR)
            if isinstance(desc, dict) and otp_field_like(desc):
                return cand
    except Exception:  # pylint: disable=broad-exception-caught
        return None
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
    otp_field = _otp_field(page)  # re-query: the wait may have taken s
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
    password input. Registration fields never count (``_login_password`` /
    ``_login_username``). Both None after `timeout_s`.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        pw_field = _login_password(page)
        user_field = _login_username(page)
        if pw_field is not None or user_field is not None:
            return user_field, pw_field
        if time.monotonic() >= deadline:
            return None, None
        _check_challenge(page, submitted=False)
        page.wait_for_timeout(250)


def password_choice_name(name: str) -> bool:
    """True iff `name` (an accessible name) is a "use password" choice and
    mentions no passkey / WebAuthn option."""
    return bool(PASSWORD_CHOICE_RE.match(name)) and not PASSKEY_RE.search(name)


def _password_choice(page: Any) -> Any:
    """The first visible button or link whose accessible name is a "use
    password" choice (never a passkey option), or None."""
    for role in ("button", "link"):
        try:
            loc = page.get_by_role(role, name=PASSWORD_CHOICE_RE)
            for i in range(loc.count()):
                el = loc.nth(i)
                if not el.is_visible():
                    continue
                label = " ".join(
                    str(v or "")
                    for v in (el.get_attribute("aria-label"), el.inner_text())
                )
                if PASSKEY_RE.search(label):
                    continue
                return el
        except Exception:  # pylint: disable=broad-exception-caught
            continue
    return None


def _pre_click(page: Any, selector: str, allowed: list[str], *, dev: bool) -> bool:
    """``agent_pre_click``: click `selector` as soon as it is visible — unless
    the login password field shows first, or nothing shows within
    ``STEP_TIMEOUT_S``. True iff clicked.

    A SPA may show the element before its click handler is attached: on
    Jellyfin (2026-10-08) a click at first sight did nothing and the user
    picker stayed. So while the element stays visible and no login field
    appears, it is clicked again every ``PRE_CLICK_RETRY_S``; it is done once
    the element is gone or a login field shows. Every click (no secret
    involved) happens only while the page AND the element's own frame are on
    a fill origin."""
    deadline = time.monotonic() + STEP_TIMEOUT_S
    last_click: float | None = None
    while time.monotonic() < deadline:
        _check_challenge(page, submitted=False)
        if last_click is not None and (
            _login_password(page) is not None or _login_username(page) is not None
        ):
            return True
        el = _visible(page, selector)
        if el is None:
            if last_click is not None:
                return True  # the element went away: the click took effect
            if _login_password(page) is not None:
                return False
        elif last_click is None or time.monotonic() - last_click >= PRE_CLICK_RETRY_S:
            if not origin_allowed(_frame_url(el), allowed, dev=dev):
                raise OriginViolation("the pre-click element is not on a fill origin")
            _click_on_fill_origin(page, el, allowed, dev=dev)
            last_click = time.monotonic()
        page.wait_for_timeout(250)
    return last_click is not None


def _password_after_identifier(page: Any, allowed: list[str], *, dev: bool) -> Any:
    """The visible password field after the username step, or None.

    When none shows within ``PASSWORD_CHOICE_GRACE_S`` but a "use password"
    choice does, click it ONCE (only while on a fill origin) and wait a fresh
    ``STEP_TIMEOUT_S`` for the field."""
    start = time.monotonic()
    deadline = start + STEP_TIMEOUT_S
    clicked = False
    while time.monotonic() < deadline:
        el = _login_password(page)
        if el is not None:
            return el
        _check_challenge(page, submitted=False)
        if not clicked and time.monotonic() - start >= PASSWORD_CHOICE_GRACE_S:
            choice = _password_choice(page)
            if choice is not None:
                _click_on_fill_origin(page, choice, allowed, dev=dev)
                clicked = True
                deadline = time.monotonic() + STEP_TIMEOUT_S
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
    origin too).

    The click is a fallback only. A disabled button means the page is still
    busy with the Enter (Zoho turns "Next" into a disabled spinner during its
    lookup) and is left alone; a click that cannot happen within
    ``FALLBACK_CLICK_TIMEOUT_S`` is given up. Either way the caller's wait
    for the password field decides."""
    before = page.url
    user_field.press("Enter")
    deadline = time.monotonic() + SUBMIT_CHANGE_S
    while time.monotonic() < deadline:
        page.wait_for_timeout(250)
        if (
            page.url != before
            or not _still_there(user_field)
            or _login_password(page) is not None
        ):
            return
    handle = user_field.evaluate_handle(SUBMIT_BUTTON_JS)
    button = handle.as_element() if handle is not None else None
    if button is None or not _enabled(button):
        return
    _guard(page, user_field, allowed, dev=dev)
    frame_url = _frame_url(button)
    own_action = button.get_attribute("formaction")
    if own_action and not form_action_allowed(frame_url, own_action, allowed, dev=dev):
        raise OriginViolation("submit button posts off the fill origins")
    try:
        button.click(timeout=FALLBACK_CLICK_TIMEOUT_S * 1000)
    except Exception:  # pylint: disable=broad-exception-caught
        pass  # not clickable (detached, covered): the Enter may still land


def _enabled(element: Any) -> bool:
    try:
        return bool(element.is_enabled())
    except Exception:  # pylint: disable=broad-exception-caught
        return False


def _submit_password(
    page: Any, pw_field: Any, allowed: list[str], *, dev: bool
) -> None:
    """Submit the typed password: Enter in the field, unless Enter would fire
    a form button that does something else (``pick_submit_button``: a
    "forgot password" default button, Calibre-Web Automated 2026-10-08) — then
    click the form's login button instead. Guarded like every submit: the
    field, the button's own frame and its ``formaction`` stay on a fill
    origin. Raises before anything is submitted when no login button shows."""
    _guard(page, pw_field, allowed, dev=dev)
    buttons = form_submit_buttons(pw_field)
    descs: list[dict[str, Any]] = []
    for button in buttons:
        try:
            desc = button.evaluate(BUTTON_DESCRIBE_JS)
        except Exception:  # pylint: disable=broad-exception-caught
            desc = None
        descs.append(desc if isinstance(desc, dict) else {})
    choice = pick_submit_button(descs)
    if choice is None:
        pw_field.press("Enter")
        return
    if choice < 0:
        raise LoginFailed(
            "Enter would press the form's non-login default button and no login"
            " button is showing"
        )
    button = buttons[choice]
    frame_url = _frame_url(button)
    if not origin_allowed(frame_url, allowed, dev=dev):
        raise OriginViolation("the submit button is not on a fill origin")
    own_action = button.get_attribute("formaction")
    if own_action and not form_action_allowed(frame_url, own_action, allowed, dev=dev):
        raise OriginViolation("submit button posts off the fill origins")
    _click_on_fill_origin(page, button, allowed, dev=dev)


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
    ``agent_login_url``: an Auth0 login needs the ``state`` the site creates);
    an item's ``agent_pre_click`` element is clicked once before the login
    fields are looked for (``_pre_click``).
    Returns once the page left the login (sentinel visible / off the fill
    origins) or `settle_s` passed; the caller then runs the POSITIVE check
    ``check_logged_in`` — this function's return alone proves nothing.
    """
    allowed = list(item.fill_origins)
    page.goto(item.login_url, wait_until="domcontentloaded")
    _check_challenge(page, submitted=False)
    if item.pre_click:
        _pre_click(page, item.pre_click, allowed, dev=dev)
    user_field, pw_field = _wait_login_fields(page, STEP_TIMEOUT_S)
    if user_field is None and pw_field is None:
        _check_challenge(page, submitted=False)
        raise LoginFailed("no visible username or password field on the login page")
    if pw_field is None:  # identifier-first: username page, then password page
        _guard(page, user_field, allowed, dev=dev)
        user_field.fill(secret.username)
        _guard(page, user_field, allowed, dev=dev)
        _submit_identifier(page, user_field, allowed, dev=dev)
        pw_field = _password_after_identifier(page, allowed, dev=dev)
        if pw_field is None:
            _check_challenge(page, submitted=False)
            raise LoginFailed("no visible password field after the username step")
    user_handle = pw_field.evaluate_handle(USERNAME_JS)
    user_field = user_handle.as_element() if user_handle is not None else None
    if user_field is not None and secret.username:
        if _needs_fill(user_field, secret.username):
            _guard(page, user_field, allowed, dev=dev)
            user_field.fill(secret.username)
    pw_field = _fill_password(page, pw_field, secret, allowed, dev=dev)
    _submit_password(page, pw_field, allowed, dev=dev)

    otp_done = trusted = False
    deadline = time.monotonic() + settle_s
    while time.monotonic() < deadline:
        page.wait_for_timeout(500)
        _check_challenge(page, submitted=True)
        otp_field = None if otp_done else _otp_field(page)
        if otp_field is not None:
            _fill_otp(
                page, otp_field, secret, allowed, dev=dev, otp_label=item.otp_label
            )
            otp_done = True
            continue
        if _left_login(page, item, dev=dev):
            return
        trust = (
            None
            if trusted or off_fill_origins(page.url, allowed, dev=dev)
            else (trust_prompt_button(page))
        )
        if trust is not None:
            trust.click(timeout=5000)
            trusted = True
    # Still on the login after the password: wrong password, an e-mail code, a
    # captcha... Fail HERE so the failure report shows this page.
    raise LoginFailed(
        "still on the login page after submitting the password", submitted=True
    )


def _left_login(page: Any, item: SiteItem, *, dev: bool) -> bool:
    """Cheap "the login is over" signal for the settle loop (NOT the proof)."""
    if item.logged_in_selector and sentinel_shown(page, item.logged_in_selector):
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


# HomePort keeps its 40-hex DRF token somewhere in localStorage (same regex as
# browser.py ``_scan_token``: anywhere in the value, not only the whole value).
CSCS_HAS_TOKEN_JS = (
    "() => { const re=/\\b[0-9a-f]{40}\\b/;"
    "for (let i=0;i<localStorage.length;i++)"
    "{const v=localStorage.getItem(localStorage.key(i));"
    "if (v && re.test(v)) return true;} return false; }"
)


def cscs_portal_ready(page: Any, *, wait_s: float = 8.0) -> bool:
    """The CSCS positive check: the portal app holds its Waldur token.

    Being on ``portal.cscs.ch`` proves nothing: the SPA renders there first and
    only then redirects a token-less session to Keycloak. So poll (up to
    ``wait_s``) until the token is in localStorage while still on the portal;
    a move to Keycloak or anywhere else is "not logged in".
    """
    deadline = time.monotonic() + wait_s
    while True:
        if not cscs_on_portal(page.url):
            if not page.url.startswith(CSCS_PORTAL_ORIGIN + "/"):
                return False  # redirected off the portal (Keycloak login)
        else:
            try:
                if page.evaluate(CSCS_HAS_TOKEN_JS):
                    return True
            except Exception:  # pylint: disable=broad-exception-caught
                pass  # navigating mid-evaluate: try again
        if time.monotonic() >= deadline:
            return False
        page.wait_for_timeout(500)


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
    if cscs_portal_ready(page, wait_s=8.0):
        return  # the profile's session still holds a token
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


# Smartsheet's login wizard (verified 2026-10-06): e-mail + Continue, then
# /login/providers offering Microsoft / Google / Apple and either "Sign in with
# email and password" directly or behind "More sign-in options" (a fresh
# profile; older variant: "Try another way"), then
# a password field with NO <form> and a type=button "Sign in". Every step is on
# https://app.smartsheet.com; a fresh profile shows the e-mail step, a profile
# that remembers the address starts at the providers page.
SMARTSHEET_EMAIL_SELECTOR = "#loginEmail, input[type=email], input[name=email]"
SMARTSHEET_SIGN_IN = "#signInControl"
# Wizard buttons towards the password field, the furthest-along first.
SMARTSHEET_STEPS = (
    "#emailPasswordOption",
    "text='More sign-in options'",
    "text='Try another way'",
)


def _click_on_fill_origin(
    page: Any, element: Any, allowed: list[str], *, dev: bool
) -> None:
    """Click a wizard button (no secret involved) only while on a fill origin."""
    if not origin_allowed(page.url, allowed, dev=dev):
        raise OriginViolation("page is not on a fill origin")
    element.click()


def _smartsheet_password_field(
    page: Any, secret: Secret, allowed: list[str], *, dev: bool
) -> Any:
    """Walk the wizard up to the visible password field; None after the timeout."""
    email_done = False
    deadline = time.monotonic() + 2 * STEP_TIMEOUT_S
    while time.monotonic() < deadline:
        _check_challenge(page, submitted=False)
        pw_field = _visible(page, PASSWORD_SELECTOR)
        if pw_field is not None:
            return pw_field
        option = next(
            (el for sel in SMARTSHEET_STEPS if (el := _visible(page, sel))), None
        )
        if option is not None:
            _click_on_fill_origin(page, option, allowed, dev=dev)
            page.wait_for_timeout(1000)
            continue
        email = None if email_done else _visible(page, SMARTSHEET_EMAIL_SELECTOR)
        if email is not None:
            _guard(page, email, allowed, dev=dev)
            email.fill(secret.username)
            _guard(page, email, allowed, dev=dev)
            _submit_identifier(page, email, allowed, dev=dev)
            email_done = True
            continue
        page.wait_for_timeout(250)
    return None


def smartsheet_login(
    page: Any,
    item: SiteItem,
    secret: Secret,
    *,
    dev: bool = False,
    settle_s: float = SETTLE_TIMEOUT_S,
) -> None:
    """Smartsheet e-mail/password login through its multi-step wizard.

    Secrets are typed only on the item's fill origins (``_guard`` before each
    fill); wizard buttons are clicked only while the page is on one. Returns
    once the sentinel shows or the page left the login; the caller's
    ``check_logged_in`` is the proof.
    """
    allowed = list(item.fill_origins)
    sentinel = item.logged_in_selector or DEFAULT_LOGGED_IN_SELECTORS["smartsheet"]
    page.goto(item.login_url, wait_until="domcontentloaded")
    if _wait_visible(page, sentinel, 5.0) is not None:
        return  # the profile's session is still valid
    pw_field = _smartsheet_password_field(page, secret, allowed, dev=dev)
    if pw_field is None:
        _check_challenge(page, submitted=False)
        raise LoginFailed("no password field after the Smartsheet login steps")
    pw_field = _fill_password(page, pw_field, secret, allowed, dev=dev)
    _guard(page, pw_field, allowed, dev=dev)
    button = _visible(page, SMARTSHEET_SIGN_IN)
    if button is not None:
        _click_on_fill_origin(page, button, allowed, dev=dev)
    else:
        pw_field.press("Enter")

    deadline = time.monotonic() + settle_s
    while time.monotonic() < deadline:
        page.wait_for_timeout(500)
        _check_challenge(page, submitted=True)
        if _visible(page, sentinel) is not None:
            return
        if off_fill_origins(page.url, allowed, dev=dev) and (
            _visible(page, PASSWORD_SELECTOR) is None
        ):
            return
    raise LoginFailed(
        "still on the Smartsheet login after submitting the password", submitted=True
    )


Recipe = Callable[..., None]


def recipe_for(site: str) -> Recipe:
    """The recipe for a site id (recipes are code: changing one needs sudo)."""
    return {"cscs": cscs_login, "smartsheet": smartsheet_login}.get(site, generic_login)
