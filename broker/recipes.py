"""Login recipes: where and how the broker types a site's secret.

A recipe decides where a secret is typed, so every fill and every submit is
preceded by ``_guard``: the page's CURRENT origin and the form's effective
action must both be one of the item's ``agent_fill_origins`` (exact scheme +
host + port). A redirect to a look-alike host between two fills is caught
because the check runs again right before each one.

Success needs POSITIVE proof (``check_logged_in``): on the site's check page
(``agent_check_url`` or a built-in default from ``DEFAULT_CHECK_URLS``) the
item's authenticated sentinel (``agent_logged_in_selector``) is visible; a site
with a registered server proof (``PROOFS``: CSCS asks ``/api/users/me/`` with
the stored token) needs no sentinel. "Ended off the fill origins with no
password field" proves nothing — it also holds on an "Access denied" page — and
an item without either is never logged in.

Every recipe takes an ``attempt`` (``AttemptController``): ``entered()``
before the password first reaches the page, ``mark_submitted()`` right before
the click/Enter that submits a secret — the daemon persists both in its
limiter, and the submit marker decides whether a failure counts against the
site.

Exceptions carry ``submitted``: whether a secret had already been submitted
when the recipe gave up. The daemon maps a failure after submission to the
limiter's ``unknown`` outcome (never retried automatically).
"""

from __future__ import annotations

# every recipe and its proof share the guarded helpers.
# pylint: disable=too-many-lines
import contextlib
import math
import re
import time
import urllib.parse
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from broker.login_form import (
    FIELD_DESCRIBE_JS,
    FORM_ACTION_JS,
    REMEMBER_BOX_HANDLES_JS,
    REMEMBER_BOXES_JS,
    SUBMIT_BUTTON_JS,
    USERNAME_JS,
    body_pairs,
    concealed,
    describe_buttons,
    pick_login_password,
    pick_login_username,
    pick_remember_me,
    pick_submit_button,
    pick_visible,
    read_submit_buttons,
    registration_field_like,
    secondary_button_like,
    secondary_hit,
    secondary_pairs,
)
from broker.origins import (
    access_gated,
    access_gated_via,
    form_action_allowed,
    origin_allowed,
    origin_hint,
    url_origin,
)
from broker.otp_detect import OTP_CANDIDATE_SELECTOR, OTP_DESCRIBE_JS, otp_field_like
from broker.page_state import (
    PROCESSING_CHALLENGE_KINDS,
    await_sentinel,
    challenge_detail,
    challenge_reason,
    challenge_snapshot,
    interstitial_title,
    page_blank,
    password_shown,
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
# `agent_login_mode=username-only` (``vault.USERNAME_ONLY`` is this value:
# vault imports this module): the item's username alone is the credential,
# typed and submitted like a password (``_credential_login``).
USERNAME_ONLY_MODE = "username-only"
# Where a username-only login's account number / username may go when the page
# does not mask it in a password field (Mullvad does: type=password
# name=account_number): the username candidates plus account-number fields.
ACCOUNT_SELECTOR = (
    USERNAME_SELECTOR + ", input[name*=account i], input[id*=account i], "
    "input[autocomplete~=username]"
)
# Input types an account number can be typed into.
ACCOUNT_FIELD_TYPES = frozenset({"", "text", "email", "tel", "number", "password"})
# The OTHER visible text-like inputs of a field's form — `form.elements`, so
# controls outside the <form> tag joined by `form=` count too — or, for a
# form-less field, the page's other form-less ones. A username-only login types
# into a field only when this is 0: a form that also asks for something else
# is a password login, never guessed at.
OTHER_FIELDS_JS = """e => {
  const vis = el => !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length);
  const skip = ['hidden', 'checkbox', 'radio', 'submit', 'button', 'image', 'reset',
                'file', 'range', 'color'];
  const all = e.form ? Array.from(e.form.elements)
      : Array.from(e.ownerDocument.querySelectorAll('input, textarea')).filter(i => !i.form);
  return all.filter(i =>
      i !== e && (i.tagName === 'INPUT' || i.tagName === 'TEXTAREA') && vis(i)
      && !(i.tagName === 'INPUT' && skip.includes((i.type || 'text').toLowerCase()))
  ).length;
}"""
# A field whose name / id says "account" (Mullvad: name=account_number).
ACCOUNT_NAME_RE = re.compile(r"account", re.IGNORECASE)
STEP_TIMEOUT_S = 20.0
# Post-login prompts answered per login (page_state.POST_LOGIN_PROMPTS): Zoho
# can ask "Trust this browser?" and then "Review your account details".
MAX_POST_LOGIN_PROMPTS = 2
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
# A challenge seen AFTER the submit counts only once it has stayed this long
# on ONE document (``ChallengeWatch``): an interstitial that clears itself
# (MyFRITZ's invisible reCAPTCHA page submits after 2-4 s) moves on before
# that. Must stay well inside SETTLE_TIMEOUT_S.
CHALLENGE_GRACE_S = 8.0
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

    def __init__(
        self,
        detail: str,
        *,
        submitted: bool = False,
        phase: str | None = None,
        auth_proven: bool = False,
        unsent: bool = False,
    ) -> None:
        super().__init__(detail)
        self.detail = detail
        self.submitted = submitted
        # Where it stopped (broker/phases.py); None = derived from the marker.
        self.phase = phase
        # The login itself was PROVEN (sentinel after a fresh submit) and a later
        # step failed: the limiter treats it as a fresh authentication.
        self.auth_proven = auth_proven
        # Set only after the recipe VERIFIED, when giving up, that the typed
        # password still sits in its field on a fill origin: the form was not
        # submitted, although the password was entered.
        self.unsent = unsent
        # Set only by the POST tripwire (``SubmitTripwire``): the submit WAS
        # triggered, but its request was aborted inside the browser and no
        # other request with a body reached a fill origin after the password
        # was typed — the password never left the machine.
        self.never_sent = False


class LoginFailed(RecipeError):
    """The login did not reach a logged-in state."""


class SubmitUnidentified(LoginFailed):
    """The form's submit buttons could not be read, or only secondary ones
    (forgot password, register …) show: nothing is submitted. Pressing Enter
    then would fire the form's default button — a guess, and on Calibre-Web
    Automated (2026-10-08) the guess reset the admin password."""

    code = "submit_unidentified"


class SecondaryActionBlocked(RecipeError):
    """The POST tripwire aborted a request that named a secondary form action
    (``login_form.secondary_post``): the broker's own submit would have run
    "forgot password", reset, register or resend instead of the login."""

    code = "secondary_action_blocked"

    def __init__(self, detail: str, *, never_sent: bool) -> None:
        super().__init__(detail, phase="submit", submitted=not never_sent)
        self.never_sent = never_sent


# A login page that answers one of these has no login form of the site's (an
# Access block page, an IP or country gate): nothing is typed there.
BLOCKED_STATUSES = frozenset({401, 403})


class AccessGated(RecipeError):
    """The site's page is a Cloudflare Access login (``origins.access_gated``):
    off-LAN, the app is behind Access and unreachable from here. Nothing is
    reserved, typed or submitted."""

    code = "access_gated"

    def __init__(self, detail: str = "") -> None:
        super().__init__(
            detail
            or "the site redirects to its Cloudflare Access login — unreachable "
            "off-LAN, nothing typed",
            phase="precheck",
        )


class NavTrail:
    """The URLs of every main-frame navigation request of `page` while the
    trail is open — each HTTP redirect hop is a request of its own — so a
    Cloudflare Access hop is seen even when Access sends the browser straight
    on to its single identity provider (``origins.access_gated_via``).
    Best effort: a page without ``on``/``remove_listener`` (a test double)
    records nothing."""

    def __init__(self, page: Any) -> None:
        self.page = page
        self.urls: list[str] = []
        self._on = False

    def _record(self, request: Any) -> None:
        try:
            if not request.is_navigation_request():
                return
            if request.frame != self.page.main_frame:
                return
            self.urls.append(str(request.url or ""))
        except Exception:  # pylint: disable=broad-exception-caught
            return

    def start(self) -> NavTrail:
        """Listen from now on; idempotent."""
        if not self._on:
            with contextlib.suppress(Exception):
                self.page.on("request", self._record)
                self._on = True
        return self

    def stop(self) -> None:
        """Stop listening (the URLs seen so far stay)."""
        if self._on:
            with contextlib.suppress(Exception):
                self.page.remove_listener("request", self._record)
            self._on = False

    def __enter__(self) -> NavTrail:
        return self.start()

    def __exit__(self, *_exc: object) -> None:
        self.stop()


def _access_own_origins(item: SiteItem) -> list[str]:
    """The site's own origins for the Access rule: its fill and proof
    origins and the origins of its login and check URLs."""
    fill = getattr(item, "fill_origins", None) or []
    proof = getattr(item, "proof_origins", None) or []
    out = [str(o) for o in [*fill, *proof]]
    for url in (getattr(item, "login_url", ""), getattr(item, "check_url", "")):
        origin = url_origin(url, dev=True) if url else None
        if origin:
            out.append(origin)
    return out


def page_access_gated(page: Any, item: SiteItem, trail: list[str]) -> bool:
    """``origins.access_gated_via`` for `item` on `page` after `trail`."""
    return access_gated_via(
        trail, str(getattr(page, "url", "") or ""), _access_own_origins(item)
    )


class OriginViolation(RecipeError):
    """The page or form left the item's fill origins before a fill or submit."""

    code = "origin_violation"


class NeedsHuman(RecipeError):
    """A captcha / bot challenge or a missing second factor.

    ``challenge``: for a challenge, ``page_state.challenge_snapshot`` of the
    page it was SEEN on (the page may move on before the failure report)."""

    code = "needs_human"

    def __init__(
        self, detail: str, *, challenge: dict[str, str] | None = None, **kw: Any
    ) -> None:
        super().__init__(detail, **kw)
        self.challenge = challenge


class ExportFailed(RecipeError):
    """The login was proven, but the session could not be exported."""

    code = "export_failed"


class BundleExportError(ExportFailed):
    """A site's REQUIRED session storage could not be exported (CSCS: no
    server-validated ``waldur/auth/token`` on the portal): the bundle would not
    log anybody in, so none is handed out — never a silent empty export."""

    code = "bundle_export"

    def __init__(self, detail: str) -> None:
        super().__init__(detail, phase="bundle-export")


class LoginBlocked(AccessGated):
    """The login page answered HTTP 401/403 (``BLOCKED_STATUSES``): blocked
    from here — nothing is reserved (precheck) or typed."""

    code = "login_blocked"

    def __init__(self, status: int) -> None:
        super().__init__(
            f"the login page answers HTTP {status} — blocked from here, nothing typed"
        )


def raise_if_blocked(page: Any, resp: Any) -> None:
    """The login page answered 401/403 (``BLOCKED_STATUSES``): a bot
    challenge (Cloudflare's ``cf-mitigated: challenge``, "Just a moment", a
    captcha — ``challenge_reason``) is ``NeedsHuman`` (exit 4), anything else
    ``LoginBlocked``. Phase ``precheck``: nothing typed."""
    status = getattr(resp, "status", None)
    if status not in BLOCKED_STATUSES:
        return
    try:
        mitigated = str((resp.headers or {}).get("cf-mitigated") or "").lower()
    except Exception:  # pylint: disable=broad-exception-caught
        mitigated = ""
    reason = "captcha" if mitigated == "challenge" else challenge_reason(page)
    if reason:
        raise NeedsHuman(reason, phase="precheck")
    raise LoginBlocked(int(status))


def load_document(page: Any, url: str, *, wait_until: str = "domcontentloaded") -> Any:
    """``page.goto(url)`` that loads a DOCUMENT and returns its Response.

    Playwright answers None (no Response, status unknown) for a same-document
    navigation: a target that differs from the page's URL only after ``#`` —
    an SPA's hash route (``/#!/home`` after ``/#!/auth``, ``/web/#/home``
    twice). Then a 401/403 (``raise_if_blocked``) or a 5xx goes unseen. So on
    a None, unless the target is an ``about:`` page itself, the page goes to
    ``about:blank`` and loads `url` once more: a real document load with its
    own Response. A None on that second load stays None (status unknown).

    No URL comparison (a redirect or a router's rewrite would defeat it) and
    no ``page.reload()``: a reload repeats the page's own last request, which
    may be the login form's POST — outside the submit tripwire. Exceptions
    propagate."""
    resp = page.goto(url, wait_until=wait_until)
    if resp is not None or str(url).startswith("about:"):
        return resp
    page.goto("about:blank", wait_until=wait_until)
    return page.goto(url, wait_until=wait_until)


class AttemptController:
    """What a recipe tells the broker's limiter about its attempt.

    ``entered()`` right before the password first reaches the page (a crash
    from then on counts as post-submit); ``mark_submitted()`` right before the
    click/Enter that submits a secret, after the element was found — the
    marker decides the attempt's outcome. An exception from either aborts the
    recipe BEFORE that step. This base class does nothing (tests, callers
    without a limiter); the daemon passes one bound to its reservation.
    """

    submitted = False
    was_entered = False

    def entered(self) -> None:
        """The password is about to be typed."""
        self.was_entered = True

    def mark_submitted(self) -> None:
        """The submitting click/Enter is next."""
        self.submitted = True


# Stateless stand-in for helpers called without a controller (never marked).
class _NoAttempt(AttemptController):
    def entered(self) -> None:
        """Nothing to record."""

    def mark_submitted(self) -> None:
        """Nothing to record."""


NO_ATTEMPT: AttemptController = _NoAttempt()


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


def proof_origins(item: SiteItem, *, dev: bool = False) -> list[str]:
    """Where a proof may end: the check page's origin plus the item's
    ``agent_proof_origins``."""
    out = [o for o in [url_origin(check_page_url(item), dev=dev)] if o]
    return out + [o for o in item.proof_origins if o not in out]


# The answers of a logged-in proof.
VALID, INVALID, INDETERMINATE = "valid", "invalid", "indeterminate"
Proof = Callable[..., str]


def sentinel_proof(
    page: Any, item: SiteItem, *, wait_s: float = 8.0, dev: bool = False
) -> str:
    """The STRICT proof on the CURRENT page (the check page), tri-state.

    The page may still be booting (an SPA reads its token, asks its API, then
    renders) or reloading, so nothing negative is concluded early:
    ``await_sentinel`` polls every match (any visible one counts) on a proof
    origin for `wait_s`, then waits (bounded) for network idle and looks once
    more. Only then: sentinel shown → ``valid``;
    off the proof origins, or a login form showing → ``invalid``; a blank,
    unrendered page → ``indeterminate`` (it proves neither state); any other
    rendered page → ``invalid``.
    """
    origins = proof_origins(item, dev=dev)

    def on_origin(p: Any) -> bool:
        return url_origin(p.url, dev=dev) in origins

    def logged_out(p: Any) -> bool:  # an IdP login page: no need to wait
        return not on_origin(p) and password_shown(p)

    sentinel = str(item.logged_in_selector)
    if await_sentinel(page, sentinel, wait_s, where=on_origin, give_up=logged_out):
        # The sentinel may show while a redirect is still under way: re-check.
        return VALID if on_origin(page) else INVALID
    if not on_origin(page) or _visible(page, PASSWORD_SELECTOR) is not None:
        return INVALID
    return INDETERMINATE if page_blank(page) else INVALID


def logged_in(
    page: Any, item: SiteItem, *, wait_s: float = 8.0, dev: bool = False
) -> bool:
    """Positive success test on the CURRENT page (the check page).

    With a sentinel (the STRICT proof, ``sentinel_proof``): the page is on a
    proof origin (``proof_origins``) and the item's authenticated sentinel is
    visible. Without one: the OLD, weaker proof (``legacy_logged_in``) — kept
    only until the item gets a sentinel; a scheduled login never relies on it.
    """
    if not item.logged_in_selector:
        return legacy_logged_in(page, item, dev=dev)
    return sentinel_proof(page, item, wait_s=wait_s, dev=dev) == VALID


def legacy_logged_in(page: Any, item: SiteItem, *, dev: bool = False) -> bool:
    """The pre-WS1a proof of an item WITHOUT a sentinel: the item has a check
    URL and the page ended off every fill origin, with no bot interstitial and
    no visible password field. It also holds on an "Access denied" page — hence
    weak, never for a scheduled login, never enough to promote a site."""
    if not item.check_url:
        return False
    if not off_fill_origins(page.url, list(item.fill_origins), dev=dev):
        return False
    if interstitial_title(page):
        return False
    return _visible(page, PASSWORD_SELECTOR) is None


def generic_proof(
    page: Any, item: SiteItem, *, dev: bool = False, wait_s: float = 8.0
) -> str:
    """The generic proof on the loaded check page: tri-state with a sentinel
    (``sentinel_proof``), the old valid/invalid one without."""
    if item.logged_in_selector:
        return sentinel_proof(page, item, wait_s=wait_s, dev=dev)
    return VALID if legacy_logged_in(page, item, dev=dev) else INVALID


def _cscs_proof(
    page: Any, item: SiteItem, *, dev: bool = False, wait_s: float = 8.0
) -> str:
    """CSCS: the SERVER accepts the portal's stored token (``cscs_token_proof``:
    ``/api/users/me/`` 200 with an identity, asked from the portal page) — and,
    when the item has one, its DOM sentinel too (optional extra)."""
    answer = cscs_token_proof(page, wait_s=max(wait_s, 8.0))
    if answer != VALID or not item.logged_in_selector:
        return answer
    return generic_proof(page, item, dev=dev, wait_s=wait_s)


# Site-specific proofs (a recipe's own answer on the loaded check page);
# anything else uses `generic_proof`. Every entry here is a SERVER proof: it
# asks the site's API with the stored session (an authenticated call answered
# with the account's identity) instead of reading page content, so it is the
# STRICT proof on its own — a DOM sentinel is optional for these sites (WS2-cscs).
PROOFS: dict[str, Proof] = {"cscs": _cscs_proof}


def proof_for(site: str) -> Proof:
    """The proof of `site` (``PROOFS`` entry, else ``generic_proof``)."""
    return PROOFS.get(site, generic_proof)


def has_server_proof(site: str) -> bool:
    """`site` has a registered server proof (``PROOFS``): strict without a
    sentinel."""
    return site in PROOFS


def strict_proof(item: SiteItem) -> bool:
    """The item is proven by a sentinel or a registered server proof, not the
    old "off the fill origins" heuristic."""
    return bool(item.logged_in_selector) or has_server_proof(item.site)


# Why a proof answered what it did (``check_proof_reason``): the code goes
# into the failure detail and ``last_diag[site]["proof_reason"]``, so an
# overview tells the undecided cases apart. "" for a valid proof.
PROOF_REASONS: dict[str, str] = {
    # indeterminate
    "raised": "loading or reading the check page raised",
    "second-load-none": "the check page gave no HTTP response, even on a fresh load",
    "status-unknown": "the check page's HTTP status is unknown",
    "5xx": "the check page answered 5xx",
    "blank": "the check page stayed blank",
    "server-proof": "the site's server proof could not decide",
    # invalid
    "no-check-page": "the item has no check page",
    "4xx": "the check page answered 4xx",
    "not-logged-in": "the check page does not show a logged-in state",
}


def proof_reason_text(reason: str | None) -> str:
    """`reason` (a ``PROOF_REASONS`` code) for a failure detail:
    ``"<text> [<code>]"``; "" for no or an unknown code."""
    text = PROOF_REASONS.get(reason or "")
    return f"{text} [{reason}]" if text else ""


# One return per answer of the proof, in the order they are decided.
def check_proof_reason(  # pylint: disable=too-many-return-statements
    page: Any, item: SiteItem, *, dev: bool = False, wait_s: float = 8.0
) -> tuple[str, str]:
    """``check_proof`` with its reason: ``(answer, PROOF_REASONS code)``,
    the code "" for ``valid``."""
    url = check_page_url(item)
    if not url:
        return INVALID, "no-check-page"
    try:
        # a fresh document load: after an SPA login the page sits on the
        # same document, and a hash-only goto has no Response
        resp = load_document(page, url)
    except Exception:  # pylint: disable=broad-exception-caught
        return INDETERMINATE, "raised"
    try:
        page.wait_for_load_state("load", timeout=10_000)
    except Exception:  # pylint: disable=broad-exception-caught
        pass
    raw = getattr(resp, "status", None) if resp is not None else None
    status = raw if isinstance(raw, int) and not isinstance(raw, bool) else 0
    if status <= 0 and strict_proof(item):
        return INDETERMINATE, "second-load-none" if resp is None else "status-unknown"
    if status >= 500:
        return INDETERMINATE, "5xx"
    if status >= 400:
        return INVALID, "4xx"
    try:
        page.wait_for_timeout(1000)
        answer = proof_for(item.site)(page, item, dev=dev, wait_s=wait_s)
    except Exception:  # pylint: disable=broad-exception-caught
        return INDETERMINATE, "raised"
    if answer == VALID:
        return VALID, ""
    if answer == INVALID:
        return INVALID, "not-logged-in"
    # the generic proof is undecided only on a blank page (`sentinel_proof`)
    return INDETERMINATE, "server-proof" if has_server_proof(item.site) else "blank"


def check_proof(
    page: Any, item: SiteItem, *, dev: bool = False, wait_s: float = 8.0
) -> str:
    """Navigate to the check page and prove the login: ``valid``, ``invalid``
    or ``indeterminate``.

    The check page is loaded as a fresh document (``load_document``).
    Indeterminate: the page did not load, answered 5xx, the proof raised, or —
    for the strict proof — the status is unknown (no Response even on the
    fresh load, status 0). HTTP 4xx → invalid. No check page → invalid.
    ``check_proof_reason`` says why.
    """
    return check_proof_reason(page, item, dev=dev, wait_s=wait_s)[0]


def check_logged_in(
    page: Any, item: SiteItem, *, dev: bool = False, wait_s: float = 8.0
) -> bool:
    """``check_proof(...) == "valid"``."""
    return check_proof(page, item, dev=dev, wait_s=wait_s) == VALID


# ---------------------------------------------------------------------------
# Session refresh before export (storage-token SPAs)
# ---------------------------------------------------------------------------
# A token kept in localStorage expires on its own schedule (NPM: 1 day). A
# reused broker profile whose token is nearly expired would hand the shared
# browser a session that dies within hours — and the next check would cost a
# password submit. So, on a reuse, a site's refresher renews the token through
# the app's own authenticated endpoint first. Refreshers are code (a broker
# release, like recipes); the vault only picks one by name.
#
# Answers: "fresh" (enough time left, nothing done), "refreshed" (renewed,
# written back and read back), "rejected" (the server refused the token: the
# profile is not reusable, the key was dropped so the login form shows),
# "failed" (could not tell / could not renew; the session as it is), "none"
# (the item has no refresher).
REFRESH_FRESH, REFRESH_DONE = "fresh", "refreshed"
REFRESH_REJECTED, REFRESH_FAILED, REFRESH_NONE = "rejected", "failed", "none"
# Renew when less than this is left.
REFRESH_MIN_LEFT_S = 12 * 3600

# Nginx Proxy Manager 2.x keeps `[{token, expires}, ...]` under
# `authentications` (the last entry is the active one; `expires` an ISO date)
# and renews with an authenticated `GET /api/tokens` (its own timer does the
# same every 5 minutes, but only in a tab open that long). The token never
# leaves the page: only a state and the seconds left come back. Bounded: the
# fetch is aborted after REFRESH_FETCH_S, the whole script gives up after
# REFRESH_TOTAL_S (a hang must never look like a failed login). Only a 401
# drops the stored token; a 403 (a WAF, Cloudflare Access) says nothing about
# it. The entry's other fields are kept.
REFRESH_FETCH_S = 10
REFRESH_TOTAL_S = 15
_NPM_REFRESH_JS = """async ([key, minLeftS, fetchS, totalS]) => {
  const expiry = v => {
    if (typeof v === 'number') return v < 1e12 ? v * 1000 : v;
    const t = Date.parse(String(v || ''));
    return Number.isNaN(t) ? null : t;
  };
  const work = async () => {
    let list;
    try { list = JSON.parse(localStorage.getItem(key) || 'null'); }
    catch (e) { return {state: 'failed', why: 'unparsable'}; }
    if (!Array.isArray(list) || !list.length) return {state: 'failed', why: 'no token'};
    const last = list[list.length - 1] || {};
    const exp = expiry(last.expires);
    if (typeof last.token !== 'string' || exp === null)
      return {state: 'failed', why: 'malformed'};
    const left = Math.round((exp - Date.now()) / 1000);
    if (left > minLeftS) return {state: 'fresh', left_s: left};
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), fetchS * 1000);
    let r;
    try {
      r = await fetch('/api/tokens', {headers: {Authorization: 'Bearer ' + last.token},
        cache: 'no-store', credentials: 'same-origin', redirect: 'error',
        signal: ctl.signal});
    } catch (e) {
      return {state: 'failed', why: e && e.name === 'AbortError' ? 'timeout' : 'network',
              left_s: left};
    } finally { clearTimeout(timer); }
    if (r.status === 401) {
      localStorage.removeItem(key);
      return {state: 'rejected', status: r.status};
    }
    if (!r.ok) return {state: 'failed', why: 'status', status: r.status, left_s: left};
    let body;
    try { body = await r.json(); } catch (e) { return {state: 'failed', why: 'body'}; }
    const nexp = body ? expiry(body.expires) : null;
    if (!body || typeof body.token !== 'string' || !body.token || nexp === null)
      return {state: 'failed', why: 'body', left_s: left};
    list[list.length - 1] = {...last, token: body.token, expires: body.expires};
    localStorage.setItem(key, JSON.stringify(list));
    let back;
    try { back = JSON.parse(localStorage.getItem(key) || 'null'); } catch (e) { back = null; }
    const ok = Array.isArray(back) && back.length === list.length
      && back[back.length - 1].token === body.token;
    return ok ? {state: 'refreshed', left_s: Math.round((nexp - Date.now()) / 1000)}
              : {state: 'failed', why: 'read-back'};
  };
  let timer;
  const cap = new Promise(res => {
    timer = setTimeout(() => res({state: 'failed', why: 'deadline'}), totalS * 1000);
  });
  try { return await Promise.race([work(), cap]); } finally { clearTimeout(timer); }
}"""
# The seconds left on the last stored NPM token (null: none / unreadable);
# never the token itself.
NPM_TOKEN_LEFT_JS = """key => {
  try {
    const l = JSON.parse(localStorage.getItem(key) || 'null');
    if (!Array.isArray(l) || !l.length || !l[l.length - 1]) return null;
    const v = l[l.length - 1].expires;
    const t = typeof v === 'number' ? (v < 1e12 ? v * 1000 : v) : Date.parse(String(v || ''));
    return Number.isNaN(t) ? null : Math.round((t - Date.now()) / 1000);
  } catch (e) { return null; }
}"""
NPM_TOKEN_KEY = "authentications"


def npm_jwt_refresh(
    page: Any,
    item: SiteItem,
    *,
    dev: bool = False,
    min_left_s: float = REFRESH_MIN_LEFT_S,
) -> str:
    """NPM: renew the JWT in localStorage when less than `min_left_s` is left
    (see ``_NPM_REFRESH_JS``). Runs only on an origin whose storage the item
    exports with the ``authentications`` key — never elsewhere."""
    origin = url_origin(page.url, dev=dev)
    if origin is None or NPM_TOKEN_KEY not in item.storage_keys.get(origin, []):
        return REFRESH_FAILED
    try:
        got = page.evaluate(
            _NPM_REFRESH_JS,
            [NPM_TOKEN_KEY, int(min_left_s), REFRESH_FETCH_S, REFRESH_TOTAL_S],
        )
    except Exception:  # pylint: disable=broad-exception-caught
        return REFRESH_FAILED
    state = got.get("state") if isinstance(got, dict) else None
    ok = (REFRESH_FRESH, REFRESH_DONE, REFRESH_REJECTED, REFRESH_FAILED)
    return state if state in ok else REFRESH_FAILED


Refresher = Callable[..., str]
# Refresher name -> code. An item picks one with `agent_session_refresh`
# (validated against this table; "none" switches a default off).
SESSION_REFRESHERS: dict[str, Refresher] = {"npm-jwt": npm_jwt_refresh}
# Built-in choices by site id (an item's `agent_session_refresh` overrides).
DEFAULT_SESSION_REFRESH = {
    "npm-nixos": "npm-jwt",
    "npm-raspi": "npm-jwt",
    "cscs": "waldur-token",  # registered below, next to the CSCS proof
}


def session_refresh_name(item: SiteItem) -> str | None:
    """The refresher an item uses: its own field, else the built-in default
    for its site id; None when it has none ("none" included)."""
    chosen = item.session_refresh
    name = DEFAULT_SESSION_REFRESH.get(item.site) if chosen is None else chosen
    return name if name in SESSION_REFRESHERS else None


def refresh_session(page: Any, item: SiteItem, *, dev: bool = False) -> str:
    """Run the item's refresher on the CURRENT page (the proven check page);
    ``none`` without one, ``failed`` when it raises."""
    name = session_refresh_name(item)
    if name is None:
        return REFRESH_NONE
    try:
        return SESSION_REFRESHERS[name](page, item, dev=dev)
    except Exception:  # pylint: disable=broad-exception-caught
        return REFRESH_FAILED


# Refresher name -> (storage key, JS returning the seconds left on the stored
# token): the CLIENT reads it in the shared browser to know when to ask the
# broker for a `refresh_only` re-export. Never the token itself.
SESSION_LEFT_JS: dict[str, tuple[str, str]] = {
    "npm-jwt": (NPM_TOKEN_KEY, NPM_TOKEN_LEFT_JS)
}


def session_left_s(page: Any, name: str) -> int | None:
    """Seconds left on the token refresher `name` manages, read on the
    CURRENT page (its storage origin); None when unknown."""
    spec = SESSION_LEFT_JS.get(name)
    if spec is None:
        return None
    try:
        left = page.evaluate(spec[1], spec[0])
    except Exception:  # pylint: disable=broad-exception-caught
        return None
    if isinstance(left, bool) or not isinstance(left, (int, float)):
        return None
    return int(left)


# A freshly shown password page may still re-render (and clear inputs) while its
# JS hydrates; give it this long before typing, then verify the value stuck.
HYDRATE_S = 1.5


def _fill_password(  # pylint: disable=too-many-arguments
    page: Any,
    pw_field: Any,
    secret: Secret,
    allowed: list[str],
    *,
    dev: bool,
    attempt: AttemptController | None = None,
    locate: Callable[[Any], Any] | None = None,
    sent: Callable[[], bool] | None = None,
) -> Any:
    """Type the password and make sure the field KEEPS it; returns the field used.

    One retry types it key by key into the (re-located) visible password field;
    a field that still drops the value fails BEFORE anything is submitted.
    `attempt.entered()` runs right before the first character is typed.
    `locate` re-locates the field (default: the login password field; a
    username-only login: ``_credential_field``, never another field).
    `sent` (a username-only login: the tripwire's ``secret_sent``): the page
    sent the value by itself — it is not checked or typed again.
    """
    find = locate or _login_password
    went = sent or (lambda: False)
    page.wait_for_timeout(HYDRATE_S * 1000)
    _check_challenge(page, submitted=False)
    pw_field = find(page) or pw_field
    _guard(page, pw_field, allowed, dev=dev)
    (attempt or NO_ATTEMPT).entered()
    pw_field.fill(secret.password)
    page.wait_for_timeout(500)
    if went() or _holds(_field_value(pw_field), secret):
        return pw_field
    pw_field = find(page) or pw_field
    _guard(page, pw_field, allowed, dev=dev)
    pw_field.fill("")
    pw_field.press_sequentially(secret.password, delay=60)
    page.wait_for_timeout(500)
    if not went() and not _holds(_field_value(pw_field), secret):
        raise LoginFailed("the password field did not keep the typed value")
    return pw_field


def _compact(value: str) -> str:
    return re.sub(r"[\s-]+", "", value)


def _holds(value: str | None, secret: Secret) -> bool:
    """The field `value` is exactly the typed secret — for a username-only
    login up to the spaces / hyphens a page inserts into an account number
    (``1234 5678 …``)."""
    if value is None:
        return False
    if secret.mode == USERNAME_ONLY_MODE:
        return _compact(value) == _compact(secret.password)
    return value == secret.password


def _field_value(field: Any) -> str | None:
    try:
        return str(field.input_value())
    except Exception:  # pylint: disable=broad-exception-caught
        return None


def _challenge_error(
    detail: dict[str, str], snapshot: dict[str, str], *, submitted: bool
) -> NeedsHuman:
    """``NeedsHuman`` naming the challenge kind and the page it was seen on
    (origin + path only, never page text or a query)."""
    text = detail["reason"]
    if detail["kind"] != "blocked":
        text += f" ({detail['kind']} on {snapshot.get('url') or '?'})"
    return NeedsHuman(text, submitted=submitted, challenge=snapshot)


def _check_challenge(page: Any, *, submitted: bool) -> None:
    """Raise ``NeedsHuman`` when a challenge shows. A confirmed one (checkbox,
    challenge popup, block page) raises at once; one that may clear by itself
    (``PROCESSING_CHALLENGE_KINDS``: Turnstile, "Just a moment", an
    unrecognised provider frame) is watched up to ``CHALLENGE_GRACE_S`` first,
    touching nothing. A page that cannot be inspected (``unknown``, e.g.
    mid-navigation) is looked at again for as long; still uninspectable, the
    login ends here (``LoginFailed``) — the caller types and clicks only
    after a definite "no challenge". The post-submit settle loops use
    ``ChallengeWatch``."""
    detail = challenge_detail(page)
    if detail and detail["kind"] in PROCESSING_CHALLENGE_KINDS:
        deadline = time.monotonic() + CHALLENGE_GRACE_S
        while (
            detail
            and detail["kind"] in PROCESSING_CHALLENGE_KINDS
            and time.monotonic() < deadline
        ):
            page.wait_for_timeout(500)
            detail = challenge_detail(page)
    if detail and detail["kind"] == "unknown":
        raise LoginFailed(
            "the page could not be checked for a bot challenge — nothing typed",
            submitted=submitted,
        )
    if detail:
        snapshot = challenge_snapshot(page, detail["kind"])
        raise _challenge_error(detail, snapshot, submitted=submitted)


def _document_key(page: Any) -> tuple[str, Any]:
    """Identifies the page's current document: its URL plus the document's
    ``performance.timeOrigin`` (a form POST that answers on the same URL is a
    new document too). Unreadable (mid-navigation) → None for the second."""
    try:
        origin = page.evaluate("() => performance.timeOrigin")
    except Exception:  # pylint: disable=broad-exception-caught
        origin = None
    return (str(page.url), origin)


class ChallengeWatch:
    """The post-submit challenge check of a settle loop, with a grace.

    A challenge (``page_state.challenge_detail``; invisible widgets never
    count) must stay ``grace_s`` on ONE document before it is ``NeedsHuman``;
    every navigation, and every check that sees none, starts over. A
    fraud-protection page (kind ``blocked``) needs no grace. A page that
    cannot be inspected (``unknown``) keeps the state as it is and counts as
    ``pending`` for that check: the loop acts on nothing it could not see.
    Where the challenge was seen is snapshotted at first sight on that
    document (``challenge_snapshot``) and travels with the error. Nothing is
    ever clicked: the page either clears it by itself or a human must."""

    def __init__(
        self,
        *,
        grace_s: float | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.grace_s = CHALLENGE_GRACE_S if grace_s is None else grace_s
        self._clock = clock
        self._doc: tuple[str, Any] | None = None
        self._since: float | None = None
        self._detail: dict[str, str] | None = None
        self._unknown = False
        self.snapshot: dict[str, str] | None = None

    def check(self, page: Any, *, submitted: bool = True) -> None:
        """One look at `page`; raises ``NeedsHuman`` once the grace is over."""
        detail = challenge_detail(page)
        self._unknown = detail is not None and detail["kind"] == "unknown"
        if self._unknown:
            return
        if detail is None:
            self._since = self._doc = self._detail = None
            return
        if detail["kind"] == "blocked":
            snapshot = challenge_snapshot(page, detail["kind"])
            raise _challenge_error(detail, snapshot, submitted=submitted)
        doc = _document_key(page)
        now = self._clock()
        # A new document or another kind of challenge starts over (timer and
        # snapshot): the report names what was seen, where.
        kind_changed = (self._detail or {}).get("kind") != detail["kind"]
        if self._since is None or doc != self._doc or kind_changed:
            self._doc, self._since = doc, now
            self.snapshot = challenge_snapshot(page, detail["kind"])
        self._detail = detail
        if now - self._since >= self.grace_s and self.snapshot:
            raise _challenge_error(detail, self.snapshot, submitted=submitted)

    def clear(self, page: Any) -> bool:
        """``check`` and True when nothing is pending: safe to act now."""
        self.check(page)
        return not self.pending

    @property
    def pending(self) -> bool:
        """The latest check saw a challenge (still within its grace) or could
        not inspect the page: act on nothing this round."""
        return self._unknown or self._since is not None

    def final(self, page: Any, *, submitted: bool = True) -> None:
        """For the end of a settle loop: ONE fresh look at `page` (never the
        cached state); a challenge that shows now needs a human, whatever is
        left of its grace. Nothing showing (or not inspectable): returns."""
        grace, self.grace_s = self.grace_s, 0.0
        try:
            self.check(page, submitted=submitted)
        finally:
            self.grace_s = grace


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
    attempt: AttemptController | None = None,
    tripwire: SubmitTripwire | None = None,
    watch: ChallengeWatch | None = None,
) -> bool:
    """Type the TOTP code and submit it like the password
    (``_submit_password``: Enter only on a login default button, else the
    identified button — "Verify", never a "Resend code" default — under the
    tripwire with the OTP form's own button pairs). A page that submits
    itself once the code is complete (GitHub) is not pressed again: when the
    field is gone or the URL changed after the fill, the submit is marked and
    the caller's settle loop decides.

    With a `watch`, the page is checked for a challenge right before the
    first click/keystroke (after the code wait): one showing → False,
    nothing selected or typed, the caller's loop comes back. True = the code
    went in."""
    if not secret.totp_seed:
        raise NeedsHuman("otp required but the item has no TOTP seed", submitted=True)
    code = fresh_totp(secret.totp_seed)
    if not code:
        raise LoginFailed("could not produce a TOTP code", submitted=True)
    if watch is not None and not watch.clear(page):
        return False
    otp_field = _otp_field(page)  # re-query: the wait may have taken s
    if otp_field is None:
        raise LoginFailed("the OTP field disappeared", submitted=True)
    _select_authenticator(page, otp_label)
    try:
        _guard(page, otp_field, allowed, dev=dev)
    except OriginViolation as exc:
        exc.submitted = True
        raise
    before = page.url
    otp_field.fill(code)
    page.wait_for_timeout(OTP_SELF_SUBMIT_MS)
    if _submitted_itself(page, otp_field, before):
        (attempt or NO_ATTEMPT).mark_submitted()
        return True
    try:
        _submit_password(
            page, otp_field, allowed, dev=dev, attempt=attempt, tripwire=tripwire
        )
    except RecipeError as exc:
        if isinstance(exc, SubmitUnidentified) and _submitted_itself(
            page, otp_field, before
        ):  # it went on its own while the buttons were read
            (attempt or NO_ATTEMPT).mark_submitted()
            return True
        exc.submitted = True  # the password went before the code
        raise
    return True


# How long a page may take to submit a complete OTP code by itself.
OTP_SELF_SUBMIT_MS = 400


def _submitted_itself(page: Any, field: Any, url_before: str) -> bool:
    """The page moved on after the fill without a submit of ours: the URL
    changed or the field is gone."""
    return page.url != url_before or not _still_there(field)


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


def _field_name(field: Any) -> str:
    """The `name` attribute of a field ("" when unreadable)."""
    try:
        return str(field.get_attribute("name") or "")
    except Exception:  # pylint: disable=broad-exception-caught
        return ""


class SubmitTripwire:  # pylint: disable=too-many-instance-attributes  # screen + proof state
    """Screens the requests of a login while the broker submits it (installed
    by ``generic_login`` before its first submit). A request to a fill origin
    that names a secondary form action (``login_form.secondary_hit``: a
    "forgot password" button's (name, value), ``forgot_password=``,
    ``action=reset``, a ``/register`` URL …) is aborted inside the browser;
    ``check`` then raises ``SecondaryActionBlocked``.

    What is screened (the route matches only fill-origin URLs; the browser
    CONTEXT is routed, so a form posting into a popup counts too):
    * a FORM NAVIGATION (a navigation with a body, or a GET navigation with a
      query — its URL path only on the first hop), until the login went out;
    * any request that CARRIES a shielded key (the username / password /
      OTP field's name) — the login itself, whatever transport.
    Once a request carrying a shielded key went through, only such requests
    are screened: the app's own traffic after the login (``POST
    /api/push/register``, ``{"e": {"recovery": …}}``) is none of the
    tripwire's business. Requests a service worker makes itself are not
    routable — hence the worker rule of ``never_sent``. A tripped tripwire
    stays installed until the context closes.

    The broker's button choice (``pick_submit_button``) is the first line of
    defence; this one holds when a page's buttons fool it. A body that cannot
    be read passes. ``never_sent`` — the attempt may count as not submitted —
    needs PROOF that nothing left: armed before the password is typed
    (``arm``), no service worker of a fill origin running then, and every
    request that could carry it (a body, post data, a query or an
    ``Authorization`` header) the whole context issued since then — any
    origin, popups included — is one this tripwire PROVABLY aborted (by
    request identity)."""

    def __init__(
        self,
        page: Any,
        allowed: list[str],
        *,
        dev: bool,
        attempt: AttemptController | None = None,
    ) -> None:
        self.page = page
        self.allowed = list(allowed)
        self.dev = dev
        self.protect: set[str] = set()
        # The keys of the fields that hold the SECRET (the password field, a
        # username-only login's field): once armed, a request carrying one is
        # the secret leaving — the attempt is marked submitted before it goes
        # (a page that submits by itself while the broker types), and a
        # marker that cannot be written stops it (``marker_failed``).
        self.secret_keys: set[str] = set()
        # the secret itself: a request counts only when it carries ALL of it
        # (an empty or partial check request is not the submit)
        self._secret: Secret | None = None
        self.attempt = attempt
        self.marker_failed = False
        self._carries_secret = False
        # (name, value) of the CURRENT step's secondary submit buttons
        self.button_pairs: set[tuple[str, str]] = set()
        self.tripped: str | None = None
        # identities of the requests that could carry the password since
        # `arm`: seen by the context / provably aborted here
        self.ids: dict[str, set[Any]] = {"seen": set(), "aborted": set()}
        self.proof = {
            "armed": False,
            "workers": False,
            "login_sent": False,
            "secret_sent": False,
        }

    def _match(self, url: str) -> bool:
        return origin_allowed(url, self.allowed, dev=self.dev)

    @staticmethod
    def _identity(req: Any) -> Any:
        return getattr(req, "_guid", None) or id(req)

    @staticmethod
    def _header(req: Any, name: str) -> str:
        try:
            return str((req.headers or {}).get(name) or "")
        except Exception:  # pylint: disable=broad-exception-caught
            return ""

    @classmethod
    def _carrier(cls, req: Any) -> bool:
        """`req` could carry a typed secret: any method but GET/HEAD, post
        data, a query, or an ``Authorization`` header (HTTP Basic logins)."""
        if str(req.method).upper() not in ("GET", "HEAD"):
            return True
        try:
            if req.post_data_buffer:
                return True
        except Exception:  # pylint: disable=broad-exception-caught
            return True
        if cls._header(req, "authorization"):
            return True
        return bool(urllib.parse.urlsplit(str(req.url)).query)

    @staticmethod
    def _navigation(req: Any) -> bool:
        try:
            return bool(req.is_navigation_request())
        except Exception:  # pylint: disable=broad-exception-caught
            return True  # cannot tell: screen it

    def _seen(self, req: Any) -> None:
        with contextlib.suppress(Exception):
            if self.proof["armed"] and self._carrier(req):
                self.ids["seen"].add(self._identity(req))

    def _verdict(self, req: Any) -> tuple[str | None, bool]:
        """(what makes `req` a secondary action or None, whether it carries
        a shielded key) — see the class docstring for what is screened.
        Sets ``_carries_secret`` (a ``secret_keys`` key in it) as it goes."""
        self._carries_secret = False
        method = str(req.method).upper()
        nav = self._navigation(req)
        query = urllib.parse.urlsplit(str(req.url)).query
        if method in ("GET", "HEAD"):
            pairs = urllib.parse.parse_qsl(query, keep_blank_values=True)
            every = pairs
            form_nav = nav and bool(query)
            first = getattr(req, "redirected_from", None) is None
            path_url = str(req.url) if first else ""
        else:
            raw = req.post_data_buffer
            body = raw.decode("utf-8", "replace") if raw else ""
            ctype = self._header(req, "content-type")
            pairs = body_pairs(body, ctype)
            every = body_pairs(body, ctype, nested=True)
            form_nav = nav
            path_url = str(req.url)
        shield = {p.lower() for p in self.protect}
        shielded = any(k.lower() in shield for k, _v in every)
        keys = {k.lower() for k in self.secret_keys}
        held = self._secret
        self._carries_secret = held is not None and any(
            k.lower() in keys and _holds(v, held) for k, v in every
        )
        if not shielded and (self.proof["login_sent"] or not form_nav):
            return None, False
        hit = secondary_hit(
            path_url, pairs, protect=self.protect, button_pairs=self.button_pairs
        )
        return hit, shielded

    def _handle(self, route: Any) -> None:
        try:
            hit, shielded = self._verdict(route.request)
        except Exception:  # pylint: disable=broad-exception-caught
            hit, shielded = None, False  # unreadable: let it pass (counted as seen)
            self._carries_secret = False
        if not hit and self._carries_secret and self.proof["armed"]:
            if not self._mark_secret_sent():
                self._abort(route)  # no marker on record: it must not go
                return
        if not hit:
            with contextlib.suppress(Exception):
                route.continue_()
            if shielded:
                self.proof["login_sent"] = True
            return
        self.tripped = self.tripped or hit
        self._abort(route)

    def _mark_secret_sent(self) -> bool:
        """The secret is leaving: mark the attempt submitted first (idempotent
        in the limiter). False when the marker could not be written."""
        try:
            if self.attempt is not None and not self.attempt.submitted:
                self.attempt.mark_submitted()
        except Exception:  # pylint: disable=broad-exception-caught
            self.marker_failed = True
            return False
        self.proof["secret_sent"] = True
        return True

    def _abort(self, route: Any) -> None:
        """Abort `route` in the browser; counted when provably stopped."""
        try:
            route.abort("blockedbyclient")
        except Exception:  # pylint: disable=broad-exception-caught
            return  # not provably stopped: never counted as aborted
        if self.proof["armed"]:
            self.ids["aborted"].add(self._identity(route.request))

    def __enter__(self) -> SubmitTripwire:
        # Context scope: popups (a form with target=_blank) are screened too;
        # the URL predicate keeps every other origin off the route.
        context = self.page.context
        context.on("request", self._seen)
        context.route(self._match, self._handle)
        return self

    def __exit__(self, *_exc: object) -> None:
        if self.tripped:
            return  # keeps screening until the context closes
        context = self.page.context
        with contextlib.suppress(Exception):  # the context may be gone
            context.unroute(self._match, self._handle)
        with contextlib.suppress(Exception):
            context.remove_listener("request", self._seen)

    @property
    def secret_sent(self) -> bool:
        """A request carrying the secret went out (the attempt is marked)."""
        return bool(self.proof["secret_sent"])

    def secret_fields(self, *fields: Any, secret: Secret | None = None) -> None:
        """These fields hold `secret`: shielded, and a request carrying one of
        their keys WITH the whole secret as its value marks the attempt
        submitted before it goes."""
        if secret is not None:
            self._secret = secret
        self.shield(*fields)
        self.secret_keys.update(
            n for f in fields if f is not None if (n := _field_name(f))
        )

    def shield(self, *fields: Any) -> None:
        """Never read the values of these fields' keys (username, password,
        OTP) for the secondary-action verdict; a request carrying one of them
        is the login itself. (``secret_fields`` compares the secret field's
        value with the secret, only to mark the attempt submitted.)"""
        self.protect.update(n for f in fields if f is not None if (n := _field_name(f)))

    def step(self, descs: list[dict[str, Any]], *fields: Any) -> None:
        """A new submit step: ITS form's secondary (name, value) pairs replace
        the last step's (page 1's names must not judge page 2), and its
        fields are shielded."""
        self.button_pairs = secondary_pairs(descs)
        self.shield(*fields)

    def arm(self) -> None:
        """The password is about to be typed: from now on every request that
        could carry it is recorded, and a running service worker of a fill
        origin (unscreened) rules out ``never_sent``."""
        self.ids = {"seen": set(), "aborted": set()}
        self.proof["armed"] = True
        try:
            workers = list(self.page.context.service_workers)
            self.proof["workers"] = any(self._match(str(w.url)) for w in workers)
        except Exception:  # pylint: disable=broad-exception-caught
            self.proof["workers"] = True  # cannot tell: no proof

    @property
    def never_sent(self) -> bool:
        """Provably nothing that could carry the password left the browser."""
        return (
            bool(self.proof["armed"])
            and not self.proof["workers"]
            and self.ids["seen"] <= self.ids["aborted"]
        )

    def check(self) -> None:
        """Raise ``SecondaryActionBlocked`` once a request was aborted, and
        ``LoginFailed`` once the secret was stopped for want of a marker."""
        if self.marker_failed:
            raise LoginFailed(
                "the submit marker could not be recorded — the login request "
                "was stopped in the browser"
            )
        if self.tripped:
            raise SecondaryActionBlocked(
                f"a submit named a secondary form action ({self.tripped}) — "
                "aborted in the browser before it reached the site",
                never_sent=self.never_sent,
            )


def _guarded_button(page: Any, button: Any, allowed: list[str], *, dev: bool) -> str:
    """Why `button` may not be clicked to submit (its frame, its own
    ``formaction`` or the page off the fill origins), or ""."""
    frame_url = _frame_url(button)
    if not origin_allowed(frame_url, allowed, dev=dev):
        return "the submit button is not on a fill origin"
    own_action = button.get_attribute("formaction")
    if own_action and not form_action_allowed(frame_url, own_action, allowed, dev=dev):
        return "submit button posts off the fill origins"
    if not origin_allowed(page.url, allowed, dev=dev):
        return "page is not on a fill origin"
    return ""


def _primary_index(descs: list[dict[str, Any]]) -> int | None:
    """The first visible, enabled submit button that is not secondary."""
    for i, desc in enumerate(descs):
        if desc.get("visible") and not desc.get("disabled"):
            if not secondary_button_like(desc):
                return i
    return None


def _formless_fallback(field: Any) -> Any:
    """The first visible submit button of the field's form (no form: its
    document), only when it can be read and is not secondary; else None."""
    try:
        handle = field.evaluate_handle(SUBMIT_BUTTON_JS)
        button = handle.as_element() if handle is not None else None
    except Exception:  # pylint: disable=broad-exception-caught
        return None
    descs = describe_buttons([button]) if button is not None else None
    if not descs or secondary_button_like(descs[0]):
        return None
    return button


def _submit_identifier(
    page: Any,
    user_field: Any,
    allowed: list[str],
    *,
    dev: bool,
    tripwire: SubmitTripwire | None = None,
) -> None:
    """Submit the username step — like the password, never by a guess: the
    form's submit buttons are read first (``read_submit_buttons``); unreadable
    → ``SubmitUnidentified`` (nothing submitted). A secondary default button
    (``pick_submit_button``) → the login button is clicked instead of Enter,
    or, with none showing, ``SubmitUnidentified``. Otherwise Enter; if neither
    the URL nor the DOM changes within ``SUBMIT_CHANGE_S``, click the form's
    first visible login button (re-guarded: the button's own ``formaction``
    must stay on a fill origin too; a form-less field only a readable,
    non-secondary one).

    The click is a fallback only. A disabled button means the page is still
    busy with the Enter (Zoho turns "Next" into a disabled spinner during its
    lookup) and is left alone; a click that cannot happen within
    ``FALLBACK_CLICK_TIMEOUT_S`` is given up. Either way the caller's wait
    for the password field decides."""
    read = read_submit_buttons(user_field)
    if read is None:
        raise SubmitUnidentified(
            "the username step's submit buttons could not be read — nothing submitted"
        )
    buttons, descs = read
    if tripwire is not None:
        tripwire.step(descs, user_field)
    choice = pick_submit_button(descs)
    if choice is not None and choice < 0:
        raise SubmitUnidentified(
            "Enter would press the username form's non-login default button and "
            "no login button is showing"
        )
    if choice is not None:
        problem = _guarded_button(page, buttons[choice], allowed, dev=dev)
        if problem:
            raise OriginViolation(problem)
        _click_on_fill_origin(page, buttons[choice], allowed, dev=dev)
        return
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
    primary = _primary_index(descs)
    if descs:
        button = buttons[primary] if primary is not None else None
    else:
        button = _formless_fallback(user_field)
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


def _unsent(
    page: Any, field: Any, secret: Secret | None, allowed: list[str], *, dev: bool
) -> bool:
    """True only when the typed password provably was NOT submitted: the page
    is still on a fill origin and `field` still holds exactly the password."""
    if secret is None or not origin_allowed(page.url, allowed, dev=dev):
        return False
    return _holds(_field_value(field), secret)


def _sent_by_itself(tripwire: SubmitTripwire | None, secret: Secret | None) -> bool:
    """A username-only login whose page sent the account number by itself
    while it was typed (the tripwire marked the attempt first): never a
    second submit. Password logins keep their submit — a page may post the
    password field in a check request before its form is sent."""
    return (
        tripwire is not None
        and tripwire.secret_sent
        and secret is not None
        and secret.mode == USERNAME_ONLY_MODE
    )


def _submit_password(  # pylint: disable=too-many-arguments
    page: Any,
    pw_field: Any,
    allowed: list[str],
    *,
    dev: bool,
    attempt: AttemptController | None = None,
    secret: Secret | None = None,
    tripwire: SubmitTripwire | None = None,
) -> None:
    """Submit the typed password — never by a guess. The form's submit
    buttons are read first (``read_submit_buttons``): when they cannot be
    read, nothing is submitted (``SubmitUnidentified``, before the submit
    marker). Enter in the field only when the form has no submit button (a
    form-less field: the page's script handles Enter) or its default button
    is a login button; when Enter would fire a button that does something
    else (``pick_submit_button``: a "forgot password" default button,
    Calibre-Web Automated 2026-10-08) the form's login button is clicked
    instead; with none showing, ``SubmitUnidentified``. Guarded like every
    submit: the field, the button's own frame and its ``formaction`` stay on
    a fill origin. ``attempt.mark_submitted()`` runs only right before the
    Enter or the click on the identified button. A username-only login the
    page already sent by itself is not submitted again (``_sent_by_itself``)."""
    if _sent_by_itself(tripwire, secret):
        return
    _guard(page, pw_field, allowed, dev=dev)
    read = read_submit_buttons(pw_field)
    if read is None:
        if _sent_by_itself(tripwire, secret):
            return
        raise SubmitUnidentified(
            "the login form's submit buttons could not be read — nothing submitted",
            unsent=_unsent(page, pw_field, secret, allowed, dev=dev),
        )
    buttons, descs = read
    if tripwire is not None:
        tripwire.step(descs, pw_field)
    if _sent_by_itself(tripwire, secret):
        return
    choice = pick_submit_button(descs)
    if choice is None:
        (attempt or NO_ATTEMPT).mark_submitted()
        pw_field.press("Enter")
        return
    if choice < 0:
        raise SubmitUnidentified(
            "Enter would press the form's non-login default button and no login"
            " button is showing",
            unsent=_unsent(page, pw_field, secret, allowed, dev=dev),
        )
    button = buttons[choice]
    problem = _guarded_button(page, button, allowed, dev=dev)
    if problem:
        raise OriginViolation(
            problem, unsent=_unsent(page, pw_field, secret, allowed, dev=dev)
        )
    (attempt or NO_ATTEMPT).mark_submitted()
    _click_on_fill_origin(page, button, allowed, dev=dev)


# The visible label of a checkbox (its first `labels` entry, else the label
# around it), or null.
_BOX_LABEL_JS = """b => {
  const vis = el => !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length);
  const all = Array.from(b.labels || []);
  const wrap = b.closest('label');
  if (wrap && !all.includes(wrap)) all.push(wrap);
  return all.find(vis) || null;
}"""


def _tick_remember_me(
    page: Any, pw_field: Any, allowed: list[str], *, dev: bool
) -> bool:
    """Tick the login form's "remember me" checkbox when it has one
    (``login_form.pick_remember_me``), before the password is typed: apps
    that bind a session to IP + User-Agent keep an injected session only
    through their remember-me cookie. Best effort — only on a fill origin
    (an ``OriginViolation`` propagates); True iff the box ends up ticked."""
    try:
        descs = pw_field.evaluate(REMEMBER_BOXES_JS)
        handle = pw_field.evaluate_handle(REMEMBER_BOX_HANDLES_JS)
        props = handle.get_properties()
        boxes = [
            v.as_element()
            for _, v in sorted(
                ((int(k), v) for k, v in props.items() if str(k).isdigit()),
                key=lambda kv: kv[0],
            )
        ]
    except Exception:  # pylint: disable=broad-exception-caught
        return False
    if not isinstance(descs, list) or len(descs) != len(boxes):
        return False
    idx = pick_remember_me([d if isinstance(d, dict) else {} for d in descs])
    if idx is None or boxes[idx] is None:
        return False
    box = boxes[idx]
    _guard(page, box, allowed, dev=dev)
    try:
        if not box.is_checked():
            if descs[idx].get("visible"):
                box.check(timeout=3000)
            else:  # a styled box: click its visible label, like a human
                label = box.evaluate_handle(_BOX_LABEL_JS).as_element()
                if label is None or not label.is_visible():
                    return False
                _guard(page, label, allowed, dev=dev)
                label.click(timeout=3000)
        return bool(box.is_checked())
    except Exception:  # pylint: disable=broad-exception-caught
        return False


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


def open_login_page(page: Any, url: str, item: SiteItem | None = None) -> None:
    """Load the login page as a fresh document (a hash-only goto has no
    Response, and ``raise_if_blocked`` would be blind to a 401/403):
    a Cloudflare Access login — with `item`, also a load whose redirect chain
    passed Access and ended off the site (``page_access_gated``) — →
    ``AccessGated``, HTTP 401/403 →
    ``LoginBlocked``, a challenge page → ``NeedsHuman`` — nothing typed."""
    with NavTrail(page) as trail:
        resp = load_document(page, url)
    if access_gated(page.url) or (
        item is not None and page_access_gated(page, item, trail.urls)
    ):
        raise AccessGated()
    raise_if_blocked(page, resp)
    _check_challenge(page, submitted=False)


def generic_login(
    page: Any,
    item: SiteItem,
    secret: Secret,
    *,
    dev: bool = False,
    settle_s: float = SETTLE_TIMEOUT_S,
    attempt: AttemptController | None = None,
) -> None:
    """Username/password(/TOTP) form login, one-page or identifier-first.

    Starts at the login URL (= the check URL when the item sets no
    ``agent_login_url``: an Auth0 login needs the ``state`` the site creates);
    an item's ``agent_pre_click`` element is clicked once before the login
    fields are looked for (``_pre_click``).
    Returns once the page left the login (sentinel visible / off the fill
    origins) or `settle_s` passed; the caller then runs the POSITIVE check
    ``check_logged_in`` — this function's return alone proves nothing.

    A login page that is a Cloudflare Access login (off-LAN) ends it at once
    (``AccessGated``, nothing typed). A "remember me" box is ticked before the
    password is typed. From the first submit on, ``SubmitTripwire`` aborts
    any request that names a secondary form action.
    """
    allowed = list(item.fill_origins)
    open_login_page(page, item.login_url, item)
    if item.pre_click:
        _pre_click(page, item.pre_click, allowed, dev=dev)
    if secret.mode == USERNAME_ONLY_MODE:
        _credential_login(
            page, item, secret, dev=dev, settle_s=settle_s, attempt=attempt
        )
        return
    user_field, pw_field = _wait_login_fields(page, STEP_TIMEOUT_S)
    if user_field is None and pw_field is None:
        if access_gated(page.url):
            raise AccessGated()
        _check_challenge(page, submitted=False)
        raise LoginFailed("no visible username or password field on the login page")
    if access_gated(page.url):
        raise AccessGated()  # its e-mail field is not the site's
    with SubmitTripwire(page, allowed, dev=dev, attempt=attempt) as trip:
        _login_steps(
            page,
            item,
            secret,
            (user_field, pw_field),
            dev=dev,
            settle_s=settle_s,
            attempt=attempt,
            trip=trip,
        )


# One step after the other, as the login page asks for them.
def _login_steps(  # pylint: disable=too-many-arguments,too-many-locals
    page: Any,
    item: SiteItem,
    secret: Secret,
    fields: tuple[Any, Any],
    *,
    dev: bool,
    settle_s: float,
    attempt: AttemptController | None,
    trip: SubmitTripwire,
) -> None:
    """``generic_login`` from the first visible login field on, under its
    POST tripwire `trip`."""
    allowed = list(item.fill_origins)
    user_field, pw_field = fields
    if pw_field is None:  # identifier-first: username page, then password page
        _guard(page, user_field, allowed, dev=dev)
        user_field.fill(secret.username)
        _guard(page, user_field, allowed, dev=dev)
        _submit_identifier(page, user_field, allowed, dev=dev, tripwire=trip)
        trip.check()
        pw_field = _password_after_identifier(page, allowed, dev=dev)
        trip.check()
        if pw_field is None:
            _check_challenge(page, submitted=False)
            raise LoginFailed("no visible password field after the username step")
    user_handle = pw_field.evaluate_handle(USERNAME_JS)
    user_field = user_handle.as_element() if user_handle is not None else None
    if user_field is not None and secret.username:
        if _needs_fill(user_field, secret.username):
            _guard(page, user_field, allowed, dev=dev)
            user_field.fill(secret.username)
    trip.shield(user_field)
    trip.secret_fields(pw_field, secret=secret)
    _tick_remember_me(page, pw_field, allowed, dev=dev)
    trip.arm()
    pw_field = _fill_password(page, pw_field, secret, allowed, dev=dev, attempt=attempt)
    trip.secret_fields(pw_field)  # re-located: its key may differ
    _submit_password(
        page,
        pw_field,
        allowed,
        dev=dev,
        attempt=attempt,
        secret=secret,
        tripwire=trip,
    )
    _settle(page, item, secret, dev=dev, settle_s=settle_s, attempt=attempt, trip=trip)


def _account_like(desc: dict[str, Any]) -> bool:
    """A visible field an account number can be typed into: a text-like type,
    neither concealed nor a registration field."""
    return (
        str(desc.get("type") or "") in ACCOUNT_FIELD_TYPES
        and not concealed(desc)
        and not registration_field_like(desc)
    )


def _credential_candidates(page: Any) -> list[tuple[Any, dict[str, Any]]]:
    """Every visible (field, descriptor) a username-only login could type into:
    login password fields (Mullvad masks its account number in one) and
    username / account-number fields (``ACCOUNT_SELECTOR``), each once."""
    out: list[tuple[Any, dict[str, Any]]] = []
    try:
        for el in page.query_selector_all(PASSWORD_SELECTOR + ", " + ACCOUNT_SELECTOR):
            if not el.is_visible():
                continue
            desc = el.evaluate(FIELD_DESCRIBE_JS)
            if isinstance(desc, dict) and _account_like(desc):
                out.append((el, desc))
    except Exception:  # pylint: disable=broad-exception-caught
        return []  # re-rendered: look again
    return out


def _credential_field(page: Any) -> Any:
    """A username-only login's field, or None while none shows: the ONE
    visible candidate (``_credential_candidates``), or — among several — the
    one whose name / id says "account". Several candidates and no single
    account field, or a field that is not the ONLY visible text-like input of
    its form (``OTHER_FIELDS_JS``: that form asks for more than the username),
    raise ``LoginFailed``: nothing is typed on a page the broker would have
    to guess on."""
    found = _credential_candidates(page)
    if not found:
        return None
    if len(found) > 1:
        named = [
            el
            for el, d in found
            if ACCOUNT_NAME_RE.search(f"{d.get('name') or ''} {d.get('id') or ''}")
        ]
        if len(named) != 1:
            raise LoginFailed(
                "agent_login_mode=username-only, but the page shows several "
                "fields it could go into — nothing typed"
            )
        field = named[0]
    else:
        field = found[0][0]
    try:
        others = int(field.evaluate(OTHER_FIELDS_JS))
    except Exception:  # pylint: disable=broad-exception-caught
        return None  # re-rendered: look again
    if others:
        raise LoginFailed(
            "agent_login_mode=username-only, but the login form asks for more "
            "than the username/account number — nothing typed"
        )
    return field


def _wait_credential_field(page: Any, timeout_s: float) -> Any:
    """``_credential_field`` once it shows (polled), or None after `timeout_s`."""
    deadline = time.monotonic() + timeout_s
    while True:
        field = _credential_field(page)
        if field is not None or time.monotonic() >= deadline:
            return field
        _check_challenge(page, submitted=False)
        page.wait_for_timeout(250)


def _credential_login(  # pylint: disable=too-many-arguments
    page: Any,
    item: SiteItem,
    secret: Secret,
    *,
    dev: bool,
    settle_s: float,
    attempt: AttemptController | None,
) -> None:
    """``generic_login`` for ``agent_login_mode=username-only``: the item's
    username (``Secret.password`` of such an item, e.g. Mullvad's account
    number) is the ONLY thing typed, into the form's only field
    (``_credential_field``), and submitted with the password's rules — the
    tripwire armed before typing, the form's buttons read fail-closed, the
    submit marker right before the Enter / click — then the same settle loop."""
    allowed = list(item.fill_origins)
    field = _wait_credential_field(page, STEP_TIMEOUT_S)
    if access_gated(page.url):
        raise AccessGated()
    if field is None:
        _check_challenge(page, submitted=False)
        raise LoginFailed("no visible username/account-number field on the login page")
    with SubmitTripwire(page, allowed, dev=dev, attempt=attempt) as trip:
        trip.secret_fields(field, secret=secret)
        _tick_remember_me(page, field, allowed, dev=dev)
        trip.arm()
        field = _fill_password(
            page,
            field,
            secret,
            allowed,
            dev=dev,
            attempt=attempt,
            locate=_credential_field,
            sent=lambda: trip.secret_sent,
        )
        trip.secret_fields(field)
        trip.check()  # a marker that could not be written stopped a self-submit
        _submit_password(
            page,
            field,
            allowed,
            dev=dev,
            attempt=attempt,
            secret=secret,
            tripwire=trip,
        )
        _settle(
            page,
            item,
            secret,
            dev=dev,
            settle_s=settle_s,
            attempt=attempt,
            trip=trip,
            credential=field,
        )


def _same_field(field: Any, other: Any) -> bool:
    """`field` is `other` (still on the page); True when it cannot be told —
    the caller then never types into it."""
    if not _still_there(other):
        return False
    try:
        return bool(field.evaluate("(a, b) => a === b", other))
    except Exception:  # pylint: disable=broad-exception-caught
        return True


# The settle loop after the submit: one branch per thing the page may show.
def _settle(  # pylint: disable=too-many-arguments
    page: Any,
    item: SiteItem,
    secret: Secret,
    *,
    dev: bool,
    settle_s: float,
    attempt: AttemptController | None,
    trip: SubmitTripwire,
    credential: Any = None,
) -> None:
    """After the (password / username-only) submit: answer an OTP step and
    known post-login prompts until the page left the login (`settle_s`).
    `credential`: a username-only login's field — never taken for an OTP
    field (an account-number field looks numeric). A challenge on the way is
    watched (``ChallengeWatch``): while one shows nothing is typed or clicked."""
    allowed = list(item.fill_origins)
    otp_done = False
    prompts_answered = 0
    watch = ChallengeWatch()
    deadline = time.monotonic() + settle_s
    while time.monotonic() < deadline:
        page.wait_for_timeout(500)
        trip.check()
        # The item's own sentinel first: a widget left on the logged-in page
        # never holds up a login it shows (the positive proof decides).
        if _sentinel_up(page, item):
            trip.check()
            return
        if not watch.clear(page):
            continue  # nothing typed or clicked while one shows
        otp_field = None if otp_done else _otp_field(page)
        if (
            otp_field is not None
            and credential is not None
            and _same_field(otp_field, credential)
        ):
            otp_field = None
        if otp_field is not None:
            otp_done = _fill_otp(
                page,
                otp_field,
                secret,
                allowed,
                dev=dev,
                otp_label=item.otp_label,
                attempt=attempt,
                tripwire=trip,
                watch=watch,  # checked again right before typing
            )
            continue
        if _left_login(page, item, dev=dev):
            trip.check()
            return
        trust = (
            None
            if prompts_answered >= MAX_POST_LOGIN_PROMPTS
            or off_fill_origins(page.url, allowed, dev=dev)
            else trust_prompt_button(page)
        )
        if trust is not None and watch.clear(page):  # right before clicking
            trust.click(timeout=5000)
            prompts_answered += 1
    trip.check()
    if _sentinel_up(page, item):
        return
    watch.final(page)
    if _visible(page, PASSWORD_SELECTOR) is None and page_blank(page):
        # A blank page proves nothing either way: an SPA that is reloading or
        # whose bundle failed to load (NPM 2026-10-10: the login had worked).
        # The caller's positive proof reloads the check page and decides —
        # blank there too is "indeterminate", never "wrong password".
        return
    # Still on the login after the password: wrong password, an e-mail code, a
    # captcha... Fail HERE so the failure report shows this page.
    what = (
        "the username/account number"
        if secret.mode == USERNAME_ONLY_MODE
        else "the password"
    )
    raise LoginFailed(
        f"still on the login page after submitting {what}", submitted=True
    )


def _sentinel_up(page: Any, item: SiteItem) -> bool:
    """The item's own logged-in sentinel shows (False without one)."""
    selector = item.logged_in_selector
    return bool(selector) and sentinel_shown(page, str(selector))


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


# --- CSCS: the SERVER decides (WS2-cscs) -------------------------------------
# HomePort (Waldur) keeps its DRF token in localStorage `waldur/auth/token`
# (StorageManager), next to `waldur/auth/token_expires_at` (the expiry the
# backend reported on /users/me/; it slides forward with every authenticated
# call) and `waldur/auth/method`. A token's SHAPE proves nothing — an expired
# one looks exactly like a live one (the 2026-10-09 failure: a dead broker
# profile passed, its export then raced the portal's boot-redirect.js on `/`
# and handed out nothing). So the proof asks the server, FROM the portal page:
# `GET /api/users/me/` with the stored token, the app's own auth scheme
# (`Token`, `Bearer` only when the method is not local/passkey and the portal's
# /api/configuration/ enables OIDC access tokens), no cookies, no redirects,
# bounded. The token never leaves the page; only a state, the storage key's
# NAME and (for the export) the allowlisted values come back.
CSCS_TOKEN_KEY = "waldur/auth/token"
CSCS_EXPIRES_KEY = "waldur/auth/token_expires_at"
CSCS_METHOD_KEY = "waldur/auth/method"
# What a CSCS bundle may carry from the portal origin: the token (required)
# plus its expiry and method when present (boot-redirect.js treats a missing
# expiry as live, an expired one as no session).
CSCS_EXPORT_KEYS = (CSCS_TOKEN_KEY, CSCS_EXPIRES_KEY, CSCS_METHOD_KEY)
CSCS_FETCH_S = 8.0  # one API call
CSCS_CHECK_TOTAL_S = 20.0  # the whole in-page check (config + candidates)
CSCS_POLL_MS = 500
_CSCS_TOKEN_JS = """async ([mode, fetchMs, totalMs, keys]) => {
  const TOKEN = 'waldur/auth/token', EXPIRES = 'waldur/auth/token_expires_at';
  const HEX = /^[0-9a-f]{40}$/;
  const get = async (path, auth) => {
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), fetchMs);
    try {
      const headers = {Accept: 'application/json'};
      if (auth) headers.Authorization = auth;
      const r = await fetch(path, {headers, credentials: 'omit', redirect: 'error',
                                   cache: 'no-store', signal: ctl.signal});
      let body;
      try { body = r.status === 200 ? await r.json() : null; } catch (e) { body = undefined; }
      return {status: r.status, body};
    } catch (e) {
      return {status: 0, why: e && e.name === 'AbortError' ? 'timeout' : 'network'};
    } finally { clearTimeout(timer); }
  };
  // The app's expiry rule (its SC()): the reported expiry, or none at all for
  // an impersonation / OIDC token / no expiry. True when it stuck.
  const recordExpiry = (oidc, exp) => {
    if (localStorage.getItem('waldur/auth/impersonation') || oidc || !exp) {
      localStorage.removeItem(EXPIRES);
      return localStorage.getItem(EXPIRES) === null;
    }
    localStorage.setItem(EXPIRES, exp);
    return localStorage.getItem(EXPIRES) === exp;
  };
  const check = async () => {
    // Storage that cannot be read proves nothing either way.
    let main, method;
    const cands = [];
    try {
      main = (localStorage.getItem(TOKEN) || '').trim();
      method = localStorage.getItem('waldur/auth/method');
      if (main) cands.push(TOKEN);
      else {
        for (let i = 0; i < localStorage.length && cands.length < 3; i++) {
          const k = localStorage.key(i);
          if (k && HEX.test((localStorage.getItem(k) || '').trim())) cands.push(k);
        }
      }
    } catch (e) { return {state: 'storage_error'}; }
    if (!cands.length) return {state: 'none'};
    let scheme = 'Token', sure = true, oidc = false;
    if (method !== 'local' && method !== 'passkey') {
      const c = await get('/api/configuration/', null);
      const core = c.body && typeof c.body === 'object' ? c.body.WALDUR_CORE : null;
      if (c.status === 200 && core && typeof core === 'object') {
        oidc = core.OIDC_ACCESS_TOKEN_ENABLED === true;
        if (oidc) scheme = 'Bearer';
      } else sure = false;
    }
    let undecided = null;
    for (const key of cands) {
      let tok;
      try { tok = (localStorage.getItem(key) || '').trim(); }
      catch (e) { return {state: 'storage_error'}; }
      if (!tok) continue;
      const r = await get('/api/users/me/', scheme + ' ' + tok);
      if (r.status === 200) {
        const b = r.body;
        const ident = !!b && typeof b === 'object' && !Array.isArray(b)
          && ['uuid', 'username'].some(f => typeof b[f] === 'string' && b[f].length > 0);
        if (!ident) { undecided = undecided || 'malformed'; continue; }
        // Only the key the app itself reads makes a usable session.
        if (key !== TOKEN) return {state: 'wrong_key'};
        const exp = typeof b.token_expires_at === 'string' ? b.token_expires_at : null;
        return {state: 'valid', key, tok, oidc, exp};
      }
      if (r.status === 401 || r.status === 403) {
        if (!sure) undecided = undecided || 'scheme';
        continue;
      }
      undecided = undecided || (r.status ? 'status ' + r.status : r.why);
    }
    return undecided ? {state: 'indeterminate', why: undecided} : {state: 'invalid'};
  };
  const finish = async () => {
    const got = await check();
    if (got.state !== 'valid') return got;
    const out = {state: 'valid', key: got.key};
    if (mode === 'export' || mode === 'refresh') {
      let wrote;
      try { wrote = recordExpiry(got.oidc, got.exp); } catch (e) { wrote = false; }
      const t = got.exp ? Date.parse(got.exp) : NaN;
      out.left_s = Number.isNaN(t) ? null : Math.round((t - Date.now()) / 1000);
      if (mode === 'refresh') { out.state = wrote ? 'refreshed' : 'failed'; return out; }
      if (!wrote) return {state: 'indeterminate', why: 'expiry'};
      const values = {};
      try {
        if ((localStorage.getItem(TOKEN) || '').trim() !== got.tok)
          return {state: 'indeterminate', why: 'changed'};
        for (const k of keys) { const v = localStorage.getItem(k); if (v !== null) values[k] = v; }
      } catch (e) { return {state: 'storage_error'}; }
      out.values = values;
    }
    return out;
  };
  let timer;
  const cap = new Promise(res => {
    timer = setTimeout(() => res({state: 'indeterminate', why: 'deadline'}), totalMs);
  });
  try { return await Promise.race([finish(), cap]); } finally { clearTimeout(timer); }
}"""
# One in-page check never gets less than this (a shorter budget cannot even
# finish one API call).
CSCS_MIN_CHECK_S = 1.0


def cscs_token_state(
    page: Any,
    mode: str = "check",
    keys: tuple[str, ...] = (),
    *,
    budget_s: float = CSCS_CHECK_TOTAL_S,
) -> dict[str, Any]:
    """ONE in-page server check of the portal's stored token (``_CSCS_TOKEN_JS``)
    on the CURRENT page, bounded by `budget_s` (clamped to
    [``CSCS_MIN_CHECK_S``, ``CSCS_CHECK_TOTAL_S``]): ``{"state": "valid" |
    "invalid" | "indeterminate" | "none" | "wrong_key" | "storage_error" |
    "error" | …}`` plus the storage key's name — never the token. ``wrong_key``:
    the only token the server accepts is not under ``waldur/auth/token`` (the
    app would not use it). ``storage_error``: localStorage could not be read.
    `mode` ``export`` first records the expiry the server just reported (the
    app's rule), then adds the allowlisted `keys`' values; ``refresh`` only
    records the expiry. ``error``: the page navigated mid-check (or the
    evaluate failed) — ask again."""
    total = min(max(budget_s, CSCS_MIN_CHECK_S), CSCS_CHECK_TOTAL_S)
    fetch = min(CSCS_FETCH_S, total)
    try:
        got = page.evaluate(
            _CSCS_TOKEN_JS, [mode, int(fetch * 1000), int(total * 1000), list(keys)]
        )
    except Exception:  # pylint: disable=broad-exception-caught
        return {"state": "error"}
    if not isinstance(got, dict) or not isinstance(got.get("state"), str):
        return {"state": "error"}
    got.pop("tok", None)  # never set by the script's returns; belt and braces
    return got


def cscs_token_proof(page: Any, *, wait_s: float = 8.0) -> str:
    """The CSCS logged-in proof on the CURRENT page, tri-state, bounded by
    about `wait_s` (+ ``CSCS_MIN_CHECK_S``): each in-page check gets only what
    is left.

    Polls while the portal app lands: off the portal (Keycloak, anywhere
    else) → ``invalid``; on the portal, the first server answer decides —
    ``valid`` (``/api/users/me/`` 200 with an identity, token under
    ``waldur/auth/token``), ``invalid`` (401/403 for every candidate),
    ``indeterminate`` (timeout, 5xx, a redirect, a malformed answer, unreadable
    storage, a valid token under another key). No token yet / navigating
    mid-check → poll again; the portal settled WITHOUT a token (storage read
    fine) → ``invalid``; never decided → ``indeterminate``."""
    ticks = max(1, math.ceil(wait_s * 1000 / CSCS_POLL_MS))
    deadline = time.monotonic() + wait_s
    last = None
    for tick in range(ticks + 1):
        url = str(page.url or "")
        if cscs_on_portal(url):
            left = deadline - time.monotonic()
            state = cscs_token_state(page, budget_s=left).get("state")
            if state in (VALID, INVALID, INDETERMINATE):
                return str(state)
            if state in ("wrong_key", "storage_error"):
                return INDETERMINATE
            last = state  # "none" (no token yet) or "error" (navigating)
        elif not url.startswith(CSCS_PORTAL_ORIGIN + "/"):
            return INVALID  # redirected off the portal (Keycloak login)
        if tick >= ticks or time.monotonic() >= deadline:
            break
        page.wait_for_timeout(CSCS_POLL_MS)
    return INVALID if last == "none" else INDETERMINATE


def cscs_export_storage(
    page: Any, item_keys: list[str] | None = None
) -> dict[str, str]:
    """The portal's allowlisted storage, read on the CURRENT page (the
    ``/profile/`` check page, never `/`) in the SAME in-page step that
    server-validated ``waldur/auth/token`` and recorded the expiry the server
    reported (so token and expiry are coherent) — raises ``BundleExportError``
    when there is no valid token under that key (or it cannot be told).
    `item_keys`: further portal keys the item itself lists."""
    keys = tuple(dict.fromkeys([*CSCS_EXPORT_KEYS, *(item_keys or [])]))
    got: dict[str, Any] = {"state": "error"}
    for _ in range(3):  # the SPA may navigate mid-check: ask again
        got = cscs_token_state(page, "export", keys)
        if got.get("state") != "error":
            break
        page.wait_for_timeout(CSCS_POLL_MS)
    values = got.get("values")
    if got.get("state") != VALID or not isinstance(values, dict):
        why = {
            INVALID: "the server rejected the portal's stored token",
            "none": "the portal holds no token",
            "wrong_key": f"the portal's valid token is not under {CSCS_TOKEN_KEY}",
            "storage_error": "the portal's storage could not be read",
        }.get(str(got.get("state")), "the portal's token could not be validated")
        raise BundleExportError(f"cscs: {why} — no session exported")
    out = {str(k): str(v) for k, v in values.items() if isinstance(v, str)}
    if not out.get(CSCS_TOKEN_KEY, "").strip():
        raise BundleExportError(f"cscs: {CSCS_TOKEN_KEY} could not be read back")
    return out


def waldur_token_refresh(page: Any, item: SiteItem, *, dev: bool = False) -> str:
    """CSCS (Waldur): keep a reused profile's session coherent before export.

    Waldur has no renewal endpoint: its DRF token lives ~1 h and the backend
    slides the expiry forward with every authenticated call. So the refresher
    makes one (``/api/users/me/``, which IS the renewal) and writes the expiry
    the server reports back into ``waldur/auth/token_expires_at`` exactly as
    the app does (removed for OIDC/impersonation/no expiry) — otherwise
    boot-redirect.js sends the injected session to Keycloak on `/` while the
    token still works. (The export repeats that write in its own step, so the
    exported tuple is coherent even when this one failed.) 401/403 →
    ``rejected`` (not reusable: log in); undecided → ``failed``."""
    del item
    if url_origin(page.url, dev=dev) != CSCS_PORTAL_ORIGIN:
        return REFRESH_FAILED
    got = cscs_token_state(page, "refresh")
    state = got.get("state")
    if state == "refreshed":
        return REFRESH_DONE
    if state == INVALID:
        return REFRESH_REJECTED
    return REFRESH_FAILED


# No SESSION_LEFT_JS entry on purpose: a ~1 h sliding token is always "due"
# by the client's 12 h rule, which would make every passing check ask for a
# refresh-only re-export. The refresher runs on the broker's profile reuse.
SESSION_REFRESHERS["waldur-token"] = waldur_token_refresh


# Keycloak's "Remember me": with it the IdP's SSO cookie survives the broker
# Chromium's restart, so the next login of a dead portal token is a silent
# SSO (no password); without it every expired 1 h token costs a submit.
KEYCLOAK_REMEMBER_ME = "#rememberMe"
# After the form wait: one last server check before "form not found" (a
# silent SSO that landed on the portal late).
CSCS_FINAL_CHECK_S = 8.0


def _cscs_form_or_portal(page: Any, timeout_s: float) -> Any:
    """Wait for Keycloak's username field — or for the portal with a token the
    server accepts (a silent SSO through the IdP's own session, or a session
    that still works): then None, nothing to type. Raises ``LoginFailed``
    ("Keycloak login form not found", pre-submit) when neither shows, after a
    final server check; a bot challenge raises ``NeedsHuman``. Bounded by about
    `timeout_s` + ``CSCS_FINAL_CHECK_S`` (+ 2 × ``CSCS_MIN_CHECK_S``): every
    in-page check gets only what is left."""
    ticks = max(1, math.ceil(timeout_s * 1000 / CSCS_POLL_MS))
    deadline = time.monotonic() + timeout_s
    for tick in range(ticks + 1):
        user = _visible(page, "#username")
        if user is not None:
            return user
        if cscs_on_portal(str(page.url or "")):
            left = deadline - time.monotonic()
            if cscs_token_state(page, budget_s=left).get("state") == VALID:
                return None
        _check_challenge(page, submitted=False)
        if tick >= ticks or time.monotonic() >= deadline:
            break
        page.wait_for_timeout(CSCS_POLL_MS)
    if cscs_token_proof(page, wait_s=CSCS_FINAL_CHECK_S) == VALID:
        return None
    raise LoginFailed("Keycloak login form not found")


def cscs_preflight(page: Any, item: SiteItem, *, dev: bool = False) -> str:
    """Before any reservation or secret read: load the login page and see
    whether the IdP's own session logs the portal in by itself (silent SSO)
    — ``valid`` — or shows the Keycloak form — ``invalid`` (a password login
    is needed). Neither → ``LoginFailed`` (pre-submit, nothing reserved); a
    bot challenge → ``NeedsHuman``. A silent SSO then costs the limiter
    nothing."""
    del dev
    page.goto(item.login_url or CSCS_LOGIN_URL, wait_until="domcontentloaded")
    return VALID if _cscs_form_or_portal(page, STEP_TIMEOUT_S) is None else INVALID


# Site -> its preflight (``run_in_context`` runs it after a failed profile
# proof, before `get_secret`).
PREFLIGHTS: dict[str, Callable[..., str]] = {"cscs": cscs_preflight}


def _remember_me(page: Any, allowed: list[str], *, dev: bool) -> None:
    """Tick Keycloak's "Remember me" (only on a fill origin; best effort)."""
    box = _visible(page, KEYCLOAK_REMEMBER_ME)
    if box is None:
        return
    try:
        _guard(page, box, allowed, dev=dev)
        if not box.is_checked():
            box.check()
    except OriginViolation:
        raise
    except Exception:  # pylint: disable=broad-exception-caught
        pass


# Keycloak's own login button, then (a themed login page) a generic submit
# button — only one that reads as a login button, never a secondary one.
KEYCLOAK_SUBMITS = ("#kc-login", "input[name=login]")
KEYCLOAK_FALLBACK_SUBMITS = "button[type=submit], input[type=submit]"


def click_keycloak_submit(
    page: Any,
    attempt: AttemptController | None = None,
    *,
    allowed: list[str] | None = None,
    dev: bool = False,
) -> bool:
    """Click Keycloak's login button; False when none is found (nothing sent).
    The generic fallback takes the first VISIBLE, enabled submit button whose
    description can be read and is not ``secondary_button_like`` (a themed
    page's "forgot password" button is never a guess). With `allowed` (the
    broker's fill origins) the chosen button is guarded like every submit
    (``_guarded_button``: its frame, its ``formaction`` and the page on a fill
    origin — else ``OriginViolation`` before anything is marked).
    `attempt.mark_submitted()` runs right before the click."""
    chosen = None
    for sel in KEYCLOAK_SUBMITS:
        chosen = page.query_selector(sel)
        if chosen:
            break
    if not chosen:
        for el in page.query_selector_all(KEYCLOAK_FALLBACK_SUBMITS):
            descs = describe_buttons([el])
            if not descs or secondary_button_like(descs[0]):
                continue
            if descs[0].get("visible") and not descs[0].get("disabled"):
                chosen = el
                break
    if not chosen:
        return False
    if allowed is not None:
        problem = _guarded_button(page, chosen, allowed, dev=dev)
        if problem:
            raise OriginViolation(problem)
    (attempt or NO_ATTEMPT).mark_submitted()
    chosen.click()
    return True


def cscs_login(
    page: Any,
    item: SiteItem,
    secret: Secret,
    *,
    dev: bool = False,
    settle_s: float = SETTLE_TIMEOUT_S,
    attempt: AttemptController | None = None,
) -> None:
    """CSCS Keycloak login (port of ``browser.py cmd_cscs_login``) with exact hosts.

    Secrets are typed only on ``https://auth.cscs.ch`` (and only if the item
    lists it); success is the settled ``https://portal.cscs.ch`` app — the
    caller's server proof (``cscs_token_proof``) decides. A portal that lands
    with a token the server accepts instead of the Keycloak form (a silent SSO
    through the IdP's remembered session) ends the recipe with nothing typed.
    """
    allowed = [o for o in item.fill_origins if o == CSCS_AUTH_ORIGIN]
    if dev:
        allowed = list(item.fill_origins)
    if not allowed:
        raise OriginViolation("the cscs item does not list https://auth.cscs.ch")
    page.goto(item.login_url or CSCS_LOGIN_URL, wait_until="domcontentloaded")
    user = _cscs_form_or_portal(page, STEP_TIMEOUT_S)
    if user is None:
        return  # silent SSO / a session that still works: nothing to type
    pw_field = _visible(page, "#password")
    if pw_field is None:
        raise LoginFailed("Keycloak login form not found")
    _guard(page, user, allowed, dev=dev)
    user.fill(secret.username)
    _remember_me(page, allowed, dev=dev)
    # Same protected entry as the generic recipe: wait for the page to settle,
    # verify the field KEPT the password, retry key by key, fail before submit.
    pw_field = _fill_password(page, pw_field, secret, allowed, dev=dev, attempt=attempt)
    _guard(page, pw_field, allowed, dev=dev)
    if not click_keycloak_submit(page, attempt, allowed=allowed, dev=dev):
        raise LoginFailed(
            "Keycloak login button not found",
            unsent=_unsent(page, pw_field, secret, allowed, dev=dev),
        )

    otp_done = False
    watch = ChallengeWatch()
    deadline = time.monotonic() + settle_s
    while time.monotonic() < deadline:
        page.wait_for_timeout(500)
        if cscs_on_portal(page.url):
            return
        if not watch.clear(page):
            continue
        if not otp_done:
            otp_field = _visible(page, OTP_SELECTOR)
            if otp_field is not None:
                otp_done = _fill_otp(
                    page,
                    otp_field,
                    secret,
                    allowed,
                    dev=dev,
                    otp_label=item.otp_label,
                    attempt=attempt,
                    watch=watch,  # checked again right before typing
                )
    if cscs_on_portal(page.url):
        return
    watch.final(page)
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
    attempt: AttemptController | None = None,
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
    pw_field = _fill_password(page, pw_field, secret, allowed, dev=dev, attempt=attempt)
    _guard(page, pw_field, allowed, dev=dev)
    button = _visible(page, SMARTSHEET_SIGN_IN)
    if button is None:  # its known login button, or nothing (never a guess)
        raise SubmitUnidentified(
            "the Smartsheet sign-in button is not showing — nothing submitted",
            unsent=_unsent(page, pw_field, secret, allowed, dev=dev),
        )
    if not origin_allowed(page.url, allowed, dev=dev):
        raise OriginViolation("page is not on a fill origin")  # unsent unprovable
    (attempt or NO_ATTEMPT).mark_submitted()
    _click_on_fill_origin(page, button, allowed, dev=dev)

    watch = ChallengeWatch()
    deadline = time.monotonic() + settle_s
    while time.monotonic() < deadline:
        page.wait_for_timeout(500)
        if _visible(page, sentinel) is not None:
            return  # the sentinel first: the positive proof decides
        if not watch.clear(page):
            continue
        if off_fill_origins(page.url, allowed, dev=dev) and (
            _visible(page, PASSWORD_SELECTOR) is None
        ):
            return
    if _visible(page, sentinel) is not None:
        return
    watch.final(page)
    raise LoginFailed(
        "still on the Smartsheet login after submitting the password", submitted=True
    )


Recipe = Callable[..., None]

# The broker items that log into authentik (one site, two accounts: WS5);
# their recipe is ``broker.authentik.authentik_login``.
AUTHENTIK_SITES = frozenset({"authentik-akadmin", "authentik-glensk"})


def recipe_for(site: str) -> Recipe:
    """The recipe for a site id (recipes are code: changing one needs sudo).
    The authentik items log in through authentik's flow executor API
    (``broker/authentik.py``: its login page hides the real form in shadow
    roots behind a password-manager helper form)."""
    if site in AUTHENTIK_SITES:
        # broker.authentik builds on this module's helpers: imported on use
        # pylint: disable-next=import-outside-toplevel,cyclic-import
        from broker.authentik import authentik_login

        return authentik_login
    return {"cscs": cscs_login, "smartsheet": smartsheet_login}.get(site, generic_login)
