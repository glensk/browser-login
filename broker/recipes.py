"""Login recipes: where and how the broker types a site's secret.

A recipe decides where a secret is typed, so every fill and every submit is
preceded by ``_guard``: the page's CURRENT origin and the form's effective
action must both be one of the item's ``agent_fill_origins`` (exact scheme +
host + port). A redirect to a look-alike host between two fills is caught
because the check runs again right before each one.

Success needs POSITIVE proof (``check_logged_in``): on the site's check page
(``agent_check_url`` or a built-in default from ``DEFAULT_CHECK_URLS``) the
item's authenticated sentinel (``agent_logged_in_selector``) is visible; CSCS
keeps its portal-token rule. "Ended off the fill origins with no password
field" proves nothing — it also holds on an "Access denied" page — and an item
without a sentinel is never logged in.

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
from broker.page_state import (
    await_sentinel,
    challenge_reason,
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


class LoginFailed(RecipeError):
    """The login did not reach a logged-in state."""


class OriginViolation(RecipeError):
    """The page or form left the item's fill origins before a fill or submit."""

    code = "origin_violation"


class NeedsHuman(RecipeError):
    """A captcha / bot challenge or a missing second factor."""

    code = "needs_human"


class ExportFailed(RecipeError):
    """The login was proven, but the session could not be exported."""

    code = "export_failed"


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
    """CSCS: the portal app holds its token (its rule until WS2-cscs), AND —
    once the item has one — the DOM sentinel on a proof origin."""
    if item.logged_in_selector:
        answer = generic_proof(page, item, dev=dev, wait_s=wait_s)
        if answer != VALID:
            return answer
    return VALID if cscs_portal_ready(page, wait_s=max(wait_s, 8.0)) else INVALID


# Site-specific proofs (a recipe's own answer on the loaded check page);
# anything else uses `generic_proof`.
PROOFS: dict[str, Proof] = {"cscs": _cscs_proof}


def proof_for(site: str) -> Proof:
    """The proof of `site` (``PROOFS`` entry, else ``generic_proof``)."""
    return PROOFS.get(site, generic_proof)


def strict_proof(item: SiteItem) -> bool:
    """The item is proven by a sentinel (or CSCS's token rule), not the old
    "off the fill origins" heuristic."""
    return bool(item.logged_in_selector) or item.site == "cscs"


# One return per answer of the proof, in the order they are decided.
def check_proof(  # pylint: disable=too-many-return-statements
    page: Any, item: SiteItem, *, dev: bool = False, wait_s: float = 8.0
) -> str:
    """Navigate to the check page and prove the login: ``valid``, ``invalid``
    or ``indeterminate``.

    Indeterminate: the page did not load, answered 5xx, the proof raised, or —
    for the strict proof — the status is unknown (no Response, status 0).
    HTTP 4xx → invalid. No check page → invalid.
    """
    url = check_page_url(item)
    if not url:
        return INVALID
    try:
        resp = page.goto(url, wait_until="domcontentloaded")
    except Exception:  # pylint: disable=broad-exception-caught
        return INDETERMINATE
    try:
        page.wait_for_load_state("load", timeout=10_000)
    except Exception:  # pylint: disable=broad-exception-caught
        pass
    raw = getattr(resp, "status", None) if resp is not None else None
    status = raw if isinstance(raw, int) and not isinstance(raw, bool) else 0
    if status <= 0 and strict_proof(item):
        return INDETERMINATE
    if status >= 500:
        return INDETERMINATE
    if status >= 400:
        return INVALID
    try:
        page.wait_for_timeout(1000)
        answer = proof_for(item.site)(page, item, dev=dev, wait_s=wait_s)
    except Exception:  # pylint: disable=broad-exception-caught
        return INDETERMINATE
    return answer if answer in (VALID, INVALID, INDETERMINATE) else INDETERMINATE


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
DEFAULT_SESSION_REFRESH = {"npm-nixos": "npm-jwt", "npm-raspi": "npm-jwt"}


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
) -> Any:
    """Type the password and make sure the field KEEPS it; returns the field used.

    One retry types it key by key into the (re-located) visible password field;
    a field that still drops the value fails BEFORE anything is submitted.
    `attempt.entered()` runs right before the first character is typed.
    """
    page.wait_for_timeout(HYDRATE_S * 1000)
    _check_challenge(page, submitted=False)
    pw_field = _login_password(page) or pw_field
    _guard(page, pw_field, allowed, dev=dev)
    (attempt or NO_ATTEMPT).entered()
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
    attempt: AttemptController | None = None,
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
    (attempt or NO_ATTEMPT).mark_submitted()
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


def _unsent(
    page: Any, field: Any, secret: Secret | None, allowed: list[str], *, dev: bool
) -> bool:
    """True only when the typed password provably was NOT submitted: the page
    is still on a fill origin and `field` still holds exactly the password."""
    if secret is None or not origin_allowed(page.url, allowed, dev=dev):
        return False
    return _field_value(field) == secret.password


def _submit_password(  # pylint: disable=too-many-arguments
    page: Any,
    pw_field: Any,
    allowed: list[str],
    *,
    dev: bool,
    attempt: AttemptController | None = None,
    secret: Secret | None = None,
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
        (attempt or NO_ATTEMPT).mark_submitted()
        pw_field.press("Enter")
        return
    if choice < 0:
        raise LoginFailed(
            "Enter would press the form's non-login default button and no login"
            " button is showing",
            unsent=_unsent(page, pw_field, secret, allowed, dev=dev),
        )
    button = buttons[choice]
    frame_url = _frame_url(button)
    problem = ""
    if not origin_allowed(frame_url, allowed, dev=dev):
        problem = "the submit button is not on a fill origin"
    else:
        own_action = button.get_attribute("formaction")
        if own_action and not form_action_allowed(
            frame_url, own_action, allowed, dev=dev
        ):
            problem = "submit button posts off the fill origins"
        elif not origin_allowed(page.url, allowed, dev=dev):
            problem = "page is not on a fill origin"
    if problem:
        raise OriginViolation(
            problem, unsent=_unsent(page, pw_field, secret, allowed, dev=dev)
        )
    (attempt or NO_ATTEMPT).mark_submitted()
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
    pw_field = _fill_password(page, pw_field, secret, allowed, dev=dev, attempt=attempt)
    _submit_password(page, pw_field, allowed, dev=dev, attempt=attempt, secret=secret)

    otp_done = False
    prompts_answered = 0
    deadline = time.monotonic() + settle_s
    while time.monotonic() < deadline:
        page.wait_for_timeout(500)
        _check_challenge(page, submitted=True)
        otp_field = None if otp_done else _otp_field(page)
        if otp_field is not None:
            _fill_otp(
                page,
                otp_field,
                secret,
                allowed,
                dev=dev,
                otp_label=item.otp_label,
                attempt=attempt,
            )
            otp_done = True
            continue
        if _left_login(page, item, dev=dev):
            return
        trust = (
            None
            if prompts_answered >= MAX_POST_LOGIN_PROMPTS
            or off_fill_origins(page.url, allowed, dev=dev)
            else trust_prompt_button(page)
        )
        if trust is not None:
            trust.click(timeout=5000)
            prompts_answered += 1
    if _visible(page, PASSWORD_SELECTOR) is None and page_blank(page):
        # A blank page proves nothing either way: an SPA that is reloading or
        # whose bundle failed to load (NPM 2026-10-10: the login had worked).
        # The caller's positive proof reloads the check page and decides —
        # blank there too is "indeterminate", never "wrong password".
        return
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


def click_keycloak_submit(page: Any, attempt: AttemptController | None = None) -> bool:
    """Click Keycloak's login button; False when none is found (nothing sent).
    `attempt.mark_submitted()` runs right before the click."""
    for sel in (
        "#kc-login",
        "input[name=login]",
        "button[type=submit]",
        "input[type=submit]",
    ):
        el = page.query_selector(sel)
        if el:
            (attempt or NO_ATTEMPT).mark_submitted()
            el.click()
            return True
    return False


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
    pw_field = _fill_password(page, pw_field, secret, allowed, dev=dev, attempt=attempt)
    _guard(page, pw_field, allowed, dev=dev)
    if not click_keycloak_submit(page, attempt):
        raise LoginFailed(
            "Keycloak login button not found",
            unsent=_unsent(page, pw_field, secret, allowed, dev=dev),
        )

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
                    page,
                    otp_field,
                    secret,
                    allowed,
                    dev=dev,
                    otp_label=item.otp_label,
                    attempt=attempt,
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
    if button is not None and not origin_allowed(page.url, allowed, dev=dev):
        raise OriginViolation("page is not on a fill origin")  # unsent unprovable
    (attempt or NO_ATTEMPT).mark_submitted()
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
