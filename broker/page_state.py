"""What a page shows a human: bot challenges, logged-in sentinels and the
secret-free picture of a page a login stopped on (``diagnose``).

Pure page inspection for the login recipes (``broker.recipes``), the daemon's
failure report and the client-side check in ``bin/browser.py`` — nothing here
types, clicks or reads a field value.
"""

from __future__ import annotations

import math
import re
import time
import urllib.parse
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # annotations only
    from broker.vault import Secret

CHALLENGE_SRC_RE = re.compile(
    r"recaptcha|hcaptcha|turnstile|challenges\.cloudflare", re.IGNORECASE
)
CHALLENGE_TITLES = ("nur einen moment", "just a moment")


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


# src of every iframe a human could see. A captcha widget that is rendered but
# hidden (Infomaniak keeps an idle reCAPTCHA in a ``<div hidden>`` on every
# login step, verified from its bundle 2026-10-07) is no challenge; once the
# site reveals it, the next check sees it.
# Shown also means ON SCREEN and not transparent: Google parks its reCAPTCHA
# challenge popup (``bframe``) at ``top: -10000px`` / ``opacity: 0`` until it
# is needed, and Playwright's ``is_visible`` counts both as visible.
_ON_SCREEN_JS = """e => {
  const r = e.getBoundingClientRect();
  if (r.width <= 0 || r.height <= 0) return false;
  if (r.right <= 0 || r.bottom <= 0 || r.left >= innerWidth || r.top >= innerHeight)
    return false;
  for (let n = e; n && n.nodeType === 1; n = n.parentElement)
    if (parseFloat(getComputedStyle(n).opacity) === 0) return false;
  return true;
}"""
_SHOWN_IFRAME_SRCS_JS = (
    "els => els.filter(e => e.getClientRects().length > 0"
    " && getComputedStyle(e).visibility !== 'hidden' && ("
    + _ON_SCREEN_JS
    + ")(e)).map(e => e.getAttribute('src') || '')"
)


def _frame_shown(frame: Any) -> bool:
    """False only for a child frame whose <iframe> element — or the element
    of any frame it is nested in — is provably hidden (no box /
    ``visibility: hidden``, e.g. inside ``display: none``; off screen;
    ``opacity: 0``). The main frame and any frame that cannot be inspected
    count as shown (fail closed: a challenge there still means "needs a
    human")."""
    try:
        while getattr(frame, "parent_frame", None) is not None:
            element = frame.frame_element()
            if not element.is_visible():
                return False
            try:
                if element.evaluate(_ON_SCREEN_JS) is False:
                    return False
            except Exception:  # pylint: disable=broad-exception-caught
                pass  # not inspectable: counts as on screen
            frame = frame.parent_frame
        return True
    except Exception:  # pylint: disable=broad-exception-caught
        return True


# What a challenge-provider frame is, by its URL. Only the INVISIBLE widgets
# are passive: an invisible / score-based reCAPTCHA (its ``anchor`` frame
# carries ``size=invisible``; it sits in the ``.grecaptcha-badge`` corner box)
# and an invisible hCaptcha (``frame=checkbox-invisible``) ask a human nothing
# until the provider decides to pop up a challenge, and that popup is its own
# frame (reCAPTCHA ``bframe``, hCaptcha ``frame=challenge``), which counts
# once it is shown. Evidence: MyFRITZ (sso.myfritz.net, Keycloak) shows an
# invisible reCAPTCHA page between password and OTP that submits itself after
# 2-4 s (its theme's recaptcha-page.js, 2026-10-10); reporting its badge as a
# captcha made those logins a false ``needs_human``.
PASSIVE_CHALLENGE_KINDS = frozenset(
    {"recaptcha-invisible", "recaptcha-helper", "hcaptcha-invisible"}
)
_RECAPTCHA_FRAME_RE = re.compile(
    r"/recaptcha/(?:api2|enterprise)/(anchor|bframe|aframe|webworker)\b",
    re.IGNORECASE,
)
_TURNSTILE_RE = re.compile(r"turnstile|challenges\.cloudflare", re.IGNORECASE)
# Which kind a report names when a page shows several (most specific first).
_KIND_ORDER = (
    "recaptcha-challenge",
    "hcaptcha-challenge",
    "recaptcha-checkbox",
    "hcaptcha-checkbox",
    "turnstile",
    "captcha-other",
)


def _url_params(parts: urllib.parse.SplitResult) -> dict[str, list[str]]:
    """Query and fragment parameters of a URL (hCaptcha keeps its own in the
    fragment); values lower-cased."""
    out: dict[str, list[str]] = {}
    for raw in (parts.query, parts.fragment):
        for key, values in urllib.parse.parse_qs(raw).items():
            out.setdefault(key.lower(), []).extend(v.lower() for v in values)
    return out


def challenge_kind(url: str) -> str | None:
    """The kind of challenge widget a frame at `url` is; None for a frame of
    no challenge provider. ``PASSIVE_CHALLENGE_KINDS`` ask a human nothing;
    anything unrecognised from a provider is ``captcha-other`` (fail closed)."""
    text = str(url or "")
    if not CHALLENGE_SRC_RE.search(text):
        return None
    try:
        parts = urllib.parse.urlsplit(text)
    except ValueError:
        return "captcha-other"
    params = _url_params(parts)
    invisible = "invisible" in params.get("size", [])
    match = _RECAPTCHA_FRAME_RE.search(parts.path)
    host = (parts.hostname or "").lower()
    if match:
        kind = {
            "anchor": "recaptcha-invisible" if invisible else "recaptcha-checkbox",
            "bframe": "recaptcha-challenge",
        }.get(match.group(1).lower(), "recaptcha-helper")
    elif host == "hcaptcha.com" or host.endswith(".hcaptcha.com"):
        frame = (params.get("frame") or [""])[0]
        kind = {
            "checkbox-invisible": "hcaptcha-invisible",
            "checkbox": "hcaptcha-invisible" if invisible else "hcaptcha-checkbox",
            "challenge": "hcaptcha-challenge",
        }.get(frame, "captcha-other")
    else:
        kind = "turnstile" if _TURNSTILE_RE.search(text) else "captcha-other"
    return kind


# Kinds that may still clear by themselves (a managed Turnstile that passes on
# its own, a Cloudflare "Just a moment" JS check, an unrecognised provider
# frame): the login waits a bounded time before it calls them a challenge,
# touching nothing meanwhile. ``unknown`` = the page could not be inspected
# (mid-navigation): never a challenge by itself, but no action is taken on it.
PROCESSING_CHALLENGE_KINDS = frozenset(
    {"interstitial", "turnstile", "captcha-other", "unknown"}
)
# A Turnstile widget whose response token is set has passed (the widget puts a
# hidden ``cf-turnstile-response`` input into the page); only the presence of
# a value is read, never the value.
_TURNSTILE_SOLVED_JS = """() => {
  const els = [...document.querySelectorAll('input[name="cf-turnstile-response"]')];
  return els.length > 0 && els.every(i => (i.value || '').length > 0);
}"""
_UNKNOWN = {"reason": "", "kind": "unknown"}


def _turnstile_solved(page: Any) -> bool:
    try:
        return page.evaluate(_TURNSTILE_SOLVED_JS) is True
    except Exception:  # pylint: disable=broad-exception-caught
        return False


def challenge_detail(page: Any) -> dict[str, str] | None:
    """The challenge a human would have to answer on `page`, or None.

    ``{"reason": ..., "kind": ...}``: ``reason`` is what ``challenge_reason``
    answers; ``kind`` is ``interstitial`` (a "Just a moment" page), a frame
    kind of ``challenge_kind`` (passive kinds never count; a Turnstile whose
    token is set neither), ``blocked`` (a fraud-protection text) or
    ``unknown`` (the page could not be inspected; ``reason`` empty). Shown
    frames only: a widget rendered but hidden (Infomaniak's idle reCAPTCHA in
    a ``<div hidden>``, a reCAPTCHA ``bframe`` parked off screen) is no
    challenge; once the site reveals it, the next check sees it. Never clicks
    or types anything."""
    if interstitial_title(page):
        return {"reason": "captcha", "kind": "interstitial"}
    try:
        frames = [f.url for f in page.frames if _frame_shown(f)]
        srcs = page.eval_on_selector_all("iframe", _SHOWN_IFRAME_SRCS_JS)
    except Exception:  # pylint: disable=broad-exception-caught
        return dict(_UNKNOWN)
    kinds = {challenge_kind(str(u or "")) for u in [*frames, *srcs]}
    if "turnstile" in kinds and _turnstile_solved(page):
        kinds.discard("turnstile")
    for kind in _KIND_ORDER:
        if kind in kinds:
            return {"reason": "captcha", "kind": kind}
    try:
        text = str(
            page.evaluate("() => (document.body?.innerText || '').slice(0, 4000)")
        )
    except Exception:  # pylint: disable=broad-exception-caught
        return dict(_UNKNOWN)
    if BLOCKED_TEXT_RE.search(text):
        return {
            "reason": "the site blocked this IP range / too many attempts"
            " — stop and retry later",
            "kind": "blocked",
        }
    return None


def challenge_reason(page: Any) -> str | None:
    """``"captcha"`` when a captcha / bot challenge a human must answer is on
    the page (an invisible widget is none — ``challenge_detail``), the
    block-page text on a fraud-protection page, else None (also when the page
    could not be inspected)."""
    detail = challenge_detail(page)
    return detail["reason"] if detail and detail["kind"] != "unknown" else None


def page_origin_path(url: str) -> str:
    """``scheme://host[:port]/path`` of `url` — no query, no fragment."""
    try:
        parts = urllib.parse.urlsplit(str(url or ""))
    except ValueError:
        return ""
    return f"{parts.scheme}://{parts.netloc}{parts.path}"


def challenge_snapshot(page: Any, kind: str) -> dict[str, str]:
    """Where a challenge was SEEN, taken at detection time (the page may
    submit itself away before the failure report runs): the page URL without
    query/fragment, the challenge kind and the page title (cut to 120
    characters; the daemon masks username/password in it). No page text."""
    try:
        title = str(page.title() or "")[:120]
    except Exception:  # pylint: disable=broad-exception-caught
        title = ""
    return {"url": page_origin_path(page.url), "frame": kind, "title": title}


# A sentinel may render without a box of its own: Kavita's `app-side-nav`
# (2026-10-08) is an inline custom element whose only child is
# position: fixed, so its own box is 0x0 and Playwright calls it hidden. It
# counts when one of its descendants (open shadow roots included) has a box
# and is not visibility: hidden. The walk is bounded.
_SHOWN_DESCENDANT_JS = """e => {
  const shown = n => {
    const r = n.getBoundingClientRect();
    return r.width > 0 && r.height > 0 && getComputedStyle(n).visibility !== 'hidden';
  };
  const stack = [e];
  let budget = 3000;
  while (stack.length && budget-- > 0) {
    const n = stack.pop();
    for (const c of [...n.children, ...(n.shadowRoot ? n.shadowRoot.children : [])]) {
      if (shown(c)) return true;
      stack.push(c);
    }
  }
  return false;
}"""


def sentinel_shown(page: Any, selector: str) -> bool:
    """True iff an element matching the sentinel `selector` is visible, or has
    a visible descendant (``_SHOWN_DESCENDANT_JS``). No waiting."""
    try:
        elements = page.query_selector_all(selector)
    except Exception:  # pylint: disable=broad-exception-caught
        return False
    for el in elements:
        try:
            if el.is_visible() or el.evaluate(_SHOWN_DESCENDANT_JS):
                return True
        except Exception:  # pylint: disable=broad-exception-caught
            continue
    return False


# How often a proof looks for its sentinel while a page boots.
POLL_INTERVAL_MS = 300
# At most this long for "network idle" before a NEGATIVE answer (an SPA still
# busy with its boot requests); a page that keeps a connection open never gets
# there, so it is bounded.
NETWORK_IDLE_S = 3.0


def wait_network_idle(page: Any, timeout_s: float) -> None:
    """Bounded wait for the page's network to go idle; never raises."""
    if timeout_s <= 0:
        return
    try:
        page.wait_for_load_state("networkidle", timeout=timeout_s * 1000)
    except Exception:  # pylint: disable=broad-exception-caught
        pass


def poll_sentinel(
    page: Any,
    selector: str,
    wait_s: float,
    *,
    where: Callable[[Any], bool] | None = None,
    give_up: Callable[[Any], bool] | None = None,
) -> bool:
    """Poll `sentinel_shown` (EVERY match, any visible one counts) until it
    holds — and `where(page)` too, when given — or `wait_s` passed.

    ``wait_for_selector(state="visible")`` looks at the FIRST match only and
    times out when that one is hidden (NPM's navbar link before its dashboard
    card); a one-shot scan misses an SPA that renders a moment later. At least
    one look; the loop is also bounded by its tick count, so a page whose
    ``wait_for_timeout`` returns at once (tests) cannot spin. `give_up(page)`
    true ends the wait early with False (a settled logged-out page)."""
    ticks = max(1, math.ceil(wait_s * 1000 / POLL_INTERVAL_MS))
    deadline = time.monotonic() + wait_s
    for tick in range(ticks + 1):
        if (where is None or where(page)) and sentinel_shown(page, selector):
            return True
        if give_up is not None and _safe(give_up, page):
            return False
        if tick >= ticks or time.monotonic() >= deadline:
            return False
        try:
            page.wait_for_timeout(POLL_INTERVAL_MS)
        except Exception:  # pylint: disable=broad-exception-caught
            return False
    return False


def await_sentinel(
    page: Any,
    selector: str,
    wait_s: float,
    *,
    where: Callable[[Any], bool] | None = None,
    give_up: Callable[[Any], bool] | None = None,
) -> bool:
    """`poll_sentinel` for `wait_s`; before giving up, a bounded wait for
    network idle (``NETWORK_IDLE_S``: the SPA may still be fetching) and one
    last look. A sentinel that shows early ends the wait at once; so does
    `give_up(page)` (no network-idle wait then)."""
    if poll_sentinel(page, selector, wait_s, where=where, give_up=give_up):
        return True
    if give_up is not None and _safe(give_up, page):
        return False
    wait_network_idle(page, min(NETWORK_IDLE_S, wait_s))
    return poll_sentinel(page, selector, 0.0, where=where)


def _safe(check: Callable[[Any], bool], page: Any) -> bool:
    """`check(page)`, False when it raises (a page mid-navigation)."""
    try:
        return bool(check(page))
    except Exception:  # pylint: disable=broad-exception-caught
        return False


def password_shown(page: Any) -> bool:
    """A password field is visible (a login form); open shadow roots
    included (Playwright's CSS engine pierces them). False when unreadable."""
    try:
        return any(el.is_visible() for el in page.query_selector_all(PASSWORD_CSS))
    except Exception:  # pylint: disable=broad-exception-caught
        return False


PASSWORD_CSS = "input[type=password]"


# Nothing a human could see: no rendered text and no element with a box that
# shows something by itself (a field, a button, media, its own text) — in the
# document or in any open shadow root (Home Assistant's login form lives in
# one); text inside a hidden element does not count. A custom element whose
# shadow root is closed counts as rendered once it has a box. An SPA whose
# bundle failed, or one still booting or reloading, looks like this. The walk
# is bounded; a page too big to walk counts as rendered.
_BLANK_JS = """() => {
  const b = document.body;
  if (!b) return true;
  if ((b.innerText || '').trim()) return false;
  const shown = e => {
    const r = e.getBoundingClientRect();
    return r.width > 0 && r.height > 0 && getComputedStyle(e).visibility !== 'hidden';
  };
  const media = /^(INPUT|BUTTON|SELECT|TEXTAREA|IMG|SVG|CANVAS|VIDEO|IFRAME|OBJECT)$/i;
  const ownText = n => [...n.childNodes].some(
    c => c.nodeType === Node.TEXT_NODE && (c.textContent || '').trim());
  const stack = [b];
  let budget = 5000;
  while (stack.length) {
    if (budget-- <= 0) return false;
    const n = stack.pop();
    if (n !== b && (media.test(n.tagName) || ownText(n)) && shown(n)) return false;
    // A custom element without an OPEN shadow root (closed, or rendered by
    // other means) cannot be looked into: with a box, it counts as rendered.
    if (n !== b && n.tagName.includes('-') && !n.shadowRoot && shown(n)) return false;
    if (n.shadowRoot) stack.push(...n.shadowRoot.children);
    stack.push(...n.children);
  }
  return true;
}"""


def page_blank(page: Any) -> bool:
    """True only when the page PROVABLY shows nothing (``_BLANK_JS``); a page
    that cannot be inspected counts as rendered (False) — the caller's old
    answer stands then."""
    try:
        return page.evaluate(_BLANK_JS) is True
    except Exception:  # pylint: disable=broad-exception-caught
        return False


# What a failure report lists: visible message-like elements and buttons.
# Texts come back long (``DIAG_RAW_CHARS``) and are cut in Python only AFTER
# masking: a secret cut at the page-side limit would leave its prefix unmasked.
DIAG_RAW_CHARS = 2000
DIAG_LIMITS = {"messages": 200, "buttons": 40, "title": 120}
_DIAG_JS = """(raw) => {
  const vis = e => !!(e.offsetWidth || e.offsetHeight || e.getClientRects().length);
  const txt = e => (e.innerText || e.value || e.getAttribute('aria-label') || '')
    .replace(/\\s+/g, ' ').trim();
  const pick = (sel, n) => [...document.querySelectorAll(sel)].filter(vis)
    .map(txt).filter(Boolean).map(t => t.slice(0, raw)).slice(0, n);
  const inputs = [...document.querySelectorAll('input')].filter(vis)
    .map(i => (i.type || 'text') + (i.name ? ':' + i.name : '')).slice(0, 10);
  return {
    messages: pick('[role=alert], [aria-live], .error, [class*=error i], [class*=alert i],'
      + ' [id*=error i], .ulp-input-error-message, .ulp-validator-error', 5),
    buttons: pick('button, input[type=submit]', 6),
    inputs: inputs,
    frames: [...document.querySelectorAll('iframe')].map(f => {
      try { return new URL(f.src).host; } catch (e) { return ''; } }).filter(Boolean)
      .slice(0, 6),
  };
}"""


# Separators a page may put into an echoed value ("1234 5678 9012 3456").
_ECHO_SEPARATORS = r"[\s-]*"
_LOOSE_MIN_CHARS = 4


def _loose_pattern(value: str) -> re.Pattern[str] | None:
    """`value` with any run of whitespace / hyphens allowed between its
    characters (an account number shown in groups), or None when fewer than
    ``_LOOSE_MIN_CHARS`` characters are left."""
    chars = [c for c in value if not c.isspace() and c != "-"]
    if len(chars) < _LOOSE_MIN_CHARS:
        return None
    return re.compile(_ECHO_SEPARATORS.join(re.escape(c) for c in chars))


def _redact(text: str, secret: Secret) -> str:
    """Mask the username and password wherever a page echoes them — also
    regrouped with spaces or hyphens (a username-only login's account number
    is the secret, and pages show it in groups). Longest value first: a
    password inside the username must not leave the username's rest."""
    values = sorted(
        {v for v in (secret.password, secret.username) if v}, key=len, reverse=True
    )
    for value in values:
        text = text.replace(value, "***")
    for value in values:
        loose = _loose_pattern(value)
        if loose is not None:
            text = loose.sub("***", text)
    return text


def redacted_snapshot(snapshot: dict[str, Any], secret: Secret) -> dict[str, str]:
    """A ``challenge_snapshot`` for the failure report: the three known keys
    only, username/password masked in the title."""
    return {
        "url": str(snapshot.get("url") or ""),
        "frame": str(snapshot.get("frame") or ""),
        "title": _redact(str(snapshot.get("title") or "")[:120], secret),
    }


def diagnose(page: Any, secret: Secret) -> dict[str, Any]:
    """Secret-free picture of the page a login stopped on.

    URL without user info, query and fragment (host and decoded path
    masked), title, visible inputs (type:name only, never values),
    message-like texts and buttons (username/password masked BEFORE they are
    cut to length), iframe hosts, and whether a bot challenge is showing —
    every string masked.
    """
    parts = urllib.parse.urlsplit(page.url)
    raw = page.evaluate(_DIAG_JS, DIAG_RAW_CHARS)
    raw = raw if isinstance(raw, dict) else {}

    def clean(text: object, key: str) -> str:
        shown = str(text)
        if len(shown) >= DIAG_RAW_CHARS:
            # cut page-side: a secret (however its separators stretch it)
            # may straddle that cut and escape the mask
            return "<withheld>"
        return _redact(shown, secret)[: DIAG_LIMITS[key]]

    def mask(text: object) -> str:
        return _redact(str(text), secret)

    try:
        port = f":{parts.port}" if parts.port else ""
    except ValueError:
        port = ""
    host = mask(urllib.parse.unquote(parts.hostname or "")) + port
    path = mask(urllib.parse.unquote(parts.path))
    return {
        "url": f"{parts.scheme}://{host}{path}",
        "title": clean(page.title() or "", "title"),
        "inputs": [mask(x) for x in raw.get("inputs", [])],
        "messages": [clean(x, "messages") for x in raw.get("messages", [])],
        "buttons": [clean(x, "buttons") for x in raw.get("buttons", [])],
        "frames": [mask(x) for x in raw.get("frames", [])],
        "challenge": challenge_reason(page) or "",
    }


# Pages a site shows AFTER the password and second factor were accepted, each
# with the control the broker answers it with, in order of preference. The login
# is done; the page only waits for this answer.
# - "Trust this browser?" / "Stay signed in?" (Zoho accounts: "Trust" | "Not
#   now"): answering "trust" keeps the broker's own profile out of the second
#   factor next time.
# - Zoho's periodic "Review your account details" ("Confirm" | "Remind me
#   later"): postponed, so the broker never vouches for the account's contact
#   details; "Confirm" only when no postpone control is shown.
# - Infomaniak's periodic "Verification of your back-up email address"
#   (manager.infomaniak.com/…/security-check: "Confirm" | "Verify later"),
#   which the manager shows on the CHECK page right after a fresh login
#   (tp#1472, 2026-10-31): only ever postponed — "Confirm" vouches for the
#   account's backup address, so it is never clicked.
TRUST_PROMPT_RE = re.compile(
    r"trust this (?:browser|device)\?|stay signed in\?|remember this (?:browser|device)\?",
    re.IGNORECASE,
)
TRUST_BUTTON_LABELS = ("trust", "trust browser", "trust this browser", "yes")
REVIEW_PROMPT_RE = re.compile(r"review your account details", re.IGNORECASE)
REVIEW_BUTTON_LABELS = ("remind me later", "confirm")
BACKUP_EMAIL_PROMPT_RE = re.compile(
    r"verification of your back-?up e-?mail address", re.IGNORECASE
)
BACKUP_EMAIL_BUTTON_LABELS = ("verify later",)
POST_LOGIN_PROMPTS = (
    (TRUST_PROMPT_RE, TRUST_BUTTON_LABELS),
    (REVIEW_PROMPT_RE, REVIEW_BUTTON_LABELS),
    (BACKUP_EMAIL_PROMPT_RE, BACKUP_EMAIL_BUTTON_LABELS),
)
# "Remind me later" is a styled link or span on Zoho, not a button.
_PROMPT_CONTROLS = (
    "button, input[type=submit], input[type=button], [role=button], a, span"
)


def trust_prompt_button(page: Any) -> Any:
    """The visible control that answers a known post-login prompt (see
    ``POST_LOGIN_PROMPTS``), or None (no such prompt, or no matching control).
    Inspection only."""
    try:
        text = page.inner_text("body", timeout=1000) or ""
    except Exception:  # pylint: disable=broad-exception-caught
        return None
    for prompt_re, labels in POST_LOGIN_PROMPTS:
        if prompt_re.search(text):
            return _first_control(page, labels)
    return None


def _first_control(page: Any, labels: tuple[str, ...]) -> Any:
    """The visible control whose label is the earliest entry of ``labels``."""
    found: dict[str, Any] = {}
    try:
        for control in page.query_selector_all(_PROMPT_CONTROLS):
            label = control.inner_text() or control.get_attribute("value") or ""
            label = label.strip().lower()
            if label in labels and label not in found and control.is_visible():
                found[label] = control
    except Exception:  # pylint: disable=broad-exception-caught
        return None
    return next((found[label] for label in labels if label in found), None)
