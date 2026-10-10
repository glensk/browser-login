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
_SHOWN_IFRAME_SRCS_JS = """els => els.filter(e => e.getClientRects().length > 0
    && getComputedStyle(e).visibility !== 'hidden')
  .map(e => e.getAttribute('src') || '')"""


def _frame_shown(frame: Any) -> bool:
    """False only for a child frame whose <iframe> element is provably hidden
    (no box / ``visibility: hidden``, e.g. inside ``display: none``). The main
    frame and any frame that cannot be inspected count as shown (fail closed:
    a challenge there still means "needs a human")."""
    try:
        if getattr(frame, "parent_frame", None) is None:
            return True
        element = frame.frame_element()
        return bool(element.is_visible())
    except Exception:  # pylint: disable=broad-exception-caught
        return True


def challenge_reason(page: Any) -> str | None:
    """``"captcha"`` when a captcha / bot-challenge is on the page, else None."""
    if interstitial_title(page):
        return "captcha"
    try:
        frames = [f.url for f in page.frames if _frame_shown(f)]
        srcs = page.eval_on_selector_all("iframe", _SHOWN_IFRAME_SRCS_JS)
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


# Pages a site shows AFTER the password and second factor were accepted, each
# with the control the broker answers it with, in order of preference. The login
# is done; the page only waits for this answer.
# - "Trust this browser?" / "Stay signed in?" (Zoho accounts: "Trust" | "Not
#   now"): answering "trust" keeps the broker's own profile out of the second
#   factor next time.
# - Zoho's periodic "Review your account details" ("Confirm" | "Remind me
#   later"): postponed, so the broker never vouches for the account's contact
#   details; "Confirm" only when no postpone control is shown.
TRUST_PROMPT_RE = re.compile(
    r"trust this (?:browser|device)\?|stay signed in\?|remember this (?:browser|device)\?",
    re.IGNORECASE,
)
TRUST_BUTTON_LABELS = ("trust", "trust browser", "trust this browser", "yes")
REVIEW_PROMPT_RE = re.compile(r"review your account details", re.IGNORECASE)
REVIEW_BUTTON_LABELS = ("remind me later", "confirm")
POST_LOGIN_PROMPTS = (
    (TRUST_PROMPT_RE, TRUST_BUTTON_LABELS),
    (REVIEW_PROMPT_RE, REVIEW_BUTTON_LABELS),
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
