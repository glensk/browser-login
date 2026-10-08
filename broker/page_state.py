"""What a page shows a human: bot challenges, logged-in sentinels and the
secret-free picture of a page a login stopped on (``diagnose``).

Pure page inspection for the login recipes (``broker.recipes``), the daemon's
failure report and the client-side check in ``bin/browser.py`` — nothing here
types, clicks or reads a field value.
"""

from __future__ import annotations

import re
import urllib.parse
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
