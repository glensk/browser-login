"""Login phase codes: WHERE a login stopped, from the broker to agent-login.py.

One closed, versioned vocabulary (``PHASE_V``) shared by the broker's replies,
``browser.py``'s result file (``login/logged-in -R PATH``) and agent-login's
``last-check.json``. Every phase and every code has a FIXED short text: that is
all ``agents.md`` ever shows (never a detail, never page text). ``redact``
bounds the free-text detail Albert's own overview may show.

Pure: no I/O, no imports beyond the standard library.
"""

from __future__ import annotations

import re

PHASE_V = 1

# phase -> fixed text (order = the pipeline's order)
PHASE_TEXT = {
    "precheck": "before the login (site lookup, broker reachable, client gates)",
    "limiter": "the broker's rate limiter refused",
    "vault": "the broker's Bitwarden item",
    "recipe": "the login form, before the password was submitted",
    "submit": "after the password was submitted",
    "profile-proof": "the broker profile's logged-in proof, before any login",
    "broker-proof": "the broker's logged-in proof after the login",
    "bundle-export": "exporting the session from the broker",
    "cookie-inject": "copying cookies into the shared Chromium",
    "storage-inject": "writing localStorage into the shared Chromium",
    "client-proof": "the logged-in check in the shared Chromium",
    "consumer-followup": "the site's follow-up after the login",
    "safari-source": "your Safari session",
    "unknown": "unknown whether the password was submitted",
    "ok": "logged in",
}
PHASES = frozenset(PHASE_TEXT)

# code -> fixed text
CODE_TEXT = {
    "ok": "logged in",
    "logged_out": "not logged in",
    "broker_unavailable": "the login broker does not answer",
    "quarantined": "quarantined after a failed login — needs a release",
    "pending": "new site, not promoted yet",
    "busy": "another login of this site or its group is in progress",
    "locked": "hard-blocked after failed logins — needs a root reset",
    "cooldown": "cooldown after a failed login",
    "interval": "minimum interval between logins",
    "cap": "hourly/daily login cap reached",
    "unreadable": "the limiter state is unreadable",
    "rate_limited": "rate limited by the broker",
    "unknown_site": "not in the Bitwarden agent-login collection",
    "refused": "the Bitwarden item is refused",
    "needs_sentinel": "the item has no logged-in sentinel — cannot prove a login",
    "vault_error": "the broker cannot read Bitwarden",
    "needs_human": "the site wants a human (captcha / bot check / second factor)",
    "origin_violation": "the login page left the fill origins",
    "login_failed": "the login did not reach a logged-in state",
    "export_failed": "the session could not be exported",
    "empty_bundle": "the exported session holds no cookie and no storage key",
    "no_cookies": "no cookie could be injected",
    "storage_failed": "localStorage could not be written",
    "followup_failed": "the follow-up step failed",
    "no_safari_session": "Safari holds no usable session",
    "timeout": "the step did not finish in time",
    "killed": "the run was killed by its runner",
    "internal": "internal error",
    "forbidden": "the broker does not serve this user",
    "bad_request": "the broker rejected the request",
    "candidate_unverifiable": "the candidate sentinel could not be verified two-sided",
    "indeterminate": "the check page did not load or answered 5xx",
    "offline": "no network — not checked",
    "browser_down": "the shared Chromium is down — not checked",
    "state_unreadable": "agent-login's site state is unreadable",
    "needs_sentinel_old_proof": "no sentinel yet — checked with the old, weaker proof",
}

# Broker error code -> phase, for replies WITHOUT a phase (an older broker).
# Anything that may have happened after a submit maps to "unknown": never
# assume pre-submit when the broker did not say so.
_ERROR_PHASE = {
    "rate_limited": "limiter",
    "vault_error": "vault",
    "unknown_site": "vault",
    "refused": "vault",
    "needs_sentinel": "vault",
    "forbidden": "precheck",
    "bad_request": "precheck",
}

# Phases after which a password may have been typed and submitted — used only
# for replies that do not carry the submit state itself (an older broker).
POST_SUBMIT_PHASES = frozenset({"submit", "broker-proof", "unknown"})
# Phases that end before the broker was even asked for a login.
PRE_REQUEST_PHASES = frozenset({"precheck"})


# Details an OLDER broker (no `phase` in its replies) raised only BEFORE any
# password reached the page: those failures are pre-submit for sure.
_PRE_SUBMIT_DETAILS = (
    "no visible username or password field",
    "no visible password field after the username step",
    "keycloak login form not found",
    "no password field after the smartsheet login steps",
    "the cscs item does not list",
)


def phase_for_error(code: str, phase: object = None, detail: object = "") -> str:
    """The reply's own `phase` when valid, else derived from the error code —
    and, for an older broker's `login_failed`, from a detail it raised only
    before the password was typed (`recipe`). Everything else stays
    `unknown`: never assume pre-submit when the broker did not prove it."""
    if isinstance(phase, str) and phase in PHASES:
        return phase
    if code in _ERROR_PHASE:
        return _ERROR_PHASE[code]
    said = str(detail or "").strip().lower()
    if code == "login_failed" and any(said.startswith(d) for d in _PRE_SUBMIT_DETAILS):
        return "recipe"
    return "unknown"


def post_submit(phase: str, submitted: object) -> bool:
    """True when a failure at `phase` may have burnt a password attempt.

    The persisted submit state decides (`submitted` True/False from the
    broker); only a reply without it falls back to the phase. A proven login
    whose export failed (`bundle-export`) burnt nothing."""
    if phase in ("ok", "bundle-export"):
        return False
    if isinstance(submitted, bool):
        return submitted
    return phase in POST_SUBMIT_PHASES


def text(phase: str, code: str = "") -> str:
    """``<phase text>: <code text>`` — fixed strings only (agents.md)."""
    head = PHASE_TEXT.get(phase, PHASE_TEXT["unknown"])
    tail = CODE_TEXT.get(code, "")
    return f"{head}: {tail}" if tail and tail != head else head


DETAIL_MAX = 200
_CTRL = re.compile(r"[\x00-\x1f\x7f]+")
_EMAIL = re.compile(r"[\w.+-]+@[\w-]+(\.[\w-]+)+")
_URL = re.compile(r"\b(https?://[^/\s?#]+)[^\s]*")
_LONG = re.compile(r"[A-Za-z0-9+/=_-]{20,}")


def _mask_token(match: re.Match[str]) -> str:
    """A long run with a digit in it looks like a token/hash; plain words stay."""
    run = match.group(0)
    return "<…>" if any(c.isdigit() for c in run) else run


def redact(value: object, limit: int = DETAIL_MAX) -> str:
    """A detail safe for Albert's overview: control characters out, e-mail
    addresses and long token-like runs masked, URLs cut to their origin,
    at most `limit` characters."""
    out = _CTRL.sub(" ", str(value or "")).strip()
    out = _EMAIL.sub("<email>", out)
    out = _URL.sub(r"\1", out)
    out = _LONG.sub(_mask_token, out)
    if len(out) > limit:
        out = out[: limit - 1] + "…"
    return out
