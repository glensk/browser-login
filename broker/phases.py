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
    # tp#965: a credential rotation leased the site or wrote agent_hold
    "held": "a credential rotation holds this site — skipped, re-check later",
    # tp#1082 D5: the broker never logs in with a fill-only item
    "fill_only": "a fill-only item — agents fill it into Albert's Safari "
    "(safari.py -L), never a login",
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
    "no_password": (
        "the item has no password — an account-number login needs "
        "agent_login_mode=username-only"
    ),
    "no_username": "the username-only item has no username (account number)",
    "needs_human": "the site wants a human (captcha / bot check / second factor)",
    "submit_disabled": "the broker never submits a password here — Albert's session only",
    # The identity provider's own answer to the password (allowlisted enum of
    # its JSON reply, broker/idp_reasons.py) — never its words.
    "idp_invalid_credentials": "the identity provider answered: invalid credentials",
    "idp_unknown": "the identity provider refused without a reason (often a bot check)",
    "captcha_required": "the identity provider wants a captcha",
    "origin_violation": "the login page left the fill origins",
    "access_gated": "unreachable off-LAN (Cloudflare Access) — not checked",
    "login_blocked": "the login page is blocked from here (HTTP 401/403) — nothing typed",
    "submit_unidentified": "the login button could not be identified — nothing submitted",
    "secondary_action_blocked": (
        "the submit would have run forgot/reset/register — blocked in the browser"
    ),
    "login_failed": "the login did not reach a logged-in state",
    "export_failed": "the session could not be exported",
    "empty_bundle": "the exported session holds no cookie and no storage key",
    "incomplete_bundle": "the exported session lacks a configured storage key",
    "bundle_export": "the session's required token could not be exported",
    "bundle_rejected": "the site's API rejects the exported session",
    "refresh_unavailable": "the broker profile cannot be reused — a refresh never logs in",
    "no_cookies": "no cookie could be injected",
    "storage_failed": "localStorage could not be written",
    "followup_failed": "the follow-up step failed",
    "no_safari_session": "Safari holds no usable session",
    "manual_import": "the Safari import of this site runs by hand only",
    # WS1b: an agent's login in Albert's Safari (`agent-login.py -L SITE`).
    # The four `needs_albert_*` stops (and a locked vault) are the ONLY ones
    # that are Albert's; every other code is for the agent.
    "needs_albert_captcha": "needs Albert: a CAPTCHA in Safari",
    "needs_albert_sms": "needs Albert: an SMS code",
    "needs_albert_push": "needs Albert: a push approval on his phone",
    "needs_albert_hardware_key": "needs Albert: a security key / passkey",
    "needs_albert_vault_locked": "needs Albert: unlock Vaultwarden in Safari",
    "email_code": (
        "the site sent an e-mail code — an agent reads it from the mailbox "
        "and types it in Safari, then re-runs -L"
    ),
    "recipe_stuck": "the Safari login recipe found no next step on the page",
    "safari_unavailable": (
        "Safari is not running, or JavaScript from Apple Events is off"
    ),
    "safari_py_missing": "safari.py (mydotfiles bin) is not installed",
    "safari_py_outdated": "safari.py lacks a feature this login needs (mydotfiles)",
    "safari_tab_moved": "the Safari login tab left the recipe's hosts — stopped",
    "safari_no_recipe": "no Safari login recipe for this site",
    "safari_flush_timeout": "Safari did not write the new session to disk in time",
    "identity_unconfigured": (
        "no expected account configured for this import — nothing imported"
    ),
    "safari_timeout": "safari.py overstayed its budget and was stopped",
    "safari_signal": "safari.py died of a signal — its step may have been done",
    "safari_window_unknown": (
        "Safari opened a login window without naming it — it may be left open"
    ),
    # WS1b S5: a Safari login never runs on an unattended Mac.
    "scheduled": "a scheduled run never drives Safari",
    "console_locked": "the Mac's screen is locked — no Safari login now",
    "not_on_console": "Albert's session is not on the console — no Safari login now",
    "console_unknown": "the console state cannot be read — no Safari login now",
    "albert_idle": "nobody used the Mac recently — no Safari login now",
    "idle_unknown": "the Mac's idle time cannot be read — no Safari login now",
    "timeout": "the step did not finish in time",
    "killed": "the run was killed by its runner",
    "internal": "internal error",
    "forbidden": "the broker does not serve this user",
    "bad_request": "the broker rejected the request",
    "candidate_unverifiable": "the candidate sentinel could not be verified two-sided",
    "indeterminate": "the check page did not load, answered 5xx or stayed blank",
    "offline": "no network — not checked",
    "browser_down": "the shared Chromium is down — not checked",
    "state_unreadable": "agent-login's site state is unreadable",
    "needs_sentinel_old_proof": "no sentinel yet — checked with the old, weaker proof",
    # WS5 (tp#833): the item shares its cookie scope with another account.
    "identity_unproven": (
        "account unproven: the site shares its login with another account"
    ),
    # WS5 S1: the server identity proof (broker/identity.py) disagreed.
    "wrong_account": "logged in as another account than the item's",
    "privilege_mismatch": "the account's admin rights do not match the item's",
    "identity_indeterminate": "the site's account check could not tell which account",
    # WS5 S2: the client side of the proof and the role browser instances.
    "wrong_instance": (
        "the site lives in another browser instance (CLAUDE_BROWSER_INSTANCE)"
    ),
    "identity_blocked": (
        "the broker blocks this site's account checks after a mismatch "
        "(cooldown, or until a root reset)"
    ),
}

# Broker error code -> phase, for replies WITHOUT a phase (an older broker).
# Anything that may have happened after a submit maps to "unknown": never
# assume pre-submit when the broker did not say so.
_ERROR_PHASE = {
    "rate_limited": "limiter",
    "vault_error": "vault",
    "no_password": "vault",
    "no_username": "vault",
    "unknown_site": "vault",
    "refused": "vault",
    "needs_sentinel": "vault",
    "submit_disabled": "vault",
    "forbidden": "precheck",
    "bad_request": "precheck",
    "access_gated": "precheck",
    "login_blocked": "precheck",
    "held": "precheck",
    "fill_only": "precheck",
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
