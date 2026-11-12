"""Helpers of agent-login.py's Safari keep-alive (`-k`, tp#1644 B19).

Albert's decision (2026-11-13, tp#1644): a LaunchAgent may log HIS Safari in
again by itself — the one exemption from "`-L` is agent-invoked only", and
only within these limits (agent-login.py `keepalive_site` enforces them):

* only the sites of `KEEPALIVE_SITES` (one config key);
* only while Albert is active (`agent_login_safari.attended_gate`, the
  < 15 min idle gate, without the `scheduled` refusal);
* only after the `-O` proof of the same run (the Safari Machine, never a
  login) said `safari_logged_out` — never on an unknown answer or an error;
* never while quarantined or during a live guided-login maintenance record;
* at most one proof + login attempt per site per `ATTEMPT_COOLDOWN_S`
  (stamped BEFORE the attempt: failures count too), at most one desktop
  notification per site per `NOTIFY_COOLDOWN_S` (exit 4 of the proof or the
  login: push, passkey, CAPTCHA, SMS — Albert's step; and ANY failed
  re-login), a macOS banner with a gog mail to Albert as the fallback when
  the banner fails;
* a logged-in Safari is proven by `safari.py --background` (a tab at the end
  of the front window, never the current tab, no activation, closed by
  safari.py itself): no window, no focus change, nothing left open. A tab
  safari.py reports as not closed is closed here (`--close-tab --expect-host`)
  only when it is provably that tab.

This module holds the pure / state parts; it never drives Safari itself
except through the `Runner` it is given.
"""

from __future__ import annotations

import json
import subprocess
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import agent_login_safari as alsafari
import agent_login_state as als

# The ONE config key: sites the keep-alive job may log Safari in to by itself
# (github joins once its canary passed — Albert's call, tp#1644 B19).
KEEPALIVE_SITES: tuple[str, ...] = ("cscs",)
# At most one proof + login attempt per site in this window (failures too).
ATTEMPT_COOLDOWN_S = 6 * 3600.0
# At most one notification per site in this window.
NOTIFY_COOLDOWN_S = 6 * 3600.0
STATE_FILE = "safari-keepalive.json"
# safari.py --background --wait (seconds): the page load on the site's origin.
PROBE_WAIT_S = 20
# The probe's own safari.py features (on top of the base set).
PROBE_FEATURES = frozenset({"background", "eval", "tabs", "close_tab"})
PROBE_MARK = "// agent-login:keepalive-probe"
NOTIFY_TITLE = "agent-login keep-alive"

# The probe's states: the sentinel was seen (`logged_in`); safari.py ran
# normally and the sentinel was NOT seen (`not_proven`: the page left the
# site's origin — a logged-out portal goes straight to its login host — or it
# rendered without the sentinel); anything else (`error`: no decision).
PROBE_STATES = frozenset({"logged_in", "not_proven", "error"})


@dataclass(frozen=True)
class Probe:
    """One background probe: its state, a fixed reason word, the background
    tab safari.py could not close ((window id, tab index), else None) and
    whether Safari's front tab stayed the same (None = not reported)."""

    state: str
    why: str
    tab_left: tuple[int, int] | None = None
    focus_kept: bool | None = None


def probe_js(sentinel: str) -> str:
    """The probe's page script: is the sentinel visible? (booleans only)."""
    return (
        f"{PROBE_MARK}\n(() => {{\n"
        f"  const SEL = {json.dumps(sentinel)};\n"
        "  const vis = (e) => !!e && e.getClientRects().length > 0 &&\n"
        '    getComputedStyle(e).visibility !== "hidden";\n'
        "  let seen = false;\n"
        "  try { seen = [...document.querySelectorAll(SEL)].some(vis); }\n"
        "  catch (err) { seen = false; }\n"
        "  return JSON.stringify({ sentinel: seen });\n"
        "})()"
    )


def _int(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _tab_left(data: dict[str, Any]) -> tuple[int, int] | None:
    """(window id, tab) of a background tab safari.py says it did not close."""
    bg = data.get("background")
    if not isinstance(bg, dict) or bg.get("closed") is not False:
        return None
    wid, tab = _int(bg.get("window_id")), _int(bg.get("tab"))
    return (wid, tab) if wid is not None and tab is not None else None


# One return per probe state, in the order they are decided.
def classify(  # pylint: disable=too-many-return-statements
    reply: alsafari.Reply,
) -> Probe:
    """The probe state of one `safari.py --background URL --eval FILE` call."""
    data = reply.data if isinstance(reply.data, dict) else {}
    left = _tab_left(data)
    kept = data.get("focus_kept")
    focus = kept if isinstance(kept, bool) else None
    if reply.killed or alsafari.interrupted(reply):
        return Probe("error", "safari_timeout", left, focus)
    if reply.rc == 0:
        result = alsafari.json_object(data.get("result"))
        seen = result.get("sentinel") if result is not None else None
        if seen is True:
            return Probe("logged_in", "sentinel", left, focus)
        if seen is False:
            return Probe("not_proven", "no_sentinel", left, focus)
        return Probe("error", "bad_answer", left, focus)
    if reply.rc == 2 and data.get("reason") == "origin":
        return Probe("not_proven", "left_origin", left, focus)
    if reply.rc == alsafari.ENV_RC:
        return Probe("error", "safari_unavailable", left, focus)
    return Probe("error", "probe_failed", left, focus)


def probe(call: alsafari.Runner, url: str, sentinel: str) -> Probe:
    """Prove the session in a background tab of Albert's Safari (closed by
    safari.py; the page script reads the sentinel, nothing else)."""
    with alsafari.private_js(probe_js(sentinel)) as path:
        reply = call(["--background", url, "--eval", path, "--wait", str(PROBE_WAIT_S)])
    return classify(reply)


def close_left_tab(
    call: alsafari.Runner, where: tuple[int, int], hosts: tuple[str, ...]
) -> bool:
    """Close the background tab safari.py could not close — only when it is
    provably that tab: it exists at (window id, tab), is its window's LAST
    tab (safari.py opens it at the end), is not the current tab, its window
    holds other tabs, and its host is one of the site's `hosts`. safari.py's
    `--close-tab --expect-host` re-checks host, tab count and URL in the
    call that closes. True = closed."""
    wid, index = where
    listing = call(["--tabs"])
    rows = listing.data.get("tabs") if listing.rc == 0 else None
    if not isinstance(rows, list):
        return False
    mine = [r for r in rows if isinstance(r, dict) and r.get("window_id") == wid]
    here = [r for r in mine if r.get("tab") == index]
    if len(here) != 1 or len(mine) < 2:
        return False
    row = here[0]
    host = urllib.parse.urlsplit(str(row.get("url") or "")).hostname or ""
    last = max(_int(r.get("tab")) or 0 for r in mine)
    if host not in hosts or row.get("current") is not False or index != last:
        return False
    reply = call(["--close-tab", f"{wid}:{index}", "--expect-host", host])
    return reply.rc == 0


# ---------------------------------------------------------------------------
# the per-site cooldowns (one state file, locked updates)
# ---------------------------------------------------------------------------


def cooldown_left(site: str, key: str, span: float, now: float) -> float | None:
    """Seconds left of `site`'s `key` cooldown (0: none); None when the
    state cannot be read (fail closed). A stamp from the future counts as
    the full span."""
    try:
        data = als.read(STATE_FILE, strict=True)
    except als.StateError:
        return None
    sites = data.get("sites", {})
    entry = sites.get(site, {}) if isinstance(sites, dict) else None
    if not isinstance(entry, dict):
        return None
    at = entry.get(key)
    if at is None:
        return 0.0
    if not isinstance(at, (int, float)) or isinstance(at, bool):
        return None
    if at > now:
        return span
    return max(0.0, span - (now - at))


def stamp(site: str, key: str, now: float) -> bool:
    """Write `site`'s `key` stamp (locked, atomic, 0600); False on failure."""

    def put(data: dict[str, Any]) -> None:
        sites = data.setdefault("sites", {})
        if not isinstance(sites, dict):
            raise als.StateError("sites is not an object")
        entry = sites.setdefault(site, {})
        if not isinstance(entry, dict):
            raise als.StateError("site entry is not an object")
        entry[key] = now

    try:
        als.update(STATE_FILE, put, strict=True)
    except (als.StateError, OSError):
        return False
    return True


# ---------------------------------------------------------------------------
# the notification (one per site per NOTIFY_COOLDOWN_S)
# ---------------------------------------------------------------------------

Run = Callable[..., Any]

# AppleScript with its text in argv (never spliced into the script): a
# Notification Center banner — it activates no app and raises no window.
NOTIFY_SCRIPT = (
    "on run argv",
    "display notification (item 2 of argv) with title (item 1 of argv)",
    "end run",
)


def desktop_notify(text: str, run: Run = subprocess.run) -> bool:
    """One Notification Center banner; False when osascript failed."""
    args = ["/usr/bin/osascript"]
    for line in NOTIFY_SCRIPT:
        args += ["-e", line]
    try:
        res = run(
            [*args, NOTIFY_TITLE, text], check=False, capture_output=True, timeout=15
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return getattr(res, "returncode", 1) == 0


def notify_once(
    site: str,
    text: str,
    now: float,
    send: Callable[[str], bool] = desktop_notify,
    fallback: Callable[[str], bool] | None = None,
) -> str:
    """Notify Albert about `site` unless that was done within
    `NOTIFY_COOLDOWN_S` (or the stamp is unreadable / unwritable: no
    notification rather than a storm). `fallback` (the gog mail) runs only
    when the banner failed. Returns sent / mailed / suppressed / failed."""
    left = cooldown_left(site, "notified_at", NOTIFY_COOLDOWN_S, now)
    if left is None or left > 0:
        return "suppressed"
    if not stamp(site, "notified_at", now):
        return "suppressed"
    if send(text):
        return "sent"
    if fallback is not None and fallback(text):
        return "mailed"
    return "failed"


__all__ = [
    "ATTEMPT_COOLDOWN_S",
    "KEEPALIVE_SITES",
    "NOTIFY_COOLDOWN_S",
    "PROBE_FEATURES",
    "PROBE_STATES",
    "Probe",
    "classify",
    "close_left_tab",
    "cooldown_left",
    "desktop_notify",
    "notify_once",
    "probe",
    "probe_js",
    "stamp",
]
