"""Helpers of agent-login.py's Safari keep-alive (`-k`, tp#1644 B19).

Albert's decision (2026-11-13, tp#1644): a LaunchAgent may log HIS Safari in
again by itself — the one exemption from "`-L` is agent-invoked only", and
only within these limits (agent-login.py `keepalive_site` enforces them):

* only the sites of `KEEPALIVE_SITES` (one config key);
* only while Albert is active (`agent_login_safari.attended_gate`, the
  < 15 min idle gate, without the `scheduled` refusal);
* the background probe alone is never proof either way: whenever it did
  not see the session (not seen, or it could not tell — e.g. the logged-out
  portal redirected the tab to its login host, which safari.py reports as
  `bg-lost`), the `-O` proof of the same run decides (the Safari Machine,
  never a login), and only its `safari_logged_out` leads to the login —
  never an unknown answer or an error of that proof;
* never while quarantined or during a live guided-login maintenance record;
* at most one proof + login attempt per site per `ATTEMPT_COOLDOWN_S`
  (stamped BEFORE the attempt as `typed`: failures count too); a `-O`
  proof that stopped with nothing typed (no broker fill, no submit, no
  code mail: `Outcome.credential` False) re-marks it `untyped` —
  `ATTEMPT_UNTYPED_COOLDOWN_S` then; both less `ATTEMPT_SLACK_S`, so the
  30-min launchd cadence landing a few seconds early keeps its cycle
  (Albert, 2026-11-18); at most one desktop
  notification per site per `NOTIFY_COOLDOWN_S` (exit 4 of the proof or the
  login: push, passkey, CAPTCHA, SMS — Albert's step; ANY failed
  re-login; and `UNPROVEN_NOTIFY_AFTER` runs in a row that proved no
  session — never silent), a macOS banner with a gog mail to Albert as the
  fallback when the banner fails;
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
import re
import subprocess
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any

import agent_login_safari as alsafari
import agent_login_state as als

# The ONE config key: sites the keep-alive job may log Safari in to by itself
# (github joins once its canary passed — Albert's call, tp#1644 B19).
KEEPALIVE_SITES: tuple[str, ...] = ("cscs",)
# At most one proof + login attempt per site in this window (failures too).
ATTEMPT_COOLDOWN_S = 6 * 3600.0
# ... but only this one after a -O proof that stopped with nothing typed
# (Albert, 2026-11-18, tp#1644 B19 follow-up).
ATTEMPT_UNTYPED_COOLDOWN_S = 1 * 3600.0
# An attempt is allowed once its window less this slack has passed: the
# 30-min launchd cadence may land a few seconds early.
ATTEMPT_SLACK_S = 120.0
# The attempt stamp's kinds; a stamp without one (older format) is `typed`.
ATTEMPT_TYPED = "typed"
ATTEMPT_UNTYPED = "untyped"
# At most one notification per site in this window.
NOTIFY_COOLDOWN_S = 6 * 3600.0
# Notify (within NOTIFY_COOLDOWN_S) once this many probing runs in a row
# proved no session (neither the probe nor the -O proof nor a login).
UNPROVEN_NOTIFY_AFTER = 3
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
# rendered without the sentinel); anything else (`error`: it could not tell).
# Only `logged_in` ends the run; the other two go on to the `-O` proof.
PROBE_STATES = frozenset({"logged_in", "not_proven", "error"})


@dataclass(frozen=True)
class Probe:
    """One background probe: its state, a fixed reason word, the background
    tab safari.py could not close ((window id, tab index), else None),
    whether Safari's front tab stayed the same (None = not reported) and
    where the tab ended (`tab_hint`: host + path, '' = unknown)."""

    state: str
    why: str
    tab_left: tuple[int, int] | None = None
    focus_kept: bool | None = None
    hint: str = ""


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


# A path segment `tab_hint` keeps as is (anything else: `*`).
_PLAIN_SEGMENT = re.compile(r"^[A-Za-z][A-Za-z_.-]{0,31}$")


def tab_hint(url: object) -> str:
    """A tab's place for the log (tp#1644): the https host and the path —
    never the query or the fragment; a path segment that is not a plain
    word (ids, tokens, digits) becomes `*`. '' for anything else."""
    host = alsafari.safe_host(url)
    if not host:
        return ""
    path = urllib.parse.urlsplit(str(url)).path
    parts = [p if _PLAIN_SEGMENT.match(p) else "*" for p in path.split("/") if p]
    return (host + "/" + "/".join(parts))[:120]


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
            hint = tab_hint(data.get("url"))
            return Probe("not_proven", "no_sentinel", left, focus, hint)
        return Probe("error", "bad_answer", left, focus)
    if reply.rc == 2 and data.get("reason") == "origin":
        return Probe("not_proven", "left_origin", left, focus)
    if reply.rc == 2 and data.get("reason") == "bg-lost":
        # safari.py finds its tab by the origin it opened: a tab redirected
        # to the login host (a logged-out portal) and a tab that is gone
        # answer alike — it cannot tell which (tp#1644).
        return Probe("error", "tab_lost_or_left_origin", left, focus)
    if reply.rc == alsafari.ENV_RC:
        return Probe("error", "safari_unavailable", left, focus)
    return Probe("error", "probe_failed", left, focus)


def probe(call: alsafari.Runner, url: str, sentinel: str) -> Probe:
    """Prove the session in a background tab of Albert's Safari (closed by
    safari.py; the page script reads the sentinel, nothing else)."""
    with alsafari.private_js(probe_js(sentinel)) as path:
        reply = call(["--background", url, "--eval", path, "--wait", str(PROBE_WAIT_S)])
    return classify(reply)


def tab_rows(call: alsafari.Runner) -> list[dict[str, Any]] | None:
    """safari.py `--tabs` (None when it failed)."""
    listing = call(["--tabs"])
    rows = listing.data.get("tabs") if listing.rc == 0 else None
    if not isinstance(rows, list):
        return None
    return [r for r in rows if isinstance(r, dict)]


def locate(
    seen: Probe,
    rows: list[dict[str, Any]] | None,
    hosts: tuple[str, ...],
    sentinel_host: str,
) -> Probe:
    """tp#1644: where a `bg-lost` probe's tab went. safari.py finds its tab
    by the origin it opened, so a tab redirected away and a tab that is gone
    answer alike; the listing at the tab's place (window id, index) tells:
    on one of the site's hosts other than the sentinel's (CSCS: the
    logged-out portal sent it to its Keycloak, auth.cscs.ch) →
    `not_proven` / `login_host`; no tab there → `tab_gone`; no listing →
    unchanged; any other tab there → unchanged, with its hint. Only the
    reason word and the hint change: the `-O` proof decides either way."""
    if seen.why != "tab_lost_or_left_origin" or seen.tab_left is None:
        return seen
    if rows is None:
        return seen
    wid, index = seen.tab_left
    here = [r for r in rows if r.get("window_id") == wid and r.get("tab") == index]
    if not here:
        return replace(seen, why="tab_gone")
    url = here[0].get("url")
    host = alsafari.safe_host(url)
    if host and host in hosts and host != sentinel_host:
        return replace(seen, state="not_proven", why="login_host", hint=tab_hint(url))
    return replace(seen, hint=tab_hint(url))


def close_left_tab(
    call: alsafari.Runner,
    where: tuple[int, int],
    hosts: tuple[str, ...],
    rows: list[dict[str, Any]] | None = None,
) -> bool:
    """Close the background tab safari.py could not close — only when it is
    provably that tab: it exists at (window id, tab), is its window's LAST
    tab (safari.py opens it at the end), is not the current tab, its window
    holds other tabs, and its host is one of the site's `hosts`. safari.py's
    `--close-tab --expect-host` re-checks host, tab count and URL in the
    call that closes. `rows`: a `tab_rows` listing already read (else it is
    read here). True = closed."""
    wid, index = where
    if rows is None:
        rows = tab_rows(call)
    if rows is None:
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


def _entry(data: dict[str, Any], site: str) -> dict[str, Any]:
    """`site`'s entry of the state (created when absent)."""
    sites = data.setdefault("sites", {})
    if not isinstance(sites, dict):
        raise als.StateError("sites is not an object")
    entry = sites.setdefault(site, {})
    if not isinstance(entry, dict):
        raise als.StateError("site entry is not an object")
    return entry


def stamp(site: str, key: str, now: float) -> bool:
    """Write `site`'s `key` stamp (locked, atomic, 0600); False on failure."""

    def put(data: dict[str, Any]) -> None:
        _entry(data, site)[key] = now

    try:
        als.update(STATE_FILE, put, strict=True)
    except (als.StateError, OSError):
        return False
    return True


def attempt_kind(site: str) -> str | None:
    """The kind of `site`'s attempt stamp: `untyped` only when recorded so,
    else `typed` (no kind = an older stamp; an unknown word counts as the
    longer window); None when the state cannot be read (fail closed)."""
    try:
        data = als.read(STATE_FILE, strict=True)
    except als.StateError:
        return None
    sites = data.get("sites", {})
    entry = sites.get(site, {}) if isinstance(sites, dict) else None
    if not isinstance(entry, dict):
        return None
    if entry.get("attempt_kind") == ATTEMPT_UNTYPED:
        return ATTEMPT_UNTYPED
    return ATTEMPT_TYPED


def attempt_span(kind: str) -> float:
    """The attempt window of a stamp of `kind` (without the slack)."""
    if kind == ATTEMPT_UNTYPED:
        return ATTEMPT_UNTYPED_COOLDOWN_S
    return ATTEMPT_COOLDOWN_S


def attempt_left(site: str, now: float) -> tuple[float | None, str]:
    """(seconds left of `site`'s attempt window, the stamp's kind): the
    window of its kind less `ATTEMPT_SLACK_S`; None seconds when the state
    cannot be read (fail closed)."""
    kind = attempt_kind(site)
    if kind is None:
        return None, ATTEMPT_TYPED
    span = attempt_span(kind) - ATTEMPT_SLACK_S
    return cooldown_left(site, "attempt_at", span, now), kind


def stamp_attempt(site: str, now: float) -> bool:
    """Stamp `site`'s attempt BEFORE it runs, as `typed` (the full window
    unless `mark_untyped` shortens it); False on failure."""

    def put(data: dict[str, Any]) -> None:
        entry = _entry(data, site)
        entry["attempt_at"] = now
        entry["attempt_kind"] = ATTEMPT_TYPED

    try:
        als.update(STATE_FILE, put, strict=True)
    except (als.StateError, OSError):
        return False
    return True


def mark_untyped(site: str, at: float) -> bool:
    """Re-mark the attempt stamped at `at` as `untyped` (its `-O` proof
    stopped with nothing typed); only that stamp — a newer one stays as it
    is. False when nothing was written."""
    done: list[bool] = []

    def put(data: dict[str, Any]) -> None:
        entry = _entry(data, site)
        if entry.get("attempt_at") == at:
            entry["attempt_kind"] = ATTEMPT_UNTYPED
            done.append(True)

    try:
        als.update(STATE_FILE, put, strict=True)
    except (als.StateError, OSError):
        return False
    return bool(done)


def unproven_runs(site: str, *, proven: bool) -> int | None:
    """Count `site`'s probing runs in a row that proved no session
    (`proven` False: +1; True: back to 0). The new count; None when the
    state cannot be updated (no notification then)."""
    got: list[int] = []

    def put(data: dict[str, Any]) -> None:
        entry = _entry(data, site)
        old = _int(entry.get("unproven_runs")) or 0
        entry["unproven_runs"] = 0 if proven else max(0, old) + 1
        got.append(entry["unproven_runs"])

    try:
        als.update(STATE_FILE, put, strict=True)
    except (als.StateError, OSError):
        return None
    return got[0] if got else None


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
    "ATTEMPT_SLACK_S",
    "ATTEMPT_TYPED",
    "ATTEMPT_UNTYPED",
    "ATTEMPT_UNTYPED_COOLDOWN_S",
    "KEEPALIVE_SITES",
    "NOTIFY_COOLDOWN_S",
    "PROBE_FEATURES",
    "PROBE_STATES",
    "Probe",
    "UNPROVEN_NOTIFY_AFTER",
    "attempt_kind",
    "attempt_left",
    "attempt_span",
    "classify",
    "close_left_tab",
    "cooldown_left",
    "desktop_notify",
    "locate",
    "mark_untyped",
    "notify_once",
    "probe",
    "probe_js",
    "stamp",
    "stamp_attempt",
    "tab_hint",
    "tab_rows",
    "unproven_runs",
]
