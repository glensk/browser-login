"""Credentials stored in two or more places — agent-login.py's credctl section (tp#991).

Reads ONLY mydotfiles credctl's daily state file
(``~/.local/state/credctl/check-latest.json``, written by ``credctl.py check
-e -w``; ``$CREDCTL_STATE_FILE`` overrides it) — the envelope::

    {"v": 1, "manifest_digest": ..., "attempt": started|completed|failed|timeout,
     "started_at": ISO-8601 UTC, "completed_at": ISO-8601 UTC | null,
     "exit": int | null, "results": [{..., "id", "verdict", "location_count"}]}

and prints one line per credential with ``location_count >= 2``, derived
from the file (no hand-written list): ✅ ``equal``; ❌ ``DRIFT`` /
``missing`` / ``unreadable``; ⚠️ ``uncompared`` with the command that
compares it. An ``uncompared`` result credctl marks ``accepted_uncompared:
true`` (an ``accept_uncompared`` reason in the manifest, or the classes
external-master / machine-only — uncompared by design, tp#889 R3b) is no
warning: all of them fold into ONE quiet ``·`` count line, since a per-id
line would carry no action and drown the real findings. A failed or
timed-out run, or one that started more than an hour ago and never finished,
is ONE ❌ line; a run still in progress, a last run older than 36 h and a
missing, unreadable or unknown-version file are ONE ⚠️ line each.

Closed schema: every field that is printed is validated (the id against the
site-id pattern, the verdict and attempt against their closed sets, the
count as an int 0..64, the timestamps as ``YYYY-MM-DDTHH:MM:SSZ``); nothing
else of the file is ever printed — no detail text, no copy reference, no
unknown key.
"""

from __future__ import annotations

import calendar
import json
import os
import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

STATE_ENV = "CREDCTL_STATE_FILE"
DEFAULT_STATE = Path.home() / ".local/state/credctl/check-latest.json"
VERSION = 1
STALE_S = 36 * 3600
STARTED_GRACE_S = 3600
MAX_LOCATIONS = 64
MYDOTFILES_BIN = Path.home() / "obsidian/42-Git/home/mydotfiles/bin"
DAILY = str(MYDOTFILES_BIN / "credctl-daily.sh")
CREDCTL = str(MYDOTFILES_BIN / "credctl.py")

ATTEMPTS = frozenset({"started", "completed", "failed", "timeout"})
EQUAL, UNCOMPARED = "equal", "uncompared"
BAD = ("DRIFT", "missing", "unreadable")
VERDICTS = frozenset({EQUAL, "single", UNCOMPARED, *BAD})
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_TS_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")

OK, FAIL, WARN, QUIET = "✅", "❌", "⚠️", "·"


@dataclass
class CredState:
    """What the state file says, reduced to validated fields only."""

    status: str  # absent | unreadable | ok
    attempt: str = ""
    started_at: str = ""
    completed_at: str = ""
    exit: int | None = None
    results: list[dict[str, Any]] = field(default_factory=list)
    invalid: int = 0


def state_path() -> Path:
    """The state file (``$CREDCTL_STATE_FILE`` overrides)."""
    env = os.environ.get(STATE_ENV)
    return Path(env) if env else DEFAULT_STATE


def parse_ts(value: object) -> float | None:
    """Epoch seconds of a ``YYYY-MM-DDTHH:MM:SSZ`` string, else None."""
    if not isinstance(value, str) or not _TS_RE.match(value):
        return None
    try:
        return float(calendar.timegm(time.strptime(value, "%Y-%m-%dT%H:%M:%SZ")))
    except ValueError:
        return None


def _result(row: object) -> dict[str, Any] | None:
    if not isinstance(row, dict):
        return None
    cid, verdict, count = row.get("id"), row.get("verdict"), row.get("location_count")
    if not isinstance(cid, str) or not _ID_RE.match(cid):
        return None
    if verdict not in VERDICTS:
        return None
    if isinstance(count, bool) or not isinstance(count, int):
        return None
    if not 0 <= count <= MAX_LOCATIONS:
        return None
    # Only a literal ``true`` on an ``uncompared`` row is accepted; anything
    # else stays a warning (fail towards showing it).
    accepted = verdict == UNCOMPARED and row.get("accepted_uncompared") is True
    return {
        "id": cid,
        "verdict": verdict,
        "location_count": count,
        "accepted_uncompared": accepted,
    }


# One early return per envelope rule.
# pylint: disable-next=too-many-return-statements,too-many-branches
def load(path: Path | None = None) -> CredState:
    """The validated state (``absent`` / ``unreadable`` when it cannot be used)."""
    path = path or state_path()
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return CredState("absent")
    except OSError:
        return CredState("unreadable")
    try:
        doc = json.loads(raw)
    except ValueError:
        return CredState("unreadable")
    if not isinstance(doc, dict) or doc.get("v") != VERSION:
        return CredState("unreadable")
    attempt, started = doc.get("attempt"), doc.get("started_at")
    completed, rc = doc.get("completed_at"), doc.get("exit")
    if attempt not in ATTEMPTS or parse_ts(started) is None:
        return CredState("unreadable")
    if attempt == "started":
        if completed is not None:
            return CredState("unreadable")
    elif parse_ts(completed) is None:
        return CredState("unreadable")
    if rc is not None and (isinstance(rc, bool) or not isinstance(rc, int)):
        return CredState("unreadable")
    rows = doc.get("results")
    if not isinstance(rows, list):
        return CredState("unreadable")
    results: list[dict[str, Any]] = []
    invalid = 0
    for row in rows:
        res = _result(row)
        if res is None:
            invalid += 1
        else:
            results.append(res)
    return CredState(
        "ok",
        attempt=str(attempt),
        started_at=str(started),
        completed_at=str(completed or ""),
        exit=rc,
        results=results,
        invalid=invalid,
    )


def _result_line(res: dict[str, Any]) -> tuple[str, str]:
    cid, verdict, count = res["id"], res["verdict"], res["location_count"]
    places = f"{count} places"
    if verdict == EQUAL:
        return OK, f"{cid} — all {places} equal"
    if verdict in BAD:
        return FAIL, f"{cid} — {verdict} ({places}) — run: {CREDCTL} check {cid}"
    return WARN, f"{cid} — uncompared ({places}) — run: {CREDCTL} check -T {cid}"


def lines(state: CredState, now: float | None = None) -> list[tuple[str, str]]:
    """(mark, text) lines of the section — validated fields only."""
    now = time.time() if now is None else now
    if state.status == "absent":
        return [(WARN, f"no credctl check has run yet — run: {DAILY}")]
    if state.status != "ok":
        return [
            (
                WARN,
                "the credctl state file is unreadable or of an unknown version — "
                f"run: {DAILY}",
            )
        ]
    out: list[tuple[str, str]] = []
    if state.attempt in ("failed", "timeout"):
        rc = "?" if state.exit is None else str(state.exit)
        out.append(
            (
                FAIL,
                f"the last credctl check {state.attempt} (exit {rc}) at "
                f"{state.completed_at} — run: {DAILY}",
            )
        )
    elif state.attempt == "started":
        started = parse_ts(state.started_at) or 0.0
        if now - started > STARTED_GRACE_S:
            out.append(
                (
                    FAIL,
                    f"the credctl check started {state.started_at} never finished — "
                    f"run: {DAILY}",
                )
            )
        else:
            out.append((WARN, f"a credctl check is running (since {state.started_at})"))
    else:
        done = parse_ts(state.completed_at) or 0.0
        if now - done > STALE_S:
            out.append(
                (
                    WARN,
                    f"the last credctl check is from {state.completed_at} (older than "
                    f"36 h) — run: {DAILY}",
                )
            )
    if state.invalid:
        out.append((WARN, f"{state.invalid} result(s) unreadable in the state file"))
    multi = [r for r in state.results if r["location_count"] >= 2]
    shown = [r for r in multi if not r["accepted_uncompared"]]
    out += [_result_line(r) for r in sorted(shown, key=lambda r: r["id"])]
    accepted = len(multi) - len(shown)
    if accepted:
        out.append(
            (
                QUIET,
                f"{accepted} accepted as uncompared by design (external master, "
                f"machine-only or browser-only login) — list: {CREDCTL} check -e",
            )
        )
    return out


def summary(state: CredState, now: float | None = None) -> dict[str, Any]:
    """The ``credentials`` key of ``agent-login.py -j`` (validated fields only)."""
    return {
        "status": state.status,
        "attempt": state.attempt or None,
        "started_at": state.started_at or None,
        "completed_at": state.completed_at or None,
        "exit": state.exit,
        "invalid_results": state.invalid,
        "results": [r for r in state.results if r["location_count"] >= 2],
        "lines": [f"{m} {t}" for m, t in lines(state, now)],
    }


def print_section(
    color: Callable[[str, str], str],
    *,
    path: Path | None = None,
    now: float | None = None,
) -> None:
    """The overview section (after the login-keychain list)."""
    state = load(path)
    when = f", last run {state.completed_at}" if state.completed_at else ""
    print(
        color("1", "Credentials in two or more places")
        + f"  (credctl daily check{when})"
    )
    shown = lines(state, now)
    if state.status == "ok" and not any(
        r["location_count"] >= 2 for r in state.results
    ):
        shown.append((QUIET, "no credential is stored in two or more places"))
    for mark, text in shown:
        print(f"  {mark} {text}")
