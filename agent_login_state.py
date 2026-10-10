"""agent-login's client state: check records, site stages, quarantine (WS1a).

Three files in the state dir (``~/.local/state/agent-login``, or the directory
of ``$AGENT_LOGIN_STATE_FILE`` in tests), each replaced atomically under an
exclusive ``flock`` on ``<file>.lock`` — agent-login.py and every browser.py
process write them:

* ``checks.json`` (v2) — per site the LATEST check: ``state``
  (ok / failed / unknown), when, the phase it stopped at (broker/phases.py),
  its code, a redacted detail, the failure screenshot, ``last_success``.
  The new code reads only this file.
* ``last-check.json`` — the legacy projection (``ok``/``how``/``at``) for
  older readers; written, never read.
* ``site-state.json`` — per broker site: ``stage`` (``pending`` until promoted,
  then ``usable``), ``quarantine`` (after a login that may have submitted the
  password and failed), and an audit trail of promotions and releases.

``scheduled_gate`` is fail-closed: a missing, corrupt or unreadable
``site-state.json`` refuses a scheduled login. Never page text in here
beyond the redacted detail; agents.md renders only fixed vocabulary.
"""

from __future__ import annotations

import contextlib
import fcntl
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))  # the repo's `broker`
# pylint: disable=wrong-import-position
from broker.phases import PHASES, redact  # noqa: E402

# pylint: enable=wrong-import-position

CHECKS_FILE = "checks.json"
LEGACY_FILE = "last-check.json"
SITE_STATE_FILE = "site-state.json"
CHECKS_V = 2
# A ✅ older than this reads "stale" (the daily check runs every 24 h).
MAX_STATUS_AGE_S = 36 * 3600.0
STATES = frozenset({"ok", "failed", "unknown"})
SCREENSHOT_RE = re.compile(r"^/var/db/login-broker-run/last-failure-[a-z0-9._-]+\.png$")
LOCK_TIMEOUT_S = 10.0


class StateError(RuntimeError):
    """A state file exists but cannot be read or locked (callers fail closed)."""


def state_dir() -> Path:
    """The state dir: $AGENT_LOGIN_STATE_FILE's directory, else the default."""
    env = os.environ.get("AGENT_LOGIN_STATE_FILE")
    return Path(env).parent if env else Path.home() / ".local/state/agent-login"


def max_status_age_s() -> float:
    """``$AGENT_LOGIN_MAX_STATUS_AGE_S`` (seconds, > 0) or 36 h."""
    try:
        value = float(os.environ.get("AGENT_LOGIN_MAX_STATUS_AGE_S", ""))
    except ValueError:
        return MAX_STATUS_AGE_S
    return value if value > 0 else MAX_STATUS_AGE_S


@contextlib.contextmanager
def _locked(path: Path, timeout_s: float = LOCK_TIMEOUT_S) -> Iterator[None]:
    """Exclusive flock on ``<path>.lock`` (StateError after `timeout_s`)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    lock = path.with_name(path.name + ".lock")
    try:
        fd = os.open(str(lock), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    except OSError as exc:
        raise StateError(f"cannot open {lock}") from exc
    try:
        deadline = time.monotonic() + timeout_s
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise StateError(f"{lock} stays locked") from None
                time.sleep(0.05)
        yield
    finally:
        os.close(fd)


def _read(path: Path, *, strict: bool) -> dict[str, Any]:
    """The JSON object in `path` ({} when missing); a corrupt file is {} or,
    with `strict`, a StateError."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as exc:
        if strict:
            raise StateError(f"cannot read {path}") from exc
        return {}
    if not isinstance(data, dict):
        if strict:
            raise StateError(f"{path} is not a JSON object")
        return {}
    return data


def _write(path: Path, data: dict[str, Any]) -> None:
    """Atomic replace (temp file in the same dir, 0600, fsync, rename)."""
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=1, sort_keys=True)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def update(
    name: str, fn: Callable[[dict[str, Any]], None], *, strict: bool = False
) -> dict[str, Any]:
    """Read-modify-write one state file under its lock; returns the new data."""
    path = state_dir() / name
    with _locked(path):
        data = _read(path, strict=strict)
        fn(data)
        _write(path, data)
    return data


def read(name: str, *, strict: bool = False) -> dict[str, Any]:
    """One state file (no lock: readers see the old or the new file)."""
    return _read(state_dir() / name, strict=strict)


# ---------------------------------------------------------------------------
# checks.json
# ---------------------------------------------------------------------------


def _when(ts: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(ts))


def safe_screenshot(path: object, site: str) -> str | None:
    """The broker's failure screenshot of `site`, or None for anything else."""
    text = str(path or "")
    if SCREENSHOT_RE.match(text) and text.endswith(f"last-failure-{site}.png"):
        return text
    return None


def record_check(  # pylint: disable=too-many-arguments
    site: str,
    state: str,
    how: str,
    *,
    phase: str = "",
    code: str = "",
    detail: str = "",
    screenshot: object = None,
    stop_origin: str = "",
    submitted: object = None,
    route: str = "",
    proof_v: int = 0,
    final_origin: str = "",
    origin_ok: object = None,
    now: float | None = None,
) -> dict[str, Any]:
    """Record a site's LATEST check (checks.json v2 + the legacy projection).

    `state` is ok / failed / unknown; an `unknown` never overwrites the
    previous `last_success`, and only `ok` sets it. Returns the record.
    """
    if state not in STATES:
        raise ValueError(f"state must be one of {sorted(STATES)}")
    now = time.time() if now is None else now
    rec: dict[str, Any] = {
        "v": CHECKS_V,
        "state": state,
        "at": now,
        "at_text": _when(now),
        "phase": phase if phase in PHASES else ("ok" if state == "ok" else "unknown"),
        "code": code or ("ok" if state == "ok" else ""),
        "how": redact(how, 300),
        "detail": redact(detail),
        "screenshot": safe_screenshot(screenshot, site),
        "stop_origin": stop_origin
        if re.match(r"^https?://[^/\s]+$", stop_origin or "")
        else "",
        "submitted": submitted if isinstance(submitted, bool) else None,
        "route": route if re.match(r"^[a-z-]{0,32}$", route or "") else "",
        "proof_v": int(proof_v),
        # Where the check page ended (origin only) and whether that is a proof
        # origin: `agent-login.py -x` lists the mismatches.
        "final_origin": final_origin
        if re.match(r"^https?://[^/\s]+$", final_origin or "")
        else "",
        "origin_ok": origin_ok if isinstance(origin_ok, bool) else None,
    }

    def put(data: dict[str, Any]) -> None:
        old = data.get(site) if isinstance(data.get(site), dict) else {}
        last = old.get("last_success") if isinstance(old, dict) else None
        rec["last_success"] = now if state == "ok" else last
        data[site] = rec

    update(CHECKS_FILE, put)

    def legacy(data: dict[str, Any]) -> None:
        # The contract infra/status reads (ok, how, at "YYYY-MM-DD HH:MM"):
        # ok=false is red, an `at` older than 36 h is red. A check that could
        # not tell (offline, busy, broker down) is ok=false and must NOT bump
        # `at` — it keeps the time of the last real verdict.
        old = data.get(site) if isinstance(data.get(site), dict) else {}
        at = rec["at_text"]
        if state == "unknown" and isinstance(old, dict) and old.get("at"):
            at = str(old["at"])
        data[site] = {"ok": state == "ok", "how": rec["how"], "at": at}

    with contextlib.suppress(StateError, OSError):
        update(LEGACY_FILE, legacy)
    return rec


def checks() -> dict[str, dict[str, Any]]:
    """``{site: record}`` of checks.json (v2 records only)."""
    data = read(CHECKS_FILE)
    return {
        k: v
        for k, v in data.items()
        if isinstance(v, dict) and v.get("v") == CHECKS_V and v.get("state") in STATES
    }


def freshness(rec: dict[str, Any] | None, now: float | None = None) -> str:
    """``ok`` (latest check ok and fresh), ``stale`` (ok, too old),
    ``failed``, ``unknown``, or ``unchecked`` (no record)."""
    if not rec:
        return "unchecked"
    state = str(rec.get("state"))
    if state != "ok":
        return state if state in STATES else "unknown"
    now = time.time() if now is None else now
    try:
        age = now - float(rec.get("at", 0))
    except (TypeError, ValueError):
        return "unknown"
    return "ok" if 0 <= age <= max_status_age_s() else "stale"


# ---------------------------------------------------------------------------
# site-state.json
# ---------------------------------------------------------------------------


def _site(data: dict[str, Any], site: str, now: float) -> dict[str, Any]:
    entry = data.get(site)
    if not isinstance(entry, dict):
        entry = {
            "stage": "pending",
            "quarantine": None,
            "audit": [],
            "known_since": now,
        }
        data[site] = entry
    return entry


def ensure_known(sites: list[str], now: float | None = None) -> None:
    """Every broker site not seen before starts ``pending``."""
    now = time.time() if now is None else now

    def add(data: dict[str, Any]) -> None:
        for site in sites:
            _site(data, site, now)

    update(SITE_STATE_FILE, add, strict=True)


def site_states(*, strict: bool = False) -> dict[str, dict[str, Any]]:
    """``{site: entry}`` of site-state.json."""
    return {
        k: v
        for k, v in read(SITE_STATE_FILE, strict=strict).items()
        if isinstance(v, dict)
    }


def _audit_entry(action: str, why: str, now: float) -> dict[str, Any]:
    parent = ""
    with contextlib.suppress(OSError, subprocess.SubprocessError):
        parent = subprocess.run(
            ["/bin/ps", "-o", "comm=", "-p", str(os.getppid())],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        ).stdout.strip()[-80:]
    return {
        "action": action,
        "at": now,
        "at_text": _when(now),
        "argv": " ".join(sys.argv[:4])[:200],
        "ppid": os.getppid(),
        "parent": parent,
        "session": os.environ.get("CLAUDE_SESSION_ID", "")[:64],
        "why": redact(why, 120),
    }


def quarantine(site: str, phase: str, code: str, now: float | None = None) -> None:
    """Quarantine `site` after a login that may have burnt a password attempt."""
    now = time.time() if now is None else now

    def put(data: dict[str, Any]) -> None:
        entry = _site(data, site, now)
        entry["quarantine"] = {
            "phase": phase if phase in PHASES else "unknown",
            "code": re.sub(r"[^a-z_]", "", code)[:32],
            "at": now,
            "at_text": _when(now),
        }
        entry.setdefault("audit", []).append(_audit_entry("quarantine", phase, now))

    update(SITE_STATE_FILE, put, strict=True)


def release(site: str, why: str = "", now: float | None = None) -> bool:
    """Lift `site`'s quarantine (audited); False when it had none."""
    now = time.time() if now is None else now
    had: list[bool] = []

    def put(data: dict[str, Any]) -> None:
        entry = _site(data, site, now)
        had.append(bool(entry.get("quarantine")))
        entry["quarantine"] = None
        entry.setdefault("audit", []).append(_audit_entry("release", why, now))

    update(SITE_STATE_FILE, put, strict=True)
    return bool(had and had[0])


def promote(site: str, why: str = "", now: float | None = None) -> None:
    """Mark `site` usable for scheduled logins (audited; checks are the caller's)."""
    now = time.time() if now is None else now

    def put(data: dict[str, Any]) -> None:
        entry = _site(data, site, now)
        entry["stage"] = "usable"
        entry.setdefault("audit", []).append(_audit_entry("promote", why, now))

    update(SITE_STATE_FILE, put, strict=True)


def quarantined(site: str) -> dict[str, Any] | None:
    """`site`'s quarantine record, or None (unreadable state = None here: the
    non-scheduled gate is best effort, the scheduled one is strict)."""
    try:
        entry = site_states().get(site)
    except StateError:
        return None
    q = entry.get("quarantine") if entry else None
    return q if isinstance(q, dict) else None


def scheduled_gate(site: str) -> tuple[bool, str, str]:
    """(allowed, code, reason) for a SCHEDULED broker login of `site`.
    Fail-closed: anything but a readable ``usable`` and unquarantined entry
    refuses."""
    try:
        entry = read(SITE_STATE_FILE, strict=True).get(site)
    except StateError as exc:
        return False, "state_unreadable", f"site state unreadable ({exc})"
    if not isinstance(entry, dict):
        return False, "pending", "new site, not promoted yet"
    q = entry.get("quarantine")
    if isinstance(q, dict):
        return (
            False,
            "quarantined",
            (f"quarantined after {q.get('phase', '?')} at {q.get('at_text', '?')}"),
        )
    if entry.get("stage") != "usable":
        return False, "pending", "not promoted yet"
    return True, "", ""


def prune(keep: set[str]) -> list[str]:
    """Drop every site not in `keep` from all three files; returns them.
    Call it ONLY with a fresh, live broker listing (plus the static targets).
    A site-state entry that carries a quarantine or an audit trail is never
    deleted (it is evidence, and a re-added item must not lose its quarantine)."""
    gone: set[str] = set()

    def drop(data: dict[str, Any]) -> None:
        for site in [k for k in data if k not in keep]:
            gone.add(site)
            del data[site]

    def drop_states(data: dict[str, Any]) -> None:
        for site in [k for k in data if k not in keep]:
            entry = data[site] if isinstance(data[site], dict) else {}
            if entry.get("quarantine") or entry.get("audit"):
                continue
            gone.add(site)
            del data[site]

    for name, fn, strict in (
        (CHECKS_FILE, drop, False),
        (SITE_STATE_FILE, drop_states, True),
        (LEGACY_FILE, drop, False),
    ):
        with contextlib.suppress(StateError, OSError):
            update(name, fn, strict=strict)
    return sorted(gone)
