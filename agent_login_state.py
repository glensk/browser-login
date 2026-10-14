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
from broker.identity import ROLE_INSTANCES  # noqa: E402
from broker.limiter import owner_alive, proc_start  # noqa: E402
from broker.onboarding import CONFIG_V  # noqa: E402
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
CONFIG_RE = re.compile(r"^[0-9a-f]{64}$")
SITE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")  # broker/vault.py's rule
AUDIT_FILE = "audit.jsonl"
# A trial login's result proves that no broker request reached the password:
# the login's own free check found the session (route ``already``), or it
# stopped in one of these phases with ``submitted`` False.
PRE_SUBMIT_PHASES = frozenset({"precheck", "limiter", "vault", "profile-proof"})
# WS1b: a server probe's verdicts (Notion) as recorded in checks.json.
SERVER_VERDICTS = frozenset({"valid", "invalid", "indeterminate"})
# Two failed checks count as two in a row only this far apart (and from two
# different runs): a re-probe minutes later is not an independent result.
STREAK_SPACING_S = 3600.0


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
    instance: str = "",
    identity: str = "",
    config: str = "",
    server: str = "",
    cookie_days_left: object = None,
    run_id: str = "",
    now: float | None = None,
) -> dict[str, Any]:
    """Record a site's LATEST check (checks.json v2 + the legacy projection).

    `state` is ok / failed / unknown; an `unknown` never overwrites the
    previous `last_success`, and only `ok` sets it. `instance`: the browser
    instance the check ran in ('' = the shared one; WS5: a ✅ from another
    instance than the item's current one is stale). Returns the record.

    WS1b: `server` is a server probe's verdict (valid / invalid /
    indeterminate, Notion), `cookie_days_left` the session cookie's days to
    expiry (telemetry). ``invalid_streak`` counts RUNS with a failed verdict:
    +1 at most once per `run_id` and only ``STREAK_SPACING_S`` after the
    previous counted failure; ok resets it, unknown keeps it (the failure
    mail of an assisted site waits for 2).
    """
    if state not in STATES:
        raise ValueError(f"state must be one of {sorted(STATES)}")
    ts: float = time.time() if now is None else now
    rec: dict[str, Any] = {
        "v": CHECKS_V,
        "state": state,
        "at": ts,
        "at_text": _when(ts),
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
        "instance": instance if re.match(r"^[a-z]{0,16}$", instance or "") else "?",
        # WS5: the identity proof's verdict (a word of browser.py's fixed set;
        # '' = no proof ran).
        "identity": identity if re.match(r"^[a-z_]{0,32}$", identity or "") else "?",
        # WS3: the config digest (broker/onboarding.config_digest) of the item
        # the proof ran against ('' = unknown): a promotion holds for it only.
        "config": config if CONFIG_RE.match(config or "") else "",
        "server": server if server in SERVER_VERDICTS else "",
        "cookie_days_left": (
            cookie_days_left
            if isinstance(cookie_days_left, int)
            and not isinstance(cookie_days_left, bool)
            else None
        ),
    }

    def put(data: dict[str, Any]) -> None:
        old = data.get(site) if isinstance(data.get(site), dict) else {}
        last = old.get("last_success") if isinstance(old, dict) else None
        rec["last_success"] = ts if state == "ok" else last
        rec.update(_streak(old if isinstance(old, dict) else {}, state, run_id, ts))
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


def _streak(old: dict[str, Any], state: str, run_id: str, now: float) -> dict[str, Any]:
    """The ``invalid_streak`` fields of a new record (see `record_check`)."""
    count = old.get("invalid_streak")
    count = count if isinstance(count, int) and not isinstance(count, bool) else 0
    at = old.get("invalid_at")
    at = (
        float(at) if isinstance(at, (int, float)) and not isinstance(at, bool) else None
    )
    run = str(old.get("invalid_run") or "")
    if state == "ok":
        return {"invalid_streak": 0, "invalid_at": None, "invalid_run": ""}
    if state != "failed":
        return {"invalid_streak": count, "invalid_at": at, "invalid_run": run}
    same_run = bool(run_id) and run_id == run
    too_soon = at is not None and now - at < STREAK_SPACING_S
    if count and (same_run or too_soon):
        return {"invalid_streak": count, "invalid_at": at, "invalid_run": run}
    return {
        "invalid_streak": count + 1,
        "invalid_at": now,
        "invalid_run": run_id[:64],
    }


def drop_legacy(site: str) -> None:
    """Remove `site`'s row from the legacy ``last-check.json`` projection
    (WS1b: an on-demand site is not judged by infra/status)."""

    def drop(data: dict[str, Any]) -> None:
        data.pop(site, None)

    with contextlib.suppress(StateError, OSError):
        update(LEGACY_FILE, drop)


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
    ts: float = time.time() if now is None else now
    try:
        age = ts - float(rec.get("at", 0))
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
    ts: float = time.time() if now is None else now

    def add(data: dict[str, Any]) -> None:
        for site in sites:
            _site(data, site, ts)

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
    ts: float = time.time() if now is None else now

    def put(data: dict[str, Any]) -> None:
        entry = _site(data, site, ts)
        entry["quarantine"] = {
            "phase": phase if phase in PHASES else "unknown",
            "code": re.sub(r"[^a-z_]", "", code)[:32],
            "at": ts,
            "at_text": _when(ts),
        }
        entry.setdefault("audit", []).append(_audit_entry("quarantine", phase, ts))

    update(SITE_STATE_FILE, put, strict=True)


def release(site: str, why: str = "", now: float | None = None) -> bool:
    """Lift `site`'s quarantine (audited); False when it had none."""
    ts: float = time.time() if now is None else now
    had: list[bool] = []

    def put(data: dict[str, Any]) -> None:
        entry = _site(data, site, ts)
        had.append(bool(entry.get("quarantine")))
        entry["quarantine"] = None
        entry.setdefault("audit", []).append(_audit_entry("release", why, ts))

    update(SITE_STATE_FILE, put, strict=True)
    return bool(had and had[0])


def promote(
    site: str, why: str = "", now: float | None = None, *, config: str = ""
) -> None:
    """Mark `site` usable for scheduled logins (audited; checks are the
    caller's) — for the configuration whose digest is `config` (WS3: a
    changed item is not usable until it is promoted again)."""
    ts: float = time.time() if now is None else now

    def put(data: dict[str, Any]) -> None:
        entry = _site(data, site, ts)
        entry["stage"] = "usable"
        good = bool(CONFIG_RE.match(config or ""))
        entry["config"] = config if good else None
        entry["config_v"] = CONFIG_V if good else None
        entry.pop("trial", None)  # a promoted site starts a fresh budget later
        entry.setdefault("audit", []).append(_audit_entry("promote", why, ts))

    update(SITE_STATE_FILE, put, strict=True)


def demote(site: str, why: str = "", now: float | None = None) -> None:
    """Back to ``pending`` (audited): `agent-login.py -D` phase 1."""
    ts: float = time.time() if now is None else now

    def put(data: dict[str, Any]) -> None:
        entry = _site(data, site, ts)
        entry["stage"] = "pending"
        entry.setdefault("audit", []).append(_audit_entry("demote", why, ts))

    update(SITE_STATE_FILE, put, strict=True)


def _config_v(entry: dict[str, Any]) -> int:
    """The digest version an entry's promotion was recorded with (0 = none,
    a promotion from before WS3)."""
    value = entry.get("config_v")
    if not entry.get("config") or isinstance(value, bool) or not isinstance(value, int):
        return 0
    return value


def strict_fresh_ok(rec: dict[str, Any] | None, now: float | None = None) -> bool:
    """`rec` is a fresh (`freshness`) ✅ from the strict proof (``proof_v`` 1)."""
    if not rec or freshness(rec, now) != "ok":
        return False
    try:
        return int(rec.get("proof_v") or 0) >= 1
    except (TypeError, ValueError):
        return False


def adopt_configs(digests: dict[str, str], now: float | None = None) -> list[str]:
    """WS3 migration: a ``usable`` entry whose promotion was recorded with an
    OLDER digest version (or none: before WS3) adopts its CURRENT digest
    (`digests`, of the current `CONFIG_V`) — only while its latest check is
    a fresh strict ✅ (`strict_fresh_ok`), audited. A current-version
    promotion is never re-adopted (a changed item stays ``changed``). Call
    it only with a FRESH live listing. Returns the adopting sites."""
    ts: float = time.time() if now is None else now
    recs = checks()
    adopted: list[str] = []

    def put(data: dict[str, Any]) -> None:
        for site, digest in digests.items():
            entry = data.get(site)
            if not isinstance(entry, dict) or entry.get("stage") != "usable":
                continue
            if _config_v(entry) >= CONFIG_V or not CONFIG_RE.match(digest or ""):
                continue
            if not strict_fresh_ok(recs.get(site), ts):
                continue
            old = _config_v(entry)
            entry["config"] = digest
            entry["config_v"] = CONFIG_V
            entry.setdefault("audit", []).append(
                _audit_entry("adopt_config", f"config_v {old} -> {CONFIG_V}", ts)
            )
            adopted.append(site)

    update(SITE_STATE_FILE, put, strict=True)
    return adopted


def usable_for(entry: dict[str, Any] | None, config: str | None) -> bool:
    """`entry` is promoted FOR `config` of the current digest version (None:
    the stage alone decides)."""
    if not isinstance(entry, dict) or entry.get("stage") != "usable":
        return False
    if config is None:
        return True
    return _config_v(entry) == CONFIG_V and entry.get("config") == config


def quarantined(site: str) -> dict[str, Any] | None:
    """`site`'s quarantine record, or None (unreadable state = None here: the
    non-scheduled gate is best effort, the scheduled one is strict)."""
    try:
        entry = site_states().get(site)
    except StateError:
        return None
    q = entry.get("quarantine") if entry else None
    return q if isinstance(q, dict) else None


# One early return per refusal, in the order they are checked.
def scheduled_gate(  # pylint: disable=too-many-return-statements
    site: str, config: str | None = None
) -> tuple[bool, str, str]:
    """(allowed, code, reason) for a SCHEDULED broker login of `site`.
    Fail-closed: anything but a readable ``usable`` and unquarantined entry
    refuses; with `config` (the listed item's digest, WS3) also a promotion
    of another configuration (``changed``) or of an unknown one
    (``config_unknown``)."""
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
    if config is not None:
        stored = entry.get("config")
        if not stored or _config_v(entry) != CONFIG_V:
            return (
                False,
                "config_unknown",
                (
                    "promoted with an older (or no) config record — adopted after "
                    "a fresh strict check, or re-promote"
                ),
            )
        if stored != config:
            return False, "changed", "the item changed since its promotion"
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
    for site in gone:  # WS3: its session-age record goes with it
        delete_cache_files(site, login_log=False)
    return sorted(gone)


# ---------------------------------------------------------------------------
# WS3: the promotion trial budget (one login per site, claimed under the lock)
# ---------------------------------------------------------------------------


# A claim whose owner's start time is unknown cannot tell a reused pid from
# its owner: past this age it counts as dead. It is far beyond one promotion
# login (browser.py's LOGIN_TIMEOUT_S 480 s + the runner's 90 s margin).
TRIAL_STALE_S = 15 * 60.0


def _owner_alive(inflight: dict[str, Any], now: float | None = None) -> bool:
    """The claim's owner still runs (pid + start time, the limiter's rule).
    An unknown start time counts as alive — never recover a claim that may
    be live — until the claim is older than `TRIAL_STALE_S` (pid reuse)."""
    if not inflight.get("pid_start"):
        now = time.time() if now is None else now
        try:
            if now - float(inflight.get("at") or 0) > TRIAL_STALE_S:
                return False
        except (TypeError, ValueError):
            return False
    return owner_alive(inflight.get("pid"), inflight.get("pid_start"))


def _trial_of(entry: dict[str, Any]) -> dict[str, Any]:
    raw = entry.get("trial")
    return raw if isinstance(raw, dict) else {}


def trial_state(site: str) -> dict[str, Any]:
    """`site`'s trial record ({} = budget unspent, nothing running)."""
    try:
        entry = site_states().get(site)
    except StateError:
        return {}
    return _trial_of(entry) if isinstance(entry, dict) else {}


def _recover_trial(entry: dict[str, Any], now: float) -> None:
    """A claim whose owner died: spent, outcome unknown (it may have
    submitted)."""
    trial = entry.get("trial")
    inflight = trial.get("inflight") if isinstance(trial, dict) else None
    if isinstance(inflight, dict) and not _owner_alive(inflight, now):
        entry["trial"] = {
            "spent": True,
            "at": now,
            "at_text": _when(now),
            "phase": "unknown",
            "code": "crashed",
            "submitted": None,
            "outcome": "unknown",
        }
        entry.setdefault("audit", []).append(
            _audit_entry("trial_recovered", "owner died", now)
        )


def claim_trial(
    site: str, config: str | None = None, now: float | None = None
) -> tuple[bool, str, str]:
    """Claim `site`'s ONE promotion login (atomic, under the site-state
    flock): (claimed, code, why). Refused when the site is already usable
    for `config`, quarantined, its budget is spent, or a LIVE claim exists;
    a dead owner's claim is recovered as spent first."""
    ts: float = time.time() if now is None else now
    verdict: list[tuple[bool, str, str]] = []

    def put(data: dict[str, Any]) -> None:
        entry = _site(data, site, ts)
        _recover_trial(entry, ts)
        trial = _trial_of(entry)
        q = entry.get("quarantine")
        if usable_for(entry, config):
            verdict.append((False, "usable", "already usable for its current config"))
        elif isinstance(q, dict):
            verdict.append(
                (False, "quarantined", f"quarantined after {q.get('phase', '?')}")
            )
        elif isinstance(trial.get("inflight"), dict):
            verdict.append((False, "busy", "another promotion login is running"))
        elif trial.get("spent"):
            verdict.append(
                (
                    False,
                    "spent",
                    f"trial already used {trial.get('at_text', '?')} "
                    f"({trial.get('phase') or '?'})",
                )
            )
        else:
            entry["trial"] = {
                "inflight": {
                    "pid": os.getpid(),
                    "pid_start": proc_start(os.getpid()),
                    "at": ts,
                }
            }
            entry.setdefault("audit", []).append(_audit_entry("trial_claim", "", ts))
            verdict.append((True, "", ""))

    update(SITE_STATE_FILE, put, strict=True)
    return verdict[0]


def trial_refund(result: dict[str, Any] | None) -> bool:
    """A trial login's result proves the password was never sent: its free
    check found the session (route ``already``), or it stopped before the
    broker reached the secret (``submitted`` False in a PRE_SUBMIT_PHASES
    phase), or browser.py refused to run at all (exit 75 ``busy``: a guided
    login owns the browser — refused at registration, before any check or
    request)."""
    r = result or {}
    if r.get("route") == "already" and r.get("phase") == "ok":
        return True
    if r.get("phase") == "precheck" and r.get("code") in ("busy", "not_started"):
        return True
    return r.get("submitted") is False and r.get("phase") in PRE_SUBMIT_PHASES


def finish_trial(
    site: str, result: dict[str, Any] | None, now: float | None = None
) -> bool:
    """End `site`'s claim: refunded (budget unspent) when `trial_refund`
    holds, else spent with the phase / code / submitted it stopped at.
    Returns True when the budget was spent."""
    ts: float = time.time() if now is None else now
    r = result or {}
    refund = trial_refund(r)

    def put(data: dict[str, Any]) -> None:
        entry = _site(data, site, ts)
        if refund:
            entry.pop("trial", None)
        else:
            submitted = r.get("submitted")
            entry["trial"] = {
                "spent": True,
                "at": ts,
                "at_text": _when(ts),
                "phase": str(r.get("phase") or "unknown")
                if r.get("phase") in PHASES
                else "unknown",
                "code": re.sub(r"[^a-z_]", "", str(r.get("code") or ""))[:32],
                "submitted": submitted if isinstance(submitted, bool) else None,
                "outcome": "ok" if r.get("phase") == "ok" else "failed",
            }
        entry.setdefault("audit", []).append(
            _audit_entry("trial_finish", "refunded" if refund else "spent", ts)
        )

    update(SITE_STATE_FILE, put, strict=True)
    return not refund


def rearm(site: str, why: str = "", now: float | None = None) -> bool:
    """Give `site` its promotion login back (`-E`, audited); False when its
    budget was unspent. A LIVE claim is never re-armed."""
    ts: float = time.time() if now is None else now
    had: list[bool] = []

    def put(data: dict[str, Any]) -> None:
        entry = _site(data, site, ts)
        _recover_trial(entry, ts)
        trial = _trial_of(entry)
        if isinstance(trial.get("inflight"), dict):
            raise StateError("a promotion login is running — re-arm after it ends")
        had.append(bool(trial.get("spent")))
        entry.pop("trial", None)
        entry.setdefault("audit", []).append(_audit_entry("rearm", why, ts))

    update(SITE_STATE_FILE, put, strict=True)
    return bool(had and had[0])


# ---------------------------------------------------------------------------
# WS3: removal (`agent-login.py -D` phase 2)
# ---------------------------------------------------------------------------


def cache_dirs() -> list[Path]:
    """browser.py's cache dir of every instance (``$CLAUDE_BROWSER_CACHE_DIR``
    alone when set: the tests' and a disposable browser's)."""
    env = os.environ.get("CLAUDE_BROWSER_CACHE_DIR")
    if env:
        return [Path(env)]
    base = Path.home() / ".cache"
    names = ["claude-browser"] + [
        f"claude-browser-{i}" for i in ("private", *ROLE_INSTANCES)
    ]
    return [base / n for n in names]


def _delete_session_age(directory: Path, site: str) -> bool:
    """Delete ``<site>.json`` under the site's own flock (browser.py's
    `_session_age_lock`). The lock file itself stays — empty, no content:
    unlinking a lock another process may hold would let a second writer
    take a second inode. Never creates a lock that was not there."""
    lock = directory / f"{site}.lock"
    record = directory / f"{site}.json"
    if not record.exists():
        return False
    try:
        fd = os.open(str(lock), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    except OSError:
        return False
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        had = record.exists()
        record.unlink(missing_ok=True)
        return had
    finally:
        os.close(fd)


def delete_cache_files(site: str, *, login_log: bool = True) -> list[str]:
    """Delete `site`'s session-age record (and, with `login_log`, its real-
    login log) in every instance's cache dir; returns what went (paths)."""
    if not SITE_ID_RE.match(site):
        return []
    gone: list[str] = []
    for base in cache_dirs():
        with contextlib.suppress(OSError):
            if _delete_session_age(base / "session-age", site):
                gone.append(str(base / "session-age" / f"{site}.json"))
        if login_log:
            log = base / "login-log" / f"{site}.jsonl"
            with contextlib.suppress(OSError):
                if log.is_file() and not log.is_symlink():
                    log.unlink()
                    gone.append(str(log))
    return gone


def audit_event(
    action: str, site: str, why: str = "", now: float | None = None
) -> None:
    """One line in ``audit.jsonl`` (append-only history, never state)."""
    ts: float = time.time() if now is None else now
    rec = {"site": site if SITE_ID_RE.match(site) else "?"}
    rec.update(_audit_entry(action, why, ts))
    path = state_dir() / AUDIT_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(
        str(path), os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600
    )
    try:
        os.write(fd, (json.dumps(rec, sort_keys=True) + "\n").encode())
    finally:
        os.close(fd)


def remove_site(site: str, *, kept: dict[str, str] | None = None) -> dict[str, Any]:
    """Delete EVERY client-side trace of `site` (the caller proved with a
    fresh listing that no vault item carries it): its checks.json,
    last-check.json and site-state.json entries — quarantine and audit
    included — and its session-age / login-log files in every cache dir.
    Then one line in ``audit.jsonl``. Returns what was removed.

    `kept`: the broker kept blocking state for the site (``forget``'s
    ``left``: key -> locked / cooldown / quarantined / identity_*). Then the
    site-state entry STAYS — demoted, with a quarantine naming that state
    when it had none — so a re-added item shows the real lockout, not only
    "rate limited"; everything else goes."""
    if not SITE_ID_RE.match(site):
        raise StateError("not a site id")
    removed: dict[str, Any] = {}

    def drop(name: str) -> Callable[[dict[str, Any]], None]:
        def fn(data: dict[str, Any]) -> None:
            removed[name] = data.pop(site, None) is not None

        return fn

    if kept:
        state = next(iter(sorted(kept.values())))
        phase = "client-proof" if state.startswith("identity") else "limiter"
        if quarantined(site) is None:
            quarantine(site, phase, state)
        demote(site, why="agent-login.py -D: the broker kept a block")
        removed[SITE_STATE_FILE] = False
    else:
        update(SITE_STATE_FILE, drop(SITE_STATE_FILE), strict=True)
    update(CHECKS_FILE, drop(CHECKS_FILE))
    update(LEGACY_FILE, drop(LEGACY_FILE))
    removed["files"] = delete_cache_files(site)
    audit_event("remove", site, "agent-login.py -D")
    return removed
