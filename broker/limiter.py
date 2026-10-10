"""Per-key login rate limiter with crash-safe, fsync'd, flock'ed state.

An attempt is a real login (the secret was fetched and the form driven); a
re-export from a still-logged-in broker profile is not one. Stored outcomes:

* ``ok`` — a fresh authentication was PROVEN (sentinel after a submit);
  counted against the interval and caps; clears the failure streak;
* ``failed`` — nothing was submitted (gave up before, or the session was still
  valid); counted against the interval and caps only;
* ``unknown`` — anything after the secret was submitted that is not a proven
  login (wrong password, timeout, crash). It starts a COOLDOWN (default 30 min,
  ``LOGIN_BROKER_COOLDOWN_S``) after which one attempt is allowed again; the
  ``max_consecutive``-th (default 3) such failure in a row HARD-BLOCKS the key
  until ``reset(key)``, which only the root / ``--dev`` CLI (``daemon.py -r
  KEY``) exposes. Retrying a half-known login quickly is how accounts get
  locked; waiting on sudo for every hiccup is what the broker exists to avoid.

Logins use the OUTCOME-AWARE attempt API. The keys of a site are the site id
plus ``group:<id>`` for its current attempt group AND every group it was ever
bound to (a group change never escapes an old group's block); the binding is
recorded on every reservation, granted or denied. ``peek_site`` reports (never
records), ``reserve_site`` checks every key atomically and, only when all pass,
writes a ``pending`` attempt and a ``reserved`` in-flight mark on each.
``mark_entered`` (the password is about to reach the page) and
``mark_submitted`` (the submitting click/Enter is next) advance the mark;
``finish`` closes it with ``ok`` | ``not_submitted`` | ``unknown``. Every key
enforces the hard block, its cooldown, "another attempt in flight" (``busy``),
for a SCHEDULED reservation any unresolved post-submit failure
(``quarantined``), the minimum interval and the caps.

Crash recovery: a mark whose owner is gone (another instance, and its pid dead
or reused — start time differs) is finished on the next reservation or peek of
that key: ``entered``/``submitted`` → ``unknown``, ``reserved`` →
``not_submitted``. A live owner's mark is never touched, however old. The
older ``begin_attempt``/``record_attempt`` pair (one key, mark without pid)
keeps its rule: a mark of another instance counts as ``unknown``.

``reserve(keys)`` is the atomic form the secret ops use: under ONE lock it
checks every key's caps and, only when all pass, records the attempt for every
key and fsyncs the state before releasing — so N concurrent callers against a
cap of M get exactly M grants. Per-key caps come from ``key_caps`` (exact key,
else the longest matching prefix, else the instance defaults). Any state
problem denies (fail closed).

Every read-modify-write holds the thread lock AND an exclusive ``flock`` on
``<state>.lock`` (opened without following symlinks; it must be a regular file
with one link) — the daemon and a root ``daemon.py -r`` never interleave, and
``reset`` refuses a key a live owner is logging in on. Old code reading new
state only reads ``attempts[i][0]``; group keys and 3-element attempts are
invisible to it.
"""

from __future__ import annotations

import contextlib
import fcntl
import json
import os
import stat
import subprocess
import threading
import uuid
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from broker.statefile import write_json_atomic

OUTCOMES = frozenset({"ok", "failed", "unknown"})
# finish() outcome -> the attempt outcome stored on every key
FINISH_OUTCOMES = {
    "ok": "ok",
    "not_submitted": "failed",
    "unknown": "unknown",
    # A proven candidate-sentinel login: counted for interval and caps, but it
    # never clears a streak or a cooldown (its proof was not trusted yet).
    "candidate": "candidate",
}
# In-flight states after which a crash counts as a post-submit failure.
RISKY_STATES = frozenset({"entered", "submitted"})
HOUR_S = 3600.0
DAY_S = 86400.0
DEFAULT_COOLDOWN_S = 30 * 60
DEFAULT_MAX_CONSECUTIVE = 3
RESET_HINT = "sudo install/install.sh -r {key}"


def default_cooldown_s() -> float:
    """``$LOGIN_BROKER_COOLDOWN_S`` (seconds, > 0) or 30 min."""
    try:
        value = float(os.environ.get("LOGIN_BROKER_COOLDOWN_S", ""))
    except ValueError:
        return DEFAULT_COOLDOWN_S
    return value if value > 0 else DEFAULT_COOLDOWN_S


def pid_alive(pid: object) -> bool:
    """True when `pid` names a running process (any owner); False for a bad pid."""
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def proc_start(pid: int) -> str | None:
    """The start time ``ps`` reports for `pid` (None when unknown). Pinned to
    the C locale and UTC: the daemon (_loginbroker), a root reset and a test
    must read the same string for the same process."""
    try:
        out = subprocess.run(
            ["/bin/ps", "-o", "lstart=", "-p", str(int(pid))],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
            env={"LC_ALL": "C", "LANG": "C", "TZ": "UTC", "PATH": "/bin:/usr/bin"},
        )
    except (OSError, subprocess.SubprocessError, ValueError):
        return None
    text = out.stdout.strip()
    return text or None


def group_key(group: str) -> str:
    """The limiter key of an attempt group."""
    return f"group:{group}"


class LimiterStateError(RuntimeError):
    """The state file exists but cannot be read — the limiter fails closed."""


class LimiterBusy(RuntimeError):
    """``reset`` refused: a live owner holds an in-flight mark on the key."""


@dataclass(frozen=True)
class Reservation:
    """Granted: the attempt is recorded for every key."""

    keys: tuple[str, ...]
    ts: float


@dataclass(frozen=True)
class AttemptGrant:
    """A granted login attempt: ``pending`` attempt + in-flight mark on every key."""

    attempt_id: str
    keys: tuple[str, ...]
    ts: float


@dataclass(frozen=True)
class Denied:
    """Refused: no attempt was recorded. `key` is the first blocking key.

    `state` classifies the refusal (``locked`` | ``cooldown`` | ``quarantined``
    | ``busy`` | ``interval`` | ``cap`` | ``unreadable``); `retry_s` says when
    it lifts (0 = only a reset or a release lifts it)."""

    key: str
    reason: str
    state: str = "cap"
    retry_s: float = 0.0
    consecutive: int = 0

    def limit(self) -> dict[str, Any]:
        """The secret-free ``limit`` object of a broker reply."""
        out: dict[str, Any] = {
            "key": self.key,
            "state": self.state,
            "retry_s": round(self.retry_s),
            "consecutive": self.consecutive,
        }
        if self.state in ("locked", "unreadable"):
            out["reset"] = RESET_HINT.format(key=self.key)
        elif self.state == "cooldown":
            out["reset"] = f"wait {self.retry_s:.0f}s, or " + RESET_HINT.format(
                key=self.key
            )
        elif self.state == "quarantined":
            out["reset"] = (
                "an approved manual login (./agent-login.py -t SITE), or "
                + RESET_HINT.format(key=self.key)
            )
        return out


# (per_hour, per_day); 0 = no cap of that kind.
KeyCaps = Mapping[str, tuple[int, int]]


class Limiter:  # pylint: disable=too-many-instance-attributes,too-many-public-methods
    """Minimum interval + hourly + daily caps per key; JSON state at `state_path`."""

    def __init__(  # pylint: disable=too-many-arguments
        self,
        state_path: str | os.PathLike[str],
        min_interval_s: float,
        per_hour: int,
        per_day: int,
        *,
        cooldown_s: float | None = None,
        max_consecutive: int = DEFAULT_MAX_CONSECUTIVE,
        key_caps: KeyCaps | None = None,
    ) -> None:
        self.state_path = Path(state_path)
        self.key_caps = dict(key_caps or {})
        self.cooldown_s = default_cooldown_s() if cooldown_s is None else cooldown_s
        self.max_consecutive = int(max_consecutive)
        self.min_interval_s = float(min_interval_s)
        self.per_hour = int(per_hour)
        self.per_day = int(per_day)
        self._instance = uuid.uuid4().hex
        self._lock = threading.Lock()
        self._pid_start: str | None = None
        # Attempts whose `finish` could not be written: attempt id -> stored
        # outcome. Our own in-flight mark of such an attempt is recovered with
        # that outcome on the next read, so the key is not "busy" until restart.
        self._unfinished: dict[str, str] = {}

    @property
    def lock_path(self) -> Path:
        """The sidecar lock file every read-modify-write flocks."""
        return self.state_path.with_name(self.state_path.name + ".lock")

    # -- persistence ------------------------------------------------------
    def _open_lock(self) -> int:
        """The lock file's descriptor: no symlink, a regular file, one link."""
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(self.lock_path), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            os.close(fd)
            raise LimiterStateError(f"{self.lock_path} is not a plain file")
        return fd

    @contextlib.contextmanager
    def _locked(self) -> Iterator[int]:
        """Thread lock + exclusive flock on the sidecar (yields its descriptor);
        LimiterStateError when it cannot be opened (fail closed)."""
        with self._lock:
            try:
                fd = self._open_lock()
            except OSError as exc:
                raise LimiterStateError(f"cannot lock {self.lock_path}") from exc
            try:
                fcntl.flock(fd, fcntl.LOCK_EX)
                yield fd
            finally:
                os.close(fd)  # closing the descriptor drops the flock

    def ensure_lock_file(self) -> None:
        """Create the lock file now (the daemon at start: it owns it then)."""
        with self._locked():
            pass

    def _load(self) -> dict[str, Any]:
        try:
            raw = self.state_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return {"sites": {}}
        except OSError as exc:
            raise LimiterStateError(f"cannot read {self.state_path}") from exc
        try:
            data = json.loads(raw)
        except ValueError as exc:
            raise LimiterStateError(f"corrupt {self.state_path}") from exc
        if not isinstance(data, dict) or not isinstance(data.get("sites"), dict):
            raise LimiterStateError(f"corrupt {self.state_path}")
        return data

    def _save(self, data: dict[str, Any]) -> None:
        write_json_atomic(self.state_path, data)

    @staticmethod
    def _site(data: dict[str, Any], site: str) -> dict[str, Any]:
        entry: dict[str, Any] = data["sites"].setdefault(site, {})
        entry.setdefault("attempts", [])
        return entry

    def _post_submit_failure(self, entry: dict[str, Any], ts: float) -> None:
        """One more failure after submission: cooldown, or the hard block."""
        streak = int(entry.get("consecutive", 0)) + 1
        entry["consecutive"] = streak
        if streak >= self.max_consecutive:
            entry["blocked"] = True
        else:
            entry["cooldown_until"] = ts + self.cooldown_s

    def _apply_outcome(self, entry: dict[str, Any], stored: str, ts: float) -> None:
        """The streak rules of one finished attempt on one key."""
        if stored == "unknown":
            self._post_submit_failure(entry, ts)
        elif stored == "ok":
            entry["consecutive"] = 0
            entry.pop("cooldown_until", None)

    @staticmethod
    def _prune(entry: dict[str, Any], now: float) -> None:
        entry["attempts"] = [
            a
            for a in entry.get("attempts", [])
            if isinstance(a, list) and a and now - float(a[0]) < DAY_S
        ]

    def _my_start(self) -> str | None:
        if self._pid_start is None:
            self._pid_start = proc_start(os.getpid())
        return self._pid_start

    def _owner_alive(self, inflight: dict[str, Any]) -> bool:
        """The mark's owner still runs: its pid is alive with the recorded
        start time (unknown start time on either side = alive: never recover
        a mark that might be live)."""
        pid = inflight.get("pid")
        if not pid_alive(pid):
            return False
        want = inflight.get("pid_start")
        if not want or not isinstance(pid, int):
            return True
        now_start = proc_start(pid)
        return now_start is None or now_start == want

    def _abandoned(self, inflight: dict[str, Any]) -> bool:
        """An in-flight mark of a dead owner (see the module docstring), or
        one of ours whose `finish` failed to persist."""
        if inflight.get("instance") == self._instance:
            return str(inflight.get("id")) in self._unfinished
        if "pid" not in inflight:  # a begin_attempt mark: the old rule
            return True
        return not self._owner_alive(inflight)

    def _recover(self, data: dict[str, Any], keys: tuple[str, ...], now: float) -> bool:
        """Finish dead owners' in-flight marks on `keys`; True when changed."""
        changed = False
        for key in keys:
            entry = data["sites"].get(key)
            if not isinstance(entry, dict):
                continue
            inflight = entry.get("inflight")
            if not isinstance(inflight, dict) or not self._abandoned(inflight):
                continue
            entry = self._site(data, key)
            entry.pop("inflight", None)
            try:
                ts = float(inflight.get("ts", now))
            except (TypeError, ValueError):
                ts = now
            risky = "pid" not in inflight or inflight.get("state") in RISKY_STATES
            stored = "unknown" if risky else "failed"
            if inflight.get("instance") == self._instance:  # our failed finish
                stored = self._unfinished.get(str(inflight.get("id")), stored)
            self._set_attempt(entry, inflight.get("id"), ts, stored)
            self._apply_outcome(entry, stored, ts)
            changed = True
        return changed

    @staticmethod
    def _set_attempt(
        entry: dict[str, Any], attempt_id: object, ts: float, stored: str
    ) -> None:
        """Rewrite attempt `attempt_id`'s outcome, else append a new one."""
        for a in entry.setdefault("attempts", []):
            if (
                isinstance(a, list)
                and len(a) >= 3
                and attempt_id
                and a[2] == attempt_id
            ):
                a[1] = stored
                return
        entry["attempts"].append([ts, stored])

    # -- bindings -------------------------------------------------------------
    @staticmethod
    def _bound_groups(data: dict[str, Any], site: str) -> list[str]:
        entry = data["sites"].get(site)
        groups = entry.get("groups") if isinstance(entry, dict) else None
        return [g for g in groups if isinstance(g, str) and g] if groups else []

    def _bind(self, data: dict[str, Any], site: str, group: str | None) -> list[str]:
        """Record `group` for `site` (current first); returns every bound group."""
        bound = self._bound_groups(data, site)
        if group and (not bound or bound[0] != group):
            bound = [group, *[g for g in bound if g != group]]
            self._site(data, site)["groups"] = bound
        return bound

    def site_keys(self, site: str, group: str | None = None) -> list[str]:
        """The keys a login of `site` is checked against (bindings included)."""
        try:
            with self._locked():
                bound = self._bound_groups(self._load(), site)
        except (LimiterStateError, OSError):
            bound = []
        groups = list(dict.fromkeys([g for g in [group, *bound] if g]))
        return [site, *(group_key(g) for g in groups)]

    # -- API ---------------------------------------------------------------
    def check(self, site: str, now: float) -> tuple[bool, str]:
        """(ok, reason): may a login attempt for `site` start at `now`? (one key)"""
        denied = self.peek([site], now)
        return (True, "") if denied is None else (False, denied.reason)

    def peek(
        self, keys: list[str], now: float, *, scheduled: bool = False
    ) -> Denied | None:
        """None when an attempt over `keys` may start at `now`, else why not.
        Finishes dead owners' in-flight marks; never records an attempt."""
        uniq = tuple(dict.fromkeys(keys))
        key = uniq[0] if uniq else ""
        try:
            with self._locked():
                data = self._load()
                if self._recover(data, uniq, now):
                    self._save(data)
                return self._first_denial(data, uniq, now, scheduled=scheduled)
        except (LimiterStateError, OSError) as exc:
            return Denied(
                key, f"limiter state unreadable ({exc}); reset required", "unreadable"
            )

    def blocking(self, keys: list[str], now: float) -> Denied | None:
        """`peek` as a PURE read (no crash recovery, nothing written): what a
        root process may call without leaving a root-owned state file."""
        uniq = tuple(dict.fromkeys(keys))
        try:
            with self._locked():
                data = self._load()
        except (LimiterStateError, OSError):
            return None
        return self._first_denial(data, uniq, now, busy=False)

    def peek_site(
        self, site: str, now: float, *, group: str | None = None
    ) -> Denied | None:
        """`peek` over a site's keys (bindings included) — reporting only."""
        return self.peek(self.site_keys(site, group), now)

    def _first_denial(
        self,
        data: dict[str, Any],
        keys: tuple[str, ...],
        now: float,
        *,
        scheduled: bool = False,
        busy: bool = True,
    ) -> Denied | None:
        for key in keys:
            denied = self._deny(
                key, data["sites"].get(key) or {}, now, scheduled=scheduled, busy=busy
            )
            if denied is not None:
                return denied
        return None

    # One early return per blocking rule, in the order they are checked.
    def _deny(  # pylint: disable=too-many-return-statements,too-many-arguments
        self,
        key: str,
        entry: dict[str, Any],
        now: float,
        *,
        scheduled: bool,
        busy: bool,
    ) -> Denied | None:
        """Why `key` may not take another attempt at `now` (None = it may)."""
        streak = int(entry.get("consecutive", 0) or 0)
        if entry.get("blocked"):
            return Denied(
                key,
                f"{entry.get('consecutive', self.max_consecutive)} failed logins in "
                f"a row; reset required ({RESET_HINT.format(key=key)})",
                "locked",
                0.0,
                streak,
            )
        until = float(entry.get("cooldown_until") or 0)
        if now < until:
            return Denied(
                key,
                f"cooldown after a failed login: retry in {until - now:.0f}s",
                "cooldown",
                until - now,
                streak,
            )
        if scheduled and streak > 0:
            return Denied(
                key,
                f"{streak} unresolved failed login(s) on {key}: a scheduled run "
                "or a candidate-sentinel login never retries it",
                "quarantined",
                0.0,
                streak,
            )
        if busy and isinstance(entry.get("inflight"), dict):
            return Denied(key, f"another login attempt on {key} is in progress", "busy")
        stamps = [
            float(a[0]) for a in entry.get("attempts", []) if isinstance(a, list) and a
        ]
        if stamps and now - max(stamps) < self.min_interval_s:
            wait = self.min_interval_s - (now - max(stamps))
            return Denied(
                key, f"minimum interval: retry in {wait:.0f}s", "interval", wait, streak
            )
        per_hour, per_day = self.caps_for(key)
        hour = [t for t in stamps if now - t < HOUR_S]
        if per_hour and len(hour) >= per_hour:
            wait = HOUR_S - (now - min(hour))
            return Denied(
                key, f"hourly cap of {per_hour} reached for {key}", "cap", wait, streak
            )
        day = [t for t in stamps if now - t < DAY_S]
        if per_day and len(day) >= per_day:
            wait = DAY_S - (now - min(day))
            return Denied(
                key, f"daily cap of {per_day} reached for {key}", "cap", wait, streak
            )
        return None

    def reserve_site(
        self,
        site: str,
        now: float,
        *,
        group: str | None = None,
        scheduled: bool = False,
        candidate: bool = False,
    ) -> AttemptGrant | Denied:
        """Bind `group` to `site`, then check every key of the site (bindings
        included) and, only when all pass, record a ``pending`` attempt and a
        ``reserved`` in-flight mark on each — atomically and fsync'd. A
        `scheduled` or `candidate` reservation is also refused while any key
        has an unresolved post-submit failure."""
        attempt_id = uuid.uuid4().hex
        try:
            with self._locked():
                data = self._load()
                groups = list(
                    dict.fromkeys(
                        [g for g in [group, *self._bind(data, site, group)] if g]
                    )
                )
                keys = (site, *(group_key(g) for g in groups))
                self._recover(data, keys, now)
                denied = self._first_denial(
                    data, keys, now, scheduled=scheduled or candidate
                )
                if denied is None:
                    self._grant(data, keys, now, attempt_id)
                self._save(data)
        except (LimiterStateError, OSError) as exc:
            return Denied(
                site, f"limiter state unusable ({exc}); reset required", "unreadable"
            )
        return denied if denied is not None else AttemptGrant(attempt_id, keys, now)

    def _grant(
        self, data: dict[str, Any], keys: tuple[str, ...], now: float, attempt_id: str
    ) -> None:
        for key in keys:
            entry = self._site(data, key)
            self._prune(entry, now)
            entry["attempts"].append([now, "pending", attempt_id])
            entry["inflight"] = {
                "id": attempt_id,
                "ts": now,
                "state": "reserved",
                "instance": self._instance,
                "pid": os.getpid(),
                "pid_start": self._my_start(),
            }

    def _update_attempt(
        self,
        grant: AttemptGrant,
        fn: Callable[[dict[str, Any], dict[str, Any]], None],
    ) -> None:
        """Apply `fn(entry, inflight)` to every key still holding the grant's mark."""
        with self._locked():
            data = self._load()
            for key in grant.keys:
                entry = data["sites"].get(key)
                if not isinstance(entry, dict):
                    continue
                inflight = entry.get("inflight")
                if (
                    isinstance(inflight, dict)
                    and inflight.get("id") == grant.attempt_id
                ):
                    fn(entry, inflight)
            self._save(data)

    def _advance(self, grant: AttemptGrant, state: str) -> None:
        def mark(_entry: dict[str, Any], inflight: dict[str, Any]) -> None:
            if inflight.get("state") != "submitted":
                inflight["state"] = state

        self._update_attempt(grant, mark)

    def mark_entered(self, grant: AttemptGrant) -> None:
        """The password is about to reach the page: from now on a CRASH counts
        as a post-submit failure. Raises on a state error (do not type then)."""
        self._advance(grant, "entered")

    def mark_submitted(self, grant: AttemptGrant) -> None:
        """The submitting click/Enter is next: the attempt is post-submit from
        now on. Raises on a state error — the caller must not submit then."""
        self._advance(grant, "submitted")

    def finish(self, grant: AttemptGrant, outcome: str, now: float) -> None:
        """Close the attempt on every key with `outcome` (see FINISH_OUTCOMES)."""
        stored = FINISH_OUTCOMES.get(outcome)
        if stored is None:
            raise ValueError(f"outcome must be one of {sorted(FINISH_OUTCOMES)}")

        def done(entry: dict[str, Any], _inflight: dict[str, Any]) -> None:
            entry.pop("inflight", None)
            self._set_attempt(entry, grant.attempt_id, grant.ts, stored)
            self._apply_outcome(entry, stored, now)
            self._prune(entry, now)

        try:
            self._update_attempt(grant, done)
        except BaseException:
            # Not persisted: remember the outcome so the next read of these
            # keys recovers our own mark with it (never "busy" until restart).
            self._unfinished[grant.attempt_id] = stored
            raise
        self._unfinished.pop(grant.attempt_id, None)

    def begin_attempt(self, site: str, now: float) -> None:
        """Mark an attempt in flight on disk (a crash leaves it as ``unknown``)."""
        with self._locked():
            data = self._load()
            self._site(data, site)["inflight"] = {"ts": now, "instance": self._instance}
            self._save(data)

    def record_attempt(self, site: str, now: float, outcome: str) -> None:
        """Record a finished attempt (see the module docstring for the rules)."""
        if outcome not in OUTCOMES:
            raise ValueError(f"outcome must be one of {sorted(OUTCOMES)}")
        with self._locked():
            data = self._load()
            entry = self._site(data, site)
            inflight = entry.pop("inflight", None)
            ts = float(inflight["ts"]) if isinstance(inflight, dict) else now
            self._prune(entry, now)
            entry["attempts"].append([ts, outcome])
            self._apply_outcome(entry, outcome, now)
            self._save(data)

    def caps_for(self, key: str) -> tuple[int, int]:
        """(per_hour, per_day) of `key`: exact entry, longest prefix, defaults."""
        if key in self.key_caps:
            return self.key_caps[key]
        best = ""
        for prefix in self.key_caps:
            if key.startswith(prefix) and len(prefix) > len(best):
                best = prefix
        if best:
            return self.key_caps[best]
        return self.per_hour, self.per_day

    def reserve(self, keys: list[str], now: float) -> Reservation | Denied:
        """Check every key and record one attempt for all of them, atomically
        and fsync'd; any failure (cap, unreadable or unwritable state) denies."""
        uniq = tuple(dict.fromkeys(keys))
        if not uniq:
            return Denied("", "no limiter key", "unreadable")
        try:
            with self._locked():
                data = self._load()
                denied = self._first_denial(data, uniq, now, busy=False)
                if denied is not None:
                    return denied
                for key in uniq:
                    entry = self._site(data, key)
                    self._prune(entry, now)
                    entry["attempts"].append([now, "ok"])
                try:
                    self._save(data)
                except OSError as exc:
                    return Denied(
                        uniq[0],
                        f"limiter state unwritable ({exc.strerror or exc})",
                        "unreadable",
                    )
                return Reservation(uniq, now)
        except LimiterStateError as exc:
            return Denied(
                uniq[0],
                f"limiter state unreadable ({exc}); reset required",
                "unreadable",
            )

    def groups_of(self, site: str) -> list[str]:
        """Every group `site` is bound to, current first ([] when unreadable)."""
        try:
            with self._locked():
                return self._bound_groups(self._load(), site)
        except (LimiterStateError, OSError):
            return []

    def reset(
        self,
        key: str,
        *,
        owner: tuple[int, int] | None = None,
        keep_bindings: bool = True,
    ) -> list[str]:
        """Forget everything about `key` (root CLI only — never over the socket)
        but, unless `keep_bindings` is False, the groups the site is bound to:
        a later ``-r SITE -G`` must still find them, and a group change must
        never escape an old group's block. Returns those bound groups.

        Raises LimiterBusy while a LIVE owner holds an in-flight mark on it.
        Other keys stay as they are; no crash recovery runs here. `owner`
        (uid, gid): chown the replaced state (never following a symlink) and
        the lock file BEFORE the lock is released.
        """
        with self._locked() as fd:
            try:
                data = self._load()
            except LimiterStateError:
                data = {"sites": {}}
            entry = data["sites"].get(key)
            inflight = entry.get("inflight") if isinstance(entry, dict) else None
            if isinstance(inflight, dict) and not self._abandoned(inflight):
                raise LimiterBusy(
                    f"a login is in flight on {key} (pid {inflight.get('pid')}) — "
                    "retry after it ends, or stop the daemon first"
                )
            groups = self._bound_groups(data, key)
            data["sites"].pop(key, None)
            if keep_bindings and groups:
                data["sites"][key] = {"attempts": [], "groups": groups}
            self._save(data)
            if owner is not None:
                os.chown(self.state_path, *owner, follow_symlinks=False)
                os.fchown(fd, *owner)
            return groups
