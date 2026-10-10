# pylint: disable=duplicate-code
# FROZEN copy of broker/limiter.py before WS1a (commit b58c127): the code a
# rollback would run. tests/test_ws1a_broker.py loads it against new state.
# Never edit it.
"""Per-site login rate limiter with crash-safe, fsync'd state.

An attempt is a real login (the secret was fetched and the form driven); a
re-export from a still-logged-in broker profile is not one. Outcomes:

* ``ok`` — counted against the interval and caps; clears the failure streak;
* ``failed`` — gave up BEFORE the secret was submitted; counted against the
  interval and caps only;
* ``unknown`` — any failure AFTER the secret was submitted (wrong password,
  timeout, crash). It starts a COOLDOWN (default 30 min,
  ``LOGIN_BROKER_COOLDOWN_S``) after which one attempt is allowed again; the
  ``max_consecutive``-th (default 3) such failure in a row HARD-BLOCKS the site
  until ``reset(site)``, which only the root / ``--dev`` CLI (``daemon.py -r
  SITE``) exposes. Retrying a half-known login quickly is how accounts get
  locked; waiting on sudo for every hiccup is what the broker exists to avoid.

``begin_attempt`` marks an attempt in flight on disk BEFORE the login runs; an
in-flight mark left by another (crashed) instance counts as one ``unknown``.

``reserve(keys)`` is the atomic form the secret ops use: under ONE lock it
checks every key's caps and, only when all pass, records the attempt for every
key and fsyncs the state before releasing — so N concurrent callers against a
cap of M get exactly M grants. Per-key caps come from ``key_caps`` (exact key,
else the longest matching prefix, else the instance defaults). Any state
problem denies (fail closed).
"""

from __future__ import annotations

import json
import os
import threading
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from broker.statefile import write_json_atomic

OUTCOMES = frozenset({"ok", "failed", "unknown"})
HOUR_S = 3600.0
DAY_S = 86400.0
DEFAULT_COOLDOWN_S = 30 * 60
DEFAULT_MAX_CONSECUTIVE = 3


def default_cooldown_s() -> float:
    """``$LOGIN_BROKER_COOLDOWN_S`` (seconds, > 0) or 30 min."""
    try:
        value = float(os.environ.get("LOGIN_BROKER_COOLDOWN_S", ""))
    except ValueError:
        return DEFAULT_COOLDOWN_S
    return value if value > 0 else DEFAULT_COOLDOWN_S


class LimiterStateError(RuntimeError):
    """The state file exists but cannot be read — the limiter fails closed."""


@dataclass(frozen=True)
class Reservation:
    """Granted: the attempt is recorded for every key."""

    keys: tuple[str, ...]
    ts: float


@dataclass(frozen=True)
class Denied:
    """Refused: nothing was recorded. `key` is the first key over its cap."""

    key: str
    reason: str


# (per_hour, per_day); 0 = no cap of that kind.
KeyCaps = Mapping[str, tuple[int, int]]


class Limiter:  # pylint: disable=too-many-instance-attributes  # 7 policy knobs + 2 internals
    """Minimum interval + hourly + daily caps per site; JSON state at `state_path`."""

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

    # -- persistence ------------------------------------------------------
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

    # -- API ---------------------------------------------------------------
    # One early return per blocking rule, each with its own reason.
    def check(self, site: str, now: float) -> tuple[bool, str]:  # pylint: disable=too-many-return-statements
        """(ok, reason): may a login attempt for `site` start at `now`?"""
        with self._lock:
            try:
                data = self._load()
            except LimiterStateError as exc:
                return False, f"limiter state unreadable ({exc}); reset required"
            entry = data["sites"].get(site) or {}
            inflight = entry.get("inflight")
            if (
                isinstance(inflight, dict)
                and inflight.get("instance") != self._instance
            ):
                # A crashed instance's attempt: one post-submit failure, once.
                entry = self._site(data, site)
                entry.pop("inflight", None)
                ts = float(inflight.get("ts", now))
                entry["attempts"].append([ts, "unknown"])
                self._post_submit_failure(entry, ts)
                self._save(data)
            if entry.get("blocked"):
                return False, (
                    f"{entry.get('consecutive', self.max_consecutive)} failed logins in "
                    "a row; reset required (daemon.py -r SITE as root)"
                )
            until = float(entry.get("cooldown_until") or 0)
            if now < until:
                return False, (
                    f"cooldown after a failed login: retry in {until - now:.0f}s"
                )
            stamps = [
                float(a[0])
                for a in entry.get("attempts", [])
                if isinstance(a, list) and a
            ]
            if stamps and now - max(stamps) < self.min_interval_s:
                wait = self.min_interval_s - (now - max(stamps))
                return False, f"minimum interval: retry in {wait:.0f}s"
            if sum(1 for t in stamps if now - t < HOUR_S) >= self.per_hour:
                return False, f"hourly cap of {self.per_hour} reached"
            if sum(1 for t in stamps if now - t < DAY_S) >= self.per_day:
                return False, f"daily cap of {self.per_day} reached"
            return True, ""

    def begin_attempt(self, site: str, now: float) -> None:
        """Mark an attempt in flight on disk (a crash leaves it as ``unknown``)."""
        with self._lock:
            data = self._load()
            self._site(data, site)["inflight"] = {"ts": now, "instance": self._instance}
            self._save(data)

    def record_attempt(self, site: str, now: float, outcome: str) -> None:
        """Record a finished attempt (see the module docstring for the rules)."""
        if outcome not in OUTCOMES:
            raise ValueError(f"outcome must be one of {sorted(OUTCOMES)}")
        with self._lock:
            data = self._load()
            entry = self._site(data, site)
            inflight = entry.pop("inflight", None)
            ts = float(inflight["ts"]) if isinstance(inflight, dict) else now
            attempts = [
                a
                for a in entry["attempts"]
                if isinstance(a, list) and a and now - float(a[0]) < DAY_S
            ]
            attempts.append([ts, outcome])
            entry["attempts"] = attempts
            if outcome == "unknown":
                self._post_submit_failure(entry, now)
            elif outcome == "ok":
                entry["consecutive"] = 0
                entry.pop("cooldown_until", None)
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

    def _deny_reason(self, key: str, entry: dict[str, Any], now: float) -> str:
        """Why `key` may not take another attempt at `now` ('' = it may)."""
        if entry.get("blocked"):
            return "blocked; reset required (daemon.py -r KEY as root)"
        stamps = [
            float(a[0]) for a in entry.get("attempts", []) if isinstance(a, list) and a
        ]
        if stamps and now - max(stamps) < self.min_interval_s:
            return f"minimum interval: retry in {self.min_interval_s - (now - max(stamps)):.0f}s"
        per_hour, per_day = self.caps_for(key)
        if per_hour and sum(1 for t in stamps if now - t < HOUR_S) >= per_hour:
            return f"hourly cap of {per_hour} reached for {key}"
        if per_day and sum(1 for t in stamps if now - t < DAY_S) >= per_day:
            return f"daily cap of {per_day} reached for {key}"
        return ""

    def reserve(self, keys: list[str], now: float) -> Reservation | Denied:
        """Check every key and record one attempt for all of them, atomically
        and fsync'd; any failure (cap, unreadable or unwritable state) denies."""
        uniq = tuple(dict.fromkeys(keys))
        if not uniq:
            return Denied("", "no limiter key")
        with self._lock:
            try:
                data = self._load()
            except LimiterStateError as exc:
                return Denied(
                    uniq[0], f"limiter state unreadable ({exc}); reset required"
                )
            for key in uniq:
                reason = self._deny_reason(key, data["sites"].get(key) or {}, now)
                if reason:
                    return Denied(key, reason)
            for key in uniq:
                entry = self._site(data, key)
                entry["attempts"] = [
                    a
                    for a in entry["attempts"]
                    if isinstance(a, list) and a and now - float(a[0]) < DAY_S
                ]
                entry["attempts"].append([now, "ok"])
            try:
                self._save(data)
            except OSError as exc:
                return Denied(
                    uniq[0], f"limiter state unwritable ({exc.strerror or exc})"
                )
            return Reservation(uniq, now)

    def reset(self, site: str) -> None:
        """Forget everything about `site` (root CLI only — never over the socket)."""
        with self._lock:
            try:
                data = self._load()
            except LimiterStateError:
                data = {"sites": {}}
            data["sites"].pop(site, None)
            self._save(data)
