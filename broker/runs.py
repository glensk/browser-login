"""Issued-run table: one row per granted ``secret`` request, closed by ``secret_done``.

``<home>/secret-runs.json`` (0600, fsync'd, atomic replace). A row holds the
nonce (32 random bytes, hex), the peer uid, the requested ``item:field`` names,
the env var NAMES, the command's basename and the issue time — never a value.
``close`` accepts a live nonce exactly once (and only from the uid it was
issued to); a second use, an unknown nonce or a row past ``RUN_TTL_S`` is
refused. ``expire`` marks rows older than ``RUN_TTL_S`` as ``abandoned`` (the
caller writes the audit line); finished rows are pruned after a day.
"""

from __future__ import annotations

import json
import os
import secrets
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from broker.statefile import write_json_atomic

RUN_TTL_S = 600.0
PRUNE_AFTER_S = 86400.0
NONCE_PREFIX_LEN = 8


class RunError(RuntimeError):
    """``secret_done`` refused (unknown, reused, expired or foreign nonce)."""


class RunStateError(RuntimeError):
    """The table exists but cannot be read — callers fail closed."""


def nonce_prefix(nonce: str) -> str:
    """The first 8 hex characters: what audit lines carry."""
    return nonce[:NONCE_PREFIX_LEN]


class RunTable:
    """Crash-safe JSON table of issued secret runs."""

    def __init__(
        self,
        path: str | os.PathLike[str],
        *,
        ttl_s: float = RUN_TTL_S,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.path = Path(path)
        self.ttl_s = ttl_s
        self.clock = clock
        self._lock = threading.Lock()

    def _load(self) -> dict[str, Any]:
        try:
            raw = self.path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return {"runs": {}}
        except OSError as exc:
            raise RunStateError(f"cannot read {self.path}") from exc
        try:
            data = json.loads(raw)
        except ValueError as exc:
            raise RunStateError(f"corrupt {self.path}") from exc
        if not isinstance(data, dict) or not isinstance(data.get("runs"), dict):
            raise RunStateError(f"corrupt {self.path}")
        return data

    def _save(self, data: dict[str, Any]) -> None:
        write_json_atomic(self.path, data)

    def _expire(self, data: dict[str, Any], now: float) -> list[dict[str, Any]]:
        abandoned = []
        for nonce, row in list(data["runs"].items()):
            if not isinstance(row, dict):
                del data["runs"][nonce]
                continue
            age = now - float(row.get("issued_at", 0))
            if row.get("state") == "open" and age >= self.ttl_s:
                row["state"] = "abandoned"
                abandoned.append({**row, "nonce": nonce_prefix(nonce)})
            elif row.get("state") != "open" and age >= PRUNE_AFTER_S:
                del data["runs"][nonce]
        return abandoned

    def issue(
        self, uid: int | None, items: list[str], env: list[str], argv0: str
    ) -> str:
        """Write an open row; returns its nonce (raises OSError/RunStateError)."""
        nonce = secrets.token_hex(32)
        with self._lock:
            data = self._load()
            now = self.clock()
            self._expire(data, now)
            data["runs"][nonce] = {
                "uid": uid,
                "items": list(items),
                "env": list(env),
                "argv0": argv0,
                "issued_at": now,
                "state": "open",
            }
            self._save(data)
        return nonce

    def close(
        self, nonce: str, uid: int | None, *, exit_code: int, masked: int
    ) -> dict[str, Any]:
        """Close a live row once; returns it (without the nonce)."""
        with self._lock:
            data = self._load()
            now = self.clock()
            self._expire(data, now)
            row = data["runs"].get(nonce)
            if not isinstance(row, dict):
                raise RunError("unknown nonce")
            if row.get("uid") != uid:
                raise RunError("nonce issued to another uid")
            if row.get("state") != "open":
                raise RunError(f"run already {row.get('state')}")
            row.update(state="done", exit=exit_code, masked=masked, done_at=now)
            self._save(data)
            return dict(row)

    def expire(self) -> list[dict[str, Any]]:
        """Mark stale open rows ``abandoned``; returns them (nonce prefix only)."""
        with self._lock:
            data = self._load()
            abandoned = self._expire(data, self.clock())
            if abandoned:
                self._save(data)
            return abandoned
