"""Register every value the ``secret`` op hands out with the secretkeeper.

The secretkeeper (mydotfiles ``bin/secret-broker.py``, LaunchDaemon
``com.albert.secret-broker``) holds the value inventory the out-of-session
scanners (``secret-leak-tripwire.py``, ``transcript-secret-scan.py``,
``secret-check-index.py``) match against. Before the login broker answers a
``secret`` request it pushes the values::

  {"op": "sync", "replace": false,
   "secrets": [{"label": "loginbroker:<item>:<field>", "value": ...,
                ["raw_only": true]}]}

``raw_only`` marks a value shorter than 8 bytes (only reachable through an item
with ``agent_secret_allow_short``): the secretkeeper registers it raw-only. The
answer must list every pushed label in ``accepted`` (an older secretkeeper
without ``accepted`` counts as accepted when ``ok`` is true); anything else ->
``LeakCheckUnavailable`` and the ``secret`` op fails closed
(``leakcheck_unavailable``).

The issued ``(item, field)`` NAMES are persisted in
``<home>/leakcheck-labels.json`` (0600). The secretkeeper's inventory lives in
memory only, so a daemon thread calls ``refresh`` every ``REPUSH_INTERVAL_S``:
it asks ``ping`` for ``namespaces.loginbroker`` (this caller's label count) and
re-pushes when that is lower than the persisted set — or unconditionally when
the key is missing (an older secretkeeper). The login broker's uid may only use
``ping`` and ``sync``. Logs and errors carry labels, never values.
"""

from __future__ import annotations

import json
import os
import socket
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any, Protocol

from broker.statefile import write_json_atomic

DEFAULT_SOCKET = "/Library/SecretBroker/run/broker.sock"
NAMESPACE = "loginbroker"
REPUSH_INTERVAL_S = 600.0
RAW_ONLY_BELOW_BYTES = 8
TIMEOUT_S = 10.0
MAX_RESPONSE = 1024 * 1024


class LeakCheckUnavailable(RuntimeError):
    """The value could not be registered. The message never carries a value."""


def label_for(item: str, field: str) -> str:
    """``loginbroker:<item>:<field>``."""
    return f"{NAMESPACE}:{item}:{field}"


class Registrar(Protocol):
    """What the daemon needs from a leak-check backend."""

    def register(self, entries: list[tuple[str, str, str]]) -> None:
        """Push ``(item, field, value)`` entries or raise LeakCheckUnavailable."""

    def refresh(self, fetch: Callable[[str, str], str | None]) -> int:
        """Re-push the persisted labels when needed; returns how many."""


class DisabledLeakCheck:
    """``daemon.py --no-leakcheck`` (dev only): registers nothing."""

    def register(self, entries: list[tuple[str, str, str]]) -> None:
        """No-op."""
        del entries

    def refresh(self, fetch: Callable[[str, str], str | None]) -> int:
        """No-op."""
        del fetch
        return 0


class UnconfiguredLeakCheck:
    """The default when no backend was wired: every push fails (closed)."""

    def register(self, entries: list[tuple[str, str, str]]) -> None:
        """Always refuses."""
        del entries
        raise LeakCheckUnavailable("no secretkeeper configured")

    def refresh(self, fetch: Callable[[str, str], str | None]) -> int:
        """Nothing to refresh."""
        del fetch
        return 0


class LeakCheck:
    """Client of the secretkeeper socket + the persisted label set."""

    def __init__(
        self,
        socket_path: str | os.PathLike[str],
        labels_path: str | os.PathLike[str],
        *,
        timeout: float = TIMEOUT_S,
    ) -> None:
        self.socket_path = str(socket_path)
        self.labels_path = Path(labels_path)
        self.timeout = timeout
        self._lock = threading.Lock()

    # -- transport -----------------------------------------------------------
    def _request(self, payload: dict[str, Any]) -> dict[str, Any]:
        buf = bytearray()
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                sock.connect(self.socket_path)
                sock.sendall(json.dumps(payload).encode() + b"\n")
                while not buf.endswith(b"\n"):
                    chunk = sock.recv(65536)
                    if not chunk:
                        break
                    buf += chunk
                    if len(buf) > MAX_RESPONSE:
                        raise LeakCheckUnavailable("secretkeeper reply too large")
        except OSError as exc:
            raise LeakCheckUnavailable(
                f"secretkeeper not reachable at {self.socket_path} "
                f"({exc.strerror or type(exc).__name__})"
            ) from None
        try:
            resp = json.loads(bytes(buf))
        except ValueError:
            raise LeakCheckUnavailable("secretkeeper sent no JSON") from None
        if not isinstance(resp, dict):
            raise LeakCheckUnavailable("secretkeeper sent no JSON object")
        return resp

    # -- persisted label set -------------------------------------------------
    def persisted(self) -> list[tuple[str, str]]:
        """The ``(item, field)`` names registered so far."""
        try:
            data = json.loads(self.labels_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return []
        rows = data.get("labels") if isinstance(data, dict) else None
        out: list[tuple[str, str]] = []
        for row in rows or []:
            if isinstance(row, list) and len(row) == 2:
                out.append((str(row[0]), str(row[1])))
        return out

    def _persist(self, names: list[tuple[str, str]], *, replace: bool = False) -> None:
        old = [] if replace else self.persisted()
        merged = list(dict.fromkeys([*old, *names]))
        write_json_atomic(self.labels_path, {"labels": [list(n) for n in merged]})

    # -- API -----------------------------------------------------------------
    def register(
        self, entries: list[tuple[str, str, str]], *, replace_persisted: bool = False
    ) -> None:
        """Push the values; raises LeakCheckUnavailable unless every label is
        accepted. The names are persisted for ``refresh`` (added, or with
        `replace_persisted` the persisted set becomes exactly these)."""
        if not entries:
            return
        secrets = []
        for item, field, value in entries:
            entry: dict[str, Any] = {"label": label_for(item, field), "value": value}
            if len(value.encode("utf-8", "surrogateescape")) < RAW_ONLY_BELOW_BYTES:
                entry["raw_only"] = True
            secrets.append(entry)
        labels = [s["label"] for s in secrets]
        with self._lock:
            resp = self._request({"op": "sync", "secrets": secrets, "replace": False})
            if resp.get("ok") is not True:
                raise LeakCheckUnavailable("secretkeeper refused the sync")
            accepted = resp.get("accepted")
            if accepted is not None:
                if not isinstance(accepted, list):
                    raise LeakCheckUnavailable("secretkeeper sent a malformed reply")
                missing = [lab for lab in labels if lab not in accepted]
                if missing:
                    raise LeakCheckUnavailable(
                        "secretkeeper did not accept " + ", ".join(sorted(set(missing)))
                    )
            try:
                self._persist(
                    [(item, field) for item, field, _v in entries],
                    replace=replace_persisted,
                )
            except OSError as exc:
                raise LeakCheckUnavailable(
                    f"cannot persist the label set ({exc.strerror or exc})"
                ) from None

    def needs_repush(self) -> bool:
        """True when the secretkeeper holds fewer of our labels than we issued
        (or cannot tell: an older secretkeeper without ``namespaces``)."""
        expected = len(self.persisted())
        if not expected:
            return False
        resp = self._request({"op": "ping"})
        if resp.get("ok") is not True:
            raise LeakCheckUnavailable("secretkeeper ping failed")
        namespaces = resp.get("namespaces")
        if not isinstance(namespaces, dict):
            return True
        try:
            count = int(namespaces.get(NAMESPACE, 0))
        except (TypeError, ValueError):
            return True
        return count < expected

    def refresh(self, fetch: Callable[[str, str], str | None]) -> int:
        """Re-push every persisted label whose value `fetch` still returns; the
        persisted set shrinks to those (a removed item stops being re-pushed)."""
        if not self.needs_repush():
            return 0
        entries = []
        for item, field in self.persisted():
            value = fetch(item, field)
            if value:
                entries.append((item, field, value))
        if not entries:
            self._persist([], replace=True)
            return 0
        self.register(entries, replace_persisted=True)
        return len(entries)
