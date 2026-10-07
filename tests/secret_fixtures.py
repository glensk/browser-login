"""Shared fixtures for the secret-op tests: random sentinels, a secrets
collection in the FixtureVault format, a fake secretkeeper socket and an
in-process broker on a temp socket.

The fake secretkeeper models the agreed protocol (tp#818): ``ping`` carries
``namespaces`` (the caller's ``loginbroker`` label count) and
``baseline_ready``; ``sync`` answers ``accepted`` / ``dropped`` (a value under
8 bytes is dropped unless the entry says ``raw_only``); ``inventory`` is
refused, like the ACL for the login broker's uid. Switches model an older
secretkeeper (no ``namespaces`` / no ``accepted``) and a refusing one.
"""

from __future__ import annotations

# pylint: disable=import-error,too-many-instance-attributes,too-many-arguments
# pylint: disable=wrong-import-position
import base64
import contextlib
import json
import os
import secrets
import shutil
import socketserver
import sys
import tempfile
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from broker import daemon, leakcheck, limiter, vault  # noqa: E402


def sentinel() -> str:
    """A random 24-byte secret value (URL-safe text, 32 characters)."""
    return secrets.token_urlsafe(24)


def totp_seed() -> str:
    """A random base32 TOTP seed."""
    return base64.b32encode(os.urandom(20)).decode()


def secret_item(
    name: str,
    password: str | None,
    *,
    fields: dict[str, str] | None = None,
    username: str = "",
    notes: str | None = None,
    totp: str | None = None,
    org: str | None = None,
    collections: list[str] | None = None,
) -> dict[str, Any]:
    """A Bitwarden-shaped item for the secrets collection."""
    item: dict[str, Any] = {
        "id": f"id-{name}",
        "name": name,
        "login": {"username": username, "password": password, "totp": totp},
        "fields": [
            {"name": k, "value": v, "type": 0} for k, v in (fields or {}).items()
        ],
    }
    if notes is not None:
        item["notes"] = notes
    if org is not None:
        item["organizationId"] = org
    if collections is not None:
        item["collectionIds"] = collections
    return item


def write_vault(path: Path, secrets_items: list[dict] | None, **extra: Any) -> Path:
    """FixtureVault file with an (optional) secrets collection."""
    data: dict[str, Any] = {"logins": [], **extra}
    if secrets_items is not None:
        data["secrets"] = secrets_items
    path.write_text(json.dumps(data))
    return path


class FakeSecretkeeper:
    """A Unix-socket stand-in for mydotfiles' secret-broker.py."""

    def __init__(
        self,
        path: str,
        *,
        namespaces: bool = True,
        accepted: bool = True,
        refuse: bool = False,
    ) -> None:
        self.path = path
        self.namespaces = namespaces
        self.accepted = accepted
        self.refuse = refuse
        self.labels: dict[str, tuple[str, bool]] = {}
        self.syncs: list[dict[str, Any]] = []
        self.ops: list[str] = []
        self.lock = threading.Lock()
        fake = self

        class Handler(socketserver.StreamRequestHandler):
            def handle(self) -> None:
                line = self.rfile.readline()
                try:
                    req = json.loads(line)
                except ValueError:
                    req = {}
                resp = fake.answer(req if isinstance(req, dict) else {})
                self.wfile.write(json.dumps(resp).encode() + b"\n")

        self.server = socketserver.ThreadingUnixStreamServer(path, Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def answer(self, req: dict[str, Any]) -> dict[str, Any]:
        """One request -> one answer."""
        op = req.get("op")
        with self.lock:
            self.ops.append(str(op))
            if op == "ping":
                resp: dict[str, Any] = {"ok": True, "labels": len(self.labels)}
                if self.namespaces:
                    count = sum(1 for k in self.labels if k.startswith("loginbroker:"))
                    resp["namespaces"] = {"loginbroker": count}
                    resp["baseline_ready"] = True
                return resp
            if op == "inventory":
                return {"ok": False, "error": "uid 450 not allowed for inventory"}
            if op == "sync":
                self.syncs.append(req)
                if self.refuse:
                    return {"ok": False, "error": "uid not allowed"}
                accepted, dropped = [], []
                for entry in req.get("secrets") or []:
                    label = str(entry.get("label"))
                    value = str(entry.get("value"))
                    raw_only = bool(entry.get("raw_only"))
                    if len(value.encode()) < 8 and not raw_only:
                        dropped.append({"label": label, "reason": "too short"})
                        continue
                    self.labels[label] = (value, raw_only)
                    accepted.append(label)
                resp = {"ok": True, "labels": len(self.labels)}
                if self.accepted:
                    resp["accepted"] = accepted
                    resp["dropped"] = dropped
                return resp
            return {"ok": False, "error": f"unknown op {op!r}"}

    def restart(self) -> None:
        """Model a secretkeeper restart: the in-memory inventory is empty."""
        with self.lock:
            self.labels.clear()

    def close(self) -> None:
        """Stop serving."""
        self.server.shutdown()
        self.server.server_close()


@contextlib.contextmanager
def sockdir() -> Iterator[Path]:
    """A short temp dir (AF_UNIX paths are capped at 104 bytes on macOS)."""
    d = tempfile.mkdtemp(prefix="sr-")
    try:
        yield Path(d)
    finally:
        shutil.rmtree(d, ignore_errors=True)


class _NoRunner:  # pylint: disable=too-few-public-methods
    def __call__(self, item: Any, get_secret: Any) -> dict[str, Any]:
        raise AssertionError("no login expected")


def make_broker(
    home: Path,
    vault_path: Path,
    *,
    allow_uid: int | None,
    keeper_sock: str | None,
    secret_limiter: limiter.Limiter | None = None,
) -> daemon.Broker:
    """A Broker on a FixtureVault; leak check against `keeper_sock` (None =
    the default, failing backend)."""
    reg = (
        leakcheck.LeakCheck(keeper_sock, home / "leakcheck-labels.json")
        if keeper_sock
        else None
    )
    return daemon.Broker(
        vault.FixtureVault(vault_path, dev=True),
        limiter.Limiter(home / "limiter.json", 0, 100, 100),
        home,
        runner=_NoRunner(),
        allow_uid=allow_uid,
        secret_limiter=secret_limiter,
        leakcheck=reg,
    )


@contextlib.contextmanager
def serving(broker: daemon.Broker, path: str, allow_uid: int) -> Iterator[str]:
    """The broker on a real Unix socket (a thread) for the test's lifetime."""
    srv = daemon.make_server(path, broker, allow_uid)
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    try:
        yield path
    finally:
        srv.shutdown()
        srv.server_close()
