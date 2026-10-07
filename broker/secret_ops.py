"""The login broker's secret ops (``secrets``, ``secret``, ``totp``,
``secret_done``, ``audit``, ``invalidate``) — a mixin of ``daemon.Broker``.

Only the configured peer uid is served; anything else is ``forbidden`` before
any vault read. ``secret`` is the only response that carries values, and only
after the per-item + global limiter granted the request atomically, every value
was registered with the secretkeeper (else ``leakcheck_unavailable``) and the
run row was written. Audit lines carry names, never values (see
``Broker.audit``).
"""

from __future__ import annotations

import json
import os
import re
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from broker.leakcheck import LeakCheckUnavailable, Registrar
from broker.limiter import Denied, Limiter
from broker.recipes import fresh_totp, parse_totp
from broker.runs import RunError, RunStateError, RunTable, nonce_prefix
from broker.variants import VARIANT_POLICY_VERSION
from broker.vault import (
    NO_SECRETS_COLLECTION,
    SAFE_NAME_RE,
    SITE_ID_RE,
    SecretItem,
    SecretsNotConfigured,
    Vault,
    VaultError,
    is_short,
    safe_name,
)

# Secret ops (Q3, 2026-10-07): per item, per TOTP item, and over all items.
SECRET_PER_HOUR = 120
SECRET_PER_DAY = 1000
TOTP_PER_HOUR = 20
SECRET_GLOBAL_PER_HOUR = 600
GLOBAL_SECRET_KEY = "secret:*"
SECRET_KEY_CAPS = {
    GLOBAL_SECRET_KEY: (SECRET_GLOBAL_PER_HOUR, 0),
    "secret:": (SECRET_PER_HOUR, SECRET_PER_DAY),
    "totp:": (TOTP_PER_HOUR, 0),
}
LIMITER_KEY_RE = re.compile(r"^(secret|totp):([a-z0-9][a-z0-9._-]{0,63}|\*)$")
MAX_SECRET_ITEMS = 16
MAX_ENV_NAMES = 64
ENV_NAME_RE = re.compile(r"^[A-Z_][A-Z0-9_]{0,127}$")
NONCE_RE = re.compile(r"^[0-9a-f]{64}$")
AUDIT_DEFAULT_LINES = 50
AUDIT_MAX_LINES = 500
AUDIT_TAIL_BYTES = 512 * 1024
SECRET_OPS = frozenset(
    {"secrets", "secret", "totp", "secret_done", "audit", "invalidate"}
)


def _err(code: str, detail: str = "") -> dict[str, Any]:
    return {"ok": False, "error": code, "detail": detail}


def build_secret_limiter(home: Path) -> Limiter:
    """The secret-op limiter on ``<home>/secret-limiter.json`` (keys
    ``secret:<item>``, ``totp:<item>``, ``secret:*``; caps SECRET_KEY_CAPS)."""
    return Limiter(
        home / "secret-limiter.json",
        0,
        SECRET_PER_HOUR,
        SECRET_PER_DAY,
        key_caps=SECRET_KEY_CAPS,
    )


class SecretOps:  # pylint: disable=too-few-public-methods
    """Mixin: needs the attributes ``Broker.__init__`` sets."""

    vault: Vault
    home: Path
    clock: Callable[[], float]
    allow_uid: int | None
    secret_limiter: Limiter
    runs: RunTable
    leakcheck: Registrar
    _items_lock: threading.Lock
    _items_cache: Any

    def audit(  # pylint: disable=too-many-arguments
        self,
        op: str,
        site: str | None,
        result: str,
        uid: int | None,
        extra: dict[str, Any] | None = None,
    ) -> None:
        """Provided by ``Broker``."""
        raise NotImplementedError

    def _secret_op(
        self, op: str, req: dict[str, Any], uid: int | None, extra: dict[str, Any]
    ) -> dict[str, Any]:
        if self.allow_uid is None or uid != self.allow_uid:
            return _err("forbidden")
        self._expire_runs()
        handlers: dict[str, Callable[[], dict[str, Any]]] = {
            "secrets": self._secrets,
            "secret": lambda: self._secret(req, uid, extra),
            "totp": lambda: self._totp(req, extra),
            "secret_done": lambda: self._secret_done(req, uid, extra),
            "audit": lambda: self._audit_tail(req),
            "invalidate": self._invalidate,
        }
        return handlers[op]()

    def _expire_runs(self) -> None:
        """Rows past their TTL become ``abandoned``, each with an audit line."""
        try:
            abandoned = self.runs.expire()
        except (OSError, RunStateError):
            return
        for row in abandoned:
            self.audit(
                "secret_run",
                None,
                "abandoned",
                row.get("uid"),
                {
                    "nonce": row.get("nonce"),
                    "items": row.get("items"),
                    "argv0": row.get("argv0"),
                },
            )

    def _secret_listing(self) -> dict[str, SecretItem] | dict[str, Any]:
        """{id: SecretItem}, or an error response (key "ok")."""
        try:
            return {it.secret_id: it for it in self.vault.secret_items()}
        except SecretsNotConfigured:
            return _err("refused", NO_SECRETS_COLLECTION)
        except VaultError as exc:
            return _err("vault_error", str(exc))

    def _secrets(self) -> dict[str, Any]:
        listing = self._secret_listing()
        if "ok" in listing:
            return listing
        return {"ok": True, "secrets": [it.public() for it in listing.values()]}

    @staticmethod
    # A flat validator: one early return per rule.
    # pylint: disable-next=too-many-return-statements
    def _parse_secret_request(
        req: dict[str, Any],
    ) -> tuple[list[tuple[str, str]], list[str], str] | str:
        """(item/field pairs, env names, argv0 basename) or a bad_request detail."""
        raw_items = req.get("items")
        if (
            not isinstance(raw_items, list)
            or not 1 <= len(raw_items) <= MAX_SECRET_ITEMS
        ):
            return f"items must be a list of 1-{MAX_SECRET_ITEMS} entries"
        pairs: list[tuple[str, str]] = []
        for entry in raw_items:
            if not isinstance(entry, dict):
                return 'each item is {"item": ID, "field": NAME}'
            item = entry.get("item")
            fld = entry.get("field", "password")
            if not isinstance(item, str) or not SITE_ID_RE.match(item):
                return "invalid item id"
            if not isinstance(fld, str) or not SAFE_NAME_RE.match(fld):
                return "invalid field name"
            pairs.append((item, fld))
        env = req.get("env", [])
        if not isinstance(env, list) or len(env) > MAX_ENV_NAMES:
            return "env must be a list of names"
        if not all(isinstance(e, str) and ENV_NAME_RE.match(e) for e in env):
            return "invalid env name"
        argv0 = req.get("argv0", "")
        if not isinstance(argv0, str):
            return "argv0 must be a string"
        return (
            pairs,
            list(env),
            safe_name(os.path.basename(argv0) or "-", 0, prefix="argv0"),
        )

    # One early return per protocol error code, in the order they are checked.
    # pylint: disable-next=too-many-return-statements,too-many-locals,too-many-branches
    def _secret(
        self, req: dict[str, Any], uid: int | None, extra: dict[str, Any]
    ) -> dict[str, Any]:
        parsed = self._parse_secret_request(req)
        if isinstance(parsed, str):
            return _err("bad_request", parsed)
        pairs, env, argv0 = parsed
        names = [f"{i}:{f}" for i, f in pairs]
        extra.update(items=names, env=env, argv0=argv0)
        listing = self._secret_listing()
        if "ok" in listing:
            return listing
        allow_short: dict[str, bool] = {}
        for item, fld in pairs:
            it = listing.get(item)
            if not isinstance(it, SecretItem):
                return _err(
                    "unknown_item", f"{item!r} is not in the secrets collection"
                )
            if it.refused:
                return _err("refused", f"{item}: {it.refused}")
            if fld not in it.listed:
                return _err("unknown_field", f"{item}: field {fld!r} is not exposed")
            allow_short[item] = it.allow_short
        ids = list(dict.fromkeys(i for i, _f in pairs))
        granted = self.secret_limiter.reserve(
            [f"secret:{i}" for i in ids] + [GLOBAL_SECRET_KEY], self.clock()
        )
        if isinstance(granted, Denied):
            return _err("rate_limited", granted.reason)
        values: list[str] = []
        shorts: list[bool] = []
        for item, fld in pairs:
            try:
                value = self.vault.secret_values(item).fields.get(fld)
            except VaultError as exc:
                return _err("vault_error", str(exc))
            if not value:
                return _err(
                    "unknown_field", f"{item}: field {fld!r} is listed but empty"
                )
            short = is_short(value)
            if short and not allow_short[item]:
                return _err("refused", f"{item}: value too short to mask")
            values.append(value)
            shorts.append(short)
        try:
            self.leakcheck.register([(i, f, v) for (i, f), v in zip(pairs, values)])
        except LeakCheckUnavailable as exc:
            return _err("leakcheck_unavailable", str(exc))
        try:
            nonce = self.runs.issue(uid, names, env, argv0)
        except (OSError, RunStateError):
            return _err("internal", "the run table is not writable")
        extra["nonce"] = nonce_prefix(nonce)
        resp: dict[str, Any] = {
            "ok": True,
            "values": values,
            "nonce": nonce,
            "variants_policy": VARIANT_POLICY_VERSION,
        }
        if any(shorts):
            resp["short"] = True
            resp["short_values"] = shorts
        return resp

    def _totp(self, req: dict[str, Any], extra: dict[str, Any]) -> dict[str, Any]:  # pylint: disable=too-many-return-statements
        item = req.get("item")
        if not isinstance(item, str) or not SITE_ID_RE.match(item):
            return _err("bad_request", "missing or invalid item id")
        extra["items"] = [f"{item}:totp"]
        listing = self._secret_listing()
        if "ok" in listing:
            return listing
        it = listing.get(item)
        if not isinstance(it, SecretItem):
            return _err("unknown_item", f"{item!r} is not in the secrets collection")
        if it.refused:
            return _err("refused", f"{item}: {it.refused}")
        if not it.has_totp:
            return _err("unknown_field", f"{item}: no TOTP")
        granted = self.secret_limiter.reserve(
            [f"totp:{item}", GLOBAL_SECRET_KEY], self.clock()
        )
        if isinstance(granted, Denied):
            return _err("rate_limited", granted.reason)
        try:
            seed = self.vault.secret_values(item).totp_seed
        except VaultError as exc:
            return _err("vault_error", str(exc))
        otp = parse_totp(seed or "")
        code = fresh_totp(seed or "") if otp is not None else None
        if otp is None or code is None:
            return _err("refused", f"{item}: the TOTP seed is not usable")
        valid_s = int(otp.interval - (time.time() % otp.interval))
        return {"ok": True, "code": code, "valid_s": valid_s}

    def _secret_done(
        self, req: dict[str, Any], uid: int | None, extra: dict[str, Any]
    ) -> dict[str, Any]:
        nonce = req.get("nonce")
        exit_code = req.get("exit")
        masked = req.get("masked", 0)
        if not isinstance(nonce, str) or not NONCE_RE.match(nonce):
            return _err("bad_request", "missing or invalid nonce")
        if isinstance(exit_code, bool) or not isinstance(exit_code, int):
            return _err("bad_request", "exit must be an integer")
        if isinstance(masked, bool) or not isinstance(masked, int) or masked < 0:
            return _err("bad_request", "masked must be a non-negative integer")
        extra.update(nonce=nonce_prefix(nonce), exit=exit_code, masked=masked)
        try:
            row = self.runs.close(nonce, uid, exit_code=exit_code, masked=masked)
        except RunError as exc:
            return _err("forbidden", str(exc))
        except (OSError, RunStateError):
            return _err("internal", "the run table is not readable")
        extra.update(items=row.get("items"), argv0=row.get("argv0"))
        return {"ok": True}

    def _audit_tail(self, req: dict[str, Any]) -> dict[str, Any]:
        n = req.get("n", AUDIT_DEFAULT_LINES)
        if isinstance(n, bool) or not isinstance(n, int) or n < 1:
            return _err("bad_request", "n must be a positive integer")
        n = min(n, AUDIT_MAX_LINES)
        path = self.home / "audit.log"
        try:
            with path.open("rb") as fh:
                fh.seek(0, os.SEEK_END)
                size = fh.tell()
                fh.seek(max(0, size - AUDIT_TAIL_BYTES))
                tail = fh.read()
        except FileNotFoundError:
            return {"ok": True, "lines": []}
        except OSError:
            return _err("internal", "audit log not readable")
        lines = []
        for raw in tail.splitlines()[-n:]:
            try:
                rec = json.loads(raw)
            except ValueError:
                continue
            if isinstance(rec, dict):
                lines.append(rec)
        return {"ok": True, "lines": lines}

    def _invalidate(self) -> dict[str, Any]:
        generation = self.invalidate()
        return {"ok": True, "generation": generation}

    def invalidate(self) -> int:
        """Drop cached values and the cached site list (``invalidate`` op, SIGHUP)."""
        with self._items_lock:
            self._items_cache = None
        return self.vault.invalidate()

    def refresh_leakcheck(self) -> int:
        """Re-push issued labels when the secretkeeper lost them (thread body)."""

        def fetch(item: str, fld: str) -> str | None:
            try:
                return self.vault.secret_values(item).fields.get(fld)
            except VaultError:
                return None

        try:
            pushed = self.leakcheck.refresh(fetch)
        except LeakCheckUnavailable as exc:
            self.audit(
                "leakcheck_refresh",
                None,
                "leakcheck_unavailable",
                None,
                {"detail": str(exc)},
            )
            return 0
        if pushed:
            self.audit("leakcheck_refresh", None, "ok", None, {"pushed": pushed})
        return pushed
