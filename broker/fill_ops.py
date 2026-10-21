"""The login broker's ``safari_fill`` op (tp#1082) — a mixin of ``daemon.Broker``.

An agent (peer uid ``--allow-uid`` only) asks for the username / password or
the TOTP code of ONE login item to fill it into Albert's own Safari::

  {"op": "safari_fill", "item": "<vault item name, site id or alias>",
   "origin": "https://host[:port]",
   "fields": ["username", "password"] | ["password"] | ["username"] | ["totp"]}

Threat model: accidental-leak containment and blast-radius reduction, not a
boundary against a hostile uid-501 process (it can speak this protocol too).
Only items Albert opted in (``agent_safari_fill = true``, ``fill_enabled``),
only for an origin listed on the item, only while someone is at the Mac,
rate-limited, leak-registered and audited.

Checked in this order (every refusal: a code + a detail with names only):

1. peer uid ≠ ``allow_uid`` → ``forbidden`` (before any vault or listing read);
   shape → ``bad_request``;
2. resolve in the site listing: exact ``name``, else ``site`` id, else
   ``alias`` → ``no_item`` (detail: the site ids whose fill origins contain
   ``origin``) / ``ambiguous`` (several items of that name);
3. ``refused`` (refused or username-only), ``not_enabled``,
   ``origin_violation``;
4. live rotation lease or ``agent_hold`` → ``held``; a fresh read
   (``Vault.fill_secret``: a hold found there is ``held`` too) →
   ``no_password`` / ``unknown_field`` / ``vault_error``;
5. the password registered with the secretkeeper (label
   ``loginbroker:fill.<site>:password``) → ``leakcheck_unavailable``; the
   username too, best effort (the secretkeeper drops values below its
   length floor; a username is never a refusal);
6. the attended gate (``broker/attended.py``) → ``unattended``;
7. the limiter, charged only now: ``fill:<site>`` / ``filltotp:<site>`` and
   ``fill:*``, plus at most ``FILL_DISTINCT_MAX`` distinct sites per rolling
   ``FILL_DISTINCT_WINDOW_S`` (``<home>/fill-distinct.json``, 0600) →
   ``rate_limited``;
8. the answer: ``{"ok": true, "site": S, "values": {field: value}}`` or, for
   ``["totp"]``, ``{"ok": true, "site": S, "code": "123456", "valid_s": N}``.

A TOTP code is not registered with the secretkeeper (like the ``totp`` op):
it is short-lived and below the scanners' length floor.
"""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from broker.leakcheck import LeakCheckUnavailable, Registrar
from broker.limiter import Denied, Limiter
from broker.origins import parse_fill_origins
from broker.recipes import fresh_totp, parse_totp
from broker.secret_ops import GLOBAL_FILL_KEY
from broker.statefile import write_json_atomic
from broker.vault import (
    FILL_LABEL_PREFIX,
    SITE_ID_RE,
    TXID_RE,
    USERNAME_ONLY,
    Held,
    MissingSecret,
    NotFillable,
    Secret,
    SiteItem,
    Vault,
    VaultError,
    fill_enabled,
)

FILL_OPS = frozenset({"safari_fill"})
FILL_FIELDS = ("username", "password", "totp")
MAX_ITEM_CHARS = 200
FILL_DISTINCT_MAX = 15
FILL_DISTINCT_WINDOW_S = 24 * 3600.0
FILL_DISTINCT_FILE = "fill-distinct.json"


def _err(code: str, detail: str = "") -> dict[str, Any]:
    return {"ok": False, "error": code, "detail": detail}


def _held_reply(txid: str) -> dict[str, Any]:
    shown = txid if TXID_RE.match(txid) else None
    return {
        **_err("held", f"rotation {shown or 'malformed'} in progress — re-check later"),
        "txid": shown,
    }


def parse_origin(raw: object) -> str | None:
    """`raw` as one exact ``https://host[:port]`` origin, else None."""
    if not isinstance(raw, str) or not raw or len(raw) > 300:
        return None
    if any(c in raw for c in ",\n\r") or not raw.isprintable():
        return None
    try:
        parsed = parse_fill_origins(raw, dev=False)
    except ValueError:
        return None
    if len(parsed) != 1 or not parsed[0].startswith("https://"):
        return None
    return parsed[0]


# A flat validator: one early return per rule.
# pylint: disable-next=too-many-return-statements
def parse_fill_request(req: dict[str, Any]) -> tuple[str, str, list[str]] | str:
    """(item, origin, fields) or a bad_request detail (names only)."""
    item = req.get("item")
    if (
        not isinstance(item, str)
        or not item.strip()
        or len(item) > MAX_ITEM_CHARS
        or not item.isprintable()
    ):
        return f"item must be 1-{MAX_ITEM_CHARS} printable characters"
    origin = parse_origin(req.get("origin"))
    if origin is None:
        return "origin must be exactly https://host[:port]"
    fields = req.get("fields")
    if not isinstance(fields, list) or not fields:
        return "fields must be a non-empty list"
    if not all(isinstance(f, str) and f in FILL_FIELDS for f in fields):
        return "fields: username, password or totp"
    if len(set(fields)) != len(fields):
        return "fields: no duplicates"
    if "totp" in fields and len(fields) != 1:
        return "fields: totp goes alone"
    return item, origin, list(fields)


def resolve_item(items: list[SiteItem], wanted: str) -> SiteItem | str:
    """The item `wanted` names (exact name, else site id, else alias), or
    ``no_item`` / ``ambiguous``."""
    named = [it for it in items if it.name == wanted]
    if len(named) > 1:
        return "ambiguous"
    if named:
        return named[0]
    sid = wanted.strip().lower()
    if not SITE_ID_RE.match(sid):
        return "no_item"
    by_id = next((it for it in items if it.site == sid), None)
    if by_id is not None:
        return by_id
    aliased = [it for it in items if it.alias and it.alias == sid]
    if len(aliased) > 1:
        return "ambiguous"
    return aliased[0] if aliased else "no_item"


class FillOps:  # pylint: disable=too-few-public-methods
    """Mixin: needs the attributes ``Broker.__init__`` sets."""

    allow_uid: int | None
    attended: Callable[[int], str | None]
    vault: Vault
    leakcheck: Registrar
    secret_limiter: Limiter
    clock: Callable[[], float]
    home: Path
    _fill_lock: threading.Lock

    def _items(self, *, fresh: bool = False) -> list[SiteItem]:
        """Provided by ``Broker``."""
        raise NotImplementedError

    def _held(self, site: str, item: SiteItem | None = None) -> dict[str, Any] | None:
        """Provided by ``Broker``."""
        raise NotImplementedError

    # pylint: disable-next=too-many-arguments
    def _fill_op(
        self,
        op: str,
        req: dict[str, Any],
        *,
        uid: int | None,
        pid: int | None,
        extra: dict[str, Any],
    ) -> tuple[str | None, dict[str, Any]]:
        """``safari_fill`` → ``(canonical site for the audit, reply)``. `extra`
        gets ``fields``, ``origin`` (parsed, or "-") and the peer ``pid``."""
        del op
        extra.update(pid=pid, origin="-", fields=[])
        if self.allow_uid is None or uid != self.allow_uid:
            return None, _err("forbidden")
        parsed = parse_fill_request(req)
        if isinstance(parsed, str):
            fields = req.get("fields")
            if isinstance(fields, list):
                extra["fields"] = [f for f in fields if f in FILL_FIELDS]
            return None, _err("bad_request", parsed)
        wanted, origin, fields = parsed
        extra.update(origin=origin, fields=fields)
        return self._safari_fill(wanted, origin, fields)

    # One early return per protocol error code, in the order they are checked.
    # pylint: disable-next=too-many-return-statements,too-many-branches
    def _safari_fill(
        self, wanted: str, origin: str, fields: list[str]
    ) -> tuple[str | None, dict[str, Any]]:
        try:
            items = self._items()
        except VaultError as exc:
            return None, _err("vault_error", str(exc))
        hit = resolve_item(items, wanted)
        if isinstance(hit, str):
            if hit == "ambiguous":
                return None, _err("ambiguous", "several items answer to that name")
            serving = sorted({it.site for it in items if origin in it.fill_origins})
            return None, _err(
                "no_item",
                f"no item of that name, site id or alias; items for {origin}: "
                + (", ".join(serving) or "none"),
            )
        site = hit.site
        if hit.refused:
            return site, _err("refused", f"{site}: {hit.refused}")
        if hit.login_mode == USERNAME_ONLY:
            return site, _err("refused", f"{site}: a username-only login is not filled")
        if not fill_enabled(hit):
            return site, _err(
                "not_enabled", f"{site}: not opted in (agent_safari_fill = true)"
            )
        if origin not in hit.fill_origins:
            return site, _err(
                "origin_violation", f"{origin} is not a fill origin of {site}"
            )
        held = self._held(site, hit)
        if held is not None:
            return site, held
        read = self._fill_read(site, fields)
        if "error" in read:
            return site, read
        label = f"{FILL_LABEL_PREFIX}{site}"
        got = read.get("values", {})
        # the password must be registered (fail closed); a username is an
        # identifier, not a credential, and is never registered (tp#1138)
        if "password" in got:
            try:
                self.leakcheck.register([(label, "password", got["password"])])
            except LeakCheckUnavailable as exc:
                return site, _err("leakcheck_unavailable", str(exc))
        if self.allow_uid is None:  # unreachable: _fill_op checked it
            return site, _err("forbidden")
        why = self.attended(self.allow_uid)
        if why is not None:
            return site, _err("unattended", why)
        denied = self._fill_charge(site, totp="totp" in fields)
        if denied is not None:
            return site, _err("rate_limited", denied)
        return site, {"ok": True, "site": site, **read}

    # pylint: disable-next=too-many-return-statements
    def _fill_read(self, site: str, fields: list[str]) -> dict[str, Any]:
        """The fresh read: ``{"values": {...}}`` / ``{"code", "valid_s"}``, or
        an error reply (key ``error``)."""
        try:
            sec: Secret = self.vault.fill_secret(site)
        except Held as exc:
            return _held_reply(exc.txid)
        except NotFillable as exc:
            return _err(exc.code, str(exc))
        except MissingSecret as exc:
            code = "no_password" if exc.code == "no_password" else "unknown_field"
            return _err(code, f"{site}: {exc}")
        except VaultError as exc:
            return _err("vault_error", str(exc))
        if fields == ["totp"]:
            seed = sec.totp_seed or ""
            otp = parse_totp(seed)
            code = fresh_totp(seed) if otp is not None else None
            if otp is None or code is None:
                return _err("unknown_field", f"{site}: no usable TOTP")
            valid_s = int(otp.interval - (time.time() % otp.interval))
            return {"code": code, "valid_s": valid_s}
        values: dict[str, str] = {}
        for fld in fields:
            value = sec.username if fld == "username" else sec.password
            if not value:
                if fld == "password":
                    return _err("no_password", f"{site}: the item has no password")
                return _err("unknown_field", f"{site}: field {fld!r} is empty")
            values[fld] = value
        return {"values": values}

    # -- the limiter and the distinct-item cap --------------------------------
    def _fill_charge(self, site: str, *, totp: bool) -> str | None:
        """Charge the request (None) or say why not (nothing charged then):
        the distinct-site cap first, then the limiter keys, atomically per
        key set; the site is recorded in the distinct set only on a grant."""
        now = self.clock()
        path = self.home / FILL_DISTINCT_FILE
        with self._fill_lock:
            recent = _load_distinct(path, now)
            if recent is None:
                return f"{FILL_DISTINCT_FILE} unreadable; reset required"
            if site not in recent and len(recent) >= FILL_DISTINCT_MAX:
                return (
                    f"at most {FILL_DISTINCT_MAX} distinct items per "
                    f"{FILL_DISTINCT_WINDOW_S / 3600:.0f} h"
                )
            key = f"filltotp:{site}" if totp else f"fill:{site}"
            granted = self.secret_limiter.reserve([key, GLOBAL_FILL_KEY], now)
            if isinstance(granted, Denied):
                return granted.reason
            recent[site] = now
            try:
                write_json_atomic(path, {"sites": recent})
            except OSError as exc:
                return f"{FILL_DISTINCT_FILE} unwritable ({exc.strerror or exc})"
        return None


def _load_distinct(path: Path, now: float) -> dict[str, float] | None:
    """{site: last fill ts} within the window; {} when absent, None when
    unreadable or malformed (fail closed)."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except (OSError, ValueError):
        return None
    sites = data.get("sites") if isinstance(data, dict) else None
    if not isinstance(sites, dict):
        return None
    out: dict[str, float] = {}
    for site, ts in sites.items():
        if not isinstance(site, str) or isinstance(ts, bool):
            return None
        if not isinstance(ts, (int, float)):
            return None
        if now - float(ts) < FILL_DISTINCT_WINDOW_S:
            out[site] = float(ts)
    return out
