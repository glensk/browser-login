"""The broker's WS5 identity ops (tp#833): challenges, the mismatch guard,
account tags.

``identity_challenge {site}`` hands the client a one-use nonce for one item;
the client's recipe hashes ``nonce || normalised account name`` in the probe
page (``identity.RECIPE_JS``), and ``identity_answer {challenge_id, digest}``
says ``match`` / ``mismatch`` / ``expired``. The username never leaves the
broker, the page's value never leaves the page: only the digest travels.

The pair is an online oracle for "is the account name X?": the caller can
hash any guess itself. So it is bounded hard:

- a challenge is issued only for an item a ``login`` would serve too (the
  daemon's gates: not refused, a proof, a usable recipe, no limiter block,
  the caller's browser instance) and only while ``IdentityGuard`` allows it;
- issuing is capped per site (``PER_SITE_PER_MIN``) and per peer process
  (``PER_PID_PER_MIN``); a challenge is bound to its site and its pid
  (LOCAL_PEERPID), lives ``CHALLENGE_TTL_S`` and is consumed by its first
  answer, whatever that answer is;
- every ``mismatch`` costs: the site's challenges stop for 1 h, then 6 h;
  the third mismatch within 7 days quarantines them until a root reset
  (``install.sh -r SITE``). A real mismatch is rare by design (one account
  per scope per browser instance), so this costs a legitimate client little.

The account tag (``identity.account_tag``) is an HMAC of the normalised
username under a 32-byte key in the broker's home (``TAG_KEY_NAME``, 0600,
owned by the broker's own uid, created on first use and kept across
releases). It is a sanity check only: a DECLARED same-account pair with
unequal tags is refused. "Are these two items one account?" is answered by
the ROOT-only CLI ``install.sh -S A B`` (``daemon.py -S``), never over the
socket.

Never logs a nonce, digest, tag or name.
"""

from __future__ import annotations

import contextlib
import fcntl
import hmac
import json
import os
import secrets
import stat
import tempfile
import threading
import time
from collections import deque
from collections.abc import Callable, Iterator
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from broker import identity
from broker.statefile import write_json_atomic
from broker.vault import SiteItem

IDENTITY_OPS = frozenset({"identity_challenge", "identity_answer"})
TAG_KEY_NAME = "account-tag.key"
TAG_KEY_BYTES = 32
CHALLENGE_TTL_S = 60.0
PER_SITE_PER_MIN = 6
PER_PID_PER_MIN = 6
_WINDOW_S = 60.0
GUARD_NAME = "identity-guard.json"
# Cooldown after the 1st and 2nd mismatch inside GUARD_WINDOW_S; the 3rd
# quarantines the site's challenges until a root reset.
GUARD_COOLDOWNS_S = (3600.0, 6 * 3600.0)
GUARD_WINDOW_S = 7 * 86400.0
GUARD_QUARANTINE_AFTER = 3
RESET_HINT = "sudo install/install.sh -r {site}"


class TagKeyError(RuntimeError):
    """The tag key is missing, unreadable, or not the broker's own 0600 file."""


class GuardStateError(RuntimeError):
    """The mismatch guard's state cannot be read or written (fail closed)."""


def load_tag_key(path: Path, *, create: bool = True) -> bytes:
    """The 32-byte tag key at `path`, created (atomically, 0600) when absent.

    The file must be a regular file (no symlink) owned by this process's
    euid, without group/other bits, exactly 32 bytes; anything else raises
    ``TagKeyError`` (callers fail closed)."""
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        if not create:
            raise TagKeyError("account tag key missing") from None
        _create_key(path)
        return load_tag_key(path, create=False)
    except OSError as exc:
        raise TagKeyError("account tag key unreadable") from exc
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise TagKeyError("account tag key is not a regular file")
        if st.st_uid != os.geteuid() or st.st_mode & 0o077:
            raise TagKeyError("account tag key: wrong owner or mode (want 0600)")
        data = os.read(fd, TAG_KEY_BYTES + 1)
    finally:
        os.close(fd)
    if len(data) != TAG_KEY_BYTES:
        raise TagKeyError("account tag key has the wrong length")
    return data


def _create_key(path: Path) -> None:
    """Write a fresh key next to `path`, then link it into place (a reader
    never sees a half-written key; a concurrent creator wins or loses whole)."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".tag-", dir=str(path.parent))
    try:
        os.fchmod(fd, 0o600)
        os.write(fd, secrets.token_bytes(TAG_KEY_BYTES))
        os.fsync(fd)
        os.close(fd)
        fd = -1
        with contextlib.suppress(FileExistsError):
            os.link(tmp, path)
    finally:
        if fd >= 0:
            os.close(fd)
        with contextlib.suppress(OSError):
            os.unlink(tmp)


def same_account_answer(items: list[SiteItem], a: str, b: str, key: bytes) -> str:
    """``same`` / ``different`` / ``unknown`` (an item missing or without a
    username, a name that does not normalise) for two site ids — the
    root-only CLI's answer, never a socket op."""
    by_site = {it.site: it for it in items}
    found = [by_site.get(a), by_site.get(b)]
    tags = [identity.account_tag(key, it.account_name) if it else None for it in found]
    if tags[0] is None or tags[1] is None:
        return "unknown"
    return "same" if hmac.compare_digest(tags[0], tags[1]) else "different"


def apply_tags(items: list[SiteItem], key_of: Callable[[], bytes]) -> list[SiteItem]:
    """Refuse every DECLARED same-account pair whose tags differ (or cannot
    be computed: no key, a name that does not normalise), and recompute
    ``multi_account`` (a refused pair loses its declaration)."""
    pairs = [it for it in items if it.same_account_as and not it.refused]
    if not pairs:
        return items
    try:
        key: bytes | None = key_of()
    except TagKeyError:
        key = None
    by_site = {it.site: it for it in items}
    bad: dict[str, str] = {}
    for it in pairs:
        partner = by_site.get(it.same_account_as)
        if key is None:
            bad[it.site] = (
                "account tag key unavailable: a same-account pair is unverifiable"
            )
            continue
        mine = identity.account_tag(key, it.account_name)
        theirs = identity.account_tag(key, partner.account_name) if partner else None
        if mine is None or theirs is None or not hmac.compare_digest(mine, theirs):
            bad[it.site] = (
                f"agent_same_account_as {it.same_account_as}: the two items "
                "do not log into the same account name"
            )
    if not bad:
        return items
    out = [
        replace(it, refused=bad[it.site], same_account_as="") if it.site in bad else it
        for it in items
    ]
    conflicts = identity.scope_conflicts([it.public() for it in out])
    return [replace(it, multi_account=it.site in conflicts) for it in out]


class IdentityGuard:
    """What a challenge ``mismatch`` costs, persisted in ``GUARD_NAME``
    (flock on its ``.lock`` sidecar; a root reset and the daemon share it).

    ``{"sites": {site: {"mismatches": [ts, ...], "until": ts,
    "quarantined": bool}}}``. An unreadable state denies (fail closed)."""

    def __init__(self, home: Path) -> None:
        self.path = home / GUARD_NAME
        self._lock = threading.Lock()
        # Sites whose mismatch could not be persisted: blocked in memory for
        # the life of this process (a full disk must never reopen the oracle).
        self._poisoned: set[str] = set()

    @property
    def lock_path(self) -> Path:
        """The flock sidecar."""
        return self.path.with_name(self.path.name + ".lock")

    @contextlib.contextmanager
    def _locked(self) -> Iterator[int]:
        with self._lock:
            try:
                self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                fd = os.open(
                    str(self.lock_path), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600
                )
            except OSError as exc:
                raise GuardStateError(f"cannot lock {self.lock_path}") from exc
            try:
                st = os.fstat(fd)
                if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
                    raise GuardStateError(f"{self.lock_path} is not a plain file")
                fcntl.flock(fd, fcntl.LOCK_EX)
                yield fd
            finally:
                os.close(fd)

    def _load(self) -> dict[str, Any]:
        try:
            fd = os.open(str(self.path), os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            return {"sites": {}}
        except OSError as exc:
            raise GuardStateError(f"cannot read {self.path}") from exc
        try:
            with os.fdopen(fd, encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError) as exc:
            raise GuardStateError(f"corrupt {self.path}") from exc
        if not isinstance(data, dict) or not isinstance(data.get("sites"), dict):
            raise GuardStateError(f"corrupt {self.path}")
        return data

    def denial(self, site: str, now: float) -> tuple[str, str] | None:
        """``(state, reason)`` while `site`'s challenges are blocked
        (``identity_blocked`` / ``identity_cooldown`` /
        ``identity_quarantined`` / ``identity_unreadable``), else None.
        ``identity_blocked``: a mismatch of the site could not be written —
        blocked until the broker restarts (and a root reset)."""
        if site in self._poisoned:
            return (
                "identity_blocked",
                "an identity mismatch could not be recorded: challenges blocked "
                f"until the broker restarts ({RESET_HINT.format(site=site)})",
            )
        try:
            with self._locked():
                entry = self._load()["sites"].get(site) or {}
        except (GuardStateError, OSError) as exc:
            return "identity_unreadable", f"identity guard unreadable ({exc})"
        if entry.get("quarantined"):
            return (
                "identity_quarantined",
                f"{GUARD_QUARANTINE_AFTER} identity mismatches within 7 days: "
                f"challenges blocked until {RESET_HINT.format(site=site)}",
            )
        until = float(entry.get("until") or 0)
        if now < until:
            return (
                "identity_cooldown",
                f"identity mismatch: challenges blocked for {until - now:.0f}s",
            )
        return None

    def writable(self) -> bool:
        """Can a mismatch be recorded right now? Writes a probe the size of
        the state plus a margin through the same atomic writer, then drops
        it. False (fail closed: no challenge is issued) on any error — a
        full disk, a read-only or unreadable state."""
        probe = self.path.with_name(self.path.name + ".probe")
        try:
            with self._locked():
                data = self._load()
                write_json_atomic(probe, {"state": data, "margin": "0" * 4096})
                probe.unlink()
        except (GuardStateError, OSError):
            with contextlib.suppress(OSError):
                probe.unlink()
            return False
        return True

    def record_mismatch(self, site: str, now: float) -> str:
        """One more mismatch: ``cooldown`` (1 h, then 6 h) or
        ``quarantined`` (the 3rd within 7 days). On ANY failure (a full
        disk included) the site is blocked in memory for the life of the
        process, then GuardStateError is raised."""
        try:
            return self._record(site, now)
        except (GuardStateError, OSError) as exc:
            self._poisoned.add(site)
            raise GuardStateError(f"cannot record the mismatch ({exc})") from exc

    def _record(self, site: str, now: float) -> str:
        with self._locked():
            data = self._load()
            entry = data["sites"].setdefault(site, {})
            seen = [
                float(t)
                for t in entry.get("mismatches", [])
                if isinstance(t, (int, float)) and now - float(t) < GUARD_WINDOW_S
            ]
            seen.append(now)
            entry["mismatches"] = seen
            if len(seen) >= GUARD_QUARANTINE_AFTER:
                entry["quarantined"] = True
                state = "quarantined"
            else:
                step = min(len(seen), len(GUARD_COOLDOWNS_S)) - 1
                entry["until"] = now + GUARD_COOLDOWNS_S[step]
                state = "cooldown"
            write_json_atomic(self.path, data)
        return state

    def reset(self, site: str, owner: tuple[int, int] | None = None) -> bool:
        """Forget `site` (root CLI). True when there was something to forget.
        `owner`: chown the state and lock files back to the broker. No
        state file → nothing to forget, and nothing is created (a root reset
        never leaves a root-owned file behind)."""
        if not self.path.exists():
            return False
        with self._locked() as fd:
            data = self._load()
            existed = data["sites"].pop(site, None) is not None
            if existed:
                write_json_atomic(self.path, data)
            if owner is not None:
                if self.path.exists():
                    os.chown(self.path, *owner, follow_symlinks=False)
                os.fchown(fd, *owner)
        return existed


@dataclass(frozen=True)
class _Challenge:
    site: str
    expected: str  # sha256(nonce || normalised vault username), hex
    pid: int
    expires: float


def _err(code: str, detail: str = "") -> dict[str, Any]:
    return {"ok": False, "error": code, "detail": detail}


class IdentityOps:
    """Challenge store, issue caps, the mismatch guard and the tag key of
    one broker."""

    def __init__(self, home: Path, clock: Callable[[], float] = time.time) -> None:
        self.home = home
        self.clock = clock
        self.guard = IdentityGuard(home)
        self._lock = threading.Lock()
        self._answer_lock = threading.Lock()  # one answer decided at a time
        self._open: dict[str, _Challenge] = {}
        self._issued: deque[tuple[float, str, int]] = deque()

    # -- tag key -------------------------------------------------------------
    def tag_key(self) -> bytes:
        """The broker's tag key (``TagKeyError`` when unusable)."""
        with self._lock:
            return load_tag_key(self.home / TAG_KEY_NAME)

    def apply_tags(self, items: list[SiteItem]) -> list[SiteItem]:
        """`apply_tags` with this broker's key."""
        return apply_tags(items, self.tag_key)

    # -- challenges ----------------------------------------------------------
    def _prune(self, now: float) -> None:
        while self._issued and now - self._issued[0][0] >= _WINDOW_S:
            self._issued.popleft()
        for cid in [c for c, ch in self._open.items() if ch.expires <= now]:
            del self._open[cid]

    # One early return per refusal, in the order they are checked.
    def challenge(  # pylint: disable=too-many-return-statements
        self, item: SiteItem, pid: int | None
    ) -> dict[str, Any]:
        """``identity_challenge`` for an item the daemon already admitted
        (`Broker._challenge_gates`) → ``{ok, challenge_id, nonce, ...}``."""
        site = item.site
        if item.identity_recipe is None:
            return _err("identity_unproven", f"{site}: no usable identity recipe")
        if not isinstance(pid, int) or pid <= 0:
            return _err("bad_request", "the peer process is unknown")
        norm = identity.normalize_identity(item.account_name)
        if norm is None:
            return _err(
                "identity_indeterminate",
                f"{site}: the account name cannot be compared (empty or non-ASCII)",
            )
        now = self.clock()
        denied = self.guard.denial(site, now)
        if denied is not None:
            return _err(*denied)
        if not self.guard.writable():
            # a mismatch could not be recorded: no challenge at all
            return _err(
                "identity_unwritable",
                "the identity guard state cannot be written — no challenges",
            )
        with self._lock:
            self._prune(now)
            per_site = sum(1 for _, s, _p in self._issued if s == site)
            per_pid = sum(1 for _, _s, p in self._issued if p == pid)
            if per_site >= PER_SITE_PER_MIN or per_pid >= PER_PID_PER_MIN:
                return _err(
                    "rate_limited", "too many identity challenges — retry later"
                )
            nonce = secrets.token_hex(identity.NONCE_BYTES)
            cid = secrets.token_urlsafe(18)
            self._open[cid] = _Challenge(
                site=site,
                expected=identity.challenge_digest(nonce, norm),
                pid=pid,
                expires=now + CHALLENGE_TTL_S,
            )
            self._issued.append((now, site, pid))
        return {
            "ok": True,
            "challenge_id": cid,
            "nonce": nonce,
            "identity": item.identity,
            "privilege": item.privilege,
            "ttl_s": int(CHALLENGE_TTL_S),
        }

    # One return per answer, in the order they are decided.
    def answer(  # pylint: disable=too-many-return-statements
        self, req: dict[str, Any], pid: int | None
    ) -> tuple[str | None, dict[str, Any], str | None]:
        """``identity_answer {challenge_id, digest}`` → ``(site, reply, guard
        state after a mismatch or None)``.

        The challenge is consumed by this call whatever it says; unknown,
        used, expired or asked by another process → ``expired``. While the
        guard blocks the site (cooldown / quarantine / unreadable) there is
        no verdict at all: ``expired``. A ``mismatch`` drops EVERY open
        challenge of the site (no burst of pre-fetched challenges answers
        after it) and is recorded in the guard; a guard that cannot record
        it answers ``internal`` (still not a match). One answer is decided
        at a time, so two concurrent answers cannot both get a verdict past
        a mismatch."""
        cid = req.get("challenge_id")
        digest = req.get("digest")
        if not isinstance(cid, str) or not cid or len(cid) > 64:
            return None, _err("bad_request", "challenge_id: one string"), None
        expired = {"ok": True, "result": "expired"}
        with self._answer_lock:
            now = self.clock()
            with self._lock:
                ch = self._open.pop(cid, None)
                self._prune(now)
            if ch is None:
                return None, expired, None
            if now > ch.expires or pid != ch.pid:
                return ch.site, expired, None
            if not identity.is_digest(digest):
                return (
                    ch.site,
                    _err("bad_request", "digest: ONE lower-case hex SHA-256"),
                    None,
                )
            if self.guard.denial(ch.site, now) is not None:
                return ch.site, expired, None
            if hmac.compare_digest(str(digest), ch.expected):
                return ch.site, {"ok": True, "result": "match"}, None
            with self._lock:
                for other in [c for c, o in self._open.items() if o.site == ch.site]:
                    del self._open[other]
            try:
                state = self.guard.record_mismatch(ch.site, now)
            except GuardStateError:
                return (
                    ch.site,
                    _err("internal", "identity guard unwritable"),
                    "unwritable",
                )
            return ch.site, {"ok": True, "result": "mismatch"}, state
