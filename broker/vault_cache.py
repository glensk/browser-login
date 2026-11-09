"""The login broker's value cache (see ``broker/vault.py``)."""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from collections.abc import Callable, Hashable
from typing import Any

SECRET_TTL_S = 300.0
CACHE_MAX_ITEMS = 64
CACHE_MAX_BYTES = 256 * 1024
# tp#1963: a listing (no values) read at a Vaultwarden account revision is
# served again while the revision is unchanged, but never after this long.
REVISION_MAX_AGE_S = 6 * 3600.0
MEMO_MAX_ITEMS = 8


class VaultCache:  # pylint: disable=too-many-instance-attributes
    """Values cache: monotonic TTL, item and byte caps (oldest evicted first) and
    a generation; an entry stored under an older generation is never served.

    The revision memo (tp#1963) holds value-free listings (site items, the
    secret listing) tagged with the account revision they were read at: served
    only for the same revision, within ``REVISION_MAX_AGE_S`` and the same
    generation; ``bump`` drops it with everything else."""

    def __init__(
        self,
        *,
        ttl_s: float = SECRET_TTL_S,
        max_items: int = CACHE_MAX_ITEMS,
        max_bytes: int = CACHE_MAX_BYTES,
        clock: Callable[[], float] = time.monotonic,
        revision_max_age_s: float = REVISION_MAX_AGE_S,
    ) -> None:
        self.ttl_s = ttl_s
        self.revision_max_age_s = revision_max_age_s
        self.max_items = max_items
        self.max_bytes = max_bytes
        self.clock = clock
        self._gen = 0
        self._lock = threading.Lock()
        # key -> (generation, stored_at, size, value)
        self._entries: OrderedDict[Hashable, tuple[int, float, int, Any]] = (
            OrderedDict()
        )
        # key -> (generation, revision, stored_at, value)
        self._memo: OrderedDict[Hashable, tuple[int, str, float, Any]] = OrderedDict()

    @property
    def generation(self) -> int:
        """The current generation."""
        with self._lock:
            return self._gen

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)

    @property
    def nbytes(self) -> int:
        """Bytes held (by the callers' size estimates)."""
        with self._lock:
            return sum(e[2] for e in self._entries.values())

    def get(self, key: Hashable) -> Any:
        """The value under `key`, or None (missing, expired or older generation)."""
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return None
            gen, stored, _size, value = entry
            if gen != self._gen or self.clock() - stored >= self.ttl_s:
                del self._entries[key]
                return None
            return value

    def put(self, key: Hashable, value: Any, *, size: int, generation: int) -> bool:
        """Store unless `generation` is stale or the entry alone exceeds the byte
        cap; evicts the oldest entries until both caps hold."""
        with self._lock:
            if generation != self._gen or size > self.max_bytes:
                return False
            self._entries.pop(key, None)
            self._entries[key] = (generation, self.clock(), size, value)
            total = sum(e[2] for e in self._entries.values())
            while self._entries and (
                len(self._entries) > self.max_items or total > self.max_bytes
            ):
                _k, old = self._entries.popitem(last=False)
                total -= old[2]
            return True

    def memo_get(self, key: Hashable, revision: str) -> Any:
        """The listing stored under `key` at `revision`, or None (missing, other
        revision, older generation or older than ``revision_max_age_s``)."""
        if not revision:
            return None
        with self._lock:
            entry = self._memo.get(key)
            if entry is None:
                return None
            gen, rev, stored, value = entry
            if (
                gen != self._gen
                or rev != revision
                or self.clock() - stored >= self.revision_max_age_s
            ):
                del self._memo[key]
                return None
            return value

    def memo_put(
        self, key: Hashable, revision: str, value: Any, *, generation: int
    ) -> bool:
        """Store a listing read at `revision` unless `generation` is stale (the
        revision must be read BEFORE the vault read it tags)."""
        if not revision:
            return False
        with self._lock:
            if generation != self._gen:
                return False
            self._memo.pop(key, None)
            self._memo[key] = (generation, revision, self.clock(), value)
            while len(self._memo) > MEMO_MAX_ITEMS:
                self._memo.popitem(last=False)
            return True

    def bump(self) -> int:
        """New generation: every entry (memo included) is dropped. Returns it."""
        with self._lock:
            self._gen += 1
            self._entries.clear()
            self._memo.clear()
            return self._gen
