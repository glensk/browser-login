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


class VaultCache:
    """Values cache: monotonic TTL, item and byte caps (oldest evicted first) and
    a generation; an entry stored under an older generation is never served."""

    def __init__(
        self,
        *,
        ttl_s: float = SECRET_TTL_S,
        max_items: int = CACHE_MAX_ITEMS,
        max_bytes: int = CACHE_MAX_BYTES,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.ttl_s = ttl_s
        self.max_items = max_items
        self.max_bytes = max_bytes
        self.clock = clock
        self._gen = 0
        self._lock = threading.Lock()
        # key -> (generation, stored_at, size, value)
        self._entries: OrderedDict[Hashable, tuple[int, float, int, Any]] = (
            OrderedDict()
        )

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

    def bump(self) -> int:
        """New generation: every entry is dropped. Returns it."""
        with self._lock:
            self._gen += 1
            self._entries.clear()
            return self._gen
