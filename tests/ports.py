"""A CDP port for tests that nothing uses — and that the kernel never hands out.

A fake CDP port inside the ephemeral range (macOS: 49152-65535) can collide
with the LOCAL port of some unrelated outgoing connection on the machine, which
``lsof -iTCP:<port>`` then reports (tp#905). Ports below that range are never
assigned as ephemeral source ports, so a port there that nothing listens on
has no established connection either.
"""

from __future__ import annotations

import random
import socket

EPHEMERAL_FIRST = 49152
_LOW, _HIGH = 20000, EPHEMERAL_FIRST - 1


def _unused(port: int) -> bool:
    """True when `port` can be bound on loopback and nobody accepts on it."""
    try:
        with socket.socket() as s:
            s.bind(("127.0.0.1", port))
    except OSError:
        return False
    with socket.socket() as s:
        s.settimeout(0.5)
        return s.connect_ex(("127.0.0.1", port)) != 0


def unused_port() -> int:
    """A random loopback port below the ephemeral range that is not in use."""
    rng = random.SystemRandom()
    for _ in range(200):
        port = rng.randint(_LOW, _HIGH)
        if _unused(port):
            return port
    raise RuntimeError(f"no unused port in {_LOW}-{_HIGH}")
