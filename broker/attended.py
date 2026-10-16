"""Is someone at Albert's Mac? The console / idle reads both the Safari logins
(``agent_login_safari.interactive_gate``) and the broker's ``safari_fill`` op
gate on.

``attended(uid)`` is None when `uid`'s console session is on the console,
unlocked, and had keyboard / mouse input within ``IDLE_MAX_S``; else a fixed
reason code (``console_locked``, ``not_on_console``, ``console_unknown``,
``albert_idle``, ``idle_unknown``). Fail closed: unreadable = refused.

What it proves: SOMEONE is at this unlocked Mac and used it recently. It does
NOT prove that Albert started the request. The reads are ``ioreg`` plists
(IORegistry root's ``IOConsoleUsers``, IOHIDSystem's ``HIDIdleTime``); they
work from any uid, the broker's role account included.
"""

from __future__ import annotations

import os
import plistlib
import subprocess
from collections.abc import Callable
from typing import Any

IDLE_MAX_S = 15 * 60.0
IOREG = "/usr/sbin/ioreg"
ATTENDED_REASONS = frozenset(
    {
        "console_locked",
        "not_on_console",
        "console_unknown",
        "albert_idle",
        "idle_unknown",
    }
)
Run = Callable[..., subprocess.CompletedProcess]


def _ioreg(args: list[str], run: Run) -> Any:
    """`ioreg ARGS -a` parsed (a plist), None on any failure."""
    try:
        res = run(
            [IOREG, *args, "-a"],
            capture_output=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if res.returncode != 0 or not res.stdout:
        return None
    try:
        raw = res.stdout if isinstance(res.stdout, bytes) else res.stdout.encode()
        return plistlib.loads(raw)
    except (plistlib.InvalidFileException, ValueError):
        return None


def console_state(run: Run = subprocess.run, uid: int | None = None) -> str:
    """``unlocked`` / ``locked`` / ``not_on_console`` / ``unknown`` for `uid`'s
    console session (default: this process's uid; IORegistry root's
    ``IOConsoleUsers``). Locked = ``CGSSessionScreenIsLocked`` (the user's
    session) or ``IOConsoleLocked`` (the root's or the session's) is true;
    either one present but not a boolean = unknown (fail closed). An absent
    key is "not locked"."""
    uid = os.getuid() if uid is None else uid
    root = _ioreg(["-n", "Root", "-d1"], run)
    users = root.get("IOConsoleUsers") if isinstance(root, dict) else None
    if not isinstance(users, list) or not isinstance(root, dict):
        return "unknown"
    mine = [
        u for u in users if isinstance(u, dict) and u.get("kCGSSessionUserIDKey") == uid
    ]
    if not mine or not any(u.get("kCGSSessionOnConsoleKey") is True for u in mine):
        return "not_on_console"
    flags = [root.get("IOConsoleLocked")]
    for u in mine:
        flags += [u.get("CGSSessionScreenIsLocked"), u.get("IOConsoleLocked")]
    present = [f for f in flags if f is not None]
    if any(not isinstance(f, bool) for f in present):
        return "unknown"
    return "locked" if any(present) else "unlocked"


def idle_seconds(run: Run = subprocess.run) -> float | None:
    """Seconds since the last keyboard / mouse input (HIDIdleTime), None
    when it cannot be read."""
    data = _ioreg(["-c", "IOHIDSystem", "-r", "-d1"], run)
    entries = data if isinstance(data, list) else [data]
    for entry in entries:
        if isinstance(entry, dict):
            ns = entry.get("HIDIdleTime")
            if isinstance(ns, int) and not isinstance(ns, bool) and ns >= 0:
                return ns / 1e9
    return None


def attended(uid: int, run: Run = subprocess.run) -> str | None:
    """None when `uid`'s console session is on the console, unlocked and was
    used within ``IDLE_MAX_S``; else one of ``ATTENDED_REASONS``."""
    state = console_state(run, uid)
    if state != "unlocked":
        return {"locked": "console_locked", "not_on_console": "not_on_console"}.get(
            state, "console_unknown"
        )
    idle = idle_seconds(run)
    if idle is None:
        return "idle_unknown"
    if idle > IDLE_MAX_S:
        return "albert_idle"
    return None
