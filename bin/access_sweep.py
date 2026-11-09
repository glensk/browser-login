#!/usr/bin/env python3
"""`browser.py sweep-access`, cheap enough for every minute (tp#1963).

The LaunchAgent com.albert.browser-access-sweep runs this. With `-A` (and no
instance env, CDP port or cache dir pinning one browser) it first probes
every known instance's CDP port and exits 0 at once when none listens —
`sweep-access -A` sweeps, records and prints nothing for a stopped instance
either. Otherwise it imports browser.py as a module (its cached bytecode,
instead of compiling the whole file as a script every run) and runs
``browser.py sweep-access ARGS`` in this process: same sweep, same state
file, same exit codes.
"""

from __future__ import annotations

import argparse
import errno
import os
import socket
import sys
from collections.abc import Mapping
from pathlib import Path

BIN = Path(__file__).resolve().parent
sys.path.insert(0, str(BIN.parent))
# pylint: disable=wrong-import-position
from broker.identity import ROLE_INSTANCE_PORTS  # noqa: E402

# pylint: enable=wrong-import-position

#: browser.INSTANCE_PORTS (tests pin the two equal).
INSTANCE_PORTS = {"": 9222, "private": 9223, **ROLE_INSTANCE_PORTS}
#: One TCP connect per port: refused = nothing listens (down).
PROBE_S = 1.0
PIN_ENVS = (
    "CLAUDE_BROWSER_INSTANCE",
    "CLAUDE_BROWSER_CDP_PORT",
    "CLAUDE_BROWSER_CACHE_DIR",
)


def parse_args(argv: list[str]) -> argparse.Namespace:
    """The `sweep-access` options, passed on unchanged."""
    p = argparse.ArgumentParser(
        description="Run `browser.py sweep-access` (the Cloudflare Access "
        "team-cookie sweep) in-process; with -A exit 0 at once when no "
        "shared-browser instance listens. Exit 0 ok/down, 1 a failure, "
        "75 busy (0 with -S).",
        epilog="Example: access_sweep.py -A -q -S  (the LaunchAgent's call)",
    )
    p.add_argument("-A", "--all-instances", action="store_true", help="every instance")
    p.add_argument(
        "-q", "--quiet", action="store_true", help="print only drops and failures"
    )
    p.add_argument(
        "-n", "--dry-run", action="store_true", help="only list the team cookies"
    )
    p.add_argument("-S", "--scheduled", action="store_true", help="busy (75) exits 0")
    return p.parse_args(argv)


def port_down(port: int, timeout_s: float = PROBE_S) -> bool:
    """True only when 127.0.0.1:`port` refuses the connection; an answer,
    a timeout or any other error counts as maybe-up (the full sweep decides)."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout_s)
        try:
            code = sock.connect_ex(("127.0.0.1", port))
        except OSError:
            return False
    return code == errno.ECONNREFUSED


def nothing_runs(env: Mapping[str, str]) -> bool:
    """`-A` unpinned and every known instance's port refuses: nothing to do."""
    if any(env.get(name) for name in PIN_ENVS):
        return False
    return all(port_down(port) for port in INSTANCE_PORTS.values())


def forward_argv(args: argparse.Namespace) -> list[str]:
    """The ``browser.py`` argv of the same sweep."""
    flags = [
        ("-A", args.all_instances),
        ("-q", args.quiet),
        ("-n", args.dry_run),
        ("-S", args.scheduled),
    ]
    return ["sweep-access", *(flag for flag, on in flags if on)]


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    if args.all_instances and nothing_runs(os.environ):
        return 0
    sys.path.insert(0, str(BIN))
    sys.argv = [str(BIN / "browser.py"), *forward_argv(args)]
    import browser  # pylint: disable=import-outside-toplevel

    return int(browser.main())


if __name__ == "__main__":
    sys.exit(main())
