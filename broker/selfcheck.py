#!/usr/bin/env python3
"""Read-only check of the login broker's security boundary, run as the agent uid.

Checks (each printed PASS/FAIL; exit 1 on any FAIL):
  a) live broker Chromium processes (argv contains the broker profile root) carry
     neither --remote-debugging-port nor --no-sandbox, and do not run as you;
  b) the broker home is not readable/traversable by you;
  c) the code dir is not writable by you;
  d) the broker socket is not owned by you.

Not installed (neither home nor code dir exists): prints ``SKIP not installed``
and exits 0 with -s/--skip-missing, else 2.

Examples:
  selfcheck.py -b
  selfcheck.py -b -s
  selfcheck.py -b -H /var/db/login-broker -c /usr/local/libexec/login-broker/current
"""

from __future__ import annotations

import argparse
import os
import pwd
import subprocess
import sys
from pathlib import Path

DEFAULT_HOME = "/var/db/login-broker"
DEFAULT_CODE = "/usr/local/libexec/login-broker/current"
DEFAULT_SOCKET = "/var/db/login-broker-run/broker.sock"


def _me() -> tuple[int, str]:
    uid = os.getuid()
    try:
        return uid, pwd.getpwuid(uid).pw_name
    except KeyError:
        return uid, str(uid)


def broker_processes(profile_root: str) -> list[tuple[str, str, str]]:
    """(pid, user, args) of every process whose argv mentions `profile_root`."""
    proc = subprocess.run(
        ["ps", "-axww", "-o", "pid=,user=,args="],
        capture_output=True,
        text=True,
        check=False,
    )
    out: list[tuple[str, str, str]] = []
    for line in proc.stdout.splitlines():
        parts = line.strip().split(None, 2)
        if len(parts) == 3 and profile_root in parts[2]:
            out.append((parts[0], parts[1], parts[2]))
    return out


def check_processes(
    procs: list[tuple[str, str, str]], me_names: set[str]
) -> list[tuple[bool, str]]:
    """Verdicts for check (a)."""
    if not procs:
        return [(True, "a) no broker Chromium running (nothing to inspect)")]
    results: list[tuple[bool, str]] = []
    for pid, user, args in procs:
        bad = [f for f in ("--remote-debugging-port", "--no-sandbox") if f in args]
        if bad:
            results.append((False, f"a) pid {pid} runs with {', '.join(bad)}"))
        if user in me_names:
            results.append((False, f"a) pid {pid} runs as the invoking user"))
    if all(ok for ok, _ in results):
        results.append(
            (True, f"a) {len(procs)} broker process(es): pipe-only, sandboxed")
        )
    return results


def run_checks(home: Path, code: Path, sock: Path) -> list[tuple[bool, str]]:
    """All four checks; read-only."""
    uid, name = _me()
    results = check_processes(
        broker_processes(str(home / "profiles")), {name, str(uid)}
    )
    if not home.exists():
        results.append((False, f"b) {home} is missing"))
    elif os.access(home, os.R_OK) or os.access(home, os.X_OK):
        results.append((False, f"b) {home} is readable/traversable by {name}"))
    else:
        results.append((True, f"b) {home} is closed to {name}"))
    writable = [
        p for p in (code, code.resolve()) if p.exists() and os.access(p, os.W_OK)
    ]
    if not code.exists():
        results.append((False, f"c) {code} is missing"))
    elif writable:
        results.append((False, f"c) {writable[0]} is writable by {name}"))
    else:
        results.append((True, f"c) {code} is not writable by {name}"))
    try:
        owner = os.lstat(sock).st_uid
    except FileNotFoundError:
        results.append((False, f"d) socket {sock} is missing (broker not running?)"))
    except OSError as exc:
        results.append((False, f"d) cannot stat socket {sock}: {exc.strerror}"))
    else:
        if owner == uid:
            results.append((False, f"d) socket {sock} is owned by {name}"))
        else:
            results.append((True, f"d) socket {sock} is owned by uid {owner}"))
    return results


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    p = argparse.ArgumentParser(
        prog="selfcheck.py",
        description=__doc__.split("\n\n", 1)[0] if __doc__ else None,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  selfcheck.py -b          # full boundary check\n"
            "  selfcheck.py -b -s       # exit 0 with SKIP when not installed\n"
        ),
    )
    p.add_argument("-b", "--boundary", action="store_true", help="run the checks")
    p.add_argument("-H", "--home", default=DEFAULT_HOME, help="broker home dir")
    p.add_argument("-c", "--code-dir", default=DEFAULT_CODE, help="broker code dir")
    p.add_argument("-S", "--socket", default=DEFAULT_SOCKET, help="broker socket")
    p.add_argument(
        "-s",
        "--skip-missing",
        action="store_true",
        help="exit 0 with 'SKIP not installed' when the broker is not installed",
    )
    args = p.parse_args(argv)
    if not args.boundary:
        p.print_usage(sys.stderr)
        print("selfcheck.py: nothing to do — pass -b/--boundary", file=sys.stderr)
        return 2
    home, code, sock = Path(args.home), Path(args.code_dir), Path(args.socket)
    if not home.exists() and not code.exists():
        print("SKIP not installed")
        return 0 if args.skip_missing else 2
    results = run_checks(home, code, sock)
    for ok, msg in results:
        print(f"{'PASS' if ok else 'FAIL'} {msg}")
    return 0 if all(ok for ok, _ in results) else 1


if __name__ == "__main__":
    sys.exit(main())
