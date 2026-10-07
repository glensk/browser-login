#!/usr/bin/env python3
"""Read-only check of the login broker's security boundary.

-b/--boundary, run as the agent uid (each check printed ✅/❌; exit 1 on any ❌):
  a) live broker Chromium processes (argv contains the broker profile root) carry
     neither --remote-debugging-port nor --no-sandbox, and do not run as you;
  b) the broker home is not readable/traversable by you;
  c) the code dir is not writable by you;
  d) the broker socket is not owned by you;
  e) /usr/local/bin/secret-run is a root-owned symlink into <code>/bin/;
  f) the secret-run client, its wrapper and the venv are not writable by you.

-F/--forbidden-probe, run as a uid the broker does NOT serve (install.sh uses
``nobody``): g) a ``secret`` request is answered ``forbidden``.

-P/--state-perms, run as root or the role account (the home is closed to the
agent uid): h) secret-limiter.json / secret-runs.json / leakcheck-labels.json
are 0600 and owned by the home's owner (absent = not used yet).

Not installed (neither home nor code dir exists): prints ``⚠️ SKIP not
installed`` and exits 0 with -s/--skip-missing, else 2.

Examples:
  selfcheck.py -b
  selfcheck.py -b -s
  selfcheck.py -b -H /var/db/login-broker -c /usr/local/libexec/login-broker/current
  sudo -u nobody selfcheck.py -F
  sudo selfcheck.py -P
"""

from __future__ import annotations

import argparse
import json
import os
import pwd
import socket
import stat
import subprocess
import sys
from pathlib import Path

DEFAULT_HOME = "/var/db/login-broker"
DEFAULT_CODE = "/usr/local/libexec/login-broker/current"
DEFAULT_SOCKET = "/var/db/login-broker-run/broker.sock"
DEFAULT_LINK = "/usr/local/bin/secret-run"
PRIVATE_STATE = ("secret-limiter.json", "secret-runs.json", "leakcheck-labels.json")


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


def check_link(link: Path, code: Path) -> tuple[bool, str]:
    """(e) the secret-run entry point: a root-owned symlink into <code>/bin/."""
    try:
        st = os.lstat(link)
    except OSError:
        return False, f"e) {link} is missing"
    if not stat.S_ISLNK(st.st_mode):
        return False, f"e) {link} is not a symlink"
    if st.st_uid != 0:
        return False, f"e) {link} is not owned by root"
    target = Path(os.readlink(link))
    if target != code / "bin" / "secret-run":
        return False, f"e) {link} points to {target}, not {code}/bin/secret-run"
    return True, f"e) {link} -> {target} (root-owned symlink)"


def check_client_writable(code: Path, name: str) -> tuple[bool, str]:
    """(f) neither the client, its wrapper nor the venv is writable by us."""
    paths = [
        code / "bin" / "secret_run.py",
        code / "bin" / "secret-run",
        code / "bin",
        code / "venv",
        code / "venv" / "bin",
    ]
    missing = [p for p in paths[:2] if not p.exists()]
    if missing:
        return False, f"f) {missing[0]} is missing"
    writable = [p for p in paths if p.exists() and os.access(p, os.W_OK)]
    if writable:
        return False, f"f) {writable[0]} is writable by {name}"
    return True, f"f) secret-run client and venv are not writable by {name}"


def probe_forbidden(sock: Path, timeout: float = 10.0) -> tuple[bool, str]:
    """(g) a ``secret`` request from this uid is answered ``forbidden``."""
    uid = os.getuid()
    req = {"op": "secret", "items": [{"item": "selfcheck", "field": "password"}]}
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect(str(sock))
            s.sendall(json.dumps(req).encode() + b"\n")
            with s.makefile("rb") as reader:
                line = reader.readline()
        resp = json.loads(line or b"{}")
    except (OSError, ValueError) as exc:
        return False, f"g) secret probe as uid {uid} got no answer ({exc})"
    if (
        isinstance(resp, dict)
        and resp.get("error") == "forbidden"
        and "values" not in resp
    ):
        return True, f"g) secret request as uid {uid} is forbidden"
    return False, f"g) secret request as uid {uid} was NOT refused as forbidden"


def check_state_perms(home: Path) -> list[tuple[bool, str]]:
    """(h) the secret-op state files: 0600, owned by the home's owner."""
    try:
        owner = home.stat().st_uid
    except OSError as exc:
        return [(False, f"h) cannot stat {home}: {exc.strerror}")]
    results = []
    for name in PRIVATE_STATE:
        path = home / name
        try:
            st = os.lstat(path)
        except FileNotFoundError:
            results.append((True, f"h) {name} not created yet"))
            continue
        except OSError as exc:
            results.append((False, f"h) cannot stat {path}: {exc.strerror}"))
            continue
        mode = stat.S_IMODE(st.st_mode)
        if not stat.S_ISREG(st.st_mode) or mode != 0o600 or st.st_uid != owner:
            results.append(
                (
                    False,
                    f"h) {name} is {oct(mode)} uid {st.st_uid} (want 0600 uid {owner})",
                )
            )
        else:
            results.append((True, f"h) {name} is 0600, owned by uid {owner}"))
    return results


def run_checks(
    home: Path, code: Path, sock: Path, link: Path | None = None
) -> list[tuple[bool, str]]:
    """The -b checks (a-f; e/f only with `link`); read-only."""
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
    if link is not None:
        results.append(check_link(link, code))
        results.append(check_client_writable(code, name))
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
            "  sudo -u nobody selfcheck.py -F   # secret op refused for other uids\n"
            "  sudo selfcheck.py -P     # secret-op state file modes\n"
        ),
    )
    p.add_argument("-b", "--boundary", action="store_true", help="run the checks")
    p.add_argument(
        "-F",
        "--forbidden-probe",
        action="store_true",
        help="(as a uid the broker does not serve) a secret request is forbidden",
    )
    p.add_argument(
        "-P",
        "--state-perms",
        action="store_true",
        help="(as root / the role account) the secret-op state files are 0600",
    )
    p.add_argument(
        "-l",
        "--link",
        default=DEFAULT_LINK,
        help=f"the secret-run entry point (default {DEFAULT_LINK})",
    )
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
    if not (args.boundary or args.forbidden_probe or args.state_perms):
        p.print_usage(sys.stderr)
        print("❌ selfcheck.py: nothing to do — pass -b, -F or -P", file=sys.stderr)
        return 2
    home, code, sock = Path(args.home), Path(args.code_dir), Path(args.socket)
    if args.boundary and not home.exists() and not code.exists():
        print("⚠️ SKIP not installed")
        return 0 if args.skip_missing else 2
    results: list[tuple[bool, str]] = []
    if args.boundary:
        results += run_checks(home, code, sock, Path(args.link))
    if args.forbidden_probe:
        results.append(probe_forbidden(sock))
    if args.state_perms:
        results += check_state_perms(home)
    for ok, msg in results:
        print(f"{'✅' if ok else '❌'} {msg}")
    return 0 if all(ok for ok, _ in results) else 1


if __name__ == "__main__":
    sys.exit(main())
