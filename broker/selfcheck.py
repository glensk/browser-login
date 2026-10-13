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
agent uid): h) the limiter / secret-run state and lock files
are 0600 and owned by the home's owner (absent = not used yet).

-R/--route-probe, run as the role account (install.sh does, after the checks
above passed): i) credential-free PAC-route probe — the broker's own headless
Chromium, launched with the release's home-proxy PAC (``broker/pac.py``, the
same switches as a login run) in a throwaway profile, loads
https://komga.dom42.space/ (≤ 20 s). ``routed`` = komga answered through the
home proxy; ``access_gated`` = Cloudflare Access answered (homeproxy down, or
the Mac is off-LAN without the tunnel); ``unreachable`` = navigation failed.
INFORMATIONAL ONLY: no reservation, no secret, no typing, and it never makes
the self-check (or an install) fail — -R alone always exits 0.

Not installed (neither home nor code dir exists): prints ``⚠️ SKIP not
installed`` and exits 0 with -s/--skip-missing, else 2.

Examples:
  selfcheck.py -b
  selfcheck.py -b -s
  selfcheck.py -b -H /var/db/login-broker -c /usr/local/libexec/login-broker/current
  sudo -u nobody selfcheck.py -F
  sudo selfcheck.py -P
  selfcheck.py -R            # as the role account
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import pwd
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import urllib.parse
from collections.abc import Callable
from pathlib import Path
from typing import Any

DEFAULT_HOME = "/var/db/login-broker"
DEFAULT_CODE = "/usr/local/libexec/login-broker/current"
DEFAULT_SOCKET = "/var/db/login-broker-run/broker.sock"
DEFAULT_LINK = "/usr/local/bin/secret-run"
PRIVATE_STATE = (
    "secret-limiter.json",
    "secret-limiter.json.lock",
    "secret-runs.json",
    "leakcheck-labels.json",
    "limiter.json",
    "limiter.json.lock",
    # WS5: the account-tag key and the identity challenge guard
    "account-tag.key",
    "identity-guard.json",
    "identity-guard.json.lock",
)


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
            # The broker answers `forbidden` and closes WITHOUT reading the
            # request: when that wins the race, our send fails (EPIPE) while
            # its answer already waits in our buffer — read it anyway.
            with contextlib.suppress(BrokenPipeError, ConnectionResetError):
                s.sendall(json.dumps(req).encode() + b"\n")
            with s.makefile("rb") as reader:
                line = reader.readline()
        if not line.strip():  # closed without a word: no answer, never a pass
            return False, f"g) secret probe as uid {uid} got no answer (empty reply)"
        resp = json.loads(line)
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
    """(h) the limiter and secret-op state files: 0600, owned by the home's owner."""
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


# (i) the PAC-route probe: one gated host, bounded, informational.
ROUTE_PROBE_URL = "https://komga.dom42.space/"
ROUTE_PROBE_LAUNCH_S = 6.0
ROUTE_PROBE_GOTO_S = 9.0
# Hard stop for the whole probe; past it the process exits with the verdict of
# the other checks, so an install never waits longer. The verdict is printed
# BEFORE the browser closes: a sandboxed Chromium can take ~30 s to exit
# (measured 2026-10-13, any page, with or without the PAC), and that wait must
# not cost the line.
ROUTE_PROBE_DEADLINE_S = 20
ROUTED, ACCESS_GATED, UNREACHABLE = "routed", "access_gated", "unreachable"
# (main-frame URLs in order, final URL or None, error text or "")
Navigation = tuple[list[str], str | None, str]
# A navigator loads the URL, hands its Navigation to the callback as soon as it
# is known (before any cleanup), and returns it.
Navigator = Callable[[str, Callable[[Navigation], None]], Navigation]
# Throwaway profiles of a running probe (removed on the deadline exit too).
_PROBE_DIRS: list[str] = []


def _broker_import() -> None:
    """Make the ``broker`` package importable when run as a script."""
    root = str(Path(__file__).resolve().parent.parent)
    if root not in sys.path:
        sys.path.insert(0, root)


def _origin(url: str) -> str:
    """``scheme://host`` of `url` (never path or query), "" when unparseable."""
    try:
        parts = urllib.parse.urlsplit(url)
        host = (parts.hostname or "").lower()
    except ValueError:
        return ""
    return f"{parts.scheme}://{host}" if parts.scheme and host else ""


def classify_route(nav: Navigation, url: str = ROUTE_PROBE_URL) -> tuple[str, str]:
    """(result, detail) of one probe navigation: ``access_gated`` when an
    Access page answered (``origins.access_gated_via``), ``routed`` when the
    page ended on the probe's own origin, else ``unreachable``."""
    _broker_import()
    from broker.origins import (  # pylint: disable=import-outside-toplevel
        access_gated_via,
    )

    trail, final, error = nav
    own = _origin(url)
    if final is not None and access_gated_via(trail, final, [own]):
        return ACCESS_GATED, f"Cloudflare Access answered ({_origin(final)})"
    if final is None or error:
        return UNREACHABLE, f"navigation failed ({error or 'no page'})"
    if _origin(final) == own:
        return ROUTED, f"{own} answered through the home proxy"
    return UNREACHABLE, f"ended on {_origin(final) or 'an unparseable URL'}"


def _navigate(
    pw: Any, url: str, profile: Path, seen: Callable[[Navigation], None]
) -> Navigation:
    """Load `url` once in a broker Chromium on `profile`: the daemon's own
    launch arguments (``daemon.launch_kwargs`` — the release PAC included),
    the full ``chromium`` build, sandbox on, nothing typed, nothing stored."""
    _broker_import()
    from broker.daemon import (  # pylint: disable=import-outside-toplevel
        launch_kwargs,
    )

    kwargs = launch_kwargs(pw, profile)
    kwargs["timeout"] = ROUTE_PROBE_LAUNCH_S * 1000
    ctx = pw.chromium.launch_persistent_context(channel="chromium", **kwargs)
    trail: list[str] = []
    try:
        page = ctx.pages[0] if ctx.pages else ctx.new_page()

        def on_nav(frame: Any) -> None:
            if frame == page.main_frame:
                trail.append(frame.url)

        page.on("framenavigated", on_nav)
        try:
            resp = page.goto(url, timeout=ROUTE_PROBE_GOTO_S * 1000)
            final: str | None = page.url
            error = ""
        except Exception as exc:  # pylint: disable=broad-exception-caught
            # Only the first line (the net:: error), never page content.
            text = str(exc).splitlines()[0] if str(exc) else type(exc).__name__
            resp, final, error = None, None, text.split(" at ", 1)[0][:120]
        if resp is not None:
            hops: list[str] = []
            req = resp.request
            while req is not None:
                hops.append(req.url)
                req = req.redirected_from
            trail = [*reversed(hops), *trail]
        nav: Navigation = (trail, final, error)
        seen(nav)
        return nav
    finally:
        ctx.close()


def _navigate_live(url: str, seen: Callable[[Navigation], None]) -> Navigation:
    """`_navigate` in a fresh Playwright and a throwaway profile."""
    from playwright.sync_api import (  # pylint: disable=import-outside-toplevel
        sync_playwright,
    )

    tmp = tempfile.mkdtemp(prefix="login-broker-pac-probe-")
    _PROBE_DIRS.append(tmp)
    try:
        with sync_playwright() as pw:
            return _navigate(pw, url, Path(tmp) / "profile", seen)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
        _PROBE_DIRS.remove(tmp)


def probe_pac_route(
    navigate: Navigator | None = None,
    url: str = ROUTE_PROBE_URL,
    report: Callable[[str, str], None] | None = None,
) -> tuple[str, str]:
    """(result, detail) of the PAC-route probe; never raises. `report` gets
    the verdict exactly once, as soon as it is known (before the cleanup)."""
    verdict: list[tuple[str, str]] = []

    def seen(nav: Navigation) -> None:
        if not verdict:
            verdict.append(classify_route(nav, url))
            if report is not None:
                report(*verdict[0])

    try:
        nav = (navigate or _navigate_live)(url, seen)
        seen(nav)
    except Exception as exc:  # pylint: disable=broad-exception-caught
        if not verdict:
            verdict.append((UNREACHABLE, f"probe could not run ({type(exc).__name__})"))
            if report is not None:
                report(*verdict[0])
    return verdict[0]


def route_line(result: str, detail: str) -> str:
    """The printed line: ✅ for routed, ℹ️ otherwise (never ❌)."""
    mark = "✅" if result == ROUTED else "ℹ️"
    note = "" if result == ROUTED else " — informational, not a release failure"
    return f"{mark} i) PAC route: {result}: {detail}{note}"


def _run_route_probe(rc: int, navigate: Navigator | None) -> None:
    """Print the probe's line under a hard deadline; past it, exit with `rc`
    (the line printed when the verdict was in time, the "exceeded" line else;
    the throwaway profile removed either way)."""
    printed: list[bool] = []

    def emit(result: str, detail: str) -> None:
        print(route_line(result, detail), flush=True)
        printed.append(True)

    def _expired(_signum: int, _frame: Any) -> None:
        if not printed:
            emit(UNREACHABLE, f"probe exceeded {ROUTE_PROBE_DEADLINE_S} s")
        for path in list(_PROBE_DIRS):
            shutil.rmtree(path, ignore_errors=True)
        os._exit(rc)

    previous = signal.signal(signal.SIGALRM, _expired)
    signal.alarm(ROUTE_PROBE_DEADLINE_S)
    try:
        probe_pac_route(navigate, report=emit)
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)


def main(
    argv: list[str] | None = None,
    route_navigate: Navigator | None = None,
) -> int:
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
            "  selfcheck.py -R          # (as the role account) PAC route, info only\n"
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
        "-R",
        "--route-probe",
        action="store_true",
        help="(as the role account) informational PAC-route probe; never fails",
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
    if not (
        args.boundary or args.forbidden_probe or args.state_perms or args.route_probe
    ):
        p.print_usage(sys.stderr)
        print("❌ selfcheck.py: nothing to do — pass -b, -F, -P or -R", file=sys.stderr)
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
        print(f"{'✅' if ok else '❌'} {msg}", flush=True)
    rc = 0 if all(ok for ok, _ in results) else 1
    if args.route_probe:
        _run_route_probe(rc, route_navigate)
    return rc


if __name__ == "__main__":
    sys.exit(main())
