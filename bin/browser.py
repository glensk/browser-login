#!/usr/bin/env python3
"""Shared, logged-in Chromium that Claude can drive — two ways at once.

This launches a single persistent Chromium (dedicated profile, remote-debugging
on a fixed port) that you log into *once*. Two clients then attach to that same
browser over the Chrome DevTools Protocol (CDP):

  * Option 2 — Playwright MCP connects via ``--cdp-endpoint http://localhost:<port>``
    so Claude Code gets native browser tools (navigate/click/type/snapshot).
  * Option 3 — this script's ``open``/``eval``/``token`` subcommands connect via
    ``connect_over_cdp`` so Claude can script the browser from Bash.

Because both share one profile, you authenticate (Keycloak SSO) a single time;
the session persists in the profile dir across browser restarts.

Generic lifecycle:
  up        Launch the shared browser (idempotent). Log into sites once here.
            [-H|--headless] opts into a windowless browser (same profile, same
            logins) — everything works except assisted (human) logins.
  status    Show CDP health, browser version, open tabs, and the lifecycle record.
  switch MODE
            Transactionally switch to headed|headless: stop the browser and
            relaunch it on the SAME profile (every login persists). Waits for
            registered CDP clients to drain and REFUSES while an unregistered
            client is attached ([-f|--force] switches anyway).
  clients   Show who is attached over CDP: the registered clients (tool, pid,
            purpose) plus any unregistered ones a switch would refuse.
  doctor    Full health check: the lifecycle record, client coordination, and a
            drivability probe (rAF/click/screenshot) on a disposable tab.
  register-exec [-t NAME] -- CMD ARGS…
            Run a long-lived CDP client (e.g. the Playwright MCP server) as a
            REGISTERED client: the registration lives exactly as long as CMD.
  down      Quit the shared browser.
  open URL  Open/navigate a tab to URL in the shared browser.
  eval JS   Run a JS expression in the active (or --url-matched) tab; print JSON.

Generic multi-site login (a SITE is one of the entries in the SITES registry —
currently ``cscs``, ``anthropic``/``claude``, ``openai``/``chatgpt``, ``slack``
and ``biopolwifi``; add more by registering a Site):
  login SITE        Ensure SITE is logged in in the shared browser. Automated for
                    sites with stored credentials (CSCS Keycloak). For claude.ai:
                    FULLY automatic when $ANTHROPIC_LOGIN_EMAIL is set and himalaya
                    is installed (triggers the magic-link email, reads it, opens
                    the link — no password, no code); otherwise ASSISTED (you
                    complete the email login in the window). For chatgpt.com:
                    ASSISTED (Google SSO + 2FA once in the shared window; the
                    session persists). Records a login event.
  logged-in SITE    Exit 0 if SITE is logged in, 2 if not (no login attempted).
  login-log SITE    Show how often a *real* login was actually needed for SITE
                    (count, first/last, average interval) — read from the log.
  store-creds SITE  Store SITE credentials in the macOS keychain (password+TOTP
                    sites only, e.g. cscs). forget-creds SITE removes them.

CSCS aliases (kept for back-compat; cscs-api.py depends on them):
  token             Read the 40-hex Waldur DRF token from the portal tab and cache
                    it at ~/.cache/cscs-api/portal_token (what cscs-api.py uses).
  cscs-login        = login cscs   (logs in + caches the token).
  cscs-store-creds  = store-creds cscs   ·   cscs-forget-creds = forget-creds cscs

The chromium binary is Playwright's bundled "Chrome for Testing" (already on
disk). No system browser is touched, so this never collides with your daily Brave.
"""

import argparse
import atexit
import contextlib
import fcntl
import glob
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

DEFAULT_CDP_PORT = int(os.environ.get("CLAUDE_BROWSER_CDP_PORT", "9222"))
CACHE_DIR = Path.home() / ".cache" / "claude-browser"
PROFILE_DIR = CACHE_DIR / "profile"
PID_FILE = CACHE_DIR / "browser.pid"
# Single source of truth for "what is the shared browser doing right now" — see
# the lifecycle section below. NO file means cleanly down.
LIFECYCLE_FILE = CACHE_DIR / ".browser-lifecycle.json"
PORTAL_PROFILE_URL = "https://portal.cscs.ch/profile/"
PORTAL_API_ME = "https://portal.cscs.ch/api/users/me/"
CSCS_TOKEN_CACHE = Path.home() / ".cache" / "cscs-api" / "portal_token"
HEX40 = re.compile(r"\b[0-9a-f]{40}\b")

# Credential sources for `cscs-login`, tried in this order:
#   1. macOS login keychain — three generic-password items below. Read via the
#      Apple-signed `security` binary from an already-unlocked keychain, so NO
#      Touch ID / fingerprint is needed. Populate once with `cscs-store-creds`.
#   2. Fallback: the single 1Password item (username + password + live TOTP) via
#      the `op` CLI — Touch-ID-gated, vault never loaded into the browser.
# Override the 1Password reference/account with these env vars; defaults match
# Albert's setup.
CSCS_OP_ITEM = os.environ.get("CSCS_OP_ITEM", "CSCS")
CSCS_OP_ACCOUNT = os.environ.get("CSCS_OP_ACCOUNT", "my.1password.com")

# Keychain item "service" names (account = the current login user). The TOTP
# item stores the *seed* (a base32 secret or a full otpauth:// URI), from which
# we generate live 6-digit codes locally with pyotp — no 1Password round-trip.
KEYCHAIN_SVC_USER = os.environ.get("CSCS_KEYCHAIN_USER", "cscs-api: username")
KEYCHAIN_SVC_PASS = os.environ.get("CSCS_KEYCHAIN_PASS", "cscs-api: password")
KEYCHAIN_SVC_TOTP = os.environ.get("CSCS_KEYCHAIN_TOTP", "cscs-api: totp-seed")

# --- claude.ai (Anthropic Team admin) site ---------------------------------
# claude.ai uses passwordless EMAIL-CODE login, which can't be scripted from a
# stored secret the way CSCS Keycloak can — so this site does ASSISTED login: we
# open the page and you type the emailed code in the shared window; the session
# then persists in the profile. No token is extracted (anthropic-api.py drives
# the browser directly over CDP). Optional pre-fill of the email field if set.
CLAUDE_HOME_URL = "https://claude.ai/"
CLAUDE_LOGIN_URL = "https://claude.ai/login"
CLAUDE_BILLING_URL = "https://claude.ai/admin-settings/billing"
ANTHROPIC_LOGIN_EMAIL = os.environ.get("ANTHROPIC_LOGIN_EMAIL")  # optional convenience

# --- chatgpt.com (ChatGPT Business admin) site ------------------------------
# ChatGPT Business logs in via Google SSO + 2FA, which cannot be replayed from
# stored credentials — so this site does ASSISTED login: we open the admin page
# and you complete the SSO once in the shared window; the session then persists
# in the profile. No token is extracted (openai-team.py drives the browser
# directly over CDP). Logged-in sentinel = the 'Invite member' button on
# /admin/members (same signal openai-team.py relies on).
CHATGPT_ADMIN_URL = "https://chatgpt.com/admin/members"

# Slack (assisted login; extracts the session xoxc token + `d` cookie so admin
# calls like users.admin.setInactive work on the Pro plan — where the xoxp bot
# token is scope-blocked — exactly as the Manage-members admin UI does). No
# token is cached (xoxc rotates); `slack-session` prints it fresh on demand.
SLACK_APP_URL = "https://app.slack.com/client"
# Land the assisted login straight on the SDSC workspace's sign-in (skips the
# generic workspace picker). Override with $SLACK_WORKSPACE_URL if it ever moves.
SLACK_WORKSPACE_URL = os.environ.get(
    "SLACK_WORKSPACE_URL", "https://swiss-data-science.slack.com/"
)
# Pre-fill the sign-in email when set (best-effort; you still complete the
# code/SSO step). Albert's is albert.glensk@epfl.ch — export it to persist.
SLACK_LOGIN_EMAIL = os.environ.get("SLACK_LOGIN_EMAIL", "")
SLACK_SIGNIN_MARKERS = (
    "workspace-signin",
    "/signin",
    "/sign-in",
    "slack.com/get-started",
)

# --- Biopol WiFi (Ruckus Cloudpath MDU portal) site -------------------------
# The SDSC Biopole WiFi units are managed through a Ruckus Cloudpath MDU
# property-management portal — a plain Vue SPA at cloudpath.edificom.cloud whose
# login is an ordinary email+password form (no SSO, no TOTP). That makes this
# site UNATTENDED like CSCS: we fill the form from two macOS-keychain items and
# submit. Those two items are SHARED VERBATIM with sdsc/biopol-wifi/biopol-wifi.py
# (the pure-`requests` CLI that drives the SAME portal's REST API) — do NOT rename
# them, or the CLI stops finding its credentials. No token is extracted here; this
# Site only keeps the GUI logged in for manual portal work. Logged-in sentinel =
# the property name "SDSC - Biopole" / a "Properties" breadcrumb (the login form
# page has neither; it shows input[placeholder="Email Address"]).
BIOPOLWIFI_PORTAL_URL = (
    "https://cloudpath.edificom.cloud/management-portal/"
    "MduPortalAccess-ba2441af-c90a-47bd-9f00-847a817da979"
    "?redirect=%2FMduPortalAccess-ba2441af-c90a-47bd-9f00-847a817da979%2Fproperties"
)
KEYCHAIN_SVC_BIOPOL_EMAIL = "biopol-wifi: email"
KEYCHAIN_SVC_BIOPOL_PASS = "biopol-wifi: password"

# Per-site log of REAL (cold) logins — one JSON object per line. Appended only
# when `login <site>` actually had to sign in (never on a warm/already-logged-in
# run), so `login-log <site>` shows how often you truly re-authenticated.
LOGIN_LOG_DIR = CACHE_DIR / "login-log"


def parse_args() -> argparse.Namespace:
    """Parse args before any heavy import so ``-h`` is instant."""
    p = argparse.ArgumentParser(
        prog="browser.py",
        description=(
            "Launch and drive a single shared, logged-in Chromium that both "
            "Playwright MCP and this script attach to over CDP."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  ./browser.py up                 # start it, then log into sites once\n"
            "  ./browser.py up --headless      # windowless (same profile/logins)\n"
            "  ./browser.py switch headless    # stop + relaunch windowless\n"
            "  ./browser.py status             # CDP health + tabs + lifecycle\n"
            "  ./browser.py clients            # who is attached over CDP\n"
            "  ./browser.py doctor             # full health check (disposable tab)\n"
            "  ./browser.py open https://portal.cscs.ch/profile/\n"
            "  ./browser.py eval 'document.title'\n"
            "  ./browser.py token              # cache the CSCS portal token\n"
            "  ./browser.py cscs-store-creds   # one-time: cache CSCS creds in keychain\n"
            "  ./browser.py cscs-login         # auto-login to CSCS (keychain, no Touch ID)\n"
            "  ./browser.py store-creds biopolwifi  # one-time: cache Cloudpath portal creds\n"
            "  ./browser.py login biopolwifi   # auto-login to the Cloudpath MDU WiFi portal\n"
            "  ./browser.py down               # quit the shared browser\n"
        ),
    )
    p.add_argument(
        "--cdp-port",
        type=int,
        default=DEFAULT_CDP_PORT,
        help=f"CDP remote-debugging port (default {DEFAULT_CDP_PORT}; "
        "env CLAUDE_BROWSER_CDP_PORT).",
    )
    sub = p.add_subparsers(dest="cmd", required=True)
    pup = sub.add_parser("up", help="Launch the shared browser (idempotent).")
    pup.add_argument(
        "-H",
        "--headless",
        action="store_true",
        default=os.environ.get("CLAUDE_BROWSER_HEADLESS") == "1",
        help="Opt-in headless mode (--headless=new): same profile, same logins, "
        "no window at all (env default CLAUDE_BROWSER_HEADLESS=1).",
    )
    sub.add_parser(
        "status", help="Show CDP health, version, open tabs, and the lifecycle record."
    )
    psw = sub.add_parser(
        "switch",
        help="Transactional mode switch: stop the browser and relaunch it in MODE "
        "on the SAME profile (every login persists).",
    )
    psw.add_argument(
        "mode",
        choices=("headed", "headless"),
        help="Target mode to switch the shared browser to.",
    )
    psw.add_argument(
        "-f",
        "--force",
        action="store_true",
        help="Switch even with unknown (unregistered) or unverifiable CDP "
        "clients attached — they lose their connection.",
    )
    sub.add_parser(
        "clients",
        help="Show the registered CDP clients plus any unregistered ones (a "
        "switch refuses while those are attached).",
    )
    sub.add_parser(
        "doctor",
        help="Full health check of the shared browser: lifecycle record, "
        "coordination, and a drivability probe on a disposable page — never "
        "touches real tabs.",
    )
    pre = sub.add_parser(
        "register-exec",
        help="Run CMD as a REGISTERED CDP client: hold a registry registration "
        "for exactly as long as CMD runs (for long-lived clients like the "
        "Playwright MCP server). Usage: register-exec [-t NAME] -- CMD ARGS…",
    )
    pre.add_argument(
        "-t",
        "--tool",
        default="wrapped",
        help="Tool name recorded in the registration (default: wrapped).",
    )
    pre.add_argument(
        "cmd_",  # NOT "cmd" — that would clobber the subparsers' dest="cmd"
        metavar="cmd",
        nargs=argparse.REMAINDER,
        help="Command to run (prefix with -- to stop flag parsing).",
    )
    sub.add_parser("down", help="Quit the shared browser.")
    po = sub.add_parser("open", help="Open/navigate a tab to URL.")
    po.add_argument("url", help="URL to open.")
    po.add_argument(
        "-r",
        "--reuse",
        action="store_true",
        help=(
            "Navigate an existing tab already on this URL (compared without "
            "query/fragment) instead of opening a new tab. Picks the oldest "
            "match — the same tab `eval --url` targets."
        ),
    )
    pe = sub.add_parser("eval", help="Eval a JS expression in a tab; print JSON.")
    pe.add_argument("js", help="JavaScript expression to evaluate.")
    pe.add_argument(
        "--url",
        default=None,
        help="Substring to pick the target tab (default: first/active tab).",
    )
    sub.add_parser("token", help="Cache the CSCS portal token from the portal tab.")
    sub.add_parser(
        "slack-session",
        help="Print the logged-in Slack session creds as JSON {token,cookie,"
        "team_domain} for slack_api.py (bearer creds → stdout only, never cached).",
    )
    sub.add_parser(
        "cscs-login",
        help="Log into CSCS in the shared browser, then cache the token. Uses "
        "macOS-keychain creds when set up (no fingerprint), else the single "
        "1Password item (op, Touch-ID-gated).",
    )
    sub.add_parser(
        "cscs-store-creds",
        help="One-time setup: store CSCS username/password/TOTP-seed in the macOS "
        "keychain (from 1Password, one last Touch ID) for fingerprint-free login.",
    )
    sub.add_parser(
        "cscs-forget-creds",
        help="Delete the CSCS credentials stored in the macOS keychain.",
    )

    # --- generic multi-site login (SITE = cscs | anthropic | …) ---
    pl = sub.add_parser(
        "login", help="Ensure SITE is logged in (automated or assisted)."
    )
    pl.add_argument(
        "site",
        help="Site to log into (e.g. cscs, anthropic/claude, openai/chatgpt, "
        "slack, biopolwifi).",
    )
    pli = sub.add_parser(
        "logged-in", help="Exit 0 if SITE is logged in, 2 if not (no login)."
    )
    pli.add_argument("site", help="Site to check.")
    pll = sub.add_parser(
        "login-log",
        help="How often a real login was needed. No SITE = live aggregate across "
        "every tool; with a SITE = just that one.",
    )
    pll.add_argument(
        "site", nargs="?", default=None, help="Site to show (omit for all sites)."
    )
    psc = sub.add_parser(
        "store-creds",
        help="Store SITE credentials in the macOS keychain (password+TOTP sites).",
    )
    psc.add_argument("site", help="Site whose credentials to store.")
    pfc = sub.add_parser(
        "forget-creds", help="Delete SITE credentials from the macOS keychain."
    )
    pfc.add_argument("site", help="Site whose credentials to forget.")
    return p.parse_args()


def ensure_deps():  # literal "def ensure_deps():" required by pre-commit hook
    """Auto-create an isolated venv (NOT cscs-api's) and re-exec into it.

    Browser deps (playwright) are heavy, so they live in a dedicated venv under
    ~/.cache to avoid bloating the cscs-api client's .venv.
    """
    try:
        import playwright  # noqa: F401
        import pyotp  # noqa: F401
        import requests  # noqa: F401

        return
    except ImportError:
        pass

    venv_dir = Path.home() / ".cache" / "claude-browser" / "venv"
    venv_python = venv_dir / "bin" / "python3"
    deps = ["playwright", "requests", "pyotp"]
    sys.argv[0] = os.path.abspath(sys.argv[0])

    def _pip_install() -> None:
        """Install deps into the venv via uv, falling back to venv pip."""
        try:
            subprocess.run(
                ["uv", "pip", "install", "--python", str(venv_python), *deps],
                check=True,
            )
        except (FileNotFoundError, subprocess.CalledProcessError):
            subprocess.run(
                [str(venv_python), "-m", "pip", "install", *deps], check=True
            )

    if venv_dir.exists():
        if Path(sys.executable) != venv_python:
            os.execv(str(venv_python), [str(venv_python), *sys.argv])
        # Inside the venv but a dep is missing (e.g. pyotp added after creation).
        # Self-heal by installing the missing deps rather than erroring out.
        print("Installing missing browser deps (pyotp)…", file=sys.stderr)
        _pip_install()
        os.execv(str(venv_python), [str(venv_python), *sys.argv])

    print(
        "First run: creating browser venv (playwright, requests, pyotp)...",
        file=sys.stderr,
    )
    try:
        subprocess.run(["uv", "venv", str(venv_dir)], check=True)
        _pip_install()
    except (FileNotFoundError, subprocess.CalledProcessError):
        subprocess.run([sys.executable, "-m", "venv", str(venv_dir)], check=True)
        _pip_install()
    os.execv(str(venv_python), [str(venv_python), *sys.argv])


def _chromium_binary() -> str:
    """Resolve Playwright's bundled Chromium executable (newest revision)."""
    cache = Path.home() / "Library" / "Caches" / "ms-playwright"
    pats = [
        str(
            cache
            / "chromium-*"
            / "chrome-mac-arm64"
            / "*.app"
            / "Contents"
            / "MacOS"
            / "*"
        ),
        str(cache / "chromium-*" / "chrome-mac" / "*.app" / "Contents" / "MacOS" / "*"),
    ]
    found: list[tuple[int, str]] = []
    for pat in pats:
        for path in glob.glob(pat):
            if os.access(path, os.X_OK) and os.path.isfile(path):
                m = re.search(r"chromium-(\d+)", path)
                found.append((int(m.group(1)) if m else 0, path))
    if not found:
        sys.exit(
            "No Playwright Chromium found. Run: "
            "uv run --with playwright playwright install chromium"
        )
    found.sort(reverse=True)
    return found[0][1]


def _cdp_get(port: int, path: str, timeout: float = 2.0) -> object | None:
    """GET a CDP JSON endpoint; return parsed JSON or None if unreachable.

    Uses ``127.0.0.1`` (not ``localhost``): on macOS ``localhost`` resolves to
    IPv6 ``::1`` first, but Chrome's remote-debugging port listens only on IPv4
    ``127.0.0.1`` — connecting via the name stalls or ECONNREFUSEs on ``::1``.
    """
    try:
        with urllib.request.urlopen(
            f"http://127.0.0.1:{port}{path}", timeout=timeout
        ) as r:
            parsed: object = json.loads(r.read().decode())
            return parsed
    except (urllib.error.URLError, OSError, ValueError):
        return None


def _is_up(port: int) -> bool:
    return _cdp_get(port, "/json/version") is not None


def _browser_mode(port: int) -> str | None:
    """Mode of the RUNNING browser: ``"headless"``, ``"headed"``, or None if down.

    ``/json/version`` names the flavour, but WHERE moved between Chrome versions:
    older builds prefix the ``Browser`` field (``HeadlessChrome/<version>``), while
    Chrome for Testing 151 reports a plain ``Browser`` and only the ``User-Agent``
    says ``HeadlessChrome`` (verified 2026-08-20). Check both. The mode is read off
    the live browser instead of remembered from launch — correct even for a
    browser this process didn't start.
    """
    ver = _cdp_get(port, "/json/version")
    if not isinstance(ver, dict):
        return None
    headless = str(ver.get("Browser", "")).startswith("Headless") or (
        "HeadlessChrome" in str(ver.get("User-Agent", ""))
    )
    return "headless" if headless else "headed"


def _require_headed_for_assisted(port: int, site: str) -> bool:
    """True if a human could see the browser; else explain the fix and return False.

    An ASSISTED login hands the window to the human (type an emailed code, finish
    an SSO+2FA prompt), which is impossible with no window. Fail fast with the
    remedy instead of blocking for 5–10 min on a wait nobody can satisfy.
    """
    if _browser_mode(port) != "headless":
        return True
    print(
        f"❌ Assisted login for {site} needs a visible window, but the shared "
        "browser is running HEADLESS.\n"
        "   Run `browser.py down && browser.py up` (headed), then retry.",
        file=sys.stderr,
    )
    return False


def _clear_session_restore() -> int:
    """Delete Chrome's session-restore state so a cold launch opens ONE clean tab.

    Chrome reopens the previous window's tabs from a handful of files under the
    profile's ``Default/`` dir — the timestamped ``Sessions/`` records plus the
    ``Current/Last Session`` and ``Current/Last Tabs`` blobs (which one it uses
    depends on Chrome version and clean-vs-crash exit). Removing all of them
    leaves nothing to restore, so the browser starts fresh. Logins are NOT here
    (they live in ``Cookies`` / ``Local Storage`` / ``Login Data``), so they
    persist. Opt out with ``CLAUDE_BROWSER_KEEP_TABS=1``. Fully guarded — a
    failure here must never block ``up``. Returns the number of items removed.
    """
    if os.environ.get("CLAUDE_BROWSER_KEEP_TABS") == "1":
        return 0
    default_dir = PROFILE_DIR / "Default"
    removed = 0
    try:
        sessions = default_dir / "Sessions"
        if sessions.is_dir():
            shutil.rmtree(sessions, ignore_errors=True)
            removed += 1
        for name in ("Current Session", "Current Tabs", "Last Session", "Last Tabs"):
            f = default_dir / name
            if f.exists():
                f.unlink(missing_ok=True)
                removed += 1
    except OSError:
        pass
    return removed


def _app_bundle(binary: str) -> Path | None:
    """The ``.app`` bundle enclosing a macOS executable, or None if not bundled.

    e.g. ``…/Chromium.app/Contents/MacOS/Chromium`` → ``…/Chromium.app``.
    """
    for parent in Path(binary).parents:
        if parent.suffix == ".app":
            return parent
    return None


def _launch_browser(
    binary: str, flags: list[str], headless: bool = False
) -> int | None:
    """Start the browser detached and WITHOUT stealing window focus.

    On macOS a subprocess-launched ``.app`` activates itself and grabs the
    foreground — it pops over whatever you're working on. ``open -g`` launches it
    in the background (its window opens *behind* the current app), and ``-n``
    forces our profile instance instead of focusing an unrelated running one.
    ``open`` doesn't return the browser's PID, so the caller resolves it after
    CDP is up (``_record_running`` → ``_find_root_pids``). On other platforms a
    plain detached ``Popen`` doesn't steal focus and yields the real PID. With ``headless`` there
    is no window to hide, so the ``open`` dance is pointless — go straight to
    ``Popen``, which also hands back the real PID immediately. Returns the PID if
    known immediately, else None. Opt out of background launch with
    ``CLAUDE_BROWSER_FOREGROUND=1`` (falls back to a direct foreground launch).
    """
    foreground = os.environ.get("CLAUDE_BROWSER_FOREGROUND") == "1"
    if sys.platform == "darwin" and not foreground and not headless:
        app = _app_bundle(binary)
        if app is not None:
            subprocess.run(
                ["open", "-g", "-n", "-a", str(app), "--args", *flags],
                check=False,
            )
            return None
    proc = subprocess.Popen(
        [binary, *flags],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    return proc.pid


# ---------------------------------------------------------------------------
# Lifecycle record — at most ONE validated root browser, transactional switches
# ---------------------------------------------------------------------------
# The record (LIFECYCLE_FILE) answers "what is the shared browser doing right
# now" for every client: {state, mode, pid, process_start_time, nonce, port,
# iso}. NO file = cleanly down. A transitional state (starting/stopping/
# switching) is the ONLY situation in which zero browser processes are
# legitimate; in state `running` the record must agree with the live browser.
# Nothing here trusts PID_FILE — a PID alone is forgeable by PID reuse, so the
# (pid, ps start time, command line, executable path) tuple in the record is
# what authorises a signal (see _validated_root_pid).

TRANSITIONAL_STATES = ("starting", "stopping", "switching")
# A transition that has not finished within this long is a dead transition
# (something crashed mid-flight) — reported, and overwritable by a new launch.
TRANSITION_STALE_S = 120.0


def _lifecycle_read() -> dict | None:
    """The current lifecycle record, or None when absent or unreadable.

    A missing file is the normal "cleanly down" state. A corrupt/truncated file
    also reads as None rather than raising: the caller's job is to reconcile
    with the live processes anyway, and `_lifecycle_problems` reports whatever
    disagreement that causes.
    """
    try:
        data = json.loads(LIFECYCLE_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _lifecycle_write(  # pylint: disable=too-many-arguments
    state: str,
    mode: str,
    *,
    pid: int | None = None,
    process_start_time: str | None = None,
    nonce: str | None = None,
    port: int,
) -> dict:
    """Atomically write the lifecycle record; return the record written.

    Written to a sibling ``.tmp`` and ``os.replace``d, so a concurrent reader
    sees either the old or the new record but never a half-written one, and
    chmod'ed 0600 (it names our profile's processes). A fresh ``nonce`` is
    minted per transition unless the caller deliberately carries one over.
    """
    rec = {
        "state": state,
        "mode": mode,
        "pid": pid,
        "process_start_time": process_start_time,
        "nonce": nonce or uuid.uuid4().hex,
        "port": port,
        "iso": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    }
    LIFECYCLE_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = LIFECYCLE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(rec, indent=2) + "\n", encoding="utf-8")
    tmp.chmod(0o600)
    os.replace(tmp, LIFECYCLE_FILE)
    return rec


def _lifecycle_clear() -> None:
    """Remove the record — i.e. declare the browser cleanly down. Idempotent."""
    LIFECYCLE_FILE.unlink(missing_ok=True)


def _ps_field(pid: int, fmt: str) -> str | None:
    """One ``ps -o <fmt>`` field for PID, stripped; None if the process is gone.

    ``LC_ALL=C`` pins the formatting (notably ``lstart``'s month/day names), so
    a recorded start time stays comparable across locale changes.
    """
    try:
        r = subprocess.run(
            ["ps", "-p", str(pid), "-o", fmt],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
            env={**os.environ, "LC_ALL": "C"},
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return r.stdout.strip() or None


def _proc_lstart(pid: int) -> str | None:
    """The process start time of PID (``ps -o lstart=``), or None if it's gone.

    (pid, start time) is what makes a PID unforgeable: a recycled PID always
    has a later start time than the one the record remembers.
    """
    return _ps_field(pid, "lstart=")


def _proc_command(pid: int) -> str | None:
    """The full command line of PID (``ps -o command=``), or None if it's gone."""
    return _ps_field(pid, "command=")


def _playwright_cache_root() -> Path:
    """Playwright's browser cache dir — the only place our chromium may live."""
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Caches" / "ms-playwright"
    return Path.home() / ".cache" / "ms-playwright"


def _is_root_command(cmd: str, port: int) -> bool:
    """True if a ``ps`` command line is OUR ROOT browser process on `port`.

    Renderer/GPU/utility children inherit the flags but every one of them
    carries ``--type=<kind>``; only the top-level browser process has none. That
    single negative check separates the one process we may signal from its dozen
    helpers, and the profile-dir check keeps other people's Chromiums out.
    """
    return (
        f"remote-debugging-port={port}" in cmd
        and f"--user-data-dir={PROFILE_DIR}" in cmd
        and "--type=" not in cmd
    )


def _find_root_pids(port: int) -> list[int]:
    """PIDs of every root browser process for our profile on `port` (normally ≤1).

    pgrep on the debug-port flag catches the whole process tree, so each
    candidate is re-checked against its command line (`_is_root_command`). More
    than one hit means two roots on one profile — the corrupted state
    `_launch_guard` refuses to add to.
    """
    try:
        res = subprocess.run(
            ["pgrep", "-f", f"remote-debugging-port={port}"],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return []
    pids: list[int] = []
    for tok in res.stdout.split():
        if not tok.strip().isdigit():
            continue
        pid = int(tok)
        cmd = _proc_command(pid)
        if cmd and _is_root_command(cmd, port):
            pids.append(pid)
    return sorted(pids)


def _validated_root_pid(rec: dict | None) -> int | None:
    """The record's PID iff it is STILL the exact process the record describes.

    Every one of these must hold: an int PID; the process alive; its ``ps``
    start time identical to the recorded one; a command line that is a root
    browser for the recorded port and our profile; and an executable inside
    Playwright's browser cache. This is the ONLY PID this script ever signals
    directly — a recycled PID fails the start-time check, so we can never
    SIGTERM some unrelated process that inherited the number.
    """
    if not isinstance(rec, dict):
        return None
    pid, want_start, port = (
        rec.get("pid"),
        rec.get("process_start_time"),
        rec.get("port"),
    )
    if not (
        isinstance(pid, int)
        and isinstance(port, int)
        and isinstance(want_start, str)
        and want_start
    ):
        return None
    if _proc_lstart(pid) != want_start:
        return None
    cmd = _proc_command(pid)
    if not cmd or not _is_root_command(cmd, port):
        return None
    if not cmd.split()[0].startswith(str(_playwright_cache_root())):
        return None
    return pid


def _singleton_lock() -> tuple[Path, str | None]:
    """The profile's ``SingletonLock`` path plus its ``<host>-<pid>`` target.

    Chrome creates it as a DANGLING symlink (the target names a host and PID,
    not a real file), so presence must be probed with ``os.path.lexists`` —
    ``Path.exists()`` follows the link and reports False for a lock that is very
    much there. Second element is None when the lock is absent or unreadable.
    """
    lock = PROFILE_DIR / "SingletonLock"
    if not os.path.lexists(lock):
        return lock, None
    try:
        return lock, os.readlink(lock)
    except OSError:
        return lock, None


def _singleton_lock_stale(target: str | None, port: int) -> bool:
    """True if a present ``SingletonLock`` is crash debris, not a live lock.

    Stale when the PID part of the target can't be parsed, the PID is gone, or
    it belongs to something that is demonstrably not our browser. Deliberately
    CONSERVATIVE: a live PID whose command line mentions our profile dir counts
    as a real lock and is never removed — deleting a live lock invites two
    browsers onto one profile, the exact corruption this step exists to prevent.
    """
    pid_part = (target or "").rsplit("-", 1)[-1]
    if not pid_part.isdigit():
        return True
    pid = int(pid_part)
    cmd = _proc_command(pid)
    if cmd is None:
        return True  # nothing alive is holding it
    if str(PROFILE_DIR) in cmd:
        return False  # a live process on our profile: real lock, hands off
    return pid not in _find_root_pids(port)


def _iso_age_s(iso: object) -> float | None:
    """Seconds since a record's ``iso`` timestamp, or None if it won't parse."""
    import datetime as _dt

    if not isinstance(iso, str):
        return None
    try:
        then = _dt.datetime.strptime(iso, "%Y-%m-%dT%H:%M:%S%z")
    except (ValueError, TypeError):
        return None
    return (_dt.datetime.now(_dt.timezone.utc) - then).total_seconds()


def _record_problems(rec: dict, port: int, *, up: bool) -> list[str]:
    """Everything wrong with a PRESENT lifecycle record, relative to reality."""
    problems: list[str] = []
    state = str(rec.get("state", "?"))
    rec_port = rec.get("port")
    if isinstance(rec_port, int) and rec_port != port:
        problems.append(f"record is for port {rec_port}, not the probed port {port}")
    if state in TRANSITIONAL_STATES:
        age = _iso_age_s(rec.get("iso"))
        if age is None:
            problems.append(
                f"record is mid-transition ({state}) with an unparsable "
                f"timestamp {rec.get('iso')!r}"
            )
        elif age > TRANSITION_STALE_S:
            problems.append(
                f"record stuck mid-transition ({state}) for {age / 60:.1f} min — "
                "a transition died; `browser.py down` then `up` resets it"
            )
        return problems
    if state != "running":
        problems.append(f"record has an unknown state {state!r}")
        return problems
    if not up:
        problems.append(
            "record says 'running' but there is no CDP — the browser crashed "
            "or was killed"
        )
    if _validated_root_pid(rec) is None:
        problems.append(
            f"recorded pid {rec.get('pid')} does not validate any more (gone, "
            "restarted, or a different process)"
        )
    live_mode = _browser_mode(port)
    if live_mode is not None and live_mode != rec.get("mode"):
        problems.append(
            f"live browser is {live_mode.upper()} but the record says "
            f"{str(rec.get('mode')).upper()}"
        )
    return problems


def _lifecycle_problems(port: int) -> list[str]:
    """Human-readable list of lifecycle invariant violations; empty = healthy.

    The invariants: at most ONE validated root browser process; zero processes
    only while a transitional state is recorded; and, in state ``running``, a
    record that agrees with the live browser (pid, mode, port, CDP up). Used by
    ``status`` today and by ``doctor`` later.
    """
    rec = _lifecycle_read()
    roots = _find_root_pids(port)
    up = _is_up(port)
    problems: list[str] = []
    if len(roots) > 1:
        pids = ", ".join(str(p) for p in roots)
        problems.append(
            f"{len(roots)} root browser processes on this profile (pids {pids}) — "
            "expected at most one"
        )
    if rec is None:
        if up or roots:
            problems.append(
                "browser is running but there is no lifecycle record (started "
                "outside browser.py, or the record was lost)"
            )
    else:
        problems.extend(_record_problems(rec, port, up=up))
    lock, target = _singleton_lock()
    if not up and os.path.lexists(lock) and _singleton_lock_stale(target, port):
        problems.append(
            f"stale SingletonLock in the profile ({target or 'unreadable'}) — "
            "`browser.py up` clears it"
        )
    return problems


def _cdp_browser_close(port: int) -> bool:
    """Ask the browser to quit itself over CDP (``Browser.close``); True if sent.

    The graceful path: Chrome flushes the profile (cookies, sessions) and
    removes its own SingletonLock, neither of which a signal-based kill gets
    right. A dropped connection while the command is in flight is the EXPECTED
    success case (the browser died before answering), so that counts as sent.
    Deliberately not routed through `_connect`, which ``sys.exit``s when the
    browser is down — and, since `switch`/`down` call this while they hold the
    client gate EXCLUSIVELY, must NOT register a client here either: a second fd
    asking for the same gate shared would deadlock against our own hold (see the
    deadlock rule in the client-coordination section). Keep it CDP-only.
    """
    try:
        from playwright.sync_api import Error as PlaywrightError
        from playwright.sync_api import sync_playwright
    except ImportError:
        return False
    try:
        pw = sync_playwright().start()
    except (PlaywrightError, OSError):
        return False
    sent = False
    try:
        browser = pw.chromium.connect_over_cdp(f"http://127.0.0.1:{port}")
        browser.new_browser_cdp_session().send("Browser.close")
        sent = True
    except PlaywrightError as exc:
        # "Target closed"/"connection closed" == the browser went away while the
        # command was in flight, which is exactly what we asked for.
        sent = any(
            m in str(exc).lower() for m in ("closed", "disconnected", "not connected")
        )
    except OSError:
        sent = False
    finally:
        try:
            pw.stop()
        except (PlaywrightError, OSError):
            pass
    return sent


def _wait_for_roots_gone(port: int, timeout_s: float) -> bool:
    """Poll in 0.25 s steps until no root browser process is left; True if gone."""
    deadline = time.monotonic() + timeout_s
    while True:
        if not _find_root_pids(port):
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.25)


def _clear_lock_after_shutdown(port: int) -> None:
    """Drop a ``SingletonLock`` the stopped browser left behind (best-effort).

    Chrome removes the lock only on a GRACEFUL exit; after a SIGTERM/pkill it
    dangles and the next launch refuses to start ("profile appears to be in
    use"). Give the browser up to 5 s to clean up after itself, then unlink the
    lock ourselves — but only if it is provably stale — and say so on stderr.
    """
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        lock, _target = _singleton_lock()
        if not os.path.lexists(lock):
            return
        time.sleep(0.25)
    lock, target = _singleton_lock()
    if not os.path.lexists(lock):
        return
    if not _singleton_lock_stale(target, port):
        print(
            f"⚠ SingletonLock ({target}) still looks live — left in place.",
            file=sys.stderr,
        )
        return
    try:
        lock.unlink()
        print("  removed the SingletonLock the killed browser left.", file=sys.stderr)
    except OSError as exc:
        print(f"⚠ could not remove {lock}: {exc}", file=sys.stderr)


def _shutdown_browser(port: int, rec: dict | None = None) -> bool:
    """Stop the shared browser, escalating only as far as needed. True if gone.

    Assumes the caller ALREADY wrote a transitional record (``stopping`` /
    ``switching``), so an observer that finds zero processes can tell a
    transition from a crash. Ladder, every step polled instead of slept blindly:

      1. CDP ``Browser.close`` — graceful, flushes the profile, drops the lock.
      2. up to 5 s waiting for every root process to disappear.
      3. ``SIGTERM`` to the ONE validated root PID (`_validated_root_pid` of the
         pre-shutdown record — never a bare PID from a file), then wait until
         10 s total have passed.
      4. ``pkill -f user-data-dir=<profile>`` — pattern-scoped to our profile,
         the fallback for `open`-launched roots whose PID we never captured.
      5. a final ≤5 s poll, plus removal of a leftover SingletonLock.
    """
    rec = _lifecycle_read() if rec is None else rec
    pid = _validated_root_pid(rec)
    start = time.monotonic()
    if _is_up(port):
        _cdp_browser_close(port)
    if not _wait_for_roots_gone(port, 5.0):
        if pid is not None:
            try:
                os.kill(pid, signal.SIGTERM)
            except (ProcessLookupError, PermissionError):
                pass
        remaining = max(0.5, 10.0 - (time.monotonic() - start))
        if not _wait_for_roots_gone(port, remaining):
            # Pattern must NOT start with '-', or BSD pkill parses it as an
            # option ("illegal option -- -"); 'user-data-dir=<profile>' still
            # matches only our browser's processes.
            subprocess.run(["pkill", "-f", f"user-data-dir={PROFILE_DIR}"], check=False)
            _wait_for_roots_gone(port, 5.0)
    gone = not _find_root_pids(port)
    if gone:
        _clear_lock_after_shutdown(port)
    return gone


def _launch_guard(port: int) -> str | None:
    """Reason a relaunch must ABORT, or None when launching is safe.

    Blockers: a surviving root process (a second root on one profile is the
    corruption this step exists to prevent) and a ``SingletonLock`` that is not
    demonstrably stale. A provably stale lock is removed here (crash leftover);
    a dead transitional record is NOT a blocker — it is reported and then
    overwritten by the launch.
    """
    roots = _find_root_pids(port)
    if roots:
        pids = ", ".join(str(p) for p in roots)
        return f"a root browser process for this profile is still alive (pid(s) {pids})"
    lock, target = _singleton_lock()
    if os.path.lexists(lock):
        if not _singleton_lock_stale(target, port):
            return f"the profile's SingletonLock is held by a live process ({target})"
        try:
            lock.unlink()
            print("removed stale SingletonLock (crash leftover)", file=sys.stderr)
        except OSError as exc:
            return f"the stale SingletonLock {lock} could not be removed: {exc}"
    rec = _lifecycle_read()
    state = str(rec.get("state", "?")) if rec else ""
    if state in TRANSITIONAL_STATES:
        age = _iso_age_s(rec.get("iso") if rec else None)
        if age is None or age > 60:
            print(
                f"overwriting a dead '{state}' lifecycle record "
                "(no browser process is running)",
                file=sys.stderr,
            )
    return None


def _lifecycle_transition(state: str, mode: str, rec: dict | None, port: int) -> dict:
    """Record a ``stopping``/``switching`` transition over the OLD process.

    Carrying the running browser's pid + start time into the transitional record
    keeps the shutdown ladder able to signal a *validated* PID after the record
    has already moved on; the nonce is fresh, one per transition. For
    ``switching``, ``mode`` is the TARGET mode. When the previous record does not
    (or does not any more) describe the live root — a browser started before
    this mechanism existed, or by hand — the pid + start time are re-read from
    the process table here, so the shutdown still gets a validated PID instead
    of falling straight through to ``pkill``.
    """
    pid = _validated_root_pid(rec)
    lstart = rec.get("process_start_time") if rec and pid is not None else None
    if pid is None:
        roots = _find_root_pids(port)
        pid = roots[0] if len(roots) == 1 else None
        lstart = _proc_lstart(pid) if pid is not None else None
    return _lifecycle_write(state, mode, pid=pid, process_start_time=lstart, port=port)


def _record_running(
    port: int, mode: str, pid: int | None = None, nonce: str | None = None
) -> int | None:
    """Write the ``running`` record for the live browser; return its root PID.

    The PID is resolved from the process table rather than trusted: an
    `open`-launched browser never handed us one. The finished record is then
    re-validated (`_validated_root_pid`) so a browser that does not match its
    own record is flagged immediately instead of at the next `down`.
    """
    roots = _find_root_pids(port)
    if pid not in roots:
        pid = roots[0] if roots else None
    lstart = _proc_lstart(pid) if pid is not None else None
    rec = _lifecycle_write(
        "running", mode, pid=pid, process_start_time=lstart, nonce=nonce, port=port
    )
    if pid is None:
        print(
            "⚠ browser is up but no root process matched our profile — "
            "lifecycle record written without a pid.",
            file=sys.stderr,
        )
    elif _validated_root_pid(rec) is None:
        print(
            f"⚠ pid {pid} does not validate against its own lifecycle record; "
            "`browser.py status` will keep reporting it.",
            file=sys.stderr,
        )
    else:
        PID_FILE.write_text(str(pid))  # legacy, for external observers only
    return pid


def _heal_running_record(port: int, mode: str) -> bool:
    """Make the record match an already-running browser; True if it was rewritten.

    Covers the honest cases where a perfectly good browser has a wrong record:
    it predates this mechanism, was started by hand, or the record was lost.
    """
    rec = _lifecycle_read()
    if (
        _validated_root_pid(rec) is not None
        and rec is not None
        and rec.get("state") == "running"
        and rec.get("mode") == mode
        and rec.get("port") == port
    ):
        return False
    _record_running(port, mode)
    return True


def _launch_and_record(port: int, headless: bool) -> int:
    """Cold-launch the shared browser and record it. Shared by ``up``/``switch``.

    Order matters: `_launch_guard` first (never a second root on one profile),
    then a ``starting`` record BEFORE the launch (so the window in which zero
    processes exist is an explicitly recorded transition), then a ``running``
    record with the validated PID once CDP answers. If CDP never comes up the
    ``starting`` record is deliberately left behind for `status`/`doctor`.
    """
    want = "headless" if headless else "headed"
    reason = _launch_guard(port)
    if reason is not None:
        return _fail(
            f"Refusing to launch a second browser on this profile: {reason}.\n"
            "   Stop the old one first: browser.py down   "
            "(then `browser.py doctor` should certify a clean state)."
        )
    PROFILE_DIR.mkdir(parents=True, exist_ok=True)
    # Cold start (nothing was running, per _browser_mode): wipe stale tab-restore
    # state so the window opens clean instead of resurrecting every tab from the
    # last session.
    _clear_session_restore()
    binary = _chromium_binary()
    flags = [
        f"--user-data-dir={PROFILE_DIR}",
        f"--remote-debugging-port={port}",
        "--no-first-run",
        "--no-default-browser-check",
        "--hide-crash-restore-bubble",
        "--remote-allow-origins=*",
        # The window deliberately opens in the background (open -g) and is
        # therefore usually OCCLUDED — macOS then pauses rendering, freezing
        # requestAnimationFrame, which makes Playwright's click actionability
        # wait ("stable" = 2 consecutive rAF frames) time out for EVERY driver
        # (observed 2026-08-19: anthropic-api.py --team-* clicks all timing
        # out). Keep rendering + timers alive while occluded/backgrounded:
        "--disable-backgrounding-occluded-windows",
        "--disable-renderer-backgrounding",
        "--disable-background-timer-throttling",
    ]
    if headless:
        # `--headless=new` is the real browser minus the window (full CDP, same
        # profile, same logins). The anti-throttling flags above are kept — with
        # no window they're moot, but harmless, and one mode difference less.
        flags.append("--headless=new")
    rec = _lifecycle_write("starting", want, port=port)
    # Launch in the background so it never steals focus (see _launch_browser).
    pid = _launch_browser(binary, flags, headless=headless)
    if pid is not None:
        PID_FILE.write_text(str(pid))
    for _ in range(50):  # up to ~10s
        if _is_up(port):
            pid = _record_running(port, want, pid, rec["nonce"])
            if headless:
                print(
                    f"✓ Shared browser launched HEADLESS "
                    f"(no window; pid {pid or '?'}, CDP http://localhost:{port}).\n"
                    "  Logins from the profile still apply; assisted (human) "
                    "logins need a window — `browser.py switch headed` for those.\n"
                    f"  Profile: {PROFILE_DIR}"
                )
            else:
                print(
                    f"✓ Shared browser launched in background "
                    f"(pid {pid or '?'}, CDP http://localhost:{port}).\n"
                    "  Log into your sites in that window ONCE; the session persists.\n"
                    f"  Profile: {PROFILE_DIR}"
                )
            return 0
        time.sleep(0.2)
    return _fail(
        "Browser started but CDP endpoint never came up — lifecycle record left "
        "in state 'starting' (see `browser.py status`)."
    )


# ---------------------------------------------------------------------------
# Client coordination — layer 1: CDP-client registry, layer 2: interaction lease
# ---------------------------------------------------------------------------
# One browser, many drivers (this script, Playwright MCP, anthropic-api.py,
# openai-team.py). Two advisory flocks under CACHE_DIR keep them out of each
# other's way; because they are flocks, the kernel releases them even when a
# holder is SIGKILLed, so there is no stale-lock class of bug to clean up.
#
#   Layer 1 — the GATE (REGISTRY_GATE). Every attached CDP client holds it
#   SHARED for the whole connection; `switch`/`down` take it EXCLUSIVELY, which
#   by construction waits for every registered client to drain before the
#   browser is touched. The per-client metadata file (CLIENTS_DIR/<nonce>.json,
#   LOCK_EX'd by its owner) turns that anonymous shared lock into a NAMED set:
#   the gate says somebody is attached, the files say who — and a file whose own
#   lock is free belongs to a client that died, i.e. it is debris to reap.
#
#   Layer 2 — the LEASE (INTERACTION_LOCK). Exclusive "I am the one driving
#   focus/input/screenshots right now", taken only around interactive sections.
#   It is the SAME file the consumer CLIs already flock, so they and we
#   serialise against each other.
#
# DEADLOCK RULE: an flock belongs to the open file DESCRIPTION, so a second fd
# in the SAME process conflicts with our own exclusive hold exactly as another
# process would. Any code path that already holds the gate exclusively must
# therefore NEVER register and never take the gate shared — which is why
# `_cdp_browser_close` (called from `switch`/`down` while the gate is held)
# deliberately bypasses `_connect`.

CLIENTS_DIR = CACHE_DIR / "clients"
REGISTRY_GATE = CLIENTS_DIR / ".registry.lock"
# How long a client waits for the gate to become shareable (i.e. for a mode
# switch or a shutdown to finish) before it fails loud instead of attaching.
REGISTRY_SH_WAIT_S = 15.0
# How long `switch`/`down` wait for every registered client to drain.
REGISTRY_EX_WAIT_S = 20.0
# `up` only needs to know that no switch/shutdown is mid-flight — a short wait.
REGISTRY_UP_WAIT_S = 5.0

INTERACTION_LOCK = CACHE_DIR / "interaction.lock"
INTERACTION_WAIT_S = 30.0
INTERACTION_HEARTBEAT_S = 10.0

# What this process is doing, for its registry entry — filled in by main() from
# the chosen subcommand. A one-element list (not a rebindable str) so main can
# set it without a `global` statement.
_PURPOSE: list[str] = []


def _set_purpose(text: str) -> None:
    """Record WHAT this process is doing; reported in its registry entry."""
    _PURPOSE[:] = [text]


def _purpose() -> str:
    """This process's purpose string, or a neutral default if never set."""
    return _PURPOSE[0] if _PURPOSE else "(unspecified)"


def _flock_wait(fd: int, kind: int, wait_s: float) -> bool:
    """Poll for `kind` (LOCK_SH/LOCK_EX) on `fd` in 0.25 s steps; True if held.

    Non-blocking polling rather than a blocking ``flock``: a blocking wait would
    hang a CLI forever behind a wedged holder, while a bounded poll lets every
    caller report WHO is in the way and exit.
    """
    deadline = time.monotonic() + wait_s
    while True:
        try:
            fcntl.flock(fd, kind | fcntl.LOCK_NB)
            return True
        except OSError:
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.25)


def _read_json_dict(path: Path) -> dict | None:
    """Parse a JSON object from `path`, or None if absent/garbage/not an object."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _registry_live_clients() -> list[dict]:
    """Every LIVE client registration; reaps the files of dead ones on the way.

    Liveness is the file's own flock, not its content: a registrant holds
    LOCK_EX on its metadata file for as long as it is attached, so a file we
    CAN lock shared belongs to a process that is gone (crashed, SIGKILLed, or
    exited without releasing) and is unlinked here. That makes the listing
    self-healing — no reaper daemon, no timeout heuristics.
    """
    live: list[dict] = []
    try:
        paths = sorted(CLIENTS_DIR.glob("*.json"))
    except OSError:
        return live
    for path in paths:
        try:
            fd = os.open(str(path), os.O_RDONLY)
        except OSError:
            continue
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
            except OSError:
                rec = _read_json_dict(path)  # locked → a live client
                if rec is not None:
                    live.append(rec)
                continue
            fcntl.flock(fd, fcntl.LOCK_UN)
            path.unlink(missing_ok=True)  # lockable → dead client's debris
        finally:
            os.close(fd)
    return live


def _describe_client(rec: dict) -> str:
    """One human line for a registration: tool, pid, purpose, when, age."""
    age = _iso_age_s(rec.get("heartbeat_iso") or rec.get("iso"))
    return (
        f"{rec.get('tool') or '?'} pid {rec.get('pid') or '?'} — "
        f"{rec.get('purpose') or '(unspecified)'} "
        f"(since {rec.get('iso') or '?'}"
        + (f", {age:.0f}s ago)" if age is not None else ")")
    )


def _registry_register(tool: str, purpose: str, port: int) -> Callable[[], None]:
    """Register this process as an attached CDP client; return its ``release()``.

    Two locks are taken and held until release: the gate SHARED (so `switch`
    and `down` — which need it exclusively — cannot pull the browser out from
    under a live connection) and LOCK_EX on our own metadata file (which is
    both the liveness signal other readers test and the record of who we are).
    The file is created ``O_EXCL`` and locked BEFORE it is written, so the
    window in which a concurrent reaper could mistake it for debris is as small
    as an open() syscall.

    Fails loud (exit) when the gate cannot be shared within
    REGISTRY_SH_WAIT_S: that means a mode switch or a shutdown is mid-flight,
    and attaching anyway is exactly the race this layer exists to prevent.
    """
    CLIENTS_DIR.mkdir(parents=True, exist_ok=True)
    gate_fd = os.open(str(REGISTRY_GATE), os.O_RDWR | os.O_CREAT, 0o600)
    if not _flock_wait(gate_fd, fcntl.LOCK_SH, REGISTRY_SH_WAIT_S):
        os.close(gate_fd)
        sys.exit(
            "❌ Cannot attach to the shared browser: it is being switched or "
            f"stopped right now (waited {REGISTRY_SH_WAIT_S:.0f}s for the client "
            "gate).\n   Retry in a moment; `browser.py status` shows the "
            "lifecycle state."
        )
    nonce = uuid.uuid4().hex
    while True:
        path = CLIENTS_DIR / f"{nonce}.json"
        try:
            own_fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
            break
        except FileExistsError:
            nonce = uuid.uuid4().hex  # a 128-bit collision, humoured anyway
        except OSError as exc:
            fcntl.flock(gate_fd, fcntl.LOCK_UN)
            os.close(gate_fd)
            sys.exit(f"❌ Cannot register a CDP client in {CLIENTS_DIR}: {exc}")
    fcntl.flock(own_fd, fcntl.LOCK_EX)  # uncontended by construction
    now = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    rec = {
        "nonce": nonce,
        "pid": os.getpid(),
        "pid_start_time": _proc_lstart(os.getpid()),
        "tool": tool,
        "purpose": purpose,
        "port": port,
        "iso": now,
        "heartbeat_iso": now,
    }
    os.pwrite(own_fd, (json.dumps(rec) + "\n").encode(), 0)
    released = False

    def release() -> None:
        """Drop the registration: unlink our file, then both locks. Idempotent."""
        nonlocal released
        if released:
            return
        released = True
        current = _read_json_dict(path)
        if current is not None and current.get("nonce") not in (None, nonce):
            print(
                f"⚠ registration {path.name} was overwritten by nonce "
                f"{current.get('nonce')} — leaving it alone (not ours to remove).",
                file=sys.stderr,
            )
        else:
            path.unlink(missing_ok=True)
        for fd in (own_fd, gate_fd):
            with contextlib.suppress(OSError):
                fcntl.flock(fd, fcntl.LOCK_UN)
            with contextlib.suppress(OSError):
                os.close(fd)

    return release


def _gate_acquire(kind: int, wait_s: float) -> int | None:
    """Hold the registry gate (`kind` = LOCK_SH/LOCK_EX); its fd, or None.

    NEVER call this from a path that already holds the gate exclusively — see
    the deadlock rule above. Silent on failure: the caller words the refusal,
    which differs per command (`switch` aborts, `down` warns and proceeds).
    """
    CLIENTS_DIR.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(REGISTRY_GATE), os.O_RDWR | os.O_CREAT, 0o600)
    if _flock_wait(fd, kind, wait_s):
        return fd
    os.close(fd)
    return None


def _gate_release(fd: int) -> None:
    """Drop a gate hold: unlock, then close. Fully guarded."""
    with contextlib.suppress(OSError):
        fcntl.flock(fd, fcntl.LOCK_UN)
    with contextlib.suppress(OSError):
        os.close(fd)


def _gate_busy(action: str) -> str:
    """The "clients are still attached" refusal for `action`, naming them."""
    lines = [
        f"   still attached: {_describe_client(r)}" for r in _registry_live_clients()
    ]
    return (
        f"Cannot {action}: registered CDP client(s) did not drain within "
        f"{REGISTRY_EX_WAIT_S:.0f}s.\n"
        + (
            "\n".join(lines)
            or "   (no registration file left — see `browser.py clients`)"
        )
        + "\n   Let them finish, then retry."
    )


def _established_cdp_clients(port: int) -> list[tuple[int, str]]:
    """(pid, command) for every process with an ESTABLISHED connection to `port`.

    ``lsof -F`` prints one field per line, letter-prefixed (``p<pid>``,
    ``c<command>``), grouped per process — which is why the parse is a tiny
    state machine. Both ends of each loopback pair show up, so the browser side
    is filtered out by its ``--user-data-dir=<our profile>`` command line, as is
    this process. Returns [] when lsof is missing or fails; callers MUST treat
    "no lsof" as CANNOT VERIFY (see `_unknown_cdp_clients`) rather than as
    "nobody is attached".
    """
    try:
        res = subprocess.run(
            ["lsof", "-nP", f"-iTCP:{port}", "-sTCP:ESTABLISHED", "-Fpc"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    found: list[tuple[int, str]] = []
    seen: set[int] = set()
    pid: int | None = None
    for line in res.stdout.splitlines():
        if line[:1] == "p" and line[1:].strip().isdigit():
            pid = int(line[1:])
        elif line[:1] == "c" and pid is not None:
            if pid in seen or pid == os.getpid():
                continue
            seen.add(pid)
            cmd = _proc_command(pid) or line[1:].strip()
            if f"--user-data-dir={PROFILE_DIR}" not in cmd:
                found.append((pid, cmd))
    return sorted(found)


def _proc_ppid(pid: int) -> int | None:
    """The parent PID of `pid`, or None when the process is gone."""
    out = _ps_field(pid, "ppid=")
    return int(out) if out and out.isdigit() else None


def _pid_or_ancestor_registered(pid: int, known: set[object]) -> bool:
    """True if `pid` or any ancestor (≤15 hops) is a registered client PID.

    A ``register-exec`` wrapper records the pid of the child it spawned, but
    the actual CDP socket may belong to a GRANDchild (npx → node for the
    Playwright MCP server), so a connection counts as registered when any
    process on its ancestry chain is.
    """
    for _ in range(15):
        if pid in known:
            return True
        parent = _proc_ppid(pid)
        if parent is None or parent <= 1:
            return False
        pid = parent
    return False


def _unknown_cdp_clients(port: int) -> list[tuple[int, str]] | None:
    """Attached CDP clients that are NOT registered; None if unverifiable.

    Compares the kernel's view (lsof) with the registry. ``None`` means the
    comparison could not be MADE at all (no lsof on PATH) — fail-closed callers
    must treat that like "unknown clients present", never like "none". A
    connection is "known" when its pid OR an ancestor is registered (see
    `_pid_or_ancestor_registered`).
    """
    if shutil.which("lsof") is None:
        return None
    known = {rec.get("pid") for rec in _registry_live_clients()}
    return [
        (pid, cmd)
        for pid, cmd in _established_cdp_clients(port)
        if not _pid_or_ancestor_registered(pid, known)
    ]


def _unknown_clients_verdict(port: int) -> str | None:
    """Why stopping/switching the browser is unsafe, or None when it is safe.

    Fail-closed by design: an unregistered established CDP connection means
    somebody we cannot coordinate with is driving the browser — and so does
    being unable to LOOK. Both are reported; what to do about it is the
    caller's call (`switch` refuses, `down` only warns).
    """
    unknown = _unknown_cdp_clients(port)
    if unknown is None:
        return "cannot verify who is attached to the CDP port (no lsof on PATH)"
    if unknown:
        listing = "\n".join(f"     pid {pid}: {cmd}" for pid, cmd in unknown)
        return f"{len(unknown)} unregistered CDP client(s) attached:\n{listing}"
    return None


def _lease_record(base: dict) -> bytes:
    """The lease's one-line JSON record: `base` plus a FRESH ``heartbeat_iso``."""
    stamped = {**base, "heartbeat_iso": time.strftime("%Y-%m-%dT%H:%M:%S%z")}
    return (json.dumps(stamped) + "\n").encode()


def _lease_write(fd: int, base: dict) -> None:
    """Replace the lease file's content with a freshly stamped record."""
    os.ftruncate(fd, 0)
    os.pwrite(fd, _lease_record(base), 0)


def _lease_heartbeat(fd: int, base: dict, stop: threading.Event) -> None:
    """Refresh the lease's ``heartbeat_iso`` until `stop` is set (daemon thread).

    A heartbeat proves the holder is not merely *alive* but still working — the
    flock alone cannot say that. The interval is read from
    INTERACTION_HEARTBEAT_S on every pass (so a test can shrink it), and any
    write error ends the thread quietly: the lock, not the file content, is the
    actual mutex.
    """
    while not stop.wait(INTERACTION_HEARTBEAT_S):
        try:
            _lease_write(fd, base)
        except OSError:
            return


def _lease_holder(fd: int) -> str:
    """Whatever the lease file says about its holder, for diagnostics only."""
    try:
        return os.pread(fd, 4096, 0).decode("utf-8", "replace").strip()
    except OSError:
        return ""


@contextlib.contextmanager
def _interaction_lease(
    purpose: str, wait_s: float = INTERACTION_WAIT_S
) -> Iterator[str]:
    """Hold the exclusive INTERACTION lease for the block; yield the owner nonce.

    Layer 2 of the coordination: the gate only says "somebody is attached",
    this says "I am the one driving focus, input and screenshots right now".
    It locks the SAME file the consumer CLIs (anthropic-api.py, openai-team.py)
    already lock, so all of them serialise; they write a plain
    ``pid purpose timestamp`` line and we write JSON, and NEITHER side parses
    the other's — the flock is the contract, the content is diagnostics, so any
    format is tolerated when reporting a holder.

    LOCK ORDERING (never invert): the gate is taken FIRST (in `_connect`, via
    the registration) and the lease SECOND. `switch`/`down` take the gate
    exclusively and never take the lease, so no cycle can form.

    On timeout: fail loud naming the holder — never proceed into a browser
    somebody else is clicking. On release: stop the heartbeat, then
    compare-before-release (a foreign nonce means somebody wrote the file
    WITHOUT the lock, which flock should make impossible — so it is reported,
    loudly, instead of silently overwritten).

    REENTRANCY: a parent that already holds this lock and then shells
    ``browser.py login <site>`` (anthropic-api.py's --download-csv does) would
    deadlock the child against its own parent. Such a parent exports
    ``CLAUDE_BROWSER_LEASE_HELD=1``; the child then yields without locking —
    the parent's flock is the exclusion, exactly as before this lease existed.
    """
    if os.environ.get("CLAUDE_BROWSER_LEASE_HELD") == "1":
        yield "inherited"  # parent's flock is the real exclusion
        return
    INTERACTION_LOCK.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(INTERACTION_LOCK), os.O_RDWR | os.O_CREAT, 0o600)
    if not _flock_wait(fd, fcntl.LOCK_EX, wait_s):
        holder = _lease_holder(fd) or "<unknown holder>"
        os.close(fd)
        sys.exit(
            f"❌ Another browser interaction holds the lease: {holder}\n"
            f"   Waited {wait_s:.0f}s. Retry later (lease: {INTERACTION_LOCK})."
        )
    nonce = uuid.uuid4().hex
    base = {
        "pid": os.getpid(),
        "pid_start_time": _proc_lstart(os.getpid()),
        "nonce": nonce,
        "purpose": purpose,
        "iso": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    }
    _lease_write(fd, base)
    stop = threading.Event()
    beat = threading.Thread(
        target=_lease_heartbeat,
        args=(fd, base, stop),
        name="browser-lease-heartbeat",
        daemon=True,
    )
    beat.start()
    try:
        yield nonce
    finally:
        stop.set()
        beat.join(timeout=2.0)
        current = _read_json_dict(INTERACTION_LOCK)
        if current is not None and current.get("nonce") not in (None, nonce):
            print(
                f"⚠ the interaction lease was rewritten by nonce "
                f"{current.get('nonce')} while we held it — somebody is writing "
                f"{INTERACTION_LOCK} without taking the lock.",
                file=sys.stderr,
            )
        with contextlib.suppress(OSError):
            os.ftruncate(fd, 0)
        with contextlib.suppress(OSError):
            fcntl.flock(fd, fcntl.LOCK_UN)
        with contextlib.suppress(OSError):
            os.close(fd)


def cmd_up(port: int, headless: bool = False) -> int:
    """Launch the shared browser if not already running (idempotent).

    ``headless`` opts into ``--headless=new``: same profile, same logins, no
    window at all. The mode is fixed at launch, so a request that disagrees with
    the browser already running is REFUSED (loudly) instead of silently ignored —
    ``browser.py switch MODE`` does that transactionally. When the running mode
    DOES match, the lifecycle record is healed to describe the live process.

    A COLD launch takes the client gate shared for its duration, so it cannot
    slip into the middle of a `switch`/`down` window and race the relaunch that
    switch is about to do itself. The already-up branch needs no gate — it
    touches no process.
    """
    want = "headless" if headless else "headed"
    running = _browser_mode(port)
    if running is not None:
        if running != want:
            print(
                f"❌ Mode mismatch: the shared browser is up in {running.upper()} "
                f"mode, but {want.upper()} was requested.\n"
                "   The mode is fixed at launch. Switch it in one transaction:\n"
                f"     browser.py switch {want}",
                file=sys.stderr,
            )
            return 1
        healed = _heal_running_record(port, running)
        print(
            f"✓ Shared browser already up, {running.upper()} "
            f"(CDP http://localhost:{port})."
            + (" (lifecycle record refreshed)" if healed else "")
        )
        return 0
    gate = _gate_acquire(fcntl.LOCK_SH, REGISTRY_UP_WAIT_S)
    if gate is None:
        return _fail(
            "Not launching: a mode switch or shutdown is in progress (waited "
            f"{REGISTRY_UP_WAIT_S:.0f}s for the client gate). Retry in a moment; "
            "`browser.py status` shows the lifecycle state."
        )
    try:
        return _launch_and_record(port, headless)
    finally:
        _gate_release(gate)


def cmd_switch(port: int, target: str, force: bool = False) -> int:
    """Switch the running browser between headed and headless, transactionally.

    The mode is fixed at launch, so switching means stop + relaunch — on the
    SAME profile, so every login survives (they live in the profile, not the
    process). Each phase is recorded (``switching`` → ``starting`` → ``running``)
    and the relaunch is refused while the old root process or its SingletonLock
    is still around, so a failed switch leaves ONE state to inspect instead of
    two browsers fighting over one profile.

    Before ANY of that, the client gate is taken exclusively — which waits for
    every registered CDP client to drain — and the port is checked for clients
    nobody registered. An unknown client (or the inability to look, i.e. no
    lsof) makes an automatic switch FAIL CLOSED: killing a browser out from
    under a driver we cannot coordinate with is the interference this layer
    exists to prevent. ``--force`` is the deliberate override; the relaunch
    itself must NOT re-acquire the gate (deadlock rule), so `_launch_and_record`
    is called directly here while we still hold it.
    """
    live = _browser_mode(port)
    if live is None:
        return _fail(
            "Nothing to switch — the shared browser is down. Run: browser.py up"
            f"{' --headless' if target == 'headless' else ''}"
        )
    if live == target:
        healed = _heal_running_record(port, live)
        print(
            f"✓ Shared browser already in {target.upper()} mode "
            f"(CDP http://localhost:{port})."
            + (" (lifecycle record refreshed)" if healed else "")
        )
        return 0
    gate = _gate_acquire(fcntl.LOCK_EX, REGISTRY_EX_WAIT_S)
    if gate is None:
        return _fail(_gate_busy(f"switch to {target.upper()}"))
    try:
        verdict = _unknown_clients_verdict(port)
        if verdict is not None and not force:
            return _fail(
                f"Switch aborted — {verdict}\n"
                "   Stop the attached client(s) (or install lsof so they can be "
                "identified), then retry — or re-run with --force to switch anyway "
                "(any attached client WILL lose its connection)."
            )
        if verdict is not None:
            print(f"⚠ --force: switching anyway — {verdict}", file=sys.stderr)
        switching = _lifecycle_transition("switching", target, _lifecycle_read(), port)
        print(f"Switching {live.upper()} → {target.upper()} (stopping the browser)…")
        if not _shutdown_browser(port, switching):
            survivors = ", ".join(str(p) for p in _find_root_pids(port)) or "unknown"
            return _fail(
                f"Switch aborted: the browser did NOT stop (pid(s) {survivors} "
                "still alive). The lifecycle record is left in state 'switching' "
                "— see `browser.py status`."
            )
        rc = _launch_and_record(port, target == "headless")
        if rc != 0:
            return rc
    finally:
        _gate_release(gate)
    print(f"✓ Switched to {target.upper()}.")
    return 0


def _print_lifecycle(port: int) -> None:
    """Print the lifecycle record summary plus every invariant violation."""
    rec = _lifecycle_read()
    if rec is None:
        print("Lifecycle: no record (cleanly down, or never started by browser.py)")
    else:
        pid = rec.get("pid")
        print(
            f"Lifecycle: {rec.get('state', '?')} / {rec.get('mode', '?')} / "
            f"pid {pid if pid is not None else '-'} (since {rec.get('iso', '?')})"
        )
    for problem in _lifecycle_problems(port):
        print(f"  ⚠ {problem}")


def cmd_status(port: int) -> int:
    """Print CDP health, browser version, open tabs, and the lifecycle state."""
    ver = _cdp_get(port, "/json/version")
    if ver is None:
        print(
            f"✗ Shared browser is DOWN (no CDP on http://localhost:{port}). Run: browser.py up"
        )
        _print_lifecycle(port)
        return 1
    assert isinstance(ver, dict)
    mode = _browser_mode(port) or "?"
    print(f"✓ Up — {ver.get('Browser')} ({mode}) | CDP http://localhost:{port}")
    tabs = _cdp_get(port, "/json/list")
    tab_list = tabs if isinstance(tabs, list) else []
    pages = [t for t in tab_list if isinstance(t, dict) and t.get("type") == "page"]
    print(f"  {len(pages)} tab(s):")
    for t in pages:
        print(f"   - {t.get('title') or '(untitled)'}  →  {t.get('url')}")
    _print_lifecycle(port)
    return 0


def cmd_clients(port: int) -> int:
    """Show who is attached over CDP: the registered clients and the unknown ones.

    Purely diagnostic — it reports, it never judges, so it always exits 0;
    turning an unknown client into a refusal is `switch`'s job. Listing the
    registrations also REAPS the files of clients that died holding one, so
    running this is the cheapest way to clean up after a crash.
    """
    live = _registry_live_clients()
    if live:
        print(f"{len(live)} registered CDP client(s):")
        for rec in live:
            print(f"  - {_describe_client(rec)}")
    else:
        print("No registered CDP clients.")
    unknown = _unknown_cdp_clients(port)
    if unknown is None:
        print(
            "Unregistered clients: CANNOT VERIFY (no lsof on PATH) — "
            "`switch` fails closed in this state; --force overrides."
        )
    elif unknown:
        print(f"{len(unknown)} UNREGISTERED client(s) on port {port}:")
        for pid, cmd in unknown:
            print(f"  - pid {pid}: {cmd}")
    else:
        print(f"No unregistered clients on port {port}.")
    return 0


def cmd_register_exec(port: int, tool: str, cmd: list[str]) -> int:
    """Run CMD as a registered CDP client; exit with CMD's exit code.

    For long-lived clients this script cannot instrument from the inside —
    above all the Playwright MCP server, which otherwise shows up as an
    UNKNOWN client and fails every `switch` closed. The wrapper registers the
    CHILD's pid (the socket may even belong to a grandchild — npx → node —
    which the ancestry walk in `_unknown_cdp_clients` resolves), stays alive
    as its parent with stdio inherited (transparent for MCP's stdio protocol),
    forwards SIGTERM/SIGINT, and releases the registration when CMD exits.
    """
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]  # argparse.REMAINDER keeps the separator; drop it
    if not cmd:
        return _fail("register-exec: no command given (usage: … -t NAME -- CMD ARGS…)")
    # Register FIRST (fails loud while a switch holds the gate), THEN spawn:
    # a child must never run unregistered. The record carries the WRAPPER's
    # pid; the child's/grandchild's sockets resolve to it via the ancestry
    # walk in _unknown_cdp_clients.
    release = _registry_register(tool, " ".join(cmd)[:160], port)
    try:
        proc = subprocess.Popen(cmd)
    except OSError as exc:
        release()
        return _fail(f"register-exec: cannot start {cmd[0]!r}: {exc}")

    def _forward(signum: int, _frame: object) -> None:
        with contextlib.suppress(OSError):
            proc.send_signal(signum)

    signal.signal(signal.SIGTERM, _forward)
    signal.signal(signal.SIGINT, _forward)
    try:
        rc = proc.wait()
    finally:
        release()
    return rc


def cmd_down(port: int) -> int:
    """Quit the shared browser: record the stop, escalate as needed, verify.

    A ``stopping`` record goes down FIRST, so a concurrent observer that finds
    zero browser processes can tell an intentional shutdown from a crash. The
    record is cleared only once no root process is left; otherwise it stays as
    the breadcrumb for `status` and this command reports failure instead of the
    old unconditional "✓ stopped".

    Like `switch` this waits (exclusively, on the client gate) for every
    registered CDP client to drain — but unknown clients only earn a WARNING
    here: a human asking for the browser to stop must not be blocked by
    something they can see in the message. Fail-closed is for the AUTOMATIC
    decision (`switch`), not for an explicit human one.
    """
    rec = _lifecycle_read()
    if rec is None and not _find_root_pids(port) and not _is_up(port):
        PID_FILE.unlink(missing_ok=True)
        print("Stopped (or was not running).")
        return 0
    rec_mode = rec.get("mode") if rec else None
    mode = (
        _browser_mode(port)
        or (rec_mode if isinstance(rec_mode, str) else None)
        or "headed"
    )
    gate = _gate_acquire(fcntl.LOCK_EX, REGISTRY_EX_WAIT_S)
    if gate is None:
        return _fail(_gate_busy("stop the shared browser"))
    try:
        verdict = _unknown_clients_verdict(port)
        if verdict is not None:
            print(f"⚠ stopping anyway — {verdict}", file=sys.stderr)
        stopping = _lifecycle_transition("stopping", mode, rec, port)
        if not _shutdown_browser(port, stopping):
            survivors = ", ".join(str(p) for p in _find_root_pids(port)) or "unknown"
            return _fail(
                f"Shared browser did NOT stop — root process(es) {survivors} still "
                "alive. The lifecycle record is left in state 'stopping'; retry "
                "`browser.py down`, or inspect with `browser.py status`."
            )
        _lifecycle_clear()
        PID_FILE.unlink(missing_ok=True)  # legacy, kept for external observers
    finally:
        _gate_release(gate)
    print("✓ Shared browser stopped.")
    return 0


def _connect(port: int, purpose: str = ""):
    """Connect Playwright to the shared browser over CDP. Returns (pw, browser).

    Registers this process in the client registry FIRST (see
    `_registry_register`): the shared gate lock that registration holds is what
    makes `switch`/`down` wait for us instead of yanking the browser away
    mid-action. `purpose` defaults to the running subcommand (`_purpose`, set
    once in main) so no call site has to pass anything.

    The registration is dropped by an ``atexit`` handler rather than by the ~20
    callers: each already closes the browser in a ``finally`` and then returns
    straight into process exit, so releasing at exit is precise enough for the
    gate and leaves every call site untouched. NEVER call this from a path that
    already holds the gate exclusively — see the deadlock rule above.
    """
    from playwright.sync_api import sync_playwright

    if not _is_up(port):
        sys.exit("Shared browser is down. Run: browser.py up")
    atexit.register(_registry_register("browser.py", purpose or _purpose(), port))
    pw = sync_playwright().start()
    # 127.0.0.1, not localhost — see _cdp_get (avoids the IPv6 ::1 stall).
    browser = pw.chromium.connect_over_cdp(f"http://127.0.0.1:{port}")
    return pw, browser


def _is_blank(url: str) -> bool:
    """True for an empty/new-tab/blank page that's safe to reuse."""
    return not url or url == "about:blank" or url.startswith("chrome://")


def _open_background_tab(port: int, browser, url: str) -> dict:
    """Open URL in a NEW tab WITHOUT focusing it; return {url, title}.

    Playwright's ``ctx.new_page()`` sends CDP ``Target.createTarget`` with
    ``background: false``, which activates the tab and raises the Chrome
    window on macOS — stealing OS focus from whatever the user is doing.
    ``background: true`` avoids that, but Playwright never adopts targets
    created externally mid-session (they only appear on the next connect),
    so the tab is created and observed purely over CDP: creation through a
    browser-level CDP session, load progress through the ``/json`` HTTP
    target list.
    """
    session = browser.new_browser_cdp_session()
    created = session.send("Target.createTarget", {"url": url, "background": True})
    tid = created["targetId"]
    info: dict = {}
    deadline = time.time() + 15
    while time.time() < deadline:
        targets = _cdp_get(port, "/json")
        for t in targets if isinstance(targets, list) else []:
            if t.get("id") == tid:
                info = t
                break
        if info.get("url") not in (None, "", "about:blank"):
            break
        time.sleep(0.25)
    return {"url": info.get("url", url), "title": info.get("title", "")}


def _pick_page(browser, url_substr: str | None):
    """Return a page (optionally matching url_substr), creating one if needed."""
    ctx = browser.contexts[0] if browser.contexts else browser.new_context()
    pages = list(ctx.pages)
    if url_substr:
        for pg in pages:
            if url_substr in pg.url:
                return ctx, pg
    # Default: prefer a real content tab over an empty new-tab/chrome:// page.
    content = [pg for pg in pages if not _is_blank(pg.url)]
    if content:
        return ctx, content[-1]
    if pages:
        return ctx, pages[-1]
    # Zero pages only happens right after launch, when Chrome is already
    # frontmost anyway — the focusing new_page() is fine here.
    return ctx, ctx.new_page()


def _strip_query(url: str) -> str:
    """URL without query/fragment or trailing slash — for tab-reuse matching."""
    return url.split("#", 1)[0].split("?", 1)[0].rstrip("/")


def cmd_open(port: int, url: str, reuse: bool = False) -> int:
    """Open/navigate a tab to URL."""
    pw, browser = _connect(port)
    try:
        ctx = browser.contexts[0] if browser.contexts else browser.new_context()
        if reuse:
            base = _strip_query(url)
            same = [pg for pg in ctx.pages if _strip_query(pg.url) == base]
            if same:  # oldest match = the tab `eval --url` would pick
                page = same[0]
                page.goto(url, wait_until="domcontentloaded")
                print(f"✓ Reused tab: {page.url}  (title: {page.title()!r})")
                return 0
        blank = [pg for pg in ctx.pages if _is_blank(pg.url)]
        if blank:  # reuse a blank tab in place — navigation does not focus it
            page = blank[0]
            page.goto(url, wait_until="domcontentloaded")
            print(f"✓ Opened: {page.url}  (title: {page.title()!r})")
        else:  # new tab, created in the background so Chrome stays unfocused
            info = _open_background_tab(port, browser, url)
            print(f"✓ Opened: {info['url']}  (title: {info['title']!r})")
        return 0
    finally:
        browser.close()  # detaches CDP; the real browser keeps running
        pw.stop()


def cmd_eval(port: int, js: str, url_substr: str | None) -> int:
    """Eval a JS expression in a tab and print the JSON result."""
    pw, browser = _connect(port)
    try:
        _ctx, page = _pick_page(browser, url_substr)
        result = page.evaluate(f"() => ({js})")
        print(json.dumps(result, indent=2, default=str))
        return 0
    finally:
        browser.close()
        pw.stop()


# ---------------------------------------------------------------------------
# doctor — certify a RUNNING browser without touching a single real tab
# ---------------------------------------------------------------------------
# `status` answers "does the browser reply?"; `doctor` answers "can it actually
# be DRIVEN?" — and proves it the only way that is safe on a shared, logged-in
# browser: on a disposable `data:` page of its own, under the interaction lease
# (so no other driver is clicking meanwhile), with every step bounded by a
# timeout or a JS sentinel. The frontmost app and the window z-order are
# snapshotted before and after, because the whole point of the background launch
# is that driving the browser NEVER steals focus: a probe that raised the window
# is a regression to report, not a detail to shrug at.

DOCTOR_MARKS = {"ok": "✅", "warn": "⚠", "fail": "❌"}
# The probe page: a title to recognise it by, and one button whose handler sets
# a sentinel — so a click is VERIFIED from the page instead of inferred from the
# absence of an exception.
DOCTOR_PROBE_URL = (
    "data:text/html,<title>doctor-probe</title>"
    '<button id="b" onclick="window.__clicked=1">go</button>'
)
# Chrome percent-encodes the quotes and spaces of that URL once it is loaded, so
# a probe tab is recognised by this prefix plus the title word, never by the
# full string — and that pair matches nothing but our own throwaway pages.
DOCTOR_PROBE_PREFIX = "data:text/html"
# Rendering liveness: 2 nested requestAnimationFrame callbacks (Playwright's own
# "element is stable" criterion) RACED against a 5 s setTimeout sentinel. The
# race is what bounds the evaluate — an occluded window whose rendering macOS
# paused never fires a frame, and without the sentinel the evaluate would hang
# forever instead of reporting the freeze.
DOCTOR_RAF_JS = """() => {
  const t0 = performance.now();
  const frames = new Promise((res) =>
    requestAnimationFrame(() => requestAnimationFrame(() => res(true))));
  const sentinel = new Promise((res) => setTimeout(() => res(false), 5000));
  return Promise.race([frames, sentinel]).then(
    (alive) => ({ alive, delta: performance.now() - t0 }));
}"""
# How a Chrome-for-Testing window identifies itself as an app/window owner
# (matched case-insensitively): "Google Chrome for Testing".
CHROME_OWNER_MARK = "chrome for testing"
# One-line AppleScript for `osascript -e`: the name of the active application.
FRONTMOST_OSASCRIPT = (
    'tell application "System Events" to get name of first process '
    "whose frontmost is true"
)


def _doctor_add(log: list[str], level: str, check: str, detail: str) -> None:
    """Print one ``✅/⚠/❌ <check>: <detail>`` line; record its level in `log`.

    The log is nothing but the list of levels — the verdict counts them — and
    printing as we go keeps a probe that takes seconds readable in real time.
    """
    print(f"{DOCTOR_MARKS[level]} {check}: {detail}")
    log.append(level)


def _exc_line(exc: BaseException) -> str:
    """The first, clipped line of an exception message — enough to diagnose."""
    lines = str(exc).strip().splitlines()
    return lines[0][:160] if lines else type(exc).__name__


def _is_probe_url(url: str) -> bool:
    """True only for one of doctor's own disposable probe pages.

    Deliberately narrow: a bare ``data:text/html`` test would also match a page
    somebody else opened, and doctor closes what this matches.
    """
    return url.startswith(DOCTOR_PROBE_PREFIX) and "doctor-probe" in url


def _frontmost_app() -> str | None:
    """The name of the frontmost macOS application, or None if unreadable.

    Read through System Events, which needs Automation permission for the
    calling terminal; a refusal (or any other osascript failure) is reported as
    a SKIPPED check, never as a violation — not knowing is not a regression.
    """
    try:
        res = subprocess.run(
            ["osascript", "-e", FRONTMOST_OSASCRIPT],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return res.stdout.strip() or None


def _quartz_module() -> Any:
    """The ``Quartz`` module if it is importable right now, else None."""
    try:
        import Quartz

        return Quartz
    except ImportError:
        return None


def _import_quartz() -> Any:
    """Quartz, self-healing ONE pyobjc install if missing; None if unavailable.

    pyobjc is NOT one of this script's dependencies (`ensure_deps`) — the window
    z-order check is the only thing that wants it — so it is installed on first
    need, into the same isolated venv and the same way a dep added after that
    venv was created is. If the install (no uv, no network) or the re-import
    fails, the caller degrades to a frontmost-only comparison.
    """
    quartz = _quartz_module()
    if quartz is not None:
        return quartz
    venv_python = CACHE_DIR / "venv" / "bin" / "python3"
    print(
        "doctor: installing pyobjc-framework-Quartz (window z-order check)…",
        file=sys.stderr,
    )
    try:
        subprocess.run(
            [
                "uv",
                "pip",
                "install",
                "--python",
                str(venv_python),
                "pyobjc-framework-Quartz",
            ],
            check=True,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return _quartz_module()


def _window_owners() -> list[str] | None:
    """Owner app of every ordinary on-screen window, FRONT to BACK; None if unknown.

    ``CGWindowListCopyWindowInfo`` lists windows in z-order, frontmost first.
    Only layer 0 — the normal window layer — is kept: menu bars, the Dock,
    tooltips and other overlays appear and vanish on their own and would make
    the before/after comparison noisy without saying anything about who raised
    whose window.
    """
    quartz = _import_quartz()
    if quartz is None:
        return None
    owners: list[str] = []
    try:
        infos = quartz.CGWindowListCopyWindowInfo(
            quartz.kCGWindowListOptionOnScreenOnly
            | quartz.kCGWindowListExcludeDesktopElements,
            quartz.kCGNullWindowID,
        )
        for info in infos or []:
            if int(info.get("kCGWindowLayer") or 0) != 0:
                continue
            owners.append(str(info.get("kCGWindowOwnerName") or "?"))
    except (AttributeError, OSError, TypeError, ValueError):
        return None
    return owners


def _window_snapshot() -> dict | None:
    """The desktop right now: ``{"frontmost", "owners"}``; None when not on macOS.

    Either field is None when that particular reading is unavailable (no
    Automation permission, no pyobjc), which the caller reports as a skipped
    check and then leaves out of the comparison.
    """
    if sys.platform != "darwin":
        return None
    return {"frontmost": _frontmost_app(), "owners": _window_owners()}


def _chrome_z_index(owners: list[str]) -> int:
    """Front-most z-order index of a Chrome-for-Testing window in `owners`.

    ``len(owners)`` — behind everything listed — when the shared browser has no
    on-screen window at all, so "its window appeared" compares as a move UP
    exactly like "its window was raised" does.
    """
    for i, name in enumerate(owners):
        if CHROME_OWNER_MARK in name.lower():
            return i
    return len(owners)


def _windows_verdict(before: dict, after: dict) -> tuple[str, str]:
    """Compare two `_window_snapshot`s: ``(level, message)`` for one check line.

    The invariant being certified is that DRIVING the browser never raises it: a
    tab-level ``bring_to_front``, a click and a screenshot must leave the
    desktop as they found it. Exactly two differences are real failures — the
    browser became frontmost, or it climbed the z-order — because only the
    browser can cause those. Every other difference is somebody using their Mac
    while doctor ran, which is reported as a warning to rerun on a quiet desktop
    rather than as a false accusation. Unknown readings are not compared at all.
    """
    fbefore, fafter = before.get("frontmost"), after.get("frontmost")
    obefore, oafter = before.get("owners"), after.get("owners")
    front_known = isinstance(fbefore, str) and isinstance(fafter, str)
    owners_known = isinstance(obefore, list) and isinstance(oafter, list)
    front_changed = front_known and fbefore != fafter
    owners_changed = owners_known and obefore != oafter
    if front_changed and CHROME_OWNER_MARK in str(fafter).lower():
        return "fail", (
            f"the browser RAISED ITSELF to the front ({fbefore!r} → {fafter!r}) "
            "— driving it must never steal focus"
        )
    if owners_known:
        zbefore = _chrome_z_index(list(obefore or []))
        zafter = _chrome_z_index(list(oafter or []))
        if zafter < zbefore:
            return "fail", (
                f"the browser moved UP the window z-order (index {zbefore} → "
                f"{zafter}) — something raised its window"
            )
    if front_changed or owners_changed:
        return "warn", (
            "window order changed by user activity (not the browser) — rerun "
            "doctor on a quiet desktop to confirm"
        )
    compared = (
        " + ".join(
            name
            for name, known in (
                ("frontmost app", front_known),
                ("z-order", owners_known),
            )
            if known
        )
        or "nothing — both readings unavailable"
    )
    return "ok", f"unchanged by the probe ({compared})"


def _doctor_lifecycle(log: list[str], port: int) -> bool:
    """Validate the lifecycle record against reality; True if a browser is up.

    Every entry `_lifecycle_problems` reports is an INVARIANT violation (two
    roots on one profile, a record that disagrees with the live browser, crash
    debris), so each becomes a ❌ here — where `status`, a pure report, only
    lists them.
    """
    problems = _lifecycle_problems(port)
    for problem in problems:
        _doctor_add(log, "fail", "lifecycle", problem)
    if not problems:
        rec = _lifecycle_read()
        if rec is None:
            _doctor_add(
                log, "ok", "lifecycle", "no record — nothing is recorded as running"
            )
        else:
            _doctor_add(
                log,
                "ok",
                "lifecycle",
                f"record agrees with the live browser: {rec.get('state')}/"
                f"{rec.get('mode')}, pid {rec.get('pid')} (since {rec.get('iso')})",
            )
    return _is_up(port)


def _doctor_coordination(log: list[str], port: int) -> None:
    """Report who else is attached over CDP — informational, never a failure.

    Turning an unregistered client into a refusal is `switch`'s job: it has to
    fail closed BEFORE it kills a browser somebody else is driving. Doctor only
    certifies, so an unknown (or unverifiable) client is a ⚠ that leaves the
    exit code alone. Listing the registrations also reaps dead ones.
    """
    live = _registry_live_clients()
    if live:
        listing = "; ".join(_describe_client(rec) for rec in live)
        _doctor_add(log, "ok", "registered clients", f"{len(live)} attached: {listing}")
    else:
        _doctor_add(log, "ok", "registered clients", "none attached")
    unknown = _unknown_cdp_clients(port)
    if unknown is None:
        _doctor_add(
            log,
            "warn",
            "unregistered clients",
            "cannot verify (no lsof on PATH) — `switch` fails closed in this state",
        )
    elif unknown:
        listing = "; ".join(f"pid {pid}: {cmd[:60]}" for pid, cmd in unknown)
        _doctor_add(
            log,
            "warn",
            "unregistered clients",
            f"{len(unknown)} nobody registered ({listing}) — `switch` would refuse",
        )
    else:
        _doctor_add(log, "ok", "unregistered clients", f"none on port {port}")


def _doctor_windows_before(log: list[str]) -> dict | None:
    """Snapshot the desktop BEFORE the probe; None when there is nothing to compare."""
    before = _window_snapshot()
    if before is None:
        _doctor_add(log, "warn", "window checks", "skipped (not macOS)")
        return None
    if before.get("frontmost") is None:
        _doctor_add(
            log,
            "warn",
            "frontmost check",
            "skipped (osascript could not name the frontmost app — Automation "
            "permission?)",
        )
    if before.get("owners") is None:
        _doctor_add(
            log,
            "warn",
            "z-order check",
            "skipped (pyobjc-framework-Quartz unavailable)",
        )
    if before.get("frontmost") is None and before.get("owners") is None:
        return None
    owners = before.get("owners")
    _doctor_add(
        log,
        "ok",
        "window snapshot",
        f"frontmost {before.get('frontmost')!r}, "
        + (
            f"{len(owners)} on-screen window(s)"
            if owners is not None
            else "z-order unknown"
        ),
    )
    return before


def _doctor_windows_after(log: list[str], before: dict) -> None:
    """Re-snapshot the desktop and judge whether the probe disturbed it."""
    after = _window_snapshot()
    if after is None:
        _doctor_add(
            log, "warn", "window order", "could not re-read the desktop after the probe"
        )
        return
    level, message = _windows_verdict(before, after)
    _doctor_add(log, level, "window order", message)


def _doctor_raf(log: list[str], page, *, escalated: bool) -> bool:
    """rAF liveness: does the (usually occluded) window still paint frames?

    The check that would have caught the 2026-08-19 regression, where macOS
    paused rendering for the occluded background window and EVERY driver's
    clicks timed out on Playwright's "element is stable" wait — 2 consecutive
    animation frames, exactly what is measured here. Returns True when alive.
    With ``escalated=False`` a frozen result is only a ⚠ — the caller retries
    after ``bring_to_front``; the second attempt (``escalated=True``) is the
    real verdict. (The 5 s setTimeout sentinel that bounds the evaluate relies
    on ``--disable-background-timer-throttling``, which ``up`` always sets.)
    """
    from playwright.sync_api import Error as PlaywrightError

    label = "rendering (rAF, after bring_to_front)" if escalated else "rendering (rAF)"
    try:
        result = page.evaluate(DOCTOR_RAF_JS)
    except PlaywrightError as exc:
        _doctor_add(log, "fail", label, f"evaluate failed: {_exc_line(exc)}")
        return False
    if not isinstance(result, dict):
        _doctor_add(log, "fail", label, f"unexpected probe result {result!r}")
        return False
    delta = result.get("delta")
    took = f"{float(delta):.0f} ms" if isinstance(delta, int | float) else "? ms"
    if result.get("alive"):
        _doctor_add(
            log,
            "ok",
            label,
            f"2 animation frames in {took} — the window paints while occluded",
        )
        return True
    if not escalated:
        _doctor_add(
            log,
            "warn",
            label,
            f"no animation frame within 5000 ms ({took}) — rendering is frozen; "
            "escalating to tab-level bring_to_front (the consumer fallback)",
        )
        return False
    _doctor_add(
        log,
        "fail",
        label,
        f"no animation frame within 5000 ms ({took}) even after bring_to_front "
        "— rendering is frozen, so every click will time out",
    )
    return False


def _doctor_click(log: list[str], page) -> None:
    """A REAL click on the probe button — normal actionability, never forced.

    ``force=True`` would skip precisely the hit-testing and stability waits that
    a frozen or occluded window breaks, i.e. it would make this check pass while
    every consumer's click still failed. The button's handler sets
    ``window.__clicked``, so success is read back from the page.
    """
    from playwright.sync_api import Error as PlaywrightError

    try:
        page.click("#b", timeout=8000)
        clicked = page.evaluate("() => window.__clicked === 1")
    except PlaywrightError as exc:
        _doctor_add(log, "fail", "click", f"page.click('#b') failed: {_exc_line(exc)}")
        return
    if clicked:
        _doctor_add(
            log, "ok", "click", "the button was clicked and its handler ran (no force)"
        )
    else:
        _doctor_add(
            log, "fail", "click", "click() returned but the handler set no sentinel"
        )


def _doctor_screenshot(log: list[str], page) -> None:
    """A bounded screenshot, kept in memory — the capture path consumers rely on."""
    from playwright.sync_api import Error as PlaywrightError

    try:
        shot = page.screenshot(timeout=10000)
    except PlaywrightError as exc:
        _doctor_add(
            log, "fail", "screenshot", f"page.screenshot() failed: {_exc_line(exc)}"
        )
        return
    if len(shot) < 1000:
        _doctor_add(
            log,
            "warn",
            "screenshot",
            f"only {len(shot)} bytes — suspiciously small for a real capture",
        )
    else:
        _doctor_add(
            log,
            "ok",
            "screenshot",
            f"{len(shot)} bytes captured in memory (no file written)",
        )


def _doctor_drivability(log: list[str], page) -> None:
    """The bounded drivability checks on the probe page, in consumer order.

    ``bring_to_front`` is an ESCALATION, not a default: on Chrome for Testing
    151 ``Page.bringToFront`` can raise the window and even steal macOS focus
    (measured 2026-08-20, reproducible), so the probe only reaches for it when
    rendering is actually frozen — exactly the situation in which a consumer
    would need it — and flags the escalation so the window checks that follow
    are read in that light.
    """
    from playwright.sync_api import Error as PlaywrightError

    if _doctor_raf(log, page, escalated=False):
        _doctor_add(
            log,
            "ok",
            "bring_to_front",
            "not needed — rendering is alive without it (and on CfT 151 it can "
            "raise the window / steal focus)",
        )
    else:
        try:
            page.bring_to_front()
            _doctor_add(
                log,
                "warn",
                "bring_to_front",
                "escalated: rendering was frozen without it — NOTE: on CfT 151 "
                "this can raise the window / steal focus",
            )
        except PlaywrightError as exc:
            _doctor_add(
                log,
                "fail",
                "bring_to_front",
                f"bring_to_front() failed: {_exc_line(exc)}",
            )
        _doctor_raf(log, page, escalated=True)
    _doctor_click(log, page)
    _doctor_screenshot(log, page)


def _doctor_open_probe(log: list[str], port: int) -> bool:
    """Create the disposable probe tab in the BACKGROUND; True if it loaded.

    Created over CDP with ``background: true`` (see `_open_background_tab`) so
    it cannot raise the window, and this connection is then dropped again:
    Playwright only adopts targets that already existed when it attached, so the
    page object has to come from a FRESH connection.
    """
    pw, browser = _connect(port)
    try:
        info = _open_background_tab(port, browser, DOCTOR_PROBE_URL)
    finally:
        browser.close()
        pw.stop()
    url = str(info.get("url") or "")
    if not _is_probe_url(url):
        _doctor_add(
            log,
            "fail",
            "probe setup",
            f"the background probe tab never loaded (target url {url!r})",
        )
        return False
    _doctor_add(
        log,
        "ok",
        "probe page",
        f"disposable data: tab created in the background (title {info.get('title')!r})",
    )
    return True


def _close_probe_targets(port: int, browser) -> int:
    """Close every leftover probe target over CDP; return how many were closed.

    The fallback for the one case ``page.close()`` cannot cover: a probe tab
    Playwright never adopted. Scoped by `_is_probe_url`, so it can only ever
    close doctor's own throwaway pages.
    """
    session = browser.new_browser_cdp_session()
    targets = _cdp_get(port, "/json")
    closed = 0
    for t in targets if isinstance(targets, list) else []:
        tid = t.get("id") if isinstance(t, dict) else None
        if tid and _is_probe_url(str(t.get("url") or "")):
            session.send("Target.closeTarget", {"targetId": tid})
            closed += 1
    return closed


def _doctor_probe(log: list[str], port: int) -> None:
    """Drive a disposable probe page and report every drivability check.

    Nothing here touches a real tab: the page is created by
    `_doctor_open_probe`, driven, and closed again in a ``finally`` — including
    the path where Playwright cannot see it, which is cleaned up over CDP. A
    failed check therefore costs a throwaway tab at worst, never a login.
    """
    from playwright.sync_api import Error as PlaywrightError

    if not _doctor_open_probe(log, port):
        return
    pw, browser = _connect(port)
    page = None
    try:
        pages = [pg for ctx in browser.contexts for pg in ctx.pages]
        for candidate in pages:
            if _is_probe_url(candidate.url):
                page = candidate
                break
        if page is None:
            _doctor_add(
                log,
                "fail",
                "probe setup",
                f"the probe tab is invisible to Playwright after reconnecting "
                f"({len(pages)} tab(s) seen)",
            )
            return
        _doctor_drivability(log, page)
    finally:
        if page is not None:
            with contextlib.suppress(PlaywrightError):
                page.close()
        else:
            with contextlib.suppress(PlaywrightError):
                _close_probe_targets(port, browser)
        browser.close()
        pw.stop()


def cmd_doctor(port: int) -> int:
    """Certify a RUNNING shared browser end to end; 0 only if nothing FAILED.

    The order is deliberate: the lifecycle record is validated against the live
    process first (a browser that disagrees with its own record is not worth
    probing, and a cleanly DOWN one is not certifiable at all — doctor's job is
    certifying a running browser, so that exits 1), then who else is attached,
    then the desktop snapshot, then the probe itself.

    LOCKS: a client registration is held for the WHOLE probe before the
    interaction lease is taken — the documented gate-then-lease order — which
    also keeps a `switch`/`down` from stealing the browser between the probe's
    two CDP connections. ⚠ lines never change the exit code: "somebody else is
    attached" and "you moved a window mid-probe" are facts to report, not
    verdicts to fail on.
    """
    log: list[str] = []
    if not _doctor_lifecycle(log, port):
        _doctor_add(log, "fail", "doctor", "browser is down — nothing to probe")
        return 1
    _doctor_coordination(log, port)
    before = _doctor_windows_before(log)
    release = _registry_register("browser.py", _purpose(), port)
    try:
        with _interaction_lease("doctor") as owner:
            _doctor_add(
                log,
                "ok",
                "interaction lease",
                "inherited from the parent (CLAUDE_BROWSER_LEASE_HELD=1)"
                if owner == "inherited"
                else f"held exclusively for the probe (owner {owner[:8]})",
            )
            _doctor_probe(log, port)
            if before is not None:
                _doctor_windows_after(log, before)
    finally:
        release()
    failed = log.count("fail")
    if failed:
        print(f"❌ doctor: {failed} check(s) failed")
        return 1
    print(f"✅ doctor: all checks passed ({log.count('ok')} ✅, {log.count('warn')} ⚠)")
    return 0


def _scan_token(ctx, page) -> str | None:
    """Find the 40-hex Waldur DRF token in the portal tab's storage, or None.

    Scans ``localStorage`` (where Waldur HomePort keeps it) first, then cookies
    (incl. httpOnly ones invisible to ``document.cookie``). Returns ``None``
    rather than raising if the page navigates mid-scan — the SPA periodically
    re-renders/redirects, destroying the JS execution context — so the caller can
    just retry.
    """
    from playwright.sync_api import Error as PlaywrightError

    try:
        token = page.evaluate(
            "() => { const re=/\\b[0-9a-f]{40}\\b/;"
            "for (let i=0;i<localStorage.length;i++){const v=localStorage.getItem(localStorage.key(i));"
            "const m=v&&v.match(re); if(m) return m[0];} return null; }"
        )
        if token:
            return str(token)
        for ck in ctx.cookies():
            m = HEX40.search(str(ck.get("value", "")))
            if m:
                return m.group(0)
    except PlaywrightError:
        return None
    return None


def _capture_and_cache_token(ctx, page) -> int:
    """Capture the DRF token from a portal ``page`` and cache it.

    Shared by ``cmd_token`` and ``cmd_cscs_login`` so a login flow can grab the
    token from its existing connection instead of reconnecting over CDP (each
    ``connect_over_cdp`` re-attaches to every open tab and costs seconds).

    Resilient to the Waldur SPA navigating/repopulating: scans a few times with
    short waits, then falls back to an explicit reload of the portal profile to
    force a settled state before giving up.
    """
    import requests
    from playwright.sync_api import Error as PlaywrightError

    token = None
    for _ in range(4):  # SPA may be mid-navigation / still populating storage
        token = _scan_token(ctx, page)
        if token:
            break
        page.wait_for_timeout(800)
    if not token:  # deterministic fallback: reload to a known-settled state
        try:
            page.goto(PORTAL_PROFILE_URL, wait_until="domcontentloaded")
            page.wait_for_timeout(1500)
        except PlaywrightError:
            pass
        token = _scan_token(ctx, page)
    if not token:
        return _fail(
            "Logged in, but no 40-hex token found in storage. The portal may have "
            "changed where it stores the token — open DevTools → Network → an /api/ "
            "request → Authorization header to find it."
        )
    CSCS_TOKEN_CACHE.parent.mkdir(parents=True, exist_ok=True)
    CSCS_TOKEN_CACHE.write_text(token)
    CSCS_TOKEN_CACHE.chmod(0o600)
    print(f"✓ Token cached at {CSCS_TOKEN_CACHE} (mode 0600).")
    resp = requests.get(
        PORTAL_API_ME, headers={"Authorization": f"Token {token}"}, timeout=15
    )
    if resp.status_code == 200:
        data = resp.json()
        print(f"✓ Authenticated as: {data.get('username')} ({data.get('email')})")
        return 0
    return _fail(
        f"Portal rejected the cached token ({resp.status_code}): {resp.text[:200]}"
    )


def _pick_portal_page(browser):
    """Return ``(ctx, page)`` preferring a settled, logged-in portal app tab.

    Skips the transient OAuth-callback tabs that a naive ``portal.cscs.ch``
    substring match would grab (they redirect away mid-evaluate — see
    ``_on_portal``). Falls back to a ``cscs.ch`` tab (e.g. Keycloak) or any
    reusable tab when no settled app tab exists; the caller then navigates it.
    """
    ctx = browser.contexts[0] if browser.contexts else browser.new_context()
    for pg in ctx.pages:
        if _on_portal(pg):
            return ctx, pg
    return _pick_page(browser, "cscs.ch")


def _close_stale_cscs_tabs(ctx, keep=None) -> int:
    """Close leftover CSCS OAuth-callback / stale Keycloak tabs; return the count.

    The SSO flow leaves transient ``oauth_login_completed`` and
    ``api-auth/keycloak/complete`` tabs, plus old ``auth.cscs.ch`` login tabs,
    that never close themselves. They pile up and slow EVERY ``connect_over_cdp``
    (which re-attaches to all open tabs) — the usual cause of a sluggish or
    "hanging" login. They are dead redirect stubs, so closing them is safe; the
    live ``keep`` page and all non-CSCS tabs are left untouched.
    """
    from playwright.sync_api import Error as PlaywrightError

    markers = (
        "/oauth_login_completed/",
        "/api-auth/keycloak/complete/",
        "auth.cscs.ch",
    )
    closed = 0
    for pg in list(ctx.pages):
        if pg is keep:
            continue
        try:
            if any(m in pg.url for m in markers):
                pg.close()
                closed += 1
        except PlaywrightError:
            continue
    return closed


def cmd_token(port: int) -> int:
    """Read the 40-hex Waldur token from the portal tab and cache it."""
    pw, browser = _connect(port)
    try:
        ctx, page = _pick_portal_page(browser)
        if not _on_portal(page):
            page.goto(PORTAL_PROFILE_URL, wait_until="domcontentloaded")
            page.wait_for_timeout(1500)
        if "auth.cscs.ch" in page.url:  # portal bounced us to Keycloak → not logged in
            page.bring_to_front()  # surface the login tab in the shared window
            _fail(
                "Not logged in — the portal redirected to Keycloak.\n"
                "Log into CSCS in THIS shared browser window (Chrome for Testing), "
                "then re-run: browser.py token"
            )
            return 2  # distinct code: caller maps this to a 'needs login' hint
        rc = _capture_and_cache_token(ctx, page)
        _close_stale_cscs_tabs(ctx, keep=page)  # clear dead OAuth/login stubs
        return rc
    finally:
        browser.close()
        pw.stop()


def _kc_account() -> str:
    """The keychain 'account' our items are stored under (the login user)."""
    import getpass

    return getpass.getuser()


def _keychain_get(service: str) -> str | None:
    """Read a generic-password item from the login keychain (prompt-free).

    Returns the secret string, or ``None`` if the item is absent. Reading an
    already-unlocked login keychain via the Apple-signed ``security`` binary
    needs NO Touch ID — that is the whole point versus the ``op`` path.
    """
    try:
        r = subprocess.run(
            [
                "security",
                "find-generic-password",
                "-a",
                _kc_account(),
                "-s",
                service,
                "-w",
            ],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if r.returncode != 0:
        return None
    # `-w` prints the secret + a trailing newline; strip only that newline so a
    # password ending in spaces is preserved verbatim.
    value = r.stdout.rstrip("\n")
    return value or None


def _keychain_set(service: str, value: str) -> bool:
    """Create/replace a login-keychain item; return ``True`` on success.

    ``-U`` updates in place if the item exists. ``-T /usr/bin/security`` scopes
    silent (no-prompt) access to the ``security`` binary that our reads use.
    """
    try:
        r = subprocess.run(
            [
                "security",
                "add-generic-password",
                "-a",
                _kc_account(),
                "-s",
                service,
                "-w",
                value,
                "-D",
                "cscs-api credential",
                "-T",
                "/usr/bin/security",
                "-U",
            ],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return r.returncode == 0


def _keychain_delete(service: str) -> bool:
    """Delete a login-keychain item; ``True`` if it was deleted or already gone."""
    try:
        subprocess.run(
            [
                "security",
                "delete-generic-password",
                "-a",
                _kc_account(),
                "-s",
                service,
            ],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return True


def _totp_now(seed_or_uri: str) -> str | None:
    """Current 6-digit TOTP code from a base32 seed or an ``otpauth://`` URI.

    Returns ``None`` if the seed/URI is malformed (bad base32, unparseable URI).
    """
    import binascii

    import pyotp

    s = seed_or_uri.strip()
    try:
        if s.lower().startswith("otpauth://"):
            return str(pyotp.parse_uri(s).now())
        return str(pyotp.TOTP(s.replace(" ", "").upper()).now())
    except (ValueError, binascii.Error):
        return None


def _keychain_creds() -> tuple[str, str, str] | None:
    """Read CSCS user/password/TOTP from the keychain → ``(user, password, otp)``.

    The OTP is generated locally from the stored seed (no live 1Password call).
    Returns ``None`` if any item is missing or the seed can't produce a code, so
    the caller falls back to the Touch-ID ``op`` path.
    """
    user = _keychain_get(KEYCHAIN_SVC_USER)
    password = _keychain_get(KEYCHAIN_SVC_PASS)
    seed = _keychain_get(KEYCHAIN_SVC_TOTP)
    if not (user and password and seed):
        return None
    otp = _totp_now(seed)
    if not otp:
        return None
    return user, password, otp


def _op_totp_uri(item: str, account: str) -> str | None:
    """Read the TOTP ``otpauth://`` URI (the *seed*) for ONE 1Password item.

    Touch-ID-gated like the rest of ``op``. Returns the URI or ``None`` (some
    items expose only a live code, not the seed). Never printed/logged.
    """
    try:
        r = subprocess.run(
            [
                "op",
                "item",
                "get",
                item,
                "--account",
                account,
                "--fields",
                "type=otp",
                "--reveal",
                "--format",
                "json",
            ],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if r.returncode != 0:
        return None
    try:
        data = json.loads(r.stdout)
    except (ValueError, TypeError):
        return None
    fields = data if isinstance(data, list) else [data]
    for f in fields:
        if not isinstance(f, dict):
            continue
        for key in ("totp", "value"):
            v = f.get(key)
            if isinstance(v, str) and v.lower().startswith("otpauth://"):
                return v
    return None


def _op_creds(item: str, account: str) -> tuple[str, str, str] | None:
    """Read username, password and the live TOTP for ONE 1Password item via op.

    Returns ``(username, password, otp)`` or ``None`` on failure. Secrets are
    returned in memory and NEVER printed/logged. Touch-ID-gated when the 1Password
    desktop app's "Integrate with 1Password CLI" is enabled.
    """
    base = ["op", "item", "get", item, "--account", account]
    try:
        creds = subprocess.run(
            [
                *base,
                "--fields",
                "label=username,label=password",
                "--reveal",
                "--format",
                "json",
            ],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        otp_r = subprocess.run(
            [*base, "--otp"], capture_output=True, text=True, timeout=60, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if creds.returncode != 0 or otp_r.returncode != 0:
        return None
    try:
        fields = {f.get("label"): f.get("value") for f in json.loads(creds.stdout)}
    except (ValueError, AttributeError, TypeError):
        return None
    user, password, otp = (
        fields.get("username"),
        fields.get("password"),
        otp_r.stdout.strip(),
    )
    if not (user and password and otp):
        return None
    return user, password, otp


def _click_keycloak_submit(page) -> None:
    """Click the Keycloak login/submit button (tolerant of theme differences)."""
    for sel in (
        "#kc-login",
        "input[name=login]",
        "button[type=submit]",
        "input[type=submit]",
    ):
        el = page.query_selector(sel)
        if el:
            el.click()
            return


def _on_portal(page) -> bool:
    """True only on the settled, logged-in portal *app* (HomePort SPA).

    Excludes the Keycloak login and the transient OAuth-callback landing pages
    (``/api-auth/keycloak/complete/``, ``/oauth_login_completed/``, anything with
    a ``code=`` param) — those redirect away within a beat, so treating them as
    "logged in" and then evaluating JS on them races with the navigation and
    destroys the execution context.
    """
    url = page.url
    if "portal.cscs.ch" not in url or "auth.cscs.ch" in url:
        return False
    return not any(
        marker in url for marker in ("/api-auth/", "/oauth_login_completed/", "code=")
    )


def _cscs_creds(*, announce: bool = True) -> tuple[tuple[str, str, str] | None, str]:
    """Resolve ``(user, password, otp)`` for CSCS plus the source that produced it.

    Keychain first (prompt-free; the 6-digit code is generated locally from the
    stored seed), else the single 1Password item (Touch-ID-gated). Called once
    per login ATTEMPT so a retry gets a FRESH code — a TOTP is valid ~30s and a
    retried attempt lands well past that.
    """
    creds = _keychain_creds()
    if creds is not None:
        if announce:
            print("Using CSCS credentials from the macOS keychain (no Touch ID).")
        return creds, "keychain"
    if announce:
        print(
            "No keychain credentials yet — falling back to 1Password "
            "(approve Touch ID). Run `browser.py cscs-store-creds` once to "
            "make future logins fingerprint-free."
        )
    return _op_creds(CSCS_OP_ITEM, CSCS_OP_ACCOUNT), "1password"


def _keycloak_flow_expired(page) -> bool:
    """True when Keycloak aborted the flow because ITS auth session went stale.

    Symptom (seen 2026-09-03): submitting a Keycloak login page that has been
    sitting open for hours carries a dead ``session_code``, so instead of the
    portal we land on ``/api-auth/keycloak/complete/`` with
    ``error=temporarily_unavailable`` +
    ``error_description=authentication_expired``
    — nothing is wrong with the credentials. A fresh navigation to the portal
    starts a new authorization request and succeeds, so this is worth exactly
    one retry (see ``cmd_cscs_login``).
    """
    # URL check first, so the common case needs no playwright import at all.
    if any(
        marker in page.url
        for marker in ("authentication_expired", "temporarily_unavailable")
    ):
        return True
    from playwright.sync_api import Error as PlaywrightError

    try:
        body = page.inner_text("body", timeout=2000).lower()
    except PlaywrightError:
        return False
    return any(
        phrase in body
        for phrase in (
            "your login attempt timed out",
            "action expired",
            "you took too long to login",
        )
    )


def _submit_keycloak_login(page, creds: tuple[str, str, str]) -> bool:
    """Fill the Keycloak form (+ the OTP step) and wait for the portal to settle.

    Returns ``True`` once ``_on_portal`` holds, ``False`` after ~20s without it
    (the caller decides whether that is a stale flow worth retrying or a real
    credential failure).
    """
    user, password, otp = creds
    page.fill("#username", user)
    page.fill("#password", password)
    _click_keycloak_submit(page)
    # Wait for EITHER the OTP step or a direct landing on the portal.
    otp_filled = False
    for _ in range(40):  # ~20s
        if _on_portal(page):
            return True
        if not otp_filled:
            otp_el = (
                page.query_selector("#otp")
                or page.query_selector("input[name=otp]")
                or page.query_selector("input[autocomplete=one-time-code]")
            )
            if otp_el:
                otp_el.fill(otp)
                _click_keycloak_submit(page)
                otp_filled = True
        page.wait_for_timeout(500)
    return _on_portal(page)


def cmd_cscs_login(port: int) -> int:
    """Log into CSCS in the shared browser using stored credentials, then cache.

    Fills the Keycloak username/password + TOTP from the macOS keychain when set
    up (``cscs-store-creds``, no fingerprint), else from the single ``op`` item
    (Touch-ID-gated; vault never exposed to the browser). Captures the API token
    from the SAME connection (no second ``connect_over_cdp``). Idempotent: if
    already logged in, it skips the login form and just refreshes the token.

    Everything that drives the page happens under the INTERACTION lease, so it
    can never interleave with another tool's clicks (it waits, then fails loud
    naming the holder).
    """
    pw, browser = _connect(port)
    try:
        with _interaction_lease("login cscs"):
            # Prefer a settled portal app tab (already logged in) so we skip a full
            # SPA reload — the slow part of a repeated `cscs-login`. _pick_portal_page
            # ignores transient OAuth-callback tabs; only navigate when there is no
            # settled app tab yet (cold session / Keycloak tab).
            ctx, page = _pick_portal_page(browser)
            if not _on_portal(page):
                # Prune dead OAuth/Keycloak stubs (e.g. an `authentication_expired`
                # callback left over from a failed run) BEFORE navigating: they
                # slow every connect_over_cdp and confuse a later tab pick.
                _close_stale_cscs_tabs(ctx, keep=page)
                page.goto(PORTAL_PROFILE_URL, wait_until="domcontentloaded")
                page.wait_for_timeout(1500)
            if _on_portal(page):
                print("✓ Already logged into CSCS.")
            elif "auth.cscs.ch" not in page.url:
                return _fail(f"Unexpected page (not portal, not Keycloak): {page.url}")
            else:
                cscs_login_mode = "keychain"
                for attempt in (1, 2):
                    creds, cscs_login_mode = _cscs_creds(announce=attempt == 1)
                    if creds is None:
                        return _fail(
                            "No CSCS credentials available. Either run "
                            "`browser.py cscs-store-creds` (keychain, no fingerprint), "
                            f"or make 1Password item '{CSCS_OP_ITEM}' (account "
                            f"{CSCS_OP_ACCOUNT}) readable via op (desktop 'Integrate "
                            "with 1Password CLI' on, Touch ID approved)."
                        )
                    if _submit_keycloak_login(page, creds):
                        break
                    # Only a stale Keycloak auth session earns a retry; a wrong
                    # password must still fail on the first attempt (retrying it
                    # would burn a second try toward the account lockout).
                    if attempt == 2 or not _keycloak_flow_expired(page):
                        return _fail(
                            "Login did not reach the portal — wrong "
                            "username/password/OTP, or an unexpected page "
                            f"({page.url})."
                        )
                    print(
                        "Keycloak aborted the flow (authentication_expired) — "
                        "restarting the login once from a fresh page."
                    )
                    _close_stale_cscs_tabs(ctx, keep=page)
                    page.goto(PORTAL_PROFILE_URL, wait_until="domcontentloaded")
                    page.wait_for_timeout(1500)
                    if _on_portal(page):
                        break  # the fresh authorization request re-used the SSO session
                    if "auth.cscs.ch" not in page.url:
                        return _fail(
                            f"Retry did not reach the Keycloak form ({page.url})."
                        )
                print("✓ Logged into CSCS.")
                _record_login_event("cscs", cscs_login_mode)
            # Capture the token from THIS connection — no second connect_over_cdp
            # (cmd_token would re-attach to every open tab again, costing seconds).
            rc = _capture_and_cache_token(ctx, page)
            _close_stale_cscs_tabs(ctx, keep=page)  # clear dead OAuth/login stubs
            return rc
    finally:
        browser.close()
        pw.stop()


def cmd_cscs_store_creds() -> int:
    """One-time setup: store CSCS user/password/TOTP-seed in the macOS keychain.

    Pulls them from the single 1Password item by default (one last Touch ID),
    prompting interactively for anything ``op`` can't supply — notably the TOTP
    *seed*, which some items expose only as a live code. Validates the seed
    actually generates a code before writing. Afterwards ``cscs-login`` (and
    cscs-api.py auto-login) run fully unattended — no fingerprint.

    SECURITY: storing the password AND the TOTP seed on this machine collapses
    your 2-factor login into 1-factor for the CSCS account — anything that can
    run as you can now log in silently. FileVault + the 0600/ACL'd keychain
    protect the secrets at rest and from other local users, NOT from code
    running as you. This is the inherent cost of fingerprint-free automation.
    """
    import getpass

    print(
        "Setting up fingerprint-free CSCS login.\n"
        "Secrets are stored in your macOS login keychain (encrypted at rest, "
        "read only by the `security` tool, no Touch ID on later reads).\n"
        "⚠ Storing the password + TOTP seed together makes CSCS effectively "
        "single-factor on this machine — see the docstring.\n"
    )

    user: str | None = None
    password: str | None = None
    seed: str | None = None

    if shutil.which("op"):
        print(f"Reading '{CSCS_OP_ITEM}' from 1Password (approve Touch ID)…")
        creds = _op_creds(CSCS_OP_ITEM, CSCS_OP_ACCOUNT)
        if creds is not None:
            user, password, _ = creds
        seed = _op_totp_uri(CSCS_OP_ITEM, CSCS_OP_ACCOUNT)
    else:
        print("`op` not on PATH — entering everything manually.")

    if not user:
        user = input("CSCS username: ").strip()
    if not password:
        password = getpass.getpass("CSCS password: ")
    if not seed:
        print(
            "\nCould not read the TOTP *seed* from 1Password automatically.\n"
            "Paste the TOTP secret — either the base32 seed (the 'manual entry / "
            "setup key' shown when you enrolled CSCS 2FA) or a full otpauth://… URI."
        )
        seed = getpass.getpass("CSCS TOTP secret/URI: ").strip()

    if not (user and password and seed):
        return _fail("Missing username, password or TOTP seed — nothing stored.")

    if _totp_now(seed) is None:
        return _fail(
            "That TOTP secret did not produce a valid code (bad base32 / URI). "
            "Nothing stored — re-run and paste the correct seed."
        )

    if not (
        _keychain_set(KEYCHAIN_SVC_USER, user)
        and _keychain_set(KEYCHAIN_SVC_PASS, password)
        and _keychain_set(KEYCHAIN_SVC_TOTP, seed)
    ):
        return _fail("Failed to write one or more keychain items.")

    print(
        "✓ Stored CSCS username, password and TOTP seed in the macOS keychain.\n"
        "  `browser.py cscs-login` (and cscs-api.py auto-login) now run without "
        "Touch ID.\n  Verify with:  browser.py cscs-login   (or: cscs-api.py --login)\n"
        "  Revoke with:  browser.py cscs-forget-creds"
    )
    return 0


def cmd_cscs_forget_creds() -> int:
    """Delete the CSCS credentials stored in the macOS keychain."""
    for svc in (KEYCHAIN_SVC_USER, KEYCHAIN_SVC_PASS, KEYCHAIN_SVC_TOTP):
        _keychain_delete(svc)
    print(
        "✓ Removed CSCS keychain credentials. `cscs-login` will fall back to "
        "1Password (Touch ID) again."
    )
    return 0


# ---------------------------------------------------------------------------
# claude.ai (Anthropic) — assisted email-code login, no token
# ---------------------------------------------------------------------------


def _claude_billing_sentinel(page) -> bool:
    """True if the current page looks like the logged-in admin BILLING surface.

    A stable DOM/text sentinel (NOT merely "url isn't /login"): the billing page
    renders dollar-amount invoice rows each with a 'View' link. Tolerates the SPA
    still settling by being lenient on either signal. Returns False on any error
    (page mid-navigation), so the caller treats it as "not confirmed yet".
    """
    from playwright.sync_api import Error as PlaywrightError

    try:
        return bool(
            page.evaluate(
                "() => { const t = document.body ? document.body.innerText : '';"
                " const hasView = /\\bView\\b/.test(t);"
                " const hasAmt = /\\$\\s?[0-9][0-9,]*\\.[0-9]{2}/.test(t);"
                " const billingWord = /\\bBilling\\b/.test(t);"
                " return (hasView && hasAmt) || (billingWord && hasAmt); }"
            )
        )
    except PlaywrightError:
        return False


def _claude_logged_in(page) -> bool:
    """ACTIVE check: navigate to the billing admin page and confirm we land there
    logged in (per O3 — reaching the SDSC admin/billing surface, not just "not
    /login"). A redirect to /login or /logout means not logged in; never reaching
    the billing route + sentinel within ~15 s means not confirmed (wrong org /
    no admin rights / SPA never settled).

    POLLED, not a one-shot: the billing SPA renders its invoice rows well after
    domcontentloaded, and the old fixed 2.5 s wait raced that render — a cold
    SPA load intermittently produced FALSE NEGATIVES ("Not logged into Claude"
    while the profile session was fine, observed 2026-08-19 blocking
    anthropic-api.py --team-remove)."""
    from playwright.sync_api import Error as PlaywrightError

    try:
        page.goto(CLAUDE_BILLING_URL, wait_until="domcontentloaded")
    except PlaywrightError:
        return False
    for _ in range(30):  # up to ~15 s
        try:
            page.wait_for_timeout(500)
            url = page.url
        except PlaywrightError:
            return False
        if "/login" in url or "/logout" in url:
            return False  # definitive: bounced to the login surface
        if "/admin-settings/billing" in url and _claude_billing_sentinel(page):
            return True
    return False  # never confirmed — treat as not logged in (fail closed)


def _claude_fill_email_and_continue(page, email: str) -> bool:
    """On /login: fill the email field and click 'Continue with email' (which makes
    Anthropic send the magic-link email). Returns True if it got that far. Tolerant
    of DOM drift; wrapped so a failure just yields False (→ assisted fallback)."""
    from playwright.sync_api import Error as PlaywrightError

    sel = "input[type=email], input[name=email], input[autocomplete=email]"
    cont = re.compile("continue with email", re.IGNORECASE)
    try:
        # The login SPA renders after domcontentloaded — WAIT for the field
        # (query_selector right away races the render and returns None).
        field = None
        try:
            field = page.wait_for_selector(sel, timeout=15000, state="visible")
        except PlaywrightError:
            field = None
        if field is None:  # some variants hide the field behind a first click
            btn0 = page.get_by_role("button", name=cont).first
            if btn0.count():
                btn0.click()
                try:
                    field = page.wait_for_selector(sel, timeout=8000, state="visible")
                except PlaywrightError:
                    field = None
        if field is None:
            return False
        field.fill(email)
        btn = page.get_by_role("button", name=cont).first
        if btn.count():
            btn.click()
        else:
            field.press("Enter")
        return True
    except PlaywrightError:
        return False


# --- himalaya: read the magic-link email to fully automate login -------------
# The login email contains a DIRECT https://claude.ai/magic-link#<token>:<b64email>
# whose credential is in the URL FRAGMENT (#…) — HTTP redirects drop fragments, so
# we must use this direct link (not the email's tracking link) and let the SPA read
# the hash. The link is a bearer secret → never printed/logged.
_MAGIC_LINK_RE = re.compile(r"https://claude\.ai/magic-link#[A-Za-z0-9:+/=_-]+")


def _himalaya_bin() -> str | None:
    """Locate the himalaya CLI (PATH, else ~/.cargo/bin); None if absent."""
    found = shutil.which("himalaya")
    if found:
        return found
    cargo = Path.home() / ".cargo" / "bin" / "himalaya"
    return str(cargo) if cargo.is_file() else None


def _himalaya_date_epoch(s: str) -> float:
    """Parse a himalaya envelope date ('2026-06-28 12:24+00:00') → epoch seconds."""
    import datetime as _dt

    try:
        return _dt.datetime.strptime(s.strip(), "%Y-%m-%d %H:%M%z").timestamp()
    except (ValueError, TypeError):
        return 0.0


# Anthropic has renamed the magic-link subject at least once, so sender is the
# primary signal and the subject is only a fallback hint. Observed subjects:
#   2026-08  "Your secure link to Claude.ai is here | <timestamp>"
# The original filter demanded "log in to Claude.ai", which never matched.
_ANTHROPIC_MAIL_DOMAIN = "mail.anthropic.com"
_CLAUDE_SUBJECT_HINTS = ("secure link to Claude.ai", "log in to Claude.ai")


def _diag(sink: list[str] | None, msg: str) -> None:
    """Record a one-line reason for a silent skip, de-duplicated."""
    if sink is not None and msg not in sink:
        sink.append(msg)


def _is_claude_login_mail(env: dict) -> bool:
    """True for an Anthropic magic-link mail.

    A known subject wins outright. Otherwise fall back to the sender — the
    localpart is randomised per message (`no-reply-<random>@mail.anthropic.com`)
    but the domain is stable — AND require the subject to look like a link mail:
    ordinary product mail ("You have new requests from your team") ships from
    that same domain, and selecting it would starve the real login mail.
    """
    subject = (env.get("subject") or "").lower()
    if any(h.lower() in subject for h in _CLAUDE_SUBJECT_HINTS):
        return True
    sender = ((env.get("from") or {}).get("addr") or "").lower()
    if not sender.endswith("@" + _ANTHROPIC_MAIL_DOMAIN):
        return False
    return "claude" in subject and "link" in subject


def _himalaya_latest_login_mail(
    himalaya: str,
    email: str,
    since_ts: float,
    account: str | None = None,
    diag: list[str] | None = None,
) -> tuple[str, str] | None:
    """Newest Anthropic magic-link mail to `email`, not clearly older than
    `since_ts`. Searches INBOX + Archive (a server rule auto-archives them).

    Matching is on SENDER first (`*@mail.anthropic.com`) and only then on a
    subject substring, because Anthropic has changed the subject at least once:
    the real 2026 subject is "Your secure link to Claude.ai is here | <ts>",
    while this function used to require "log in to Claude.ai" — a string that
    has never appeared in either folder, so auto-login silently never engaged.

    `diag`, if given, collects one-line reasons explaining why nothing matched;
    the caller prints them, because every failure path here is otherwise silent.

    Returns (folder, id) or None."""
    best_folder: str | None = None
    best_id: str | None = None
    best_key = (-1, -1.0)  # (has_parsable_date, ts) — a dated mail always wins
    seen = matched = 0
    for folder in ("INBOX", "Archive"):
        argv = [himalaya, "envelope", "list", "--folder", folder]
        if account:
            argv += ["-a", account]
        argv += ["--page-size", "30", "-o", "json"]
        try:
            res = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            _diag(diag, f"{folder}: himalaya could not be run ({exc})")
            continue
        if res.returncode != 0:
            _diag(
                diag,
                f"{folder}: himalaya exited {res.returncode} "
                f"({(res.stderr or '').strip()[:160] or 'no stderr'})",
            )
            continue
        try:
            envs = json.loads(res.stdout)
        except (ValueError, TypeError) as exc:
            _diag(diag, f"{folder}: himalaya output was not JSON ({exc})")
            continue
        if not isinstance(envs, list):
            _diag(diag, f"{folder}: himalaya JSON was not a list")
            continue
        for env in envs:
            seen += 1
            if not _is_claude_login_mail(env):
                continue
            matched += 1
            to = ((env.get("to") or {}).get("addr") or "").lower()
            if email and to and to != email.lower():
                _diag(
                    diag,
                    f"{folder}: a Claude login mail was addressed to {to}, not {email}",
                )
                continue
            raw_date = env.get("date") or ""
            ts = _himalaya_date_epoch(raw_date)
            if ts and ts + 180 < since_ts:  # clearly older than our trigger → skip
                continue
            if not ts:
                # Unparsable date: still eligible, but ranked BELOW any dated
                # candidate. Previously ts==0.0 was falsy, so it skipped the
                # freshness guard above AND beat best_ts=-1.0 — i.e. a date-format
                # change would make this silently consume an arbitrary old mail.
                _diag(diag, f"{folder}: could not parse mail date {raw_date!r}")
            key = (1 if ts else 0, ts)
            if key > best_key:
                best_key, best_folder, best_id = key, folder, str(env.get("id"))
    if best_folder is None or best_id is None:
        if matched == 0:
            _diag(
                diag,
                f"no Anthropic login mail among the {seen} newest envelopes "
                f"(looked for sender *@{_ANTHROPIC_MAIL_DOMAIN} or subject ~ "
                f"{_CLAUDE_SUBJECT_HINTS[0]!r})",
            )
        return None
    return (best_folder, best_id)


def _himalaya_extract_magic_link(himalaya: str, folder: str, msg_id: str) -> str | None:
    """Read the mail body and pull out the claude.ai/magic-link#… URL (a bearer
    credential — never printed/logged)."""
    try:
        res = subprocess.run(
            [himalaya, "message", "read", msg_id, "--folder", folder],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if res.returncode != 0:
        return None
    m = _MAGIC_LINK_RE.search(res.stdout)
    return m.group(0) if m else None


def _claude_auto_login(page, email: str, himalaya: str) -> bool:
    """Fully automatic login: trigger the magic-link email, read it via himalaya,
    open the link in the shared browser (the SPA reads the #token and signs in).
    No password, no manual code. Returns True on success, False (→ assisted)."""
    from playwright.sync_api import Error as PlaywrightError

    trigger_ts = time.time()
    if not _claude_fill_email_and_continue(page, email):
        print(
            "  Could not submit the email on the login form — no link was requested.",
            file=sys.stderr,
        )
        return False
    account = os.environ.get("ANTHROPIC_LOGIN_HIMALAYA_ACCOUNT")
    print(
        f"  Sent a login link to {email}; reading it via himalaya"
        f"{f' (account {account})' if account else ' (default account)'}…",
        file=sys.stderr,
    )
    link = None
    diag: list[str] = []
    # EPFL Exchange delivery can lag well past a minute; overridable because the
    # right value is a property of the mail path, not of this code.
    try:
        wait_s = max(10, int(os.environ.get("ANTHROPIC_LOGIN_MAIL_TIMEOUT", "180")))
    except ValueError:
        wait_s = 180
    deadline = time.monotonic() + wait_s
    while time.monotonic() < deadline:
        diag.clear()  # keep only the last round's reasons
        hit = _himalaya_latest_login_mail(
            himalaya, email, trigger_ts, account=account, diag=diag
        )
        if hit:
            link = _himalaya_extract_magic_link(himalaya, hit[0], hit[1])
            if link:
                break
            _diag(
                diag,
                f"found the mail ({hit[0]} id {hit[1]}) but no magic link in its body",
            )
        time.sleep(3)
    if not link:
        print(f"  No magic-link email arrived within {wait_s}s.", file=sys.stderr)
        for reason in diag:
            print(f"    · {reason}", file=sys.stderr)
        return False
    try:
        page.goto(link, wait_until="domcontentloaded")  # SPA consumes #token → signs in
    except PlaywrightError:
        return False
    # CRITICAL: let the SPA finish consuming the #token and redirect to the app
    # BEFORE navigating anywhere. Navigating mid-exchange (e.g. straight to billing)
    # aborts sign-in — that race is what made earlier attempts fail.
    for _ in range(25):  # up to ~25s for /magic-link → /new
        try:
            url = page.url
        except Exception:  # pylint: disable=broad-exception-caught
            url = ""
        if "claude.ai" in url and "/magic-link" not in url and "/login" not in url:
            break
        page.wait_for_timeout(1000)
    page.wait_for_timeout(1500)  # settle the app shell
    for _ in range(3):  # billing surface can be slow to settle after sign-in
        if _claude_logged_in(page):
            return True
        page.wait_for_timeout(2000)
    return False


def _claude_wait_for_login(page, timeout_s: int = 300) -> bool:
    """PASSIVE poll (per O4): watch the login tab WITHOUT navigating it (so we
    don't interrupt you mid-code-entry). Once the SPA leaves /login for the
    claude.ai app, confirm once with an ACTIVE billing check. Heartbeats to
    stderr; gives up after timeout_s."""
    start = time.monotonic()
    last_beat = 0.0
    while time.monotonic() - start < timeout_s:
        try:
            url = page.url
        except Exception:  # pylint: disable=broad-exception-caught
            url = ""
        if "claude.ai" in url and "/login" not in url and "/logout" not in url:
            if _claude_logged_in(page):  # one active confirmation
                return True
        elapsed = time.monotonic() - start
        if elapsed - last_beat >= 30:
            print(
                f"  …waiting for you to finish the email-code login in the shared "
                f"browser window ({int(elapsed)}s elapsed)…",
                file=sys.stderr,
            )
            last_beat = elapsed
        try:
            page.wait_for_timeout(2000)
        except Exception:  # pylint: disable=broad-exception-caught
            time.sleep(2)
    return False


def cmd_anthropic_login(port: int) -> int:
    """Ensure claude.ai is logged in. Idempotent (a warm session just returns 0).

    If $ANTHROPIC_LOGIN_EMAIL is set AND himalaya is available, logs in FULLY
    AUTOMATICALLY: triggers the magic-link email, reads it via himalaya, opens the
    link — no password, no manual code. Otherwise (or if that fails) falls back to
    ASSISTED: you complete the email login in the shared window; it auto-detects.
    Held under the INTERACTION lease — no other tool clicks in the meantime."""
    pw, browser = _connect(port)
    try:
        # Warm probe FIRST, outside the lease — the same read-only check
        # `logged-in` does lease-free, so an ensure-login call with a warm
        # session never waits behind another tool's interaction.
        _ctx, page = _pick_page(browser, "claude.ai")
        if _claude_logged_in(page):
            print("✓ Already logged into Claude (claude.ai).")
            return 0
        with _interaction_lease("login anthropic"):
            from playwright.sync_api import Error as PlaywrightError

            try:
                page.goto(CLAUDE_LOGIN_URL, wait_until="domcontentloaded")
                page.bring_to_front()
            except PlaywrightError:
                pass

            himalaya = _himalaya_bin()
            auto_attempted = False
            if ANTHROPIC_LOGIN_EMAIL and himalaya:
                auto_attempted = True
                print(
                    f"Automatic login for {ANTHROPIC_LOGIN_EMAIL} (magic-link via himalaya)…",
                    file=sys.stderr,
                )
                if _claude_auto_login(page, ANTHROPIC_LOGIN_EMAIL, himalaya):
                    print("✓ Logged into Claude (claude.ai).")
                    _record_login_event("anthropic", "auto")
                    return 0
                print(
                    "  Automatic login didn't complete — falling back to assisted.",
                    file=sys.stderr,
                )

            # Assisted fallback — needs a human at a real window (the automatic
            # magic-link path above works fine headless, so it is NOT gated).
            if not _require_headed_for_assisted(port, "claude.ai"):
                return 2
            # If auto already triggered the email, don't re-send.
            if ANTHROPIC_LOGIN_EMAIL and not auto_attempted:
                _claude_fill_email_and_continue(page, ANTHROPIC_LOGIN_EMAIL)
            hint = (
                "set $ANTHROPIC_LOGIN_EMAIL and install himalaya to fully automate this"
                if not (ANTHROPIC_LOGIN_EMAIL and himalaya)
                else "open the login link Anthropic just emailed you"
            )
            print(
                "\n🔐 Claude (claude.ai) needs a login.\n"
                "   In the shared Chrome window (now in front):\n"
                "     1. Continue with email"
                + (
                    f" (pre-filled: {ANTHROPIC_LOGIN_EMAIL})"
                    if ANTHROPIC_LOGIN_EMAIL
                    else ""
                )
                + ".\n"
                "     2. Open the login link Anthropic emails you (or enter the code).\n"
                "     3. Make sure the org switcher shows 'SDSC · Team plan'.\n"
                f"   I'll detect success automatically. Tip: {hint}.\n",
                file=sys.stderr,
            )
            if not _claude_wait_for_login(page, timeout_s=300):
                return _fail(
                    "Claude login not detected within 5 min. Finish the email login in "
                    "the shared browser, then re-run: browser.py login anthropic"
                )
            print("✓ Logged into Claude (claude.ai).")
            _record_login_event("anthropic", "assisted")
            return 0
    finally:
        browser.close()
        pw.stop()


def cmd_anthropic_logged_in(port: int) -> int:
    """Exit 0 if claude.ai is logged in (billing surface reachable), else 2."""
    pw, browser = _connect(port)
    try:
        _ctx, page = _pick_page(browser, "claude.ai")
        if _claude_logged_in(page):
            print("✓ Logged into Claude (claude.ai).")
            return 0
        print("Not logged into Claude (claude.ai).", file=sys.stderr)
        return 2
    finally:
        browser.close()
        pw.stop()


# ---------------------------------------------------------------------------
# chatgpt.com (OpenAI / ChatGPT Business) — assisted Google-SSO login, no token
# ---------------------------------------------------------------------------


def _chatgpt_logged_in(page) -> bool:
    """ACTIVE check: navigate to the ChatGPT Business admin members page and
    confirm we land there logged in. The 'Invite member' button is the most
    stable signal that we're on the right page AND have admin rights (same
    sentinel openai-team.py uses). A bounce to the auth screen or away from
    /admin/members means not logged in (or no admin rights)."""
    from playwright.sync_api import Error as PlaywrightError

    try:
        page.goto(CHATGPT_ADMIN_URL, wait_until="domcontentloaded")
        page.wait_for_timeout(2500)
    except PlaywrightError:
        return False
    if "/admin/members" not in page.url:
        return False
    try:
        page.wait_for_selector('button:has-text("Invite member")', timeout=15000)
        return True
    except PlaywrightError:
        return False


def _chatgpt_wait_for_login(page, timeout_s: int = 300) -> bool:
    """PASSIVE poll: watch the login tab WITHOUT navigating it (so we don't
    interrupt the SSO mid-flow). Once the tab leaves the auth screens for
    chatgpt.com, confirm with an ACTIVE admin-members check. Heartbeats to
    stderr; gives up after timeout_s."""
    start = time.monotonic()
    last_beat = 0.0
    while time.monotonic() - start < timeout_s:
        try:
            url = page.url
        except Exception:  # pylint: disable=broad-exception-caught
            url = ""
        past_auth = (
            "chatgpt.com" in url
            and "auth.openai.com" not in url
            and "/auth/" not in url
            and "login" not in url
        )
        if past_auth and _chatgpt_logged_in(page):
            return True
        elapsed = time.monotonic() - start
        if elapsed - last_beat >= 30:
            print(
                f"  …waiting for you to finish the ChatGPT SSO login in the shared "
                f"browser window ({int(elapsed)}s elapsed)…",
                file=sys.stderr,
            )
            last_beat = elapsed
        try:
            page.wait_for_timeout(3000)
        except Exception:  # pylint: disable=broad-exception-caught
            time.sleep(3)
    return False


def cmd_openai_login(port: int) -> int:
    """Ensure chatgpt.com (ChatGPT Business admin) is logged in. Idempotent (a
    warm session just returns 0). ChatGPT logs in via Google SSO + 2FA, which
    can't be replayed from stored credentials — a cold session is ASSISTED: you
    complete the SSO once in the shared window; the session then persists. Held
    under the INTERACTION lease — no other tool clicks in the meantime."""
    pw, browser = _connect(port)
    try:
        # Warm probe + headless guard FIRST, outside the lease (both are the
        # read-only checks `logged-in` does lease-free); only the assisted
        # interaction below needs the exclusive lease.
        _ctx, page = _pick_page(browser, "chatgpt.com")
        if _chatgpt_logged_in(page):
            print("✓ Already logged into ChatGPT (chatgpt.com).")
            return 0
        # A cold session is assisted-only — pointless without a window.
        if not _require_headed_for_assisted(port, "chatgpt.com"):
            return 2
        with _interaction_lease("login openai"):
            from playwright.sync_api import Error as PlaywrightError

            try:
                page.bring_to_front()
            except PlaywrightError:
                pass
            print(
                "\n🔐 ChatGPT (chatgpt.com) needs a login.\n"
                "   In the shared Chrome window (now in front):\n"
                "     1. Log in on the page that opened (Google SSO + 2FA).\n"
                "        If Google refuses ('this browser may not be secure'), use\n"
                "        the account's email+password login instead of the SSO button.\n"
                "     2. Land anywhere on chatgpt.com — success is auto-detected and\n"
                "        admin access confirmed on chatgpt.com/admin/members.\n",
                file=sys.stderr,
            )
            if not _chatgpt_wait_for_login(page, timeout_s=300):
                return _fail(
                    "ChatGPT login not detected within 5 min. Finish the SSO login in "
                    "the shared browser, then re-run: browser.py login openai"
                )
            print("✓ Logged into ChatGPT (chatgpt.com).")
            _record_login_event("openai", "assisted")
            return 0
    finally:
        browser.close()
        pw.stop()


def cmd_openai_logged_in(port: int) -> int:
    """Exit 0 if chatgpt.com admin is logged in ('Invite member' reachable), else 2."""
    pw, browser = _connect(port)
    try:
        _ctx, page = _pick_page(browser, "chatgpt.com")
        if _chatgpt_logged_in(page):
            print("✓ Logged into ChatGPT (chatgpt.com).")
            return 0
        print("Not logged into ChatGPT (chatgpt.com).", file=sys.stderr)
        return 2
    finally:
        browser.close()
        pw.stop()


# ---------------------------------------------------------------------------
# Slack (app.slack.com) — assisted login; extracts session xoxc token + d cookie
# ---------------------------------------------------------------------------


def _slack_session_from_page(ctx, page) -> dict | None:
    """Read the live Slack session creds from a logged-in app.slack.com tab:
    the `xoxc-` token from the active team in ``localStorage.localConfig_v2`` and
    the `d` (`xoxd-`) cookie from the browser context (httpOnly — invisible to
    ``document.cookie``, but ``ctx.cookies()`` returns it). Returns
    ``{token, cookie, team_domain}`` or ``None`` if not logged in / not found."""
    from playwright.sync_api import Error as PlaywrightError

    try:
        info = page.evaluate(
            "() => { try {"
            " const c = JSON.parse(localStorage.getItem('localConfig_v2')||'{}');"
            " const teams = Object.values(c.teams||{});"
            " if(!teams.length) return null;"
            " const active = c.lastActiveTeamId && c.teams[c.lastActiveTeamId];"
            " const t = active || teams.find(x=>x.token) || teams[0];"
            " return t && t.token ? {token:t.token, domain:t.domain||''} : null;"
            "} catch(e){ return null; } }"
        )
    except PlaywrightError:
        return None
    if not info or not info.get("token"):
        return None
    cookie = None
    try:
        for ck in ctx.cookies():
            if ck.get("name") == "d" and "slack.com" in str(ck.get("domain", "")):
                cookie = str(ck.get("value", ""))
                break
    except PlaywrightError:
        return None
    if not cookie:
        return None
    return {
        "token": str(info["token"]),
        "cookie": cookie,
        "team_domain": info.get("domain", ""),
    }


def _slack_logged_in(page) -> bool:
    """ACTIVE check: navigate to the Slack web client and confirm a real session
    (a team with an xoxc token in localStorage), not the workspace-signin page."""
    from playwright.sync_api import Error as PlaywrightError

    try:
        page.goto(SLACK_APP_URL, wait_until="domcontentloaded")
        page.wait_for_timeout(3000)
    except PlaywrightError:
        return False
    url = ""
    try:
        url = page.url
    except PlaywrightError:
        return False
    if any(m in url for m in SLACK_SIGNIN_MARKERS):
        return False
    ctx = page.context
    return _slack_session_from_page(ctx, page) is not None


def _slack_prefill_email(page) -> None:
    """Best-effort: type SLACK_LOGIN_EMAIL into the sign-in email field so you
    only complete the code/SSO step. Silent no-op if the field isn't present
    (SSO screen, already past email, DOM changed) — never blocks the login."""
    if not SLACK_LOGIN_EMAIL:
        return
    from playwright.sync_api import Error as PlaywrightError

    for sel in (
        'input[data-qa="signin_domain_email"]',
        'input[type="email"]',
        "#email",
    ):
        try:
            field = page.query_selector(sel)
            if field:
                field.fill(SLACK_LOGIN_EMAIL)
                return
        except PlaywrightError:
            continue


def _slack_wait_for_login(page, timeout_s: int = 600) -> bool:
    """PASSIVE poll: watch the login tab WITHOUT navigating it — navigating would
    reload the page and wipe whatever you're typing (the bug that made login
    'refresh too quickly'). Reading ``page.url`` + localStorage does NOT navigate,
    so it never interrupts you. Returns True once a live session (xoxc token)
    appears. Heartbeats to stderr; gives up after ``timeout_s``."""
    start = time.monotonic()
    last_beat = 0.0
    while time.monotonic() - start < timeout_s:
        try:
            url = page.url
        except Exception:  # pylint: disable=broad-exception-caught
            url = ""
        # Once we're on a workspace surface (past the signin/get-started pages),
        # look for the session token — a read, never a navigation.
        if url and not any(m in url for m in SLACK_SIGNIN_MARKERS):
            try:
                if _slack_session_from_page(page.context, page):
                    return True
            except Exception:  # pylint: disable=broad-exception-caught
                pass
        elapsed = time.monotonic() - start
        if elapsed - last_beat >= 30:
            print(
                f"  …waiting for you to finish the Slack login in the shared "
                f"browser window ({int(elapsed)}s elapsed, timeout {timeout_s}s)…",
                file=sys.stderr,
            )
            last_beat = elapsed
        try:
            page.wait_for_timeout(3000)
        except Exception:  # pylint: disable=broad-exception-caught
            time.sleep(3)
    return False


def cmd_slack_login(port: int) -> int:
    """Ensure Slack is logged in. Idempotent (a warm session returns 0).

    Slack web logs in via email-code / SSO, which can't be replayed from a stored
    secret — a cold session is ASSISTED: complete it once in the shared window;
    the session then persists in the profile (so this is a ONE-TIME step).
    `slack_api.py` reuses it via `browser.py slack-session`. The wait is PASSIVE
    (10 min) — the page is NOT reloaded while you type, and $SLACK_LOGIN_EMAIL is
    pre-filled when set. Held under the INTERACTION lease throughout, so no other
    tool clicks in the shared window while you sign in."""
    pw, browser = _connect(port)
    try:
        # Warm probe + headless guard FIRST, outside the lease (read-only, the
        # same checks `logged-in` does lease-free).
        _ctx, page = _pick_page(browser, "slack.com")
        if _slack_logged_in(page):
            print("✓ Already logged into Slack — session persists; nothing to do.")
            return 0
        # A cold session is assisted-only — pointless without a window.
        if not _require_headed_for_assisted(port, "Slack"):
            return 2
        with _interaction_lease("login slack"):
            from playwright.sync_api import Error as PlaywrightError

            # Land straight on the SDSC workspace sign-in (skips the workspace picker).
            try:
                page.goto(SLACK_WORKSPACE_URL, wait_until="domcontentloaded")
                page.bring_to_front()
                page.wait_for_timeout(1500)
                _slack_prefill_email(page)
            except PlaywrightError:
                pass
            email_note = (
                f" (email pre-filled: {SLACK_LOGIN_EMAIL})"
                if SLACK_LOGIN_EMAIL
                else " (tip: export SLACK_LOGIN_EMAIL=albert.glensk@epfl.ch to pre-fill it)"
            )
            print(
                "\n🔐 Slack needs a ONE-TIME login (the session then persists).\n"
                f"   In the shared Chrome window (now in front){email_note}:\n"
                f"     1. Workspace: swiss-data-science ({SLACK_WORKSPACE_URL}).\n"
                "     2. Sign in (email code or SSO) as an Owner/Admin.\n"
                "     3. Land in the workspace — I detect success automatically.\n"
                "   Take your time — the page is NOT reloaded while you type.\n",
                file=sys.stderr,
            )
            if not _slack_wait_for_login(page, timeout_s=600):
                return _fail(
                    "Slack login not detected within 10 min. Finish it in the shared "
                    "browser, then re-run: browser.py login slack"
                )
            print("✓ Logged into Slack — session saved in the shared profile.")
            _record_login_event("slack", "assisted")
            return 0
    finally:
        browser.close()
        pw.stop()


def cmd_slack_logged_in(port: int) -> int:
    """Exit 0 if app.slack.com is logged in, 2 if not."""
    pw, browser = _connect(port)
    try:
        _ctx, page = _pick_page(browser, "slack.com")
        if _slack_logged_in(page):
            print("✓ Logged into Slack (app.slack.com).")
            return 0
        print("Not logged into Slack (app.slack.com).", file=sys.stderr)
        return 2
    finally:
        browser.close()
        pw.stop()


def cmd_slack_session(port: int) -> int:
    """Print the live Slack session creds as JSON `{token, cookie, team_domain}`
    for a consumer (slack_api.py) to make admin API calls. These are BEARER
    credentials — emitted to stdout only (like `token` for CSCS), never cached to
    disk (xoxc rotates) or logged. Exits 2 (with a hint) when not logged in."""
    pw, browser = _connect(port)
    try:
        _ctx, page = _pick_page(browser, "slack.com")
        if not _slack_logged_in(page):
            page.bring_to_front()
            print(
                "Not logged into Slack. Run: browser.py login slack",
                file=sys.stderr,
            )
            return 2
        creds = _slack_session_from_page(page.context, page)
        if not creds:
            return _fail(
                "Logged in, but no xoxc token / d cookie found in the Slack tab."
            )
        print(json.dumps(creds))
        return 0
    finally:
        browser.close()
        pw.stop()


# ---------------------------------------------------------------------------
# Biopol WiFi (cloudpath.edificom.cloud) — unattended keychain email+password
# ---------------------------------------------------------------------------


def _biopolwifi_logged_in(page) -> bool:
    """True on the settled, logged-in Cloudpath portal (the properties surface).

    Sentinel is a DOM/text signal, NOT "the URL isn't the login form": the
    logged-in portal renders the property name 'SDSC - Biopole' and a 'Properties'
    breadcrumb, while the login form page (input[placeholder="Email Address"]) has
    neither. Returns False on any Playwright error (page mid-navigation) so the
    caller treats it as 'not confirmed yet'."""
    from playwright.sync_api import Error as PlaywrightError

    try:
        return bool(
            page.evaluate(
                "() => { const t = document.body ? document.body.innerText : '';"
                " return /SDSC - Biopole/.test(t) || /\\bProperties\\b/.test(t); }"
            )
        )
    except PlaywrightError:
        return False


def cmd_biopolwifi_login(port: int) -> int:
    """Ensure the Cloudpath MDU portal (cloudpath.edificom.cloud) is logged in.

    UNATTENDED like CSCS: the portal login is a plain email+password Vue form, so
    we fill it from the two macOS-keychain items (shared with biopol-wifi.py) and
    submit — no SSO, no 1Password fallback for this site. Idempotent: a warm
    session (the 'SDSC - Biopole' / 'Properties' sentinel already present) just
    returns 0. No token is extracted; this only keeps the GUI logged in. Held
    under the INTERACTION lease — no other tool clicks in the meantime."""
    pw, browser = _connect(port)
    try:
        with _interaction_lease("login biopolwifi"):
            from playwright.sync_api import Error as PlaywrightError

            _ctx, page = _pick_page(browser, "cloudpath.edificom.cloud")
            # If the picked tab isn't already on the portal (cold session reuses
            # whatever content tab _pick_page returned), navigate there and settle.
            if "cloudpath.edificom.cloud" not in page.url:
                try:
                    page.goto(BIOPOLWIFI_PORTAL_URL, wait_until="domcontentloaded")
                    page.wait_for_timeout(2000)  # let the Vue SPA render
                except PlaywrightError:
                    pass
            # The Vue login form can render a beat after domcontentloaded — WAIT for
            # the email field before deciding which state we're in (query_selector
            # right away races the render and returns None). Skip the wait entirely
            # when the logged-in sentinel is already present (warm session).
            email_sel = 'input[placeholder="Email Address"]'
            pass_sel = 'input[placeholder="Password"]'
            form_ready = False
            if not _biopolwifi_logged_in(page):
                try:
                    page.wait_for_selector(email_sel, timeout=15000, state="visible")
                    form_ready = True
                except PlaywrightError:
                    form_ready = False
            if not form_ready:
                # No login form — either already logged in (sentinel) or a stray page.
                if _biopolwifi_logged_in(page):
                    print("✓ Already logged into the Cloudpath MDU portal (edificom).")
                    return 0
                return _fail(
                    "Cloudpath portal showed neither the login form nor the logged-in "
                    f"sentinel — unexpected page ({page.url})."
                )
            email = _keychain_get(KEYCHAIN_SVC_BIOPOL_EMAIL)
            password = _keychain_get(KEYCHAIN_SVC_BIOPOL_PASS)
            if not (email and password):
                return _fail(
                    "No Cloudpath portal credentials in the keychain. "
                    "Run: browser.py store-creds biopolwifi"
                )
            try:
                page.fill(email_sel, email)
                page.fill(pass_sel, password)
                page.click('button:has-text("Login")')
            except PlaywrightError as exc:
                return _fail(f"Could not submit the Cloudpath login form: {exc}")
            # Poll up to ~20s for the logged-in sentinel.
            for _ in range(40):
                if _biopolwifi_logged_in(page):
                    print("✓ Logged into the Cloudpath MDU portal (edificom).")
                    _record_login_event("biopolwifi", "keychain")
                    return 0
                page.wait_for_timeout(500)
            return _fail(
                "Cloudpath login did not reach the properties page — wrong "
                f"email/password, or an unexpected page ({page.url})."
            )
    finally:
        browser.close()
        pw.stop()


def cmd_biopolwifi_logged_in(port: int) -> int:
    """Exit 0 if the Cloudpath MDU portal is logged in, 2 if not (no login).

    PASSIVE check: navigate to the portal, settle, and confirm the 'SDSC - Biopole'
    / 'Properties' sentinel on the properties surface (never merely 'the URL isn't
    the login form')."""
    pw, browser = _connect(port)
    try:
        from playwright.sync_api import Error as PlaywrightError

        _ctx, page = _pick_page(browser, "cloudpath.edificom.cloud")
        try:
            page.goto(BIOPOLWIFI_PORTAL_URL, wait_until="domcontentloaded")
            page.wait_for_timeout(2500)
        except PlaywrightError:
            pass
        if _biopolwifi_logged_in(page):
            print("✓ Logged into the Cloudpath MDU portal (edificom).")
            return 0
        print("Not logged into the Cloudpath MDU portal (edificom).", file=sys.stderr)
        return 2
    finally:
        browser.close()
        pw.stop()


def cmd_biopolwifi_store_creds() -> int:
    """Store the Cloudpath MDU portal email+password in the macOS keychain.

    Interactive one-time setup: prompt for the portal email (shown) and password
    (hidden via getpass), then write the two items — SHARED with biopol-wifi.py —
    so `browser.py login biopolwifi` runs unattended. No 1Password / TOTP for this
    site; it's a plain email+password form."""
    import getpass

    print(
        "Setting up unattended Cloudpath MDU portal (cloudpath.edificom.cloud) "
        "login.\nCredentials are stored in your macOS login keychain (encrypted at "
        "rest, read only by the `security` tool, no Touch ID on later reads).\n"
    )
    email = input("Cloudpath portal email (e.g. albert.glensk@epfl.ch): ").strip()
    password = getpass.getpass("Cloudpath portal password: ")
    if not (email and password):
        return _fail("Missing email or password — nothing stored.")
    if not (
        _keychain_set(KEYCHAIN_SVC_BIOPOL_EMAIL, email)
        and _keychain_set(KEYCHAIN_SVC_BIOPOL_PASS, password)
    ):
        return _fail("Failed to write one or more keychain items.")
    print(
        "✓ Stored the Cloudpath portal email and password in the macOS keychain.\n"
        "  `browser.py login biopolwifi` now runs without a prompt.\n"
        "  Verify with:  browser.py login biopolwifi\n"
        "  Revoke with:  browser.py forget-creds biopolwifi"
    )
    return 0


def cmd_biopolwifi_forget_creds() -> int:
    """Delete the Cloudpath MDU portal credentials from the macOS keychain."""
    for svc in (KEYCHAIN_SVC_BIOPOL_EMAIL, KEYCHAIN_SVC_BIOPOL_PASS):
        _keychain_delete(svc)
    print(
        "✓ Removed the Cloudpath portal keychain credentials. "
        "`browser.py login biopolwifi` needs `store-creds biopolwifi` again."
    )
    return 0


# ---------------------------------------------------------------------------
# Login-frequency log (how often a real login was actually needed)
# ---------------------------------------------------------------------------


def _record_login_event(site_name: str, mode: str) -> None:
    """Append one real-login record to the site's log. Best-effort: never raises
    (a logging failure must not break a successful login)."""
    try:
        LOGIN_LOG_DIR.mkdir(parents=True, exist_ok=True)
        rec = {
            "ts": round(time.time(), 3),
            "iso": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "mode": mode,
        }
        with (LOGIN_LOG_DIR / f"{site_name}.jsonl").open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec) + "\n")
    except OSError:
        pass


# Modes where a HUMAN had to act (vs. fully unattended re-auth). The aggregate
# view highlights the assisted count — that's "how often we had to sign in".
ASSISTED_MODES = {"assisted", "1password"}


def _load_login_events(site_name: str) -> list[dict]:
    """All recorded real-login events for one site, each tagged with `site`.
    Empty list when nothing's recorded yet."""
    path = LOGIN_LOG_DIR / f"{site_name}.jsonl"
    if not path.is_file():
        return []
    events: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            e = json.loads(line)
        except ValueError:
            continue
        e.setdefault("site", site_name)
        events.append(e)
    return events


def _print_login_stats(label: str, events: list[dict]) -> None:
    """Shared header: total (+assisted), first/last, average interval."""
    events.sort(key=lambda e: e.get("ts", 0))
    n = len(events)
    assisted = sum(1 for e in events if e.get("mode") in ASSISTED_MODES)
    print(
        f"Login frequency — {label}: {n} real login(s)  [{assisted} you had to sign in]."
    )
    print(f"  first: {events[0].get('iso', '?')}")
    print(f"  last:  {events[-1].get('iso', '?')}")
    if n >= 2:
        span_days = (events[-1]["ts"] - events[0]["ts"]) / 86400
        avg = span_days / (n - 1)
        print(f"  span:  {span_days:.1f} days  →  every ~{avg:.1f} days on average")


def cmd_login_log(site_name: str | None) -> int:
    """How often a *real* login was actually needed. With a SITE, that one site;
    with no SITE, a LIVE aggregate across EVERY registered site (total, the count
    where you had to sign in, per-site breakdown, and recent events)."""
    if site_name:
        site = _resolve_site(site_name)
        events = _load_login_events(site.name)
        if not events:
            print(
                f"No real logins recorded yet for '{site.name}'. "
                f"(Each time `login {site.name}` actually had to sign in is logged.)"
            )
            return 0
        _print_login_stats(f"'{site.name}'", events)
        print("  recent:")
        for e in sorted(events, key=lambda e: e.get("ts", 0))[-10:]:
            print(f"    {e.get('iso', '?')}  ({e.get('mode', '?')})")
        return 0

    # Aggregate across all sites (the live "how often did we sign in" view).
    per_site = {s.name: _load_login_events(s.name) for s in _sites()}
    events = [e for evs in per_site.values() for e in evs]
    if not events:
        print(
            "No real logins recorded on any site yet. Each time `browser.py login "
            "<site>` actually has to sign in is logged under "
            f"{LOGIN_LOG_DIR}/<site>.jsonl."
        )
        return 0
    _print_login_stats("all sites", events)
    print("  by site:")
    for name in sorted(per_site, key=lambda k: -len(per_site[k])):
        evs = sorted(per_site[name], key=lambda e: e.get("ts", 0))
        if not evs:
            continue
        last = evs[-1]
        print(
            f"    {name:<11} {len(evs):>3}   last {last.get('iso', '?')}  "
            f"({last.get('mode', '?')})"
        )
    print("  recent (all sites):")
    for e in sorted(events, key=lambda e: e.get("ts", 0))[-12:]:
        print(
            f"    {e.get('iso', '?')}  {e.get('site', '?')!s:<11} "
            f"({e.get('mode', '?')})"
        )
    return 0


# ---------------------------------------------------------------------------
# Site registry — generic multi-site login (facade over per-site functions)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Site:
    """One loginnable site. CSCS reuses the existing cmd_cscs_* functions verbatim
    (facade — zero behaviour change); claude.ai uses the assisted functions above.
    `login`/`logged_in` take the CDP port; `store_creds`/`forget_creds` take none
    (None when the site has no stored-credential flow, e.g. claude.ai)."""

    name: str
    aliases: tuple[str, ...]
    blurb: str
    login: Callable[[int], int]
    logged_in: Callable[[int], int]
    store_creds: Callable[[], int] | None = None
    forget_creds: Callable[[], int] | None = None


def _sites() -> list[Site]:
    """The registry. Defined as a function so it can reference module functions
    declared above without forward-reference juggling."""
    return [
        Site(
            name="cscs",
            aliases=("portal", "cscs.ch"),
            blurb="CSCS portal (Keycloak user/password/TOTP; caches a DRF token)",
            login=cmd_cscs_login,
            logged_in=cmd_token,  # exit 0 logged-in / 2 not — and refreshes token
            store_creds=cmd_cscs_store_creds,
            forget_creds=cmd_cscs_forget_creds,
        ),
        Site(
            name="anthropic",
            aliases=("claude", "claude.ai", "claude-ai"),
            blurb="claude.ai Team admin (assisted email-code login; no token)",
            login=cmd_anthropic_login,
            logged_in=cmd_anthropic_logged_in,
        ),
        Site(
            name="openai",
            aliases=("chatgpt", "chatgpt.com", "oai"),
            blurb="chatgpt.com Business admin (assisted Google-SSO login; no token)",
            login=cmd_openai_login,
            logged_in=cmd_openai_logged_in,
        ),
        Site(
            name="slack",
            aliases=("slack.com", "app.slack.com"),
            blurb="app.slack.com (assisted login; `slack-session` prints xoxc+d creds)",
            login=cmd_slack_login,
            logged_in=cmd_slack_logged_in,
        ),
        Site(
            name="biopolwifi",
            aliases=("biopol", "cloudpath", "edificom"),
            blurb="Cloudpath MDU WiFi portal (keychain email+password; SDSC Biopole units)",
            login=cmd_biopolwifi_login,
            logged_in=cmd_biopolwifi_logged_in,
            store_creds=cmd_biopolwifi_store_creds,
            forget_creds=cmd_biopolwifi_forget_creds,
        ),
    ]


def _resolve_site(name: str) -> Site:
    """Find a Site by name or alias (case-insensitive), or exit with the list."""
    key = name.strip().lower()
    for site in _sites():
        if key == site.name or key in site.aliases:
            return site
    avail = "\n".join(f"  {s.name:<10} {s.blurb}" for s in _sites())
    print(f"❌ Unknown site: {name!r}. Available:\n{avail}", file=sys.stderr)
    sys.exit(2)


def cmd_login(port: int, site_name: str) -> int:
    """Ensure SITE is logged in (automated or assisted, per the site)."""
    return _resolve_site(site_name).login(port)


def cmd_logged_in(port: int, site_name: str) -> int:
    """Exit 0 if SITE is logged in, 2 if not."""
    return _resolve_site(site_name).logged_in(port)


def cmd_store_creds(site_name: str) -> int:
    """Store SITE credentials in the macOS keychain (credential-based sites only)."""
    site = _resolve_site(site_name)
    if site.store_creds is None:
        return _fail(
            f"'{site.name}' uses assisted login — there are no credentials to store."
        )
    return site.store_creds()


def cmd_forget_creds(site_name: str) -> int:
    """Delete SITE credentials from the macOS keychain."""
    site = _resolve_site(site_name)
    if site.forget_creds is None:
        return _fail(f"'{site.name}' has no stored credentials to forget.")
    return site.forget_creds()


def _fail(msg: str) -> int:
    print(f"❌ {msg}", file=sys.stderr)
    return 1


def main() -> int:
    """Dispatch the chosen subcommand."""
    args = parse_args()
    ensure_deps()
    port = args.cdp_port
    # Say what we are doing BEFORE anything attaches over CDP: this is the
    # `purpose` every client registration reports to whoever waits on the gate.
    site = getattr(args, "site", None)
    _set_purpose(f"{args.cmd} {site}" if site else str(args.cmd))
    if args.cmd == "up":
        return cmd_up(port, args.headless)
    if args.cmd == "status":
        return cmd_status(port)
    if args.cmd == "switch":
        return cmd_switch(port, args.mode, args.force)
    if args.cmd == "clients":
        return cmd_clients(port)
    if args.cmd == "doctor":
        return cmd_doctor(port)
    if args.cmd == "register-exec":
        return cmd_register_exec(port, args.tool, args.cmd_)
    if args.cmd == "down":
        return cmd_down(port)
    if args.cmd == "open":
        return cmd_open(port, args.url, reuse=args.reuse)
    if args.cmd == "eval":
        return cmd_eval(port, args.js, args.url)
    if args.cmd == "token":
        return cmd_token(port)
    if args.cmd == "slack-session":
        return cmd_slack_session(port)
    # Generic multi-site commands.
    if args.cmd == "login":
        return cmd_login(port, args.site)
    if args.cmd == "logged-in":
        return cmd_logged_in(port, args.site)
    if args.cmd == "login-log":
        return cmd_login_log(args.site)
    if args.cmd == "store-creds":
        return cmd_store_creds(args.site)
    if args.cmd == "forget-creds":
        return cmd_forget_creds(args.site)
    # CSCS aliases (back-compat; cscs-api.py depends on these names).
    if args.cmd == "cscs-login":
        return cmd_login(port, "cscs")
    if args.cmd == "cscs-store-creds":
        return cmd_store_creds("cscs")
    if args.cmd == "cscs-forget-creds":
        return cmd_forget_creds("cscs")
    return 2


if __name__ == "__main__":
    args_ns = parse_args()  # parse first so -h is instant (no venv/import cost)
    ensure_deps()
    sys.exit(main())
