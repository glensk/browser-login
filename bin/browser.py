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
  up        Launch the shared browser, always HEADLESS (idempotent; -H is a
            no-op kept for compatibility). Headed exists only inside a guided
            login (agent-login.py -g SITE holds the headed lease); a headed
            browser without a live lease is reverted by every command.
  status    Show CDP health, browser version, open tabs (origins only; -f full
            URLs), and the lifecycle record. [-p|--probe] also probes every tab
            over raw CDP and marks the ones that answer nothing.
  close-hung [-y|--yes]
            Close tabs whose renderer answers no CDP command — one such tab
            blocks every Playwright attach. Only tabs that failed three
            consecutive probes; asks first unless -y.
  switch MODE
            Transactionally switch to headed|headless: stop the browser and
            relaunch it on the SAME profile (every login persists). `headed`
            only for the holder of the live headed lease (else exit 2). Waits for
            registered CDP clients to drain and REFUSES while an unregistered
            client is attached ([-f|--force] switches anyway). Exit 75 (busy)
            while a guided login owns the browser ([-F|--force-maintenance]).
  clients   Show who is attached over CDP: the registered clients (tool, pid,
            purpose) plus any unregistered ones a switch would refuse.
  journal [-n N] [-e EVENT] [-j]
            Tail the append-only, redacted journal (origins only): who ran
            up/switch/down/login, every window raise, client (un)registrations
            — with pid, parent chain and argv.
  doctor    Full health check: the lifecycle record, client coordination, and a
            drivability probe (rAF/click/screenshot) on a disposable tab.
  register-exec [-t NAME] -- CMD ARGS…
            Run a long-lived CDP client (e.g. the Playwright MCP server) as a
            REGISTERED client: the registration lives exactly as long as CMD.
  down [-f|--force] [-F|--force-maintenance]
            Quit the shared browser. Waits for registered CDP clients to drain
            and refuses while one stays attached (-f/--force stops anyway —
            they lose their connection); a stale lifecycle record with no
            browser behind it is cleared without waiting.
  open URL  Open/navigate a tab to URL in the shared browser.
            [-N|--new] always a NEW background tab over raw CDP; prints
            `target=<id>` — the id this caller owns (tp#786).
  eval JS   Run a JS expression in the active (or --url-matched) tab; print JSON.
            [-t|--timeout SECONDS] hard deadline (default 60), attach included.
            [-T|--target TID] evaluates in exactly that target over raw CDP
            (JSON-serialisable results only); exit 1 if it is gone.
  close     Close tabs you own: -i/--id TID… (ids `open -N` printed), or for
            manual cleanup URL… (exact match sans query/fragment, http(s)
            only). Takes the interaction lease, re-checks each tab right before
            closing it, never closes the last tab; -n dry run, -w lease wait,
            -d overall deadline.

Every Playwright attach gives up after $CLAUDE_BROWSER_CONNECT_TIMEOUT_S (default
30) and names the tab that blocked it (see `status -p` / `close-hung`).

Generic multi-site login (a SITE is one of the entries in the SITES registry —
currently ``cscs``, ``anthropic``/``claude``, ``openai``/``chatgpt``, ``slack``,
``notion``, ``biopolwifi`` and ``switch``; add more by registering a Site):
  login SITE        Ensure SITE is logged in in the shared browser. Automated for
                    sites with stored credentials (CSCS Keycloak). For claude.ai:
                    FULLY automatic when $ANTHROPIC_LOGIN_EMAIL is set and himalaya
                    is installed (triggers the magic-link email, reads it, opens
                    the link — no password, no code; only a NEW link, from a
                    sender in $ANTHROPIC_LOGIN_MAIL_SENDERS, for that email);
                    otherwise ASSISTED (you complete the email login in the
                    window). For chatgpt.com:
                    ASSISTED (Google SSO + 2FA once in the shared window; the
                    session persists). For Notion: ASSISTED (e-mail code or
                    SSO once in the shared window). For the Switch Cloud
                    Portal: clicks the edu-ID sign-in button (no password while
                    the edu-ID session is alive), otherwise ASSISTED. Records a
                    login event. An ASSISTED step runs ONLY inside a guided
                    login (agent-login.py -g SITE, which holds the headed
                    lease); anywhere else `login` exits 4 and prints
                    `needs Albert: agent-login.py -g SITE`.
  logged-in SITE    Exit 0 if SITE is logged in, 2 if not (no login attempted).
  login-log SITE    Show how often a *real* login was actually needed for SITE
                    (count, first/last, average interval) — read from the log.
  store-creds SITE  Store SITE credentials in the macOS keychain (password+TOTP
                    sites only, e.g. cscs). forget-creds SITE removes them.

Login broker (PLAN_login-broker.md): a root-installed broker logs into the sites
Albert whitelisted in Bitwarden `agent-logins` and hands over a session bundle
(cookies + named storage keys), never a password. `login SITE` resolves the
static registry first, then the broker's list ($LOGIN_BROKER_SOCKET overrides
the socket). Exit codes: 0 ok, 2 not logged in, 3 broker unavailable, 4 needs a
human.
  broker-sites      List the broker's sites (id, fill origins, status).
  logout SITE       Drop the broker profile for SITE + delete its cookies here.
  import-safari SITE [-n]
                    Copy SITE's session cookies from Safari (sites in
                    SAFARI_SITES the broker lists = Albert's consent); bot-check
                    cookies stay behind; -n lists names/expiry only. `login SITE`
                    for such a site tries Safari first, then the broker
                    (kleinanzeigen only). $SAFARI_COOKIES overrides the file.
  login-cscs-assisted
                    Human-only pre-broker CSCS login (keychain / 1Password).
  assisted-login SITE [-u URL] [-a] [-f]
                    Human-only guided login (agent-login.py -g SITE): type the
                    site name on your terminal to start; log in through a
                    remote view of a headless tab (B), or in the shown window
                    (-a, or offered when B cannot do it). Pauses registered
                    long-lived clients for its duration; no terminal → exit 2.

CSCS aliases (kept for back-compat; cscs-api.py depends on them):
  token             Read the 40-hex Waldur DRF token from the portal tab and cache
                    it at ~/.cache/cscs-api/portal_token (what cscs-api.py uses).
  cscs-login        = login cscs   (logs in + caches the token).
  cscs-store-creds  = store-creds cscs   ·   cscs-forget-creds = forget-creds cscs

The chromium binary is Playwright's bundled "Chrome for Testing" (already on
disk). No system browser is touched, so this never collides with your daily Brave.
"""

# Two pylint messages are properties of this tool's documented architecture, not
# defects (canonical lint command: `uv run pylint bin/browser.py`, AGENTS.md):
#   * too-many-lines — browser.py is deliberately ONE self-contained file so any
#     consumer repo (and any agent) can exec it straight off PATH with nothing to
#     install; splitting it into a package would break that contract.
#   * import-outside-toplevel — playwright/pyotp/requests (and Quartz, getpass,
#     binascii, datetime) are imported inside the functions that use them so
#     `-h`, `status` and `ensure_deps` itself run BEFORE those packages exist;
#     the self-bootstrapping venv in `ensure_deps` is impossible otherwise.
# Every other pylint exemption in this file is per-line, with its own reason.
# pylint: disable=too-many-lines,import-outside-toplevel

import argparse
import atexit
import contextlib
import dataclasses
import fcntl
import functools
import glob
import json
import os
import queue
import re
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, NamedTuple

# The broker package (repo root) is the one home of the TOTP, Keycloak-submit
# and identity-provider helpers; browser.py reuses them instead of copies.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
# pylint: disable=wrong-import-position
from broker import safari_cookies as _safari  # noqa: E402
from broker.bundle import IDP_HOSTS as BROKER_IDP_HOSTS  # noqa: E402
from broker.bundle import IDP_LABELS as BROKER_IDP_LABELS  # noqa: E402
from broker.recipes import click_keycloak_submit as _click_keycloak_submit  # noqa: E402
from broker.recipes import cscs_portal_ready as _broker_cscs_portal_ready  # noqa: E402
from broker.recipes import fresh_totp as _broker_fresh_totp  # noqa: E402
from broker.recipes import interstitial_title as _broker_interstitial  # noqa: E402
from broker.recipes import off_fill_origins as _broker_off_fill_origins  # noqa: E402
from broker.recipes import parse_totp as _parse_totp  # noqa: E402
from broker.recipes import sentinel_shown as _broker_sentinel_shown  # noqa: E402
from broker.useragent import engine_user_agent as _engine_user_agent  # noqa: E402

# pylint: enable=wrong-import-position
# Named instances: a second shared browser with its OWN profile, port and
# coordination files (e.g. "private" for Albert's private claude.ai account — one
# profile holds one claude.ai session). Unset = the default shared browser.
INSTANCE_PORTS = {"": 9222, "private": 9223}
INSTANCE = os.environ.get("CLAUDE_BROWSER_INSTANCE", "").strip().lower()
if INSTANCE not in INSTANCE_PORTS:
    sys.exit(
        f"❌ CLAUDE_BROWSER_INSTANCE={INSTANCE!r} is unknown "
        f"(known: {', '.join(k for k in INSTANCE_PORTS if k)})"
    )
DEFAULT_CDP_PORT = int(
    os.environ.get("CLAUDE_BROWSER_CDP_PORT", str(INSTANCE_PORTS[INSTANCE]))
)


def _connect_timeout_s(raw: str | None, default: float = 30.0) -> float:
    """Parse ``CLAUDE_BROWSER_CONNECT_TIMEOUT_S``; invalid or <= 0 → `default`."""
    try:
        value = float(raw) if raw is not None else default
    except ValueError:
        return default
    return value if 0 < value < float("inf") else default  # NaN fails both


# How long a Playwright attach (`connect_over_cdp`) may take before browser.py
# gives up and names the tab that blocks it (tp#693). Playwright's own default
# is its 180 s launch timeout — long enough to look like a hang to every caller.
CONNECT_TIMEOUT_S = _connect_timeout_s(
    os.environ.get("CLAUDE_BROWSER_CONNECT_TIMEOUT_S")
)
# Test-only override: the tests point every coordination file (registry, lease,
# lifecycle) at a temp dir so they never touch the live browser's state.
CACHE_DIR = (
    Path(os.environ["CLAUDE_BROWSER_CACHE_DIR"])
    if os.environ.get("CLAUDE_BROWSER_CACHE_DIR")
    else Path.home()
    / ".cache"
    / ("claude-browser" + (f"-{INSTANCE}" if INSTANCE else ""))
)
PROFILE_DIR = CACHE_DIR / "profile"
# Test-only: set by tests/conftest.py; `_launch_browser` refuses while it is 1.
TEST_NO_LAUNCH_ENV = "CLAUDE_BROWSER_TEST_NO_LAUNCH"
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

# --- Notion (app.notion.com) site --------------------------------------------
# Notion logs in by e-mail code or SSO, which cannot be replayed from a stored
# secret — so this site does ASSISTED login: you sign in once in the shared
# window; the session then persists in the profile. No token is extracted.
# notion.so redirects to app.notion.com, and so does its /login page — the host
# alone proves nothing. Logged-in sentinel = the workspace sidebar (or its
# workspace switcher), which neither /login nor the www.notion.com marketing
# page renders.
NOTION_APP_ORIGIN = "https://app.notion.com"
NOTION_APP_HOST = "app.notion.com"
NOTION_LOGIN_URL = NOTION_APP_ORIGIN + "/login"
NOTION_SIDEBAR_SELECTOR = ".notion-sidebar, .notion-sidebar-switcher"

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


# `eval`'s default hard deadline (seconds), attach included — see cmd_eval.
EVAL_TIMEOUT_S = 60.0
# `close`: default lease wait and overall deadline (seconds) — see cmd_close.
CLOSE_WAIT_S = 30.0
CLOSE_DEADLINE_S = 20.0


def _positive_seconds(raw: str) -> float:
    """argparse type: a finite number of seconds > 0."""
    try:
        value = float(raw)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a number: {raw!r}") from None
    if not 0 < value < float("inf"):
        raise argparse.ArgumentTypeError(f"must be > 0 seconds: {raw!r}")
    return value


def _add_open_eval_parsers(sub: Any) -> None:
    """The `open` and `eval` subparsers (kept out of `parse_args` for size)."""
    po = sub.add_parser("open", help="Open/navigate a tab to URL.")
    po.add_argument("url", help="URL to open.")
    pog = po.add_mutually_exclusive_group()
    pog.add_argument(
        "-r",
        "--reuse",
        action="store_true",
        help=(
            "Navigate an existing tab already on this URL (compared without "
            "query/fragment) instead of opening a new tab. Picks the oldest "
            "match — the same tab `eval --url` targets. Mutually exclusive "
            "with -N."
        ),
    )
    pog.add_argument(
        "-N",
        "--new",
        action="store_true",
        help=(
            "Always create a NEW background tab (raw CDP Target.createTarget, "
            "no Playwright attach; never reuses a tab) and print `target=<id>` "
            "on its own line after the ✓ line. That id is the caller's tab: "
            "pass it to `eval -T` and `close -i`. Mutually exclusive with -r."
        ),
    )
    pe = sub.add_parser("eval", help="Eval a JS expression in a tab; print JSON.")
    pe.add_argument("js", help="JavaScript expression to evaluate.")
    peg = pe.add_mutually_exclusive_group()
    peg.add_argument(
        "--url",
        default=None,
        help="Substring to pick the target tab (default: first/active tab). "
        "Exits 1 when no tab matches — never evaluates in another tab.",
    )
    peg.add_argument(
        "-T",
        "--target",
        default=None,
        metavar="TID",
        help="Evaluate in exactly the tab with this CDP target id (the id "
        "`open -N` printed), over raw CDP on that tab's own websocket — no "
        "Playwright attach, so another tab cannot slow it down. Exits 1 when "
        "the target is gone. Trade-off: the result is returned by value, so "
        "only JSON-serialisable values survive (undefined prints null), not "
        "Playwright's richer serialisation. Mutually exclusive with --url.",
    )
    pe.add_argument(
        "-t",
        "--timeout",
        type=_positive_seconds,
        default=EVAL_TIMEOUT_S,
        metavar="SECONDS",
        help=f"hard deadline for the whole eval, attach included (default "
        f"{EVAL_TIMEOUT_S:g}). On expiry: a ❌ line and exit 1. JS already "
        "running in the page is NOT stopped.",
    )


def _add_journal_parser(sub: Any) -> None:
    """The `journal` subcommand: tail/filter the append-only journal."""
    pjn = sub.add_parser(
        "journal",
        help="Show the append-only journal (origins only): who launched, switched "
        "or stopped the browser, logins, window raises, client (un)registrations.",
    )
    pjn.add_argument(
        "-n",
        "--lines",
        type=int,
        default=50,
        help="show the last N entries (default 50; 0 = all, incl. rotated files)",
    )
    pjn.add_argument(
        "-e",
        "--event",
        default=None,
        help="only this event: up, switch, down, login, bring_to_front, register, "
        "unregister, register_refused, revert_headed, headed_lease, guided_login, "
        "maintenance, client_pause, client_resume, watchdog_recover",
    )
    pjn.add_argument(
        "-j", "--json", action="store_true", help="print the raw JSON lines"
    )


def _add_force_maintenance(parser: argparse.ArgumentParser) -> None:
    """`-F/--force-maintenance` for `down` and `switch`."""
    parser.add_argument(
        "-F",
        "--force-maintenance",
        action="store_true",
        help="act even while a guided login (agent-login.py -g) owns the browser "
        "— it loses its browser (otherwise exit 75, busy).",
    )


def _add_down_parser(sub: Any) -> None:
    """The `down` subcommand."""
    pdn = sub.add_parser("down", help="Quit the shared browser.")
    pdn.add_argument(
        "-f",
        "--force",
        action="store_true",
        help="Stop even while registered CDP clients (e.g. the Playwright MCP "
        "server) are attached — they lose their connection.",
    )
    _add_force_maintenance(pdn)


def _add_guided_parsers(sub: Any) -> None:
    """`assisted-login` (the human entry) and the internal `maintenance-watchdog`."""
    pal = sub.add_parser(
        "assisted-login",
        help="Human-only guided login for SITE: confirm by typing the site name "
        "on your terminal, then log in through a remote view of a headless tab "
        "(B); as fallback in the shown window (A). No terminal (an agent) → exit 2.",
    )
    pal.add_argument("site", help="Site to log into (e.g. slack, notion, anibis).")
    pal.add_argument(
        "-u",
        "--url",
        default=None,
        help="where the login starts (default: the site's known login URL)",
    )
    pal.add_argument(
        "-a",
        "--fallback-window",
        action="store_true",
        help="skip the remote view: log in in the shown shared window (path A)",
    )
    pal.add_argument(
        "-f",
        "--force",
        action="store_true",
        help="start even with UNREGISTERED CDP clients attached (they are not "
        "paused and keep running)",
    )
    pmw = sub.add_parser(
        "maintenance-watchdog",
        help="(internal) recovery watchdog a guided login starts for itself",
    )
    pmw.add_argument(
        "-n", "--nonce", required=True, help="the guided login's owner nonce (prefix)"
    )


def _add_close_parser(sub: Any) -> argparse.ArgumentParser:
    """The `close` subparser; returned so `parse_args` can reject bad mixes."""
    pcl: argparse.ArgumentParser = sub.add_parser(
        "close",
        help="Close tabs you own: by CDP target id (-i, the ids `open -N` "
        "printed), or — manual cleanup only — by exact URL. Takes the "
        "interaction lease, re-checks each tab right before closing it, and "
        "never closes the last tab (opens a blank keep-alive first). Exit 0 "
        "when every requested tab is closed or already gone (also: no match, "
        "browser down); 1 on a refused URL, lease timeout, unreadable tab list, "
        "deadline hit, failed close or failed keep-alive.",
    )
    pcl.add_argument(
        "urls",
        nargs="*",
        metavar="URL",
        help="close every tab whose URL equals one of these, compared without "
        "query, fragment and trailing slash. http(s) URLs only. For cleaning up "
        "leftover tabs by hand; tools close by -i.",
    )
    pcl.add_argument(
        "-i",
        "--id",
        nargs="+",
        dest="ids",
        default=None,
        metavar="TID",
        help="close the tabs with these CDP target ids (from `open -N`). A "
        "missing id counts as already gone.",
    )
    pcl.add_argument(
        "-n",
        "--dry-run",
        action="store_true",
        help="only print `would close:` per matching tab; close nothing.",
    )
    pcl.add_argument(
        "-w",
        "--wait",
        type=_positive_seconds,
        default=CLOSE_WAIT_S,
        metavar="SECONDS",
        help=f"how long to wait for the interaction lease (default "
        f"{CLOSE_WAIT_S:g}, capped by what is left of -d). On timeout: exit 1, "
        "nothing closed.",
    )
    pcl.add_argument(
        "-d",
        "--deadline",
        type=_positive_seconds,
        default=CLOSE_DEADLINE_S,
        metavar="SECONDS",
        help=f"one overall deadline for the whole command (default "
        f"{CLOSE_DEADLINE_S:g}): the lease wait, every re-list and every close "
        "get only what is left. Tabs not reached in time: ❌, exit 1.",
    )
    return pcl


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
            "  ./browser.py switch headless    # revert a headed browser (stop + relaunch)\n"
            "  ./browser.py status             # CDP health + tabs (origins only) + lifecycle\n"
            "  ./browser.py clients            # who is attached over CDP\n"
            "  ./browser.py journal -n 20 -e up  # who launched the browser, lately\n"
            "  ./browser.py doctor             # full health check (disposable tab)\n"
            "  ./browser.py open https://portal.cscs.ch/profile/\n"
            "  ./browser.py eval -t 20 'document.title'\n"
            "  ./browser.py open -N https://example.org/   # own tab → target=<id>\n"
            "  ./browser.py eval -T <id> 'location.host'   # eval in exactly that tab\n"
            "  ./browser.py close -i <id>      # close the tab you opened\n"
            "  ./browser.py close -n https://app.example.com/login  # dry run, by URL\n"
            "  ./browser.py status -p          # + mark tabs that answer no CDP\n"
            "  ./browser.py close-hung         # close such tabs (asks first)\n"
            "  ./browser.py token              # cache the CSCS portal token\n"
            "  ./browser.py cscs-store-creds   # one-time: cache CSCS creds in keychain\n"
            "  ./browser.py cscs-login         # auto-login to CSCS (keychain, no Touch ID)\n"
            "  ./browser.py store-creds biopolwifi  # one-time: cache Cloudpath portal creds\n"
            "  ./browser.py login biopolwifi   # auto-login to the Cloudpath MDU WiFi portal\n"
            "  ./browser.py broker-sites       # sites the login broker may log into\n"
            "  ./browser.py login ricardo      # broker site: session bundle, no password\n"
            "  ./browser.py logout ricardo     # drop that session again\n"
            "  ./browser.py import-safari -n anibis  # Safari cookies (names only)\n"
            "  ./browser.py import-safari anibis     # reuse your Safari session\n"
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
    pup = sub.add_parser(
        "up",
        help="Launch the shared browser, always HEADLESS (idempotent); a headed "
        "browser without a live guided-login lease is switched back to headless.",
    )
    pup.add_argument(
        "-H",
        "--headless",
        action="store_true",
        help="No-op, kept for compatibility: `up` is always headless. "
        "($CLAUDE_BROWSER_HEADLESS is ignored too.)",
    )
    pst = sub.add_parser(
        "status",
        help="Show CDP health, version, open tabs (origins only), and the lifecycle "
        "record.",
    )
    pst.add_argument(
        "-f",
        "--full-urls",
        action="store_true",
        help="print each tab's full URL — path, query and fragment. UNSAFE from an "
        "agent session: in-flight auth tabs carry codes/tokens and status output "
        "lands in logs and LLM transcripts. Default: origin only.",
    )
    pst.add_argument(
        "-p",
        "--probe",
        action="store_true",
        help="also probe every tab over raw CDP (read-only Runtime.evaluate('1'), "
        f"{PROBE_BUDGET_S:g}s budget) and mark the ones that answer nothing: "
        "'⚠ unresponsive' (such a tab blocks every Playwright attach — see "
        "close-hung) or '? indeterminate'. Exit 1 when the tab list is unreadable.",
    )
    pch = sub.add_parser(
        "close-hung",
        help="Close tabs whose renderer answers no CDP command (they block every "
        "Playwright attach). Closes only tabs that failed three consecutive CDP "
        "probes; a responsive tab is never a candidate. Asks first.",
    )
    pch.add_argument(
        "-y",
        "--yes",
        action="store_true",
        help="close without asking (default: list the candidates and ask; no TTY "
        "without -y closes nothing and exits 1).",
    )
    pcl = _add_close_parser(sub)
    psw = sub.add_parser(
        "switch",
        help="Transactional mode switch: stop the browser and relaunch it in MODE "
        "on the SAME profile (every login persists). `headed` only for the holder "
        "of the live guided-login lease (agent-login.py -g SITE); else exit 2.",
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
    _add_force_maintenance(psw)
    sub.add_parser(
        "clients",
        help="Show the registered CDP clients plus any unregistered ones (a "
        "switch refuses while those are attached).",
    )
    _add_journal_parser(sub)
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
    _add_down_parser(sub)
    _add_open_eval_parsers(sub)
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
        "slack, notion, biopolwifi, switch).",
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

    # --- login broker (Bitwarden agent-logins; PLAN_login-broker.md) ---
    sub.add_parser(
        "broker-sites",
        help="List the login broker's sites: id, fill origins, status (exit 3 "
        "when no broker answers).",
    )
    plo = sub.add_parser(
        "logout",
        help="Remove the broker's own profile for SITE and delete SITE's "
        "allowlisted cookies from the shared browser.",
    )
    plo.add_argument("site", help="Broker site to log out.")
    pis = sub.add_parser(
        "import-safari",
        help="Copy SITE's session cookies from Safari into the shared browser "
        "(sites in broker/safari_cookies.SAFARI_SITES that the broker lists; "
        "bot-check cookies never travel; values are never printed).",
    )
    pis.add_argument(
        "site", help=f"Site to import ({', '.join(_safari.SAFARI_SITES)})."
    )
    pis.add_argument(
        "-n",
        "--dry-run",
        action="store_true",
        help="only list the cookies that would be copied (names, never values)",
    )
    _add_guided_parsers(sub)
    sub.add_parser(
        "login-cscs-assisted",
        help="Human-only: the pre-broker CSCS login (keychain / 1Password), "
        "refused without a terminal.",
    )
    args = p.parse_args()
    if args.cmd == "close":
        _check_close_args(pcl, args)
    return args


def _check_close_args(pcl: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    """`close` needs URLs XOR ids; exits 2 (argparse) otherwise."""
    if bool(args.urls) == bool(args.ids):
        pcl.error("give either URL… or -i/--id TID…, not both and not neither")
    if any("/" in tid for tid in args.ids or []):
        # `-i` is nargs="+": a URL after the ids would be read as an id.
        pcl.error("-i/--id takes CDP target ids, not URLs")


def ensure_deps():  # literal "def ensure_deps():" required by pre-commit hook
    """Auto-create an isolated venv (NOT cscs-api's) and re-exec into it.

    Browser deps (playwright) are heavy, so they live in a dedicated venv under
    ~/.cache to avoid bloating the cscs-api client's .venv.
    """
    try:
        import playwright  # noqa: F401  # pylint: disable=unused-import
        import pyotp  # noqa: F401  # pylint: disable=unused-import
        import requests  # noqa: F401  # pylint: disable=unused-import
        import websockets  # noqa: F401  # pylint: disable=unused-import

        return
    except ImportError:
        pass

    venv_dir = Path.home() / ".cache" / "claude-browser" / "venv"
    venv_python = venv_dir / "bin" / "python3"
    deps = ["playwright", "requests", "pyotp", "websockets>=15"]
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
        print("Installing missing browser deps (pyotp, websockets)…", file=sys.stderr)
        _pip_install()
        os.execv(str(venv_python), [str(venv_python), *sys.argv])

    print(
        "First run: creating browser venv (playwright, requests, pyotp, websockets)...",
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


def _cdp_new_tab(port: int, url: str = "about:blank", timeout: float = 5.0) -> bool:
    """Create a tab over the CDP HTTP endpoint; True if Chrome created one.

    ``PUT /json/new`` is the ONLY way to get a page into a browser that has
    none — every Playwright API needs a browser context, and a Chromium with
    zero page targets exposes none (see `_ensure_page_target`). PUT, not GET:
    Chrome rejects the GET form of /json/new since 111.
    """
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/json/new?{url}", method="PUT"
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return 200 <= int(r.status) < 300
    except (urllib.error.URLError, OSError, ValueError):
        return False


def _page_targets(port: int) -> list[dict]:
    """The browser's page targets (tabs) as reported by ``/json/list``."""
    targets = _cdp_get(port, "/json/list")
    if not isinstance(targets, list):
        return []
    return [t for t in targets if isinstance(t, dict) and t.get("type") == "page"]


def _ensure_page_target(port: int, timeout: float = 5.0) -> None:
    """Guarantee the browser has >=1 tab before Playwright attaches to it.

    A Chromium whose last tab was closed keeps running with zero page targets,
    and ``connect_over_cdp`` then fails for EVERY consumer with "Protocol error
    (Browser.setDownloadBehavior): Browser context management is not supported"
    — Playwright finds no browser context to adopt. One blank tab restores it
    (tp#317). It is not litter: `cmd_open` and `_pick_page` prefer reusing a
    blank tab (`_is_blank`) over creating another one. Best effort — if the tab
    cannot be created we fall through and let `connect_over_cdp` raise the real
    error rather than masking it with one of our own.
    """
    if _page_targets(port):
        return
    if not _cdp_new_tab(port):
        return
    deadline = time.time() + timeout
    while not _page_targets(port) and time.time() < deadline:
        time.sleep(0.1)


def _is_up(port: int) -> bool:
    return _cdp_get(port, "/json/version") is not None


# ---------------------------------------------------------------------------
# Raw CDP over one websocket — the path that still works when Playwright hangs
# ---------------------------------------------------------------------------
# Playwright's `connect_over_cdp` attaches to EVERY page target and waits until
# each one answers its initialisation commands, so a single tab whose renderer
# stopped answering CDP blocks every attach (tp#693). These helpers talk to ONE
# target (or the browser endpoint) directly, under a hard monotonic deadline,
# so they can diagnose, and close, such a tab. They are registration-free on
# purpose: `down`/`switch` call `_cdp_browser_close` while holding the client
# gate exclusively (see the deadlock rule in the client-coordination section);
# the COMMANDS built on them (`status -p`, `close-hung`, `doctor`) register.

# Per-connection caps inside a call's budget: the TCP connect + websocket
# handshake, and the closing handshake. Both are ALSO capped by what is left of
# the budget — events or a slow close can never extend a call.
CDP_WS_OPEN_TIMEOUT_S = 1.0
CDP_WS_CLOSE_TIMEOUT_S = 1.0
# `_probe_targets`: the shared budget of one probe round, and the thread cap.
PROBE_BUDGET_S = 6.0
PROBE_MAX_TARGETS = 32


@dataclass
class CdpResult:
    """Outcome of one `_cdp_ws_call`.

    ``status`` is ``ok`` (a reply with our id arrived — including a CDP error
    reply, which still proves the target answers), ``timeout`` (no reply within
    the budget) or ``transport-error``. ``opened`` says whether the websocket
    handshake completed, ``sent`` whether the command went out: a connection
    dropped AFTER sending is how a target that closes itself (``Browser.close``)
    answers.
    """

    status: str
    opened: bool = False
    sent: bool = False
    result: dict | None = None
    error: str = ""


def _cdp_ws_call(
    ws_url: str, method: str, params: dict | None = None, budget_s: float = 5.0
) -> CdpResult:
    """Send ONE CDP command over its own websocket; wait for the reply by id.

    One monotonic deadline covers the whole call — connect, handshake, reply
    and close. Events (messages without our id) are ignored and never extend
    it. Never raises: every failure is a tagged `CdpResult`.
    """
    deadline = time.monotonic() + budget_s

    def left() -> float:
        return max(0.0, deadline - time.monotonic())

    try:
        from websockets.sync.client import connect as ws_connect
    except ImportError as exc:
        return CdpResult("transport-error", error=f"websockets unavailable: {exc}")
    out = CdpResult("timeout")
    try:
        with ws_connect(
            ws_url,
            open_timeout=max(0.01, min(CDP_WS_OPEN_TIMEOUT_S, left())),
            close_timeout=max(0.01, min(CDP_WS_CLOSE_TIMEOUT_S, left())),
            proxy=None,  # 127.0.0.1 only — never route through $ALL_PROXY
            compression=None,
            max_size=None,  # a CDP reply (a frame tree, a screenshot) can be big
            ping_interval=None,
            user_agent_header=None,
            # No Origin header: without --remote-allow-origins Chrome answers
            # 403 to any WebSocket that sends one (tp#836).
            origin=None,
        ) as ws:
            out.opened = True
            _cdp_ws_exchange(ws, method, params, left, out)
            # The closing handshake gets only what is left of the budget.
            ws.close_timeout = max(0.01, min(CDP_WS_CLOSE_TIMEOUT_S, left()))
    except Exception as exc:  # pylint: disable=broad-exception-caught
        if out.opened:
            return out  # only the close failed; the exchange's result is final
        # TimeoutError = the handshake stalled; everything else (refused,
        # websockets' InvalidHandshake family — e.g. a 404 for a vanished
        # target) is a transport error.
        if isinstance(exc, TimeoutError):
            return CdpResult("timeout", error="websocket handshake timed out")
        return CdpResult("transport-error", error=_exc_line(exc))
    return out


def _cdp_ws_exchange(
    ws: Any,
    method: str,
    params: dict | None,
    left: Callable[[], float],
    out: CdpResult,
) -> None:
    """Send one command on the open `ws`; fill `out` from the reply with our id."""
    msg_id = 1
    try:
        ws.send(json.dumps({"id": msg_id, "method": method, "params": params or {}}))
        out.sent = True
        while True:
            remaining = left()
            if remaining <= 0:
                out.status, out.error = "timeout", f"no reply to {method}"
                return
            try:
                raw = ws.recv(timeout=remaining)
            except TimeoutError:
                out.status, out.error = "timeout", f"no reply to {method}"
                return
            try:
                msg = json.loads(raw)
            except ValueError:
                continue
            if isinstance(msg, dict) and msg.get("id") == msg_id:
                out.status = "ok"
                res = msg.get("result")
                out.result = res if isinstance(res, dict) else {}
                if "error" in msg:
                    out.error = str(msg.get("error"))[:200]
                return
    except Exception as exc:  # pylint: disable=broad-exception-caught
        # ConnectionClosed after `sent` is how Browser.close "answers".
        out.status, out.error = "transport-error", _exc_line(exc)


def _browser_ws_url(port: int, timeout: float = 2.0) -> str | None:
    """The browser-level ``webSocketDebuggerUrl`` from ``/json/version``."""
    ver = _cdp_get(port, "/json/version", timeout=timeout)
    url = ver.get("webSocketDebuggerUrl") if isinstance(ver, dict) else None
    return url if isinstance(url, str) and url else None


def _cdp_close_target(
    port: int, target_id: str, budget_s: float = 5.0, ws_url: str | None = None
) -> bool:
    """Close ONE target by id over the browser-level websocket; True on success.

    ``ws_url`` is the browser websocket when the caller already resolved it
    (`close` resolves it once, under its own deadline); None reads it here.
    """
    if ws_url is None:
        ws_url = _browser_ws_url(port)
    if ws_url is None:
        return False
    res = _cdp_ws_call(ws_url, "Target.closeTarget", {"targetId": target_id}, budget_s)
    return (
        res.status == "ok"
        and not res.error
        and bool((res.result or {}).get("success", True))
    )


def _cdp_create_background_target(
    ws_url: str, url: str, budget_s: float = 5.0
) -> str | None:
    """Create a tab over the browser websocket WITHOUT focusing it; its target id.

    ``Target.createTarget`` with ``background: true`` — the raw counterpart of
    `_open_background_tab`, so no Playwright attach (which waits for every
    page target, tp#693/tp#786) is involved. None on any failure.
    """
    res = _cdp_ws_call(
        ws_url, "Target.createTarget", {"url": url, "background": True}, budget_s
    )
    if res.status != "ok" or res.error:
        return None
    tid = (res.result or {}).get("targetId")
    return tid if isinstance(tid, str) and tid else None


def _target_label(url: object, title: object, tid: object) -> str:
    """Origin-only, fail-closed human name of a target: ``title → origin [id8]``.

    Title through `_tab_title`, URL through `_tab_hint` — never a raw URL. A
    non-printable id (ids can come from the command line) renders as ``?``.
    """
    url_s = url if isinstance(url, str) else ""
    return f"{_tab_title(title, url_s)}  →  {_tab_hint(url_s)}  {_id8(tid)}"


def _id8(tid: object) -> str:
    """``[id <first 8 chars>]``; a non-printable id renders as ``[id ?]``."""
    tid_s = str(tid or "")[:8]
    return f"[id {tid_s if tid_s.isprintable() else '?'}]"


@dataclass
class TargetProbe:
    """One page target and how it answered `_probe_targets`' ``Runtime.evaluate``.

    ``outcome``: ``responsive`` | ``unresponsive`` (websocket open, no reply
    within the budget — the renderer is wedged) | ``gone`` (the target
    vanished while we probed) | ``indeterminate`` (any other failure: we
    cannot tell, so nothing may act on it).
    """

    target_id: str
    url: str
    title: str
    outcome: str
    detail: str = ""

    def label(self) -> str:
        """Origin-only, fail-closed human name: ``title → origin [id8]``."""
        return _target_label(self.url, self.title, self.target_id)


@dataclass
class ProbeReport:
    """Result of one `_probe_targets` round.

    ``indeterminate`` (a reason string) means the target list itself could not
    be read — then ``targets`` is empty and NOTHING may be concluded.
    """

    targets: list[TargetProbe]
    indeterminate: str | None = None

    def with_outcome(self, outcome: str) -> list[TargetProbe]:
        """The probed targets whose outcome is `outcome`."""
        return [t for t in self.targets if t.outcome == outcome]


def _probe_one(ws_url: str, budget_s: float, slot: list[CdpResult]) -> None:
    """Thread body: one read-only ``Runtime.evaluate("1")`` into ``slot``."""
    slot.append(_cdp_ws_call(ws_url, "Runtime.evaluate", {"expression": "1"}, budget_s))


def _probe_targets(
    port: int, budget_s: float | None = None, only_ids: Sequence[str] | None = None
) -> ProbeReport:
    """Ask every page target (or just `only_ids`) to evaluate ``1``; classify each.

    Read-only: the ONLY command sent is ``Runtime.evaluate("1")``, over each
    target's own ``webSocketDebuggerUrl`` — Playwright is never involved, so a
    wedged tab cannot block the probe the way it blocks `connect_over_cdp`.
    Targets are probed concurrently (one thread each, at most
    PROBE_MAX_TARGETS; the rest count as indeterminate) under ONE shared
    monotonic budget (`budget_s`, default PROBE_BUDGET_S). Uses its own
    ``/json/list`` read, not `_page_targets`, because that one maps a failure
    to "no tabs".
    """
    budget_s = PROBE_BUDGET_S if budget_s is None else budget_s
    deadline = time.monotonic() + budget_s
    listing = _cdp_get(port, "/json/list", timeout=min(2.0, budget_s))
    if not isinstance(listing, list):
        return ProbeReport([], indeterminate="could not read /json/list")
    pages = [t for t in listing if isinstance(t, dict) and t.get("type") == "page"]
    if only_ids is not None:
        wanted = set(only_ids)
        pages = [t for t in pages if t.get("id") in wanted]
    report = ProbeReport([])
    jobs: list[tuple[TargetProbe, threading.Thread, list[CdpResult]]] = []
    for i, t in enumerate(pages):
        url, title = t.get("url"), t.get("title")
        probe = TargetProbe(
            target_id=str(t.get("id") or ""),
            url=url if isinstance(url, str) else "",
            title=title if isinstance(title, str) else "",
            outcome="indeterminate",
        )
        report.targets.append(probe)
        ws_url = t.get("webSocketDebuggerUrl")
        if i >= PROBE_MAX_TARGETS:
            probe.detail = f"not probed (more than {PROBE_MAX_TARGETS} tabs)"
            continue
        if not isinstance(ws_url, str) or not ws_url:
            # Chrome omits the URL while another client holds an exclusive
            # session (legacy single-client mode) — we cannot tell.
            probe.detail = "no webSocketDebuggerUrl"
            continue
        slot: list[CdpResult] = []
        th = threading.Thread(
            target=_probe_one,
            args=(ws_url, max(0.0, deadline - time.monotonic()), slot),
            name=f"cdp-probe-{probe.target_id[:8]}",
            daemon=True,
        )
        th.start()
        jobs.append((probe, th, slot))
    for probe, th, slot in jobs:
        # The call bounds itself; the small slack only covers thread scheduling.
        th.join(timeout=max(0.0, deadline - time.monotonic()) + 0.5)
        _classify_probe(probe, slot[0] if slot else None)
    _mark_gone(port, [p for p, _th, _slot in jobs if p.outcome == "indeterminate"])
    return report


def _classify_probe(probe: TargetProbe, res: CdpResult | None) -> None:
    """Set `probe`'s outcome from its call result (None = the thread hung)."""
    if res is None:
        probe.detail = "probe thread did not finish"
    elif res.status == "ok":
        probe.outcome = "responsive"
    elif res.status == "timeout" and res.opened:
        probe.outcome, probe.detail = "unresponsive", res.error
    else:
        probe.detail = res.error or res.status


def _mark_gone(port: int, failed: list[TargetProbe]) -> None:
    """Re-list the targets once; a failed probe whose target vanished is ``gone``.

    A socket refused or closed under us usually means the tab closed
    meanwhile; only a fresh listing can tell "gone" from "cannot tell".
    """
    if not failed:
        return
    again = _cdp_get(port, "/json/list", timeout=1.0)
    if not isinstance(again, list):
        return
    alive = {t.get("id") for t in again if isinstance(t, dict)}
    for p in failed:
        if p.target_id not in alive:
            p.outcome = "gone"


def _headless_user_agent(binary: str) -> str | None:
    """A plain desktop-Chrome User-Agent for the headless browser, or None.

    ``--headless=new`` announces itself as ``HeadlessChrome/<v>`` and Cloudflare
    answers that with its "Just a moment…" page (claude.ai, 2026-10-06; the same
    page with the normal UA loads). The version comes from the app's Info.plist
    so the UA matches the real engine; unknown version → no override.
    """
    user_agent: str | None = _engine_user_agent(binary)
    return user_agent


def _browser_mode(port: int) -> str | None:
    """Mode of the RUNNING browser: ``"headless"``, ``"headed"``, or None if down.

    ``/json/version`` names the flavour, but WHERE moved between Chrome versions:
    older builds prefix the ``Browser`` field (``HeadlessChrome/<version>``), while
    Chrome for Testing 151 reports a plain ``Browser`` and only the ``User-Agent``
    says ``HeadlessChrome`` (verified 2026-08-20). Check both. The mode is read off
    the live browser instead of remembered from launch — correct even for a
    browser this process didn't start. A headless browser launched with a plain
    User-Agent (`_headless_user_agent`) shows neither marker, so the root
    process's own ``--headless`` flag counts too.
    """
    ver = _cdp_get(port, "/json/version")
    if not isinstance(ver, dict):
        return None
    headless = str(ver.get("Browser", "")).startswith("Headless") or (
        "HeadlessChrome" in str(ver.get("User-Agent", ""))
    )
    if not headless:
        headless = any(
            "--headless" in (_proc_command(pid) or "") for pid in _find_root_pids(port)
        )
    return "headless" if headless else "headed"


def _guided_login_allowed(port: int, site: str, label: str) -> bool:
    """True when a login may hand the window to a human; else say so and False.

    An ASSISTED step (type an emailed code, finish SSO+2FA) needs Albert at a
    visible window. That exists only inside a guided login: this process tree
    holds the live headed lease (`_headed_lease_held`) and the browser runs
    headed. Everybody else gets ``needs Albert: agent-login.py -g <site>`` and
    the caller exits NEEDS_ALBERT_RC — `browser.py login` never opens a human
    flow on its own (tp#836). No TTY or environment heuristics.
    """
    if _headed_lease_held() and _browser_mode(port) == "headed":
        return True
    print(
        f"❌ {label} needs a login only you can finish.\n"
        f"needs Albert: agent-login.py -g {site}",
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

    The default on every platform is a plain detached ``Popen`` of the binary,
    which yields the real PID. On macOS it must NOT go through ``open -a``
    (tp#703, 2026-09-29): LaunchServices makes the app its own "responsible
    process", and macOS Local Network privacy then judges the browser by its
    own entry, which denied every LAN address (``ERR_ADDRESS_UNREACHABLE`` on
    192.168.178.x and *.dom42.space) even with the toggle ON. Spawned directly,
    the browser inherits the launching terminal's Local Network grant — the
    same binary then reaches the LAN. Measured the same day: the direct launch
    opens its window behind the frontmost app and does not take focus, exactly
    like ``open -g -n``. ``CLAUDE_BROWSER_OPEN_LAUNCH=1`` restores the old
    ``open -g -n`` launch (no PID; the caller resolves it after CDP is up via
    ``_record_running`` → ``_find_root_pids``). Returns the PID if known
    immediately, else None. ``CLAUDE_BROWSER_FOREGROUND=1`` forces the direct
    launch even when ``CLAUDE_BROWSER_OPEN_LAUNCH=1`` is set.
    """
    if os.environ.get(TEST_NO_LAUNCH_ENV) == "1":
        # tests/conftest.py sets this for every test that does not opt in
        # (marker `launches_chrome`): a test must never leave a real Chrome.
        sys.exit(
            "❌ test guard: this test tried to launch a real Chrome "
            f"({TEST_NO_LAUNCH_ENV}=1); mark it `launches_chrome` if it must."
        )
    foreground = os.environ.get("CLAUDE_BROWSER_FOREGROUND") == "1"
    open_launch = os.environ.get("CLAUDE_BROWSER_OPEN_LAUNCH") == "1"
    if sys.platform == "darwin" and open_launch and not foreground and not headless:
        app = _app_bundle(binary)
        if app is not None:
            subprocess.run(
                ["open", "-g", "-n", "-a", str(app), "--args", *flags],
                check=False,
            )
            return None
    proc = subprocess.Popen(  # pylint: disable=consider-using-with
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


# ---------------------------------------------------------------------------
# Journal — append-only, redacted history: who launched / switched / stopped
# ---------------------------------------------------------------------------
# The lifecycle record is ONE current state and a client's registry file is
# deleted on unregister, so neither can say who launched the headed browser at
# 10:42 or which command raised its window. The journal can: one JSON object
# per line in CACHE_DIR/journal.jsonl (so each instance has its own), appended
# with O_APPEND in a single os.write, so concurrent writers interleave whole
# lines, never bytes. Redacted like `status`: any URL in argv or a field is cut
# to its origin, an `eval` expression to its length. Best effort by contract —
# a journal failure warns once on stderr and never changes a command's outcome.

JOURNAL_NAME = "journal.jsonl"
# Past this size the next writer rotates journal.jsonl → .1 → .2 (oldest dropped).
JOURNAL_MAX_BYTES = 10 * 1024 * 1024
JOURNAL_KEEP = 2
# A line stays well under a pipe buffer, so one O_APPEND write lands whole.
JOURNAL_LINE_MAX = 4000
JOURNAL_PARENT_DEPTH = 5
JOURNAL_ARG_MAX = 160
JOURNAL_ARGV_MAX = 16
# URL-shaped substrings, matched fail closed (over-redaction is the price):
#   - the opaque schemes whose payload may hold quotes and spaces (a `data:`
#     page, a `javascript:` bookmarklet) — to the END of the string;
#   - `scheme://` or `scheme:\\` with ANY scheme-shaped prefix, no word
#     boundary needed (`foo_https://…`, `1https://…`), and `http(s):` followed
#     by any run of `/` or `\` including none (`https:h.example/p?t=…`);
#   - `mailto:` / `about:` not glued to a preceding scheme character.
# The URL body runs to the next whitespace and, when any later word of the
# same string carries a `?` or `#`, on through the last such word — so a URL
# with spaces in its path (`https://h/a b?t=…`) cannot leak its query.
_JOURNAL_URL_RE = re.compile(
    r"(?:(?<![A-Za-z])(?:data|javascript|vbscript|blob):.*"
    r"|(?:[A-Za-z][A-Za-z0-9+.-]*:[/\\]{2}|https?:[/\\]*"
    r"|(?<![A-Za-z0-9+.-])(?:mailto|about):)"
    r"\S*(?:(?:\s+\S+)*\s+\S*[?#]\S*)?)",
    re.DOTALL | re.IGNORECASE,
)
# An argument that is just a word (site, mode, target id, number, flag) — any
# other positional gets the origin treatment in the journal's argv.
_JOURNAL_PLAIN_ARG = re.compile(r"[A-Za-z0-9_.@+-]{1,80}")
_JOURNAL_STD_KEYS = (
    "ts",
    "instance",
    "event",
    "pid",
    "ppid",
    "parents",
    "argv",
    "mode",
)
# Events that carry the full parent chain. Client (un)registrations — one per
# attach, on every `eval` — and the watchdog carry pid + ppid only.
_JOURNAL_CHAIN_EVENTS = frozenset(
    {
        "up",
        "switch",
        "down",
        "login",
        "bring_to_front",
        "revert_headed",
        "revert_failed",
        "headed_lease",
        "guided_login",
        "maintenance",
        "watchdog_recover",
    }
)
# Per-process state: the redacted argv main() recorded, the parent chain (looked
# up once), what a command noted for its end event, and the warn-once flag.
_JOURNAL_ARGV: list[list[str]] = []
_JOURNAL_PARENTS: list[list[dict[str, object]]] = []
_JOURNAL_NOTES: dict[str, object] = {}
_JOURNAL_WARNED: list[bool] = []


def _journal_path() -> Path:
    """This instance's journal; ``CLAUDE_BROWSER_JOURNAL_FILE`` overrides (tests)."""
    override = os.environ.get("CLAUDE_BROWSER_JOURNAL_FILE")
    return Path(override) if override else CACHE_DIR / JOURNAL_NAME


def _journal_redact(text: object, limit: int = JOURNAL_ARG_MAX) -> str:
    """`text` with every URL reduced to its origin, printable, at most `limit`.

    The URL pass runs on the whole string BEFORE the cut, so a URL can never be
    half-kept; non-printable characters become ``?`` so a value cannot forge a
    line in the human `journal` output.
    """
    out = _JOURNAL_URL_RE.sub(lambda m: _tab_hint(m.group(0)), str(text))
    if not out.isprintable():
        out = "".join(c if c.isprintable() else "?" for c in out)
    return out if len(out) <= limit else out[: limit - 1] + "…"


def _journal_origin(arg: str) -> str:
    """Origin of a URL argument, fail closed; scheme-less ``host/path`` → host."""
    hint = _tab_hint(arg)
    if hint == "<unparseable url>" and "://" not in arg:
        alt = _tab_hint("//" + arg)  # `open h.example/reset?token=…`
        if alt.startswith("://"):
            return alt[3:]
    return hint


def _journal_wrapped_cmd(cmd: Sequence[str]) -> str:
    """A wrapped command as basename + argument count — never its arguments."""
    rest = list(cmd[1:] if cmd and cmd[0] == "--" else cmd)
    if not rest:
        return "(none)"
    return f"{os.path.basename(rest[0])} (+{len(rest) - 1} args)"


def _journal_set_argv(args: argparse.Namespace) -> None:
    """Record this process's redacted argv; main() calls it once after parsing.

    Structural first, by what each argument IS: an ``eval`` expression becomes
    its length (JS can carry anything, including a value it types into a
    form), `open`'s URL and `close`'s URLs their origin, a ``register-exec``
    command its basename + argument count. Any other value that is not a plain
    word (site, mode, id, number) gets the origin treatment too, and then
    everything goes through `_journal_redact` (URLs anywhere → origin).
    """
    cmd = getattr(args, "cmd", None)
    raw = list(sys.argv[1:])
    tail: list[str] = []
    if cmd == "register-exec":
        wrapped = list(getattr(args, "cmd_", None) or [])
        if wrapped and raw[-len(wrapped) :] == wrapped:
            raw = raw[: -len(wrapped)]
            if wrapped[0] == "--":
                raw.append("--")
        tail = [_journal_wrapped_cmd(wrapped)]
    js = getattr(args, "js", None) if cmd == "eval" else None
    urls: set[str] = set()
    if cmd == "open" and isinstance(getattr(args, "url", None), str):
        urls.add(args.url)
    if cmd == "close":
        urls.update(u for u in getattr(args, "urls", None) or [] if isinstance(u, str))
    argv = [os.path.basename(sys.argv[0]) if sys.argv else "browser.py"]
    for arg in raw:
        if js and arg == js:
            argv.append(f"<js: {len(arg)} chars>")
        elif arg in urls:
            argv.append(_journal_origin(arg))
        elif arg.startswith("-") and "=" in arg:
            flag, _, value = arg.partition("=")
            plain = _JOURNAL_PLAIN_ARG.fullmatch(value)
            argv.append(f"{flag}={value if plain else _journal_origin(value)}")
        elif arg.startswith("-") or _JOURNAL_PLAIN_ARG.fullmatch(arg):
            argv.append(arg)
        else:
            argv.append(_journal_origin(arg))
    _JOURNAL_ARGV[:] = [_journal_argv_redacted(argv + tail)]


def _journal_argv_redacted(argv: Sequence[str]) -> list[str]:
    """`argv` redacted per element and capped in count."""
    out = [_journal_redact(a) for a in argv[:JOURNAL_ARGV_MAX]]
    if len(argv) > JOURNAL_ARGV_MAX:
        out.append(f"<+{len(argv) - JOURNAL_ARGV_MAX} args>")
    return out


def _journal_argv() -> list[str]:
    """The argv main() recorded, else a generically redacted ``sys.argv``."""
    if _JOURNAL_ARGV:
        return _JOURNAL_ARGV[0]
    return _journal_argv_redacted(
        [os.path.basename(sys.argv[0]) if sys.argv else "?", *sys.argv[1:]]
    )


def _journal_parent_chain() -> list[dict[str, object]]:
    """Up to JOURNAL_PARENT_DEPTH ancestors as ``[{"pid", "comm"}, …]``, parent first.

    ONE ``ps -A`` call (2 s bound), cached for the process. Called ONLY from
    `_journaled_dispatch` before the command runs — never from `_journal`
    itself — so no ``ps`` ever runs while this process holds the registry gate
    or the interaction lease. Any failure (no ``ps``, the timeout, garbage
    output) yields an empty chain; it never raises.
    """
    if _JOURNAL_PARENTS:
        return _JOURNAL_PARENTS[0]
    chain: list[dict[str, object]] = []
    try:
        r = subprocess.run(
            ["ps", "-A", "-o", "pid=", "-o", "ppid=", "-o", "comm="],
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
            env={**os.environ, "LC_ALL": "C"},
        )
        table: dict[int, tuple[int, str]] = {}
        for line in str(r.stdout or "").splitlines():
            parts = line.split(None, 2)
            if len(parts) == 3 and parts[0].isdigit() and parts[1].isdigit():
                table[int(parts[0])] = (int(parts[1]), parts[2].strip())
        pid = os.getppid()
        while pid > 0 and len(chain) < JOURNAL_PARENT_DEPTH and pid in table:
            ppid, comm = table[pid]
            chain.append({"pid": pid, "comm": _journal_redact(comm, 100)})
            if pid in (1, ppid):
                break
            pid = ppid
    except Exception:  # pylint: disable=broad-exception-caught
        pass
    _JOURNAL_PARENTS[:] = [chain]
    return chain


def _journal_note(**fields: object) -> None:
    """Add fields to the END event main() writes for this command (e.g. ``flow``)."""
    _JOURNAL_NOTES.update(fields)


def _journal_warn(exc: BaseException) -> None:
    """Report a journal failure on stderr — once per process, never raising."""
    if _JOURNAL_WARNED:
        return
    _JOURNAL_WARNED.append(True)
    with contextlib.suppress(Exception):
        print(
            f"⚠ journal: not recorded ({_journal_path()}): {_exc_line(exc)}",
            file=sys.stderr,
        )


def _journal_encode(rec: dict[str, object]) -> bytes:
    """One JSON line ≤ JOURNAL_LINE_MAX; shrinks argv/parents, then minimal."""
    for attempt in range(3):
        line = json.dumps(rec, ensure_ascii=True, separators=(",", ":")) + "\n"
        if len(line) <= JOURNAL_LINE_MAX:
            return line.encode()
        if attempt == 0:
            argv = rec.get("argv")
            parents = rec.get("parents")
            rec = {
                **rec,
                "argv": [*(argv[:3] if isinstance(argv, list) else []), "<truncated>"],
                "parents": parents[:2] if isinstance(parents, list) else [],
            }
        else:
            rec = {k: rec.get(k) for k in ("ts", "instance", "event", "pid", "ppid")}
            rec["truncated"] = True
    return (json.dumps(rec, ensure_ascii=True, separators=(",", ":")) + "\n").encode()


def _journal_append(data: bytes) -> None:
    """Append one encoded line: O_APPEND, a single write, 0600; rotate when big.

    Rotation never waits: the writer that finds the file over
    JOURNAL_MAX_BYTES tries ``flock(LOCK_EX|LOCK_NB)`` on its fd — busy means
    another writer is rotating, so it just appends. Holding the lock it
    re-stats, and shifts ``.1`` → ``.2`` and renames the live file to ``.1``
    only while the path still names the file its fd has open (a writer that
    already rotated changed the inode). Plain appends take no lock, so its own
    line, and any racing writer's, lands in ``.1`` or the new file, never
    nowhere.
    """
    path = _journal_path()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(str(path), os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        if os.fstat(fd).st_size >= JOURNAL_MAX_BYTES:
            _journal_rotate(path, fd)
        with contextlib.suppress(OSError):
            os.fchmod(fd, 0o600)
        os.write(fd, data)
    finally:
        os.close(fd)


def _journal_rotate(path: Path, fd: int) -> None:
    """Rotate `path` if `fd` still names it and no other writer is rotating."""
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        return  # another writer holds it: that writer rotates
    try:
        st = os.fstat(fd)
        cur = os.stat(path)
        if st.st_size < JOURNAL_MAX_BYTES or (cur.st_ino, cur.st_dev) != (
            st.st_ino,
            st.st_dev,
        ):
            return
        for i in range(JOURNAL_KEEP, 1, -1):
            with contextlib.suppress(FileNotFoundError):
                os.replace(f"{path}.{i - 1}", f"{path}.{i}")
        os.replace(path, f"{path}.1")
    except OSError:
        return
    finally:
        with contextlib.suppress(OSError):
            fcntl.flock(fd, fcntl.LOCK_UN)


def _journal_ts() -> str:
    """Local ISO-8601 time with milliseconds and UTC offset, from ONE clock read."""
    now = time.time()
    local = time.localtime(now)
    return (
        time.strftime("%Y-%m-%dT%H:%M:%S", local)
        + f".{int(now * 1000) % 1000:03d}"
        + time.strftime("%z", local)
    )


def _journal(event: str, **fields: object) -> None:
    """Append one redacted event to the journal. Never raises.

    Every event carries who (pid, ppid), how (redacted argv) and the browser
    mode — from ``fields["mode"]`` when the caller knows it, else from the
    lifecycle record. The events in _JOURNAL_CHAIN_EVENTS also carry the
    parent chain — the one `_journaled_dispatch` collected BEFORE the command
    ran; this function never runs ``ps`` (it is called under the registry gate
    and the interaction lease, and from the eval watchdog). String field
    values are redacted again here (URLs → origin), so a caller cannot leak a
    path or query by accident.
    """
    try:
        rec: dict[str, object] = {
            "ts": _journal_ts(),
            "instance": INSTANCE or "default",
            "event": event,
            "pid": os.getpid(),
            "ppid": os.getppid(),
            "argv": _journal_argv(),
        }
        if event in _JOURNAL_CHAIN_EVENTS:
            rec["parents"] = _JOURNAL_PARENTS[0] if _JOURNAL_PARENTS else None
        if "mode" not in fields:
            lrec = _lifecycle_read()
            rec["mode"] = lrec.get("mode") if lrec else None
        for key, value in fields.items():
            rec[key] = (
                _journal_redact(value)
                if isinstance(value, str)
                else value
                if value is None or isinstance(value, (bool, int, float))
                else _journal_redact(value)
            )
        _journal_append(_journal_encode(rec))
    except Exception as exc:  # pylint: disable=broad-exception-caught
        _journal_warn(exc)


def _bring_to_front_skip(mode: str | None, lease_held: bool) -> str | None:
    """Why a raise must NOT happen (``"no-lease"``/``"headless"``), or None. Pure.

    Only the holder of the live headed lease (a guided login Albert started)
    may surface the window, and only while the browser is headed (tp#836).
    """
    if not lease_held:
        return "no-lease"
    if mode != "headed":
        return "headless"
    return None


def _bring_to_front(page: Any, reason: str, port: int | None = None) -> None:
    """Journal a focus-capable ``page.bring_to_front()``, then do it — or skip it.

    Outside a guided login (no headed lease held by this process tree) or in
    a headless browser it is a journaled no-op (``skipped``). Otherwise the
    journal entry is written FIRST so a raise that steals focus is on record
    even when the call itself then fails; the call's own exception propagates
    unchanged — callers keep their existing error handling.
    """
    try:
        origin = _tab_hint(str(getattr(page, "url", "") or ""))
    except Exception:  # pylint: disable=broad-exception-caught
        origin = "<unknown>"
    held = _headed_lease_held()
    mode = _browser_mode(DEFAULT_CDP_PORT if port is None else port) if held else None
    skip = _bring_to_front_skip(mode, held)
    if skip is not None:
        _journal("bring_to_front", command=reason, origin=origin, skipped=skip)
        return
    _journal("bring_to_front", command=reason, origin=origin)
    page.bring_to_front()


def _journal_read_lines(limit: int, event: str | None) -> list[str]:
    """The last `limit` raw journal lines (0 = all), optionally for one event.

    Reads the live file and, when it alone does not hold `limit` matching
    lines, the rotated ``.1``/``.2`` before it — oldest first in the result.
    Lines that are not a JSON object are skipped.
    """
    path = _journal_path()
    files = [path] + [Path(f"{path}.{i}") for i in range(1, JOURNAL_KEEP + 1)]
    picked: list[str] = []
    for f in files:
        try:
            raw = f.read_text(encoding="utf-8", errors="replace").splitlines()
        except FileNotFoundError:
            continue
        chunk = []
        for line in raw:
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            if isinstance(rec, dict) and (event is None or rec.get("event") == event):
                chunk.append(line)
        picked = chunk + picked
        if limit and len(picked) >= limit:
            break
    return picked[-limit:] if limit else picked


def _journal_format(rec: dict) -> str:
    """One human line for a journal record — every value re-redacted."""
    event = _journal_redact(rec.get("event", "?"), 40)
    phase = rec.get("phase")
    head = f"{event}/{_journal_redact(phase, 10)}" if phase else event
    extras = [
        f"{_journal_redact(k, 40)}={_journal_redact(v, 80)}"
        for k, v in rec.items()
        if k not in _JOURNAL_STD_KEYS and k != "phase"
    ]
    mode = rec.get("mode")
    if mode:
        extras.insert(0, f"mode={_journal_redact(mode, 20)}")
    parents = rec.get("parents") or []
    chain = " < ".join(
        f"{os.path.basename(_journal_redact(p.get('comm', '?'), 100))}"
        f"({_journal_redact(p.get('pid', '?'), 10)})"
        for p in parents
        if isinstance(p, dict)
    )
    argv = rec.get("argv") or []
    argv_s = (
        " ".join(_journal_redact(a, 80) for a in argv) if isinstance(argv, list) else ""
    )
    return (
        f"{_journal_redact(rec.get('ts', '?'), 40)}  {head:<22} "
        f"pid {_journal_redact(rec.get('pid', '?'), 10)}  "
        + ("  ".join(extras) + "  " if extras else "")
        + (f"[{argv_s}]" if argv_s else "")
        + (f"  ← {chain}" if chain else "")
    )


def cmd_journal(lines: int, event: str | None, as_json: bool) -> int:
    """Print the tail of the journal: one human line per event, or raw JSON."""
    if lines < 0:
        return _fail("-n/--lines must be >= 0 (0 = everything)")
    picked = _journal_read_lines(lines, event)
    if not picked:
        print(
            f"(no journal entries{f' for event {event!r}' if event else ''} in "
            f"{_journal_path()})"
        )
        return 0
    for line in picked:
        if as_json:
            print(line)
        else:
            print(_journal_format(json.loads(line)))
    return 0


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


def _cdp_browser_close(port: int, budget_s: float = 5.0) -> bool:
    """Ask the browser to quit itself over CDP (``Browser.close``); True if sent.

    The graceful path: Chrome flushes the profile (cookies, sessions) and
    removes its own SingletonLock, neither of which a signal-based kill gets
    right. A dropped connection while the command is in flight is the EXPECTED
    success case (the browser died before answering), so that counts as sent;
    a timeout counts as NOT sent, so `_shutdown_browser` escalates with its
    budget intact. Raw CDP on the browser-level websocket (`_cdp_ws_call`),
    never Playwright: a Playwright attach waits for every tab and one wedged
    renderer stalls it (tp#693). Registration-free on purpose — `switch`/`down`
    call this while they hold the client gate EXCLUSIVELY, and a second fd
    asking for the same gate shared would deadlock against our own hold (see
    the deadlock rule in the client-coordination section).
    """
    ws_url = _browser_ws_url(port)
    if ws_url is None:
        return False
    res = _cdp_ws_call(ws_url, "Browser.close", None, budget_s)
    return res.status == "ok" or (res.status == "transport-error" and res.sent)


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


DOWNLOAD_DIR = CACHE_DIR / "downloads"
# Profile prefs merged into Default/Preferences before every launch (tp#836):
# permission requests default to "block" (2) — together with
# `--deny-permission-prompts` no permission prompt can appear — and downloads
# land in DOWNLOAD_DIR without a Save dialog. Prefs, not a CDP
# `Browser.setDownloadBehavior`: that one is reset when the CDP session that set
# it detaches (measured on CfT 153), and every Playwright attach sets its own.
# `--disable-notifications` is deliberately NOT used: with it, a plain page
# script probing `Notification`/`navigator.permissions` threw on CfT 153, and
# the block pref + `--deny-permission-prompts` already deny notifications.
_PROFILE_PREFS: tuple[tuple[tuple[str, ...], object], ...] = (
    (("profile", "default_content_setting_values", "notifications"), 2),
    (("profile", "default_content_setting_values", "geolocation"), 2),
    (("profile", "default_content_setting_values", "media_stream_camera"), 2),
    (("profile", "default_content_setting_values", "media_stream_mic"), 2),
    (("download", "prompt_for_download"), False),
    (("download", "directory_upgrade"), True),
)


def _profile_pref_values() -> list[tuple[tuple[str, ...], object]]:
    """Every pref `_apply_profile_prefs` enforces, the download dir included."""
    return [*_PROFILE_PREFS, (("download", "default_directory"), str(DOWNLOAD_DIR))]


def _merge_prefs(data: dict, values: Sequence[tuple[tuple[str, ...], object]]) -> bool:
    """Set each dotted-path pref in `data` (in place); True if anything changed."""
    changed = False
    for path, value in values:
        node = data
        for key in path[:-1]:
            nxt = node.get(key)
            if not isinstance(nxt, dict):
                nxt = {}
                node[key] = nxt
            node = nxt
        if node.get(path[-1]) != value:
            node[path[-1]] = value
            changed = True
    return changed


def _apply_profile_prefs() -> str | None:
    """Merge the native-UI prefs into the profile's Preferences; a problem or None.

    Called only by `_launch_and_record` after `_launch_guard` passed, i.e. while
    no browser runs on this profile, so Chrome cannot rewrite the file under
    us. A Preferences file that is not a JSON object is left untouched (a
    rewrite would lose whatever Chrome keeps there); the caller only warns —
    `--deny-permission-prompts` still blocks every permission prompt.
    """
    prefs = PROFILE_DIR / "Default" / "Preferences"
    try:
        DOWNLOAD_DIR.mkdir(parents=True, exist_ok=True)
        data: object = (
            json.loads(prefs.read_text(encoding="utf-8")) if prefs.exists() else {}
        )
        if not isinstance(data, dict):
            return f"{prefs} is not a JSON object — left untouched"
        if not _merge_prefs(data, _profile_pref_values()):
            return None
        prefs.parent.mkdir(parents=True, exist_ok=True)
        tmp = _unique_tmp(prefs)
        tmp.write_text(json.dumps(data), encoding="utf-8")
        tmp.chmod(0o600)
        os.replace(tmp, prefs)
    except (OSError, ValueError) as exc:
        return f"{prefs}: {exc}"
    return None


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
        # No `--remote-allow-origins`: without it Chrome rejects (403) every
        # CDP WebSocket that sends an Origin header, so a web page can never
        # drive this browser. Every consumer (Playwright py/node, websockets
        # in this repo) sends none (tp#836).
        # Native UI: a permission request is denied instead of prompted
        # (notifications/geolocation/camera/mic also default to "block" in the
        # profile prefs, see `_apply_profile_prefs`).
        "--deny-permission-prompts",
        # The window deliberately opens behind the frontmost app and is
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
        user_agent = _headless_user_agent(binary)
        if user_agent:
            flags.append(f"--user-agent={user_agent}")
    pref_problem = _apply_profile_prefs()
    if pref_problem is not None:
        print(f"⚠ profile prefs not applied: {pref_problem}", file=sys.stderr)
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
                    f"(no window; pid {pid or '?'}, CDP http://127.0.0.1:{port}).\n"
                    "  Logins from the profile still apply; a login that needs "
                    "you runs as a guided login: agent-login.py -g <site>.\n"
                    f"  Profile: {PROFILE_DIR}"
                )
            else:
                print(
                    f"✓ Shared browser launched HEADED for the guided login "
                    f"(pid {pid or '?'}, CDP http://127.0.0.1:{port}).\n"
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


def _registry_live_clients(dead: list[dict] | None = None) -> list[dict]:
    """Every LIVE client registration; reaps the files of dead ones on the way
    (their records go into `dead` when the caller passes a list).

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
            if dead is not None and (gone := _read_json_dict(path)) is not None:
                dead.append(gone)
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


# Two fds, the metadata, the gate state and the bookkeeping of one registration:
# splitting them would only scatter one lock-holder's state.
class Registration:  # pylint: disable=too-many-instance-attributes
    """One live client registration (see `_registry_register`); calling it releases.

    Holds the gate SHARED and LOCK_EX on its own metadata file. `update`
    rewrites the metadata in place (the pause protocol of `register-exec`
    records its child's process group and its paused state there);
    `drop_gate`/`retake_gate` let a PAUSED long-lived client stop blocking a
    guided login's exclusive gate while keeping its registration (and so its
    "known client" status for the unregistered-peer check).
    """

    def __init__(  # pylint: disable=too-many-arguments
        self,
        path: Path,
        nonce: str,
        own_fd: int,
        gate_fd: int,
        rec: dict,
    ) -> None:
        self.path = path
        self.nonce = nonce
        self.own_fd = own_fd
        self.gate_fd = gate_fd
        self.rec = rec
        self.gate_held = True
        self.released = False
        self.registered_at = time.monotonic()

    def __call__(self) -> None:
        self.release()

    def update(self, **fields: object) -> None:
        """Merge `fields` into our metadata file (never raises).

        Written padded to the old length, then truncated: a concurrent reader
        sees either the old record or the new one plus trailing blanks, both
        valid JSON — never an empty file.
        """
        self.rec.update(fields)
        data = (json.dumps(self.rec) + "\n").encode()
        try:
            old = os.fstat(self.own_fd).st_size
            os.pwrite(self.own_fd, data.ljust(old), 0)
            os.ftruncate(self.own_fd, len(data))
        except OSError as exc:
            print(
                f"⚠ could not update registration {self.path.name}: {exc}",
                file=sys.stderr,
            )

    def drop_gate(self) -> None:
        """Stop holding the gate shared (the registration itself stays live)."""
        if self.gate_held:
            with contextlib.suppress(OSError):
                fcntl.flock(self.gate_fd, fcntl.LOCK_UN)
            self.gate_held = False

    def retake_gate(self, wait_s: float) -> bool:
        """Hold the gate shared again (bounded); True when held."""
        if not self.gate_held:
            self.gate_held = _flock_wait(self.gate_fd, fcntl.LOCK_SH, wait_s)
        return self.gate_held

    def release(self) -> None:
        """Drop the registration: unlink our file, then both locks. Idempotent."""
        if self.released:
            return
        self.released = True
        current = _read_json_dict(self.path)
        if current is not None and current.get("nonce") not in (None, self.nonce):
            print(
                f"⚠ registration {self.path.name} was overwritten by nonce "
                f"{current.get('nonce')} — leaving it alone (not ours to remove).",
                file=sys.stderr,
            )
        else:
            self.path.unlink(missing_ok=True)
        for fd in (self.own_fd, self.gate_fd):
            with contextlib.suppress(OSError):
                fcntl.flock(fd, fcntl.LOCK_UN)
            with contextlib.suppress(OSError):
                os.close(fd)
        _journal(
            "unregister",
            client=self.rec.get("tool"),
            client_pid=os.getpid(),
            nonce=self.nonce[:12],
            held_ms=int((time.monotonic() - self.registered_at) * 1000),
        )


def _registry_register(
    tool: str,
    purpose: str,
    port: int,
    wait_s: float = REGISTRY_SH_WAIT_S,
    *,
    journal_purpose: str | None = None,
    extra: dict[str, object] | None = None,
) -> Registration:
    """Register this process as an attached CDP client; return its `Registration`
    (call it — or its ``release()`` — to unregister).

    Two locks are taken and held until release: the gate SHARED (so `switch`
    and `down` — which need it exclusively — cannot pull the browser out from
    under a live connection) and LOCK_EX on our own metadata file (which is
    both the liveness signal other readers test and the record of who we are).
    The file is created ``O_EXCL`` and locked BEFORE it is written, so the
    window in which a concurrent reaper could mistake it for debris is as small
    as an open() syscall.

    Fails loud (exit) when the gate cannot be shared within `wait_s`
    (default REGISTRY_SH_WAIT_S; `close` passes what is left of its deadline):
    that means a mode switch or a shutdown is mid-flight, and attaching anyway
    is exactly the race this layer exists to prevent. Refuses with exit 2 while
    a guided login's maintenance record is live and this process does not
    carry its owner token ($CLAUDE_BROWSER_MAINTENANCE): the guided login owns
    the browser for its duration.
    """
    CLIENTS_DIR.mkdir(parents=True, exist_ok=True)
    gate_fd = os.open(str(REGISTRY_GATE), os.O_RDWR | os.O_CREAT, 0o600)
    if not _flock_wait(gate_fd, fcntl.LOCK_SH, wait_s):
        os.close(gate_fd)
        sys.exit(
            "❌ Cannot attach to the shared browser: it is being switched or "
            f"stopped right now (waited {wait_s:.0f}s for the client "
            "gate).\n   Retry in a moment; `browser.py status` shows the "
            "lifecycle state."
        )
    maint = _maint_live()
    owner = _maint_owner() if maint is not None else False
    if maint is not None and not owner:
        _gate_release(gate_fd)
        _journal("register_refused", client=tool, site=maint.get("site"))
        print(_maint_refusal(maint), file=sys.stderr)
        sys.exit(BUSY_RC)
    nonce = uuid.uuid4().hex
    while True:
        path = CLIENTS_DIR / f"{nonce}.json"
        try:
            own_fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
            break
        except FileExistsError:
            nonce = uuid.uuid4().hex  # a 128-bit collision, humoured anyway
        except OSError as exc:
            _gate_release(gate_fd)
            sys.exit(f"❌ Cannot register a CDP client in {CLIENTS_DIR}: {exc}")
    fcntl.flock(own_fd, fcntl.LOCK_EX)  # uncontended by construction
    now = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    rec: dict[str, object] = {
        "nonce": nonce,
        "pid": os.getpid(),
        "pid_start_time": _proc_lstart(os.getpid()),
        "tool": tool,
        "purpose": purpose,
        "port": port,
        "iso": now,
        "heartbeat_iso": now,
    }
    rec.update(extra or {})
    if owner:
        # A guided login's own client: never paused by its own transaction.
        rec["maintenance"] = os.environ.get(MAINTENANCE_ENV, "")
    os.pwrite(own_fd, (json.dumps(rec) + "\n").encode(), 0)
    _journal(
        "register",
        client=tool,
        client_pid=os.getpid(),
        nonce=nonce[:12],
        purpose=purpose if journal_purpose is None else journal_purpose,
        port=port,
    )
    return Registration(path, nonce, own_fd, gate_fd, rec)


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


def _gate_busy(action: str, hint: str = "") -> str:
    """The "clients are still attached" refusal for `action`, naming them.

    `hint` is appended to the closing "Let them finish, then retry" line — the
    command's override, when it has one (`down` passes its `-f/--force`).
    """
    lines = [f"   still attached: {line}" for line in _registry_client_lines()]
    return (
        f"Cannot {action}: registered CDP client(s) did not drain within "
        f"{REGISTRY_EX_WAIT_S:.0f}s.\n"
        + (
            "\n".join(lines)
            or "   (no registration file left — see `browser.py clients`)"
        )
        + f"\n   Let them finish, then retry{hint}."
    )


def _registry_client_lines() -> list[str]:
    """One `_describe_client` line per live registration."""
    return [_describe_client(r) for r in _registry_live_clients()]


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


# ---------------------------------------------------------------------------
# Headless by default — desired mode, maintenance record, preflight revert (tp#836)
# ---------------------------------------------------------------------------
# THE INVARIANT: the shared browser runs HEADLESS unless a live guided-login
# MAINTENANCE RECORD of mode A exists. Only a guided login Albert starts himself
# (`agent-login.py -g SITE` → `browser.py assisted-login SITE`) writes that
# record; mode B (remote viewer) keeps the browser headless, mode A (fallback)
# switches headed for the login and back. With no window there is nothing that
# can take focus, be raised or pop native UI.
#
#   * DESIRED_MODE_FILE records the mode `up` launches in. It is always
#     "headless" (absent = headless); any other value is reported and ignored.
#   * MAINTENANCE_FILE {owner_nonce, pid, pid_start_time, site, mode A|B, state
#     preparing|active, owned_targets, paused, watchdog_pid, started,
#     heartbeat} — ONE record, the single source of truth for "a guided login
#     owns the browser". Phase 2's headed lease IS this record with mode A
#     (a record without a mode is mode A). Refreshed every 10 s. It is LIVE
#     while the owner pid is alive with the recorded start time (no pid
#     reuse), unless the heartbeat is older than 120 s (a hung owner; a Mac
#     asleep for less than that keeps it). The owner exports its nonce as
#     $CLAUDE_BROWSER_MAINTENANCE, so its own `browser.py` children (switch
#     headed, login SITE, open -N, logged-in …) are recognised as the owner.
#   * While a record is live, a NEW client registration without that nonce
#     refuses (exit 2): the guided login owns the browser (see `_maintenance`).
#   * Every connecting command first reverts a headed browser that has NO
#     live mode-A record (`_preflight`), before it takes the registry gate
#     itself. A revert that fails only warns: the command proceeds and the next
#     command tries again (a lock-out of every agent is worse than a headed
#     minute).

DESIRED_MODE_FILE = CACHE_DIR / "desired-mode.json"
MAINTENANCE_FILE = CACHE_DIR / "maintenance.json"
# Serialises take/heartbeat/update/release of the record (never held for long).
MAINTENANCE_LOCK = CACHE_DIR / ".maintenance.lock"
MAINTENANCE_ENV = "CLAUDE_BROWSER_MAINTENANCE"
MAINTENANCE_HEARTBEAT_S = 10.0
# A live owner pid keeps the record; only a heartbeat older than this (a hung
# owner) ends it. Generous on purpose: a Mac asleep for a minute must not cost
# Albert his guided-login window.
MAINTENANCE_HUNG_S = 120.0
# Exit code of a login that needs Albert (same meaning as the broker's 4).
NEEDS_ALBERT_RC = 4
# `logged-in` runs its active check in a fresh background tab, never a picked
# one, when this is "1" (the guided login's own probes set it).
PROBE_BACKGROUND_ENV = "CLAUDE_BROWSER_PROBE_BACKGROUND"
# Exit code while a guided login owns the browser (EX_TEMPFAIL): "busy, retry
# later" — never "not logged in" (2), so checks skip instead of logging in.
BUSY_RC = 75
# How long a preflight revert waits for registered clients to drain.
PREFLIGHT_GATE_WAIT_S = 5.0
# Commands that never drive the browser over CDP, plus the lifecycle commands
# that handle the mode themselves: no preflight revert for them.
_PREFLIGHT_SKIP_CMDS = frozenset(
    {
        "up",
        "status",
        "journal",
        "down",
        "switch",
        "clients",
        "login-log",
        "store-creds",
        "forget-creds",
        "cscs-store-creds",
        "cscs-forget-creds",
        "broker-sites",
        # Recovery tools: they must work in exactly the state a revert is for.
        "doctor",
        "close-hung",
        "close",
        "maintenance-watchdog",
    }
)


class HeadedLeaseError(RuntimeError):
    """The maintenance record (headed lease) cannot be taken (see the message)."""


class HeadedLeaseBusy(HeadedLeaseError):
    """Another live guided login holds the maintenance record (or is taking it)."""


def _unique_tmp(path: Path) -> Path:
    """A sibling temp path no other process, thread or call can pick."""
    tag = f"{os.getpid()}.{threading.get_ident()}.{uuid.uuid4().hex[:8]}"
    return path.with_name(f".{path.name}.{tag}.tmp")


def _json_write_atomic(path: Path, data: dict) -> None:
    """Write `data` as JSON to `path` via a unique sibling tmp + ``os.replace``."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = _unique_tmp(path)
    tmp.write_text(json.dumps(data) + "\n", encoding="utf-8")
    tmp.chmod(0o600)
    os.replace(tmp, path)


def _desired_mode_state() -> str:
    """What the desired-mode file says, for `doctor`/`status` (never raises)."""
    if not DESIRED_MODE_FILE.exists():
        return "headless (no file — the default)"
    data = _read_json_dict(DESIRED_MODE_FILE)
    mode = data.get("mode") if data else None
    if mode == "headless":
        return "headless"
    return f"{mode!r} is not allowed — treated as headless"


def _desired_mode() -> str:
    """The mode `up` launches in: always ``"headless"`` (tp#836).

    Headed exists only inside a live mode-A maintenance record, so nothing
    persistent can ask for it; a stray value in the file is reported by
    `doctor`, not obeyed.
    """
    return "headless"


def _desired_mode_write() -> None:
    """Persist ``{"mode": "headless"}``; a write failure only warns."""
    try:
        _json_write_atomic(DESIRED_MODE_FILE, {"mode": "headless"})
    except OSError as exc:
        print(f"⚠ could not write {DESIRED_MODE_FILE}: {exc}", file=sys.stderr)


def _pid_alive(pid: int) -> bool:
    """True while `pid` exists (signal 0; EPERM = exists, another user's)."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except OSError:
        return True  # EPERM, or cannot tell: never declare an owner dead on a hiccup
    return True


def _headed_lease_state(rec: dict | None, now: float | None = None) -> str:
    """``live``, or why not: ``none``, ``invalid``, ``hung owner``,
    ``dead pid`` or ``pid reused`` — the liveness rule of the maintenance record.

    The owner pid decides: alive with the recorded start time = LIVE, whatever
    the heartbeat's age (a Mac asleep for 40 s is not a dead owner) — unless the
    heartbeat is older than MAINTENANCE_HUNG_S (a hung owner). A recycled pid
    always has a later start time. When ``ps`` cannot read the start time of a
    live pid (timeout, failure) the answer is unknown, i.e. LIVE: a ``ps``
    hiccup must never revert a guided login's window.
    """
    if rec is None:
        return "none"
    pid, beat = rec.get("pid"), rec.get("heartbeat")
    pid_ok = isinstance(pid, int) and not isinstance(pid, bool) and pid > 0
    fields_ok = bool(rec.get("owner_nonce")) and bool(rec.get("pid_start_time"))
    if not (pid_ok and fields_ok and isinstance(beat, (int, float))):
        return "invalid"
    assert isinstance(pid, int) and isinstance(beat, (int, float))  # for mypy
    age = (time.time() if now is None else now) - float(beat)
    if age > MAINTENANCE_HUNG_S:
        return "hung owner"
    if not _pid_alive(pid):
        return "dead pid"
    lstart = _proc_lstart(pid)
    if lstart is not None and lstart != rec.get("pid_start_time"):
        return "pid reused"
    return "live"


def _maint_mode(rec: dict) -> str:
    """``"B"`` (remote viewer, headless) or ``"A"`` (window) — no mode = A."""
    return "B" if rec.get("mode") == "B" else "A"


def _maint_live() -> dict | None:
    """The live maintenance record (any mode), or None."""
    rec = _read_json_dict(MAINTENANCE_FILE)
    return rec if _headed_lease_state(rec) == "live" else None


def _headed_lease_live() -> dict | None:
    """The live maintenance record of mode A (the "headed lease"), or None."""
    rec = _maint_live()
    return rec if rec is not None and _maint_mode(rec) == "A" else None


def _maint_owner() -> bool:
    """True when THIS process tree owns the live maintenance record (any mode).

    The owner exports its nonce in $CLAUDE_BROWSER_MAINTENANCE; a child sees
    the same value, a stranger does not know it. No TTY or other heuristics.
    """
    nonce = os.environ.get(MAINTENANCE_ENV, "")
    if not nonce:
        return False
    rec = _maint_live()
    return rec is not None and rec.get("owner_nonce") == nonce


def _headed_lease_held() -> bool:
    """True when THIS process tree owns the live record AND it is mode A."""
    return _maint_owner() and _headed_lease_live() is not None


def _headed_lease_describe() -> str:
    """One line on the maintenance record, for `status`/`doctor`/the journal."""
    rec = _read_json_dict(MAINTENANCE_FILE)
    state = _headed_lease_state(rec)
    if rec is None:
        return "none"
    who = (
        f"site {rec.get('site')!s}, mode {_maint_mode(rec)}, pid {rec.get('pid')!s}, "
        f"since {rec.get('started')!s}"
    )
    return f"{state} ({who})"


def _maint_refusal(rec: dict) -> str:
    """The refusal a registrant without the owner token gets while `rec` lives
    (first line machine-stable: ``busy: guided login for SITE in progress``)."""
    until = rec.get("until")
    when = (
        time.strftime("%H:%M", time.localtime(float(until)))
        if isinstance(until, (int, float)) and not isinstance(until, bool)
        else "?"
    )
    return (
        f"busy: guided login for {rec.get('site')!s} in progress (until ~{when})\n"
        f"   The guided login (agent-login.py -g {rec.get('site')!s}, mode "
        f"{_maint_mode(rec)}, pid {rec.get('pid')!s}) owns the shared browser; "
        f"retry after it ends (exit {BUSY_RC} = busy, not logged out)."
    )


def _maint_blocks(force_maintenance: bool) -> str | None:
    """Why `down`/`switch` must not touch the browser now, or None.

    A live guided login owns the browser: only its own process tree (the owner
    token) may switch it; everybody else needs ``-F/--force-maintenance``.
    """
    rec = _maint_live()
    if rec is None or force_maintenance or _maint_owner():
        return None
    return (
        _maint_refusal(rec)
        + "\n   -F/--force-maintenance overrides (the guided login loses its browser)."
    )


@contextlib.contextmanager
def _maint_locked(wait_s: float = 5.0) -> Iterator[bool]:
    """Hold MAINTENANCE_LOCK for the block; yields False when it timed out."""
    MAINTENANCE_LOCK.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(MAINTENANCE_LOCK), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        yield _flock_wait(fd, fcntl.LOCK_EX, wait_s)
    finally:
        os.close(fd)  # closing the fd drops its flock


def _maint_update(nonce: str, **fields: object) -> bool:
    """Merge `fields` (+ a fresh heartbeat) into the record iff it is ours.

    Compare-before-write under the lock: a record that names another owner (or
    is gone) is never written — a heartbeat or an update never resurrects a
    record. Returns True when written. OSError propagates (the heartbeat
    thread retries; other callers warn).
    """
    with _maint_locked(2.0) as ok:
        if not ok:
            return False
        cur = _read_json_dict(MAINTENANCE_FILE)
        if cur is None or cur.get("owner_nonce") != nonce:
            return False
        _json_write_atomic(
            MAINTENANCE_FILE, {**cur, **fields, "heartbeat": time.time()}
        )
        return True


def _headed_lease_heartbeat(nonce: str, stop: threading.Event) -> None:
    """Refresh the record's heartbeat every MAINTENANCE_HEARTBEAT_S (daemon thread).

    Stops once the record names another owner (or is gone). An OSError (full
    disk, a transient EIO) is logged once and retried on the next beat: giving
    up would make a live guided login look hung.
    """
    warned = False
    while not stop.wait(MAINTENANCE_HEARTBEAT_S):
        try:
            cur = _read_json_dict(MAINTENANCE_FILE)
            if cur is None or cur.get("owner_nonce") != nonce:
                return
            _maint_update(nonce)
        except OSError as exc:
            if not warned:
                print(
                    f"⚠ maintenance-record heartbeat failed (retrying): {exc}",
                    file=sys.stderr,
                )
                warned = True


@contextlib.contextmanager
def _maint_record(site: str, mode: str = "A", state: str = "active") -> Iterator[str]:
    """Hold the MAINTENANCE RECORD for the block; yield the owner nonce.

    Refuses (`HeadedLeaseBusy`) while another live record exists. Sets
    $CLAUDE_BROWSER_MAINTENANCE for the block so this process's `browser.py`
    children are the owner; restores it on exit. Release is
    compare-before-release: the file is removed only while it still carries
    our nonce. The record alone — `_maintenance` is the full transaction.
    """
    with _maint_locked(5.0) as ok:
        if not ok:
            raise HeadedLeaseBusy("another process is taking the maintenance record")
        current = _read_json_dict(MAINTENANCE_FILE)
        if _headed_lease_state(current) == "live" and current is not None:
            raise HeadedLeaseBusy(
                f"a guided login already owns the browser (site "
                f"{current.get('site')}, mode {_maint_mode(current)}, pid "
                f"{current.get('pid')})"
            )
        nonce = uuid.uuid4().hex
        lstart = _proc_lstart(os.getpid())
        if not lstart:
            raise HeadedLeaseError(
                "cannot read this process's start time (`ps -o lstart=` failed); "
                "the maintenance record needs it to rule out pid reuse — retry"
            )
        base = {
            "owner_nonce": nonce,
            "pid": os.getpid(),
            "pid_start_time": lstart,
            "site": site,
            "mode": "B" if mode == "B" else "A",
            "state": state,
            "owned_targets": [],
            "paused": [],
            "started": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "until": time.time() + GUIDED_TOTAL_S,
        }
        _json_write_atomic(MAINTENANCE_FILE, {**base, "heartbeat": time.time()})
    _journal("headed_lease", phase="start", site=site, mode=base["mode"])
    old_env = os.environ.get(MAINTENANCE_ENV)
    os.environ[MAINTENANCE_ENV] = nonce
    stop = threading.Event()
    beat = threading.Thread(
        target=_headed_lease_heartbeat,
        args=(nonce, stop),
        name="browser-maintenance-heartbeat",
        daemon=True,
    )
    beat.start()
    try:
        yield nonce
    finally:
        stop.set()
        beat.join(timeout=3.0)
        if old_env is None:
            os.environ.pop(MAINTENANCE_ENV, None)
        else:
            os.environ[MAINTENANCE_ENV] = old_env
        _headed_lease_release(nonce)
        _journal("headed_lease", phase="end", site=site)


def _headed_lease(site: str) -> contextlib.AbstractContextManager[str]:
    """The mode-A maintenance record alone (Phase 2's "headed lease")."""
    return _maint_record(site, "A")


def _headed_lease_release(nonce: str) -> None:
    """Remove the record iff it still carries `nonce` (under the lock)."""
    try:
        with _maint_locked(5.0):
            cur = _read_json_dict(MAINTENANCE_FILE)
            if cur is not None and cur.get("owner_nonce") == nonce:
                MAINTENANCE_FILE.unlink(missing_ok=True)
            elif cur is not None:
                print(
                    f"⚠ the maintenance record was rewritten by owner "
                    f"{str(cur.get('owner_nonce'))[:8]} while we held it — left in "
                    f"place ({MAINTENANCE_FILE}).",
                    file=sys.stderr,
                )
    except OSError as exc:
        print(f"⚠ could not release the maintenance record: {exc}", file=sys.stderr)


def _preflight_action(cmd: str, mode: str | None, lease_live: bool) -> str | None:
    """``"revert"`` when `cmd` must first switch a lease-less headed browser
    back to headless; else None. Pure — the decision `_preflight` acts on."""
    if cmd in _PREFLIGHT_SKIP_CMDS or mode != "headed" or lease_live:
        return None
    return "revert"


def _revert_headed(port: int, why: str) -> int:
    """Switch a headed browser that has no live lease back to headless.

    Journaled as ``revert_headed`` (start + end with the exit code). Uses
    `cmd_switch`'s own transaction (exclusive gate, unknown-client refusal,
    re-check under the gate) with a short gate wait — never `--force`. With
    ``revert=True`` the switch also stands down when a guided login took the
    lease while we waited for the gate.
    """
    print(
        f"⚠ the shared browser is HEADED without a live guided-login lease — "
        f"reverting to headless before {why} …",
        file=sys.stderr,
    )
    _journal(
        "revert_headed", phase="start", trigger=why, lease=_headed_lease_describe()
    )
    rc = cmd_switch(port, "headless", gate_wait_s=PREFLIGHT_GATE_WAIT_S, revert=True)
    _journal("revert_headed", phase="end", trigger=why, result=rc)
    return rc


@contextlib.contextmanager
def _stdout_to_stderr() -> Iterator[None]:
    """Route stdout — Python's AND fd 1, so child processes too — to stderr.

    A preflight revert must never print into the triggering command's stdout:
    consumers parse it (`slack-session` JSON, `token`, `open -N`'s target=).
    """
    sys.stdout.flush()
    saved = os.dup(1)
    try:
        os.dup2(2, 1)
        with contextlib.redirect_stdout(sys.stderr):
            yield
    finally:
        with contextlib.suppress(Exception):
            sys.stderr.flush()
        os.dup2(saved, 1)
        os.close(saved)


def _preflight(cmd: str, port: int) -> None:
    """Revert a lease-less headed browser before `cmd` works — best effort.

    Runs in `main` before the command takes the registry gate or any lease,
    so the revert's exclusive gate cannot deadlock against this process.
    Everything it prints goes to stderr. It never blocks the command: a fresh
    transition (another up/switch/down in flight) skips the revert, and a
    revert that fails is one ❌ line + a ``revert_failed`` journal event, then
    the command runs anyway — the next command enforces the invariant again.
    """
    if cmd in _PREFLIGHT_SKIP_CMDS:
        return
    mode = _browser_mode(port)
    if mode != "headed":
        return
    if _preflight_action(cmd, mode, _headed_lease_live() is not None) is None:
        return
    busy = _fresh_transition(_lifecycle_read())
    if busy is not None:
        _journal("revert_skipped", reason=f"transition:{busy}", trigger=cmd)
        return
    _journal_parent_chain()  # before the gate is taken (no ps under the gate)
    with _stdout_to_stderr():
        rc = _revert_headed(port, f"`{cmd}`")
    if rc != 0:
        reason = f"switch headless exit {rc}"
        _journal("revert_failed", trigger=cmd, reason=reason)
        print(
            f"❌ headed without lease — revert failed: {reason}; run browser.py "
            "switch headless",
            file=sys.stderr,
        )


def cmd_up(port: int, headless: bool = True) -> int:  # pylint: disable=unused-argument
    """Launch the shared browser HEADLESS if not already running (idempotent).

    ``headless`` is accepted for compatibility (``up -H``) and ignored: `up`
    always launches in the desired mode, which is always headless (tp#836).
    A running HEADED browser is fine only inside a live headed lease (a guided
    login); without one it is switched back to headless here. When the running
    mode matches, the lifecycle record is healed to describe the live process.

    A COLD launch takes the client gate shared for its duration, so it cannot
    slip into the middle of a `switch`/`down` window and race the relaunch that
    switch is about to do itself. The already-up branch needs no gate — it
    touches no process.
    """
    want = _desired_mode()
    _desired_mode_write()
    running = _browser_mode(port)
    if running is not None:
        if running != want:
            live = _headed_lease_live()
            if live is not None:
                print(
                    f"✓ Shared browser up, HEADED inside a guided login (site "
                    f"{live.get('site')}, pid {live.get('pid')}); it returns to "
                    f"headless when that login ends (CDP http://127.0.0.1:{port})."
                )
                return 0
            return _revert_headed(port, "`up`")
        healed = _heal_running_record(port, running)
        print(
            f"✓ Shared browser already up, {running.upper()} "
            f"(CDP http://127.0.0.1:{port})."
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
        return _launch_and_record(port, want == "headless")
    finally:
        _gate_release(gate)


def _switch_recheck(port: int, target: str, revert: bool) -> int | None:
    """The re-check `cmd_switch` runs once it HOLDS the gate; an exit code when
    the switch must not happen any more, else None.

    While we waited, a guided login may have taken the lease (a preflight
    revert then stands down: ``revert_skipped``), another switch may have
    reached `target` already, or the browser may have gone down.
    """
    if revert and _headed_lease_live() is not None:
        _journal("revert_skipped", reason="lease")
        print("✓ a guided login took the headed lease meanwhile — not reverting.")
        return 0
    live = _browser_mode(port)
    if live is None:
        return _fail("Nothing to switch — the shared browser went down meanwhile.")
    if live == target:
        print(f"✓ Shared browser already {target.upper()} (switched meanwhile).")
        return 0
    return None


HEADED_REFUSAL = (
    "❌ headed mode only inside a guided login: agent-login.py -g <site>\n"
    "   (the shared browser stays headless; `switch headed` needs the live "
    "headed lease that guided login holds)."
)


def cmd_switch(  # pylint: disable=too-many-arguments
    port: int,
    target: str,
    force: bool = False,
    gate_wait_s: float | None = None,
    *,
    revert: bool = False,
    force_maintenance: bool = False,
) -> int:
    """Switch the running browser between headed and headless, transactionally.

    ``switch headed`` is allowed ONLY to the holder of the live headed lease
    (`_headed_lease_held`, i.e. a guided login and its children); anybody
    else gets exit 2 and the guided-login hint. ``switch headless`` is always
    allowed — it is also what the preflight revert runs (``revert=True``).

    The mode is RE-READ once the gate is held: a waiting switch whose target
    another switch already reached does nothing, and a preflight revert stands
    down (journal ``revert_skipped``) when a guided login took the lease
    meanwhile — a revert queued behind the gate never kills a guided window.

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
    # Each of the exits is a distinct, named refusal (down / already in that
    # mode / unknown CDP client / stale lock / no lease …) that callers read off
    # stdout; funnelling them through one return would hide which one refused.
    # pylint: disable=too-many-return-statements
    if target == "headed" and not _headed_lease_held():
        print(HEADED_REFUSAL, file=sys.stderr)
        return 2
    blocked = _maint_blocks(force_maintenance)
    if blocked is not None:
        print(blocked, file=sys.stderr)
        return BUSY_RC
    if target == "headless":
        _desired_mode_write()
    live = _browser_mode(port)
    if live is None:
        return _fail(
            "Nothing to switch — the shared browser is down. Run: browser.py up"
        )
    if live == target:
        healed = _heal_running_record(port, live)
        print(
            f"✓ Shared browser already in {target.upper()} mode "
            f"(CDP http://127.0.0.1:{port})."
            + (" (lifecycle record refreshed)" if healed else "")
        )
        return 0
    wait_s = REGISTRY_EX_WAIT_S if gate_wait_s is None else gate_wait_s
    gate = _gate_acquire(fcntl.LOCK_EX, wait_s)
    if gate is None:
        return _fail(_gate_busy(f"switch to {target.upper()}"))
    try:
        settled = _switch_recheck(port, target, revert)
        if settled is not None:
            return settled
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
    print(f"Desired mode: {_desired_mode_state()}")
    print(f"Headed lease: {_headed_lease_describe()}")


PROBE_MARKS = {"unresponsive": "  ⚠ unresponsive", "indeterminate": "  ? indeterminate"}


def cmd_status(port: int, full_urls: bool = False, probe: bool = False) -> int:
    """Print CDP health, browser version, open tabs, and the lifecycle state.

    Tab lines show origins only (`_tab_line`): this output lands in logs and
    LLM transcripts, and an in-flight OAuth/magic-link tab carries its code or
    token in the path/query (tp#365). ``full_urls`` is the human opt-in.
    ``probe`` adds `_probe_targets`' verdict to each tab line (registered as a
    client for the probe's lifetime); without it `status` stays HTTP-only.
    """
    if probe:
        return _cmd_status_probe(port, full_urls)
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
        print(_tab_line(t, full_urls))
    _print_lifecycle(port)
    return 0


def _cmd_status_probe(port: int, full_urls: bool) -> int:
    """`status -p`: the tab list with a responsiveness mark per tab."""
    if _cdp_get(port, "/json/version") is None:
        return cmd_status(port, full_urls)  # the DOWN report, exit 1
    release = _registry_register("browser.py", _purpose(), port)
    try:
        report = _probe_targets(port)
    finally:
        release()
    ver = _cdp_get(port, "/json/version")
    browser_name = ver.get("Browser") if isinstance(ver, dict) else "?"
    mode = _browser_mode(port) or "?"
    print(f"✓ Up — {browser_name} ({mode}) | CDP http://localhost:{port}")
    if report.indeterminate:
        print(f"  probe indeterminate: {report.indeterminate}")
        _print_lifecycle(port)
        return 1
    print(f"  {len(report.targets)} tab(s), probed:")
    for t in report.targets:
        line = _tab_line({"url": t.url, "title": t.title}, full_urls)
        print(line + PROBE_MARKS.get(t.outcome, ""))
    hung = report.with_outcome("unresponsive")
    if hung:
        print(
            f"  ⚠ {len(hung)} tab(s) answer no CDP command — they block every "
            "Playwright attach (open/eval/doctor/login). Remedy: "
            "`browser.py close-hung`."
        )
    _print_lifecycle(port)
    return 0


def _confirm(prompt: str) -> bool:
    """Ask yes/no on the TTY; False on no TTY, EOF or anything but y/yes."""
    if not sys.stdin.isatty():
        return False
    try:
        answer = input(prompt)
    except EOFError:
        return False
    return answer.strip().lower() in ("y", "yes")


def cmd_close_hung(port: int, assume_yes: bool = False) -> int:
    """Close the tabs whose renderer answers no CDP command — only after asking.

    Contract: closes only tabs that failed THREE consecutive CDP probes (the
    listing probe, a re-probe, and a final re-probe AFTER confirmation, with
    an unchanged URL); a responsive tab is never a candidate. Never automatic —
    `open`/`eval`/`doctor` only NAME such a tab. Registered as a client and
    holding the interaction lease (gate-then-lease order) for the whole run.
    Exit 0 when nothing was hung or every approved candidate was closed or
    recovered; 1 on an indeterminate probe, a declined prompt, or a failed close.
    """
    if not _is_up(port):
        return _fail("Shared browser is down — nothing to close.")
    release = _registry_register("browser.py", _purpose(), port)
    try:
        with _interaction_lease("close-hung"):
            return _close_hung_locked(port, assume_yes)
    finally:
        release()


def _close_hung_locked(port: int, assume_yes: bool) -> int:
    """`close-hung` body; the caller holds the registration and the lease."""
    first = _probe_targets(port)
    if first.indeterminate:
        return _fail(f"probe indeterminate: {first.indeterminate} — closed nothing.")
    unsure = first.with_outcome("indeterminate")
    if unsure:
        print(f"? {len(unsure)} tab(s) could not be probed (left alone).")
    hung1 = first.with_outcome("unresponsive")
    if not hung1:
        print(f"✓ No unresponsive tab ({len(first.targets)} probed).")
        return 0
    second = _probe_targets(port, only_ids=[t.target_id for t in hung1])
    if second.indeterminate:
        return _fail(f"probe indeterminate: {second.indeterminate} — closed nothing.")
    urls1 = {t.target_id: t.url for t in hung1}
    cands = [
        t
        for t in second.with_outcome("unresponsive")
        if urls1.get(t.target_id) == t.url
    ]
    if not cands:
        print(f"✓ The {len(hung1)} unresponsive tab(s) recovered on a re-probe.")
        return 0
    print(f"{len(cands)} tab(s) failed two consecutive CDP probes:")
    for t in cands:
        print(f"   - {t.label()}")
    if not assume_yes and not _confirm("Close them? [y/N] "):
        print("Nothing closed (not confirmed; -y/--yes skips the question).")
        return 1
    return _close_approved(port, cands)


def _close_approved(port: int, cands: list[TargetProbe]) -> int:
    """Probe #3 on the approved tabs; close each one that is STILL wedged.

    A tab closes only when it is still ``unresponsive`` with an unchanged URL;
    a recovered, changed or vanished one is skipped and said so. 1 on an
    indeterminate probe or a failed close.
    """
    third = _probe_targets(port, only_ids=[t.target_id for t in cands])
    if third.indeterminate:
        return _fail(f"probe indeterminate: {third.indeterminate} — closed nothing.")
    now = {t.target_id: t for t in third.targets}
    failed = 0
    for t in cands:
        cur = now.get(t.target_id)
        if cur is None or cur.outcome == "gone":
            print(f"   skipped (already gone): {t.label()}")
        elif cur.outcome == "responsive":
            print(f"   skipped (recovered): {t.label()}")
        elif cur.outcome != "unresponsive":
            print(f"   skipped (probe indeterminate): {t.label()}")
            failed += 1
        elif cur.url != t.url:
            print(f"   skipped (changed): {t.label()}")
        elif _cdp_close_target(port, t.target_id):
            print(f"✓ closed: {t.label()}")
        else:
            print(f"❌ close failed: {t.label()}", file=sys.stderr)
            failed += 1
    return 1 if failed else 0


# ---------------------------------------------------------------------------
# close — a caller closes the tabs it OWNS (tp#786)
# ---------------------------------------------------------------------------
# `close-hung` picks its victims by heuristic, so they may belong to anyone:
# three probes plus a confirmation. `close -i` closes only target ids the
# caller was handed by `open -N` — proof of ownership, not a heuristic. The URL
# mode (exact match sans query/fragment, http(s) only) exists for cleaning up
# legacy litter by hand; tools never use it. Both re-read the tab list under
# the interaction lease right before each close, never close the last page
# (tp#317), and run under ONE monotonic deadline over raw CDP, so a wedged
# foreign tab cannot stall them. Unregistered clients take no lease, so the
# re-check is best-effort against them.


def _close_refusal(url: str) -> str | None:
    """Why `close URL` refuses `url` (non-http(s), no hostname), or None."""
    try:
        parts = urllib.parse.urlsplit(url)
        host = parts.hostname
    except ValueError:
        return "unparseable URL"
    if parts.scheme not in ("http", "https"):
        return "not an http(s) URL"
    if not host:
        return "no hostname"
    return None


def _close_matches(pages: Sequence[dict], urls: Sequence[str]) -> list[dict]:
    """The page targets whose URL equals one of `urls` after `_strip_query`."""
    wanted = {_strip_query(u) for u in urls}
    return [
        t
        for t in pages
        if t.get("type") == "page"
        and isinstance(t.get("url"), str)
        and _strip_query(t["url"]) in wanted
    ]


def _close_list_pages(port: int, left: Callable[[], float]) -> list[dict] | None:
    """The current page targets, read within what is left; None if unreadable."""
    listing = _cdp_get(port, "/json/list", timeout=max(0.01, min(2.0, left())))
    if not isinstance(listing, list):
        return None
    return [t for t in listing if isinstance(t, dict) and t.get("type") == "page"]


# One parameter per `close` flag; bundling them would only move the list.
def cmd_close(  # pylint: disable=too-many-arguments
    port: int,
    urls: Sequence[str] | None,
    ids: Sequence[str] | None,
    *,
    dry_run: bool = False,
    wait_s: float = CLOSE_WAIT_S,
    deadline_s: float = CLOSE_DEADLINE_S,
) -> int:
    """Close the tabs named by target id (`ids`) or by exact URL (`urls`).

    Order: validate the URLs, then the registration, then the interaction
    lease (gate → lease, the existing lock order), all under one monotonic
    deadline (`deadline_s`); the lease wait is ``min(wait_s, left)``. A lease
    timeout exits 1 with nothing closed (`_interaction_lease` raises
    SystemExit; the registration is released in the ``finally``). Exit codes:
    see the `close` help.
    """
    deadline = time.monotonic() + deadline_s

    def left() -> float:
        return max(0.0, deadline - time.monotonic())

    urls, ids = list(urls or []), list(ids or [])
    for u in urls:
        why = _close_refusal(u)
        if why:
            return _fail(
                f"refusing to close by URL {_tab_hint(u)}: {why} — closed nothing."
            )
    if not _is_up(port):
        print("✓ Shared browser is down — nothing to close.")
        return 0
    release = _registry_register("browser.py", _purpose(), port, wait_s=left())
    try:
        with _interaction_lease("close", wait_s=min(wait_s, left())):
            return _close_locked(port, urls, ids, dry_run, left)
    finally:
        release()


def _close_candidates(
    pages: list[dict], urls: list[str], ids: list[str]
) -> tuple[list[dict], list[str]]:
    """``(candidates, missing ids)`` from the first listing."""
    if urls:
        return _close_matches(pages, urls), []
    by_id = {t.get("id"): t for t in pages}
    cands: list[dict] = []
    missing: list[str] = []
    for tid in dict.fromkeys(ids):  # dedupe, keep order
        if tid in by_id:
            cands.append(by_id[tid])
        else:
            missing.append(tid)
    return cands, missing


def _label_of(t: dict) -> str:
    """`_target_label` of a ``/json/list`` entry."""
    return _target_label(t.get("url"), t.get("title"), t.get("id"))


def _close_locked(
    port: int,
    urls: list[str],
    ids: list[str],
    dry_run: bool,
    left: Callable[[], float],
) -> int:
    """`close` body; the caller holds the registration and the lease."""
    ws_url = _browser_ws_url(port, timeout=max(0.01, min(2.0, left())))
    if ws_url is None:
        return _fail("could not read the browser endpoint — closed nothing.")
    pages = _close_list_pages(port, left)
    if pages is None:
        return _fail("could not read the tab list — closed nothing.")
    cands, missing = _close_candidates(pages, urls, ids)
    for tid in missing:
        print(f"- gone: {_id8(tid)}")
    if not cands and urls:
        print("✓ No matching tab — nothing to close.")
    if dry_run or not cands:
        for t in cands:
            print(f"would close: {_label_of(t)}")
        return 0
    run = _CloseRun(port, ws_url, {_strip_query(u) for u in urls} if urls else None)
    rc = 0
    for i, t in enumerate(cands):
        now = _close_list_pages(port, left) if left() > 0 else None
        if now is None:
            why = "deadline" if left() <= 0 else "tab list unreadable"
            for rest in cands[i:]:
                print(f"❌ failed ({why}): {_label_of(rest)}", file=sys.stderr)
            return 1
        rc |= _close_one(run, t, now, left)
    return rc


@dataclass
class _CloseRun:
    """What every `_close_one` of one `close` run shares.

    ``wanted`` is the set of `_strip_query`'d URLs in URL mode, None in id mode.
    """

    port: int
    ws_url: str
    wanted: set[str] | None


def _close_one(
    run: _CloseRun, t: dict, now: list[dict], left: Callable[[], float]
) -> int:
    """Re-check candidate `t` against the fresh listing `now`; close it. 0/1.

    Gone → ``- gone``; URL mode (``run.wanted`` set) and the URL no longer matches →
    ``skipped (changed)``; the only page left → a blank keep-alive first
    (tp#317: zero tabs break every `connect_over_cdp`), and if that fails the
    tab stays open.
    """
    tid = str(t.get("id") or "")
    label = _label_of(t)
    cur = next((p for p in now if p.get("id") == tid), None)
    if cur is None:
        print(f"- gone: {label}")
        return 0
    cur_url = cur.get("url")
    if run.wanted is not None and not (
        isinstance(cur_url, str) and _strip_query(cur_url) in run.wanted
    ):
        print(f"skipped (changed): {label}")
        return 0
    if len(now) <= 1 and not _cdp_create_background_target(
        run.ws_url, "about:blank", min(5.0, left())
    ):
        print(
            f"❌ failed (could not open a keep-alive tab; left open): {label}",
            file=sys.stderr,
        )
        return 1
    if _cdp_close_target(run.port, tid, left(), ws_url=run.ws_url):
        print(f"✓ closed: {label}")
        return 0
    print(f"❌ failed: {label}", file=sys.stderr)
    return 1


def cmd_clients(port: int) -> int:
    """Show who is attached over CDP: the registered clients and the unknown ones.

    Purely diagnostic — it reports, it never judges, so it always exits 0;
    turning an unknown client into a refusal is `switch`'s job. Listing the
    registrations also REAPS the files of clients that died holding one, so
    running this is the cheapest way to clean up after a crash.
    """
    dead: list[dict] = []
    live = _registry_live_clients(dead)
    for rec in dead:
        if rec.get("kind") == "exec":
            how = _kill_orphan_group(rec)
            if how in ("terminated", "killed"):
                print(
                    f"⚠ {rec.get('tool')}: its register-exec wrapper died; the "
                    f"orphaned child group {rec.get('child_pgid')} was {how}."
                )
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
    UNKNOWN client and fails every `switch` closed. The wrapper registers
    (kind ``exec``, then its child's pid/start time and process group), stays
    alive as the parent with stdio inherited (transparent for MCP's stdio
    protocol), forwards SIGTERM/SIGINT/SIGHUP to the child's process group, and
    releases the registration when CMD exits.

    PAUSE PROTOCOL (guided login, `_maintenance`): the child runs in its OWN
    process group so the wrapper can freeze it as a whole (npx → node).
    SIGUSR1 = pause: only while a maintenance record is live, the wrapper
    SIGSTOPs the child's group, drops its shared hold on the registry gate
    (so the guided login can take it exclusively) and records
    ``paused: true``. SIGUSR2 = resume: retake the gate (bounded), SIGCONT the
    group, ``paused: false``. Every handler is installed BEFORE the
    registration says ``kind: exec`` and before the child exists: a signal in
    between is queued, never lost and never fatal. A paused wrapper resumes
    ITSELF once the record that paused it is gone or names another owner — or,
    as a last resort, after it has been not-live for EXEC_ORPHAN_RESUME_S (the
    watchdog that should have recovered it is presumed dead). A record whose
    owner merely died is NOT a reason: the watchdog first needs the gate
    exclusively to switch a headed browser back to headless.
    """
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]  # argparse.REMAINDER keeps the separator; drop it
    if not cmd:
        return _fail("register-exec: no command given (usage: … -t NAME -- CMD ARGS…)")
    wrapper = _ExecWrapper()
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, wrapper.forward)
    signal.signal(signal.SIGUSR1, wrapper.request)
    signal.signal(signal.SIGUSR2, wrapper.request)
    # Register FIRST (fails loud while a switch holds the gate), THEN spawn:
    # a child must never run unregistered. The record carries the WRAPPER's
    # pid; the child's/grandchild's sockets resolve to it via the ancestry
    # walk in _unknown_cdp_clients.
    reg = _registry_register(
        tool,
        " ".join(cmd)[:160],
        port,
        journal_purpose=_journal_wrapped_cmd(cmd),
        extra={"kind": "exec", "paused": False},
    )
    try:
        # Own process group (not a new session: the controlling terminal and
        # stdio stay as they were) — what the pause protocol stops as a whole.
        proc = subprocess.Popen(cmd, process_group=0)  # pylint: disable=consider-using-with
    except OSError as exc:
        reg.release()
        return _fail(f"register-exec: cannot start {cmd[0]!r}: {exc}")
    reg.update(
        child_pid=proc.pid,
        child_pgid=proc.pid,
        child_start_time=_proc_lstart(proc.pid),
    )
    try:
        return wrapper.run(reg, proc)
    finally:
        reg.release()


# How often a register-exec wrapper looks at its child and its pause state.
EXEC_POLL_S = 0.2
# How often a PAUSED wrapper re-checks the record that paused it.
EXEC_SELF_CHECK_S = 2.0
# A paused wrapper whose record has been NOT live (dead/hung owner) this long
# presumes the watchdog dead and resumes itself. (Test hook: a disposable
# cache dir may shorten it via $CLAUDE_BROWSER_EXEC_ORPHAN_S.)
EXEC_ORPHAN_RESUME_S = (
    float(os.environ.get("CLAUDE_BROWSER_EXEC_ORPHAN_S", "60"))
    if os.environ.get("CLAUDE_BROWSER_CACHE_DIR")
    else 60.0
)


def _exec_self_resume(
    rec: dict | None, paused_by: str, stale_since: float | None, now: float
) -> tuple[str | None, float | None]:
    """A paused wrapper's decision: (why to resume or None, new stale_since). Pure.

    Resume when the record FILE is gone or names another owner. A record that
    is still OURS but not live (owner dead/hung) is the watchdog's to recover —
    resuming now would retake the gate its revert needs — unless it has been
    not-live for EXEC_ORPHAN_RESUME_S (the watchdog is presumed dead).
    """
    if rec is None or rec.get("owner_nonce") != paused_by:
        return "maintenance record gone", None
    if _headed_lease_state(rec) == "live":
        return None, None
    since = now if stale_since is None else stale_since
    if now - since >= EXEC_ORPHAN_RESUME_S:
        return "guided login dead and not recovered (watchdog presumed dead)", since
    return None, since


class _ExecWrapper:
    """The `register-exec` main loop: wait for the child, act on pause/resume.

    Created (and its handlers installed) before the registration and the
    child exist; `run` gets both once they do.
    """

    def __init__(self) -> None:
        self.reg: Registration | None = None
        self.proc: subprocess.Popen | None = None
        self.pgid = 0
        self.pending: list[int] = []  # SIGUSR1/2, handled on the main loop
        self.early: list[int] = []  # terminating signals before the child exists
        self.paused_by = ""
        self.stale_since: float | None = None

    def forward(self, signum: int, _frame: object) -> None:
        """Forward a terminating signal to the child's group (resumed first)."""
        if not self.pgid:
            self.early.append(signum)
            return
        with contextlib.suppress(OSError):
            os.killpg(self.pgid, signum)
        if self.paused_by:
            with contextlib.suppress(OSError):
                os.killpg(self.pgid, signal.SIGCONT)

    def request(self, signum: int, _frame: object) -> None:
        """Signal handler: queue pause/resume for the main loop (no I/O here)."""
        self.pending.append(signum)

    def run(self, reg: Registration, proc: subprocess.Popen) -> int:
        """Wait for the child; pause/resume on request; self-resume when orphaned."""
        self.reg, self.proc, self.pgid = reg, proc, proc.pid
        for signum in self.early:  # a SIGTERM that came before the child did
            self.forward(signum, None)
        last_check = time.monotonic()
        while True:
            try:
                return proc.wait(timeout=EXEC_POLL_S)
            except subprocess.TimeoutExpired:
                pass
            while self.pending:
                if self.pending.pop(0) == signal.SIGUSR1:
                    self.pause()
                else:
                    self.resume("requested")
            now = time.monotonic()
            if self.paused_by and now - last_check >= EXEC_SELF_CHECK_S:
                last_check = now
                why, self.stale_since = _exec_self_resume(
                    _read_json_dict(MAINTENANCE_FILE),
                    self.paused_by,
                    self.stale_since,
                    now,
                )
                if why:
                    self.resume(why)

    def _tool(self) -> object:
        return self.reg.rec.get("tool") if self.reg is not None else None

    def pause(self) -> None:
        """SIGSTOP the child's group, release the gate — only inside a guided login."""
        if self.paused_by or self.reg is None:
            return
        rec = _maint_live()
        if rec is None:
            _journal("client_pause", client=self._tool(), result="ignored")
            return
        try:
            os.killpg(self.pgid, signal.SIGSTOP)
        except OSError as exc:
            _journal("client_pause", client=self._tool(), result=f"error:{exc}")
            return
        self.paused_by = str(rec.get("owner_nonce"))
        self.stale_since = None
        self.reg.drop_gate()
        self.reg.update(paused=True, paused_by=self.paused_by[:12])
        _journal(
            "client_pause",
            client=self._tool(),
            child_pgid=self.pgid,
            site=rec.get("site"),
        )

    def resume(self, why: str) -> None:
        """Retake the gate (bounded), SIGCONT the child's group."""
        if not self.paused_by or self.reg is None:
            return
        gate = self.reg.retake_gate(REGISTRY_SH_WAIT_S)
        with contextlib.suppress(OSError):
            os.killpg(self.pgid, signal.SIGCONT)
        self.paused_by = ""
        self.stale_since = None
        self.reg.update(paused=False, paused_by="")
        _journal(
            "client_resume",
            client=self._tool(),
            child_pgid=self.pgid,
            why=why,
            gate="held" if gate else "lost",
        )
        if not gate:
            print(
                "⚠ register-exec: resumed without the client gate (a switch or "
                "shutdown held it) — the next switch will not wait for this client.",
                file=sys.stderr,
            )


def _kill_orphan_group(entry: dict) -> str:
    """Stop the child group of a `register-exec` wrapper that is DEAD.

    Only a validated group: the wrapper pid must be gone (or reused) and the
    group leader must still run with the recorded start time. SIGTERM (+
    SIGCONT, a stopped process cannot act on it), then SIGKILL after 5 s.
    Returns what happened: ``killed``, ``terminated``, or why not.
    """
    if _client_validated(entry.get("pid"), entry.get("pid_start_time")):
        return "wrapper alive"
    child, lstart = entry.get("child_pid"), entry.get("child_start_time")
    pgid = entry.get("child_pgid")
    if not _client_validated(child, lstart) or pgid != child:
        return "no validated orphan"
    assert isinstance(child, int)  # for mypy (validated above)
    for sig in (signal.SIGTERM, signal.SIGCONT):
        with contextlib.suppress(OSError):
            os.killpg(child, sig)
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        if not _pid_alive(child):
            break
        time.sleep(0.1)
    how = "terminated"
    if _pid_alive(child) and _proc_lstart(child) == lstart:
        with contextlib.suppress(OSError):
            os.killpg(child, signal.SIGKILL)
        how = "killed"
    _journal("orphan_kill", client=entry.get("tool"), child_pgid=child, how=how)
    return how


def _fresh_transition(rec: dict | None) -> str | None:
    """The record's transitional state if it is still FRESH, else None.

    Fresh = ``starting``/``stopping``/``switching`` no older than
    TRANSITION_STALE_S, or with an unparsable timestamp (fail safe: another
    process may be mid-launch/mid-switch with no CDP answer yet). A stuck,
    older transition is a dead one and reads as None.
    """
    if not rec:
        return None
    state = str(rec.get("state", ""))
    if state not in TRANSITIONAL_STATES:
        return None
    age = _iso_age_s(rec.get("iso"))
    return state if age is None or age <= TRANSITION_STALE_S else None


def _down_clear_stale(port: int, rec: dict | None) -> bool:
    """Clear a record no browser stands behind, WITHOUT the gate; True if done.

    With no CDP answer and no root process on our profile there is nothing a
    registered client could lose, so waiting for the gate would only let a
    long-lived client (the Playwright MCP server) keep a stale record alive
    forever. A FRESH transitional record is left alone — another process may be
    launching or switching and simply has no CDP yet. The record is re-read
    right before the unlink and cleared only if it is still the one judged
    here (same nonce), so a concurrent `up` that just wrote ``starting`` keeps
    its record.
    """
    if _fresh_transition(rec) is not None or _is_up(port) or _find_root_pids(port):
        return False
    current = _lifecycle_read()
    if rec is not None and (
        current is None or current.get("nonce") != rec.get("nonce")
    ):
        return False  # changed under us — let the gated path decide
    if rec is None and current is not None:
        return False
    _lifecycle_clear()
    PID_FILE.unlink(missing_ok=True)  # legacy, kept for external observers
    print(
        "Stopped (stale lifecycle record cleared)."
        if rec is not None
        else "Stopped (or was not running)."
    )
    return True


def cmd_down(port: int, force: bool = False, force_maintenance: bool = False) -> int:
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

    Registered clients, by contrast, keep the default fail-closed: a client
    that does not drain within REGISTRY_EX_WAIT_S makes `down` refuse, naming
    it. ``force`` gives the gate a short grace (REGISTRY_UP_WAIT_S, enough for
    one-shot `open`/`eval` clients) and then stops WITHOUT it — the registered
    wrappers are not killed, only their CDP connection drops. Even ``force``
    refuses on a FRESH transitional record: a live `up`/`switch` is mid-flight.

    A record with no browser behind it (no CDP, no root process) is cleared
    straight away, without the gate — see `_down_clear_stale`.
    """
    blocked = _maint_blocks(force_maintenance)
    if blocked is not None:
        print(blocked, file=sys.stderr)
        return BUSY_RC
    rec = _lifecycle_read()
    if _down_clear_stale(port, rec):
        return 0
    if force and (busy := _fresh_transition(rec)) is not None:
        return _fail(
            f"Cannot force-stop the shared browser: a '{busy}' transition is in "
            "flight (another `up`/`switch`/`down`). Retry once it has finished; "
            "`browser.py status` shows the lifecycle state."
        )
    rec_mode = rec.get("mode") if rec else None
    mode = (
        _browser_mode(port)
        or (rec_mode if isinstance(rec_mode, str) else None)
        or "headed"
    )
    gate = _gate_acquire(
        fcntl.LOCK_EX, REGISTRY_UP_WAIT_S if force else REGISTRY_EX_WAIT_S
    )
    if gate is None and not force:
        return _fail(
            _gate_busy(
                "stop the shared browser", " — or re-run with -f/--force to stop anyway"
            )
        )
    if gate is None:
        print(
            "⚠ --force: stopping without draining — these registered CDP "
            "client(s) lose their connection:\n"
            + (
                "\n".join(f"   {line}" for line in _registry_client_lines())
                or "   (no registration file left — see `browser.py clients`)"
            ),
            file=sys.stderr,
        )
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
        if gate is not None:
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
    from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
    from playwright.sync_api import sync_playwright

    if not _is_up(port):
        sys.exit("Shared browser is down. Run: browser.py up")
    _ensure_page_target(port)  # zero tabs => connect_over_cdp dies (tp#317)
    atexit.register(_registry_register("browser.py", purpose or _purpose(), port))
    pw = sync_playwright().start()
    try:
        # 127.0.0.1, not localhost — see _cdp_get (avoids the IPv6 ::1 stall).
        # The explicit timeout replaces Playwright's 180 s launch default: one
        # tab whose renderer answers no CDP command stalls the attach (tp#693).
        browser = pw.chromium.connect_over_cdp(
            f"http://127.0.0.1:{port}", timeout=CONNECT_TIMEOUT_S * 1000
        )
    except PlaywrightTimeoutError:
        _stop_playwright_bounded(pw)
        raise BrowserAttachTimeout(_attach_timeout_message(port)) from None
    return pw, browser


class BrowserAttachTimeout(Exception):
    """Playwright could not attach within CONNECT_TIMEOUT_S; the message names why.

    `main` turns it into a ❌ line and exit 1; `doctor` reports it as a check.
    """


def _stop_playwright_bounded(pw: Any, wait_s: float = 5.0) -> None:
    """``pw.stop()`` in a daemon thread, errors suppressed, joined for `wait_s`."""

    def _stop() -> None:
        with contextlib.suppress(Exception):
            pw.stop()

    th = threading.Thread(target=_stop, name="playwright-stop", daemon=True)
    th.start()
    th.join(timeout=wait_s)


def _attach_timeout_message(port: int) -> str:
    """Diagnose a timed-out attach with `_probe_targets` and word the ❌ message."""
    report = _probe_targets(port)
    head = (
        f"Playwright could not attach to the shared browser within "
        f"{CONNECT_TIMEOUT_S:g}s (CLAUDE_BROWSER_CONNECT_TIMEOUT_S)."
    )
    if report.indeterminate:
        return (
            f"{head}\n   Tab probe indeterminate ({report.indeterminate}) — retry, "
            "or run `browser.py status -p`."
        )
    hung = report.with_outcome("unresponsive")
    unsure = len(report.with_outcome("indeterminate"))
    if not hung:
        return (
            f"{head}\n   No tab failed the CDP probe ({unsure} indeterminate) — "
            "the stall is elsewhere; retry, or run `browser.py status -p`."
        )
    lines = [
        f"{head}",
        f"   {len(hung)} tab(s) answer no CDP command, and one such tab blocks "
        "every Playwright attach:",
        *(f"   - {t.label()}" for t in hung),
        "   Remedy: `browser.py close-hung` (asks before closing), or reload/close "
        "that tab by hand.",
    ]
    if unsure:
        lines.append(f"   ({unsure} more tab(s) could not be probed.)")
    return "\n".join(lines)


def _is_blank(url: str) -> bool:
    """True for an empty/new-tab/blank page that's safe to reuse."""
    return not url or url == "about:blank" or url.startswith("chrome://")


def _await_target_load(port: int, tid: str, timeout_s: float = 15.0) -> dict:
    """Poll ``/json/list`` until target `tid` left the blank page; its listing.

    Returns the last listing seen for `tid` (``{}`` if it never appeared).
    """
    info: dict = {}
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        targets = _cdp_get(port, "/json/list")
        for t in targets if isinstance(targets, list) else []:
            if isinstance(t, dict) and t.get("id") == tid:
                info = t
                break
        if info.get("url") not in (None, "", "about:blank"):
            break
        time.sleep(0.25)
    return info


def _open_background_tab(port: int, browser, url: str) -> dict:
    """Open URL in a NEW tab WITHOUT focusing it; return {url, title, id}.

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
    return {"url": info.get("url", url), "title": info.get("title", ""), "id": tid}


def _pick_page(browser, url_substr: str | None, *, require_match: bool = False):
    """Return ``(ctx, page)`` (optionally matching url_substr), creating one if needed.

    With ``require_match`` the caller gets ``(ctx, None)`` when no tab matches,
    instead of an arbitrary other tab. That is what `eval --url` needs: falling
    back silently ran a SharePoint query inside a Slack tab and returned Slack's
    HTML, which reads like an API error rather than a wrong-tab result (tp#317).
    The in-repo site flows keep the default fallback on purpose — they pick a
    reusable tab and then NAVIGATE it to their own URL.
    """
    ctx = browser.contexts[0] if browser.contexts else browser.new_context()
    pages = list(ctx.pages)
    if url_substr:
        for pg in pages:
            if url_substr in pg.url:
                return ctx, pg
        if require_match:
            return ctx, None
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


def _tab_hint(url: str) -> str:
    """Origin-only rendering of a tab URL for `status` and the `eval --url`
    no-match error.

    Only ``scheme://host[:port]`` survives: the path, query, fragment and
    userinfo are withheld because a password-reset tab, a magic-link tab or a
    ``data:`` page carries its secret there, and the error line lands in logs
    and LLM transcripts (tp#337). A URL without a hostname collapses to
    ``<scheme>:…``, except the literal ``about:blank`` (the "only a blank tab —
    use `open`" signal). Fails closed: a malformed URL renders as a placeholder
    and none of its bytes reach the output. Hostnames are NOT promised secret —
    they are the ``--url`` selector's own vocabulary, and `open` already prints
    every navigated URL.
    """
    if not url:
        return "(empty)"
    if url == "about:blank":
        return url
    try:
        parts = urllib.parse.urlsplit(url)
        host, port = parts.hostname, parts.port  # both raise on malformed input
    except ValueError:
        return "<unparseable url>"
    if not host:
        return f"{parts.scheme}:…" if parts.scheme else "<unparseable url>"
    if not host.isprintable():  # urlsplit lets control characters through
        return "<unparseable url>"
    if ":" in host:  # IPv6 literal — urlsplit strips the brackets
        host = f"[{host}]"
    return f"{parts.scheme}://{host}" + (f":{port}" if port is not None else "")


def _tab_title(title: object, url: object) -> str:
    """Fail-closed rendering of a tab title for `status`.

    Chrome titles a page that has no ``<title>`` with its own URL minus the
    scheme — path and query included — so a title-less OAuth callback or
    magic-link hop would print its token through the title column even once
    the URL column is origin-only (tp#365). A title contained in the raw or
    the percent-decoded URL therefore renders as ``(untitled)``, as does a
    non-string, blank or non-printable one (a newline in ``document.title``
    would forge output lines). Long titles are cut at 100 characters. A site
    that deliberately writes a secret into its own ``<title>`` is site
    content — the same bytes every CDP client reads — and outside this guard.
    """
    if not isinstance(title, str) or not title.strip():
        return "(untitled)"
    if isinstance(url, str) and url:
        if title in url or title in urllib.parse.unquote(url):
            return "(untitled)"
    if not title.isprintable():
        return "(untitled)"
    if len(title) > 100:
        return title[:97] + "…"
    return title


def _tab_line(target: dict[str, object], full_urls: bool = False) -> str:
    """One `status` tab line: fail-closed title, origin-only URL.

    ``full_urls`` puts the raw URL in the URL column — the title column still
    goes through `_tab_title` (the flag opts into raw URLs, not raw bytes on
    stdout). A ``url`` that is not a string never reaches `_tab_hint`.
    """
    url = target.get("url")
    title = _tab_title(target.get("title"), url)
    if url is None:
        hint = "(empty)"
    elif not isinstance(url, str):
        hint = "<unparseable url>"
    elif full_urls:
        hint = url or "(empty)"
    else:
        hint = _tab_hint(url)
    return f"   - {title}  →  {hint}"


def _open_new_raw(port: int, url: str) -> int:
    """`open -N`: a NEW background tab over raw CDP; prints ``target=<id>``.

    No Playwright attach (it waits for every page target, so one heavy or
    wedged foreign tab would slow this down — tp#786). Registers like `open`;
    takes no lease. Exit 1 when the tab cannot be created.
    """
    if not _is_up(port):
        sys.exit("Shared browser is down. Run: browser.py up")
    _ensure_page_target(port)  # zero tabs: createTarget may open a window
    release = _registry_register("browser.py", _purpose(), port)
    try:
        ws_url = _browser_ws_url(port)
        tid = _cdp_create_background_target(ws_url, url) if ws_url else None
        if tid is None:
            return _fail("could not create a background tab (Target.createTarget).")
        info = _await_target_load(port, tid)
        print(f"✓ Opened: {info.get('url', url)}  (title: {info.get('title', '')!r})")
        print(f"target={tid}")
        return 0
    finally:
        release()


def cmd_open(port: int, url: str, reuse: bool = False, new: bool = False) -> int:
    """Open/navigate a tab to URL (`new`: always a new tab, see `_open_new_raw`)."""
    if new:
        return _open_new_raw(port, url)
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


def _eval_watchdog_fire(timeout_s: float) -> None:
    """`eval`'s deadline expired: say so and leave NOW, from the timer thread.

    ``os._exit`` because the main thread is blocked inside Playwright, where no
    exception can reach it. Skipping the atexit handlers is safe: the registry
    flock dies with the process and `_registry_live_clients` reaps the file.
    """
    sys.stderr.write(
        f"❌ eval: no result after {timeout_s:g}s (tab unresponsive or expression "
        "never settled)\n"
    )
    sys.stderr.flush()
    _journal("watchdog", command="eval", timeout_s=timeout_s)  # never raises
    os._exit(1)  # pylint: disable=protected-access


def cmd_eval(
    port: int,
    js: str,
    url_substr: str | None,
    timeout_s: float = EVAL_TIMEOUT_S,
    target: str | None = None,
) -> int:
    """Eval a JS expression in a tab and print the JSON result.

    ``timeout_s`` is a Python-side hard deadline over the whole command, armed
    BEFORE the attach: a timer inside the page could not bound it, because it
    would run in the very renderer that stopped answering (tp#693). An
    abandoned expression may keep running in the page.
    """
    watchdog = threading.Timer(timeout_s, _eval_watchdog_fire, args=(timeout_s,))
    watchdog.daemon = True
    watchdog.start()
    try:
        if target is not None:
            return _eval_target_raw(port, target, js, timeout_s)
        return _eval_attached(port, js, url_substr)
    finally:
        watchdog.cancel()


def _cdp_exception_line(details: object) -> str:
    """One printable line (≤200 chars) from a CDP ``exceptionDetails``."""
    text = ""
    if isinstance(details, dict):
        exc = details.get("exception")
        desc = exc.get("description") if isinstance(exc, dict) else None
        text = desc if isinstance(desc, str) and desc else str(details.get("text", ""))
    line = (text.splitlines() or ["JS exception"])[0]
    line = "".join(ch if ch.isprintable() else "?" for ch in line)
    return line[:200] or "JS exception"


def _eval_target_raw(port: int, tid: str, js: str, budget_s: float) -> int:
    """`eval -T`: ``Runtime.evaluate`` on target `tid`'s own websocket; print JSON.

    Registers (no lease), finds `tid` in ``/json/list`` and sends ONE
    ``Runtime.evaluate`` with ``awaitPromise`` and ``returnByValue`` under what
    is left of `budget_s`. A JS exception, a missing target or a timeout is a
    ❌ line and exit 1. ``undefined`` prints ``null``; a value JSON cannot hold
    (NaN, Infinity, -0, a BigInt) prints as its JS spelling in a string.
    """
    deadline = time.monotonic() + budget_s

    def left() -> float:
        return max(0.0, deadline - time.monotonic())

    if not _is_up(port):
        sys.exit("Shared browser is down. Run: browser.py up")
    release = _registry_register("browser.py", _purpose(), port)
    try:
        listing = _cdp_get(port, "/json/list", timeout=max(0.01, min(2.0, left())))
        if not isinstance(listing, list):
            return _fail("could not read the tab list — nothing evaluated.")
        found = next(
            (t for t in listing if isinstance(t, dict) and t.get("id") == tid), None
        )
        ws_url = found.get("webSocketDebuggerUrl") if found else None
        if not isinstance(ws_url, str) or not ws_url:
            return _fail(
                f"no tab with target id {_id8(tid)} (closed, or not attachable) — "
                "nothing evaluated."
            )
        res = _cdp_ws_call(
            ws_url,
            "Runtime.evaluate",
            {"expression": f"({js})", "awaitPromise": True, "returnByValue": True},
            left(),
        )
        if res.status == "timeout":
            return _fail(
                f"eval: no result after {budget_s:g}s (tab unresponsive or "
                "expression never settled)"
            )
        if res.status != "ok" or res.error:
            return _fail(f"eval -T {_id8(tid)}: {res.error or res.status}")
        out = res.result or {}
        if out.get("exceptionDetails"):
            return _fail(f"eval -T: {_cdp_exception_line(out['exceptionDetails'])}")
        remote = out.get("result")
        remote = remote if isinstance(remote, dict) else {}
        value = remote.get("value", remote.get("unserializableValue"))
        print(json.dumps(value, indent=2, default=str))
        return 0
    finally:
        release()


def _eval_attached(port: int, js: str, url_substr: str | None) -> int:
    """`eval`'s attach-pick-evaluate body (the watchdog is the caller's)."""
    pw, browser = _connect(port)
    try:
        ctx, page = _pick_page(browser, url_substr, require_match=True)
        if page is None:
            # Tabs are named by origin only (tp#337): the path, query, fragment
            # and userinfo of a reset/magic-link/data: tab are secrets, and this
            # line lands in logs and transcripts. Deduplicate ALL hints first
            # (first-appearance order, ×N per repeated origin), THEN cap at 8 —
            # the "+N more" unit is origins, not tabs.
            counts: dict[str, int] = {}
            for pg in ctx.pages:
                hint = _tab_hint(pg.url)
                counts[hint] = counts.get(hint, 0) + 1
            hints = [h if n == 1 else f"{h} ×{n}" for h, n in counts.items()]
            open_tabs = ", ".join(hints[:8]) or "none"
            if len(hints) > 8:
                open_tabs += f", … (+{len(hints) - 8} more origins)"
            return _fail(
                f"No tab matching {url_substr!r} — nothing evaluated. Open one "
                f"first: browser.py open <url>. Open tabs: {open_tabs}"
            )
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


def _doctor_mode(log: list[str], port: int) -> None:
    """Certify the headless invariant (tp#836): mode, desired mode, headed lease.

    ❌ when the browser runs headed without a live headed lease (the preflight
    revert failed or something launched it behind browser.py's back); headed
    under a live lease is a guided login in progress (⚠, informational).
    """
    mode = _browser_mode(port)
    lease = _headed_lease_live()
    lease_line = _headed_lease_describe()
    if mode == "headless":
        _doctor_add(log, "ok", "mode", "headless")
    elif mode == "headed" and lease is not None:
        _doctor_add(
            log, "warn", "mode", f"headed inside a guided login — lease {lease_line}"
        )
    elif mode == "headed":
        _doctor_add(
            log,
            "fail",
            "mode",
            f"HEADED without a live guided-login lease (lease: {lease_line}) — "
            "run: browser.py switch headless",
        )
    else:
        _doctor_add(log, "fail", "mode", "unknown — /json/version did not answer")
    _doctor_add(
        log, "ok", "desired mode", f"{_desired_mode_state()} ({DESIRED_MODE_FILE})"
    )
    if lease is None:
        _doctor_add(log, "ok", "headed lease", lease_line)


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
            f"no animation frame within 5000 ms ({took}) — rendering is frozen "
            "(bring_to_front is the escalation, only inside a guided login)",
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


def _doctor_drivability(log: list[str], page, port: int = DEFAULT_CDP_PORT) -> None:
    """The bounded drivability checks on the probe page, in consumer order.

    ``bring_to_front`` is an ESCALATION, not a default: on Chrome for Testing
    151 ``Page.bringToFront`` can raise the window and even steal macOS focus
    (measured 2026-08-20, reproducible), so the probe only reaches for it when
    rendering is actually frozen — exactly the situation in which a consumer
    would need it — and flags the escalation so the window checks that follow
    are read in that light. Headless, or outside the guided login that holds
    the headed lease, it never escalates (tp#836): a frozen frame is a ❌.
    """
    from playwright.sync_api import Error as PlaywrightError

    held = _headed_lease_held()
    if _doctor_raf(log, page, escalated=False):
        _doctor_add(
            log,
            "ok",
            "bring_to_front",
            "not needed — rendering is alive without it (and on CfT 151 it can "
            "raise the window / steal focus)",
        )
    elif _bring_to_front_skip(_browser_mode(port) if held else None, held):
        # Headless (or headed outside the guided login that owns the window):
        # never escalate — frozen rendering is the verdict, not a raise.
        _doctor_add(
            log,
            "fail",
            "rendering (rAF)",
            "frozen and NOT escalated — bring_to_front only inside a guided "
            "login (headless rendering should never freeze)",
        )
    else:
        try:
            _bring_to_front(page, "doctor", port)
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


def _doctor_open_probe(log: list[str], port: int, created: list[str]) -> bool:
    """Create the disposable probe tab in the BACKGROUND; True if it loaded.

    Created over CDP with ``background: true`` (see `_open_background_tab`) so
    it cannot raise the window, and this connection is then dropped again:
    Playwright only adopts targets that already existed when it attached, so the
    page object has to come from a FRESH connection. The new target's id is
    appended to `created` the moment it exists, so the caller's cleanup can
    close it by id even when Playwright never gets to see it.
    """
    pw, browser = _connect(port)
    try:
        info = _open_background_tab(port, browser, DOCTOR_PROBE_URL)
        if info.get("id"):
            created.append(str(info["id"]))
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


def _doctor_responsiveness(log: list[str], port: int) -> bool:
    """Probe every tab over raw CDP; False when one is wedged (skip the probe).

    A tab whose renderer answers no CDP command blocks every Playwright attach
    (tp#693) — the drivability probe would only time out behind it, so it is
    skipped and the tab is named instead. An indeterminate result is a ⚠: the
    probe still runs, bounded by CONNECT_TIMEOUT_S.
    """
    report = _probe_targets(port)
    if report.indeterminate:
        _doctor_add(
            log, "warn", "tab responsiveness", f"indeterminate: {report.indeterminate}"
        )
        return True
    hung = report.with_outcome("unresponsive")
    unsure = report.with_outcome("indeterminate")
    if hung:
        names = "; ".join(t.label() for t in hung)
        _doctor_add(
            log,
            "fail",
            "tab responsiveness",
            f"{len(hung)} tab(s) answer no CDP command ({names}) — they block every "
            "Playwright attach; run `browser.py close-hung`. Drivability probe skipped.",
        )
        return False
    if unsure:
        _doctor_add(
            log,
            "warn",
            "tab responsiveness",
            f"{len(unsure)} of {len(report.targets)} tab(s) could not be probed",
        )
        return True
    _doctor_add(
        log,
        "ok",
        "tab responsiveness",
        f"all {len(report.targets)} tab(s) answer CDP",
    )
    return True


def _doctor_probe(log: list[str], port: int) -> None:
    """Drive a disposable probe page and report every drivability check.

    Nothing here touches a real tab: the page is created by
    `_doctor_open_probe`, driven, and closed again in ONE ``finally`` that also
    covers the tab creation and the reconnect — by ``page.close()`` when
    Playwright has the page, else by the created target's id over raw CDP, else
    by the `_is_probe_url` sweep. A timed-out attach is a ❌ line, not a crash.
    A failed check therefore costs a throwaway tab at worst, never a login.
    """

    created: list[str] = []
    pw = browser = page = None
    try:
        if not _doctor_open_probe(log, port, created):
            return
        pw, browser = _connect(port)
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
        _doctor_drivability(log, page, port)
    except BrowserAttachTimeout as exc:
        _doctor_add(log, "fail", "attach", str(exc).replace("\n", " "))
    finally:
        _doctor_probe_cleanup(log, port, page, created, (pw, browser))


def _doctor_probe_cleanup(
    log: list[str], port: int, page: Any, created: list[str], conn: tuple[Any, Any]
) -> None:
    """Close the probe tab however we can, then drop the Playwright connection.

    ``page.close()`` when Playwright has the page; else the created target's id
    over raw CDP (works even when the re-attach timed out); else, with a live
    connection but no id, the `_is_probe_url` sweep. Never raises.
    """
    from playwright.sync_api import Error as PlaywrightError

    pw, browser = conn
    if page is not None:
        with contextlib.suppress(PlaywrightError):
            page.close()
    elif created:
        for tid in created:
            if not _cdp_close_target(port, tid):
                _doctor_add(
                    log,
                    "warn",
                    "probe cleanup",
                    f"could not close the probe tab [id {tid[:8]}]",
                )
    elif browser is not None:
        with contextlib.suppress(PlaywrightError):
            _close_probe_targets(port, browser)
    if browser is not None:
        with contextlib.suppress(PlaywrightError):
            browser.close()
    if pw is not None:
        _stop_playwright_bounded(pw)


def cmd_doctor(port: int) -> int:
    """Certify a RUNNING shared browser end to end; 0 only if nothing FAILED.

    The order is deliberate: the lifecycle record is validated against the live
    process first (a browser that disagrees with its own record is not worth
    probing, and a cleanly DOWN one is not certifiable at all — doctor's job is
    certifying a running browser, so that exits 1), then who else is attached,
    then the desktop snapshot, then whether every tab answers CDP at all (one
    wedged tab blocks every Playwright attach, so the probe is skipped behind
    it), then the probe itself.

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
    _doctor_mode(log, port)
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
            if _doctor_responsiveness(log, port):
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

    Scans ``localStorage`` (where Waldur HomePort keeps it) first, then the
    cookies sent to the portal (incl. httpOnly ones invisible to
    ``document.cookie``) — never the whole profile's: a 40-hex cookie from
    another site must not be cached and sent to CSCS as a token. Returns ``None``
    rather than raising if the page navigates mid-scan — the SPA periodically
    re-renders/redirects, destroying the JS execution context — so the caller can
    just retry.
    """
    from playwright.sync_api import Error as PlaywrightError

    try:
        token = page.evaluate(
            "() => { const re=/\\b[0-9a-f]{40}\\b/;"
            "for (let i=0;i<localStorage.length;i++)"
            "{const v=localStorage.getItem(localStorage.key(i));"
            "const m=v&&v.match(re); if(m) return m[0];} return null; }"
        )
        if token:
            return str(token)
        for ck in ctx.cookies(PORTAL_PROFILE_URL):
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
    # Created 0600 and tightened BEFORE the write (a pre-existing file keeps its
    # old mode through O_CREAT) — never write-then-chmod, which leaves the token
    # readable by other users in between.
    fd = os.open(CSCS_TOKEN_CACHE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        os.fchmod(fh.fileno(), 0o600)
        fh.write(token)
    print(f"✓ Token cached at {CSCS_TOKEN_CACHE} (mode 0600).")
    # Cached BEFORE the check on purpose: a token scanned from the logged-in
    # portal is almost always valid, and cscs-api.py self-heals on a 401. A
    # failed check exits 1 (cscs-api.py maps 2 to "needs login", which it isn't).
    # Error lines name only the exception TYPE and the status code — a response
    # body or exception text may echo the token.
    try:
        resp = requests.get(
            PORTAL_API_ME, headers={"Authorization": f"Token {token}"}, timeout=15
        )
        data = resp.json() if resp.status_code == 200 else None
    except (requests.RequestException, ValueError) as exc:
        return _fail(
            f"Token cached at {CSCS_TOKEN_CACHE}, but verifying it against the "
            f"portal failed ({type(exc).__name__}) — check the network, then "
            "re-run: browser.py token"
        )
    if resp.status_code != 200:
        return _fail(
            f"Portal rejected the cached token (HTTP {resp.status_code}) — "
            "log into CSCS again (browser.py cscs-login)."
        )
    if not isinstance(data, dict):
        return _fail(
            f"Token cached at {CSCS_TOKEN_CACHE}, but the portal's /api/me/ "
            "answer was not a JSON object — cannot confirm the token."
        )
    user, email = _printable(data.get("username")), _printable(data.get("email"))
    print(f"✓ Authenticated as: {user} ({email})")
    return 0


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
            _fail(
                "Not logged in — the portal redirected to Keycloak.\n"
                "Run: browser.py login cscs   (then re-run: browser.py token)"
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


_KC_PW_PREFIX = "password:"
_KC_HEX_RE = re.compile(r"0x([0-9A-Fa-f]*)(?: .*)?")


def _kc_parse_password(stderr: str) -> str | None:
    """Decode the secret from ``find-generic-password -g`` stderr, or ``None``.

    ``-g`` labels its encoding (tp#498): a quoted value is the stored text
    verbatim (inner ``"`` unescaped, so it is everything between the first and
    the last quote); otherwise ``0x<HEX>`` holds the UTF-8 bytes, optionally
    followed by a space and a rendering that is ignored. The last
    ``password:`` line wins. Empty, unparsable or non-UTF-8 values give
    ``None``. Never logs.
    """
    line = None
    for raw in stderr.split("\n"):
        if raw.startswith(_KC_PW_PREFIX):
            line = raw
    if line is None:
        return None
    text = line.rstrip("\r")[len(_KC_PW_PREFIX) :]
    if text.startswith(" "):
        text = text[1:]
    if text.startswith("0x"):
        m = _KC_HEX_RE.fullmatch(text)
        if m is None or not m.group(1) or len(m.group(1)) % 2:
            return None
        try:
            return bytes.fromhex(m.group(1)).decode("utf-8")
        except UnicodeDecodeError:
            return None
    if len(text) >= 2 and text.startswith('"') and text.endswith('"'):
        return text[1:-1] or None
    return None


@dataclass(frozen=True)
class SecurityResult:
    """Outcome of one ``_security_run``.

    ``state``: ``"not_started"`` (``Popen`` raised ``OSError`` — provably
    nothing ran), ``"done"`` (the child exited normally; ``rc`` is its exit
    code) or ``"unknown"`` (it ran, but an error after launch or a signal
    death means its effect cannot be known).
    """

    state: str
    rc: int | None = None
    stdout: bytes = b""
    stderr: bytes = b""


class SecurityInterrupted(KeyboardInterrupt):
    """Ctrl-C arrived while ``security`` ran; raised only after it exited.

    ``result`` is that finished call's outcome, so a caller can still tell
    whether its mutation happened before it re-raises.
    """

    def __init__(self, result: SecurityResult) -> None:
        super().__init__()
        self.result = result


def _security_run(argv: Sequence[str], *, data: bytes | None = None) -> SecurityResult:
    """Run one ``security`` command to completion; never kill it, never time it out.

    On 2026-09-24 a 15 s ``subprocess.run`` timeout killed a ``security`` client
    while its SecurityAgent prompt was open, and ``securityd`` aborted
    (SIGABRT) at that moment — afterwards every login-keychain read hung. So:
    no deadline (a locked keychain makes a read wait for the user's unlock),
    no ``kill``/``terminate``/``send_signal``, and the child runs in its own
    session (``start_new_session``) so a terminal Ctrl-C never reaches it.

    A ``KeyboardInterrupt`` in the parent is deferred: the child is still
    drained and reaped, then ``SecurityInterrupted`` (carrying the result) is
    raised. ``data`` goes to the child's stdin (secrets never go on argv).
    """
    try:
        # pylint: disable-next=consider-using-with  # reaped below, never killed
        proc = subprocess.Popen(
            list(argv),
            stdin=subprocess.PIPE if data is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except OSError:
        return SecurityResult("not_started")
    out: bytes | None = None
    err: bytes | None = None
    interrupted = broken = False
    pending = data
    while True:
        try:
            if broken:
                proc.wait()
            else:
                # a retry passes None: Popen keeps the unsent rest of the input
                out, err = proc.communicate(pending)
            break
        except KeyboardInterrupt:
            interrupted = True
        except Exception:  # pylint: disable=broad-exception-caught
            broken = True  # the child's effect is unknown; still reap it
        pending = None
    rc = proc.returncode
    state = "unknown" if broken or rc is None or rc < 0 else "done"
    result = SecurityResult(state, rc, out or b"", err or b"")
    if interrupted:
        raise SecurityInterrupted(result)
    return result


def _kc_target_keychain() -> str | None:
    """Path of the user's default keychain (where writes go), or ``None``.

    Delete and add both name this path, so they cannot address two different
    keychains (an unnamed delete takes the first search-list match, an unnamed
    add the default keychain). ``None`` unless it resolves to an existing file.
    """
    r = _security_run(["security", "default-keychain", "-d", "user"])
    if r.state != "done" or r.rc != 0:
        return None
    path = r.stdout.decode("utf-8", errors="replace").strip().strip('"').strip()
    return path if path and os.path.isfile(path) else None


def _keychain_get(service: str) -> str | None:
    """Read a generic-password item from the login keychain (prompt-free).

    Returns the secret string, or ``None`` if the item is absent or its value
    cannot be decoded. Reading an already-unlocked login keychain via the
    Apple-signed ``security`` binary needs NO Touch ID — that is the whole
    point versus the ``op`` path. The read names no keychain: it sees what
    every consumer sees (the first search-list match). A LOCKED keychain makes
    it wait for the user's unlock — ``security`` is never timed out.

    Uses ``-g`` (labelled dump on stderr), not ``-w``: ``-w`` prints
    non-printable values as bare hex with no marker, so ``cafe`` and the hex
    of a UTF-8 password are indistinguishable (tp#498). The captured output is
    never printed; a decode failure warns naming the service label only.
    """
    r = _security_run(
        ["security", "find-generic-password", "-a", _kc_account(), "-s", service, "-g"]
    )
    if r.state != "done" or r.rc != 0:
        return None
    # stdout holds only the attribute dump (account, service, description).
    value = _kc_parse_password(r.stderr.decode("utf-8", errors="replace"))
    if value is None:
        print(
            f"Keychain item {service} has an unreadable value — ignoring it.",
            file=sys.stderr,
        )
    return value


# `security -i` reads one command per line into a 4096-byte buffer; a longer
# line is split and its tail parsed as a new command (measured). Margin kept.
_KC_LINE_MAX = 4000


def _kc_quote(s: str) -> str:
    """Quote one token for the ``security -i`` tokenizer.

    Inside ``"…"`` only ``\\`` and ``\"`` are escapes (measured: spaces, quotes,
    backslashes, ``$;|&#`` and UTF-8 round-trip exactly).
    """
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _kc_add_line(
    service: str, value: str, description: str, keychain: str
) -> bytes | None:
    """The ``add-generic-password`` command line for ``security -i``, or ``None``.

    ``None`` when any field (the keychain path included) holds a control
    character (a newline would end the command early and the fragment would
    land in the keychain), cannot be encoded as UTF-8 (lone surrogates), or the
    line exceeds ``_KC_LINE_MAX`` bytes. Insert-only — no ``-U``: updating an
    existing item re-sets its access list, which can raise a SecurityAgent
    prompt (tp#504). The keychain is named explicitly, so an invalid path
    fails the insert instead of falling back. The value never appears in any
    error text.
    """
    fields = (_kc_account(), service, value, description, keychain)
    if any(ord(c) < 0x20 or ord(c) == 0x7F for f in fields for c in f):
        return None
    account = fields[0]
    line = (
        f"add-generic-password -a {_kc_quote(account)} -s {_kc_quote(service)}"
        f" -w {_kc_quote(value)} -D {_kc_quote(description)}"
        f" -T /usr/bin/security {_kc_quote(keychain)}"
    )
    try:
        data = line.encode("utf-8")
    except UnicodeEncodeError:
        return None
    if len(data) > _KC_LINE_MAX:
        return None
    return data + b"\n"


def _kc_delete_outcome(r: SecurityResult) -> str:
    """``"deleted"`` / ``"absent"`` / ``"rejected"`` / ``"unknown"`` for a delete."""
    if r.state == "unknown":
        return "unknown"
    if r.state == "done" and r.rc == 0:
        return "deleted"
    # 44 = errSecItemNotFound; anything else (51: locked) left the item stored
    return "absent" if r.state == "done" and r.rc == 44 else "rejected"


def _kc_delete(service: str, keychain: str) -> str:
    """Delete one item from *keychain*; the outcome of ``_kc_delete_outcome``."""
    argv = ["security", "delete-generic-password", "-a", _kc_account()]
    return _kc_delete_outcome(_security_run([*argv, "-s", service, keychain]))


def _kc_add_outcome(add: SecurityResult, gone: str) -> str:
    """``"added"`` / ``"uncertain"`` / ``"lost"`` / ``"rejected"`` for the add
    that followed a delete with outcome *gone* (``"deleted"`` or ``"absent"``).

    Only an add that never started is a provable no-op: a finished add with a
    non-zero exit is not proof that nothing was stored (tp#509), so after
    ``"absent"`` it is ``"uncertain"``.
    """
    if add.state == "unknown":
        return "uncertain"
    if add.state == "done" and add.rc == 0:
        return "added"
    if gone == "deleted":
        return "lost"
    return "rejected" if add.state == "not_started" else "uncertain"


class _KcTouched:
    """Whether a batch's keychain may already differ from before (mutable flag)."""

    def __init__(self) -> None:
        self.value = False


def _keychain_write(
    service: str,
    value: str,
    description: str,
    keychain: str,
    touched: _KcTouched | None = None,
) -> str:
    """Replace an item in *keychain* (delete, then add); return the outcome.

    ``"ok"``; ``"invalid"`` (``_kc_add_line`` refused it — nothing ran);
    ``"rejected"`` (the delete was refused, or the item was absent and the add
    never started — nothing changed); ``"lost"`` (the old item was deleted,
    then the add was refused — the item is now missing); ``"uncertain"`` (the
    delete or the add has an unknown effect, or the item was absent and the
    add exited non-zero — it may still have stored the item; after an unknown
    delete no add is started); ``"mismatch"`` (added, but the read-back
    differs).

    Delete-then-add instead of ``add -U``: an update re-sets the item's access
    list, which can prompt (tp#504); a fresh add does not. Not atomic — a
    concurrent reader can see the item missing in between. The secret goes to
    ``security -i`` on stdin, never on argv (argv is readable by every
    same-user process via ``ps``); ``-T /usr/bin/security`` scopes silent
    access to the ``security`` binary our reads use.

    The read-back goes through ``_keychain_get`` (unpinned) and must equal
    ``value`` exactly: a byte-exact round-trip check that also catches a
    tokenizer divergence (tp#498) and a shadowing copy earlier in the search
    list. *touched* is set while a mutation may have happened; it is reset
    only when a step proves to be a no-op (a refused delete, an add that never
    started), also when Ctrl-C interrupts the delete. A Ctrl-C during the add
    keeps it set: the add ran, so its effect is not provably nil.
    """
    line = _kc_add_line(service, value, description, keychain)
    if line is None:
        return "invalid"
    mark = touched if touched is not None else _KcTouched()
    before = mark.value
    mark.value = True
    try:
        gone = _kc_delete(service, keychain)
    except SecurityInterrupted as exc:
        if _kc_delete_outcome(exc.result) in ("absent", "rejected"):
            mark.value = before
        raise
    if gone == "unknown":
        return "uncertain"
    if gone == "rejected":
        mark.value = before
        return "rejected"
    add = _security_run(["security", "-i"], data=line)
    outcome = _kc_add_outcome(add, gone)
    if outcome == "rejected":
        mark.value = before
    if outcome != "added":
        return outcome
    return "ok" if _keychain_get(service) == value else "mismatch"


def _keychain_set(
    service: str, value: str, description: str = "cscs-api credential"
) -> bool:
    """Create/replace an item in the default keychain; ``True`` on success
    (see ``_keychain_write`` for the delete-then-add and the read-back)."""
    keychain = _kc_target_keychain()
    if keychain is None:
        return False
    return _keychain_write(service, value, description, keychain) == "ok"


@dataclass
class KeychainBatchResult:
    """Outcome of ``_keychain_set_all``.

    ``ok``: every item written and read back. ``changed``: the keychain may
    differ from before (a write ran, or its outcome is unknown). ``removed`` /
    ``surviving``: the batch's services the cleanup deleted / could NOT delete.
    """

    ok: bool
    changed: bool = False
    removed: tuple[str, ...] = ()
    surviving: tuple[str, ...] = ()


def _kc_cleanup(
    services: Sequence[str], keychain: str
) -> tuple[tuple[str, ...], tuple[str, ...], SecurityInterrupted | None]:
    """Delete every service from *keychain*: ``(removed, surviving, interrupt)``.

    A Ctrl-C during one delete does not stop the others; the first such
    interrupt is returned for the caller to re-raise.
    """
    removed: list[str] = []
    surviving: list[str] = []
    interrupt: SecurityInterrupted | None = None
    for svc in services:
        try:
            outcome = _kc_delete(svc, keychain)
        except SecurityInterrupted as exc:
            interrupt = interrupt or exc
            outcome = _kc_delete_outcome(exc.result)
        (removed if outcome in ("deleted", "absent") else surviving).append(svc)
    return tuple(removed), tuple(surviving), interrupt


def _keychain_set_all(
    items: Sequence[tuple[str, str]], description: str
) -> KeychainBatchResult:
    """Write several ``(service, value)`` items as one credential set.

    The target is the default keychain, resolved once; every delete and add
    names it (no ``-U`` — see ``_keychain_write``). Every item is validated
    before the first write, so an invalid last field leaves the keychain
    untouched. Writes stop at the first failure; unless the FIRST write
    provably changed nothing (its delete was refused, or its add never
    started), every item of the batch is then deleted — a mixed old/new set
    would make a login submit a wrong pair (lockout risk), a missing one makes
    it fall back to 1Password. A refused add after an absent first item is
    cleaned up too: the add may have stored it, and the old set was already
    unusable without that item. The cleanup can also delete an item a
    concurrent writer just created. A Ctrl-C (or any other exception) that
    aborts the batch after something may have changed runs the same cleanup,
    then propagates.

    Best effort, NOT atomic: a login running concurrently can still read a
    mixed or missing set in the window, and a delete can fail (``surviving``).
    """
    keychain = _kc_target_keychain()
    if keychain is None:
        return KeychainBatchResult(ok=False)
    if any(_kc_add_line(svc, v, description, keychain) is None for svc, v in items):
        return KeychainBatchResult(ok=False)
    services = [svc for svc, _ in items]  # every item: one may hold OLD bytes
    touched = _KcTouched()
    try:
        for i, (svc, v) in enumerate(items):
            outcome = _keychain_write(svc, v, description, keychain, touched)
            if outcome == "ok":
                continue
            if i == 0 and outcome in ("rejected", "invalid"):
                return KeychainBatchResult(ok=False)
            break
        else:
            return KeychainBatchResult(ok=True, changed=True)
    except BaseException as exc:
        if touched.value:
            _, surviving, _ = _kc_cleanup(services, keychain)
            word = "Interrupted" if isinstance(exc, KeyboardInterrupt) else "Aborted"
            print(
                f"{word} — the partially written keychain items were removed."
                if not surviving
                else f"{word} — keychain cleanup FAILED for "
                f"{', '.join(surviving)}; remove them with forget-creds.",
                file=sys.stderr,
            )
        raise
    removed, surviving, interrupt = _kc_cleanup(services, keychain)
    if interrupt is not None:
        raise interrupt
    return KeychainBatchResult(False, True, removed, surviving)


def _report_keychain_batch_failure(
    result: KeychainBatchResult, store_cmd: str, forget_cmd: str
) -> int:
    """The one failure line for a ``_keychain_set_all`` that did not succeed.

    Names service labels only, never values; claims the set is gone only when
    every delete succeeded.
    """
    if not result.changed:
        return _fail("Failed to write the keychain items — nothing changed.")
    if not result.surviving:
        return _fail(
            "Failed to write the keychain items; the partially written items were "
            f"removed — no stored set remains. Re-run `browser.py {store_cmd}`."
        )
    return _fail(
        "Failed to write the keychain items, and cleanup FAILED for "
        f"{', '.join(result.surviving)} — run `browser.py {forget_cmd}`."
    )


def _keychain_delete(service: str) -> bool:
    """Delete an item from the default keychain; ``True`` if deleted or already gone."""
    keychain = _kc_target_keychain()
    if keychain is None:
        return False
    return _kc_delete(service, keychain) in ("deleted", "absent")


def _totp_now(seed_or_uri: str) -> str | None:
    """Current 6-digit TOTP code from a base32 seed or an ``otpauth://`` URI.

    ``None`` for anything ``_parse_totp`` rejects.
    """
    otp = _parse_totp(seed_or_uri)
    return None if otp is None else str(otp.now())


def _fresh_totp(
    seed_or_uri: str,
    *,
    clock: Callable[[], float] = time.time,
    sleep: Callable[[float], None] = time.sleep,
) -> str | None:
    """A TOTP code with time left to be used (``broker.recipes.fresh_totp``).

    Called at fill time (see ``CscsCreds``) so a code is never stale by the
    time Keycloak checks it (tp#491 D2).
    """
    code: str | None = _broker_fresh_totp(seed_or_uri, clock=clock, sleep=sleep)
    return code


class CscsCreds(NamedTuple):
    """CSCS login credentials; the OTP is produced LAZILY at fill time.

    ``otp()`` returns a fresh code (or ``None`` on failure) and is called only
    once Keycloak shows the OTP field — a code captured before the password
    submit could be ~20 s stale by then (tp#491 D2).
    """

    user: str
    password: str
    otp: Callable[[], str | None]


def _keychain_creds() -> CscsCreds | None:
    """Read CSCS user/password/TOTP seed from the keychain.

    The OTP is generated locally from the stored seed at fill time (no live
    1Password call). Returns ``None`` if any item is missing or the seed can't
    produce a code, so the caller falls back to the Touch-ID ``op`` path.
    """
    user = _keychain_get(KEYCHAIN_SVC_USER)
    password = _keychain_get(KEYCHAIN_SVC_PASS)
    seed = _keychain_get(KEYCHAIN_SVC_TOTP)
    if not (user and password and seed):
        return None
    if _totp_now(seed) is None:
        return None
    return CscsCreds(user, password, functools.partial(_fresh_totp, seed))


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


def _op_otp(item: str, account: str) -> str | None:
    """The live TOTP code of ONE 1Password item (the ``--otp`` form of op).

    Run at fill time (see ``CscsCreds``), so the code is fresh when Keycloak
    checks it. ``None`` on any failure; the code is never printed/logged.
    """
    try:
        r = subprocess.run(
            ["op", "item", "get", item, "--account", account, "--otp"],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if r.returncode != 0:
        return None
    return r.stdout.strip() or None


def _op_creds(item: str, account: str) -> CscsCreds | None:
    """Read username + password for ONE 1Password item via op; OTP stays lazy.

    Returns ``CscsCreds`` (its ``otp()`` runs ``_op_otp`` at fill time) or
    ``None`` on failure. Secrets are returned in memory and NEVER printed/logged.
    Touch-ID-gated when the 1Password desktop app's "Integrate with 1Password
    CLI" is enabled.
    """
    try:
        creds = subprocess.run(
            [
                "op",
                "item",
                "get",
                item,
                "--account",
                account,
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
    except (OSError, subprocess.SubprocessError):
        return None
    if creds.returncode != 0:
        return None
    try:
        fields = {f.get("label"): f.get("value") for f in json.loads(creds.stdout)}
    except (ValueError, AttributeError, TypeError):
        return None
    user, password = fields.get("username"), fields.get("password")
    if not (isinstance(user, str) and isinstance(password, str) and user and password):
        return None
    return CscsCreds(user, password, functools.partial(_op_otp, item, account))


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


def _cscs_creds(
    *, announce: bool = True, allow_op: bool = False
) -> tuple[CscsCreds | None, str]:
    """Resolve ``CscsCreds`` for CSCS plus the source that produced it.

    Keychain first (prompt-free; the 6-digit code is generated locally from the
    stored seed). The 1Password item (``op``, Touch-ID-gated — native UI) is
    tried ONLY when `allow_op` is set, i.e. by the human-only
    ``login-cscs-assisted``; an unattended ``login cscs`` never falls back to it
    (tp#836: no Touch ID prompt outside a human flow; ``op`` is not installed).
    Called once per login ATTEMPT; the OTP itself is produced only at fill time
    (``CscsCreds.otp``), so every OTP step gets a code with time left.
    """
    creds = _keychain_creds()
    if creds is not None:
        if announce:
            print("Using CSCS credentials from the macOS keychain (no Touch ID).")
        return creds, "keychain"
    if not allow_op:
        return None, "none"
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


def _keycloak_otp_field(page):
    """The Keycloak OTP input element, or ``None`` when it is not on the page."""
    return (
        page.query_selector("#otp")
        or page.query_selector("input[name=otp]")
        or page.query_selector("input[autocomplete=one-time-code]")
    )


def _fill_keycloak_otp(page, otp: Callable[[], str | None]) -> bool:
    """Produce a fresh code NOW, then fill + submit the OTP step; ``True`` if sent.

    ``otp()`` may take seconds (``op`` / waiting out a step boundary), so the
    page is re-checked afterwards and the field re-queried: a page that moved
    on, or a detached field, gets NO code typed into it. Status lines are fixed
    text — never a code or exception detail.
    """
    from playwright.sync_api import Error as PlaywrightError

    code = otp()
    if not code:
        print("⚠ Could not produce a TOTP code — OTP step not submitted.")
        return False
    try:
        if _on_portal(page) or "auth.cscs.ch" not in page.url:
            print("⚠ The Keycloak page moved on before the OTP could be filled.")
            return False
        otp_input = _keycloak_otp_field(page)
        if otp_input is None:
            print("⚠ The Keycloak OTP field disappeared before it could be filled.")
            return False
        otp_input.fill(code)
        _click_keycloak_submit(page)
    except PlaywrightError:
        print("⚠ The Keycloak OTP step changed while filling it — not submitted.")
        return False
    return True


def _submit_keycloak_login(page, creds: CscsCreds) -> bool:
    """Fill the Keycloak form (+ the OTP step) and wait for the portal to settle.

    Returns ``True`` once ``_on_portal`` holds, ``False`` after ~20s without it
    or when the OTP step could not be filled (the caller decides whether that is
    a stale flow worth retrying or a real credential failure). The OTP code is
    generated only once the OTP field is shown (``_fill_keycloak_otp``).
    """
    page.fill("#username", creds.user)
    page.fill("#password", creds.password)
    _click_keycloak_submit(page)
    # Wait for EITHER the OTP step or a direct landing on the portal.
    otp_filled = False
    for _ in range(40):  # ~20s
        if _on_portal(page):
            return True
        if not otp_filled and _keycloak_otp_field(page):
            if not _fill_keycloak_otp(page, creds.otp):
                return _on_portal(page)
            otp_filled = True
        page.wait_for_timeout(500)
    return _on_portal(page)


def cmd_cscs_login(port: int, allow_op: bool = False) -> int:
    """Log into CSCS in the shared browser using stored credentials, then cache.

    Fills the Keycloak username/password + TOTP from the macOS keychain when set
    up (``cscs-store-creds``, no fingerprint); only with `allow_op` (the
    human-only ``login-cscs-assisted``) else from the single ``op`` item
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
                return _fail(
                    f"Unexpected page (not portal, not Keycloak): {_tab_hint(page.url)}"
                )
            else:
                cscs_login_mode = "keychain"
                for attempt in (1, 2):
                    creds, cscs_login_mode = _cscs_creds(
                        announce=attempt == 1, allow_op=allow_op
                    )
                    if creds is None:
                        return _fail(
                            "No CSCS credentials in the macOS keychain. Run "
                            "`browser.py cscs-store-creds` once (keychain, no "
                            "fingerprint) — an unattended login never falls back "
                            "to 1Password/Touch ID."
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
                            f"({_tab_hint(page.url)})."
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
                            f"Retry did not reach the Keycloak form ({_tab_hint(page.url)})."
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

    print("If macOS shows a keychain dialog, answer it.", file=sys.stderr)
    result = _keychain_set_all(
        [
            (KEYCHAIN_SVC_USER, user),
            (KEYCHAIN_SVC_PASS, password),
            (KEYCHAIN_SVC_TOTP, seed),
        ],
        "cscs-api credential",
    )
    if not result.ok:
        return _report_keychain_batch_failure(
            result, "store-creds cscs", "forget-creds cscs"
        )

    print(
        "✓ Stored CSCS username, password and TOTP seed in the macOS keychain.\n"
        "  `browser.py cscs-login` (and cscs-api.py auto-login) now run without "
        "Touch ID.\n  Verify with:  browser.py cscs-login   (or: cscs-api.py --login)\n"
        "  Revoke with:  browser.py cscs-forget-creds"
    )
    return 0


def cmd_cscs_forget_creds() -> int:
    """Delete the CSCS credentials stored in the macOS keychain."""
    services = (KEYCHAIN_SVC_USER, KEYCHAIN_SVC_PASS, KEYCHAIN_SVC_TOTP)
    left = [svc for svc in services if not _keychain_delete(svc)]
    if left:
        return _fail(f"Could not remove keychain item(s): {', '.join(left)}.")
    print(
        "✓ Removed CSCS keychain credentials. `browser.py login cscs` uses the "
        "login broker (Bitwarden)."
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


# Anthropic has renamed the magic-link subject at least once. Observed subjects:
#   2026-08  "Your secure link to Claude.ai is here | <timestamp>"
# The original filter demanded "log in to Claude.ai", which never matched.
# The subject only RECOGNISES a login mail; the SENDER authorises it (tp#490):
# anyone can write that subject, but a From on mail.anthropic.com is covered by
# DMARC p=reject (anthropic.com and mail.anthropic.com), so a DMARC-honouring
# receiver drops a forgery. The localpart is randomised per message
# (`no-reply-<random>@mail.anthropic.com`), so the default entry is a domain.
_ANTHROPIC_LOGIN_MAIL_SENDERS_DEFAULT = ("mail.anthropic.com",)
_CLAUDE_SUBJECT_HINTS = ("secure link to Claude.ai", "log in to Claude.ai")
_DOMAIN_LABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?")


def _diag(sink: list[str] | None, msg: str) -> None:
    """Record a one-line reason for a silent skip, de-duplicated."""
    if sink is not None and msg not in sink:
        sink.append(msg)


def _printable(s: object, limit: int = 120) -> str:
    """`s` made safe to echo to a terminal: every non-printable character
    (ESC, CR, LF, other control and format characters) dropped, truncated to
    `limit` characters with '…'. For attacker-controlled senders/subjects."""
    out = "".join(c for c in str(s) if c.isprintable())
    return out if len(out) <= limit else out[: limit - 1] + "…"


def _valid_mail_domain(dom: str) -> bool:
    """Lower-case DNS name with at least one dot; labels [a-z0-9-], no edge '-'."""
    labels = dom.split(".")
    return (
        len(dom) <= 253
        and len(labels) >= 2
        and all(len(lb) <= 63 and _DOMAIN_LABEL_RE.fullmatch(lb) for lb in labels)
    )


def _login_mail_senders() -> tuple[tuple[str, ...], str | None]:
    """The login-mail sender allow-list → (entries, config error).

    `ANTHROPIC_LOGIN_MAIL_SENDERS` is comma-separated; each entry is an exact
    address (`no-reply@mail.anthropic.com`) or an exact domain
    (`mail.anthropic.com` or `@mail.anthropic.com`). Unset/blank → the default.
    Any invalid entry makes the whole override an error (entries `()`), so a
    typo disables auto-login instead of silently widening or narrowing it.
    Domain entries are returned bare, address entries with their '@'."""
    raw = os.environ.get("ANTHROPIC_LOGIN_MAIL_SENDERS", "")
    if not raw.strip():
        return _ANTHROPIC_LOGIN_MAIL_SENDERS_DEFAULT, None
    entries: list[str] = []
    for item in raw.split(","):
        entry = item.strip().lower()
        if not entry:
            continue
        if entry.startswith("@"):
            ok = "@" not in entry[1:] and _valid_mail_domain(entry[1:])
            entry = entry[1:]
        elif "@" in entry:
            local, _, dom = entry.partition("@")
            ok = (
                "@" not in dom
                and bool(local)
                and not any(c.isspace() for c in local)
                and local.isprintable()
                and _valid_mail_domain(dom)
            )
        else:
            ok = _valid_mail_domain(entry)
        if not ok:
            return (), (
                "ANTHROPIC_LOGIN_MAIL_SENDERS has an invalid entry "
                f"{_printable(item.strip())!r} (want an address or a domain)"
            )
        if entry not in entries:
            entries.append(entry)
    if not entries:
        return (), "ANTHROPIC_LOGIN_MAIL_SENDERS has no entries"
    return tuple(entries), None


def _sender_allowed(addr: str, allow: tuple[str, ...]) -> bool:
    """Exact-address or exact-domain match — never a suffix/subdomain match."""
    addr = (addr or "").strip().lower()
    if addr.count("@") != 1:
        return False
    dom = addr.partition("@")[2]
    return any(addr == e if "@" in e else dom == e for e in allow)


def _env_str(env: Mapping[str, object], key: str) -> str:
    """A himalaya envelope field as a string; any non-string shape is ``""``."""
    value = env.get(key)
    return value if isinstance(value, str) else ""


def _env_addrs(env: Mapping[str, object], key: str) -> tuple[str, list[str]]:
    """The lower-cased addresses of envelope field `key` as ``(state, addrs)``.

    himalaya's JSON shape varies across versions/backends: ``{"addr": …}``, a
    list of those or of strings, or a plain (possibly comma-separated,
    display-named) string. ``state`` is ``"absent"`` (missing/empty),
    ``"valid"`` or ``"malformed"`` — anything unparseable, so a sender check can
    never turn odd input into acceptance (tp#491 D4).
    """
    from email.utils import getaddresses

    raw = env.get(key)
    if raw is None or raw in ("", [], {}):
        return "absent", []
    addrs: list[str] = []
    for item in raw if isinstance(raw, list) else [raw]:
        if isinstance(item, dict):
            found = item.get("addr")
            if not isinstance(found, str):
                return "malformed", []
            parsed = [found.strip()]
        elif isinstance(item, str):
            parsed = [a.strip() for _name, a in getaddresses([item])]
        else:
            return "malformed", []
        if not parsed or any(a.count("@") != 1 for a in parsed):
            return "malformed", []
        addrs += [a.lower() for a in parsed]
    return "valid", addrs


def _mail_sender(env: Mapping[str, object]) -> str:
    """The one sender address, or ``""`` when absent, malformed or multiple."""
    state, addrs = _env_addrs(env, "from")
    return addrs[0] if state == "valid" and len(addrs) == 1 else ""


def _looks_like_claude_login_mail(env: Mapping[str, object]) -> bool:
    """Subject-only recognition of a magic-link mail — says nothing about who
    sent it. Ordinary product mail ("You have new requests from your team")
    ships from the same domain and must not match, or it would starve the real
    login mail."""
    subject = _env_str(env, "subject").lower()
    if any(h.lower() in subject for h in _CLAUDE_SUBJECT_HINTS):
        return True
    return "claude" in subject and "link" in subject


def _is_claude_login_mail(
    env: Mapping[str, object], allow: tuple[str, ...] | None = None
) -> bool:
    """A login-looking mail from an allow-listed sender (see
    `_login_mail_senders`; an invalid override allows nobody)."""
    if allow is None:
        allow = _login_mail_senders()[0]
    return _looks_like_claude_login_mail(env) and _sender_allowed(
        _mail_sender(env), allow
    )


def _himalaya_list_folder(
    himalaya: str,
    folder: str,
    account: str | None = None,
    diag: list[str] | None = None,
) -> list[dict] | None:
    """The newest 30 envelopes of `folder`, or None (reason in `diag`)."""
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
        return None
    if res.returncode != 0:
        _diag(
            diag,
            f"{folder}: himalaya exited {res.returncode} "
            f"({(res.stderr or '').strip()[:160] or 'no stderr'})",
        )
        return None
    try:
        envs = json.loads(res.stdout)
    except (ValueError, TypeError) as exc:
        _diag(diag, f"{folder}: himalaya output was not JSON ({exc})")
        return None
    if not isinstance(envs, list):
        _diag(diag, f"{folder}: himalaya JSON was not a list")
        return None
    return [e for e in envs if isinstance(e, dict)]


_LOGIN_MAIL_FOLDERS = ("INBOX", "Archive")  # a server rule auto-archives them
_MAX_REJECTED_SENDERS = 5


def _himalaya_login_mail_candidates(
    himalaya: str,
    email: str,
    since_ts: float,
    *,
    account: str | None = None,
    diag: list[str] | None = None,
    rejected_senders: list[str] | None = None,
    allow: tuple[str, ...] | None = None,
) -> list[tuple[str, str]]:
    """Every eligible Anthropic magic-link mail to `email` as (folder, id),
    newest first (a dated mail always before an undated one). Searches INBOX +
    Archive.

    A login-looking mail from a sender outside the allow-list is never a
    candidate; its sanitized sender goes to `rejected_senders` (de-duplicated,
    at most 5). The `since_ts` date window is only a backstop — the caller's
    pre-trigger baseline is what excludes old mails. `diag` collects one-line
    reasons for every other skip; the caller prints them, because every
    failure path here is otherwise silent."""
    if allow is None:
        allow = _login_mail_senders()[0]
    ranked: list[tuple[tuple[int, float], str, str]] = []
    seen = looked_like = 0
    for folder in _LOGIN_MAIL_FOLDERS:
        envs = _himalaya_list_folder(himalaya, folder, account=account, diag=diag)
        for env in envs or []:
            seen += 1
            if not _looks_like_claude_login_mail(env):
                continue
            looked_like += 1
            sender = _mail_sender(env)
            if not _sender_allowed(sender, allow):
                msg = (
                    f"{folder}: rejected a Claude login-looking mail from "
                    f"{_printable(sender) or '<no single valid sender>'} — not in "
                    f"ANTHROPIC_LOGIN_MAIL_SENDERS ({', '.join(allow)})"
                )
                if (
                    rejected_senders is not None
                    and len(rejected_senders) < _MAX_REJECTED_SENDERS
                ):
                    _diag(rejected_senders, msg)
                continue
            to_state, to = _env_addrs(env, "to")
            if email and to_state == "malformed":
                _diag(diag, f"{folder}: a Claude login mail had an unreadable To:")
                continue
            if email and to_state == "valid" and email.lower() not in to:
                _diag(
                    diag,
                    f"{folder}: a Claude login mail was addressed to "
                    f"{_printable(', '.join(to))}, not {email}",
                )
                continue
            raw_date = _env_str(env, "date")
            ts = _himalaya_date_epoch(raw_date)
            if ts and ts + 180 < since_ts:  # clearly older than our trigger → skip
                continue
            if not ts:
                # Unparsable date: still eligible, but ranked BELOW any dated
                # candidate — a date-format change must not make an arbitrary
                # old mail win.
                _diag(
                    diag,
                    f"{folder}: could not parse mail date {_printable(raw_date)!r}",
                )
            ranked.append(((1 if ts else 0, ts), folder, str(env.get("id"))))
    if not ranked and looked_like == 0:
        _diag(
            diag,
            f"no Anthropic login mail among the {seen} newest envelopes "
            f"(looked for subject ~ {_CLAUDE_SUBJECT_HINTS[0]!r} from "
            f"ANTHROPIC_LOGIN_MAIL_SENDERS: {', '.join(allow) or '<none>'})",
        )
    ranked.sort(key=lambda r: r[0], reverse=True)  # stable: listing order on ties
    return [(folder, msg_id) for _key, folder, msg_id in ranked]


def _himalaya_read_message(
    himalaya: str,
    folder: str,
    msg_id: str,
    account: str | None = None,
    preview: bool = False,
) -> str | None:
    """The rendered message, or None when himalaya failed. `preview` keeps the
    seen flag untouched (`message read --preview`)."""
    argv = [himalaya, "message", "read", msg_id, "--folder", folder]
    if preview:
        argv.append("--preview")
    if account:
        argv += ["-a", account]
    try:
        res = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if res.returncode != 0:
        return None
    return res.stdout or ""


def _himalaya_extract_magic_link(
    himalaya: str,
    folder: str,
    msg_id: str,
    account: str | None = None,
    preview: bool = False,
) -> str | None:
    """Read the mail body and pull out the claude.ai/magic-link#… URL (a bearer
    credential — never printed/logged). `account` must be the one the envelope
    was found in: a message id is only meaningful within its own mailbox."""
    body = _himalaya_read_message(
        himalaya, folder, msg_id, account=account, preview=preview
    )
    m = _MAGIC_LINK_RE.search(body or "")
    return m.group(0) if m else None


def _magic_link_digest(link: str) -> str:
    """sha256 of a magic link — lets us remember a link without keeping it."""
    import hashlib

    return hashlib.sha256(link.encode("utf-8")).hexdigest()


def _himalaya_login_link_baseline(
    himalaya: str, account: str | None = None, diag: list[str] | None = None
) -> set[str] | None:
    """Digests of every magic link already in the mailbox BEFORE we trigger a
    new one. Sender-independent on purpose, so a pre-planted forged mail is
    excluded as well. Keyed by link (not by folder/id/date), so it survives the
    INBOX→Archive server rule and has no minute-precision collisions.

    None when any folder or login-looking body could not be read: then old and
    new mails cannot be told apart, and the caller must not auto-login."""
    digests: set[str] = set()
    for folder in _LOGIN_MAIL_FOLDERS:
        envs = _himalaya_list_folder(himalaya, folder, account=account, diag=diag)
        if envs is None:
            return None
        for env in envs:
            if not _looks_like_claude_login_mail(env):
                continue
            msg_id = str(env.get("id"))
            body = _himalaya_read_message(
                himalaya, folder, msg_id, account=account, preview=True
            )
            if body is None:
                _diag(diag, f"{folder}: could not read login mail id {msg_id}")
                return None
            m = _MAGIC_LINK_RE.search(body)
            if m:
                digests.add(_magic_link_digest(m.group(0)))
    return digests


def _magic_link_email(link: str) -> str | None:
    """The account a magic link names: `#<token>:<base64 email>` → the email,
    lower-cased. Standard or URL-safe base64, padding optional. None when the
    link is not a full `_MAGIC_LINK_RE` match or the part does not decode to
    exactly one address."""
    import base64
    import binascii

    if not link or not _MAGIC_LINK_RE.fullmatch(link):
        return None
    frag = link.partition("#")[2]
    if ":" not in frag:
        return None
    b64 = frag.rsplit(":", 1)[1].rstrip("=").replace("-", "+").replace("_", "/")
    if not b64:
        return None
    try:
        raw = base64.b64decode(b64 + "=" * (-len(b64) % 4), validate=True)
        addr = raw.decode("utf-8").strip().lower()
    except (binascii.Error, ValueError):
        return None
    if addr.count("@") != 1 or not addr.isprintable() or " " in addr:
        return None
    local, _, dom = addr.partition("@")
    return addr if local and dom else None


def _claude_next_magic_link(
    himalaya: str,
    email: str,
    since_ts: float,
    *,
    account: str | None,
    allow: tuple[str, ...],
    baseline: set[str],
    rejected: dict[str, str],
    diag: list[str],
    rejected_senders: list[str],
) -> str | None:
    """One poll round: the newest candidate whose link is new (not in
    `baseline`) and names `email`. Every refused candidate goes to `rejected`
    (envelope key → reason) so it is never re-read and never starves an older,
    valid candidate in the same round."""
    want = email.strip().lower()
    for folder, msg_id in _himalaya_login_mail_candidates(
        himalaya,
        email,
        since_ts,
        account=account,
        diag=diag,
        rejected_senders=rejected_senders,
        allow=allow,
    ):
        key = f"{folder}\0{msg_id}"
        if key in rejected:
            continue
        body = _himalaya_read_message(
            himalaya, folder, msg_id, account=account, preview=True
        )
        if body is None:  # transient read failure → retry next round
            _diag(diag, f"could not read the login mail ({folder} id {msg_id})")
            continue
        m = _MAGIC_LINK_RE.search(body)
        if not m:
            rejected[key] = f"found a mail ({folder} id {msg_id}) but no magic link"
            continue
        link = m.group(0)
        if _magic_link_digest(link) in baseline:
            rejected[key] = (
                f"skipped a login mail ({folder} id {msg_id}) that predates "
                "this attempt"
            )
            continue
        if _magic_link_email(link) != want:
            # Never print the link or the foreign email it names.
            rejected[key] = (
                f"found a login mail ({folder} id {msg_id}) whose link is for a "
                "different account — refusing to open it"
            )
            continue
        return link
    return None


def _claude_auto_login(page, email: str, himalaya: str) -> str:
    """Fully automatic login: trigger the magic-link email, read it via himalaya,
    open the link in the shared browser (the SPA reads the #token and signs in).
    No password, no manual code.

    Returns "ok" (logged in), "submitted" (the email form was submitted — a
    link is on its way — but login did not complete) or "not_submitted"
    (nothing was requested: bad allow-list, no baseline, or the form failed).

    Three guards against opening someone else's link (login CSRF, tp#490):
    the sender allow-list, the pre-trigger baseline, and the link's embedded
    email must equal `email` (defense in depth)."""
    # One branch per step of the magic-link handshake (baseline → submit email
    # → poll the mailbox → open the link → confirm the session), each with its
    # own operator message before falling back to assisted login.
    # pylint: disable=too-many-branches,too-many-return-statements
    from playwright.sync_api import Error as PlaywrightError

    allow, err = _login_mail_senders()
    if err:
        print(f"  {err} — not auto-logging in.", file=sys.stderr)
        return "not_submitted"
    account = os.environ.get("ANTHROPIC_LOGIN_HIMALAYA_ACCOUNT")
    diag: list[str] = []
    baseline = _himalaya_login_link_baseline(himalaya, account=account, diag=diag)
    if baseline is None:
        print(
            "  Cannot tell old login mails from new ones — not auto-logging in.",
            file=sys.stderr,
        )
        for reason in diag:
            print(f"    · {reason}", file=sys.stderr)
        return "not_submitted"
    trigger_ts = time.time()
    if not _claude_fill_email_and_continue(page, email):
        print(
            "  Could not submit the email on the login form — no link was requested.",
            file=sys.stderr,
        )
        return "not_submitted"
    print(
        f"  Sent a login link to {email}; reading it via himalaya"
        f"{f' (account {account})' if account else ' (default account)'}…",
        file=sys.stderr,
    )
    link = None
    rejected: dict[str, str] = {}  # per attempt: envelope key → why refused
    rejected_senders: list[str] = []  # kept across rounds, printed on failure
    # EPFL Exchange delivery can lag well past a minute; overridable because the
    # right value is a property of the mail path, not of this code.
    try:
        wait_s = max(10, int(os.environ.get("ANTHROPIC_LOGIN_MAIL_TIMEOUT", "180")))
    except ValueError:
        wait_s = 180
    deadline = time.monotonic() + wait_s
    while time.monotonic() < deadline:
        diag.clear()  # keep only the last round's transient reasons
        link = _claude_next_magic_link(
            himalaya,
            email,
            trigger_ts,
            account=account,
            allow=allow,
            baseline=baseline,
            rejected=rejected,
            diag=diag,
            rejected_senders=rejected_senders,
        )
        if link:
            break
        time.sleep(3)
    if not link:
        print(
            f"  No usable magic-link email arrived within {wait_s}s.", file=sys.stderr
        )
        reasons = [*rejected_senders, *dict.fromkeys(rejected.values()), *diag]
        for reason in reasons:
            print(f"    · {reason}", file=sys.stderr)
        return "submitted"
    try:
        page.goto(link, wait_until="domcontentloaded")  # SPA consumes #token → signs in
    except PlaywrightError:
        return "submitted"
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
            return "ok"
        page.wait_for_timeout(2000)
    return "submitted"


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
                _bring_to_front(page, "login anthropic", port)
            except PlaywrightError:
                pass

            himalaya = _himalaya_bin()
            auto_attempted = False  # True once auto-login submitted the email
            if ANTHROPIC_LOGIN_EMAIL and himalaya:
                print(
                    f"Automatic login for {ANTHROPIC_LOGIN_EMAIL} (magic-link via himalaya)…",
                    file=sys.stderr,
                )
                result = _claude_auto_login(page, ANTHROPIC_LOGIN_EMAIL, himalaya)
                if result == "ok":
                    print("✓ Logged into Claude (claude.ai).")
                    _record_login_event("anthropic", "auto")
                    return 0
                auto_attempted = result == "submitted"
                print(
                    "  Automatic login didn't complete — falling back to assisted.",
                    file=sys.stderr,
                )

            # Assisted fallback — needs a human at a real window (the automatic
            # magic-link path above works fine headless, so it is NOT gated).
            if not _guided_login_allowed(port, "anthropic", "claude.ai"):
                return NEEDS_ALBERT_RC
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


def _logged_in_page_check(
    port: int, url_substr: str, check: Callable[[Any], bool]
) -> bool:
    """Run an ACTIVE logged-in `check(page)` (it navigates the page itself).

    Normally on the tab `_pick_page` finds for `url_substr`. While a guided
    login is live, ONLY in a fresh background tab of its own: the picked tab
    could be the guided login's OWNED login tab (or its OAuth popup), and the
    check's navigation would reload Albert's half-typed login every 5 s. The
    guided login's own probes always run that way ($PROBE_BACKGROUND_ENV),
    the one before the transaction too: it must not leave or reuse a tab.
    """
    if _maint_live() is not None or os.environ.get(PROBE_BACKGROUND_ENV) == "1":
        return bool(_with_background_page(port, "about:blank", check))
    pw, browser = _connect(port)
    try:
        _ctx, page = _pick_page(browser, url_substr)
        return bool(check(page))
    finally:
        browser.close()
        pw.stop()


def cmd_anthropic_logged_in(port: int) -> int:
    """Exit 0 if claude.ai is logged in (billing surface reachable), else 2."""
    if _logged_in_page_check(port, "claude.ai", _claude_logged_in):
        print("✓ Logged into Claude (claude.ai).")
        return 0
    print("Not logged into Claude (claude.ai).", file=sys.stderr)
    return 2


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
        # Warm probe + guided-login gate FIRST, outside the lease (both are the
        # read-only checks `logged-in` does lease-free); only the assisted
        # interaction below needs the exclusive lease.
        _ctx, page = _pick_page(browser, "chatgpt.com")
        if _chatgpt_logged_in(page):
            print("✓ Already logged into ChatGPT (chatgpt.com).")
            return 0
        # A cold session needs Albert — only inside a guided login (exit 4).
        if not _guided_login_allowed(port, "openai", "chatgpt.com"):
            return NEEDS_ALBERT_RC
        with _interaction_lease("login openai"):
            from playwright.sync_api import Error as PlaywrightError

            try:
                _bring_to_front(page, "login openai", port)
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
    if _logged_in_page_check(port, "chatgpt.com", _chatgpt_logged_in):
        print("✓ Logged into ChatGPT (chatgpt.com).")
        return 0
    print("Not logged into ChatGPT (chatgpt.com).", file=sys.stderr)
    return 2


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
        # Warm probe + guided-login gate FIRST, outside the lease (read-only, the
        # same checks `logged-in` does lease-free).
        _ctx, page = _pick_page(browser, "slack.com")
        if _slack_logged_in(page):
            print("✓ Already logged into Slack — session persists; nothing to do.")
            return 0
        # A cold session needs Albert — only inside a guided login (exit 4).
        if not _guided_login_allowed(port, "slack", "Slack"):
            return NEEDS_ALBERT_RC
        with _interaction_lease("login slack"):
            from playwright.sync_api import Error as PlaywrightError

            # Land straight on the SDSC workspace sign-in (skips the workspace picker).
            try:
                page.goto(SLACK_WORKSPACE_URL, wait_until="domcontentloaded")
                _bring_to_front(page, "login slack", port)
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
    if _logged_in_page_check(port, "slack.com", _slack_logged_in):
        print("✓ Logged into Slack (app.slack.com).")
        return 0
    print("Not logged into Slack (app.slack.com).", file=sys.stderr)
    return 2


def cmd_slack_session(port: int) -> int:
    """Print the live Slack session creds as JSON `{token, cookie, team_domain}`
    for a consumer (slack_api.py) to make admin API calls. These are BEARER
    credentials — emitted to stdout only (like `token` for CSCS), never cached to
    disk (xoxc rotates) or logged. Exits 2 (with a hint) when not logged in."""
    pw, browser = _connect(port)
    try:
        _ctx, page = _pick_page(browser, "slack.com")
        if not _slack_logged_in(page):
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
    print("If macOS shows a keychain dialog, answer it.", file=sys.stderr)
    result = _keychain_set_all(
        [
            (KEYCHAIN_SVC_BIOPOL_EMAIL, email),
            (KEYCHAIN_SVC_BIOPOL_PASS, password),
        ],
        "biopol-wifi credential",
    )
    if not result.ok:
        return _report_keychain_batch_failure(
            result, "store-creds biopolwifi", "forget-creds biopolwifi"
        )
    print(
        "✓ Stored the Cloudpath portal email and password in the macOS keychain.\n"
        "  `browser.py login biopolwifi` now runs without a prompt.\n"
        "  Verify with:  browser.py login biopolwifi\n"
        "  Revoke with:  browser.py forget-creds biopolwifi"
    )
    return 0


def cmd_biopolwifi_forget_creds() -> int:
    """Delete the Cloudpath MDU portal credentials from the macOS keychain."""
    services = (KEYCHAIN_SVC_BIOPOL_EMAIL, KEYCHAIN_SVC_BIOPOL_PASS)
    left = [svc for svc in services if not _keychain_delete(svc)]
    if left:
        return _fail(f"Could not remove keychain item(s): {', '.join(left)}.")
    print(
        "✓ Removed the Cloudpath portal keychain credentials. "
        "`browser.py login biopolwifi` needs `store-creds biopolwifi` again."
    )
    return 0


# ---------------------------------------------------------------------------
# Switch Cloud Portal (cloud.switch.ch) — edu-ID SSO click, assisted fallback, no token
# ---------------------------------------------------------------------------
# SDSC's tenant of the SWITCH Cloud Portal authenticates through SWITCH edu-ID
# (OpenID Connect). Its /auth/login page carries exactly ONE control: a button
# that POSTs to /auth/openid_connect_eduid_ch. While the browser's edu-ID IdP
# session is alive, that click IS the whole login (no password, no 2-step code);
# otherwise it lands on login.eduid.ch and a human finishes it once (ASSISTED).
# No token is extracted — the consumer (switch-cloud's `-P` saga) drives the
# portal itself and only needs the session to exist.
#
# The portal's session cookie is a BROWSER-SESSION cookie, so every restart of
# the shared Chromium logs it out again; `logged-in switch` is therefore polled
# (every 30 min by the infra/status check `switch-portal-login`) and must stay
# strictly read-only: no interaction lease, no focus, no navigating a tab the
# user owns.
SWITCH_ORIGIN = "https://cloud.switch.ch"
SWITCH_LOGIN_PATH = "/auth/login"
SWITCH_SIGN_IN_FORM_ACTION = "/auth/openid_connect_eduid_ch"
SWITCH_SIGN_IN_FORM_SELECTOR = f'form[action="{SWITCH_SIGN_IN_FORM_ACTION}"]'
SWITCH_SIGN_IN_BUTTON_SELECTOR = SWITCH_SIGN_IN_FORM_SELECTOR + " button[type=submit]"


def _switch_verdict(url: str, has_sign_in_form: bool) -> str:
    """Classify a portal page as ``login`` / ``logged-in`` / ``unknown`` (pure).

    The FORM is the primary evidence, the URL only secondary: an anonymous
    ``GET /`` answers 200 **at** ``/`` and renders the edu-ID sign-in page right
    there (verified 2026-09-14 with curl), so "the tab is on cloud.switch.ch" is
    never evidence of a session — the absence of that form is.

    Everything that is not positively one of the two — an off-origin IdP page
    (login.eduid.ch), ``about:blank``, a ``chrome-error://`` page, an empty URL,
    an OIDC callback still under ``/auth/`` — is ``unknown``. This fails CLOSED:
    callers treat ``unknown`` exactly as "not logged in".
    """
    if has_sign_in_form or SWITCH_LOGIN_PATH in url:
        return "login"
    if url == SWITCH_ORIGIN or url.startswith(SWITCH_ORIGIN + "/"):
        if not url[len(SWITCH_ORIGIN) :].startswith("/auth/"):
            return "logged-in"
    return "unknown"


def _switch_has_sign_in_form(page) -> bool | None:
    """True/False whether the edu-ID sign-in form is in the DOM; None if unknown.

    None (the page navigated away mid-query, the target died, CDP hiccuped) is
    deliberately NOT False: "we could not read the DOM" must never be promoted
    into "there is no login form", i.e. into evidence of a session.
    """
    try:
        return page.query_selector(SWITCH_SIGN_IN_FORM_SELECTOR) is not None
    except Exception:  # pylint: disable=broad-exception-caught
        return None


def _switch_page_verdict(page) -> str:
    """`_switch_verdict` for a live page, with the fail-closed rule applied: a
    DOM we could not read never yields ``logged-in``."""
    try:
        url = page.url
    except Exception:  # pylint: disable=broad-exception-caught
        return "unknown"
    has_form = _switch_has_sign_in_form(page)
    verdict = _switch_verdict(url, bool(has_form))
    if has_form is None and verdict == "logged-in":
        return "unknown"
    return verdict


def _switch_page_by_target(browser, tid: str):
    """The Playwright page whose CDP target id is `tid`, or None.

    `doctor` finds its probe tab by URL; that is NOT acceptable here — a stale,
    logged-out portal tab the user left open would answer for our probe and be
    read as the session's state. The target id is the only identity a real tab
    cannot accidentally impersonate.
    """
    from playwright.sync_api import Error as PlaywrightError

    for ctx in browser.contexts:
        for pg in ctx.pages:
            session = None
            try:
                session = ctx.new_cdp_session(pg)
                info = session.send("Target.getTargetInfo")
                if str(info.get("targetInfo", {}).get("targetId") or "") == tid:
                    return pg
            except PlaywrightError:
                continue
            finally:
                if session is not None:
                    with contextlib.suppress(PlaywrightError):
                        session.detach()
    return None


def _switch_close_target(browser, tid: str) -> None:
    """Close the probe target over CDP — the path for a tab Playwright never
    adopted, which `page.close()` cannot reach (it would else stay open)."""
    session = browser.new_browser_cdp_session()
    session.send("Target.closeTarget", {"targetId": tid})


def _switch_probe(port: int) -> tuple[str, str]:
    """READ-ONLY portal probe; returns (verdict, observed url). Never focuses.

    Takes NO interaction lease and touches no tab of the user's: the probe page
    is created in the BACKGROUND over CDP (``background: true`` cannot raise the
    window), read, and closed again in the ``finally``. Playwright never adopts
    a target created mid-session, so the connection is dropped and re-made —
    the same dance as `_doctor_probe`, except that the page is identified by its
    TARGET ID (see `_switch_page_by_target`).

    Anything that goes wrong is ``unknown``, never ``logged-in``.
    """
    from playwright.sync_api import Error as PlaywrightError

    pw, browser = _connect(port)
    tid = ""
    try:
        session = browser.new_browser_cdp_session()
        created = session.send(
            "Target.createTarget",
            {"url": SWITCH_ORIGIN + "/", "background": True},
        )
        tid = str(created.get("targetId") or "")
    except PlaywrightError:  # TimeoutError subclasses this
        return ("unknown", "")
    finally:
        browser.close()
        pw.stop()
    if not tid:
        return ("unknown", "")

    pw, browser = _connect(port)
    page = None
    url = ""
    try:
        page = _switch_page_by_target(browser, tid)
        if page is None:
            return ("unknown", "")
        page.wait_for_load_state("domcontentloaded", timeout=10_000)
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            url = page.url
            if not _is_blank(url):
                break
            time.sleep(0.25)
        page.wait_for_timeout(500)  # let a Turbo redirect land
        url = page.url
        return (_switch_page_verdict(page), url)
    except PlaywrightError:  # TimeoutError subclasses this
        return ("unknown", url)
    finally:
        if page is not None:
            with contextlib.suppress(PlaywrightError):
                page.close()
        else:
            with contextlib.suppress(PlaywrightError):
                _switch_close_target(browser, tid)
        browser.close()
        pw.stop()


def _switch_wait_for_login(
    page, timeout_s: float, poll_s: float = 0.5, heartbeat: bool = False
) -> bool:
    """PASSIVE poll of the login tab: True as soon as it settles logged in.

    Never navigates the tab — a `goto` mid-flight would abort the edu-ID
    redirect chain the human is completing. `heartbeat` prints a progress line
    to stderr every 30 s (the long assisted wait), exactly like
    `_chatgpt_wait_for_login`.
    """
    start = time.monotonic()
    last_beat = 0.0
    while time.monotonic() - start < timeout_s:
        if _switch_page_verdict(page) == "logged-in":
            return True
        elapsed = time.monotonic() - start
        if heartbeat and elapsed - last_beat >= 30:
            print(
                f"  …waiting for you to finish the SWITCH edu-ID login in the "
                f"shared browser window ({int(elapsed)}s elapsed)…",
                file=sys.stderr,
            )
            last_beat = elapsed
        try:
            page.wait_for_timeout(poll_s * 1000)
        except Exception:  # pylint: disable=broad-exception-caught
            time.sleep(poll_s)
    return False


def cmd_switch_logged_in(port: int) -> int:
    """Exit 0 if the Switch Cloud Portal is logged in, 2 if not — and 2 when it
    cannot be told (fail CLOSED; a monitoring check treats 2 as red).

    READ-ONLY by contract: no interaction lease, no `bring_to_front`, no
    `new_page` — it opens one background tab and closes it again.
    """
    verdict, url = _switch_probe(port)
    if verdict == "logged-in":
        print("✓ Logged into Switch Cloud Portal (cloud.switch.ch).")
        return 0
    if verdict == "login":
        print("Not logged into Switch Cloud Portal (cloud.switch.ch).", file=sys.stderr)
        return 2
    print(
        f"Cannot tell whether Switch Cloud Portal is logged in — the probe "
        f"landed on {url!r}.",
        file=sys.stderr,
    )
    return 2


def _switch_eduid_broker_listed() -> bool:
    """True when the login broker lists a usable (not refused) ``eduid`` item.

    Read-only (the broker's ``sites`` list); an unreachable broker is False —
    the caller then takes the window-based flow as before.
    """
    try:
        entry = _broker_site("eduid")
    except BrokerUnavailable:
        return False
    return entry is not None and not entry.get("refused")


def _switch_sso_click_background(port: int) -> bool:
    """The edu-ID SSO click in a BACKGROUND tab; True iff it ends logged in.

    Needs no visible window (the IdP session already lives in the profile, so
    the click completes without typing). Proof is `_switch_page_verdict` on
    that same tab, polled by `_switch_wait_for_login`. Held under the
    interaction lease like the window flow, so no other tool clicks meanwhile.
    """
    from playwright.sync_api import Error as PlaywrightError

    def click(page) -> bool:
        # No form = already logged in or mid-flow: the verdict decides.
        with contextlib.suppress(PlaywrightError):
            page.click(SWITCH_SIGN_IN_BUTTON_SELECTOR, timeout=10_000)
        return _switch_wait_for_login(page, timeout_s=20)

    with _interaction_lease("login switch"):
        return bool(
            _with_background_page(port, SWITCH_ORIGIN + SWITCH_LOGIN_PATH, click)
        )


def _switch_login_via_eduid_broker(port: int) -> bool:
    """Chain the broker's ``eduid`` login into the portal's SSO click.

    Returns True when the portal ends logged in (event ``broker-sso`` recorded);
    False — after a ⚠️ line saying why — when the broker has no ``eduid``, its
    login fails, or the click does not complete; the caller then falls back to
    the window-based flow.
    """
    if not _switch_eduid_broker_listed():
        return False
    print("▶ edu-ID session from the login broker, then the SSO click (background).")
    rc = _broker_login(port, "eduid")
    if rc != 0:
        print(
            f"⚠️ broker login eduid failed (exit {rc}) — falling back to the "
            "window flow.",
            file=sys.stderr,
        )
        return False
    if _switch_sso_click_background(port):
        print("✅ Logged into Switch Cloud Portal (broker edu-ID session + SSO click).")
        _record_login_event("switch", "broker-sso")
        return True
    print(
        "⚠️ SSO click with the broker's edu-ID session did not log in — falling "
        "back to the window flow.",
        file=sys.stderr,
    )
    return False


def _switch_warm_or_via_broker(port: int) -> bool:
    """True when the portal is already logged in, or gets logged in through the
    broker's edu-ID session — the two window-free ways `cmd_switch_login` tries
    before the window flow."""
    if _switch_probe(port)[0] == "logged-in":
        print("✓ Already logged into Switch Cloud Portal (cloud.switch.ch).")
        return True
    return _switch_login_via_eduid_broker(port)


def cmd_switch_login(port: int) -> int:
    """Ensure the Switch Cloud Portal is logged in. Idempotent (a warm session
    just returns 0).

    A cold session is one click: the /auth/login page's single edu-ID button
    completes the login with NO password while the browser's edu-ID IdP session
    is alive. When the login broker lists ``eduid``, that IdP session is first
    obtained from the broker and the click runs in a BACKGROUND tab — no window
    needed, headless works (mode ``broker-sso``, `_switch_login_via_eduid_broker`).
    Otherwise (or if that fails) the click runs in the shared window (mode
    ``sso``), and when it lands on login.eduid.ch the run becomes ASSISTED — you
    finish the edu-ID login once there. The interactive part is held under the
    INTERACTION lease, so no other tool clicks in the meantime.
    """
    from playwright.sync_api import Error as PlaywrightError

    # Warm probe + guided-login gate FIRST, outside the lease (both are read-only,
    # exactly what `logged-in` does lease-free).
    if _switch_warm_or_via_broker(port):
        return 0
    if not _guided_login_allowed(port, "switch", "Switch Cloud Portal"):
        return NEEDS_ALBERT_RC
    pw, browser = _connect(port)
    try:
        with _interaction_lease("login switch"):
            ctx = browser.contexts[0] if browser.contexts else browser.new_context()
            page = next((pg for pg in ctx.pages if "cloud.switch.ch" in pg.url), None)
            if page is None:
                # Allowed here and nowhere else in this site: the flow is
                # interactive and the window is headed by the guard above.
                page = ctx.new_page()
            try:
                page.goto(
                    SWITCH_ORIGIN + SWITCH_LOGIN_PATH, wait_until="domcontentloaded"
                )
            except PlaywrightError as exc:
                return _fail(
                    f"could not open {SWITCH_ORIGIN}{SWITCH_LOGIN_PATH} in the shared "
                    f"browser: {exc}"
                )
            with contextlib.suppress(PlaywrightError):
                _bring_to_front(page, "login switch", port)
            # A failed click is not fatal: it just means no sign-in form was
            # there (already mid-flow, or already logged in) — fall through to
            # the wait, which decides on evidence.
            with contextlib.suppress(PlaywrightError):
                page.click(SWITCH_SIGN_IN_BUTTON_SELECTOR, timeout=10_000)
            if _switch_wait_for_login(page, timeout_s=15):
                print("✓ Logged into Switch Cloud Portal (SSO, no password needed).")
                _record_login_event("switch", "sso")
                return 0
            print(
                "\n🔐 Switch Cloud Portal (cloud.switch.ch) needs a login.\n"
                "   In the shared Chrome window (now in front):\n"
                "     1. Sign in with your SWITCH edu-ID on the page that opened (email,\n"
                "        password, and the 2-step code unless this browser is remembered).\n"
                "     2. Land back on cloud.switch.ch — success is auto-detected.\n",
                file=sys.stderr,
            )
            if not _switch_wait_for_login(
                page, timeout_s=300, poll_s=2.0, heartbeat=True
            ):
                return _fail(
                    "Switch Cloud Portal login not detected within 5 min. Finish the "
                    "edu-ID login in the shared browser, then re-run: "
                    "browser.py login switch"
                )
            print("✓ Logged into Switch Cloud Portal (cloud.switch.ch).")
            _record_login_event("switch", "assisted")
            return 0
    finally:
        browser.close()
        pw.stop()


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
# `sso` (an edu-ID click that completed without a password) is AUTOMATED.
ASSISTED_MODES = {"assisted", "1password"}


def _load_login_events(site_name: str) -> list[dict]:
    """All recorded real-login events for one site, each tagged with `site`.
    Empty list when nothing's recorded yet. Lines that are not a JSON object
    with a numeric `ts` (torn writes, hand edits) are skipped, not fatal."""
    path = LOGIN_LOG_DIR / f"{site_name}.jsonl"
    if not path.is_file():
        return []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    events: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            e = json.loads(line)
        except ValueError:
            continue
        ts = e.get("ts") if isinstance(e, dict) else None
        if isinstance(ts, bool) or not isinstance(ts, (int, float)):
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
# Login broker client (PLAN_login-broker.md) — sessions without credentials
# ---------------------------------------------------------------------------
#
# A root-installed broker (`broker/daemon.py`, its own uid) logs into sites Albert
# whitelisted in Bitwarden `agent-logins` and hands this process a SESSION BUNDLE
# (allowlisted cookies + named localStorage keys) — never a password or TOTP seed.
# We inject the bundle into the shared browser. Exit codes of the broker paths:
# 0 logged in · 2 not logged in / not whitelisted · 3 broker unavailable ·
# 4 the site needs a human (captcha / second factor).

BROKER_SOCKET_DEFAULT = "/var/db/login-broker-run/broker.sock"
BROKER_TIMEOUT_S = 180.0
BROKER_MAX_RESPONSE = 16 * 1024 * 1024
# How long the cscs check polls the portal for its token (broker/recipes.py
# ``cscs_portal_ready``, the broker's own positive check, uses the same 8 s).
CSCS_PROBE_WAIT_S = 8.0
BROKER_ERRORS = {
    "needs_human": "the site wants a human (captcha / bot check / second factor)",
    "origin_violation": "the login page left the item's agent_fill_origins — "
    "the broker refused to type there",
    "rate_limited": "rate limited by the broker",
    "login_failed": "the broker's login did not reach a logged-in state",
    "unknown_site": "not whitelisted in Bitwarden agent-logins",
    "refused": "the agent-logins item is refused",
    "vault_error": "the broker cannot read Bitwarden",
    "forbidden": "the broker does not serve this uid",
    "bad_request": "the broker rejected the request",
    "internal": "internal broker error",
}
_BROKER_SITES_CACHE: list[list[dict]] = []


class BrokerUnavailable(Exception):
    """No (working) login broker answers on the socket."""


def _broker_socket() -> str:
    """The broker socket: $LOGIN_BROKER_SOCKET or the installed default."""
    return os.environ.get("LOGIN_BROKER_SOCKET") or BROKER_SOCKET_DEFAULT


def _print_broker_diag(diag: object) -> None:
    """Print the broker's secret-free failure report (where the login stopped)."""
    if not isinstance(diag, dict):
        return
    print("  broker stopped at:", diag.get("url", "?"), f"— {diag.get('title', '')!r}")
    for key, label in (
        ("challenge", "bot check"),
        ("messages", "page says"),
        ("inputs", "visible fields"),
        ("buttons", "buttons"),
        ("frames", "frames"),
        ("password_check", "password used (compare with your vault copy)"),
        ("screenshot", "screenshot"),
        ("before_check", "page before the final check"),
    ):
        value = diag.get(key)
        if value:
            shown = "; ".join(map(str, value)) if isinstance(value, list) else value
            print(f"  {label}: {shown}")


def _broker_request(op: str, *, timeout: float = BROKER_TIMEOUT_S, **kw: Any) -> dict:
    """One JSON request over the broker's Unix socket; the decoded reply.

    Raises ``BrokerUnavailable`` when nothing answers, the reply is cut off, or
    it is not a JSON object. A broker-side error is a normal reply
    (``{"ok": false, "error": …}``) — the caller maps it.
    """
    payload = json.dumps({"op": op, **kw}).encode() + b"\n"
    path = _broker_socket()
    buf = bytearray()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        try:
            sock.connect(path)
        except OSError as exc:
            raise BrokerUnavailable(
                f"no login broker at {path} ({exc.strerror or exc})"
            ) from None
        try:
            sock.sendall(payload)
            while not buf.endswith(b"\n"):
                chunk = sock.recv(65536)
                if not chunk:
                    break
                buf += chunk
                if len(buf) > BROKER_MAX_RESPONSE:
                    raise BrokerUnavailable("login broker reply too large")
        except OSError as exc:  # socket.timeout is an OSError
            raise BrokerUnavailable(f"login broker did not answer ({exc})") from None
    try:
        resp = json.loads(bytes(buf))
    except ValueError:
        raise BrokerUnavailable("login broker sent no JSON") from None
    if not isinstance(resp, dict):
        raise BrokerUnavailable("login broker sent no JSON object")
    return resp


def _broker_sites() -> list[dict]:
    """The broker's ``sites`` list (cached per process)."""
    if _BROKER_SITES_CACHE:
        return _BROKER_SITES_CACHE[0]
    resp = _broker_request("sites", timeout=60)
    if not resp.get("ok"):
        code = str(resp.get("error"))
        raise BrokerUnavailable(
            f"login broker: {BROKER_ERRORS.get(code, code)}"
            + (f" ({resp['detail']})" if resp.get("detail") else "")
        )
    sites = [s for s in resp.get("sites") or [] if isinstance(s, dict)]
    _BROKER_SITES_CACHE[:] = [sites]
    return sites


def _broker_site(site: str) -> dict | None:
    """The broker's entry for `site` (refused ones included), or None."""
    for entry in _broker_sites():
        if entry.get("site") == site:
            return entry
    return None


def _broker_cookie_in_scope(
    domain: str, name: str, hosts: Sequence[str], names: Sequence[str] | None
) -> bool:
    """Client copy of broker/bundle.py ``cookie_in_scope``: host (or subdomain)
    allowlist, identity-provider hosts only when named exactly, name allowlist."""
    d = (domain or "").strip().lstrip(".").lower()
    norm = [h.strip().lstrip(".").lower() for h in hosts if h and h.strip()]
    if not d or not any(d == h or d.endswith("." + h) for h in norm):
        return False
    idp = d in BROKER_IDP_HOSTS or d.split(".", 1)[0] in BROKER_IDP_LABELS
    if idp and d not in norm:
        return False
    return names is None or name in names


def _url_origin(url: str) -> str:
    """``scheme://host[:port]`` of `url` (default ports dropped), '' if unparsable."""
    try:
        parts = urllib.parse.urlsplit(url)
        host, port = parts.hostname, parts.port
    except ValueError:
        return ""
    if not host:
        return ""
    default = {"https": 443, "http": 80}.get(parts.scheme)
    suffix = "" if port in (None, default) else f":{port}"
    return f"{parts.scheme}://{host.lower()}{suffix}"


def _with_background_page(port: int, url: str, fn: Callable[[Any], Any]) -> Any:
    """Open `url` in a BACKGROUND tab (never focused), run ``fn(page)``, close it.

    The `_switch_probe` dance: create the target over CDP with
    ``background: true``, reconnect so Playwright adopts it, find it by target
    id, call `fn`, close. Returns ``fn``'s result, or None when anything fails.
    """
    return _background_page_run(port, url, None, fn)


def _with_prepared_background_page(
    port: int,
    url: str,
    prepare: Callable[[Any], None],
    fn: Callable[[Any], Any],
) -> Any:
    """`_with_background_page`, but ``prepare(page)`` runs BEFORE `url` loads.

    The tab is created on ``about:blank``; `prepare` gets the adopted page (e.g.
    to ``add_init_script``), only then the tab navigates to `url`. For state a
    site must find at its very first script — a SPA that redirects a session
    without it away before any post-load ``evaluate`` could run.
    """
    return _background_page_run(port, url, prepare, fn)


def _background_page_run(
    port: int,
    url: str,
    prepare: Callable[[Any], None] | None,
    fn: Callable[[Any], Any],
) -> Any:
    """Shared body of the two background-page helpers (None on any failure)."""
    from playwright.sync_api import Error as PlaywrightError

    pw, browser = _connect(port)
    tid = ""
    start = "about:blank" if prepare is not None else url
    try:
        created = browser.new_browser_cdp_session().send(
            "Target.createTarget", {"url": start, "background": True}
        )
        tid = str(created.get("targetId") or "")
    except PlaywrightError:
        return None
    finally:
        browser.close()
        pw.stop()
    if not tid:
        return None
    pw, browser = _connect(port)
    page = None
    try:
        page = _switch_page_by_target(browser, tid)
        if page is None:
            return None
        if prepare is not None:
            prepare(page)
            page.goto(url, wait_until="domcontentloaded", timeout=15_000)
        else:
            page.wait_for_load_state("domcontentloaded", timeout=15_000)
        with contextlib.suppress(PlaywrightError):
            page.wait_for_load_state("load", timeout=10_000)
        return fn(page)
    except PlaywrightError:
        return None
    finally:
        if page is not None:
            with contextlib.suppress(PlaywrightError):
                page.close()
        else:
            with contextlib.suppress(PlaywrightError):
                _switch_close_target(browser, tid)
        browser.close()
        pw.stop()


def _broker_fail(rc: int, msg: str) -> int:
    print(f"❌ {msg}", file=sys.stderr)
    return rc


def _broker_entry_or_rc(site: str) -> tuple[dict | None, int]:
    """(entry, 0) for a usable broker site, else (None, exit code) after a message."""
    try:
        entry = _broker_site(site)
    except BrokerUnavailable as exc:
        return None, _broker_fail(3, str(exc))
    if entry is None:
        return None, _broker_fail(
            2, f"{site}: not whitelisted in Bitwarden agent-logins."
        )
    if entry.get("refused"):
        return None, _broker_fail(
            2, f"{site}: agent-logins item refused — {entry.get('reason') or '?'}"
        )
    return entry, 0


def _broker_wait_sentinel(page, sentinel: str) -> bool:
    """The item's sentinel is visible within 8 s — or, without a box of its
    own (an inline custom element around a fixed-position child), shows a
    visible descendant, like the broker's own check."""
    from playwright.sync_api import Error as PlaywrightError

    try:
        page.wait_for_selector(sentinel, state="visible", timeout=8_000)
        return True
    except PlaywrightError:
        return bool(_broker_sentinel_shown(page, sentinel))


def _broker_probe(page, entry: dict) -> bool:
    """The broker's positive check, client side, on the loaded check page.

    Logged in iff the item's sentinel is visible, or — the item has a check
    URL — the page ended OFF every fill origin (https only), shows no bot
    challenge and no visible password field. CSCS: the portal app holds its
    token (polled up to ``CSCS_PROBE_WAIT_S`` while on the portal).
    "No password field" alone proves nothing (page 2 of an Auth0 login).
    """
    if entry.get("site") == "cscs":
        # The SPA renders on the portal first and only then sends a token-less
        # session to Keycloak: poll for the token while still on the portal.
        ready: bool = _broker_cscs_portal_ready(page, wait_s=CSCS_PROBE_WAIT_S)
        return ready
    page.wait_for_timeout(1000)
    sentinel = entry.get("logged_in_selector")
    if sentinel and _broker_wait_sentinel(page, str(sentinel)):
        return True
    if not entry.get("check_url"):
        return False
    fill = [str(o) for o in entry.get("fill_origins") or []]
    if not _broker_off_fill_origins(page.url, fill, dev=False):
        return False
    if _broker_interstitial(page):
        return False
    return not any(
        el.is_visible() for el in page.query_selector_all("input[type=password]")
    )


def _broker_logged_in(port: int, site: str) -> int:
    """Exit 0 if the shared browser is logged into broker site `site`, 2 if not.

    READ-ONLY: one BACKGROUND tab (never brought to front) on the item's check
    URL (``check_url`` from the broker's ``sites`` list; sentinel-only items:
    the login URL), closed again; ``_broker_probe`` decides.
    """
    entry, rc = _broker_entry_or_rc(site)
    if entry is None:
        return rc
    return _broker_check_entry(port, site, entry)


# The probe tab gets the broker's own window size: a background tab of the
# headed shared browser is ~800x460, where responsive apps hide what the
# broker (1280x720 headless) saw as the sentinel — Komga's Vuetify navigation
# drawer is `visibility: hidden` below its desktop breakpoint (2026-10-08).
BROKER_PROBE_VIEWPORT = {"width": 1280, "height": 720}


def _broker_probe_viewport(page) -> None:
    """Size the probe tab like the broker's page before the check URL loads."""
    page.set_viewport_size(BROKER_PROBE_VIEWPORT)


def _broker_check_entry(port: int, site: str, entry: dict) -> int:
    """`_broker_logged_in` for an entry already in hand (refused ones included)."""
    check_url = str(entry.get("check_url") or "")
    if not check_url and not entry.get("logged_in_selector"):
        return _broker_fail(
            2, f"{site}: the broker lists no check URL or sentinel — cannot verify."
        )
    url = check_url or str(entry.get("login_url") or "")
    if not url.startswith("https://"):
        return _broker_fail(2, f"{site}: the broker lists no https check URL.")

    if _with_prepared_background_page(
        port, url, _broker_probe_viewport, lambda page: _broker_probe(page, entry)
    ):
        print(f"✓ Logged into {site} (checked {_tab_hint(url)}).")
        return 0
    print(f"Not logged into {site} (checked {_tab_hint(url)}).", file=sys.stderr)
    return 2


def _broker_replace_cookies(browser, bundle: dict) -> int:
    """Delete the shared browser's in-scope cookies, add the bundle's; return count."""
    ctx = browser.contexts[0] if browser.contexts else browser.new_context()
    hosts = [str(h) for h in bundle.get("cookie_hosts") or []]
    raw_names = bundle.get("cookie_names")
    names = [str(n) for n in raw_names] if isinstance(raw_names, list) else None
    for ck in ctx.cookies():
        if _broker_cookie_in_scope(
            str(ck.get("domain")), str(ck.get("name")), hosts, names
        ):
            ctx.clear_cookies(name=ck["name"], domain=ck["domain"], path=ck["path"])
    # Defence in depth: never inject a cookie outside the declared scope.
    cookies = [
        c
        for c in bundle.get("cookies") or []
        if isinstance(c, dict)
        and _broker_cookie_in_scope(
            str(c.get("domain")), str(c.get("name")), hosts, names
        )
    ]
    if cookies:
        ctx.add_cookies(cookies)
    return len(cookies)


# The init script _broker_write_storage installs: it sets the bundle's keys at
# document start, and only on the bundle's own origin (a redirect, an iframe
# or a later navigation elsewhere gets nothing). Placeholders are JSON literals.
_BROKER_STORAGE_INIT_JS = (
    "(() => { const origin = __ORIGIN__; const kv = __KV__;"
    " if (location.origin !== origin) return;"
    " try { for (const [k, v] of Object.entries(kv)) localStorage.setItem(k, v); }"
    " catch (e) {} })();"
)
# Read-back proof: every key holds exactly the bundle's value (names in, bool out).
_BROKER_STORAGE_CHECK_JS = (
    "kv => Object.entries(kv).every(([k, v]) => localStorage.getItem(k) === v)"
)


def _broker_storage_init_script(origin: str, kv: dict[str, str]) -> str:
    """The `_BROKER_STORAGE_INIT_JS` source for one origin's keys (never logged)."""
    return _BROKER_STORAGE_INIT_JS.replace("__ORIGIN__", json.dumps(origin)).replace(
        "__KV__", json.dumps(kv)
    )


def _broker_write_storage(port: int, bundle: dict) -> int:
    """Write the bundle's localStorage keys, one background tab per origin.

    A SPA may redirect a session without its token away right after ``load``
    (the CSCS portal sends it to Keycloak), so a post-load ``setItem`` loses the
    race. Instead the tab starts on ``about:blank``, gets an init script that
    sets the keys at document start when ``location.origin`` is the bundle's
    origin, then navigates there; the keys are read back on that page as the
    proof. Values never reach a log line — only key counts and origins.
    """
    written = 0
    storage = bundle.get("storage") or {}
    for origin, kv in storage.items() if isinstance(storage, dict) else []:
        if not isinstance(kv, dict) or _url_origin(str(origin)) != origin:
            continue
        if not str(origin).startswith("https://"):
            continue
        values = {str(k): str(v) for k, v in kv.items()}

        def prepare(page, origin=origin, values=values) -> None:
            page.add_init_script(script=_broker_storage_init_script(origin, values))

        def verify(page, origin=origin, values=values) -> bool:
            if _url_origin(page.url) != origin:  # redirected elsewhere: no proof
                return False
            return bool(page.evaluate(_BROKER_STORAGE_CHECK_JS, values))

        if _with_prepared_background_page(port, origin + "/", prepare, verify):
            written += len(values)
        else:
            print(
                f"⚠️ could not write {len(values)} localStorage key(s) on {origin}",
                file=sys.stderr,
            )
    return written


def _broker_after_login(port: int, site: str) -> int:
    """Site-specific follow-up once logged in: CSCS caches its API token."""
    return cmd_token(port) if site == "cscs" else 0


# One return per exit code of the broker contract (0 / 2 / 3 / 4) + the cscs follow-up.
def _broker_login(port: int, site: str) -> int:  # pylint: disable=too-many-return-statements
    """Log the shared browser into broker site `site` via a session bundle.

    Already logged in → no broker call. Else: interaction lease (gate first,
    via `_connect`, then the lease — the documented lock order), request the
    bundle, replace the site's in-scope cookies, write its storage keys, then
    verify with `_broker_logged_in`.
    """
    rc = _broker_logged_in(port, site)
    if rc == 0:
        return _broker_after_login(port, site)
    if rc != 2:
        return rc
    entry, rc = _broker_entry_or_rc(site)
    if entry is None:
        return rc
    pw, browser = _connect(port)
    connected = True
    try:
        with _interaction_lease(f"login {site}"):
            try:
                resp = _broker_request("login", site=site)
            except BrokerUnavailable as exc:
                return _broker_fail(3, str(exc))
            if not resp.get("ok"):
                code = str(resp.get("error"))
                detail = str(resp.get("detail") or "")
                msg = f"{site}: {BROKER_ERRORS.get(code, code)}"
                _print_broker_diag(resp.get("diag"))
                return _broker_fail(
                    4 if code == "needs_human" else 2,
                    msg + (f" ({detail})" if detail else ""),
                )
            bundle = resp.get("bundle") if isinstance(resp.get("bundle"), dict) else {}
            n_cookies = _broker_replace_cookies(browser, bundle or {})
            browser.close()
            pw.stop()
            connected = False
            n_keys = _broker_write_storage(port, bundle or {})
            print(
                f"Injected {n_cookies} cookie(s) and {n_keys} storage key(s) for {site}."
            )
    finally:
        if connected:
            browser.close()
            pw.stop()
    rc = _broker_logged_in(port, site)
    if rc != 0:
        return _broker_fail(
            2, f"{site}: session injected but the site is not logged in."
        )
    _record_login_event(site, "broker")
    return _broker_after_login(port, site)


def cmd_broker_sites() -> int:
    """Table of the broker's sites: id, fill origins, status."""
    try:
        sites = _broker_sites()
    except BrokerUnavailable as exc:
        return _broker_fail(3, str(exc))
    if not sites:
        print("(no items in Bitwarden agent-logins)")
        return 0
    rows = [("SITE", "FILL ORIGINS", "CHECK", "STATUS")]
    for s in sorted(sites, key=lambda e: str(e.get("site"))):
        status = f"refused: {s.get('reason') or '?'}" if s.get("refused") else "ok"
        check = str(s.get("check_url") or "") or (
            "sentinel" if s.get("logged_in_selector") else "-"
        )
        rows.append(
            (
                str(s.get("site")),
                ", ".join(s.get("fill_origins") or []) or "-",
                check,
                status,
            )
        )
    w0 = max(len(r[0]) for r in rows)
    w1 = max(len(r[1]) for r in rows)
    w2 = max(len(r[2]) for r in rows)
    for r in rows:
        print(f"{r[0]:<{w0}}  {r[1]:<{w1}}  {r[2]:<{w2}}  {r[3]}")
    return 0


def cmd_broker_logout(port: int, site_name: str) -> int:
    """Drop the broker's own profile for SITE and delete SITE's in-scope cookies
    from the shared browser (the session ends here; server-side sessions live on
    until the site expires them)."""
    site = site_name.strip().lower()
    try:
        entry = _broker_site(site)
        resp = _broker_request("logout", site=site)
    except BrokerUnavailable as exc:
        return _broker_fail(3, str(exc))
    if not resp.get("ok"):
        code = str(resp.get("error"))
        return _broker_fail(2, f"{site}: {BROKER_ERRORS.get(code, code)}")
    print(
        f"✓ broker profile for {site} removed."
        if resp.get("removed")
        else f"✓ broker had no profile for {site}."
    )
    if entry is None:
        return _broker_fail(
            2,
            f"{site} is not listed by the broker — its cookie scope is unknown, so "
            "no cookie in the shared browser was touched.",
        )
    hosts = [str(h) for h in entry.get("cookie_hosts") or []]
    raw_names = entry.get("cookie_names")
    names = [str(n) for n in raw_names] if isinstance(raw_names, list) else None
    pw, browser = _connect(port)
    try:
        with _interaction_lease(f"logout {site}"):
            ctx = browser.contexts[0] if browser.contexts else browser.new_context()
            gone = 0
            for ck in ctx.cookies():
                if _broker_cookie_in_scope(
                    str(ck.get("domain")), str(ck.get("name")), hosts, names
                ):
                    ctx.clear_cookies(
                        name=ck["name"], domain=ck["domain"], path=ck["path"]
                    )
                    gone += 1
    finally:
        browser.close()
        pw.stop()
    print(f"✓ deleted {gone} {site} cookie(s) from the shared browser.")
    return 0


# ---------------------------------------------------------------------------
# Safari session import (tp#733) — reuse Albert's own Safari login
# ---------------------------------------------------------------------------
#
# Albert logs into some sites in Safari (Bitwarden autofill, passes Cloudflare's
# "are you human" box); those sessions last for months. `import-safari SITE`
# copies ONLY that site's cookies (minus the bot-management ones, which are bound
# to Safari's user agent / IP) into the shared browser. Two gates: the site is in
# `broker.safari_cookies.SAFARI_SITES`, and the broker lists it (the Bitwarden
# agent-login item, refused or not, is Albert's consent). Values never print.

SAFARI_FIX = "open the site in Safari and log in, then run ./agent-login.py -t {site}"


def _safari_entry_or_rc(site: str) -> tuple[dict | None, int]:
    """(broker entry, 0) when `site` may be imported from Safari, else (None, rc)."""
    if site not in _safari.SAFARI_SITES:
        known = ", ".join(_safari.SAFARI_SITES)
        return None, _broker_fail(
            2, f"{site}: no Safari import for this site (known: {known})."
        )
    try:
        entry = _broker_site(site)
    except BrokerUnavailable as exc:
        return None, _broker_fail(
            3,
            f"{site}: refusing the Safari import — cannot confirm the site is "
            f"whitelisted in Bitwarden agent-login ({exc}).",
        )
    if entry is None:
        return None, _broker_fail(
            2,
            f"{site}: not listed in Bitwarden agent-login — move its item into "
            "that collection to allow the Safari import.",
        )
    return entry, 0


def _safari_site_cookies(site: str) -> tuple[list[_safari.Cookie], int]:
    """(`site`'s usable cookies from Safari's jar, 0), or ([], 2) after a message."""
    try:
        cookies = _safari.read_binarycookies()
    except OSError as exc:
        return [], _broker_fail(
            2,
            f"cannot read Safari's cookies ({exc.strerror or exc}) — the calling "
            "terminal needs Full Disk Access.",
        )
    except ValueError as exc:
        return [], _broker_fail(2, f"Safari's cookie file: {exc}")
    return _safari.site_cookies(cookies, site), 0


def _safari_when(ts: float) -> str:
    """Local ``YYYY-MM-DD HH:MM`` of a unix time ('?' when out of range)."""
    try:
        return time.strftime("%Y-%m-%d %H:%M", time.localtime(ts))
    except (OverflowError, OSError, ValueError):
        return "?"


def _safari_print_table(cookies: Sequence[_safari.Cookie]) -> None:
    """Domain, name, expiry and flags of `cookies` — NEVER a value."""
    rows = [("DOMAIN", "NAME", "EXPIRES", "FLAGS")]
    for c in sorted(cookies, key=lambda c: (c.domain, c.name, c.path)):
        flags = [f for f, on in (("secure", c.secure), ("httponly", c.http_only)) if on]
        rows.append((c.domain, c.name, _safari_when(c.expires), ",".join(flags) or "-"))
    w0 = max(len(r[0]) for r in rows)
    w1 = max(len(r[1]) for r in rows)
    w2 = max(len(r[2]) for r in rows)
    for r in rows:
        print(f"{r[0]:<{w0}}  {r[1]:<{w1}}  {r[2]:<{w2}}  {r[3]}")


def _safari_replace_cookies(
    browser, site: str, cookies: Sequence[_safari.Cookie]
) -> int:
    """Delete the shared browser's cookies for `site`'s domains (bot-check ones
    stay: they are Chromium's own), add `cookies`; return how many were added."""
    rules = _safari.SAFARI_SITES[site]

    def in_scope(domain: str, name: str) -> bool:
        return any(
            _safari.domain_matches(domain, r) for r in rules.domains
        ) and not _safari.denied(name, rules)

    ctx = browser.contexts[0] if browser.contexts else browser.new_context()
    for ck in ctx.cookies():
        if in_scope(str(ck.get("domain")), str(ck.get("name"))):
            ctx.clear_cookies(name=ck["name"], domain=ck["domain"], path=ck["path"])
    # Defence in depth: never inject a cookie outside the site's scope.
    picked = [c.to_playwright() for c in cookies if in_scope(c.domain, c.name)]
    if picked:
        ctx.add_cookies(picked)
    return len(picked)


def _safari_inject(port: int, site: str, cookies: Sequence[_safari.Cookie]) -> int:
    """Copy `cookies` into the shared browser under the interaction lease."""
    pw, browser = _connect(port)
    try:
        with _interaction_lease(f"import-safari {site}"):
            n = _safari_replace_cookies(browser, site, cookies)
    finally:
        browser.close()
        pw.stop()
    print(f"Copied {n} {site} cookie(s) from Safari (values not shown).")
    return n


def _safari_dry_run(site: str, cookies: Sequence[_safari.Cookie]) -> int:
    """`import-safari -n`: the table (never a value); 0 if there is anything to copy."""
    if not cookies:
        print(f"Safari holds no usable {site} cookies.")
        return 2
    _safari_print_table(cookies)
    print(f"{len(cookies)} cookie(s) would be copied (values not shown).")
    return 0


def cmd_import_safari(port: int, site_name: str, *, dry_run: bool = False) -> int:
    """Copy SITE's Safari session into the shared browser, then the positive check.

    Exit 0 logged in (dry run: cookies found), 2 not logged in / not allowed /
    nothing in Safari, 3 broker unreachable (consent cannot be confirmed).
    """
    site = site_name.strip().lower()
    entry, rc = _safari_entry_or_rc(site)
    if entry is None:
        return rc
    cookies, rc = _safari_site_cookies(site)
    if rc:
        return rc
    if dry_run:
        return _safari_dry_run(site, cookies)
    if not cookies:
        return _broker_fail(
            2,
            f"{site}: Safari holds no usable session — {SAFARI_FIX.format(site=site)}",
        )
    _safari_inject(port, site, cookies)
    rc = _broker_check_entry(port, site, entry)
    if rc == 0:
        _record_login_event(site, "safari")
        print(f"✅ {site}: logged in with your Safari session.")
        return 0
    return _broker_fail(
        rc,
        f"{site}: Safari session copied but the site is NOT logged in — "
        + SAFARI_FIX.format(site=site),
    )


def _safari_logged_in(port: int, site: str) -> int:
    """`logged-in SITE` for a Safari-import site (refused broker items included)."""
    entry, rc = _safari_entry_or_rc(site)
    if entry is None:
        return rc
    return _broker_check_entry(port, site, entry)


def _safari_try_import(port: int, site: str, entry: dict) -> bool:
    """Copy Safari's session for `site` (if it holds one); True once logged in."""
    cookies, _rc = _safari_site_cookies(site)
    if not cookies:
        print(f"Safari holds no usable {site} session.", file=sys.stderr)
        return False
    print(f"▶ route: Safari session ({len(cookies)} cookie(s))")
    _safari_inject(port, site, cookies)
    if _broker_check_entry(port, site, entry) != 0:
        return False
    _record_login_event(site, "safari")
    print(f"✅ {site}: logged in — route: Safari session")
    return True


def _safari_login(port: int, site: str) -> int:
    """`login SITE` for a Safari-import site: Safari session first, then — only
    for sites with ``broker_fallback`` and a non-refused broker item — the broker.
    Prints the route it used."""
    entry, rc = _safari_entry_or_rc(site)
    if entry is None:
        return rc
    if _broker_check_entry(port, site, entry) == 0:
        print(f"route: already logged in ({site})")
        return 0
    if _safari_try_import(port, site, entry):
        return 0
    if _safari.SAFARI_SITES[site].broker_fallback and not entry.get("refused"):
        print("▶ route: login broker (fallback)")
        rc = _broker_login(port, site)
        if rc == 0:
            print(f"✅ {site}: logged in — route: login broker")
        return rc
    return _broker_fail(2, f"{site}: not logged in — {SAFARI_FIX.format(site=site)}")


def cmd_login_cscs_assisted(port: int) -> int:
    """The pre-broker CSCS login (keychain / 1Password) — human-only."""
    if not sys.stdin.isatty():
        return _fail(
            "login-cscs-assisted is human-only (needs a terminal). Agents use "
            "`browser.py login cscs` (login broker)."
        )
    return cmd_cscs_login(port, allow_op=True)


# ---------------------------------------------------------------------------
# Notion (app.notion.com) — assisted e-mail-code / SSO login, no token
# ---------------------------------------------------------------------------


def _notion_verdict(url: str, has_sidebar: bool) -> bool:
    """True iff a tab at `url` showing (or not) the workspace sidebar is a
    logged-in Notion session: on app.notion.com, outside /login, sidebar up."""
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        return False
    if parts.scheme != "https" or parts.hostname != NOTION_APP_HOST:
        return False
    if parts.path.startswith("/login"):
        return False
    return has_sidebar


def _notion_page_logged_in(page) -> bool:
    """READ-ONLY check of a live tab (never navigates it); False when the DOM
    cannot be read — fail closed."""
    try:
        url = page.url
        has_sidebar = page.query_selector(NOTION_SIDEBAR_SELECTOR) is not None
    except Exception:  # pylint: disable=broad-exception-caught
        return False
    return _notion_verdict(url, has_sidebar)


def _notion_wait_for_login(
    page, timeout_s: float, poll_s: float = 1.0, heartbeat: bool = False
) -> bool:
    """PASSIVE poll of `page`: True as soon as it shows a logged-in workspace.

    Never navigates — a `goto` would wipe the e-mail code you are typing.
    `heartbeat` prints a progress line to stderr every 30 s (the long assisted
    wait), like `_chatgpt_wait_for_login`.
    """
    start = time.monotonic()
    last_beat = 0.0
    while time.monotonic() - start < timeout_s:
        if _notion_page_logged_in(page):
            return True
        elapsed = time.monotonic() - start
        if heartbeat and elapsed - last_beat >= 30:
            print(
                f"  …waiting for you to finish the Notion login in the shared "
                f"browser window ({int(elapsed)}s elapsed)…",
                file=sys.stderr,
            )
            last_beat = elapsed
        try:
            page.wait_for_timeout(poll_s * 1000)
        except Exception:  # pylint: disable=broad-exception-caught
            time.sleep(poll_s)
    return False


def _notion_probe(port: int) -> bool:
    """READ-ONLY: open app.notion.com in a BACKGROUND tab (never focused, no
    tab of the user's touched), wait up to 30 s for the workspace sidebar,
    close the tab. Anything that goes wrong is False (fail closed)."""
    return bool(
        _with_background_page(
            port,
            NOTION_APP_ORIGIN + "/",
            lambda page: _notion_wait_for_login(page, timeout_s=30, poll_s=0.5),
        )
    )


def cmd_notion_login(port: int) -> int:
    """Ensure Notion (app.notion.com) is logged in. Idempotent (a warm session
    just returns 0). Notion logs in by e-mail code or SSO, which can't be
    replayed from stored credentials — a cold session is ASSISTED: you sign in
    once in the shared window; the session then persists. Held under the
    INTERACTION lease — no other tool clicks in the meantime."""
    from playwright.sync_api import Error as PlaywrightError

    # Warm probe + guided-login gate FIRST, outside the lease (both are the
    # read-only checks `logged-in` does lease-free).
    if _notion_probe(port):
        print("✓ Already logged into Notion (app.notion.com).")
        return 0
    if not _guided_login_allowed(port, "notion", "Notion"):
        return NEEDS_ALBERT_RC
    pw, browser = _connect(port)
    try:
        with _interaction_lease("login notion"):
            ctx = browser.contexts[0] if browser.contexts else browser.new_context()
            # Interactive and headed (guard above): a new tab in the window is
            # what the human works in; it stays open afterwards.
            page = ctx.new_page()
            try:
                page.goto(NOTION_LOGIN_URL, wait_until="domcontentloaded")
            except PlaywrightError as exc:
                return _fail(
                    f"could not open {NOTION_LOGIN_URL} in the shared browser: {exc}"
                )
            with contextlib.suppress(PlaywrightError):
                _bring_to_front(page, "login notion", port)
            print(
                "\n🔐 Notion (app.notion.com) needs a login.\n"
                "   In the shared Chrome window (now in front):\n"
                "     1. Log in on the page that opened (e-mail code, or SSO).\n"
                "     2. Land in the workspace — success is auto-detected once the\n"
                "        sidebar shows.\n",
                file=sys.stderr,
            )
            if not _notion_wait_for_login(
                page, timeout_s=300, poll_s=2.0, heartbeat=True
            ):
                return _fail(
                    "Notion login not detected within 5 min. Finish the login in "
                    "the shared browser, then re-run: browser.py login notion"
                )
            print("✓ Logged into Notion (app.notion.com).")
            _record_login_event("notion", "assisted")
            return 0
    finally:
        browser.close()
        pw.stop()


def cmd_notion_logged_in(port: int) -> int:
    """Exit 0 if Notion is logged in (workspace sidebar on app.notion.com), else
    2 — also when it cannot be told (fail closed). READ-ONLY: no lease, one
    background tab, closed again."""
    if _notion_probe(port):
        print("✓ Logged into Notion (app.notion.com).")
        return 0
    print("Not logged into Notion (app.notion.com).", file=sys.stderr)
    return 2


# ---------------------------------------------------------------------------
# Guided login (`assisted-login`, PLAN_focus-free-browser.md Phase 3)
# ---------------------------------------------------------------------------
# ONE human entry: `browser.py assisted-login SITE` (agent-login.py -g SITE calls
# it), confirmed by typing the site name on /dev/tty — no terminal, no start.
#
#   B (primary): an OWNED background tab on the login URL, shown to Albert by
#     bin/login_viewer.py — a loopback relay that streams the headless tab into
#     a dedicated, extension-free Brave app window and forwards his input. The
#     browser stays headless the whole time.
#   A (fallback, -a or offered when B cannot do the login): `switch headed`
#     under the same transaction, the old window flow, `switch headless` in a
#     finally. The only path that shows a window.
#
# Both run inside `_maintenance`, the transaction that makes the guided login
# the browser's only user: registered long-lived clients are PAUSED (SIGSTOP of
# their process group via the register-exec wrapper), the registry gate is
# taken exclusively, unregistered CDP peers refuse the start (-f overrides),
# the maintenance record (owner nonce, mode, owned targets, paused clients,
# 10 s heartbeat) is written, then the gate is released so the transaction's
# own `browser.py` children (they carry $CLAUDE_BROWSER_MAINTENANCE) can
# register — everybody else's new registration refuses (exit 2) until the
# record is gone. The interaction lease is held throughout. On ANY exit:
# owned targets closed → headless ensured → record cleared → clients resumed,
# every step journaled. A detached watchdog (`maintenance-watchdog`) does the
# same if the owner dies or hangs.

GUIDED_TOTAL_S = 15 * 60
GUIDED_IDLE_S = 5 * 60
GUIDED_PROBE_EVERY_S = 5.0
# How long a paused client has to confirm (its wrapper writes paused: true).
PAUSE_ACK_S = 5.0
WATCHDOG_POLL_S = 2.0
VIEWER_PY = Path(__file__).resolve().parent / "login_viewer.py"
# The dedicated, extension-free Brave profile the viewer opens in.
VIEWER_PROFILE_DIR = CACHE_DIR / "viewer-profile"
BRAVE_APP = Path("/Applications/Brave Browser.app")
# login_viewer.py's exit code for "this login needs a real window" (an
# unsupported surface, or Albert pressed "Use a window instead").
VIEWER_FALLBACK_RC = 5
# Where B starts for the built-in sites (broker sites: their login_url).
GUIDED_START_URLS = {
    "anthropic": CLAUDE_LOGIN_URL,
    "openai": CHATGPT_ADMIN_URL,
    "slack": SLACK_WORKSPACE_URL,
    "notion": NOTION_LOGIN_URL,
    "switch": SWITCH_ORIGIN + SWITCH_LOGIN_PATH,
}
# Built-in sites whose own `login SITE` flow is the window flow of path A.
GUIDED_BUILTIN_WINDOW = frozenset({"anthropic", "openai", "slack", "notion", "switch"})
# Test hooks, honoured ONLY with CLAUDE_BROWSER_CACHE_DIR set (a disposable
# browser): extra sites from a JSON file, and the viewer URL written to a file
# instead of opening a window.
TEST_SITES_ENV = "CLAUDE_BROWSER_TEST_SITES"
TEST_VIEWER_URL_ENV = "CLAUDE_BROWSER_TEST_VIEWER_URL_FILE"
WATCHDOG_NONCE_LEN = 16


class MaintenanceRefused(RuntimeError):
    """The guided login cannot start (see the message); nothing was changed."""


@dataclass
class Maintenance:
    """A live guided-login transaction (what `_maintenance` yields)."""

    nonce: str
    site: str
    mode: str
    port: int
    owned: list[str] = dataclasses.field(default_factory=list)
    paused: list[dict] = dataclasses.field(default_factory=list)

    def note(self, **fields: object) -> None:
        """Merge `fields` into the record (a failed write only warns)."""
        try:
            if not _maint_update(self.nonce, **fields):
                print("⚠ the maintenance record is not ours any more", file=sys.stderr)
        except OSError as exc:
            print(f"⚠ could not update the maintenance record: {exc}", file=sys.stderr)

    def add_owned(self, tid: str) -> None:
        """Record a target this guided login owns (closed on every exit)."""
        if tid and tid not in self.owned:
            self.owned.append(tid)
            self.note(owned_targets=list(self.owned))

    def drop_owned(self, tid: str) -> None:
        """Forget an owned target that is gone."""
        if tid in self.owned:
            self.owned.remove(tid)
            self.note(owned_targets=list(self.owned))

    def set_mode(self, mode: str) -> None:
        """Switch the record between B and A (A: `switch headed` is allowed)."""
        self.mode = mode
        self.note(mode=mode)
        _journal("maintenance", phase="mode", site=self.site, mode=mode)


def _osc8(url: str, text: str) -> str:
    """OSC 8 hyperlink (invisible where unsupported)."""
    return f"\x1b]8;;{url}\x1b\\{text}\x1b]8;;\x1b\\"


def _test_mode() -> bool:
    """True only for a disposable browser (CLAUDE_BROWSER_CACHE_DIR set)."""
    return bool(os.environ.get("CLAUDE_BROWSER_CACHE_DIR"))


def _test_sites() -> dict[str, dict]:
    """Test-hook sites ({name: {login_url, check_url, logged_in_selector}})."""
    path = os.environ.get(TEST_SITES_ENV, "")
    if not path or not _test_mode():
        return {}
    data = _read_json_dict(Path(path)) or {}
    return {str(k): v for k, v in data.items() if isinstance(v, dict)}


def _test_site_logged_in(port: int, site: str, entry: dict) -> int:
    """`logged-in` for a test-hook site: its sentinel on its check URL."""
    url = str(entry.get("check_url") or "")
    sel = str(entry.get("logged_in_selector") or "")

    def check(page: Any) -> bool:  # an ACTIVE check, like the built-in sites'
        page.goto(url, wait_until="domcontentloaded", timeout=15_000)
        return _broker_wait_sentinel(page, sel)

    if not (url and sel):
        ok = False
    elif entry.get("probe") == "pick":
        # Like slack/openai/claude: the tab `_pick_page` finds — except during
        # a guided login (`_logged_in_page_check`), which the tests pin.
        ok = _logged_in_page_check(port, _url_origin(url), check)
    else:
        ok = bool(
            _with_background_page(
                port, url, lambda page: _broker_wait_sentinel(page, sel)
            )
        )
    if ok:
        print(f"✓ Logged into {site} (checked {_tab_hint(url)}).")
        return 0
    print(f"Not logged into {site} (checked {_tab_hint(url)}).", file=sys.stderr)
    return 2


def _test_site_obj(site: str, entry: dict) -> "Site":
    """A Site for a test-hook entry (login = needs Albert, like every human site)."""

    def login(_port: int) -> int:
        print(f"needs Albert: agent-login.py -g {site}", file=sys.stderr)
        return NEEDS_ALBERT_RC

    return Site(
        name=site,
        aliases=(),
        blurb="test site (CLAUDE_BROWSER_TEST_SITES)",
        login=login,
        logged_in=functools.partial(_test_site_logged_in, site=site, entry=entry),
    )


def _static_site_name(site: str) -> str | None:
    """The built-in site `site` names (aliases resolved), or None."""
    key = site.strip().lower()
    for s in _sites():
        if key == s.name or key in s.aliases:
            return s.name
    return None


def _guided_start_url(site: str, override: str | None) -> str | None:
    """Where the guided login starts: -u, a test site, built-in, broker; or None."""
    if override:
        return override
    key = site.strip().lower()
    test = _test_sites().get(key)
    if test is not None:
        return str(test.get("login_url") or "") or None
    name = _static_site_name(key)
    if name is not None:
        return GUIDED_START_URLS.get(name)
    try:
        entry = _broker_site(key)
    except BrokerUnavailable:
        entry = None
    if entry is None or entry.get("refused"):
        return None
    return str(entry.get("login_url") or entry.get("check_url") or "") or None


def _self_run(
    port: int,
    *args: str,
    capture: bool = True,
    timeout: float | None = 120.0,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess:
    """Run this browser.py with `args` (inherits the owner token); never raises."""
    argv = [sys.executable, str(Path(__file__).resolve()), "--cdp-port", str(port)]
    try:
        return subprocess.run(
            [*argv, *args],
            check=False,
            capture_output=capture,
            text=True,
            timeout=timeout,
            stdin=subprocess.DEVNULL,
            env=None if env is None else {**os.environ, **env},
        )
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(args, 124, "", "timed out")
    except OSError as exc:
        return subprocess.CompletedProcess(args, 1, "", str(exc))


def _guided_probe(port: int, site: str) -> bool:
    """`logged-in SITE` — the site's own positive check, ALWAYS in a fresh
    background tab (never a picked one: it could be the owned login tab)."""
    res = _self_run(
        port, "logged-in", site, timeout=90.0, env={PROBE_BACKGROUND_ENV: "1"}
    )
    return res.returncode == 0


def _guided_open_owned(tx: Maintenance, url: str) -> str | None:
    """`open -N URL` (background, raw CDP) → the new owned target id, recorded."""
    res = _self_run(tx.port, "open", "-N", url, timeout=60.0)
    tid = next(
        (
            line.split("=", 1)[1].strip()
            for line in (res.stdout or "").splitlines()
            if line.startswith("target=")
        ),
        "",
    )
    if res.returncode != 0 or not tid:
        print(
            f"❌ could not open the login tab (open -N exit {res.returncode})",
            file=sys.stderr,
        )
        return None
    tx.add_owned(tid)
    return tid


def _close_owned_targets(port: int, ids: Sequence[str]) -> list[str]:
    """Close every still-open owned target (raw CDP); the ids that are gone now.

    Never closes the last page target: a blank keep-alive goes first (tp#317).
    """
    gone: list[str] = []
    ws_url = _browser_ws_url(port)
    if ws_url is None:
        return list(ids)  # browser down: nothing left to close
    for tid in ids:
        pages = _page_targets(port)
        if not any(t.get("id") == tid for t in pages):
            gone.append(tid)
            continue
        if len(pages) <= 1:
            _cdp_create_background_target(ws_url, "about:blank", 3.0)
        if _cdp_close_target(port, tid, 3.0, ws_url=ws_url):
            gone.append(tid)
    _journal("maintenance", phase="close_owned", closed=len(gone), owned=len(ids))
    return gone


def _ensure_headless(port: int) -> bool:
    """`switch headless` when the browser is headed: one retry, loud on failure."""
    for attempt in (1, 2):
        if _browser_mode(port) != "headed":
            return True
        print("▶ hiding the Chromium window again (switch headless) …")
        if cmd_switch(port, "headless") == 0:
            return True
        print(f"❌ switch headless failed (attempt {attempt}/2)", file=sys.stderr)
        if attempt == 1:
            time.sleep(2)
    print(
        "❌ the shared Chromium is still HEADED after the guided login. Every "
        "browser.py command will try to revert it; fix it now: browser.py switch "
        "headless   (-f if an unregistered client blocks it)",
        file=sys.stderr,
    )
    return False


# --- pause protocol (transaction side) ----------------------------------------


def _client_validated(pid: object, lstart: object) -> bool:
    """`pid` still runs with start time `lstart` (never a bare number)."""
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        return False
    if not lstart:
        return False
    return _pid_alive(pid) and _proc_lstart(pid) == lstart


def _pause_targets(nonce: str) -> list[dict]:
    """Live `register-exec` registrations that are not this transaction's own.

    Refuses (`MaintenanceRefused`) when a long-lived wrapper from before the
    pause protocol is registered (no ``kind``; any tool but browser.py's own
    one-shot commands): it cannot be paused and would hold the gate forever.
    """
    live = _registry_live_clients()
    legacy = [
        rec for rec in live if not rec.get("kind") and rec.get("tool") != "browser.py"
    ]
    if legacy:
        pids = ", ".join(f"{r.get('tool')} pid {r.get('pid')}" for r in legacy)
        raise MaintenanceRefused(
            f"registered client(s) from before the guided-login pause protocol: "
            f"{pids}.\n   Restart the Claude sessions that run the Playwright "
            "MCP (or stop those pids), then retry."
        )
    return [
        rec
        for rec in live
        if rec.get("kind") == "exec" and rec.get("maintenance") != nonce
    ]


def _pause_acked(entry: dict) -> bool:
    rec = _read_json_dict(CLIENTS_DIR / f"{entry.get('nonce')}.json")
    return bool(rec and rec.get("paused"))


def _pause_clients(tx: Maintenance) -> None:
    """SIGUSR1 every validated long-lived client; wait for each to confirm.

    The entry goes into the record BEFORE the signal, so a crash right after
    still lets the watchdog resume it. A registration whose pid/start time
    cannot be validated is never signalled — the start refuses instead.
    """
    for rec in _pause_targets(tx.nonce):
        if not _client_validated(rec.get("pid"), rec.get("pid_start_time")):
            raise MaintenanceRefused(
                f"cannot validate the registered client {_describe_client(rec)} "
                "(pid/start time) — not signalling it"
            )
        entry = {
            k: rec.get(k)
            for k in (
                "nonce",
                "pid",
                "pid_start_time",
                "tool",
                "child_pid",
                "child_pgid",
                "child_start_time",
            )
        }
        tx.paused.append(entry)
        tx.note(paused=list(tx.paused))
        os.kill(int(rec["pid"]), signal.SIGUSR1)
        _journal(
            "maintenance",
            phase="pause",
            client=rec.get("tool"),
            client_pid=rec.get("pid"),
        )
    deadline = time.monotonic() + PAUSE_ACK_S
    pending = list(tx.paused)
    while pending and time.monotonic() < deadline:
        time.sleep(0.1)
        pending = [p for p in pending if not _pause_acked(p)]
    if pending:
        names = ", ".join(f"{p.get('tool')} pid {p.get('pid')}" for p in pending)
        raise MaintenanceRefused(f"client(s) did not confirm the pause: {names}")
    if tx.paused:
        print(f"⏸  paused {len(tx.paused)} registered client(s) for the guided login")


def _resume_clients(paused: Sequence[dict]) -> list[str]:
    """Resume every paused client; the ones that could not be signalled.

    Preferred: SIGUSR2 to the validated wrapper (it retakes the gate, then
    SIGCONTs its child's group). Wrapper gone: the child group is an ORPHAN —
    unregistered, it would fail every later switch closed — so it is stopped
    (`_kill_orphan_group`: validated leader only, SIGTERM, SIGKILL after 5 s).
    Anything else is left alone and reported.
    """
    problems: list[str] = []
    for p in paused:
        how = "gone"
        try:
            if _client_validated(p.get("pid"), p.get("pid_start_time")):
                os.kill(int(p["pid"]), signal.SIGUSR2)
                how = "wrapper"
            else:
                how = _kill_orphan_group(p)
        except (OSError, KeyError, TypeError, ValueError) as exc:
            how = f"error:{type(exc).__name__}"
        if how not in ("wrapper", "terminated", "killed"):
            problems.append(f"{p.get('tool')} pid {p.get('pid')}: {how}")
        _journal("maintenance", phase="resume", client=p.get("tool"), how=how)
    return problems


# --- the transaction ----------------------------------------------------------


def _spawn_watchdog(port: int, nonce: str) -> int | None:
    """Start the detached recovery watchdog (own session, no stdio); its pid."""
    argv = [
        sys.executable,
        str(Path(__file__).resolve()),
        "--cdp-port",
        str(port),
        "maintenance-watchdog",
        "-n",
        nonce[:WATCHDOG_NONCE_LEN],
    ]
    env = {k: v for k, v in os.environ.items() if k != MAINTENANCE_ENV}
    try:
        proc = subprocess.Popen(  # pylint: disable=consider-using-with
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
            env=env,
        )
    except OSError as exc:
        print(f"⚠ could not start the guided-login watchdog: {exc}", file=sys.stderr)
        return None
    return proc.pid


def _maint_take_gate(tx: Maintenance, stack: contextlib.ExitStack, force: bool) -> None:
    """Gate EX → unregistered-peer check → interaction lease → state active → gate."""
    gate = _gate_acquire(fcntl.LOCK_EX, REGISTRY_EX_WAIT_S)
    if gate is None:
        raise MaintenanceRefused(_gate_busy("start a guided login"))
    try:
        if _is_up(tx.port):
            verdict = _unknown_clients_verdict(tx.port)
            if verdict is not None and not force:
                raise MaintenanceRefused(
                    f"{verdict}\n   Stop them (or register them via register-exec), "
                    "or re-run with -f/--force (they keep running, unpaused)."
                )
            if verdict is not None:
                print(f"⚠ --force: guided login anyway — {verdict}", file=sys.stderr)
        try:
            stack.enter_context(_interaction_lease(f"guided login {tx.site}"))
        except SystemExit as exc:
            raise MaintenanceRefused(str(exc.code)) from None
        tx.note(state="active")
    finally:
        _gate_release(gate)


@contextlib.contextmanager
def _maintenance(
    site: str, mode: str = "B", *, port: int = DEFAULT_CDP_PORT, force: bool = False
) -> Iterator[Maintenance]:
    """THE guided-login transaction (B and A); yields the live `Maintenance`.

    Order: record (state ``preparing``; new foreign registrations refuse from
    here on) → watchdog → pause registered long-lived clients → gate EX
    (bounded; refusal names the holders) → unregistered-peer check (refuse
    unless `force`) → interaction lease → state ``active`` → gate released (our
    own children register with the token) → the block. Exit, whatever the
    cause: close owned targets → `switch headless` if headed → lease released
    → record cleared → clients resumed. Raises `MaintenanceRefused` /
    `HeadedLeaseBusy` when it cannot start (everything undone).
    """
    _journal_parent_chain()
    _journal("maintenance", phase="start", site=site, mode=mode)
    tx: Maintenance | None = None
    problems: list[str] = []
    result = "exception"
    old_held = os.environ.get("CLAUDE_BROWSER_LEASE_HELD")
    try:
        with _maint_record(site, mode, state="preparing") as nonce:
            tx = Maintenance(nonce, site, "B" if mode == "B" else "A", port)
            with contextlib.ExitStack() as stack:
                try:
                    tx.note(watchdog_pid=_spawn_watchdog(port, nonce))
                    _pause_clients(tx)
                    _maint_take_gate(tx, stack, force)
                    # The lease is ours: children that take it must not wait on us.
                    os.environ["CLAUDE_BROWSER_LEASE_HELD"] = "1"
                    yield tx
                    result = "ok"
                finally:
                    if old_held is None:
                        os.environ.pop("CLAUDE_BROWSER_LEASE_HELD", None)
                    else:
                        os.environ["CLAUDE_BROWSER_LEASE_HELD"] = old_held
                    _close_owned_targets(port, list(tx.owned))
                    tx.owned.clear()
                    if not _ensure_headless(port):
                        problems.append("still headed")
    finally:
        if tx is not None:
            problems += _resume_clients(tx.paused)
        for line in problems:
            print(f"❌ guided-login cleanup: {line}", file=sys.stderr)
        _journal(
            "maintenance", phase="end", site=site, result=result, problems=len(problems)
        )


# --- watchdog -----------------------------------------------------------------


def cmd_maintenance_watchdog(port: int, nonce: str) -> int:
    """Recover a guided login whose owner died or hung; exit when it ends normally.

    Polls the record every WATCHDOG_POLL_S. Gone or another owner's → done
    (exit 0). Not live any more (owner pid dead / reused / heartbeat older
    than MAINTENANCE_HUNG_S) → recover: close the owned targets, switch a
    headed browser back to headless, clear the record (compare-before-
    release), resume the paused clients — in that order: a resumed wrapper
    retakes the gate shared, which would make the revert's exclusive gate
    wait for a client that never drains.
    """
    prefix = nonce[:WATCHDOG_NONCE_LEN]
    if len(prefix) < 8:
        return _fail("maintenance-watchdog: -n/--nonce is too short")
    while True:
        rec = _read_json_dict(MAINTENANCE_FILE)
        if rec is None or not str(rec.get("owner_nonce", "")).startswith(prefix):
            return 0
        state = _headed_lease_state(rec)
        if state != "live":
            return _watchdog_recover(port, rec, state)
        time.sleep(WATCHDOG_POLL_S)


def _watchdog_recover(port: int, rec: dict, state: str) -> int:
    """The watchdog's recovery (see `cmd_maintenance_watchdog`)."""
    _journal("watchdog_recover", phase="start", reason=state, site=rec.get("site"))
    owned = [str(t) for t in rec.get("owned_targets") or [] if isinstance(t, str)]
    closed = _close_owned_targets(port, owned) if owned else []
    reverted: object = "headless"
    if _browser_mode(port) == "headed":
        with _stdout_to_stderr():
            reverted = cmd_switch(port, "headless", revert=True)
    with _maint_locked(5.0):
        cur = _read_json_dict(MAINTENANCE_FILE)
        if cur is not None and cur.get("owner_nonce") == rec.get("owner_nonce"):
            MAINTENANCE_FILE.unlink(missing_ok=True)
    paused = [p for p in rec.get("paused") or [] if isinstance(p, dict)]
    problems = _resume_clients(paused)
    _journal(
        "watchdog_recover",
        phase="end",
        reason=state,
        site=rec.get("site"),
        closed=len(closed),
        owned=len(owned),
        revert=reverted,
        resumed=len(paused) - len(problems),
        problems=len(problems),
    )
    return 0


# --- B: remote viewer -----------------------------------------------------------


def _open_viewer_window(url: str) -> str:
    """Show the viewer URL to Albert: a dedicated, extension-free Brave app window.

    Test hook (disposable browser only): write the URL to a file instead.
    Fallback without Brave: the default browser (`open URL`) with a ⚠ — that
    profile is NOT dedicated. Returns how it was opened.
    """
    test_file = os.environ.get(TEST_VIEWER_URL_ENV, "")
    if test_file and _test_mode():
        fd = os.open(test_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(url + "\n")
        return "test-file"
    if BRAVE_APP.exists():
        VIEWER_PROFILE_DIR.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            [
                "open",
                "-na",
                str(BRAVE_APP),
                "--args",
                f"--user-data-dir={VIEWER_PROFILE_DIR}",
                "--no-first-run",
                "--no-default-browser-check",
                "--disable-extensions",
                f"--app={url}",
            ],
            check=False,
        )
        return "brave"
    print(
        "⚠ Brave Browser not found — opening the login view in your DEFAULT "
        "browser (not a dedicated profile).",
        file=sys.stderr,
    )
    subprocess.run(["open", url], check=False)
    return "default"


def _start_viewer(tx: Maintenance, tid: str) -> subprocess.Popen:
    """bin/login_viewer.py on the owned target, as a REGISTERED long-lived client."""
    argv = [
        sys.executable,
        str(Path(__file__).resolve()),
        "--cdp-port",
        str(tx.port),
        "register-exec",
        "-t",
        "login-viewer",
        "--",
        sys.executable,
        str(VIEWER_PY),
        "-c",
        f"http://127.0.0.1:{tx.port}",
        "-t",
        tid,
        "-A",
        "-j",
        "-E",
        "-i",
        str(int(GUIDED_IDLE_S)),
        "-M",
        str(MAINTENANCE_FILE),
    ]
    return subprocess.Popen(  # pylint: disable=consider-using-with
        argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, text=True
    )


def _pump_lines(stream: Any, out: "queue.Queue[dict | None]") -> None:
    """Reader thread: the relay's JSON lines → `out`; None at EOF."""
    try:
        for line in stream:
            with contextlib.suppress(ValueError):
                obj = json.loads(line)
                if isinstance(obj, dict):
                    out.put(obj)
    finally:
        out.put(None)


def _stop_viewer(relay: subprocess.Popen) -> None:
    """SIGTERM the relay's wrapper (forwarded to the relay), then make sure."""
    if relay.poll() is None:
        with contextlib.suppress(OSError):
            relay.send_signal(signal.SIGTERM)
        try:
            relay.wait(10)
        except subprocess.TimeoutExpired:
            relay.kill()
            relay.wait(5)


@dataclass
class _ViewerRun:
    """What the B loop learned from the relay's events."""

    surface: str = ""
    end: str = ""
    connected: bool = False


def _viewer_event(tx: Maintenance, run: _ViewerRun, ev: dict) -> None:
    """Act on one relay event (owned target, popup closed, surface, viewer)."""
    kind = ev.get("ev")
    tid = str(ev.get("target") or "")
    if kind == "owned":
        tx.add_owned(tid)
        print("ℹ️  following a popup of the login tab in the viewer")
    elif kind == "released":
        tx.drop_owned(tid)
    elif kind == "surface":
        run.surface = str(ev.get("reason") or "unsupported prompt")
    elif kind == "viewer":
        run.connected = bool(ev.get("connected"))
    elif kind == "end":
        run.end = str(ev.get("reason") or "")


def _guided_b(tx: Maintenance, site: str, url: str, deadline: float) -> tuple[str, str]:
    """Path B; ``(outcome, why)`` with outcome ok | fallback | fail | timeout."""
    tid = _guided_open_owned(tx, url)
    if tid is None:
        return "fail", "could not open the login tab"
    relay = _start_viewer(tx, tid)
    events: queue.Queue[dict | None] = queue.Queue()
    threading.Thread(
        target=_pump_lines,
        args=(relay.stdout, events),
        daemon=True,
        name="viewer-events",
    ).start()
    try:
        try:
            first = events.get(timeout=30)
        except queue.Empty:
            first = None
        if not first or "url" not in first:
            return "fail", "the viewer relay did not start"
        url_v = str(first["url"])
        how = _open_viewer_window(url_v)
        print(
            f"👤 Log in to {site} in the login view ({how}): "
            f"{_osc8(url_v, 'open the login view')} — it closes by itself when "
            f"you are logged in (max {GUIDED_TOTAL_S // 60} min, "
            f"{GUIDED_IDLE_S // 60} min without the view open)."
        )
        del url_v, first
        return _viewer_loop(tx, site, relay, events, deadline)
    finally:
        _stop_viewer(relay)


def _viewer_loop(
    tx: Maintenance,
    site: str,
    relay: subprocess.Popen,
    events: "queue.Queue[dict | None]",
    deadline: float,
) -> tuple[str, str]:
    """B's wait: relay events, a `logged-in` probe every GUIDED_PROBE_EVERY_S."""
    run = _ViewerRun()
    next_probe = time.monotonic() + GUIDED_PROBE_EVERY_S
    while time.monotonic() <= deadline:
        try:
            ev = events.get(timeout=0.5)
        except queue.Empty:
            ev = {}
        if ev is None:  # the relay ended
            return _viewer_ended(tx, site, relay.wait(), run)
        if ev:
            _viewer_event(tx, run, ev)
        if time.monotonic() >= next_probe:
            if _guided_probe(tx.port, site):
                return "ok", ""
            next_probe = time.monotonic() + GUIDED_PROBE_EVERY_S
    return "timeout", f"no login within {GUIDED_TOTAL_S // 60} min"


def _viewer_ended(
    tx: Maintenance, site: str, rc: int, run: _ViewerRun
) -> tuple[str, str]:
    """Why the relay ended: a surface (→ fallback), the login done, or a failure."""
    if rc == VIEWER_FALLBACK_RC or run.surface:
        return "fallback", run.surface or run.end or "the viewer asked for a window"
    if _guided_probe(tx.port, site):
        return "ok", ""
    return "fail", f"the login view ended: {run.end or f'exit {rc}'}"


# --- A: the window --------------------------------------------------------------


def _activate_owned(tx: Maintenance, tid: str) -> None:
    """Bring the owned login tab to the front of the shown window (lease only)."""
    if not _headed_lease_held():
        _journal("bring_to_front", command="guided-login", skipped="no-lease")
        return
    ws_url = _browser_ws_url(tx.port)
    if ws_url is None:
        return
    _journal("bring_to_front", command="guided-login", origin="owned-target")
    _cdp_ws_call(ws_url, "Target.activateTarget", {"targetId": tid}, 3.0)


def _guided_a(
    tx: Maintenance, site: str, url: str | None, deadline: float
) -> tuple[str, str]:
    """Path A: headed under the record (mode A), the window flow, headless after."""
    tx.set_mode("A")
    try:
        print("▶ showing the shared Chromium window (guided login) …")
        if _self_run(tx.port, "switch", "headed", capture=False).returncode != 0:
            return "fail", "browser.py switch headed failed"
        if _static_site_name(site) in GUIDED_BUILTIN_WINDOW:
            # The site's own `login` window flow (it waits for Albert itself).
            left = max(60.0, deadline - time.monotonic())
            rc = _self_run(
                tx.port, "login", site, capture=False, timeout=left
            ).returncode
            if _guided_probe(tx.port, site):
                return "ok", ""
            return "fail", f"browser.py login {site} exit {rc}"
        return _guided_a_tab(tx, site, url, deadline)
    finally:
        _close_owned_targets(tx.port, list(tx.owned))
        tx.owned.clear()
        tx.note(owned_targets=[])
        _ensure_headless(tx.port)


def _guided_a_tab(
    tx: Maintenance, site: str, url: str | None, deadline: float
) -> tuple[str, str]:
    """A for a site without a window flow: an owned tab, in front, probed."""
    if not url:
        return "fail", f"no login URL known for {site} (pass -u URL)"
    tid = _guided_open_owned(tx, url)
    if tid is None:
        return "fail", "could not open the login tab"
    _activate_owned(tx, tid)
    print(
        f"👤 In the Chromium window: log in to {site}. Waiting up to "
        f"{max(0, int(deadline - time.monotonic()) // 60)} min …"
    )
    while time.monotonic() < deadline:
        time.sleep(GUIDED_PROBE_EVERY_S)
        if _guided_probe(tx.port, site):
            return "ok", ""
    return "timeout", f"no login within {GUIDED_TOTAL_S // 60} min"


# --- the command ------------------------------------------------------------------


class _Tty:
    """The controlling terminal (/dev/tty), read and written unbuffered.

    Not a text file object: a tty is not seekable, which `open(…, "r+")`
    requires. A context manager that closes the fd.
    """

    def __init__(self, fd: int) -> None:
        self.fd = fd

    def __enter__(self) -> "_Tty":
        return self

    def __exit__(self, *_exc: object) -> None:
        with contextlib.suppress(OSError):
            os.close(self.fd)

    def ask(self, prompt: str) -> str:
        """Write `prompt`, read one line; the stripped answer ('' on EOF)."""
        os.write(self.fd, prompt.encode())
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = os.read(self.fd, 1024)
            if not chunk:
                break
            buf += chunk
        return buf.decode("utf-8", "replace").strip()


def _open_tty() -> _Tty | None:
    """The controlling terminal, or None when there is none (agents, launchd)."""
    try:
        fd = os.open("/dev/tty", os.O_RDWR)
    except OSError:
        return None
    return _Tty(fd)


def _tty_ask(tty: Any, prompt: str) -> str:
    """Ask on the terminal; the stripped answer ('' on EOF)."""
    return str(tty.ask(prompt))


GUIDED_NO_TTY = (
    "❌ assisted-login needs your terminal: it is the human entry for a guided "
    "login (agent-login.py -g SITE) and asks you to confirm. Agents cannot start it."
)


@dataclass(frozen=True)
class GuidedRequest:
    """What `assisted-login` was asked for."""

    site: str
    url: str | None = None
    window: bool = False  # -a: straight to the window (A)
    force: bool = False  # -f: past unregistered CDP clients


def cmd_assisted_login(port: int, req: GuidedRequest) -> int:
    """Guided login for SITE: B (remote view) first, A (window) as fallback.

    Exit 0 logged in (or already was), 1 an error (incl. a failed cleanup),
    2 refused (no terminal, not confirmed, busy) or still not logged in,
    130 cancelled with Ctrl-C.
    """
    tty = _open_tty()
    if tty is None:
        print(GUIDED_NO_TTY, file=sys.stderr)
        return 2
    with tty:
        return _assisted_login_tty(tty, port, req)


def _assisted_precheck(tty: Any, port: int, req: GuidedRequest) -> int | None:
    """Before the transaction: a start URL, a running browser, already logged
    in, the typed confirmation. An exit code, or None to go ahead."""
    start = _guided_start_url(req.site, req.url)
    if start is None and _static_site_name(req.site) not in GUIDED_BUILTIN_WINDOW:
        print(
            f"❌ no login URL known for {req.site!r}; pass -u/--url URL",
            file=sys.stderr,
        )
        return 2
    if not _is_up(port) and cmd_up(port) != 0:
        return 1
    if _guided_probe(port, req.site):
        print(
            f"✅ {req.site}: the shared Chromium is already logged in — nothing to do"
        )
        return 0
    answer = _tty_ask(
        tty, f"Guided login for {req.site}: type the site name to start: "
    )
    if answer.lower() != req.site.strip().lower():
        print(
            f"❌ not confirmed (expected {req.site!r}) — nothing started",
            file=sys.stderr,
        )
        return 2
    return None


def _assisted_login_tty(tty: Any, port: int, req: GuidedRequest) -> int:
    """`assisted-login` once the terminal is open (see `cmd_assisted_login`)."""
    rc = _assisted_precheck(tty, port, req)
    if rc is not None:
        return rc
    start = _guided_start_url(req.site, req.url)
    deadline = time.monotonic() + GUIDED_TOTAL_S
    try:
        with _maintenance(
            req.site, "A" if req.window else "B", port=port, force=req.force
        ) as tx:
            if req.window:
                outcome, why = _guided_a(tx, req.site, start, deadline)
            else:
                outcome, why = _guided_b(tx, req.site, str(start or ""), deadline)
                if outcome == "fallback":
                    outcome, why = _offer_window(tty, tx, start, deadline, why)
    except (MaintenanceRefused, HeadedLeaseError) as exc:
        print(f"❌ guided login refused: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("❌ guided login cancelled — cleaned up", file=sys.stderr)
        return 130
    return _guided_report(req.site, outcome, why)


def _offer_window(
    tty: Any, tx: Maintenance, start: str | None, deadline: float, why: str
) -> tuple[str, str]:
    """B could not finish: close its tabs, ask for the window (A) on the terminal."""
    print(f"⚠ the login view cannot finish this login: {why}")
    _close_owned_targets(tx.port, list(tx.owned))
    for tid in list(tx.owned):
        tx.drop_owned(tid)
    answer = _tty_ask(tty, "switch to a visible window for this login? [y/N] ")
    if answer.lower() in ("y", "yes"):
        return _guided_a(tx, tx.site, start, deadline)
    return "declined", why


def _guided_report(site: str, outcome: str, why: str) -> int:
    """The final ✅/❌ line and the exit code."""
    if outcome == "ok":
        print(f"✅ {site}: logged in — agents can use this session")
        return 0
    if outcome == "fail":
        print(f"❌ {site}: {why}", file=sys.stderr)
        return 1
    print(f"❌ {site}: still not logged in ({why or outcome})", file=sys.stderr)
    return 2


def _broker_site_obj(site: str) -> "Site":
    """A dynamic registry entry for a broker-only site."""
    return Site(
        name=site,
        aliases=(),
        blurb="login broker (Bitwarden agent-logins)",
        login=functools.partial(_broker_login, site=site),
        logged_in=functools.partial(_broker_logged_in, site=site),
    )


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
            name="notion",
            aliases=("notion.so", "app.notion.com", "notion.com"),
            blurb="app.notion.com (assisted e-mail-code / SSO login; no token)",
            login=cmd_notion_login,
            logged_in=cmd_notion_logged_in,
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
        Site(
            name="switch",
            aliases=("switch-cloud", "cloud.switch.ch", "scp"),
            blurb="Switch Cloud Portal (edu-ID SSO click, assisted fallback; no token)",
            login=cmd_switch_login,
            logged_in=cmd_switch_logged_in,
        ),
    ]


def _resolve_site(name: str, *, for_login: bool = False) -> Site:
    """Find a Site: static registry first, then the login broker's `sites` list.

    Static names win. For ``login cscs`` (`for_login`) a broker that lists cscs
    takes over the login itself (the keychain flow stays reachable only as the
    human-only ``login-cscs-assisted``). An unknown name that the broker lists
    (not refused) becomes a dynamic broker Site; anything else exits 2.
    """
    key = name.strip().lower()
    test = _test_sites().get(key)
    if test is not None:
        return _test_site_obj(key, test)
    for site in _sites():
        if key == site.name or key in site.aliases:
            if site.name == "cscs" and for_login:
                try:
                    entry = _broker_site("cscs")
                except BrokerUnavailable:
                    entry = None
                if entry is not None and not entry.get("refused"):
                    return dataclasses.replace(
                        site,
                        blurb="CSCS portal via the login broker",
                        login=functools.partial(_broker_login, site="cscs"),
                    )
            return site
    reason = ""
    try:
        entry = _broker_site(key)
    except BrokerUnavailable as exc:
        entry, reason = None, f" ({exc})"
    if entry is not None and not entry.get("refused"):
        return _broker_site_obj(key)
    if entry is not None:
        reason = f" (agent-logins item refused: {entry.get('reason') or '?'})"
    avail = "\n".join(f"  {s.name:<10} {s.blurb}" for s in _sites())
    print(
        f"❌ Unknown site: {name!r} — not whitelisted in Bitwarden agent-logins or "
        f"broker down{reason}.\nBuilt-in sites:\n{avail}",
        file=sys.stderr,
    )
    sys.exit(2)


def cmd_login(port: int, site_name: str) -> int:
    """Ensure SITE is logged in (automated or assisted, per the site)."""
    key = site_name.strip().lower()
    if key in _safari.SAFARI_SITES:
        _journal_note(flow="safari")
        return _safari_login(port, key)
    site = _resolve_site(site_name, for_login=True)
    is_broker = (
        isinstance(site.login, functools.partial) and site.login.func is _broker_login
    )
    _journal_note(site=site.name, flow="broker" if is_broker else "builtin")
    return site.login(port)


def cmd_logged_in(port: int, site_name: str) -> int:
    """Exit 0 if SITE is logged in, 2 if not."""
    key = site_name.strip().lower()
    if key in _safari.SAFARI_SITES:
        return _safari_logged_in(port, key)
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
    """Parse, bootstrap, and dispatch; a timed-out Playwright attach is a ❌ line."""
    args = parse_args()
    ensure_deps()
    # Say what we are doing BEFORE anything attaches over CDP: this is the
    # `purpose` every client registration reports to whoever waits on the gate.
    site = getattr(args, "site", None)
    _set_purpose(f"{args.cmd} {site}" if site else str(args.cmd))
    _journal_set_argv(args)
    try:
        # Headless invariant (tp#836): a headed browser without a live
        # guided-login lease is reverted BEFORE the command takes any gate
        # (best effort: a failed revert warns, the command still runs).
        _preflight(str(args.cmd), args.cdp_port)
        return _journaled_dispatch(args, args.cdp_port)
    except BrowserAttachTimeout as exc:
        return _fail(str(exc))


# Subcommands whose start and end go to the journal, keyed to their event name.
_JOURNALED_CMDS = {
    "up": "up",
    "switch": "switch",
    "down": "down",
    "login": "login",
    "cscs-login": "login",
    "login-cscs-assisted": "login",
    "assisted-login": "guided_login",
}


# Unjournaled commands that may raise the window (`_bring_to_front`): their
# parent chain is collected up front so the raise event can carry it.
_JOURNAL_RAISING_CMDS = frozenset({"doctor"})


def _journal_cmd_fields(args: argparse.Namespace) -> dict[str, object]:
    """The event-specific journal fields of a journaled subcommand."""
    if args.cmd == "up":
        return {"mode": _desired_mode()}
    if args.cmd == "switch":
        rec = _lifecycle_read()
        return {"from": rec.get("mode") if rec else None, "to": args.mode}
    if args.cmd == "down":
        return {"forced": bool(args.force)}
    if args.cmd == "login-cscs-assisted":
        return {"site": "cscs", "flow": "cscs-assisted"}
    return {"site": "cscs" if args.cmd == "cscs-login" else str(args.site)}


def _journaled_dispatch(args: argparse.Namespace, port: int) -> int:
    """`_dispatch`, with a start and an end journal event for lifecycle/login.

    The end event carries the exit code (or the exception's class name), the
    wall-clock duration and whatever the command noted via `_journal_note`
    (e.g. a login's flow). A ``sys.exit`` inside a command is recorded with
    its code and re-raised unchanged.
    """
    event = _JOURNALED_CMDS.get(str(args.cmd))
    if event is not None or args.cmd in _JOURNAL_RAISING_CMDS:
        _journal_parent_chain()  # now, before any gate/lease is held
    if event is None:
        return _dispatch(args, port)
    try:
        fields = _journal_cmd_fields(args)
    except Exception:  # pylint: disable=broad-exception-caught
        fields = {}
    _journal(event, phase="start", **fields)
    t0 = time.monotonic()
    result: object = "exception"
    try:
        rc = _dispatch(args, port)
        result = rc
        return rc
    except SystemExit as exc:
        code = exc.code
        result = 0 if code is None else code if isinstance(code, int) else 1
        raise
    except BaseException as exc:
        result = f"exception:{type(exc).__name__}"
        raise
    finally:
        _journal(
            event,
            phase="end",
            **{
                **fields,
                **_JOURNAL_NOTES,
                "result": result,
                "duration_ms": int((time.monotonic() - t0) * 1000),
            },
        )


def _dispatch(args: argparse.Namespace, port: int) -> int:
    """Run the chosen subcommand."""
    # A flat `if args.cmd == …: return cmd_…(…)` chain: one branch and one return
    # per subcommand, each forwarding a different argument set. A dispatch table
    # would need a per-command adapter lambda — more indirection, not less.
    # pylint: disable=too-many-return-statements,too-many-branches
    if args.cmd == "up":
        return cmd_up(port)
    if args.cmd == "status":
        if args.probe:
            return cmd_status(port, args.full_urls, probe=True)
        return cmd_status(port, args.full_urls)
    if args.cmd == "close-hung":
        return cmd_close_hung(port, assume_yes=args.yes)
    if args.cmd == "close":
        return cmd_close(
            port,
            args.urls,
            args.ids,
            dry_run=args.dry_run,
            wait_s=args.wait,
            deadline_s=args.deadline,
        )
    if args.cmd == "switch":
        return cmd_switch(
            port,
            args.mode,
            args.force,
            force_maintenance=getattr(args, "force_maintenance", False),
        )
    if args.cmd == "clients":
        return cmd_clients(port)
    if args.cmd == "journal":
        return cmd_journal(args.lines, args.event, args.json)
    if args.cmd == "doctor":
        return cmd_doctor(port)
    if args.cmd == "register-exec":
        return cmd_register_exec(port, args.tool, args.cmd_)
    if args.cmd == "down":
        return cmd_down(port, args.force, getattr(args, "force_maintenance", False))
    if args.cmd == "open":
        return cmd_open(port, args.url, reuse=args.reuse, new=args.new)
    if args.cmd == "eval":
        return cmd_eval(
            port, args.js, args.url, timeout_s=args.timeout, target=args.target
        )
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
    # Login broker (sessions for Bitwarden agent-logins sites).
    if args.cmd == "broker-sites":
        return cmd_broker_sites()
    if args.cmd == "logout":
        return cmd_broker_logout(port, args.site)
    if args.cmd == "import-safari":
        return cmd_import_safari(port, args.site, dry_run=args.dry_run)
    if args.cmd == "login-cscs-assisted":
        return cmd_login_cscs_assisted(port)
    if args.cmd == "assisted-login":
        return cmd_assisted_login(
            port,
            GuidedRequest(args.site, args.url, args.fallback_window, args.force),
        )
    if args.cmd == "maintenance-watchdog":
        return cmd_maintenance_watchdog(port, args.nonce)
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
