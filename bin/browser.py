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
  status    Show CDP health, browser version, and open tabs.
  down      Quit the shared browser.
  open URL  Open/navigate a tab to URL in the shared browser.
  eval JS   Run a JS expression in the active (or --url-matched) tab; print JSON.

Generic multi-site login (a SITE is one of the entries in the SITES registry —
currently ``cscs`` and ``anthropic``/``claude``; add more by registering a Site):
  login SITE        Ensure SITE is logged in in the shared browser. Automated for
                    sites with stored credentials (CSCS Keycloak). For claude.ai:
                    FULLY automatic when $ANTHROPIC_LOGIN_EMAIL is set and himalaya
                    is installed (triggers the magic-link email, reads it, opens
                    the link — no password, no code); otherwise ASSISTED (you
                    complete the email login in the window). Records a login event.
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
import glob
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

DEFAULT_CDP_PORT = int(os.environ.get("CLAUDE_BROWSER_CDP_PORT", "9222"))
PROFILE_DIR = Path.home() / ".cache" / "claude-browser" / "profile"
PID_FILE = Path.home() / ".cache" / "claude-browser" / "browser.pid"
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

# Per-site log of REAL (cold) logins — one JSON object per line. Appended only
# when `login <site>` actually had to sign in (never on a warm/already-logged-in
# run), so `login-log <site>` shows how often you truly re-authenticated.
LOGIN_LOG_DIR = Path.home() / ".cache" / "claude-browser" / "login-log"


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
            "  ./browser.py status             # CDP health + open tabs\n"
            "  ./browser.py open https://portal.cscs.ch/profile/\n"
            "  ./browser.py eval 'document.title'\n"
            "  ./browser.py token              # cache the CSCS portal token\n"
            "  ./browser.py cscs-store-creds   # one-time: cache CSCS creds in keychain\n"
            "  ./browser.py cscs-login         # auto-login to CSCS (keychain, no Touch ID)\n"
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
    sub.add_parser("up", help="Launch the shared browser (idempotent).")
    sub.add_parser("status", help="Show CDP health, version, and open tabs.")
    sub.add_parser("down", help="Quit the shared browser.")
    po = sub.add_parser("open", help="Open/navigate a tab to URL.")
    po.add_argument("url", help="URL to open.")
    pe = sub.add_parser("eval", help="Eval a JS expression in a tab; print JSON.")
    pe.add_argument("js", help="JavaScript expression to evaluate.")
    pe.add_argument(
        "--url",
        default=None,
        help="Substring to pick the target tab (default: first/active tab).",
    )
    sub.add_parser("token", help="Cache the CSCS portal token from the portal tab.")
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
    pl.add_argument("site", help="Site to log into (e.g. cscs, anthropic/claude).")
    pli = sub.add_parser(
        "logged-in", help="Exit 0 if SITE is logged in, 2 if not (no login)."
    )
    pli.add_argument("site", help="Site to check.")
    pll = sub.add_parser(
        "login-log", help="Show how often a real login was needed for SITE."
    )
    pll.add_argument("site", help="Site whose login log to show.")
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


def ensure_deps():  # noqa: ANN201  # literal "def ensure_deps():" required by pre-commit hook
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


def cmd_up(port: int) -> int:
    """Launch the shared browser if not already running (idempotent)."""
    if _is_up(port):
        print(f"✓ Shared browser already up (CDP http://localhost:{port}).")
        return 0
    PROFILE_DIR.mkdir(parents=True, exist_ok=True)
    binary = _chromium_binary()
    args = [
        binary,
        f"--user-data-dir={PROFILE_DIR}",
        f"--remote-debugging-port={port}",
        "--no-first-run",
        "--no-default-browser-check",
        "--remote-allow-origins=*",
    ]
    proc = subprocess.Popen(  # noqa: S603 - launching a known browser binary
        args,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    PID_FILE.write_text(str(proc.pid))
    for _ in range(50):  # up to ~10s
        if _is_up(port):
            print(
                f"✓ Shared browser launched (pid {proc.pid}, CDP http://localhost:{port}).\n"
                "  Log into your sites in that window ONCE; the session persists.\n"
                f"  Profile: {PROFILE_DIR}"
            )
            return 0
        time.sleep(0.2)
    return _fail("Browser started but CDP endpoint never came up.")


def cmd_status(port: int) -> int:
    """Print CDP health, browser version, and open tabs."""
    ver = _cdp_get(port, "/json/version")
    if ver is None:
        print(
            f"✗ Shared browser is DOWN (no CDP on http://localhost:{port}). Run: browser.py up"
        )
        return 1
    assert isinstance(ver, dict)
    print(f"✓ Up — {ver.get('Browser')} | CDP http://localhost:{port}")
    tabs = _cdp_get(port, "/json/list")
    tab_list = tabs if isinstance(tabs, list) else []
    pages = [t for t in tab_list if isinstance(t, dict) and t.get("type") == "page"]
    print(f"  {len(pages)} tab(s):")
    for t in pages:
        print(f"   - {t.get('title') or '(untitled)'}  →  {t.get('url')}")
    return 0


def cmd_down() -> int:
    """Quit the shared browser."""
    killed = False
    if PID_FILE.exists():
        try:
            pid = int(PID_FILE.read_text().strip())
            os.kill(pid, 15)
            killed = True
        except (ValueError, ProcessLookupError, PermissionError):
            pass
        PID_FILE.unlink(missing_ok=True)
    # Fallback: match by profile dir.
    subprocess.run(  # noqa: S603,S607
        ["pkill", "-f", f"--user-data-dir={PROFILE_DIR}"], check=False
    )
    print("✓ Shared browser stopped." if killed else "Stopped (or was not running).")
    return 0


def _connect(port: int):
    """Connect Playwright to the shared browser over CDP. Returns (pw, browser)."""
    from playwright.sync_api import sync_playwright

    if not _is_up(port):
        sys.exit("Shared browser is down. Run: browser.py up")
    pw = sync_playwright().start()
    # 127.0.0.1, not localhost — see _cdp_get (avoids the IPv6 ::1 stall).
    browser = pw.chromium.connect_over_cdp(f"http://127.0.0.1:{port}")
    return pw, browser


def _is_blank(url: str) -> bool:
    """True for an empty/new-tab/blank page that's safe to reuse."""
    return not url or url == "about:blank" or url.startswith("chrome://")


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
    return ctx, ctx.new_page()


def cmd_open(port: int, url: str) -> int:
    """Open/navigate a tab to URL."""
    pw, browser = _connect(port)
    try:
        ctx = browser.contexts[0] if browser.contexts else browser.new_context()
        blank = [pg for pg in ctx.pages if _is_blank(pg.url)]
        page = blank[0] if blank else ctx.new_page()
        page.goto(url, wait_until="domcontentloaded")
        print(f"✓ Opened: {page.url}  (title: {page.title()!r})")
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
        r = subprocess.run(  # noqa: S603
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
        r = subprocess.run(  # noqa: S603
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
        subprocess.run(  # noqa: S603
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
        r = subprocess.run(  # noqa: S603
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
        creds = subprocess.run(  # noqa: S603
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
        otp_r = subprocess.run(  # noqa: S603
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


def cmd_cscs_login(port: int) -> int:
    """Log into CSCS in the shared browser using stored credentials, then cache.

    Fills the Keycloak username/password + TOTP from the macOS keychain when set
    up (``cscs-store-creds``, no fingerprint), else from the single ``op`` item
    (Touch-ID-gated; vault never exposed to the browser). Captures the API token
    from the SAME connection (no second ``connect_over_cdp``). Idempotent: if
    already logged in, it skips the login form and just refreshes the token.
    """
    pw, browser = _connect(port)
    try:
        # Prefer a settled portal app tab (already logged in) so we skip a full
        # SPA reload — the slow part of a repeated `cscs-login`. _pick_portal_page
        # ignores transient OAuth-callback tabs; only navigate when there is no
        # settled app tab yet (cold session / Keycloak tab).
        ctx, page = _pick_portal_page(browser)
        if not _on_portal(page):
            page.goto(PORTAL_PROFILE_URL, wait_until="domcontentloaded")
            page.wait_for_timeout(1500)
        if _on_portal(page):
            print("✓ Already logged into CSCS.")
        elif "auth.cscs.ch" not in page.url:
            return _fail(f"Unexpected page (not portal, not Keycloak): {page.url}")
        else:
            creds = _keychain_creds()
            if creds is not None:
                print("Using CSCS credentials from the macOS keychain (no Touch ID).")
            else:
                print(
                    "No keychain credentials yet — falling back to 1Password "
                    "(approve Touch ID). Run `browser.py cscs-store-creds` once to "
                    "make future logins fingerprint-free."
                )
                creds = _op_creds(CSCS_OP_ITEM, CSCS_OP_ACCOUNT)
            if creds is None:
                return _fail(
                    "No CSCS credentials available. Either run "
                    "`browser.py cscs-store-creds` (keychain, no fingerprint), or "
                    f"make 1Password item '{CSCS_OP_ITEM}' (account "
                    f"{CSCS_OP_ACCOUNT}) readable via op (desktop 'Integrate with "
                    "1Password CLI' on, Touch ID approved)."
                )
            user, password, otp = creds
            page.fill("#username", user)
            page.fill("#password", password)
            _click_keycloak_submit(page)
            # Wait for EITHER the OTP step or a direct landing on the portal.
            otp_filled = False
            for _ in range(40):  # ~20s
                if _on_portal(page):
                    break
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
            if not _on_portal(page):
                return _fail(
                    "Login did not reach the portal — wrong username/password/OTP, "
                    f"or an unexpected page ({page.url})."
                )
            print("✓ Logged into CSCS.")
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
    /login"). A redirect to /login or /logout, or bouncing off the billing route,
    means not logged in (or no admin rights in this org)."""
    from playwright.sync_api import Error as PlaywrightError

    try:
        page.goto(CLAUDE_BILLING_URL, wait_until="domcontentloaded")
        page.wait_for_timeout(2500)
    except PlaywrightError:
        return False
    url = page.url
    if "/login" in url or "/logout" in url:
        return False
    if "/admin-settings/billing" not in url:
        return False  # bounced elsewhere — wrong org / not an admin
    return _claude_billing_sentinel(page)


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


def _himalaya_latest_login_mail(
    himalaya: str, email: str, since_ts: float
) -> tuple[str, str] | None:
    """Newest 'log in to Claude.ai' mail to `email`, not clearly older than
    `since_ts`. Searches INBOX + Archive (a server rule auto-archives them).
    Returns (folder, id) or None."""
    best_folder: str | None = None
    best_id: str | None = None
    best_ts = -1.0
    for folder in ("INBOX", "Archive"):
        try:
            res = subprocess.run(  # noqa: S603
                [
                    himalaya,
                    "envelope",
                    "list",
                    "--folder",
                    folder,
                    "--page-size",
                    "30",
                    "-o",
                    "json",
                ],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            continue
        if res.returncode != 0:
            continue
        try:
            envs = json.loads(res.stdout)
        except (ValueError, TypeError):
            continue
        for env in envs if isinstance(envs, list) else []:
            if "log in to Claude.ai" not in (env.get("subject") or ""):
                continue
            to = ((env.get("to") or {}).get("addr") or "").lower()
            if email and to and to != email.lower():
                continue
            ts = _himalaya_date_epoch(env.get("date") or "")
            if ts and ts + 180 < since_ts:  # clearly older than our trigger → skip
                continue
            if ts > best_ts:
                best_ts, best_folder, best_id = ts, folder, str(env.get("id"))
    if best_folder is None or best_id is None:
        return None
    return (best_folder, best_id)


def _himalaya_extract_magic_link(himalaya: str, folder: str, msg_id: str) -> str | None:
    """Read the mail body and pull out the claude.ai/magic-link#… URL (a bearer
    credential — never printed/logged)."""
    try:
        res = subprocess.run(  # noqa: S603
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
        return False
    print(f"  Sent a login link to {email}; reading it via himalaya…", file=sys.stderr)
    link = None
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        hit = _himalaya_latest_login_mail(himalaya, email, trigger_ts)
        if hit:
            link = _himalaya_extract_magic_link(himalaya, hit[0], hit[1])
            if link:
                break
        time.sleep(3)
    if not link:
        print("  No magic-link email arrived within 90s.", file=sys.stderr)
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
    ASSISTED: you complete the email login in the shared window; it auto-detects."""
    pw, browser = _connect(port)
    try:
        _ctx, page = _pick_page(browser, "claude.ai")
        if _claude_logged_in(page):
            print("✓ Already logged into Claude (claude.ai).")
            return 0
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

        # Assisted fallback. If auto already triggered the email, don't re-send.
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


def cmd_login_log(site_name: str) -> int:
    """Show how often a *real* login was needed for SITE (count, first/last,
    average interval, recent events)."""
    site = _resolve_site(site_name)
    path = LOGIN_LOG_DIR / f"{site.name}.jsonl"
    if not path.is_file():
        print(
            f"No real logins recorded yet for '{site.name}'. "
            f"(Each time `login {site.name}` actually had to sign in is logged here.)"
        )
        return 0
    events: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except ValueError:
            continue
    if not events:
        print(f"No real logins recorded yet for '{site.name}'.")
        return 0
    events.sort(key=lambda e: e.get("ts", 0))
    n = len(events)
    print(f"Login frequency for '{site.name}': {n} real login(s).")
    print(f"  first: {events[0].get('iso', '?')}")
    print(f"  last:  {events[-1].get('iso', '?')}")
    if n >= 2:
        span_days = (events[-1]["ts"] - events[0]["ts"]) / 86400
        avg = span_days / (n - 1)
        print(f"  span:  {span_days:.1f} days  →  every ~{avg:.1f} days on average")
    print("  recent:")
    for e in events[-10:]:
        print(f"    {e.get('iso', '?')}  ({e.get('mode', '?')})")
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
    store_creds: Optional[Callable[[], int]] = None
    forget_creds: Optional[Callable[[], int]] = None


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
    if args.cmd == "up":
        return cmd_up(port)
    if args.cmd == "status":
        return cmd_status(port)
    if args.cmd == "down":
        return cmd_down()
    if args.cmd == "open":
        return cmd_open(port, args.url)
    if args.cmd == "eval":
        return cmd_eval(port, args.js, args.url)
    if args.cmd == "token":
        return cmd_token(port)
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
