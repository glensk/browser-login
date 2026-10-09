"""Helpers of agent-login.py: LaunchAgents, mail, network wait, Safari sessions,
the shared Chromium's window mode (guided logins under the headed lease)."""

from __future__ import annotations

import contextlib
import importlib.util
import math
import os
import shutil
import socket
import subprocess
import sys
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType

from broker import safari_cookies

MAIL_TO = "albert.glensk@gmail.com"
SCRIPT = Path(__file__).resolve().parent / "agent-login.py"
BROWSER_PY = Path(__file__).resolve().parent / "bin" / "browser.py"
LAUNCH_LABEL = "com.albert.agent-login-check"
LAUNCH_PLIST = Path.home() / "Library" / "LaunchAgents" / f"{LAUNCH_LABEL}.plist"
LAUNCH_LOG = Path.home() / "Library" / "Logs" / f"{LAUNCH_LABEL}.log"
LAUNCH_HOUR, LAUNCH_MINUTE = 9, 15


SNAPSHOT_LABEL = "com.albert.agent-login-snapshot"
SNAPSHOT_INTERVAL_S = 600


def _plist_path(label: str) -> Path:
    return Path.home() / "Library" / "LaunchAgents" / f"{label}.plist"


def snapshot_plist() -> str:
    """The every-10-min LaunchAgent (`agent-login.py -S`), as text. Pure."""
    return launchagent_plist(
        label=SNAPSHOT_LABEL,
        args=("-S",),
        schedule=(
            f"<key>StartInterval</key>\n    <integer>{SNAPSHOT_INTERVAL_S}</integer>"
        ),
        run_at_load=True,
    )


def launchagent_plist(
    *,
    label: str = LAUNCH_LABEL,
    args: tuple[str, ...] = ("-c", "-m"),
    schedule: str = "",
    run_at_load: bool = False,
) -> str:
    """A LaunchAgent running this script; default: daily `-c -m` at 09:15. Pure."""
    if not schedule:
        schedule = f"""<key>StartCalendarInterval</key>
    <dict>
        <key>Hour</key>
        <integer>{LAUNCH_HOUR}</integer>
        <key>Minute</key>
        <integer>{LAUNCH_MINUTE}</integer>
    </dict>"""
    log = Path.home() / "Library" / "Logs" / f"{label}.log"
    arg_xml = "".join(f"\n        <string>{a}</string>" for a in args)
    search_path = ":".join(
        [
            str(Path.home() / ".local" / "bin"),
            "/opt/homebrew/bin",
            "/usr/local/bin",
            "/usr/bin",
            "/bin",
        ]
    )
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/bin/env</string>
        <string>python3</string>
        <string>{SCRIPT}</string>{arg_xml}
    </array>
    {schedule}
    <key>StandardOutPath</key>
    <string>{log}</string>
    <key>StandardErrorPath</key>
    <string>{log}</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>{search_path}</string>
    </dict>
    <key>RunAtLoad</key>
    <{"true" if run_at_load else "false"}/>
</dict>
</plist>
"""


def _bootout(label: str) -> None:
    subprocess.run(
        ["launchctl", "bootout", f"gui/{os.getuid()}/{label}"],
        check=False,
        capture_output=True,
    )


def _install_agent(label: str, text: str, what: str) -> int:
    path = _plist_path(label)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    _bootout(label)
    rc = subprocess.run(
        ["launchctl", "bootstrap", f"gui/{os.getuid()}", str(path)], check=False
    ).returncode
    if rc != 0:
        print(f"❌ launchctl bootstrap {path} failed (exit {rc})")
        return 1
    print(f"✅ installed {label} ({what})")
    return 0


def install_daily() -> int:
    """Write + (re)load both LaunchAgents: the daily check and the snapshot."""
    rc = _install_agent(
        LAUNCH_LABEL,
        launchagent_plist(),
        f"daily {LAUNCH_HOUR:02d}:{LAUNCH_MINUTE:02d}, -c -m; log {LAUNCH_LOG}",
    )
    return rc or _install_agent(
        SNAPSHOT_LABEL,
        snapshot_plist(),
        f"every {SNAPSHOT_INTERVAL_S // 60} min, -S: site list + agents file",
    )


def uninstall_daily() -> int:
    """Unload + remove both LaunchAgents."""
    for label in (LAUNCH_LABEL, SNAPSHOT_LABEL):
        _bootout(label)
        _plist_path(label).unlink(missing_ok=True)
        print(f"removed {label}")
    return 0


def gog_bin() -> str | None:
    """gog: $GOG_BIN, then PATH, then the Homebrew default; None when absent."""
    for cand in (
        os.environ.get("GOG_BIN"),
        shutil.which("gog"),
        "/opt/homebrew/bin/gog",
    ):
        if cand and Path(cand).is_file():
            return cand
    return None


def send_mail(subject: str, body: str) -> bool:
    """Mail Albert through gog's Gmail API; False (after a message) on failure."""
    gog = gog_bin()
    if gog is None:
        print("❌ gog (gogcli) not found — set GOG_BIN or install gogcli; no mail sent")
        return False
    res = subprocess.run(
        [
            gog,
            "gmail",
            "send",
            "-a",
            MAIL_TO,
            "--to",
            MAIL_TO,
            "--subject",
            subject,
            "--body-file",
            "-",
            "--no-input",
        ],
        input=body,
        text=True,
        check=False,
        capture_output=True,
    )
    if res.returncode != 0:
        print(f"❌ gog gmail send failed (exit {res.returncode}): {res.stderr.strip()}")
        return False
    print(f"✉️  mailed {MAIL_TO}: {subject}")
    return True


# The daily run fires right after the Mac wakes, often before the network is up.
NETWORK_HOST = "vaultwarden.dom42.space"
NETWORK_WAIT_S = 300


def wait_for_network(
    host: str = NETWORK_HOST,
    timeout_s: float = NETWORK_WAIT_S,
    *,
    sleep=time.sleep,
    clock=time.monotonic,
) -> bool:
    """True once `host` resolves (polled every 15 s), False after `timeout_s`."""
    deadline = clock() + timeout_s
    while True:
        try:
            socket.getaddrinfo(host, 443)
            return True
        except OSError:
            if clock() >= deadline:
                return False
            sleep(15)


def safari_sessions(sites: list[str]) -> dict[str, dict]:
    """Per site: does Safari hold usable cookies, and until when (names/expiry only).

    ``{"safari": True/False/None, "safari_cookies": n, "safari_expires": "YYYY-MM-DD"
    or None, "safari_error": ""}`` — ``None`` when Safari's cookie file is unreadable.
    """
    try:
        jar = safari_cookies.read_binarycookies()
    except (OSError, ValueError) as exc:
        err = str(getattr(exc, "strerror", None) or exc)
        return {
            s: {
                "safari": None,
                "safari_cookies": 0,
                "safari_expires": None,
                "safari_error": err,
            }
            for s in sites
        }
    out = {}
    for site in sites:
        picked = safari_cookies.site_cookies(jar, site)
        names = safari_cookies.SAFARI_SITES[site].session_cookies
        if names:  # only the cookies that ARE the login count
            picked = [c for c in picked if c.name in names]
        latest = max((c.expires for c in picked), default=None)
        out[site] = {
            "safari": bool(picked),
            "safari_cookies": len(picked),
            "safari_expires": (
                time.strftime("%Y-%m-%d", time.localtime(latest)) if latest else None
            ),
            "safari_error": "",
        }
    return out


# --- running bin/browser.py: every call has an explicit time budget (tp#843) ---
# browser.py bounds an unattended `login`/`logged-in` itself (its LoginDeadline
# exits 124/125); the runner's subprocess timeout is the last resort for when
# that inner layer fails too. It derives from the SAME env var + a margin for
# interpreter start, venv bootstrap and the inner 15 s tab cleanup.

LOGIN_TIMEOUT_ENV = "CLAUDE_BROWSER_LOGIN_TIMEOUT_S"
LOGIN_TIMEOUT_DEFAULT_S = 300.0
RUNNER_MARGIN_S = 90.0
# browser.py's exit codes of a fired LoginDeadline: tabs closed / unconfirmed.
LOGIN_TIMEOUT_RC = 124
LOGIN_TIMEOUT_DIRTY_RC = 125
# `_browser`'s exit code after the RUNNER killed browser.py (never BUSY_RC).
KILLED_RC = -9
# Fixed budgets of the other subcommands (seconds; `logged-in` = 120 + margin;
# `eval`/`eval-fresh` are always called with `-t 30`).
BROWSER_TIMEOUTS = {
    "logged-in": 120.0 + RUNNER_MARGIN_S,
    "status": 30.0,
    "up": 120.0,
    "switch": 120.0,
    "down": 60.0,
    "open": 60.0,
    "eval": 60.0,
    "eval-fresh": 60.0,
    "reap-owned": 60.0,
    # Stale-record recovery (`recover_stale_guided_login`): close the owned
    # tabs (15 s), reap (gate wait + raw CDP), revert headed, resume clients.
    "maintenance-watchdog": 120.0,
}


def env_seconds(raw: str | None, default: float) -> float:
    """browser.py's `_env_seconds`: a finite number > 0, else `default` (pinned
    to the same answers by tests/test_login_timeout.py)."""
    if raw is None:
        return default
    try:
        value = float(raw)
    except ValueError:
        return default
    return value if math.isfinite(value) and value > 0 else default


def login_timeout_s() -> float:
    """browser.py's inner `login` deadline ($CLAUDE_BROWSER_LOGIN_TIMEOUT_S)."""
    return env_seconds(os.environ.get(LOGIN_TIMEOUT_ENV), LOGIN_TIMEOUT_DEFAULT_S)


def browser_timeout(cmd: str) -> float:
    """The runner's budget for `browser.py CMD` (KeyError for an unknown CMD)."""
    if cmd == "login":
        return login_timeout_s() + RUNNER_MARGIN_S
    return BROWSER_TIMEOUTS[cmd]


@dataclass
class BrowserRun:
    """One `browser.py` run: its exit code (None when the runner killed it)."""

    rc: int | None
    killed: bool
    stdout: str
    elapsed_s: float


def run_browser(
    *args: str, timeout_s: float | None, capture: bool = False, quiet: bool = False
) -> BrowserRun:
    """Run bin/browser.py with `args`, killed after `timeout_s` (None = never:
    only for a guided login, which waits for Albert).

    `capture` collects stdout (stderr too, not returned); `quiet` discards
    both; neither = they go to our terminal. On a timeout ``subprocess.run``
    SIGKILLs browser.py only — its `security` children run in their own
    session and are left alone (tp#504). A killed run cannot close the tab it
    owned, so `reap_owned_tabs` runs right after (tp#845).
    """
    argv = [sys.executable, str(BROWSER_PY), *args]
    t0 = time.monotonic()
    try:
        if capture:
            res = subprocess.run(
                argv, check=False, capture_output=True, text=True, timeout=timeout_s
            )
        else:
            out = subprocess.DEVNULL if quiet else None
            res = subprocess.run(
                argv, check=False, stdout=out, stderr=out, timeout=timeout_s
            )
    except subprocess.TimeoutExpired as exc:
        partial = exc.stdout or ""
        if isinstance(partial, bytes):
            partial = partial.decode(errors="replace")
        killed = BrowserRun(None, True, partial, time.monotonic() - t0)
        if args[:1] != ("reap-owned",):
            reap_owned_tabs()
        return killed
    stdout = res.stdout if capture and isinstance(res.stdout, str) else ""
    return BrowserRun(res.returncode, False, stdout, time.monotonic() - t0)


def reap_owned_tabs() -> int | None:
    """`browser.py reap-owned`: close the tabs dead browser.py runs left
    (after a kill, and at the start of the daily check). Its exit code, None
    when it had to be killed itself; never raises."""
    run = run_browser("reap-owned", timeout_s=browser_timeout("reap-owned"), quiet=True)
    return run.rc


def _browser(*args: str, quiet: bool = False, timeout_s: float | None) -> int:
    """`run_browser` → its exit code, KILLED_RC after an outer kill."""
    run = run_browser(*args, timeout_s=timeout_s, quiet=quiet)
    return KILLED_RC if run.rc is None else run.rc


def browser_mode() -> str | None:
    """ "headless" / "headed" for the running shared Chromium, None when down
    (or when `status` itself had to be killed: unknown)."""
    run = run_browser("status", timeout_s=browser_timeout("status"), capture=True)
    first = (run.stdout.splitlines() or [""])[0]
    if run.killed or not first.startswith("✓ Up"):
        return None
    return "headless" if "(headless)" in first else "headed"


def _browser_module() -> ModuleType:
    """bin/browser.py loaded as a module, fresh, for the CURRENT instance.

    browser.py reads $CLAUDE_BROWSER_INSTANCE (and so its cache dir, where the
    headed lease lives) at import time, and `site_instance` changes it per
    site — hence a fresh load per guided login instead of a cached import.
    """
    spec = importlib.util.spec_from_file_location("browser_py_guided", BROWSER_PY)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {BROWSER_PY}")
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    except SystemExit as exc:  # e.g. an unknown $CLAUDE_BROWSER_INSTANCE
        raise RuntimeError(f"cannot load {BROWSER_PY}: {exc.code}") from None
    return mod


# browser.py's exit code while a guided login owns the browser (EX_TEMPFAIL):
# busy, re-check later — never "logged out", never a reason to log in or mail.
BUSY_RC = 75


def guided_busy() -> str | None:
    """``busy: guided login for SITE …`` while one owns the shared browser."""
    try:
        mod = _browser_module()
        rec = mod._maint_live()  # pylint: disable=protected-access
    except (RuntimeError, OSError):
        return None
    if rec is None:
        return None
    return str(mod._maint_refusal(rec)).splitlines()[0]  # pylint: disable=protected-access


@dataclass
class GuidedWindow:
    """What `guided_window` reports back: did the window go away again?"""

    restored: bool = True


def hide_window(mod: ModuleType | None = None, nonce: str | None = None) -> bool:
    """`browser.py switch headless`, one retry; False (loudly) when both fail.

    With `mod`/`nonce` (the guided login's own lease) it first checks the lease
    file: when ANOTHER owner's lease is live now (ours was lost and a new
    guided login took over), that window is not ours to close — skip, True.
    Our own live lease, or none at all, means switch back.

    Never silent: a browser left headed outside the lease is exactly what the
    headless invariant forbids — the next browser.py command would revert it,
    but the human must know now.
    """
    if mod is not None and nonce is not None:
        live = mod._headed_lease_live()  # pylint: disable=protected-access
        if live is not None and live.get("owner_nonce") != nonce:
            print(
                "⚠ another guided login holds the headed lease now — leaving its "
                "window alone (not switching headless)."
            )
            return True
    print("▶ hiding the Chromium window again (switch headless) …")
    for attempt in (1, 2):
        if _browser("switch", "headless", timeout_s=browser_timeout("switch")) == 0:
            return True
        print(f"❌ browser.py switch headless failed (attempt {attempt}/2)")
        if attempt == 1:
            time.sleep(2)
    print(
        "❌ the shared Chromium is still HEADED after the guided login. Every "
        "browser.py command will try to revert it; fix it now: "
        f"{BROWSER_PY} switch headless   (-f if an unregistered client blocks it)"
    )
    return False


@contextlib.contextmanager
def guided_window(site: str, force: bool = False) -> Iterator[GuidedWindow]:
    """Show the shared Chromium for a guided login, then hide it again.

    Order (tp#836): enter the guided-login maintenance transaction in mode A
    (`_maintenance(site, "A")`: pauses registered long-lived clients, takes the
    gate and the interaction lease, writes the record whose nonce every child
    browser.py inherits, starts the recovery watchdog) → `switch headed` → the
    block → `switch headless` (one retry, loud on failure) → the transaction's
    cleanup (owned tabs closed, record cleared, clients resumed). A failed
    `switch headed` raises RuntimeError after reverting whatever is left
    headed. The yielded `GuidedWindow.restored` says whether the window is gone.
    `force` (agent-login -g SITE -F): start even with unregistered CDP clients
    attached.
    """
    state = GuidedWindow()
    with contextlib.ExitStack() as stack:
        try:
            mod = _browser_module()
            tx = stack.enter_context(
                mod._maintenance(  # pylint: disable=protected-access
                    site, "A", force=force
                )
            )
            nonce = tx.nonce
        except RuntimeError as exc:  # MaintenanceRefused/HeadedLease*, load failure
            print(f"❌ guided login refused: {exc}")
            raise
        print("▶ showing the shared Chromium window (guided login) …")
        if _browser("switch", "headed", timeout_s=browser_timeout("switch")) != 0:
            if browser_mode() == "headed":
                hide_window(mod, nonce)
            raise RuntimeError("browser.py switch headed failed")
        try:
            yield state
        finally:
            state.restored = hide_window(mod, nonce)


# How long a not-live record without a known watchdog pid must sit before the
# backstop treats it as abandoned: a watchdog the owner spawned but never got
# to record polls every 2 s, so it would have cleared the record long before.
STALE_NO_WATCHDOG_S = 120.0


def _watchdog_gone(mod: ModuleType, rec: dict) -> bool:
    """True only when the record's watchdog is certainly not running.

    A recorded pid that is gone (or, when the record carries a
    ``watchdog_start_time``, reused by a later process) is dead. No pid at all
    (the spawn failed, or the owner died before noting it) counts as dead only
    once the heartbeat is older than STALE_NO_WATCHDOG_S. Anything else —
    a live pid, a malformed value, an unreadable start time — is "maybe
    alive": the backstop does nothing.
    """
    # pylint: disable=protected-access
    pid = rec.get("watchdog_pid")
    if pid is None:
        beat = rec.get("heartbeat")
        if not isinstance(beat, (int, float)) or isinstance(beat, bool):
            return False
        return time.time() - float(beat) > STALE_NO_WATCHDOG_S
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        return False
    if not mod._pid_alive(pid):
        return True
    want = rec.get("watchdog_start_time")
    if not want:
        return False
    lstart = mod._proc_lstart(pid)
    return lstart is not None and lstart != want


def _record_port(mod: ModuleType, rec: dict) -> int:
    """The CDP port a maintenance record's recovery must act on.

    The record's own ``port`` (the transaction writes it); for a record
    without one, the port of the instance whose cache dir holds it
    (`mod.DEFAULT_CDP_PORT`, derived exactly as browser.py does:
    $CLAUDE_BROWSER_CDP_PORT, else the instance's INSTANCE_PORTS entry).
    Never an implicit default: a non-default instance must not act on 9222.
    """
    port = rec.get("port")
    if isinstance(port, int) and not isinstance(port, bool) and 0 < port < 65536:
        return port
    return int(mod.DEFAULT_CDP_PORT)


def recover_stale_guided_login() -> str | None:
    """Backstop for a guided login whose owner AND its watchdog both died.

    Reads browser.py's maintenance record (the current instance's cache dir);
    when it is NOT live and its detached watchdog is certainly gone
    (`_watchdog_gone`), runs ``browser.py --cdp-port <port>
    maintenance-watchdog -n <prefix>`` against the record's port
    (`_record_port`) — the watchdog's own recovery (owned tabs closed, reap, headed reverted,
    record cleared, paused clients resumed) — bounded by the runner. Returns
    one ✅/❌ line, or None when there is nothing to do. A live record is
    never touched. The owner nonce is a token: it never appears in the
    output (the subprocess gets the same prefix the watchdog itself is
    started with, `WATCHDOG_NONCE_LEN`).
    """
    # pylint: disable=protected-access
    try:
        mod = _browser_module()
        rec = mod._read_json_dict(mod.MAINTENANCE_FILE)
        if rec is None:
            return None
        state = str(mod._headed_lease_state(rec))
        if state == "live" or not _watchdog_gone(mod, rec):
            return None
        prefix_len = int(mod.WATCHDOG_NONCE_LEN)
    except (RuntimeError, OSError):
        return None
    nonce = rec.get("owner_nonce")
    if not isinstance(nonce, str) or len(nonce) < 8:
        return None  # maintenance-watchdog refuses a short prefix anyway
    site = str(rec.get("site") or "?")
    budget = browser_timeout("maintenance-watchdog")
    run = run_browser(
        "--cdp-port",
        str(_record_port(mod, rec)),
        "maintenance-watchdog",
        "-n",
        nonce[:prefix_len],
        timeout_s=budget,
        quiet=True,
    )
    what = f"stale guided login for {site} (owner: {state}, watchdog gone)"
    problem = _recovery_problem(mod, run, nonce, budget)
    return (
        f"❌ {what}: {problem}" if problem else f"✅ recovered {what}: record cleared"
    )


def _recovery_problem(
    mod: ModuleType, run: BrowserRun, nonce: str, budget: float
) -> str | None:
    """Why the `maintenance-watchdog` run did not clear the record, or None."""
    if run.killed:
        return f"browser.py maintenance-watchdog killed after {budget:.0f} s"
    if run.rc != 0:
        return f"browser.py maintenance-watchdog exit {run.rc}"
    try:
        cur = mod._read_json_dict(mod.MAINTENANCE_FILE)  # pylint: disable=protected-access
    except OSError:
        cur = None
    if cur is not None and cur.get("owner_nonce") == nonce:
        return "the maintenance record is still in place"
    return None
