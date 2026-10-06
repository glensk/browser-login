"""Helpers of agent-login.py: LaunchAgents, mail, network wait, Safari sessions,
the shared Chromium's window mode."""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

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


def _browser(*args: str, quiet: bool = False) -> int:
    """Run bin/browser.py with `args`; its exit code."""
    out = subprocess.DEVNULL if quiet else None
    return subprocess.run(
        [sys.executable, str(BROWSER_PY), *args], check=False, stdout=out, stderr=out
    ).returncode


def browser_mode() -> str | None:
    """ "headless" / "headed" for the running shared Chromium, None when down."""
    res = subprocess.run(
        [sys.executable, str(BROWSER_PY), "status"],
        check=False,
        capture_output=True,
        text=True,
    )
    first = (res.stdout.splitlines() or [""])[0]
    if not first.startswith("✓ Up"):
        return None
    return "headless" if "(headless)" in first else "headed"


def show_window() -> str | None:
    """Switch the shared Chromium to headed; the mode to go back to (or None)."""
    before = browser_mode()
    print("▶ showing the shared Chromium window …")
    if _browser("switch", "headed") != 0:
        raise RuntimeError("browser.py switch headed failed")
    return before


def restore_mode(before: str | None) -> None:
    """Back to headless only when the browser WAS headless before -g."""
    if before == "headless":
        print("▶ hiding the Chromium window again …")
        _browser("switch", "headless", quiet=True)
