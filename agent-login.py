#!/usr/bin/env python3
"""agent-login.py — which of Albert's logins can agents use through the login broker?

Without arguments: a health line for the broker, the logins agents can use right now,
and the full list of logins we want to make work, each with its status and what is
missing. Read-only: it asks the broker for its site list (never a secret), reads the
names and expiry dates (never values) of Safari's cookies, and logs into nothing unless
you pass -t or -c.

The marketplace sites (anibis, tutti, Ricardo, Kleinanzeigen) run on YOUR Safari
session: you log in in Safari, `browser.py login SITE` copies that site's session
cookies into the shared Chromium (Kleinanzeigen falls back to the broker).

Examples:
  ./agent-login.py              # overview
  ./agent-login.py -t anibis    # real test: `browser.py login` (Safari session first,
                                # then the broker), then the positive logged-in check
  ./agent-login.py -c           # every usable site: logged in? if not, log in
  ./agent-login.py -c -m        # the same, and mail Albert when a site stays logged out
  ./agent-login.py -g anibis    # guided login typed by hand in the shared Chromium
  ./agent-login.py -P           # print the daily LaunchAgent (-I installs, -U removes)
  ./agent-login.py -j           # the same overview as JSON
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))  # the repo's `broker` package
# pylint: disable=wrong-import-position
from broker import safari_cookies  # noqa: E402
from broker.recipes import DEFAULT_CHECK_URLS  # noqa: E402

# pylint: enable=wrong-import-position

SOCKET = os.environ.get("LOGIN_BROKER_SOCKET", "/var/db/login-broker-run/broker.sock")
CODE_DIR = Path("/usr/local/libexec/login-broker/current")
BROWSER_PY = Path(__file__).resolve().parent / "bin" / "browser.py"
VAULT_URL = "https://vaultwarden.dom42.space"

# Login flows the broker's recipes can drive today.
SUPPORTED_FLOWS = {"one-page", "two-step", "cscs"}
# Albert's Safari session, copied by `browser.py login` (broker/safari_cookies.py).
SAFARI_FLOW = "safari"
MAIL_TO = "albert.glensk@gmail.com"
LAUNCH_LABEL = "com.albert.agent-login-check"
LAUNCH_PLIST = Path.home() / "Library" / "LaunchAgents" / f"{LAUNCH_LABEL}.plist"
LAUNCH_LOG = Path.home() / "Library" / "Logs" / f"{LAUNCH_LABEL}.log"
LAUNCH_HOUR, LAUNCH_MINUTE = 9, 15


@dataclass(frozen=True)
class Target:
    """A login we want agents to be able to use."""

    site: str  # broker site id (agent_site field, else the item name as a slug)
    name: str
    fill_origin: str  # value for the item's agent_fill_origins field ("" = unknown yet)
    flow: str  # one-page | two-step | cscs | safari | manual | unknown
    note: str = ""
    fallback: str = ""  # broker flow tried when the Safari session does not work


_SAFARI_NOTE = "log in in Safari now and then; agents copy that session"

TARGETS = (
    Target(
        "kleinanzeigen",
        "Kleinanzeigen",
        "https://login.kleinanzeigen.de",
        SAFARI_FLOW,
        _SAFARI_NOTE + " (broker logs in when Safari has none)",
        fallback="two-step",
    ),
    Target("anibis", "anibis", "https://auth.anibis.ch", SAFARI_FLOW, _SAFARI_NOTE),
    Target(
        "ricardo",
        "Ricardo",
        "https://login.ricardo.ch",
        SAFARI_FLOW,
        "Cloudflare blocks automated browsers: agents work in your Safari directly",
    ),
    Target("tutti", "tutti", "https://auth.tutti.ch", SAFARI_FLOW, _SAFARI_NOTE),
    Target("geizhals", "geizhals", "", "unknown", "login address not known yet"),
    Target(
        "cscs",
        "CSCS",
        "https://auth.cscs.ch",
        "cscs",
        "broker login (password + TOTP from Bitwarden; agent_otp_label picks the authenticator)",
    ),
)

# status -> (icon, label); order = how the overview sorts
STATUS = {
    "ready": ("✅", "ready"),
    "safari": ("🧭", "via your Safari session"),
    "manual": ("👤", "agents use YOUR session"),
    "needs-flow": ("🛠 ", "broker can't do this login yet"),
    "refused": ("⚠️ ", "in Bitwarden but refused"),
    "missing": ("➕", "not in Bitwarden agent-login yet"),
    "unknown": ("❓", "login address unknown"),
    "unchecked": ("⏸ ", "cannot check — broker can't read Bitwarden"),
    "extra": ("✅", "ready (not in the plan list)"),
}

USE = os.isatty(1) and not os.environ.get("NO_COLOR")


def _c(code: str, text: str) -> str:
    return f"\x1b[{code}m{text}\x1b[0m" if USE else text


def _link(url: str, text: str | None = None) -> str:
    """OSC 8 hyperlink (invisible where unsupported)."""
    return f"\x1b]8;;{url}\x1b\\{text or url}\x1b]8;;\x1b\\" if USE else (text or url)


def broker_request(op: str, timeout: float = 120.0, **kw: str) -> dict:
    """One JSON request to the broker; raises OSError/ValueError when unreachable."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        s.connect(SOCKET)
        s.sendall((json.dumps({"op": op, **kw}) + "\n").encode())
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
    data = json.loads(buf.decode() or "{}")
    if not isinstance(data, dict):
        raise ValueError("broker sent no JSON object")
    return data


def broker_state() -> tuple[str, list[dict]]:
    """(health message, broker site list); the list is empty when the broker is down."""
    if not CODE_DIR.exists():
        return "not installed — run: sudo install/install.sh", []
    if not os.path.exists(SOCKET):
        return f"installed but not running (no socket {SOCKET})", []
    try:
        resp = broker_request("sites")
    except (OSError, ValueError) as exc:
        return f"not reachable: {exc}", []
    if not resp.get("ok"):
        detail = resp.get("detail") or resp.get("error") or "unknown error"
        return f"running, but {detail}", []
    return "running, Bitwarden readable", list(resp.get("sites") or [])


def classify(
    target: Target, listed: dict[str, dict], *, readable: bool = True
) -> tuple[str, str]:
    """(status key, detail) for a planned target."""
    if not target.fill_origin:
        return "unknown", ""
    if not readable:
        return "unchecked", ""
    entry = listed.get(target.site)
    if entry is None:
        return "missing", f"add agent_fill_origins = {target.fill_origin}"
    return _classify_listed(target, entry)


def _classify_listed(target: Target, entry: dict) -> tuple[str, str]:
    """`classify` for a target the broker lists."""
    refused = entry.get("refused")
    reason = str(entry.get("reason") or refused)
    if target.flow == SAFARI_FLOW:
        # Listed at all = Albert's consent for the Safari import; a refused item
        # only rules out the broker fallback.
        if refused:
            return "safari", f"{target.note}; broker item refused: {reason}"
        return "safari", target.note
    if refused:
        return "refused", reason
    if target.flow == "manual":
        status = "manual"
    else:
        status = "ready" if target.flow in SUPPORTED_FLOWS else "needs-flow"
    return status, target.note


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


def overview() -> dict:
    """Everything the report shows, as data."""
    health, sites = broker_state()
    readable = health.startswith("running, Bitwarden")
    listed = {str(s.get("site")): s for s in sites}
    safari = safari_sessions([t.site for t in TARGETS if t.flow == SAFARI_FLOW])
    rows = []
    for t in TARGETS:
        status, detail = classify(t, listed, readable=readable)
        entry = listed.get(t.site) or {}
        check = str(entry.get("check_url") or DEFAULT_CHECK_URLS.get(t.site, ""))
        rows.append(
            {
                **asdict(t),
                "check_url": check,
                "status": status,
                "detail": detail,
                **safari.get(t.site, {}),
            }
        )
    planned = {t.site for t in TARGETS}
    for site, entry in sorted(listed.items()):
        if site in planned:
            continue
        refused = entry.get("refused")
        rows.append(
            {
                "site": site,
                "name": site,
                "fill_origin": ", ".join(entry.get("fill_origins") or []),
                "flow": "one-page",
                "note": "",
                "check_url": str(entry.get("check_url") or ""),
                "status": "refused" if refused else "extra",
                "detail": str(entry.get("reason") or "") if refused else "",
            }
        )
    return {
        "broker": health,
        "broker_ok": readable,
        "rows": rows,
    }


def safari_cell(row: dict) -> str:
    """The overview's Safari column: session held, and its latest expiry."""
    if row.get("flow") != SAFARI_FLOW:
        return ""
    if row.get("safari") is None:
        return "Safari: unreadable"
    if not row.get("safari"):
        return "Safari: no session"
    return f"Safari: until {row.get('safari_expires')}"


def print_overview(data: dict) -> None:
    """The human report."""
    rows = data["rows"]
    ok = data["broker_ok"]
    print(
        _c("1", "Agent logins")
        + "  (login broker → Bitwarden "
        + _link(VAULT_URL, "agent-login")
        + ")"
    )
    print(f"  broker: {'🟢' if ok else '🔴'} {data['broker']}\n")

    ready = [
        r
        for r in rows
        if r["status"] in ("ready", "extra")
        or (r["status"] == "safari" and r.get("safari"))
    ]
    print(_c("1", "Agents can use now"))
    if ready:
        for r in ready:
            where = (
                f"Safari session until {r['safari_expires']}"
                if r["status"] == "safari"
                else r["fill_origin"]
            )
            print(f"  ✅ {_c('1', r['name']):<24} {where}")
        print(_c("2", "     test one for real:  ./agent-login.py -t <site>"))
    else:
        print(_c("2", "  none yet"))
    print()

    order = list(STATUS)
    print(_c("1", "All planned logins"))
    width = max(len(r["name"]) for r in rows)
    for r in sorted(rows, key=lambda r: (order.index(r["status"]), r["name"].lower())):
        icon, label = STATUS[r["status"]]
        name = r["name"].ljust(width)
        line = f"  {icon} {_c('1', name)}  {safari_cell(r):<24}  {label}"
        if r["detail"]:
            line += _c("2", f" — {r['detail']}")
        print(line)
    print()
    print(
        _c(
            "2",
            "  ➕ add: move the item into the agent-login collection and add a custom text",
        )
    )
    print(_c("2", "     field agent_fill_origins with the address shown."))
    errors = {r.get("safari_error") for r in rows if r.get("safari_error")}
    for err in sorted(errors):
        print(
            _c("2", f"  🧭 Safari's cookies unreadable ({err}) — give the terminal ")
            + _c("2", "Full Disk Access.")
        )


def run_test(site: str) -> int:
    """Real end-to-end test: `browser.py login` (Safari session first for the
    SAFARI_SITES, else the login broker) → session in the shared Chromium → the
    client's POSITIVE check (check URL / sentinel, in a background tab).

    The verdict is the positive check, never the login command's exit code
    alone: a login that "succeeded" while the check page still redirects to the
    login page is reported as NOT logged in.
    """
    print(
        f"▶ browser.py login {site}  (Safari session or login broker; "
        "you see no password)"
    )
    login_rc = subprocess.run(
        [sys.executable, str(BROWSER_PY), "login", site], check=False
    ).returncode
    if login_rc != 0:
        print(f"❌ login {site} failed (exit {login_rc})")
    print(f"▶ browser.py logged-in {site}  (positive check on the check URL)")
    rc = subprocess.run(
        [sys.executable, str(BROWSER_PY), "logged-in", site], check=False
    ).returncode
    print(
        ("✅ " if rc == 0 else "❌ ")
        + f"{site}: shared Chromium is "
        + ("logged in" if rc == 0 else "NOT logged in")
        + " (positive check)"
    )
    return rc or login_rc


# Where a manual login starts (logged out, each redirects to its login page).
MANUAL_START = {
    "anibis": "https://www.anibis.ch/fr/user/searches",
    "tutti": "https://www.tutti.ch/de/myads/active",
    "ricardo": "https://www.ricardo.ch/de/my-ricardo/saved/articles/",
}
MANUAL_WAIT_S = 15 * 60


def _browser(*args: str, quiet: bool = False) -> int:
    """Run bin/browser.py with `args`; its exit code."""
    out = subprocess.DEVNULL if quiet else None
    return subprocess.run(
        [sys.executable, str(BROWSER_PY), *args], check=False, stdout=out, stderr=out
    ).returncode


def manual_login(site: str) -> int:
    """Guided manual login in the shared Chromium for sites behind a human check.

    Shows the Chromium window, opens the site's login, waits (up to 15 min) until
    the positive check passes, then hides the window again. You type the password
    yourself (paste it from Bitwarden) — no agent sees it; agents then use the
    session until the site expires it.
    """
    start = MANUAL_START.get(site)
    if not start:
        print(
            f"❌ no manual login known for {site!r} (known: {', '.join(MANUAL_START)})"
        )
        return 2
    if _browser("logged-in", site, quiet=True) == 0:
        print(f"✅ {site}: the shared Chromium is already logged in — nothing to do")
        return 0
    print("▶ showing the shared Chromium window …")
    if _browser("switch", "headed") != 0:
        return 1
    _browser("open", start, quiet=True)
    print(
        f"👤 In the Chromium window: tick 'I am human' if asked, enter your e-mail,\n"
        f"   paste the password from Bitwarden, finish the login. Waiting up to "
        f"{MANUAL_WAIT_S // 60} min …"
    )
    deadline = time.monotonic() + MANUAL_WAIT_S
    ok = False
    while time.monotonic() < deadline:
        time.sleep(10)
        if _browser("logged-in", site, quiet=True) == 0:
            ok = True
            break
    print("▶ hiding the Chromium window again …")
    _browser("switch", "headless", quiet=True)
    print(
        f"✅ {site}: logged in — agents can use this session"
        if ok
        else f"❌ {site}: still not logged in after {MANUAL_WAIT_S // 60} min"
    )
    return 0 if ok else 2


def ensure_logged_in(site: str) -> tuple[bool, str]:
    """(logged in?, how) — positive check, else `browser.py login`, then re-check."""
    if _browser("logged-in", site, quiet=True) == 0:
        return True, "logged in"
    res = subprocess.run(
        [sys.executable, str(BROWSER_PY), "login", site],
        check=False,
        capture_output=True,
        text=True,
    )
    routes = [
        line.split("route:", 1)[1].strip()
        for line in res.stdout.splitlines()
        if "route:" in line
    ]
    if _browser("logged-in", site, quiet=True) == 0:
        return True, f"logged in again ({routes[-1] if routes else 'browser.py login'})"
    return False, f"NOT logged in (browser.py login exit {res.returncode})"


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


def failure_mail(failed: list[tuple[str, str]]) -> tuple[str, str]:
    """(subject, body) of the one mail for sites that stay logged out."""
    subject = f"agent-login: {len(failed)} site(s) not logged in"
    lines = [
        "The daily agent-login check found sites the shared Chromium is NOT "
        "logged into, even after `browser.py login`:",
        "",
    ]
    lines += [f"- {site}: {how}" for site, how in failed]
    lines += ["", "Fix, per site:"]
    lines += [f"- {site}: {safari_fix(site)}" for site, _how in failed]
    return subject, "\n".join(lines) + "\n"


def safari_fix(site: str) -> str:
    """What Albert does when `site` is logged out."""
    return (
        f"open the site in Safari and log in, then run ./agent-login.py -t {site} "
        f"(in {Path(__file__).resolve().parent})"
    )


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


def check_all(*, mail: bool = False) -> int:
    """Every usable site (Safari or broker): logged in? If not, log in. One line
    per site; exit 1 if any stays logged out (and, with `mail`, ONE mail).
    Waits for the network first; still offline after 5 min = skip quietly."""
    if not wait_for_network():
        print(f"⏸  no network ({NETWORK_HOST} does not resolve) — skipped, no mail")
        return 0
    data = overview()
    failed: list[tuple[str, str]] = []
    if not data["broker_ok"]:
        print(f"❌ login broker: {data['broker']}")
        failed.append(("login broker", data["broker"]))
    for row in data["rows"]:
        if row["status"] not in ("ready", "extra", "safari"):
            continue
        rule = safari_cookies.SAFARI_SITES.get(row["site"])
        if rule is not None and not rule.auto:
            print(f"⏭  {row['site']}: not imported unattended (see SAFARI_SITES)")
            continue
        ok, how = ensure_logged_in(row["site"])
        print(f"{'✅' if ok else '❌'} {row['site']}: {how}")
        if not ok:
            failed.append((row["site"], how))
    if failed and mail:
        send_mail(*failure_mail(failed))
    return 1 if failed else 0


def launchagent_plist() -> str:
    """The daily LaunchAgent (`agent-login.py -c -m` at 09:15), as text. Pure."""
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
    <string>{LAUNCH_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/bin/env</string>
        <string>python3</string>
        <string>{Path(__file__).resolve()}</string>
        <string>-c</string>
        <string>-m</string>
    </array>
    <key>StartCalendarInterval</key>
    <dict>
        <key>Hour</key>
        <integer>{LAUNCH_HOUR}</integer>
        <key>Minute</key>
        <integer>{LAUNCH_MINUTE}</integer>
    </dict>
    <key>StandardOutPath</key>
    <string>{LAUNCH_LOG}</string>
    <key>StandardErrorPath</key>
    <string>{LAUNCH_LOG}</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>{search_path}</string>
    </dict>
    <key>RunAtLoad</key>
    <false/>
</dict>
</plist>
"""


def _bootout() -> None:
    subprocess.run(
        ["launchctl", "bootout", f"gui/{os.getuid()}/{LAUNCH_LABEL}"],
        check=False,
        capture_output=True,
    )


def install_daily() -> int:
    """Write + (re)load the LaunchAgent."""
    LAUNCH_PLIST.parent.mkdir(parents=True, exist_ok=True)
    LAUNCH_PLIST.write_text(launchagent_plist(), encoding="utf-8")
    _bootout()
    rc = subprocess.run(
        ["launchctl", "bootstrap", f"gui/{os.getuid()}", str(LAUNCH_PLIST)],
        check=False,
    ).returncode
    if rc != 0:
        print(f"❌ launchctl bootstrap {LAUNCH_PLIST} failed (exit {rc})")
        return 1
    print(
        f"✅ installed {LAUNCH_LABEL} (daily {LAUNCH_HOUR:02d}:{LAUNCH_MINUTE:02d}, "
        f"-c -m; log {LAUNCH_LOG})"
    )
    return 0


def uninstall_daily() -> int:
    """Unload + remove the LaunchAgent."""
    _bootout()
    LAUNCH_PLIST.unlink(missing_ok=True)
    print(f"removed {LAUNCH_LABEL}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    """The CLI."""
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("-t", "--test", metavar="SITE", help="real login test for SITE")
    ap.add_argument(
        "-g",
        "--guided",
        metavar="SITE",
        help="guided login typed by hand in the shared Chromium window",
    )
    ap.add_argument(
        "-c",
        "--check-all",
        action="store_true",
        help="every usable site: logged in? if not, `browser.py login`; one line "
        "per site, exit 1 if any stays logged out",
    )
    ap.add_argument(
        "-m",
        "-M",
        "--mail",
        action="store_true",
        help=f"with -c: mail {MAIL_TO} (gog) when a site stays logged out",
    )
    ap.add_argument(
        "-I",
        "--install-daily",
        action="store_true",
        help=f"install + load the LaunchAgent {LAUNCH_LABEL} "
        f"(`-c -m` daily {LAUNCH_HOUR:02d}:{LAUNCH_MINUTE:02d})",
    )
    ap.add_argument(
        "-U",
        "--uninstall-daily",
        action="store_true",
        help="unload + remove that LaunchAgent",
    )
    ap.add_argument(
        "-P",
        "--print-plist",
        action="store_true",
        help="print the LaunchAgent plist (writes nothing)",
    )
    ap.add_argument(
        "-j", "--json", action="store_true", help="print the overview as JSON"
    )
    return ap


def launch_action(args: argparse.Namespace) -> int | None:
    """-P / -I / -U, or None when none was asked for."""
    if args.print_plist:
        print(launchagent_plist(), end="")
        return 0
    if args.install_daily:
        return install_daily()
    if args.uninstall_daily:
        return uninstall_daily()
    return None


def login_action(args: argparse.Namespace) -> int | None:
    """-t / -g / -c, or None when none was asked for."""
    if args.test:
        return run_test(args.test)
    if args.guided:
        return manual_login(args.guided)
    if args.check_all:
        return check_all(mail=args.mail)
    return None


def main() -> int:
    """CLI entry point."""
    ap = build_parser()
    args = ap.parse_args()
    if args.mail and not args.check_all:
        ap.error("-m/--mail only works together with -c/--check-all")
    rc = launch_action(args)
    if rc is None:
        rc = login_action(args)
    if rc is not None:
        return rc
    data = overview()
    if args.json:
        print(json.dumps(data, indent=1))
    else:
        print_overview(data)
    return 0 if data["broker_ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
