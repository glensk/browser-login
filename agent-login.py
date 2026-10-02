#!/usr/bin/env python3
"""agent-login.py — which of Albert's logins can agents use through the login broker?

Without arguments: a health line for the broker, the logins agents can use right now,
and the full list of logins we want to make work, each with its status and what is
missing. Read-only: it asks the broker for its site list (never a secret) and logs into
nothing unless you pass -t.

Examples:
  ./agent-login.py              # overview
  ./agent-login.py -t kleinanzeigen   # real test: broker logs in, session lands in the
                                      # shared Chromium, then the logged-in check
  ./agent-login.py -m anibis    # guided manual login (sites with an 'are you human' box)
  ./agent-login.py -j           # the same overview as JSON
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))  # the repo's `broker` package
# pylint: disable-next=wrong-import-position
from broker.recipes import DEFAULT_CHECK_URLS  # noqa: E402

SOCKET = os.environ.get("LOGIN_BROKER_SOCKET", "/var/db/login-broker-run/broker.sock")
CODE_DIR = Path("/usr/local/libexec/login-broker/current")
BROWSER_PY = Path(__file__).resolve().parent / "bin" / "browser.py"
VAULT_URL = "https://vaultwarden.dom42.space"

# Login flows the broker's recipes can drive today.
SUPPORTED_FLOWS = {"one-page", "two-step", "cscs"}


@dataclass(frozen=True)
class Target:
    """A login we want agents to be able to use."""

    site: str  # broker site id (agent_site field, else the item name as a slug)
    name: str
    fill_origin: str  # value for the item's agent_fill_origins field ("" = unknown yet)
    flow: str  # one-page | two-step | cscs | manual | unknown
    note: str = ""


TARGETS = (
    Target(
        "kleinanzeigen", "Kleinanzeigen", "https://login.kleinanzeigen.de", "two-step"
    ),
    Target(
        "anibis",
        "anibis",
        "https://auth.anibis.ch",
        "manual",
        "Cloudflare 'are you human' box at login: log in by hand now and then (-m)",
    ),
    Target(
        "ricardo",
        "Ricardo",
        "https://login.ricardo.ch",
        "manual",
        "Cloudflare 'are you human' box at login: log in by hand now and then (-m)",
    ),
    Target(
        "tutti",
        "tutti",
        "https://auth.tutti.ch",
        "manual",
        "Cloudflare 'are you human' box at login: log in by hand now and then (-m)",
    ),
    Target("geizhals", "geizhals", "", "unknown", "login address not known yet"),
    Target(
        "cscs",
        "CSCS",
        "https://auth.cscs.ch",
        "cscs",
        "first rotate the CSCS password + 2FA",
    ),
)

# status -> (icon, label); order = how the overview sorts
STATUS = {
    "ready": ("✅", "ready"),
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
    if entry.get("refused"):
        return "refused", str(entry.get("reason") or entry.get("refused"))
    if target.flow == "manual":
        status = "manual"
    else:
        status = "ready" if target.flow in SUPPORTED_FLOWS else "needs-flow"
    return status, target.note


def overview() -> dict:
    """Everything the report shows, as data."""
    health, sites = broker_state()
    readable = health.startswith("running, Bitwarden")
    listed = {str(s.get("site")): s for s in sites}
    rows = []
    for t in TARGETS:
        status, detail = classify(t, listed, readable=readable)
        entry = listed.get(t.site) or {}
        check = str(entry.get("check_url") or DEFAULT_CHECK_URLS.get(t.site, ""))
        rows.append(
            {**asdict(t), "check_url": check, "status": status, "detail": detail}
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

    ready = [r for r in rows if r["status"] in ("ready", "extra")]
    print(_c("1", "Agents can use now"))
    if ready:
        for r in ready:
            print(f"  ✅ {_c('1', r['name']):<24} {r['fill_origin']}")
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
        line = f"  {icon} {_c('1', name)}  {label}"
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


def run_test(site: str) -> int:
    """Real end-to-end test: broker login → session in the shared Chromium → the
    client's POSITIVE check (check URL / sentinel, in a background tab).

    The verdict is the positive check, never the login command's exit code
    alone: a login that "succeeded" while the check page still redirects to the
    login page is reported as NOT logged in.
    """
    print(f"▶ browser.py login {site}  (the broker logs in; you see no password)")
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


def main() -> int:
    """CLI entry point."""
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("-t", "--test", metavar="SITE", help="real login test for SITE")
    ap.add_argument(
        "-m",
        "--manual",
        metavar="SITE",
        help="guided manual login in the shared Chromium (sites behind a human check)",
    )
    ap.add_argument(
        "-j", "--json", action="store_true", help="print the overview as JSON"
    )
    args = ap.parse_args()
    if args.test:
        return run_test(args.test)
    if args.manual:
        return manual_login(args.manual)
    data = overview()
    if args.json:
        print(json.dumps(data, indent=1))
    else:
        print_overview(data)
    return 0 if data["broker_ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
