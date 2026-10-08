#!/usr/bin/env python3
"""agent-login.py — which of Albert's logins can agents use through the login broker?

Without arguments: a health line for the broker, then every login we want agents to
use, once: ✅ when it works for agents (setup complete AND the latest real check, -c/-t,
passed) or ❌ with the reason. Read-only: it asks the broker for its site list (never a
secret), reads the names and expiry dates (never values) of Safari's cookies, and logs
into nothing unless you pass -t, -g or -c.

The marketplace sites (anibis, tutti, Ricardo, Kleinanzeigen) run on YOUR Safari
session: you log in in Safari, `browser.py login SITE` copies that site's session
cookies into the shared Chromium (Kleinanzeigen falls back to the broker). CSCS and
Smartsheet log in through the broker. SWITCH Cloud logs in with the broker's edu-ID
session plus the portal's SSO click (no window; your own login only when the broker has
no usable `eduid` item). Anthropic, OpenAI and Slack need you once (email code / SSO):
`-g SITE` shows the window and waits; -t and -c only check them.

Examples:
  ./agent-login.py              # overview
  ./agent-login.py -t anibis    # real test: `browser.py login` (Safari session first,
                                # then the broker), then the positive logged-in check
  ./agent-login.py -c           # every usable site: logged in? if not, log in
  ./agent-login.py -c -m        # the same, and mail Albert when a site stays logged out
  ./agent-login.py -t https://auth.cscs.ch   # SITE may also be a name or login address
  ./agent-login.py -g anibis    # guided login typed by hand in the shared Chromium
  ./agent-login.py -g anthropic # your login (email code) in the shown shared Chromium
  ./agent-login.py -P           # print the daily LaunchAgent (-I installs, -U removes)
  ./agent-login.py -j           # the same overview as JSON
"""

from __future__ import annotations

# One CLI over the whole login table (status, tests, guided logins, jobs);
# helpers already live in the agent_login_* modules.
# pylint: disable=too-many-lines
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
# pylint: disable=wrong-import-position
import agent_login_keychain  # noqa: E402
import agent_login_secrets  # noqa: E402
from agent_login_claude import (  # noqa: E402
    CLAUDE_ACCOUNTS,
    SITE_INSTANCE,
    browser_site,
    claude_account_email,
    claude_login_by_hand,
    site_instance,
)
from agent_login_jobs import (  # noqa: E402
    LAUNCH_HOUR,
    LAUNCH_LABEL,
    LAUNCH_MINUTE,
    MAIL_TO,
    NETWORK_HOST,
    SNAPSHOT_INTERVAL_S,
    SNAPSHOT_LABEL,
    _browser,
    browser_mode,
    install_daily,
    launchagent_plist,
    restore_mode,
    safari_sessions,
    send_mail,
    show_window,
    snapshot_plist,
    uninstall_daily,
    wait_for_network,
)
from broker import safari_cookies  # noqa: E402
from broker.recipes import DEFAULT_CHECK_URLS  # noqa: E402

# pylint: enable=wrong-import-position

SOCKET = os.environ.get("LOGIN_BROKER_SOCKET", "/var/db/login-broker-run/broker.sock")
CODE_DIR = Path("/usr/local/libexec/login-broker/current")
BROWSER_PY = Path(__file__).resolve().parent / "bin" / "browser.py"
VAULT_URL = "https://vaultwarden.dom42.space"

# Login flows the broker's recipes can drive today.
SUPPORTED_FLOWS = {"one-page", "two-step", "cscs", "smartsheet", "eduid-sso"}
# browser.py site whose login is the broker's `eduid` item (an edu-ID IdP session)
# followed by the site's own SSO click in a background tab — no window needed.
# Without a usable broker `eduid` item it is an ASSISTED login (your session).
EDUID_SSO_FLOW = "eduid-sso"
# Albert's Safari session, copied by `browser.py login` (broker/safari_cookies.py).
SAFARI_FLOW = "safari"
# Built-in browser.py sites whose login needs Albert (email code, SSO click): agents
# use the session he leaves in the shared Chromium; the check never logs in.
ASSISTED_FLOW = "assisted"


@dataclass(frozen=True)
class Target:
    """A login we want agents to be able to use."""

    site: str  # broker site id (agent_site field, else the item name as a slug)
    name: str
    fill_origin: str  # value for the item's agent_fill_origins field ("" = unknown yet)
    # one-page | two-step | cscs | smartsheet | eduid-sso | safari | assisted | manual
    # | unknown
    flow: str
    note: str = ""
    fallback: str = ""  # broker flow tried when the Safari session does not work
    broker_site: str = ""  # broker item the login runs through when it is not `site`


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
    Target(
        "cscs",
        "CSCS",
        "https://auth.cscs.ch",
        "cscs",
        "broker login (password + TOTP from Bitwarden; agent_otp_label picks the authenticator)",
    ),
    Target(
        "smartsheet",
        "Smartsheet",
        "https://app.smartsheet.com",
        "smartsheet",
        "broker login (e-mail + password wizard from Bitwarden; consumer: "
        "sdsc/smartsheet-api)",
    ),
    Target(
        "anthropic",
        "Anthropic work",
        "https://claude.ai",
        ASSISTED_FLOW,
        "claude.ai work account (SDSC Team admin): ./agent-login.py -g anthropic",
    ),
    Target(
        "anthropic-private",
        "Anthropic private",
        "https://claude.ai",
        ASSISTED_FLOW,
        "claude.ai private account, own browser instance "
        "(CLAUDE_BROWSER_INSTANCE=private, CDP 9223): ./agent-login.py -g "
        "anthropic-private",
    ),
    Target(
        "openai",
        "OpenAI",
        "https://chatgpt.com",
        ASSISTED_FLOW,
        "chatgpt.com Business admin: log in with ./agent-login.py -g openai (Google SSO)",
    ),
    Target(
        "slack",
        "Slack",
        "https://app.slack.com",
        ASSISTED_FLOW,
        "SDSC Slack: log in with ./agent-login.py -g slack",
    ),
    Target(
        "switch",
        "SWITCH Cloud",
        "https://cloud.switch.ch",
        EDUID_SSO_FLOW,
        "Switch Cloud Portal: broker edu-ID session + SSO click (no window); "
        "your own login: ./agent-login.py -g switch",
        broker_site="eduid",
    ),
)

# status -> (icon, label); order = how the overview sorts
STATUS = {
    "ready": ("✅", "ready"),
    "safari": ("🧭", "via your Safari session"),
    "assisted": ("👤", "your login in the shared Chromium"),
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


STATE_DIR = Path.home() / ".local/state/agent-login"
SITES_SNAPSHOT_MAX_AGE_S = 30 * 60  # the snapshot job refreshes every 10 min


def _state_path(name: str) -> Path:
    """A file in the state dir ($AGENT_LOGIN_STATE_FILE's dir in tests)."""
    env = os.environ.get("AGENT_LOGIN_STATE_FILE")
    return (Path(env).parent if env else STATE_DIR) / name


def _write_json_atomic(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=1), encoding="utf-8")
    tmp.replace(path)


def broker_state(*, fresh: bool = False) -> tuple[str, list[dict]]:
    """(health message, broker site list) — from the snapshot when it is recent.

    The broker's `sites` answer costs a Bitwarden unlock (~30-40 s when its own
    cache is cold), so the overview reads the snapshot that `-S` (every 10 min,
    LaunchAgent) writes; `fresh` asks the broker and re-reads Bitwarden.
    """
    snap = _state_path("sites.json")
    if not fresh:
        try:
            data = json.loads(snap.read_text(encoding="utf-8"))
            age = time.time() - float(data["at"])
            if 0 <= age < SITES_SNAPSHOT_MAX_AGE_S and os.path.exists(SOCKET):
                return str(data["health"]), list(data["sites"])
        except (OSError, ValueError, KeyError, TypeError):
            pass
    health, sites = _broker_state_live(fresh=fresh)
    if health.startswith("running, Bitwarden"):
        _write_json_atomic(snap, {"at": time.time(), "health": health, "sites": sites})
    return health, sites


def _broker_state_live(*, fresh: bool) -> tuple[str, list[dict]]:
    """(health message, broker site list); the list is empty when the broker is down."""
    if not CODE_DIR.exists():
        return "not installed — run: sudo install/install.sh", []
    if not os.path.exists(SOCKET):
        return f"installed but not running (no socket {SOCKET})", []
    try:
        resp = broker_request("sites", fresh="1") if fresh else broker_request("sites")
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
    if target.flow == ASSISTED_FLOW:  # browser.py built-in, no broker involved
        return "assisted", target.note
    if target.flow == EDUID_SSO_FLOW:
        return _classify_eduid_sso(target, listed, readable=readable)
    if not readable:
        return "unchecked", ""
    entry = listed.get(target.site)
    if entry is None:
        return "missing", f"add agent_fill_origins = {target.fill_origin}"
    return _classify_listed(target, entry)


def _classify_eduid_sso(
    target: Target, listed: dict[str, dict], *, readable: bool
) -> tuple[str, str]:
    """`classify` for an eduid-sso target: ready with a usable broker item,
    else assisted (`browser.py login` falls back to the window flow)."""
    entry = listed.get(target.broker_site) if readable else None
    if entry is None or entry.get("refused"):
        return "assisted", (
            f"no usable broker item {target.broker_site!r} — your own login: "
            f"./agent-login.py -g {target.site}"
        )
    return "ready", target.note


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


def safari_state(sites: list[str]) -> dict[str, dict]:
    """`safari_sessions`, falling back to the last readable state.

    The 10-min LaunchAgent has no Full Disk Access, so Safari's cookie file is
    unreadable there; the names/expiry dates an interactive run read stay valid
    (the verdict checks the expiry date itself).
    """
    snap = _state_path("safari.json")
    now = safari_sessions(sites)
    if all(v.get("safari") is not None for v in now.values()):
        _write_json_atomic(snap, now)
        return now
    try:
        old = json.loads(snap.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return now
    return {
        s: old[s] if v.get("safari") is None and isinstance(old.get(s), dict) else v
        for s, v in now.items()
    }


def overview(*, fresh: bool = False) -> dict:
    """Everything the report shows, as data."""
    health, sites = broker_state(fresh=fresh)
    readable = health.startswith("running, Bitwarden")
    listed = {str(s.get("site")): s for s in sites}
    safari = safari_state([t.site for t in TARGETS if t.flow == SAFARI_FLOW])
    rows = []
    for t in TARGETS:
        status, detail = classify(t, listed, readable=readable)
        entry = listed.get(t.site) or {}
        check = str(entry.get("check_url") or DEFAULT_CHECK_URLS.get(t.site, ""))
        if t.broker_site:  # Bitwarden holds the broker item, not the site
            entry = listed.get(t.broker_site) or {}
        rows.append(
            {
                **asdict(t),
                "check_url": check,
                "status": status,
                "detail": detail,
                "in_bitwarden": bool(entry.get("fill_origins")),
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
                "in_bitwarden": bool(entry.get("fill_origins")),
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


LAST_CHECK_FILE = Path.home() / ".local/state/agent-login/last-check.json"


def _state_file() -> Path:
    """LAST_CHECK_FILE, or $AGENT_LOGIN_STATE_FILE (tests point it at a temp dir)."""
    env = os.environ.get("AGENT_LOGIN_STATE_FILE")
    return Path(env) if env else LAST_CHECK_FILE


AGENTS_FILE_NAME = "agents.md"
# How each kind of login is used by an agent (the summary's ✅ lines).
_HOW_TO_USE = {
    "safari": "Albert's Safari session",
    "ready": "login broker",
    "extra": "login broker",
    "assisted": "Albert's session in the shared Chromium",
}


def agent_summary(data: dict, checks: dict[str, dict]) -> str:
    """The short Markdown every agent session gets at start (SessionStart hook)."""
    ok_lines, bad_lines = [], []
    for row in sorted(data["rows"], key=lambda r: r["name"].lower()):
        works, why = verdict(row, checks)
        if works:
            how = _HOW_TO_USE.get(row["status"], row["status"])
            detail = str((checks.get(row["site"]) or {}).get("how") or "")
            if detail.startswith("logged in as"):
                how += f", {detail[len('logged in as ') :]}"
            inst = SITE_INSTANCE.get(row["site"])
            if inst:
                how += (
                    f" — its own browser (CDP 127.0.0.1:9223), stopped when idle: "
                    f"`CLAUDE_BROWSER_INSTANCE={inst} browser.py up -H` first, "
                    "`… down` when done; every browser.py call needs that prefix"
                )
            ok_lines.append(
                f"- ✅ {row['name']} (`{browser_site(row['site'])}`): {how}"
            )
        else:
            bad_lines.append(f"- ❌ {row['name']}: {why}")
    here = Path(__file__).resolve().parent
    out = [
        f"## Web logins agents can use (agent-login.py, {time.strftime('%Y-%m-%d %H:%M')})",
        "",
        "The shared logged-in Chromium (CDP http://127.0.0.1:9222; `browser.py`, "
        "Playwright MCP `browser_*` tools) holds these sessions. Before using a "
        "site: `browser.py logged-in <site>`. If it fails: for broker/Safari sites "
        "run `browser.py login <site>` (never asks for a password); for sites on "
        "Albert's session do NOT start a login — ask Albert to run "
        "`agent-login.py -g <site>`. Never ask Albert for passwords.",
        "",
        *ok_lines,
        *bad_lines,
        *agent_login_secrets.summary_lines(data.get("secrets") or []),
        "",
        f"Full status: `{here}/agent-login.py` (❌ items need Albert unless noted).",
    ]
    if not data.get("broker_ok"):
        out.insert(2, f"⚠️ login broker: {data.get('broker')}\n")
    return "\n".join(out) + "\n"


def write_agent_summary(data: dict | None = None) -> Path:
    """(Re)write the agents file from the overview (the snapshot, no logins)."""
    data = data or overview()
    path = _state_path(AGENTS_FILE_NAME)
    path.parent.mkdir(parents=True, exist_ok=True)
    if "secrets" not in data:  # the -S snapshot's list; never a broker call here
        data = {**data, "secrets": agent_login_secrets.snapshot_secrets(path.parent)}
    tmp = path.with_suffix(".tmp")
    tmp.write_text(agent_summary(data, last_checks()), encoding="utf-8")
    tmp.replace(path)
    return path


def record_check(site: str, ok: bool, how: str, path: Path | None = None) -> None:
    """Remember a site's latest REAL check (what the overview shows)."""
    path = path or _state_file()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        data = {}
    data[site] = {"ok": ok, "how": how, "at": time.strftime("%Y-%m-%d %H:%M")}
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=1), encoding="utf-8")
    tmp.replace(path)


def last_checks(path: Path | None = None) -> dict[str, dict]:
    """``{site: {"ok", "how", "at"}}`` from the last check runs (empty if none)."""
    try:
        data = json.loads((path or _state_file()).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def check_cell(site: str, checks: dict[str, dict]) -> str:
    """'✅ 2026-10-04 21:15' / '❌ …' / 'not checked yet'."""
    c = checks.get(site)
    if not c:
        return "not checked yet"
    return f"{'✅' if c.get('ok') else '❌'} {c.get('at', '?')}"


# Setup problems: the site cannot work for agents whatever the last check said.
_SETUP_REASON = {
    "unknown": "no Vaultwarden item / login address yet",
    "missing": "not in the Bitwarden agent-login collection",
    "refused": "Bitwarden item refused",
    "needs-flow": "the broker cannot do this login flow yet",
    "unchecked": "broker cannot read Bitwarden",
}


def _setup_problem(row: dict) -> str | None:
    """Why a login cannot work whatever its last check said, or None."""
    status = row["status"]
    if status in _SETUP_REASON:
        detail = f" ({row['detail']})" if row.get("detail") else ""
        return _SETUP_REASON[status] + detail
    if status != "safari" or row.get("fallback"):
        return None
    expires = row.get("safari_expires")
    problem = None
    if row.get("safari") is None:
        problem = "Safari's cookies unreadable (terminal needs Full Disk Access)"
    elif not row.get("safari"):
        problem = f"no Safari session — log in to {row['name']} in Safari"
    elif expires and expires < time.strftime("%Y-%m-%d"):
        problem = f"Safari session expired {expires} — log in in Safari"
    return problem


def verdict(row: dict, checks: dict[str, dict]) -> tuple[bool, str]:
    """(works for agents?, reason/detail) — one answer per login.

    ✅ only when the setup is complete AND the latest REAL check (``-c``/``-t``)
    passed; everything else is ❌ with the first thing that is wrong.
    """
    problem = _setup_problem(row)
    c = checks.get(row["site"])
    if problem or not c or not c.get("ok"):
        if problem:
            return False, problem
        if not c:
            return False, f"not checked yet — ./agent-login.py -t {row['site']}"
        return False, f"last check {c.get('at', '?')}: {c.get('how', 'failed')}"
    how = f"checked {c.get('at', '?')}"
    if row["status"] == "safari" and row.get("safari"):
        how += f", Safari session until {row.get('safari_expires')}"
    elif row.get("flow") == ASSISTED_FLOW or row["status"] == "assisted":
        detail = str(c.get("how") or "")
        how += f", {detail}" if detail.startswith("logged in as") else ", your session"
    else:
        how += ", login broker"
    return True, how


def print_overview(data: dict) -> None:
    """The human report: every login once, ✅ works for agents / ❌ + why."""
    rows = data["rows"]
    ok = data["broker_ok"]
    print(
        _c("1", "Agent logins")
        + "  (login broker → Bitwarden "
        + _link(VAULT_URL, "agent-login")
        + ")"
    )
    print(f"  broker: {'🟢' if ok else '🔴'} {data['broker']}\n")
    checks = last_checks()
    judged = [(r, *verdict(r, checks)) for r in rows]
    judged.sort(key=lambda x: (not x[1], x[0]["name"].lower()))
    width = max(len(r["name"]) for r in rows)
    col = "agent_fill_origins"
    print(_c("2", f"     {'login'.ljust(width)}  {col}  status"))
    for r, works, why in judged:
        bw = str(bool(r.get("in_bitwarden"))).ljust(len(col))
        line = f"  {'✅' if works else '❌'} {_c('1', r['name'].ljust(width))}  {bw}  "
        print(line + (_c("2", why) if works else why))
    print()
    print(
        _c(
            "2",
            "  re-check all: ./agent-login.py -c  ·  one site: -t <site>  ·  "
            "your own login: -g <site>",
        )
    )
    print(
        _c(
            "2",
            "  add a site: move its item into the agent-login collection and add a "
            "custom text field agent_fill_origins",
        )
    )


def resolve_site(arg: str) -> str:
    """A site id from an id, a display name or a login address (``https://…``)."""
    key = arg.strip().lower().rstrip("/")
    for t in TARGETS:
        if key in (t.site, t.name.lower(), t.fill_origin.lower()):
            return t.site
    return arg


def _eduid_sso_assisted(site: str) -> bool:
    """True for an eduid-sso site the broker cannot log in right now (its broker
    item missing, refused or Bitwarden unreadable): `-t` then only checks."""
    target = next((t for t in TARGETS if t.site == site), None)
    if target is None or target.flow != EDUID_SSO_FLOW:
        return False
    health, sites = broker_state()
    listed = {str(s.get("site")): s for s in sites}
    readable = health.startswith("running, Bitwarden")
    return classify(target, listed, readable=readable)[0] == "assisted"


def run_test(site: str) -> int:
    """Real end-to-end test: `browser.py login` (Safari session first for the
    SAFARI_SITES, else the login broker) → session in the shared Chromium → the
    client's POSITIVE check (check URL / sentinel, in a background tab).

    The verdict is the positive check, never the login command's exit code
    alone: a login that "succeeded" while the check page still redirects to the
    login page is reported as NOT logged in. The result is recorded for the overview.
    """
    site = resolve_site(site)
    if site in ASSISTED_SITES or _eduid_sso_assisted(site):
        # its login needs you: -g; -t only checks
        print(f"▶ {site}: your own login (./agent-login.py -g {site}); checking only")
        ok, how = assisted_check(site)
        record_check(site, ok, how)
        print(f"{'✅' if ok else '❌'} {site}: {how}")
        return 0 if ok else 2
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
    if rc == 0:
        how = "logged in"
    else:
        how = f"NOT logged in (browser.py login exit {login_rc}, check exit {rc})"
    record_check(site, rc == 0, how)
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


def manual_login(site: str) -> int:
    """Guided manual login in the shared Chromium for sites behind a human check.

    Shows the Chromium window, opens the site's login, waits (up to 15 min) until
    the positive check passes, then hides the window again. You type the password
    yourself (paste it from Bitwarden) — no agent sees it; agents then use the
    session until the site expires it.
    """
    site = resolve_site(site)
    if site in ASSISTED_SITES or site in EDUID_SSO_SITES:
        return assisted_login(site)
    start = MANUAL_START.get(site)
    if not start:
        known = ", ".join([*MANUAL_START, *sorted(ASSISTED_SITES | EDUID_SSO_SITES)])
        print(f"❌ no guided login known for {site!r} (known: {known})")
        return 2
    if _browser("logged-in", site, quiet=True) == 0:
        print(f"✅ {site}: the shared Chromium is already logged in — nothing to do")
        return 0
    try:
        before = show_window()
    except RuntimeError:
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
    restore_mode(before)
    print(
        f"✅ {site}: logged in — agents can use this session"
        if ok
        else f"❌ {site}: still not logged in after {MANUAL_WAIT_S // 60} min"
    )
    return 0 if ok else 2


ASSISTED_SITES = {t.site for t in TARGETS if t.flow == ASSISTED_FLOW}
# -g works for these too: `browser.py login` with the window shown.
EDUID_SSO_SITES = {t.site for t in TARGETS if t.flow == EDUID_SSO_FLOW}


def assisted_check(site: str) -> tuple[bool, str]:
    """(works?, how) for a site you log into yourself; never starts a login."""
    with site_instance(site):
        return _assisted_check(site)


def _assisted_check(site: str) -> tuple[bool, str]:
    hint = f"log in once: ./agent-login.py -g {site}"
    if site not in CLAUDE_ACCOUNTS:
        if _browser("logged-in", site, quiet=True) == 0:
            return True, "logged in"
        return False, f"NOT logged in — {hint}"
    email = claude_account_email()
    want = CLAUDE_ACCOUNTS[site].lower()
    if not email:
        return False, f"NOT logged in to claude.ai — {hint}"
    if email != want:
        where = SITE_INSTANCE.get(site, "default")
        return False, (
            f"the {where} browser instance holds {email} — one claude.ai session "
            "per browser profile"
        )
    if site == "anthropic" and _browser("logged-in", "anthropic", quiet=True) != 0:
        return False, f"{email} logged in, but the Team admin billing page fails"
    return True, f"logged in as {email}"


def assisted_login(site: str) -> int:
    """`browser.py login SITE` with the shared Chromium window shown: the site's
    own assisted flow (email code / SSO click) waits until you finish it."""
    ok, how = assisted_check(site)
    if ok:
        print(f"✅ {site}: {how} — nothing to do")
        record_check(site, True, how)
        return 0
    if "one claude.ai session per browser profile" in how:
        # Logging in here would replace the other account's session.
        print(f"❌ {site}: {how}; log that account out first (claude.ai → Log out)")
        record_check(site, False, how)
        return 2
    with site_instance(site):
        try:
            before = show_window()
        except RuntimeError:
            return 1
        try:
            if site in SITE_INSTANCE and site in CLAUDE_ACCOUNTS:
                claude_login_by_hand(site)
            else:
                _browser("login", browser_site(site))
        finally:
            restore_mode(before)
    ok, how = assisted_check(site)
    record_check(site, ok, how)
    print(f"{'✅' if ok else '❌'} {site}: {how}")
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
    """What Albert does when `site` is logged out (depends on its login flow)."""
    here = Path(__file__).resolve().parent
    flow = next((t.flow for t in TARGETS if t.site == site), "")
    if flow == ASSISTED_FLOW:
        return f"run ./agent-login.py -g {site} and finish the login (in {here})"
    if flow == EDUID_SSO_FLOW:
        return (
            f"run ./agent-login.py -t {site}; if it stays logged out, "
            f"./agent-login.py -g {site} and finish the edu-ID login (in {here})"
        )
    if flow == SAFARI_FLOW:
        return (
            f"open the site in Safari and log in, then run ./agent-login.py -t {site} "
            f"(in {here})"
        )
    return f"run ./agent-login.py -t {site} and read its error (in {here})"


def ensure_browser_up() -> bool:
    """Start the shared Chromium (headless) when it is down. Every site check runs
    through it: checking while it is down reports each site as logged out."""
    if browser_mode() is not None:
        return True
    print("▶ shared Chromium is down — starting it (browser.py up --headless)")
    _browser("up", "--headless", quiet=True)
    return browser_mode() is not None


def check_all(*, mail: bool = False) -> int:
    """Every usable site (Safari or broker): logged in? If not, log in. One line
    per site; exit 1 if any stays logged out (and, with `mail`, ONE mail).
    Waits for the network first; still offline after 5 min = skip quietly."""
    if not wait_for_network():
        print(f"⏸  no network ({NETWORK_HOST} does not resolve) — skipped, no mail")
        return 0
    if not ensure_browser_up():
        how = "down, and `browser.py up --headless` did not start it"
        print(f"❌ shared Chromium: {how} — no site checked")
        if mail:
            send_mail(
                "agent-login: shared Chromium does not start",
                f"The daily agent-login check found the shared Chromium {how}.\n"
                "No site was checked. Fix: run `browser.py up` and read its error, "
                "then ./agent-login.py -c.\n",
            )
        return 1
    data = overview()
    failed: list[tuple[str, str]] = []
    if not data["broker_ok"]:
        print(f"❌ login broker: {data['broker']}")
        failed.append(("login broker", data["broker"]))
    for row in data["rows"]:
        if row["status"] == "assisted":
            ok, how = assisted_check(row["site"])
            print(f"{'✅' if ok else '❌'} {row['site']}: {how}")
            record_check(row["site"], ok, how)
            if not ok:
                failed.append((row["site"], how))
            continue
        if row["status"] not in ("ready", "extra", "safari"):
            continue
        rule = safari_cookies.SAFARI_SITES.get(row["site"])
        if rule is not None and not rule.auto:
            print(f"⏭  {row['site']}: not imported unattended (see SAFARI_SITES)")
            continue
        ok, how = ensure_logged_in(row["site"])
        print(f"{'✅' if ok else '❌'} {row['site']}: {how}")
        record_check(row["site"], ok, how)
        if not ok:
            failed.append((row["site"], how))
    if failed and mail:
        send_mail(*failure_mail(failed))
    return 1 if failed else 0


def build_parser() -> argparse.ArgumentParser:
    """The CLI."""
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("-t", "--test", metavar="SITE", help="real login test for SITE")
    ap.add_argument(
        "-f",
        "--fingerprint",
        metavar="SITE",
        help="length + 4 hex of the SHA-256 of the broker's password for SITE (no login)",
    )
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
        "-r",
        "--refresh",
        action="store_true",
        help="ask the broker now (re-reads Bitwarden, ~40 s) instead of the snapshot",
    )
    ap.add_argument(
        "-S",
        "--snapshot",
        action="store_true",
        help="refresh the site-list and secret-run snapshots and the agents file "
        "(which also lists the secrets agents can inject), print nothing "
        "(LaunchAgent, every 10 min)",
    )
    ap.add_argument(
        "-K",
        "--keychain",
        action="store_true",
        help="rescan the login keychain (~15 s) and list every item (names only) "
        "with whether agents can read it",
    )
    ap.add_argument(
        "-A",
        "--agents",
        action="store_true",
        help="print the summary agent sessions get at start (the agents file)",
    )
    ap.add_argument(
        "-I",
        "--install-daily",
        action="store_true",
        help=f"install + load the LaunchAgents {LAUNCH_LABEL} "
        f"(`-c -m` daily {LAUNCH_HOUR:02d}:{LAUNCH_MINUTE:02d}) and {SNAPSHOT_LABEL} "
        f"(`-S` every {SNAPSHOT_INTERVAL_S // 60} min)",
    )
    ap.add_argument(
        "-U",
        "--uninstall-daily",
        action="store_true",
        help="unload + remove both LaunchAgents",
    )
    ap.add_argument(
        "-P",
        "--print-plist",
        action="store_true",
        help="print both LaunchAgent plists (writes nothing)",
    )
    ap.add_argument(
        "-j", "--json", action="store_true", help="print the overview as JSON"
    )
    return ap


def launch_action(args: argparse.Namespace) -> int | None:
    """-P / -I / -U, or None when none was asked for."""
    if args.print_plist:
        print(launchagent_plist(), end="")
        print(snapshot_plist(), end="")
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
    if args.fingerprint:
        resp = broker_request("fingerprint", site=args.fingerprint)
        if not resp.get("ok"):
            print(f"❌ {resp.get('error')}: {resp.get('detail', '')}")
            return 1
        print(f"broker's {args.fingerprint} password: {resp['password_check']}")
        print(
            'compare: printf %s "<password from Bitwarden>" | shasum -a 256 | cut -c1-4'
        )
        return 0
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
    if rc is not None:
        return rc
    if args.snapshot:
        data = overview(fresh=True)
        _note, data["secrets"] = agent_login_secrets.secrets_state(
            broker_request, _state_path(AGENTS_FILE_NAME).parent, fresh=True
        )
        write_agent_summary(data)
        agent_login_keychain.refresh(_state_path("keychain.json"))
        return 0 if data["broker_ok"] else 1
    rc = login_action(args)
    if rc is not None:
        write_agent_summary()  # a check changed what agents can use
        return rc
    data = overview(fresh=args.refresh)
    write_agent_summary(data)
    if args.agents:
        print(agent_summary(data, last_checks()), end="")
        return 0
    if args.keychain:
        agent_login_keychain.refresh(_state_path("keychain.json"), force=True)
        agent_login_keychain.print_list(_state_path("keychain.json"), _c, full=True)
        return 0
    if args.json:
        print(json.dumps(data, indent=1))
    else:
        print_overview(data)
        print()
        agent_login_keychain.print_list(_state_path("keychain.json"), _c)
    return 0 if data["broker_ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
