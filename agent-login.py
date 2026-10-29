#!/usr/bin/env python3
"""agent-login.py — which of Albert's logins can agents use through the login broker?

Without arguments: a health line for the broker, then every login we want agents to
use, once: ✅ when it works for agents (setup complete AND the latest real check, -c/-t,
passed) or ❌ with the reason. Read-only: it asks the broker for its site list (never a
secret), reads the names and expiry dates (never values) of Safari's cookies, and logs
into nothing unless you pass -t, -g or -c.

The marketplace sites (anibis, tutti, Ricardo, Kleinanzeigen), Galaxus and
Galaxus DE run on YOUR Safari session: `browser.py login SITE` copies that site's
session cookies into the shared Chromium (Kleinanzeigen falls back to the broker).
The broker never submits a password for galaxus and galaxus-de (their bot check
rejects it; any item opts in with agent_no_submit=true). When such a session or
one of Notion, Slack, OpenAI or claude.ai lapses, an AGENT renews it: `-L SITE`
imports your Safari session — logging Safari in first (safari.py with every
feature its recipe needs; the credentials from the login broker, else your
Vaultwarden tab) when it has lapsed there too — claude.ai through its automated
magic link. Only a CAPTCHA, an SMS code, a push / security-key approval (exit 4,
named) and the Touch ID touch stay yours: a locked vault is the agent's — it runs
`~/.local/libexec/vault-touchid unlock-safari -a main` (you touch Touch ID once) or onboards the
item into the broker (`broker-add.py ITEM -Y`/`-Z`); `-g SITE` is still there
for a login by hand. CSCS and Smartsheet log in through the broker.
SWITCH Cloud logs in with the portal's SSO click, on the browser's own edu-ID
session first, then on the broker's (no window).

Examples:
  ./agent-login.py              # overview
  ./agent-login.py -t anibis    # real test: `browser.py login` (Safari session first,
                                # then the broker), then the positive logged-in check
  ./agent-login.py -c           # every usable site: logged in? if not, log in
  ./agent-login.py -c -m        # the same + mail Albert (manual; the daily job does not mail)
  ./agent-login.py -t https://auth.cscs.ch   # SITE may also be a name or login address
  ./agent-login.py -g anibis    # guided login: confirm, then log in via the remote view
  ./agent-login.py -g anthropic # your login (email code) in the shown shared Chromium
  ./agent-login.py -g galaxus-de # your login, straight in the shown window (bot check)
  ./agent-login.py -g notion -F # the same, even with unregistered CDP clients attached
  ./agent-login.py -P           # print the daily LaunchAgent (-I installs, -U removes)
  ./agent-login.py -j           # the same overview as JSON
  ./agent-login.py -x           # acceptance matrix (-x -j: as JSON)
  ./agent-login.py -p github    # promote (one budgeted login at most): -c may log it in
  ./agent-login.py -E github    # re-arm its one promotion login (after review, audited)
  ./agent-login.py -Q galaxus   # release a quarantine (main session, audited)
  ./agent-login.py -V           # onboarding review of every broker item (read-only)
  ./agent-login.py -V -i new.json  # review a PLANNED item before the vault write
  ./agent-login.py -D docker    # remove: run while listed, again after the vault item went
  ./agent-login.py -L notion    # an AGENT imports Albert's Safari session (+ a Safari login)
  ./agent-login.py -L galaxus-de -n  # what -L would do (no import, no Safari login)
  ./agent-login.py -R           # refresh-only pass (NPM tokens; LaunchAgent every 6 h)
  ./agent-login.py -l           # items agents can fill into Albert's Safari (safari.py -L)
  ./agent-login.py -H runai-test3  # its identity proofs that did not say match (all: -H)

Sites on Albert's session (Safari sites, galaxus-de, Notion, Slack, OpenAI,
claude.ai) are renewed by AGENTS with -L — never a to-do for Albert, except
a CAPTCHA, an SMS code or a push / security-key approval (exit 4, named) and
the Touch ID touch of `~/.local/libexec/vault-touchid unlock-safari -a main` / `broker-add.py`,
which the agent runs itself when the vault is locked. myfritz is on demand: never checked daily.

Where a login broke: every check records its PHASE (precheck, limiter, vault,
recipe, submit, profile-proof, broker-proof, bundle-export, cookie-inject,
storage-inject, client-proof, consumer-followup, safari-source, unknown) and a
code, a redacted detail and the broker's screenshot; the overview shows them.
A ✅ is a fresh (≤ 36 h), proven check; older reads ❓. The daily check (-c)
never logs in a site that is pending, quarantined, locked, in cooldown,
without a sentinel, changed since its promotion or flagged by the onboarding
review, and never retries after the password may have been sent. Adding a
site: README "Adding a site to the broker".

A credential rotation (mydotfiles credctl) holds its sites: ⏸ held (rotation
TXID) — never logged in, never a failure mail, re-checked later. The old -f
(password length + hash) is gone (tp#965, it was a password oracle): compare
a password with `credctl.py check -T` in mydotfiles.

Fill-only items (`agent_fill_only = true`, tp#1082): the broker never logs in
with them, so they get no ✅/❌ row and are never checked, promoted or tested;
the agents file carries one line with their count, `-l` lists them.
"""

from __future__ import annotations

# One CLI over the whole login table (status, tests, guided logins, jobs);
# helpers already live in the agent_login_* modules.
# pylint: disable=too-many-lines
import argparse
import contextlib
import fcntl
import json
import os
import shutil
import socket
import sys
import time
import urllib.parse
from collections.abc import Callable, Iterator
from dataclasses import asdict, dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))  # the repo's `broker` package
# pylint: disable=wrong-import-position
import agent_login_cred  # noqa: E402
import agent_login_keychain  # noqa: E402
import agent_login_safari as alsafari  # noqa: E402
import agent_login_secrets  # noqa: E402
import agent_login_state as als  # noqa: E402
import agent_login_toolchain  # noqa: E402
from agent_login_claude import (  # noqa: E402
    CLAUDE_ACCOUNTS,
    CONSOLE_ACCOUNTS,
    SITE_INSTANCE,
    browser_site,
    claude_account_email,
    claude_login_by_hand,
    console_account_email,
    instance_session,
)
from agent_login_jobs import (  # noqa: E402
    BUSY_RC,
    KILLED_RC,
    LAUNCH_HOUR,
    LAUNCH_LABEL,
    LAUNCH_MINUTE,
    LOGIN_TIMEOUT_DIRTY_RC,
    LOGIN_TIMEOUT_RC,
    MAIL_TO,
    NETWORK_HOST,
    REFRESH_INTERVAL_S,
    REFRESH_LABEL,
    SNAPSHOT_INTERVAL_S,
    SNAPSHOT_LABEL,
    BrowserRun,
    _browser,
    browser_mode,
    browser_timeout,
    daily_loaded,
    guided_busy,
    guided_window,
    install_daily,
    launchagent_plist,
    login_timeout_s,
    recover_stale_guided_login,
    refresh_plist,
    run_browser,
    safari_sessions,
    send_mail,
    snapshot_plist,
    uninstall_daily,
    wait_for_network,
)
from broker import (  # noqa: E402
    identity,  # noqa: E402
    onboarding,
    phases,
    safari_cookies,
)
from broker.identity import scope_conflicts  # noqa: E402
from broker.recipes import DEFAULT_CHECK_URLS, REFRESH_MIN_LEFT_S  # noqa: E402
from broker.vault import (  # noqa: E402
    NO_SUBMIT_SITES,
    SITE_ID_RE,
    TXID_RE,
    selector_ok,
)

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
# Built-in browser.py sites whose login needs a human-style step (email code,
# SSO click): the check never logs in; an AGENT renews them through Albert's
# Safari (`-L SITE`, WS1b) — claude.ai through its automated magic link.
ASSISTED_FLOW = "assisted"
# WS1b: logged in when an agent needs it, never by the daily check (Albert,
# 2026-10-11: MyFRITZ's Keycloak session lasts 10 h — a daily ✅ would be
# stale by the evening). `-c` neither checks nor logs them in.
ON_DEMAND_SITES = frozenset({"myfritz"})
# One id per agent-login run: a site's failed checks count as two in a row
# only from two different runs (agent_login_state.record_check, WS1b O10).
RUN_ID = f"{os.getpid()}-{int(time.time())}"


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
        "galaxus",
        "Galaxus",
        "https://id.digitecgalaxus.ch",
        SAFARI_FLOW,
        _SAFARI_NOTE + " (the broker never submits a password here)",
    ),
    Target(
        "galaxus-de",
        "Galaxus DE",
        "https://id.galaxus.eu",
        SAFARI_FLOW,
        "a separate account in Albert's Safari; the broker never submits here",
    ),
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
        "claude.ai work account (SDSC Team admin)",
    ),
    Target(
        "anthropic-private",
        "Anthropic private",
        "https://claude.ai",
        ASSISTED_FLOW,
        "claude.ai private account, own browser instance "
        "(CLAUDE_BROWSER_INSTANCE=private, CDP 9223)",
    ),
    Target(
        "console",
        "Claude Console work",
        "https://platform.claude.com",
        ASSISTED_FLOW,
        "platform.claude.com work org (billing read by console-balance.py)",
    ),
    Target(
        "console-private",
        "Claude Console private",
        "https://platform.claude.com",
        ASSISTED_FLOW,
        "platform.claude.com private org (Google SSO), own browser instance "
        "(CLAUDE_BROWSER_INSTANCE=private, CDP 9223)",
    ),
    Target(
        "openai",
        "OpenAI",
        "https://chatgpt.com",
        ASSISTED_FLOW,
        "chatgpt.com Business admin (Google SSO)",
    ),
    Target(
        "slack",
        "Slack",
        "https://app.slack.com",
        ASSISTED_FLOW,
        "SDSC Slack",
    ),
    Target(
        "notion",
        "Notion",
        "https://app.notion.com",
        ASSISTED_FLOW,
        "Notion (SDSC/Renku workspace)",
    ),
    Target(
        "switch",
        "SWITCH Cloud",
        "https://cloud.switch.ch",
        EDUID_SSO_FLOW,
        "Switch Cloud Portal: SSO click on the browser's own edu-ID session, else "
        "the broker's (no window); "
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
        if fresh:
            adopt_configs(sites)
    return health, sites


def adopt_configs(sites: list[dict]) -> list[str]:
    """WS3 migration, from a FRESH live listing only: a site promoted with an
    older (or no) config digest adopts its current digest once (audited) —
    at once when its config is unchanged, else after a fresh strict ✅."""
    listed = [
        s
        for s in sites
        if s.get("site") and not s.get("refused") and not is_fill_only(s)
    ]
    digests = {str(s["site"]): onboarding.config_digest(s) for s in listed}
    legacy = {
        str(s["site"]): {
            v: onboarding.legacy_digests(s, v) for v in range(1, onboarding.CONFIG_V)
        }
        for s in listed
    }
    with contextlib.suppress(als.StateError, OSError):
        return als.adopt_configs(digests, legacy=legacy)
    return []


def _snapshot_sites() -> list[dict]:
    """The last `sites` snapshot's entries, whatever its age ([] when none)."""
    try:
        data = json.loads(_state_path("sites.json").read_text(encoding="utf-8"))
        return [s for s in data.get("sites") or [] if isinstance(s, dict)]
    except (OSError, ValueError, AttributeError, TypeError):
        return []


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
        return "assisted", target.note + route_hint(target.site)
    if target.flow == EDUID_SSO_FLOW:
        return _classify_eduid_sso(target, listed, readable=readable)
    if not readable:
        return "unchecked", ""
    entry = listed.get(target.site)
    if entry is None:
        return "missing", f"add agent_fill_origins = {target.fill_origin}"
    return _classify_listed(target, entry)


def has_sentinel(entry: dict) -> bool:
    """The broker item has an authenticated proof — a DOM sentinel, or a
    registered server proof (CSCS: its API answers the stored token;
    ``recipes.PROOFS``) — AS THE BROKER ADVERTISES IT: `strict_proof` from a
    WS2-cscs broker, else `sentinel` (WS1a), else `logged_in_selector`. An
    older broker without `strict_proof` still runs its old proof, so its
    CSCS is never assumed strict from this (newer) code."""
    strict = entry.get("strict_proof")
    if isinstance(strict, bool):
        return strict
    flag = entry.get("sentinel")
    if isinstance(flag, bool):
        return flag
    return bool(entry.get("logged_in_selector"))


SENTINEL_HINT = (
    "no agent_logged_in_selector — a login cannot be proven; find one: "
    "browser.py logged-in {site} -x 'CSS' (logged out everywhere: one approved "
    "browser.py login {site} -x 'CSS'), then broker-add.py -L"
)


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
        # only rules out the broker fallback. (No sentinel: the row's
        # `sentinel` flag says so — the old proof still decides.)
        if refused:
            return "safari", (
                f"{target.note}{route_hint(target.site)}; broker item refused: {reason}"
            )
        return "safari", target.note + route_hint(target.site)
    if refused:
        return "refused", reason
    if is_no_submit(target.site, entry):
        return "assisted", NO_SUBMIT_NOTE.format(site=target.site)
    if target.flow == "manual":
        status = "manual"
    else:
        status = "ready" if target.flow in SUPPORTED_FLOWS else "needs-flow"
    return status, target.note


NO_SUBMIT_NOTE = (
    "the broker never submits a password here (agent_no_submit) — your own "
    "login: ./agent-login.py -g {site}"
)


def is_no_submit(site: str, entry: dict | None = None) -> bool:
    """The broker never submits a password for `site`: built in
    (``vault.NO_SUBMIT_SITES``) or its item says so (`no_submit`, advertised
    by a broker with the guard). Such a site is logged in by Albert — a
    guided login or his Safari session — and only ever CHECKED by agents."""
    return site in NO_SUBMIT_SITES or bool((entry or {}).get("no_submit"))


def is_fill_only(entry: dict | None) -> bool:
    """A broker row of a fill-only item (tp#1082 D5): the broker never logs
    in with it — no ✅/❌ row, never checked (-c), promoted or tested; agents
    fill it into Albert's Safari (`safari.py -L`)."""
    return bool(entry) and (entry or {}).get("fill_only") is True


def _hint_host(origins: object) -> str:
    """The host of the first fill origin ('' when none)."""
    first = origins[0] if isinstance(origins, list) and origins else ""
    return urllib.parse.urlsplit(str(first)).hostname or ""


def fillable_rows(sites: list[dict]) -> list[dict]:
    """Every listed, non-refused item `safari_fill` may serve (fill-only, or a
    login item with `agent_safari_fill`): site id, name, fill origins and
    whether it is fill-only — names and origins only, never a value."""
    rows = []
    for entry in sites:
        site = str(entry.get("site") or "")
        if not SITE_ID_RE.match(site) or entry.get("refused"):
            continue
        fill_only = entry.get("fill_only") is True
        if not (fill_only or entry.get("safari_fill") is True):
            continue
        origins = [str(o) for o in entry.get("fill_origins") or []]
        rows.append(
            {
                "site": site,
                "name": _clean_name(entry.get("name"), site),
                "fill_origins": origins,
                "fill_only": fill_only,
            }
        )
    return sorted(rows, key=lambda r: r["site"])


def _clean_name(value: object, fallback: str) -> str:
    """A vault item name for a listing: printable, one line, ≤ 64 chars."""
    text = str(value or "")
    if not text or len(text) > 64 or not text.isprintable():
        return fallback
    return text


def fillable_action(*, as_json: bool, fresh: bool) -> int:
    """`-l`: every item agents can fill into Albert's Safari (`safari.py -L`),
    from the broker's `sites` listing — `site  name  fill origins`."""
    health, sites = broker_state(fresh=fresh)
    rows = fillable_rows(sites)
    if as_json:
        print(json.dumps(rows, indent=1))
        return 0
    if not health.startswith("running, Bitwarden"):
        print(f"⚠️ login broker: {health}", file=sys.stderr)
    if not rows:
        print("(no item can be filled into Albert's Safari)")
        return 0
    w0 = max(len(r["site"]) for r in rows)
    w1 = max(len(r["name"]) for r in rows)
    for r in rows:
        tag = "" if r["fill_only"] else "  (login item, agent_safari_fill)"
        print(
            f"{r['site']:<{w0}}  {r['name']:<{w1}}  {', '.join(r['fill_origins'])}{tag}"
        )
    return 0


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


def _broker_fields(entry: dict) -> dict:
    """The broker columns of a row (limiter state, group, scope, sentinel)."""
    limit = entry.get("limit") if isinstance(entry.get("limit"), dict) else None
    return {
        "limit": limit,
        "attempt_group": entry.get("attempt_group"),
        "sentinel": has_sentinel(entry) if entry else None,
        "cookie_hosts": list(entry.get("cookie_hosts") or []),
        "storage_origins": list(entry.get("storage_origins") or []),
        "proof_origins": list(entry.get("proof_origins") or []),
        "session_refresh": entry.get("session_refresh"),
        # WS3: the configuration a promotion holds for
        "config": onboarding.config_digest(entry) if entry else None,
        # tp#965: a credential rotation holds the item (lease or agent_hold)
        "held": entry.get("held") is True,
        "held_txid": _txid_or_none(entry.get("held_txid")),
        **_identity_fields(entry),
    }


def _txid_or_none(value: object) -> str | None:
    """A validated rotation txid, else None (never free text)."""
    return value if isinstance(value, str) and TXID_RE.match(value) else None


def held_how(row: dict | None = None, res: dict | None = None) -> str | None:
    """``held (rotation TXID) — …`` when a credential rotation holds the row
    (its ``sites`` entry) or the login answered ``held``, else None."""
    if (row or {}).get("held"):
        txid = (row or {}).get("held_txid")
    elif (res or {}).get("code") == "held":
        txid = (res or {}).get("txid")
    else:
        return None
    return f"held (rotation {_txid_or_none(txid) or '?'}) — skipped, re-check later"


def _slug_or_none(value: object) -> str | None:
    """A validated site-id-shaped slug, else None (never free text)."""
    return value if isinstance(value, str) and SITE_ID_RE.match(value) else None


def _identity_fields(entry: dict) -> dict:
    """The WS5 columns of a row, from the broker's `sites` entry: browser
    instance, privilege, identity recipe, alias, same-account partner, the
    broker's multi-account flag and whether the CLIENT can prove the account
    (`identity.proof_ready`). Only fixed vocabularies and slugs survive."""
    inst = identity.instance_of(entry) if entry else ""
    privilege = entry.get("privilege") if entry else None
    recipe = entry.get("identity") if entry else None
    same = [s for s in (entry.get("same_account_as") or []) if _slug_or_none(s)]
    return {
        "instance": inst if inst in identity.INSTANCES else "?",
        "privilege": privilege if privilege in identity.PRIVILEGES else None,
        "identity": recipe if recipe in identity.IDENTITIES else None,
        "alias": _slug_or_none(entry.get("alias")) if entry else None,
        "same_account_as": same if entry else [],
        "multi_account": bool(entry.get("multi_account")) if entry else False,
        "proof_ready": identity.proof_ready(entry) if entry else False,
    }


def _known_extras(planned: set[str]) -> list[str]:
    """Broker sites known from earlier runs (site-state.json, the last
    sites.json snapshot whatever its age): shown while the broker is down."""
    known = set(als.site_states())
    try:
        snap = json.loads(_state_path("sites.json").read_text(encoding="utf-8"))
        known |= {str(s.get("site")) for s in snap.get("sites") or [] if s.get("site")}
    except (OSError, ValueError, AttributeError, TypeError):
        pass
    return sorted(s for s in known - planned if SITE_ID_RE.match(s))


def overview(*, fresh: bool = False) -> dict:
    """Everything the report shows, as data."""
    health, sites = broker_state(fresh=fresh)
    readable = health.startswith("running, Bitwarden")
    listed = {str(s.get("site")): s for s in sites}
    if readable and listed:
        with contextlib.suppress(als.StateError, OSError):
            als.ensure_known(
                [
                    s
                    for s, e in listed.items()
                    if SITE_ID_RE.match(s) and not is_fill_only(e)
                ]
            )
    try:
        stages = als.site_states()
    except als.StateError:
        stages = {}
    safari = safari_state(
        [
            t.site
            for t in TARGETS
            if t.flow == SAFARI_FLOW or t.site in safari_cookies.SAFARI_BUILTIN
        ]
    )
    shared = scope_conflicts(sites)  # WS5: items sharing a login with another account
    risks = onboarding_risks(sites)  # WS3: never logged in unattended
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
                **_broker_fields(entry),
                # a static site's own instance (claude.ai private) wins
                **(
                    {"instance": SITE_INSTANCE[t.site]}
                    if t.site in SITE_INSTANCE
                    else {}
                ),
                "shares_login_with": list(shared.get(t.broker_site or t.site, ())),
                "onboarding_risk": risks.get(t.broker_site or t.site, []),
                **_stage_fields(stages.get(t.broker_site or t.site)),
                **safari.get(t.site, {}),
            }
        )
    planned = {t.site for t in TARGETS}
    for site, entry in sorted(listed.items()):
        if site in planned or is_fill_only(entry):
            continue  # a fill-only item: the one agents.md line, `-l`
        refused = entry.get("refused")
        status, detail = "extra", ""
        if refused:
            status, detail = "refused", str(entry.get("reason") or "")
        elif is_no_submit(site, entry):
            status, detail = "assisted", NO_SUBMIT_NOTE.format(site=site)
        rows.append(
            {
                "site": site,
                "name": site,
                "fill_origin": ", ".join(entry.get("fill_origins") or []),
                "flow": "one-page",
                "note": "",
                "check_url": str(entry.get("check_url") or ""),
                "status": status,
                "detail": detail,
                "in_bitwarden": bool(entry.get("fill_origins")),
                **_broker_fields(entry),
                "shares_login_with": list(shared.get(site, ())),
                "onboarding_risk": risks.get(site, []),
                **_stage_fields(stages.get(site)),
            }
        )
    if not readable:
        for site in _known_extras(planned):
            rows.append(
                {
                    "site": site,
                    "name": site,
                    "fill_origin": "",
                    "flow": "one-page",
                    "note": "",
                    "check_url": "",
                    "status": "unchecked",
                    "detail": "broker unreadable — known from earlier runs",
                    "in_bitwarden": None,
                    **_broker_fields({}),
                    "shares_login_with": [],
                    **_stage_fields(stages.get(site)),
                }
            )
    return {
        "broker": health,
        "broker_ok": readable,
        "rows": rows,
        "fillable": fillable_rows(sites),
    }


def onboarding_risks(sites: list[dict]) -> dict[str, list[str]]:
    """``{site: [risk codes]}`` of the listed items (WS3 `onboarding`): such
    a row is never logged in unattended. Fixed codes only."""
    out: dict[str, list[str]] = {}
    for site, findings in onboarding.collection_findings(sites).items():
        codes = sorted({f.code for f in findings if f.level == "risk"})
        if codes:
            out[site] = codes
    return out


def _stage_fields(entry: dict | None) -> dict:
    """The site-state columns of a row: stage, the config it was promoted
    for (WS3) and quarantine."""
    entry = entry or {}
    q = entry.get("quarantine") if isinstance(entry.get("quarantine"), dict) else None
    return {
        "stage": entry.get("stage"),
        "promoted_config": entry.get("config"),
        "promoted_config_v": entry.get("config_v"),
        "quarantine": q,
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


AGENTS_FILE_NAME = "agents.md"
# How each kind of login is used by an agent (the summary's ✅ lines).
_HOW_TO_USE = {
    "safari": "Albert's Safari session",
    "ready": "login broker",
    "extra": "login broker",
    "assisted": "Albert's session in the shared Chromium",
}


TARGET_SITES = {t.site for t in TARGETS}
_CHECK_FIRST = {
    "stale": "its last success is older than the status age",
    "unknown": "its last check could not tell",
    "unchecked": "not checked yet",
    "unreachable": "unreachable off-LAN (Cloudflare Access)",
}


def _summary_name(row: dict) -> str | None:
    """A row's display name for agents.md: a static TARGETS name, else the
    validated site id — never a name read from Bitwarden or a page."""
    site = str(row.get("site") or "")
    if not SITE_ID_RE.match(site):
        return None
    if site in TARGET_SITES:
        return next(t.name for t in TARGETS if t.site == site)
    return site


def _summary_reason(  # pylint: disable=too-many-return-statements
    row: dict, state: str, checks: dict[str, dict]
) -> str:
    """The ❌ text of agents.md: fixed vocabulary only (phase/code texts, the
    fixed setup reasons, fixed hints) — never a detail or a page's words."""
    site = row["site"]
    if state == "setup":
        if row["status"] == "refused":
            return refusal_text(row)
        if row["status"] in _SETUP_REASON:
            return _SETUP_REASON[row["status"]]
        return (
            "Safari session missing, expired or unreadable — Albert logs in in Safari"
        )
    rec = checks.get(site) or {}
    code = str(rec.get("code") or "")
    text = phases.text(str(rec.get("phase") or ""), code)
    if code.startswith("needs_albert_"):
        return f"not logged in — {phases.CODE_TEXT.get(code, 'needs Albert')}"
    if code == "vault_locked":  # the agent's own fix, named (never Albert's)
        return f"not logged in — {phases.CODE_TEXT[code]}"
    if isinstance(row.get("quarantine"), dict):
        return (
            "not logged in — quarantined after a login that may have sent a "
            f"credential; the main session releases it: ./agent-login.py -Q {site}"
        )
    if agent_route(site, row):
        return f"not logged in{route_hint(site, row)} — never ask Albert"
    if row.get("flow") == ASSISTED_FLOW or row["status"] == "assisted":
        return f"not logged in — needs Albert: ./agent-login.py -g {site}"
    if manual_import(site):
        return f"not logged in — needs Albert: ./agent-login.py -t {site}"
    return f"not logged in — {text}"


def _route_header(rows: list[dict]) -> str:
    """agents.md's sentence on sites that live on Albert's session, built from
    `agent_route` (SF2): `-L` is promised only for the sites it can renew
    now; the rest keep "ask Albert"."""
    routed = sorted(
        {
            r["site"]
            for r in rows
            if SITE_ID_RE.match(str(r.get("site") or "")) and agent_route(r["site"], r)
        }
    )
    rest = (
        "for the other sites on Albert's session do NOT start a login — ask "
        "Albert to run `agent-login.py -g <site>`."
    )
    if not routed:
        return rest
    return (
        f"for {', '.join(routed)} run `agent-login.py -L <site>` yourself (it "
        "renews the session through Albert's Safari or the magic link; one run, "
        "no retries) — never ask Albert to log in: only a CAPTCHA, an SMS code, "
        "a push / security-key approval and the Touch ID touch are his, and -L "
        "names them; a locked vault is NOT his: -L takes the login from the "
        "broker first, else run `~/.local/libexec/vault-touchid unlock-safari -a main` yourself "
        "(Albert touches Touch ID once); exit 3 = the Mac is locked or idle: "
        f"retry later, do not ask Albert; {rest}"
    )


def agent_route(site: str, row: dict | None = None) -> bool:
    """WS1b S2: an agent can renew `site` itself with `-L` — claude.ai through
    its automated magic link; a recipe site when the installed safari.py
    offers EVERY feature its recipe needs, or (no safari.py driving at all)
    when Safari already holds a session `-L` would import (`row`'s Safari
    columns, an importable recipe). Else the old wording stays."""
    if site in alsafari.MAGIC_LINK_SITES:
        return True
    recipe = alsafari.RECIPES.get(site)
    if recipe is None:
        return False
    if not alsafari.missing_features(site):
        return True
    return recipe.import_after and _safari_session_live(row or {})


def _safari_session_live(row: dict) -> bool:
    """`row`'s Safari columns: Safari holds the site's session, not expired."""
    expires = row.get("safari_expires")
    fresh = not expires or str(expires) >= time.strftime("%Y-%m-%d")
    return row.get("safari") is True and fresh


def route_hint(site: str, row: dict | None = None) -> str:
    """The note's renewal hint for `site` (fixed words; '' when none)."""
    if agent_route(site, row):
        if site in alsafari.MAGIC_LINK_SITES:
            return f" — an agent renews it: ./agent-login.py -L {site} (magic link)"
        if alsafari.missing_features(site):
            return (
                f" — an agent imports Albert's existing Safari session: "
                f"./agent-login.py -L {site}"
            )
        return f" — an agent renews it: ./agent-login.py -L {site} (Albert's Safari)"
    if site in alsafari.RECIPES and site in {
        t.site for t in TARGETS if t.flow == SAFARI_FLOW
    }:
        return f" — Albert logs in in Safari, then ./agent-login.py -t {site}"
    return f" — your own login: ./agent-login.py -g {site}"


# agents.md words for an item's `agent_privilege` (ADMIN in capitals: an
# agent must choose an admin account consciously).
_PRIVILEGE_WORDS = {
    "admin": "ADMIN account",
    "user": "user account",
    "readonly": "read-only account",
}


def _instance_note(inst: str) -> str:
    """How an agent reaches a role instance's browser (fixed text)."""
    port = identity.ROLE_INSTANCE_PORTS.get(inst)
    if port is None:
        return ""
    mcp = (
        "; Playwright MCP only through the opt-in `playwright-admin` config"
        if inst == "admin"
        else "; not reachable by the Playwright MCP tools"
    )
    return (
        f"its own browser (CDP 127.0.0.1:{port}), stopped when idle: "
        f"`CLAUDE_BROWSER_INSTANCE={inst} browser.py up` first, `… down` when "
        f"done; every browser.py call needs that prefix{mcp}"
    )


def _account_note(row: dict) -> str:
    """The WS5 part of a row's agents.md line: privilege, alias, instance —
    fixed words and validated slugs only."""
    parts = []
    word = _PRIVILEGE_WORDS.get(str(row.get("privilege") or ""))
    if word:
        parts.append(word)
    alias = _slug_or_none(row.get("alias"))
    if alias:
        parts.append(f"the default — alias `{alias}`")
    note = _instance_note(row_instance(row))
    if note:
        parts.append(note)
    return "; ".join(parts)


# One return per row state agents.md renders.
def _summary_line(  # pylint: disable=too-many-return-statements
    row: dict, checks: dict[str, dict], indent: str = ""
) -> tuple[str, str] | None:
    """(section, line) of one row in agents.md (None: no valid name)."""
    name = _summary_name(row)
    if name is None:
        return None
    site = row["site"]
    state, _why = row_state(row, checks)
    inst = row_instance(row)
    # every non-default instance, `private` included (else the check would
    # ask the shared browser, i.e. another claude.ai account)
    prefix = f"CLAUDE_BROWSER_INSTANCE={inst} " if inst and inst != "?" else ""
    if state == "ok":
        how = _HOW_TO_USE.get(row["status"], "login broker")
        if manual_import(site) and agent_route(site, row):
            how = (
                "Albert's Safari session; the daily run only checks it — when "
                f"it lapses{route_hint(site, row)}"
            )
        elif manual_import(site):
            how = f"check only; Albert re-imports (`agent-login.py -t {site}`)"
        if site in CLAUDE_ACCOUNTS or site in CONSOLE_ACCOUNTS:
            how += f", {CLAUDE_ACCOUNTS.get(site) or CONSOLE_ACCOUNTS[site]}"
        inst = SITE_INSTANCE.get(site, "")
        if inst:
            how += (
                f" — its own browser (CDP 127.0.0.1:9223), stopped when idle: "
                f"`CLAUDE_BROWSER_INSTANCE={inst} browser.py up` first, "
                "`… down` when done; every browser.py call needs that prefix"
            )
        note = _account_note(row)
        if note:
            how += f" — {note}"
        if needs_sentinel(row):
            how += " — weak proof (no sentinel yet)"
        return "ok", f"{indent}- ✅ {name} (`{browser_site(site)}`): {how}"
    if state == "unproven":
        return "warn", f"{indent}- ⚠ {name} (`{site}`): {unproven_text(row)}"
    if state == "held":
        # a skip like busy: never a login, never ❌ (txid validated)
        return "check", (
            f"{indent}- ⏸ {name} (`{site}`): held (rotation "
            f"{_txid_or_none(row.get('held_txid')) or '?'}) — a credential "
            "rotation is in progress; do not log in, re-check later"
        )
    if state == "on-demand":
        return "ok", (
            f"{indent}- ⏯ {name} (`{site}`): on demand — `{prefix}browser.py "
            f"logged-in {site}`; if it fails, `{prefix}browser.py login {site}` "
            "(broker login, about a minute); its sessions are short"
        )
    if state in _CHECK_FIRST:
        note = _account_note(row)
        return "check", (
            f"{indent}- ❓ {name} (`{browser_site(site)}`): {_CHECK_FIRST[state]} — "
            f"check first: `{prefix}browser.py logged-in {browser_site(site)}`"
            + (f" — {note}" if note else "")
        )
    return "bad", f"{indent}- ❌ {name}: {_summary_reason(row, state, checks)}"


def _account_groups(rows: list[dict]) -> list[tuple[str, ...]]:
    """The connected groups of rows that share a login (`shares_login`),
    each sorted, groups sorted — validated site ids only."""
    graph: dict[str, set[str]] = {}
    for row in rows:
        if not SITE_ID_RE.match(str(row.get("site") or "")):
            continue
        for other in shares_login(row):
            graph.setdefault(row["site"], set()).add(other)
            graph.setdefault(other, set()).add(row["site"])
    return identity.connected_groups(graph)


def _group_summary(
    groups: list[tuple[str, ...]], rows: list[dict], checks: dict[str, dict]
) -> dict[str, list[str]]:
    """agents.md lines of the WS5 groups, per section (ok / check / warn /
    bad): in each section a group's members land in, one header for the
    site with several accounts, then those members indented."""
    by_site = {r["site"]: r for r in rows}
    out: dict[str, list[str]] = {}
    for group in groups:
        per: dict[str, list[str]] = {}
        for site in group:
            got = (
                _summary_line(by_site[site], checks, indent="  ")
                if site in by_site
                else None
            )
            if got is not None:
                per.setdefault(got[0], []).append(got[1])
        for section, member_lines in per.items():
            out.setdefault(section, []).append(
                f"- one site, several accounts ({', '.join(group)}) — never two in "
                "one browser; pick the account the task needs (ADMIN = admin rights):"
            )
            out[section] += member_lines
    return out


def agent_summary(data: dict, checks: dict[str, dict]) -> str:
    """The short Markdown every agent session gets at start (SessionStart hook).

    Prompt-injection surface: it renders ONLY fixed vocabulary (phase/code
    texts, fixed reasons and hints) and validated identifiers (static names,
    site ids, the expected claude.ai account) — never a detail, a broker
    reason, a screenshot path or anything a page said. Sites with several
    accounts (WS5) are grouped, each member with its privilege (ADMIN in
    capitals), the group's alias and its browser instance."""
    lines: dict[str, list[str]] = {"ok": [], "check": [], "warn": [], "bad": []}
    rows = sorted(data["rows"], key=lambda r: str(r["name"]).lower())
    grouped = _account_groups(rows)
    in_group = {site for group in grouped for site in group}
    for row in rows:
        if row["site"] in in_group:
            continue
        got = _summary_line(row, checks)
        if got is not None:
            lines[got[0]].append(got[1])
    for section, group_lines in _group_summary(grouped, rows, checks).items():
        lines[section] += group_lines
    here = Path(__file__).resolve().parent
    ok_lines, check_lines = lines["ok"], lines["check"]
    warn_lines, bad_lines = lines["warn"], lines["bad"]
    out = [
        f"## Web logins agents can use (agent-login.py, {time.strftime('%Y-%m-%d %H:%M')})",
        "",
        "The shared logged-in Chromium (CDP http://127.0.0.1:9222; `browser.py`, "
        "Playwright MCP `browser_*` tools) holds these sessions. Before using a "
        "site: `browser.py logged-in <site>`. If it fails: for broker sites run "
        "`browser.py login <site>` (never asks for a password); "
        + _route_header(data["rows"])
        + " A site that fails after its password was submitted is quarantined: "
        "do not retry it.",
        "",
        *ok_lines,
        *check_lines,
        *warn_lines,
        *bad_lines,
        *fill_only_lines(data),
        *agent_login_secrets.summary_lines(data.get("secrets") or []),
        "",
        f"Full status: `{here}/agent-login.py` (❌ items name the command an "
        "agent runs; only lines saying 'needs Albert' are his).",
    ]
    if not data.get("broker_ok"):
        out.insert(2, "⚠️ login broker unavailable — broker sites cannot log in now\n")
    return "\n".join(out) + "\n"


def fill_only_lines(data: dict) -> list[str]:
    """The ONE agents-file line about fill-only items (none when there are
    none): a count and fixed text only."""
    n = sum(1 for r in data.get("fillable") or [] if r.get("fill_only") is True)
    if not n:
        return []
    what = "1 site can" if n == 1 else f"{n} sites can"
    return [
        f"- {what} be filled into Albert's Safari (login broker, fill-only): "
        '`safari.py -L "<item>" -u <host>`; list them with `agent-login.py -l`'
    ]


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


def configured_instance(site: str) -> str:
    """The browser instance `site` lives in: its static one (claude.ai
    private), else its broker item's role instance from the last `sites`
    snapshot (no broker call), else '' (the shared one). Never the ambient
    $CLAUDE_BROWSER_INSTANCE."""
    if site in SITE_INSTANCE:
        return SITE_INSTANCE[site]
    entry = next((s for s in _snapshot_sites() if s.get("site") == site), None)
    inst = identity.instance_of(entry) if entry else ""
    return inst if inst in identity.ROLE_INSTANCES else ""


def record_check(
    site: str,
    ok: bool | None,
    how: str,
    result: dict | None = None,
    instance: str | None = None,
) -> None:
    """Remember a site's latest REAL check (`agent_login_state.record_check`):
    ok True / False / None (= could not tell), plus where it stopped —
    browser.py's result record (`-R`) when there is one. The instance it
    ran in: browser.py's own word, else `instance`, else the site's
    configured one (`configured_instance`); the identity verdict (WS5) as
    browser.py recorded it."""
    r = result or {}
    state = "ok" if ok else ("unknown" if ok is None else "failed")
    proof_v = r.get("proof_v")
    inst = r.get("instance")
    if not isinstance(inst, str):
        inst = configured_instance(site) if instance is None else instance
    with contextlib.suppress(als.StateError, OSError):
        als.record_check(
            site,
            state,
            how,
            phase=str(r.get("phase") or ""),
            code=str(r.get("code") or ""),
            detail=str(r.get("detail") or ""),
            screenshot=r.get("screenshot"),
            stop_origin=str(r.get("stop_origin") or ""),
            submitted=r.get("submitted"),
            route=str(r.get("route") or ""),
            proof_v=proof_v if isinstance(proof_v, int) else 0,
            final_origin=str(r.get("final_origin") or ""),
            origin_ok=r.get("origin_ok"),
            instance=inst,
            identity=str(r.get("identity") or ""),
            identity_why=str(r.get("identity_why") or ""),
            identity_status=r.get("identity_status"),
            config=str(r.get("config") or ""),
            server=str(r.get("server") or ""),
            cookie_days_left=r.get("cookie_days_left"),
            run_id=RUN_ID,
        )


def last_checks() -> dict[str, dict]:
    """``{site: record}`` of the latest checks (checks.json v2)."""
    return als.checks()


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
    if status != "safari" or row.get("fallback") or agent_route(row["site"], row):
        # WS1b: a site an agent can log Safari into (`-L`) is judged by its
        # check alone; a missing Safari session is a flag (`_row_flags`).
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


def shares_login(row: dict) -> list[str]:
    """The validated site ids `row` shares its cookie scope with, when they
    are another account (WS5, ``broker.identity.scope_conflicts``)."""
    return [s for s in row.get("shares_login_with") or [] if SITE_ID_RE.match(s)]


def unproven_text(row: dict) -> str:
    """The fixed ⚠ text of a multi-account row (site ids only, never a name
    read from Bitwarden or a page)."""
    return (
        f"account unproven (shares login with {', '.join(shares_login(row))}) — "
        "the check cannot tell which account the shared browser holds; not "
        "usable by agents, never logged in"
    )


def account_unproven(row: dict) -> bool:
    """A multi-account row whose account the client cannot prove (WS5): no
    usable identity recipe / privilege, or a broker without the identity
    protocol. A proof-ready one is checked like any row — its check runs
    the server identity proof, and only a proven account is ✅."""
    return is_multi_account(row) and not row.get("proof_ready")


def is_multi_account(row: dict) -> bool:
    """The row shares its login scope with another account: by the client's
    own `scope_conflicts`, or by the broker's `multi_account` flag."""
    return bool(shares_login(row)) or row.get("multi_account") is True


def row_instance(row: dict) -> str:
    """The browser instance a row's session lives in ('' = the shared one)."""
    inst = row.get("instance")
    return inst if isinstance(inst, str) else ""


# A WS5 refusal of the broker → a fixed text for agents.md (the broker's own
# reason is free text: never shown to agents). First matching prefix wins.
_WS5_REFUSALS = (
    (
        "shares its login scope",
        "shares its login with another account — needs agent_privilege",
    ),
    (
        "scope conflict in instance",
        "another account of this site is in the same browser instance — needs agent_instance",
    ),
    ("agent_same_account_as", "its same-account declaration is refused"),
    ("bad agent_alias", "its agent_alias is refused"),
    ("agent_alias", "its agent_alias is refused"),
    ("bad agent_instance", "unknown agent_instance"),
    ("bad agent_privilege", "unknown agent_privilege"),
    ("bad agent_identity", "its agent_identity is not usable"),
    ("agent_identity", "its agent_identity is not usable"),
    ("the vault holds an", "its agent_identity is not usable"),
)


def refusal_text(row: dict) -> str:
    """The fixed agents.md reason of a refused row: the WS5 refusals by kind
    (plus the validated site ids it shares its login with), else the plain
    "Bitwarden item refused"."""
    reason = str(row.get("detail") or "")
    text = next((t for p, t in _WS5_REFUSALS if reason.startswith(p)), None)
    if text is None:
        return _SETUP_REASON["refused"]
    shared = shares_login(row)
    if shared:
        text += f" (shares login with {', '.join(shared)})"
    return f"{_SETUP_REASON['refused']}: {text}"


# One return per state, in the order they are decided.
def row_state(  # pylint: disable=too-many-return-statements,too-many-branches
    row: dict, checks: dict[str, dict]
) -> tuple[str, str]:
    """(state, why) of one login: ``ok`` (setup complete AND the latest real
    check passed, fresh), ``stale`` (that ✅ is older than the max status
    age), ``unknown`` (the latest check could not tell), ``unreachable``
    (it met a Cloudflare Access login: off-LAN), ``unchecked``, ``failed``,
    ``setup`` (cannot work whatever a check says), or ``unproven`` (it
    shares its login with another account: never ✅ whatever a check said,
    WS5)."""
    problem = _setup_problem(row)
    if problem:
        return "setup", problem
    if account_unproven(row):
        return "unproven", unproven_text(row)
    held = held_how(row)
    if held:  # tp#965: a credential rotation is in progress — a skip
        return "held", held
    site = row["site"]
    rec = checks.get(site)
    fresh = als.freshness(rec)
    if site in ON_DEMAND_SITES:
        # WS1b: never judged by age — its session is short on purpose.
        last = (
            f"last check {rec.get('at_text', '?')}: {rec.get('state')}"
            if rec
            else "never checked"
        )
        return "on-demand", f"on demand — {last}; log in when needed"
    if not rec or fresh == "unchecked":
        return "unchecked", f"not checked yet — ./agent-login.py -t {site}"
    when = rec.get("at_text", "?")
    # A record from before WS5 S3 has no instance: it ran where the site
    # lived then (role instances did not exist yet).
    checked_in = str(rec.get("instance", SITE_INSTANCE.get(site, "")) or "")
    if checked_in != row_instance(row):
        # WS5: the item moved to another browser instance since that check —
        # its verdict says nothing about the session where it lives now.
        return "stale", (
            f"last check {when} ran in the {checked_in or 'default'} browser, the "
            f"item now lives in the {row_instance(row) or 'default'} one — verify: "
            f"./agent-login.py -t {site}"
        )
    reason = phases.text(str(rec.get("phase") or ""), str(rec.get("code") or ""))
    if fresh == "stale":
        hours = als.max_status_age_s() / 3600
        return "stale", (
            f"last success {when} is older than {hours:g} h — verify: "
            f"browser.py logged-in {browser_site(site)}"
        )
    if fresh in ("unknown", "failed") and rec.get("code") == "access_gated":
        # Off-LAN behind Cloudflare Access: neither logged in nor out.
        fresh = "unreachable"
    if fresh != "ok":
        state = fresh if fresh in ("unknown", "unreachable") else "failed"
        told = " could not tell —" if state == "unknown" else ":"
        return state, f"last check {when}{told} {reason}"
    if is_multi_account(row) and rec.get("identity") != "match":
        # WS5: a ✅ of a multi-account item counts only with the account
        # proven (an old ✅ from before it had siblings does not).
        return "stale", (
            f"last success {when} did not prove WHICH account — verify: "
            f"./agent-login.py -t {site}"
        )
    how = f"checked {when}"
    if row["status"] == "safari" and row.get("safari"):
        how += f", Safari session until {row.get('safari_expires')}"
    elif site in CLAUDE_ACCOUNTS or site in CONSOLE_ACCOUNTS:
        how += f", logged in as {CLAUDE_ACCOUNTS.get(site) or CONSOLE_ACCOUNTS[site]}"
    elif row.get("flow") == ASSISTED_FLOW or row["status"] == "assisted":
        how += ", your session"
    else:
        how += ", login broker"
    return "ok", how


def verdict(row: dict, checks: dict[str, dict]) -> tuple[bool, str]:
    """(works for agents?, reason/detail) — one answer per login (✅ only for
    a fresh, proven check of a complete setup)."""
    state, why = row_state(row, checks)
    return state == "ok", why


def needs_sentinel(row: dict) -> bool:
    """A broker-backed row whose item has no authenticated sentinel yet: its
    checks use the old proof, it is never logged in by a scheduled run and
    cannot be promoted (C2) — a warning for agents, not a ❌."""
    return row.get("sentinel") is False and row["status"] in (
        "ready",
        "extra",
        "safari",
        "assisted",
    )


def _row_flags(row: dict) -> str:
    """Stage, quarantine and limiter state of a broker row, with the command
    that lifts each (empty for rows without them)."""
    site = row["site"]
    item = row.get("broker_site") or site  # switch -> its broker item eduid
    flags = []
    # WS5: where the account lives, its rights, the group alias
    if row_instance(row) in identity.ROLE_INSTANCES:
        flags.append(f"{row_instance(row)} browser")
    if row.get("privilege") == "admin":
        flags.append("ADMIN")
    if row.get("alias"):
        flags.append(f"default — alias {row['alias']}")
    if needs_sentinel(row):
        flags.append(
            "needs sentinel (old proof) — "
            + SENTINEL_HINT.format(site=item).split(";", 1)[1].strip()
        )
    q = row.get("quarantine")
    if isinstance(q, dict):
        flags.append(
            f"quarantined after {q.get('phase')} {q.get('at_text', '')} "
            f"(release: ./agent-login.py -Q {item})"
        )
    limit = row.get("limit") or {}
    if limit.get("state") in ("locked", "cooldown", "quarantined", "busy"):
        flags.append(f"{limit['state']}: {limit.get('reset') or limit.get('key')}")
    if row.get("held"):
        flags.append(f"⏸ held (rotation {row.get('held_txid') or '?'})")
    if row.get("stage") == "pending" and row["status"] in ("ready", "extra"):
        if site not in ON_DEMAND_SITES:
            flags.append(
                f"pending — no scheduled login until ./agent-login.py -p {site}"
            )
    if site in ON_DEMAND_SITES:
        flags.append(f"on demand — never checked daily; browser.py login {site}")
    if (
        row["status"] == "safari"
        and agent_route(site, row)
        and row.get("safari") is False
    ):
        flags.append(f"Safari session missing — renew: ./agent-login.py -L {site}")
    return "; ".join(flags)


def cookie_warning(rec: dict) -> str:
    """The overview's expiry warning of a check record (WS1b telemetry: the
    session cookie's days left, < 30 → warn), else ''."""
    days = rec.get("cookie_days_left")
    if isinstance(days, int) and not isinstance(days, bool) and days < 30:
        return f"session cookie expires in {days} day(s) — a visit renews it"
    return ""


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
    judged = [(r, *row_state(r, checks)) for r in rows]
    order = {
        "ok": 0,
        "on-demand": 0,
        "stale": 1,
        "unknown": 1,
        "unreachable": 1,
        "unchecked": 1,
        "held": 1,
        "unproven": 2,
    }
    judged.sort(key=lambda x: (order.get(x[1], 3), x[0]["name"].lower()))
    width = max(len(r["name"]) for r in rows)
    col = "agent_fill_origins"
    icons = {
        "ok": "✅",
        "on-demand": "⏯ ",
        "stale": "❓",
        "unknown": "❓",
        "unreachable": "❓",
        "unchecked": "❓",
        "held": "⏸ ",
        "unproven": "⚠️",
    }
    print(_c("2", f"     {'login'.ljust(width)}  {col}  status"))
    for r, state, why in judged:
        bw = str(bool(r.get("in_bitwarden"))).ljust(len(col))
        icon = icons.get(state, "❌")
        line = f"  {icon} {_c('1', r['name'].ljust(width))}  {bw}  "
        rec = checks.get(r["site"]) or {}
        if state == "failed":
            if rec.get("detail"):
                why += f" — {rec['detail']}"
            if rec.get("screenshot"):
                why += f"  📷 {rec['screenshot']}"
        flags = "; ".join(f for f in (_row_flags(r), cookie_warning(rec)) if f)
        if flags:
            why += f"  [{flags}]"
        print(line + (_c("2", why) if state == "ok" else why))
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
    # WS5: a group alias names its default member (after site ids, never
    # before). From the last snapshot only (no broker call just to resolve a
    # name); browser.py resolves aliases itself against the live listing.
    sites = _snapshot_sites()
    if any(s.get("site") == key for s in sites):
        return key
    hits = [
        str(s["site"])
        for s in sites
        if s.get("alias") == key and not s.get("refused") and s.get("site")
    ]
    if len(hits) == 1:
        print(f"↪ {key} = {hits[0]} (the group's default account)")
        return hits[0]
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


def manual_import(site: str) -> bool:
    """A Safari site whose import never runs unattended (``import_unattended``
    False): `browser.py login` refuses it, the daily check only checks it,
    and only `-t` (Albert) imports — through `browser.py import-safari`."""
    rule = safari_cookies.SAFARI_SITES.get(site)
    return rule is not None and not rule.import_unattended


def _no_submit_assisted(site: str) -> bool:
    """True for a broker site whose password the broker never submits and
    that has no Safari session import: `-t` then only checks (the login
    would only answer submit_disabled)."""
    if site in safari_cookies.SAFARI_SITES:
        return False
    if site in NO_SUBMIT_SITES:
        return True
    _health, sites = broker_state()
    entry = next((s for s in sites if s.get("site") == site), None)
    return entry is not None and is_no_submit(site, entry)


# One return per exit-code meaning.
def derived_result(run: BrowserRun) -> dict:  # pylint: disable=too-many-return-statements
    """The phase record of a `browser.py login` that wrote none (killed,
    an older browser.py): what its exit code tells."""
    if not run.started:  # the exec failed: nothing ran, nothing was sent
        return {"phase": "precheck", "code": "not_started", "submitted": False}
    if run.result:
        return run.result
    if run.killed:
        return {"phase": "unknown", "code": "killed", "submitted": None}
    rc = run.rc
    if rc in (LOGIN_TIMEOUT_RC, LOGIN_TIMEOUT_DIRTY_RC):
        return {"phase": "unknown", "code": "timeout", "submitted": None}
    if rc == 3:
        return {"phase": "precheck", "code": "broker_unavailable"}
    if rc == BUSY_RC:
        return {"phase": "precheck", "code": "busy"}
    if rc == 0:
        return {"phase": "ok", "code": "ok"}
    return {"phase": "unknown", "code": "internal"}


def _quarantine_after_kill(site: str, run: BrowserRun) -> None:
    """A login the RUNNER killed may have been inside the broker request:
    quarantine the broker item (browser.py could not write it)."""
    if not run.killed:
        return
    target = next((t for t in TARGETS if t.site == site), None)
    key = (target.broker_site if target and target.broker_site else "") or site
    with contextlib.suppress(als.StateError, OSError):
        als.quarantine(key, "unknown", "killed")


def failure_how(res: dict, login_rc: int | None, check_rc: int | None = None) -> str:
    """`NOT logged in — <phase text>: <code text>[ — detail]` for the overview."""
    text = phases.text(str(res.get("phase") or ""), str(res.get("code") or ""))
    how = f"NOT logged in — {text}"
    if res.get("detail"):
        how += f" — {res['detail']}"
    exits = f"browser.py login exit {login_rc}"
    if check_rc is not None:
        exits += f", check exit {check_rc}"
    return f"{how} ({exits})"


def run_test(site: str) -> int:
    """`-t SITE`: `_test_site`, then the site's latest identity proofs that
    did not say ``match`` (tp#1137) — the reason the latest record no longer
    shows."""
    site = resolve_site(site)
    rc = _test_site(site)
    lines = identity_history_lines(site, limit=TEST_HISTORY_LINES)
    if lines:
        print(f"ℹ️ {site}: identity proofs that did not say match (newest last):")
        for line in lines:
            print(f"  {line}")
        print(f"  all of them: ./agent-login.py -H {site}")
    return rc


# `-t` shows this many of a site's identity history entries (`-H`: all).
TEST_HISTORY_LINES = 3


def identity_history_lines(site: str, limit: int | None = None) -> list[str]:
    """One line per recorded non-``match`` identity proof of `site`
    (``agent_login_state.identity_history``), oldest first; `limit` keeps
    the newest ones."""
    with contextlib.suppress(als.StateError, OSError):
        hist = als.identity_history(site)
        if limit is not None:
            hist = hist[-limit:]
        out = []
        for e in hist:
            why = f" why={e['why']}" if e.get("why") else ""
            status = f" http={e['status']}" if e.get("status") is not None else ""
            code = f" code={e['code']}" if e.get("code") else ""
            detail = f" — {e['detail']}" if e.get("detail") else ""
            out.append(
                f"{e.get('at_text', '?')}  {e.get('state', '?')}  "
                f"identity={e.get('identity', '?')}{why}{status}{code}{detail}"
            )
        return out
    return []


def identity_history_action(site: str, *, as_json: bool) -> int:
    """`-H [SITE]`: the recorded identity proofs that did not say ``match``
    (checks.json ``identity_history``, tp#1137) of SITE, or of every site
    that has any. Read-only."""
    try:
        recs = als.checks()
    except (als.StateError, OSError) as exc:
        print(f"❌ checks.json unreadable: {exc}", file=sys.stderr)
        return 1
    sites = [resolve_site(site)] if site else sorted(recs)
    data = {s: list((recs.get(s) or {}).get("identity_history") or []) for s in sites}
    data = {s: h for s, h in data.items() if h or site}
    if as_json:
        print(json.dumps(data, indent=1))
        return 0
    if not any(data.values()):
        where = f" for {site}" if site else ""
        print(f"(no identity proof on record that did not say match{where})")
        return 0
    for s in data:
        print(f"{s}:")
        for line in identity_history_lines(s) or ["(none)"]:
            print(f"  {line}")
    return 0


def _test_site(site: str) -> int:
    """Real end-to-end test: `browser.py login` (Safari session first for the
    SAFARI_SITES, else the login broker) → session in the shared Chromium → the
    client's POSITIVE check (check URL / sentinel, in a background tab).

    The verdict is the positive check, never the login command's exit code
    alone. The result is recorded for the overview with WHERE it stopped
    (browser.py's phase record). A test never promotes a site. A site in a
    role instance (WS5) is tested there: the instance is started for the
    test if it was down, and stopped again afterwards (`instance_session`).
    """
    static = site in ASSISTED_SITES or site in safari_cookies.SAFARI_SITES
    if not static:
        entry = next((s for s in _snapshot_sites() if s.get("site") == site), None)
        if is_fill_only(entry):
            host = _hint_host((entry or {}).get("fill_origins")) or "<host>"
            print(
                f"❌ {site}: a fill-only item — the broker never logs in with it; "
                f'agents fill it into Albert\'s Safari: safari.py -L "<item>" -u {host}'
            )
            return 2
    inst = "" if static else broker_instance(site)
    if not inst:
        return _run_test(site)
    with instance_session(inst) as sess:
        if not sess.up:
            print(f"❌ {site}: the {inst} browser does not start (browser.py up)")
            rc = 1
        else:
            print(f"▶ {site}: in the {inst} browser (CLAUDE_BROWSER_INSTANCE={inst})")
            rc = _run_test(site)
    for problem in sess.problems:
        print(f"⚠️ {problem}")
    return rc


@contextlib.contextmanager
def site_session(site: str) -> Iterator[None]:
    """Every browser.py call inside runs in `site`'s browser instance: its
    static one (claude.ai private) or its broker item's role instance
    (WS5, from the last `sites` snapshot: `configured_instance`), started and
    stopped like `instance_session`. A stale snapshot is safe: browser.py
    itself refuses an item outside its instance."""
    inst = configured_instance(site)
    with instance_session(inst) as sess:
        yield
    for problem in sess.problems:
        print(f"⚠️ {problem}")


def broker_instance(site: str) -> str:
    """The role instance (admin / alt) the broker puts `site` into, else ''."""
    _health, sites = broker_state()
    entry = next((s for s in sites if s.get("site") == site), None)
    inst = identity.instance_of(entry) if entry else ""
    return inst if inst in identity.ROLE_INSTANCES else ""


def _run_test(site: str) -> int:
    """`run_test`'s body, in the current browser instance."""
    if site in ASSISTED_SITES or _eduid_sso_assisted(site) or _no_submit_assisted(site):
        # its login needs you: -g; -t only checks
        print(f"▶ {site}: your own login (./agent-login.py -g {site}); checking only")
        ok, how = assisted_check(site)
        if ok is None:
            print(f"⏸  {site}: {how}")
            return BUSY_RC
        record_check(site, ok, how)
        print(f"{'✅' if ok else '❌'} {site}: {how}")
        return 0 if ok else 2
    if manual_import(site):
        # `browser.py login` refuses it (never unattended): the explicit import
        print(f"▶ browser.py import-safari {site}  (your Safari session, by hand)")
        login = run_browser(
            "import-safari",
            site,
            timeout_s=browser_timeout("import-safari"),
            result=True,
        )
    else:
        # WS3: a broker site not usable for its current config takes the
        # promotion budget (one login, `-E` re-arms): no unbudgeted bypass.
        claimed, refusal = _trial_claim_for_test(site)
        if refusal is not None:
            print(f"❌ {site}: {refusal} (no login tried)")
            return 2
        print(
            f"▶ browser.py login {site}  (Safari session or login broker; "
            "you see no password)" + ("; budgeted: one login" if claimed else "")
        )
        login = _budgeted_login(site, claimed)
    res = derived_result(login)
    failed = login_run_failure(login)
    if failed is not None:  # 125 or an outer kill: never retried, no check
        _quarantine_after_kill(site, login)
        print(f"❌ {site}: {failed}")
        record_check(site, False, failed, res)
        return 1 if login.rc is None else login.rc
    login_rc = int(login.rc or 0)
    if login_rc != 0:
        print(f"❌ login {site} failed (exit {login_rc}) at {res.get('phase')}")
    print(f"▶ browser.py logged-in {site}  (positive check on the check URL)")
    rc, check = probe(site, quiet=False)
    if BUSY_RC in (rc, login_rc):
        held = held_how(res=res) if login_rc == BUSY_RC else None
        how = held or BUSY_HOW
        print(f"⏸  {site}: {how}")
        record_check(
            site, None, how, res if held else {"phase": "precheck", "code": "busy"}
        )
        return BUSY_RC
    if rc == 0:
        how = INNER_TIMEOUT_OK if login_rc == LOGIN_TIMEOUT_RC else "logged in"
        record_check(
            site, True, how, {**res, **(check or {}), "phase": "ok", "code": "ok"}
        )
    else:
        if login_rc == 0:  # the login said yes, the check says no
            res = {**res, "phase": "client-proof", "code": "logged_out"}
        how = failure_how(res, login_rc, rc)
        record_check(site, False, how, res)
    print(
        ("✅ " if rc == 0 else "❌ ")
        + f"{site}: shared Chromium is "
        + ("logged in" if rc == 0 else f"NOT logged in — stopped at {res.get('phase')}")
        + " (positive check)"
    )
    return rc or login_rc


# Where a manual login starts (logged out, each redirects to its login page).
MANUAL_START = {
    "anibis": "https://www.anibis.ch/fr/user/searches",
    "tutti": "https://www.tutti.ch/de/myads/active",
    "ricardo": "https://www.ricardo.ch/de/my-ricardo/saved/articles/",
    "galaxus": "https://www.galaxus.ch/de/orders",
    "galaxus-de": "https://www.galaxus.de/de/orders",
}
# Guided logins that go straight to the shown window (`assisted-login -a`):
# the relayed headless tab keeps the headless browser's bot fingerprint, which
# these IdPs (Akamai Bot Manager + reCAPTCHA) reject even for a human's typing.
# Every no-submit broker site (`is_no_submit`) takes the window too.
WINDOW_START = frozenset({"galaxus", "galaxus-de"})


def manual_login(site: str, force: bool = False) -> int:
    """`-g SITE`: the guided login — a human login in the shared Chromium.

    Sites whose guided flow is just "Albert logs in by hand" (the marketplace
    sites behind a human check, and the assisted sites he logs into with an
    email code / SSO) go through `browser.py assisted-login SITE` — confirmed on
    the terminal, then a remote view of a headless tab (the window only as a
    fallback). The claude.ai accounts and SWITCH keep their own window flows
    (`assisted_login`). You type the password yourself (paste it from
    Bitwarden) — no agent sees it; agents then use the session until the site
    expires it. `force` (-F): start even with unregistered CDP clients
    attached (`assisted-login -f`; the window flows' transaction the same).
    """
    site = resolve_site(site)
    if site in VIEWER_SITES:
        return viewer_login(site, force=force)
    if site in ASSISTED_SITES or site in EDUID_SSO_SITES:
        return assisted_login(site, force=force)
    start = MANUAL_START.get(site)
    window = site in WINDOW_START or _no_submit_assisted(site)
    if not start and not window:
        known = ", ".join([*MANUAL_START, *sorted(ASSISTED_SITES | EDUID_SSO_SITES)])
        print(f"❌ no guided login known for {site!r} (known: {known})")
        return 2
    # A no-submit site without a MANUAL_START URL starts at its broker item's
    # login URL (browser.py resolves it). WS5: in the item's own instance.
    with site_session(site):
        return assisted_login_cmd(site, start, force=force, window=window)


def assisted_login_argv(
    site: str, start: str | None = None, force: bool = False, window: bool = False
) -> list[str]:
    """The browser.py arguments `assisted-login SITE [-u START] [-a] [-f]`."""
    argv = ["assisted-login", site]
    if start:
        argv += ["-u", start]
    if window:
        argv.append("-a")
    if force:
        argv.append("-f")
    return argv


def assisted_login_cmd(
    site: str, start: str | None = None, force: bool = False, window: bool = False
) -> int:
    """`browser.py assisted-login SITE [-u START] [-a] [-f]` (it asks on the
    terminal; `window`: straight to the shown window, path A).

    No time limit: a guided login waits for Albert (it bounds itself)."""
    return _browser(*assisted_login_argv(site, start, force, window), timeout_s=None)


def viewer_login(site: str, force: bool = False) -> int:
    """An assisted site (email code / SSO) through `assisted-login`, with the
    pre- and post-check (and the recorded result) of `assisted_login`."""
    ok, how = assisted_check(site)
    if ok:
        print(f"✅ {site}: {how} — nothing to do")
        record_check(site, True, how)
        return 0
    with site_session(site):
        rc = assisted_login_cmd(browser_site(site), force=force)
    ok, how = assisted_check(site)
    if ok is not None:
        record_check(site, ok, how)
    print(f"{'✅' if ok else '❌'} {site}: {how}")
    if rc not in (0, 2):
        return rc
    return 0 if ok else 2


ASSISTED_SITES = {t.site for t in TARGETS if t.flow == ASSISTED_FLOW}
# -g works for these too: `browser.py login` with the window shown.
EDUID_SSO_SITES = {t.site for t in TARGETS if t.flow == EDUID_SSO_FLOW}
# Assisted sites whose guided login is a plain human login → the remote view
# (`browser.py assisted-login`). claude.ai keeps its own flow: its magic link
# arrives by mail and must be opened in the shared browser itself.
VIEWER_SITES = ASSISTED_SITES - set(CLAUDE_ACCOUNTS)


def assisted_check(site: str) -> tuple[bool | None, str]:
    """(works?, how) for a site you log into yourself; never starts a login."""
    ok, how, _res = assisted_probe(site)
    return ok, how


def assisted_probe(site: str) -> tuple[bool | None, str, dict | None]:
    """`assisted_check` plus browser.py's result record (a tri-state site's
    ``server`` / ``proof`` / ``cookie_days_left``), None when there is none."""
    with site_session(site):
        return _assisted_check(site)


def assisted_verdict(site: str) -> tuple[bool | None, str, dict | None]:
    """What `-c` uses: a tri-state site's full probe (its result record),
    every other assisted site's plain `assisted_check`."""
    if site in TRISTATE_SITES:
        return assisted_probe(site)
    ok, how = assisted_check(site)
    return ok, how, None


# WS1b D8: built-in sites whose `logged-in` is tri-state (its result record
# says `indeterminate` when it cannot tell — never "logged out").
TRISTATE_SITES = frozenset({"notion", "slack", "openai"})


def _login_hint(site: str) -> str:
    """How a logged-out site you own the session of gets back (fixed text)."""
    if agent_route(site):
        return f"an agent runs ./agent-login.py -L {site}"
    return f"log in once: ./agent-login.py -g {site}"


# One return per verdict (busy, tri-state, plain, claude.ai).
def _assisted_check(  # pylint: disable=too-many-return-statements
    site: str,
) -> tuple[bool | None, str, dict | None]:
    """(True, how) logged in, (False, how) not, (None, how) it cannot be told
    right now: a guided login owns the browser (busy) or a tri-state check
    could not decide — re-check later, it says nothing either way."""
    busy = guided_busy()
    if busy:
        return None, f"{busy} — re-check later", None
    hint = _login_hint(site)
    if site in TRISTATE_SITES:
        run = run_browser(
            "logged-in",
            site,
            timeout_s=browser_timeout("logged-in"),
            quiet=True,
            result=True,
        )
        res = run.result or {}
        if run.rc == BUSY_RC:
            return None, BUSY_RECHECK, None
        if run.rc == 0:
            return True, "logged in", res
        code = str(res.get("code") or "")
        if code == "logged_out":
            return False, f"NOT logged in — {hint}", res
        if code == "wrong_account":
            return False, "logged in as ANOTHER account — " + hint, res
        return None, "could not tell — " + phases.text("client-proof", code), res
    if site in CONSOLE_ACCOUNTS:
        ok, how = _console_check(site, hint)
        return ok, how, None
    if site not in CLAUDE_ACCOUNTS:
        rc = _browser(
            "logged-in", site, quiet=True, timeout_s=browser_timeout("logged-in")
        )
        if rc == BUSY_RC:
            return None, BUSY_RECHECK, None
        if rc == 0:
            return True, "logged in", None
        return False, f"NOT logged in — {hint}", None
    ok, how = _claude_check(site, hint)
    return ok, how, None


BUSY_RECHECK = "busy: guided login in progress — re-check later"


def _console_check(site: str, hint: str) -> tuple[bool | None, str]:
    """`_assisted_check` for a Claude Console account: logged in, and as the
    right account (one Console session per browser profile)."""
    email = console_account_email()
    if email is None:
        return None, "could not tell — the Console did not answer; re-check later"
    if not email:
        return False, f"NOT logged in to the Claude Console — {hint}"
    want = CONSOLE_ACCOUNTS[site].lower()
    if email != want:
        where = SITE_INSTANCE.get(site, "default")
        return False, (
            f"the {where} browser instance holds the Console account {email}, not {want}"
        )
    return True, f"logged in as {email}"


def _claude_check(site: str, hint: str) -> tuple[bool | None, str]:
    """`_assisted_check` for a claude.ai account: the right account, and for
    the work one the Team admin billing page."""
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
    rc = (
        _browser(
            "logged-in", "anthropic", quiet=True, timeout_s=browser_timeout("logged-in")
        )
        if site == "anthropic"
        else 0
    )
    if rc == BUSY_RC:
        return None, BUSY_RECHECK
    if rc != 0:
        return False, f"{email} logged in, but the Team admin billing page fails"
    return True, f"logged in as {email}"


def assisted_login(site: str, force: bool = False) -> int:
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
    with site_session(site):
        try:
            with guided_window(site, force=force) as win:
                if site in SITE_INSTANCE and site in CLAUDE_ACCOUNTS:
                    claude_login_by_hand(site)
                else:
                    # Guided: the site's window flow waits for Albert — no limit.
                    _browser("login", browser_site(site), timeout_s=None)
        except RuntimeError:
            return 1
    ok, how = assisted_check(site)
    if ok is not None:
        record_check(site, ok, how)
    print(f"{'✅' if ok else '❌'} {site}: {how}")
    if not win.restored:
        return 1
    return 0 if ok else 2


BUSY_HOW = "busy: guided login in progress — skipped, re-check later"
UNREACHABLE_HOW = "unreachable off-LAN (Cloudflare Access) — not checked"


Outcome = tuple[bool | None, str, dict | None]

# WS5 verdicts of a check that cannot tell WHICH account right now (the
# site's account API is unclear, the broker rate-limits or blocks the site's
# account checks): "could not tell" — never a login, never a failure mail.
IDENTITY_UNKNOWN_CODES = frozenset(
    {"identity_indeterminate", "rate_limited", "identity_blocked"}
)
# Verdicts a login cannot fix: ❌ without a login attempt.
IDENTITY_FATAL_CODES = frozenset(
    {"privilege_mismatch", "wrong_instance", "identity_unproven"}
)


def identity_text(res: dict | None) -> str:
    """The fixed text of a check's phase/code (never its detail)."""
    r = res or {}
    return phases.text(str(r.get("phase") or ""), str(r.get("code") or ""))


def _identity_login_outcome(run: BrowserRun, res: dict, routes: list[str]) -> Outcome:
    """`_after_login` when the login's verify ran the identity proof: exit 0
    = ✅; an identity verdict that cannot tell (a blocked or rate-limited
    challenge, typically right after a replaced foreign session) = unknown;
    anything else = ❌."""
    if run.rc == 0:
        how = f"logged in again ({routes[-1] if routes else 'browser.py login'})"
        return True, how, {**res, "phase": "ok", "code": "ok"}
    if str(res.get("code") or "") in IDENTITY_UNKNOWN_CODES:
        return None, f"could not tell — {identity_text(res)}", res
    return False, failure_how(res, run.rc), res


def probe(site: str, *, quiet: bool = True) -> tuple[int, dict | None]:
    """The free `browser.py logged-in SITE` check: (exit code, its phase
    record — strict or old proof, final origin)."""
    run = run_browser(
        "logged-in",
        site,
        timeout_s=browser_timeout("logged-in"),
        quiet=quiet,
        result=True,
    )
    return (KILLED_RC if run.rc is None else run.rc), run.result


# One return per verdict of the free check, then the login's.
def ensure_logged_in(  # pylint: disable=too-many-return-statements
    site: str, gate: tuple[str, str] | None = None
) -> Outcome:
    """(logged in?, how, phase record) — positive check, else ONE scheduled
    `browser.py login -s`, then re-check.

    None = busy (exit 75: a guided login owns the browser): never a login
    attempt, never "logged out". `gate` (code, why): the site may not be
    logged in by a scheduled run (pending, quarantined, locked, …) — the free
    check still runs, the login does not. A login whose deadline fired is
    retried ONCE, and only when its record proves it stopped BEFORE the broker
    request (phase precheck); 125, an outer kill and any later phase are
    never retried — the broker may have typed the password."""
    rc, check = probe(site)
    code = str((check or {}).get("code") or "")
    if rc == BUSY_RC:
        return None, BUSY_HOW, {"phase": "precheck", "code": "busy"}
    if rc != 0 and code == "access_gated":
        # Off-LAN behind Cloudflare Access: unreachable, never a login.
        return None, UNREACHABLE_HOW, {**(check or {}), "phase": "precheck"}
    if rc != 0 and code in IDENTITY_UNKNOWN_CODES:
        # WS5: the account cannot be told right now — unknown, never a login.
        return None, f"could not tell — {identity_text(check)}", check
    if rc == 0:
        weak = gate is not None and gate[0] == "needs_sentinel"
        how = "needs sentinel (old proof)" if weak else "logged in"
        return True, how, {**(check or {}), "phase": "ok", "code": "ok"}
    if code in IDENTITY_FATAL_CODES:
        # A login cannot fix it (wrong admin rights, wrong instance, unproven).
        return False, f"NOT usable — {identity_text(check)}", check
    if gate is not None and code == "wrong_account":
        # WS5: the check itself cleared the foreign session (browser.py); a
        # gated row is not logged in — ❌ with that verdict, no login.
        return (
            False,
            f"NOT logged in — another account's session was here (cleared); {gate[1]}",
            check,
        )
    if gate is not None:
        gate_code, why = gate
        return (
            False,
            f"NOT logged in — {why}",
            {**(check or {}), "phase": "precheck", "code": gate_code},
        )
    # A wrong_account probe already cleared the foreign session: the login's
    # free check sees "logged out" (no challenge); its verify is the second.
    for attempt in (1, 2):
        run = run_browser(
            "login",
            site,
            "-s",
            timeout_s=browser_timeout("login"),
            capture=True,
            result=True,
        )
        outcome = _after_login(site, run, retry_left=attempt == 1)
        if outcome is not None:
            return outcome
        print(
            f"↻ {site}: {_inner_timeout_text()} before the broker request — retrying once"
        )
    return False, f"NOT logged in ({_inner_timeout_text()}, twice)", None  # not reached


INNER_TIMEOUT_OK = "logged in (after an inner timeout)"


def _inner_timeout_text() -> str:
    """How a login whose inner deadline fired is described."""
    return f"browser.py login timed out after {login_timeout_s():g}s"


def _after_inner_timeout(
    check_rc: int, res: dict, *, retry_left: bool
) -> Outcome | None:
    """Exit 124 (tabs closed): the check decides; a failed check → retry once,
    but only when the record proves the deadline fired before the broker
    request (phase precheck)."""
    if check_rc == 0:
        return True, INNER_TIMEOUT_OK, {"phase": "ok", "code": "ok"}
    if retry_left and res.get("phase") == "precheck":
        return None
    return False, failure_how(res, LOGIN_TIMEOUT_RC, check_rc), res


def login_run_failure(run: BrowserRun) -> str | None:
    """The NOT-logged-in wording of a login that must not be retried — its
    tab cleanup is unconfirmed (125) or the runner had to kill it — else None.
    Both reach the failure mail (so does a child that never started)."""
    if not run.started:
        return "NOT logged in (browser.py could not be started)"
    if run.killed:
        return (
            f"NOT logged in (browser.py login killed by the runner after "
            f"{browser_timeout('login'):g}s (inner watchdog failed))"
        )
    if run.rc == LOGIN_TIMEOUT_DIRTY_RC:
        return (
            f"NOT logged in ({_inner_timeout_text()}; owned tabs may remain — see "
            "browser.py journal, event owned_target)"
        )
    return None


# One return per verdict of the login run, in the order they are decided.
def _after_login(  # pylint: disable=too-many-return-statements
    site: str, run: BrowserRun, *, retry_left: bool
) -> Outcome | None:
    """`ensure_logged_in`'s verdict after one `browser.py login`; None = retry."""
    res = derived_result(run)
    failed = login_run_failure(run)
    if failed is not None:
        _quarantine_after_kill(site, run)
        return False, failed, res
    routes = [
        line.split("route:", 1)[1].strip()
        for line in run.stdout.splitlines()
        if "route:" in line
    ]
    if res.get("identity") and run.rc in (0, 2):
        # WS5: the login's own verify ran the identity proof — its verdict is
        # final (a re-probe would cost another broker challenge, ≤ 2 a run).
        return _identity_login_outcome(run, res, routes)
    held = held_how(res=res) if run.rc == BUSY_RC else None
    if held:  # tp#965: a rotation holds the site — a skip like busy
        return None, held, res
    rc, check = probe(site)
    if BUSY_RC in (rc, run.rc):
        return None, BUSY_HOW, {"phase": "precheck", "code": "busy"}
    if run.rc == LOGIN_TIMEOUT_RC:
        return _after_inner_timeout(rc, res, retry_left=retry_left)
    if rc == 0:
        how = f"logged in again ({routes[-1] if routes else 'browser.py login'})"
        return True, how, {**res, **(check or {}), "phase": "ok", "code": "ok"}
    if run.rc == 0:
        res = {**res, "phase": "client-proof", "code": "logged_out"}
    return False, failure_how(res, run.rc), res


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
    """What to do when `site` is logged out (depends on its login flow)."""
    here = Path(__file__).resolve().parent
    flow = next((t.flow for t in TARGETS if t.site == site), "")
    if agent_route(site):
        return (
            f"an agent runs ./agent-login.py -L {site} (through your Safari; "
            f"it names the step only you can do, if any) (in {here})"
        )
    if flow == ASSISTED_FLOW or (flow != SAFARI_FLOW and _no_submit_assisted(site)):
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
    print("▶ shared Chromium is down — starting it (browser.py up, headless)")
    _browser("up", quiet=True, timeout_s=browser_timeout("up"))
    return browser_mode() is not None


def _check_assisted_row(
    site: str,
    failed: list[tuple[str, str]],
    deferred: list[str] | None = None,
) -> None:
    """`-c` for a site you log into yourself: check only; busy or a
    tri-state "cannot tell" = unknown. A first "logged out" is re-probed ONCE
    at the end of the run (`deferred`, `recheck_deferred`) before it counts;
    the failure mail lists it only from its second failed RUN (O10)."""
    ok, how, res = assisted_verdict(site)
    if ok is None:
        print(f"⏸  {site}: {how}")
        record_check(site, None, how, res or {"phase": "precheck", "code": "busy"})
        return
    if not ok and deferred is not None:
        print(f"↻ {site}: {how} — re-checked at the end of this run")
        deferred.append(site)
        return
    _record_assisted(site, ok, how, res, failed)


def _record_assisted(
    site: str,
    ok: bool,
    how: str,
    res: dict | None,
    failed: list[tuple[str, str]],
) -> None:
    """Record an assisted row's verdict; a failure joins `failed` (the mail)
    only at ``invalid_streak`` ≥ 2."""
    print(f"{'✅' if ok else '❌'} {site}: {how}")
    # a check that named another account keeps that verdict (N7)
    code = (
        "wrong_account" if (res or {}).get("code") == "wrong_account" else "logged_out"
    )
    result = res if ok else {**(res or {}), "phase": "client-proof", "code": code}
    record_check(site, ok, how, result)
    if ok:
        return
    streak = int((last_checks().get(site) or {}).get("invalid_streak") or 0)
    if streak >= ASSISTED_MAIL_STREAK:
        failed.append((site, how))
    else:
        print(
            f"   {site}: first failed run — the mail waits for a second one "
            f"(≥ {als.STREAK_SPACING_S / 3600:g} h later)"
        )


# The failure mail names an assisted site only after this many failed RUNS.
ASSISTED_MAIL_STREAK = 2


def recheck_deferred(deferred: list[str], failed: list[tuple[str, str]]) -> None:
    """End of `-c`: the one re-probe of each assisted row that read "logged
    out" earlier in this run; it decides this run's verdict only."""
    for site in deferred:
        ok, how, res = assisted_verdict(site)
        if ok is None:
            print(f"⏸  {site}: {how}")
            record_check(site, None, how, res or {"phase": "precheck", "code": "busy"})
            continue
        _record_assisted(site, ok, how, res, failed)


# One early return per gate, in the order they are checked.
def schedule_gate(row: dict) -> tuple[str, str] | None:  # pylint: disable=too-many-return-statements
    """Why a SCHEDULED run must not log `row` in (code, text with the exact
    command that lifts it), or None. Pure broker rows only: a Safari import
    and the edu-ID SSO click are free — `browser.py login -s` gates their
    broker fallback itself."""
    site = row["site"]
    if row["status"] not in ("ready", "extra") or row.get("flow") in (
        SAFARI_FLOW,
        EDUID_SSO_FLOW,
    ):
        return None
    q = row.get("quarantine")
    if isinstance(q, dict):
        return "quarantined", (
            f"quarantined after {q.get('phase')} {q.get('at_text', '')} — release: "
            f"./agent-login.py -Q {site}"
        )
    if needs_sentinel(row):
        return "needs_sentinel", (
            f"needs sentinel — no scheduled login with the old proof; find one: "
            f"browser.py logged-in {site} -x 'CSS'"
        )
    risk = [c for c in row.get("onboarding_risk") or [] if SITE_ID_RE.match(c)]
    if risk:
        return "onboarding_risk", (
            f"onboarding risk ({', '.join(risk)}) — fix the item, see ./agent-login.py -V"
        )
    limit = row.get("limit") or {}
    if limit.get("state") in ("locked", "cooldown", "quarantined"):
        return str(limit["state"]), (
            f"{limit['state']} — {limit.get('reset') or 'sudo install/install.sh -r ' + site}"
        )
    if row.get("stage") != "usable":
        return "pending", f"pending — promote: ./agent-login.py -p {site}"
    promoted = row.get("promoted_config")
    if not promoted or row.get("promoted_config_v") != onboarding.CONFIG_V:
        return "config_unknown", (
            "promoted with an older (or no) config record — adopted at the next "
            "./agent-login.py -S after a fresh strict ✅ (logged out: "
            f"./agent-login.py -t {site} gives one), or re-promote: "
            f"./agent-login.py -p {site}"
        )
    if row.get("config") and promoted != row.get("config"):
        return (
            "changed",
            f"changed since its promotion — re-promote: ./agent-login.py -p {site}",
        )
    return None


def check_only_gate(row: dict) -> tuple[str, str] | None:
    """`schedule_gate`, plus: a Safari site whose import must not run
    unattended (``import_unattended``) is only checked by the daily run, and
    a multi-account row whose account cannot be proven (WS5) is never logged
    in (a proof-ready one goes through the gates below like any row)."""
    if account_unproven(row):
        return "identity_unproven", unproven_text(row)
    rule = safari_cookies.SAFARI_SITES.get(row["site"])
    if row.get("flow") == SAFARI_FLOW and rule is not None:
        if not rule.import_unattended:
            site = row["site"]
            if agent_route(site, row):
                return "manual_import", (
                    f"the Safari import runs by hand only{route_hint(site, row)} "
                    f"(a plain import: -t {site})"
                )
            return "manual_import", (
                f"the Safari import runs by hand only — ./agent-login.py -t {site}"
            )
    return schedule_gate(row)


def refresh_step(site: str, check: dict | None, how: str) -> str:
    """A fresh ✅ of a site with a session refresher (NPM): when its stored
    token has less than ``REFRESH_MIN_LEFT_S`` left (the free check read it,
    ``session_left_s``), `browser.py login SITE -F` has the broker re-export
    it renewed. Refresh-only never logs in or submits a password, so it also
    runs for pending and quarantined sites — and it never quarantines. Returns
    the row's `how`, with what happened."""
    left = (check or {}).get("session_left_s")
    if isinstance(left, bool) or not isinstance(left, int):
        return how
    if left >= REFRESH_MIN_LEFT_S:
        return how
    run = run_browser(
        "login",
        site,
        "-F",
        timeout_s=browser_timeout("login"),
        capture=True,
        result=True,
    )
    res = run.result or {}
    if run.rc == 0 and res.get("refresh") == "refreshed":
        return f"{how} (token renewed)"
    if run.rc == 0:
        why = res.get("refresh") or "not needed"
        return f"{how} (token NOT renewed: {why}; {max(left, 0) // 3600} h left)"
    print(f"⚠️ {site}: refresh-only run exit {run.rc} — the session may end soon")
    return f"{how} (token refresh failed, exit {run.rc})"


# One return per outcome of the renewal, in the order they are decided.
def renew_step(  # pylint: disable=too-many-return-statements
    site: str, row: dict, check: dict | None, how: str
) -> Outcome:
    """A fresh ✅ whose session is due for renewal (``renew_due``: the item's
    ``agent_max_session_days`` reached since the last proven fresh login —
    servers like Calibre-Web Automated end a session a fixed time after its
    login, however much it is used): ONE scheduled `browser.py login SITE -s`,
    which logs in fresh while the old session still works. The scheduled
    gates apply (`schedule_gate`: pending, quarantined, locked … → no login,
    only a note). A failed renewal with the old session still working stays
    ✅ with the reason in `how`."""
    res: dict = check or {}
    if not res.get("renew_due"):
        return True, how, res
    gate = schedule_gate(row)
    if gate is not None:
        return True, f"{how} (session renewal due — {gate[1]})", res
    run = run_browser(
        "login",
        site,
        "-s",
        timeout_s=browser_timeout("login"),
        capture=True,
        result=True,
    )
    out = derived_result(run)
    failed = login_run_failure(run)
    if failed is not None:
        _quarantine_after_kill(site, run)
        return False, failed, out
    if run.rc != 0:
        return False, failure_how(out, run.rc), out
    renewal = out.get("renewal")
    if renewal == "renewed":
        return True, f"{how} (session renewed with a fresh login)", out
    if renewal == "failed":
        text = phases.text(
            str(out.get("renewal_phase") or ""), str(out.get("renewal_code") or "")
        )
        print(f"⚠️ {site}: session renewal failed — {text}")
        return True, f"{how} (session renewal FAILED — {text})", out
    return True, f"{how} (session renewal: {renewal or 'not needed'})", out


def _record_unchecked(data: dict | None, code: str, why: str) -> None:
    """A run that could not check anything records `unknown` for every
    checkable row (never success, never "logged out")."""
    for row in (data or {}).get("rows") or []:
        if row["status"] in ("ready", "extra", "safari", "assisted"):
            record_check(row["site"], None, why, {"phase": "precheck", "code": code})


def _unproven_skipped(row: dict) -> bool:
    """`-c` for a multi-account row (WS5): no check can tell which account the
    browser holds, so it is neither checked nor logged in — recorded as
    "could not tell" with its code, never as a failure (no mail). True when
    skipped. A proof-ready one is checked (its check proves the account)."""
    if not account_unproven(row):
        return False
    how = unproven_text(row)
    print(f"⚠️  {row['site']}: {how}")
    record_check(
        row["site"],
        None,
        how,
        {
            "phase": "client-proof",
            "code": "identity_unproven",
            "instance": row_instance(row),  # nothing ran: where it lives
        },
    )
    return True


def check_all(*, mail: bool = False) -> int:  # pylint: disable=too-many-branches
    """Every usable site (Safari or broker): logged in? If not — and a
    scheduled login is allowed (`schedule_gate`) — ONE `browser.py login -s`.
    One line per site; with `mail`, ONE mail when any stays logged out. The
    exit code is `check_exit`'s. Waits for the network first; still offline
    after 5 min = every row `unknown`, no mail."""
    if not wait_for_network():
        print(f"⏸  no network ({NETWORK_HOST} does not resolve) — skipped, no mail")
        _record_unchecked(overview(), "offline", "no network — not checked")
        return 0
    if not ensure_browser_up():
        how = "down, and `browser.py up` did not start it"
        print(f"❌ shared Chromium: {how} — no site checked")
        _record_unchecked(overview(), "browser_down", f"shared Chromium {how}")
        if mail:
            send_mail(
                "agent-login: shared Chromium does not start",
                f"The daily agent-login check found the shared Chromium {how}.\n"
                "No site was checked. Fix: run `browser.py up` and read its error, "
                "then ./agent-login.py -c.\n",
            )
        return 1
    # Tabs that killed browser.py runs left (since the last run) go first (tp#845).
    _browser("reap-owned", quiet=True, timeout_s=browser_timeout("reap-owned"))
    data = overview()
    failed: list[tuple[str, str]] = []
    if not data["broker_ok"]:
        print(f"❌ login broker: {data['broker']}")
        failed.append(("login broker", data["broker"]))
    psl = report_psl()  # once per run, never a per-site gate
    if psl:
        failed.append(("onboarding review", psl))
    failed += toolchain_report()  # WS1b D9: after a brew upgrade
    by_instance: dict[str, list[dict]] = {}
    for row in data["rows"]:
        by_instance.setdefault(check_instance(row), []).append(row)
    deferred: list[str] = []
    for row in by_instance.pop("", []):
        if not _check_row(row, failed, ensure_browser_up, deferred):
            break
    recheck_deferred(deferred, failed)
    for inst in identity.ROLE_INSTANCES:
        _check_role_instance(inst, by_instance.pop(inst, []), failed)
    if failed and mail:
        send_mail(*failure_mail(failed))
    return check_exit(failed)


def check_exit(failed: list[tuple[str, str]]) -> int:
    """`-c`'s exit code: 0 when the run completed and every failure is a site
    whose ❌ is in last-check.json — infra/status's mac/agent-login row
    reports those, so the daily job's launchd row must not report them a
    second time (tp#1127). 1 when anything else failed (broker, a browser,
    toolchain, Public Suffix List) or a site's ❌ is not on record there; a
    crash stays an uncaught exit 1."""
    if not failed:
        return 0
    try:
        legacy = als.read(als.LEGACY_FILE, strict=True)
    except (als.StateError, OSError):
        return 1
    for label, _how in failed:
        rec = legacy.get(label)
        if not (isinstance(rec, dict) and rec.get("ok") is False):
            return 1
    return 0


def check_instance(row: dict) -> str:
    """The role instance (WS5: admin / alt) `-c` checks `row` in; '' for the
    default one — a static site's own instance (claude.ai private) is
    handled by its assisted check itself."""
    inst = row_instance(row)
    return inst if inst in identity.ROLE_INSTANCES else ""


def needs_browser(row: dict) -> bool:
    """Does `-c` drive a browser for `row` (else it only records why not)?"""
    if row["status"] not in ("ready", "extra", "safari") or account_unproven(row):
        return False
    rule = safari_cookies.SAFARI_SITES.get(row["site"])
    return rule is None or rule.auto


def _with_instance(res: dict | None, inst: str) -> dict | None:
    """`res` with the row's instance when browser.py did not record one."""
    if res is None:
        return None
    return res if isinstance(res.get("instance"), str) else {**res, "instance": inst}


def _check_role_instance(
    inst: str, rows: list[dict], failed: list[tuple[str, str]]
) -> None:
    """`-c` for the rows of role instance `inst`: the rows that need no
    browser first, then — only when some row needs one — the instance is
    started if it was down, its rows checked (same gates as the shared
    browser), and stopped again if this run started it and nothing else
    uses it (`instance_session`)."""
    busy = [r for r in rows if needs_browser(r)]
    for row in rows:
        if row not in busy:
            _check_row(row, failed, lambda: True)
    if not busy:
        return
    with instance_session(inst) as sess:
        if not sess.up:
            how = f"the {inst} browser is down and `browser.py up` did not start it"
            print(f"❌ {inst} browser: {how} — its sites not checked")
            failed.append((f"{inst} browser", how))
            for row in busy:
                record_check(
                    row["site"],
                    None,
                    how,
                    {"phase": "precheck", "code": "browser_down", "instance": inst},
                )
        else:
            for row in busy:
                if not _check_row(row, failed, lambda: browser_mode() is not None):
                    break
    for problem in sess.problems:  # a failed stop, an unreadable client list
        print(f"❌ {problem}")
        failed.append((f"{inst} browser", problem))


# One return per way a row ends (skipped, recorded, checked, browser gone).
def _check_row(  # pylint: disable=too-many-return-statements
    row: dict,
    failed: list[tuple[str, str]],
    alive: Callable[[], bool],
    deferred: list[str] | None = None,
) -> bool:
    """`-c` for one row in the CURRENT browser instance; False when the
    browser went away (the caller stops: never fail every remaining site).
    `deferred`: where a first-failed assisted row waits for its re-probe."""
    site, inst = row["site"], row_instance(row)
    if site in ON_DEMAND_SITES:
        # WS1b D6: never checked or logged in by the daily run; its row
        # leaves the legacy projection so infra/status does not judge it.
        print(f"⏭  {site}: on demand — not checked")
        als.drop_legacy(site)
        return True
    if row["status"] == "assisted":
        _check_assisted_row(site, failed, deferred)
        return True
    if row["status"] == "unchecked":  # the broker cannot read Bitwarden
        record_check(
            site,
            None,
            "broker unreadable — not checked",
            {"phase": "precheck", "code": "broker_unavailable", "instance": inst},
        )
        return True
    if row["status"] not in ("ready", "extra", "safari") or _unproven_skipped(row):
        return True
    held = held_how(row)
    if held:
        # tp#965: like busy — no login, no failure mail, no quarantine
        print(f"⏸  {site}: {held}")
        record_check(
            site,
            None,
            held,
            {
                "phase": "precheck",
                "code": "held",
                "txid": row.get("held_txid"),
                "instance": inst,
            },
        )
        return True
    rule = safari_cookies.SAFARI_SITES.get(site)
    if rule is not None and not rule.auto:
        print(f"⏭  {site}: not imported unattended (see SAFARI_SITES)")
        return True
    if not alive():
        # The browser went away mid-run: stop instead of failing every site.
        how = "the browser went down mid-run and did not restart"
        print(f"❌ {site}: {how} — remaining sites not checked")
        failed.append(("shared Chromium", how))
        return False
    ok, how, res = ensure_logged_in(site, gate=check_only_gate(row))
    if ok is None:
        print(f"⏸  {site}: {how}")
        record_check(site, None, how, _with_instance(res, inst))
        return True
    if ok and row.get("session_refresh"):
        how = refresh_step(site, res, how)
    if ok and (res or {}).get("renew_due"):
        ok, how, res = renew_step(site, row, res, how)
    print(f"{'✅' if ok else '❌'} {site}: {how}")
    record_check(site, ok, how, _with_instance(res, inst))
    if not ok:
        failed.append((site, how))
    return True


def prune_removed(data: dict) -> list[str]:
    """After a FRESH live broker listing (`-S`, `-r`): drop the state of
    sites that are neither planned nor listed any more (e.g. zendesk)."""
    rows = data.get("rows") or []
    if not data.get("broker_ok") or not rows:
        return []
    keep = {r["site"] for r in rows} | {t.broker_site for t in TARGETS if t.broker_site}
    with contextlib.suppress(als.StateError, OSError):
        return als.prune(keep)
    return []


SELECTOR_FIELDS = (
    ("logged_in_selector", "agent_logged_in_selector"),
    ("pre_click", "agent_pre_click"),
)


def selector_audit(sites: list[dict]) -> int:
    """The plain-CSS part of `-V`: every live broker item whose sentinel or
    pre-click selector the broker refuses (Playwright `text=`/`xpath=`/`>>`,
    `:has-text(` …). How many there are."""
    bad = [
        (onboarding.safe_id(s.get("site")), field)
        for s in sites
        for key, field in SELECTOR_FIELDS
        if s.get(key) and not selector_ok(str(s.get(key)))
    ]
    for site, field in bad:
        print(f"❌ {site}: {field} is not plain CSS")
    if bad:
        print(
            f"{len(bad)} selector(s) the broker refuses — fix them (broker-add.py) "
            "before `sudo install/install.sh`."
        )
    return len(bad)


def report_psl() -> str:
    """Print the vendored Public Suffix List's problem ONCE (an
    infrastructure error: every item's public-suffix judgement is unknown,
    nothing else is affected) and return it; '' when the list is fine."""
    problem = onboarding.psl_problem()
    if problem:
        print(
            f"❌ infrastructure: the Public Suffix List is unusable ({problem}) — "
            "no item's cookie host was checked against it"
        )
    return problem


LEVEL_ICONS = {"refused": "❌", "unusable": "❌", "risk": "⚠️ ", "hint": "ℹ️ "}


def print_findings(findings: list) -> int:
    """One line per finding (most severe first); how many block."""
    for f in findings:
        print(
            f"{LEVEL_ICONS.get(f.level, '?')} {f.site}: {f.level} {f.code} — {f.text}"
        )
    return sum(1 for f in findings if f.blocking)


def validate_action(item_file: str | None, *, fresh: bool) -> int:
    """`-V [-i MANIFEST]`: the onboarding review (broker/onboarding.py) of
    every listed item, or of a PLANNED change against the listing. Read-only,
    no secrets (a manifest holding a password is refused). Exit 0 nothing
    blocks, 1 something does, 2 a bad manifest, 3 no list."""
    health, sites = broker_state(fresh=fresh)
    if not sites:
        print(f"❌ no broker site list to check ({health})")
        return 3
    if item_file is not None:
        if report_psl():
            print(
                "❌ planned change not reviewed — the onboarding review is incomplete"
            )
            return 1
        try:
            raw = (
                sys.stdin.read()
                if item_file == "-"
                else Path(item_file).read_text(encoding="utf-8")
            )
            manifest = json.loads(raw)
            if not isinstance(manifest, dict):
                raise ValueError("not a JSON object")
            gate = agent_login_secrets.gate_state(
                broker_request, _state_path(AGENTS_FILE_NAME).parent, fresh=fresh
            )
            review = onboarding.review_planned(manifest, sites, gate=gate)
        except (OSError, ValueError) as exc:
            print(f"❌ manifest not usable: {onboarding.safe_reason(exc)}")
            return 2
        planned = ", ".join(review.planned) or "nothing"
        print(f"onboarding review of {planned} against {len(sites)} listed items:")
        blocking = print_findings(review.findings)
        if not review.findings:
            print("✅ no findings")
        return 1 if blocking else 0
    bad = selector_audit(sites)
    blocking = 1 if report_psl() else 0
    for _site, findings in sorted(onboarding.collection_findings(sites).items()):
        blocking += print_findings(findings)
    print(
        f"{'✅' if not (bad or blocking) else '❌'} {len(sites)} broker items: "
        f"{bad} selector(s) refused, {blocking} blocking finding(s)"
    )
    return 1 if (bad or blocking) else 0


def release_action(site: str) -> int:
    """`-Q SITE`: lift a quarantine (the main session's call; audited)."""
    site = resolve_site(site)
    if not SITE_ID_RE.match(site):
        print(f"❌ not a site id: {site!r}")
        return 2
    try:
        had = als.release(site, why="agent-login.py -Q")
    except als.StateError as exc:
        print(f"❌ {site}: site state not usable ({exc})")
        return 1
    print(
        f"✅ {site}: quarantine released (audited)"
        if had
        else f"ℹ️ {site} was not quarantined (audit entry written)"
    )
    return 0


# One early return per static precondition, in the order they are checked.
def promote_precheck(  # pylint: disable=too-many-return-statements
    site: str,
) -> tuple[str | None, dict | None, list[dict]]:
    """(why not, entry, listing) — the static preconditions of a promotion,
    from a FRESH broker listing: listed and not refused, a broker login
    (never a no-submit, assisted or Safari site), a strict proof (sentinel
    or server proof), no blocking onboarding finding (WS3), the account
    provable (WS5), not quarantined. No login, no check."""
    health, sites = broker_state(fresh=True)
    if not health.startswith("running, Bitwarden"):
        return f"no fresh broker listing ({health})", None, sites
    entry = next((s for s in sites if s.get("site") == site), None)
    if entry is None:
        return "not listed by the broker", None, sites
    if entry.get("refused"):
        reason = onboarding.safe_reason(entry.get("reason") or "?")
        return f"the broker refuses the item ({reason})", entry, sites
    if is_fill_only(entry):
        return (
            "a fill-only item: the broker never logs in with it (agents fill "
            "it into Albert's Safari: safari.py -L)",
            entry,
            sites,
        )
    if (
        is_no_submit(site, entry)
        or site in ASSISTED_SITES
        or site in safari_cookies.SAFARI_SITES
    ):
        return (
            "not a broker login (your session / Safari): nothing to promote",
            entry,
            sites,
        )
    if not has_sentinel(entry):
        return "the item has no agent_logged_in_selector", entry, sites
    siblings = scope_conflicts(sites).get(site)
    multi = bool(siblings) or entry.get("multi_account") is True
    if multi and not identity.proof_ready(entry):
        return (
            (
                f"account unproven: shares its login with {', '.join(siblings or ())} "
                "(WS5: no proof of WHICH account the browser holds)"
            ),
            entry,
            sites,
        )
    blocking = [
        f for f in onboarding.blocking_findings(entry, sites) if f.code != "no_proof"
    ]
    if blocking:
        codes = ", ".join(sorted({f.code for f in blocking}))
        return (
            f"onboarding review blocks it ({codes}) — ./agent-login.py -V",
            entry,
            sites,
        )
    if als.quarantined(site):
        return f"quarantined — release first: ./agent-login.py -Q {site}", entry, sites
    return None, entry, sites


# One early return per check-record precondition.
def record_refusal(  # pylint: disable=too-many-return-statements
    site: str, entry: dict, sites: list[dict]
) -> str | None:
    """Why the latest check record does not prove `entry` as listed: a fresh
    ok from the strict proof, in the item's instance, of THIS configuration
    (WS3 digest), with the account proven for a multi-account item."""
    rec = als.checks().get(site)
    if als.freshness(rec) != "ok" or not rec:
        return f"no fresh successful check — run ./agent-login.py -p {site}"
    if int(rec.get("proof_v") or 0) < 1:
        return "the last check predates the strict proof — re-run ./agent-login.py -p"
    if str(rec.get("instance") or "") != identity.instance_of(entry):
        return (
            "the last check ran in another browser instance than the item's — "
            f"re-run ./agent-login.py -p {site}"
        )
    siblings = scope_conflicts(sites).get(site)
    multi = bool(siblings) or entry.get("multi_account") is True
    if multi and rec.get("identity") != "match":
        return (
            "the last check did not prove WHICH account (WS5) — re-run "
            f"./agent-login.py -p {site}"
        )
    if rec.get("config") != onboarding.config_digest(entry):
        return (
            "the last check proved another configuration of the item (it changed, "
            f"or the check predates WS3) — re-run ./agent-login.py -p {site}"
        )
    return None


def promote_refusal(site: str) -> str | None:
    """Why `site` may not be promoted WITHOUT a login, or None: the static
    preconditions (`promote_precheck`) and a check record that proves the
    listed configuration (`record_refusal`)."""
    why, entry, sites = promote_precheck(site)
    if why is not None or entry is None:
        return why or "not listed by the broker"
    return record_refusal(site, entry, sites)


TRIAL_LIMIT_STATES = ("locked", "cooldown", "quarantined", "busy")


def _promote(site: str, entry: dict) -> int:
    try:
        als.promote(
            site, why="agent-login.py -p", config=onboarding.config_digest(entry)
        )
    except als.StateError as exc:
        print(f"❌ {site}: site state not usable ({exc})")
        return 1
    print(f"✅ {site}: promoted — the daily check may log it in from now on")
    return 0


# One early return per step of the promotion transaction.
def promote_action(site: str) -> int:  # pylint: disable=too-many-return-statements
    """`-p SITE`: THE promotion transaction (WS3). Static preconditions on a
    fresh listing; already usable for its config → done; a fresh strict ✅ of
    this config on record → promote (no login); else the budgeted trial: ONE
    `browser.py login SITE -R` (its own free check is the probe, its own
    verify the proof; no retry), claimed atomically (`als.claim_trial`), then
    promote when it proved the listed config. Audited."""
    site = resolve_site(site)
    if not SITE_ID_RE.match(site):
        print(f"❌ not a site id: {site!r}")
        return 2
    why, entry, sites = promote_precheck(site)
    if why is not None or entry is None:
        print(f"❌ {site}: not promoted — {why or 'not listed by the broker'}")
        return 2
    if report_psl():
        # a cookie host on a public suffix could not be ruled out: no new
        # usable site until the list is fixed (`-c` stays ungated)
        print(f"❌ {site}: not promoted — the onboarding review is incomplete")
        return 1
    digest = onboarding.config_digest(entry)
    if als.usable_for(als.site_states().get(site), digest):
        print(f"✅ {site}: already usable for its current configuration")
        return 0
    if record_refusal(site, entry, sites) is None:
        return _promote(site, entry)
    raw_limit = entry.get("limit")
    limit: dict = raw_limit if isinstance(raw_limit, dict) else {}
    if limit.get("state") in TRIAL_LIMIT_STATES:
        print(
            f"❌ {site}: not promoted — limiter {limit['state']}: "
            f"{limit.get('reset') or 'wait'} (no login tried)"
        )
        return 2
    try:
        claimed, code, why_not = als.claim_trial(site, digest)
    except als.StateError as exc:
        print(f"❌ {site}: site state not usable ({exc})")
        return 1
    if not claimed:
        hint = f" — after review: ./agent-login.py -E {site}" if code == "spent" else ""
        print(f"❌ {site}: not promoted — {why_not}{hint} (no login tried)")
        return 2
    print(f"▶ {site}: promotion login (one attempt, budgeted): browser.py login {site}")
    _trial_login(site)
    why = record_refusal(site, entry, sites)
    if why is not None:
        print(f"❌ {site}: not promoted — {why}")
        return 1
    return _promote(site, entry)


def _trial_login(site: str) -> dict:
    """The budgeted login of a claimed trial: ONE `browser.py login SITE -R`
    in the item's instance, recorded, the claim finished (spent, or refunded
    when the record proves no password was sent). Its phase record."""
    # Until browser.py is started nothing can have been sent: an exception
    # before that (e.g. the item's instance does not start) refunds.
    res: dict = {"phase": "precheck", "code": "not_started", "submitted": False}
    try:
        with site_session(site):
            res = {"phase": "unknown", "code": "internal", "submitted": None}
            run = run_browser(
                "login", site, timeout_s=browser_timeout("login"), result=True
            )
        res = derived_result(run)
        failed = login_run_failure(run)
        if failed is not None:
            _quarantine_after_kill(site, run)
            record_check(site, False, failed, res)
        elif run.rc == 0:
            record_check(site, True, "logged in (promotion login)", res)
        elif run.rc == BUSY_RC:
            record_check(site, None, BUSY_HOW, {"phase": "precheck", "code": "busy"})
        else:
            record_check(site, False, failure_how(res, run.rc), res)
    finally:
        with contextlib.suppress(als.StateError, OSError):
            spent = als.finish_trial(site, res)
            print(
                f"  trial budget: {'spent' if spent else 'refunded (no password sent)'}"
            )
    return res


def rearm_action(site: str) -> int:
    """`-E SITE`: give a site its one promotion login back (audited; the
    main session's call after reviewing why the last one failed)."""
    site = resolve_site(site)
    if not SITE_ID_RE.match(site):
        print(f"❌ not a site id: {site!r}")
        return 2
    try:
        had = als.rearm(site, why="agent-login.py -E")
    except als.StateError as exc:
        print(f"❌ {site}: {exc}")
        return 1
    print(
        f"✅ {site}: promotion login re-armed (audited)"
        if had
        else f"ℹ️ {site} had its promotion login unspent (audit entry written)"
    )
    return 0


STATIC_SITES = {t.site for t in TARGETS} | {
    t.broker_site for t in TARGETS if t.broker_site
}


# One early return per step of the two phases.
def remove_action(site: str, force: bool = False) -> int:  # pylint: disable=too-many-return-statements
    """`-D SITE` (WS3 removal), run twice. A FRESH listing decides the phase:

    1. still listed: back to ``pending`` (audited; `-c` never logs it in
       again), then `browser.py logout SITE` in its instance (the broker's
       profile, its in-scope cookies, its declared storage keys); then the
       vault step is Albert's (broker-add.py NAME -D, or the web vault);
    2. gone from the vault: the broker's ``forget`` (limiter, identity guard,
       profile, screenshot — under its site lock, after its own fresh vault
       read), then every client-side trace (`als.remove_site`): checks.json,
       last-check.json, site-state.json, session-age and login-log files;
       one line stays in audit.jsonl. agents.md is rewritten."""
    site = resolve_site(site)
    if not SITE_ID_RE.match(site):
        print(f"❌ not a site id: {site!r}")
        return 2
    if site in STATIC_SITES:
        print(
            f"❌ {site} is a built-in target (TARGETS in agent-login.py), not removable here"
        )
        return 2
    health, sites = broker_state(fresh=True)
    if not health.startswith("running, Bitwarden"):
        print(f"❌ {site}: no fresh broker listing ({health}) — nothing changed")
        return 1
    if any(s.get("site") == site for s in sites):
        return _remove_phase1(site, sites, force=force)
    try:
        resp = broker_request("forget", timeout=300.0, site=site)
    except (OSError, ValueError) as exc:
        print(
            f"❌ {site}: the broker's forget did not answer ({exc}) — nothing changed"
        )
        return 1
    if not resp.get("ok") and resp.get("error") != "forget_incomplete":
        code = onboarding.safe_reason(resp.get("error"), 40)
        detail = onboarding.safe_reason(resp.get("detail"))
        print(f"❌ {site}: broker forget refused ({code}: {detail}) — nothing changed")
        return 1
    raw_left = resp.get("left")
    left: dict[str, str] = (
        {str(k): str(v) for k, v in raw_left.items()}
        if isinstance(raw_left, dict)
        else {}
    )
    try:
        # the broker kept a block: the client keeps the site's state record
        # (demoted, quarantined) so a re-added item shows the real lockout
        removed = als.remove_site(site, kept=left or None)
    except (als.StateError, OSError) as exc:
        print(f"❌ {site}: client state not usable ({exc})")
        return 1
    write_agent_summary()
    files = len(removed.get("files") or [])
    print(
        f"✅ {site}: removed — broker: limiter {'yes' if resp.get('limiter') else 'none'}, "
        f"{resp.get('groups') or 0} group key(s), guard {'yes' if resp.get('guard') else 'none'}, "
        f"profile {'yes' if resp.get('profile') else 'none'}, screenshot "
        f"{'yes' if resp.get('screenshot') else 'none'}; client: state files, {files} cache "
        "file(s); one line in audit.jsonl"
    )
    if left:
        held = ", ".join(
            f"{onboarding.safe_reason(k, 40)} ({onboarding.safe_reason(v, 30)})"
            for k, v in sorted(left.items())
        )
        print(
            f"⚠️ {site}: kept by the broker — {held}: a removal never lifts a block "
            "(its client state record stays, quarantined); "
            f"after review: sudo install/install.sh -r {site}"
        )
    if not resp.get("ok"):
        print(
            f"⚠️ {site}: the broker could not remove everything "
            f"({onboarding.safe_reason(resp.get('detail'))}) — look, then run -D again"
        )
        return 1
    return 0


def sibling_in_instance(site: str, sites: list[dict]) -> list[str]:
    """The REMAINING items of another account that share `site`'s login
    scope in the same browser instance (`scope_conflicts`): a logout there
    would end THEIR session too (abs-root / abs-albert, navidrome-*)."""
    entry = next((s for s in sites if s.get("site") == site), None)
    if entry is None:
        return []
    inst = identity.instance_of(entry)
    by_id = {str(s.get("site")): s for s in sites}
    return [
        other
        for other in scope_conflicts(sites).get(site, ())
        if other in by_id and identity.instance_of(by_id[other]) == inst
    ]


def _remove_phase1(site: str, sites: list[dict], *, force: bool = False) -> int:
    """`-D` while the site is still listed: demote, then log out — unless
    another account's item shares the scope in the same instance (its
    session would go too): then only the state is changed, unless `force`
    (`-F`)."""
    try:
        als.demote(site, why="agent-login.py -D (phase 1)")
    except als.StateError as exc:
        print(f"❌ {site}: site state not usable ({exc})")
        return 1
    print(f"▶ {site}: demoted to pending (the daily check never logs it in again)")
    siblings = sibling_in_instance(site, sites)
    if siblings and not force:
        print(
            f"⚠️ {site}: NOT logged out — {', '.join(siblings)} share(s) its login "
            "scope in the same browser, and a logout would end that session too "
            "(-F forces it). The broker's own profile goes with the next -D. "
            "Next: remove its vault item from agent-login (broker-add.py NAME -D, "
            f"or the web vault), then ./agent-login.py -D {site} again"
        )
        return 0
    entry = next((s for s in sites if s.get("site") == site), None)
    if is_fill_only(entry):
        # tp#1385: a fill-only item never had a broker browser session, and
        # `browser.py logout` refuses it — nothing to log out.
        print(
            f"✅ {site}: fill-only: no broker session to log out. Next: remove its "
            "vault item from agent-login (broker-add.py NAME -D, or the web vault), "
            f"then ./agent-login.py -D {site} again"
        )
        return 0
    with site_session(site):
        run = run_browser("logout", site, timeout_s=browser_timeout("logout"))
    if run.rc != 0:
        print(
            f"❌ {site}: browser.py logout failed (exit {run.rc}) — the site stays "
            f"demoted; fix that, then ./agent-login.py -D {site} again"
        )
        return 1
    print(
        f"✅ {site}: logged out (broker profile, cookies, storage). Next: remove its "
        "vault item from agent-login (broker-add.py NAME -D, or the web vault), "
        f"then ./agent-login.py -D {site} again"
    )
    return 0


def _budgeted_login(site: str, claimed: bool) -> BrowserRun:
    """`-t`'s one `browser.py login SITE -R`; a `claimed` trial is finished
    whatever happens (spent, or refunded when no password was sent)."""
    run: BrowserRun | None = None
    try:
        run = run_browser(
            "login", site, timeout_s=browser_timeout("login"), result=True
        )
        return run
    finally:
        if claimed:
            # Refunded only when the record proves no password was sent —
            # `run_browser`'s own "not started" marker included. An exception
            # out of it (the child may have run) leaves None: spent.
            res = derived_result(run) if run is not None else None
            with contextlib.suppress(als.StateError, OSError):
                als.finish_trial(site, res)


def _trial_claim_for_test(site: str) -> tuple[bool, str | None]:
    """`-t` of a broker site that is not usable for its current config takes
    the SAME budget as `-p` (WS3): (claimed, refusal or None)."""
    if site in ASSISTED_SITES or site in safari_cookies.SAFARI_SITES:
        return False, None
    _health, sites = broker_state()
    entry = next((s for s in sites if s.get("site") == site), None)
    if entry is None or entry.get("refused") or is_no_submit(site, entry):
        return False, None
    digest = onboarding.config_digest(entry)
    try:
        if als.usable_for(als.site_states().get(site), digest):
            return False, None
        claimed, code, why = als.claim_trial(site, digest)
    except als.StateError as exc:
        return False, f"site state not usable ({exc})"
    if claimed:
        return True, None
    hint = f" — after review: ./agent-login.py -E {site}" if code == "spent" else ""
    return False, f"not promoted yet and its one login is not available: {why}{hint}"


# consumer, privilege — only what the code knows; anything else is "?".
MATRIX_META = {
    "cscs": ("cscs-api.py (Waldur)", "user"),
    "smartsheet": ("sdsc/smartsheet-api", "user"),
    "slack": ("slack_api.py (users.admin.*)", "admin"),
    "anthropic": ("anthropic-api.py (Team admin)", "admin"),
    "console": ("console-balance.py (billing, read-only)", "admin"),
    "console-private": ("console-balance.py (billing, read-only)", "admin"),
    "openai": ("ChatGPT Business admin", "admin"),
    "switch": ("Switch Cloud Portal", "user"),
}


def refresh_policy(row: dict) -> str:
    """How the row's session is renewed."""
    if row["status"] == "safari":
        return "Albert's Safari session"
    if row["status"] == "assisted" or row.get("flow") == ASSISTED_FLOW:
        return "Albert: ./agent-login.py -g"
    if needs_sentinel(row):
        return "none (needs a sentinel)"
    if row.get("quarantine"):
        return "none (quarantined)"
    if row["status"] in ("ready", "extra"):
        base = "daily -c" if row.get("stage") == "usable" else "none (pending)"
        if row.get("session_refresh"):  # -c renews its token, pending or not
            base += f" + token refresh ({row['session_refresh']})"
        return base
    return "none"


def matrix_rows(data: dict, checks: dict[str, dict]) -> list[dict]:
    """The acceptance matrix: one row per inventory item."""
    out = []
    for row in data["rows"]:
        site = row["site"]
        consumer, privilege = MATRIX_META.get(site, ("?", "?"))
        privilege = row.get("privilege") or privilege  # the item's agent_privilege
        rec = checks.get(site) or {}
        limit = row.get("limit") or {}
        sentinel = row.get("sentinel")
        out.append(
            {
                "site": site,
                "flow": row.get("flow"),
                "consumer": consumer,
                "privilege": privilege,
                "check_url": row.get("check_url") or "",
                "sentinel": "unknown"
                if sentinel is None
                else ("yes" if sentinel else "none"),
                "proof_origins": row.get("proof_origins") or [],
                "bundle_scope": {
                    "cookie_hosts": row.get("cookie_hosts") or [],
                    "storage_origins": row.get("storage_origins") or [],
                },
                "attempt_group": row.get("attempt_group") or "",
                "shares_login": ",".join(shares_login(row)),
                # WS5: the browser instance, multi-account, the identity
                # recipe and whether the client can prove it, the privilege,
                # the group alias and a declared same-account partner
                "instance": row_instance(row) or "default",
                "multi": "yes" if is_multi_account(row) else "no",
                "identity": (row.get("identity") or "-")
                + (" (unproven)" if account_unproven(row) else ""),
                "alias": row.get("alias") or "",
                "same_account": ",".join(row.get("same_account_as") or []),
                "refresh": "none (account unproven)"
                if account_unproven(row)
                else refresh_policy(row),
                "stage": row.get("stage")
                or ("n/a" if row["status"] in ("assisted", "safari") else "unknown"),
                "quarantine": bool(row.get("quarantine")),
                "limit": limit.get("state")
                or ("unknown" if not data["broker_ok"] else "n/a"),
                "last_phase": rec.get("phase") or "",
                "final_origin": rec.get("final_origin") or "",
                "origin_ok": rec.get("origin_ok"),
                "state": row_state(row, checks)[0],
            }
        )
    return out


def print_matrix(data: dict, *, as_json: bool) -> int:
    """`-x`: the acceptance matrix (table or JSON)."""
    rows = matrix_rows(data, last_checks())
    if as_json:
        print(json.dumps(rows, indent=1))
        return 0
    cols = (
        "site",
        "flow",
        "consumer",
        "privilege",
        "sentinel",
        "attempt_group",
        "shares_login",
        "instance",
        "multi",
        "identity",
        "alias",
        "same_account",
        "refresh",
        "stage",
        "limit",
        "last_phase",
        "state",
    )
    table = [list(cols)] + [[str(r[c]) for c in cols] for r in rows]
    widths = [max(len(line[i]) for line in table) for i in range(len(cols))]
    for line in table:
        print("  ".join(cell.ljust(w) for cell, w in zip(line, widths)).rstrip())
    mismatches = origin_mismatches(rows)
    if mismatches:
        print(
            "\nLast check ended on ANOTHER origin than the check URL's (set "
            "agent_proof_origins before release, or fix agent_check_url):"
        )
        for r in mismatches:
            print(
                f"  {r['site']}: ended on {r['final_origin']} (check URL {r['check_url']})"
            )
    return 0


def origin_mismatches(rows: list[dict]) -> list[dict]:
    """Matrix rows whose latest check ended off the proof origins."""
    return [r for r in rows if r.get("origin_ok") is False and r.get("final_origin")]


# ---------------------------------------------------------------------------
# WS1b: `-L SITE` — an agent's login through Albert's Safari, then the import
# (PLAN_ws1b-durability.md D1). Explicit and attended only: never from a
# LaunchAgent, never on a locked or unattended Mac (`interactive_gate`).
# ---------------------------------------------------------------------------

SAFARI_LOCK_WAIT_S = 120.0
FLUSH_WAIT_S = 90.0
FLUSH_POLL_S = 2.0
# The ONLY free-check verdicts `-L` goes on from (B1): a definite "logged
# out" — for Notion also another account, which the import's own proof
# handles. Everything else (cannot tell, internal, gated) stops.
CONTINUE_CODES = {"notion": frozenset({"logged_out", "wrong_account"})}
DEFAULT_CONTINUE = frozenset({"logged_out"})
# An import that ran out of time or met a guided login: the shared browser's
# state is unknown — never followed by a Safari login (N5).
IMPORT_STOP_RCS = frozenset({BUSY_RC, LOGIN_TIMEOUT_RC, LOGIN_TIMEOUT_DIRTY_RC})


@contextlib.contextmanager
def safari_login_lock(wait_s: float = SAFARI_LOCK_WAIT_S) -> Iterator[bool]:
    """One Safari login at a time (they share Albert's Safari and clipboard):
    an exclusive flock on ``<state>/safari-login.lock``; yields False when it
    was not free within `wait_s`."""
    path = als.state_dir() / "safari-login.lock"
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(path), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        deadline = time.monotonic() + wait_s
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                got = True
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    got = False
                    break
                time.sleep(0.5)
        yield got
    finally:
        os.close(fd)


def _mail_detail(out: alsafari.Outcome) -> dict:
    """The fixed ``mail_archived`` status of a used login-code mail as a
    result-record detail ({} when no mail code was used)."""
    return (
        {"detail": f"mail_archived: {out.mail_archived}"} if out.mail_archived else {}
    )


def _safari_fail(site: str, out: alsafari.Outcome, how: str) -> int:
    """Record a failed `-L` (phase/code fixed), quarantine when a credential
    step may have sent something; the exit code. Says "quarantined" only
    when the quarantine was written (N8)."""
    quarantined = False
    if out.credential:
        try:
            als.quarantine(site, out.phase, out.code)
            quarantined = True
        except (als.StateError, OSError):
            quarantined = False
    record_check(
        site,
        None if out.rc in (BUSY_RC, 3) else False,
        how,
        {
            "phase": out.phase,
            "code": out.code,
            "route": "safari-login",
            **_mail_detail(out),
        },
    )
    who = "needs Albert" if out.rc == alsafari.NEEDS_ALBERT_RC else "not logged in"
    print(f"❌ {site}: {who} — {phases.text(out.phase, out.code)}")
    if quarantined:
        print(
            f"   quarantined (a credential step ran) — the main session releases "
            f"it: ./agent-login.py -Q {site}"
        )
    elif out.credential:
        print(
            "   a credential step ran but the quarantine could NOT be written — "
            f"do not run -L {site} again before the main session looked at it"
        )
    if out.window_left:
        print("   a Safari login window may be left open (its id never came back)")
    return out.rc


def _safari_jar(site: str) -> tuple[list, str | None]:
    """(`site`'s usable Safari cookies, None) or ([], why) — values stay in
    memory only."""
    try:
        jar = safari_cookies.read_binarycookies()
    except (OSError, ValueError) as exc:
        return [], str(getattr(exc, "strerror", None) or type(exc).__name__)
    return safari_cookies.site_cookies(jar, site), None


def _import_run(site: str, agent: bool) -> BrowserRun:
    """`browser.py import-safari SITE -R` (`-a`: after an agent's login)."""
    args = ["import-safari", site, *(["-a"] if agent else [])]
    with site_session(site):
        return run_browser(
            *args, timeout_s=browser_timeout("import-safari"), capture=True, result=True
        )


def _free_check(site: str) -> tuple[int, dict]:
    """The free `logged-in` probe in the site's instance."""
    with site_session(site):
        rc, check = probe(browser_site(site))
    return rc, check or {}


def _import_how(run: BrowserRun, base: str) -> str:
    """`base`, plus a failed undo the import recorded (S6)."""
    if (run.result or {}).get("undo") == "failed":
        return f"{base} — the import's UNDO FAILED (cookies may be left)"
    return base


# One return per stage of the pipeline (D1).
def safari_login_action(  # pylint: disable=too-many-return-statements
    site: str, *, dry_run: bool = False
) -> int:
    """`-L SITE`: free check → Safari's own session → a login in Safari →
    import. See the section comment; one run, no retries."""
    site = resolve_site(site)
    if alsafari.scheduled():
        print(
            f"❌ -L drives Albert's Safari: never from a LaunchAgent "
            f"({alsafari.SCHEDULED_ENV}=1) — an agent runs it when it needs {site}"
        )
        return 2
    if site in alsafari.MAGIC_LINK_SITES:
        return magic_link_login(site, dry_run=dry_run)
    recipe = alsafari.RECIPES.get(site)
    if recipe is None:
        known = ", ".join(sorted([*alsafari.RECIPES, *alsafari.MAGIC_LINK_SITES]))
        print(f"❌ {site}: no Safari login for this site (known: {known})")
        return 2
    if dry_run:
        return safari_dry_run(site, recipe)
    gate = alsafari.interactive_gate()
    if gate is not None:
        print(f"❌ {site}: {phases.CODE_TEXT.get(gate, gate)} ({gate})")
        return 3
    q = als.quarantined(site)
    if q is not None:
        print(
            f"❌ {site}: quarantined after {q.get('phase')} {q.get('at_text', '')} — "
            f"the main session releases it: ./agent-login.py -Q {site}"
        )
        return 2
    with safari_login_lock() as got:
        if not got:
            print(f"⏸  {site}: another Safari login runs — try again later")
            return BUSY_RC
        return _safari_login_locked(site, recipe)


def safari_dry_run(site: str, recipe: alsafari.Recipe) -> int:
    """`-L SITE -n`: READ-ONLY — safari.py's capabilities against the recipe,
    the interactive gate, whether Safari holds a session. No check, no
    import, no record."""
    have = alsafari.available_features()
    missing = recipe.features() - have
    if missing:
        print(
            f"ℹ️ {site}: safari.py lacks {', '.join(sorted(missing))} — -L would only "
            "import a session Safari already holds (mydotfiles specs)"
        )
    else:
        print(f"ℹ️ {site}: safari.py offers every feature the recipe needs")
    gate = alsafari.interactive_gate()
    print(
        f"ℹ️ {site}: interactive gate "
        + ("open" if gate is None else f"closed — {phases.CODE_TEXT.get(gate, gate)}")
    )
    cookies, why = _safari_jar(site)
    if why is not None:
        print(f"ℹ️ {site}: Safari's cookie file unreadable ({why})")
        return 0
    held = safari_cookies.has_session(site, cookies)
    print(
        f"ℹ️ {site}: Safari {'holds' if held else 'holds NO'} session — -L would "
        + ("import it first" if held and recipe.import_after else "log Safari in")
    )
    return 0


def _free_check_gate(site: str) -> int | None:
    """None when `-L` may go on (a DEFINITE logged-out, B1); else the exit
    code after saying why — the session works (0), busy (75) or the check
    could not tell (2, its code named)."""
    rc, check = _free_check(site)
    code = str(check.get("code") or "")
    if rc == 0:
        print(f"✅ {site}: the shared Chromium is logged in — nothing to do")
        record_check(site, True, "logged in", {**check, "phase": "ok", "code": "ok"})
        return 0
    if rc == BUSY_RC:
        print(f"⏸  {site}: {BUSY_HOW}")
        return BUSY_RC
    if rc == 2 and code in CONTINUE_CODES.get(site, DEFAULT_CONTINUE):
        return None
    print(
        f"⏸  {site}: the free check is not a definite logged-out "
        f"(exit {rc}, code {code or 'none'}: {identity_text(check)}) — nothing "
        "replaced; try again later"
    )
    return 2


# One return per stage, in pipeline order.
def _safari_login_locked(  # pylint: disable=too-many-return-statements
    site: str, recipe: alsafari.Recipe
) -> int:
    """`safari_login_action` under the Safari-login lock."""
    if recipe.import_after:
        stop = _free_check_gate(site)
        if stop is not None:
            return stop
    cookies, why = _safari_jar(site)
    if why is not None:
        out = alsafari.Outcome(3, "no_safari_session")
        return _safari_fail(site, out, f"Safari's cookie file unreadable ({why})")
    before = safari_cookies.session_fingerprint(site, cookies)
    if safari_cookies.has_session(site, cookies) and recipe.import_after:
        print(f"▶ {site}: Safari holds a session — importing it")
        run = _import_run(site, agent=False)
        if run.rc == 0:
            record_check(
                site,
                True,
                "logged in (Safari session imported)",
                {
                    **(run.result or {}),
                    "phase": "ok",
                    "code": "ok",
                    "route": "safari-import",
                },
            )
            print(f"✅ {site}: logged in with Albert's Safari session")
            return 0
        res = run.result or {}
        code = str(res.get("code") or "")
        if (
            run.rc in IMPORT_STOP_RCS
            or run.rc is None
            or code
            in (
                "identity_unconfigured",
                "wrong_account",
                "indeterminate",
            )
        ):
            # a Safari login cannot fix it, or the browser's state is unknown
            out = alsafari.Outcome(
                BUSY_RC if run.rc == BUSY_RC else 2,
                code or "timeout",
                phase=str(res.get("phase") or "client-proof"),
            )
            return _safari_fail(
                site, out, _import_how(run, f"Safari session not imported — {out.code}")
            )
        print(f"↻ {site}: the imported session does not work — logging Safari in")
    out = _drive_safari(site, recipe)
    if out.mail_archived == "failed":
        print(f"⚠️ {site}: the login-code mail could not be archived (left in INBOX)")
    if not out.ok:
        return _safari_fail(site, out, f"Safari login stopped — {out.code}")
    if not recipe.import_after:
        record_check(
            site,
            True,
            "Safari logged in (agents use Safari)",
            {"phase": "ok", "code": "ok", "route": "safari-login", **_mail_detail(out)},
        )
        print(f"✅ {site}: Safari is logged in (agents work in Safari for {site})")
        return 0
    if not _wait_flush(site, before):
        print(f"⚠️ {site}: Safari did not write the new session yet — importing anyway")
    run = _import_run(site, agent=bool(out.steps))
    if run.rc == 0:
        record_check(
            site,
            True,
            "logged in (agent's Safari login)",
            {
                **_mail_detail(out),
                **(run.result or {}),
                "phase": "ok",
                "code": "ok",
                "route": "safari-login",
            },
        )
        print(f"✅ {site}: logged in through Albert's Safari")
        return 0
    res = run.result or {}
    failed = alsafari.Outcome(
        BUSY_RC if run.rc == BUSY_RC else 2,
        str(
            res.get("code")
            or ("timeout" if run.rc in IMPORT_STOP_RCS else "logged_out")
        ),
        credential=out.credential,
        phase=str(res.get("phase") or "client-proof"),
        mail_archived=out.mail_archived,
    )
    return _safari_fail(
        site, failed, _import_how(run, "Safari login done, the import failed")
    )


def _wait_flush(site: str, before: str) -> bool:
    """Wait until Safari's cookie file holds a NEW session for `site` (a
    value-inclusive digest differs from `before`)."""
    deadline = time.monotonic() + FLUSH_WAIT_S
    while time.monotonic() < deadline:
        cookies, why = _safari_jar(site)
        if why is None and safari_cookies.has_session(site, cookies):
            if safari_cookies.session_fingerprint(site, cookies) != before:
                return True
        time.sleep(FLUSH_POLL_S)
    return False


# One return per thing the Safari run needs before it can start.
def _drive_safari(  # pylint: disable=too-many-return-statements
    site: str, recipe: alsafari.Recipe
) -> alsafari.Outcome:
    """Resolve what the recipe needs, check safari.py, run the step machine."""
    binary = alsafari.safari_py_bin()
    if binary is None:
        return alsafari.Outcome(3, "safari_py_missing")
    call = alsafari.run_safari_py(binary)
    missing = recipe.features() - alsafari.features(call)
    if missing:
        print(f"   safari.py lacks: {', '.join(sorted(missing))} (mydotfiles specs)")
        return alsafari.Outcome(3, "safari_py_outdated")
    status = call(["--status"])
    if status.rc != 0 or status.data.get("javascript") is not True:
        return alsafari.Outcome(3, "safari_unavailable")
    try:
        over = alsafari.load_overrides().get(site, {})
    except alsafari.OverrideError as exc:
        print(f"   {exc}")
        return alsafari.Outcome(2, "identity_unconfigured")
    plan = _safari_plan(site, recipe, over)
    if plan is None:
        return alsafari.Outcome(2, "safari_no_recipe")
    print(f"▶ {site}: logging in in Albert's Safari (a new window; his clipboard)")
    return alsafari.Machine(recipe, plan, call).run()


def _safari_plan(
    site: str, recipe: alsafari.Recipe, over: dict
) -> alsafari.Plan | None:
    """The run's start page, sentinel, vault item, account and mailbox."""
    entry: dict = {}
    if recipe.broker:
        _health, sites = broker_state()
        entry = next((s for s in sites if s.get("site") == site), {}) or {}
    start = recipe.start_url or str(entry.get("login_url") or "")
    sentinel = recipe.sentinel or str(entry.get("logged_in_selector") or "")
    item = str(over.get("item") or entry.get("name") or "")
    if not start or not sentinel or (recipe.broker and not item):
        return None
    mail = None
    if any(s.kind == "mail_code" for s in recipe.steps):
        himalaya = shutil.which("himalaya")
        if himalaya:
            mail = alsafari.MailReader(
                himalaya,
                str(over.get("mailbox") or "")
                or os.environ.get("ANTHROPIC_LOGIN_HIMALAYA_ACCOUNT"),
            )
    return alsafari.Plan(
        start_url=start,
        sentinel=sentinel,
        item=item,
        account=str(over.get("account") or ""),
        expected_email=str(over.get("expected_email") or ""),
        mail=mail,
    )


@contextlib.contextmanager
def _env(**values: str) -> Iterator[None]:
    """Set environment variables for the child processes of the block."""
    old = {k: os.environ.get(k) for k in values}
    os.environ.update(values)
    try:
        yield
    finally:
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def magic_link_login(site: str, *, dry_run: bool = False) -> int:
    """`-L anthropic[-private]`: claude.ai's automated magic link (sender
    allow-list, baseline, embedded-e-mail check, bin/browser.py
    `_claude_auto_login`) in the account's own browser instance — no Safari.
    Without a readable mailbox it stops with browser.py's "needs Albert"."""
    if dry_run:
        print(f"ℹ️ {site}: -L would run the automated magic-link login (no Safari)")
        return 0
    ok, how = assisted_check(site)
    if ok:
        print(f"✅ {site}: {how} — nothing to do")
        record_check(site, True, how)
        return 0
    if ok is None:
        print(f"⏸  {site}: {how}")
        return BUSY_RC
    if "one claude.ai session per browser profile" in how:
        print(f"❌ {site}: {how}")
        return 2
    print(f"▶ {site}: automated magic-link login (mail read by himalaya)")
    with site_session(site), _env(ANTHROPIC_LOGIN_EMAIL=CLAUDE_ACCOUNTS[site]):
        rc = _browser("login", "anthropic", timeout_s=browser_timeout("login"))
    ok, how = assisted_check(site)
    if ok is not None:
        record_check(site, ok, how)
    print(f"{'✅' if ok else '❌'} {site}: {how}")
    if rc == alsafari.NEEDS_ALBERT_RC and not ok:
        print("   needs a mailbox himalaya can read for this account (plan L8)")
    return 0 if ok else (rc or 2)


# ---------------------------------------------------------------------------
# WS1b: `-R` — the refresh-only pass (D7) and the toolchain lines (D9)
# ---------------------------------------------------------------------------

REFRESH_NETWORK_WAIT_S = 60.0


def refresh_pass() -> int:
    """Renew every refreshable token (NPM's JWT) that has < 12 h left: the
    free probe, then `login -F` (never a login, never a password, never a
    quarantine). Records nothing; exit 1 when a refresh failed. Skipped
    while the daily check is not loaded (N2: the pass belongs to that set)."""
    if not daily_loaded():
        print(f"⏭  {LAUNCH_LABEL} is not loaded — refresh pass skipped")
        return 0
    if not wait_for_network(timeout_s=REFRESH_NETWORK_WAIT_S):
        print(f"⏸  no network ({NETWORK_HOST}) — refresh pass skipped")
        return 0
    if not ensure_browser_up():
        print("❌ shared Chromium down and `browser.py up` failed — no refresh")
        return 1
    _browser("reap-owned", quiet=True, timeout_s=browser_timeout("reap-owned"))
    bad = 0
    for row in overview()["rows"]:
        site = row["site"]
        if not row.get("session_refresh"):
            continue
        if check_instance(row):
            print(f"⏭  {site}: lives in the {check_instance(row)} browser — skipped")
            continue
        rc, check = probe(site)
        if rc == BUSY_RC:
            print(f"⏸  {site}: {BUSY_HOW}")
            continue
        if rc != 0:
            print(f"⏭  {site}: not logged in — the daily check handles it")
            continue
        how = refresh_step(site, check, "logged in")
        print(f"✅ {site}: {how}")
        if "refresh failed" in how:
            bad += 1
    return 1 if bad else 0


def toolchain_report() -> list[tuple[str, str]]:
    """Print the toolchain findings (D9); the `failed` rows for `-c`."""
    out = []
    for finding in agent_login_toolchain.findings():
        print(finding.line())
        if not finding.unknown:
            out.append(("toolchain", finding.line()))
    return out


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
        help="guided login by hand (browser.py assisted-login: confirm on the "
        "terminal, remote view of a headless tab; the window as fallback)",
    )
    ap.add_argument(
        "-F",
        "--force",
        action="store_true",
        help="with -g: start even with UNREGISTERED CDP clients attached "
        "(browser.py assisted-login -f; they are not paused and keep running); "
        "with -D: log out even when another account's item shares the scope "
        "in the same browser instance",
    )
    ap.add_argument(
        "-c",
        "--check-all",
        action="store_true",
        help="every usable site: logged in? if not, `browser.py login`; one line "
        "per site; exit 0 when every failure is a site on record in "
        "last-check.json, 1 when the broker, a browser or the check failed",
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
        help="recover a stale guided login whose watchdog died (one line), "
        "refresh the site-list and secret-run snapshots and the agents file "
        "(which also lists the secrets agents can inject), print nothing else "
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
        f"(`-c` daily {LAUNCH_HOUR:02d}:{LAUNCH_MINUTE:02d}), {SNAPSHOT_LABEL} "
        f"(`-S` every {SNAPSHOT_INTERVAL_S // 60} min) and {REFRESH_LABEL} "
        f"(`-R` every {REFRESH_INTERVAL_S // 3600} h) as one transaction "
        "(any failure restores the previous set)",
    )
    ap.add_argument(
        "-U",
        "--uninstall-daily",
        action="store_true",
        help="unload + remove all three LaunchAgents",
    )
    ap.add_argument(
        "-P",
        "--print-plist",
        action="store_true",
        help="print the three LaunchAgent plists (writes nothing)",
    )
    ap.add_argument(
        "-j",
        "--json",
        action="store_true",
        help="print the overview (with -x: the matrix) as JSON",
    )
    ap.add_argument(
        "-x",
        "--matrix",
        action="store_true",
        help="the acceptance matrix: one row per login (consumer, privilege, "
        "sentinel, scope, attempt group, refresh, stage, limit, last phase)",
    )
    ap.add_argument(
        "-p",
        "--promote",
        metavar="SITE",
        help="the ONE promotion transaction (pending -> usable for scheduled "
        "logins): a fresh listing, the onboarding review, then a fresh strict ok "
        "of this configuration on record, or ONE budgeted `browser.py login` "
        "(no retry); audited",
    )
    ap.add_argument(
        "-V",
        "--validate",
        "--validate-selectors",
        dest="validate",
        action="store_true",
        help="the onboarding review (no login, no vault write): selectors the broker refuses, "
        "then every listed item's findings (refused / unusable / risk / hint); "
        "with -i: a PLANNED change; with -r: ask the broker now and refresh the "
        "site-list snapshot first (~40 s) instead of reading it; exit 1 when "
        "anything blocks",
    )
    ap.add_argument(
        "-i",
        "--item",
        metavar="MANIFEST",
        help="with -V: review a planned item / batch (JSON: {name, fields, "
        "replaces?, username_form?, reveals?} or {items: [...], removes: [...]}; "
        "'-' = stdin; never a password) against the listing, displacement included",
    )
    ap.add_argument(
        "-E",
        "--rearm",
        metavar="SITE",
        help="give SITE its one promotion login back (after reviewing why it "
        "failed) — the main session's decision, audited",
    )
    ap.add_argument(
        "-D",
        "--remove",
        metavar="SITE",
        help="remove a broker site, run twice: while it is listed -> demote + "
        "browser.py logout; after its vault item is gone -> drop every trace "
        "(broker `forget`, state files, cache files); audited",
    )
    ap.add_argument(
        "-Q",
        "--release",
        metavar="SITE",
        help="release SITE's quarantine (after a failed login that may have "
        "submitted the password) — the main session's decision, audited",
    )
    ap.add_argument(
        "-L",
        "--safari-login",
        metavar="SITE",
        help="an AGENT's login through Albert's Safari (WS1b): free check, "
        "else import Safari's own session (works without new safari.py "
        "features), else log Safari in (safari.py, a "
        "new window; the login broker's credentials, else his Vaultwarden "
        "tab and clipboard) and import it; "
        "claude.ai: the automated magic link. One run, no retries; never "
        "from a LaunchAgent. Exit 4 = needs Albert (CAPTCHA, SMS, push / "
        "security key); a locked vault is the agent's: `vault-touchid "
        "unlock-safari -a main` (Albert touches once); exit 3 = the Mac is "
        "locked or idle: retry later",
    )
    ap.add_argument(
        "-l",
        "--fillable",
        action="store_true",
        help="list every item agents can fill into Albert's Safari (fill-only "
        "items and login items with agent_safari_fill): site, name, fill "
        "origins — names only, never a value (from the broker's site listing; "
        "-r asks the broker now; -j: JSON)",
    )
    ap.add_argument(
        "-n",
        "--dry-run",
        action="store_true",
        help="with -L: report what it would do (no import, no Safari login)",
    )
    ap.add_argument(
        "-H",
        "--identity-history",
        nargs="?",
        const="",
        default=None,
        metavar="SITE",
        help="read-only: the last identity proofs of SITE (no SITE: of every "
        "site) that did not say match — when, state, verdict, the recipe's "
        "reason word, HTTP status, code, redacted detail (checks.json keeps "
        "the last 10 per site; the latest check overwrites its detail); "
        "-j: JSON",
    )
    ap.add_argument(
        "-R",
        "--refresh-pass",
        action="store_true",
        help=f"refresh-only pass: renew every refreshable token (NPM) with "
        f"< 12 h left; never logs in (LaunchAgent {REFRESH_LABEL}, every "
        f"{REFRESH_INTERVAL_S // 3600} h)",
    )
    return ap


def launch_action(args: argparse.Namespace) -> int | None:
    """-P / -I / -U, or None when none was asked for."""
    if args.print_plist:
        print(launchagent_plist(), end="")
        print(snapshot_plist(), end="")
        print(refresh_plist(), end="")
        return 0
    if args.install_daily:
        return install_daily()
    if args.uninstall_daily:
        return uninstall_daily()
    return None


# One return per action flag.
def login_action(args: argparse.Namespace) -> int | None:  # pylint: disable=too-many-return-statements
    """-t / -g / -c, or None when none was asked for."""
    if args.test:
        return run_test(args.test)
    if args.guided:
        return manual_login(args.guided, force=args.force)
    if args.check_all:
        return check_all(mail=args.mail)
    if args.promote:
        return promote_action(args.promote)
    if args.release:
        return release_action(args.release)
    if args.rearm:
        return rearm_action(args.rearm)
    if args.remove:
        return remove_action(args.remove, force=args.force)
    if args.safari_login:
        return safari_login_action(args.safari_login, dry_run=args.dry_run)
    if args.refresh_pass:
        return refresh_pass()
    return None


def listing_action(args: argparse.Namespace) -> int | None:
    """-V / -H / -l (read-only, not even the agents file), or None when none
    was asked for."""
    if args.validate:
        return validate_action(args.item, fresh=args.refresh)
    if args.identity_history is not None:  # checks.json only
        return identity_history_action(args.identity_history, as_json=args.json)
    if args.fillable:  # names and origins only
        return fillable_action(as_json=args.json, fresh=args.refresh)
    return None


# One early exit per CLI mode.
def main() -> int:  # pylint: disable=too-many-return-statements,too-many-branches
    """CLI entry point."""
    ap = build_parser()
    args = ap.parse_args()
    if args.mail and not args.check_all:
        ap.error("-m/--mail only works together with -c/--check-all")
    if args.force and not (args.guided or args.remove):
        ap.error("-F/--force only works together with -g/--guided or -D/--remove")
    if args.item and not args.validate:
        ap.error("-i/--item only works together with -V/--validate")
    if args.dry_run and not args.safari_login:
        ap.error("-n/--dry-run only works together with -L/--safari-login")
    others = (
        args.check_all,
        args.snapshot,
        args.refresh_pass,
        args.install_daily,
        args.uninstall_daily,
        args.test,
        args.guided,
        args.promote,
        args.release,
        args.remove,
        args.rearm,
    )
    if args.safari_login and any(others):
        ap.error(
            "-L/--safari-login runs alone (not with -c/-S/-R/-I/-U/-t/-g/-p/-Q/-D/-E)"
        )
    rc = launch_action(args)
    if rc is None:
        rc = listing_action(args)
    if rc is not None:
        return rc
    if args.snapshot:
        # First, before anything else touches the browser: a guided login
        # whose owner and watchdog both died leaves its record behind.
        outcome = recover_stale_guided_login()
        if outcome is not None:
            print(outcome)
        data = overview(fresh=True)
        prune_removed(data)
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
    if args.refresh:
        prune_removed(data)
    write_agent_summary(data)
    if args.agents:
        print(agent_summary(data, last_checks()), end="")
        return 0
    if args.matrix:
        return print_matrix(data, as_json=args.json)
    if args.keychain:
        agent_login_keychain.refresh(_state_path("keychain.json"), force=True)
        agent_login_keychain.print_list(_state_path("keychain.json"), _c, full=True)
        return 0
    if args.json:
        data["credentials"] = agent_login_cred.summary(agent_login_cred.load())
        print(json.dumps(data, indent=1))
    else:
        print_overview(data)
        for line in agent_login_toolchain.describe():  # WS1b D9
            print(f"  {line}")
        print()
        agent_login_keychain.print_list(_state_path("keychain.json"), _c)
        print()
        agent_login_cred.print_section(_c)  # tp#991: credctl's daily verdicts
    return 0 if data["broker_ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
