"""login-broker daemon: logs into whitelisted sites, hands out session bundles.

Runs as the role account ``_loginbroker`` (LaunchDaemon). Agents (uid 501) talk
to it over a Unix socket; every connection's peer uid is checked with
LOCAL_PEERCRED. One JSON request per connection, newline-terminated, at most
64 KiB:

  {"op": "ping"}
  {"op": "sites"}                 ids, fill origins, cookie scope, check URL and
                                  sentinel — never secrets; cached SITES_TTL_S,
                                  "fresh": true re-reads Bitwarden
  {"op": "login", "site": "X"}    -> {"ok": true, "bundle": {...}}
  {"op": "logout", "site": "X"}   delete the broker's own profile for X
  {"op": "fingerprint", ...}      REMOVED (tp#965: it was a password oracle):
                                  answers {"ok": false, "error": "removed"};
                                  compare with mydotfiles credctl.py check -T
  {"op": "forget", "site": "X"}   WS3 removal: X's limiter key + bindings
                                  (an orphan group key too), identity guard,
                                  profile and failure screenshot - only when
                                  a FRESH vault read has no item X
                                  (``still_listed`` otherwise), under X's
                                  site lock; -> counts / flags only

Account identity (WS5, broker/identity_ops.py; a username never leaves the
broker, the page's value never leaves the page):

  {"op": "identity_challenge", "site": "X", "instance": ""}
                                  -> {"ok": true, "challenge_id": "...",
                                      "nonce": "<64 hex>", "identity": "gitlab",
                                      "privilege": "user", "ttl_s": 60}
                                  only for an item a login would serve (same
                                  gates, the caller's browser instance); one
                                  use, bound to X and the peer pid; capped per
                                  site and per pid
  {"op": "identity_answer", "challenge_id": "...", "digest": "<64 hex>"}
                                  sha256(nonce || normalised account name)
                                  -> {"ok": true, "result": "match" |
                                      "mismatch" | "expired"}; a mismatch
                                  blocks X's challenges 1 h, then 6 h, the
                                  3rd in 7 days until install.sh -r X

Credential rotation (tp#965; mydotfiles ``credctl rotate``, peer uid
``--allow-uid`` only):

  {"op": "rotation_lease", "txid": "20261013T120000Z-a1b2c3",
   "sites": ["x", "y"], "ttl_s": 1200}
                                  record the lease FIRST (persisted 0600 in
                                  the broker home: a restart keeps it until
                                  its TTL; default 1200 s, at most 3600 s),
                                  so every NEW login, scheduled login,
                                  sentinel probe and identity challenge of a
                                  leased site answers "held"; then drain:
                                  wait (bounded, DRAIN_S) until each site's
                                  in-flight login released its site lock
                                  -> {"ok": true, "result": "leased", ...};
                                  drain timeout -> lease dropped, "busy";
                                  an unknown site, or one leased by another
                                  txid, is refused (nothing recorded)
  {"op": "rotation_release", "txid": "..."}
                                  drop the lease -> {"ok": true, "result":
                                  "released", "released": true|false}

  A leased site, or one whose item carries ``agent_hold = <txid>`` (written
  by credctl, removed when the copy holds the new value), answers
  {"ok": false, "error": "held", "txid": "..."|null}: a skip, never counted
  by the limiter, never a quarantine or a failure mail. An expired lease is
  dropped by the next request that reads it.

"Are A and B one account?" is root-only, never a socket op:
``sudo install/install.sh -S A B`` (``daemon.py -S A B`` as the broker uid)
prints same / different / unknown.

Secrets for agents (``secret-run``; the secrets collection of the bootstrap,
peer uid ``--allow-uid`` only — anything else is ``forbidden`` before any
vault read):

  {"op": "secrets"}               ids, exposed field NAMES, has_totp, short
  {"op": "secret", "items": [{"item": "x", "field": "password"}],
   "env": ["X"], "argv0": "kubectl"}
                                  -> {"ok": true, "values": [...], "nonce": "...",
                                      "variants_policy": N} — the ONLY response
                                  that carries a value; every value is first
                                  registered with the secretkeeper
  {"op": "totp", "item": "x"}     -> {"ok": true, "code": "123456", "valid_s": N}
  {"op": "secret_done", "nonce": "...", "exit": 0, "masked": 2}
                                  closes the run row (once)
  {"op": "audit", "n": 50}        the last N audit lines (secret-free)
  {"op": "invalidate"}            drop cached values (also SIGHUP)

Fill into Albert's Safari (tp#1082, broker/fill_ops.py; peer uid
``--allow-uid`` only, ``forbidden`` before any vault read; only items with
``agent_safari_fill = true``, only for one of the item's fill origins, only
while the console is unlocked and used within 15 min):

  {"op": "safari_fill", "item": "<name|site id|alias>",
   "origin": "https://host[:port]", "fields": ["username", "password"]}
                                  -> {"ok": true, "site": "x", "values":
                                      {"username": ..., "password": ...}}
                                  (only the requested fields; every value
                                  registered with the secretkeeper first,
                                  labels loginbroker:fill.<site>:<field>)
  {"op": "safari_fill", ..., "fields": ["totp"]}
                                  -> {"ok": true, "site": "x", "code":
                                      "123456", "valid_s": N}
                                  limiter fill:<site> 10/h 40/day,
                                  filltotp:<site> 10/h, fill:* 20/h 60/day,
                                  at most 15 distinct items per 24 h

Errors: {"ok": false, "error": "needs_human" | "origin_violation" |
"rate_limited" | "login_failed" | "export_failed" | "bundle_export" |
"timeout" | "unknown_site" | "unknown_item" | "still_listed" | "busy" |
"forget_incomplete" | "held" | "removed" |
"unknown_field" | "refused" | "vault_error" | "leakcheck_unavailable" |
"no_item" | "ambiguous" | "not_enabled" | "no_password" | "unattended" |
"fill_only" | "forbidden" | "bad_request" | "internal", "detail": "..."} —
never a secret. ``fill_only`` (tp#1082 D5): ``login`` (scheduled, candidate,
refresh_only), ``sentinel_absent`` and ``identity_challenge`` of an item with
``agent_fill_only = true`` — a skip answered before any limiter charge,
quarantine, failure screenshot or mail; only ``safari_fill`` serves it.

Examples:
  daemon.py                                   # production (as _loginbroker)
  daemon.py -d -f items.json -H /tmp/lb -s /tmp/lb/broker.sock -u 501 -L
  daemon.py -C -H /var/db/login-broker        # list visible collections (IDs)
  sudo daemon.py -r ricardo                   # reset the limiter for one site
  sudo daemon.py -r secret:github             # reset a secret item's limiter
  sudo daemon.py -r fill:github               # reset a site's safari_fill limiter
  sudo daemon.py -r group:galaxus             # reset an attempt group
  sudo daemon.py -r galaxus -G                # reset a site and its groups
  daemon.py -M                                # dual / unreadable members, as
                                              # the broker uid (install.sh -M)
"""

from __future__ import annotations

# runner, protocol and CLI of one daemon.
# pylint: disable=too-many-lines
import argparse
import calendar
import contextlib
import dataclasses
import json
import os
import re
import secrets
import shutil
import signal
import socketserver
import stat
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

if __package__ in (None, ""):  # run as a script: make `broker` importable
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# pylint: disable=wrong-import-position
from broker import auditlog  # noqa: E402
from broker import identity as _identity  # noqa: E402
from broker.attended import attended as attended_gate  # noqa: E402
from broker.bundle import (  # noqa: E402
    DIAG_CAP,
    cookie_diag,
    filter_cookies,
    filter_storage,
)
from broker.fill_ops import FILL_OPS, FillOps  # noqa: E402
from broker.identity_ops import (  # noqa: E402
    IDENTITY_OPS,
    TAG_KEY_NAME,
    GuardStateError,
    IdentityGuard,
    IdentityOps,
    TagKeyError,
    load_tag_key,
    same_account_answer,
)
from broker.idp_reasons import MAX_KEPT as IDP_MAX_KEPT  # noqa: E402
from broker.idp_reasons import body_too_large  # noqa: E402
from broker.idp_reasons import classify as idp_classify  # noqa: E402
from broker.idp_reasons import rule_for as idp_rule_for  # noqa: E402
from broker.leakcheck import (  # noqa: E402
    DEFAULT_SOCKET as SECRETKEEPER_SOCKET,
)
from broker.leakcheck import (  # noqa: E402
    REPUSH_INTERVAL_S,
    DisabledLeakCheck,
    LeakCheck,
    Registrar,
    UnconfiguredLeakCheck,
)
from broker.limiter import (  # noqa: E402
    AttemptGrant,
    Denied,
    Limiter,
    LimiterBusy,
    LimiterStateError,
    group_key,
    proc_start,
)
from broker.origins import access_gated, origin_allowed  # noqa: E402
from broker.pac import pac_flag  # noqa: E402
from broker.page_state import (  # noqa: E402
    diagnose,
    redacted_snapshot,
    sentinel_shown,
)
from broker.peercred import peer_pid, peer_uid  # noqa: E402
from broker.phases import PHASE_V  # noqa: E402
from broker.recipes import (  # noqa: E402
    INDETERMINATE,
    NO_PASSKEY_JS,
    PREFLIGHTS,
    REFRESH_NONE,
    REFRESH_REJECTED,
    VALID,
    AccessGated,
    AttemptController,
    BundleExportError,
    ExportFailed,
    LoginFailed,
    NavTrail,
    NeedsHuman,
    OriginViolation,
    RecipeError,
    check_page_url,
    check_proof_reason,
    cscs_export_storage,
    load_document,
    page_access_gated,
    proof_reason_text,
    raise_if_blocked,
    recipe_for,
    refresh_session,
)
from broker.runs import RunTable  # noqa: E402
from broker.secret_ops import (  # noqa: E402
    LIMITER_KEY_PREFIXES,
    LIMITER_KEY_RE,
    SECRET_OPS,
    SecretOps,
    build_secret_limiter,
)
from broker.statefile import write_json_atomic  # noqa: E402
from broker.useragent import CHROME_UA_TEMPLATE, engine_user_agent  # noqa: E402
from broker.vault import (  # noqa: E402
    GATE_OK,
    SITE_ID_RE,
    TXID_RE,
    USERNAME_ONLY,
    BwBootstrap,
    BwVault,
    FillOnly,
    FixtureVault,
    GateRow,
    Held,
    Secret,
    SecretItem,
    SecretValues,
    SiteItem,
    Vault,
    VaultCache,
    VaultError,
    fill_only_detail,
    hold_view,
    selector_ok,
    slugify,
)

# pylint: enable=wrong-import-position

DEFAULT_SOCKET = "/var/db/login-broker-run/broker.sock"
DEFAULT_HOME = "/var/db/login-broker"
DEFAULT_ALLOW_UID = 501
MAX_REQUEST = 64 * 1024
READ_TIMEOUT_S = 30.0
MIN_INTERVAL_S = 120.0
PER_HOUR = 4
PER_DAY = 10
# A plain desktop-Chrome User-Agent (headless Chromium says HeadlessChrome,
# which Cloudflare challenges). Its major version must be the ENGINE's: the
# browser still sends Sec-CH-UA with the real version, and a mismatch is a bot
# signal — gitlab.ethz.ch's Anubis answered a fixed "Chrome/141" on engine 148
# with proof-of-work difficulty 7 (~20 min) instead of 2 (verified 2026-10-08).
# LOGIN_BROKER_USER_AGENT overrides; the fixed version is only the fallback
# when the engine's version cannot be read.
FALLBACK_CHROME_UA = CHROME_UA_TEMPLATE.format(major=141)
CHROME_ARGS = ["--use-mock-keychain", "--disable-blink-features=AutomationControlled"]


def launch_args() -> list[str]:
    """The broker Chromium's command-line switches: CHROME_ARGS plus the
    release's home-proxy PAC (``broker/pac.py`` — a constant, never the
    agent-writable ``bin/pac_hosts.json``). Playwright adds no proxy switch of
    its own while ``proxy`` is unset, so this PAC is the one in force."""
    return [*CHROME_ARGS, pac_flag()]


def launch_kwargs(pw: Any, profile: Path) -> dict[str, Any]:
    """``launch_persistent_context`` keyword arguments for a broker Chromium
    on `profile` (no ``channel``; the caller picks it)."""
    return {
        "user_data_dir": str(profile),
        "headless": True,
        "args": launch_args(),
        "user_agent": broker_user_agent(pw),
        "chromium_sandbox": True,
    }


_BLANK_PASSWORDS_JS = (
    "() => document.querySelectorAll('input[type=password]').forEach(i => i.value = '')"
)
CSCS_PORTAL_ORIGIN = "https://portal.cscs.ch"
# The portal page the CSCS export reads on: /profile/, never `/` — the portal's
# boot-redirect.js races a read there (it sends a session it thinks expired to
# the IdP before the app runs).
CSCS_EXPORT_URL = CSCS_PORTAL_ORIGIN + "/profile/"
_STORAGE_JS = "keys => Object.fromEntries(keys.map(k => [k, localStorage.getItem(k)]))"
# `login` with ``diag`` (value-free): the storage NAMES of an already open
# page — localStorage / sessionStorage keys and IndexedDB database names,
# sorted, at most `cap` each; never a value. Run in an isolated world.
_STORAGE_NAMES_JS = (
    "async cap => { const keys = s => Object.keys(s).sort().slice(0, cap);"
    " let idb = null;"
    " try { idb = (await indexedDB.databases()).map(d => String(d.name))"
    ".sort().slice(0, cap); } catch (e) {}"
    " return {local: keys(localStorage), local_n: localStorage.length,"
    " session: keys(sessionStorage), session_n: sessionStorage.length,"
    " indexeddb: idb}; }"
)
# The bundle key the runner hands its diagnostics to `_do_login` under; never
# sent as part of the bundle (`Broker._do_login` moves it to the reply).
BUNDLE_DIAG_KEY = "bundle_diag"


# How long the broker profile's proof polls for the sentinel (an SPA boots:
# reads its token, asks its API, renders).
PROFILE_PROOF_WAIT_S = 8.0

# The broker's own bound on ONE login run (profile proof, secret, recipe,
# proof, export). Callers wait longer, in this order (tests pin it):
#   RUN_DEADLINE_S (255) < browser.py BROKER_TIMEOUT_S (285, its socket)
#   < browser.py LOGIN_TIMEOUT_S (480) < agent-login's runner (+90) and the
#   consumers' subprocess timeouts (cscs-api.py)
# so a client always gets the broker's answer, never a cut-off reply while the
# broker goes on. A fresh CSCS login (vault read + Keycloak + TOTP) measured
# 188 s on 2026-10-09. Past the deadline `RunWatchdog` kills the run's
# Chromium: every pending Playwright call fails and the run ends as `timeout`.
RUN_DEADLINE_S = 255.0
# A password login starts only while this much of the run is left: a login
# cut off right after its submit would count as `unknown` (cooldown) although
# nothing was wrong with it.
MIN_LOGIN_LEFT_S = 150.0


# The executable of a Chromium process: Playwright's Chromium, Chrome for
# Testing, the headless shell and their helpers ("Chromium Helper (Renderer)").
_CHROME_EXE_RE = re.compile(r"chrom|headless_shell", re.IGNORECASE)
_PS_ENV = {"LC_ALL": "C", "LANG": "C", "TZ": "UTC", "PATH": "/bin:/usr/bin"}


def chrome_pids(profile: Path) -> list[int]:
    """Pids of the Chromium processes running on `profile`; [] when unknown.

    ``/bin/ps`` (pinned, C locale) prints each command line with its argv
    joined by spaces, so a path with a space cannot be split back into
    argv. A line counts when its EXECUTABLE (everything before the first
    `` --``) is a Chromium binary and ``--user-data-dir=<profile>`` appears
    followed by the end of the line or the next `` --`` option — so a
    sibling profile (``<profile>-other``), a profile path with a space, and
    a process that merely carries the flag as data (``grep``) are told
    apart."""
    try:
        out = subprocess.run(
            ["/bin/ps", "-axww", "-o", "pid=,command="],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
            env=_PS_ENV,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    flag = re.compile(r" --user-data-dir=" + re.escape(str(profile)) + r"(?= --|$)")
    pids = []
    for line in out.splitlines():
        pid, _, cmd = line.strip().partition(" ")
        cmd = cmd.strip()
        exe = cmd.split(" --", 1)[0]
        if (
            pid.isdigit()
            and int(pid) != os.getpid()
            and _CHROME_EXE_RE.search(os.path.basename(exe))
            and flag.search(cmd)
        ):
            pids.append(int(pid))
    return pids


def start_epoch(pid: int) -> float | None:
    """When `pid` started (epoch seconds, ``ps`` lstart in UTC); None when
    unknown."""
    text = proc_start(pid)
    if not text:
        return None
    try:
        parsed = time.strptime(" ".join(text.split()), "%a %b %d %H:%M:%S %Y")
    except ValueError:
        return None
    return float(calendar.timegm(parsed))


class RunWatchdog:  # pylint: disable=too-many-instance-attributes  # identity + 2 events
    """Kills the Chromium of `profile` once `limit_s` passed (unless the run
    ended first); ``fired`` (an Event) says the deadline passed. A sync
    Playwright call cannot be interrupted from another thread, but a dead
    browser ends every one.

    Identity: ``arm()`` records the run's Chromium pids with their start
    times right after the launch. At the deadline a pid is killed only while
    it still runs on `profile` (``chrome_pids``: unique to the site and its
    site lock) AND either still has its recorded start time, or — a pid not
    seen at ``arm()`` (a helper started later) — started no earlier than
    this run (1 s ``ps`` resolution). A reused pid is never touched; a run
    that ended meanwhile (``_stop``) kills nothing more."""

    def __init__(self, profile: Path, limit_s: float) -> None:
        self.profile = profile
        self.limit_s = limit_s
        self.started = time.time()
        self.fired = threading.Event()
        self.killed: list[int] = []
        self._armed: dict[int, str | None] = {}
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def arm(self) -> None:
        """Record the run's Chromium (pid -> start time), after the launch."""
        self._armed = {pid: proc_start(pid) for pid in chrome_pids(self.profile)}

    def _ours(self, pid: int) -> bool:
        if pid in self._armed:
            want = self._armed[pid]
            return want is not None and proc_start(pid) == want
        began = start_epoch(pid)
        return began is not None and began >= self.started - 1.0

    def _run(self) -> None:
        if self._stop.wait(self.limit_s):
            return
        self.fired.set()
        for pid in chrome_pids(self.profile):
            if self._stop.is_set():
                return  # the run ended meanwhile
            if not self._ours(pid):
                continue
            with contextlib.suppress(OSError):
                os.kill(pid, signal.SIGKILL)
                self.killed.append(pid)

    def __enter__(self) -> RunWatchdog:
        self._thread.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self._stop.set()
        self._thread.join(timeout=2)


class DeadlineError(LoginFailed):
    """The run passed ``RUN_DEADLINE_S`` (code ``timeout``)."""

    code = "timeout"


# WS5 verdict of the broker's own identity proof -> (code, fixed detail).
_IDENTITY_FAILURES = {
    _identity.WRONG_ACCOUNT: (
        "wrong_account",
        "the session in the broker's profile belongs to another account",
    ),
    _identity.PRIVILEGE_MISMATCH: (
        "privilege_mismatch",
        "the account's admin bit does not match agent_privilege",
    ),
    _identity.LOGGED_OUT: (
        "login_failed",
        "the site's identity endpoint says logged out after the login",
    ),
}


class IdentityMismatch(LoginFailed):
    """WS5: the broker's own identity proof (``identity.local_verdict``) did
    not say ``match`` — phase ``broker-proof``, no bundle. The detail is
    fixed text: never a name, nonce or digest."""

    def __init__(
        self, verdict: str, *, submitted: bool = False, auth_proven: bool = False
    ) -> None:
        code, detail = _IDENTITY_FAILURES.get(
            verdict,
            (
                "identity_indeterminate",
                "the site's identity endpoint could not tell which account is "
                "logged in",
            ),
        )
        super().__init__(
            detail, phase="broker-proof", submitted=submitted, auth_proven=auth_proven
        )
        self.code = code
        self.verdict = verdict


def evaluate_isolated(page: Any, js: str, arg: Any) -> Any:
    """``js(arg)`` (an async function's source) in a FRESH CDP isolated world
    of `page`'s main frame, its value returned by value: page scripts share
    the DOM but not the world's ``fetch`` / ``crypto`` / prototypes, so they
    cannot hook the identity fetch or its hash. Service workers are bypassed
    for this session only (its own network agent; detaching drops it). Any
    CDP or script failure raises — the
    caller treats it as ``indeterminate``; there is no main-world fallback."""
    session = page.context.new_cdp_session(page)
    try:
        tree = session.send("Page.getFrameTree")
        frame_id = tree["frameTree"]["frame"]["id"]
        world = session.send(
            "Page.createIsolatedWorld",
            {"frameId": frame_id, "worldName": f"ws5-{secrets.token_hex(6)}"},
        )
        context_id = world["executionContextId"]
        this = session.send(
            "Runtime.evaluate", {"expression": "globalThis", "contextId": context_id}
        )
        object_id = this["result"]["objectId"]
        # The bypass is a setting of THIS DevTools session's network agent:
        # detaching the session (below) drops it; nobody else's is touched.
        session.send("Network.enable")
        session.send("Network.setBypassServiceWorker", {"bypass": True})
        got = session.send(
            "Runtime.callFunctionOn",
            {
                "functionDeclaration": js,
                "objectId": object_id,
                "arguments": [{"value": arg}],
                "awaitPromise": True,
                "returnByValue": True,
            },
        )
        if got.get("exceptionDetails"):
            raise RuntimeError("the identity recipe raised")
        return (got.get("result") or {}).get("value")
    finally:
        with contextlib.suppress(Exception):
            session.detach()


def deadline_error(exc: BaseException) -> DeadlineError:
    """The run's error once its watchdog fired: code ``timeout``, the phase
    and submit/auth flags of the error it caused (if a recipe error)."""
    err = DeadlineError(
        f"the broker run passed its {RUN_DEADLINE_S:g} s deadline"
        + (f" ({exc.detail})" if isinstance(exc, RecipeError) else ""),
        submitted=bool(getattr(exc, "submitted", False)),
        phase=getattr(exc, "phase", None),
        auth_proven=bool(getattr(exc, "auth_proven", False)),
        unsent=bool(getattr(exc, "unsent", False)),
    )
    return err


def clear_http_cache(ctx: Any) -> bool:
    """Drop the profile's HTTP cache — cookies and storage stay.

    A persistent profile serves a page with no ``Cache-Control`` from its
    heuristic cache (10 % of its ``Last-Modified`` age) without asking the
    server. After an app upgrade that is a stale SPA ``index.html`` naming
    hashed chunks the server no longer has; the server's SPA fallback answers
    them with HTML, the lazy route fails and the page stays blank — NPM
    2026-10-10: the login succeeded server-side, the dashboard never rendered
    (its Dashboard chunk of the old build came back as ``text/html``). Each
    broker run starts on the server's current build instead.

    When the clear fails, the first page ignores the cache instead
    (``Network.setCacheDisabled`` on a session kept with the context) and a
    warning goes to the broker log. Returns whether the cache was cleared."""
    page = None
    try:
        page = ctx.pages[0] if ctx.pages else ctx.new_page()
        session = ctx.new_cdp_session(page)
        try:
            session.send("Network.clearBrowserCache")
        finally:
            with contextlib.suppress(Exception):
                session.detach()
        return True
    except Exception as exc:  # pylint: disable=broad-exception-caught
        why = exception_site(exc)
    fallback = "no fallback"
    with contextlib.suppress(Exception):
        session = ctx.new_cdp_session(page)
        session.send("Network.enable")
        session.send("Network.setCacheDisabled", {"cacheDisabled": True})
        _NOCACHE_SESSIONS[id(ctx)] = session
        fallback = "the first page ignores the cache"
    print(f"⚠️ could not clear the HTTP cache ({why}); {fallback}", file=sys.stderr)
    return False


# id(context) -> the CDP session that keeps `clear_http_cache`'s fallback alive.
_NOCACHE_SESSIONS: dict[int, Any] = {}


def item_origins(item: SiteItem) -> list[str]:
    """Every origin the item's login and session use: fill origins, storage
    origins, the check / login pages' origins and the proof origins."""
    out: list[str] = []
    pages = [item.check_url, item.login_url]
    for origin in [
        *item.fill_origins,
        *item.storage_keys,
        *(
            urllib.parse.urlsplit(u)._replace(path="", query="", fragment="").geturl()
            for u in pages
            if u
        ),
        *item.proof_origins,
    ]:
        if origin and origin not in out:
            out.append(origin)
    return out


def clear_origin_workers(ctx: Any, origins: list[str]) -> bool:
    """Unregister the service workers and drop the Cache Storage of
    `origins` (``Storage.clearDataForOrigin``): a worker can serve a stale
    app shell like the HTTP cache does (`clear_http_cache`). Cookies and
    localStorage stay. Best effort; a failure is logged. True when cleared."""
    try:
        page = ctx.pages[0] if ctx.pages else ctx.new_page()
        session = ctx.new_cdp_session(page)
        try:
            for origin in origins:
                session.send(
                    "Storage.clearDataForOrigin",
                    {"origin": origin, "storageTypes": "service_workers,cache_storage"},
                )
        finally:
            with contextlib.suppress(Exception):
                session.detach()
        return True
    except Exception as exc:  # pylint: disable=broad-exception-caught
        print(
            f"⚠️ could not clear service workers ({exception_site(exc)})",
            file=sys.stderr,
        )
        return False


# id(context) -> file names of scripts the site answered with HTML in this run.
_HTML_SCRIPTS: dict[int, list[str]] = {}


def watch_script_mime(ctx: Any) -> list[str]:
    """Record every script the site answers with ``text/html`` (path only).

    A SPA whose server answers a missing hashed chunk with its HTML fallback
    renders blank (a stale cached build, or an asset deleted by an upgrade):
    the failure report names it, so the server side can be fixed too
    (``Cache-Control: no-cache`` on the SPA HTML, 404 for missing assets)."""
    seen: list[str] = []

    def on_response(resp: Any) -> None:
        try:
            ctype = str(resp.headers.get("content-type") or "")
            if resp.request.resource_type == "script" and "text/html" in ctype:
                # The file name only: a path can carry a session token (Home
                # Assistant's ingress URLs).
                path = urllib.parse.urlsplit(str(resp.url)).path
                seen.append(path.rsplit("/", 1)[-1][:80] or "/")
        except Exception:  # pylint: disable=broad-exception-caught
            pass

    with contextlib.suppress(Exception):
        ctx.on("response", on_response)
        _HTML_SCRIPTS[id(ctx)] = seen
    return seen


# id(context) -> the finished requests to IdP password endpoints
# (``broker/idp_reasons.py``) of this run.
_IDP_RESPONSES: dict[int, list[Any]] = {}


def watch_idp_responses(ctx: Any) -> list[Any]:
    """Keep the FINISHED requests to known IdP password endpoints (POST, https,
    allowlisted host + path; the last ``IDP_MAX_KEPT``). Only the request
    objects: their responses are read once the recipe is done (`idp_reason`),
    never in the handler — and a finished request's body is complete, so the
    read never waits for the network."""
    kept: list[Any] = []

    def on_finished(req: Any) -> None:
        try:
            if idp_rule_for(str(req.method), str(req.url)) is not None:
                kept.append(req)
                del kept[:-IDP_MAX_KEPT]
        except Exception:  # pylint: disable=broad-exception-caught
            pass

    with contextlib.suppress(Exception):
        ctx.on("requestfinished", on_finished)
        _IDP_RESPONSES[id(ctx)] = kept
    return kept


def idp_reason(ctx: Any) -> str | None:
    """The phase code of the run's LAST readable IdP password answer
    (``idp_invalid_credentials`` / ``idp_unknown`` / ``captcha_required``), or
    None. Call it right after the recipe, before anything navigates away (a
    navigation discards the bodies)."""
    for req in reversed(_IDP_RESPONSES.get(id(ctx)) or []):
        try:
            resp = req.response()
            if resp is None or body_too_large(resp.headers):
                continue
            return idp_classify(
                str(req.method), str(req.url), int(resp.status), resp.body()
            )
        except Exception:  # pylint: disable=broad-exception-caught
            continue
    return None


def html_script_hint(page: Any) -> str:
    """`` — the site served HTML for N script(s) (...)`` when that happened
    in this run (`watch_script_mime`), else ``""``."""
    try:
        seen = _HTML_SCRIPTS.get(id(page.context)) or []
    except Exception:  # pylint: disable=broad-exception-caught
        return ""
    if not seen:
        return ""
    return (
        f" — the site served HTML for {len(set(seen))} script(s): a stale "
        "cached build or a missing asset"
    )


def broker_user_agent(pw: Any) -> str:
    """``LOGIN_BROKER_USER_AGENT``, else the engine's own version
    (``engine_user_agent``), else ``FALLBACK_CHROME_UA``."""
    override = os.environ.get("LOGIN_BROKER_USER_AGENT")
    if override:
        return override
    try:
        executable = str(pw.chromium.executable_path)
    except Exception:  # pylint: disable=broad-exception-caught
        executable = ""
    return (executable and engine_user_agent(executable)) or FALLBACK_CHROME_UA


# A login runner: (item, get_secret) -> bundle. Raises RecipeError on failure.
Runner = Callable[[SiteItem, Callable[[], Secret]], dict[str, Any]]


# ---------------------------------------------------------------------------
# Playwright runner (the real one; tests inject a stub)
# ---------------------------------------------------------------------------


class PlaywrightRunner:
    """Own headless Chromium per site: persistent profile, sandbox on, pipe CDP."""

    def __init__(
        self, home: Path, *, dev: bool = False, diag_dir: Path | None = None
    ) -> None:
        self.home = home
        self.dev = dev
        self.channel_fallback = False  # set when dev fell back to the default build
        # Failure screenshots go where the agent user may read them (the socket
        # dir); the broker home stays closed.
        self.diag_dir = diag_dir or (home if dev else Path(DEFAULT_SOCKET).parent)
        self.last_diag: dict[str, dict[str, Any]] = {}
        # site -> the reason code of its latest `_profile_proof`
        # (``recipes.PROOF_REASONS``; "" valid)
        self.proof_reasons: dict[str, str] = {}

    def profile_dir(self, site: str) -> Path:
        """The broker's own profile for `site`."""
        return self.home / "profiles" / site

    def _launch(self, pw: Any, profile: Path, item: SiteItem | None = None) -> Any:
        kwargs = launch_kwargs(pw, profile)
        try:
            ctx = pw.chromium.launch_persistent_context(channel="chromium", **kwargs)
        except Exception:  # pylint: disable=broad-exception-caught
            if not self.dev:
                raise
            # Dev only: the full `chromium` build may be missing from the local
            # Playwright cache; the default build is good enough for a fixture.
            self.channel_fallback = True
            ctx = pw.chromium.launch_persistent_context(**kwargs)
        # Every page and frame of the context, the already open one included.
        ctx.add_init_script(NO_PASSKEY_JS)
        clear_http_cache(ctx)
        if item is not None:
            clear_origin_workers(ctx, item_origins(item))
        watch_script_mime(ctx)
        watch_idp_responses(ctx)
        return ctx

    def _profile_proof(self, page: Any, item: SiteItem) -> str:
        """The tri-state proof (``recipes.check_proof``) on the broker's own
        profile; an exception is ``indeterminate``. Its reason code is kept
        in ``proof_reasons[site]`` (``_proof_reason``)."""
        try:
            answer, reason = check_proof_reason(
                page, item, dev=self.dev, wait_s=PROFILE_PROOF_WAIT_S
            )
        except Exception:  # pylint: disable=broad-exception-caught
            answer, reason = INDETERMINATE, "raised"
        self.proof_reasons[item.site] = reason
        return answer

    def _proof_reason(self, item: SiteItem) -> str:
        """The latest proof's reason code of `item`, also recorded as
        ``last_diag[site]["proof_reason"]``; "" when none is known."""
        reason = self.proof_reasons.get(item.site, "")
        if reason:
            self.last_diag.setdefault(item.site, {})["proof_reason"] = reason
        return reason

    @staticmethod
    def _identity_verdict(page: Any, item: SiteItem, username: str) -> str:
        """WS5: the item's identity recipe (``identity.usable_recipe``) in an
        ISOLATED world of the broker's OWN page (``evaluate_isolated``: page
        scripts cannot hook its fetch or crypto, service workers bypassed),
        on the proven check page, against `username` — compared in-process
        with a fresh local nonce. ``match`` when the item names no recipe;
        an item naming one that is not usable is ``indeterminate``."""
        if not item.identity:
            return _identity.MATCH
        # (`identity.item_recipe`: usable, this site and check origin, this
        # privilege — the same rule as the validation and the client)
        recipe = item.identity_recipe
        if recipe is None:
            return _identity.INDETERMINATE
        nonce = secrets.token_hex(_identity.NONCE_BYTES)
        try:
            answer = evaluate_isolated(
                page,
                _identity.RECIPE_JS,
                _identity.recipe_args(recipe, check_page_url(item), nonce),
            )
        except Exception:  # pylint: disable=broad-exception-caught
            answer = None
        return _identity.local_verdict(answer, nonce, username, item.privilege)

    def _identity_reuse(self, page: Any, item: SiteItem) -> str:
        """WS5 on a profile or SSO reuse (nothing reserved yet): ``ok`` (the
        item's account, export it), ``login`` (logged out: log in), or
        ``reset`` (ANOTHER account: clear the site's cookies and storage in
        the broker profile, then ONE fresh login — an attempt like any other,
        proven again afterwards). Anything else raises before anything is
        reserved or submitted: ``indeterminate`` (the endpoint could not
        tell: no guess-login on a 5xx) and a wrong admin bit on the right
        account (a login cannot fix it)."""
        verdict = self._identity_verdict(page, item, item.account_name)
        if verdict == _identity.MATCH:
            return "ok"
        if verdict == _identity.LOGGED_OUT:
            return "login"
        if verdict == _identity.WRONG_ACCOUNT:
            return "reset"
        raise IdentityMismatch(verdict)

    def _identity_after_login(
        self, page: Any, item: SiteItem, username: str, attempt: AttemptController
    ) -> None:
        """WS5 after a VALID login proof: anything but ``match`` raises
        ``IdentityMismatch`` with ``auth_proven`` — the password worked, so
        it never feeds the bad-password streak (outcome
        ``identity_mismatch``) — and no bundle leaves."""
        verdict = self._identity_verdict(page, item, username)
        if verdict != _identity.MATCH:
            raise IdentityMismatch(
                verdict, submitted=attempt.submitted, auth_proven=True
            )

    def _record_failure(self, page: Any, item: SiteItem, secret: Secret) -> None:
        """Secret-free failure report + screenshot (password fields emptied first)."""
        try:
            diag: dict[str, Any] = diagnose(page, secret)
        except Exception:  # pylint: disable=broad-exception-caught
            diag = {"error": "page could not be inspected"}
        if secret.mode == USERNAME_ONLY:
            # The credential is an account number the site may show anywhere
            # (a field, an error text, the account page): no picture at all,
            # and none of an earlier run's left behind under this site's name.
            diag["screenshot_withheld"] = "username-only login: the page may show it"
            with contextlib.suppress(OSError):
                (self.diag_dir / f"last-failure-{item.site}.png").unlink()
            self.last_diag[item.site] = diag
            return
        try:
            page.evaluate(_BLANK_PASSWORDS_JS)
            shot = self.diag_dir / f"last-failure-{item.site}.png"
            page.screenshot(path=str(shot), full_page=False)
            os.chmod(shot, 0o644)
            diag["screenshot"] = str(shot)
        except Exception:  # pylint: disable=broad-exception-caught
            pass
        with contextlib.suppress(Exception):
            seen = _HTML_SCRIPTS.get(id(page.context)) or []
            if seen:
                diag["script_as_html"] = sorted(set(seen))[:3]
        self.last_diag[item.site] = diag

    def _note_challenge(self, item: SiteItem, exc: RecipeError, secret: Secret) -> None:
        """The page a challenge was SEEN on (``NeedsHuman.challenge``, taken
        at detection) as ``challenge_at_detection`` in the failure report: the
        screenshot and page picture show the page at failure time, which an
        interstitial that submits itself may already have left."""
        snapshot = getattr(exc, "challenge", None)
        if isinstance(snapshot, dict) and snapshot:
            self.last_diag.setdefault(item.site, {})["challenge_at_detection"] = (
                redacted_snapshot(snapshot, secret)
            )

    def _note_idp(
        self, item: SiteItem, reason: str | None, exc: RecipeError
    ) -> RecipeError:
        """The IdP's answer (`idp_reason`) in the failure report and, for a
        plain ``login_failed``, as its code (the phase stays). Returns `exc`."""
        if reason:
            self.last_diag.setdefault(item.site, {})["idp_reason"] = reason
            if exc.code == "login_failed":
                exc.code = reason
        return exc

    def _cscs_portal_storage(self, ctx: Any, item: SiteItem) -> dict[str, str]:
        """CSCS: the portal's allowlisted storage (``recipes.CSCS_EXPORT_KEYS``
        plus any portal key the item lists), read on ``/profile/`` in the same
        in-page step that server-validated ``waldur/auth/token``
        (``recipes.cscs_export_storage``). No validated token there →
        ``BundleExportError``: a CSCS bundle without it would log nobody in."""
        page = ctx.new_page()
        try:
            page.goto(CSCS_EXPORT_URL, wait_until="domcontentloaded")
            with contextlib.suppress(Exception):
                page.wait_for_load_state("load", timeout=10_000)
            if not origin_allowed(page.url, [CSCS_PORTAL_ORIGIN], dev=self.dev):
                raise BundleExportError(
                    "cscs: the portal page did not stay on the portal (redirected "
                    "to the IdP: the broker profile holds no live session)"
                )
            return cscs_export_storage(
                page, list(item.storage_keys.get(CSCS_PORTAL_ORIGIN, []))
            )
        except BundleExportError:
            raise
        except Exception as exc:  # pylint: disable=broad-exception-caught
            raise BundleExportError(
                f"cscs: the portal page could not be read ({exception_site(exc)})"
            ) from exc
        finally:
            with contextlib.suppress(Exception):
                page.close()

    def storage_names(self, ctx: Any, item: SiteItem) -> dict[str, Any]:
        """``diag`` only: the storage NAMES (`_STORAGE_NAMES_JS`) of the
        item's check, storage and fill origins, read on a page ALREADY open
        on that origin (no navigation: a load would run the app and might
        rotate the session the bundle just exported). None for an origin
        with no open page, ``{"error": ...}`` when it could not be read."""
        check = _identity.check_origin(check_page_url(item))
        origins = list(
            dict.fromkeys(
                [*([check] if check else []), *item.storage_keys, *item.fill_origins]
            )
        )
        out: dict[str, Any] = {}
        for origin in origins:
            page = next(
                (
                    pg
                    for pg in list(getattr(ctx, "pages", []) or [])
                    if _identity.check_origin(str(getattr(pg, "url", "") or ""))
                    == origin.lower()
                ),
                None,
            )
            if page is None:
                out[origin] = None
                continue
            try:
                got = evaluate_isolated(page, _STORAGE_NAMES_JS, DIAG_CAP)
                out[origin] = got if isinstance(got, dict) else {"error": "no answer"}
            except Exception:  # pylint: disable=broad-exception-caught
                out[origin] = {"error": "unreadable"}
        return out

    def export_bundle(
        self, ctx: Any, item: SiteItem, via: str, *, diag: bool = False
    ) -> dict[str, Any]:
        """Allowlisted cookies + named localStorage keys of the listed origins.

        CSCS's portal origin is read by `_cscs_portal_storage` (validated,
        on ``/profile/``); its keys are the ones actually present.

        `diag` (``login`` with ``"diag": true``): also ``BUNDLE_DIAG_KEY`` —
        the jar the export read, value-free (``bundle.cookie_diag``: every
        cookie on, under or above a scope host, kept or dropped and why),
        ``via`` and the open pages' storage names (`storage_names`).
        ``Broker._do_login`` moves it out of the bundle into the reply."""
        spec = item.bundle_spec
        raw: dict[str, dict[str, Any]] = {}
        if item.site == "cscs":
            portal = self._cscs_portal_storage(ctx, item)
            raw[CSCS_PORTAL_ORIGIN] = portal
            storage = {**spec.storage_keys, CSCS_PORTAL_ORIGIN: list(portal)}
            spec = dataclasses.replace(spec, storage_keys=storage)
        # Every cookie of the context, NO url filter: a url-filtered read
        # (`cookies(url)`) would drop a cookie whose path the url does not
        # path-match (``/realms/sdsc/`` for the root url).
        jar = ctx.cookies()
        cookies = filter_cookies(jar, spec)
        found: dict[str, Any] | None = None
        if diag:
            found = {
                **cookie_diag(jar, spec),
                "via": via,
                "storage_names": self.storage_names(ctx, item),
            }
        for origin, keys in spec.storage_keys.items():
            if origin in raw:
                continue
            page = ctx.new_page()
            try:
                page.goto(origin + "/", wait_until="domcontentloaded")
                # A redirect to another origin must not label ITS storage as ours.
                if origin_allowed(page.url, [origin], dev=self.dev):
                    values = page.evaluate(_STORAGE_JS, keys)
                    if isinstance(values, dict):
                        raw[origin] = values
            finally:
                with contextlib.suppress(Exception):
                    page.close()
        bundle: dict[str, Any] = {
            "site": item.site,
            "via": via,
            "cookies": cookies,
            "storage": filter_storage(raw, spec),
            "cookie_hosts": list(spec.cookie_hosts),
            # WS5 S4c: the scopes with their paths (the client clears and
            # injects only inside them; an older client reads the hosts)
            "cookie_scopes": [s.view() for s in spec.scopes],
            "scope_v": _identity.SCOPE_V,
            "cookie_names": spec.cookie_names,
            # The key NAMES the bundle must carry (the client checks the
            # bundle is complete before it touches the shared browser).
            "storage_keys": {o: list(k) for o, k in spec.storage_keys.items()},
        }
        if found is not None:
            bundle[BUNDLE_DIAG_KEY] = found
        return bundle

    def clear_site_cookies(self, ctx: Any, item: SiteItem) -> int:
        """``agent_fresh_login``: delete every cookie of the broker's OWN profile
        that the browser would send to one of the site's cookie hosts or fill
        origin hosts (the host itself, a subdomain or a parent domain of it),
        every path (`fresh_login_scopes`).

        Afterwards neither the site's long-lived account cookie nor a stale IdP
        cookie can short-circuit the login. Returns the number deleted.
        """
        scopes = fresh_login_scopes(item)
        cleared = 0
        for ck in ctx.cookies():
            domain = str(ck.get("domain") or "")
            if _identity.scopes_reach(scopes, domain, str(ck.get("path") or "/")):
                ctx.clear_cookies(
                    name=ck.get("name"), domain=domain, path=ck.get("path") or "/"
                )
                cleared += 1
        return cleared

    def reset_site_profile(self, ctx: Any, page: Any, item: SiteItem) -> Any:
        """WS5 reset of the broker's OWN profile for `item` (another
        account's session was found in it), returning the tab to log in on.

        First the tab leaves the app (``about:blank``) so its in-memory code
        cannot write a token back; then the site's cookies go
        (``clear_site_cookies``), and for every origin its session may live
        on (fill origins, storage origins, the check page's origin) the
        localStorage, IndexedDB, Cache Storage and service workers
        (``Storage.clearDataForOrigin``); finally a FRESH tab replaces the
        old one (its sessionStorage dies with it). Raises ``LoginFailed``
        (nothing typed yet) when any step fails: a fresh login on a
        half-cleared profile proves nothing. Host-wide on purpose, also
        for an item with path scopes (WS5 S4c): the broker's profile is the
        item's own — no sibling account lives in it to spare."""
        check = _identity.check_origin(check_page_url(item))
        origins = list(
            dict.fromkeys(
                [*item.fill_origins, *item.storage_keys, *([check] if check else [])]
            )
        )
        try:
            page.goto("about:blank")
            self.clear_site_cookies(ctx, item)
            session = ctx.new_cdp_session(page)
            try:
                for origin in origins:
                    session.send(
                        "Storage.clearDataForOrigin",
                        {"origin": origin, "storageTypes": SITE_STORAGE_TYPES},
                    )
            finally:
                with contextlib.suppress(Exception):
                    session.detach()
            fresh = ctx.new_page()
            page.close()
            return fresh
        except Exception as exc:
            raise LoginFailed(
                "could not reset the broker profile's site data before the fresh login",
                phase="profile-proof",
            ) from exc

    # One run's pipeline: reuse (with the WS5 identity check), or reserve,
    # log in, prove, export — kept in one place on purpose.
    def run_in_context(  # pylint: disable=too-many-branches,too-many-statements
        self,
        ctx: Any,
        item: SiteItem,
        get_secret: Callable[[], Secret],
        *,
        deadline: float | None = None,
    ) -> dict[str, Any]:
        """Profile proof (or, with ``fresh_login``, reservation + cookie wipe),
        recipe, positive proof and export on an already launched context.

        The limiter is only touched through `get_secret` (it reserves the
        attempt): a validated profile reuse never calls it, so it works during
        a cooldown and leaves the limiter untouched. `get_secret.attempt` (when
        present) is the ``AttemptController`` handed to the recipe.
        `deadline` (monotonic): the run's end; a password login is not started
        with less than ``MIN_LOGIN_LEFT_S`` left (code ``timeout``, nothing
        reserved).
        """
        page = ctx.pages[0] if ctx.pages else ctx.new_page()
        if getattr(get_secret, "candidate", False) and not getattr(
            get_secret, "candidate_checked", False
        ):
            # Two-sided: the candidate must be ABSENT on the check page of a
            # fresh, logged-OUT throwaway profile — before anything is reserved
            # or a cookie is cleared (`fresh_login` included). `__call__` does
            # it with its own Playwright before the site context opens.
            self._candidate_absent(self._throwaway_answer(item))
        if item.fresh_login:
            # Never "via profile": the login must pass through the IdP in this
            # run so its session-only SSO cookie exists when the bundle is cut.
            # Off-LAN behind Cloudflare Access: stop before anything is
            # reserved (the profile proof below does it for the other items).
            self._access_precheck(page, item, None)
            # Reserve FIRST: a denied reservation leaves the profile untouched.
            secret = get_secret()
            self.clear_site_cookies(ctx, item)
        else:
            # The proof's own redirect chain counts for the Access precheck
            # (a single-IdP Access sends it on to github.com/login).
            with NavTrail(page) as trail:
                proof = self._profile_proof(page, item)
            # Even after a VALID one: the old proof of a sentinel-less item
            # passes on an Access page (off the fill origins, no password).
            self._access_precheck(page, item, proof, trail.urls)
            # WS5: [True] once the profile holds ANOTHER account: its cookies
            # and site storage go before the one fresh login.
            reset = [False]
            if proof == VALID:
                # A storage token near its expiry is renewed first; a token
                # the server rejects means the profile is not reusable.
                refreshed = refresh_session(page, item, dev=self.dev)
                if refreshed != REFRESH_REJECTED:
                    # WS5: a multi-account profile must hold the item's account
                    # (an IdP SSO session may have logged it into another one).
                    reuse = self._identity_reuse(page, item)
                    if reuse == "ok":
                        # (a candidate: present here + absent logged out = verified)
                        return self._export(
                            ctx,
                            item,
                            "profile",
                            proven=False,
                            refresh=refreshed,
                            diag=bool(getattr(get_secret, "diag", False)),
                        )
                    reset[0] = reuse == "reset"
            if getattr(get_secret, "refresh_only", False):
                # Not reusable (invalid, indeterminate or token rejected): a
                # refresh-only request ends here, as `refresh_unavailable`.
                get_secret()
            if proof == INDETERMINATE:
                why = proof_reason_text(self._proof_reason(item))
                raise LoginFailed(
                    "could not tell whether the broker profile is logged in ("
                    + (why or "check page did not load, answered 5xx or stayed blank")
                    + ")"
                    + html_script_hint(page),
                    phase="profile-proof",
                )
            bundle = self._before_secret(
                ctx, page, item, get_secret, deadline, reset=reset
            )
            if bundle is not None:
                return bundle
            secret = get_secret()
            if reset[0]:
                # Reserved first (a denied reservation leaves the profile as
                # it is); then ONE fresh login, in a fresh tab, proven again.
                page = self.reset_site_profile(ctx, page, item)
        attempt: AttemptController = getattr(get_secret, "attempt", None) or (
            AttemptController()
        )
        try:
            recipe_for(item.site)(page, item, secret, dev=self.dev, attempt=attempt)
        except RecipeError as exc:
            reason = idp_reason(ctx)  # before anything navigates away
            self._record_failure(page, item, secret)
            self._note_challenge(item, exc, secret)
            self._note_idp(item, reason, exc)
            exc.submitted = exc.submitted or attempt.submitted
            exc.detail += html_script_hint(page)
            raise
        except Exception as exc:  # pylint: disable=broad-exception-caught
            # A Playwright timeout or a detached element: report it like a
            # recipe failure (screenshot, page picture) and say where it
            # happened. The submit marker decides the limiter outcome.
            self._record_failure(page, item, secret)
            raise LoginFailed(
                f"unexpected error in the login recipe: {exception_site(exc)}"
                + html_script_hint(page),
                submitted=True,
            ) from exc
        # Snapshot where the recipe ended — the check below navigates away.
        reason = idp_reason(ctx)
        try:
            before = diagnose(page, secret)
        except Exception:  # pylint: disable=broad-exception-caught
            before = {}
        # Positive proof after EVERY login, whatever the recipe saw.
        proof = self._profile_proof(page, item)
        if proof != VALID:
            self._record_failure(page, item, secret)
            self.last_diag.setdefault(item.site, {})["before_check"] = before
            why = proof_reason_text(self._proof_reason(item))
            failed = LoginFailed(
                (
                    "login did not reach a logged-in state ("
                    + (why or "status / origin / sentinel")
                    + ")"
                    if proof != INDETERMINATE
                    else "the logged-in proof could not decide ("
                    + (why or "check page did not load, answered 5xx or stayed blank")
                    + ")"
                )
                + html_script_hint(page),
                submitted=attempt.submitted,
                phase="broker-proof",
            )
            raise self._note_idp(item, reason, failed)
        # WS5: logged in, but as WHICH account? (no screenshot: the page may
        # show another account's name)
        self._identity_after_login(page, item, secret.username, attempt)
        return self._export(
            ctx,
            item,
            "login",
            proven=True,
            diag=bool(getattr(get_secret, "diag", False)),
        )

    @staticmethod
    def _access_precheck(
        page: Any, item: SiteItem, proof: str | None, seen: list[str] | None = None
    ) -> None:
        """Before anything is reserved: raise ``AccessGated`` (phase
        ``precheck``) when the site's page is a Cloudflare Access login —
        off-LAN the app is unreachable, and that login is not the site's —
        and ``LoginBlocked`` when the login page answers HTTP 401/403 (an
        Access block page, an IP gate: no login form of the site's, nothing
        may be typed there).

        `proof`: the profile proof's answer (None: no proof ran, a
        ``fresh_login``). A login is next unless it was ``valid``: then the
        login URL is loaded first (after a profile proof not for a site with
        its own preflight, which loads it itself; a ``fresh_login`` always)
        and judged by URL — even after a failed load — and status; a
        ``valid`` proof's own page is judged by URL (the old proof of a
        sentinel-less item passes on an Access page).

        Judged by the navigation trail too (`seen`: the profile proof's, plus
        this load's): a chain that passed a Cloudflare Access hop and ended
        off the site is gated even when Access sent it straight on to its
        single identity provider (``recipes.page_access_gated``)."""
        resp = None
        trail = list(seen or [])
        if proof is None or (proof != VALID and item.site not in PREFLIGHTS):
            # a failed load may still have ended on the Access page
            with NavTrail(page) as nav, contextlib.suppress(Exception):
                # a fresh document load: a hash-only goto (an SPA's check
                # page -> its login route) has no Response to judge
                resp = load_document(page, item.login_url)
            trail += nav.urls
        if access_gated(str(getattr(page, "url", "") or "")) or page_access_gated(
            page, item, trail
        ):
            raise AccessGated()
        raise_if_blocked(page, resp)

    def _before_secret(  # pylint: disable=too-many-arguments
        self,
        ctx: Any,
        page: Any,
        item: SiteItem,
        get_secret: Callable[[], Secret],
        deadline: float | None,
        *,
        reset: list[bool] | None = None,
    ) -> dict[str, Any] | None:
        """The last steps before a password login reserves and reads the
        secret: the site's preflight (``recipes.PREFLIGHTS``) — when the IdP's
        own session logs the site in by itself (CSCS silent SSO) and the proof
        holds, the bundle (``via`` sso): nothing typed, the limiter never
        touched — then, right before the secret, the refusal when too little
        of the run is left (code ``timeout``). None: go on with the login.
        `reset` (WS5): set to [True] when the SSO session holds another
        account (``_identity_reuse``): the caller clears the site's cookies
        before its login."""
        preflight = PREFLIGHTS.get(item.site)
        if preflight is not None and not getattr(get_secret, "candidate", False):
            if (
                preflight(page, item, dev=self.dev) == VALID
                and self._profile_proof(page, item) == VALID
            ):
                refreshed = refresh_session(page, item, dev=self.dev)
                reuse = (  # like the profile path
                    self._identity_reuse(page, item)
                    if refreshed != REFRESH_REJECTED
                    else "login"
                )
                if reset is not None and reuse == "reset":
                    reset[0] = True
                if reuse == "ok":
                    return self._export(
                        ctx,
                        item,
                        "sso",
                        proven=False,
                        refresh=refreshed,
                        diag=bool(getattr(get_secret, "diag", False)),
                    )
        if deadline is not None and deadline - time.monotonic() < MIN_LOGIN_LEFT_S:
            late = LoginFailed(
                "too little of the broker run is left to start a login",
                phase="profile-proof",
            )
            late.code = "timeout"
            raise late
        return None

    def _throwaway_answer(self, item: SiteItem, *, pw: Any = None) -> str:
        """The candidate sentinel on the check page of a fresh, logged-out
        throwaway profile: ``invalid`` = loaded (status < 400) and ABSENT,
        ``valid`` = it shows logged out, ``indeterminate`` = could not tell.
        `pw`: the caller's running Playwright (one per thread: a nested
        ``sync_playwright()`` raises inside the outer one's event loop)."""
        got = self.sentinel_absent(item, str(item.logged_in_selector), pw=pw)
        status = got.get("status")
        if not got.get("loaded") or not isinstance(status, int) or status <= 0:
            return INDETERMINATE
        if status >= 400:
            return INDETERMINATE
        return VALID if got.get("present") else "invalid"

    @staticmethod
    def _candidate_absent(proof: str) -> None:
        """A candidate sentinel must be ABSENT when logged out (two-sided
        proof); present or undecidable -> ``candidate_unverifiable``."""
        if proof == "invalid":
            return
        err = LoginFailed(
            "the candidate sentinel shows on a logged-OUT page too: it proves nothing"
            if proof == VALID
            else "the logged-out check page did not load: the candidate "
            "sentinel cannot be verified",
            phase="profile-proof",
        )
        err.code = "candidate_unverifiable"
        raise err

    def sentinel_absent(
        self, item: SiteItem, sentinel: str, *, pw: Any = None
    ) -> dict[str, Any]:
        """Load the item's check page in a FRESH throwaway profile (no cookies,
        no secret, never the site's profile) and report whether `sentinel`
        shows there: a sentinel that shows logged out proves nothing. `pw`: a
        running Playwright to reuse (else one of its own)."""
        if pw is None:
            from playwright.sync_api import (  # pylint: disable=import-outside-toplevel
                sync_playwright,
            )

            with sync_playwright() as own:
                return self.sentinel_absent(item, sentinel, pw=own)
        url = item.check_url or item.login_url
        tmp_root = self.home / "tmp"
        tmp_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        tmp = Path(tempfile.mkdtemp(prefix="sentinel-", dir=str(tmp_root)))
        try:
            ctx = self._launch(pw, tmp)
            try:
                page = ctx.pages[0] if ctx.pages else ctx.new_page()
                try:
                    resp = page.goto(url, wait_until="domcontentloaded")
                    with contextlib.suppress(Exception):
                        page.wait_for_load_state("load", timeout=10_000)
                    page.wait_for_timeout(1500)
                except Exception:  # pylint: disable=broad-exception-caught
                    return {"loaded": False, "status": None, "present": None}
                status = getattr(resp, "status", None) if resp else None
                present = bool(sentinel_shown(page, sentinel))
                return {"loaded": True, "status": status, "present": present}
            finally:
                _NOCACHE_SESSIONS.pop(id(ctx), None)
                _HTML_SCRIPTS.pop(id(ctx), None)
                _IDP_RESPONSES.pop(id(ctx), None)
                with contextlib.suppress(Exception):
                    ctx.close()
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def _export(
        self,
        ctx: Any,
        item: SiteItem,
        via: str,
        *,
        proven: bool,
        refresh: str = REFRESH_NONE,
        diag: bool = False,
    ) -> dict[str, Any]:
        """`export_bundle`, raising ``ExportFailed`` when it fails or the
        bundle holds no cookie and no storage key. `proven`: a fresh login was
        proven just before (the limiter counts it as ``ok`` anyway). `diag`:
        `export_bundle`'s value-free diagnostics."""
        try:
            bundle = (
                self.export_bundle(ctx, item, via, diag=True)
                if diag
                else self.export_bundle(ctx, item, via)
            )
        except BundleExportError as exc:
            # its own code (`bundle_export`): the login stands or falls with it
            exc.auth_proven = proven
            exc.submitted = proven
            raise
        except Exception as exc:  # pylint: disable=broad-exception-caught
            raise ExportFailed(
                f"export failed: {exception_site(exc)}",
                phase="bundle-export",
                auth_proven=proven,
                submitted=proven,
            ) from exc
        if not bundle.get("cookies") and not any(
            (bundle.get("storage") or {}).values()
        ):
            err = ExportFailed(
                "the exported session holds no cookie and no storage key "
                "(check agent_cookie_hosts / agent_storage_keys)",
                phase="bundle-export",
                auth_proven=proven,
                submitted=proven,
            )
            err.code = "empty_bundle"
            raise err
        bundle["session_refresh"] = refresh
        return bundle

    def __call__(
        self, item: SiteItem, get_secret: Callable[[], Secret]
    ) -> dict[str, Any]:
        from playwright.sync_api import (  # pylint: disable=import-outside-toplevel
            sync_playwright,
        )

        profile = self.profile_dir(item.site)
        profile.mkdir(mode=0o700, parents=True, exist_ok=True)
        with sync_playwright() as pw:
            if getattr(get_secret, "candidate", False):
                # The logged-out half of a candidate's proof, with THIS
                # Playwright and before the site's own context opens.
                self._candidate_absent(self._throwaway_answer(item, pw=pw))
                with contextlib.suppress(AttributeError, TypeError):
                    setattr(get_secret, "candidate_checked", True)
            # One deadline per REQUEST (`_SecretGate.deadline`, set when the
            # broker received it: the vault item read and a candidate's
            # throwaway check count too); a bare runner call starts its own.
            deadline = getattr(get_secret, "deadline", None)
            if not isinstance(deadline, float):
                deadline = time.monotonic() + RUN_DEADLINE_S

            def past_deadline() -> bool:
                return dog.fired.is_set() or time.monotonic() >= deadline

            ctx: Any = None
            left = max(0.0, deadline - time.monotonic())
            with RunWatchdog(profile, left) as dog:
                try:
                    if past_deadline():
                        raise LoginFailed(
                            "before the browser started", phase="precheck"
                        )
                    ctx = self._launch(pw, profile, item)
                    dog.arm()
                    bundle = self.run_in_context(
                        ctx, item, get_secret, deadline=deadline
                    )
                    if past_deadline():
                        # Finished after the deadline (the kill did not take):
                        # the client may have given up, so no bundle leaves.
                        # The login itself was proven: the limiter counts it
                        # (`auth_proven`), and the session stays in the
                        # profile — the next request reuses it, no password.
                        overdue = deadline_error(
                            LoginFailed("finished after it", phase="bundle-export")
                        )
                        overdue.auth_proven = True
                        raise overdue
                    return bundle
                except (
                    DeadlineError,
                    NeedsHuman,
                    OriginViolation,
                    _RateLimited,
                    _HeldStop,
                    _SubmitDisabled,
                    IdentityMismatch,
                ):
                    # unchanged past the deadline too: exit 4, the origin
                    # violation's audit and the limiter's answer stay theirs
                    raise
                except Exception as exc:
                    if past_deadline():
                        raise deadline_error(exc) from exc
                    raise
                finally:
                    if ctx is not None:
                        _NOCACHE_SESSIONS.pop(id(ctx), None)
                        _HTML_SCRIPTS.pop(id(ctx), None)
                        _IDP_RESPONSES.pop(id(ctx), None)
                        with contextlib.suppress(Exception):
                            ctx.close()


def exception_site(exc: BaseException) -> str:
    """``TimeoutError in _submit_identifier (recipes.py:612)``: the exception's
    class and the innermost frame of the broker package it passed through,
    this module's own frames aside (else the innermost frame at all). Never
    the message — a Playwright error message may quote page content."""
    frames = traceback.extract_tb(exc.__traceback__)
    ours = [
        f
        for f in frames
        if Path(f.filename).parent.name == "broker"
        and Path(f.filename).name != Path(__file__).name
    ]
    where = (ours or frames)[-1:] if frames else []
    name = type(exc).__name__
    if not where:
        return name
    frame = where[0]
    return f"{name} in {frame.name} ({Path(frame.filename).name}:{frame.lineno})"


def fresh_login_scopes(item: SiteItem) -> list[_identity.CookieScope]:
    """The scopes an ``agent_fresh_login`` wipe (and the WS5 reset) covers,
    HOST-WIDE: every cookie host and every fill origin's host at path "/"
    — a cookie of the host, a subdomain or a parent domain of it, any
    path (``CookieScope.reaches``). The broker's profile is the item's own,
    so its path scopes (WS5 S4c) spare nothing here."""
    scopes: list[_identity.CookieScope] = []
    for host in [*item.cookie_hosts, *(url_host(o) for o in item.fill_origins)]:
        scope = _identity.CookieScope(host)
        if scope.host and scope not in scopes:
            scopes.append(scope)
    return scopes


def url_host(origin: str) -> str:
    """``https://login.eduid.ch:8443`` -> ``login.eduid.ch``."""
    return (urllib.parse.urlsplit(origin).hostname or "").lower()


# ---------------------------------------------------------------------------
# Request handling
# ---------------------------------------------------------------------------


def _forget_path(path: Path, *, directory: bool, problems: list[str]) -> bool:
    """`forget`: remove `path` when it is a real directory (`directory`) or a
    regular file; True when something was removed. A symlink or the other
    kind is never followed or touched — it is reported in `problems`."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return False
    except OSError:
        problems.append(f"cannot inspect {path.name}")
        return False
    want = stat.S_ISDIR(st.st_mode) if directory else stat.S_ISREG(st.st_mode)
    if not want:
        problems.append(
            f"{path.name} is not a plain {'directory' if directory else 'file'}"
        )
        return False
    try:
        if directory:
            shutil.rmtree(path)
        else:
            path.unlink()
    except OSError:
        problems.append(f"cannot remove {path.name}")
        return False
    return True


@dataclass
class _Flight:
    """One in-progress login; concurrent callers for the site share its result."""

    done: threading.Event = field(default_factory=threading.Event)
    result: dict[str, Any] = field(default_factory=dict)
    waiters: int = 0


class _LazyBwVault:
    """BwVault whose bootstrap is read per call — the daemon starts before
    enrolment, and ``install.sh -C``/``-X`` rewrite it at run time. The value
    cache outlives the per-call BwVault (it is keyed by the collection IDs)."""

    def __init__(self, home: Path) -> None:
        self.home = home
        self.cache = VaultCache()

    def _vault(self) -> BwVault:
        boot = BwBootstrap.load(self.home / "bootstrap.json")
        return BwVault(boot, self.home / "bw", cache=self.cache)

    def secret_items(self) -> list[SecretItem]:
        """See ``BwVault.secret_items``."""
        return self._vault().secret_items()

    def secret_values(self, secret_id: str) -> SecretValues:
        """See ``BwVault.secret_values``."""
        return self._vault().secret_values(secret_id)

    def invalidate(self) -> int:
        """Bump the cache generation (no bootstrap read needed)."""
        return self.cache.bump()

    def secret_gate(self) -> tuple[str, str]:
        """See ``BwVault.secret_gate`` (the bootstrap as it is NOW)."""
        return self._vault().secret_gate()

    def script_gate_report(self) -> list[GateRow]:
        """See ``BwVault.script_gate_report``."""
        return self._vault().script_gate_report()

    def items(self) -> list[SiteItem]:
        """See ``BwVault.items``."""
        return self._vault().items()

    def secret(self, site: str) -> Secret:
        """See ``BwVault.secret``."""
        return self._vault().secret(site)

    def fill_secret(self, site: str) -> Secret:
        """See ``BwVault.fill_secret``."""
        return self._vault().fill_secret(site)

    def membership_problems(self) -> list[tuple[str, str, str, str]]:
        """See ``BwVault.membership_problems``."""
        return self._vault().membership_problems()


def _err(code: str, detail: str = "") -> dict[str, Any]:
    return {"ok": False, "error": code, "detail": detail}


# tp#965 S1: what an old client asking for the removed `fingerprint` op gets.
FINGERPRINT_REMOVED = (
    "the fingerprint op was removed (it was a password oracle): compare with "
    "credctl.py check -T in mydotfiles"
)

# ---------------------------------------------------------------------------
# tp#965 S3: credential-rotation leases
# ---------------------------------------------------------------------------

ROTATION_OPS = frozenset({"rotation_lease", "rotation_release"})
LEASE_FILE = "rotation-leases.json"
# Above the Touch ID helper's 15-min deadline; a request may ask for less.
LEASE_TTL_S = 1200.0
LEASE_TTL_MAX_S = 3600.0
# How long a lease waits for the in-flight login of each site (all sites
# together) before it is dropped again (`busy`).
DRAIN_S = 120.0
MAX_LEASE_SITES = 64
# `RotationLeases.holder` when the lease file cannot be read: every site is
# held (fail closed) until the file is readable again or removed by root.
LEASE_UNREADABLE = "unreadable"


class LeaseStateError(RuntimeError):
    """The lease file exists but cannot be read or parsed."""


class RotationLeases:
    """The persisted rotation leases ``{txid: {"sites": [...], "expires":
    epoch}}`` in ``<home>/rotation-leases.json`` (0600, atomic replace,
    never followed through a symlink). An expired lease is dropped by the
    next read. Thread-safe."""

    def __init__(self, path: Path, clock: Callable[[], float]) -> None:
        self.path = path
        self.clock = clock
        self._lock = threading.Lock()

    def _read(self) -> dict[str, dict[str, Any]]:
        try:
            fd = os.open(str(self.path), os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            return {}
        except OSError as exc:
            raise LeaseStateError("lease file unreadable") from exc
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise LeaseStateError("lease file is not a regular file")
            with os.fdopen(fd, encoding="utf-8") as fh:
                fd = -1  # the file object owns it now
                data = json.load(fh)
        except (OSError, ValueError) as exc:
            raise LeaseStateError("lease file unreadable") from exc
        finally:
            if fd >= 0:
                os.close(fd)
        leases = data.get("leases") if isinstance(data, dict) else None
        if not isinstance(leases, dict):
            raise LeaseStateError("lease file malformed")
        out: dict[str, dict[str, Any]] = {}
        for txid, rec in leases.items():
            sites = rec.get("sites") if isinstance(rec, dict) else None
            expires = rec.get("expires") if isinstance(rec, dict) else None
            if (
                not isinstance(txid, str)
                or not isinstance(sites, list)
                or not all(isinstance(s, str) for s in sites)
                or isinstance(expires, bool)
                or not isinstance(expires, (int, float))
            ):
                raise LeaseStateError("lease file malformed")
            out[txid] = {"sites": list(sites), "expires": float(expires)}
        return out

    def _write(self, leases: dict[str, dict[str, Any]]) -> None:
        write_json_atomic(self.path, {"v": 1, "leases": leases})

    def _live(self) -> dict[str, dict[str, Any]]:
        """The live leases (caller holds the lock); expired ones are dropped
        from the file (a failed write only delays that)."""
        leases = self._read()
        now = self.clock()
        live = {t: r for t, r in leases.items() if r["expires"] > now}
        if len(live) != len(leases):
            with contextlib.suppress(OSError):
                self._write(live)
        return live

    def live(self) -> dict[str, dict[str, Any]]:
        """The live leases (raises LeaseStateError)."""
        with self._lock:
            return self._live()

    def holder(self, site: str) -> str | None:
        """The txid of the live lease covering `site`, ``LEASE_UNREADABLE``
        when the file cannot be read (fail closed), else None."""
        try:
            leases = self.live()
        except LeaseStateError:
            return LEASE_UNREADABLE
        return next((t for t, r in sorted(leases.items()) if site in r["sites"]), None)

    def grant(self, txid: str, sites: list[str], ttl_s: float) -> tuple[str, float]:
        """Record (or renew) `txid`'s lease. Returns ('', expiry), or (a site
        another live txid already leases, 0.0) with nothing recorded.
        Raises LeaseStateError / OSError."""
        with self._lock:
            leases = self._live()
            for other, rec in sorted(leases.items()):
                clash = next((s for s in sites if s in rec["sites"]), None)
                if other != txid and clash is not None:
                    return clash, 0.0
            expires = self.clock() + ttl_s
            leases[txid] = {"sites": sorted(sites), "expires": expires}
            self._write(leases)
            return "", expires

    def drop(self, txid: str) -> bool:
        """Remove `txid`'s lease; True when there was a live one. Raises
        LeaseStateError / OSError."""
        with self._lock:
            leases = self._live()
            had = leases.pop(txid, None) is not None
            if had:
                self._write(leases)
            return had


# What a WS5 reset clears per origin of the item (cookies go separately).
SITE_STORAGE_TYPES = "local_storage,indexeddb,cache_storage,service_workers"

# Limiter states that refuse an identity challenge like they refuse a login
# (interval / caps / busy do not: a challenge is not a login attempt).
_CHALLENGE_BLOCKS = frozenset({"locked", "cooldown", "quarantined", "unreadable"})

# The site list (ids, origins, check URLs — no secrets) is kept this long: each
# Bitwarden read is an unlock + sync + list + lock of ~30-40 s. Secrets are
# always read fresh.
SITES_TTL_S = 600.0


class Broker(SecretOps, FillOps):  # pylint: disable=too-many-instance-attributes  # deps + 4 locks/maps
    """Protocol logic, independent of the socket (unit-testable).

    The secret ops and ``safari_fill`` answer only `allow_uid` (None =
    nobody). `leakcheck` defaults to a backend that always fails, so a broker
    wired without one fails closed (``leakcheck_unavailable``). `attended`
    (``broker.attended.attended``; tests inject a fake) gates ``safari_fill``.
    """

    def __init__(  # pylint: disable=too-many-arguments
        self,
        vault: Vault,
        limiter: Limiter,
        home: Path,
        *,
        runner: Runner,
        clock: Callable[[], float] = time.time,
        allow_uid: int | None = None,
        secret_limiter: Limiter | None = None,
        runs: RunTable | None = None,
        leakcheck: Registrar | None = None,
        attended: Callable[[int], str | None] = attended_gate,
    ) -> None:
        self.vault = vault
        self.limiter = limiter
        self.home = home
        self.runner = runner
        self.clock = clock
        self.allow_uid = allow_uid
        self.secret_limiter = (
            secret_limiter if secret_limiter is not None else build_secret_limiter(home)
        )
        self.runs = runs if runs is not None else RunTable(home / "secret-runs.json")
        self.leakcheck: Registrar = (
            leakcheck if leakcheck is not None else UnconfiguredLeakCheck()
        )
        self._guard = threading.Lock()
        self._site_locks: dict[str, threading.Lock] = {}
        self._flights: dict[str, _Flight] = {}
        self._audit_lock = threading.Lock()
        self._items_lock = threading.Lock()
        self._items_cache: tuple[float, list[SiteItem]] | None = None
        self._probe_slot = threading.Lock()  # `sentinel_absent`: one at a time
        # WS5: identity challenges and the account-tag key (broker home)
        self.identity_ops = IdentityOps(home, clock)
        # tp#965: credential-rotation leases (persisted in the broker home)
        self.leases = RotationLeases(home / LEASE_FILE, clock)
        self.drain_s = DRAIN_S
        # tp#1082: `safari_fill`'s attended gate and its distinct-item cap
        self.attended = attended
        self._fill_lock = threading.Lock()

    def _items(self, *, fresh: bool = False) -> list[SiteItem]:
        """The vault's site items, cached SITES_TTL_S (raises VaultError);
        declared same-account pairs are checked against their account tags."""
        with self._items_lock:
            now = self.clock()
            cached = self._items_cache
            if not fresh and cached and now - cached[0] < SITES_TTL_S:
                return cached[1]
            items = self.identity_ops.apply_tags(self.vault.items())
            self._items_cache = (now, items)
            return items

    # -- audit ---------------------------------------------------------------
    def audit(  # pylint: disable=too-many-arguments
        self,
        op: str,
        site: str | None,
        result: str,
        uid: int | None,
        extra: dict[str, Any] | None = None,
    ) -> None:
        """One JSON line per request: never a secret, never a cookie value.

        `extra` (secret ops): item/field NAMES, env NAMES, the command's
        basename, exit, masked count, nonce prefix — never a value or argv.
        """
        rec: dict[str, Any] = dict(extra or {})
        rec.update(
            {
                "ts": round(self.clock(), 3),
                "op": op,
                "site": site,
                "result": result,
                "uid": uid,
            }
        )
        line = json.dumps(rec, sort_keys=True) + "\n"
        with self._audit_lock:
            self.home.mkdir(parents=True, exist_ok=True)
            auditlog.append_line(self.home, line)

    def _site_lock(self, site: str) -> threading.Lock:
        with self._guard:
            return self._site_locks.setdefault(site, threading.Lock())

    # -- ops -------------------------------------------------------------------
    # One branch per op family (secret, sites, login ops, identity ops).
    def handle(  # pylint: disable=too-many-branches
        self, req: Any, uid: int | None = None, pid: int | None = None
    ) -> dict[str, Any]:
        """Dispatch one decoded request; always returns a JSON-able dict.
        `pid`: the peer process (LOCAL_PEERPID) — identity challenges are
        bound to it."""
        if not isinstance(req, dict) or not isinstance(req.get("op"), str):
            resp = _err("bad_request", 'expected {"op": ...}')
            self.audit("?", None, "bad_request", uid)
            return resp
        op = req["op"]
        site = req.get("site")
        site = site.strip().lower() if isinstance(site, str) else None
        extra: dict[str, Any] = {}
        try:
            if op in SECRET_OPS:
                site = None
                resp = self._secret_op(op, req, uid, extra)
            elif op == "ping":
                resp = {"ok": True, "pong": True}
            elif op == "sites":
                resp = self._sites(fresh=req.get("fresh") in (True, "1", "true"))
            elif op == "fingerprint":
                # tp#965 S1: removed (an offline password verifier); one
                # release answers this, then the op is unknown.
                site = None
                resp = _err("removed", FINGERPRINT_REMOVED)
            elif op in ROTATION_OPS:
                site = None
                resp = self._rotation_op(op, req, uid, extra)
            elif op in ("login", "logout", "sentinel_absent", "forget"):
                if not site or not SITE_ID_RE.match(site):
                    resp = _err("bad_request", "missing or invalid site id")
                elif op == "login":
                    resp = self._login_request(site, req)
                    bundle = resp.get("bundle")
                    extra.update(
                        scheduled=req.get("scheduled") in (True, "1", "true"),
                        candidate=req.get("candidate_sentinel") is not None,
                        refresh_only=req.get("refresh_only") in (True, "1", "true"),
                        session_refresh=bundle.get("session_refresh")
                        if isinstance(bundle, dict)
                        else None,
                        phase=resp.get("phase"),
                        fresh_auth=resp.get("fresh_auth"),
                        # value-free diagnostics asked for (`login -G`)
                        diag=req.get("diag") in (True, "1", "true"),
                    )
                elif op == "sentinel_absent":
                    resp = self._sentinel_absent(site, req.get("sentinel"))
                elif op == "forget":
                    resp = self._forget(site)
                    extra.update(
                        {
                            k: resp.get(k)
                            for k in (
                                "limiter",
                                "groups",
                                "guard",
                                "profile",
                                "screenshot",
                            )
                        }
                    )
                else:
                    resp = self._logout(site)
            elif op in IDENTITY_OPS:
                site, resp = self._identity_op(
                    op, req, site, uid=uid, pid=pid, extra=extra
                )
            elif op in FILL_OPS:
                site, resp = self._fill_op(op, req, uid=uid, pid=pid, extra=extra)
            else:
                resp = _err("bad_request", f"unknown op {op!r}")
        except Exception:  # pylint: disable=broad-exception-caught
            resp = _err("internal", "unexpected broker error")
        result = "ok" if resp.get("ok") else str(resp.get("error"))
        self.audit(op, site, result, uid, extra or None)
        return resp

    def _sites(self, *, fresh: bool = False) -> dict[str, Any]:
        try:
            items = self._items(fresh=fresh)
        except VaultError as exc:
            return _err("vault_error", str(exc))
        now = self.clock()
        out = []
        for it in items:
            entry = it.public()
            lease = self.leases.holder(it.site)
            if lease is not None:  # a live rotation lease holds it too
                entry.update(hold_view(lease))
            if not it.refused and it.loginable:
                denied = self.limiter.peek_site(it.site, now, group=it.attempt_group)
                entry["limit"] = denied.limit() if denied else {"state": "ok"}
            out.append(entry)
        return {"ok": True, "sites": out, "identity_v": _identity.IDENTITY_V}

    def _identity_op(  # pylint: disable=too-many-arguments
        self,
        op: str,
        req: dict[str, Any],
        site: str | None,
        *,
        uid: int | None,
        pid: int | None,
        extra: dict[str, Any],
    ) -> tuple[str | None, dict[str, Any]]:
        """WS5 ``identity_challenge`` / ``identity_answer``
        (``broker.identity_ops``) → ``(site for the audit, reply)``. The
        audit gets the answer's enum, never a nonce, digest, tag or name; a
        mismatch adds its own ``identity_guard`` line (cooldown / quarantined)."""
        if op == "identity_answer":
            got_site, resp, guard = self.identity_ops.answer(req, pid)
            if resp.get("ok"):
                extra["answer"] = resp.get("result")
            if guard is not None:
                self.audit("identity_guard", got_site, guard, uid)
            return got_site, resp
        if not site or not SITE_ID_RE.match(site):
            return None, _err("bad_request", "missing or invalid site id")
        try:
            items = self._items()
        except VaultError as exc:
            return site, _err("vault_error", str(exc))
        item = next((it for it in items if it.site == site), None)
        refusal = self._challenge_gates(item, site, req.get("instance", ""))
        if refusal is not None or item is None:
            return site, refusal or _err("unknown_site", site)
        return site, self.identity_ops.challenge(item, pid)

    # One early return per gate, in the order a login checks them.
    def _challenge_gates(  # pylint: disable=too-many-return-statements
        self, item: SiteItem | None, site: str, instance: object
    ) -> dict[str, Any] | None:
        """The gates a ``login`` of the item would pass, before a challenge
        is issued (None = issue it): known, not refused, a proof, a usable
        identity recipe, asked from the item's own browser instance, and no
        limiter block (locked / cooldown / quarantined / unreadable) on any
        of its keys — a challenge never serves a site its login would not."""
        if item is None:
            return _err("unknown_site", f"{site!r} is not in agent-logins")
        if not item.loginable:
            return _err("fill_only", fill_only_detail(site))
        held = self._held(site, item)
        if held is not None:
            return held
        if item.refused:
            return _err("refused", item.refused)
        if not item.has_proof:
            return _err("needs_sentinel", "the item has no logged-in proof")
        if item.identity_recipe is None:
            return _err("identity_unproven", f"{site}: no usable identity recipe")
        if not isinstance(instance, str) or instance != item.instance:
            return _err(
                "wrong_instance",
                f"{site} lives in browser instance {item.instance or 'default'}",
            )
        now = self.clock()
        for key in self.limiter.site_keys(site, item.attempt_group):
            denied = self.limiter.peek([key], now, scheduled=True)
            if denied is not None and denied.state in _CHALLENGE_BLOCKS:
                return {**_err("rate_limited", denied.reason), "limit": denied.limit()}
        return None

    # -- tp#965: rotation leases ----------------------------------------------
    def _held(self, site: str, item: SiteItem | None = None) -> dict[str, Any] | None:
        """The ``held`` reply when a live rotation lease covers `site`, or
        `item` carries ``agent_hold``; else None. Never touches the limiter."""
        txid = self.leases.holder(site) or (item.hold if item is not None else "")
        if not txid:
            return None
        shown = txid if TXID_RE.match(txid) else None
        return {
            **_phase_err(
                "held",
                f"rotation {shown or txid} in progress — skip, re-check later",
                "precheck",
            ),
            "txid": shown,
        }

    def _drop_items_cache(self) -> None:
        """The next login re-reads the vault (an ``agent_hold`` written or
        removed during the rotation is seen at once)."""
        with self._items_lock:
            self._items_cache = None

    def _rotation_op(
        self, op: str, req: dict[str, Any], uid: int | None, extra: dict[str, Any]
    ) -> dict[str, Any]:
        """``rotation_lease`` / ``rotation_release`` (peer uid `allow_uid`
        only, like the secret ops). The audit gets the txid and site ids."""
        if self.allow_uid is None or uid != self.allow_uid:
            return _err("forbidden")
        txid = req.get("txid")
        if not isinstance(txid, str) or not TXID_RE.match(txid):
            return _err("bad_request", "txid: YYYYMMDDTHHMMSSZ-<6 hex>")
        extra["txid"] = txid
        if op == "rotation_release":
            try:
                released = self.leases.drop(txid)
            except (LeaseStateError, OSError):
                return _err("internal", "rotation lease state not usable")
            self._drop_items_cache()
            extra["released"] = released
            return {"ok": True, "result": "released", "released": released}
        return self._rotation_lease(txid, req, extra)

    # One early return per refusal, then the drain.
    def _rotation_lease(  # pylint: disable=too-many-return-statements
        self, txid: str, req: dict[str, Any], extra: dict[str, Any]
    ) -> dict[str, Any]:
        """Validate, record the lease (from now on every new login of its
        sites is ``held``), then drain each site's lock within ``drain_s``:
        a login already past its secret read finishes first. Drain timeout:
        the lease is dropped again and the answer is ``busy``."""
        raw_sites = req.get("sites")
        if (
            not isinstance(raw_sites, list)
            or not raw_sites
            or len(raw_sites) > MAX_LEASE_SITES
            or not all(isinstance(s, str) and SITE_ID_RE.match(s) for s in raw_sites)
        ):
            return _err("bad_request", f"sites: 1-{MAX_LEASE_SITES} site ids")
        sites = sorted(set(raw_sites))
        extra["sites"] = sites
        ttl = req.get("ttl_s", LEASE_TTL_S)
        if (
            isinstance(ttl, bool)
            or not isinstance(ttl, (int, float))
            or not 1 <= ttl <= LEASE_TTL_MAX_S
        ):
            return _err("bad_request", f"ttl_s: 1-{LEASE_TTL_MAX_S:g} seconds")
        try:
            known = {it.site for it in self._items()}
            if not set(sites) <= known:
                known = {it.site for it in self._items(fresh=True)}
        except VaultError as exc:
            return _err("vault_error", str(exc))
        unknown = [s for s in sites if s not in known]
        if unknown:
            return _err("unknown_site", f"not in agent-logins: {', '.join(unknown)}")
        try:
            clash, expires = self.leases.grant(txid, sites, float(ttl))
        except (LeaseStateError, OSError):
            return _err("internal", "rotation lease state not usable")
        if clash:
            return _err("busy", f"{clash} is leased by another rotation")
        self._drop_items_cache()
        deadline = time.monotonic() + self.drain_s
        for site in sites:
            lock = self._site_lock(site)
            if not lock.acquire(timeout=max(0.0, deadline - time.monotonic())):
                with contextlib.suppress(LeaseStateError, OSError):
                    self.leases.drop(txid)
                extra["drained"] = False
                return _err(
                    "busy",
                    f"a login of {site} did not finish within {self.drain_s:g}s "
                    "— lease dropped, nothing held",
                )
            lock.release()
        extra["drained"] = True
        return {
            "ok": True,
            "result": "leased",
            "txid": txid,
            "sites": sites,
            "expires": round(expires, 3),
        }

    def _logout(self, site: str) -> dict[str, Any]:
        with self._site_lock(site):
            profile = self.home / "profiles" / site
            existed = profile.exists()
            if existed:
                shutil.rmtree(profile)
        return {"ok": True, "removed": existed}

    # One early return per refusal, then the removals.
    def _forget_items(self, site: str) -> tuple[list[SiteItem] | None, dict[str, Any]]:
        """`_forget`'s fresh vault read and its refusals: (items, {}) when the
        site may be forgotten, else (None, the error reply). Refused: an
        unreadable vault; an EMPTY read, or one smaller than half the cached
        item count (a half-synced or wrong collection must never look like
        "every site was removed"); any item — a refused one too — that
        resolves to the site id (its ``agent_site``, or the slug of its name
        that the vault falls back to)."""
        cached = self._items_cache
        before = len(cached[1]) if cached else 0
        try:
            items = self._items(fresh=True)
        except VaultError as exc:
            return None, _err("vault_error", str(exc))
        if not items or (before and len(items) * 2 < before):
            return None, _err(
                "vault_suspect",
                f"the fresh vault read has {len(items)} item(s) (cached: {before}) "
                "— refusing to forget anything on it",
            )
        if any(site in (it.site, slugify(it.name)) for it in items):
            return None, _err(
                "still_listed",
                f"{site} is still a vault item — remove it from agent-login first",
            )
        return items, {}

    def _forget_guard(
        self, site: str, left: dict[str, str], problems: list[str]
    ) -> bool:
        """`_forget`'s identity-guard step: a site whose challenges are in a
        lockout or quarantined (or whose guard state is unreadable) keeps
        its entry for ``install.sh -r``; else the entry goes. Removed?"""
        guard = self.identity_ops.guard
        denied = guard.denial(site, self.clock())
        if denied is not None:
            left["identity-guard"] = denied[0]
            return False
        try:
            return bool(guard.reset(site))
        except (GuardStateError, OSError):
            problems.append("identity guard state not usable")
            return False

    # One early return per refusal, then the removals.
    def _forget(self, site: str) -> dict[str, Any]:  # pylint: disable=too-many-return-statements
        """``forget`` (WS3 removal, `agent-login.py -D` phase 2): drop the
        broker-side traces of a site that NO vault item carries any more —
        under the site's own lock (every login of it holds that lock), after
        a FRESH vault read that also replaces the item cache (a later login
        answers ``unknown_site``; `_forget_items` lists the refusals), and
        never while a login is in flight on the site or one of its groups.
        It is never a way around the limiter: a limiter key that is locked,
        cooling down or quarantined, and an identity-guard entry in a lockout
        or quarantine, stay (``left``, for ``sudo install/install.sh -r
        SITE``); the rest goes: the limiter key and bindings (a group key
        only when no other entry binds it and no item, refused ones
        included, declares it), the guard entry, the profile directory and
        the failure screenshot. Idempotent; the reply carries counts, flags
        and state words only."""
        with self._site_lock(site):
            items, refusal = self._forget_items(site)
            if items is None:
                return refusal
            keep = {it.attempt_group for it in items if it.attempt_group}
            try:
                pruned = self.limiter.prune_site(site, keep, self.clock())
            except LimiterBusy:
                return _err("busy", f"a login is in flight on {site} or its group")
            except (LimiterStateError, OSError):
                return _err("internal", "limiter state not usable")
            problems: list[str] = []
            left: dict[str, str] = dict(pruned.get("left") or {})
            guard = self._forget_guard(site, left, problems)
            profile = _forget_path(
                self.home / "profiles" / site, directory=True, problems=problems
            )
            diag_dir = getattr(self.runner, "diag_dir", None)
            shot = (
                _forget_path(
                    Path(diag_dir) / f"last-failure-{site}.png",
                    directory=False,
                    problems=problems,
                )
                if diag_dir is not None
                else False
            )
            for name in ("last_diag", "proof_reasons"):
                memo = getattr(self.runner, name, None)
                if isinstance(memo, dict):
                    memo.pop(site, None)
        reply: dict[str, Any] = {
            "ok": not problems,
            "limiter": pruned["site"],
            "groups": len(pruned["groups"]),
            "guard": guard,
            "profile": profile,
            "screenshot": shot,
            # keys kept for root (key -> locked / cooldown / quarantined /
            # identity_cooldown / identity_quarantined …): `install.sh -r SITE`
            "left": left,
        }
        if problems:
            reply.update(_err("forget_incomplete", "; ".join(problems)))
        return reply

    # One return per refusal of an option combination, then one per route.
    def _login_request(self, site: str, req: dict[str, Any]) -> dict[str, Any]:
        """``login`` with its options (`_login_options`); the reply carries
        ``bundle_diag`` only when THIS request asked for it (``"diag":
        true``) — a request that joined another's run never gets that run's
        diagnostics, nor does one that did not ask."""
        want = req.get("diag") in (True, "1", "true")
        resp = self._login_options(site, req, diag=want)
        if BUNDLE_DIAG_KEY not in resp or want:
            return resp
        return {k: v for k, v in resp.items() if k != BUNDLE_DIAG_KEY}

    def _login_options(  # pylint: disable=too-many-return-statements
        self, site: str, req: dict[str, Any], *, diag: bool = False
    ) -> dict[str, Any]:
        """``login`` with its options: ``scheduled`` (the daily check), a
        one-shot ``candidate_sentinel`` (never for a scheduled run) and
        ``refresh_only`` (re-export a still-valid profile, its storage token
        renewed when due — never a password: a profile that is not reusable
        answers ``refresh_unavailable`` without touching the limiter).
        `diag`: the runner adds its value-free bundle diagnostics."""
        scheduled = req.get("scheduled") in (True, "1", "true")
        candidate = req.get("candidate_sentinel")
        refresh_only = req.get("refresh_only") in (True, "1", "true")
        started = time.monotonic()  # the run deadline counts from here
        held = self._held(site)  # at once; `_do_login` re-checks under the lock
        if held is not None:
            return held
        if refresh_only and candidate is not None:
            return _phase_err(
                "bad_request", "refresh_only never tries a candidate", "precheck"
            )
        if refresh_only:
            with self._site_lock(site):
                return self._do_login(
                    site,
                    scheduled=scheduled,
                    refresh_only=True,
                    started=started,
                    diag=diag,
                )
        if candidate is None:
            return self._login(site, scheduled=scheduled, started=started, diag=diag)
        if not isinstance(candidate, str) or not selector_ok(candidate.strip()):
            return _phase_err(
                "bad_request",
                "candidate_sentinel: one CSS selector, one line, <=512 chars",
                "precheck",
            )
        if not candidate.strip():
            return _phase_err("bad_request", "candidate_sentinel is empty", "precheck")
        if scheduled:
            return _phase_err(
                "refused",
                "a scheduled login never tries a candidate sentinel",
                "precheck",
            )
        with self._site_lock(site):
            return self._do_login(
                site, candidate=candidate.strip(), started=started, diag=diag
            )

    # One early return per refusal, in the order they are checked.
    def _sentinel_absent(  # pylint: disable=too-many-return-statements,too-many-branches
        self, site: str, sentinel: object
    ) -> dict[str, Any]:
        """``sentinel_absent``: does `sentinel` show on the check page in a
        fresh, logged-out throwaway profile? (no secret, no limiter)"""
        if not isinstance(sentinel, str) or not sentinel.strip():
            return _err("bad_request", "sentinel: one CSS selector")
        if not selector_ok(sentinel.strip()):
            return _err("bad_request", "sentinel: one CSS selector, <=512 chars")
        try:
            item = next((it for it in self._items() if it.site == site), None)
        except VaultError as exc:
            return _err("vault_error", str(exc))
        if item is None:
            return _err("unknown_site", f"{site!r} is not in agent-logins")
        if not item.loginable:
            return _err("fill_only", fill_only_detail(site))
        held = self._held(site, item)
        if held is not None:
            return held
        if item.refused:
            return _err("refused", item.refused)
        probe = getattr(self.runner, "sentinel_absent", None)
        if probe is None:
            return _err("internal", "this broker runner cannot load pages")
        # One throwaway browser at a time, broker-wide, and never while a login
        # of the same site runs: it is free, so it must stay cheap.
        if not self._probe_slot.acquire(blocking=False):  # pylint: disable=consider-using-with  # released in the finally below
            return _err("busy", "another sentinel check is running — retry")
        try:
            lock = self._site_lock(site)
            if not lock.acquire(blocking=False):
                return _err("busy", f"a login of {site} is running — retry")
            try:
                held = self._held(site, item)  # a lease granted meanwhile
                if held is not None:
                    return held
                got = probe(item, sentinel.strip())
            finally:
                lock.release()
        finally:
            self._probe_slot.release()
        return {"ok": True, **got}

    def _login(
        self,
        site: str,
        *,
        scheduled: bool = False,
        started: float | None = None,
        diag: bool = False,
    ) -> dict[str, Any]:
        with self._guard:
            flight = self._flights.get(site)
            leader = flight is None
            if flight is None:
                flight = _Flight()
                self._flights[site] = flight
            else:
                flight.waiters += 1
        if not leader:
            flight.done.wait()
            return flight.result
        result = _err("internal", "unexpected broker error")
        try:
            with self._site_lock(site):
                result = self._do_login(
                    site, scheduled=scheduled, started=started, diag=diag
                )
        finally:
            flight.result = result
            with self._guard:
                self._flights.pop(site, None)
            flight.done.set()
        return result

    # One return per refusal, in the order they are checked.
    def _login_item(  # pylint: disable=too-many-return-statements
        self, site: str
    ) -> tuple[SiteItem | None, dict[str, Any]]:
        """`_do_login`'s item: (item, {}) when a login may go on, else
        (None, the reply) — vault unreadable, unknown site, fill-only
        (tp#1082), held (tp#965), refused, or an unprovable account (WS5)."""
        try:
            items = self._items()
            item = next((it for it in items if it.site == site), None)
            if item is None:  # added since the cache was filled?
                items = self._items(fresh=True)
                item = next((it for it in items if it.site == site), None)
        except VaultError as exc:
            return None, _phase_err("vault_error", str(exc), "vault")
        if item is None:
            return None, _phase_err(
                "unknown_site", f"{site!r} is not in agent-logins", "vault"
            )
        if not item.loginable:
            # tp#1082 D5: a skip — before the limiter, a secret read, a
            # quarantine, a screenshot or a mail
            return None, _phase_err("fill_only", fill_only_detail(site), "precheck")
        # Under the site lock: a lease recorded while this request waited
        # for the lock (or its drain) holds it here — before any secret read.
        held = self._held(site, item)
        if held is not None:
            return None, held
        if item.refused:
            return None, _phase_err("refused", item.refused, "vault")
        if (item.multi_account or item.identity) and item.identity_recipe is None:
            # WS5: its session could be any of the scope's accounts and no
            # usable recipe (reviewed, live-confirmed, with an admin bit) can
            # tell which: no bundle, nothing reserved.
            return None, _phase_err(
                "identity_unproven",
                "the item shares its login scope with another account, or names "
                "an identity recipe, and has no usable agent_identity recipe",
                "precheck",
            )
        return item, {}

    # One return per protocol error code, in the order they are checked.
    def _do_login(  # pylint: disable=too-many-return-statements,too-many-branches
        self,
        site: str,
        *,
        scheduled: bool = False,
        candidate: str | None = None,
        refresh_only: bool = False,
        started: float | None = None,
        diag: bool = False,
    ) -> dict[str, Any]:
        """One login: item checks, then the runner. The limiter is consulted
        only when the runner asks for the secret (`_SecretGate`), so a validated
        profile reuse works in a cooldown and leaves the limiter untouched.
        `started` (monotonic): when the request arrived — the run deadline
        (``RUN_DEADLINE_S``) counts from there. `diag`: the runner's
        value-free bundle diagnostics (``BUNDLE_DIAG_KEY``) move from the
        bundle into the reply; never left in the bundle."""
        item, refusal = self._login_item(site)
        if item is None:
            return refusal
        if candidate is not None:
            if item.logged_in_selector:
                return _phase_err(
                    "bad_request",
                    "the item already has agent_logged_in_selector; a candidate "
                    "sentinel is only for items without one",
                    "precheck",
                )
            denied = self.limiter.peek(
                self.limiter.site_keys(site, item.attempt_group),
                self.clock(),
                scheduled=True,  # any unresolved failure refuses a candidate
            )
            if denied is not None:
                return {
                    **_phase_err("rate_limited", denied.reason, "limiter"),
                    "limit": denied.limit(),
                }
            item = dataclasses.replace(item, logged_in_selector=candidate)
        if scheduled and not item.has_proof:
            return _phase_err(
                "needs_sentinel",
                "the item has no agent_logged_in_selector: a scheduled login "
                "needs the strict proof, so none is attempted",
                "vault",
            )
        gate = _SecretGate(self, item, scheduled=scheduled)
        gate.candidate = candidate is not None
        gate.refresh_only = refresh_only
        gate.diag = diag
        gate.deadline = (
            started if started is not None else time.monotonic()
        ) + RUN_DEADLINE_S
        outcome = "not_submitted"
        try:
            bundle = self.runner(item, gate)
            # The runner returns only after a VALID proof: once the password
            # was typed that is a proven fresh authentication (a candidate's
            # never clears a streak: "candidate").
            typed = gate.attempt.submitted or gate.attempt.was_entered
            outcome = ("candidate" if candidate else "ok") if typed else "not_submitted"
        except _RateLimited as exc:
            return {
                **_phase_err("rate_limited", exc.denied.reason, "limiter"),
                "limit": exc.denied.limit(),
            }
        except _HeldStop as exc:
            # The fresh read found `agent_hold`: the reservation was withdrawn
            # (never counted), nothing was typed.
            return self._held(site, dataclasses.replace(item, hold=exc.txid)) or {}
        except RecipeError as exc:
            outcome = _error_outcome(gate.attempt, exc)
            if candidate is not None and outcome == "ok":
                outcome = "candidate"
            if isinstance(exc, IdentityMismatch) and outcome != "not_submitted":
                # WS5: the password worked, the account or its admin bit did
                # not: its own outcome, never the bad-password streak.
                outcome = "identity_mismatch"
            sent = outcome != "not_submitted"
            phase = exc.phase or ("submit" if sent else "recipe")
            diag = getattr(self.runner, "last_diag", {}).pop(site, None)
            return {
                **_phase_err(exc.code, exc.detail, phase, submitted=sent),
                **({"diag": diag} if diag else {}),
            }
        except VaultError as exc:
            # `vault_error` (Bitwarden unreadable) or the item's own gap
            # (`no_password`, `no_username`: ``vault.MissingSecret``)
            return _phase_err(exc.code, str(exc), "vault")
        except Exception:  # pylint: disable=broad-exception-caught
            typed = gate.attempt.submitted or gate.attempt.was_entered
            outcome = "unknown" if typed else "not_submitted"
            return _phase_err(
                "login_failed",
                "unexpected error during login",
                "unknown" if typed else "recipe",
                submitted=typed,
            )
        finally:
            gate.finish(outcome)
        reply = {
            "ok": True,
            "bundle": bundle,
            "phase": "ok",
            "phase_v": PHASE_V,
            "fresh_auth": outcome in ("ok", "candidate"),
            "proof": "strict" if item.has_proof else "legacy",
            # out of the bundle in any case; into the reply only when asked
            **_take_bundle_diag(bundle, diag),
        }
        if candidate is not None:
            # absent logged out (checked first) + present here or after the login
            reply["candidate_verified"] = True
        return reply


def _take_bundle_diag(bundle: object, diag: bool) -> dict[str, Any]:
    """Remove the runner's diagnostics (``BUNDLE_DIAG_KEY``) from `bundle`;
    ``{BUNDLE_DIAG_KEY: …}`` when `diag` asked for them, else ``{}``."""
    found = bundle.pop(BUNDLE_DIAG_KEY, None) if isinstance(bundle, dict) else None
    return {BUNDLE_DIAG_KEY: found} if diag and isinstance(found, dict) else {}


def _error_outcome(attempt: AttemptController, exc: RecipeError) -> str:
    """The limiter outcome of a failed login (PLAN_ws1a "outcome mapping"):
    nothing typed -> not_submitted; proven auth after typing -> ok; the submit
    marker -> unknown; typed without the marker -> unknown unless the recipe
    proved the password still sat unsent in its field."""
    if not (attempt.submitted or attempt.was_entered):
        return "not_submitted"
    if exc.auth_proven:
        return "ok"
    if exc.never_sent:
        # The POST tripwire aborted the submit inside the browser and nothing
        # else with a body reached the site after the password was typed.
        return "not_submitted"
    if attempt.submitted:
        return "unknown"
    return "not_submitted" if exc.unsent else "unknown"


def _phase_err(
    code: str, detail: str, phase: str, *, submitted: bool = False
) -> dict[str, Any]:
    """An error reply with its phase (broker/phases.py) and the submit marker."""
    return {
        **_err(code, detail),
        "phase": phase,
        "phase_v": PHASE_V,
        "submitted": submitted,
    }


class _RateLimited(RecipeError):
    """The reservation inside `get_secret` was denied (nothing submitted)."""

    code = "rate_limited"

    def __init__(self, denied: Denied) -> None:
        super().__init__(denied.reason, phase="limiter")
        self.denied = denied


class _TooLate(RecipeError):
    """Less than ``MIN_LOGIN_LEFT_S`` of the run is left: no login starts
    (nothing reserved, no secret read)."""

    code = "timeout"

    def __init__(self) -> None:
        super().__init__(
            "too little of the broker run is left to start a login", phase="recipe"
        )


class _RefreshUnavailable(RecipeError):
    """A ``refresh_only`` request found no reusable profile (nothing reserved,
    no secret read)."""

    code = "refresh_unavailable"

    def __init__(self) -> None:
        super().__init__(
            "the broker profile is not reusable; a refresh-only request never logs in",
            phase="profile-proof",
        )


class _HeldStop(RecipeError):
    """The secret's fresh read found the item held (``agent_hold``): a skip,
    the reservation withdrawn, nothing typed."""

    code = "held"

    def __init__(self, txid: str) -> None:
        super().__init__(f"held: rotation {txid} in progress", phase="precheck")
        self.txid = txid


class _SubmitDisabled(RecipeError):
    """The item is ``no_submit`` (``agent_no_submit``, ``vault.NO_SUBMIT_SITES`` or
    a fill origin on ``vault.NO_SUBMIT_DOMAINS``): the login never gets the
    secret, nothing is reserved, nothing typed or submitted."""

    code = "submit_disabled"

    def __init__(self) -> None:
        super().__init__(
            "the broker never submits a password for this site (agent_no_submit): "
            "its session comes from Albert (Safari import or guided login)",
            phase="vault",
        )


class _LimiterAttempt(AttemptController):
    """The recipe's `AttemptController`, bound to the gate's reservation:
    every mark is persisted before the step it announces (a write failure
    raises and the step does not happen)."""

    def __init__(self, gate: _SecretGate) -> None:
        self.gate = gate

    def entered(self) -> None:
        if self.gate.grant is not None:
            self.gate.broker.limiter.mark_entered(self.gate.grant)
        self.was_entered = True

    def mark_submitted(self) -> None:
        if self.gate.grant is not None:
            self.gate.broker.limiter.mark_submitted(self.gate.grant)
        self.submitted = True


class _SecretGate:  # pylint: disable=too-many-instance-attributes  # deps + attempt state
    """The runner's `get_secret`: reserves the attempt (every key of the site,
    group bindings included), then reads the secret. ``attempt`` is the
    controller the runner hands to the recipe; ``finish`` closes the
    reservation once (no-op without one)."""

    def __init__(self, broker: Broker, item: SiteItem, *, scheduled: bool) -> None:
        self.broker = broker
        self.item = item
        self.scheduled = scheduled
        self.finish_failed = False
        self.grant: AttemptGrant | None = None
        self.finished = False
        self.candidate = False
        self.candidate_checked = False  # the runner did the logged-out half
        self.refresh_only = False  # a refresh never reaches the secret
        self.deadline: float | None = None  # the request's run deadline
        self.diag = False  # `login` with "diag": value-free bundle diagnostics
        self.attempt = _LimiterAttempt(self)

    def __call__(self) -> Secret:
        if self.refresh_only:
            raise _RefreshUnavailable()
        if not self.item.loginable:  # `_login_item` refused it already
            raise FillOnly(self.item.site)
        if self.item.no_submit:
            # Before the deadline check and the reservation: the limiter is
            # never touched and the login never gets the secret.
            raise _SubmitDisabled()
        if (
            self.grant is None
            and self.deadline is not None
            and self.deadline - time.monotonic() < MIN_LOGIN_LEFT_S
        ):
            # Every path (fresh_login included) asks here first: no password
            # is typed when the run deadline could cut the login after its
            # submit. Nothing reserved, nothing read.
            raise _TooLate()
        if self.grant is None:
            got = self.broker.limiter.reserve_site(
                self.item.site,
                self.broker.clock(),
                group=self.item.attempt_group,
                scheduled=self.scheduled,
                candidate=self.candidate,
            )
            if isinstance(got, Denied):
                raise _RateLimited(got)
            self.grant = got
        try:
            return self.broker.vault.secret(self.item.site)
        except Held as exc:
            # tp#965: held is never counted — take the untouched reservation
            # back (a failed withdraw leaves it to `finish`: not_submitted).
            self._withdraw()
            raise _HeldStop(exc.txid) from None
        except FillOnly:
            # tp#1082: turned fill-only since the listing — never counted
            self._withdraw()
            raise

    def _withdraw(self) -> None:
        """Undo the reservation (nothing was typed); keep it on failure."""
        if self.grant is None or self.finished:
            return
        try:
            self.broker.limiter.withdraw(self.grant)
        except Exception:  # pylint: disable=broad-exception-caught
            return
        self.grant = None

    def finish(self, outcome: str) -> None:
        """Close the reservation with `outcome` (first call wins). A failed
        write never discards the login's result: the limiter keeps the outcome
        in memory and recovers its own mark with it (not "busy" until restart)."""
        if self.grant is None or self.finished:
            return
        self.finished = True
        try:
            self.broker.limiter.finish(self.grant, outcome, self.broker.clock())
        except Exception:  # pylint: disable=broad-exception-caught
            self.finish_failed = True
            with contextlib.suppress(Exception):
                self.broker.audit(
                    "limiter_finish",
                    self.item.site,
                    "failed",
                    None,
                    {"outcome": outcome},
                )


# ---------------------------------------------------------------------------
# Socket server
# ---------------------------------------------------------------------------


class _Handler(socketserver.StreamRequestHandler):
    timeout = READ_TIMEOUT_S

    def _reply(self, obj: dict[str, Any]) -> None:
        with contextlib.suppress(OSError):
            self.wfile.write(json.dumps(obj).encode() + b"\n")
            self.wfile.flush()

    def handle(self) -> None:
        server: BrokerServer = self.server  # type: ignore[assignment]
        try:
            uid: int | None = peer_uid(self.connection)
        except (OSError, ValueError):
            uid = None
        if uid != server.allow_uid:
            server.broker.audit("?", None, "forbidden", uid)
            self._reply(_err("forbidden"))
            return
        try:
            line = self.rfile.readline(MAX_REQUEST + 1)
        except OSError:
            return
        if len(line) > MAX_REQUEST or not line.endswith(b"\n"):
            server.broker.audit("?", None, "bad_request", uid)
            self._reply(_err("bad_request", "one JSON line of at most 64 KiB"))
            return
        try:
            req = json.loads(line)
        except ValueError:
            req = None
        try:
            pid: int | None = peer_pid(self.connection)
        except (OSError, ValueError):
            pid = None  # identity challenges then refuse (fail closed)
        self._reply(server.broker.handle(req, uid, pid))


class BrokerServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    """Threaded Unix-socket server carrying the broker and the allowed peer uid."""

    daemon_threads = True

    def __init__(self, path: str, broker: Broker, allow_uid: int) -> None:
        self.broker = broker
        self.allow_uid = allow_uid
        super().__init__(path, _Handler)


def make_server(path: str, broker: Broker, allow_uid: int) -> BrokerServer:
    """Bind the socket world-connectable: the peer-uid check, not the file mode,
    is the access control.

    A stale socket left by a previous run (the socket dir is persistent, so one
    survives a crash or reboot) is unlinked — but only a SOCKET that WE own.
    Anything else at that path (another uid's socket, a regular file, a
    symlink) is refused rather than removed.
    """
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        pass
    else:
        if not stat.S_ISSOCK(st.st_mode) or st.st_uid != os.geteuid():
            raise OSError(f"refusing to replace {path}: not a socket owned by us")
        os.unlink(path)
    server = BrokerServer(path, broker, allow_uid)
    os.chmod(path, 0o666)
    return server


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Command line (every flag has a short form)."""
    p = argparse.ArgumentParser(
        prog="daemon.py",
        description="login-broker daemon (see the module docstring for the protocol).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  daemon.py                          # production, as _loginbroker\n"
            "  daemon.py -d -f items.json -H ./lb -s ./lb/broker.sock\n"
            "  daemon.py -d -f items.json -H ./lb -s ./lb/broker.sock -L  # no secretkeeper\n"
            "  daemon.py -C                       # visible collections, as _loginbroker\n"
            "  sudo daemon.py -r ricardo          # reset the limiter for one site\n"
            "  sudo daemon.py -r totp:github      # reset a TOTP item's limiter\n"
            "  sudo daemon.py -r group:galaxus    # reset an attempt group\n"
            "  sudo daemon.py -r galaxus -G       # reset a site and its groups\n"
            "  daemon.py -S docker docker-hub     # one account? as the broker uid\n"
            "  daemon.py -M                       # dual / unreadable collection\n"
            "                                     # members, as the broker uid\n"
        ),
    )
    p.add_argument("-s", "--socket", default=DEFAULT_SOCKET, help="socket path")
    p.add_argument("-H", "--home", default=DEFAULT_HOME, help="state directory")
    p.add_argument(
        "-d",
        "--dev",
        action="store_true",
        help="dev mode: allows --fixture-vault and http://127.0.0.1 origins",
    )
    p.add_argument("-f", "--fixture-vault", metavar="PATH", help="fixture items (dev)")
    p.add_argument(
        "-r",
        "--reset",
        metavar="KEY",
        help="reset the limiter for a site or group:<id>, or for secret:ITEM / "
        "totp:ITEM / secret:* / fill:SITE / filltotp:SITE / fill:* (the secret "
        "limiter), and exit (exit 3 while a login is in flight on the key)",
    )
    p.add_argument(
        "-G",
        "--with-group",
        action="store_true",
        help="with -r SITE: also reset every attempt group the site is bound to",
    )
    p.add_argument(
        "-C",
        "--collections",
        action="store_true",
        help="print the broker account's visible collections as "
        "org_id<TAB>org_name<TAB>collection_id<TAB>collection_name and exit",
    )
    p.add_argument(
        "-L",
        "--no-leakcheck",
        action="store_true",
        help="do not register issued values with the secretkeeper (dev only; "
        "the secret op otherwise fails closed when it cannot)",
    )
    p.add_argument(
        "-K",
        "--leakcheck-socket",
        default=SECRETKEEPER_SOCKET,
        metavar="PATH",
        help=f"secretkeeper socket (default {SECRETKEEPER_SOCKET})",
    )
    p.add_argument(
        "-u",
        "--allow-uid",
        type=int,
        default=DEFAULT_ALLOW_UID,
        help=f"the only peer uid served (default {DEFAULT_ALLOW_UID})",
    )
    p.add_argument(
        "-S",
        "--same-account",
        nargs=2,
        metavar=("SITE_A", "SITE_B"),
        help="as the broker uid (install.sh -S): do the two items log into the "
        "same account name? prints same / different / unknown (account tags; "
        "never a name) and exits",
    )
    p.add_argument(
        "-M",
        "--membership",
        action="store_true",
        help="as the broker uid (install.sh -M): list every item of the login "
        "and secrets collections whose collection membership is dual (in both: "
        "refused on both sides) or unreadable, as side<TAB>status<TAB>safe "
        "name<TAB>item id, and exit (0 none, 3 some listed, 1 vault error)",
    )
    p.add_argument(
        "-g",
        "--script-gate",
        action="store_true",
        help="as the broker uid (install.sh -g): the agent_script gate report — "
        "every item secret-run serves TODAY that mode agent_script would refuse, "
        "and every item with a malformed agent_script, as "
        "kind<TAB>gate_code<TAB>id<TAB>safe name<TAB>item id; exit 0 none, 3 some "
        "listed, 1 vault error. With -j: EVERY row mode agent_script would list, "
        "one JSON object each (what install.sh -D checks)",
    )
    p.add_argument(
        "-j",
        "--json",
        action="store_true",
        help="with -g: one JSON object per row (kind, gate_code, id, name, "
        "item_id, served_now — never a value)",
    )
    return p.parse_args(argv)


def build_limiter(home: Path) -> Limiter:
    """The production limiter on ``<home>/limiter.json``."""
    return Limiter(home / "limiter.json", MIN_INTERVAL_S, PER_HOUR, PER_DAY)


def _tsv_cell(text: str) -> str:
    return re.sub(r"[\t\r\n\x00-\x1f\x7f]", " ", text)


def print_collections(vault: FixtureVault | BwVault) -> int:
    """``daemon.py -C``: one TSV line per visible collection, no item data."""
    try:
        rows = vault.collections()
    except VaultError as exc:
        print(f"❌ {exc}", file=sys.stderr)
        return 1
    for row in rows:
        print("\t".join(_tsv_cell(c) for c in row))
    return 0


LOGIN_KEY_RE = re.compile(r"^(group:)?[a-z0-9][a-z0-9._-]{0,63}$")


def _home_owner(home: Path) -> tuple[int, int] | None:
    """(uid, gid) of the broker home when running as root (the reset hands
    the files back to the broker), else None."""
    if os.geteuid() != 0:
        return None
    st = home.stat()
    return st.st_uid, st.st_gid


# One early exit per refusal; the login path warns about blocking groups.
def _reset(args: argparse.Namespace, home: Path) -> int:  # pylint: disable=too-many-return-statements
    """``-r KEY [-G]``: a site, ``group:<id>`` or a secret key; see `parse_args`."""
    if os.geteuid() != 0 and not args.dev:
        print("❌ --reset needs root (or --dev)", file=sys.stderr)
        return 2
    key = args.reset.strip().lower()
    owner = _home_owner(home)
    if key.startswith(LIMITER_KEY_PREFIXES):
        if args.with_group or not LIMITER_KEY_RE.match(key):
            print(f"❌ not a secret limiter key: {key!r}", file=sys.stderr)
            return 2
        return _reset_keys(build_secret_limiter(home), [key], owner)
    if not LOGIN_KEY_RE.match(key):
        print(f"❌ not a site id or group:<id>: {key!r}", file=sys.stderr)
        return 2
    limiter = build_limiter(home)
    if key.startswith("group:"):
        if args.with_group:
            print("❌ -G/--with-group goes with a SITE, not a group", file=sys.stderr)
            return 2
        return _reset_keys(limiter, [key], owner)
    groups = [group_key(g) for g in limiter.groups_of(key)]  # pure read
    if args.with_group:
        if not groups:
            print(f"ℹ️ no group bound to {key} yet — resetting the site only")
        return _reset_keys(limiter, [key, *groups], owner, keep_bindings=False)
    rc = _reset_keys(limiter, [key], owner)
    try:
        if IdentityGuard(home).reset(key, owner):
            print(f"✅ identity challenge guard reset for {key}")
    except GuardStateError as exc:
        print(f"❌ {key}: identity guard state not usable ({exc})", file=sys.stderr)
        rc = rc or 1
    now = time.time()
    for gkey in groups:
        # A PURE read: no crash recovery, nothing written (a write as root
        # would leave limiter.json root-owned).
        denied = limiter.blocking([gkey], now)
        if denied is not None and denied.state in ("locked", "cooldown"):
            print(
                f"⚠️ {gkey} still blocks {key} ({denied.state}): "
                f"sudo install/install.sh -r {gkey}   (or -r {key} -G)"
            )
    return rc


def _reset_keys(
    limiter: Limiter,
    keys: list[str],
    owner: tuple[int, int] | None,
    *,
    keep_bindings: bool = True,
) -> int:
    """Reset every key: a live in-flight attempt refuses that key (exit 3), an
    unusable state or lock file (a symlink, a corrupt lock) every key (exit 1).
    `keep_bindings` False (``-G``): the site's group bindings go too."""
    rc = 0
    for key in keys:
        try:
            limiter.reset(key, owner=owner, keep_bindings=keep_bindings)
        except LimiterBusy as exc:
            print(f"❌ {exc}", file=sys.stderr)
            rc = 3
            continue
        except (LimiterStateError, OSError) as exc:
            print(f"❌ {key}: limiter state not usable ({exc})", file=sys.stderr)
            return 1
        print(f"✅ limiter reset for {key}")
    return rc


def _home_problem(home: Path) -> str:
    """'' when the broker home is a real directory owned by this uid with no
    group/other bits, else why not (checked at every start: an existing home
    keeps whatever mode it had)."""
    try:
        st = os.lstat(home)
    except OSError as exc:
        return f"cannot stat {home} ({exc.strerror})"
    if not stat.S_ISDIR(st.st_mode):
        return f"{home} is not a directory"
    if st.st_uid != os.geteuid() or st.st_mode & 0o077:
        return (
            f"{home} is {oct(stat.S_IMODE(st.st_mode))} uid {st.st_uid} "
            f"(want 0700 uid {os.geteuid()})"
        )
    return ""


def _same_account_cli(args: argparse.Namespace, home: Path) -> int:
    """``-S A B``: same / different / unknown from the account tags (never a
    name), as the broker's own uid — it owns the tag key and the bw state;
    ``install.sh -S`` runs it so. One audit line with the answer only."""
    if not args.dev and (os.geteuid() == 0 or _home_owner_uid(home) != os.geteuid()):
        print(
            "❌ -S runs as the broker uid (install/install.sh -S A B)", file=sys.stderr
        )
        return 2
    sites = [s.strip().lower() for s in args.same_account]
    if not all(SITE_ID_RE.match(s) for s in sites) or sites[0] == sites[1]:
        print("❌ -S needs two different site ids", file=sys.stderr)
        return 2
    vault: Vault = (
        FixtureVault(args.fixture_vault, dev=True)
        if args.fixture_vault
        else _LazyBwVault(home)
    )
    try:
        items = vault.items()
        key = load_tag_key(home / TAG_KEY_NAME)
    except (VaultError, TagKeyError) as exc:
        print(f"❌ {exc}", file=sys.stderr)
        return 1
    answer = same_account_answer(items, sites[0], sites[1], key)
    rec = {
        "ts": round(time.time(), 3),
        "op": "same_account_cli",
        "site": None,
        "sites": sites,
        "result": answer,
        "uid": os.getuid(),
    }
    auditlog.append_line(home, json.dumps(rec, sort_keys=True))
    print(answer)
    return 0


def _membership_cli(args: argparse.Namespace, home: Path) -> int:
    """``-M``: the dual-member and unreadable items of both collections
    (``vault.membership_rows``: safe name + item id, never a field or a
    value), as the broker's own uid — it owns the bw state. One audit line
    with the count only."""
    if not args.dev and (os.geteuid() == 0 or _home_owner_uid(home) != os.geteuid()):
        print("❌ -M runs as the broker uid (install/install.sh -M)", file=sys.stderr)
        return 2
    try:
        if args.fixture_vault:
            rows = FixtureVault(args.fixture_vault, dev=True).membership_problems()
        else:
            rows = _LazyBwVault(home).membership_problems()
    except VaultError as exc:
        print(f"❌ {exc}", file=sys.stderr)
        return 1
    rec = {
        "ts": round(time.time(), 3),
        "op": "membership_cli",
        "site": None,
        "result": "ok",
        "listed": len(rows),
        "uid": os.getuid(),
    }
    with contextlib.suppress(OSError):
        auditlog.append_line(home, json.dumps(rec, sort_keys=True))
    if not rows:
        print("✅ no dual-member or unreadable item in either collection")
        return 0
    for row in rows:
        print("\t".join(_tsv_cell(c) for c in row))
    print(
        f"❌ {len(rows)} item(s) refused for their collection membership: split a "
        "dual item into a login item and a secrets item",
        file=sys.stderr,
    )
    return 3


def _script_gate_cli(args: argparse.Namespace, home: Path) -> int:
    """``-g``: the agent_script gate report (``vault.script_gate_rows``: kind,
    code, id, safe name, item id — never a field or a value), as the broker's
    own uid. One audit line with the counts only."""
    if not args.dev and (os.geteuid() == 0 or _home_owner_uid(home) != os.geteuid()):
        print("❌ -g runs as the broker uid (install/install.sh -g)", file=sys.stderr)
        return 2
    try:
        if args.fixture_vault:
            rows = FixtureVault(args.fixture_vault, dev=True).script_gate_report()
        else:
            rows = _LazyBwVault(home).script_gate_report()
    except VaultError as exc:
        print(f"❌ {exc}", file=sys.stderr)
        return 1
    problems = [
        r
        for r in rows
        if r.gate_code == "bad_agent_script"
        or (r.served_now and r.gate_code != GATE_OK)
    ]
    rec = {
        "ts": round(time.time(), 3),
        "op": "script_gate_cli",
        "site": None,
        "result": "ok",
        "listed": len(problems),
        "rows": len(rows),
        "uid": os.getuid(),
    }
    with contextlib.suppress(OSError):
        auditlog.append_line(home, json.dumps(rec, sort_keys=True))
    if args.json:
        for row in rows:
            print(json.dumps(row.public(), sort_keys=True))
        return 0
    if not problems:
        print("✅ every item secret-run serves today carries agent_script=true")
        return 0
    for r in problems:
        cells = (r.kind, r.gate_code, r.secret_id, r.name, r.item_id or "?")
        print("\t".join(_tsv_cell(c) for c in cells))
    print(
        f"❌ {len(problems)} item(s) mode agent_script would refuse: set "
        "agent_script=true on the ones a script reads (broker-add.py NAME -a)",
        file=sys.stderr,
    )
    return 3


def _home_owner_uid(home: Path) -> int | None:
    try:
        return home.stat().st_uid
    except OSError:
        return None


def _leakcheck_loop(broker: Broker, stop: threading.Event) -> None:
    """Re-push at start (a secretkeeper restarted while the broker was down),
    then every REPUSH_INTERVAL_S (tp#1138 B5)."""
    while True:
        with contextlib.suppress(Exception):
            broker.refresh_leakcheck()
        if stop.wait(REPUSH_INTERVAL_S):
            return


# One early exit per CLI mode / guard.
def main(  # pylint: disable=too-many-return-statements,too-many-branches,too-many-statements
    argv: list[str] | None = None,
) -> int:
    """Run the daemon (or the limiter reset)."""
    args = parse_args(argv)
    os.umask(0o077)
    home = Path(args.home)
    if args.fixture_vault and not args.dev:
        print("❌ --fixture-vault requires --dev", file=sys.stderr)
        return 2
    if args.reset:
        return _reset(args, home)
    if args.same_account:
        return _same_account_cli(args, home)
    if args.membership:
        return _membership_cli(args, home)
    if args.script_gate:
        return _script_gate_cli(args, home)
    if args.json:
        print("❌ -j/--json only works with -g/--script-gate", file=sys.stderr)
        return 2
    if args.collections:
        if args.fixture_vault:
            return print_collections(FixtureVault(args.fixture_vault, dev=True))
        try:
            boot = BwBootstrap.load(home / "bootstrap.json")
        except VaultError as exc:
            print(f"❌ {exc}", file=sys.stderr)
            return 1
        return print_collections(BwVault(boot, home / "bw"))
    if args.with_group and not args.reset:
        print("❌ -G/--with-group only works with -r SITE", file=sys.stderr)
        return 2
    limiter = build_limiter(home)
    if not args.dev and os.geteuid() == args.allow_uid:
        print(
            f"❌ refusing to serve uid {args.allow_uid} while running AS uid "
            f"{args.allow_uid}: the boundary would be void (use --dev for local tests)",
            file=sys.stderr,
        )
        return 2
    vault: Vault
    if args.fixture_vault:
        vault = FixtureVault(args.fixture_vault, dev=True)
    else:
        vault = _LazyBwVault(home)
    home.mkdir(mode=0o700, parents=True, exist_ok=True)
    problem = _home_problem(home)
    if problem and not args.dev:
        print(f"❌ refusing to start: {problem}", file=sys.stderr)
        return 1
    limiter.ensure_lock_file()  # created by the broker itself: it owns it
    leakcheck: Registrar
    if args.no_leakcheck:
        print(
            "⚠️ --no-leakcheck: issued values are NOT registered with the secretkeeper",
            file=sys.stderr,
            flush=True,
        )
        leakcheck = DisabledLeakCheck()
    else:
        leakcheck = LeakCheck(args.leakcheck_socket, home / "leakcheck-labels.json")
    broker = Broker(
        vault,
        limiter,
        home,
        runner=PlaywrightRunner(home, dev=args.dev),
        allow_uid=args.allow_uid,
        leakcheck=leakcheck,
    )
    server = make_server(args.socket, broker, args.allow_uid)

    def _stop(_sig: int, _frm: Any) -> None:
        threading.Thread(target=server.shutdown, daemon=True).start()

    def _reload(_sig: int, _frm: Any) -> None:
        def run() -> None:
            generation = broker.invalidate()
            broker.audit("sighup", None, "ok", None, {"generation": generation})

        threading.Thread(target=run, daemon=True).start()

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGHUP, _reload)
    stop_refresh = threading.Event()
    threading.Thread(
        target=_leakcheck_loop, args=(broker, stop_refresh), daemon=True
    ).start()
    print(f"login-broker listening on {args.socket} (uid {args.allow_uid})", flush=True)
    try:
        server.serve_forever()
    finally:
        stop_refresh.set()
        server.server_close()
        with contextlib.suppress(OSError):
            os.unlink(args.socket)
    return 0


if __name__ == "__main__":
    sys.exit(main())
