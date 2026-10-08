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
  {"op": "fingerprint", "site": "X"}  len + 4 hex of the password's SHA-256

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

Errors: {"ok": false, "error": "needs_human" | "origin_violation" |
"rate_limited" | "login_failed" | "unknown_site" | "unknown_item" |
"unknown_field" | "refused" | "vault_error" | "leakcheck_unavailable" |
"forbidden" | "bad_request" | "internal", "detail": "..."} — never a secret.

Examples:
  daemon.py                                   # production (as _loginbroker)
  daemon.py -d -f items.json -H /tmp/lb -s /tmp/lb/broker.sock -u 501 -L
  daemon.py -C -H /var/db/login-broker        # list visible collections (IDs)
  sudo daemon.py -r ricardo                   # reset the limiter for one site
  sudo daemon.py -r secret:github             # reset a secret item's limiter
"""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import hashlib
import json
import os
import re
import shutil
import signal
import socketserver
import stat
import sys
import threading
import time
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

if __package__ in (None, ""):  # run as a script: make `broker` importable
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# pylint: disable=wrong-import-position
from broker.bundle import SiteBundleSpec, filter_cookies, filter_storage  # noqa: E402
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
from broker.limiter import Limiter  # noqa: E402
from broker.origins import origin_allowed  # noqa: E402
from broker.peercred import peer_uid  # noqa: E402
from broker.recipes import (  # noqa: E402
    LoginFailed,
    RecipeError,
    check_logged_in,
    cscs_portal_ready,
    diagnose,
    recipe_for,
)
from broker.runs import RunTable  # noqa: E402
from broker.secret_ops import (  # noqa: E402
    LIMITER_KEY_RE,
    SECRET_OPS,
    SecretOps,
    build_secret_limiter,
)
from broker.useragent import CHROME_UA_TEMPLATE, engine_user_agent  # noqa: E402
from broker.vault import (  # noqa: E402
    SITE_ID_RE,
    BwBootstrap,
    BwVault,
    FixtureVault,
    Secret,
    SecretItem,
    SecretValues,
    SiteItem,
    Vault,
    VaultCache,
    VaultError,
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
_BLANK_PASSWORDS_JS = (
    "() => document.querySelectorAll('input[type=password]').forEach(i => i.value = '')"
)
CSCS_PORTAL_ORIGIN = "https://portal.cscs.ch"
# localStorage keys whose value looks like a Waldur DRF token (40 hex chars).
_TOKEN_KEYS_JS = (
    "() => Object.keys(localStorage).filter(k => "
    "/\\b[0-9a-f]{40}\\b/.test(localStorage.getItem(k) || ''))"
)
_STORAGE_JS = "keys => Object.fromEntries(keys.map(k => [k, localStorage.getItem(k)]))"


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

    def profile_dir(self, site: str) -> Path:
        """The broker's own profile for `site`."""
        return self.home / "profiles" / site

    def _launch(self, pw: Any, profile: Path) -> Any:
        kwargs: dict[str, Any] = {
            "user_data_dir": str(profile),
            "headless": True,
            "args": CHROME_ARGS,
            "user_agent": broker_user_agent(pw),
            "chromium_sandbox": True,
        }
        try:
            return pw.chromium.launch_persistent_context(channel="chromium", **kwargs)
        except Exception:  # pylint: disable=broad-exception-caught
            if not self.dev:
                raise
            # Dev only: the full `chromium` build may be missing from the local
            # Playwright cache; the default build is good enough for a fixture.
            self.channel_fallback = True
            return pw.chromium.launch_persistent_context(**kwargs)

    def _profile_logged_in(self, page: Any, item: SiteItem) -> bool:
        """The positive check (check URL / sentinel) on the broker's own profile."""
        try:
            return check_logged_in(page, item, dev=self.dev, wait_s=5.0)
        except Exception:  # pylint: disable=broad-exception-caught
            return False

    def _record_failure(self, page: Any, item: SiteItem, secret: Secret) -> None:
        """Secret-free failure report + screenshot (password fields emptied first)."""
        try:
            diag = diagnose(page, secret)
        except Exception:  # pylint: disable=broad-exception-caught
            diag = {"error": "page could not be inspected"}
        diag["password_check"] = password_fingerprint(secret.password)
        try:
            page.evaluate(_BLANK_PASSWORDS_JS)
            shot = self.diag_dir / f"last-failure-{item.site}.png"
            page.screenshot(path=str(shot), full_page=False)
            os.chmod(shot, 0o644)
            diag["screenshot"] = str(shot)
        except Exception:  # pylint: disable=broad-exception-caught
            pass
        self.last_diag[item.site] = diag

    def _with_portal_token_keys(
        self, ctx: Any, item: SiteItem, spec: SiteBundleSpec
    ) -> SiteBundleSpec:
        """CSCS: add the portal's Waldur token key(s) to the export.

        HomePort keeps its 40-hex DRF token in localStorage under a key its bundle
        builds at run time, so the key is found by the VALUE's shape on the portal
        origin (what browser.py's ``_scan_token`` reads); nothing else is added.
        """
        if item.site != "cscs" or CSCS_PORTAL_ORIGIN in spec.storage_keys:
            return spec
        page = ctx.new_page()
        try:
            page.goto(CSCS_PORTAL_ORIGIN + "/", wait_until="domcontentloaded")
            cscs_portal_ready(page, wait_s=10.0)  # the token may land late
            if not origin_allowed(page.url, [CSCS_PORTAL_ORIGIN], dev=self.dev):
                return spec
            keys = page.evaluate(_TOKEN_KEYS_JS)
        except Exception:  # pylint: disable=broad-exception-caught
            return spec
        finally:
            with contextlib.suppress(Exception):
                page.close()
        if not isinstance(keys, list) or not keys:
            return spec
        storage = {**spec.storage_keys, CSCS_PORTAL_ORIGIN: [str(k) for k in keys]}
        return dataclasses.replace(spec, storage_keys=storage)

    def export_bundle(self, ctx: Any, item: SiteItem, via: str) -> dict[str, Any]:
        """Allowlisted cookies + named localStorage keys of the listed origins."""
        spec = self._with_portal_token_keys(ctx, item, item.bundle_spec)
        cookies = filter_cookies(ctx.cookies(), spec)
        raw: dict[str, dict[str, Any]] = {}
        for origin, keys in spec.storage_keys.items():
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
        return {
            "site": item.site,
            "via": via,
            "cookies": cookies,
            "storage": filter_storage(raw, spec),
            "cookie_hosts": list(spec.cookie_hosts),
            "cookie_names": spec.cookie_names,
        }

    def clear_site_cookies(self, ctx: Any, item: SiteItem) -> int:
        """``agent_fresh_login``: delete every cookie of the broker's OWN profile
        that the browser would send to one of the site's cookie hosts or fill
        origin hosts (the host itself, a subdomain or a parent domain of it).

        Afterwards neither the site's long-lived account cookie nor a stale IdP
        cookie can short-circuit the login. Returns the number deleted.
        """
        hosts = fresh_login_hosts(item)
        cleared = 0
        for ck in ctx.cookies():
            domain = str(ck.get("domain") or "")
            if cookie_reaches_hosts(domain, hosts):
                ctx.clear_cookies(
                    name=ck.get("name"), domain=domain, path=ck.get("path") or "/"
                )
                cleared += 1
        return cleared

    def run_in_context(
        self, ctx: Any, item: SiteItem, get_secret: Callable[[], Secret]
    ) -> dict[str, Any]:
        """Profile check (or, with ``fresh_login``, a cookie wipe), recipe,
        positive proof and export on an already launched context."""
        page = ctx.pages[0] if ctx.pages else ctx.new_page()
        if item.fresh_login:
            # Never "via profile": the login must pass through the IdP in this
            # run so its session-only SSO cookie exists when the bundle is cut.
            self.clear_site_cookies(ctx, item)
            reuse = False
        else:
            reuse = self._profile_logged_in(page, item)
        if reuse:
            return self.export_bundle(ctx, item, "profile")
        secret = get_secret()
        try:
            recipe_for(item.site)(page, item, secret, dev=self.dev)
        except RecipeError:
            self._record_failure(page, item, secret)
            raise
        # Snapshot where the recipe ended — the check below navigates away.
        try:
            before = diagnose(page, secret)
        except Exception:  # pylint: disable=broad-exception-caught
            before = {}
        # Positive proof after EVERY login, whatever the recipe saw.
        if not self._profile_logged_in(page, item):
            self._record_failure(page, item, secret)
            self.last_diag[item.site]["before_check"] = before
            raise LoginFailed(
                "login did not reach a logged-in state (check URL / sentinel)",
                submitted=True,
            )
        return self.export_bundle(ctx, item, "login")

    def __call__(
        self, item: SiteItem, get_secret: Callable[[], Secret]
    ) -> dict[str, Any]:
        from playwright.sync_api import (  # pylint: disable=import-outside-toplevel
            sync_playwright,
        )

        profile = self.profile_dir(item.site)
        profile.mkdir(mode=0o700, parents=True, exist_ok=True)
        with sync_playwright() as pw:
            ctx = self._launch(pw, profile)
            try:
                return self.run_in_context(ctx, item, get_secret)
            finally:
                with contextlib.suppress(Exception):
                    ctx.close()


def fresh_login_hosts(item: SiteItem) -> list[str]:
    """The hosts an ``agent_fresh_login`` wipe covers: the cookie hosts plus the
    hosts of the fill origins (lower-case, no leading dot, no port)."""
    hosts: list[str] = []
    for host in [*item.cookie_hosts, *(url_host(o) for o in item.fill_origins)]:
        h = host.strip().lstrip(".").lower()
        if h and h not in hosts:
            hosts.append(h)
    return hosts


def url_host(origin: str) -> str:
    """``https://login.eduid.ch:8443`` -> ``login.eduid.ch``."""
    return (urllib.parse.urlsplit(origin).hostname or "").lower()


def cookie_reaches_hosts(domain: str, hosts: list[str]) -> bool:
    """True iff a cookie of `domain` is sent to (or set below) one of `hosts`:
    the same host, a subdomain of it, or a parent domain of it."""
    d = domain.strip().lstrip(".").lower()
    if not d:
        return False
    return any(d == h or d.endswith("." + h) or h.endswith("." + d) for h in hosts)


# ---------------------------------------------------------------------------
# Request handling
# ---------------------------------------------------------------------------


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

    def items(self) -> list[SiteItem]:
        """See ``BwVault.items``."""
        return self._vault().items()

    def secret(self, site: str) -> Secret:
        """See ``BwVault.secret``."""
        return self._vault().secret(site)


def password_fingerprint(password: str) -> str:
    """``len=<n> sha256:<first 4 hex>`` — lets Albert check the broker used the SAME
    password as his vault (``printf %s "$PW" | shasum -a 256 | cut -c1-4``)
    without revealing it: 16 bits of a hash of a 20+-char random password."""
    digest = hashlib.sha256(password.encode("utf-8")).hexdigest()[:4]
    return f"len={len(password)} sha256:{digest}"


def _err(code: str, detail: str = "") -> dict[str, Any]:
    return {"ok": False, "error": code, "detail": detail}


# The site list (ids, origins, check URLs — no secrets) is kept this long: each
# Bitwarden read is an unlock + sync + list + lock of ~30-40 s. Secrets are
# always read fresh.
SITES_TTL_S = 600.0


class Broker(SecretOps):  # pylint: disable=too-many-instance-attributes  # deps + 4 locks/maps
    """Protocol logic, independent of the socket (unit-testable).

    The secret ops answer only `allow_uid` (None = nobody). `leakcheck`
    defaults to a backend that always fails, so a broker wired without one
    fails closed (``leakcheck_unavailable``).
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

    def _items(self, *, fresh: bool = False) -> list[SiteItem]:
        """The vault's site items, cached SITES_TTL_S (raises VaultError)."""
        with self._items_lock:
            now = self.clock()
            cached = self._items_cache
            if not fresh and cached and now - cached[0] < SITES_TTL_S:
                return cached[1]
            items = self.vault.items()
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
            fd = os.open(
                str(self.home / "audit.log"),
                os.O_WRONLY | os.O_APPEND | os.O_CREAT,
                0o600,
            )
            try:
                os.write(fd, line.encode())
            finally:
                os.close(fd)

    def _site_lock(self, site: str) -> threading.Lock:
        with self._guard:
            return self._site_locks.setdefault(site, threading.Lock())

    # -- ops -------------------------------------------------------------------
    def handle(self, req: Any, uid: int | None = None) -> dict[str, Any]:
        """Dispatch one decoded request; always returns a JSON-able dict."""
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
            elif op in ("login", "logout", "fingerprint"):
                if not site or not SITE_ID_RE.match(site):
                    resp = _err("bad_request", "missing or invalid site id")
                elif op == "login":
                    resp = self._login(site)
                elif op == "fingerprint":
                    resp = self._fingerprint(site)
                else:
                    resp = self._logout(site)
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
        return {"ok": True, "sites": [it.public() for it in items]}

    def _fingerprint(self, site: str) -> dict[str, Any]:
        """Length + 4 hex of the SHA-256 of the password the vault holds for `site`
        — to compare with Albert's copy without a login attempt or the value."""
        try:
            secret = self.vault.secret(site)
        except VaultError as exc:
            return _err("vault_error", str(exc))
        return {"ok": True, "password_check": password_fingerprint(secret.password)}

    def _logout(self, site: str) -> dict[str, Any]:
        with self._site_lock(site):
            profile = self.home / "profiles" / site
            existed = profile.exists()
            if existed:
                shutil.rmtree(profile)
        return {"ok": True, "removed": existed}

    def _login(self, site: str) -> dict[str, Any]:
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
                result = self._do_login(site)
        finally:
            flight.result = result
            with self._guard:
                self._flights.pop(site, None)
            flight.done.set()
        return result

    # One return per protocol error code, in the order they are checked.
    def _do_login(self, site: str) -> dict[str, Any]:  # pylint: disable=too-many-return-statements
        try:
            items = self._items()
            item = next((it for it in items if it.site == site), None)
            if item is None:  # added since the cache was filled?
                items = self._items(fresh=True)
                item = next((it for it in items if it.site == site), None)
        except VaultError as exc:
            return _err("vault_error", str(exc))
        if item is None:
            return _err("unknown_site", f"{site!r} is not in agent-logins")
        if item.refused:
            return _err("refused", item.refused)
        ok, reason = self.limiter.check(site, self.clock())
        if not ok:
            return _err("rate_limited", reason)

        fetched: list[bool] = []

        def get_secret() -> Secret:
            self.limiter.begin_attempt(site, self.clock())
            fetched.append(True)
            return self.vault.secret(site)

        outcome = "ok"
        try:
            bundle = self.runner(item, get_secret)
        except RecipeError as exc:
            outcome = "unknown" if exc.submitted else "failed"
            diag = getattr(self.runner, "last_diag", {}).pop(site, None)
            return {**_err(exc.code, exc.detail), **({"diag": diag} if diag else {})}
        except VaultError as exc:
            outcome = "failed"
            return _err("vault_error", str(exc))
        except Exception:  # pylint: disable=broad-exception-caught
            outcome = "unknown"
            return _err("login_failed", "unexpected error during login")
        finally:
            if fetched:
                self.limiter.record_attempt(site, self.clock(), outcome)
        return {"ok": True, "bundle": bundle}


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
        self._reply(server.broker.handle(req, uid))


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
        help="reset the limiter for a site, or for secret:ITEM / totp:ITEM / "
        "secret:* (the secret limiter), and exit",
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


def _reset(args: argparse.Namespace, home: Path) -> int:
    if os.geteuid() != 0 and not args.dev:
        print("❌ --reset needs root (or --dev)", file=sys.stderr)
        return 2
    key = args.reset.strip().lower()
    if ":" in key:
        if not LIMITER_KEY_RE.match(key):
            print(f"❌ not a secret limiter key: {key!r}", file=sys.stderr)
            return 2
        limiter = build_secret_limiter(home)
    else:
        limiter = build_limiter(home)
    limiter.reset(key)
    if os.geteuid() == 0:  # root rewrote the file: hand it back to the broker
        owner = home.stat()
        os.chown(limiter.state_path, owner.st_uid, owner.st_gid)
    print(f"✅ limiter reset for {key}")
    return 0


def _leakcheck_loop(broker: Broker, stop: threading.Event) -> None:
    while not stop.wait(REPUSH_INTERVAL_S):
        with contextlib.suppress(Exception):
            broker.refresh_leakcheck()


# One early exit per CLI mode / guard.
def main(argv: list[str] | None = None) -> int:  # pylint: disable=too-many-return-statements
    """Run the daemon (or the limiter reset)."""
    args = parse_args(argv)
    os.umask(0o077)
    home = Path(args.home)
    if args.fixture_vault and not args.dev:
        print("❌ --fixture-vault requires --dev", file=sys.stderr)
        return 2
    if args.reset:
        return _reset(args, home)
    if args.collections:
        if args.fixture_vault:
            return print_collections(FixtureVault(args.fixture_vault, dev=True))
        try:
            boot = BwBootstrap.load(home / "bootstrap.json")
        except VaultError as exc:
            print(f"❌ {exc}", file=sys.stderr)
            return 1
        return print_collections(BwVault(boot, home / "bw"))
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
