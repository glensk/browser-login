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
  sudo daemon.py -r group:galaxus             # reset an attempt group
  sudo daemon.py -r galaxus -G                # reset a site and its groups
"""

from __future__ import annotations

# runner, protocol and CLI of one daemon.
# pylint: disable=too-many-lines
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
from broker.limiter import (  # noqa: E402
    AttemptGrant,
    Denied,
    Limiter,
    LimiterBusy,
    LimiterStateError,
    group_key,
)
from broker.origins import origin_allowed  # noqa: E402
from broker.page_state import diagnose, sentinel_shown  # noqa: E402
from broker.peercred import peer_uid  # noqa: E402
from broker.phases import PHASE_V  # noqa: E402
from broker.recipes import (  # noqa: E402
    INDETERMINATE,
    NO_PASSKEY_JS,
    REFRESH_NONE,
    REFRESH_REJECTED,
    VALID,
    AttemptController,
    ExportFailed,
    LoginFailed,
    RecipeError,
    check_proof,
    cscs_portal_ready,
    recipe_for,
    refresh_session,
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
    selector_ok,
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


# How long the broker profile's proof polls for the sentinel (an SPA boots:
# reads its token, asks its API, renders).
PROFILE_PROOF_WAIT_S = 8.0


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

    def profile_dir(self, site: str) -> Path:
        """The broker's own profile for `site`."""
        return self.home / "profiles" / site

    def _launch(self, pw: Any, profile: Path, item: SiteItem | None = None) -> Any:
        kwargs: dict[str, Any] = {
            "user_data_dir": str(profile),
            "headless": True,
            "args": CHROME_ARGS,
            "user_agent": broker_user_agent(pw),
            "chromium_sandbox": True,
        }
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
        return ctx

    def _profile_proof(self, page: Any, item: SiteItem) -> str:
        """The tri-state proof (``recipes.check_proof``) on the broker's own
        profile; an exception is ``indeterminate``."""
        try:
            return check_proof(page, item, dev=self.dev, wait_s=PROFILE_PROOF_WAIT_S)
        except Exception:  # pylint: disable=broad-exception-caught
            return INDETERMINATE

    def _record_failure(self, page: Any, item: SiteItem, secret: Secret) -> None:
        """Secret-free failure report + screenshot (password fields emptied first)."""
        try:
            diag: dict[str, Any] = diagnose(page, secret)
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
        with contextlib.suppress(Exception):
            seen = _HTML_SCRIPTS.get(id(page.context)) or []
            if seen:
                diag["script_as_html"] = sorted(set(seen))[:3]
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
            # The key NAMES the bundle must carry (the client checks the
            # bundle is complete before it touches the shared browser).
            "storage_keys": {o: list(k) for o, k in spec.storage_keys.items()},
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
        """Profile proof (or, with ``fresh_login``, reservation + cookie wipe),
        recipe, positive proof and export on an already launched context.

        The limiter is only touched through `get_secret` (it reserves the
        attempt): a validated profile reuse never calls it, so it works during
        a cooldown and leaves the limiter untouched. `get_secret.attempt` (when
        present) is the ``AttemptController`` handed to the recipe.
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
            # Reserve FIRST: a denied reservation leaves the profile untouched.
            secret = get_secret()
            self.clear_site_cookies(ctx, item)
        else:
            proof = self._profile_proof(page, item)
            if proof == VALID:
                # A storage token near its expiry is renewed first; a token
                # the server rejects means the profile is not reusable.
                refreshed = refresh_session(page, item, dev=self.dev)
                if refreshed != REFRESH_REJECTED:
                    # (a candidate: present here + absent logged out = verified)
                    return self._export(
                        ctx, item, "profile", proven=False, refresh=refreshed
                    )
            if getattr(get_secret, "refresh_only", False):
                # Not reusable (invalid, indeterminate or token rejected): a
                # refresh-only request ends here, as `refresh_unavailable`.
                get_secret()
            if proof == INDETERMINATE:
                raise LoginFailed(
                    "could not tell whether the broker profile is logged in "
                    "(check page did not load, answered 5xx or stayed blank)"
                    + html_script_hint(page),
                    phase="profile-proof",
                )
            secret = get_secret()
        attempt: AttemptController = getattr(get_secret, "attempt", None) or (
            AttemptController()
        )
        try:
            recipe_for(item.site)(page, item, secret, dev=self.dev, attempt=attempt)
        except RecipeError as exc:
            self._record_failure(page, item, secret)
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
        try:
            before = diagnose(page, secret)
        except Exception:  # pylint: disable=broad-exception-caught
            before = {}
        # Positive proof after EVERY login, whatever the recipe saw.
        proof = self._profile_proof(page, item)
        if proof != VALID:
            self._record_failure(page, item, secret)
            self.last_diag[item.site]["before_check"] = before
            raise LoginFailed(
                (
                    "login did not reach a logged-in state (status / origin / sentinel)"
                    if proof != INDETERMINATE
                    else "the logged-in proof could not decide (check page did not "
                    "load, answered 5xx or stayed blank)"
                )
                + html_script_hint(page),
                submitted=attempt.submitted,
                phase="broker-proof",
            )
        return self._export(ctx, item, "login", proven=True)

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
    ) -> dict[str, Any]:
        """`export_bundle`, raising ``ExportFailed`` when it fails or the
        bundle holds no cookie and no storage key. `proven`: a fresh login was
        proven just before (the limiter counts it as ``ok`` anyway)."""
        try:
            bundle = self.export_bundle(ctx, item, via)
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
            ctx = self._launch(pw, profile, item)
            try:
                return self.run_in_context(ctx, item, get_secret)
            finally:
                _NOCACHE_SESSIONS.pop(id(ctx), None)
                _HTML_SCRIPTS.pop(id(ctx), None)
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
        self._probe_slot = threading.Lock()  # `sentinel_absent`: one at a time

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
            elif op in ("login", "logout", "fingerprint", "sentinel_absent"):
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
                    )
                elif op == "sentinel_absent":
                    resp = self._sentinel_absent(site, req.get("sentinel"))
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
        now = self.clock()
        out = []
        for it in items:
            entry = it.public()
            if not it.refused:
                denied = self.limiter.peek_site(it.site, now, group=it.attempt_group)
                entry["limit"] = denied.limit() if denied else {"state": "ok"}
            out.append(entry)
        return {"ok": True, "sites": out}

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

    # One return per refusal of an option combination, then one per route.
    def _login_request(  # pylint: disable=too-many-return-statements
        self, site: str, req: dict[str, Any]
    ) -> dict[str, Any]:
        """``login`` with its options: ``scheduled`` (the daily check), a
        one-shot ``candidate_sentinel`` (never for a scheduled run) and
        ``refresh_only`` (re-export a still-valid profile, its storage token
        renewed when due — never a password: a profile that is not reusable
        answers ``refresh_unavailable`` without touching the limiter)."""
        scheduled = req.get("scheduled") in (True, "1", "true")
        candidate = req.get("candidate_sentinel")
        refresh_only = req.get("refresh_only") in (True, "1", "true")
        if refresh_only and candidate is not None:
            return _phase_err(
                "bad_request", "refresh_only never tries a candidate", "precheck"
            )
        if refresh_only:
            with self._site_lock(site):
                return self._do_login(site, scheduled=scheduled, refresh_only=True)
        if candidate is None:
            return self._login(site, scheduled=scheduled)
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
            return self._do_login(site, candidate=candidate.strip())

    # One early return per refusal, in the order they are checked.
    def _sentinel_absent(  # pylint: disable=too-many-return-statements
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
                got = probe(item, sentinel.strip())
            finally:
                lock.release()
        finally:
            self._probe_slot.release()
        return {"ok": True, **got}

    def _login(self, site: str, *, scheduled: bool = False) -> dict[str, Any]:
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
                result = self._do_login(site, scheduled=scheduled)
        finally:
            flight.result = result
            with self._guard:
                self._flights.pop(site, None)
            flight.done.set()
        return result

    # One return per protocol error code, in the order they are checked.
    def _do_login(  # pylint: disable=too-many-return-statements,too-many-branches
        self,
        site: str,
        *,
        scheduled: bool = False,
        candidate: str | None = None,
        refresh_only: bool = False,
    ) -> dict[str, Any]:
        """One login: item checks, then the runner. The limiter is consulted
        only when the runner asks for the secret (`_SecretGate`), so a validated
        profile reuse works in a cooldown and leaves the limiter untouched."""
        try:
            items = self._items()
            item = next((it for it in items if it.site == site), None)
            if item is None:  # added since the cache was filled?
                items = self._items(fresh=True)
                item = next((it for it in items if it.site == site), None)
        except VaultError as exc:
            return _phase_err("vault_error", str(exc), "vault")
        if item is None:
            return _phase_err(
                "unknown_site", f"{site!r} is not in agent-logins", "vault"
            )
        if item.refused:
            return _phase_err("refused", item.refused, "vault")
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
        except RecipeError as exc:
            outcome = _error_outcome(gate.attempt, exc)
            if candidate is not None and outcome == "ok":
                outcome = "candidate"
            sent = outcome != "not_submitted"
            phase = exc.phase or ("submit" if sent else "recipe")
            diag = getattr(self.runner, "last_diag", {}).pop(site, None)
            return {
                **_phase_err(exc.code, exc.detail, phase, submitted=sent),
                **({"diag": diag} if diag else {}),
            }
        except VaultError as exc:
            return _phase_err("vault_error", str(exc), "vault")
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
        }
        if candidate is not None:
            # absent logged out (checked first) + present here or after the login
            reply["candidate_verified"] = True
        return reply


def _error_outcome(attempt: AttemptController, exc: RecipeError) -> str:
    """The limiter outcome of a failed login (PLAN_ws1a "outcome mapping"):
    nothing typed -> not_submitted; proven auth after typing -> ok; the submit
    marker -> unknown; typed without the marker -> unknown unless the recipe
    proved the password still sat unsent in its field."""
    if not (attempt.submitted or attempt.was_entered):
        return "not_submitted"
    if exc.auth_proven:
        return "ok"
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


class _RefreshUnavailable(RecipeError):
    """A ``refresh_only`` request found no reusable profile (nothing reserved,
    no secret read)."""

    code = "refresh_unavailable"

    def __init__(self) -> None:
        super().__init__(
            "the broker profile is not reusable; a refresh-only request never logs in",
            phase="profile-proof",
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
        self.attempt = _LimiterAttempt(self)

    def __call__(self) -> Secret:
        if self.refresh_only:
            raise _RefreshUnavailable()
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
        return self.broker.vault.secret(self.item.site)

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
            "  sudo daemon.py -r group:galaxus    # reset an attempt group\n"
            "  sudo daemon.py -r galaxus -G       # reset a site and its groups\n"
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
        "totp:ITEM / secret:* (the secret limiter), and exit (exit 3 while a "
        "login is in flight on the key)",
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
    if key.startswith(("secret:", "totp:")):
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
