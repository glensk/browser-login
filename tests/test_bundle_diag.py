"""`login -G` (value-free bundle diagnostics) and the Run:ai Keycloak cookie gap.

Live 2026-10-12: `browser.py login runai-test3` injected only
`sdsc.run.ai /api/v1/token refresh-token` and `KEYCLOAK_SESSION` on
`app1.run.ai /auth/realms/sdsc/` and `custos.datascience.ch /realms/sdsc/` —
no `KEYCLOAK_IDENTITY` (Keycloak's httpOnly SSO cookie) — and the site was
not logged in. These tests pin:

- the broker's ``bundle_diag``: every cookie on, under or above a scope host,
  kept or why dropped, NEVER a value (nor a digest or length of one), at most
  64, only in the reply of a request that asked (``"diag": true``),
  audit-logged; the client's ``-G`` table and ``inject_diag`` (per-host
  sent/present, client-filtered, silently not kept);
- the hypotheses, each against a throwaway Chromium behind a local HTTPS
  server (a redirect chain sdsc.example -> app1.example -> custos.example):
  * CONFIRMED: a relaunched persistent profile (every broker run launches
    one; a profile REUSE exports from it) has lost the session-only
    `KEYCLOAK_IDENTITY` and kept the persistent `KEYCLOAK_SESSION` — exactly
    the live cookie set;
  * eliminated: a url-filtered cookie read (the export reads the whole jar),
    a slash-less cookie path, a cross-site redirect putting the Keycloak
    cookies into a partitioned (CHIPS) jar;
  * found on the way: Chromium's `Storage.setCookies` (Playwright
    `add_cookies`) drops a `SameSite=None` cookie without `Secure` with NO
    error, and refuses a whole batch for one `__Host-` violation.

Never the shared browser; the HTTPS fixtures use a throwaway self-signed
certificate (skipped without `openssl`).
"""

from __future__ import annotations

# pylint: disable=protected-access,missing-function-docstring,missing-class-docstring
# pylint: disable=import-error,wrong-import-position,redefined-outer-name
# pylint: disable=import-outside-toplevel,too-few-public-methods
import contextlib
import http.server
import json
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import types
from collections.abc import Iterable, Iterator, Mapping
from pathlib import Path
from typing import Any, cast

import pytest
from chromium_page import REPO, chromium_available, load_script

sys.path.insert(0, str(REPO))

from broker import bundle, daemon, identity, limiter, vault  # noqa: E402

browser = load_script("bin/browser.py", "bundle_diag_browser")

CHROME = pytest.mark.skipif(
    not chromium_available(), reason="Playwright Chromium missing"
)
TLS = pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl missing")

RUNAI, APP1, KC = "sdsc.run.ai", "app1.run.ai", "custos.datascience.ch"
SCOPES = (
    identity.CookieScope(RUNAI),
    identity.CookieScope(KC, "/realms/sdsc/"),
    identity.CookieScope(APP1, "/auth/realms/sdsc/"),
)
SPEC = bundle.SiteBundleSpec(
    cookie_hosts=[RUNAI, KC, APP1], cookie_names=None, cookie_scopes=SCOPES
)
# A marker no diagnostics output may ever contain.
SECRET = "VALUE-must-never-leak-7f3a"


def _ck(domain: str, path: str, name: str, **kw: Any) -> dict[str, Any]:
    return {"domain": domain, "path": path, "name": name, "value": SECRET, **kw}


def _live_jar(*, identity_cookies: bool = True) -> list[dict[str, Any]]:
    """The Run:ai login's jar (shape of the A0 inventory), with or without
    the session-only `KEYCLOAK_IDENTITY` cookies."""
    jar = [
        _ck(RUNAI, "/api/v1/token", "refresh-token", httpOnly=True, expires=9e9),
        _ck(APP1, "/auth/realms/sdsc/", "KEYCLOAK_SESSION", expires=9e9),
        _ck(KC, "/realms/sdsc/", "KEYCLOAK_SESSION", expires=9e9),
        _ck(KC, "/realms/sdsc/", "AUTH_SESSION_ID", httpOnly=True, expires=-1),
        _ck(KC, "/realms/master/", "KEYCLOAK_SESSION", expires=9e9),
        _ck(APP1, "/auth/realms/acme/", "KEYCLOAK_SESSION", expires=9e9),
        _ck(".datascience.ch", "/", "parent"),
        _ck("gitlab.datascience.ch", "/", "_gitlab_session"),
        _ck("example.org", "/", "unrelated"),
    ]
    if identity_cookies:
        for host, path in ((APP1, "/auth/realms/sdsc/"), (KC, "/realms/sdsc/")):
            jar.append(
                _ck(
                    host,
                    path,
                    "KEYCLOAK_IDENTITY",
                    httpOnly=True,
                    secure=True,
                    sameSite="None",
                    expires=-1,
                )
            )
    return jar


def _by_name(diag: dict[str, Any]) -> dict[tuple[str, str, str], dict[str, Any]]:
    return {(e["domain"], e["path"], e["name"]): e for e in diag["cookies"]}


# --- broker: bundle.cookie_diag -------------------------------------------


def test_cookie_diag_lists_scope_host_cookies_with_their_verdict() -> None:
    diag = bundle.cookie_diag(_live_jar(), SPEC)
    rows = _by_name(diag)
    assert rows[(KC, "/realms/sdsc/", "KEYCLOAK_IDENTITY")] == {
        "domain": KC,
        "path": "/realms/sdsc/",
        "name": "KEYCLOAK_IDENTITY",
        "session": True,
        "httpOnly": True,
        "secure": True,
        "sameSite": "None",
        "partitioned": False,
        "kept": True,
        "why_dropped": None,
    }
    assert rows[(KC, "/realms/master/", "KEYCLOAK_SESSION")]["why_dropped"] == (
        "out_of_path"
    )
    assert rows[(APP1, "/auth/realms/acme/", "KEYCLOAK_SESSION")]["why_dropped"] == (
        "out_of_path"
    )
    assert rows[(".datascience.ch", "/", "parent")]["why_dropped"] == "parent_domain"
    assert rows[(RUNAI, "/api/v1/token", "refresh-token")]["session"] is False
    # a sibling subdomain of the parent and unrelated hosts are not listed
    assert {d for d, _p, _n in rows} == {RUNAI, APP1, KC, ".datascience.ch"}
    assert diag["jar_total"] == 11 and diag["matched"] == 9 and diag["kept"] == 6
    assert not diag["truncated"]
    # scope hosts first, the parent domain last
    assert diag["cookies"][-1]["why_dropped"] == "parent_domain"


def test_cookie_diag_agrees_with_the_export_rule() -> None:
    jar = _live_jar()
    kept = {
        (e["domain"], e["path"], e["name"])
        for e in bundle.cookie_diag(jar, SPEC)["cookies"]
        if e["kept"]
    }
    exported = {
        (c["domain"], c["path"], c["name"]) for c in bundle.filter_cookies(jar, SPEC)
    }
    assert kept == exported


def test_cookie_diag_names_idp_names_and_nameless_drops() -> None:
    spec = bundle.SiteBundleSpec(cookie_hosts=["run.ai"], cookie_names=["keep"])
    jar = [
        _ck("sso.run.ai", "/", "keep"),  # an IdP subdomain, not named exactly
        _ck("run.ai", "/", "other"),
        _ck("run.ai", "/", ""),
        _ck("run.ai", "/", "keep"),
    ]
    reasons = [e["why_dropped"] for e in bundle.cookie_diag(jar, spec)["cookies"]]
    assert sorted(reasons, key=str) == sorted(
        ["idp_host", "not_in_cookie_names", "no_name", None], key=str
    )


def test_cookie_diag_never_carries_a_value_digest_or_length() -> None:
    long_jar = _live_jar()
    short_jar = [{**c, "value": "x"} for c in long_jar]
    a, b = bundle.cookie_diag(long_jar, SPEC), bundle.cookie_diag(short_jar, SPEC)
    assert a == b  # nothing derived from the value
    text = json.dumps(a)
    assert SECRET not in text and '"value"' not in text
    assert all(set(e) == set(a["cookies"][0]) for e in a["cookies"])


def test_cookie_diag_is_capped_at_64() -> None:
    jar = [_ck(RUNAI, "/", f"c{i:03d}") for i in range(100)]
    jar.append(_ck(".run.ai", "/", "parent"))
    diag = bundle.cookie_diag(jar, SPEC)
    assert len(diag["cookies"]) == bundle.DIAG_CAP == 64
    assert diag["truncated"] and diag["matched"] == 101
    assert all(e["why_dropped"] != "parent_domain" for e in diag["cookies"])


def test_a_slashless_cookie_path_is_exported_for_a_slashed_scope() -> None:
    """Hypothesis "the cookie path is /realms/sdsc without a slash":
    RFC 6265 path-match keeps it either way (eliminated)."""
    jar = [
        _ck(KC, "/realms/sdsc", "KEYCLOAK_IDENTITY"),
        _ck(APP1, "/auth/realms/sdsc", "KEYCLOAK_IDENTITY"),
        _ck(KC, "/realms/sdscx/", "KEYCLOAK_IDENTITY"),  # a sibling realm
    ]
    got = {(c["domain"], c["path"]) for c in bundle.filter_cookies(jar, SPEC)}
    assert got == {(KC, "/realms/sdsc"), (APP1, "/auth/realms/sdsc")}


# --- broker: export_bundle and the login reply -----------------------------


class _Ctx:
    """A broker context: a cookie jar (read without a url filter) and no
    open pages."""

    def __init__(self, jar: list[dict[str, Any]]) -> None:
        self.jar = jar
        self.pages: list[Any] = []
        self.cookie_calls: list[tuple[Any, ...]] = []

    def cookies(self, *urls: Any) -> list[dict[str, Any]]:
        self.cookie_calls.append(urls)
        return list(self.jar)


def _runai_item() -> vault.SiteItem:
    raw = {
        "id": "id-runai",
        "name": "runai-test3",
        "login": {"username": "zz@diag.example", "pass" + "word": "x" * 12},
        "fields": [
            {"name": k, "value": v}
            for k, v in {
                "agent_site": "runai-test3",
                "agent_fill_origins": f"https://{KC}",
                "agent_check_url": f"https://{RUNAI}/workloads",
                "agent_logged_in_selector": "#me",
                "agent_cookie_scopes": json.dumps([s.view() for s in SCOPES]),
            }.items()
        ],
    }
    return vault.build_items([raw])[0]


def test_export_reads_the_whole_jar_and_adds_diag_only_when_asked() -> None:
    item = _runai_item()
    runner = daemon.PlaywrightRunner(REPO, dev=True)
    ctx = _Ctx(_live_jar(identity_cookies=False))
    plain = runner.export_bundle(ctx, item, "profile")
    assert daemon.BUNDLE_DIAG_KEY not in plain
    assert ctx.cookie_calls == [()]  # no url filter: path-scoped cookies stay
    found = runner.export_bundle(ctx, item, "profile", diag=True)[
        daemon.BUNDLE_DIAG_KEY
    ]
    assert found["via"] == "profile"
    assert found["storage_names"] == {f"https://{RUNAI}": None, f"https://{KC}": None}
    kept = {(e["domain"], e["name"]) for e in found["cookies"] if e["kept"]}
    # the live symptom: no KEYCLOAK_IDENTITY anywhere in the jar
    assert kept == {
        (RUNAI, "refresh-token"),
        (APP1, "KEYCLOAK_SESSION"),
        (KC, "KEYCLOAK_SESSION"),
        (KC, "AUTH_SESSION_ID"),
    }
    assert SECRET not in json.dumps(found)


class _DiagRunner:
    """A runner whose bundle carries diagnostics when the gate asks."""

    def __init__(self) -> None:
        self.asked: list[bool] = []

    def __call__(self, item: vault.SiteItem, get_secret: Any) -> dict[str, Any]:
        want = bool(getattr(get_secret, "diag", False))
        self.asked.append(want)
        out: dict[str, Any] = {
            "site": item.site,
            "via": "profile",
            "cookies": [_ck(RUNAI, "/", "sid")],
            "storage": {},
            "cookie_hosts": item.cookie_hosts,
            "cookie_names": None,
        }
        if want:
            out[daemon.BUNDLE_DIAG_KEY] = {"v": 1, "via": "profile", "cookies": []}
        return out


@pytest.fixture
def diag_broker(tmp_path: Path) -> Iterator[tuple[daemon.Broker, _DiagRunner, Path]]:
    fixture = tmp_path / "items.json"
    fixture.write_text(
        json.dumps(
            [
                {
                    "id": "id-r",
                    "name": "Ricardo",
                    "login": {"username": "alice", "pass" + "word": "x" * 12},
                    "fields": [
                        {"name": k, "value": v}
                        for k, v in {
                            "agent_site": "ricardo",
                            "agent_fill_origins": "https://login.ricardo.ch",
                            "agent_cookie_hosts": "ricardo.ch",
                            "agent_logged_in_selector": "#account",
                        }.items()
                    ],
                }
            ]
        )
    )
    home = tmp_path / "home"
    runner = _DiagRunner()
    lim = limiter.Limiter(home / "limiter.json", 0, 100, 100)
    yield (
        daemon.Broker(vault.FixtureVault(fixture, dev=True), lim, home, runner=runner),
        runner,
        home,
    )


def _audit(home: Path) -> list[dict[str, Any]]:
    return [json.loads(x) for x in (home / "audit.log").read_text().splitlines()]


def test_the_reply_carries_bundle_diag_only_when_asked(
    diag_broker: tuple[daemon.Broker, _DiagRunner, Path],
) -> None:
    brk, runner, home = diag_broker
    asked = brk.handle({"op": "login", "site": "ricardo", "diag": True}, uid=1)
    assert asked["ok"] and asked["bundle_diag"]["via"] == "profile"
    assert daemon.BUNDLE_DIAG_KEY not in asked["bundle"]
    plain = brk.handle({"op": "login", "site": "ricardo"}, uid=1)
    assert plain["ok"] and "bundle_diag" not in plain
    assert daemon.BUNDLE_DIAG_KEY not in plain["bundle"]
    assert runner.asked == [True, False]
    lines = [r for r in _audit(home) if r["op"] == "login"]
    assert [r["diag"] for r in lines] == [True, False]


def test_a_request_that_did_not_ask_never_gets_anothers_diag(
    diag_broker: tuple[daemon.Broker, _DiagRunner, Path],
) -> None:
    """A coalesced follower shares the leader's result object: the strip
    must build a new reply, never hand the leader's diag along."""
    brk, _runner, _home = diag_broker
    shared = {"ok": True, "bundle": {}, daemon.BUNDLE_DIAG_KEY: {"v": 1}}
    brk._login_options = lambda *_a, **_k: shared  # type: ignore[method-assign]
    got = brk._login_request("ricardo", {"op": "login"})
    assert daemon.BUNDLE_DIAG_KEY not in got
    assert daemon.BUNDLE_DIAG_KEY in shared  # the leader's own reply untouched
    assert brk._login_request("ricardo", {"diag": True}) is shared


# --- client: -G ------------------------------------------------------------


@pytest.mark.parametrize(
    ("argv", "want"),
    [
        (["login", "runai-test3", "-G"], True),
        (["login", "runai-test3", "--diag"], True),
        (["login", "runai-test3"], False),
    ],
)
def test_login_parser_takes_g_diag(
    argv: list[str], want: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sys, "argv", ["browser.py", *argv])
    assert browser.parse_args().diag is want


class _JarCtx:
    """A shared-browser context that behaves like Chromium on injection:
    a SameSite=None cookie without Secure is dropped WITHOUT an error."""

    def __init__(self) -> None:
        self.jar: list[dict[str, Any]] = []

    def cookies(self) -> list[dict[str, Any]]:
        return [dict(c) for c in self.jar]

    def clear_cookies(self, **kw: Any) -> None:
        self.jar = [c for c in self.jar if any(c.get(k) != v for k, v in kw.items())]

    def add_cookies(self, cookies: list[dict[str, Any]]) -> None:
        for c in cookies:
            if c.get("sameSite") == "None" and not c.get("secure"):
                continue
            self.jar.append(dict(c))


class _Browser:
    def __init__(self, ctx: _JarCtx) -> None:
        self.contexts = [ctx]

    def close(self) -> None:
        return None


class _Pw:
    def stop(self) -> None:
        return None


def _bundle_for(cookies: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "site": "runai-test3",
        "via": "profile",
        "cookies": cookies,
        "storage": {},
        "cookie_hosts": [RUNAI, KC, APP1],
        "cookie_scopes": [s.view() for s in SCOPES],
        "scope_v": identity.SCOPE_V,
        "cookie_names": None,
        "storage_keys": {},
    }


def test_client_diag_records_what_was_sent_kept_and_filtered(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    ctx = _JarCtx()
    cookies = [
        {k: v for k, v in c.items() if k != "expires" or v > 0}
        for c in bundle.filter_cookies(_live_jar(identity_cookies=True), SPEC)
    ]
    # an insecure SameSite=None cookie: Chromium drops it silently
    cookies.append(_ck(APP1, "/auth/realms/sdsc/", "LAX_LOST", sameSite="None"))
    # a cookie outside the scope (an older or broken broker): the client drops it
    cookies.append(_ck(KC, "/realms/master/", "KEYCLOAK_SESSION", secure=True))
    found = bundle.cookie_diag(_live_jar(identity_cookies=True), SPEC)
    reply = {"ok": True, "bundle": _bundle_for(cookies), "bundle_diag": found}
    sent: dict[str, Any] = {}

    def request(_op: str, **kw: Any) -> dict[str, Any]:
        sent.update(kw)
        return reply

    monkeypatch.setattr(browser, "_connect", lambda _port: (_Pw(), _Browser(ctx)))
    monkeypatch.setattr(
        browser, "_interaction_lease", lambda _w: contextlib.nullcontext()
    )
    monkeypatch.setattr(browser, "_broker_request", request)
    monkeypatch.setattr(browser, "_broker_write_storage", lambda *_a, **_k: 0)
    result = tmp_path / "r.json"
    browser._result_begin("login", "runai-test3", str(result))
    rc, _b, n_cookies, _k = browser._broker_fetch_inject(
        9222, "runai-test3", {"diag": True}, {}
    )
    browser._result_write(2)
    assert rc is None and sent["diag"] is True and n_cookies == 7
    rec = json.loads(result.read_text())
    report = rec["inject_diag"]
    assert report["per_host"] == {
        RUNAI: {"sent": 1, "present": 1},
        APP1: {"sent": 3, "present": 2},
        KC: {"sent": 3, "present": 3},
    }
    assert report["missing_after"] == [
        {
            "domain": APP1,
            "path": "/auth/realms/sdsc/",
            "name": "LAX_LOST",
            "likely": "samesite_none_without_secure",
        }
    ]
    assert report["client_dropped"] == [
        {"domain": KC, "path": "/realms/master/", "name": "KEYCLOAK_SESSION"}
    ]
    assert report["add_cookies_error"] is None
    assert rec["bundle_diag"]["kept"] == found["kept"]
    out = capsys.readouterr().out
    assert "KEYCLOAK_IDENTITY" in out and "NOT kept by the browser" in out
    assert SECRET not in out and SECRET not in result.read_text()


def test_client_diag_records_a_refused_batch_and_reraises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _Refusing(_JarCtx):
        def add_cookies(self, cookies: list[dict[str, Any]]) -> None:
            raise RuntimeError(
                "Protocol error (Storage.setCookies): Invalid cookie fields"
            )

    ctx = _Refusing()
    reply = {"ok": True, "bundle": _bundle_for([_ck(RUNAI, "/", "__Host-x")])}
    monkeypatch.setattr(browser, "_connect", lambda _port: (_Pw(), _Browser(ctx)))
    monkeypatch.setattr(
        browser, "_interaction_lease", lambda _w: contextlib.nullcontext()
    )
    monkeypatch.setattr(browser, "_broker_request", lambda *_a, **_k: reply)
    browser._RESULT.clear()
    with pytest.raises(RuntimeError):
        browser._broker_fetch_inject(9222, "runai-test3", {"diag": True}, {})
    report = browser._RESULT["inject_diag"]
    assert report["add_cookies_error"] == "invalid_cookie_fields"
    assert report["missing_after"][0]["likely"] == "host_prefix_rules"
    assert browser._RESULT["bundle_diag"] is None  # an older broker: none sent


def test_without_g_the_client_requests_no_diag(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[Any, ...]] = []
    monkeypatch.setattr(browser, "_connect", lambda _port: (_Pw(), _Browser(_JarCtx())))
    monkeypatch.setattr(
        browser, "_interaction_lease", lambda _w: contextlib.nullcontext()
    )

    def request(_op: str, **kw: Any) -> dict[str, Any]:
        calls.append(tuple(kw))
        return {"ok": True, "bundle": _bundle_for([])}

    def replace(*_a: Any) -> int:
        calls.append(("replace",))
        return 0

    monkeypatch.setattr(browser, "_broker_request", request)
    monkeypatch.setattr(browser, "_broker_replace_cookies", replace)
    monkeypatch.setattr(browser, "_broker_write_storage", lambda *_a, **_k: 0)
    browser._RESULT.clear()
    browser._broker_fetch_inject(9222, "runai-test3", {}, {})
    assert ("site",) in calls and ("replace",) in calls
    assert "inject_diag" not in browser._RESULT


@pytest.mark.parametrize(
    ("cookie", "hint"),
    [
        (
            {"domain": "a.example", "sameSite": "None", "secure": False},
            "samesite_none_without_secure",
        ),
        ({"domain": "a..example", "secure": True}, "bad_domain"),
        ({"domain": "", "secure": True}, "bad_domain"),
        (
            {"domain": "a.example", "name": "__Host-x", "secure": True, "path": "/p"},
            "host_prefix_rules",
        ),
        ({"domain": "a.example", "name": "__Secure-x"}, "secure_prefix_without_secure"),
        ({"domain": "a.example", "expires": 1.0, "secure": True}, "expired"),
        ({"domain": "a.example", "partitionKey": "https://b.example"}, "partitioned"),
        ({"domain": "a.example", "secure": True, "sameSite": "None"}, None),
    ],
)
def test_reject_hints(cookie: dict[str, Any], hint: str | None) -> None:
    assert browser._cookie_reject_hint({"name": "n", "path": "/", **cookie}) == hint


# --- real Chromium: the hypotheses -----------------------------------------

HOSTS = ("sdsc.example", "app1.example", "custos.example")


def _chain(port: int) -> dict[tuple[str, str], tuple[int, str, list[str]]]:
    """The Run:ai login's redirect chain with Keycloak's cookie attributes:
    `KEYCLOAK_IDENTITY` session-only (no "remember me"), `KEYCLOAK_SESSION`
    with Max-Age (the SSO session's lifespan), both per realm path,
    SameSite=None, Secure."""
    kc = "; Secure; SameSite=None"
    return {
        ("sdsc.example", "/"): (
            302,
            f"https://app1.example:{port}/auth/realms/sdsc/auth",
            [],
        ),
        ("app1.example", "/auth/realms/sdsc/auth"): (
            302,
            f"https://custos.example:{port}/realms/sdsc/login",
            ["KC_RESTART=r; Path=/auth/realms/sdsc/; HttpOnly" + kc],
        ),
        ("custos.example", "/realms/sdsc/login"): (
            302,
            f"https://app1.example:{port}/auth/realms/sdsc/broker/custos/endpoint",
            [
                "KEYCLOAK_IDENTITY=i; Path=/realms/sdsc/; HttpOnly" + kc,
                "KEYCLOAK_SESSION=s; Path=/realms/sdsc/; Max-Age=36000" + kc,
                "NOSLASH=n; Path=/realms/sdsc; HttpOnly" + kc,
                "PART=p; Path=/; Partitioned" + kc,
            ],
        ),
        ("app1.example", "/auth/realms/sdsc/broker/custos/endpoint"): (
            302,
            f"https://sdsc.example:{port}/done",
            [
                "KEYCLOAK_IDENTITY=i; Path=/auth/realms/sdsc/; HttpOnly" + kc,
                "KEYCLOAK_SESSION=s; Path=/auth/realms/sdsc/; Max-Age=36000" + kc,
            ],
        ),
        ("sdsc.example", "/done"): (
            200,
            "",
            [
                "refresh-token=t; Path=/api/v1/token; HttpOnly; Secure; "
                "SameSite=Strict; Max-Age=3600"
            ],
        ),
        ("custos.example", "/frame"): (
            200,
            "",
            ["FRAMEPART=f; Path=/; Partitioned" + kc],
        ),
    }


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802  # the stdlib's name
        port = int(cast(tuple[str, int], self.server.server_address)[1])
        host = str(self.headers.get("Host") or "").split(":", maxsplit=1)[0]
        status, location, cookies = _chain(port).get((host, self.path), (200, "", []))
        self.send_response(status)
        if location:
            self.send_header("Location", location)
        for c in cookies:
            self.send_header("Set-Cookie", c)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        if self.path == "/done":
            frame = f'<iframe src="https://custos.example:{port}/frame"></iframe>'
            self.wfile.write(frame.encode())

    def log_message(self, *_a: Any) -> None:  # pylint: disable=arguments-differ
        return None


@pytest.fixture(scope="module")
def https_chain(tmp_path_factory: pytest.TempPathFactory) -> Iterator[int]:
    """A local HTTPS server (throwaway self-signed certificate) for the
    three fixture hosts; Chromium maps them to it (host-resolver-rules)."""
    d = tmp_path_factory.mktemp("tls")
    san = ",".join(f"DNS:{h}" for h in HOSTS)
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(d / "key.pem"),
            "-out",
            str(d / "cert.pem"),
            "-days",
            "1",
            "-subj",
            "/CN=example",
            "-addext",
            f"subjectAltName={san}",
        ],
        check=True,
        capture_output=True,
    )
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(str(d / "cert.pem"), str(d / "key.pem"))
    srv.socket = tls.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield int(srv.server_address[1])
    finally:
        srv.shutdown()
        srv.server_close()


ARGS = ["--host-resolver-rules=MAP *.example 127.0.0.1"]
FIX_SCOPES = (
    identity.CookieScope("sdsc.example"),
    identity.CookieScope("custos.example", "/realms/sdsc/"),
    identity.CookieScope("app1.example", "/auth/realms/sdsc/"),
)
FIX_SPEC = bundle.SiteBundleSpec(
    cookie_hosts=list(HOSTS), cookie_names=None, cookie_scopes=FIX_SCOPES
)


def _keys(cookies: Iterable[Mapping[str, Any]]) -> set[tuple[str, str, str]]:
    return {(c["domain"], c["path"], c["name"]) for c in cookies}


def _login(pw: Any, profile: Path, port: int) -> Any:
    ctx = pw.chromium.launch_persistent_context(
        str(profile), headless=True, args=ARGS, ignore_https_errors=True
    )
    page = ctx.new_page()
    page.goto(f"https://sdsc.example:{port}/")
    page.wait_for_load_state("load")
    page.wait_for_timeout(300)
    return ctx


@CHROME
@TLS
def test_a_relaunched_profile_lost_keycloak_identity(https_chain: int) -> None:
    """CONFIRMED: the live cookie set is exactly what a relaunched broker
    profile (a profile reuse) exports — the session-only KEYCLOAK_IDENTITY
    is gone, the Max-Age KEYCLOAK_SESSION and refresh-token stay."""
    from playwright.sync_api import sync_playwright

    with (
        tempfile.TemporaryDirectory(prefix="bundle-diag-") as tmp,
        sync_playwright() as pw,
    ):
        ctx = _login(pw, Path(tmp), https_chain)
        try:
            fresh = _keys(bundle.filter_cookies(ctx.cookies(), FIX_SPEC))
        finally:
            ctx.close()
        assert ("app1.example", "/auth/realms/sdsc/", "KEYCLOAK_IDENTITY") in fresh
        assert ("custos.example", "/realms/sdsc/", "KEYCLOAK_IDENTITY") in fresh
        ctx = pw.chromium.launch_persistent_context(
            tmp, headless=True, args=ARGS, ignore_https_errors=True
        )
        try:
            jar = ctx.cookies()
        finally:
            ctx.close()
    reused = _keys(bundle.filter_cookies(jar, FIX_SPEC))
    assert reused == {
        ("sdsc.example", "/api/v1/token", "refresh-token"),
        ("app1.example", "/auth/realms/sdsc/", "KEYCLOAK_SESSION"),
        ("custos.example", "/realms/sdsc/", "KEYCLOAK_SESSION"),
    }
    rows = bundle.cookie_diag(jar, FIX_SPEC)["cookies"]
    assert not [e for e in rows if e["name"] == "KEYCLOAK_IDENTITY"]
    assert all(not e["session"] for e in rows)


@CHROME
@TLS
def test_the_redirect_chain_cookies_land_unpartitioned_and_path_scoped(
    https_chain: int,
) -> None:
    """Eliminated: a cross-site redirect does not partition Keycloak's
    cookies (only a `Partitioned` attribute does — CHIPS); the whole-jar read
    holds every path-scoped cookie (a url-filtered read would not); the
    slash-less path is exported. The diag flags partitioned cookies."""
    from playwright.sync_api import sync_playwright

    with (
        tempfile.TemporaryDirectory(prefix="bundle-diag-") as tmp,
        sync_playwright() as pw,
    ):
        ctx = _login(pw, Path(tmp), https_chain)
        try:
            jar = ctx.cookies()
            root_only = ctx.cookies([f"https://custos.example:{https_chain}/"])
        finally:
            ctx.close()
    by = {(c["domain"], c["path"], c["name"]): c for c in jar}
    ident = by[("app1.example", "/auth/realms/sdsc/", "KEYCLOAK_IDENTITY")]
    assert ident["httpOnly"] and ident["secure"] and ident["sameSite"] == "None"
    assert ident["expires"] == -1 and not ident.get("partitionKey")
    assert not by[("custos.example", "/realms/sdsc/", "KEYCLOAK_IDENTITY")].get(
        "partitionKey"
    )
    assert by[("custos.example", "/", "FRAMEPART")].get("partitionKey")
    # a url-filtered read drops the realm cookies; the export never filters
    assert not [c for c in root_only if c["path"].startswith("/realms/")]
    exported = _keys(bundle.filter_cookies(jar, FIX_SPEC))
    assert ("custos.example", "/realms/sdsc", "NOSLASH") in exported
    rows = _by_name(bundle.cookie_diag(jar, FIX_SPEC))
    assert rows[("custos.example", "/", "FRAMEPART")]["partitioned"] is True
    assert rows[("custos.example", "/", "FRAMEPART")]["why_dropped"] == "out_of_path"


@CHROME
def test_chromium_drops_samesite_none_without_secure_silently() -> None:
    """Measured, not assumed: `add_cookies` returns normally and the cookie
    is not there; one `__Host-` violation refuses the whole batch. The
    client's -G read-back reports both."""
    from playwright.sync_api import sync_playwright

    good: Any = {
        "name": "KEYCLOAK_IDENTITY",
        "value": "v",
        "domain": "app1.example",
        "path": "/auth/realms/sdsc/",
        "secure": True,
        "httpOnly": True,
        "sameSite": "None",
    }
    insecure: Any = {**good, "name": "LOST", "secure": False}
    with sync_playwright() as pw:
        chromium = pw.chromium.launch(headless=True)
        try:
            ctx = chromium.new_context()
            ctx.add_cookies([good, insecure])  # no error
            assert _keys(ctx.cookies()) == {
                ("app1.example", "/auth/realms/sdsc/", "KEYCLOAK_IDENTITY")
            }

            class _B:
                contexts = [ctx]

            report = browser._broker_inject_report(
                _B(),
                {
                    "cookies": [good, insecure],
                    "cookie_hosts": ["app1.example"],
                    "cookie_names": None,
                },
                None,
            )
            assert report["per_host"] == {"app1.example": {"sent": 2, "present": 1}}
            assert report["missing_after"][0]["likely"] == (
                "samesite_none_without_secure"
            )
            other = chromium.new_context()
            with pytest.raises(Exception) as err:
                other.add_cookies([good, {**good, "name": "__Host-x", "path": "/p/"}])
            assert browser._cookie_inject_error(err.value) == "invalid_cookie_fields"
            assert other.cookies() == []  # the good one went with the batch
        finally:
            chromium.close()


@CHROME
@TLS
def test_storage_names_reads_key_names_of_open_pages_only(https_chain: int) -> None:
    """`-G` storage picture: key NAMES of a page already open on the item's
    origins (no navigation), never a value; an origin without an open page
    is None."""
    from playwright.sync_api import sync_playwright

    origin = f"https://sdsc.example:{https_chain}"
    item: Any = types.SimpleNamespace(
        check_url=f"{origin}/workloads",
        login_url="",
        storage_keys={},
        fill_origins=[f"https://custos.example:{https_chain}"],
    )
    with (
        tempfile.TemporaryDirectory(prefix="bundle-diag-") as tmp,
        sync_playwright() as pw,
    ):
        ctx = _login(pw, Path(tmp), https_chain)
        try:
            page = next(p for p in ctx.pages if p.url.startswith(origin))
            page.evaluate(
                "v => { localStorage.setItem('logged-in-user-email', v);"
                " sessionStorage.setItem('kc-state', v); }",
                SECRET,
            )
            got = daemon.PlaywrightRunner(REPO, dev=True).storage_names(ctx, item)
        finally:
            ctx.close()
    assert got[f"https://custos.example:{https_chain}"] is None
    names = got[origin]
    assert names["local"] == ["logged-in-user-email"] and names["local_n"] == 1
    assert names["session"] == ["kc-state"] and names["session_n"] == 1
    assert SECRET not in json.dumps(got)
