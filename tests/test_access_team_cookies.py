"""tp#1466: no Cloudflare Access TEAM-domain cookie ever stays in the shared browser.

A broker login of an Access-protected home service must leave only the app's
own cookies (``calibre.example`` …); the team session on
``<team>.cloudflareaccess.com`` (CF_Authorization, CF_Session, CF_Device) would
let Access open every app of the team — decide included. Hermetic: fake cookie
jars, a fake CDP reply; no browser, no broker.

Run: uv run --no-sync pytest tests/test_access_team_cookies.py
"""

from __future__ import annotations

# pylint: disable=protected-access,missing-function-docstring,import-error
# pylint: disable=wrong-import-position,too-few-public-methods
import contextlib
import importlib.util
import json
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from broker import access_team, bundle  # noqa: E402
from broker import safari_cookies as safari  # noqa: E402

TEAM = "team.cloudflareaccess.com"
APP = "calibre.example"
COOKIE_VALUE = "VALUE-MUST-NOT-PRINT"


def _load_browser() -> Any:
    path = REPO / "bin" / "browser.py"
    spec = importlib.util.spec_from_file_location("browser_access_team_test", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["browser_access_team_test"] = mod
    spec.loader.exec_module(mod)
    return mod


browser = _load_browser()


def _ck(domain: str, name: str, value: str = COOKIE_VALUE) -> dict[str, Any]:
    return {"domain": domain, "name": name, "value": value, "path": "/"}


TEAM_COOKIES = [_ck(TEAM, n) for n in ("CF_Authorization", "CF_Session", "CF_Device")]
APP_COOKIE = _ck(APP, "CF_Authorization")


def _identity(c: dict[str, Any]) -> tuple[str, str, str, str]:
    """Chromium's cookie identity: name, stored domain (``.x`` = domain
    cookie, ``x`` = host-only), path, partition key."""
    return (
        str(c.get("name")),
        str(c.get("domain")),
        str(c.get("path") or "/"),
        json.dumps(c.get("partitionKey"), sort_keys=True),
    )


def _set_cookies(jar: list[dict[str, Any]], entries: list[dict[str, Any]]) -> None:
    """``Storage.setCookies`` as Chromium applies it: ``url`` without
    ``domain`` → host-only; a ``domain`` is ALWAYS stored as ``.domain``; an
    expired entry deletes the cookie with the same identity (and only it)."""
    for e in entries:
        stored = dict(e)
        if "domain" in e:
            stored["domain"] = "." + str(e["domain"]).lstrip(".")
        else:
            stored["domain"] = str(e["url"]).split("/")[2]
        stored.pop("url", None)
        key = _identity(stored)
        jar[:] = [c for c in jar if _identity(c) != key]
        if stored.get("expires") != 1:
            jar.append(stored)


class _Session:
    """A browser-level CDP session on a `_Jar`."""

    def __init__(self, owner: _Jar) -> None:
        self.owner = owner

    def send(self, method: str, params: Any = None) -> dict[str, Any]:
        if method == "Storage.getCookies":
            return self.owner.read()
        assert method == "Storage.setCookies"
        self.owner.sent += params["cookies"]
        if self.owner.deletes:
            _set_cookies(self.owner.jar, params["cookies"])
        return {}

    def detach(self) -> None:
        self.owner.detached += 1


class _Jar:
    """Playwright's cookie API on a list, plus `ctx.browser`'s CDP session."""

    def __init__(self, cookies: list[dict[str, Any]], *, deletes: bool = True) -> None:
        self.jar = [dict(c) for c in cookies]
        self.added: list[str] = []
        self.sent: list[dict[str, Any]] = []
        self.deletes = deletes
        self.detached = 0

    @property
    def browser(self) -> _Jar:
        return self

    @property
    def contexts(self) -> list[_Jar]:
        """As a Playwright Browser: the jar is its own default context."""
        return [self]

    def new_browser_cdp_session(self) -> _Session:
        return _Session(self)

    def read(self) -> dict[str, Any]:
        return {"cookies": [dict(c) for c in self.jar]}

    def cookies(self) -> list[dict[str, Any]]:
        return [dict(c) for c in self.jar]

    def clear_cookies(self, *, name: Any = None, domain: Any = None, path: Any = None):
        self.jar = [
            c
            for c in self.jar
            if not (c["name"] == name and c["domain"] == domain and c["path"] == path)
        ]

    def add_cookies(self, cookies: list[dict[str, Any]]) -> None:
        self.added += [f"{c['domain']} {c['name']}" for c in cookies]
        self.jar += [dict(c) for c in cookies]


class _Browser:
    """A Playwright Browser whose default context is `ctx` (none: no context)."""

    def __init__(self, ctx: _Jar | None) -> None:
        self.contexts = [ctx] if ctx is not None else []
        self.sessions = 0
        self.sent: list[str] = []

    def new_browser_cdp_session(self) -> Any:
        self.sessions += 1
        if self.contexts:
            return _Session(self.contexts[0])
        browser_self = self

        class _Recording:
            def send(self, method: str, _params: Any = None) -> dict[str, Any]:
                browser_self.sent.append(method)
                return {"cookies": []}

            def detach(self) -> None:
                return None

        return _Recording()

    def new_context(self) -> Any:
        raise AssertionError("an isolated context is never the shared jar")


@pytest.fixture(autouse=True)
def _no_edge(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """No configured team domain unless a test sets one (the suffix rule alone)."""
    monkeypatch.delenv(access_team.TEAM_DOMAIN_ENV, raising=False)
    monkeypatch.setenv(access_team.EDGE_FILE_ENV, str(tmp_path / "missing.json"))


@pytest.mark.parametrize(
    ("domain", "team"),
    [
        ("team.cloudflareaccess.com", True),
        (".team.cloudflareaccess.com", True),
        ("cloudflareaccess.com", True),
        (".cloudflareaccess.com", True),
        ("calibre.example", False),
        ("evilcloudflareaccess.com", False),
        ("team.cloudflareaccess.com.evil.example", False),
        ("", False),
    ],
)
def test_team_host_rule(domain: str, team: bool) -> None:
    assert access_team.is_team_host(domain) is team


def test_configured_team_domain_from_the_edge_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    edge = tmp_path / "edge.json"
    edge.write_text(json.dumps({"team_domain": "myteam.cloudflareaccess.com"}))
    monkeypatch.setenv(access_team.EDGE_FILE_ENV, str(edge))
    team, src = access_team.configured_team_domain()
    assert team == "myteam.cloudflareaccess.com" and src == str(edge)
    monkeypatch.setenv(access_team.TEAM_DOMAIN_ENV, "Other.CloudflareAccess.COM")
    assert access_team.configured_team_domain()[0] == "other.cloudflareaccess.com"


@pytest.mark.parametrize(
    "value",
    [
        "dom42.space",
        "access.example.org",
        "cloudflareaccess.com",
        "evilcloudflareaccess.com",
    ],
)
def test_team_domain_outside_cloudflareaccess_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    value: str,
) -> None:
    """A team domain is always ``<team>.cloudflareaccess.com``: anything else
    (``dom42.space`` would match every app cookie) is refused from the env
    and from the edge file, with the reason in doctor; app cookies stay."""
    monkeypatch.setenv(access_team.TEAM_DOMAIN_ENV, value)
    team, why = access_team.configured_team_domain()
    assert team is None and "not a subdomain of cloudflareaccess.com" in why
    assert access_team.TEAM_DOMAIN_ENV in why
    assert not access_team.is_team_host("calibre.dom42.space")
    assert not access_team.is_team_host(".access.example.org")
    monkeypatch.delenv(access_team.TEAM_DOMAIN_ENV)
    edge = tmp_path / "edge.json"
    edge.write_text(json.dumps({"team_domain": value}))
    monkeypatch.setenv(access_team.EDGE_FILE_ENV, str(edge))
    team, why = access_team.configured_team_domain()
    assert team is None and "not a subdomain" in why and str(edge) in why
    app = _ck("calibre.dom42.space", "CF_Authorization")
    monkeypatch.setattr(browser, "_browser_ws_url", lambda _port: "ws://fake")
    monkeypatch.setattr(browser, "_cdp_ws_call", lambda *_a, **_k: _Res([app]))
    log: list[str] = []
    browser._doctor_access_team(log, 9)
    out = capsys.readouterr().out
    assert log == ["ok"] and "not a subdomain of cloudflareaccess.com" in out


def test_missing_config_still_refuses_team_cookies() -> None:
    """Fail safe: without a configured team domain every cookie under
    cloudflareaccess.com is still refused — export, injection and Safari."""
    team, why = access_team.configured_team_domain()
    assert team is None and "missing" in why
    spec = bundle.SiteBundleSpec([TEAM, APP])  # even a site that names it
    assert bundle.cookie_drop_reason(TEAM, "CF_Authorization", spec) == "access_team"
    assert not browser._broker_cookie_in_scope(TEAM, "CF_Session", [TEAM], None)


def test_bundle_export_drops_team_cookies_at_source() -> None:
    spec = bundle.SiteBundleSpec([APP, TEAM])
    kept = bundle.filter_cookies([*TEAM_COOKIES, APP_COOKIE], spec)
    assert [(c["domain"], c["name"]) for c in kept] == [(APP, "CF_Authorization")]
    diag = bundle.cookie_diag([*TEAM_COOKIES, APP_COOKIE], spec)
    dropped = {e["why_dropped"] for e in diag["cookies"] if not e["kept"]}
    assert dropped == {"access_team"}
    assert COOKIE_VALUE not in json.dumps(diag)


def test_injection_keeps_only_app_cookies_and_sweeps_the_jar(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A bundle carrying team + app cookies (a broker that let them through)
    injects only the app cookie, and a team cookie already in the shared jar
    is removed after the injection."""
    ctx = _Jar([_ck(TEAM, "CF_Device", "old"), _ck("other.example", "keep")])
    fake_bundle = {
        "cookie_hosts": [APP, TEAM],
        "cookie_names": None,
        "cookies": [*TEAM_COOKIES, APP_COOKIE],
    }
    assert browser._broker_replace_cookies(_Browser(ctx), fake_bundle) == 1
    assert ctx.added == [f"{APP} CF_Authorization"]
    assert sorted((c["domain"], c["name"]) for c in ctx.jar) == [
        (APP, "CF_Authorization"),
        ("other.example", "keep"),
    ]
    out = capsys.readouterr()
    assert "Dropped 1 Cloudflare Access team cookie" in out.err
    assert COOKIE_VALUE not in out.out + out.err and "old" not in out.err


def test_post_login_sweep_removes_team_cookies(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    ctx = _Jar([*TEAM_COOKIES, APP_COOKIE])
    closed: list[str] = []

    class _Pw:
        def stop(self) -> None:
            closed.append("pw")

    class _B(_Browser):
        def close(self) -> None:
            closed.append("browser")

    monkeypatch.setattr(browser, "_is_up", lambda _port: True)
    monkeypatch.setattr(browser, "_connect", lambda _port: (_Pw(), _B(ctx)))
    sweep = browser._access_team_sweep(9, "login stirling")
    assert sweep.status == "ok" and not sweep.left
    assert sorted(sweep.dropped) == sorted(f"{TEAM} {c['name']}" for c in TEAM_COOKIES)
    assert [(c["domain"], c["name"]) for c in ctx.jar] == [(APP, "CF_Authorization")]
    assert closed == ["browser", "pw"]
    assert browser._JOURNAL_NOTES.get("access_team_sweep") == "login stirling"
    assert COOKIE_VALUE not in capsys.readouterr().err


def test_every_background_page_sweeps_before_it_closes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A logged-in check (or any client tab) that passed Access in the shared
    browser leaves no team session behind; the app cookie stays."""
    ctx = _Jar([APP_COOKIE])

    class _Page:
        context = ctx

    @contextlib.contextmanager
    def _owned(_port: int, *, prepare: Any = None) -> Iterator[_Page]:
        assert prepare is None
        yield _Page()

    def _check(_page: Any) -> str:
        ctx.jar += [dict(c) for c in TEAM_COOKIES]  # Access signed the tab in
        return "valid"

    monkeypatch.setattr(browser, "_owned_background_page", _owned)
    assert browser._background_page_run(9, "about:blank", None, _check) == "valid"
    assert [(c["domain"], c["name"]) for c in ctx.jar] == [(APP, "CF_Authorization")]


def test_sweep_skips_a_browser_that_is_down(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(browser, "_is_up", lambda _port: False)
    monkeypatch.setattr(
        browser, "_connect", lambda _port: pytest.fail("no attach when down")
    )
    assert browser._access_team_sweep(9, "login x").status == "down"


def test_safari_import_never_copies_team_cookies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    site = next(iter(safari.SAFARI_SITES))
    monkeypatch.setattr(safari, "in_site", lambda _d, _s: True)
    assert not safari.importable(TEAM, "CF_Authorization", site)
    assert safari.importable(APP, "sessionid", site)


class _Res:
    def __init__(self, cookies: list[dict[str, Any]]) -> None:
        self.status, self.error = "ok", None
        self.result = {"cookies": cookies}


def test_doctor_reports_team_cookies_by_name_only(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(browser, "_browser_ws_url", lambda _port: "ws://fake")
    monkeypatch.setattr(
        browser, "_cdp_ws_call", lambda *_a, **_k: _Res([*TEAM_COOKIES, APP_COOKIE])
    )
    log: list[str] = []
    browser._doctor_access_team(log, 9)
    out = capsys.readouterr().out
    assert log == ["fail"]
    assert f"{TEAM} CF_Authorization" in out and f"{TEAM} CF_Session" in out
    assert APP not in out.split("present:", 1)[1].split("—", 1)[0]
    assert COOKIE_VALUE not in out


def test_doctor_ok_without_team_cookies(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(browser, "_browser_ws_url", lambda _port: "ws://fake")
    monkeypatch.setattr(browser, "_cdp_ws_call", lambda *_a, **_k: _Res([APP_COOKIE]))
    log: list[str] = []
    browser._doctor_access_team(log, 9)
    assert log == ["ok"]
    assert "not configured" in capsys.readouterr().out


# --- the review fixes: sweep on every exit, a failed sweep is no success ---


@pytest.mark.parametrize("value", ["com", ".COM ", "localhost"])
def test_dotless_team_domain_from_the_env_is_rejected(
    monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    """``com`` would match every .com cookie: refused like the edge file's
    value, with the reason; the suffix rule still applies."""
    monkeypatch.setenv(access_team.TEAM_DOMAIN_ENV, value)
    team, why = access_team.configured_team_domain()
    assert team is None and "not a subdomain" in why
    assert access_team.TEAM_DOMAIN_ENV in why
    assert not access_team.is_team_host("calibre.com")
    assert access_team.is_team_host(TEAM)


def test_dotless_team_domain_in_the_edge_file_says_why(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    edge = tmp_path / "edge.json"
    edge.write_text(json.dumps({"team_domain": "com"}))
    monkeypatch.setenv(access_team.EDGE_FILE_ENV, str(edge))
    team, why = access_team.configured_team_domain()
    assert team is None and "not a subdomain" in why


class _BrokenJar(_Jar):
    def read(self) -> dict[str, Any]:
        raise RuntimeError("Target closed")


def test_sweep_that_leaves_a_team_cookie_is_failed(
    capsys: pytest.CaptureFixture[str],
) -> None:
    jar = _Jar([*TEAM_COOKIES], deletes=False)  # deletes silently do nothing
    sweep = browser._drop_access_team_cookies(jar, "login x")
    assert sweep.failed and sweep.status == "failed"
    assert f"{TEAM} CF_Session" in sweep.left and "still present" in sweep.error
    assert COOKIE_VALUE not in capsys.readouterr().err + repr(sweep)
    assert jar.detached == 1


def test_sweep_of_an_unreadable_jar_is_failed() -> None:
    sweep = browser._drop_access_team_cookies(_BrokenJar([]), "login x", quiet=True)
    assert sweep.failed and "Target closed" in sweep.error


def _exact_jar() -> list[dict[str, Any]]:
    """Team cookies of every scope next to app cookies that share their
    names: host-only, ``.domain`` and partitioned (CHIPS)."""
    part = {"topLevelSite": "https://example.org", "hasCrossSiteAncestor": False}
    return [
        _ck(TEAM, "CF_Authorization"),  # host-only
        _ck(f".{TEAM}", "CF_Session"),  # domain cookie
        {**_ck(TEAM, "CF_Device"), "secure": True, "partitionKey": part},
        _ck(APP, "CF_Authorization"),
        _ck(f".{APP}", "CF_Session"),
        {**_ck(APP, "CF_Device"), "secure": True, "partitionKey": part},
    ]


#: What `_exact_jar` keeps after a sweep (sorted).
APP_LEFT = [(f".{APP}", "CF_Session"), (APP, "CF_Authorization"), (APP, "CF_Device")]


def test_sweep_deletes_by_exact_identity_and_touches_nothing_else() -> None:
    """Host-only → ``url`` and no ``domain`` (a ``domain`` would address the
    ``.domain`` twin and leave the host-only cookie), ``.domain`` → domain,
    partitionKey passed through; app cookies — even same-named ones — are
    never deleted and never re-added (no clear-all window)."""
    jar = _Jar(_exact_jar())
    sweep = browser._drop_access_team_cookies(jar, "login x")
    assert sweep.status == "ok" and len(sweep.dropped) == 3, sweep
    assert sorted((c["domain"], c["name"]) for c in jar.jar) == APP_LEFT
    by_name = {k["name"]: k for k in jar.sent}
    assert by_name["CF_Authorization"]["url"] == f"https://{TEAM}/"
    assert "domain" not in by_name["CF_Authorization"]
    assert by_name["CF_Session"]["domain"] == f".{TEAM}"
    assert "url" not in by_name["CF_Session"]
    assert by_name["CF_Device"]["partitionKey"]["topLevelSite"] == "https://example.org"
    assert all(k["expires"] == 1 and k["value"] == "" for k in jar.sent)
    assert jar.added == []  # nothing re-added
    assert COOKIE_VALUE not in json.dumps(jar.sent)


def test_round1_style_delete_would_leave_the_host_only_cookie() -> None:
    """The fake models Chromium: a ``domain`` on a host-only cookie's kill
    addresses ``.domain`` — the bug this round fixes — so the exact-identity
    test above is meaningful."""
    jar = [_ck(TEAM, "CF_Authorization")]
    _set_cookies(jar, [{**_ck(TEAM, "CF_Authorization", ""), "expires": 1}])
    assert [(c["domain"], c["name"]) for c in jar] == [(TEAM, "CF_Authorization")]


def test_sweep_attach_failure_is_failed_but_down_is_ok(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    up = [True]
    monkeypatch.setattr(browser, "_is_up", lambda _port: up[0])

    def _boom(_port: int) -> Any:
        raise RuntimeError("attach timed out")

    monkeypatch.setattr(browser, "_connect", _boom)
    assert browser._access_team_sweep(9, "login x").status == "failed"
    calls = iter([True, False])  # up at first, gone by the time the attach fails
    monkeypatch.setattr(browser, "_is_up", lambda _port: next(calls))
    assert browser._access_team_sweep(9, "login x").status == "down"


@contextlib.contextmanager
def _no_deadline(*_a: Any, **_k: Any) -> Iterator[None]:
    yield None


def _recorder(seen: list[str], status: str = "ok") -> Any:
    """A stand-in sweep: records its `why`, answers `status`."""

    def _sweep(_port: int, why: str) -> Any:
        seen.append(why)
        return browser.AccessSweep(status, error="x" if status == "failed" else "")

    return _sweep


@pytest.mark.parametrize("exc", [SystemExit(124), RuntimeError("boom")])
def test_login_sweeps_even_when_the_flow_exits_or_raises(
    monkeypatch: pytest.MonkeyPatch, exc: BaseException
) -> None:
    seen: list[str] = []
    monkeypatch.setattr(browser, "_access_team_sweep", _recorder(seen))
    monkeypatch.setattr(browser, "_login_deadline", _no_deadline)

    def _raise(_port: int, _site: str) -> int:
        raise exc

    monkeypatch.setattr(browser, "_cmd_login", _raise)
    with pytest.raises(type(exc)) as got:
        browser.cmd_login(9, "Stirling")
    assert got.value is exc  # the original exit / exception propagates
    assert seen == ["login stirling"]


@pytest.mark.parametrize(
    ("status", "flow_rc", "want"),
    [("failed", 0, 1), ("down", 0, 0), ("ok", 0, 0), ("failed", 2, 2)],
)
def test_login_exit_after_the_sweep(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    status: str,
    flow_rc: int,
    want: int,
) -> None:
    """A failed sweep turns a logged-in 0 into 1 / access_team_sweep_failed;
    a browser that is down is no failure; a failed login keeps its own code."""
    monkeypatch.setattr(
        browser,
        "_access_team_sweep",
        lambda _p, _w: browser.AccessSweep(status, error="jar unreadable"),
    )
    monkeypatch.setattr(browser, "_login_deadline", _no_deadline)
    monkeypatch.setattr(browser, "_cmd_login", lambda _p, _s: flow_rc)
    out = tmp_path / "result.json"
    assert browser.cmd_login(9, "stirling", result_file=str(out)) == want
    rec = json.loads(out.read_text())
    if status == "failed" and flow_rc == 0:
        assert rec["code"] == "access_team_sweep_failed"
        assert rec["phase"] == "consumer-followup"
    elif want == 0:
        assert rec["code"] == "ok"


@pytest.mark.parametrize(
    ("code", "status", "want"),
    [(0, "failed", 1), (None, "failed", 1), (0, "ok", 0), (None, "down", 0)],
)
def test_login_systemexit_success_keeps_the_sweep_verdict(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    code: int | None,
    status: str,
    want: int,
) -> None:
    """A flow that leaves through ``SystemExit(0)`` / ``SystemExit()`` still
    gets the sweep's verdict: a failed sweep exits 1 with
    access_team_sweep_failed, never 0."""
    monkeypatch.setattr(
        browser,
        "_access_team_sweep",
        lambda _p, _w: browser.AccessSweep(status, error="jar unreadable"),
    )
    monkeypatch.setattr(browser, "_login_deadline", _no_deadline)

    def _exit(_port: int, _site: str) -> int:
        raise SystemExit(code)

    monkeypatch.setattr(browser, "_cmd_login", _exit)
    out = tmp_path / "result.json"
    with pytest.raises(SystemExit) as got:
        browser.cmd_login(9, "stirling", result_file=str(out))
    assert (got.value.code or 0) == want
    rec = json.loads(out.read_text())
    assert rec["code"] == ("access_team_sweep_failed" if want else "ok")


class _Tty:
    def __enter__(self) -> _Tty:
        return self

    def __exit__(self, *_a: Any) -> None:
        return None


@pytest.mark.parametrize(("status", "want"), [("failed", 1), ("down", 0), ("ok", 0)])
def test_assisted_login_exit_after_the_sweep(
    monkeypatch: pytest.MonkeyPatch, status: str, want: int
) -> None:
    seen: list[str] = []
    monkeypatch.setattr(browser, "_open_tty", _Tty)
    monkeypatch.setattr(browser, "_assisted_login_tty", lambda *_a: 0)
    monkeypatch.setattr(browser, "_access_team_sweep", _recorder(seen, status))
    req = browser.GuidedRequest("Calibre")
    assert browser.cmd_assisted_login(9, req) == want
    assert seen == ["assisted-login calibre"]


def test_assisted_login_sweeps_when_it_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[str] = []

    def _raise(*_a: Any) -> int:
        raise RuntimeError("boom")

    monkeypatch.setattr(browser, "_open_tty", _Tty)
    monkeypatch.setattr(browser, "_assisted_login_tty", _raise)
    monkeypatch.setattr(browser, "_access_team_sweep", _recorder(seen))
    with pytest.raises(RuntimeError, match="boom"):
        browser.cmd_assisted_login(9, browser.GuidedRequest("calibre"))
    assert seen == ["assisted-login calibre"]


def test_import_safari_sweeps_and_fails_on_a_failed_sweep(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[str] = []
    monkeypatch.setattr(browser, "_import_safari", lambda *_a, **_k: 0)
    monkeypatch.setattr(browser, "_access_team_sweep", _recorder(seen, "failed"))
    assert browser.cmd_import_safari(9, "somesite") == 1
    assert seen == ["import-safari somesite"]
    assert browser.cmd_import_safari(9, "somesite", dry_run=True) == 0
    assert seen == ["import-safari somesite"]  # a dry run writes nothing


class _CdpJar(_Jar):
    """`_cdp_ws_call` on a `_Jar` (Chromium's identity rules); records the
    budget of every call and advances a fake clock by `cost` per call."""

    def __init__(self, cookies: list[dict[str, Any]], **kw: Any) -> None:
        super().__init__(cookies, **kw)
        self.budgets: list[float] = []
        self.clock = 0.0
        self.cost = 0.0

    def __call__(
        self, _ws: str, method: str, params: Any = None, budget: float = 0
    ) -> Any:
        self.budgets.append(budget)
        self.clock += self.cost
        res = _Res([])
        res.result = _Session(self).send(method, params)
        return res


def _patch_cdp(monkeypatch: pytest.MonkeyPatch, fake: _CdpJar) -> None:
    monkeypatch.setattr(browser, "_sweep_endpoint", lambda *_a: ("ok", "ws://fake"))
    monkeypatch.setattr(browser, "_cdp_ws_call", fake)


def test_cdp_sweep_expires_team_cookies_and_verifies(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    fake = _CdpJar(_exact_jar())
    _patch_cdp(monkeypatch, fake)
    sweep = browser._access_team_sweep_cdp(9, "login x (timeout)")
    assert sweep.status == "ok" and len(sweep.dropped) == 3
    assert sorted((c["domain"], c["name"]) for c in fake.jar) == APP_LEFT
    assert all(c["expires"] == 1 and c["value"] == "" for c in fake.sent)
    assert COOKIE_VALUE not in json.dumps(fake.sent) + capsys.readouterr().err


def test_cdp_sweep_that_cannot_delete_is_failed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_cdp(monkeypatch, _CdpJar(TEAM_COOKIES, deletes=False))
    sweep = browser._access_team_sweep_cdp(9, "login x (timeout)")
    assert sweep.failed and len(sweep.left) == 3


def test_cdp_sweep_has_one_total_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    """4 s for the WHOLE deadline sweep, not per call: each call gets only
    what is left, and a sweep that runs out fails (never ``ok``)."""
    real_time = browser.time

    def _run(cost: float) -> tuple[Any, list[float]]:
        fake = _CdpJar([*TEAM_COOKIES, APP_COOKIE])
        fake.cost = cost  # every CDP call "takes" `cost` s on the fake clock

        class _Clock:  # only browser.py's clock is fake, not pytest's
            def __getattr__(self, name: str) -> Any:
                return getattr(real_time, name)

            def monotonic(self) -> float:
                return fake.clock

        _patch_cdp(monkeypatch, fake)
        monkeypatch.setattr(browser, "time", _Clock())
        sweep = browser._access_team_sweep_cdp(9, "login x (timeout)", budget_s=4.0)
        return sweep, fake.budgets

    sweep, budgets = _run(1.5)
    assert budgets == [4.0, 2.5, 1.0]  # get, set, re-read: all inside 4 s
    assert sweep.status == "ok"
    sweep, budgets = _run(3.0)
    assert budgets == [4.0, 1.0]  # the re-read finds the budget spent
    assert sweep.failed and "budget" in sweep.error


def test_deadline_hard_exit_sweeps_over_cdp(monkeypatch: pytest.MonkeyPatch) -> None:
    """124/125 is an ``os._exit`` from the watcher — no ``finally`` of
    `cmd_login` runs, so the watcher sweeps before it exits."""
    order: list[str] = []
    monkeypatch.setattr(browser, "_close_owned_targets", lambda *_a, **_k: ([], True))
    monkeypatch.setattr(browser, "_access_team_sweep_cdp", _recorder(order))
    monkeypatch.setattr(browser, "_hard_exit", lambda rc: order.append(f"exit {rc}"))
    dl = browser.LoginDeadline(9, "login", "stirling", 1.0)
    dl._fire((0.0, "overall", 1.0), [], "start")
    assert order == ["login stirling (timeout)", f"exit {browser.LOGIN_TIMEOUT_RC}"]


# --- tp#1468 B1: the sweep takes the Browser; no context is never `ok` ---


def test_sweep_helper_takes_the_browser_and_reads_its_default_jar() -> None:
    """The helper gets the Playwright Browser (never a context) and sweeps
    the default jar over one browser-level CDP session."""
    ctx = _Jar([*TEAM_COOKIES, APP_COOKIE])
    owner = _Browser(ctx)
    sweep = browser._drop_access_team_cookies(owner, "login x", quiet=True)
    assert sweep.status == "ok" and len(sweep.dropped) == 3, sweep
    assert owner.sessions == 1 and ctx.detached == 1
    assert [(c["domain"], c["name"]) for c in ctx.jar] == [(APP, "CF_Authorization")]


def test_sweep_of_a_browser_without_contexts_is_failed() -> None:
    owner = _Browser(None)
    sweep = browser._drop_access_team_cookies(owner, "login x", quiet=True)
    assert sweep.failed and "not the default context" in sweep.error
    assert owner.sessions == 0 and not owner.sent


def test_post_login_sweep_without_contexts_is_failed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owner = _Browser(None)

    class _Pw:
        def stop(self) -> None:
            return None

    monkeypatch.setattr(browser, "_is_up", lambda _port: True)
    monkeypatch.setattr(browser, "_connect", lambda _port: (_Pw(), owner))
    monkeypatch.setattr(owner, "close", lambda: None, raising=False)
    sweep = browser._access_team_sweep(9, "login x")
    assert sweep.status == "failed" and "not the default context" in sweep.error
    assert not owner.sent


def test_broker_injection_refuses_a_browser_without_contexts() -> None:
    """No `new_context()` fallback: nothing is injected into an isolated
    context, no ``Storage.setCookies`` is sent, the refusal is journaled."""
    owner = _Browser(None)
    fake_bundle = {"cookie_hosts": [APP], "cookie_names": None, "cookies": [APP_COOKIE]}
    with pytest.raises(browser.SharedJarMissing, match="not the default context"):
        browser._broker_replace_cookies(owner, fake_bundle)
    assert "Storage.setCookies" not in owner.sent and owner.sessions == 0
    assert browser._JOURNAL_NOTES.get("shared_jar_refused") == "broker-login"
    assert browser._cookie_inject_error(browser.SharedJarMissing("x")) == (
        "no_default_context"
    )


def test_safari_import_refuses_a_browser_without_contexts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owner = _Browser(None)
    monkeypatch.setattr(browser._safari, "has_session", lambda _site, _c: True)
    with pytest.raises(browser.SharedJarMissing, match="nothing injected"):
        browser._safari_replace_cookies(owner, "somesite", [])
    assert not owner.sent and owner.sessions == 0
    assert browser._JOURNAL_NOTES.get("shared_jar_refused") == "import-safari somesite"


def test_cdp_sweep_endpoint_lookup_is_inside_the_budget() -> None:
    """A ``/json/version`` that accepts and never answers costs at most the
    sweep budget (no bare `_is_up` with its own 2 s timeout) and is
    ``failed``; nothing listening is ``down``."""
    import socket  # pylint: disable=import-outside-toplevel
    import time  # pylint: disable=import-outside-toplevel

    with socket.socket() as stall:
        stall.bind(("127.0.0.1", 0))
        stall.listen(1)  # accepts into the backlog, never answers
        port = int(stall.getsockname()[1])
        start = time.monotonic()
        sweep = browser._access_team_sweep_cdp(port, "login x (timeout)", budget_s=0.3)
        elapsed = time.monotonic() - start
    assert sweep.failed and "no endpoint answer" in sweep.error, sweep
    assert elapsed < 1.5, elapsed  # the budget, not _cdp_get's 2 s
    closed = _free_port()  # bound then released: nothing listens
    assert browser._access_team_sweep_cdp(closed, "x", budget_s=0.3).status == "down"


def test_cdp_sweep_endpoint_without_a_websocket_is_failed() -> None:
    import http.server  # pylint: disable=import-outside-toplevel
    import threading  # pylint: disable=import-outside-toplevel

    class _NoWs(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - http.server's name
            body = b'{"Browser": "fake"}'
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_a: Any) -> None:
            return None

    srv = http.server.HTTPServer(("127.0.0.1", 0), _NoWs)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        port = int(srv.server_address[1])
        sweep = browser._access_team_sweep_cdp(port, "x", budget_s=2.0)
    finally:
        srv.shutdown()
        srv.server_close()
    assert sweep.failed and sweep.error == "no browser websocket"


def test_cdp_sweep_with_a_spent_budget_never_probes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        browser.urllib.request, "urlopen", lambda *_a, **_k: pytest.fail("probed")
    )
    sweep = browser._access_team_sweep_cdp(9, "x", budget_s=0.0)
    assert sweep.failed and "budget spent" in sweep.error


# --- opt-in: a THROWAWAY real Chromium (never the shared one on :9222) ---


def _free_port() -> int:
    import socket  # pylint: disable=import-outside-toplevel

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@pytest.mark.launches_chrome
@pytest.mark.skipif(
    not __import__("os").environ.get("CLAUDE_BROWSER_TEST_CDP"),
    reason="opt-in: set CLAUDE_BROWSER_TEST_CDP=1 (launches a throwaway Chromium)",
)
def test_real_chromium_keeps_only_the_app_cookie(tmp_path: Path) -> None:
    """Real cookie semantics: a host-only team cookie, a ``.team…`` domain
    cookie and a partitioned (CHIPS) team cookie go; the app cookies — a
    same-named host-only one, a ``.app`` one and a partitioned one — stay,
    untouched — through the Playwright attach (`_drop_access_team_cookies`,
    as `_access_team_sweep` uses it) and through raw CDP
    (`_access_team_sweep_cdp`, the deadline path).

    CHIPS listing proof (tp#1468, residual 3): the sweep reads the jar with
    ``Storage.getCookies``, so it must LIST partitioned cookies — asserted
    on a partitioned dummy team cookie on ``x.cloudflareaccess.com`` before
    each sweep, gone after it (``ok``, read-back empty of team cookies),
    while the partitioned app cookie survives.

    The executable is the one browser.py launches (`_chromium_binary`);
    `$CLAUDE_BROWSER_TEST_CHROMIUM` may override it. The disposable browser
    on a free port (never :9222) is closed in a ``finally``."""
    import os  # pylint: disable=import-outside-toplevel

    from playwright.sync_api import (  # pylint: disable=import-outside-toplevel
        sync_playwright,
    )

    port = _free_port()
    assert port != 9222
    part = {"topLevelSite": "https://example.org", "hasCrossSiteAncestor": False}
    chips = {"secure": True, "sameSite": "None", "partitionKey": part}
    chips_team = "x.cloudflareaccess.com"
    team_cookies = [
        {"name": "CF_Authorization", "value": "v", "url": f"https://{TEAM}/"},
        {"name": "CF_Session", "value": "v", "domain": f".{TEAM}", "path": "/"},
        {"name": "CF_Device", "value": "v", "url": f"https://{TEAM}/", **chips},
        {"name": "CF_Chips", "value": "v", "url": f"https://{chips_team}/", **chips},
    ]
    app_cookies = [
        {"name": "CF_Authorization", "value": "a1", "url": f"https://{APP}/"},
        {"name": "CF_Session", "value": "a2", "domain": f".{APP}", "path": "/"},
        {"name": "CF_Device", "value": "a3", "url": f"https://{APP}/", **chips},
    ]

    def _app_jar(cdp: Any) -> list[tuple[str, str, bool]]:
        """The jar by identity only (domain, name, partitioned) — no value."""
        got = cdp.send("Storage.getCookies", {})["cookies"]
        return sorted(
            (c["domain"], c["name"], bool(c.get("partitionKey"))) for c in got
        )

    want = [(d, n, n == "CF_Device") for d, n in APP_LEFT]
    chips_label = (chips_team, "CF_Chips", True)

    def _team_jar(cdp: Any) -> list[tuple[str, str, bool]]:
        got = cdp.send("Storage.getCookies", {})["cookies"]
        return sorted(
            (c["domain"], c["name"], bool(c.get("partitionKey")))
            for c in got
            if access_team.is_team_host(str(c["domain"]))
        )

    exe = os.environ.get("CLAUDE_BROWSER_TEST_CHROMIUM") or browser._chromium_binary()
    with sync_playwright() as pw:
        owner: Any = None
        attached: Any = None
        try:
            owner = pw.chromium.launch_persistent_context(
                str(tmp_path / "profile"),
                headless=True,
                executable_path=exe,
                args=[f"--remote-debugging-port={port}"],
            )
            attached = pw.chromium.connect_over_cdp(f"http://127.0.0.1:{port}")
            cdp = attached.new_browser_cdp_session()
            cdp.send("Storage.setCookies", {"cookies": [*team_cookies, *app_cookies]})
            assert len(cdp.send("Storage.getCookies", {})["cookies"]) == 7
            assert chips_label in _team_jar(cdp)  # CHIPS: listed, so sweepable
            # the shared browser, as `_access_team_sweep` passes it (tp#1468)
            sweep = browser._drop_access_team_cookies(attached, "integration")
            assert sweep.status == "ok" and len(sweep.dropped) == 4, sweep
            assert f"{chips_team} CF_Chips" in sweep.dropped
            assert not _team_jar(cdp) and _app_jar(cdp) == want
            cdp.send("Storage.setCookies", {"cookies": team_cookies})  # again
            assert chips_label in _team_jar(cdp)
            sweep = browser._access_team_sweep_cdp(port, "integration (cdp)")
            assert sweep.status == "ok" and len(sweep.dropped) == 4, sweep
            assert not _team_jar(cdp) and _app_jar(cdp) == want
        finally:
            if attached is not None:
                with contextlib.suppress(Exception):
                    attached.close()
            if owner is not None:
                owner.close()
