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


class _Jar:
    """Playwright's cookie API on a list."""

    def __init__(self, cookies: list[dict[str, Any]]) -> None:
        self.jar = [dict(c) for c in cookies]
        self.added: list[str] = []

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
    def __init__(self, ctx: _Jar) -> None:
        self.contexts = [ctx]


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
    edge.write_text(json.dumps({"team_domain": "access.example.org"}))
    monkeypatch.setenv(access_team.EDGE_FILE_ENV, str(edge))
    team, src = access_team.configured_team_domain()
    assert team == "access.example.org" and src == str(edge)
    # A configured team domain outside the suffix is covered too.
    assert access_team.is_team_host(".access.example.org")
    monkeypatch.setenv(access_team.TEAM_DOMAIN_ENV, "Other.Example.NET")
    assert access_team.configured_team_domain()[0] == "other.example.net"


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
    assert team is None and "no dot" in why and access_team.TEAM_DOMAIN_ENV in why
    assert not access_team.is_team_host("calibre.com")
    assert access_team.is_team_host(TEAM)


def test_dotless_team_domain_in_the_edge_file_says_why(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    edge = tmp_path / "edge.json"
    edge.write_text(json.dumps({"team_domain": "com"}))
    monkeypatch.setenv(access_team.EDGE_FILE_ENV, str(edge))
    team, why = access_team.configured_team_domain()
    assert team is None and "no dot" in why


class _StuckJar(_Jar):
    """A jar whose deletes silently do nothing."""

    def clear_cookies(self, *, name: Any = None, domain: Any = None, path: Any = None):
        del name, domain, path


class _BrokenJar(_Jar):
    def cookies(self) -> list[dict[str, Any]]:
        raise RuntimeError("Target closed")


def test_sweep_that_leaves_a_team_cookie_is_failed(
    capsys: pytest.CaptureFixture[str],
) -> None:
    sweep = browser._drop_access_team_cookies(_StuckJar([*TEAM_COOKIES]), "login x")
    assert sweep.failed and sweep.status == "failed"
    assert f"{TEAM} CF_Session" in sweep.left and "still present" in sweep.error
    assert COOKIE_VALUE not in capsys.readouterr().err + repr(sweep)


def test_sweep_of_an_unreadable_jar_is_failed() -> None:
    sweep = browser._drop_access_team_cookies(_BrokenJar([]), "login x", quiet=True)
    assert sweep.failed and "Target closed" in sweep.error


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


class _CdpJar:
    """`_cdp_ws_call` on a cookie list: getCookies / setCookies(expired)."""

    def __init__(self, cookies: list[dict[str, Any]], *, deletes: bool = True) -> None:
        self.jar = [dict(c) for c in cookies]
        self.deletes = deletes
        self.sent: list[dict[str, Any]] = []

    def __call__(self, _ws: str, method: str, params: Any = None, _b: float = 0) -> Any:
        if method == "Storage.getCookies":
            return _Res([dict(c) for c in self.jar])
        assert method == "Storage.setCookies"
        self.sent += params["cookies"]
        if self.deletes:
            gone = {(c["domain"], c["name"], c["path"]) for c in params["cookies"]}
            self.jar = [
                c for c in self.jar if (c["domain"], c["name"], c["path"]) not in gone
            ]
        return _Res([])


def test_cdp_sweep_expires_team_cookies_and_verifies(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    fake = _CdpJar([*TEAM_COOKIES, APP_COOKIE])
    monkeypatch.setattr(browser, "_is_up", lambda _port: True)
    monkeypatch.setattr(browser, "_browser_ws_url", lambda _port: "ws://fake")
    monkeypatch.setattr(browser, "_cdp_ws_call", fake)
    sweep = browser._access_team_sweep_cdp(9, "login x (timeout)")
    assert sweep.status == "ok" and len(sweep.dropped) == 3
    assert [(c["domain"], c["name"]) for c in fake.jar] == [(APP, "CF_Authorization")]
    assert all(c["expires"] == 1 and c["value"] == "" for c in fake.sent)
    assert COOKIE_VALUE not in json.dumps(fake.sent) + capsys.readouterr().err


def test_cdp_sweep_that_cannot_delete_is_failed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(browser, "_is_up", lambda _port: True)
    monkeypatch.setattr(browser, "_browser_ws_url", lambda _port: "ws://fake")
    monkeypatch.setattr(browser, "_cdp_ws_call", _CdpJar(TEAM_COOKIES, deletes=False))
    sweep = browser._access_team_sweep_cdp(9, "login x (timeout)")
    assert sweep.failed and len(sweep.left) == 3


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


# --- opt-in: a THROWAWAY real Chromium (never the shared one on :9222) ---


def _free_port() -> int:
    import socket  # pylint: disable=import-outside-toplevel

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@pytest.mark.skipif(
    not __import__("os").environ.get("CLAUDE_BROWSER_TEST_CDP"),
    reason="opt-in: set CLAUDE_BROWSER_TEST_CDP=1 (launches a throwaway Chromium)",
)
def test_real_chromium_keeps_only_the_app_cookie(tmp_path: Path) -> None:
    """Real cookie semantics: a ``.team…`` domain cookie and a host-only team
    cookie go, the app cookie stays — through Playwright (`_drop_access_team_
    cookies`) and through raw CDP (`_access_team_sweep_cdp`, the deadline
    path). `$CLAUDE_BROWSER_TEST_CHROMIUM` may name the executable."""
    import os  # pylint: disable=import-outside-toplevel

    from playwright.sync_api import (  # pylint: disable=import-outside-toplevel
        sync_playwright,
    )

    port = _free_port()
    assert port != 9222
    # Any: Playwright's SetCookieParam TypedDict (the dicts match it).
    team_cookies: list[Any] = [
        {"name": "CF_Session", "value": "v", "domain": f".{TEAM}", "path": "/"},
        {"name": "CF_Device", "value": "v", "url": f"https://{TEAM}/"},
    ]
    app: Any = {"name": "CF_Authorization", "value": "v", "url": f"https://{APP}/"}
    exe = os.environ.get("CLAUDE_BROWSER_TEST_CHROMIUM") or None
    with sync_playwright() as pw:
        ctx = pw.chromium.launch_persistent_context(
            str(tmp_path / "profile"),
            headless=True,
            executable_path=exe,
            args=[f"--remote-debugging-port={port}"],
        )
        try:
            ctx.add_cookies([*team_cookies, app])
            sweep = browser._drop_access_team_cookies(ctx, "integration")
            assert sweep.status == "ok" and len(sweep.dropped) == 2
            assert [(c["domain"], c["name"]) for c in ctx.cookies()] == [
                (APP, "CF_Authorization")
            ]
            ctx.add_cookies(team_cookies)  # again, for the raw-CDP path
            sweep = browser._access_team_sweep_cdp(port, "integration (cdp)")
            assert sweep.status == "ok" and len(sweep.dropped) == 2
            assert [(c["domain"], c["name"]) for c in ctx.cookies()] == [
                (APP, "CF_Authorization")
            ]
        finally:
            ctx.close()
