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
    gone = browser._access_team_sweep(9, "login stirling")
    assert sorted(gone or []) == sorted(f"{TEAM} {c['name']}" for c in TEAM_COOKIES)
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
    assert browser._access_team_sweep(9, "login x") is None


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
