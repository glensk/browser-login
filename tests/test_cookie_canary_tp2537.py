"""Cookie canary and Keychain grant check (tp#2537 B2).

A Chromium build that cannot read its Keychain cookie key keeps cookies in
memory only. Pinned here:

* the canary resolves ``Default/Network/Cookies``, falls back to
  ``Default/Cookies``, opens the db read-only + immutable, judges only after
  the uptime threshold, and fails when memory > 0 and disk is missing or 0;
* the pre-launch Keychain ACL check parses ``security dump-keychain -a``,
  caches per revision, refuses an unattended (``AGENT_LOGIN_SCHEDULED``)
  launch with "grant needed: <runbook>" and only warns an attended one.

Hermetic: every path lives in tmp_path, no browser, no real ``security``.

Run: uv run --no-sync pytest tests/test_cookie_canary_tp2537.py -q
"""

from __future__ import annotations

# pylint: disable=protected-access,missing-function-docstring,import-error
# pylint: disable=redefined-outer-name,unused-argument
import importlib.util
import json
import sqlite3
import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parent.parent


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


browser = _load("browser_cookie_canary_test", _REPO / "bin" / "browser.py")

APP_OK = "/c/ms-playwright/chromium-1248/chrome-mac-arm64/Google Chrome for Testing.app"
APP_NEW = (
    "/c/ms-playwright/chromium-1254/chrome-mac-arm64/Google Chrome for Testing.app"
)
BIN_NEW = f"{APP_NEW}/Contents/MacOS/Google Chrome for Testing"


def _cookies_db(path: Path, rows: int) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE cookies (host_key TEXT, name TEXT)")
    con.executemany(
        "INSERT INTO cookies VALUES (?, ?)", [("h", f"n{i}") for i in range(rows)]
    )
    con.commit()
    con.close()
    return path


# --- canary: path fallback, read-only open, predicate ------------------------


def test_db_path_prefers_network_cookies(tmp_path):
    _cookies_db(tmp_path / "Default" / "Cookies", 1)
    net = _cookies_db(tmp_path / "Default" / "Network" / "Cookies", 1)
    assert browser._cookie_db_path(tmp_path) == net


def test_db_path_falls_back_to_legacy_cookies(tmp_path):
    legacy = _cookies_db(tmp_path / "Default" / "Cookies", 1)
    assert browser._cookie_db_path(tmp_path) == legacy


def test_db_path_none_when_missing(tmp_path):
    assert browser._cookie_db_path(tmp_path) is None


def test_db_rows_counts_and_opens_read_only(tmp_path, monkeypatch):
    db = _cookies_db(tmp_path / "Default" / "Network" / "Cookies", 3)
    uris: list[tuple[str, dict]] = []
    real = sqlite3.connect

    def spy(database, *a, **kw):
        uris.append((database, kw))
        return real(database, *a, **kw)

    monkeypatch.setattr(sqlite3, "connect", spy)
    before = db.stat().st_mtime_ns
    assert browser._cookie_db_rows(db) == 3
    assert uris == [(f"file:{db}?mode=ro&immutable=1", {"uri": True})]
    assert db.stat().st_mtime_ns == before
    assert not list(db.parent.glob("Cookies-*"))  # no journal/wal created


def test_db_rows_none_for_missing_or_garbage(tmp_path):
    assert browser._cookie_db_rows(None) is None
    assert browser._cookie_db_rows(tmp_path / "nope") is None
    junk = tmp_path / "Cookies"
    junk.write_bytes(b"not a database at all" * 10)
    assert browser._cookie_db_rows(junk) is None


@pytest.mark.parametrize(
    ("memory", "disk", "uptime", "want"),
    [
        (5, 0, 120.0, "fail"),
        (5, None, 120.0, "fail"),
        (5, 4, 120.0, "ok"),
        (0, 0, 120.0, "ok"),
        (0, None, 120.0, "ok"),
        (5, 0, 59.0, "wait"),
        (5, 0, 60.0, "fail"),
        (None, 0, 120.0, "unknown"),
        (5, 0, None, "unknown"),
    ],
)
def test_verdict(memory, disk, uptime, want):
    assert browser.cookie_canary_verdict(memory, disk, uptime) == want


@pytest.mark.parametrize(
    ("etime", "secs"),
    [("00:59", 59.0), ("01:02:03", 3723.0), ("2-00:00:01", 172801.0), ("x", None)],
)
def test_etime_parse(etime, secs):
    assert browser._etime_s(etime) == secs


def _wire(monkeypatch, *, memory, uptime):
    monkeypatch.setattr(browser, "_browser_uptime_s", lambda port: uptime)
    monkeypatch.setattr(browser, "_memory_persistent_cookies", lambda port: memory)


def test_canary_fails_on_memory_only_cookies(tmp_path, monkeypatch, capsys):
    _cookies_db(tmp_path / "Default" / "Network" / "Cookies", 0)
    _wire(monkeypatch, memory=7, uptime=300.0)
    c = browser.cookie_canary(9999, tmp_path)
    assert (c.status, c.memory, c.disk, c.ok) == ("fail", 7, 0, False)
    monkeypatch.setattr(browser, "PROFILE_DIR", tmp_path)
    log: list[str] = []
    browser._doctor_cookie_canary(log, 9999)
    assert log == ["fail"]
    assert "NOT persisted" in capsys.readouterr().out


def test_canary_green_and_young_browser(tmp_path, monkeypatch, capsys):
    _cookies_db(tmp_path / "Default" / "Network" / "Cookies", 5)
    monkeypatch.setattr(browser, "PROFILE_DIR", tmp_path)
    _wire(monkeypatch, memory=5, uptime=300.0)
    assert browser.cookie_canary(9999).ok
    log: list[str] = []
    browser._doctor_cookie_canary(log, 9999)
    _wire(monkeypatch, memory=5, uptime=10.0)
    browser._doctor_cookie_canary(log, 9999)
    assert log == ["ok", "warn"]
    assert "not judged" in capsys.readouterr().out


def test_memory_count_skips_session_cookies(monkeypatch):
    res = browser.CdpResult(
        "ok",
        result={"cookies": [{"session": True}, {"session": False}, {"session": False}]},
    )
    monkeypatch.setattr(browser, "_browser_ws_url", lambda port: "ws://x")
    monkeypatch.setattr(browser, "_cdp_ws_call", lambda *a, **k: res)
    assert browser._memory_persistent_cookies(9999) == 2


# --- Keychain ACL check ------------------------------------------------------


def _dump(*apps: str, service: str = "Chromium Safe Storage") -> str:
    listed = "".join(
        f"            {i}: {a} (status -2147415734)\n"
        f'                requirement: cdhash H"00"\n'
        for i, a in enumerate(apps)
    )
    return (
        'keychain: "/k/login.keychain-db"\nclass: "genp"\nattributes:\n'
        '    "svce"<blob>="other"\naccess: 1 entries\n    entry 0:\n'
        "        authorizations (6): decrypt derive export_clear export_wrapped mac sign\n"
        "        applications (1):\n            0: /x/Other.app (OK)\n"
        'keychain: "/k/login.keychain-db"\nclass: "genp"\nattributes:\n'
        f'    "svce"<blob>="{service}"\naccess: 3 entries\n    entry 0:\n'
        "        authorizations (6): decrypt derive export_clear export_wrapped mac sign\n"
        f"        don't-require-password\n        description: {service}\n"
        f"        applications ({len(apps)}):\n{listed}"
        "    entry 1:\n        authorizations (1): encrypt\n"
        "        applications: <null>\n"
        "    entry 2:\n        authorizations (1): change_acl\n"
        "        applications (0):\n"
    )


def test_acl_parse_decrypt_entry_only():
    lists = browser._keychain_acl_apps(_dump(APP_OK), "Chromium Safe Storage")
    assert lists == [[APP_OK]]
    assert browser._keychain_acl_apps(_dump(APP_OK), "Nope") is None


class _Sec:
    def __init__(self, out: str, rc: int = 0):
        self.out, self.rc, self.calls = out, rc, 0

    def __call__(self, argv, **kw):
        assert list(argv) == ["security", "dump-keychain", "-a"]
        self.calls += 1
        return browser.SecurityResult("done", self.rc, self.out.encode(), b"")


@pytest.fixture
def acl_cache(tmp_path, monkeypatch):
    cache = tmp_path / "pin" / "keychain-acl.json"
    monkeypatch.setattr(browser, "KEYCHAIN_ACL_CACHE", cache)
    return cache


def test_grant_state_granted_cached_per_revision(acl_cache, monkeypatch):
    sec = _Sec(_dump(APP_OK))
    monkeypatch.setattr(browser, "_security_run", sec)
    assert browser._keychain_grant_state(1248, APP_OK, now=1000.0) == "granted"
    assert browser._keychain_grant_state(1248, APP_OK, now=9e9) == "granted"
    assert sec.calls == 1
    assert json.loads(acl_cache.read_text())["1248"]["state"] == "granted"


def test_grant_state_missing_rechecked_after_ttl(acl_cache, monkeypatch):
    sec = _Sec(_dump(APP_OK))
    monkeypatch.setattr(browser, "_security_run", sec)
    assert browser._keychain_grant_state(1254, APP_NEW, now=1000.0) == "missing"
    assert browser._keychain_grant_state(1254, APP_NEW, now=1100.0) == "missing"
    assert sec.calls == 1
    sec.out = _dump(APP_OK, APP_NEW)  # Albert clicked "Always Allow"
    ttl = browser.KEYCHAIN_ACL_MISS_TTL_S
    assert browser._keychain_grant_state(1254, APP_NEW, now=1001.0 + ttl) == "granted"
    assert sec.calls == 2


def test_grant_state_absent_and_unknown_not_cached(acl_cache, monkeypatch):
    monkeypatch.setattr(browser, "_security_run", _Sec(_dump(APP_OK, service="x")))
    assert browser._keychain_grant_state(1254, APP_NEW) == "absent"
    monkeypatch.setattr(browser, "_security_run", _Sec("", rc=51))
    assert browser._keychain_grant_state(1254, APP_NEW) == "unknown"
    assert not acl_cache.exists()


def test_gate_refuses_unattended_launch(acl_cache, monkeypatch):
    monkeypatch.setattr(browser, "_security_run", _Sec(_dump(APP_OK)))
    monkeypatch.setattr(browser, "_chromium_revision", lambda: 1254)
    monkeypatch.setenv("AGENT_LOGIN_SCHEDULED", "1")
    msg = browser._keychain_grant_gate(BIN_NEW)
    assert msg is not None
    assert f"grant needed: {browser.CHROMIUM_BUMP_RUNBOOK}" in msg
    assert str(browser.CHROMIUM_BUMP_RUNBOOK).endswith("docs/chromium-build-bump.md")


def test_gate_warns_attended_launch(acl_cache, monkeypatch, capsys):
    monkeypatch.setattr(browser, "_security_run", _Sec(_dump(APP_OK)))
    monkeypatch.setattr(browser, "_chromium_revision", lambda: 1254)
    monkeypatch.delenv("AGENT_LOGIN_SCHEDULED", raising=False)
    assert browser._keychain_grant_gate(BIN_NEW) is None
    assert "grant needed:" in capsys.readouterr().err


def test_gate_passes_granted_build(acl_cache, monkeypatch, capsys):
    monkeypatch.setattr(browser, "_security_run", _Sec(_dump(APP_NEW)))
    monkeypatch.setattr(browser, "_chromium_revision", lambda: 1254)
    monkeypatch.setenv("AGENT_LOGIN_SCHEDULED", "1")
    assert browser._keychain_grant_gate(BIN_NEW) is None
    assert capsys.readouterr().err == ""


def test_gate_unknown_never_refuses(acl_cache, monkeypatch):
    def boom(argv, **kw):
        raise RuntimeError("denied")

    monkeypatch.setattr(browser, "_security_run", boom)
    monkeypatch.setenv("AGENT_LOGIN_SCHEDULED", "1")
    assert browser._keychain_grant_gate(BIN_NEW) is None


def test_runbook_exists():
    assert browser.CHROMIUM_BUMP_RUNBOOK.is_file()


def test_app_path_of_bundle_and_bare_binary():
    assert browser._chromium_app_path(BIN_NEW) == APP_NEW
    assert browser._chromium_app_path("/x/chrome") == "/x/chrome"
