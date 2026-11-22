"""Cookie canary and Keychain grant check (tp#2537 B2, hardened in B2c).

A Chromium build that cannot read its Keychain cookie key keeps cookies in
memory only. Pinned here:

* the canary resolves ``Default/Network/Cookies``, falls back to
  ``Default/Cookies``, opens the db read-only + immutable, judges only after
  the uptime threshold, and fails when memory > 0 and disk is missing or 0,
  when memory is 0 and disk > 0, and when the disk rows dropped by > 50 % and
  > 10 rows against the count recorded before the spawn (B2c);
* the pre-launch Keychain ACL check parses ``security dump-keychain -a``
  (status codes, cdhash requirements, the ``partition_id`` list), checks the
  binary's CDHash, caches per revision + CDHash, refuses an unattended
  (``AGENT_LOGIN_SCHEDULED``) launch on "missing" or "unknown" with
  "grant needed: <runbook>" and only warns an attended one.

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
        (0, 13, 120.0, "fail"),
        (0, 13, 59.0, "wait"),
        (5, 0, 59.0, "wait"),
        (5, 0, 60.0, "fail"),
        (None, 0, 120.0, "unknown"),
        (5, 0, None, "unknown"),
    ],
)
def test_verdict(memory, disk, uptime, want):
    assert browser.cookie_canary_verdict(memory, disk, uptime) == want


@pytest.mark.parametrize(
    ("memory", "disk", "baseline", "want"),
    [
        (0, 13, None, "fail"),  # 0/13: the jar on disk is unreadable
        (0, 0, 1555, "fail"),  # 0/0 right after a wipe of 1555 rows
        (0, None, 1555, "fail"),  # db gone after 1555 rows
        (0, 0, 0, "ok"),  # 0/0 with recorded 0: a fresh profile
        (1500, 1480, 1555, "ok"),
        (1500, 1480, None, "ok"),
        (8, 8, 20, "fail"),  # 60 % and 12 rows: both thresholds crossed
        (5, 5, 14, "ok"),  # 64 % drop, 9 rows: not > 10
        (900, 700, 1555, "fail"),  # 55 % drop, 855 rows
        (900, 800, 1555, "ok"),  # 48.6 % drop
    ],
)
def test_verdict_against_pre_launch_baseline(memory, disk, baseline, want):
    assert browser.cookie_canary_verdict(memory, disk, 120.0, baseline) == want


def test_baseline_recorded_before_spawn(tmp_path, monkeypatch):
    monkeypatch.setattr(browser, "CACHE_DIR", tmp_path / "state")
    base = tmp_path / "state" / "cookie-baseline.json"
    assert browser._cookie_baseline() is None
    assert browser._cookie_baseline_record(tmp_path) == 0  # no db yet
    assert browser._cookie_baseline() == 0
    _cookies_db(tmp_path / "Default" / "Network" / "Cookies", 12)
    assert browser._cookie_baseline_record(tmp_path) == 12
    rec = json.loads(base.read_text())
    assert rec["rows"] == 12 and rec["db"].endswith("Network/Cookies")
    assert browser._cookie_baseline() == 12
    base.write_text('{"rows": true}')
    assert browser._cookie_baseline() is None


def test_baseline_read_only_immutable(tmp_path, monkeypatch):
    monkeypatch.setattr(browser, "CACHE_DIR", tmp_path / "state")
    db = _cookies_db(tmp_path / "Default" / "Network" / "Cookies", 2)
    uris: list[str] = []
    real = sqlite3.connect

    def spy(database, *a, **kw):
        uris.append(database)
        return real(database, *a, **kw)

    monkeypatch.setattr(sqlite3, "connect", spy)
    browser._cookie_baseline_record(tmp_path)
    assert uris == [f"file:{db}?mode=ro&immutable=1"]


def test_canary_fails_after_wipe_against_baseline(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(browser, "CACHE_DIR", tmp_path / "state")
    db = _cookies_db(tmp_path / "Default" / "Network" / "Cookies", 30)
    browser._cookie_baseline_record(tmp_path)
    db.unlink()
    _cookies_db(db, 0)
    _wire(monkeypatch, memory=0, uptime=300.0)
    c = browser.cookie_canary(9999, tmp_path)
    assert (c.status, c.memory, c.disk, c.baseline) == ("fail", 0, 0, 30)
    monkeypatch.setattr(browser, "PROFILE_DIR", tmp_path)
    log: list[str] = []
    browser._doctor_cookie_canary(log, 9999)
    assert log == ["fail"]
    assert "30 before launch" in capsys.readouterr().out


def test_launch_records_baseline_before_spawn(tmp_path, monkeypatch):
    """`_launch_and_record` writes the baseline after the grant gate and
    before `_launch_browser` (the spawn)."""
    calls: list[str] = []
    monkeypatch.setattr(browser, "_launch_guard", lambda port: None)
    monkeypatch.setattr(browser, "PROFILE_DIR", tmp_path / "profile")
    monkeypatch.setattr(browser, "_clear_session_restore", lambda: None)
    monkeypatch.setattr(browser, "_chromium_binary", lambda: "/x/chrome")
    monkeypatch.setattr(browser, "_keychain_grant_gate", lambda b: None)
    monkeypatch.setattr(
        browser, "_cookie_baseline_record", lambda: calls.append("baseline")
    )
    monkeypatch.setattr(browser, "_apply_profile_prefs", lambda: None)
    monkeypatch.setattr(browser, "_proxy_flags", lambda: [])
    monkeypatch.setattr(browser, "_headless_user_agent", lambda b: None)
    monkeypatch.setattr(browser, "_lifecycle_write", lambda *a, **k: {"nonce": "n"})

    def spawn(*a, **k):
        calls.append("spawn")
        raise RuntimeError("stop here")

    monkeypatch.setattr(browser, "_launch_browser", spawn)
    with pytest.raises(RuntimeError, match="stop here"):
        browser._launch_and_record(9999, True)
    assert calls == ["baseline", "spawn"]


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


CD_OK = "a69e8d0057c641e087d9bcc7f23cdacc41cc05d8"
CD_NEW = "9499ec77cdd4bf7ad2d5c900445ef45ad9ed43b1"
CDHASH = {APP_OK: CD_OK, APP_NEW: CD_NEW}


def _dump(
    *apps: str,
    service: str = "Chromium Safe Storage",
    status: str = "status -2147415734",
    req: dict[str, str] | None = None,
    partitions: list[str] | None = None,
) -> str:
    """A ``security dump-keychain -a`` shaped dump (as seen 2026-11-22)."""
    req = CDHASH if req is None else req
    listed = "".join(
        f"            {i}: {a} ({status})\n"
        f'                requirement: cdhash H"{req.get(a, "00")}"\n'
        for i, a in enumerate(apps)
    )
    parts = (
        ", ".join(f"cdhash:{CDHASH[a]}" for a in apps if a in CDHASH)
        if partitions is None
        else ", ".join(partitions)
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
        "    entry 2:\n        authorizations (1): partition_id\n"
        "        don't-require-password\n"
        f"        description: {parts}\n"
        "        applications: <null>\n"
        "    entry 3:\n        authorizations (1): change_acl\n"
        "        applications (0):\n"
    )


def test_acl_parse_keeps_status_requirement_and_partitions():
    items = browser._keychain_acl_apps(_dump(APP_OK), "Chromium Safe Storage")
    assert items == [
        browser.KeychainAclItem(
            (browser.KeychainAclApp(APP_OK, -2147415734, CD_OK),),
            (f"cdhash:{CD_OK}",),
        )
    ]
    assert browser._keychain_acl_apps(_dump(APP_OK), "Nope") is None
    ok = browser._keychain_acl_apps(_dump(APP_OK, status="OK"), "Chromium Safe Storage")
    assert ok is not None and ok[0].apps[0].status == 0


@pytest.mark.parametrize(
    ("dump", "cdhash", "want"),
    [
        # the live 1248 shape: unsealed status, requirement == CDHash, partitioned
        (_dump(APP_OK), CD_OK, "granted"),
        (_dump(APP_OK, status="OK"), CD_OK, "granted"),
        # status non-OK (build gone) → unknown
        (_dump(APP_OK, status="status -67068"), CD_OK, "unknown"),
        # unsealed status but the requirement names another binary → unknown
        (_dump(APP_OK, req={APP_OK: CD_NEW}), CD_OK, "unknown"),
        # CDHash missing from the partition list → unknown
        (_dump(APP_OK, status="OK", partitions=[f"cdhash:{CD_NEW}"]), CD_OK, "unknown"),
        (_dump(APP_OK, status="OK", partitions=["teamid:X"]), CD_OK, "unknown"),
        # the binary's CDHash unreadable → unknown
        (_dump(APP_OK, status="OK"), None, "unknown"),
        # not listed at all → missing
        (_dump(APP_NEW), CD_OK, "missing"),
    ],
)
def test_acl_verdict(dump, cdhash, want):
    items = browser._keychain_acl_apps(dump, "Chromium Safe Storage")
    assert browser._keychain_acl_verdict(items, APP_OK, cdhash) == want


def test_cdhash_from_codesign(monkeypatch):
    out = (
        "Identifier=Google Chrome for Testing\n"
        f"CandidateCDHash sha256={CD_OK}\nCDHash={CD_OK.upper()}\n"
    )

    def run(argv, **kw):
        assert argv == ["codesign", "-dvvv", APP_OK]
        return browser.subprocess.CompletedProcess(argv, 0, b"", out.encode())

    monkeypatch.setattr(browser.subprocess, "run", run)
    assert browser._chromium_cdhash(APP_OK) == CD_OK

    def fail(argv, **kw):
        return browser.subprocess.CompletedProcess(argv, 1, b"", b"not signed")

    monkeypatch.setattr(browser.subprocess, "run", fail)
    assert browser._chromium_cdhash(APP_OK) is None


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
    monkeypatch.setattr(browser, "_chromium_cdhash", CDHASH.get)
    return cache


def test_grant_state_granted_cached_per_revision(acl_cache, monkeypatch):
    sec = _Sec(_dump(APP_OK))
    monkeypatch.setattr(browser, "_security_run", sec)
    assert browser._keychain_grant_state(1248, APP_OK, CD_OK, now=1000.0) == "granted"
    assert browser._keychain_grant_state(1248, APP_OK, CD_OK, now=9e9) == "granted"
    assert sec.calls == 1
    assert json.loads(acl_cache.read_text())["1248"] == {
        "app": APP_OK,
        "cdhash": CD_OK,
        "state": "granted",
        "at": 1000.0,
    }
    # a rebuilt binary (new CDHash) or a pre-B2c entry is re-checked
    browser._keychain_grant_state(1248, APP_OK, CD_NEW, now=9e9)
    assert sec.calls == 2
    acl_cache.write_text(json.dumps({"1248": {"app": APP_OK, "state": "granted"}}))
    browser._keychain_grant_state(1248, APP_OK, CD_OK, now=9e9)
    assert sec.calls == 3


def test_grant_state_missing_rechecked_after_ttl(acl_cache, monkeypatch):
    sec = _Sec(_dump(APP_OK))
    monkeypatch.setattr(browser, "_security_run", sec)
    assert browser._keychain_grant_state(1254, APP_NEW, CD_NEW, now=1000.0) == "missing"
    assert browser._keychain_grant_state(1254, APP_NEW, CD_NEW, now=1100.0) == "missing"
    assert sec.calls == 1
    sec.out = _dump(APP_OK, APP_NEW)  # Albert clicked "Always Allow"
    ttl = browser.KEYCHAIN_ACL_MISS_TTL_S
    now = 1001.0 + ttl
    assert browser._keychain_grant_state(1254, APP_NEW, CD_NEW, now=now) == "granted"
    assert sec.calls == 2


def test_grant_state_absent_unknown_error_not_cached(acl_cache, monkeypatch):
    monkeypatch.setattr(browser, "_security_run", _Sec(_dump(APP_OK, service="x")))
    assert browser._keychain_grant_state(1254, APP_NEW, CD_NEW) == "absent"
    bad = _dump(APP_NEW, status="status -67068")
    monkeypatch.setattr(browser, "_security_run", _Sec(bad))
    assert browser._keychain_grant_state(1254, APP_NEW, CD_NEW) == "unknown"
    monkeypatch.setattr(browser, "_security_run", _Sec(_dump(APP_NEW)))
    assert browser._keychain_grant_state(1254, APP_NEW, None) == "unknown"
    monkeypatch.setattr(browser, "_security_run", _Sec("", rc=51))
    assert browser._keychain_grant_state(1254, APP_NEW, CD_NEW) == "error"
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


def test_gate_query_error_never_refuses(acl_cache, monkeypatch, capsys):
    def boom(argv, **kw):
        raise RuntimeError("denied")

    monkeypatch.setattr(browser, "_security_run", boom)
    monkeypatch.setenv("AGENT_LOGIN_SCHEDULED", "1")
    assert browser._keychain_grant_gate(BIN_NEW) is None
    assert "not checked" in capsys.readouterr().err


@pytest.mark.parametrize(
    "dump",
    [
        _dump(APP_NEW, status="status -67068"),  # status non-OK → unknown
        _dump(APP_NEW, partitions=[f"cdhash:{CD_OK}"]),  # cdhash not partitioned
    ],
)
def test_gate_unknown_refuses_unattended_warns_attended(
    acl_cache, monkeypatch, capsys, dump
):
    monkeypatch.setattr(browser, "_security_run", _Sec(dump))
    monkeypatch.setattr(browser, "_chromium_revision", lambda: 1254)
    monkeypatch.setenv("AGENT_LOGIN_SCHEDULED", "1")
    msg = browser._keychain_grant_gate(BIN_NEW)
    assert msg is not None and "grant is unknown" in msg
    assert f"grant needed: {browser.CHROMIUM_BUMP_RUNBOOK}" in msg
    monkeypatch.delenv("AGENT_LOGIN_SCHEDULED")
    assert browser._keychain_grant_gate(BIN_NEW) is None
    assert "grant is unknown" in capsys.readouterr().err


def test_gate_unknown_without_cdhash(acl_cache, monkeypatch):
    monkeypatch.setattr(browser, "_security_run", _Sec(_dump(APP_NEW)))
    monkeypatch.setattr(browser, "_chromium_revision", lambda: 1254)
    monkeypatch.setattr(browser, "_chromium_cdhash", lambda app: None)
    monkeypatch.setenv("AGENT_LOGIN_SCHEDULED", "1")
    msg = browser._keychain_grant_gate(BIN_NEW)
    assert msg is not None and "(unreadable)" in msg


def test_runbook_exists():
    assert browser.CHROMIUM_BUMP_RUNBOOK.is_file()


def test_app_path_of_bundle_and_bare_binary():
    assert browser._chromium_app_path(BIN_NEW) == APP_NEW
    assert browser._chromium_app_path("/x/chrome") == "/x/chrome"
