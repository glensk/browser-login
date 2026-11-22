"""Cookie migration and the profile ``Last Version`` guard (tp#2537 B2b).

Chrome 158 (chromium-1254) reads and writes its cookies with a new key (``v11``
rows, feature ``KeychainKeyProviderUserDataDirProtection``) and deletes every
``v10`` row Chrome 156 (chromium-1248) wrote. Pinned here:

* a synthetic Cookies db (meta version 24) goes through the CDP export/import
  path (mock CDP) and keeps its persistent row count; Cloudflare Access team
  cookies are never moved and the team sweep runs in a ``finally``;
* the pre-launch ``Last Version`` guard refuses an unattended
  (``AGENT_LOGIN_SCHEDULED``) launch naming the runbook and backs up + migrates
  an attended one;
* the backup records row counts and the rollback restores them, checked.

Hermetic: every path lives in tmp_path, no browser, no real ``security``.

Run: uv run --no-sync pytest tests/test_cookie_migration_tp2537.py -q
"""

from __future__ import annotations

# pylint: disable=protected-access,missing-function-docstring,import-error
# pylint: disable=redefined-outer-name,unused-argument
import importlib.util
import json
import sqlite3
import sys
from pathlib import Path
from typing import Any

import pytest

_REPO = Path(__file__).resolve().parent.parent


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


browser = _load("browser_cookie_migration_test", _REPO / "bin" / "browser.py")

OLD_BIN = "/c/chromium-1248/chrome-mac-arm64/Old.app/Contents/MacOS/Old"
NEW_BIN = "/c/chromium-1254/chrome-mac-arm64/New.app/Contents/MacOS/New"
VERSIONS = {OLD_BIN: "156.0.8078.4", NEW_BIN: "158.0.8127.18"}


@pytest.fixture(autouse=True)
def _no_team_domain(monkeypatch):
    monkeypatch.setattr(
        browser._access_team, "configured_team_domain", lambda: ("", "test")
    )
    monkeypatch.delenv(browser.SCHEDULED_ENV, raising=False)


def _v24_db(path: Path, rows: list[tuple[str, str, int]]) -> Path:
    """A Chrome-shaped Cookies db, meta version 24: (host_key, name, persistent)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT)")
    con.executemany(
        "INSERT INTO meta VALUES (?, ?)",
        [("version", "24"), ("last_compatible_version", "24")],
    )
    con.execute(
        "CREATE TABLE cookies (host_key TEXT, name TEXT, path TEXT, "
        "encrypted_value BLOB, expires_utc INTEGER, is_secure INTEGER, "
        "is_httponly INTEGER, is_persistent INTEGER)"
    )
    con.executemany(
        "INSERT INTO cookies VALUES (?, ?, '/', ?, 13500000000000000, 1, 0, ?)",
        [(h, n, b"v10" + b"\0" * 16, p) for h, n, p in rows],
    )
    con.commit()
    con.close()
    return path


def _db_as_cdp(path: Path) -> list[dict[str, Any]]:
    """What `Storage.getCookies` returns for the db's rows (no real values)."""
    con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        rows = con.execute(
            "SELECT host_key, name, path, is_secure, is_httponly, is_persistent "
            "FROM cookies"
        ).fetchall()
    finally:
        con.close()
    return [
        {
            "name": n,
            "value": "x",
            "domain": h,
            "path": p,
            "expires": 2.0e9 if pers else -1,
            "size": 2,
            "httpOnly": bool(ho),
            "secure": bool(s),
            "session": not pers,
            "priority": "Medium",
            "sourceScheme": "Secure",
            "sourcePort": 443,
        }
        for h, n, p, s, ho, pers in rows
    ]


class FakeJar:
    """A browser-level CDP jar: `Storage.setCookies` / `Storage.getCookies`."""

    def __init__(self, refuse: set[str] | None = None) -> None:
        self.jar: dict[tuple[str, str, str], dict] = {}
        self.refuse = refuse or set()
        self.batches = 0

    def send(self, method: str, params: dict) -> dict:
        if method == "Storage.getCookies":
            return {"cookies": [{"session": False, **c} for c in self.jar.values()]}
        if method == "Browser.close":
            return {}
        assert method == "Storage.setCookies"
        self.batches += 1
        cookies = params["cookies"]
        if any(c["name"] in self.refuse for c in cookies):
            raise RuntimeError("Invalid cookie fields")
        for c in cookies:
            if "url" in c:
                assert "domain" not in c  # host-only identity by url only
                host = c["url"].split("://", 1)[1].split("/", 1)[0]
            else:
                host = c["domain"]
            if c.get("expires") == 1:
                self.jar.pop((host, c["name"], c["path"]), None)
                continue
            self.jar[(host, c["name"], c["path"])] = dict(c, domain=host)
        return {}


ROWS = [(f"h{i}.example.com", f"n{i}", 1) for i in range(40)] + [
    (".example.org", "dom", 1),
    ("team.cloudflareaccess.com", "CF_Authorization", 1),
    ("h0.example.com", "sess", 0),
]


# --- export/import keeps the row count (mock CDP) ------------------------------


def test_synthetic_v24_db_keeps_its_row_count(tmp_path):
    db = _v24_db(tmp_path / "Default" / "Cookies", ROWS)
    exported = _db_as_cdp(db)
    jar = FakeJar()
    res = browser.cookie_import(jar.send, exported)
    # 41 persistent non-Access rows move; the session row and the Access row do not.
    assert (res.written, res.rejected, res.access_skipped) == (41, 0, 1)
    assert len(jar.jar) == 41
    assert not any("cloudflareaccess" in host for host, _n, _p in jar.jar)
    assert jar.batches == 1


def test_import_falls_back_to_one_by_one_on_a_refused_batch():
    cookies = [
        {"name": n, "value": "x", "domain": "a.example", "path": "/", "expires": 2e9}
        for n in ("a", "bad", "c")
    ]
    jar = FakeJar(refuse={"bad"})
    res = browser.cookie_import(jar.send, cookies)
    assert (res.written, res.rejected) == (2, 1)
    assert sorted(n for _h, n, _p in jar.jar) == ["a", "c"]


def test_cookie_param_keeps_host_only_and_domain_identity():
    host = browser._cookie_param(
        {
            "name": "__Host-x",
            "value": "v",
            "domain": "a.example",
            "path": "/p",
            "secure": True,
        }
    )
    assert host["url"] == "https://a.example/p" and "domain" not in host
    dom = browser._cookie_param(
        {"name": "d", "value": "v", "domain": ".a.example", "path": "/", "expires": 5.0}
    )
    assert dom["domain"] == ".a.example" and "url" not in dom and dom["expires"] == 5.0
    assert "size" not in dom and "session" not in dom


def _wire_cdp(monkeypatch, jar: FakeJar, sweeps: list[str]):
    monkeypatch.setattr(browser, "_browser_ws_url", lambda port, timeout=2.0: "ws://x")

    def fake_call(ws_url, method, params=None, budget_s=5.0):
        try:
            return browser.CdpResult("ok", result=jar.send(method, params or {}))
        except RuntimeError as exc:
            return browser.CdpResult("ok", result={}, error=str(exc))

    monkeypatch.setattr(browser, "_cdp_ws_call", fake_call)
    monkeypatch.setattr(
        browser,
        "_access_team_sweep_cdp",
        lambda port, why, budget_s=4.0, quiet=False: sweeps.append(why),
    )
    monkeypatch.setattr(
        browser, "_memory_persistent_cookies", lambda port: len(jar.jar)
    )
    monkeypatch.setattr(browser, "_journal_note", lambda **k: None)


def test_export_then_finish_moves_every_persistent_cookie(
    tmp_path, monkeypatch, capsys
):
    db = _v24_db(tmp_path / "Default" / "Cookies", ROWS)
    old = FakeJar()
    for c in _db_as_cdp(db):  # the old build's in-memory jar
        old.jar[(c["domain"], c["name"], c["path"])] = c
    sweeps: list[str] = []
    _wire_cdp(monkeypatch, old, sweeps)
    monkeypatch.setattr(browser, "_launch_browser", lambda b, f, headless=False: None)
    exported = browser._cookie_export(OLD_BIN, tmp_path)
    assert len(exported) == 42  # the session cookie is never exported
    new = FakeJar()
    _wire_cdp(monkeypatch, new, sweeps)
    mig = browser.CookieMigration(tmp_path / "bk", exported, "156", "158")
    assert browser._cookie_migrate_finish(9999, mig) == 0
    assert len(new.jar) == 41  # all but the Access cookie
    assert sweeps == ["cookie-migrate"]
    assert "cookies migrated" in capsys.readouterr().out


def test_finish_sweeps_in_finally_and_reports_short(tmp_path, monkeypatch, capsys):
    sweeps: list[str] = []
    jar = FakeJar()
    _wire_cdp(monkeypatch, jar, sweeps)

    def boom(send, cookies):
        raise RuntimeError("cdp gone")

    monkeypatch.setattr(browser, "cookie_import", boom)
    mig = browser.CookieMigration(tmp_path / "bk", [{"name": "a"}], "156", "158")
    assert browser._cookie_migrate_finish(9999, mig) == 1
    assert sweeps == ["cookie-migrate"]
    err = capsys.readouterr().err
    assert "cookie-rollback -b" in err and str(tmp_path / "bk") in err


# --- the Last Version guard -----------------------------------------------------


def _profile(tmp_path: Path, last: str = "156.0.8078.4") -> Path:
    prof = tmp_path / "profile"
    _v24_db(prof / "Default" / "Cookies", ROWS)
    (prof / "Last Version").write_text(last)
    (prof / "Local State").write_text("{}")
    (prof / "Default" / "Preferences").write_text("{}")
    return prof


def _wire_versions(monkeypatch, installed: list[str]):
    monkeypatch.setattr(browser, "_chromium_build_version", VERSIONS.get)
    monkeypatch.setattr(
        browser,
        "_chromium_builds_by_major",
        lambda major: [b for b in installed if VERSIONS[b].startswith(f"{major}.")],
    )


@pytest.mark.parametrize(
    ("pmaj", "bmaj", "want"),
    [
        (156, 158, "upgrade"),
        (158, 156, "downgrade"),
        (156, 156, "same"),
        (None, 158, "unknown"),
    ],
)
def test_version_verdict(pmaj, bmaj, want):
    assert browser.profile_version_verdict(pmaj, bmaj) == want


def test_guard_refuses_unattended(tmp_path, monkeypatch):
    prof = _profile(tmp_path)
    _wire_versions(monkeypatch, [OLD_BIN, NEW_BIN])
    monkeypatch.setenv(browser.SCHEDULED_ENV, "1")
    gate = browser._profile_version_gate(NEW_BIN, prof)
    assert gate.export_with is None
    assert gate.refusal and str(browser.CHROMIUM_BUMP_RUNBOOK) in gate.refusal
    assert "156.0.8078.4" in gate.refusal and "158.0.8127.18" in gate.refusal


def test_guard_attended_picks_the_old_build(tmp_path, monkeypatch):
    prof = _profile(tmp_path)
    _wire_versions(monkeypatch, [OLD_BIN, NEW_BIN])
    gate = browser._profile_version_gate(NEW_BIN, prof)
    assert (gate.refusal, gate.export_with) == (None, OLD_BIN)


def test_guard_attended_without_old_build_refuses(tmp_path, monkeypatch):
    prof = _profile(tmp_path)
    _wire_versions(monkeypatch, [NEW_BIN])
    gate = browser._profile_version_gate(NEW_BIN, prof)
    assert gate.refusal and "no installed Chrome 156" in gate.refusal


@pytest.mark.parametrize("last", ["158.0.8127.18", None])
def test_guard_passes_same_major_and_fresh_profile(tmp_path, monkeypatch, last):
    prof = _profile(tmp_path, last or "")
    _wire_versions(monkeypatch, [OLD_BIN, NEW_BIN])
    monkeypatch.setenv(browser.SCHEDULED_ENV, "1")
    gate = browser._profile_version_gate(NEW_BIN, prof)
    assert (gate.refusal, gate.export_with) == (None, None)


def test_guard_downgrade_only_warns(tmp_path, monkeypatch, capsys):
    prof = _profile(tmp_path, "158.0.8127.18")
    _wire_versions(monkeypatch, [OLD_BIN])
    gate = browser._profile_version_gate(OLD_BIN, prof)
    assert (gate.refusal, gate.export_with) == (None, None)
    assert "cookie-rollback" in capsys.readouterr().err


def _wire_launch(monkeypatch, tmp_path, prof: Path, calls: list[str]):
    monkeypatch.setattr(browser, "CACHE_DIR", tmp_path / "state")
    monkeypatch.setattr(browser, "PROFILE_DIR", prof)
    monkeypatch.setattr(browser, "_launch_guard", lambda port: None)
    monkeypatch.setattr(browser, "_clear_session_restore", lambda: 0)
    monkeypatch.setattr(browser, "_chromium_binary", lambda: NEW_BIN)
    monkeypatch.setattr(browser, "_keychain_grant_gate", lambda b: None)
    monkeypatch.setattr(browser, "_apply_profile_prefs", lambda: None)
    monkeypatch.setattr(browser, "_proxy_flags", lambda: [])
    monkeypatch.setattr(browser, "_headless_user_agent", lambda b: None)
    monkeypatch.setattr(browser, "_lifecycle_write", lambda *a, **k: {"nonce": "n"})
    monkeypatch.setattr(browser, "PID_FILE", tmp_path / "state" / "browser.pid")
    monkeypatch.setattr(browser, "_is_up", lambda port: True)
    monkeypatch.setattr(browser, "_record_running", lambda *a, **k: 4242)
    monkeypatch.setattr(browser, "_tabstate_record_startup", lambda port: None)

    def spawn(binary, flags, headless=False):
        calls.append(f"spawn {binary}")
        return 4242

    monkeypatch.setattr(browser, "_launch_browser", spawn)


def test_launch_unattended_refuses_before_any_spawn(tmp_path, monkeypatch, capsys):
    prof = _profile(tmp_path)
    calls: list[str] = []
    _wire_launch(monkeypatch, tmp_path, prof, calls)
    _wire_versions(monkeypatch, [OLD_BIN, NEW_BIN])
    monkeypatch.setenv(browser.SCHEDULED_ENV, "1")
    assert browser._launch_and_record(9999, True) == 1
    assert not calls
    assert "runbook" in capsys.readouterr().err
    assert not (tmp_path / "state" / browser.PROFILE_BACKUP_DIRNAME).exists()


def test_launch_attended_backs_up_exports_and_imports(tmp_path, monkeypatch):
    prof = _profile(tmp_path)
    calls: list[str] = []
    _wire_launch(monkeypatch, tmp_path, prof, calls)
    _wire_versions(monkeypatch, [OLD_BIN, NEW_BIN])
    exported = _db_as_cdp(prof / "Default" / "Cookies")

    def export(binary, profile):
        calls.append(f"export {binary}")
        return [c for c in exported if not c["session"]]

    def finish(port, mig):
        calls.append(f"import {len(mig.cookies)}")
        return 0

    monkeypatch.setattr(browser, "_cookie_export", export)
    monkeypatch.setattr(browser, "_cookie_migrate_finish", finish)
    assert browser._launch_and_record(9999, True) == 0
    assert calls == [f"export {OLD_BIN}", f"spawn {NEW_BIN}", "import 42"]
    (backup,) = (tmp_path / "state" / browser.PROFILE_BACKUP_DIRNAME).iterdir()
    manifest = json.loads((backup / browser.PROFILE_BACKUP_MANIFEST).read_text())
    assert manifest["rows"] == {"Default/Cookies": len(ROWS)}
    assert manifest["last_version"] == "156.0.8078.4"
    assert {
        "Default/Cookies",
        "Local State",
        "Last Version",
        "Default/Preferences",
    } <= set(manifest["items"])


def test_launch_attended_export_failure_does_not_launch(tmp_path, monkeypatch, capsys):
    prof = _profile(tmp_path)
    calls: list[str] = []
    _wire_launch(monkeypatch, tmp_path, prof, calls)
    _wire_versions(monkeypatch, [OLD_BIN, NEW_BIN])

    def export(binary, profile):
        raise RuntimeError("Storage.getCookies failed (timeout)")

    monkeypatch.setattr(browser, "_cookie_export", export)
    assert browser._launch_and_record(9999, True) == 1
    assert not calls
    assert "profile is unchanged" in capsys.readouterr().err


# --- backup and checked rollback ------------------------------------------------


def test_backup_then_rollback_restores_the_recorded_rows(tmp_path):
    prof = _profile(tmp_path)
    _v24_db(prof / "Default" / "Network" / "Cookies", ROWS[:5])
    backup = browser.profile_backup(prof, tmp_path / "bk", "chrome156-to-158")
    assert backup.stat().st_mode & 0o077 == 0
    # What a 1254 first start leaves: the legacy db gone, an empty new jar.
    (prof / "Default" / "Cookies").unlink()
    (prof / "Default" / "Network" / "Cookies").unlink()
    _v24_db(prof / "Default" / "Network" / "Cookies", [])
    (prof / "Last Version").write_text("158.0.8127.18")
    ok, summary = browser.profile_restore(backup, prof)
    assert ok, summary
    assert browser._profile_db_rows(prof) == {
        "Default/Network/Cookies": 5,
        "Default/Cookies": len(ROWS),
    }
    assert (prof / "Last Version").read_text() == "156.0.8078.4"
    # Nothing deleted: the replaced files are kept next to the backup.
    (aside,) = backup.glob("replaced-*")
    assert (aside / "Default" / "Network" / "Cookies").is_file()


def test_rollback_reports_a_count_mismatch(tmp_path):
    prof = _profile(tmp_path)
    backup = browser.profile_backup(prof, tmp_path / "bk", "x")
    manifest = backup / browser.PROFILE_BACKUP_MANIFEST
    data = json.loads(manifest.read_text())
    data["rows"]["Default/Cookies"] = 999
    manifest.write_text(json.dumps(data))
    ok, summary = browser.profile_restore(backup, prof)
    assert not ok and "999" in summary


def test_rollback_cli_refuses_while_the_browser_runs(tmp_path, monkeypatch, capsys):
    prof = _profile(tmp_path)
    monkeypatch.setattr(browser, "CACHE_DIR", tmp_path / "state")
    monkeypatch.setattr(browser, "PROFILE_DIR", prof)
    browser.profile_backup(prof, browser._profile_backup_root(), "x")
    monkeypatch.setattr(browser, "_is_up", lambda port: True)
    assert browser.cmd_cookie_rollback(9999, None, False) == 1
    assert "stop it first" in capsys.readouterr().err
    assert browser.cmd_cookie_rollback(9999, None, True) == 0
