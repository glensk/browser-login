#!/usr/bin/env python3
"""Magic-link extraction, the login-frequency log, JSON state and site dispatch.

No real mail, browser or keychain: himalaya is a stubbed `subprocess.run`, the
login log lives in a throwaway directory, and store/forget are stubbed per site.

Run: python3 -m pytest tests/ -q     (from the repo root)
"""

from __future__ import annotations

# Tests reach into browser.py's private helpers on purpose (it is a script, not
# a package, so there is no public API), and build throwaway stub classes.
# pylint: disable=protected-access,import-outside-toplevel,too-few-public-methods
# pylint: disable=missing-function-docstring,missing-class-docstring,import-error
# pylint: disable=unused-argument
import importlib.util
import json
import sys
from pathlib import Path

import pytest

_BROWSER_PY = Path(__file__).resolve().parent.parent / "bin" / "browser.py"


def _load_browser_module():
    """Import bin/browser.py as a module (it has no module-level playwright import)."""
    spec = importlib.util.spec_from_file_location("browser_under_test", _BROWSER_PY)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["browser_under_test"] = mod
    spec.loader.exec_module(mod)
    return mod


browser = _load_browser_module()

LINK = "https://claude.ai/magic-link#abc123:dXNlckBleGFtcGxlLmNvbQ=="


class _Res:
    def __init__(self, returncode: int = 0, stdout: str = "", stderr: str = ""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


# --- magic link ------------------------------------------------------------------


@pytest.mark.parametrize(
    "body, want",
    [
        (f"Click: {LINK}\nthanks", LINK),
        (f"<a href='{LINK}'>Sign in</a>", LINK),
        ("https://claude.ai.evil.example/magic-link#abc", None),
        ("https://evil.example/magic-link#abc", None),
        ("http://claude.ai/magic-link#abc", None),
        ("https://claude.ai/magic-link?abc", None),
        ("https://click.mail.anthropic.com/ls/click?upn=tracking", None),
    ],
)
def test_magic_link_regex_is_host_and_scheme_anchored(body, want):
    m = browser._MAGIC_LINK_RE.search(body)
    assert (m.group(0) if m else None) == want


def test_extract_magic_link_reads_the_message(monkeypatch):
    seen: list[list[str]] = []

    def fake_run(argv, **kwargs):
        seen.append(argv)
        assert kwargs["timeout"]
        return _Res(0, f"Subject: x\n\n{LINK}\n")

    monkeypatch.setattr(browser.subprocess, "run", fake_run)
    assert browser._himalaya_extract_magic_link("himalaya", "Archive", "42") == LINK
    assert seen[0][:4] == ["himalaya", "message", "read", "42"]
    assert seen[0][seen[0].index("--folder") + 1] == "Archive"


@pytest.mark.parametrize("res", [_Res(1, LINK, "boom"), _Res(0, "no link here")])
def test_extract_magic_link_failure_is_none(monkeypatch, res):
    monkeypatch.setattr(browser.subprocess, "run", lambda argv, **k: res)
    assert browser._himalaya_extract_magic_link("himalaya", "INBOX", "1") is None


def test_himalaya_date_epoch():
    assert browser._himalaya_date_epoch("1970-01-01 00:01+00:00") == 60.0
    assert browser._himalaya_date_epoch("1970-01-01 01:01+01:00") == 60.0
    assert browser._himalaya_date_epoch("yesterday") == 0.0


def _mail_env(date: str, to: str = "me@x.ch", mid: str = "1") -> dict:
    return {
        "id": mid,
        "subject": "Your secure link to Claude.ai is here | 1",
        "from": {"addr": "no-reply-a@mail.anthropic.com"},
        "to": {"addr": to},
        "date": date,
    }


def _serve_inbox(monkeypatch, envs: list[dict]):
    def fake_run(argv, **kwargs):
        folder = argv[argv.index("--folder") + 1]
        return _Res(0, json.dumps(envs if folder == "INBOX" else []))

    monkeypatch.setattr(browser.subprocess, "run", fake_run)


def test_mail_clearly_older_than_the_trigger_is_skipped(monkeypatch):
    # trigger at 00:10; a mail stamped 00:06 (> 3 min before) is a previous run's.
    _serve_inbox(monkeypatch, [_mail_env("1970-01-01 00:06+00:00")])
    assert browser._himalaya_latest_login_mail("h", "me@x.ch", 600.0) is None


def test_minute_truncated_date_within_tolerance_is_accepted(monkeypatch):
    # himalaya dates have minute precision: 00:09 may be 00:09:59 > trigger.
    _serve_inbox(monkeypatch, [_mail_env("1970-01-01 00:09+00:00")])
    assert browser._himalaya_latest_login_mail("h", "me@x.ch", 600.0) == ("INBOX", "1")


def test_newest_mail_wins(monkeypatch):
    _serve_inbox(
        monkeypatch,
        [
            _mail_env("1970-01-01 00:10+00:00", mid="old"),
            _mail_env("1970-01-01 00:12+00:00", mid="new"),
        ],
    )
    assert browser._himalaya_latest_login_mail("h", "", 600.0) == ("INBOX", "new")


def test_mail_to_another_recipient_is_skipped(monkeypatch):
    _serve_inbox(monkeypatch, [_mail_env("1970-01-01 00:10+00:00", to="x@y.ch")])
    diag: list[str] = []
    assert browser._himalaya_latest_login_mail("h", "me@x.ch", 600.0, diag=diag) is None
    assert any("x@y.ch" in d for d in diag)


# --- JSON state -------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw, want",
    [
        (b'{"a": 1}', {"a": 1}),
        (b"[1, 2]", None),
        (b"{trunc", None),
        (b"\xff\xfe\x00", None),
    ],
)
def test_read_json_dict(tmp_path, raw, want):
    p = tmp_path / "f.json"
    p.write_bytes(raw)
    assert browser._read_json_dict(p) == want


def test_read_json_dict_absent(tmp_path):
    assert browser._read_json_dict(tmp_path / "missing.json") is None


# --- login log --------------------------------------------------------------------


@pytest.fixture
def logdir(tmp_path, monkeypatch):
    d = tmp_path / "login-log"
    monkeypatch.setattr(browser, "LOGIN_LOG_DIR", d)
    return d


def test_login_event_roundtrip(logdir):
    browser._record_login_event("cscs", "keychain")
    browser._record_login_event("cscs", "1password")
    events = browser._load_login_events("cscs")
    assert [e["mode"] for e in events] == ["keychain", "1password"]
    assert all(e["site"] == "cscs" and isinstance(e["ts"], float) for e in events)
    assert browser._load_login_events("slack") == []


def test_record_login_event_never_raises(tmp_path, monkeypatch):
    blocker = tmp_path / "file"
    blocker.write_text("")
    monkeypatch.setattr(browser, "LOGIN_LOG_DIR", blocker / "sub")  # mkdir fails
    browser._record_login_event("cscs", "keychain")


def test_login_log_per_site_and_aggregate(logdir, capsys):
    browser._record_login_event("cscs", "keychain")
    browser._record_login_event("anthropic", "assisted")
    assert browser.cmd_login_log("portal") == 0  # alias resolves
    out = capsys.readouterr().out
    assert "'cscs': 1 real login(s)" in out and "(keychain)" in out
    assert browser.cmd_login_log(None) == 0
    out = capsys.readouterr().out
    assert "all sites: 2 real login(s)  [1 you had to sign in]" in out


def test_login_log_empty(logdir, capsys):
    assert browser.cmd_login_log(None) == 0
    assert "No real logins recorded" in capsys.readouterr().out


# --- site dispatch ------------------------------------------------------------------


@pytest.mark.parametrize(
    "name, site",
    [
        ("cscs", "cscs"),
        ("  Portal ", "cscs"),
        ("Claude.AI", "anthropic"),
        ("oai", "openai"),
        ("edificom", "biopolwifi"),
        ("scp", "switch"),
    ],
)
def test_resolve_site_by_name_or_alias(name, site):
    assert browser._resolve_site(name).name == site


def test_resolve_unknown_site_exits_2_with_the_list(capsys):
    with pytest.raises(SystemExit) as exc:
        browser._resolve_site("nope")
    assert exc.value.code == 2
    err = capsys.readouterr().err
    assert "Unknown site" in err and "biopolwifi" in err


def test_site_names_and_aliases_are_unique():
    keys = [k for s in browser._sites() for k in (s.name, *s.aliases)]
    assert len(keys) == len(set(keys))


def test_store_and_forget_creds_refused_for_assisted_sites(capsys):
    assert browser.cmd_store_creds("anthropic") == 1
    assert browser.cmd_forget_creds("slack") == 1
    err = capsys.readouterr().err
    assert "assisted login" in err and "no stored credentials" in err


def test_store_creds_dispatches_to_the_site(monkeypatch):
    monkeypatch.setattr(browser, "cmd_cscs_store_creds", lambda: 7)
    monkeypatch.setattr(browser, "cmd_biopolwifi_forget_creds", lambda: 8)
    assert browser.cmd_store_creds("cscs") == 7
    assert browser.cmd_forget_creds("biopol") == 8


def test_extract_magic_link_reads_from_the_same_account(monkeypatch):
    # Regression: the envelope search honoured ANTHROPIC_LOGIN_HIMALAYA_ACCOUNT
    # but `message read` did not, so the id found in account X was looked up in
    # the DEFAULT account — a different mailbox, a different message.
    seen: list[list[str]] = []

    def fake_run(argv, **kwargs):
        seen.append(argv)
        return _Res(0, LINK)

    monkeypatch.setattr(browser.subprocess, "run", fake_run)
    browser._himalaya_extract_magic_link("himalaya", "INBOX", "7", account="epfl")
    assert seen[-1][seen[-1].index("-a") + 1] == "epfl"
    browser._himalaya_extract_magic_link("himalaya", "INBOX", "7")
    assert "-a" not in seen[-1]


def test_auto_login_reads_the_link_from_the_configured_account(monkeypatch):
    from playwright.sync_api import Error as PlaywrightError

    calls: list[tuple] = []
    monkeypatch.setenv("ANTHROPIC_LOGIN_HIMALAYA_ACCOUNT", "epfl")
    monkeypatch.setattr(browser, "_claude_fill_email_and_continue", lambda p, e: True)
    monkeypatch.setattr(
        browser,
        "_himalaya_latest_login_mail",
        lambda h, e, ts, account=None, diag=None: ("INBOX", "7"),
    )

    def fake_extract(himalaya, folder, msg_id, account=None):
        calls.append((folder, msg_id, account))
        return LINK

    monkeypatch.setattr(browser, "_himalaya_extract_magic_link", fake_extract)

    class _Page:
        def goto(self, url, **kwargs):
            raise PlaywrightError("stop here")

    assert browser._claude_auto_login(_Page(), "me@x.ch", "himalaya") is False
    assert calls == [("INBOX", "7", "epfl")]
