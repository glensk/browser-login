"""console-balance.py and the Claude Console sites (tp#1421) — fixtures only, no browser."""

from __future__ import annotations

# pylint: disable=protected-access,import-outside-toplevel,missing-function-docstring
# pylint: disable=import-error
import importlib.util
import json
import stat
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


cb = _load("console_balance_under_test", _REPO / "console-balance.py")

# What PAGE_JS answers for the work org (shape read from the live page, 2026-10-29;
# amounts as the Console sends them: minor units, credit objects with an exponent).
PAGE = {
    "state": "ok",
    "email": "albert.glensk@epfl.ch",
    "org_name": "Example Org",
    "credits_status": 200,
    "currency": "USD",
    "purchased_minor": 10000,
    "promo": [
        {
            "remaining_minor": 49803,
            "granted_minor": 50000,
            "remaining_credit": {"amount_minor": 49803, "exponent": 2},
            "granted_credit": {"amount_minor": 50000, "exponent": 2},
            "currency": "USD",
            "expires_at": "2026-11-22T00:00:00Z",
            "granted_at": "2026-10-19T13:43:08.833000Z",
            "name": "API credit (Team)",
            "program": "subscription_api_credit",
        }
    ],
    "spend_status": 200,
    "spent_minor": 15389,
    "resets_at": "2026-11-01T00:00:00Z",
    "limits_status": 200,
    "enforced_limit_minor": 50000,
    "org_limit_text": (
        "Organization limit\nSet a monthly spend limit for your organization and get "
        "notified as you approach it.\n$153.89 spent\nResets Nov 1, 2026 (UTC)\n31% used\n"
        "Monthly spend limit\n$500\nAdjust limit\n"
    ),
}


def test_parse_page_reads_promo_purchased_and_cap() -> None:
    got = cb.parse_page(PAGE)
    assert got["purchased_usd"] == 100.0 and got["currency"] == "USD"
    assert got["promo"] == [
        {
            "remaining_usd": 498.03,
            "granted_usd": 500.0,
            "expires_at": "2026-11-22T00:00:00Z",
            "granted_at": "2026-10-19T13:43:08.833000Z",
            "name": "API credit (Team)",
        }
    ]
    assert got["cap"] == {
        "spent_usd": 153.89,
        "limit_usd": 500.0,
        "resets_at": "2026-11-01T00:00:00Z",
        "source": "page",
    }


def test_limit_text_with_thousands_and_a_disagreeing_data_limit() -> None:
    raw = dict(
        PAGE,
        org_limit_text="Organization limit\n$1.97 spent\nResets Nov 1, 2026 (UTC)\n0% used\n"
        "Monthly spend limit\n$200,000\nAdjust limit",
        spent_minor=197,
        enforced_limit_minor=40000,
    )
    cap = cb.parse_cap(raw)
    assert cap["limit_usd"] == 200000.0 and cap["spent_usd"] == 1.97
    assert cap["data_limit_usd"] == 400.0  # the page wins, the disagreement is kept


def test_cap_from_data_when_the_page_text_is_missing() -> None:
    cap = cb.parse_cap(dict(PAGE, org_limit_text=""))
    assert cap == {
        "spent_usd": 153.89,
        "limit_usd": 500.0,
        "source": "data",
        "resets_at": "2026-11-01T00:00:00Z",
    }
    assert cb.parse_cap(dict(PAGE, org_limit_text="", limits_status=500)) is None


def test_a_half_reading_is_never_good() -> None:
    with pytest.raises(ValueError):
        cb.parse_page(dict(PAGE, credits_status=403))
    with pytest.raises(ValueError):
        cb.parse_page(dict(PAGE, promo=[{"remaining_minor": None, "expires_at": "x"}]))


class _Run:
    def __init__(self, rc: int, stdout: str) -> None:
        self.rc, self.stdout, self.killed = rc, stdout, False


@pytest.fixture(name="fake_browser")
def _fake_browser(monkeypatch: pytest.MonkeyPatch):
    """`read_account` against a canned page answer; no browser instance."""
    import contextlib

    answer: dict[str, Any] = {"rc": 0, "page": PAGE}

    @contextlib.contextmanager
    def instance(_inst: str):
        yield True

    def run_browser(*_a: Any, **_k: Any) -> _Run:
        return _Run(answer["rc"], json.dumps(json.dumps(answer["page"])) + "\n")

    monkeypatch.setattr(cb, "instance", instance)
    monkeypatch.setattr(cb, "run_browser", run_browser)
    return answer


@pytest.mark.usefixtures("fake_browser")
def test_run_writes_a_0600_file_atomically(tmp_path: Path) -> None:
    status, data = cb.run_account("work", tmp_path, force=False, dry_run=False)
    assert status == "ok" and data["status"] == "ok" and data["measured_at"]
    path = tmp_path / "work.json"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    on_disk = json.loads(path.read_text())
    assert on_disk["promo"][0]["remaining_usd"] == 498.03 and on_disk["schema"] == 1
    assert not [p for p in tmp_path.iterdir() if p.name.startswith(".")]


def test_logged_out_keeps_the_last_good_figures_and_backs_off(
    tmp_path: Path, fake_browser: dict
) -> None:
    _status, good = cb.run_account("work", tmp_path, force=False, dry_run=False)
    fake_browser["page"] = {"state": "logged_out"}
    status, data = cb.run_account("work", tmp_path, force=False, dry_run=False)
    assert status == "logged_out" and data["status"] == "logged_out"
    assert data["measured_at"] == good["measured_at"] and data["promo"] == good["promo"]
    # Within the back-off the next run does not touch the browser.
    fake_browser["rc"] = 99
    assert cb.run_account("work", tmp_path, force=False, dry_run=False)[0] == "skipped"
    assert (
        cb.run_account("work", tmp_path, force=True, dry_run=False)[0] == "page_error"
    )


def test_wrong_account_and_browser_errors_are_typed(
    tmp_path: Path, fake_browser: dict
) -> None:
    fake_browser["page"] = dict(PAGE, email="someone@example.org")
    assert (
        cb.run_account("work", tmp_path, force=True, dry_run=True)[0] == "wrong_account"
    )
    fake_browser["rc"] = 75
    assert cb.run_account("work", tmp_path, force=True, dry_run=True)[0] == "busy"
    fake_browser["rc"] = 124
    assert cb.run_account("work", tmp_path, force=True, dry_run=True)[0] == "timeout"
    assert not (tmp_path / "work.json").exists()  # -n wrote nothing


def test_main_exit_codes(tmp_path: Path, fake_browser: dict, capsys) -> None:
    assert cb.main(["-a", "work", "-o", str(tmp_path)]) == 0
    assert "✅ work: promo $498.03 of $500.00" in capsys.readouterr().out
    fake_browser["page"] = {"state": "logged_out"}
    assert cb.main(["-a", "work", "-o", str(tmp_path), "-f"]) == 2
    assert "❌ work: logged_out" in capsys.readouterr().out


def test_console_sites_are_wired_per_account() -> None:
    import agent_login_claude as alc

    assert (
        alc.browser_site("console") == alc.browser_site("console-private") == "console"
    )
    assert alc.SITE_INSTANCE["console-private"] == "private"
    assert "console" not in alc.SITE_INSTANCE
    assert alc.CONSOLE_ACCOUNTS["console"] == alc.CLAUDE_ACCOUNTS["anthropic"]
    assert (
        alc.CONSOLE_ACCOUNTS["console-private"]
        == alc.CLAUDE_ACCOUNTS["anthropic-private"]
    )


def test_browser_registers_the_console_site() -> None:
    browser = _load("browser_console_under_test", _REPO / "bin" / "browser.py")
    names = {s.name: s for s in browser._sites()}
    assert names["console"].logged_in is browser.cmd_console_logged_in
    assert "platform.claude.com" in names["console"].aliases
    assert browser.GUIDED_START_URLS["console"] == "https://platform.claude.com/login"


def test_the_hourly_launchagent_runs_the_reader_quietly() -> None:
    import agent_login_jobs as jobs

    plists = {label: text for label, text, _what in jobs.agent_plists()}
    text = plists[jobs.CONSOLE_BALANCE_LABEL]
    assert str(jobs.CONSOLE_BALANCE_PY) in text and "<string>-q</string>" in text
    assert (
        "<integer>3600</integer>" in text and f"<key>{jobs.SCHEDULED_ENV}</key>" in text
    )


def test_console_magic_link_is_its_own_host(monkeypatch: pytest.MonkeyPatch) -> None:
    import base64

    browser = _load("browser_console_ml_under_test", _REPO / "bin" / "browser.py")
    tail = base64.b64encode(b"me@example.org").decode()
    console = f"https://platform.claude.com/magic-link#tok123:{tail}"
    claude = f"https://claude.ai/magic-link#tok123:{tail}"
    assert (
        browser._magic_link_email(console, browser._CONSOLE_MAGIC_LINK_RE)
        == "me@example.org"
    )
    # A claude.ai link never passes for a Console link, nor the other way round.
    assert browser._magic_link_email(claude, browser._CONSOLE_MAGIC_LINK_RE) is None
    assert browser._magic_link_email(console) is None
    monkeypatch.delenv("ANTHROPIC_LOGIN_MAIL_FOLDERS", raising=False)
    assert browser._login_mail_folders() == ("INBOX", "Archive")
    monkeypatch.setenv("ANTHROPIC_LOGIN_MAIL_FOLDERS", " INBOX , ")
    assert browser._login_mail_folders() == ("INBOX",)


def test_l_routes_the_console_accounts_to_their_mailbox(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import agent_login_safari as alsafari

    monkeypatch.delenv("CONSOLE_PRIVATE_HIMALAYA_ACCOUNT", raising=False)
    al = _load("agent_login_console_under_test", _REPO / "agent-login.py")
    assert {"console", "console-private"} <= alsafari.MAGIC_LINK_SITES
    env = al._magic_link_env("console-private")
    assert env["CONSOLE_LOGIN_EMAIL"] == al.CONSOLE_ACCOUNTS["console-private"]
    assert env["ANTHROPIC_LOGIN_HIMALAYA_ACCOUNT"] == "gmail"
    assert env["ANTHROPIC_LOGIN_MAIL_FOLDERS"] == "INBOX"
    assert al._magic_link_env("console") == {
        "CONSOLE_LOGIN_EMAIL": al.CONSOLE_ACCOUNTS["console"]
    }
    assert al._magic_link_env("anthropic") == {
        "ANTHROPIC_LOGIN_EMAIL": al.CLAUDE_ACCOUNTS["anthropic"]
    }
    # tp#1426: claude.ai of the Gmail address reads the same Gmail INBOX
    env = al._magic_link_env("anthropic-private")
    assert env == {
        "ANTHROPIC_LOGIN_EMAIL": al.CLAUDE_ACCOUNTS["anthropic-private"],
        "ANTHROPIC_LOGIN_HIMALAYA_ACCOUNT": "gmail",
        "ANTHROPIC_LOGIN_MAIL_FOLDERS": "INBOX",
    }
