"""tp#490: the claude.ai magic-link auto-login must never open a link it did not ask for.

End-to-end over `_claude_auto_login` / `cmd_anthropic_login` with a fake
mailbox (himalaya = stubbed `subprocess.run`), a fake clock and stub pages —
no real mail, browser or keychain, no real waits.

Run: uv run pytest -q     (from the repo root)
"""

from __future__ import annotations

# Tests reach into browser.py's private helpers on purpose (it is a script, not
# a package, so there is no public API), and build throwaway stub classes.
# pylint: disable=protected-access,import-outside-toplevel,too-few-public-methods
# pylint: disable=missing-function-docstring,missing-class-docstring,import-error
# pylint: disable=unused-argument
import base64
import contextlib
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

ME = "me@example.com"
SUBJECT = "Your secure link to Claude.ai is here | x"
ANTHROPIC = "no-reply-abc@mail.anthropic.com"


def _link(token: str, email: str = ME) -> str:
    return f"https://claude.ai/magic-link#{token}:" + base64.b64encode(
        email.encode()
    ).decode("ascii")


class _Res:
    def __init__(self, returncode: int = 0, stdout: str = "", stderr: str = ""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class Mailbox:
    """INBOX/Archive of (envelope, body); `arrive_after_trigger` is delivered
    once the login form has been submitted."""

    def __init__(self):
        self.folders: dict[str, list[tuple[dict, str]]] = {"INBOX": [], "Archive": []}
        self.pending: list[tuple[str, dict, str]] = []
        self.fail_list: set[str] = set()
        self.fail_read = False
        self.reads: list[list[str]] = []

    def add(self, folder, mid, body, sender=ANTHROPIC, date="2026-09-24 10:00+00:00"):
        env = {
            "id": mid,
            "subject": SUBJECT,
            "from": {"addr": sender},
            "to": {"addr": ME},
            "date": date,
        }
        self.folders[folder].append((env, body))

    def later(self, folder, mid, body, sender=ANTHROPIC):
        env = {
            "id": mid,
            "subject": SUBJECT,
            "from": {"addr": sender},
            "to": {"addr": ME},
            "date": "2026-09-24 10:05+00:00",
        }
        self.pending.append((folder, env, body))

    def deliver(self):
        for folder, env, body in self.pending:
            self.folders[folder].append((env, body))
        self.pending.clear()

    def run(self, argv, **kwargs):
        folder = argv[argv.index("--folder") + 1]
        if argv[1:3] == ["envelope", "list"]:
            if folder in self.fail_list:
                return _Res(1, "", "no such folder")
            return _Res(0, json.dumps([e for e, _ in self.folders[folder]]))
        assert argv[1:3] == ["message", "read"]
        assert "--preview" in argv  # never flip the seen flag
        self.reads.append(argv)
        if self.fail_read:
            return _Res(1, "", "boom")
        mid = argv[3]
        for env, body in self.folders[folder]:
            if env["id"] == mid:
                return _Res(0, f"Subject: {SUBJECT}\n\n{body}\n")
        return _Res(1, "", "not found")


class Page:
    def __init__(self):
        self.gotos: list[str] = []
        self.url = "https://claude.ai/login"

    def goto(self, url, **kwargs):
        self.gotos.append(url)
        self.url = "https://claude.ai/new"

    def wait_for_timeout(self, ms):
        return None


@pytest.fixture(name="mbox")
def fixture_mbox(monkeypatch):
    mbox = Mailbox()
    clock = [0.0]

    def fake_sleep(s):
        clock[0] += s

    monkeypatch.setattr(browser.subprocess, "run", mbox.run)
    monkeypatch.setattr(browser.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(browser.time, "sleep", fake_sleep)
    monkeypatch.setattr(browser.time, "time", lambda: 1_790_244_240.0)  # 10:04Z
    monkeypatch.setenv("ANTHROPIC_LOGIN_MAIL_TIMEOUT", "10")
    monkeypatch.delenv("ANTHROPIC_LOGIN_MAIL_SENDERS", raising=False)
    monkeypatch.delenv("ANTHROPIC_LOGIN_HIMALAYA_ACCOUNT", raising=False)
    monkeypatch.setattr(browser, "_claude_logged_in", lambda page: bool(page.gotos))

    def fill(page, email):
        mbox.deliver()
        return True

    monkeypatch.setattr(browser, "_claude_fill_email_and_continue", fill)
    return mbox


def test_new_matching_mail_is_opened(mbox):
    mbox.later("INBOX", "2", _link("new"))
    page = Page()
    assert browser._claude_auto_login(page, ME, "himalaya") == "ok"
    assert page.gotos == [_link("new")]


def test_baseline_mail_moved_to_archive_is_skipped(mbox, capsys):
    # A link from a previous attempt sat in INBOX when we took the baseline; the
    # server rule moves it to Archive under a new id — it must stay excluded.
    old = _link("old")
    mbox.add("INBOX", "1", old)
    mbox.pending.append(
        (
            "Archive",
            {
                "id": "99",
                "subject": SUBJECT,
                "from": {"addr": ANTHROPIC},
                "to": {"addr": ME},
                "date": "2026-09-24 10:06+00:00",
            },
            old,
        )
    )
    page = Page()
    assert browser._claude_auto_login(page, ME, "himalaya") == "submitted"
    assert not page.gotos
    assert "predates this attempt" in capsys.readouterr().err


def test_foreign_account_link_does_not_starve_a_valid_older_candidate(mbox, capsys):
    mbox.later("INBOX", "2", _link("mine"))
    mbox.pending.append(
        (
            "INBOX",
            {
                "id": "3",
                "subject": SUBJECT,
                "from": {"addr": ANTHROPIC},
                "to": {"addr": ME},
                "date": "2026-09-24 10:09+00:00",  # newest
            },
            _link("theirs", "attacker@evil.example"),
        )
    )
    page = Page()
    assert browser._claude_auto_login(page, ME, "himalaya") == "ok"
    assert page.gotos == [_link("mine")]


def test_mismatched_link_never_reaches_goto(mbox, capsys):
    mbox.later("INBOX", "3", _link("theirs", "attacker@evil.example"))
    page = Page()
    assert browser._claude_auto_login(page, ME, "himalaya") == "submitted"
    assert not page.gotos
    err = capsys.readouterr().err
    assert "different account" in err
    assert "attacker" not in err and "magic-link#" not in err
    # read once, then remembered as rejected — not re-read every round
    assert len([r for r in mbox.reads if r[3] == "3"]) == 1


def test_forged_sender_is_never_read_and_stays_in_the_final_diagnostics(mbox, capsys):
    mbox.later("INBOX", "4", _link("x"), sender="no-reply@evi1-anthropic.example")
    page = Page()
    assert browser._claude_auto_login(page, ME, "himalaya") == "submitted"
    assert not page.gotos
    assert not [r for r in mbox.reads if r[3] == "4"]
    err = capsys.readouterr().err
    assert "no-reply@evi1-anthropic.example" in err
    assert "ANTHROPIC_LOGIN_MAIL_SENDERS" in err


def test_baseline_failure_does_not_submit(mbox, monkeypatch, capsys):
    mbox.fail_list.add("Archive")
    called = []
    monkeypatch.setattr(
        browser, "_claude_fill_email_and_continue", lambda p, e: called.append(e)
    )
    assert browser._claude_auto_login(Page(), ME, "himalaya") == "not_submitted"
    assert not called
    assert "Cannot tell old login mails" in capsys.readouterr().err


def test_baseline_body_read_failure_does_not_submit(mbox, monkeypatch):
    mbox.add("INBOX", "1", _link("old"))
    mbox.fail_read = True
    called = []
    monkeypatch.setattr(
        browser, "_claude_fill_email_and_continue", lambda p, e: called.append(e)
    )
    assert browser._claude_auto_login(Page(), ME, "himalaya") == "not_submitted"
    assert not called


def test_invalid_allow_list_does_not_submit(mbox, monkeypatch, capsys):
    monkeypatch.setenv("ANTHROPIC_LOGIN_MAIL_SENDERS", "not a domain")
    called = []
    monkeypatch.setattr(
        browser, "_claude_fill_email_and_continue", lambda p, e: called.append(e)
    )
    assert browser._claude_auto_login(Page(), ME, "himalaya") == "not_submitted"
    assert not called
    assert "invalid entry" in capsys.readouterr().err


def test_form_failure_is_not_submitted(mbox, monkeypatch):
    monkeypatch.setattr(browser, "_claude_fill_email_and_continue", lambda p, e: False)
    assert browser._claude_auto_login(Page(), ME, "himalaya") == "not_submitted"


# --- cmd_anthropic_login: who submits the email for the assisted fallback -------


@pytest.mark.parametrize(
    "result, assisted_submits", [("not_submitted", True), ("submitted", False)]
)
def test_assisted_fallback_submits_only_when_auto_did_not(
    monkeypatch, result, assisted_submits
):
    fills: list[str] = []

    class _Browser:
        def close(self):
            return None

    class _Pw:
        def stop(self):
            return None

    class _LoginPage:
        def goto(self, url, **kwargs):
            return None

        def bring_to_front(self):
            return None

    logged_in = iter([False])
    monkeypatch.setattr(browser, "_connect", lambda port: (_Pw(), _Browser()))
    monkeypatch.setattr(browser, "_pick_page", lambda b, host: (None, _LoginPage()))
    monkeypatch.setattr(browser, "_claude_logged_in", lambda p: next(logged_in))
    monkeypatch.setattr(
        browser, "_interaction_lease", lambda name: contextlib.nullcontext()
    )
    monkeypatch.setattr(browser, "ANTHROPIC_LOGIN_EMAIL", ME)
    monkeypatch.setattr(browser, "_himalaya_bin", lambda: "himalaya")
    monkeypatch.setattr(browser, "_claude_auto_login", lambda p, e, h: result)
    monkeypatch.setattr(browser, "_require_headed_for_assisted", lambda port, s: True)
    monkeypatch.setattr(
        browser, "_claude_fill_email_and_continue", lambda p, e: fills.append(e)
    )
    monkeypatch.setattr(browser, "_claude_wait_for_login", lambda p, timeout_s: True)
    monkeypatch.setattr(browser, "_record_login_event", lambda site, mode: None)

    assert browser.cmd_anthropic_login(9222) == 0
    assert fills == ([ME] if assisted_submits else [])
