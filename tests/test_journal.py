"""Unit tests for the append-only, redacted journal in `browser.py`.

The journal records who launched / switched / stopped the shared browser, every
login, every window raise (`_bring_to_front`) and client (un)registration. These
tests pin its contract: origins only (never a path, query or fragment), one
JSON object per line, rotation at the size cap, a raise journaled BEFORE it
happens, and no failure mode — a missing `ps`, an unwritable file — that breaks
the command it instruments.

Everything runs against tmp_path (CACHE_DIR, the journal file and the lifecycle
record are repointed); the live shared browser is never touched.

Run: python3 -m pytest tests/test_journal.py -q     (from the repo root)
"""

from __future__ import annotations

# Tests reach into browser.py's private helpers on purpose (it is a script, not
# a package, so there is no public API).
# pylint: disable=protected-access,missing-function-docstring,import-error
# pylint: disable=redefined-outer-name,unused-argument
import argparse
import importlib.util
import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

_BROWSER_PY = Path(__file__).resolve().parent.parent / "bin" / "browser.py"
PORT = 59222
SECRET = "journal-fixture-sentinel"


def _load_browser_module():
    """Import bin/browser.py as a module (it has no module-level playwright import)."""
    spec = importlib.util.spec_from_file_location("browser_journal_test", _BROWSER_PY)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["browser_journal_test"] = mod
    spec.loader.exec_module(mod)
    return mod


browser = _load_browser_module()


@pytest.fixture
def journal(tmp_path: Path, monkeypatch) -> Path:
    """A private CACHE_DIR whose journal.jsonl is the one under test."""
    # Other loaded browser.py copies keep the live CACHE_DIR: the override stays
    # set (to the same file CACHE_DIR would give) so none of them resolves live.
    monkeypatch.setenv("CLAUDE_BROWSER_JOURNAL_FILE", str(tmp_path / "journal.jsonl"))
    monkeypatch.setattr(browser, "CACHE_DIR", tmp_path)
    monkeypatch.setattr(browser, "LIFECYCLE_FILE", tmp_path / "lifecycle.json")
    monkeypatch.setattr(browser, "CLIENTS_DIR", tmp_path / "clients")
    monkeypatch.setattr(browser, "REGISTRY_GATE", tmp_path / "clients" / ".lock")
    monkeypatch.setattr(browser, "_JOURNAL_ARGV", [])
    monkeypatch.setattr(browser, "_JOURNAL_PARENTS", [[{"pid": 1, "comm": "launchd"}]])
    monkeypatch.setattr(browser, "_JOURNAL_NOTES", {})
    monkeypatch.setattr(browser, "_JOURNAL_WARNED", [])
    return tmp_path / "journal.jsonl"


def _records(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines()]


def test_path_is_per_cache_dir(journal, monkeypatch):
    with monkeypatch.context() as m:
        m.delenv("CLAUDE_BROWSER_JOURNAL_FILE")
        assert browser._journal_path() == journal


def test_event_shape_and_file_mode(journal):
    browser._journal("up", phase="start", mode="headless")
    browser._journal("down", forced=True)
    raw = journal.read_text()
    assert raw.endswith("\n") and raw.count("\n") == 2
    first, second = _records(journal)
    assert first["event"] == "up" and first["phase"] == "start"
    assert first["mode"] == "headless" and first["instance"] == "default"
    assert first["pid"] == os.getpid() and first["ppid"] == os.getppid()
    assert first["parents"] == [{"pid": 1, "comm": "launchd"}]
    assert second["forced"] is True and second["mode"] is None
    assert stat.S_IMODE(journal.stat().st_mode) == 0o600


def test_mode_defaults_to_lifecycle_record(journal):
    browser._lifecycle_write("running", "headed", pid=123, port=PORT)
    browser._journal("register", client="x")
    assert _records(journal)[0]["mode"] == "headed"


def test_url_in_argv_reduced_to_origin(journal, monkeypatch):
    url = f"https://auth.example.org:8443/reset/{SECRET}?token={SECRET}#frag={SECRET}"
    monkeypatch.setattr(sys, "argv", ["/x/bin/browser.py", "open", "-N", url])
    browser._journal_set_argv(argparse.Namespace(cmd="open", url=url))
    browser._journal("register", client="browser.py", purpose=f"open {url}")
    raw = journal.read_text()
    assert SECRET not in raw
    rec = _records(journal)[0]
    assert rec["argv"] == ["browser.py", "open", "-N", "https://auth.example.org:8443"]
    assert rec["purpose"] == "open https://auth.example.org:8443"


def test_embedded_and_opaque_urls_redacted(journal):
    text = f"go(data:text/html,{SECRET}) then javascript:alert('{SECRET}') x"
    assert SECRET not in browser._journal_redact(text, 1000)
    embedded = f'fetch("https://api.example.org/v1?key={SECRET}")'
    assert browser._journal_redact(embedded, 1000) == 'fetch("https://api.example.org'


@pytest.mark.parametrize(
    "text",
    [
        f"foo_https://h.example/reset?token={SECRET}",
        f"1https://h.example/reset?token={SECRET}",
        f"x_data:text/html,{SECRET}",
        f"https:h.example/p?t={SECRET}",
        "https:\\\\h.example/p?t=" + SECRET,
        f"https://h.example/a b?t={SECRET}",
        f"see https://h.example/a b c#{SECRET} end",
        f"HTTPS://H.example/x?{SECRET}",
        f"javascript:void('{SECRET}')",
    ],
)
def test_reviewer_url_shapes_redacted(journal, text):
    assert SECRET not in browser._journal_redact(text, 1000)


@pytest.mark.parametrize(
    ("argv", "ns", "expected"),
    [
        (
            ["open", f"h.example/reset?token={SECRET}"],
            {"cmd": "open", "url": f"h.example/reset?token={SECRET}"},
            ["open", "h.example"],
        ),
        (
            ["open", f"https://h.example/a b?t={SECRET}"],
            {"cmd": "open", "url": f"https://h.example/a b?t={SECRET}"},
            ["open", "https://h.example"],
        ),
        (
            ["close", "-n", f"https://a.example/x?{SECRET}", f"b.example/y#{SECRET}"],
            {
                "cmd": "close",
                "urls": [f"https://a.example/x?{SECRET}", f"b.example/y#{SECRET}"],
            },
            ["close", "-n", "https://a.example", "b.example"],
        ),
        (
            ["eval", "--url", f"portal.example/reset/{SECRET}", "1"],
            {"cmd": "eval", "js": "1"},
            ["eval", "--url", "portal.example", "<js: 1 chars>"],
        ),
        (
            ["eval", f"--url=x.example/{SECRET}", "1+1"],
            {"cmd": "eval", "js": "1+1"},
            ["eval", "--url=x.example", "<js: 3 chars>"],
        ),
        (
            ["login", "anthropic"],
            {"cmd": "login", "site": "anthropic"},
            ["login", "anthropic"],
        ),
    ],
)
def test_argv_structural_redaction(journal, monkeypatch, argv, ns, expected):
    monkeypatch.setattr(sys, "argv", ["browser.py", *argv])
    browser._journal_set_argv(argparse.Namespace(**ns))
    got = browser._journal_argv()
    assert got == ["browser.py", *expected]
    assert SECRET not in json.dumps(got)


def test_register_exec_journals_basename_and_count_only(journal, monkeypatch):
    wrapped = ["--", "/opt/bin/npx", "@playwright/mcp", f"--token={SECRET}", SECRET]
    monkeypatch.setattr(
        sys, "argv", ["browser.py", "register-exec", "-t", "mcp", *wrapped]
    )
    browser._journal_set_argv(argparse.Namespace(cmd="register-exec", cmd_=wrapped))
    assert browser._journal_argv() == [
        "browser.py",
        "register-exec",
        "-t",
        "mcp",
        "--",
        "npx (+3 args)",
    ]
    release = browser._registry_register(
        "mcp",
        " ".join(wrapped),
        PORT,
        journal_purpose=browser._journal_wrapped_cmd(wrapped),
    )
    release()
    raw = journal.read_text()
    assert SECRET not in raw and "@playwright" not in raw
    assert _records(journal)[0]["purpose"] == "npx (+3 args)"


def test_journal_itself_never_runs_ps(journal, monkeypatch):
    monkeypatch.setattr(browser, "_JOURNAL_PARENTS", [])

    def no_ps(*a, **k):
        raise AssertionError("ps must not run inside _journal")

    monkeypatch.setattr(browser.subprocess, "run", no_ps)
    browser._journal("register", client="x")
    browser._journal("bring_to_front", command="token", origin="https://x.example")
    reg, raised = _records(journal)
    assert "parents" not in reg  # pid + ppid only
    assert reg["pid"] == os.getpid() and reg["ppid"] == os.getppid()
    assert raised["parents"] is None  # chain events: cache only


def test_ps_timeout_gives_empty_chain(journal, monkeypatch):
    monkeypatch.setattr(browser, "_JOURNAL_PARENTS", [])
    seen = {}

    def slow(argv, **k):
        seen["timeout"] = k.get("timeout")
        raise subprocess.TimeoutExpired(argv, k.get("timeout") or 0)

    monkeypatch.setattr(browser.subprocess, "run", slow)
    assert browser._journal_parent_chain() == []
    assert seen["timeout"] == 2


def test_dispatch_prefetches_chain_before_command(journal, monkeypatch):
    monkeypatch.setattr(browser, "_JOURNAL_PARENTS", [])
    order: list[str] = []

    def chain():
        order.append("ps")
        return []

    def token(port):
        order.append("cmd")
        return 0

    monkeypatch.setattr(browser, "_journal_parent_chain", chain)
    monkeypatch.setattr(browser, "cmd_token", token)
    assert browser._journaled_dispatch(argparse.Namespace(cmd="token"), PORT) == 0
    assert order == ["ps", "cmd"]


def test_cmd_fields_failure_does_not_break_dispatch(journal, monkeypatch):
    def boom(args):
        raise KeyError("x")

    monkeypatch.setattr(browser, "_journal_cmd_fields", boom)
    monkeypatch.setattr(browser, "cmd_down", lambda port, force: 0)
    args = argparse.Namespace(cmd="down", force=False)
    assert browser._journaled_dispatch(args, PORT) == 0
    assert [r["phase"] for r in _records(journal)] == ["start", "end"]


def test_watchdog_journals_before_exit(journal, monkeypatch, capsys):
    class Exited(Exception):
        pass

    def fake_exit(code):
        raise Exited(code)

    monkeypatch.setattr(browser.os, "_exit", fake_exit)
    with pytest.raises(Exited):
        browser._eval_watchdog_fire(5.0)
    rec = _records(journal)[0]
    assert (rec["event"], rec["command"], rec["timeout_s"]) == ("watchdog", "eval", 5.0)


def test_rotation_skipped_while_another_writer_rotates(journal, monkeypatch):
    monkeypatch.setattr(browser, "JOURNAL_MAX_BYTES", 10)
    journal.write_text('{"event":"old"}\n' * 5, encoding="utf-8")
    holder = os.open(str(journal), os.O_RDONLY)
    try:
        browser.fcntl.flock(holder, browser.fcntl.LOCK_EX)
        browser._journal("up", phase="start")
        assert not Path(f"{journal}.1").exists()  # busy lock → no rotation
        assert '"event":"up"' in journal.read_text(encoding="utf-8")
    finally:
        os.close(holder)
    browser._journal("up", phase="end")
    assert Path(f"{journal}.1").exists()  # lock free → this writer rotated


def test_eval_expression_replaced_by_length(journal, monkeypatch):
    js = f"document.querySelector('#pw').value = '{SECRET}'"
    monkeypatch.setattr(sys, "argv", ["browser.py", "eval", "-t", "5", js])
    browser._journal_set_argv(argparse.Namespace(cmd="eval", js=js))
    browser._journal("register", client="browser.py")
    assert SECRET not in journal.read_text()
    assert _records(journal)[0]["argv"][-1] == f"<js: {len(js)} chars>"


def test_long_argv_line_stays_under_cap(journal, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["browser.py", *(["x" * 500] * 40)])
    browser._journal("login", site="y" * 5000)
    raw = journal.read_bytes()
    assert len(raw) <= browser.JOURNAL_LINE_MAX
    assert _records(journal)[0]["event"] == "login"


def test_rotation_keeps_two(journal, monkeypatch):
    monkeypatch.setattr(browser, "JOURNAL_MAX_BYTES", 300)
    for i in range(12):
        browser._journal("register", client=f"c{i}")
    rotated = [Path(f"{journal}.1"), Path(f"{journal}.2")]
    assert all(p.exists() for p in rotated)
    assert not Path(f"{journal}.3").exists()
    for p in [journal, *rotated]:
        if p.exists():
            assert all(isinstance(r, dict) for r in _records(p))
    # The newest entries are readable through the CLI helper, oldest first.
    lines = browser._journal_read_lines(3, None)
    assert [json.loads(line)["client"] for line in lines] == ["c9", "c10", "c11"]


def test_rotation_skipped_when_path_already_rotated(journal, monkeypatch):
    """A writer whose fd names the old file must not rotate the fresh one."""
    monkeypatch.setattr(browser, "JOURNAL_MAX_BYTES", 10)
    journal.write_text('{"event":"old"}\n' * 5)
    real_fstat = os.fstat

    swapped: list[bool] = []

    def fstat(fd):
        st = real_fstat(fd)
        if not swapped:  # another writer swaps the path for a new inode, once
            swapped.append(True)
            os.replace(journal, f"{journal}.1")
            journal.write_text("")
        return st

    monkeypatch.setattr(browser.os, "fstat", fstat)
    browser._journal("up", phase="start")
    assert journal.read_text() == ""  # the fresh file was not rotated away
    assert not Path(f"{journal}.2").exists()
    assert '"event":"up"' in Path(f"{journal}.1").read_text(encoding="utf-8")


def test_bring_to_front_journals_then_calls(journal):
    calls: list[str] = []

    class FakePage:
        url = f"https://claude.ai/magic-link#{SECRET}"

        def bring_to_front(self):
            calls.append("raised")
            assert journal.exists(), "journal must be written BEFORE the raise"

    browser._bring_to_front(FakePage(), "login anthropic")
    assert calls == ["raised"]
    rec = _records(journal)[0]
    assert rec["event"] == "bring_to_front"
    assert rec["command"] == "login anthropic"
    assert rec["origin"] == "https://claude.ai"
    assert SECRET not in journal.read_text()


def test_bring_to_front_error_propagates_after_journal(journal):
    class Boom(RuntimeError):
        pass

    class FakePage:  # no `url` attribute at all
        def bring_to_front(self):
            raise Boom("target closed")

    with pytest.raises(Boom):
        browser._bring_to_front(FakePage(), "doctor")
    assert _records(journal)[0]["origin"] == "(empty)"


def test_parent_chain_survives_ps_failure(journal, monkeypatch):
    monkeypatch.setattr(browser, "_JOURNAL_PARENTS", [])

    def broken(*a, **k):
        raise FileNotFoundError("ps")

    monkeypatch.setattr(browser.subprocess, "run", broken)
    assert browser._journal_parent_chain() == []
    browser._journal("down", forced=False)
    assert _records(journal)[0]["parents"] == []


def test_parent_chain_parses_ps_table(journal, monkeypatch):
    monkeypatch.setattr(browser, "_JOURNAL_PARENTS", [])
    me = os.getppid()
    table = f"{me} 500 /bin/zsh\n500 1 /Applications/iTerm 2.app/iTerm2\n1 0 launchd\n"

    def fake(argv, **k):
        assert argv[0] == "ps"
        return subprocess.CompletedProcess(argv, 0, stdout=table, stderr="")

    monkeypatch.setattr(browser.subprocess, "run", fake)
    assert browser._journal_parent_chain() == [
        {"pid": me, "comm": "/bin/zsh"},
        {"pid": 500, "comm": "/Applications/iTerm 2.app/iTerm2"},
        {"pid": 1, "comm": "launchd"},
    ]


def test_unwritable_journal_warns_once_never_raises(journal, monkeypatch, capsys):
    monkeypatch.setenv("CLAUDE_BROWSER_JOURNAL_FILE", str(journal.parent))  # a dir
    browser._journal("up", phase="start")
    browser._journal("up", phase="end")
    err = capsys.readouterr().err
    assert err.count("⚠ journal: not recorded") == 1


def test_register_and_unregister_journaled(journal):
    release = browser._registry_register("playwright-mcp", "MCP server", PORT)
    release()
    events = [(r["event"], r["client"], r["client_pid"]) for r in _records(journal)]
    assert events == [
        ("register", "playwright-mcp", os.getpid()),
        ("unregister", "playwright-mcp", os.getpid()),
    ]
    assert isinstance(_records(journal)[1]["held_ms"], int)


def test_journaled_dispatch_records_start_end_and_notes(journal, monkeypatch):
    def fake_login(port, site_name):
        browser._journal_note(site="claude", flow="builtin")
        return 0

    monkeypatch.setattr(browser, "cmd_login", fake_login)
    args = argparse.Namespace(cmd="login", site="anthropic")
    assert browser._journaled_dispatch(args, PORT) == 0
    start, end = _records(journal)
    assert (start["event"], start["phase"], start["site"]) == (
        "login",
        "start",
        "anthropic",
    )
    assert (end["phase"], end["result"], end["flow"], end["site"]) == (
        "end",
        0,
        "builtin",
        "claude",
    )
    assert isinstance(end["duration_ms"], int)


def test_journaled_dispatch_records_sys_exit(journal, monkeypatch):
    def fake_switch(port, mode, force):
        sys.exit(3)

    monkeypatch.setattr(browser, "cmd_switch", fake_switch)
    browser._lifecycle_write("running", "headed", pid=1, port=PORT)
    args = argparse.Namespace(cmd="switch", mode="headless", force=False)
    with pytest.raises(SystemExit):
        browser._journaled_dispatch(args, PORT)
    start, end = _records(journal)
    assert (start["from"], start["to"]) == ("headed", "headless")
    assert end["result"] == 3


def test_unjournaled_command_writes_nothing(journal, monkeypatch):
    monkeypatch.setattr(browser, "cmd_clients", lambda port: 0)
    assert browser._journaled_dispatch(argparse.Namespace(cmd="clients"), PORT) == 0
    assert not journal.exists()


def test_cmd_journal_human_and_filters(journal, capsys):
    browser._journal("up", phase="start", mode="headless")
    browser._journal("bring_to_front", command="token", origin="https://portal.cscs.ch")
    journal.write_text(journal.read_text() + "not json\n")
    assert browser.cmd_journal(50, "bring_to_front", False) == 0
    out = capsys.readouterr().out.strip().splitlines()
    assert len(out) == 1
    assert "bring_to_front" in out[0] and "origin=https://portal.cscs.ch" in out[0]
    assert "launchd(1)" in out[0]
    assert browser.cmd_journal(1, None, True) == 0
    raw = capsys.readouterr().out.strip()
    assert json.loads(raw)["event"] == "bring_to_front"


def test_cmd_journal_reredacts_tampered_lines(journal, capsys):
    journal.write_text(
        json.dumps({"event": "up", "origin": f"https://x.org/p?t={SECRET}"}) + "\n"
    )
    assert browser.cmd_journal(5, None, False) == 0
    out = capsys.readouterr().out
    assert SECRET not in out and "origin=https://x.org" in out


def test_cli_journal_help_and_empty(tmp_path):
    env = {**os.environ, "CLAUDE_BROWSER_CACHE_DIR": str(tmp_path)}
    env.pop("CLAUDE_BROWSER_JOURNAL_FILE", None)
    helped = subprocess.run(
        [sys.executable, str(_BROWSER_PY), "journal", "-h"],
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
        check=False,
    )
    assert helped.returncode == 0 and "--event" in helped.stdout
    shown = subprocess.run(
        [sys.executable, str(_BROWSER_PY), "journal", "-n", "5"],
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
        check=False,
    )
    assert shown.returncode == 0, shown.stderr
    assert "no journal entries" in shown.stdout
    assert str(tmp_path / "journal.jsonl") in shown.stdout
