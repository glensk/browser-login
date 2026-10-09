"""Guided login (tp#836 Phase 3): `assisted-login`, the maintenance transaction,
the register-exec pause protocol, the watchdog, and the B path end to end.

Hermetic part (default): every state file lives in tmp_path; real processes
(`register-exec -- sleep`, a SIGKILLed owner) run against that tmp cache only;
nothing talks to the live shared browser (9222/9223).

Disposable-browser part (`-m browser`, opt-in via LOGIN_BROKER_E2E=1): a
headless Chrome for Testing on a free port with a temp CLAUDE_BROWSER_CACHE_DIR
(`browser.py up`), a tiny local login site injected through the
CLAUDE_BROWSER_TEST_SITES hook, `assisted-login` run under a pseudo-terminal,
and the viewer driven by Playwright from a SECOND disposable headless browser.
No window is ever opened.

Run: uv run --no-sync pytest tests/test_guided_login.py -q
     LOGIN_BROKER_E2E=1 uv run --no-sync pytest tests/test_guided_login.py -q -m browser
"""

from __future__ import annotations

# Tests reach into browser.py's private helpers on purpose (it is a script).
# pylint: disable=protected-access,missing-function-docstring,import-error
# pylint: disable=redefined-outer-name,unused-argument,consider-using-with
# One file for the whole guided-login surface (hermetic + e2e).
# pylint: disable=too-many-lines
import contextlib
import http.server
import importlib.util
import json
import os
import pty
import select
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

_REPO = Path(__file__).resolve().parent.parent
BROWSER_PY = _REPO / "bin" / "browser.py"
PY = sys.executable


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


browser = _load("browser_guided_test", BROWSER_PY)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _wait(pred, timeout: float, step: float = 0.1):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        val = pred()
        if val:
            return val
        time.sleep(step)
    return pred()


def _stat(pid: int) -> str:
    res = subprocess.run(
        ["ps", "-o", "stat=", "-p", str(pid)],
        capture_output=True,
        text=True,
        check=False,
    )
    return res.stdout.strip()


@pytest.fixture
def cache(tmp_path, monkeypatch):
    """browser.py's coordination files in tmp_path, for us AND our subprocesses."""
    monkeypatch.setenv("CLAUDE_BROWSER_CACHE_DIR", str(tmp_path))
    monkeypatch.delenv("CLAUDE_BROWSER_LEASE_HELD", raising=False)
    monkeypatch.delenv(browser.MAINTENANCE_ENV, raising=False)
    for name, value in {
        "CACHE_DIR": tmp_path,
        "PROFILE_DIR": tmp_path / "profile",
        "PID_FILE": tmp_path / "browser.pid",
        "LIFECYCLE_FILE": tmp_path / ".browser-lifecycle.json",
        "CLIENTS_DIR": tmp_path / "clients",
        "REGISTRY_GATE": tmp_path / "clients" / ".registry.lock",
        "INTERACTION_LOCK": tmp_path / "interaction.lock",
        "MAINTENANCE_FILE": tmp_path / "maintenance.json",
        "MAINTENANCE_LOCK": tmp_path / ".maintenance.lock",
        "DESIRED_MODE_FILE": tmp_path / "desired-mode.json",
    }.items():
        monkeypatch.setattr(browser, name, value)
    return tmp_path


@pytest.fixture
def quiet_tx(cache, monkeypatch):
    """`_maintenance` without a browser: no watchdog, nothing up, closes logged."""
    closed: list[list[str]] = []
    monkeypatch.setattr(browser, "_spawn_watchdog", lambda port, nonce: 4242)
    monkeypatch.setattr(browser, "_is_up", lambda port: False)
    monkeypatch.setattr(browser, "_browser_mode", lambda port: None)

    def close(port, ids):
        closed.append(list(ids))
        return list(ids)

    monkeypatch.setattr(browser, "_close_owned_targets", close)
    return closed


def _record() -> dict[str, Any]:
    rec: dict[str, Any] = json.loads(
        browser.MAINTENANCE_FILE.read_text(encoding="utf-8")
    )
    return rec


def _write_record(**over) -> None:
    rec = {
        "owner_nonce": "f" * 32,
        "pid": os.getpid(),
        "pid_start_time": browser._proc_lstart(os.getpid()),
        "site": "slack",
        "mode": "B",
        "state": "active",
        "owned_targets": [],
        "paused": [],
        "started": "2026-10-08T10:00:00+0200",
        "heartbeat": time.time(),
    }
    rec.update(over)
    browser.MAINTENANCE_FILE.parent.mkdir(parents=True, exist_ok=True)
    browser.MAINTENANCE_FILE.write_text(json.dumps(rec), encoding="utf-8")


def _env(cache: Path, **extra: str) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k != browser.MAINTENANCE_ENV}
    env.pop("CLAUDE_BROWSER_LEASE_HELD", None)
    env["CLAUDE_BROWSER_CACHE_DIR"] = str(cache)
    env.update(extra)
    return env


# --- the human entry --------------------------------------------------------------


def test_assisted_login_refuses_without_a_terminal(cache):
    """No controlling terminal (an agent, launchd) → exit 2, nothing started."""
    res = subprocess.run(
        [
            PY,
            str(BROWSER_PY),
            "--cdp-port",
            str(_free_port()),
            "assisted-login",
            "slack",
        ],
        capture_output=True,
        text=True,
        env=_env(cache),
        start_new_session=True,  # no controlling terminal: /dev/tty fails
        stdin=subprocess.DEVNULL,
        check=False,
        timeout=60,
    )
    assert res.returncode == 2, res.stderr
    assert "needs your terminal" in res.stderr
    assert not (cache / "maintenance.json").exists()


def test_assisted_login_help_has_short_flags():
    res = subprocess.run(
        [PY, str(BROWSER_PY), "assisted-login", "-h"],
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    assert res.returncode == 0
    for flag in ("-u, --url", "-a, --fallback-window", "-f, --force"):
        assert flag in res.stdout


# --- the maintenance record -------------------------------------------------------


def test_maintenance_record_lifecycle(quiet_tx, monkeypatch):
    with browser._maintenance("slack", "B", port=59990) as tx:
        rec = _record()
        assert rec["owner_nonce"] == tx.nonce and rec["mode"] == "B"
        assert rec["state"] == "active" and rec["watchdog_pid"] == 4242
        assert rec["pid"] == os.getpid() and rec["site"] == "slack"
        assert os.environ[browser.MAINTENANCE_ENV] == tx.nonce
        assert os.environ["CLAUDE_BROWSER_LEASE_HELD"] == "1"
        assert browser._maint_owner() and not browser._headed_lease_held()
        tx.add_owned("T1")
        assert _record()["owned_targets"] == ["T1"]
        tx.set_mode("A")  # the B → A handoff: now `switch headed` is allowed
        assert browser._headed_lease_live() is not None
        assert browser._headed_lease_held()
    assert not browser.MAINTENANCE_FILE.exists()
    assert browser.MAINTENANCE_ENV not in os.environ
    assert "CLAUDE_BROWSER_LEASE_HELD" not in os.environ
    assert quiet_tx == [["T1"]]


def test_maintenance_cleans_up_on_an_exception(quiet_tx):
    with pytest.raises(KeyboardInterrupt):
        with browser._maintenance("slack", "B", port=59990) as tx:
            tx.add_owned("T9")
            raise KeyboardInterrupt
    assert not browser.MAINTENANCE_FILE.exists()
    assert quiet_tx == [["T9"]]


def test_maintenance_refuses_while_another_guided_login_lives(quiet_tx):
    _write_record()
    with pytest.raises(browser.HeadedLeaseBusy, match="already owns the browser"):
        with browser._maintenance("notion", "B", port=59990):
            pytest.fail("must not start")
    assert _record()["owner_nonce"] == "f" * 32  # the other one is untouched


def test_maintenance_refuses_unregistered_peers_unless_forced(quiet_tx, monkeypatch):
    monkeypatch.setattr(browser, "_is_up", lambda port: True)
    monkeypatch.setattr(
        browser, "_unknown_clients_verdict", lambda port: "1 unregistered CDP client"
    )
    with pytest.raises(browser.MaintenanceRefused, match="unregistered") as exc:
        with browser._maintenance("slack", "B", port=59990):
            pytest.fail("must not start")
    # The refusal names both ways to force it: browser.py's and agent-login's.
    assert "-f/--force" in str(exc.value)
    assert "agent-login.py -g slack -F" in str(exc.value)
    assert not browser.MAINTENANCE_FILE.exists()
    with browser._maintenance("slack", "B", port=59990, force=True) as tx:
        assert _record()["owner_nonce"] == tx.nonce


def test_record_without_mode_is_mode_a(cache):
    _write_record(mode=None)
    assert browser._headed_lease_live() is not None
    _write_record(mode="B")
    assert browser._headed_lease_live() is None and browser._maint_live() is not None


@pytest.mark.parametrize(
    ("cmd", "mode", "live", "want"),
    [("eval", "headed", True, None), ("eval", "headed", False, "revert")],
)
def test_preflight_treats_a_mode_a_record_as_the_lease(cmd, mode, live, want):
    assert browser._preflight_action(cmd, mode, live) == want


# --- registrations while a guided login owns the browser --------------------------


def test_registration_without_the_token_refuses(cache, capsys):
    _write_record(owner_nonce="a" * 32)
    with pytest.raises(SystemExit) as exc:
        browser._registry_register("agent", "eval", 59990)
    assert exc.value.code == browser.BUSY_RC == 75  # busy, NOT "logged out" (2)
    err = capsys.readouterr().err
    assert err.startswith("busy: guided login for slack in progress (until ~")
    assert "agent-login.py -g slack" in err
    assert not list((cache / "clients").glob("*.json"))


def test_registration_with_the_token_is_marked_as_ours(cache, monkeypatch):
    _write_record(owner_nonce="a" * 32)
    monkeypatch.setenv(browser.MAINTENANCE_ENV, "a" * 32)
    reg = browser._registry_register("viewer", "relay", 59990)
    try:
        rec = json.loads(reg.path.read_text(encoding="utf-8"))
        assert rec["maintenance"] == "a" * 32
        reg.update(paused=True)
        assert json.loads(reg.path.read_text(encoding="utf-8"))["paused"] is True
    finally:
        reg()
    assert not reg.path.exists()


def test_registration_after_the_record_ended_is_normal(cache):
    _write_record(heartbeat=time.time() - 500)  # hung owner = not live
    reg = browser._registry_register("agent", "eval", 59990)
    reg()


# --- the pause protocol (real register-exec wrapper) ------------------------------


@contextlib.contextmanager
def _fake_client(cache: Path, port: int) -> Iterator[dict]:
    """`browser.py register-exec -t fake -- sleep 120`; yields its registration."""
    proc = subprocess.Popen(
        [
            PY,
            str(BROWSER_PY),
            "--cdp-port",
            str(port),
            "register-exec",
            "-t",
            "fake",
            "--",
            "sleep",
            "120",
        ],
        env=_env(cache),
        stdin=subprocess.DEVNULL,
    )

    def reg() -> dict[str, Any] | None:
        for path in (cache / "clients").glob("*.json"):
            with contextlib.suppress(OSError, ValueError):
                rec: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
                if rec.get("tool") == "fake" and rec.get("child_pid"):
                    return rec
        return None

    try:
        rec = _wait(reg, 30)
        assert rec, "register-exec never registered its child"
        yield {"proc": proc, "rec": rec, "reg": reg}
    finally:
        proc.terminate()
        try:
            proc.wait(10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(5)


def test_pause_and_resume_a_registered_client(quiet_tx):
    port = _free_port()
    with _fake_client(browser.CACHE_DIR, port) as fc:
        child = int(fc["rec"]["child_pid"])
        assert fc["rec"]["child_pgid"] == child  # own process group
        assert "T" not in _stat(child)
        with browser._maintenance("slack", "B", port=port) as tx:
            assert "T" in _stat(child), "child not SIGSTOPped"
            assert fc["reg"]()["paused"] is True
            assert [p["tool"] for p in _record()["paused"]] == ["fake"]
            assert tx.paused and tx.paused[0]["child_pid"] == child
        assert _wait(lambda: "T" not in _stat(child), 5), "child not resumed"
        assert _wait(lambda: fc["reg"]()["paused"] is False, 5)


def test_paused_wrapper_resumes_itself_when_the_record_vanishes(quiet_tx):
    """Defense in depth: a paused client never stays frozen after its owner."""
    port = _free_port()
    with _fake_client(browser.CACHE_DIR, port) as fc:
        child = int(fc["rec"]["child_pid"])
        _write_record(owner_nonce="b" * 32)
        os.kill(int(fc["rec"]["pid"]), signal.SIGUSR1)
        assert _wait(lambda: "T" in _stat(child), 5)
        browser.MAINTENANCE_FILE.unlink()
        assert _wait(lambda: "T" not in _stat(child), 8), "wrapper did not self-resume"


def test_pause_is_ignored_outside_a_guided_login(quiet_tx):
    port = _free_port()
    with _fake_client(browser.CACHE_DIR, port) as fc:
        child = int(fc["rec"]["child_pid"])
        os.kill(int(fc["rec"]["pid"]), signal.SIGUSR1)
        time.sleep(1.0)
        assert "T" not in _stat(child)
        assert fc["reg"]()["paused"] is False


# --- watchdog -----------------------------------------------------------------------

_OWNER = r"""
import importlib.util, sys, time
spec = importlib.util.spec_from_file_location("bp", sys.argv[1])
bp = importlib.util.module_from_spec(spec); spec.loader.exec_module(bp)
port = int(sys.argv[2])
with bp._maintenance("slack", "B", port=port) as tx:
    ws = bp._browser_ws_url(port)
    if ws:
        tid = bp._cdp_create_background_target(ws, "about:blank#owned")
        tx.add_owned(tid)
    print("ready", flush=True)
    time.sleep(600)
"""


def _owner(cache: Path, port: int) -> subprocess.Popen:
    proc = subprocess.Popen(
        [PY, "-c", _OWNER, str(BROWSER_PY), str(port)],
        env=_env(cache),
        stdout=subprocess.PIPE,
        stdin=subprocess.DEVNULL,
        text=True,
    )
    assert proc.stdout is not None
    started = threading.Event()

    def pump() -> None:
        assert proc.stdout is not None
        for line in proc.stdout:
            if line.strip() == "ready":
                started.set()

    threading.Thread(target=pump, daemon=True).start()
    if not started.wait(60):
        proc.kill()
        raise AssertionError("owner never started")
    return proc


def test_watchdog_recovers_after_sigkill_of_the_owner(cache):
    port = _free_port()
    with _fake_client(cache, port) as fc:
        child = int(fc["rec"]["child_pid"])
        owner = _owner(cache, port)
        assert "T" in _stat(child)
        rec = _record()
        assert rec["watchdog_pid"] and rec["paused"]
        owner.kill()
        owner.wait(5)
        assert _wait(lambda: not browser.MAINTENANCE_FILE.exists(), 20), "record kept"
        assert _wait(lambda: "T" not in _stat(child), 10), "client still stopped"
        journal = Path(os.environ["CLAUDE_BROWSER_JOURNAL_FILE"]).read_text(
            encoding="utf-8"
        )
        assert '"watchdog_recover"' in journal and "dead pid" in journal


# --- resume only validated pids ---------------------------------------------------


def test_resume_stops_a_validated_orphan_whose_wrapper_died(cache):
    """An orphan (wrapper dead) is unregistered: stopped, never just resumed."""
    child = subprocess.Popen(["sleep", "30"], process_group=0)
    try:
        os.killpg(child.pid, signal.SIGSTOP)
        assert _wait(lambda: "T" in _stat(child.pid), 5)
        entry = {
            "tool": "fake",
            "pid": 999_999_999,  # the wrapper is gone
            "pid_start_time": "Thu Jan  1 00:00:00 2026",
            "child_pid": child.pid,
            "child_pgid": child.pid,
            "child_start_time": browser._proc_lstart(child.pid),
        }
        wrong = {**entry, "child_start_time": "Mon Jan  1 00:00:00 2024"}
        assert browser._resume_clients([wrong]) == [
            "fake pid 999999999: no validated orphan"
        ]
        assert "T" in _stat(child.pid)  # a recycled pid is never signalled
        assert browser._resume_clients([entry]) == []
        assert child.wait(10) is not None  # SIGTERM (+SIGCONT) ended it
    finally:
        child.kill()
        child.wait(5)


# --- the B → A decision (no browser, no window) --------------------------------------


class _FakeTty:
    def __init__(self, *answers: str) -> None:
        self.answers = list(answers)
        self.prompts: list[str] = []

    def ask(self, prompt: str) -> str:
        self.prompts.append(prompt)
        return self.answers.pop(0) if self.answers else ""


@pytest.fixture
def flow(quiet_tx, monkeypatch):
    """`_assisted_login_tty` with B and A stubbed: which paths ran, in order."""
    log: list[str] = []
    probes = {"n": 0}

    def probe(port, site):
        probes["n"] += 1
        return False

    def path_b(tx, site, url, deadline):
        log.append(f"B {url}")
        tx.add_owned("T-B")
        return "fallback", "a passkey / security-key (WebAuthn) prompt (get)"

    def path_a(tx, site, url, deadline):
        log.append(f"A {tx.mode}")
        return "ok", ""

    monkeypatch.setattr(browser, "_is_up", lambda port: True)
    monkeypatch.setattr(browser, "_guided_probe", probe)
    monkeypatch.setattr(browser, "_guided_b", path_b)
    monkeypatch.setattr(browser, "_guided_a", path_a)
    monkeypatch.setattr(
        browser, "_test_sites", lambda: {"testsite": {"login_url": "http://x/login"}}
    )
    return log


def test_b_fallback_asks_and_switches_to_a_on_yes(flow, capsys):
    tty = _FakeTty("testsite", "y")
    assert (
        browser._assisted_login_tty(tty, 59990, browser.GuidedRequest("testsite")) == 0
    )
    assert flow == ["B http://x/login", "A B"]  # A runs inside the SAME transaction
    assert "switch to a visible window" in tty.prompts[-1]
    assert "passkey" in capsys.readouterr().out
    assert not browser.MAINTENANCE_FILE.exists()


def test_b_fallback_declined_is_exit_2(flow):
    tty = _FakeTty("testsite", "")
    assert (
        browser._assisted_login_tty(tty, 59990, browser.GuidedRequest("testsite")) == 2
    )
    assert flow == ["B http://x/login"]


def test_fallback_window_flag_goes_straight_to_a(flow):
    tty = _FakeTty("testsite")
    assert (
        browser._assisted_login_tty(
            tty, 59990, browser.GuidedRequest("testsite", window=True)
        )
        == 0
    )
    assert flow == ["A A"]
    assert len(tty.prompts) == 1  # only the confirmation


def test_wrong_confirmation_starts_nothing(flow, capsys):
    tty = _FakeTty("slack")
    assert (
        browser._assisted_login_tty(tty, 59990, browser.GuidedRequest("testsite")) == 2
    )
    assert flow == [] and "not confirmed" in capsys.readouterr().err
    assert not browser.MAINTENANCE_FILE.exists()


def test_already_logged_in_needs_no_confirmation(flow, monkeypatch):
    monkeypatch.setattr(browser, "_guided_probe", lambda port, site: True)
    tty = _FakeTty()
    assert (
        browser._assisted_login_tty(tty, 59990, browser.GuidedRequest("testsite")) == 0
    )
    assert not tty.prompts and not flow


def test_path_a_order_headed_then_headless(quiet_tx, monkeypatch):
    """A: mode A in the record → switch headed → login → headless in a finally."""
    calls: list[tuple] = []

    def self_run(port, *args, capture=True, timeout=120.0):
        calls.append(args)
        if args[0] == "switch":
            assert _record()["mode"] == "A"  # the child's `switch headed` may
        return subprocess.CompletedProcess(args, 0, "", "")

    def headless(port: int) -> bool:
        calls.append(("headless",))
        return True

    monkeypatch.setattr(browser, "_self_run", self_run)
    monkeypatch.setattr(browser, "_guided_probe", lambda port, site: True)
    monkeypatch.setattr(browser, "_ensure_headless", headless)
    with browser._maintenance("slack", "B", port=59990) as tx:
        outcome = browser._guided_a(tx, "slack", None, time.monotonic() + 60)
    assert outcome == ("ok", "")
    assert calls[:3] == [("switch", "headed"), ("login", "slack"), ("headless",)]


# --- the end of B: the view's last line -------------------------------------------

# A stand-in relay: announces its URL, then waits for the record's state to
# turn `succeeded` (what login_viewer.py's poll does) and exits by itself.
FAKE_RELAY = """
import json, sys, time
rec_path, seen = sys.argv[1], sys.argv[2]
print(json.dumps({"url": "http://127.0.0.1:1/tok/"}), flush=True)
deadline = time.monotonic() + float(sys.argv[3])
while time.monotonic() < deadline:
    rec = json.loads(open(rec_path, encoding="utf-8").read())
    if rec.get("state") == "succeeded":
        open(seen, "w", encoding="utf-8").write(rec["site"])
        sys.exit(0)
    time.sleep(0.05)
sys.exit(9)
"""


@pytest.fixture
def b_stubs(quiet_tx, monkeypatch, tmp_path):
    """`_guided_b` with a fake relay process and a stubbed wait loop."""
    seen = tmp_path / "relay-saw"
    stopped: list[int | None] = []
    real_stop = browser._stop_viewer

    def start(tx, tid):
        return subprocess.Popen(
            [PY, "-c", FAKE_RELAY, str(browser.MAINTENANCE_FILE), str(seen), "10"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            text=True,
        )

    def stop(relay):
        stopped.append(relay.poll())
        real_stop(relay)

    monkeypatch.setattr(browser, "_guided_open_owned", lambda tx, url: "T1")
    monkeypatch.setattr(browser, "_start_viewer", start)
    monkeypatch.setattr(browser, "_open_viewer_window", lambda url: "test-file")
    monkeypatch.setattr(browser, "_stop_viewer", stop)
    return seen, stopped


def test_b_success_lets_the_relay_close_the_view_itself(b_stubs, monkeypatch):
    """✅ → record state `succeeded` → the relay shows its last line and exits on
    its own within VIEWER_FINAL_S, before the transaction's cleanup."""
    seen, stopped = b_stubs
    monkeypatch.setattr(browser, "_viewer_loop", lambda *a: ("ok", ""))
    with browser._maintenance("notion", "B", port=59990) as tx:
        out = browser._guided_b(tx, "notion", "http://x/login", time.monotonic() + 60)
        assert out == ("ok", "")
        assert _record()["state"] == "succeeded"
    assert seen.read_text(encoding="utf-8") == "notion"
    assert stopped == [0]  # it had already exited by itself, exit 0
    assert not browser.MAINTENANCE_FILE.exists()


def test_b_without_success_leaves_the_state_and_stops_the_relay(b_stubs, monkeypatch):
    seen, stopped = b_stubs
    monkeypatch.setattr(browser, "_viewer_loop", lambda *a: ("timeout", "no login"))
    with browser._maintenance("notion", "B", port=59990) as tx:
        out = browser._guided_b(tx, "notion", "http://x/login", time.monotonic() + 60)
        assert out == ("timeout", "no login")
        assert _record()["state"] == "active"
    assert not seen.exists()
    assert stopped == [None]  # still running: `_stop_viewer` ended it


def test_relay_reads_the_success_the_transaction_writes(quiet_tx):
    """The contract between browser.py's record and login_viewer.py's poll."""
    lv = _load("login_viewer_contract_test", _REPO / "bin" / "login_viewer.py")
    path = browser.MAINTENANCE_FILE
    with browser._maintenance("notion", "B", port=59990) as tx:
        assert lv.maintenance_poll(path, tx.nonce) == ("live", "")
        tx.note(state="succeeded")
        assert lv.maintenance_poll(path, tx.nonce) == ("succeeded", "notion")
        assert lv.maintenance_poll(path, "x" * 32) == ("gone", "")
        assert browser._maint_live() is not None  # still live until cleanup
    assert lv.maintenance_poll(path, tx.nonce) == ("gone", "")


def test_viewer_without_brave_is_an_info_line(cache, monkeypatch, tmp_path, capsys):
    opened: list[list[str]] = []
    monkeypatch.delenv(browser.TEST_VIEWER_URL_ENV, raising=False)
    monkeypatch.setattr(browser, "BRAVE_APP", tmp_path / "no-brave.app")
    monkeypatch.setattr(
        browser.subprocess, "run", lambda argv, **k: opened.append(list(argv))
    )
    assert browser._open_viewer_window("http://127.0.0.1:1/tok/") == "default"
    assert opened == [["open", "http://127.0.0.1:1/tok/"]]
    err = capsys.readouterr().err
    assert "ℹ️  opening the login view in your default browser" in err
    assert "⚠" not in err


# --- review fixes ----------------------------------------------------------------


def test_probe_uses_a_fresh_background_tab_during_a_guided_login(cache, monkeypatch):
    """`logged-in` never picks a tab (the owned login tab!) while one lives."""
    used: list[str] = []
    monkeypatch.setattr(
        browser, "_connect", lambda *a, **k: pytest.fail("picked an existing tab")
    )

    def background(port, url, fn):
        used.append(url)
        return True

    monkeypatch.setattr(browser, "_with_background_page", background)
    _write_record()
    for cmd in (
        browser.cmd_slack_logged_in,
        browser.cmd_openai_logged_in,
        browser.cmd_anthropic_logged_in,
    ):
        assert cmd(59990) == 0
    assert used == ["about:blank"] * 3


@pytest.mark.parametrize(
    ("rec", "since", "now", "want"),
    [
        (None, None, 100.0, ("maintenance record gone", None)),
        ({"owner_nonce": "other"}, None, 100.0, ("maintenance record gone", None)),
    ],
)
def test_exec_self_resume_when_the_record_is_gone(rec, since, now, want):
    assert browser._exec_self_resume(rec, "ours", since, now) == want


def test_exec_self_resume_waits_for_the_watchdog_on_a_dead_owner(cache):
    dead = {
        "owner_nonce": "ours",
        "pid": 999_999_999,
        "pid_start_time": "x",
        "heartbeat": time.time(),
    }
    why, since = browser._exec_self_resume(dead, "ours", None, 100.0)
    assert why is None and since == 100.0  # the watchdog's turn
    why, since = browser._exec_self_resume(dead, "ours", since, 159.0)
    assert why is None
    why, _ = browser._exec_self_resume(dead, "ours", since, 160.0)
    assert why and "watchdog presumed dead" in why


def test_mode_a_crash_watchdog_reverts_before_the_client_resumes(cache, monkeypatch):
    """Owner of a mode-A login died: the paused client must NOT retake the gate
    before the watchdog's revert holds it exclusively; it resumes afterwards."""
    port = _free_port()
    with _fake_client(cache, port) as fc:
        child = int(fc["rec"]["child_pid"])
        _write_record(owner_nonce="c" * 32, mode="A")  # live (our pid) → pausable
        os.kill(int(fc["rec"]["pid"]), signal.SIGUSR1)
        assert _wait(lambda: fc["reg"]()["paused"] is True, 5)
        rec = {**_record(), "pid": 999_999_999}  # now the owner is dead
        rec["paused"] = [
            {k: fc["rec"][k] for k in ("nonce", "pid", "pid_start_time", "tool")}
            | {k: fc["rec"][k] for k in ("child_pid", "child_pgid", "child_start_time")}
        ]
        browser.MAINTENANCE_FILE.write_text(json.dumps(rec), encoding="utf-8")
        time.sleep(browser.EXEC_SELF_CHECK_S * 2 + 0.5)
        assert "T" in _stat(child), "client resumed before the watchdog recovered"
        order: list[str] = []

        def switch(port_, target, *a, **k):
            gate = browser._gate_acquire(browser.fcntl.LOCK_EX, 0.5)
            assert gate is not None, "a resumed client holds the gate"
            browser._gate_release(gate)
            assert "T" in _stat(child)
            order.append(f"switch {target}")
            return 0

        monkeypatch.setattr(browser, "_browser_mode", lambda p: "headed")
        monkeypatch.setattr(browser, "cmd_switch", switch)
        browser._watchdog_recover(port, rec, "dead pid")
        order.append("recovered")
        assert order == ["switch headless", "recovered"]
        assert not browser.MAINTENANCE_FILE.exists()
        assert _wait(lambda: "T" not in _stat(child), 5)


def test_wrapper_survives_signals_right_after_registering(cache):
    """Handlers exist before `kind: exec` is published and before the child."""
    port = _free_port()
    proc = subprocess.Popen(
        [
            PY,
            str(BROWSER_PY),
            "--cdp-port",
            str(port),
            "register-exec",
            "-t",
            "early",
            "--",
            "sleep",
            "30",
        ],
        env=_env(cache),
        stdin=subprocess.DEVNULL,
    )
    try:

        def first() -> bool:
            for path in (cache / "clients").glob("*.json"):
                with contextlib.suppress(OSError, ValueError):
                    if json.loads(path.read_text(encoding="utf-8")).get("kind"):
                        return True
            return False

        assert _wait(first, 30, step=0.005)
        os.kill(proc.pid, signal.SIGUSR1)  # default action would kill it
        os.kill(proc.pid, signal.SIGUSR2)
        time.sleep(1.0)
        assert proc.poll() is None, "the wrapper died of an early signal"
    finally:
        proc.terminate()
        proc.wait(10)


def test_clients_stops_an_orphaned_child_group(cache):
    port = _free_port()
    with _fake_client(cache, port) as fc:
        child = int(fc["rec"]["child_pid"])
        os.kill(int(fc["rec"]["pid"]), signal.SIGKILL)  # the wrapper dies
        fc["proc"].wait(5)
        assert "T" not in _stat(child) and _stat(child)  # the child lives on
        res = subprocess.run(
            [PY, str(BROWSER_PY), "--cdp-port", str(port), "clients"],
            env=_env(cache),
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        assert res.returncode == 0
        assert "orphaned child group" in res.stdout
        assert _wait(lambda: not _stat(child), 10), "orphan still running"


def test_legacy_wrapper_is_named_instead_of_a_gate_timeout(quiet_tx):
    old = browser._registry_register("playwright-mcp", "npx @playwright/mcp", 59990)
    try:
        t0 = time.monotonic()
        with pytest.raises(browser.MaintenanceRefused, match="Restart the Claude"):
            with browser._maintenance("slack", "B", port=59990):
                pytest.fail("must not start")
        assert time.monotonic() - t0 < 5  # no 20 s gate wait
    finally:
        old()
    assert not browser.MAINTENANCE_FILE.exists()


def test_down_and_switch_refuse_during_a_guided_login(cache, monkeypatch, capsys):
    _write_record(owner_nonce="d" * 32)
    assert browser.cmd_switch(59990, "headless", force=True) == 75
    assert browser.cmd_down(59990, force=True) == 75
    err = capsys.readouterr().err
    assert "busy: guided login for slack" in err and "-F/--force-maintenance" in err
    monkeypatch.setattr(browser, "_browser_mode", lambda port: None)
    # -F gets past the guard (then: nothing to switch on this port).
    assert browser.cmd_switch(59990, "headless", force_maintenance=True) == 1
    monkeypatch.setenv(browser.MAINTENANCE_ENV, "d" * 32)  # the owner itself
    assert browser.cmd_switch(59990, "headless") == 1


def test_switch_and_down_parse_force_maintenance(monkeypatch):
    for argv in (["switch", "headless", "-F"], ["down", "-F"]):
        monkeypatch.setattr(sys, "argv", ["browser.py", *argv])
        assert browser.parse_args().force_maintenance is True


def test_launch_guard_refuses_without_the_marker():
    with pytest.raises(SystemExit, match="test guard"):
        browser._launch_browser("/nonexistent/chrome", [])


def test_agent_login_treats_busy_as_skip_not_logout(monkeypatch, tmp_path):
    sys.path.insert(0, str(_REPO))
    al = _load("agent_login_busy_test", _REPO / "agent-login.py")
    calls: list[tuple] = []

    def fake_browser(*args, quiet=False):
        calls.append(args)
        return 75

    monkeypatch.setattr(al, "_browser", fake_browser)
    monkeypatch.setattr(
        al.subprocess, "run", lambda *a, **k: pytest.fail("tried `browser.py login`")
    )
    assert al.ensure_logged_in("cscs") == (None, al.BUSY_HOW)
    assert calls == [("logged-in", "cscs")]
    # -c -m: a busy site is skipped — no failure, no mail.
    monkeypatch.setattr(al, "wait_for_network", lambda: True)
    monkeypatch.setattr(al, "ensure_browser_up", lambda: True)
    monkeypatch.setattr(
        al,
        "overview",
        lambda **k: {
            "broker_ok": True,
            "broker": "ok",
            "rows": [{"site": "cscs", "status": "ready"}],
        },
    )
    monkeypatch.setattr(al, "send_mail", lambda *a: pytest.fail("mailed a failure"))
    monkeypatch.setattr(al, "record_check", lambda *a: pytest.fail("recorded busy"))
    assert al.check_all(mail=True) == 0


# --- agent-login routing ---------------------------------------------------------


def test_agent_login_g_routes_human_logins_to_assisted_login(monkeypatch):
    sys.path.insert(0, str(_REPO))
    al = _load("agent_login_guided_test", _REPO / "agent-login.py")
    calls: list[tuple] = []

    forced: list[bool] = []

    def cmd(site: str, start: str | None = None, force: bool = False) -> int:
        calls.append((site, start))
        forced.append(force)
        return 0

    def window(site: str, force: bool = False) -> int:
        calls.append(("window", site))
        forced.append(force)
        return 0

    monkeypatch.setattr(al, "assisted_login_cmd", cmd)
    monkeypatch.setattr(al, "assisted_login", window)
    monkeypatch.setattr(al, "assisted_check", lambda s: (False, "NOT logged in"))
    monkeypatch.setattr(al, "record_check", lambda *a, **k: None)
    assert al.manual_login("anibis") == 0  # assisted-login's own exit code
    assert calls[-1] == ("anibis", al.MANUAL_START["anibis"])
    assert al.manual_login("slack") == 2  # the post-check still says logged out
    assert calls[-1] == ("slack", None)
    al.manual_login("anthropic")
    assert calls[-1] == ("window", "anthropic")  # claude.ai keeps its own flow
    al.manual_login("switch")
    assert calls[-1] == ("window", "switch")
    assert "anthropic" not in al.VIEWER_SITES and "notion" in al.VIEWER_SITES
    assert not any(forced)
    # -F: every route passes the force on (assisted-login -f / the transaction).
    for site in ("anibis", "notion", "anthropic", "switch"):
        al.manual_login(site, force=True)
    assert forced[-4:] == [True] * 4


def test_agent_login_force_appends_f_and_needs_g(monkeypatch, capsys):
    sys.path.insert(0, str(_REPO))
    al = _load("agent_login_force_test", _REPO / "agent-login.py")
    assert al.assisted_login_argv("notion", None, True)[-3:] == [
        "assisted-login",
        "notion",
        "-f",
    ]
    assert al.assisted_login_argv("anibis", "https://x/l")[-4:] == [
        "assisted-login",
        "anibis",
        "-u",
        "https://x/l",
    ]
    assert al.build_parser().parse_args(["-g", "notion", "-F"]).force is True
    assert al.build_parser().parse_args(["-g", "notion", "--force"]).force is True
    monkeypatch.setattr(sys, "argv", ["agent-login.py", "-F"])
    with pytest.raises(SystemExit) as exc:
        al.main()
    assert exc.value.code == 2
    assert "-F/--force only works together with -g/--guided" in capsys.readouterr().err


# --- disposable browser end to end -------------------------------------------------

E2E = pytest.mark.skipif(
    os.environ.get("LOGIN_BROKER_E2E") != "1", reason="set LOGIN_BROKER_E2E=1"
)

LOGIN_PAGE = """<!doctype html><html><head><meta charset="utf-8"><title>test login</title>
<style>body{margin:0;font:16px sans-serif} input,button{position:absolute;left:20px;
width:300px;height:30px;font-size:16px}</style></head><body>
<form method="post" action="/login">
<input id="user" name="user" style="top:20px" autocomplete="off">
<input id="pw" name="pw" type="password" style="top:80px">
<button style="top:140px;width:120px">Sign in</button></form></body></html>"""
# A login that wants a passkey: the remote view must hand over to the window.
PASSKEY_PAGE = """<!doctype html><html><head><meta charset="utf-8"></head><body
style="margin:0"><button id="pk" style="position:absolute;left:20px;top:20px;width:200px;
height:40px" onclick="navigator.credentials.get({publicKey:{challenge:new Uint8Array(16)}})
.catch(e => document.title = e.name)">Use a passkey</button></body></html>"""
# An OAuth-style login: the form lives in a popup (window.open, openerId set).
POPUP_PAGE = """<!doctype html><html><head><meta charset="utf-8"></head><body
style="margin:0"><button id="go" style="position:absolute;left:20px;top:20px;width:200px;
height:40px" onclick="window.open('/login', 'idp', 'width=500,height=400')">Sign in with
IdP</button></body></html>"""


LOGIN_LOADS: list[float] = []


class _Site(http.server.BaseHTTPRequestHandler):
    def _send(self, code: int, body: str = "", headers: dict | None = None) -> None:
        data = body.encode()
        self.send_response(code)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/login":
            LOGIN_LOADS.append(time.monotonic())  # every (re)load of the login page
        if self.path.startswith("/account"):
            if "sid=ok" in (self.headers.get("Cookie") or ""):
                self._send(200, '<div id="account">welcome alice</div>')
            else:
                # No redirect: a GET /login then only ever comes from a tab
                # that SHOWS the login page (the owned one), never a probe.
                self._send(401, "<p>not logged in</p>")
            return
        pages = {"/passkey": PASSKEY_PAGE, "/popup": POPUP_PAGE}
        self._send(200, pages.get(self.path, LOGIN_PAGE))

    def do_POST(self) -> None:  # noqa: N802
        size = int(self.headers.get("Content-Length") or 0)
        form = urllib.parse.parse_qs(self.rfile.read(size).decode())
        if form.get("user") == ["alice"] and form.get("pw") == ["s3cret ü"]:
            self._send(
                303, "", {"Location": "/account", "Set-Cookie": "sid=ok; Path=/"}
            )
        else:
            self._send(303, "", {"Location": "/login"})

    def log_message(self, *_a: object) -> None:
        pass


@pytest.fixture
def disposable(cache, tmp_path):
    """A headless CfT on a free port (temp cache), plus the local login site."""
    LOGIN_LOADS.clear()
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Site)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    sites = tmp_path / "sites.json"
    sites.write_text(
        json.dumps(
            {
                name: {
                    "login_url": f"{base}{path}",
                    "check_url": f"{base}/account",
                    "logged_in_selector": "#account",
                    # testsite's check picks a tab by origin (like slack/openai/
                    # claude) — outside a guided login that IS the owned tab.
                    **({"probe": "pick"} if name == "testsite" else {}),
                }
                for name, path in (
                    ("testsite", "/login"),
                    ("passkeysite", "/passkey"),
                    ("popupsite", "/popup"),
                )
            }
        ),
        encoding="utf-8",
    )
    port = _free_port()
    env = _env(
        cache,
        CLAUDE_BROWSER_TEST_SITES=str(sites),
        CLAUDE_BROWSER_TEST_VIEWER_URL_FILE=str(tmp_path / "viewer-url"),
    )
    up = subprocess.run(
        [PY, str(BROWSER_PY), "--cdp-port", str(port), "up"],
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert up.returncode == 0, up.stdout + up.stderr
    assert browser._browser_mode(port) == "headless"
    try:
        yield {
            "port": port,
            "env": env,
            "base": base,
            "viewer_url": tmp_path / "viewer-url",
        }
    finally:
        subprocess.run(
            [PY, str(BROWSER_PY), "--cdp-port", str(port), "down", "-f"],
            env=env,
            capture_output=True,
            timeout=120,
            check=False,
        )
        srv.shutdown()


def _pages(port: int) -> list[dict]:
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/json/list", timeout=5) as r:
        return [t for t in json.loads(r.read()) if t.get("type") == "page"]


class _Pty:
    """`browser.py assisted-login` under a pseudo-terminal (/dev/tty works)."""

    def __init__(self, argv: list[str], env: dict[str, str]) -> None:
        self.pid, self.fd = pty.fork()
        if self.pid == 0:  # child: exec at once (no Python code after the fork)
            os.execve(argv[0], argv, env)
        self.out = ""
        self.rc: int | None = None
        # Drain the pty all the time: a full pty buffer would block the child.
        threading.Thread(target=self._drain, daemon=True).start()

    def _drain(self) -> None:
        while True:
            try:
                ready, _, _ = select.select([self.fd], [], [], 0.2)
                if ready:
                    data = os.read(self.fd, 65536)
                    if not data:
                        return
                    self.out += data.decode(errors="replace")
            except OSError:
                return  # EIO: the child side is closed

    def exited(self) -> bool:
        if self.rc is None:
            pid, status = os.waitpid(self.pid, os.WNOHANG)
            if pid:
                self.rc = os.waitstatus_to_exitcode(status)
        return self.rc is not None

    def expect(self, text: str, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if text in self.out:
                return True
            if self.exited():
                time.sleep(0.3)
                return text in self.out
            time.sleep(0.1)
        return False

    def send(self, text: str) -> None:
        os.write(self.fd, text.encode())

    def wait(self, timeout: float) -> int | None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.exited():
                time.sleep(0.3)  # let the drain thread pick up the last lines
                return self.rc
            time.sleep(0.1)
        return None

    def kill(self) -> None:
        if not self.exited():
            with contextlib.suppress(OSError):
                os.kill(self.pid, signal.SIGINT)  # the human's Ctrl-C: cleanup runs
            if self.wait(30) is None:
                with contextlib.suppress(OSError):
                    os.kill(self.pid, signal.SIGKILL)
                with contextlib.suppress(OSError):
                    os.waitpid(self.pid, 0)


def _click(page, x_css: float, y_css: float) -> None:
    """Click target CSS coordinates through the viewer canvas."""
    box = page.eval_on_selector(
        "#c",
        "c => { const r = c.getBoundingClientRect(); return [r.left, r.top, r.width]; }",
    )
    meta = page.evaluate("window.__viewerStats.meta")
    scale = box[2] / meta["deviceWidth"]
    page.mouse.click(box[0] + x_css * scale, box[1] + y_css * scale)


def _frames(page) -> int:
    return int(page.evaluate("window.__viewerStats ? window.__viewerStats.frames : 0"))


@contextlib.contextmanager
def _guided(disposable: dict, site: str) -> Iterator[tuple[_Pty, Any]]:
    """`assisted-login SITE` under a pty, confirmed, with the viewer open in a
    second disposable headless browser; yields (run, viewer page)."""
    # Deferred: only the opt-in browser tests need playwright.
    from playwright.sync_api import (  # pylint: disable=import-outside-toplevel
        sync_playwright,
    )

    port, env = disposable["port"], disposable["env"]
    argv = [PY, str(BROWSER_PY), "--cdp-port", str(port), "assisted-login", site]
    run = _Pty(argv, env)
    try:
        assert run.expect("type the site name to start", 90), run.out
        run.send(site + "\n")
        url_file = disposable["viewer_url"]
        assert _wait(url_file.exists, 60), run.out
        url = url_file.read_text(encoding="utf-8").strip()
        with sync_playwright() as pw:
            viewer = pw.chromium.launch(
                executable_path=browser._chromium_binary(), headless=True
            )
            try:
                # bypass_csp: only so the TEST can poll the viewer page with
                # wait_for_function (the page itself runs under its strict CSP).
                page = viewer.new_context(
                    viewport={"width": 1000, "height": 700}, bypass_csp=True
                ).new_page()
                page.goto(url)
                page.wait_for_function(
                    "window.__viewerStats && window.__viewerStats.frames > 2",
                    timeout=20000,
                )
                yield run, page
            finally:
                viewer.close()
    finally:
        run.kill()
        print(run.out)  # shown with -s: the human-facing transcript


def _type_login(page) -> None:
    """Fill the login form (LOGIN_PAGE coordinates) through the viewer; submit."""
    _click(page, 100, 35)
    page.keyboard.type("alice")
    _click(page, 100, 95)
    page.keyboard.insert_text("s3cret ü")  # paste-like, non-ASCII
    page.keyboard.press("Enter")


def _stranger(disposable: dict) -> subprocess.CompletedProcess:
    """A `browser.py open -N` WITHOUT the owner token, during the session."""
    env = {k: v for k, v in disposable["env"].items() if k != browser.MAINTENANCE_ENV}
    return subprocess.run(
        [
            PY,
            str(BROWSER_PY),
            "--cdp-port",
            str(disposable["port"]),
            "open",
            "-N",
            "about:blank",
        ],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


def _assert_cleaned_up(disposable: dict, owned: list[str], child: int) -> None:
    port = disposable["port"]
    assert not browser.MAINTENANCE_FILE.exists()
    assert _wait(lambda: "T" not in _stat(child), 10), "client not resumed"
    left = {t["id"] for t in _pages(port)}
    assert not set(owned) & left, "owned targets left open"
    assert not [t for t in _pages(port) if disposable["base"] in t.get("url", "")]
    assert browser._browser_mode(port) == "headless"


NO_FORK_WARNING = pytest.mark.filterwarnings(
    "ignore:This process .* is multi-threaded:DeprecationWarning"
)


@E2E
@NO_FORK_WARNING
@pytest.mark.browser
@pytest.mark.launches_chrome
def test_e2e_guided_login_through_the_viewer(disposable):
    port = disposable["port"]
    with _fake_client(browser.CACHE_DIR, port) as fc:
        child = int(fc["rec"]["child_pid"])
        with _guided(disposable, "testsite") as (run, page):
            # During the session: the client is frozen, strangers are refused.
            assert "T" in _stat(child)
            rec = _record()
            assert rec["mode"] == "B" and len(rec["owned_targets"]) == 1
            owned = list(rec["owned_targets"])
            stranger = _stranger(disposable)
            assert stranger.returncode == 75, stranger.stderr
            assert stranger.stderr.startswith("busy: guided login for testsite")
            # The success probe never touches the owned login tab: over two
            # probe rounds the login page was loaded exactly once and the
            # owned tab is still on it (a pick-the-tab probe would navigate it).
            time.sleep(2 * browser.GUIDED_PROBE_EVERY_S + 2)
            assert len(LOGIN_LOADS) == 1, LOGIN_LOADS
            tab = next(t for t in _pages(port) if t["id"] == owned[0])
            assert tab["url"].endswith("/login"), tab["url"]
            # The owned tab's viewport follows the viewer's canvas.
            assert _wait(
                lambda: page.evaluate("window.__viewerStats.meta.deviceWidth") == 1000,
                10,
            )
            _type_login(page)
            assert run.wait(90) == 0, run.out
            # The view ends with a final line, not a bare "disconnected".
            assert page.evaluate("document.getElementById('st').textContent") == (
                "✅ Logged in to testsite — you can close this tab"
            )
        assert "✅ testsite: logged in" in run.out
        _assert_cleaned_up(disposable, owned, child)


@E2E
@NO_FORK_WARNING
@pytest.mark.browser
@pytest.mark.launches_chrome
def test_e2e_oauth_popup_is_followed_and_closed(disposable):
    port = disposable["port"]
    with _fake_client(browser.CACHE_DIR, port) as fc:
        child = int(fc["rec"]["child_pid"])
        with _guided(disposable, "popupsite") as (run, page):
            n = _frames(page)
            _click(page, 120, 40)  # window.open('/login') in the owned tab
            assert _wait(lambda: len(_record()["owned_targets"]) == 2, 15), run.out
            owned = list(_record()["owned_targets"])
            popup = owned[1]
            assert any(t["id"] == popup for t in _pages(port))
            assert _wait(lambda: _frames(page) > n + 1, 10)  # the popup is shown
            _type_login(page)  # typed into the POPUP through the same viewer
            assert run.wait(90) == 0, run.out
        assert "following a popup" in run.out and "✅ popupsite: logged in" in run.out
        _assert_cleaned_up(disposable, owned, child)


@E2E
@NO_FORK_WARNING
@pytest.mark.browser
@pytest.mark.launches_chrome
def test_e2e_passkey_ends_the_view_and_offers_the_window(disposable):
    port = disposable["port"]
    with _fake_client(browser.CACHE_DIR, port) as fc:
        child = int(fc["rec"]["child_pid"])
        with _guided(disposable, "passkeysite") as (run, page):
            owned = list(_record()["owned_targets"])
            _click(page, 120, 40)  # navigator.credentials.get({publicKey})
            assert run.expect("switch to a visible window", 30), run.out
            assert "passkey" in run.out
            # The owned tab is closed BEFORE the question; nothing headed yet.
            assert not set(owned) & {t["id"] for t in _pages(port)}
            assert browser._browser_mode(port) == "headless"
            run.send("n\n")  # declined: never a window in this test
            assert run.wait(60) == 2, run.out
        assert "still not logged in" in run.out
        _assert_cleaned_up(disposable, owned, child)


@E2E
@NO_FORK_WARNING
@pytest.mark.browser
@pytest.mark.launches_chrome
def test_e2e_watchdog_closes_owned_targets_after_sigkill(disposable):
    port = disposable["port"]
    with _fake_client(browser.CACHE_DIR, port) as fc:
        child = int(fc["rec"]["child_pid"])
        owner = _owner(browser.CACHE_DIR, port)
        owned = _record()["owned_targets"]
        assert len(owned) == 1 and owned[0] in {t["id"] for t in _pages(port)}
        owner.kill()
        owner.wait(5)
        assert _wait(lambda: not browser.MAINTENANCE_FILE.exists(), 20)
        assert _wait(lambda: owned[0] not in {t["id"] for t in _pages(port)}, 10)
        assert _wait(lambda: "T" not in _stat(child), 10)
