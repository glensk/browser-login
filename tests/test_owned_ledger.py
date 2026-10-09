"""The owned-tab ledger and its reaper (tp#845).

Pinned with a fake CDP endpoint and real child processes that get SIGKILLed —
never a real Chrome, never the live browser:

* O9 — crash points: killed after the createTarget reply but before the tid is
  written, and killed with only the temp file of that write on disk → both tabs
  are reaped by their exact marker URL; nothing else is touched;
* O10 — tri-state liveness: the owner's flock wins over `ps`; a `ps` failure is
  `unknown` and never reaped; a reused pid is `dead`;
* two reapers → exactly one acts; a failed close keeps the tid; a reaper killed
  mid-pass leaves a claimable ledger; orphaned nested popups close leaves-first;
* an `open -N` handoff survives a reap pass after its creator exited;
* `reap-owned` under a foreign guided login → 75; `-n` closes nothing; `status`
  and `_preflight` never reap;
* a mode-A guided login reaps the ledger of its killed `login` child in
  `_guided_a`'s finally.

Run: uv run pytest -q tests/test_owned_ledger.py     (from the repo root)
"""

from __future__ import annotations

# Tests reach into browser.py's private helpers on purpose (it is a script).
# pylint: disable=protected-access,missing-function-docstring,import-error
# pylint: disable=redefined-outer-name,unused-argument,too-few-public-methods
# pylint: disable=missing-class-docstring
# The cache fixture mirrors test_login_timeout's on purpose.
# pylint: disable=duplicate-code
import ast
import contextlib
import fcntl
import importlib.util
import json
import os
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from pathlib import Path

import pytest
from fake_cdp import FakeCdp

_REPO = Path(__file__).resolve().parent.parent
_BROWSER_PY = _REPO / "bin" / "browser.py"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


browser = _load("browser_owned_ledger_test", _BROWSER_PY)

KEEP = "KEEP0001"
OLD_START = "Mon Jan  1 00:00:00 2001"  # no live process started then


# --- fixtures -------------------------------------------------------------------


@pytest.fixture
def fake() -> Iterator[FakeCdp]:
    srv = FakeCdp()
    srv.add(KEEP, "https://keep.example/", "keep")  # a page: no keep-alive needed
    yield srv
    srv.close()


@pytest.fixture
def cache(tmp_path, monkeypatch):
    """Every coordination file (and the journal) in tmp_path, for us and children."""
    monkeypatch.setenv("CLAUDE_BROWSER_CACHE_DIR", str(tmp_path))
    monkeypatch.setenv("CLAUDE_BROWSER_JOURNAL_FILE", str(tmp_path / "journal.jsonl"))
    monkeypatch.delenv("CLAUDE_BROWSER_LEASE_HELD", raising=False)
    monkeypatch.delenv(browser.MAINTENANCE_ENV, raising=False)
    for name, value in {
        "CACHE_DIR": tmp_path,
        "LIFECYCLE_FILE": tmp_path / ".browser-lifecycle.json",
        "CLIENTS_DIR": tmp_path / "clients",
        "REGISTRY_GATE": tmp_path / "clients" / ".registry.lock",
        "INTERACTION_LOCK": tmp_path / "interaction.lock",
        "MAINTENANCE_FILE": tmp_path / "maintenance.json",
        "MAINTENANCE_LOCK": tmp_path / ".maintenance.lock",
    }.items():
        monkeypatch.setattr(browser, name, value)
    monkeypatch.setattr(browser, "CLOSE_OWNED_CONFIRM_S", 0.3)
    browser._ACTIVE_DEADLINE.clear()
    yield tmp_path
    browser._ACTIVE_DEADLINE.clear()


def _owned(cache: Path) -> Path:
    return cache / "owned"


def _write_ledger(
    cache: Path,
    entries: list[dict],
    *,
    pid: int,
    start: str | None,
    stem: str | None = None,
) -> Path:
    """A ledger as an owner would have left it (no flock held by anybody)."""
    stem = stem or f"{pid}-deadbeef"
    path = _owned(cache) / f"{stem}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    (path.parent / f"{stem}.lock").touch()
    rec = {"pid": pid, "pid_start_time": start, "entries": entries}
    path.write_text(json.dumps(rec), encoding="utf-8")
    return path


def _dead_pid() -> int:
    with subprocess.Popen([sys.executable, "-c", "pass"]) as proc:  # noqa: S603
        proc.wait()
    return proc.pid


def _entry(tid: str | None, marker: str | None = None, parent: str | None = None):
    return {"marker": marker, "tid": tid, "parent": parent, "created": "x"}


def _write_foreign_record() -> None:
    rec = {
        "owner_nonce": "f" * 32,
        "pid": os.getpid(),
        "pid_start_time": browser._proc_lstart(os.getpid()),
        "site": "slack",
        "mode": "B",
        "state": "active",
        "owned_targets": [],
        "paused": [],
        "started": "2026-10-09T10:00:00+0200",
        "heartbeat": time.time(),
        "until": time.time() + 600,
    }
    browser.MAINTENANCE_FILE.parent.mkdir(parents=True, exist_ok=True)
    browser.MAINTENANCE_FILE.write_text(json.dumps(rec), encoding="utf-8")


# --- O9: crash points between createTarget and the tid write ------------------------

# A child that creates one owned tab against the fake and dies at a crash point.
_CRASH_CHILD = """
import importlib.util, json, os, signal, sys
spec = importlib.util.spec_from_file_location("b", sys.argv[1])
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)
port, mode = int(sys.argv[2]), sys.argv[3]

def die(*_a, **_k):
    os.kill(os.getpid(), signal.SIGKILL)

if mode == "after-reply":  # the CDP reply arrived, the tid was never written
    b.OwnedLedger.bind = die
elif mode == "tmp-only":  # the tid write got as far as its temp file
    real = b._json_write_atomic
    def write(path, data):
        if path.parent.name == "owned" and any(
            e.get("tid") for e in data.get("entries", [])
        ):
            b._unique_tmp(path).write_text(json.dumps(data))
            die()
        return real(path, data)
    b._json_write_atomic = write
elif mode == "hold":  # the tid is on record, then the process waits to be killed
    real_bind = b.OwnedLedger.bind
    def bind_and_wait(self, marker, tid):
        real_bind(self, marker, tid)
        print("bound", flush=True)
        __import__("time").sleep(600)
    b.OwnedLedger.bind = bind_and_wait
with b._owned_background_page(port):
    pass
"""


def _crash_child(port: int, mode: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-c", _CRASH_CHILD, str(_BROWSER_PY), str(port), mode],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


@pytest.mark.parametrize("mode", ["after-reply", "tmp-only"])
def test_a_crash_before_the_tid_is_written_is_reaped_by_its_marker(fake, cache, mode):
    fake.add("OTHER1", "about:blank#owned-" + "0" * 32)  # somebody else's marker
    proc = _crash_child(fake.port, mode)
    assert proc.returncode == -signal.SIGKILL, proc.stderr
    assert len(fake.created) == 1
    tid = fake.created[0]
    assert fake.targets[tid].url.startswith(browser.OWNED_MARKER_PREFIX)
    ledgers = list(_owned(cache).glob("*.json"))
    assert len(ledgers) == 1
    rec = json.loads(ledgers[0].read_text())
    assert [e["tid"] for e in rec["entries"]] == [None]  # only phase 1 on disk
    if mode == "tmp-only":
        assert list(_owned(cache).glob(".*.tmp"))
    report = browser._reap_owned(fake.port)
    assert report.closed == [tid] and not report.left
    assert fake.closed == [tid]
    assert {KEEP, "OTHER1"} <= set(fake.targets)  # nothing else touched
    assert not list(_owned(cache).iterdir())  # ledger, lock and temp file gone


# --- O10: tri-state liveness ------------------------------------------------------------


def test_the_owners_flock_wins_over_ps(fake, cache, monkeypatch):
    ledger = browser._owned_ledger()
    ledger.pending("m" * 32)
    path = _owned(cache) / f"{ledger.stem}.json"
    monkeypatch.setattr(browser, "_pid_alive", lambda pid: False)  # `ps`: dead
    monkeypatch.setattr(browser, "_proc_lstart", lambda pid: None)
    assert browser._owner_state(path) == "live"
    report = browser._reap_owned(fake.port)
    assert report.skipped == {ledger.stem: "live"} and not report.owners
    ledger.drop([], markers=["m" * 32])
    assert not list(_owned(cache).iterdir())  # the owner deletes an empty ledger


def test_a_ps_failure_is_unknown_and_never_reaped(fake, cache, monkeypatch):
    fake.add("T1", "https://x.example/")
    path = _write_ledger(cache, [_entry("T1")], pid=os.getpid(), start="whenever")
    monkeypatch.setattr(browser, "_proc_lstart", lambda pid: None)
    assert browser._owner_state(path) == "unknown"
    report = browser._reap_owned(fake.port)
    assert report.skipped == {path.stem: "unknown"} and not fake.closed
    assert path.exists()


def test_garbage_ledger_data_is_unknown(fake, cache):
    path = _write_ledger(cache, [], pid=os.getpid(), start=None)
    path.write_text("{not json", encoding="utf-8")
    assert browser._owner_state(path) == "unknown"


def test_a_reused_pid_is_dead_and_reaped(fake, cache):
    fake.add("T1", "https://x.example/")
    path = _write_ledger(cache, [_entry("T1")], pid=os.getpid(), start=OLD_START)
    assert browser._owner_state(path) == "dead"
    report = browser._reap_owned(fake.port)
    assert report.closed == ["T1"] and not path.exists()


def test_a_gone_pid_is_dead(fake, cache):
    path = _write_ledger(cache, [], pid=_dead_pid(), start="whenever")
    assert browser._owner_state(path) == "dead"


# --- concurrency and failures --------------------------------------------------------------


def test_two_reapers_exactly_one_acts(fake, cache, monkeypatch):
    fake.add("T1", "https://x.example/")
    _write_ledger(cache, [_entry("T1")], pid=_dead_pid(), start="x")
    inside, go_on = threading.Event(), threading.Event()
    real = browser._close_owned_targets

    def slow_close(port, ids, **kw):
        inside.set()
        go_on.wait(10)
        return real(port, ids, **kw)

    monkeypatch.setattr(browser, "_close_owned_targets", slow_close)
    first: list = []
    worker = threading.Thread(
        target=lambda: first.append(browser._reap_owned(fake.port)), daemon=True
    )
    worker.start()
    assert inside.wait(10)
    second = browser._reap_owned(fake.port)  # while the first one is closing
    go_on.set()
    worker.join(10)
    assert second.busy and not second.closed
    assert not first[0].busy and first[0].closed == ["T1"]
    assert fake.closed == ["T1"]


def test_a_failed_close_keeps_the_tid_for_the_next_pass(fake, cache, monkeypatch):
    fake.add("T1", "https://x.example/")
    path = _write_ledger(cache, [_entry("T1")], pid=_dead_pid(), start="x")
    with monkeypatch.context() as mp:
        mp.setattr(browser, "_cdp_close_target", lambda *a, **k: False)
        report = browser._reap_owned(fake.port)
    assert report.left == ["T1"] and not report.closed
    assert [e["tid"] for e in json.loads(path.read_text())["entries"]] == ["T1"]
    assert browser._reap_owned(fake.port).closed == ["T1"]
    assert not path.exists()


_KILLED_REAPER = """
import importlib.util, os, signal, sys
from pathlib import Path
spec = importlib.util.spec_from_file_location("b", sys.argv[1])
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)
def die(*_a, **_k):
    os.kill(os.getpid(), signal.SIGKILL)
b._close_owned_targets = die
b._reap_owned(int(sys.argv[2]))
"""


def test_a_reaper_killed_mid_pass_leaves_a_claimable_ledger(fake, cache):
    fake.add("ROOT", "https://x.example/")
    fake.add("POP1", "https://idp.example/", opener="ROOT")
    path = _write_ledger(cache, [_entry("ROOT")], pid=_dead_pid(), start="x")
    proc = subprocess.run(
        [sys.executable, "-c", _KILLED_REAPER, str(_BROWSER_PY), str(fake.port)],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert proc.returncode == -signal.SIGKILL, proc.stderr
    # The descendants were on record BEFORE the reaper tried to close anything.
    tids = [e["tid"] for e in json.loads(path.read_text())["entries"]]
    assert tids == ["ROOT", "POP1"] and not fake.closed
    report = browser._reap_owned(fake.port)  # its claim died with it
    assert report.closed == ["POP1", "ROOT"] and not path.exists()


def test_orphaned_nested_popups_close_leaves_first(fake, cache):
    fake.add("ROOT", "https://x.example/")
    fake.add("POP1", "https://idp.example/a", opener="ROOT")
    fake.add("POP2", "https://idp.example/b", opener="POP1")
    fake.add("FRAME", "https://ads.example/", type="iframe", opener="ROOT")
    fake.add("OTHER", "https://other.example/")
    _write_ledger(cache, [_entry("ROOT")], pid=_dead_pid(), start="x")
    report = browser._reap_owned(fake.port)
    assert fake.closed == ["POP2", "POP1", "ROOT"]
    assert sorted(report.closed) == ["POP1", "POP2", "ROOT"]
    assert {KEEP, "FRAME", "OTHER"} <= set(fake.targets)


def test_an_open_n_handoff_survives_a_reap_after_its_creator_exited(fake, cache):
    env = {k: v for k, v in os.environ.items() if k != browser.MAINTENANCE_ENV}
    proc = subprocess.run(
        [
            sys.executable,
            str(_BROWSER_PY),
            "--cdp-port",
            str(fake.port),
            "open",
            "-N",
            "https://handoff.example/",
        ],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    tid = fake.created[0]
    assert f"target={tid}" in proc.stdout
    assert not _owned(cache).exists() or not list(_owned(cache).glob("*.json"))
    report = browser._reap_owned(fake.port)
    assert not report.closed and tid in fake.targets


# --- coordination: 75, dry run, never from status/_preflight ---------------------------------


def test_reap_owned_under_a_foreign_guided_login_is_75(fake, cache):
    fake.add("T1", "https://x.example/")
    _write_ledger(cache, [_entry("T1")], pid=_dead_pid(), start="x")
    _write_foreign_record()
    with pytest.raises(SystemExit) as exc:
        browser.cmd_reap_owned(fake.port)
    assert exc.value.code == 75 and not fake.closed


def test_dry_run_closes_nothing_and_keeps_the_ledger(fake, cache, capsys):
    fake.add("T1", "https://x.example/")
    path = _write_ledger(cache, [_entry("T1")], pid=_dead_pid(), start="x")
    before = path.read_text()
    assert browser.cmd_reap_owned(fake.port, dry_run=True) == 0
    assert not fake.closed and path.read_text() == before
    out = capsys.readouterr().out
    assert "would close: [id T1]" in out and "1 tab(s) would be closed" in out


def test_cli_reap_owned_exits_0_then_reports(fake, cache):
    fake.add("T1", "https://x.example/")
    _write_ledger(cache, [_entry("T1")], pid=_dead_pid(), start="x")
    env = {k: v for k, v in os.environ.items() if k != browser.MAINTENANCE_ENV}
    proc = subprocess.run(
        [sys.executable, str(_BROWSER_PY), "--cdp-port", str(fake.port), "reap-owned"],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert "closed 1 tab(s)" in proc.stdout and fake.closed == ["T1"]
    events = [
        json.loads(ln)
        for ln in (cache / "journal.jsonl").read_text().splitlines()
        if '"reap_owned"' in ln
    ]
    assert events and events[0]["closed"] == 1 and events[0]["left"] == 0


def test_another_reaper_running_is_exit_0(fake, cache, capsys):
    fd = os.open(str(cache / browser.OWNED_REAPER_LOCK_NAME), os.O_RDWR | os.O_CREAT)
    _owned(cache).mkdir()
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        assert browser.cmd_reap_owned(fake.port) == 0
    finally:
        os.close(fd)
    assert "another reaper is running" in capsys.readouterr().out


def test_status_and_preflight_never_reap(fake, cache, monkeypatch):
    monkeypatch.setattr(browser, "_reap_owned", pytest.fail)
    monkeypatch.setattr(browser, "_reap_quietly", pytest.fail)
    browser._preflight("logged-in", fake.port)
    browser.cmd_status(fake.port, False)
    tree = ast.parse(_BROWSER_PY.read_text(encoding="utf-8"))
    for fn in (n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)):
        if fn.name in ("_preflight", "cmd_status", "_cmd_status_probe", "main"):
            names = {n.id for n in ast.walk(fn) if isinstance(n, ast.Name)}
            assert not names & {"_reap_owned", "_reap_quietly"}, fn.name


def test_doctor_line_is_read_only(fake, cache):
    fake.add("T1", "https://x.example/")
    path = _write_ledger(cache, [_entry("T1")], pid=_dead_pid(), start="x")
    log: list[str] = []
    browser._doctor_owned_ledgers(log)
    assert log == ["warn"] and path.exists() and not fake.closed


# --- the guided login reaps its killed `login` child --------------------------------------


def test_guided_a_reaps_the_ledger_of_its_killed_login_child(fake, cache, monkeypatch):
    """Mode A's built-in window flow runs `login SITE` as a child; killed by its
    timeout, the child's owned tab is in its ledger — `_guided_a`'s finally
    reaps it (the transaction holds the lease; strangers get 75)."""
    monkeypatch.setattr(browser, "_spawn_watchdog", lambda port, nonce: None)
    monkeypatch.setattr(browser, "_ensure_headless", lambda port: True)
    monkeypatch.setattr(browser, "_guided_probe", lambda port, site: False)
    children: list[int] = []

    def self_run(port, *args, capture=True, timeout=120.0, env=None):
        if args[0] != "login":
            return subprocess.CompletedProcess(args, 0, "", "")
        with subprocess.Popen(  # inherits the owner token: it may register
            [sys.executable, "-c", _CRASH_CHILD, str(_BROWSER_PY), str(port), "hold"],
            stdout=subprocess.PIPE,
            text=True,
        ) as child:
            children.append(child.pid)
            assert child.stdout is not None
            assert child.stdout.readline().strip() == "bound"
            child.kill()  # `subprocess.run(timeout=…)` kills it the same way
            child.wait(10)
        return subprocess.CompletedProcess(args, -9, "", "")

    monkeypatch.setattr(browser, "_self_run", self_run)
    with browser._maintenance("slack", "A", port=fake.port, force=True) as tx:
        outcome = browser._guided_a(tx, "slack", None, time.monotonic() + 60)
        tid = fake.created[0]
        assert tid not in fake.targets and tid in fake.closed  # reaped in finally
    assert outcome[0] == "fail" and children
    assert not list(_owned(cache).glob("*.json"))
    assert KEEP in fake.targets


# --- the ledger API itself ------------------------------------------------------------------


def test_ledger_lifecycle_two_phase_then_deleted(cache):
    ledger = browser._owned_ledger()
    assert ledger is browser._owned_ledger()  # one per process and cache dir
    ledger.pending("a" * 32)
    path = _owned(cache) / f"{ledger.stem}.json"
    assert json.loads(path.read_text())["entries"][0]["tid"] is None
    ledger.bind("a" * 32, "T1")
    ledger.add_children("T1", ["P1"])
    rec = json.loads(path.read_text())
    assert [(e["tid"], e["parent"]) for e in rec["entries"]] == [
        ("T1", None),
        ("P1", "T1"),
    ]
    assert rec["pid"] == os.getpid() and rec["pid_start_time"]
    ledger.drop(["P1"])
    assert ledger.tids() == ["T1"]
    ledger.drop(["T1"])
    assert not list(_owned(cache).iterdir())
    with contextlib.suppress(Exception):
        ledger.drop(["nope"])  # a drop on a deleted ledger is a no-op
    ledger.pending("b" * 32)  # a new stem, never the old one
    assert (_owned(cache) / f"{ledger.stem}.json").exists() and ledger.stem != path.stem
    ledger.drop([], markers=["b" * 32])
