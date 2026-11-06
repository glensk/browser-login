"""The shared agent Chromium never piles up (tp#1759, PLAN_browser-reap.md).

Pinned with fakes only — a fake CDP endpoint (tests/fake_cdp.py), never a real
Chrome, never the live browser:

* B1 marker v2: ``p<pid>-<h12>-<hex16>`` names its owner (pid + a hash of the
  RAW ``ps`` lstart string, never an epoch); legacy markers carry no owner;
  an owner whose start time is unknown falls back to the legacy form; a lost
  ``createTarget`` reply whose tab is listed late is still bound and closed.

Run: uv run pytest -q tests/test_browser_reap_tp1759.py     (from the repo root)
"""

from __future__ import annotations

# Tests reach into browser.py's private helpers on purpose (it is a script).
# pylint: disable=protected-access,missing-function-docstring,import-error
# pylint: disable=redefined-outer-name,unused-argument
# The cache fixture mirrors test_owned_ledger's on purpose.
# pylint: disable=duplicate-code
import hashlib
import importlib.util
import os
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


browser = _load("browser_reap_tp1759_test", _BROWSER_PY)

KEEP = "KEEP0001"
LSTART = "Thu Nov  6 09:16:00 2026"


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
    browser._SELF_LSTART.clear()
    yield tmp_path
    browser._ACTIVE_DEADLINE.clear()
    browser._SELF_LSTART.clear()


def _dead_pid() -> int:
    with subprocess.Popen([sys.executable, "-c", "pass"]) as proc:  # noqa: S603
        proc.wait()
    return proc.pid


def _ledgers(cache: Path) -> list[str]:
    owned = cache / "owned"
    return sorted(p.name for p in owned.iterdir()) if owned.is_dir() else []


def _v2(pid: int, lstart: str, tail: str = "0123456789abcdef") -> str:
    return f"p{pid}-{browser._lstart_hash(lstart)}-{tail}"


# --- B1: marker v2 --------------------------------------------------------------


def test_marker_round_trip_names_this_process(cache):
    marker = browser._new_owned_marker()
    own = browser._proc_lstart(os.getpid())
    assert own
    assert browser._marker_owner(marker) == (os.getpid(), browser._lstart_hash(own))
    assert browser._marker_owner_state(marker) == "live"
    assert browser._marker_of_url(browser._owned_marker_url(marker)) == marker


def test_marker_hash_is_the_raw_lstart_the_ledger_stores(cache, monkeypatch):
    monkeypatch.setattr(browser, "_proc_lstart", lambda pid: LSTART)
    marker = browser._new_owned_marker()
    want = hashlib.sha256(LSTART.encode()).hexdigest()[:12]  # no epoch conversion
    assert marker.split("-")[1] == want
    ledger = browser._owned_ledger()
    ledger.pending(marker)
    assert ledger.lstart == LSTART  # the ledger's pid_start_time, same raw string
    assert browser._lstart_hash(ledger.lstart) == want
    ledger.drop([], markers=[marker])


def test_legacy_marker_names_no_owner():
    legacy = "0a" * 16
    assert browser._marker_owner(legacy) is None
    assert browser._marker_owner_state(legacy) == "unknown"
    assert browser._marker_of_url(browser._owned_marker_url(legacy)) == legacy
    assert browser._marker_of_url(browser._owned_marker_url("nothex")) is None
    assert browser._marker_of_url(browser._owned_marker_url(legacy) + "x") is None


def test_unknown_own_start_time_falls_back_to_the_legacy_form(cache, monkeypatch):
    monkeypatch.setattr(browser, "_proc_lstart", lambda pid: None)
    marker = browser._new_owned_marker()
    assert browser.OWNED_MARKER_LEGACY_RE.fullmatch(marker)
    assert browser._marker_owner(marker) is None


def test_marker_owner_dead_reused_and_ps_failure(monkeypatch):
    assert browser._marker_owner_state(_v2(_dead_pid(), LSTART)) == "dead"
    reused = _v2(os.getpid(), "Mon Jan  1 00:00:00 2001")  # same pid, other start
    assert browser._marker_owner_state(reused) == "dead"
    monkeypatch.setattr(browser, "_proc_lstart", lambda pid: None)  # ps failed
    assert browser._marker_owner_state(_v2(os.getpid(), LSTART)) == "unknown"


def test_late_listing_within_the_poll_is_bound_and_closed(fake, cache, monkeypatch):
    fake.create_stall = True  # no reply, no target — the tab shows up late
    monkeypatch.setattr(browser, "OWNED_CREATE_BUDGET_S", 0.3)
    monkeypatch.setattr(browser, "OWNED_CREATE_POLL_S", 3.0)
    late: list[str] = []

    def appear() -> None:
        stop = time.monotonic() + 5.0
        while not fake.create_params and time.monotonic() < stop:
            time.sleep(0.02)
        time.sleep(0.8)  # after the reply budget, inside the poll
        fake.add("LATE0001", str(fake.create_params[0]["url"]))
        late.append("LATE0001")

    th = threading.Thread(target=appear, daemon=True)
    th.start()
    with pytest.raises(browser.OwnedTabError, match="did not answer"):
        with browser._owned_background_page(fake.port):
            pytest.fail("a lost reply's tab must never be used")
    th.join(5.0)
    assert late == ["LATE0001"]
    assert "LATE0001" in fake.closed and "LATE0001" not in fake.targets
    assert KEEP in fake.targets
    assert not [n for n in _ledgers(cache) if n.endswith(".json")]
    url = str(fake.create_params[0]["url"])
    assert browser._marker_owner(url[len(browser.OWNED_MARKER_PREFIX) :]) is not None


def test_no_listing_within_the_poll_drops_the_entry(fake, cache, monkeypatch):
    fake.create_stall = True
    monkeypatch.setattr(browser, "OWNED_CREATE_BUDGET_S", 0.2)
    monkeypatch.setattr(browser, "OWNED_CREATE_POLL_S", 0.5)
    with pytest.raises(browser.OwnedTabError, match="could not create"):
        with browser._owned_background_page(fake.port):
            pytest.fail("no tab was created")
    assert not [n for n in _ledgers(cache) if n.endswith(".json")]
