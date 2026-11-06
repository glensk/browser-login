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
import json
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


# --- B2: orphan marker rule + observation pass ------------------------------------


def _marker_url(marker: str) -> str:
    return str(browser._owned_marker_url(marker))


def _own_lstart() -> str:
    got = browser._proc_lstart(os.getpid())
    assert got
    return str(got)


def _write_ledger(cache: Path, name: str, rec: dict | str) -> Path:
    owned = cache / "owned"
    owned.mkdir(parents=True, exist_ok=True)
    path = owned / name
    path.write_text(rec if isinstance(rec, str) else json.dumps(rec), encoding="utf-8")
    return path


def _seen(cache: Path, tid: str, ago_s: float) -> None:
    state = browser._tabstate_empty()
    state["targets"][tid] = {"first_seen": time.time() - ago_s}
    (cache / browser.TABSTATE_NAME).write_text(json.dumps(state), encoding="utf-8")


def _first_seen(cache: Path, tid: str) -> object:
    path = cache / browser.TABSTATE_NAME
    if not path.exists():
        return None
    return json.loads(path.read_text())["targets"].get(tid, {}).get("first_seen")


def test_v2_marker_of_a_dead_owner_is_closed(fake, cache):
    fake.add("ORPH0001", _marker_url(_v2(_dead_pid(), LSTART)))
    report = browser._reap_owned(fake.port, coordinated=False)
    assert report.orphans.closed and "ORPH0001" in fake.closed
    assert KEEP in fake.targets
    events = (cache / "journal.jsonl").read_text()
    assert '"orphan_marker"' in events


def test_v2_marker_of_a_live_owner_is_spared(fake, cache):
    fake.add("LIVE0001", _marker_url(_v2(os.getpid(), _own_lstart())))
    report = browser._reap_owned(fake.port, coordinated=False)
    assert not report.orphans.closed and "LIVE0001" in fake.targets


def test_v2_marker_of_a_reused_pid_is_closed(fake, cache):
    fake.add("REUS0001", _marker_url(_v2(os.getpid(), "Mon Jan  1 00:00:00 2001")))
    browser._reap_owned(fake.port, coordinated=False)
    assert "REUS0001" in fake.closed


def test_ps_failure_spares_a_v2_marker(fake, cache, monkeypatch):
    fake.add("PSF00001", _marker_url(_v2(os.getpid(), LSTART)))
    monkeypatch.setattr(browser, "_proc_lstart", lambda pid: None)
    browser._reap_owned(fake.port, coordinated=False)
    assert "PSF00001" in fake.targets


def test_legacy_marker_within_the_grace_is_spared(fake, cache):
    fake.add("LEG00001", _marker_url("0b" * 16))
    _seen(cache, "LEG00001", browser.ORPHAN_MARKER_GRACE_S - 60)
    browser._reap_owned(fake.port, coordinated=False)
    assert "LEG00001" in fake.targets


def test_legacy_marker_after_the_grace_is_closed(fake, cache):
    fake.add("LEG00002", _marker_url("0c" * 16))
    _seen(cache, "LEG00002", browser.ORPHAN_MARKER_GRACE_S + 60)
    report = browser._reap_owned(fake.port, coordinated=False)
    assert "LEG00002" in fake.closed and report.orphans.closed


@pytest.mark.parametrize("how", ["live", "unknown", "tmp", "tid"])
def test_a_marker_any_ledger_names_is_never_an_orphan(fake, cache, how):
    marker = _v2(_dead_pid(), LSTART)  # would be an orphan on its own
    fake.add("NAMED001", _marker_url(marker))
    entry = {"marker": marker, "tid": None, "parent": None, "created": "x"}
    if how == "tid":
        entry = {"marker": None, "tid": "NAMED001", "parent": None, "created": "x"}
    rec = {"pid": os.getpid(), "pid_start_time": _own_lstart(), "entries": [entry]}
    if how == "unknown":
        rec["pid_start_time"] = None  # live pid, start unknown → owner unknown
    name = f"{os.getpid()}-abcd1234.json"
    if how == "tmp":
        name = f".{os.getpid()}-abcd1234.json.1a2b.tmp"
    _write_ledger(cache, name, rec)
    report = browser._reap_owned(fake.port, coordinated=False)
    assert "NAMED001" in fake.targets and not report.orphans.closed


def test_an_unreadable_ledger_stops_the_rule(fake, cache, capsys):
    fake.add("ORPH0002", _marker_url(_v2(_dead_pid(), LSTART)))
    _write_ledger(cache, f"{os.getpid()}-garbage1.json", "{not json")
    assert browser.cmd_reap_owned(fake.port) == 1
    assert "ORPH0002" in fake.targets
    assert "unreadable" in capsys.readouterr().err


def test_the_last_page_is_never_closed(fake, cache):
    fake.targets.pop(KEEP)
    fake.add("ORPH0003", _marker_url(_v2(_dead_pid(), LSTART)))
    browser._reap_owned(fake.port, coordinated=False)
    assert "ORPH0003" in fake.targets and not fake.closed


def test_a_url_changed_before_the_close_is_spared(fake, cache, monkeypatch):
    fake.add("ORPH0004", _marker_url(_v2(_dead_pid(), LSTART)))
    real = browser._target_snapshot
    calls: list[int] = []

    def snapshot(port, budget_s=3.0):
        calls.append(1)
        if len(calls) > 1:  # the fresh re-check: the tab was navigated meanwhile
            fake.targets["ORPH0004"].url = "https://now.example/"
        return real(port, budget_s)

    monkeypatch.setattr(browser, "_target_snapshot", snapshot)
    browser._reap_owned(fake.port, coordinated=False)
    assert "ORPH0004" in fake.targets and len(calls) >= 2


def test_dry_run_writes_nothing_and_closes_nothing(fake, cache, capsys):
    fake.add("ORPH0005", _marker_url(_v2(_dead_pid(), LSTART)))
    fake.add("LEG00003", _marker_url("0d" * 16))
    assert browser.cmd_reap_owned(fake.port, dry_run=True) == 0
    assert not fake.closed
    assert not (cache / browser.TABSTATE_NAME).exists()
    out = capsys.readouterr().out
    assert "would close: orphan marker (v2) [id ORPH0005]" in out
    assert "LEG00003" not in out


def test_reap_idle_skipped_75_legacy_marker_still_aged(fake, cache, monkeypatch):
    fake.add("LEG00004", _marker_url("0e" * 16))
    monkeypatch.setattr(browser, "_unknown_cdp_clients", lambda port: [(1, "mcp")])
    rc = browser.cmd_reap_idle(
        fake.port, dry_run=False, idle_h=None, max_n=20, all_instances=False, quiet=True
    )
    assert rc == browser.BUSY_RC
    assert _first_seen(cache, "LEG00004") is None
    browser._reap_owned(fake.port, coordinated=False)
    seen = _first_seen(cache, "LEG00004")
    assert isinstance(seen, float) and "LEG00004" in fake.targets
    _seen(cache, "LEG00004", browser.ORPHAN_MARKER_GRACE_S + 1)
    browser._reap_owned(fake.port, coordinated=False)
    assert "LEG00004" in fake.closed


def test_observation_keeps_opener_created_and_via(fake, cache):
    fake.add("BLANK001", "about:blank")
    state = browser._tabstate_empty()
    state["targets"]["BLANK001"] = {"created": 1.0, "via": "open", "opener": {"pid": 1}}
    (cache / browser.TABSTATE_NAME).write_text(json.dumps(state), encoding="utf-8")
    browser._reap_owned(fake.port, coordinated=False)
    entry = json.loads((cache / browser.TABSTATE_NAME).read_text())["targets"]
    assert entry["BLANK001"]["via"] == "open" and entry["BLANK001"]["created"] == 1.0
    assert entry["BLANK001"]["opener"] == {"pid": 1}
    assert "first_seen" in entry["BLANK001"] and KEEP not in entry


# --- B3: blank trim + about:blank start URL + startup record ------------------------

OLD = 3 * 3600.0  # idle well past BLANK_GRACE_S


def _page(tid: str, url: str) -> dict:
    return {"targetId": tid, "type": "page", "url": url, "title": ""}


def _state(**entries: dict) -> dict:
    state: dict = browser._tabstate_empty()
    state["targets"].update(entries)
    return state


def _ids(infos: list[dict]) -> list[str]:
    return sorted(str(i["targetId"]) for i in infos)


def _extras(pages, state, owned=frozenset(), restricted=False, now=None):
    now = time.time() if now is None else now
    return _ids(browser._blank_extras(pages, state, set(owned), restricted, now))


def test_blank_trim_keeps_exactly_one_and_prefers_about_blank():
    now = time.time()
    pages = [
        _page("NTP1", "chrome://newtab/"),
        _page("B1", "about:blank"),
        _page("B2", "about:blank"),
        _page("W1", "https://work.example/"),
    ]
    state = _state(
        NTP1={"first_seen": now - OLD - 100},  # oldest, but the NTP
        B1={"first_seen": now - OLD - 50},
        B2={"first_seen": now - OLD},
    )
    assert _extras(pages, state, now=now) == ["B2", "NTP1"]


def test_blank_trim_grace_pinned_and_last_page():
    now = time.time()
    pages = [_page("B1", "about:blank"), _page("B2", "about:blank")]
    young = _state(B1={"first_seen": now - OLD}, B2={"first_seen": now - 60})
    assert not _extras(pages, young, now=now)
    pinned = _state(
        B1={"first_seen": now - OLD}, B2={"first_seen": now - OLD + 1, "keep": True}
    )
    # The pinned one is never closed, so it is the survivor: the other goes.
    assert _extras(pages, pinned, now=now) == ["B1"]
    assert not _extras([pages[0]], _state(B1={"first_seen": now - OLD}), now=now)


def test_blank_trim_never_a_ledger_tab():
    now = time.time()
    pages = [_page("B1", "about:blank"), _page("B2", "about:blank")]
    state = _state(B1={"first_seen": now - OLD}, B2={"first_seen": now - OLD})
    assert not _extras(pages, state, owned={"B2"}, now=now)


def test_marker_urls_are_never_blank():
    now = time.time()
    pages = [
        _page("B1", "about:blank"),
        _page("M1", _marker_url("0f" * 16)),
        _page("X1", "about:blank#x"),
        _page("N2", "chrome://newtab/#x"),
    ]
    state = _state(**{t: {"first_seen": now - OLD} for t in ("B1", "M1", "X1", "N2")})
    assert not _extras(pages, state, now=now)


def test_restricted_trims_only_the_ntp_and_the_startup_blank():
    now = time.time()
    pages = [
        _page("S1", "about:blank"),
        _page("NTP1", "chrome://newtab/"),
        _page("B1", "about:blank"),  # maybe an MCP's tab: never in restricted mode
        _page("W1", "https://work.example/"),
    ]
    state = _state(
        S1={"created": now - OLD - 100, "via": "startup"},
        NTP1={"first_seen": now - OLD},
        B1={"first_seen": now - OLD},
    )
    assert _extras(pages, state, restricted=True, now=now) == ["NTP1", "S1"]
    assert _extras(pages, state, restricted=False, now=now) == ["B1", "NTP1"]


def _old_blanks(fake: FakeCdp, cache: Path) -> None:
    fake.add("B1", "about:blank")
    fake.add("B2", "about:blank")
    now = time.time()
    state = _state(B1={"first_seen": now - OLD - 10}, B2={"first_seen": now - OLD})
    (cache / browser.TABSTATE_NAME).write_text(json.dumps(state), encoding="utf-8")


@pytest.mark.parametrize("unknown", [None, [(1, "mcp")]])
def test_unknown_client_or_no_lsof_restricts_the_pass(
    fake, cache, monkeypatch, unknown
):
    _old_blanks(fake, cache)
    monkeypatch.setattr(browser, "_unknown_cdp_clients", lambda port: unknown)
    run = browser._blank_trim_pass(fake.port, dry_run=False)
    assert run.restricted and not run.closed and not fake.closed


def test_blank_trim_pass_closes_the_extra_and_drops_its_state(fake, cache, monkeypatch):
    _old_blanks(fake, cache)
    monkeypatch.setattr(browser, "_unknown_cdp_clients", lambda port: [])
    run = browser._blank_trim_pass(fake.port, dry_run=False)
    assert fake.closed == ["B2"] and len(run.closed) == 1 and not run.failed
    targets = json.loads((cache / browser.TABSTATE_NAME).read_text())["targets"]
    assert "B2" not in targets and "B1" in targets


def test_blank_trim_dry_run_closes_and_writes_nothing(fake, cache, monkeypatch):
    _old_blanks(fake, cache)
    before = (cache / browser.TABSTATE_NAME).read_text()
    monkeypatch.setattr(browser, "_unknown_cdp_clients", lambda port: [])
    run = browser._blank_trim_pass(fake.port, dry_run=True)
    assert len(run.would) == 1 and not fake.closed
    assert (cache / browser.TABSTATE_NAME).read_text() == before


def test_blank_trim_pass_spares_a_ledger_root_and_its_child(fake, cache, monkeypatch):
    _old_blanks(fake, cache)
    fake.targets["B2"].opener = "ROOT0001"  # a popup of a ledgered tab
    fake.add("ROOT0001", "about:blank")
    rec = {
        "pid": os.getpid(),
        "pid_start_time": _own_lstart(),
        "entries": [
            {"marker": None, "tid": "ROOT0001", "parent": None, "created": "x"}
        ],
    }
    _write_ledger(cache, f"{os.getpid()}-abcd1234.json", rec)
    monkeypatch.setattr(browser, "_unknown_cdp_clients", lambda port: [])
    run = browser._blank_trim_pass(fake.port, dry_run=False)
    assert not fake.closed and not run.closed


def test_an_unreadable_ledger_trims_nothing(fake, cache, monkeypatch):
    _old_blanks(fake, cache)
    _write_ledger(cache, f"{os.getpid()}-garbage1.json", "{not json")
    monkeypatch.setattr(browser, "_unknown_cdp_clients", lambda port: [])
    run = browser._blank_trim_pass(fake.port, dry_run=False)
    assert run.error and not fake.closed


def test_startup_page_is_recorded_as_startup_not_open(fake, cache):
    fake.add("START001", "about:blank")
    browser._tabstate_record_startup(fake.port, wait_s=0.5)
    entry = json.loads((cache / browser.TABSTATE_NAME).read_text())["targets"]
    assert entry["START001"]["via"] == "startup" and "opener" not in entry["START001"]
    assert KEEP not in entry


def test_launch_passes_about_blank_as_the_last_flag(cache, monkeypatch):
    seen: list[list[str]] = []

    class Stop(Exception):
        pass

    def launch(binary, flags, headless=False):
        seen.append(list(flags))
        raise Stop

    monkeypatch.setattr(browser, "PROFILE_DIR", cache / "profile")
    for name, value in {
        "_launch_guard": lambda port: None,
        "_clear_session_restore": lambda: None,
        "_chromium_binary": lambda: "/nonexistent/chrome",
        "_headless_user_agent": lambda binary: None,
        "_proxy_flags": lambda: [],
        "_apply_profile_prefs": lambda: None,
        "_lifecycle_write": lambda *a, **k: {"nonce": "n"},
        "_launch_browser": launch,
    }.items():
        monkeypatch.setattr(browser, name, value)
    with pytest.raises(Stop):
        browser._launch_and_record(1, headless=True)
    assert seen and seen[0][-1] == "about:blank"
