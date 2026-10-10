"""An unattended `login`/`logged-in` can never hang (tp#843).

Pinned here, with fakes only — never a real Chrome, never the live browser:

* `LoginDeadline` fires on a stuck background page (step deadline), closes the
  tab the command owns over raw CDP and exits 124; an unconfirmed close is 125;
  a stalled raw create leaks nothing;
* on the normal path the tab is closed by raw CDP (never ``page.close()``) and
  a failed close is retried by the command's final cleanup;
* `disarm()` racing the expiry never lets a hard exit through after it returned;
* arming follows maintenance ownership, not the kind of site;
* `_broker_request` has ONE deadline (a dribbling broker cannot stretch it), and
  the deadline is armed before `_resolve_site` talks to the broker;
* the real CLI exits 124 with its tab closed, its registration reaped and the
  gate and the interaction lease free — also while holding the lease;
* $CLAUDE_BROWSER_LOGIN_TIMEOUT_S parses the same in browser.py and the runner.

Run: uv run pytest -q tests/test_login_timeout.py     (from the repo root)
"""

from __future__ import annotations

# Tests reach into browser.py's private helpers on purpose (it is a script).
# pylint: disable=protected-access,missing-function-docstring,import-error
# pylint: disable=redefined-outer-name,unused-argument,too-few-public-methods
# pylint: disable=missing-class-docstring,too-many-arguments
# pylint: disable=too-many-positional-arguments
# The cache fixture and record writer mirror test_guided_login's on purpose.
# pylint: disable=duplicate-code
import fcntl
import importlib.util
import json
import os
import random
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fake_cdp import FakeCdp
from hypothesis import given
from hypothesis import strategies as st

_REPO = Path(__file__).resolve().parent.parent
_BROWSER_PY = _REPO / "bin" / "browser.py"
sys.path.insert(0, str(_REPO))
import agent_login_jobs as jobs  # noqa: E402  # pylint: disable=wrong-import-position


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


browser = _load("browser_login_timeout_test", _BROWSER_PY)

KEEP = "KEEP0001"


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
    monkeypatch.setattr(browser, "DEADLINE_POLL_S", 0.02)
    monkeypatch.setattr(browser, "CLOSE_OWNED_CONFIRM_S", 0.3)
    browser._ACTIVE_DEADLINE.clear()
    yield tmp_path
    browser._ACTIVE_DEADLINE.clear()


class Exits:
    """Stands in for `_hard_exit`: records the code and releases the stuck call."""

    def __init__(self) -> None:
        self.codes: list[int] = []
        self.at: list[float] = []
        self.released = threading.Event()

    def __call__(self, rc: int) -> None:
        self.codes.append(rc)
        self.at.append(time.monotonic())
        self.released.set()


@pytest.fixture
def exits(monkeypatch) -> Exits:
    ex = Exits()
    monkeypatch.setattr(browser, "_hard_exit", ex)
    return ex


class FakePage:
    """The adopted page: `evaluate` blocks until released (or answers at once)."""

    def __init__(self, release: threading.Event | None = None) -> None:
        self.release = release

    def wait_for_load_state(self, *_a, **_k) -> None:
        return None

    def goto(self, *_a, **_k) -> None:
        return None

    def evaluate(self, *_a, **_k) -> bool:
        if self.release is not None:
            self.release.wait(20)
        return True

    def close(self) -> None:
        raise AssertionError("page.close() must never close an owned tab")


class FakeBrowser:
    def close(self) -> None:
        return None


class FakePw:
    def stop(self) -> None:
        return None


@pytest.fixture
def attach(monkeypatch):
    """A fake Playwright attach; returns a setter for the page it adopts."""
    state: dict[str, FakePage] = {"page": FakePage()}
    monkeypatch.setattr(
        browser, "_connect", lambda port, purpose="": (FakePw(), FakeBrowser())
    )
    monkeypatch.setattr(
        browser, "_page_by_target", lambda _browser, _tid: state["page"]
    )

    def use(page: FakePage) -> None:
        state["page"] = page

    return use


@pytest.fixture
def close_spy(monkeypatch) -> list[str]:
    calls: list[str] = []
    real = browser._cdp_close_target

    def spy(port, tid, budget_s=5.0, ws_url=None):
        calls.append(tid)
        return real(port, tid, budget_s, ws_url=ws_url)

    monkeypatch.setattr(browser, "_cdp_close_target", spy)
    return calls


def _journal(cache: Path) -> list[dict]:
    path = cache / "journal.jsonl"
    if not path.exists():
        return []
    return [json.loads(ln) for ln in path.read_text().splitlines() if ln.strip()]


def _events(cache: Path, event: str) -> list[dict]:
    return [r for r in _journal(cache) if r.get("event") == event]


def _bg_run(port: int, fn=lambda page: page.evaluate("1")):
    return browser._background_page_run(port, "https://site.example/", None, fn)


# --- a) b) c) d): the background page under a deadline ---------------------------


def test_stuck_evaluate_fires_closes_the_owned_tab_and_exits_124(
    fake, cache, exits, attach, close_spy, monkeypatch
):
    monkeypatch.setattr(browser, "BG_PAGE_STEP_S", 0.3)
    attach(FakePage(release=exits.released))
    t0 = time.monotonic()
    with browser._login_deadline(fake.port, "login", "fakesite", 30, end_event="login"):
        _bg_run(fake.port)
    assert exits.codes == [124]
    assert exits.at[0] - t0 < 2.0
    tid = fake.created[0]
    assert tid in close_spy and tid in fake.closed and tid not in fake.targets
    dog = [r for r in _events(cache, "watchdog") if "scope" in r]
    assert dog and dog[0]["step"] == "bg:fn" and dog[0]["scope"] == "background_page"
    assert dog[0]["confirmed"] is True and tid in dog[0]["owned"]
    end = [r for r in _events(cache, "login") if r.get("phase") == "end"]
    assert end and end[0]["result"] == 124 and end[0]["reason"] == "timeout"
    ops = [(r["op"], r["tid"]) for r in _events(cache, "owned_target")]
    assert ("add", tid) in ops and ("close", tid) in ops


def test_stalled_raw_create_fires_on_bg_create_and_leaks_no_target(
    fake, cache, exits, attach, monkeypatch
):
    monkeypatch.setattr(browser, "BG_PAGE_STEP_S", 0.3)
    fake.create_stall = True
    real = browser._cdp_create_background_target
    monkeypatch.setattr(
        browser,
        "_cdp_create_background_target",
        lambda ws, url, budget_s=5.0: real(ws, url, 1.5),
    )
    with browser._login_deadline(fake.port, "login", "fakesite", 30):
        assert _bg_run(fake.port) is None
    assert exits.codes == [124]
    assert not fake.created and list(fake.targets) == [KEEP]
    dog = [r for r in _events(cache, "watchdog") if "scope" in r]
    assert dog[0]["step"] == "bg:create" and dog[0]["owned"] == ""


def test_failed_close_still_listed_is_125_unconfirmed(
    fake, cache, exits, attach, monkeypatch, capsys
):
    monkeypatch.setattr(browser, "BG_PAGE_STEP_S", 0.3)
    monkeypatch.setattr(browser, "_cdp_close_target", lambda *a, **k: False)
    attach(FakePage(release=exits.released))
    with browser._login_deadline(fake.port, "login", "fakesite", 30):
        _bg_run(fake.port)
    assert exits.codes == [125]
    tid = fake.created[0]
    assert tid in fake.targets  # really still open
    dog = [r for r in _events(cache, "watchdog") if "scope" in r]
    assert dog[0]["confirmed"] is False
    assert "may still be open" in capsys.readouterr().err


def test_normal_path_closes_by_raw_cdp_and_owns_nothing_after(
    fake, cache, exits, attach, close_spy
):
    with browser._login_deadline(fake.port, "login", "fakesite", 30) as dl:
        assert _bg_run(fake.port) is True
        assert dl is not None and dl.owned_ids() == []
    tid = fake.created[0]
    assert close_spy == [tid] and tid not in fake.targets
    assert not exits.codes


def test_failed_close_on_the_normal_path_is_retried_by_the_final_cleanup(
    fake, cache, exits, attach, monkeypatch
):
    real = browser._cdp_close_target
    calls: list[str] = []

    def flaky(port, tid, budget_s=5.0, ws_url=None):
        calls.append(tid)
        return False if len(calls) == 1 else real(port, tid, budget_s, ws_url=ws_url)

    monkeypatch.setattr(browser, "_cdp_close_target", flaky)
    with browser._login_deadline(fake.port, "login", "fakesite", 30) as dl:
        assert _bg_run(fake.port) is True
        tid = fake.created[0]
        assert dl is not None and dl.owned_ids() == [tid]  # not confirmed: kept
    assert dl.owned_ids() == [] and tid not in fake.targets
    assert len(calls) == 2 and not exits.codes


# --- e) disarm vs. expiry ----------------------------------------------------------


def test_disarm_racing_the_expiry_never_exits_after_it_returned(cache, monkeypatch):
    monkeypatch.setattr(browser, "DEADLINE_POLL_S", 0.0005)
    late: list[float] = []
    fired = 0
    for _ in range(200):
        stamps: list[float] = []
        monkeypatch.setattr(
            browser, "_hard_exit", lambda rc, s=stamps: s.append(time.monotonic())
        )
        dl = browser.LoginDeadline(1, "login", "race", 0.002)
        dl.arm()
        time.sleep(random.uniform(0.0, 0.004))
        dl.disarm()
        returned = time.monotonic()
        time.sleep(0.003)  # a watcher that slipped through would exit now
        fired += bool(stamps)
        late += [t for t in stamps if t > returned]
    assert not late
    assert 0 < fired  # the race was really exercised


# --- f) arming ---------------------------------------------------------------------


def _write_live_record(nonce: str) -> None:
    rec = {
        "owner_nonce": nonce,
        "pid": os.getpid(),
        "pid_start_time": browser._proc_lstart(os.getpid()),
        "site": "slack",
        "mode": "B",
        "state": "active",
        "owned_targets": [],
        "paused": [],
        "heartbeat": time.time(),
    }
    browser.MAINTENANCE_FILE.write_text(json.dumps(rec), encoding="utf-8")


def test_arming_follows_maintenance_ownership_not_the_site(cache, monkeypatch):
    seen: list[Any] = []

    def body(port, site):
        seen.append(browser._active_deadline())
        return 0

    monkeypatch.setattr(browser, "_cmd_login", body)
    sites = ("switch", "cscs", "anthropic", "somebrokersite")
    for site in sites:
        assert browser.cmd_login(1, site) == 0
    assert all(isinstance(d, browser.LoginDeadline) for d in seen), seen
    assert [d.timeout_s for d in seen] == [browser.LOGIN_TIMEOUT_S] * len(sites)
    assert browser._active_deadline() is None  # disarmed and cleared after

    nonce = "a" * 32
    _write_live_record(nonce)
    monkeypatch.setenv(browser.MAINTENANCE_ENV, nonce)
    seen.clear()
    for site in sites:
        browser.cmd_login(1, site)
    assert seen == [None] * len(sites)  # a guided login's child: never bounded


def test_logged_in_is_armed_with_its_own_budget(cache, monkeypatch):
    seen: list[Any] = []

    def logged_in(port):
        seen.append(browser._active_deadline())
        return 0

    site = browser.Site("x", (), "", login=logged_in, logged_in=logged_in)
    monkeypatch.setattr(browser, "_resolve_site", lambda name, **_k: site)
    assert browser.cmd_logged_in(1, "x") == 0
    assert seen[0] is not None and seen[0].timeout_s == browser.LOGGED_IN_TIMEOUT_S


def test_login_cscs_assisted_is_never_armed(cache, monkeypatch):
    seen: list[Any] = []
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)

    def cscs_login(port, allow_op=False):
        seen.append(browser._active_deadline())
        return 0

    monkeypatch.setattr(browser, "cmd_cscs_login", cscs_login)
    assert browser.cmd_login_cscs_assisted(1) == 0
    assert seen == [None]


# --- g) the broker socket ------------------------------------------------------------


class FakeBroker:
    """A Unix-socket broker: ``dribble`` (1 byte every 0.2 s, never a newline),
    ``stall`` (reads the request, answers nothing) or ``ok`` (a sites list)."""

    def __init__(self, mode: str, sites: list[dict] | None = None) -> None:
        self.mode = mode
        self.sites = sites or []
        # A short path: macOS caps a Unix socket path at 104 bytes.
        self.dir = tempfile.mkdtemp(prefix="fb-", dir="/tmp")
        self.path = os.path.join(self.dir, "b.sock")
        self.stop = threading.Event()
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.bind(self.path)
        self.sock.listen(8)
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self) -> None:
        while not self.stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn: socket.socket) -> None:
        with conn:
            try:
                buf = b""
                while not buf.endswith(b"\n"):
                    chunk = conn.recv(4096)
                    if not chunk:
                        return
                    buf += chunk
                if self.mode == "ok":
                    reply = {"ok": True, "sites": self.sites}
                    conn.sendall(json.dumps(reply).encode() + b"\n")
                    return
                while not self.stop.wait(0.2):
                    if self.mode == "dribble":
                        conn.sendall(b" ")
            except OSError:
                return

    def close(self) -> None:
        self.stop.set()
        self.sock.close()
        shutil.rmtree(self.dir, ignore_errors=True)


@pytest.fixture
def broker_factory(monkeypatch) -> Iterator:
    made: list[FakeBroker] = []

    def make(mode: str, sites: list[dict] | None = None) -> FakeBroker:
        srv = FakeBroker(mode, sites)
        made.append(srv)
        monkeypatch.setenv("LOGIN_BROKER_SOCKET", srv.path)
        return srv

    yield make
    for srv in made:
        srv.close()


def test_a_dribbling_broker_cannot_stretch_the_request(broker_factory):
    broker_factory("dribble")
    t0 = time.monotonic()
    with pytest.raises(browser.BrokerUnavailable, match="within 1.5s"):
        browser._broker_request("sites", timeout=1.5)
    assert time.monotonic() - t0 < 1.5 + 1.0


def _cli_env(cache: Path, broker: FakeBroker, **extra: str) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k != browser.MAINTENANCE_ENV}
    env.pop("CLAUDE_BROWSER_LEASE_HELD", None)
    env.update(
        {
            "CLAUDE_BROWSER_CACHE_DIR": str(cache),
            "CLAUDE_BROWSER_JOURNAL_FILE": str(cache / "journal.jsonl"),
            "LOGIN_BROKER_SOCKET": broker.path,
            **extra,
        }
    )
    return env


def _cli(port: int, env: dict[str, str], *argv: str, deadline: float = 60.0):
    t0 = time.monotonic()
    proc = subprocess.run(
        [sys.executable, str(_BROWSER_PY), "--cdp-port", str(port), *argv],
        capture_output=True,
        text=True,
        env=env,
        timeout=deadline,
        check=False,
    )
    return proc, time.monotonic() - t0


def test_a_stalled_sites_call_exits_124_at_the_login_deadline(
    fake, cache, broker_factory
):
    """Armed BEFORE `_resolve_site`: its `sites` call to the broker is bounded."""
    broker = broker_factory("stall")
    env = _cli_env(cache, broker, CLAUDE_BROWSER_LOGIN_TIMEOUT_S="2")
    proc, took = _cli(fake.port, env, "login", "fakesite")
    assert proc.returncode == 124, proc.stderr
    assert took < 2 + 10, took
    assert "no progress after 2s in step resolve" in proc.stderr
    dog = [r for r in _events(cache, "watchdog") if "scope" in r]
    assert dog[0]["step"] == "resolve" and dog[0]["scope"] == "overall"


# --- h) i) the real CLI: tabs, registration, gate, lease -------------------------------


def _flock_free(path: Path) -> bool:
    fd = os.open(str(path), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return True
    except OSError:
        return False
    finally:
        os.close(fd)


def test_cli_login_stuck_in_the_attach_exits_124_and_leaves_nothing(
    fake, cache, broker_factory
):
    site = {
        "site": "fakesite",
        "check_url": "https://fakesite.example/account",
        "logged_in_selector": "#me",
        "refused": False,
    }
    broker = broker_factory("ok", [site])
    env = _cli_env(
        cache,
        broker,
        CLAUDE_BROWSER_CONNECT_TIMEOUT_S="60",
        CLAUDE_BROWSER_LOGIN_TIMEOUT_S="3",
    )
    proc, took = _cli(fake.port, env, "login", "fakesite", deadline=90)
    assert proc.returncode == 124, proc.stderr
    assert took < 3 + 15 + 10, took
    assert len(fake.created) == 1, fake.created
    tid = fake.created[0]
    assert tid in fake.closed and tid not in fake.targets
    dog = [r for r in _events(cache, "watchdog") if "scope" in r]
    assert dog[0]["step"] == "bg:adopt" and dog[0]["confirmed"] is True
    assert list((cache / "clients").glob("*.json")), "login never registered"
    assert browser._registry_live_clients() == []
    assert _flock_free(browser.REGISTRY_GATE)
    assert _flock_free(browser.INTERACTION_LOCK)


_HOLDER = """
import importlib.util, sys, time
spec = importlib.util.spec_from_file_location("b", sys.argv[1])
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)
port = int(sys.argv[2])
b._registry_register("test", "hold the gate", port)
with b._interaction_lease("timeout test"):
    with b._login_deadline(port, "login", "held", 0.5, end_event="login"):
        time.sleep(60)
sys.exit(0)
"""


def test_a_fired_deadline_frees_the_lease_the_gate_and_the_registration(cache):
    env = {k: v for k, v in os.environ.items() if k != browser.MAINTENANCE_ENV}
    env.pop("CLAUDE_BROWSER_LEASE_HELD", None)
    env["CLAUDE_BROWSER_CACHE_DIR"] = str(cache)
    env["CLAUDE_BROWSER_JOURNAL_FILE"] = str(cache / "journal.jsonl")
    t0 = time.monotonic()
    proc = subprocess.run(
        [sys.executable, "-c", _HOLDER, str(_BROWSER_PY), "1"],
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
        check=False,
    )
    assert proc.returncode == 124, proc.stderr
    assert time.monotonic() - t0 < 10
    assert list((cache / "clients").glob("*.json")), "never registered"
    assert browser._registry_live_clients() == []
    assert _flock_free(browser.REGISTRY_GATE)
    assert _flock_free(browser.INTERACTION_LOCK)


# --- j) the env var ------------------------------------------------------------------


def test_login_timeout_env_parsing():
    parse = browser._env_seconds
    assert parse(None, 300.0) == 300.0
    assert parse("600", 300.0) == 600.0
    assert parse("0.5", 300.0) == 0.5
    for bad in ("0", "-3", "abc", "nan", "inf", "-inf", ""):
        assert parse(bad, 300.0) == 300.0, bad
    assert browser._connect_timeout_s is browser._env_seconds


@given(st.one_of(st.none(), st.text(max_size=12), st.floats().map(str)))
def test_runner_parses_the_env_var_exactly_like_browser_py(raw):
    assert jobs.env_seconds(raw, 300.0) == browser._env_seconds(raw, 300.0)
