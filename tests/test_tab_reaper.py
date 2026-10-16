"""Tab ownership, keep pins and the idle reaper (tp#1109, PLAN_tab-reaper.md).

Fakes only (tests/fake_cdp.py): never a real Chrome, never the live browser —
the one opt-in end-to-end test launches a DISPOSABLE headless browser on a free
port with its own cache dir and stops it again.

* `open` records the opener (agent session, cwd); `open -k` pins, and a pin
  that cannot be written is exit 1;
* the state file: env precedence of the opener, malformed / unknown-version
  state refuses the reaper, the stale-snapshot prune keeps entries born after
  the snapshot;
* `reap-idle` closes ONLY an unpinned, unattached, unowned, idle http(s) page —
  never a pinned tid or origin, an attached tab, an owned-ledger tab or its
  popup, a blank tab, a recent tab or the last page; a fresh re-check right
  before the close (attached, changed URL, pin) wins; the dry run persists and
  closes nothing;
* coordination: a registered client (gate held shared), an unregistered
  client, a maintenance record each make it exit 75 without closing;
* `keep`: id / prefix resolution, origin canonicalisation, release;
* `tabs -j` is origin-only unless `-f`; a tab browser.py did not open shows
  opener ``unknown``;
* the LaunchAgent runs `browser.py reap-idle -A -q` every 15 min.

Run: uv run pytest -q tests/test_tab_reaper.py     (from the repo root)
"""

from __future__ import annotations

# Tests reach into browser.py's private helpers on purpose (it is a script).
# pylint: disable=protected-access,missing-function-docstring,import-error
# pylint: disable=redefined-outer-name,unused-argument
# The cache fixture mirrors test_owned_tabs_tp845's on purpose.
# pylint: disable=duplicate-code
import argparse
import importlib.util
import json
import os
import socket
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from fake_cdp import FakeCdp

_REPO = Path(__file__).resolve().parent.parent
_BROWSER_PY = _REPO / "bin" / "browser.py"
sys.path.insert(0, str(_REPO))


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


browser = _load("browser_tab_reaper_test", _BROWSER_PY)

HOUR = 3600.0


@pytest.fixture
def cache(tmp_path, monkeypatch):
    """Every coordination file in tmp_path; no unknown CDP clients by default."""
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
    monkeypatch.setattr(browser, "_unknown_cdp_clients", lambda port: [])
    yield tmp_path


@pytest.fixture
def fake() -> Iterator[FakeCdp]:
    srv = FakeCdp()
    yield srv
    srv.close()


def _state(cache: Path) -> dict:
    data: dict = json.loads((cache / "tabs.json").read_text())
    return data


def _seed(cache: Path, targets: dict, keep_origins: list | None = None) -> None:
    (cache / "tabs.json").write_text(
        json.dumps({"v": 1, "targets": targets, "keep_origins": keep_origins or []})
    )


def _old(**kw) -> dict:
    return {"first_seen": time.time() - 3 * HOUR, **kw}


def _reap(fake: FakeCdp, **kw) -> int:
    args = {
        "dry_run": False,
        "idle_h": None,
        "max_n": 20,
        "all_instances": False,
        "quiet": False,
    }
    args.update(kw)
    rc: int = browser.cmd_reap_idle(fake.port, **args)
    return rc


# --- opener identity and state file --------------------------------------------


def test_opener_session_env_precedence(monkeypatch):
    for key in browser.OPENER_SESSION_ENVS:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("CODEX_SESSION_ID", "codex-1")
    assert browser._opener_identity()["session"] == "codex-1"
    monkeypatch.setenv("CLAUDE_SESSION_ID", "old-name")
    assert browser._opener_identity()["session"] == "old-name"
    monkeypatch.setenv("CLAUDE_CODE_SESSION_ID", "cc-session")
    monkeypatch.setenv("CLAUDE_PID", "4242")
    monkeypatch.setenv("AI_AGENT", "claude-code_2-1-301_agent")
    ident = browser._opener_identity()
    assert ident["session"] == "cc-session"
    assert ident["pid"] == 4242
    assert ident["tool"] == "claude-code"
    monkeypatch.setenv("CLAUDE_CODE_SESSION_ID", "bad\nline")
    assert browser._opener_identity()["session"] == "old-name"


def test_malformed_or_unknown_version_state_refuses_the_reaper(cache, fake):
    fake.add("A", "https://a.example/", "a")
    fake.add("B", "https://b.example/", "b")
    (cache / "tabs.json").write_text("{not json")
    assert _reap(fake) == 1
    (cache / "tabs.json").write_text(json.dumps({"v": 99, "targets": {}}))
    assert _reap(fake) == 1
    assert _reap(fake, dry_run=True) == 1
    assert not fake.closed


def test_observe_prunes_only_entries_born_before_the_snapshot():
    state = browser._tabstate_empty()
    t0 = time.time()
    state["targets"] = {
        "GONE": {"first_seen": t0 - 10},
        "NEWER": {"created": t0 + 5, "via": "open"},
        "SEEN": {"first_seen": t0 - 10, "url_h": browser._url_hash("https://x/")},
    }
    browser._tabstate_observe(
        state, [{"targetId": "SEEN", "url": "https://x/#frag"}], t0
    )
    assert set(state["targets"]) == {"NEWER", "SEEN"}
    assert "last_change" not in state["targets"]["SEEN"]  # the fragment is ignored
    browser._tabstate_observe(state, [{"targetId": "SEEN", "url": "https://x/2"}], t0)
    assert "last_change" in state["targets"]["SEEN"]


def test_open_records_the_opener_and_open_k_pins(cache, fake, monkeypatch, capsys):
    fake.add("BASE", "https://base.example/", "base")
    monkeypatch.setenv("CLAUDE_CODE_SESSION_ID", "sess-open")
    assert browser.cmd_open(fake.port, "https://new.example/", keep=True) == 0
    tid = fake.created[0]
    entry = _state(cache)["targets"][tid]
    assert entry["opener"]["session"] == "sess-open"
    assert entry["via"] == "open" and entry["keep"] is True
    assert "https://new.example" not in json.dumps(_state(cache))  # hash only
    assert f"target={tid}" in capsys.readouterr().out


def test_open_k_fails_loud_when_the_pin_cannot_be_written(cache, fake, monkeypatch):
    fake.add("BASE", "https://base.example/", "base")

    def broken(_fn):
        raise browser.TabStateError("disk full (fake)")

    monkeypatch.setattr(browser, "_tabstate_update", broken)
    assert browser.cmd_open(fake.port, "https://new.example/", keep=True) == 1
    assert browser.cmd_open(fake.port, "https://other.example/") == 0  # unpinned: warn


# --- the reap rule ---------------------------------------------------------------


def _ledger(cache: Path, entries: list[dict]) -> None:
    owned = cache / "owned"
    owned.mkdir(exist_ok=True)
    (owned / "999999-abc.json").write_text(
        json.dumps({"pid": 999999, "pid_start_time": "x", "entries": entries})
    )


def test_reap_closes_only_the_idle_unpinned_unowned_page(cache, fake):
    fake.add("IDLE", "https://ads.example/page?x=1", "ads")
    fake.add("PINTID", "https://pinned.example/", "pinned")
    fake.add("PINORG", "https://app.straiv.io/dash", "straiv")
    fake.add("ATTACH", "https://mcp.example/", "mcp", attached=True)
    fake.add("BLANK", "about:blank", "")
    fake.add("OWNED", "https://owned.example/", "owned")
    fake.add("POPUP", "https://popup.example/", "popup", opener="OWNED")
    fake.add("RECENT", "https://recent.example/", "recent")
    _seed(
        cache,
        {
            "IDLE": _old(),
            "PINTID": _old(keep=True),
            "PINORG": _old(),
            "ATTACH": _old(),
            "BLANK": _old(),
            "OWNED": _old(),
            "POPUP": _old(),
            "RECENT": {"first_seen": time.time() - 60},
        },
        keep_origins=["https://app.straiv.io"],
    )
    _ledger(cache, [{"marker": "m1", "tid": "OWNED", "parent": None}])
    assert _reap(fake) == 0
    assert fake.closed == ["IDLE"]
    assert "IDLE" not in _state(cache)["targets"]
    journal = (cache / "journal.jsonl").read_text()
    assert "tab_reaped" in journal and "x=1" not in journal


def test_marker_only_ledger_entry_protects_its_tab(cache, fake):
    marker_url = browser._owned_marker_url("m2")
    fake.add("MARK", marker_url, "")
    fake.add("CHILD", "https://child.example/", "c", opener="MARK")
    fake.add("OTHER", "https://other.example/", "o")
    _seed(cache, {"MARK": _old(), "CHILD": _old(), "OTHER": _old()})
    _ledger(cache, [{"marker": "m2", "tid": None, "parent": None}])
    assert _reap(fake) == 0
    assert fake.closed == ["OTHER"]


def test_unreadable_ledger_refuses_the_run(cache, fake):
    fake.add("A", "https://a.example/", "a")
    fake.add("B", "https://b.example/", "b")
    _seed(cache, {"A": _old(), "B": _old()})
    (cache / "owned").mkdir()
    (cache / "owned" / "1-x.json").write_text("garbage")
    assert _reap(fake) == 1
    assert not fake.closed


def test_last_page_is_never_closed(cache, fake):
    fake.add("ONLY", "https://only.example/", "only")
    _seed(cache, {"ONLY": _old()})
    assert _reap(fake) == 0
    assert not fake.closed


def test_threshold_and_env(cache, fake, monkeypatch):
    fake.add("A", "https://a.example/", "a")
    fake.add("B", "https://b.example/", "b")
    _seed(cache, {"A": {"first_seen": time.time() - 1.5 * HOUR}, "B": _old()})
    monkeypatch.setenv(browser.TAB_IDLE_ENV, "4")
    assert _reap(fake) == 0 and not fake.closed
    assert _reap(fake, idle_h=1.0) == 0
    assert fake.closed == ["B"]  # longest idle first; A is then the last page
    assert browser._tab_idle_threshold_h(0.01) == browser.TAB_IDLE_FLOOR_H


def test_fresh_recheck_wins_attached_changed_pinned(cache, fake, monkeypatch):
    for tid in ("ATT", "CHG", "PIN"):
        fake.add(tid, f"https://{tid.lower()}.example/", tid)
    fake.add("KEEPALIVE", "https://k.example/", "k")
    _seed(
        cache,
        {
            "ATT": _old(),
            "CHG": _old(),
            "PIN": _old(),
            "KEEPALIVE": {"first_seen": time.time()},
        },
    )
    real = browser._target_infos
    calls = {"n": 0}

    def flipping(port, budget_s=3.0):
        calls["n"] += 1
        if calls["n"] == 2:  # after the decision: the world changed
            fake.targets["ATT"].attached = True
            fake.targets["CHG"].url = "https://chg.example/elsewhere"
            st = _state(cache)
            st["targets"]["PIN"]["keep"] = True
            (cache / "tabs.json").write_text(json.dumps(st))
        return real(port, budget_s)

    monkeypatch.setattr(browser, "_target_infos", flipping)
    assert _reap(fake) == 0
    assert not fake.closed


def test_dry_run_persists_and_closes_nothing(cache, fake, capsys):
    fake.add("A", "https://a.example/", "a")
    fake.add("B", "https://b.example/", "b")
    assert _reap(fake, dry_run=True) == 0
    assert not (cache / "tabs.json").exists()
    _seed(cache, {"A": _old(), "B": _old()})
    before = (cache / "tabs.json").read_text()
    assert _reap(fake, dry_run=True) == 0
    out = capsys.readouterr().out
    assert out.count("would close") == 2
    assert (cache / "tabs.json").read_text() == before
    assert not fake.closed


# --- coordination --------------------------------------------------------------


def test_registered_client_makes_it_busy(cache, fake):
    fake.add("A", "https://a.example/", "a")
    fake.add("B", "https://b.example/", "b")
    _seed(cache, {"A": _old(), "B": _old()})
    release = browser._registry_register("test", "holds the gate", fake.port)
    try:
        assert _reap(fake) == browser.BUSY_RC
    finally:
        release()
    assert not fake.closed


@pytest.mark.parametrize("unknown", [None, [(123, "node mcp")]])
def test_unknown_client_makes_it_busy(cache, fake, monkeypatch, unknown):
    fake.add("A", "https://a.example/", "a")
    fake.add("B", "https://b.example/", "b")
    _seed(cache, {"A": _old(), "B": _old()})
    monkeypatch.setattr(browser, "_unknown_cdp_clients", lambda port: unknown)
    assert _reap(fake) == browser.BUSY_RC
    assert not fake.closed


def test_maintenance_record_makes_it_busy(cache, fake):
    fake.add("A", "https://a.example/", "a")
    fake.add("B", "https://b.example/", "b")
    _seed(cache, {"A": _old(), "B": _old()})
    (cache / "maintenance.json").write_text("{}")  # even a dead/garbage record
    assert _reap(fake) == browser.BUSY_RC
    assert not fake.closed


def test_worst_rc():
    assert browser._worst_rc([0, 0]) == 0
    assert browser._worst_rc([0, 75]) == 75
    assert browser._worst_rc([75, 1, 0]) == 1
    assert browser._worst_rc([]) == 0


# --- keep ------------------------------------------------------------------------


def test_keep_by_prefix_origin_and_release(cache, fake, capsys):
    fake.add("ABCDEF0123", "https://a.example/", "a")
    fake.add("ABCDEF0199", "https://b.example/", "b")
    assert (
        browser.cmd_keep(fake.port, ["ABCD"], [], release=False, list_only=False) == 2
    )
    assert (
        browser.cmd_keep(fake.port, ["ABCDEF01"], [], release=False, list_only=False)
        == 2
    )
    assert (
        browser.cmd_keep(fake.port, ["ABCDEF012"], [], release=False, list_only=False)
        == 0
    )
    assert _state(cache)["targets"]["ABCDEF0123"]["keep"] is True
    origin_args = ["https://App.Example.com/", "http://x.example:8080"]
    assert (
        browser.cmd_keep(fake.port, [], origin_args, release=False, list_only=False)
        == 0
    )
    assert _state(cache)["keep_origins"] == [
        "https://app.example.com",
        "http://x.example:8080",
    ]
    for bad in ("https://u:p@x.example", "https://x.example/path", "ftp://x.example"):
        assert (
            browser.cmd_keep(fake.port, [], [bad], release=False, list_only=False) == 2
        )
    assert (
        browser.cmd_keep(fake.port, ["ABCDEF0123"], [], release=True, list_only=False)
        == 0
    )
    assert "keep" not in _state(cache)["targets"]["ABCDEF0123"]
    capsys.readouterr()
    assert browser.cmd_keep(fake.port, [], [], release=False, list_only=True) == 0
    assert "keep origin: https://app.example.com" in capsys.readouterr().out


# --- tabs -------------------------------------------------------------------------


def _tabs_args(**kw) -> argparse.Namespace:
    base = {
        "this_instance": True,
        "json": True,
        "full_urls": False,
        "no_probe": False,
        "cdp_port_given": True,
    }
    base.update(kw)
    return argparse.Namespace(**base)


def test_tabs_json_is_origin_only_and_unknown_opener(cache, fake, capsys):
    fake.add(
        "MCP", "https://site.example/reset?token=SECRET", "Reset", eval_value=1.7e12
    )
    assert browser.cmd_tabs(_tabs_args(), fake.port) == 0
    doc = json.loads(capsys.readouterr().out)
    row = doc["tabs"][0]
    assert row["url"] == "https://site.example"
    assert "SECRET" not in json.dumps(doc)
    assert row["opener"] is None and row["first_seen"]
    assert row["loaded"] == pytest.approx(1.7e9)
    assert browser.cmd_tabs(_tabs_args(full_urls=True), fake.port) == 0
    assert "token=SECRET" in capsys.readouterr().out
    assert browser.cmd_tabs(_tabs_args(json=False), fake.port) == 0
    assert "unknown" in capsys.readouterr().out


# --- LaunchAgent -----------------------------------------------------------------


def test_launchagent_runs_reap_idle_every_15_min():
    import agent_login_jobs as jobs  # pylint: disable=import-outside-toplevel

    plists = {label: text for label, text, _what in jobs.agent_plists()}
    text = plists[jobs.TAB_REAPER_LABEL]
    assert str(jobs.BROWSER_PY) in text
    assert "<string>reap-idle</string>" in text and "<string>-A</string>" in text
    assert "<integer>900</integer>" in text
    assert "<false/>" in text  # no RunAtLoad


# --- end to end (opt-in, disposable browser) ----------------------------------------

E2E = pytest.mark.skipif(
    os.environ.get("LOGIN_BROKER_E2E") != "1", reason="set LOGIN_BROKER_E2E=1"
)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _cli(port: int, *argv: str) -> subprocess.CompletedProcess:
    env = {k: v for k, v in os.environ.items() if k != browser.MAINTENANCE_ENV}
    return subprocess.run(
        [sys.executable, str(_BROWSER_PY), "--cdp-port", str(port), *argv],
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


class _Site(BaseHTTPRequestHandler):
    def log_message(self, *_a) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        body = b"<!doctype html><title>t</title><p>ok</p>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _target_of(proc: subprocess.CompletedProcess) -> str:
    out = str(proc.stdout)
    return next(
        ln.split("=", 1)[1] for ln in out.splitlines() if ln.startswith("target=")
    )


@E2E
@pytest.mark.launches_chrome
def test_e2e_reap_idle_closes_only_the_unpinned_tab(cache):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Site)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    port = _free_port()
    up = _cli(port, "up")
    assert up.returncode == 0, up.stdout + up.stderr
    try:
        kept = _target_of(_cli(port, "open", "-N", "-k", f"{base}/kept"))
        victim = _target_of(_cli(port, "open", "-N", f"{base}/victim"))
        st = _state(cache)
        for entry in st["targets"].values():
            for key in ("created", "last_used", "last_change", "first_seen"):
                if key in entry:
                    entry[key] -= 3 * HOUR
        (cache / "tabs.json").write_text(json.dumps(st))
        dry = _cli(port, "reap-idle", "-n")
        assert dry.returncode == 0 and "would close" in dry.stdout, dry.stdout
        reap = _cli(port, "reap-idle")
        assert reap.returncode == 0, reap.stdout + reap.stderr
        listed = _cli(port, "tabs", "-j", "-n")
        live = {t["id"] for t in json.loads(listed.stdout)["tabs"]}
        assert victim not in live
        assert kept in live
        fresh = _cli(port, "eval-fresh", "-t", "30", f"{base}/fresh", "1+1")
        assert fresh.returncode == 0, fresh.stderr
    finally:
        _cli(port, "down", "-f")
        srv.shutdown()
