"""WS3 client side: the config digest, the promotion budget, removal
(agent_login_state.py), `browser.py`'s scheduled config gate and logout
storage clear, and agent-login.py's `-V -i`, `-p`, `-t`, `-E`, `-D` and `-c`
gates.

Hermetic: the state dir and every cache dir are per-test temp dirs
(conftest); `run_browser`, `broker_state` and `broker_request` are stubs; no
Chrome, no broker. No credential-shaped literals.
"""

from __future__ import annotations

# pylint: disable=missing-function-docstring,import-error,wrong-import-position
# pylint: disable=protected-access,too-many-lines
import contextlib
import json
import os
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any

import pytest

sys.path[:0] = [
    str(Path(__file__).resolve().parent.parent),
    str(Path(__file__).resolve().parent),
]

from ws3_fixtures import REPO, load_script  # noqa: E402

import agent_login_jobs as jobs  # noqa: E402
import agent_login_state as als  # noqa: E402
from broker import onboarding  # noqa: E402

browser = load_script("browser_ws3_test", "bin/browser.py")
al = load_script("agent_login_ws3_test", "agent-login.py")


@pytest.fixture(autouse=True)
def _cache_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    cache = tmp_path / "browser-cache"
    cache.mkdir()
    monkeypatch.setenv("CLAUDE_BROWSER_CACHE_DIR", str(cache))
    return cache


def _view(site: str = "app", host: str = "app.example.org", **kw: Any) -> dict:
    base = {
        "site": site,
        "name": site,
        "fill_origins": [f"https://{host}"],
        "cookie_hosts": [host],
        "check_url": f"https://{host}/me",
        "login_url": f"https://{host}/me",
        "logged_in_selector": "#me",
        "sentinel": True,
        "strict_proof": True,
        "storage_keys": {},
        "storage_origins": [],
        "refused": False,
        "reason": "",
        "identity_v": 1,
        "instance": "",
        "multi_account": False,
        "same_account_as": [],
        "limit": None,
    }
    return {**base, **kw}


def _listing(monkeypatch: pytest.MonkeyPatch, *views: dict, ok: bool = True) -> None:
    health = "running, Bitwarden readable" if ok else "not installed"
    monkeypatch.setattr(
        al, "broker_state", lambda **_k: (health, list(views) if ok else [])
    )


def _run(rc: int, rec: dict | None) -> Any:
    return al.BrowserRun(rc, False, "", 0.0, rec)


def _ok_result(view: dict) -> dict:
    return {
        "phase": "ok",
        "code": "ok",
        "proof_v": 1,
        "instance": "",
        "config": onboarding.config_digest(view),
        "route": "broker",
        "submitted": None,
    }


# ---------------------------------------------------------------------------
# agent_login_state: the config digest
# ---------------------------------------------------------------------------


def test_a_promotion_holds_for_its_config_only() -> None:
    cfg, other = "a" * 64, "b" * 64
    als.promote("s", config=cfg)
    assert als.scheduled_gate("s", config=cfg) == (True, "", "")
    allowed, code, _why = als.scheduled_gate("s", config=other)
    assert not allowed and code == "changed"
    assert als.scheduled_gate("s")[0]  # no digest asked: the stage decides
    als.promote("old")  # a pre-WS3 promotion
    assert als.scheduled_gate("old", config=cfg)[1] == "config_unknown"
    assert als.usable_for(als.site_states()["s"], cfg)
    assert not als.usable_for(als.site_states()["s"], other)


def test_adoption_needs_a_fresh_strict_check_and_happens_once() -> None:
    cfg = "c" * 64
    als.promote("old")  # a pre-WS3 promotion: no config record
    als.ensure_known(["pending-site"])
    assert not als.adopt_configs({"old": cfg})  # no check on record
    als.record_check("old", "ok", "x", proof_v=0)
    assert not als.adopt_configs({"old": cfg})  # the old, weak proof
    als.record_check("old", "ok", "x", proof_v=1, now=1.0)
    assert not als.adopt_configs({"old": cfg})  # strict but stale
    als.record_check("old", "failed", "x", proof_v=1)
    assert not als.adopt_configs({"old": cfg})  # fresh but not ok
    als.record_check("old", "ok", "x", proof_v=1)
    als.record_check("pending-site", "ok", "x", proof_v=1)
    assert als.adopt_configs({"old": cfg, "pending-site": cfg, "nobody": cfg}) == [
        "old"
    ]
    entry = als.site_states()["old"]
    assert entry["config"] == cfg and entry["config_v"] == onboarding.CONFIG_V
    assert entry["audit"][-1]["action"] == "adopt_config"
    assert "config" not in als.site_states()["pending-site"]
    assert not als.adopt_configs({"old": "d" * 64})  # current version: never again
    assert als.site_states()["old"]["config"] == cfg


def test_an_older_config_version_is_re_adopted_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cfg_old, cfg_new = "e" * 64, "f" * 64
    als.promote("s", config=cfg_old)

    def older(data: dict) -> None:
        data["s"]["config_v"] = onboarding.CONFIG_V - 1  # a previous release

    als.update(als.SITE_STATE_FILE, older)
    assert als.scheduled_gate("s", config=cfg_old)[1] == "config_unknown"
    assert not als.usable_for(als.site_states()["s"], cfg_old)
    als.record_check("s", "ok", "x", proof_v=1)
    assert als.adopt_configs({"s": cfg_new}) == ["s"]
    assert als.scheduled_gate("s", config=cfg_new) == (True, "", "")
    assert als.scheduled_gate("s", config=cfg_old)[1] == "changed"
    del monkeypatch


def test_adoption_runs_only_from_a_fresh_listing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    als.promote("app")
    als.record_check("app", "ok", "x", proof_v=1)  # a fresh strict check
    view = _view()
    monkeypatch.setattr(
        al, "_broker_state_live", lambda **_k: ("running, Bitwarden readable", [view])
    )
    monkeypatch.setattr(al.os.path, "exists", lambda _p: True)
    al.broker_state(fresh=False)
    assert not als.site_states()["app"].get("config")
    al.broker_state(fresh=True)
    assert als.site_states()["app"]["config"] == onboarding.config_digest(view)


def test_check_records_keep_only_a_wellformed_digest() -> None:
    assert als.record_check("s", "ok", "x", config="f" * 64)["config"] == "f" * 64
    assert als.record_check("s", "ok", "x", config="not a digest")["config"] == ""


# ---------------------------------------------------------------------------
# agent_login_state: the promotion budget
# ---------------------------------------------------------------------------


def test_one_trial_then_spent_until_rearmed() -> None:
    cfg = "a" * 64
    assert als.claim_trial("s", cfg) == (True, "", "")
    assert als.claim_trial("s", cfg)[1] == "busy"  # our own live claim
    assert als.finish_trial(
        "s", {"phase": "submit", "code": "login_failed", "submitted": True}
    )
    claimed, code, why = als.claim_trial("s", cfg)
    assert not claimed and code == "spent" and "submit" in why
    als.quarantine("s", "submit", "login_failed")
    assert als.release("s") is True
    assert als.claim_trial("s", cfg)[1] == "spent"  # -Q releases only the quarantine
    assert als.rearm("s", why="reviewed") is True
    assert als.claim_trial("s", cfg)[0]


@pytest.mark.parametrize(
    ("result", "refunded"),
    [
        ({"phase": "ok", "route": "already"}, True),
        ({"phase": "precheck", "code": "busy", "submitted": False}, True),
        ({"phase": "limiter", "code": "cooldown", "submitted": False}, True),
        ({"phase": "vault", "submitted": False}, True),
        ({"phase": "profile-proof", "submitted": False}, True),
        ({"phase": "precheck", "code": "busy"}, True),  # exit 75: never ran
        ({"phase": "precheck", "code": "not_started", "submitted": False}, True),
        ({"phase": "precheck", "code": "quarantined"}, False),  # submitted unknown
        ({"phase": "recipe", "submitted": False}, False),
        ({"phase": "submit", "submitted": True}, False),
        ({"phase": "unknown", "code": "timeout", "submitted": None}, False),
        ({"phase": "ok", "route": "broker"}, False),
        (None, False),
    ],
)
def test_the_budget_is_refunded_only_when_no_password_was_sent(
    result: dict | None, refunded: bool
) -> None:
    als.claim_trial("s", "a" * 64)
    assert als.finish_trial("s", result) is (not refunded)
    assert (als.trial_state("s").get("spent") is True) is (not refunded)


def test_no_claim_for_a_usable_or_quarantined_site() -> None:
    cfg = "a" * 64
    als.promote("s", config=cfg)
    assert als.claim_trial("s", cfg)[1] == "usable"
    assert als.claim_trial("s", "b" * 64)[0]  # changed since: a trial again
    als.quarantine("q", "submit", "x")
    assert als.claim_trial("q", cfg)[1] == "quarantined"


def test_concurrent_claims_in_threads_one_wins() -> None:
    results: list[bool] = []
    barrier = threading.Barrier(8)

    def claim() -> None:
        barrier.wait()
        results.append(als.claim_trial("race", "a" * 64)[0])

    threads = [threading.Thread(target=claim) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(10)
    assert results.count(True) == 1


def test_concurrent_claims_in_processes_one_wins() -> None:
    code = (
        "import sys; sys.path.insert(0, sys.argv[1]); import agent_login_state as a; "
        "print(a.claim_trial('race', 'a' * 64)[0])"
    )
    procs = [
        subprocess.Popen(  # pylint: disable=consider-using-with
            [sys.executable, "-c", code, str(REPO)],
            stdout=subprocess.PIPE,
            text=True,
            env=dict(os.environ),
        )
        for _ in range(4)
    ]
    outs = [p.communicate(timeout=60)[0].strip() for p in procs]
    assert outs.count("True") == 1, outs
    # every winner's process is gone now: its claim is recovered as spent
    claimed, code_, _why = als.claim_trial("race", "a" * 64)
    assert not claimed and code_ == "spent"
    assert als.trial_state("race")["outcome"] == "unknown"


def test_a_crashed_claim_is_spent_unknown(monkeypatch: pytest.MonkeyPatch) -> None:
    als.claim_trial("s", "a" * 64)

    def put(data: dict) -> None:
        data["s"]["trial"]["inflight"]["pid"] = 2**22 + 12345  # no such process

    als.update(als.SITE_STATE_FILE, put)
    assert als.claim_trial("s", "a" * 64)[1] == "spent"
    trial = als.trial_state("s")
    assert trial["phase"] == "unknown" and trial["code"] == "crashed"
    del monkeypatch


def test_a_stuck_claim_without_a_start_time_expires() -> None:
    """A pid whose start time was unknown may have been reused: past the
    login timeout plus margin the claim counts as dead (spent, unknown)."""
    als.claim_trial("s", "a" * 64)

    def unknown_start(age: float) -> None:
        def put(data: dict) -> None:
            inflight = data["s"]["trial"]["inflight"]
            inflight["pid_start"] = None
            inflight["at"] = als.time.time() - age

        als.update(als.SITE_STATE_FILE, put)

    unknown_start(60.0)  # our own live pid, recent: still busy
    assert als.claim_trial("s", "a" * 64)[1] == "busy"
    unknown_start(als.TRIAL_STALE_S + 60.0)
    assert als.claim_trial("s", "a" * 64)[1] == "spent"
    assert als.trial_state("s")["code"] == "crashed"


def test_rearm_refuses_a_live_claim() -> None:
    als.claim_trial("s", "a" * 64)
    with pytest.raises(als.StateError):
        als.rearm("s")


# ---------------------------------------------------------------------------
# agent_login_state: removal
# ---------------------------------------------------------------------------


def _session_age(cache: Path, site: str) -> tuple[Path, Path, Path]:
    age = cache / "session-age"
    age.mkdir(exist_ok=True)
    rec, lock = age / f"{site}.json", age / f"{site}.lock"
    rec.write_text("{}")
    lock.write_text("")
    log = cache / "login-log"
    log.mkdir(exist_ok=True)
    (log / f"{site}.jsonl").write_text("{}\n")
    return rec, lock, log / f"{site}.jsonl"


def test_remove_site_leaves_nothing_but_one_audit_line(_cache_dir: Path) -> None:
    als.record_check("gone", "failed", "x")
    als.ensure_known(["gone", "kept"])
    als.quarantine("gone", "submit", "x")
    als.promote("gone", config="a" * 64)
    rec, lock, log = _session_age(_cache_dir, "gone")
    keep = _session_age(_cache_dir, "kept")
    removed = als.remove_site("gone")
    assert removed[als.SITE_STATE_FILE] and removed[als.CHECKS_FILE]
    for name in (als.CHECKS_FILE, als.LEGACY_FILE, als.SITE_STATE_FILE):
        assert "gone" not in als.read(name)
    assert not rec.exists() and not log.exists()
    assert lock.exists() and lock.stat().st_size == 0  # the lock stays, empty
    assert all(p.exists() for p in keep) and "kept" in als.site_states()
    lines = (als.state_dir() / als.AUDIT_FILE).read_text().splitlines()
    assert len(lines) == 1 and json.loads(lines[0])["site"] == "gone"
    with pytest.raises(als.StateError):
        als.remove_site("../etc")


def test_the_automatic_prune_drops_session_age_too(_cache_dir: Path) -> None:
    als.record_check("zendesk", "failed", "x")
    rec, _lock, log = _session_age(_cache_dir, "zendesk")
    assert als.prune({"github"}) == ["zendesk"]
    assert not rec.exists()
    assert log.exists()  # history: only -D removes it


def test_cache_dirs_cover_every_instance(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CLAUDE_BROWSER_CACHE_DIR")
    names = {p.name for p in als.cache_dirs()}
    assert names == {
        "claude-browser",
        "claude-browser-private",
        "claude-browser-admin",
        "claude-browser-alt",
    }


# ---------------------------------------------------------------------------
# browser.py: the scheduled config gate, the proof's digest, logout storage
# ---------------------------------------------------------------------------


ENTRY = _view("shop", "shop.example.org")


class _Pw:
    def stop(self) -> None:
        pass


class _Browser:
    contexts: list = []

    def close(self) -> None:
        pass


def _broker_env(monkeypatch: pytest.MonkeyPatch, entry: dict, sent: list) -> None:
    monkeypatch.setattr(browser, "_broker_logged_in", lambda _p, _s: 2)
    monkeypatch.setattr(browser, "_broker_entry_or_rc", lambda _s: (entry, 0))
    monkeypatch.setattr(browser, "_broker_identity_gate", lambda *_a, **_k: None)
    monkeypatch.setattr(browser, "_connect", lambda _p: (_Pw(), _Browser()))
    monkeypatch.setattr(
        browser, "_interaction_lease", lambda _w: contextlib.nullcontext()
    )

    def request(op: str, **kw: Any) -> dict:
        sent.append((op, kw))
        return {
            "ok": False,
            "error": "login_failed",
            "phase": "recipe",
            "submitted": False,
        }

    monkeypatch.setattr(browser, "_broker_request", request)


def test_a_scheduled_login_needs_the_promoted_config(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sent: list = []
    _broker_env(monkeypatch, ENTRY, sent)
    browser._LOGIN_OPTS["scheduled"] = True
    try:
        als.promote("shop", config=onboarding.config_digest(ENTRY))
        browser._broker_login(9222, "shop")
        assert [op for op, _ in sent] == ["login"]
        sent.clear()
        changed = {**ENTRY, "logged_in_selector": "#other"}
        _broker_env(monkeypatch, changed, sent)
        assert browser._broker_login(9222, "shop") == 2
        assert not sent and browser._RESULT["code"] == "changed"
    finally:
        browser._LOGIN_OPTS.pop("scheduled", None)


def test_the_proof_records_the_config_it_proved() -> None:
    class _Page:
        url = "https://shop.example.org/me"

    browser._RESULT.clear()
    with contextlib.suppress(Exception):
        browser._broker_probe_page(_Page(), ENTRY)
    assert browser._RESULT.get("config") == onboarding.config_digest(ENTRY)


def test_logout_storage_plan_covers_declared_keys_only() -> None:
    entry = {
        **ENTRY,
        "storage_keys": {
            "https://shop.example.org": ["tok", ""],
            "http://x.example": ["k"],
        },
    }
    assert browser._logout_storage_plan(entry) == {"https://shop.example.org": ["tok"]}
    assert browser._logout_storage_plan(ENTRY) == {}


def test_logout_fails_when_storage_cannot_be_confirmed(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    entry = {**ENTRY, "storage_keys": {"https://shop.example.org": ["tok"]}}
    monkeypatch.setattr(browser, "_broker_site", lambda _s: entry)
    monkeypatch.setattr(browser, "_instance_gate", lambda *_a: None)
    monkeypatch.setattr(
        browser, "_broker_request", lambda op, **_k: {"ok": True, "removed": True}
    )
    monkeypatch.setattr(browser, "_broker_clear_cookies", lambda *_a, **_k: 2)
    plans: list = []

    def clear(_port: int, _site: str, plan: dict) -> int:
        plans.append(plan)
        raise browser.ForeignStorageError("an origin could not be confirmed clean")

    monkeypatch.setattr(browser, "_broker_clear_foreign_storage", clear)
    assert browser.cmd_broker_logout(9222, "shop") == 2
    assert plans == [{"https://shop.example.org": ["tok"]}]
    assert "could NOT be confirmed" in capsys.readouterr().err
    monkeypatch.setattr(browser, "_broker_clear_foreign_storage", lambda *_a: 1)
    assert browser.cmd_broker_logout(9222, "shop") == 0


# ---------------------------------------------------------------------------
# agent-login.py: -V -i, -p, -t, -E, -D, -c
# ---------------------------------------------------------------------------


def test_validate_a_planned_item_shows_displacement(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _listing(monkeypatch, _view("old", "same.example.org"))
    manifest = tmp_path / "planned.json"
    manifest.write_text(
        json.dumps(
            {
                "name": "aaa-new",
                "fields": {
                    "agent_site": "aaa-new",
                    "agent_fill_origins": "https://same.example.org",
                    "agent_check_url": "https://same.example.org/me",
                    "agent_logged_in_selector": "#me",
                    "agent_privilege": "user",
                },
            }
        )
    )
    assert al.validate_action(str(manifest), fresh=False) == 1
    out = capsys.readouterr().out
    assert "old: refused displaced" in out and "aaa-new" in out
    secret = {"name": "x", "fields": {}, "login": {"password": os.urandom(4).hex()}}
    manifest.write_text(json.dumps(secret))
    assert al.validate_action(str(manifest), fresh=False) == 2
    assert "no secrets" in capsys.readouterr().out


def test_validate_all_items_exit_code(monkeypatch: pytest.MonkeyPatch) -> None:
    _listing(monkeypatch, _view())
    assert al.validate_action(None, fresh=False) == 0
    _listing(monkeypatch, _view(cookie_hosts=["github.io"]))
    assert al.validate_action(None, fresh=False) == 1


def _no_login(monkeypatch: pytest.MonkeyPatch) -> list:
    calls: list = []

    def run(*args: str, **_kw: Any) -> Any:
        calls.append(args)
        raise AssertionError("no browser.py run expected")

    monkeypatch.setattr(al, "run_browser", run)
    return calls


def test_p_promotes_from_a_fresh_record_without_a_login(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    view = _view()
    _listing(monkeypatch, view)
    _no_login(monkeypatch)
    als.record_check("app", "ok", "x", proof_v=1, config=onboarding.config_digest(view))
    assert al.promote_action("app") == 0
    assert als.site_states()["app"]["config"] == onboarding.config_digest(view)
    assert al.promote_action("app") == 0  # already usable: nothing runs


def test_p_runs_one_budgeted_login_then_promotes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    view = _view()
    _listing(monkeypatch, view)
    calls: list = []

    def run(*args: str, **_kw: Any) -> Any:
        calls.append(args)
        return _run(0, _ok_result(view))

    monkeypatch.setattr(al, "run_browser", run)
    assert al.promote_action("app") == 0
    assert calls == [("login", "app")]  # one run, no outer probe, not scheduled
    st = als.site_states()["app"]
    assert st["stage"] == "usable" and "trial" not in st


def test_p_never_retries_and_the_budget_stays_spent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    view = _view()
    _listing(monkeypatch, view)
    calls: list = []
    failed = {"phase": "submit", "code": "login_failed", "submitted": True}

    def run(*args: str, **_kw: Any) -> Any:
        calls.append(args)
        return _run(2, failed)

    monkeypatch.setattr(al, "run_browser", run)
    assert al.promote_action("app") == 1
    assert al.promote_action("app") == 2  # spent: no second login
    assert calls == [("login", "app")]
    assert als.site_states()["app"]["stage"] != "usable"
    assert al.rearm_action("app") == 0
    assert al.promote_action("app") == 1 and len(calls) == 2


def test_p_refunds_when_the_free_check_found_the_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    view = _view()
    _listing(monkeypatch, view)
    res = {**_ok_result(view), "route": "already"}
    monkeypatch.setattr(al, "run_browser", lambda *_a, **_k: _run(0, res))
    assert al.promote_action("app") == 0
    assert "trial" not in als.site_states()["app"]


@pytest.mark.parametrize(
    "view",
    [
        _view(limit={"state": "cooldown", "reset": "wait"}),
        _view(cookie_hosts=["github.io"]),
        _view(sentinel=False, strict_proof=False, logged_in_selector=None),
        _view(refused=True, reason="bad agent_storage_keys: a key is not a string"),
        _view(no_submit=True),
    ],
)
def test_p_never_logs_in_when_a_gate_refuses(
    monkeypatch: pytest.MonkeyPatch, view: dict
) -> None:
    _listing(monkeypatch, view)
    calls = _no_login(monkeypatch)
    assert al.promote_action("app") == 2 and not calls
    assert "trial" not in (als.site_states().get("app") or {})


def test_p_works_for_a_server_proof_site(monkeypatch: pytest.MonkeyPatch) -> None:
    view = _view(
        "cscs",
        "portal.cscs.ch",
        logged_in_selector=None,
        sentinel=False,
        strict_proof=True,
    )
    _listing(monkeypatch, view)
    monkeypatch.setattr(al, "run_browser", lambda *_a, **_k: _run(0, _ok_result(view)))
    assert al.promote_action("cscs") == 0


def test_t_of_a_pending_broker_site_takes_the_same_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    view = _view()
    _listing(monkeypatch, view)
    calls: list = []

    def run(*args: str, **_kw: Any) -> Any:
        calls.append(args)
        if args[0] == "login":
            return _run(
                2, {"phase": "submit", "code": "login_failed", "submitted": True}
            )
        return _run(2, {"phase": "client-proof", "code": "logged_out"})

    monkeypatch.setattr(al, "run_browser", run)
    assert al._run_test("app") == 2
    assert al._run_test("app") == 2  # spent: no second login
    assert [c[0] for c in calls].count("login") == 1
    assert al.promote_action("app") == 2


def test_check_all_never_logs_in_a_risky_or_changed_row() -> None:
    cfg = "a" * 64
    row = {
        "site": "app",
        "name": "app",
        "status": "ready",
        "flow": "one-page",
        "stage": "usable",
        "config": cfg,
        "promoted_config": cfg,
        "promoted_config_v": onboarding.CONFIG_V,
    }
    assert al.check_only_gate(row) is None
    assert al.check_only_gate({**row, "onboarding_risk": ["public_suffix_scope"]})[
        0
    ] == ("onboarding_risk")
    assert al.check_only_gate({**row, "config": "b" * 64})[0] == "changed"
    assert al.check_only_gate({**row, "promoted_config": None})[0] == "config_unknown"


def test_overview_rows_carry_the_risk(monkeypatch: pytest.MonkeyPatch) -> None:
    _listing(
        monkeypatch,
        _view(cookie_hosts=["github.io"]),
        _view("fine", "fine.example.org"),
    )
    monkeypatch.setattr(al, "safari_state", lambda _n: {})
    rows = {r["site"]: r for r in al.overview()["rows"]}
    assert rows["app"]["onboarding_risk"] == ["public_suffix_scope"]
    assert rows["fine"]["onboarding_risk"] == []


def test_d_phase_one_demotes_and_logs_out(monkeypatch: pytest.MonkeyPatch) -> None:
    view = _view()
    _listing(monkeypatch, view)
    als.promote("app", config=onboarding.config_digest(view))
    calls: list = []

    def run(*args: str, **_kw: Any) -> Any:
        calls.append(args)
        return _run(0, None)

    monkeypatch.setattr(al, "run_browser", run)
    assert al.remove_action("app") == 0
    assert calls == [("logout", "app")]
    assert als.site_states()["app"]["stage"] == "pending"
    monkeypatch.setattr(al, "run_browser", lambda *_a, **_k: _run(2, None))
    assert al.remove_action("app") == 1  # a failed logout stops phase 1


def test_d_phase_one_never_logs_out_a_sibling_account(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """S2: abs-root and abs-albert share one scope in the same browser — a
    logout of the leaving one would end the other's session."""
    root = _view("abs-root", "abs.example.org", privilege="admin")
    albert = _view("abs-albert", "abs.example.org", privilege="user")
    other_instance = _view("abs-alt", "abs.example.org", instance="alt")
    _listing(monkeypatch, root, albert)
    calls = _no_login(monkeypatch)
    assert al.sibling_in_instance("abs-root", [root, albert]) == ["abs-albert"]
    assert al.remove_action("abs-root") == 0 and not calls
    out = capsys.readouterr().out
    assert "NOT logged out" in out and "abs-albert" in out and "-F" in out
    assert als.site_states()["abs-root"]["stage"] == "pending"
    # a sibling in ANOTHER instance does not share this browser's jar
    assert al.sibling_in_instance("abs-root", [root, other_instance]) == []
    # -F forces the logout
    ran: list = []

    def run(*args: str, **_kw: Any) -> Any:
        ran.append(args)
        return _run(0, None)

    monkeypatch.setattr(al, "run_browser", run)
    assert al.remove_action("abs-root", force=True) == 0
    assert ran == [("logout", "abs-root")]


def _break_psl(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """The vendored list replaced by one that is not the pinned version."""
    bad = tmp_path / "psl.dat"
    bad.write_text("com\n", encoding="utf-8")
    monkeypatch.setattr(onboarding, "PSL_FILE", bad)
    onboarding._psl.cache_clear()


@pytest.fixture(autouse=True)
def _psl_cache() -> Any:
    yield
    onboarding._psl.cache_clear()


def test_a_bad_psl_is_reported_once_and_gates_nothing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """S3: an infrastructure error, once — not a per-site gate."""
    _break_psl(monkeypatch, tmp_path)
    views = [_view("a1", "a1.example.org"), _view("a2", "a2.example.org")]
    _listing(monkeypatch, *views)
    assert al.validate_action(None, fresh=False) == 1
    assert capsys.readouterr().out.count("Public Suffix List is unusable") == 1
    monkeypatch.setattr(al, "safari_state", lambda _n: {})
    rows = {r["site"]: r for r in al.overview()["rows"]}
    assert rows["a1"]["onboarding_risk"] == [] and rows["a2"]["onboarding_risk"] == []
    view = views[0]
    monkeypatch.setattr(al, "run_browser", lambda *_a, **_k: _run(0, _ok_result(view)))
    assert al.promote_action("a1") == 1  # no new usable site meanwhile
    assert capsys.readouterr().out.count("Public Suffix List is unusable") == 1


def test_a_trial_that_never_started_is_refunded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """S4: an exception before browser.py runs (the instance does not start)
    and an exit 75 (busy) give the budget back."""
    view = _view()
    _listing(monkeypatch, view)

    @contextlib.contextmanager
    def broken(_site: str) -> Any:
        raise RuntimeError("the admin browser does not start")
        yield  # pylint: disable=unreachable

    monkeypatch.setattr(al, "site_session", broken)
    with pytest.raises(RuntimeError):
        al.promote_action("app")
    assert "trial" not in als.site_states()["app"]
    monkeypatch.setattr(al, "site_session", lambda _s: contextlib.nullcontext())
    monkeypatch.setattr(al, "run_browser", lambda *_a, **_k: _run(al.BUSY_RC, None))
    assert al.promote_action("app") == 1
    assert "trial" not in als.site_states()["app"]

    # -t: the exec of browser.py fails at Popen -> run_browser's own
    # "not started" marker -> refunded, recorded, exit 1
    monkeypatch.setattr(al, "run_browser", jobs.run_browser)

    def no_exec(*_a: Any, **_k: Any) -> Any:
        raise FileNotFoundError("no python")

    monkeypatch.setattr(jobs.subprocess, "run", no_exec)
    assert al._run_test("app") == 1
    assert "trial" not in als.site_states()["app"]
    assert "could not be started" in als.checks()["app"]["how"]


def test_an_oserror_after_the_child_started_spends_the_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Only a provably unstarted child refunds: an OSError out of the run
    after browser.py ran (the result tempdir's cleanup) spends it."""
    _listing(monkeypatch, _view())
    monkeypatch.setattr(al, "run_browser", jobs.run_browser)
    ran: list = []

    def child(argv: Any, **_k: Any) -> Any:
        ran.append(argv)
        return subprocess.CompletedProcess(argv, 2, "", "")

    monkeypatch.setattr(jobs.subprocess, "run", child)

    class _BadCleanup:
        def __init__(self, *_a: Any, **_k: Any) -> None:
            self.name = str(REPO / "tests")  # never written: result is None

        def __enter__(self) -> str:
            return "/nonexistent-ws3-dir"

        def __exit__(self, *_a: Any) -> None:
            raise OSError("cleanup failed")

    monkeypatch.setattr(jobs.tempfile, "TemporaryDirectory", _BadCleanup)
    with pytest.raises(OSError, match="cleanup failed"):
        al._run_test("app")
    assert ran  # the child DID run
    assert als.trial_state("app").get("spent") is True


def test_reap_owned_tabs_never_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_a: Any, **_k: Any) -> Any:
        raise OSError("no fork")

    monkeypatch.setattr(jobs, "run_browser", boom)
    assert jobs.reap_owned_tabs() is None


def test_a_bad_psl_refuses_promotion_and_planned_reviews(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """With the list broken, a public-suffix scope cannot be ruled out: -p
    and -V -i refuse; -c only reports it."""
    _break_psl(monkeypatch, tmp_path)
    view = _view(cookie_hosts=["co.uk"], fill_origins=["https://app.example.co.uk"])
    _listing(monkeypatch, view)
    calls = _no_login(monkeypatch)
    assert al.promote_action("app") == 1 and not calls
    assert "Public Suffix List is unusable" in capsys.readouterr().out
    assert als.site_states().get("app", {}).get("stage") != "usable"
    manifest = tmp_path / "m.json"
    manifest.write_text(json.dumps({"name": "x", "fields": {}}), encoding="utf-8")
    assert al.validate_action(str(manifest), fresh=False) == 1
    assert "not reviewed" in capsys.readouterr().out
    monkeypatch.setattr(al, "safari_state", lambda _n: {})
    rows = {r["site"]: r for r in al.overview()["rows"]}
    assert rows["app"]["onboarding_risk"] == []  # -c is not gated per site


def test_d_phase_two_forgets_everything(
    monkeypatch: pytest.MonkeyPatch, _cache_dir: Path
) -> None:
    _listing(monkeypatch, _view("kept", "kept.example.org"))
    als.record_check("gone", "ok", "x")
    als.ensure_known(["gone"])
    als.quarantine("gone", "submit", "x")
    _session_age(_cache_dir, "gone")
    asked: list = []

    def broker(op: str, **kw: Any) -> dict:
        kw.pop("timeout", None)
        asked.append((op, kw))
        return {
            "ok": True,
            "limiter": True,
            "groups": 0,
            "guard": False,
            "profile": True,
            "screenshot": False,
        }

    monkeypatch.setattr(al, "broker_request", broker)
    monkeypatch.setattr(al, "safari_state", lambda _n: {})
    assert al.remove_action("gone") == 0
    assert asked == [("forget", {"site": "gone"})]
    for name in (als.CHECKS_FILE, als.LEGACY_FILE, als.SITE_STATE_FILE):
        assert "gone" not in als.read(name)
    agents = (als.state_dir() / "agents.md").read_text()
    assert "gone" not in agents
    left = [p for p in _cache_dir.rglob("gone*") if p.suffix != ".lock"]
    assert not left  # only an empty lock file may stay (never unlinked while held)


@pytest.mark.parametrize(
    ("left", "phase"),
    [
        ({"gone": "locked"}, "limiter"),
        ({"identity-guard": "identity_cooldown"}, "client-proof"),
    ],
)
def test_d_keeps_the_client_record_while_the_broker_keeps_a_block(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    left: dict,
    phase: str,
) -> None:
    """A re-added item must show the real lockout, not only "rate limited":
    while `forget` reports `left`, the site-state record stays (demoted,
    quarantined); everything else goes. The next -D (after install.sh -r)
    removes it."""
    _listing(monkeypatch, _view("kept", "kept.example.org"))
    monkeypatch.setattr(al, "safari_state", lambda _n: {})
    als.record_check("gone", "failed", "x")
    als.promote("gone", config="a" * 64)
    reply = {"ok": True, "limiter": False, "groups": 0, "guard": False, "profile": True}
    monkeypatch.setattr(al, "broker_request", lambda *_a, **_k: {**reply, "left": left})
    assert al.remove_action("gone") == 0
    assert "install.sh -r gone" in capsys.readouterr().out
    entry = als.site_states()["gone"]
    assert entry["stage"] == "pending"
    assert entry["quarantine"]["phase"] == phase
    assert entry["quarantine"]["code"] == next(iter(left.values()))
    assert "gone" not in als.read(als.CHECKS_FILE)
    # a quarantine recorded before is kept as it was
    als.quarantine("gone", "submit", "login_failed")
    assert al.remove_action("gone") == 0
    assert als.site_states()["gone"]["quarantine"]["phase"] == "submit"
    # the block lifted by root: the next -D removes the record too
    monkeypatch.setattr(al, "broker_request", lambda *_a, **_k: {**reply, "left": {}})
    assert al.remove_action("gone") == 0
    assert "gone" not in als.site_states()


def test_d_refuses_without_a_fresh_listing_and_on_broker_refusal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    als.record_check("gone", "ok", "x")
    _listing(monkeypatch, ok=False)
    assert al.remove_action("gone") == 1
    _listing(monkeypatch)
    monkeypatch.setattr(
        al,
        "broker_request",
        lambda *_a, **_k: {"ok": False, "error": "still_listed", "detail": "x"},
    )
    assert al.remove_action("gone") == 1
    assert "gone" in als.read(als.CHECKS_FILE)  # nothing changed
    assert al.remove_action("cscs") == 2  # a built-in target
