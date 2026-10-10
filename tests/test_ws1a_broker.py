"""WS1a broker side: phases, the outcome-aware attempt API with attempt groups,
the daemon's admission order / outcome mapping / candidate sentinels, resets.

Hermetic: no Chrome, no socket — the daemon's `Broker` is driven directly with
stub runners, the limiter on a temp file.
"""

from __future__ import annotations

# pylint: disable=protected-access,missing-function-docstring,missing-class-docstring
# pylint: disable=import-error,wrong-import-position,too-few-public-methods
import argparse
import importlib.util
import json
import os
import sys
import threading
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from broker import daemon, limiter, phases, recipes, vault  # noqa: E402

PASSWORD = "pw-Sup3rSecret!"
COOL = 1800.0


def _lim(path: Path, **kw: Any) -> limiter.Limiter:
    args: dict[str, Any] = {"min_interval_s": 0, "per_hour": 50, "per_day": 100}
    args.update(kw)
    return limiter.Limiter(path, cooldown_s=COOL, **args)


def _state(path: Path) -> dict[str, Any]:
    sites: dict[str, Any] = json.loads(path.read_text())["sites"]
    return sites


# ---------------------------------------------------------------------------
# phases
# ---------------------------------------------------------------------------


def test_phase_vocabulary_is_closed_and_fixed() -> None:
    assert phases.PHASE_V == 1
    assert phases.phase_for_error("rate_limited") == "limiter"
    assert phases.phase_for_error("login_failed") == "unknown"  # never pre-submit
    assert phases.phase_for_error("login_failed", "recipe") == "recipe"
    assert phases.phase_for_error("x", "made-up") == "unknown"
    assert phases.post_submit("recipe", True)
    assert not phases.post_submit("profile-proof", False)
    assert not phases.post_submit("broker-proof", False)  # submit state decides
    assert phases.post_submit("unknown", None)
    assert phases.text("limiter", "locked").startswith(phases.PHASE_TEXT["limiter"])


@pytest.mark.parametrize(
    "raw, want",
    [
        ("plain words stay", "plain words stay"),
        ("mail alice@example.org now", "mail <email> now"),
        ("https://x.example/a/b?token=abc", "https://x.example"),
        ("tok 0123456789abcdef0123456789", "tok <…>"),
        ("authentication_expired_long_word", "authentication_expired_long_word"),
        ("a\nb\x00c", "a b c"),
    ],
)
def test_redact(raw: str, want: str) -> None:
    assert phases.redact(raw) == want


def test_redact_caps_length() -> None:
    assert len(phases.redact("w " * 500)) == phases.DETAIL_MAX


# ---------------------------------------------------------------------------
# limiter: outcome-aware attempts
# ---------------------------------------------------------------------------


def test_pre_vs_post_submit_failure(tmp_path: Path) -> None:
    state = tmp_path / "l.json"
    lim = _lim(state)
    grant = lim.reserve_site("s", 0.0)
    assert isinstance(grant, limiter.AttemptGrant)
    lim.finish(grant, "not_submitted", 1.0)
    assert lim.peek(["s"], 2.0) is None  # pre-submit: no cooldown
    grant = lim.reserve_site("s", 10.0)
    assert isinstance(grant, limiter.AttemptGrant)
    lim.mark_submitted(grant)
    lim.finish(grant, "unknown", 11.0)
    denied = lim.peek(["s"], 12.0)
    assert denied is not None and denied.state == "cooldown"
    assert _state(state)["s"]["consecutive"] == 1
    assert [a[1] for a in _state(state)["s"]["attempts"]] == ["failed", "unknown"]


def test_group_cooldown_blocks_every_member(tmp_path: Path) -> None:
    lim = _lim(tmp_path / "l.json")
    grant = lim.reserve_site("galaxus", 0.0, group="gx")
    assert isinstance(grant, limiter.AttemptGrant)
    assert grant.keys == ("galaxus", "group:gx")
    lim.mark_submitted(grant)
    lim.finish(grant, "unknown", 1.0)
    other = lim.reserve_site("galaxus-de", 2.0, group="gx")
    assert isinstance(other, limiter.Denied)
    assert other.key == "group:gx" and other.state == "cooldown"
    assert "install.sh -r group:gx" in other.limit()["reset"]
    assert lim.reserve_site("unrelated", 2.0) is not None


def test_concurrent_reservations_in_one_group(tmp_path: Path) -> None:
    state = tmp_path / "l.json"
    lims = [_lim(state), _lim(state)]  # two instances = two processes
    got: list[Any] = []
    barrier = threading.Barrier(8)

    def go(i: int) -> None:
        barrier.wait()
        got.append(lims[i % 2].reserve_site(f"site{i}", 100.0, group="one"))

    threads = [threading.Thread(target=go, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    grants = [g for g in got if isinstance(g, limiter.AttemptGrant)]
    assert len(grants) == 1  # the group's in-flight mark makes the rest busy
    assert all(g.state == "busy" for g in got if isinstance(g, limiter.Denied))


def test_scheduled_reservation_refuses_an_unresolved_failure(tmp_path: Path) -> None:
    lim = _lim(tmp_path / "l.json")
    grant = lim.reserve_site("s", 0.0)
    assert isinstance(grant, limiter.AttemptGrant)
    lim.mark_submitted(grant)
    lim.finish(grant, "unknown", 1.0)
    later = COOL + 10
    denied = lim.reserve_site("s", later, scheduled=True)
    assert isinstance(denied, limiter.Denied) and denied.state == "quarantined"
    assert isinstance(lim.reserve_site("s", later), limiter.AttemptGrant)  # manual


def test_only_fresh_auth_clears_the_streak(tmp_path: Path) -> None:
    state = tmp_path / "l.json"
    lim = _lim(state)
    t = 0.0
    for outcome in ("unknown", "not_submitted", "ok"):
        t += COOL + 10
        grant = lim.reserve_site("s", t)
        assert isinstance(grant, limiter.AttemptGrant), outcome
        lim.finish(grant, outcome, t + 1)
        if outcome != "ok":
            assert _state(state)["s"]["consecutive"] == 1
    assert _state(state)["s"]["consecutive"] == 0


def test_mark_entered_never_downgrades_submitted(tmp_path: Path) -> None:
    state = tmp_path / "l.json"
    lim = _lim(state)
    grant = lim.reserve_site("s", 0.0)
    assert isinstance(grant, limiter.AttemptGrant)
    lim.mark_submitted(grant)
    lim.mark_entered(grant)
    assert _state(state)["s"]["inflight"]["state"] == "submitted"


@pytest.mark.parametrize(
    "steps, stored, streak",
    [
        ((), "failed", 0),
        (("entered",), "unknown", 1),
        (("entered", "submitted"), "unknown", 1),
    ],
)
def test_crash_recovery_per_transition(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    steps: tuple,
    stored: str,
    streak: int,
) -> None:
    state = tmp_path / "l.json"
    dead = _lim(state)
    grant = dead.reserve_site("s", 0.0, group="g")
    assert isinstance(grant, limiter.AttemptGrant)
    for step in steps:
        getattr(dead, f"mark_{step}")(grant)
    monkeypatch.setattr(limiter, "pid_alive", lambda _pid: False)  # owner died
    fresh = _lim(state)
    fresh.peek(["s", "group:g"], COOL / 2)
    for key in ("s", "group:g"):
        entry = _state(state)[key]
        assert "inflight" not in entry
        assert entry["attempts"][-1][1] == stored
        assert int(entry.get("consecutive", 0)) == streak


def test_pid_reuse_is_recovered_but_a_live_owner_stays_busy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = tmp_path / "l.json"
    owner = _lim(state)
    grant = owner.reserve_site("s", 0.0)
    assert isinstance(grant, limiter.AttemptGrant)
    owner.mark_submitted(grant)
    other = _lim(state)
    # Alive and the same start time: busy, even ten days later (no age rule).
    monkeypatch.setattr(limiter, "proc_start", lambda _pid: owner._my_start())
    denied = other.peek(["s"], 10 * 86400.0)
    assert denied is not None and denied.state == "busy"
    # The pid now belongs to another process (start time differs): recovered.
    monkeypatch.setattr(limiter, "proc_start", lambda _pid: "Thu Jan  1 00:00:00 1970")
    other.peek(["s"], 10 * 86400.0)
    assert "inflight" not in _state(state)["s"]
    assert _state(state)["s"]["consecutive"] == 1


def test_profile_reuse_leaves_the_limiter_byte_identical(tmp_path: Path) -> None:
    state = tmp_path / "l.json"
    lim = _lim(state)
    grant = lim.reserve_site("s", 0.0)
    assert isinstance(grant, limiter.AttemptGrant)
    lim.mark_submitted(grant)
    lim.finish(grant, "unknown", 1.0)
    before = state.read_bytes()
    brk = _broker(tmp_path, lim, _Runner(proof=recipes.VALID))
    resp = brk._do_login("shop")
    assert resp["ok"] and resp["fresh_auth"] is False
    assert state.read_bytes() == before
    assert _secret_calls(brk) == 0


def test_bindings_survive_denial_and_group_changes(tmp_path: Path) -> None:
    state = tmp_path / "l.json"
    lim = _lim(state)
    # blocked before any binding existed
    _state_write(
        state, {"group:old": {"attempts": [], "blocked": True, "consecutive": 3}}
    )
    denied = lim.reserve_site("s", 0.0, group="old")
    assert isinstance(denied, limiter.Denied) and denied.key == "group:old"
    assert lim.groups_of("s") == ["old"]  # bound although denied
    # the item moves to another group: the old block still applies
    denied = lim.reserve_site("s", 1.0, group="new")
    assert isinstance(denied, limiter.Denied) and denied.key == "group:old"
    assert lim.groups_of("s") == ["new", "old"]
    assert lim.site_keys("s") == ["s", "group:new", "group:old"]


def _state_write(path: Path, sites: dict[str, Any]) -> None:
    path.write_text(json.dumps({"sites": sites}))


def test_reset_refuses_a_live_attempt_and_chowns_inside_the_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = tmp_path / "l.json"
    lim = _lim(state)
    grant = lim.reserve_site("s", 0.0)
    assert isinstance(grant, limiter.AttemptGrant)
    resetter = _lim(state)
    monkeypatch.setattr(limiter, "proc_start", lambda _pid: lim._my_start())
    with pytest.raises(limiter.LimiterBusy):
        resetter.reset("s")
    lim.finish(grant, "not_submitted", 1.0)
    chowned: list[Any] = []
    monkeypatch.setattr(
        os, "chown", lambda p, u, g, **_kw: chowned.append(("path", u, g))
    )
    monkeypatch.setattr(os, "fchown", lambda fd, u, g: chowned.append(("fd", u, g)))
    resetter.reset("s", owner=(7, 8))
    assert "s" not in _state(state)
    assert chowned == [("path", 7, 8), ("fd", 7, 8)]


def test_symlinked_lock_file_fails_closed(tmp_path: Path) -> None:
    state = tmp_path / "l.json"
    (tmp_path / "elsewhere").write_text("")
    os.symlink(tmp_path / "elsewhere", tmp_path / "l.json.lock")
    lim = _lim(state)
    denied = lim.peek(["s"], 0.0)
    assert denied is not None and denied.state == "unreadable"
    assert isinstance(lim.reserve_site("s", 0.0), limiter.Denied)


def _legacy() -> Any:
    path = REPO / "tests" / "legacy" / "limiter_pre_ws1a.py"
    spec = importlib.util.spec_from_file_location("limiter_pre_ws1a", path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod  # dataclasses look their module up
    spec.loader.exec_module(mod)
    return mod


def test_frozen_legacy_limiter_reads_new_state(tmp_path: Path) -> None:
    state = tmp_path / "l.json"
    new = _lim(state)
    # a hard-blocked site, an attempt in flight, group keys and bindings
    for t in (0.0, COOL + 10, 2 * COOL + 20):
        grant = new.reserve_site("blocked", t, group="g")
        assert isinstance(grant, limiter.AttemptGrant)
        new.mark_submitted(grant)
        new.finish(grant, "unknown", t)
        new.reset("group:g")
    assert _state(state)["blocked"]["blocked"] is True
    inflight = new.reserve_site("live", 0.0)
    assert isinstance(inflight, limiter.AttemptGrant)
    old = _legacy().Limiter(state, 0, 50, 100, cooldown_s=COOL)
    later = 3 * COOL + 30
    ok, reason = old.check("blocked", later)
    assert not ok and "reset" in reason
    old.check("live", later)  # a new-format mark counts as one more unknown
    assert _state(state)["live"]["consecutive"] == 1  # more denial, never less
    assert "inflight" not in _state(state)["live"]
    assert old.check("free", later)[0]


# ---------------------------------------------------------------------------
# vault: groups and proof origins
# ---------------------------------------------------------------------------


def _raw(fields: dict[str, str], user: str = "alice@example.org") -> dict[str, Any]:
    base = {"agent_site": "shop", "agent_fill_origins": "https://login.shop.example"}
    return {
        "id": "id-shop",
        "name": "Shop",
        "login": {"username": user, "password": PASSWORD},
        "fields": [{"name": k, "value": v} for k, v in {**base, **fields}.items()],
    }


@pytest.mark.parametrize(
    "group, refused",
    [
        ("gx-1", None),
        ("Bad Group!", "bad agent_attempt_group"),
        ("alice-shops", "must not reveal"),
        ("x-alice@example.org", "bad agent_attempt_group"),
    ],
)
def test_attempt_group_field(group: str, refused: str | None) -> None:
    item = vault.site_item_from_json(
        _raw({"agent_attempt_group": group, "agent_logged_in_selector": "#me"})
    )
    if refused is None:
        assert item.refused is None and item.limiter_keys == ["shop", f"group:{group}"]
        assert item.public()["attempt_group"] == group
    else:
        assert item.refused and refused in item.refused


# ---------------------------------------------------------------------------
# daemon: admission order, outcome mapping, phases
# ---------------------------------------------------------------------------


class _Vault:
    def __init__(self, items: list[vault.SiteItem]) -> None:
        self._items = items
        self.secret_calls = 0

    def items(self) -> list[vault.SiteItem]:
        return self._items

    def secret(self, site: str) -> vault.Secret:
        del site
        self.secret_calls += 1
        return vault.Secret(username="a", password=PASSWORD)


def _shop(**fields: str) -> vault.SiteItem:
    base = {
        "agent_check_url": "https://www.shop.example/account",
        "agent_logged_in_selector": "#me",
        "agent_cookie_hosts": "shop.example",
    }
    return vault.site_item_from_json(_raw({**base, **fields}))


class _Runner:
    """A stub runner shaped like PlaywrightRunner.run_in_context."""

    def __init__(
        self,
        *,
        proof: str = recipes.INVALID,
        recipe: Any = None,
        after: str = recipes.VALID,
        export_ok: bool = True,
        throwaway: str = "invalid",
    ) -> None:
        self.throwaway = throwaway  # the candidate on a logged-out page
        self.proof = proof
        self.recipe = recipe
        self.after = after
        self.export_ok = export_ok
        self.last_diag: dict[str, Any] = {}
        self.cookies_cleared = False

    def __call__(self, item: vault.SiteItem, get_secret: Any) -> dict[str, Any]:
        if getattr(get_secret, "candidate", False):
            daemon.PlaywrightRunner._candidate_absent(self.throwaway)
        if item.fresh_login:
            get_secret()
            self.cookies_cleared = True
        else:
            if self.proof == recipes.VALID:
                return {"via": "profile", "cookies": [{"n": 1}]}
            if self.proof == recipes.INDETERMINATE:
                raise recipes.LoginFailed("undecided", phase="profile-proof")
            get_secret()
        attempt = getattr(get_secret, "attempt", recipes.AttemptController())
        if self.recipe is not None:
            self.recipe(attempt)
        else:
            attempt.entered()
            attempt.mark_submitted()
        if self.after != recipes.VALID:
            raise recipes.LoginFailed(
                "proof failed", phase="broker-proof", submitted=attempt.submitted
            )
        if not self.export_ok:
            raise recipes.ExportFailed(
                "export failed", phase="bundle-export", auth_proven=True
            )
        return {"via": "login", "cookies": [{"n": 1}]}


def _broker(
    tmp_path: Path, lim: limiter.Limiter, runner: Any, items: list | None = None
) -> daemon.Broker:
    return daemon.Broker(
        _Vault(items if items is not None else [_shop()]),  # type: ignore[arg-type]
        lim,
        tmp_path / "home",
        runner=runner,
        clock=lambda: 10.0,  # inside the 30-min cooldown of a failure at t=0
    )


def _secret_calls(brk: daemon.Broker) -> int:
    return int(getattr(brk.vault, "secret_calls"))


def _cooldown(lim: limiter.Limiter, site: str = "shop") -> None:
    grant = lim.reserve_site(site, 0.0)
    assert isinstance(grant, limiter.AttemptGrant)
    lim.mark_submitted(grant)
    lim.finish(grant, "unknown", 0.0)


def test_cooldown_and_stale_profile_is_rate_limited_without_a_secret(
    tmp_path: Path,
) -> None:
    lim = _lim(tmp_path / "l.json")
    _cooldown(lim)
    brk = _broker(tmp_path, lim, _Runner(proof=recipes.INVALID))
    resp = brk._do_login("shop")
    assert resp["error"] == "rate_limited" and resp["phase"] == "limiter"
    assert resp["limit"]["state"] == "cooldown" and resp["submitted"] is False
    assert _secret_calls(brk) == 0


def test_fresh_login_reserves_before_clearing_cookies(tmp_path: Path) -> None:
    lim = _lim(tmp_path / "l.json")
    _cooldown(lim)
    runner = _Runner()
    item = _shop(agent_fresh_login="true")
    brk = _broker(tmp_path, lim, runner, [item])
    assert brk._do_login("shop")["error"] == "rate_limited"
    assert not runner.cookies_cleared and _secret_calls(brk) == 0


def test_profile_check_503_is_profile_proof_and_touches_nothing(tmp_path: Path) -> None:
    state = tmp_path / "l.json"
    lim = _lim(state)
    brk = _broker(tmp_path, lim, _Runner(proof=recipes.INDETERMINATE))
    resp = brk._do_login("shop")
    assert resp["phase"] == "profile-proof" and resp["submitted"] is False
    assert _secret_calls(brk) == 0 and not state.exists()


@pytest.mark.parametrize(
    "recipe, after, export_ok, phase, stored, streak",
    [
        # submit marker + valid proof + export failure -> ok (fresh auth)
        (None, recipes.VALID, False, "bundle-export", "ok", 0),
        # silent SSO: no typing at all + export failure -> not_submitted
        ("silent", recipes.VALID, False, "bundle-export", "failed", 0),
        # marker + post-auth 503 -> unknown
        (None, recipes.INDETERMINATE, True, "broker-proof", "unknown", 1),
    ],
)
def test_outcome_mapping(  # pylint: disable=too-many-arguments,too-many-positional-arguments
    tmp_path: Path,
    recipe: Any,
    after: str,
    export_ok: bool,
    phase: str,
    stored: str,
    streak: int,
) -> None:
    state = tmp_path / "l.json"
    lim = _lim(state)
    fn = (lambda _a: None) if recipe == "silent" else None
    brk = _broker(tmp_path, lim, _Runner(recipe=fn, after=after, export_ok=export_ok))
    resp = brk._do_login("shop")
    assert resp["phase"] == phase
    entry = _state(state)["shop"]
    assert entry["attempts"][-1][1] == stored
    assert int(entry.get("consecutive", 0)) == streak
    assert "inflight" not in entry


def _typed_then(exc: Exception) -> Any:
    def recipe(attempt: Any) -> None:
        attempt.entered()
        raise exc

    return recipe


@pytest.mark.parametrize(
    "exc, stored, phase",
    [
        # value still in the field, no button: provably unsent
        (recipes.LoginFailed("no login button", unsent=True), "failed", "recipe"),
        # value gone after typing (auto-submit?) and no marker: unknown
        (recipes.LoginFailed("the field dropped the value"), "unknown", "submit"),
    ],
)
def test_entered_without_marker(
    tmp_path: Path, exc: Exception, stored: str, phase: str
) -> None:
    state = tmp_path / "l.json"
    brk = _broker(tmp_path, _lim(state), _Runner(recipe=_typed_then(exc)))
    resp = brk._do_login("shop")
    assert resp["phase"] == phase
    assert _state(state)["shop"]["attempts"][-1][1] == stored


def test_success_reply_carries_phase_and_fresh_auth(tmp_path: Path) -> None:
    brk = _broker(tmp_path, _lim(tmp_path / "l.json"), _Runner())
    resp = brk._do_login("shop")
    assert resp["ok"] and resp["phase"] == "ok" and resp["fresh_auth"] is True
    assert resp["phase_v"] == phases.PHASE_V


def test_needs_sentinel_refuses_only_a_scheduled_login(tmp_path: Path) -> None:
    """C2: a sentinel-less item keeps the old proof for manual logins; a
    SCHEDULED one is refused before any secret or reservation."""
    state = tmp_path / "l.json"
    item = vault.site_item_from_json(
        _raw({"agent_check_url": "https://www.shop.example/account"})
    )
    brk = _broker(tmp_path, _lim(state), _Runner(), [item])
    resp = brk._do_login("shop", scheduled=True)
    assert resp["error"] == "needs_sentinel" and resp["phase"] == "vault"
    assert _secret_calls(brk) == 0 and not state.exists()
    resp = brk._do_login("shop")
    assert resp["ok"] and resp["proof"] == "legacy"
    assert brk._do_login.__name__  # (manual login ran with the old proof)


def test_candidate_sentinel(tmp_path: Path) -> None:
    item = vault.site_item_from_json(
        _raw({"agent_check_url": "https://www.shop.example/account"})
    )
    state = tmp_path / "l.json"
    # visible on the logged-OUT page too: unverifiable, nothing reserved
    for throwaway in (recipes.VALID, recipes.INDETERMINATE):
        brk = _broker(tmp_path, _lim(state), _Runner(throwaway=throwaway), [item])
        resp = brk._login_request("shop", {"candidate_sentinel": "#me"})
        assert resp["error"] == "candidate_unverifiable"
        assert resp["phase"] == "profile-proof"
        assert not state.exists() and _secret_calls(brk) == 0
    # absent logged out, present in the still logged-in profile: verified free
    brk = _broker(tmp_path, _lim(state), _Runner(proof=recipes.VALID), [item])
    resp = brk._login_request("shop", {"candidate_sentinel": "#me"})
    assert resp["ok"] and resp["candidate_verified"] and not state.exists()
    # absent logged out, present after a login: verified, recorded as candidate
    brk = _broker(tmp_path, _lim(state), _Runner(proof=recipes.INVALID), [item])
    resp = brk._login_request("shop", {"candidate_sentinel": "#me"})
    assert resp["ok"] and resp["candidate_verified"] is True
    assert _state(state)["shop"]["attempts"][-1][1] == "candidate"
    # never for a scheduled run, never for an item that has a sentinel
    resp = brk._login_request("shop", {"candidate_sentinel": "#me", "scheduled": True})
    assert resp["error"] == "refused"
    brk = _broker(tmp_path, _lim(state), _Runner(), [_shop()])
    assert brk._login_request("shop", {"candidate_sentinel": "#x"})["error"] == (
        "bad_request"
    )


def test_sentinel_absent_op(tmp_path: Path) -> None:
    class _Probe(_Runner):
        def sentinel_absent(self, item: Any, sentinel: str) -> dict[str, Any]:
            del item
            return {"loaded": True, "status": 200, "present": sentinel == "#logo"}

    brk = _broker(tmp_path, _lim(tmp_path / "l.json"), _Probe())
    resp = brk.handle({"op": "sentinel_absent", "site": "shop", "sentinel": "#me"})
    assert resp == {"ok": True, "loaded": True, "status": 200, "present": False}
    resp = brk.handle({"op": "sentinel_absent", "site": "shop", "sentinel": "a\nb"})
    assert resp["error"] == "bad_request"


def test_sites_op_reports_limit_group_and_sentinel(tmp_path: Path) -> None:
    lim = _lim(tmp_path / "l.json")
    _cooldown(lim)
    brk = _broker(tmp_path, lim, _Runner(), [_shop(agent_attempt_group="gx")])
    brk.clock = lambda: 10.0
    (entry,) = brk._sites()["sites"]
    assert entry["sentinel"] is True and entry["attempt_group"] == "gx"
    assert entry["limit"]["state"] == "cooldown"


# ---------------------------------------------------------------------------
# daemon.py -r
# ---------------------------------------------------------------------------


def _reset_args(key: str, with_group: bool = False) -> argparse.Namespace:
    return argparse.Namespace(reset=key, with_group=with_group, dev=True)


def test_reset_cli_groups(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    home = tmp_path
    lim = daemon.build_limiter(home)
    for t in (0.0, 4000.0, 8000.0):
        grant = lim.reserve_site("galaxus", t, group="gx")
        assert isinstance(grant, limiter.AttemptGrant)
        lim.mark_submitted(grant)
        lim.finish(grant, "unknown", t)
    assert daemon._reset(_reset_args("galaxus"), home) == 0
    out = capsys.readouterr().out
    assert "✅ limiter reset for galaxus" in out and "group:gx still blocks" in out
    assert daemon._reset(_reset_args("galaxus", with_group=True), home) == 0
    assert daemon._reset(_reset_args("group:gx"), home) == 0
    assert daemon._reset(_reset_args("group:Bad!"), home) == 2
    assert daemon._reset(_reset_args("secret:x", with_group=True), home) == 2
    assert daemon.build_limiter(home).peek(["galaxus", "group:gx"], 9000.0) is None


def test_reset_cli_refuses_a_live_attempt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lim = daemon.build_limiter(tmp_path)
    grant = lim.reserve_site("s", 0.0)
    assert isinstance(grant, limiter.AttemptGrant)
    monkeypatch.setattr(limiter, "proc_start", lambda _pid: lim._my_start())
    assert daemon._reset(_reset_args("s"), tmp_path) == 3


def test_runner_candidate_absent_rules() -> None:
    daemon.PlaywrightRunner._candidate_absent(recipes.INVALID)
    for proof in (recipes.VALID, recipes.INDETERMINATE):
        with pytest.raises(recipes.LoginFailed) as err:
            daemon.PlaywrightRunner._candidate_absent(proof)
        assert err.value.code == "candidate_unverifiable"


def test_runner_export_refuses_an_empty_bundle(tmp_path: Path) -> None:
    runner = daemon.PlaywrightRunner(tmp_path)
    runner.export_bundle = lambda *_a: {  # type: ignore[method-assign,assignment]
        "cookies": [],
        "storage": {},
    }
    with pytest.raises(recipes.ExportFailed) as err:
        runner._export(SimpleNamespace(), _shop(), "login", proven=True)
    assert err.value.code == "empty_bundle" and err.value.auth_proven


# ---------------------------------------------------------------------------
# review round 1 (B1-B5 + should-fix)
# ---------------------------------------------------------------------------


def _streak(
    lim: limiter.Limiter, site: str, t: float, group: str | None = None
) -> None:
    grant = lim.reserve_site(site, t, group=group)
    assert isinstance(grant, limiter.AttemptGrant)
    lim.mark_submitted(grant)
    lim.finish(grant, "unknown", t)


def test_b1_candidate_refused_with_any_unresolved_failure(tmp_path: Path) -> None:
    state = tmp_path / "l.json"
    lim = _lim(state)
    _streak(lim, "shop", 0.0)
    item = vault.site_item_from_json(
        _raw({"agent_check_url": "https://www.shop.example/account"})
    )
    brk = _broker(tmp_path, lim, _Runner(), [item])
    brk.clock = lambda: COOL + 100  # cooldown over, streak 1 remains
    resp = brk._login_request("shop", {"candidate_sentinel": "#me"})
    assert resp["error"] == "rate_limited" and resp["limit"]["state"] == "quarantined"
    assert _secret_calls(brk) == 0
    # and at the reservation itself (a race past the pre-check)
    denied = lim.reserve_site("shop", COOL + 100, candidate=True)
    assert isinstance(denied, limiter.Denied) and denied.state == "quarantined"


def test_b1_candidate_outcome_never_clears_a_streak(tmp_path: Path) -> None:
    state = tmp_path / "l.json"
    lim = _lim(state)
    _streak(lim, "shop", 0.0)
    grant = lim.reserve_site("shop", COOL + 100)  # manual, after the cooldown
    assert isinstance(grant, limiter.AttemptGrant)
    lim.mark_submitted(grant)
    lim.finish(grant, "candidate", COOL + 101)
    entry = _state(state)["shop"]
    assert entry["consecutive"] == 1 and entry["attempts"][-1][1] == "candidate"
    assert "cooldown_until" in entry  # untouched


def test_b1_candidate_checks_the_logged_out_page_before_anything(
    tmp_path: Path,
) -> None:
    """fresh_login + candidate: the throwaway check runs BEFORE the
    reservation and before any cookie is cleared."""
    runner = daemon.PlaywrightRunner(tmp_path)
    answers: dict[str, dict[str, Any]] = {
        "got": {"loaded": True, "status": 200, "present": True}
    }
    runner.sentinel_absent = (  # type: ignore[method-assign,assignment]
        lambda _i, _s, **_k: answers["got"]
    )
    cleared: list = []

    def clear(*_a: Any) -> int:
        cleared.append(1)
        return 0

    runner.clear_site_cookies = clear  # type: ignore[method-assign,assignment]
    item = _shop(agent_fresh_login="true")

    class _Gate:
        candidate = True
        calls = 0

        def __call__(self) -> vault.Secret:
            self.calls += 1
            return vault.Secret(username="u", password=PASSWORD)

    gate = _Gate()
    with pytest.raises(recipes.LoginFailed) as err:
        runner.run_in_context(SimpleNamespace(pages=[object()]), item, gate)
    assert err.value.code == "candidate_unverifiable"
    assert gate.calls == 0 and not cleared
    for got, want in (
        ({"loaded": True, "status": 200, "present": False}, "invalid"),
        ({"loaded": True, "status": 503, "present": False}, recipes.INDETERMINATE),
        ({"loaded": False, "status": None, "present": None}, recipes.INDETERMINATE),
    ):
        answers["got"] = got
        assert runner._throwaway_answer(item) == want


def _locked_group(lim: limiter.Limiter) -> None:
    for t in (0.0, COOL + 10, 2 * COOL + 20):
        _streak(lim, "galaxus", t, group="gx")


def test_b2_reset_site_keeps_the_binding(tmp_path: Path) -> None:
    home = tmp_path
    lim = daemon.build_limiter(home)
    _locked_group(lim)
    late = 3 * COOL + 30
    assert daemon._reset(_reset_args("galaxus"), home) == 0
    assert lim.groups_of("galaxus") == ["gx"]  # still bound
    denied = lim.reserve_site("galaxus", late, group="gx")
    assert isinstance(denied, limiter.Denied) and denied.key == "group:gx"
    # the item moves to another group: the old locked group still applies
    denied = lim.reserve_site("galaxus", late, group="other")
    assert isinstance(denied, limiter.Denied) and denied.key == "group:gx"
    # a later -r SITE -G finds and resets the group (and drops the bindings)
    assert daemon._reset(_reset_args("galaxus", with_group=True), home) == 0
    assert lim.groups_of("galaxus") == []
    grant = lim.reserve_site("galaxus", late, group="other")
    assert isinstance(grant, limiter.AttemptGrant)


def test_b3_root_reset_never_leaves_a_root_owned_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path
    lim = daemon.build_limiter(home)
    _locked_group(lim)
    # a crash leftover on the group key: a mark of a dead owner
    raw = json.loads((home / "limiter.json").read_text())
    raw["sites"]["group:gx"]["inflight"] = {
        "id": "dead",
        "ts": 1.0,
        "state": "submitted",
        "instance": "x",
        "pid": 999_999,
    }
    (home / "limiter.json").write_text(json.dumps(raw))
    events: list[str] = []
    real_save = limiter.Limiter._save

    def save(self: limiter.Limiter, data: dict) -> None:
        events.append("save")
        real_save(self, data)

    monkeypatch.setattr(limiter.Limiter, "_save", save)
    monkeypatch.setattr(daemon.os, "geteuid", lambda: 0)
    monkeypatch.setattr(os, "chown", lambda *_a, **_k: events.append("chown"))
    monkeypatch.setattr(os, "fchown", lambda *_a: events.append("fchown"))
    monkeypatch.setattr(limiter, "pid_alive", lambda _pid: False)
    assert daemon._reset(_reset_args("galaxus"), home) == 0
    # every write was handed back to the broker before the lock was released;
    # the warning's read wrote nothing (the leftover mark is not recovered)
    assert events == ["save", "chown", "fchown"]
    assert "inflight" in _state(home / "limiter.json")["group:gx"]


def test_b4_start_time_is_locale_and_tz_independent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict = {}

    def run(argv: list, **kw: Any) -> Any:
        del argv
        seen.update(kw)
        return SimpleNamespace(stdout="Thu Oct  9 21:00:00 2026\n")

    monkeypatch.setattr(limiter.subprocess, "run", run)
    assert limiter.proc_start(1) == "Thu Oct  9 21:00:00 2026"
    assert seen["env"]["LC_ALL"] == "C" and seen["env"]["TZ"] == "UTC"


def test_b5_profile_proof_and_candidate_codes_are_known() -> None:
    assert "profile-proof" in phases.PHASES
    assert "candidate_unverifiable" in phases.CODE_TEXT
    assert not phases.post_submit("profile-proof", None)
    assert not phases.post_submit("profile-proof", False)


def test_selector_ok_is_plain_css_only() -> None:
    for bad in ("text=Hi", "a >> b", "xpath=//a", 'a:has-text("x")', "//div"):
        assert not vault.selector_ok(bad), bad
    assert not vault.selector_ok("#a:visible")
    for good in ("#me", '[data-testid="x"]', "html.a:not(:has(form input))", ".a .b"):
        assert vault.selector_ok(good), good
    item = vault.site_item_from_json(_raw({"agent_logged_in_selector": "text=Hi"}))
    assert item.refused and "agent_logged_in_selector" in item.refused


def test_sentinel_absent_is_throttled_and_refuses_refused_items(
    tmp_path: Path,
) -> None:
    class _Probe(_Runner):
        def sentinel_absent(self, item: Any, sentinel: str) -> dict[str, Any]:
            del item, sentinel
            return {"loaded": True, "status": 200, "present": False}

    refused = vault.site_item_from_json(_raw({"agent_fill_origins": "ftp://x"}))
    assert refused.refused
    brk = _broker(tmp_path, _lim(tmp_path / "l.json"), _Probe(), [_shop()])
    req = {"op": "sentinel_absent", "site": "shop", "sentinel": "#me"}
    with brk._probe_slot:  # another check running
        assert brk.handle(req)["error"] == "busy"
    with brk._site_lock("shop"):  # a login of the site running
        assert brk.handle(req)["error"] == "busy"
    assert brk.handle(req)["ok"]
    brk2 = _broker(tmp_path, _lim(tmp_path / "l.json"), _Probe(), [refused])
    assert brk2.handle({**req, "site": refused.site})["error"] == "refused"


def test_a_failed_finish_keeps_the_bundle_and_frees_the_site(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = tmp_path / "l.json"
    lim = _lim(state)
    brk = _broker(tmp_path, lim, _Runner())
    real = lim._update_attempt

    def flaky(grant: Any, fn: Any) -> None:
        if fn.__name__ == "done":
            raise OSError("disk full")
        real(grant, fn)

    monkeypatch.setattr(lim, "_update_attempt", flaky)
    resp = brk._do_login("shop")
    assert resp["ok"] and resp["bundle"]  # the login's result is kept
    monkeypatch.setattr(lim, "_update_attempt", real)
    # our own mark is recovered with the intended outcome: not "busy"
    assert lim.peek(["shop"], 20.0) is None
    entry = _state(state)["shop"]
    assert "inflight" not in entry and entry["attempts"][-1][1] == "ok"


def test_login_audit_carries_the_outcome(tmp_path: Path) -> None:
    brk = _broker(tmp_path, _lim(tmp_path / "l.json"), _Runner())
    brk.handle({"op": "login", "site": "shop", "scheduled": True})
    line = (tmp_path / "home" / "audit.log").read_text().splitlines()[-1]
    rec = json.loads(line)
    assert rec["scheduled"] is True and rec["candidate"] is False
    assert rec["phase"] == "ok" and rec["fresh_auth"] is True


def test_reset_with_a_symlinked_lock_fails_cleanly(tmp_path: Path) -> None:
    (tmp_path / "elsewhere").write_text("")
    os.symlink(tmp_path / "elsewhere", tmp_path / "limiter.json.lock")
    assert daemon._reset(_reset_args("shop"), tmp_path) == 1
