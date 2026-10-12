"""WS3 removal, broker side: the ``forget`` op of the live daemon and
``Limiter.prune_site``.

Hermetic: the real ``daemon.Broker`` with a fake vault whose items change
between calls, a throwaway home and limiter; no socket, no Chrome. Usernames
and passwords are generated per run.
"""

from __future__ import annotations

# pylint: disable=missing-function-docstring,import-error,wrong-import-position
# pylint: disable=protected-access,too-few-public-methods
import json
import os
import sys
import threading
import time
from pathlib import Path
from typing import Any

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from broker import daemon, limiter, vault  # noqa: E402
from broker.identity_ops import IdentityGuard  # noqa: E402

sys.path.insert(0, str(REPO / "tests"))
from ws3_fixtures import raw_item  # noqa: E402  # pylint: disable=wrong-import-order


def _raw(site: str, host: str, **fields: str) -> dict:
    return raw_item(site, host, **fields)


class _Vault:
    """The vault the daemon reads; `fail` makes the next read raise."""

    def __init__(self, raws: list[dict]) -> None:
        self.raws = raws
        self.fail = False
        self.reads = 0

    def items(self) -> list[vault.SiteItem]:
        self.reads += 1
        if self.fail:
            raise vault.VaultError("Bitwarden unreadable")
        return vault.build_items(self.raws)


class _Runner:
    def __init__(self, diag_dir: Path) -> None:
        self.diag_dir = diag_dir
        self.last_diag: dict[str, Any] = {}
        self.proof_reasons: dict[str, str] = {}
        self.calls = 0

    def __call__(self, item: Any, get_secret: Any) -> dict[str, Any]:
        self.calls += 1
        raise AssertionError("no login in these tests")


def _broker(
    tmp_path: Path, raws: list[dict]
) -> tuple[Any, _Vault, limiter.Limiter, _Runner]:
    vlt = _Vault(raws)
    lim = limiter.Limiter(
        tmp_path / "home" / "limiter.json",
        cooldown_s=1800,
        min_interval_s=0,
        per_hour=50,
        per_day=100,
    )
    runner = _Runner(tmp_path / "run")
    (tmp_path / "run").mkdir()
    brk = daemon.Broker(vlt, lim, tmp_path / "home", runner=runner)  # type: ignore[arg-type]
    return brk, vlt, lim, runner


def _seed(tmp_path: Path, lim: limiter.Limiter, site: str, groups: list[str]) -> None:
    """A site that logged in before: limiter entry + bindings, a profile, a
    failure screenshot, an identity-guard entry."""
    data = {"sites": {site: {"attempts": [[time.time(), "ok"]], "groups": groups}}}
    for g in groups:
        data["sites"][f"group:{g}"] = {"attempts": [[time.time(), "ok"]]}
    lim.state_path.parent.mkdir(parents=True, exist_ok=True)
    lim.state_path.write_text(json.dumps(data), encoding="utf-8")
    profile = tmp_path / "home" / "profiles" / site
    profile.mkdir(parents=True)
    (profile / "Cookies").write_text("x", encoding="utf-8")
    (tmp_path / "run" / f"last-failure-{site}.png").write_bytes(b"\x89PNG")
    guard = IdentityGuard(tmp_path / "home")
    guard.record_mismatch(site, time.time() - 30 * 86400.0)  # long over: prunable


def _forget(brk: Any, site: str) -> dict:
    resp: dict = brk.handle({"op": "forget", "site": site}, 501, os.getpid())
    return resp


def test_forget_refuses_while_the_site_is_listed(tmp_path: Path) -> None:
    brk, _vlt, lim, _r = _broker(tmp_path, [_raw("gone", "gone.example")])
    _seed(tmp_path, lim, "gone", [])
    resp = _forget(brk, "gone")
    assert resp["ok"] is False and resp["error"] == "still_listed"
    assert (tmp_path / "home" / "profiles" / "gone").exists()  # nothing touched
    assert "gone" in json.loads(lim.state_path.read_text(encoding="utf-8"))["sites"]


def test_forget_refuses_a_listed_refused_item_too(tmp_path: Path) -> None:
    bad = _raw("gone", "gone.example", fresh_login="maybe")  # refused by the vault
    brk, _vlt, _lim, _r = _broker(tmp_path, [bad])
    assert brk._items()[0].refused
    assert _forget(brk, "gone")["error"] == "still_listed"


def test_forget_refuses_an_unreadable_vault(tmp_path: Path) -> None:
    brk, vlt, lim, _r = _broker(tmp_path, [_raw("kept", "kept.example")])
    _seed(tmp_path, lim, "gone", [])
    vlt.fail = True
    resp = _forget(brk, "gone")
    assert resp["ok"] is False and resp["error"] == "vault_error"
    assert (tmp_path / "home" / "profiles" / "gone").exists()


def test_forget_drops_every_broker_trace_and_is_idempotent(tmp_path: Path) -> None:
    brk, _vlt, lim, runner = _broker(tmp_path, [_raw("kept", "kept.example")])
    _seed(tmp_path, lim, "gone", ["orphan"])
    runner.last_diag["gone"] = {"x": 1}
    resp = _forget(brk, "gone")
    assert resp["ok"] is True
    assert resp["limiter"] is True and resp["groups"] == 1
    assert (
        resp["guard"] is True and resp["profile"] is True and resp["screenshot"] is True
    )
    sites = json.loads(lim.state_path.read_text(encoding="utf-8"))["sites"]
    assert "gone" not in sites and "group:orphan" not in sites
    assert not (tmp_path / "home" / "profiles" / "gone").exists()
    assert not (tmp_path / "run" / "last-failure-gone.png").exists()
    assert "gone" not in runner.last_diag
    assert IdentityGuard(tmp_path / "home").denial("gone", time.time()) is None
    again = _forget(brk, "gone")
    assert again["ok"] is True and not any(
        again[k] for k in ("limiter", "groups", "guard", "profile", "screenshot")
    )
    audit = [
        json.loads(x)
        for x in (tmp_path / "home" / "audit.log")
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    forgets = [a for a in audit if a["op"] == "forget"]
    assert len(forgets) == 2 and forgets[0]["result"] == "ok"
    assert set(forgets[0]) >= {"limiter", "groups", "guard", "profile", "screenshot"}


def test_a_group_a_remaining_item_declares_or_binds_is_kept(tmp_path: Path) -> None:
    brk, _vlt, lim, _r = _broker(
        tmp_path, [_raw("sister", "sister.example", attempt_group="declared")]
    )
    _seed(tmp_path, lim, "gone", ["declared", "bound", "orphan"])
    data = json.loads(lim.state_path.read_text(encoding="utf-8"))
    data["sites"]["other"] = {"attempts": [], "groups": ["bound"]}
    lim.state_path.write_text(json.dumps(data), encoding="utf-8")
    resp = _forget(brk, "gone")
    assert resp["ok"] and resp["groups"] == 1
    sites = json.loads(lim.state_path.read_text(encoding="utf-8"))["sites"]
    assert "group:declared" in sites and "group:bound" in sites
    assert "group:orphan" not in sites and "gone" not in sites


def test_forget_refuses_a_live_in_flight_mark(tmp_path: Path) -> None:
    brk, _vlt, lim, _r = _broker(tmp_path, [_raw("kept", "kept.example")])
    _seed(tmp_path, lim, "gone", ["g"])
    data = json.loads(lim.state_path.read_text(encoding="utf-8"))
    mark = {
        "id": "x",
        "ts": time.time(),
        "state": "submitted",
        "instance": "other",
        "pid": os.getpid(),
        "pid_start": limiter.proc_start(os.getpid()),
    }
    data["sites"]["group:g"]["inflight"] = mark
    lim.state_path.write_text(json.dumps(data), encoding="utf-8")
    resp = _forget(brk, "gone")
    assert resp["ok"] is False and resp["error"] == "busy"
    assert "gone" in json.loads(lim.state_path.read_text(encoding="utf-8"))["sites"]


def test_forget_never_follows_a_symlink(tmp_path: Path) -> None:
    brk, _vlt, lim, _r = _broker(tmp_path, [_raw("kept", "kept.example")])
    _seed(tmp_path, lim, "gone", [])
    target = tmp_path / "elsewhere"
    target.mkdir()
    (target / "keep").write_text("x", encoding="utf-8")
    profile = tmp_path / "home" / "profiles" / "gone"
    for child in profile.iterdir():
        child.unlink()
    profile.rmdir()
    profile.symlink_to(target)
    shot = tmp_path / "run" / "last-failure-gone.png"
    shot.unlink()
    shot.mkdir()  # not a regular file
    resp = _forget(brk, "gone")
    assert resp["ok"] is False and resp["error"] == "forget_incomplete"
    assert resp["limiter"] is True  # the rest still happened
    assert (target / "keep").exists() and profile.is_symlink() and shot.is_dir()


def test_after_forget_a_login_of_the_site_is_unknown(tmp_path: Path) -> None:
    kept = [_raw("kept", "kept.example")]
    brk, vlt, _lim, runner = _broker(tmp_path, [_raw("gone", "gone.example"), *kept])
    assert brk._items()  # the daemon caches the item (SITES_TTL_S)
    vlt.raws = kept  # Albert removes it from the vault
    assert _forget(brk, "gone")["ok"] is True
    resp = brk.handle({"op": "login", "site": "gone"}, 501, os.getpid())
    assert resp["ok"] is False and resp["error"] == "unknown_site"
    assert runner.calls == 0


def _limiter_sites(lim: limiter.Limiter) -> dict:
    sites: dict = json.loads(lim.state_path.read_text(encoding="utf-8"))["sites"]
    return sites


@pytest.mark.parametrize(
    ("entry", "state"),
    [
        ({"blocked": True, "consecutive": 3}, "locked"),
        # far in the future: parametrize runs at collection, long before the
        # test when the whole suite runs
        ({"cooldown_until": time.time() + 30 * 86400}, "cooldown"),
        ({"consecutive": 1}, "quarantined"),
    ],
)
def test_forget_never_lifts_a_limiter_block(
    tmp_path: Path, entry: dict, state: str
) -> None:
    """S1: no limiter bypass — a blocked key stays for `install.sh -r`."""
    brk, _vlt, lim, _r = _broker(tmp_path, [_raw("kept", "kept.example")])
    _seed(tmp_path, lim, "gone", ["g"])
    data = _limiter_sites(lim)
    data["gone"].update(entry)
    lim.state_path.write_text(json.dumps({"sites": data}), encoding="utf-8")
    resp = _forget(brk, "gone")
    assert resp["ok"] is True and resp["limiter"] is False
    assert resp["left"] == {"gone": state}
    sites = _limiter_sites(lim)
    assert sites["gone"]["groups"] == ["g"] and "group:g" in sites  # bindings kept
    assert not (tmp_path / "home" / "profiles" / "gone").exists()  # the rest went


def test_forget_never_lifts_a_blocked_group_key(tmp_path: Path) -> None:
    brk, _vlt, lim, _r = _broker(tmp_path, [_raw("kept", "kept.example")])
    _seed(tmp_path, lim, "gone", ["g"])
    data = _limiter_sites(lim)
    data["group:g"]["cooldown_until"] = time.time() + 600
    lim.state_path.write_text(json.dumps({"sites": data}), encoding="utf-8")
    resp = _forget(brk, "gone")
    assert resp["left"] == {"group:g": "cooldown"} and resp["limiter"] is True
    assert "group:g" in _limiter_sites(lim)


def test_forget_never_lifts_an_identity_lockout(tmp_path: Path) -> None:
    brk, _vlt, lim, _r = _broker(tmp_path, [_raw("kept", "kept.example")])
    _seed(tmp_path, lim, "gone", [])
    IdentityGuard(tmp_path / "home").record_mismatch("gone", time.time())  # 1 h
    resp = _forget(brk, "gone")
    assert resp["guard"] is False and resp["left"] == {
        "identity-guard": "identity_cooldown"
    }
    assert IdentityGuard(tmp_path / "home").denial("gone", time.time()) is not None


def test_forget_refuses_an_empty_or_shrunken_vault_read(tmp_path: Path) -> None:
    raws = [_raw(f"s{i}", f"s{i}.example") for i in range(6)]
    brk, vlt, lim, _r = _broker(tmp_path, raws)
    _seed(tmp_path, lim, "gone", [])
    vlt.raws = []
    assert _forget(brk, "gone")["error"] == "vault_suspect"
    assert brk._items(fresh=False) == []  # (the read replaced the cache)
    vlt.raws = raws
    brk._items(fresh=True)
    vlt.raws = raws[:2]  # 2 of 6: less than half
    assert _forget(brk, "gone")["error"] == "vault_suspect"
    vlt.raws = raws
    brk._items(fresh=True)
    vlt.raws = raws[:3]  # exactly half: fine
    assert _forget(brk, "gone")["ok"] is True


def test_a_refused_item_resolving_to_the_site_counts_as_listed(tmp_path: Path) -> None:
    # an item whose agent_site is malformed falls back to nothing usable,
    # but its NAME slugs to the site id: still listed
    named = _raw("gone", "gone.example")
    named["fields"][0]["value"] = "Not A Slug!"  # agent_site, malformed
    named["name"] = "Gone"
    brk, _vlt, lim, _r = _broker(tmp_path, [named, _raw("kept", "kept.example")])
    _seed(tmp_path, lim, "gone", [])
    assert any(it.refused for it in brk._items())
    assert _forget(brk, "gone")["error"] == "still_listed"


def test_a_refused_items_attempt_group_is_kept(tmp_path: Path) -> None:
    sister = _raw(
        "sister", "sister.example", attempt_group="shared", fresh_login="maybe"
    )
    brk, _vlt, lim, _r = _broker(tmp_path, [sister, _raw("kept", "kept.example")])
    items = {it.site: it for it in brk._items()}
    assert items["sister"].refused and items["sister"].attempt_group == "shared"
    _seed(tmp_path, lim, "gone", ["shared"])
    assert _forget(brk, "gone")["ok"] is True
    assert "group:shared" in _limiter_sites(lim)


def test_forget_waits_for_a_running_login_of_the_site(tmp_path: Path) -> None:
    brk, _vlt, _lim, _r = _broker(tmp_path, [_raw("kept", "kept.example")])
    lock = brk._site_lock("gone")
    order: list[str] = []
    lock.acquire()  # pylint: disable=consider-using-with

    def forget() -> None:
        _forget(brk, "gone")
        order.append("forget")

    worker = threading.Thread(target=forget)
    worker.start()
    time.sleep(0.2)
    order.append("login done")
    lock.release()
    worker.join(5)
    assert order == ["login done", "forget"]


def test_prune_site_keeps_a_corrupt_state_untouched(tmp_path: Path) -> None:
    lim = limiter.Limiter(
        tmp_path / "l.json", cooldown_s=1, min_interval_s=0, per_hour=1, per_day=1
    )
    lim.state_path.write_text("{corrupt", encoding="utf-8")
    with pytest.raises(limiter.LimiterStateError):
        lim.prune_site("x")
    assert lim.state_path.read_text(encoding="utf-8") == "{corrupt"
