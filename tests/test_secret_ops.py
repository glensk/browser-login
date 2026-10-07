"""The login broker's secret ops (broker/secret_ops.py) and the leak-check push
(broker/leakcheck.py), hermetic: FixtureVault, fake secretkeeper, temp home.

Every fixture value and TOTP seed is a random sentinel; besides the ``secret``
op's ``values``, no response, audit line or printed output may contain one.

Run: uv run --no-sync pytest tests/test_secret_ops.py
"""

from __future__ import annotations

# pylint: disable=missing-function-docstring,redefined-outer-name,import-error
# pylint: disable=protected-access,wrong-import-position
# `vals` is requested for its fixture side effect (the sentinels).
# pylint: disable=unused-argument
import json
import os
import re
import socket
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import secret_fixtures as sf  # noqa: E402

from broker import daemon, leakcheck, limiter, runs, vault  # noqa: E402

UID = 501


class Vals:
    """The random sentinels of one test."""

    def __init__(self) -> None:
        self.pw = sf.sentinel()
        self.token = sf.sentinel()
        self.user = sf.sentinel()
        self.other = sf.sentinel()
        self.seed = sf.totp_seed()
        self.short = "Ab3$xY7"  # 7 bytes: needs agent_secret_allow_short
        self.tiny = "Ab3$x"  # 5 bytes: always refused

    def all(self) -> list[str]:
        return [self.pw, self.token, self.user, self.other, self.seed]


@pytest.fixture
def vals() -> Vals:
    return Vals()


def _items(v: Vals) -> list[dict]:
    return [
        sf.secret_item(
            "GitHub",
            v.pw,
            username=v.user,
            fields={"agent_secret_fields": "username,api_token", "api_token": v.token},
            totp=v.seed,
        ),
        sf.secret_item("Plain", v.other),
        sf.secret_item("Short", v.short, fields={"agent_secret_allow_short": "true"}),
        sf.secret_item("Shortrefused", v.short),
        sf.secret_item("Tiny", v.tiny, fields={"agent_secret_allow_short": "true"}),
        sf.secret_item("Seven", sf.sentinel()[:9]),
        sf.secret_item(
            "Listed", v.other, fields={"agent_secret_fields": "missing_field"}
        ),
        sf.secret_item("Dup", v.other, fields={"a": "1"}),
    ]


class CountingVault(vault.FixtureVault):
    """FixtureVault that counts secret reads."""

    def __init__(self, *a, **kw) -> None:
        super().__init__(*a, **kw)
        self.calls = 0

    def secret_items(self) -> list[vault.SecretItem]:
        self.calls += 1
        return super().secret_items()

    def secret_values(self, secret_id: str) -> vault.SecretValues:
        self.calls += 1
        return super().secret_values(secret_id)


@pytest.fixture
def env(tmp_path, vals):
    """(broker, keeper, home, vault) with a fake secretkeeper."""
    with sf.sockdir() as d:
        keeper = sf.FakeSecretkeeper(str(d / "keeper.sock"))
        home = tmp_path / "home"
        vpath = sf.write_vault(tmp_path / "v.json", _items(vals))
        brk = sf.make_broker(home, vpath, allow_uid=UID, keeper_sock=keeper.path)
        brk.vault = CountingVault(vpath, dev=True)
        try:
            yield brk, keeper, home
        finally:
            keeper.close()


def _secret(brk, items, *, uid=UID, env_names=("X",), argv0="/opt/bin/kubectl"):
    req = {
        "op": "secret",
        "items": [{"item": i, "field": f} for i, f in items],
        "env": list(env_names),
        "argv0": argv0,
    }
    return brk.handle(req, uid)


def _assert_clean(text: str, v: Vals) -> None:
    for value in v.all():
        assert value not in text


def _audit(home: Path) -> str:
    return (home / "audit.log").read_text()


# ---------------------------------------------------------------------------
# uid gate
# ---------------------------------------------------------------------------

ALL_OPS = [
    {"op": "secrets"},
    {"op": "secret", "items": [{"item": "github", "field": "password"}]},
    {"op": "totp", "item": "github"},
    {"op": "secret_done", "nonce": "0" * 64, "exit": 0, "masked": 0},
    {"op": "audit", "n": 5},
    {"op": "invalidate"},
]


@pytest.mark.parametrize("uid", [None, 0, UID + 1])
def test_wrong_uid_is_forbidden_without_vault_calls(env, uid):
    brk, keeper, _home = env
    for req in ALL_OPS:
        assert brk.handle(req, uid) == {"ok": False, "error": "forbidden", "detail": ""}
    assert brk.vault.calls == 0
    assert keeper.syncs == []


def test_broker_without_allow_uid_serves_no_secret_op(tmp_path, vals):
    vpath = sf.write_vault(tmp_path / "v.json", _items(vals))
    brk = sf.make_broker(tmp_path / "h", vpath, allow_uid=None, keeper_sock=None)
    assert brk.handle({"op": "secrets"}, UID)["error"] == "forbidden"


# ---------------------------------------------------------------------------
# secrets / secret
# ---------------------------------------------------------------------------


def test_secrets_lists_names_only(env, vals):
    brk, _keeper, home = env
    resp = brk.handle({"op": "secrets"}, UID)
    text = json.dumps(resp)
    _assert_clean(text, vals)
    rows = {r["id"]: r for r in resp["secrets"]}
    assert rows["github"]["fields"] == ["password", "username", "api_token"]
    assert rows["github"]["has_totp"] is True
    assert rows["plain"]["fields"] == ["password"] and not rows["plain"]["has_totp"]
    assert rows["short"]["short"] is True
    assert rows["shortrefused"]["refused"] is True
    assert "too short" in rows["shortrefused"]["reason"]
    _assert_clean(_audit(home), vals)


def test_secret_returns_values_and_registers_them(env, vals):
    brk, keeper, home = env
    resp = _secret(brk, [("github", "password"), ("github", "api_token")])
    assert resp["ok"] is True
    assert resp["values"] == [vals.pw, vals.token]
    assert re.fullmatch(r"[0-9a-f]{64}", resp["nonce"])
    assert resp["variants_policy"] >= 1
    assert "short" not in resp
    sync = keeper.syncs[-1]
    assert sync["replace"] is False
    assert {s["label"] for s in sync["secrets"]} == {
        "loginbroker:github:password",
        "loginbroker:github:api_token",
    }
    assert {s["value"] for s in sync["secrets"]} == {vals.pw, vals.token}
    audit = _audit(home)
    _assert_clean(audit, vals)
    rec = json.loads(audit.splitlines()[-1])
    assert rec["op"] == "secret" and rec["result"] == "ok"
    assert rec["items"] == ["github:password", "github:api_token"]
    assert rec["env"] == ["X"] and rec["argv0"] == "kubectl"
    assert rec["nonce"] == resp["nonce"][:8]
    labels = json.loads((home / "leakcheck-labels.json").read_text())["labels"]
    assert ["github", "password"] in labels
    assert oct((home / "leakcheck-labels.json").stat().st_mode & 0o777) == "0o600"


def test_secret_errors_carry_no_value(env, vals):
    brk, _keeper, home = env
    cases = {
        "unknown_item": [("nope", "password")],
        "unknown_field": [("plain", "username")],
        "refused": [("shortrefused", "password")],
    }
    for code, items in cases.items():
        resp = _secret(brk, items)
        assert resp["error"] == code, (code, resp)
        _assert_clean(json.dumps(resp), vals)
    listed = _secret(brk, [("listed", "missing_field")])
    assert listed["error"] == "unknown_field" and "empty" in listed["detail"]
    for bad in (
        {"op": "secret", "items": []},
        {"op": "secret", "items": [{"item": "../x"}]},
        {"op": "secret", "items": [{"item": "plain"}], "env": ["lower"]},
        {"op": "secret", "items": [{"item": "plain", "field": "a\nb"}]},
    ):
        assert brk.handle(bad, UID)["error"] == "bad_request"
    _assert_clean(_audit(home), vals)


def test_no_secrets_collection_is_refused(tmp_path, vals):
    vpath = tmp_path / "v.json"
    vpath.write_text(json.dumps([]))  # the old list format: logins only
    brk = sf.make_broker(tmp_path / "h", vpath, allow_uid=UID, keeper_sock=None)
    for req in ({"op": "secrets"}, ALL_OPS[1], ALL_OPS[2]):
        resp = brk.handle(req, UID)
        assert resp == {
            "ok": False,
            "error": "refused",
            "detail": "no secrets collection configured",
        }


def test_short_values(env, vals):
    brk, keeper, _home = env
    resp = _secret(brk, [("short", "password")])
    assert resp["ok"] and resp["short"] is True and resp["short_values"] == [True]
    assert keeper.syncs[-1]["secrets"][0]["raw_only"] is True
    tiny = _secret(brk, [("tiny", "password")])
    assert tiny["error"] == "refused" and "too short" in tiny["detail"]
    long = _secret(brk, [("plain", "password")])
    assert long["ok"] and "raw_only" not in keeper.syncs[-1]["secrets"][0]


def test_totp_gives_the_code_never_the_seed(env, vals):
    brk, keeper, home = env
    resp = brk.handle({"op": "totp", "item": "github"}, UID)
    assert resp["ok"] is True and re.fullmatch(r"\d{6}", resp["code"])
    assert 0 < resp["valid_s"] <= 30
    _assert_clean(json.dumps(resp), vals)
    assert brk.handle({"op": "totp", "item": "plain"}, UID)["error"] == "unknown_field"
    assert brk.handle({"op": "totp", "item": "nope"}, UID)["error"] == "unknown_item"
    assert keeper.syncs == []  # a code is not a registered value
    _assert_clean(_audit(home), vals)


def test_secret_done_closes_once(env, vals):
    brk, _keeper, home = env
    nonce = _secret(brk, [("plain", "password")])["nonce"]
    done = {"op": "secret_done", "nonce": nonce, "exit": 3, "masked": 2}
    assert brk.handle(done, UID) == {"ok": True}
    again = brk.handle(done, UID)
    assert again["error"] == "forbidden"
    unknown = brk.handle({**done, "nonce": "f" * 64}, UID)
    assert unknown["error"] == "forbidden"
    assert brk.handle({**done, "nonce": "xyz"}, UID)["error"] == "bad_request"
    recs = [json.loads(line) for line in _audit(home).splitlines()]
    closed = [r for r in recs if r["op"] == "secret_done" and r["result"] == "ok"]
    assert closed[0]["exit"] == 3 and closed[0]["masked"] == 2
    assert closed[0]["nonce"] == nonce[:8] and nonce not in _audit(home)


def test_audit_op_returns_secret_free_lines(env, vals):
    brk, _keeper, _home = env
    _secret(brk, [("github", "password")])
    brk.handle({"op": "totp", "item": "github"}, UID)
    brk.handle({"op": "secrets"}, UID)
    resp = brk.handle({"op": "audit", "n": 3}, UID)
    assert resp["ok"] and len(resp["lines"]) == 3
    _assert_clean(json.dumps(resp), vals)
    assert brk.handle({"op": "audit", "n": 0}, UID)["error"] == "bad_request"


def test_invalidate_serves_rotated_value(env, vals, tmp_path):
    brk, _keeper, _home = env
    assert _secret(brk, [("plain", "password")])["values"] == [vals.other]
    rotated = sf.sentinel()
    items = _items(vals)
    items[1] = sf.secret_item("Plain", rotated)
    sf.write_vault(tmp_path / "v.json", items)
    assert _secret(brk, [("plain", "password")])["values"] == [vals.other]  # cached
    gen = brk.handle({"op": "invalidate"}, UID)
    assert gen["ok"] and gen["generation"] >= 1
    for _ in range(3):
        assert _secret(brk, [("plain", "password")])["values"] == [rotated]


def test_rate_limits(tmp_path, vals):
    with sf.sockdir() as d:
        keeper = sf.FakeSecretkeeper(str(d / "k.sock"))
        home = tmp_path / "h"
        lim = limiter.Limiter(
            home / "secret-limiter.json",
            0,
            2,
            100,
            key_caps={"secret:*": (3, 0), "secret:": (2, 0), "totp:": (1, 0)},
        )
        vpath = sf.write_vault(tmp_path / "v.json", _items(vals))
        brk = sf.make_broker(
            home, vpath, allow_uid=UID, keeper_sock=keeper.path, secret_limiter=lim
        )
        try:
            assert _secret(brk, [("plain", "password")])["ok"]
            assert _secret(brk, [("plain", "password")])["ok"]
            third = _secret(brk, [("plain", "password")])
            assert (
                third["error"] == "rate_limited" and "secret:plain" in third["detail"]
            )
            assert _secret(brk, [("github", "password")])["ok"]  # global: 3rd
            glob = _secret(brk, [("seven", "password")])
            assert glob["error"] == "rate_limited" and "secret:*" in glob["detail"]
            assert brk.handle({"op": "totp", "item": "github"}, UID)["error"] == (
                "rate_limited"
            )
        finally:
            keeper.close()


def test_default_secret_limits_match_q3(tmp_path):
    lim = daemon.build_secret_limiter(tmp_path)
    assert lim.state_path == tmp_path / "secret-limiter.json"
    assert lim.caps_for("secret:github") == (120, 1000)
    assert lim.caps_for("totp:github") == (20, 0)
    assert lim.caps_for("secret:*") == (600, 0)


# ---------------------------------------------------------------------------
# leak check (A8)
# ---------------------------------------------------------------------------


def test_secretkeeper_down_fails_closed(tmp_path, vals):
    vpath = sf.write_vault(tmp_path / "v.json", _items(vals))
    with sf.sockdir() as d:
        brk = sf.make_broker(
            tmp_path / "h", vpath, allow_uid=UID, keeper_sock=str(d / "absent.sock")
        )
        resp = _secret(brk, [("plain", "password")])
    assert resp["error"] == "leakcheck_unavailable" and "values" not in resp
    _assert_clean(json.dumps(resp), vals)
    _assert_clean(_audit(tmp_path / "h"), vals)


def test_unwired_broker_fails_closed(tmp_path, vals):
    vpath = sf.write_vault(tmp_path / "v.json", _items(vals))
    brk = sf.make_broker(tmp_path / "h", vpath, allow_uid=UID, keeper_sock=None)
    assert _secret(brk, [("plain", "password")])["error"] == "leakcheck_unavailable"


def test_refused_or_unaccepted_sync_fails_closed(tmp_path, vals):
    vpath = sf.write_vault(tmp_path / "v.json", _items(vals))
    with sf.sockdir() as d:
        keeper = sf.FakeSecretkeeper(str(d / "k.sock"), refuse=True)
        brk = sf.make_broker(
            tmp_path / "h", vpath, allow_uid=UID, keeper_sock=keeper.path
        )
        try:
            assert _secret(brk, [("plain", "password")])["error"] == (
                "leakcheck_unavailable"
            )
            keeper.refuse = False
            # A value the secretkeeper drops (here: a short one sent without
            # raw_only) must fail closed too.
            reg = leakcheck.LeakCheck(keeper.path, tmp_path / "labels.json")
            with pytest.raises(leakcheck.LeakCheckUnavailable) as exc:
                with_raw_only_off(reg, [("x", "password", "short1")])
            assert "loginbroker:x:password" in str(exc.value)
            assert "short1" not in str(exc.value)
        finally:
            keeper.close()


def with_raw_only_off(reg: leakcheck.LeakCheck, entries) -> None:
    """register() with the raw_only marking disabled (models a dropped label)."""
    old = leakcheck.RAW_ONLY_BELOW_BYTES
    leakcheck.RAW_ONLY_BELOW_BYTES = 0
    try:
        reg.register(entries)
    finally:
        leakcheck.RAW_ONLY_BELOW_BYTES = old


def test_old_secretkeeper_without_accepted_is_ok(tmp_path, vals):
    vpath = sf.write_vault(tmp_path / "v.json", _items(vals))
    with sf.sockdir() as d:
        keeper = sf.FakeSecretkeeper(str(d / "k.sock"), accepted=False)
        brk = sf.make_broker(
            tmp_path / "h", vpath, allow_uid=UID, keeper_sock=keeper.path
        )
        try:
            assert _secret(brk, [("plain", "password")])["ok"] is True
        finally:
            keeper.close()


def test_refresh_repushes_after_secretkeeper_restart(env, vals):
    brk, keeper, _home = env
    assert _secret(brk, [("github", "password"), ("plain", "password")])["ok"]
    syncs = len(keeper.syncs)
    assert brk.refresh_leakcheck() == 0  # namespaces count matches: no push
    assert len(keeper.syncs) == syncs
    keeper.restart()
    assert brk.refresh_leakcheck() == 2
    pushed = keeper.syncs[-1]
    assert pushed["replace"] is False
    assert {s["label"] for s in pushed["secrets"]} == {
        "loginbroker:github:password",
        "loginbroker:plain:password",
    }
    assert set(keeper.labels) == {
        "loginbroker:github:password",
        "loginbroker:plain:password",
    }
    assert "inventory" not in keeper.ops  # the broker's uid may not use it


def test_refresh_without_namespaces_pushes_unconditionally(tmp_path, vals):
    vpath = sf.write_vault(tmp_path / "v.json", _items(vals))
    with sf.sockdir() as d:
        keeper = sf.FakeSecretkeeper(str(d / "k.sock"), namespaces=False)
        brk = sf.make_broker(
            tmp_path / "h", vpath, allow_uid=UID, keeper_sock=keeper.path
        )
        try:
            assert _secret(brk, [("plain", "password")])["ok"]
            assert brk.refresh_leakcheck() == 1
            assert brk.refresh_leakcheck() == 1
        finally:
            keeper.close()


def test_refresh_drops_labels_of_removed_items(env, vals, tmp_path):
    brk, keeper, home = env
    assert _secret(brk, [("plain", "password"), ("github", "password")])["ok"]
    items = [i for i in _items(vals) if i["name"] != "Plain"]
    sf.write_vault(tmp_path / "v.json", items)
    brk.handle({"op": "invalidate"}, UID)
    keeper.restart()
    assert brk.refresh_leakcheck() == 1
    labels = json.loads((home / "leakcheck-labels.json").read_text())["labels"]
    assert labels == [["github", "password"]]


def test_refresh_failure_is_audited_by_label_only(env, vals):
    brk, keeper, home = env
    assert _secret(brk, [("plain", "password")])["ok"]
    keeper.close()
    assert brk.refresh_leakcheck() == 0
    rec = json.loads(_audit(home).splitlines()[-1])
    assert rec["op"] == "leakcheck_refresh"
    assert rec["result"] == "leakcheck_unavailable"
    _assert_clean(_audit(home), vals)


# ---------------------------------------------------------------------------
# socket, CLI
# ---------------------------------------------------------------------------


def _ask(path: str, obj: dict) -> dict:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(30)
        s.connect(path)
        s.sendall(json.dumps(obj).encode() + b"\n")
        with s.makefile("rb") as fh:
            resp = json.loads(fh.readline())
    assert isinstance(resp, dict)
    return resp


def test_over_the_socket_peer_uid_gates(tmp_path, vals):
    vpath = sf.write_vault(tmp_path / "v.json", _items(vals))
    with sf.sockdir() as d:
        keeper = sf.FakeSecretkeeper(str(d / "k.sock"))
        me = os.getuid()
        try:
            brk = sf.make_broker(
                tmp_path / "a", vpath, allow_uid=me, keeper_sock=keeper.path
            )
            with sf.serving(brk, str(d / "a.sock"), me) as path:
                ok = _ask(path, {"op": "secret", "items": [{"item": "plain"}]})
                assert ok["values"] == [vals.other]
            brk2 = sf.make_broker(
                tmp_path / "b", vpath, allow_uid=me + 1, keeper_sock=keeper.path
            )
            with sf.serving(brk2, str(d / "b.sock"), me + 1) as path:
                denied = _ask(path, {"op": "secret", "items": [{"item": "plain"}]})
            assert denied == {"ok": False, "error": "forbidden", "detail": ""}
        finally:
            keeper.close()


def test_collections_flag_prints_ids_and_names_only(tmp_path, vals, capsys):
    vpath = sf.write_vault(
        tmp_path / "v.json",
        _items(vals),
        collections=[
            {
                "organizationId": "org-1",
                "organizationName": "Shared",
                "id": "coll-1",
                "name": "agent-secrets",
            },
            {
                "organizationId": "org-2",
                "organizationName": "Agents\tX",
                "id": "coll-2",
                "name": "agent-login",
            },
        ],
    )
    assert daemon.main(["-d", "-f", str(vpath), "-H", str(tmp_path / "h"), "-C"]) == 0
    out = capsys.readouterr().out
    assert out.splitlines() == [
        "org-1\tShared\tcoll-1\tagent-secrets",
        "org-2\tAgents X\tcoll-2\tagent-login",
    ]
    for name in ("GitHub", "Plain", "github"):
        assert name not in out
    _assert_clean(out, vals)


FAKE_BW_COLLECTIONS = r"""#!/usr/bin/env python3
import json, sys
cmd = sys.argv[1]
if cmd == "status":
    print(json.dumps({"status": "locked"}))
elif cmd == "unlock":
    print("SESSIONKEY")
elif cmd == "list" and sys.argv[2] == "organizations":
    print(json.dumps([{"id": "org-1", "name": "Shared"}]))
elif cmd == "list" and sys.argv[2] == "collections":
    print(json.dumps([{"id": "coll-1", "organizationId": "org-1", "name": "agent-secrets"}]))
elif cmd == "list":
    print(json.dumps([{"id": "i", "name": "SECRET-ITEM-NAME"}]))
"""


def test_bw_collections_have_no_item_data(tmp_path):
    fake = tmp_path / "bw"
    fake.write_text(FAKE_BW_COLLECTIONS)
    fake.chmod(0o755)
    boot = vault.BwBootstrap("cid", "csecret", "master-pw", "coll-0")
    v = vault.BwVault(boot, tmp_path / "appdata", bw_bin=str(fake))
    rows = v.collections()
    assert rows == [("org-1", "Shared", "coll-1", "agent-secrets")]
    assert "SECRET-ITEM-NAME" not in json.dumps(rows)


def test_reset_accepts_secret_limiter_keys(tmp_path, capsys):
    home = tmp_path / "h"
    lim = daemon.build_secret_limiter(home)
    lim.reserve(["secret:github", "secret:*"], 0.0)
    assert daemon.main(["-d", "-H", str(home), "-r", "secret:github"]) == 0
    assert (
        "secret:github"
        not in json.loads(lim.state_path.read_text(encoding="utf-8"))["sites"]
    )
    assert daemon.main(["-d", "-H", str(home), "-r", "secret:*"]) == 0
    assert daemon.main(["-d", "-H", str(home), "-r", "bogus:x"]) == 2
    assert "✅" in capsys.readouterr().out


def test_run_rows_expire_with_an_audit_line(env, vals):
    brk, _keeper, home = env
    nonce = _secret(brk, [("plain", "password")])["nonce"]
    brk.runs.ttl_s = 0.0
    brk.handle({"op": "secrets"}, UID)
    recs = [json.loads(line) for line in _audit(home).splitlines()]
    abandoned = [r for r in recs if r["result"] == "abandoned"]
    assert abandoned and abandoned[0]["nonce"] == nonce[:8]
    done = {"op": "secret_done", "nonce": nonce, "exit": 0, "masked": 0}
    assert brk.handle(done, UID)["error"] == "forbidden"
    assert isinstance(brk.runs, runs.RunTable)
