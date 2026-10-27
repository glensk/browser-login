"""tp#1303: service-bound items (``vault.SERVICE_ITEMS``) and the ``service_secret`` op.

Hermetic: FixtureVault, fake secretkeeper, temp home. The bound item is
``mem-service-hmac`` -> ``com.albert.mem-serve`` (the root-installed table).
No response but ``service_secret``'s ``value``, no audit line and no printed
output may carry the sentinel.

Run: uv run --no-sync pytest tests/test_service_secret.py
"""

from __future__ import annotations

# pylint: disable=missing-function-docstring,redefined-outer-name,import-error
# pylint: disable=wrong-import-position
import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import secret_fixtures as sf  # noqa: E402

from broker import secret_ops, vault  # noqa: E402

UID = 501
ITEM = "mem-service-hmac"
SERVICE = "com.albert.mem-serve"


def _bound(value: str, **fields: str) -> dict:
    return sf.secret_item(ITEM, value, fields={"agent_secret_id": ITEM, **fields})


@pytest.fixture
def value() -> str:
    return sf.sentinel()


def _make(tmp_path, items: list[dict], *, gate: str = "agent_script"):
    keeper = sf.FakeSecretkeeper(str(tmp_path / "k.sock"))
    home = tmp_path / "home"
    if gate == "agent_script":
        vpath = sf.write_vault(
            tmp_path / "v.json", [], logins=items, secret_gate="agent_script"
        )
    else:
        vpath = sf.write_vault(tmp_path / "v.json", items)
    brk = sf.make_broker(home, vpath, allow_uid=UID, keeper_sock=keeper.path)
    return brk, keeper, home


@pytest.fixture
def env(value):
    with sf.sockdir() as d:
        other = sf.sentinel()
        brk, keeper, home = _make(
            d,
            [
                _bound(value, agent_script="true"),
                sf.secret_item("Plain", other, fields={"agent_script": "true"}),
            ],
        )
        try:
            yield brk, keeper, home
        finally:
            keeper.close()


def _service(brk, *, item=ITEM, service=SERVICE, uid=UID, pid=None, field="password"):
    req = {"op": "service_secret", "item": item, "field": field, "service": service}
    return brk.handle(req, uid, pid=pid if pid is not None else os.getpid())


def _audit_text(home: Path) -> str:
    return "".join(p.read_text() for p in home.glob("audit*"))


def test_bound_item_refused_by_secret_and_totp(env, value):
    brk, _keeper, home = env
    resp = brk.handle(
        {"op": "secret", "items": [{"item": ITEM}], "env": ["X"], "argv0": "true"},
        UID,
    )
    assert resp["ok"] is False and resp["error"] == "refused"
    assert resp["gate_code"] == "service_only"
    totp = brk.handle({"op": "totp", "item": ITEM}, UID)
    assert totp["ok"] is False and totp["gate_code"] == "service_only"
    assert value not in json.dumps(resp) + json.dumps(totp) + _audit_text(home)


def test_bound_item_hidden_from_listing(env):
    brk, _keeper, _home = env
    resp = brk.handle({"op": "secrets"}, UID)
    ids = [row["id"] for row in resp["secrets"]]
    assert ITEM not in ids and "plain" in ids


def test_service_secret_grants_the_bound_service(env, value):
    brk, keeper, home = env
    resp = _service(brk)
    assert resp == {"ok": True, "value": value}
    assert any(v == value for v, _ in keeper.labels.values())
    lines = [json.loads(x) for x in _audit_text(home).splitlines() if x.strip()]
    grant = [r for r in lines if r["op"] == "service_secret"][-1]
    assert grant["result"] == "ok" and grant["service"] == SERVICE
    assert grant["peer_pid"] == os.getpid() and grant["peer_ppid"] == os.getppid()
    assert grant["items"] == [f"{ITEM}:password"]
    assert value not in _audit_text(home)


def test_service_secret_needs_its_own_service(env, value):
    brk, _keeper, home = env
    wrong = _service(brk, service="com.albert.other")
    assert wrong["ok"] is False and wrong["error"] == "forbidden_service"
    unbound = _service(brk, item="plain")
    assert unbound["ok"] is False and unbound["error"] == "forbidden_service"
    bad = _service(brk, service="Not A Name")
    assert bad["error"] == "bad_request"
    assert value not in json.dumps([wrong, unbound, bad]) + _audit_text(home)


def test_service_secret_other_uid_forbidden(env):
    brk, _keeper, _home = env
    assert _service(brk, uid=UID + 1)["error"] == "forbidden"


def test_service_secret_without_agent_script(value):
    with sf.sockdir() as d:
        brk, keeper, _home = _make(d, [_bound(value)])
        try:
            assert _service(brk) == {"ok": True, "value": value}
            secret = brk.handle(
                {"op": "secret", "items": [{"item": ITEM}], "env": ["X"]}, UID
            )
            assert secret["gate_code"] == "service_only"
        finally:
            keeper.close()


def test_service_secret_refused_while_held(value):
    with sf.sockdir() as d:
        brk, keeper, home = _make(
            d, [_bound(value, agent_hold="20261027T120000Z-abcdef")]
        )
        try:
            resp = _service(brk)
            assert resp["ok"] is False and resp["gate_code"] == "held"
            assert value not in json.dumps(resp) + _audit_text(home)
        finally:
            keeper.close()


def test_service_secret_collections_gate(value):
    with sf.sockdir() as d:
        brk, keeper, _home = _make(d, [_bound(value)], gate="collections")
        try:
            assert _service(brk) == {"ok": True, "value": value}
            ids = [r["id"] for r in brk.handle({"op": "secrets"}, UID)["secrets"]]
            assert ITEM not in ids
        finally:
            keeper.close()


def test_service_secret_rate_limited(env):
    brk, _keeper, _home = env
    for _ in range(secret_ops.SERVICE_PER_HOUR):
        assert _service(brk)["ok"] is True
    assert _service(brk)["error"] == "rate_limited"


def test_service_secret_leakcheck_unavailable(value):
    with sf.sockdir() as d:
        brk, keeper, _home = _make(d, [_bound(value)])
        keeper.close()
        resp = _service(brk)
        assert resp["ok"] is False and resp["error"] == "leakcheck_unavailable"
        assert value not in json.dumps(resp)


def test_table_is_read_only():
    with pytest.raises(TypeError):
        vault.SERVICE_ITEMS["x"] = "y"  # type: ignore[index]
    assert vault.SERVICE_ITEMS == {ITEM: SERVICE}


def test_peer_telemetry_unknown_pid():
    out = secret_ops.peer_telemetry(None)
    assert out == {"peer_pid": None, "peer_ppid": None, "peer_exe": ""}
