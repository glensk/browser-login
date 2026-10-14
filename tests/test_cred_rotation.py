"""tp#965 — the login broker's credential-rotation safety (PLAN_cred-broker-rotation.md).

S1 the `fingerprint` password oracle is gone (op answers `removed`, no
`password_check` anywhere); S2 an item in BOTH the login and the secrets
collection is refused on both sides by its own `collectionIds`, an item whose
membership cannot be read too; S3 the rotation lease (record, drain, `held`)
and the vault's `agent_hold`; S4 `item_id` + `revision` in the metadata views.

Hermetic: a FixtureVault (or a fake `bw`), stub runners, no browser, no
network. Secret values are random (`secrets.token_hex`).

Run: uv run --no-sync pytest -q tests/test_cred_rotation.py
"""

from __future__ import annotations

# pylint: disable=protected-access,missing-function-docstring,import-error
# pylint: disable=redefined-outer-name,wrong-import-position,too-few-public-methods
# One module covers S1-S4 (broker, vault, onboarding and both clients).
# pylint: disable=too-many-lines
import importlib.util
import json
import os
import re
import secrets
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Any

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import secret_fixtures as sf  # noqa: E402

from broker import daemon, limiter, onboarding, recipes, vault  # noqa: E402

UID = os.getuid()
LOGIN = "coll-login"
SECRETS = "coll-secrets"
PASSWORD = secrets.token_hex(16)
TOKEN = secrets.token_hex(16)
TX = "20261013T120000Z-a1b2c3"
TX2 = "20261013T120500Z-d4e5f6"
REV1 = "2026-10-13T08:00:00.000Z"
REV2 = "2026-10-13T09:30:00.000Z"
# What the removed oracle printed: a length and 4 hex of a SHA-256.
ORACLE = re.compile(r"len=\d+|sha256:[0-9a-f]{4}")


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------


def _id() -> str:
    return str(uuid.uuid4())


def _login(
    name: str = "Shop",
    *,
    site: str | None = "shop",
    host: str = "shop.example",
    colls: Any = (LOGIN,),
    item_id: str | None = None,
    rev: str = REV1,
    **fields: str,
) -> dict[str, Any]:
    """A Bitwarden-shaped login item as `bw list items` lists it."""
    base = {
        "agent_site": site,
        "agent_fill_origins": f"https://login.{host}",
        "agent_cookie_hosts": host,
        "agent_logged_in_selector": "#account",
        **fields,
    }
    item: dict[str, Any] = {
        "id": item_id or _id(),
        "name": name,
        "revisionDate": rev,
        "organizationId": "org-1",
        "login": {"username": "alice", "password": PASSWORD, "totp": None},
        "fields": [
            {"name": k, "value": v, "type": 0} for k, v in base.items() if v is not None
        ],
    }
    if colls is not ...:
        item["collectionIds"] = list(colls) if isinstance(colls, tuple) else colls
    return item


def _secret(
    name: str = "Api",
    *,
    colls: Any = (SECRETS,),
    item_id: str | None = None,
    rev: str = REV1,
) -> dict[str, Any]:
    """A secrets-collection item (`secret-run`)."""
    item = sf.secret_item(name, TOKEN, collections=None)
    item["id"] = item_id or _id()
    item["revisionDate"] = rev
    item["organizationId"] = "org-1"
    if colls is not ...:
        item["collectionIds"] = list(colls) if isinstance(colls, tuple) else colls
    return item


def _write(path: Path, logins: list, secrets_items: list | None = None) -> Path:
    data: dict[str, Any] = {
        "collection_id": LOGIN,
        "secrets_collection_id": SECRETS,
        "logins": logins,
        "secrets": secrets_items or [],
    }
    path.write_text(json.dumps(data))
    return path


class _Vault(vault.FixtureVault):
    """Counts the login-secret reads."""

    reads = 0

    def secret(self, site: str) -> vault.Secret:
        self.reads += 1
        return super().secret(site)


class _Runner:
    """A login that reads the secret, types it and — while `proceed` is
    cleared — waits right before its submit (`at_submit` set)."""

    def __init__(self) -> None:
        self.calls = 0
        self.at_submit = threading.Event()
        self.proceed = threading.Event()
        self.proceed.set()

    def __call__(self, item: vault.SiteItem, get_secret: Any) -> dict[str, Any]:
        self.calls += 1
        secret = get_secret()
        assert secret.password == PASSWORD
        get_secret.attempt.entered()
        self.at_submit.set()
        assert self.proceed.wait(15)
        get_secret.attempt.mark_submitted()
        return {
            "site": item.site,
            "via": "login",
            "cookies": [{"name": "sid", "value": "v", "domain": item.cookie_hosts[0]}],
            "storage": {},
            "cookie_hosts": item.cookie_hosts,
            "cookie_names": None,
        }


class _Env:
    """A broker on a fixture vault with both collections."""

    def __init__(
        self,
        tmp_path: Path,
        logins: list,
        secrets_items: list | None = None,
        *,
        clock: list[float] | None = None,
        runner: Any = None,
    ) -> None:
        self.tmp = tmp_path
        self.path = _write(tmp_path / "vault.json", logins, secrets_items)
        self.home = tmp_path / "home"
        self.clock = clock if clock is not None else [1000.0]
        self.vault = _Vault(self.path, dev=True)
        self.runner = runner if runner is not None else _Runner()
        self.broker = self.new_broker()

    def new_broker(self) -> daemon.Broker:
        """A broker on the same home (a restart)."""
        return daemon.Broker(
            self.vault,
            limiter.Limiter(self.home / "limiter.json", 0, 100, 100),
            self.home,
            runner=self.runner,
            clock=lambda: self.clock[0],
            allow_uid=UID,
        )

    def ask(self, op: str, uid: int | None = UID, **kw: Any) -> dict[str, Any]:
        resp: dict[str, Any] = self.broker.handle({"op": op, **kw}, uid)
        return resp

    def login(self, site: str = "shop", **kw: Any) -> dict[str, Any]:
        return self.ask("login", site=site, **kw)

    def lease(self, sites: list[str], txid: str = TX, **kw: Any) -> dict[str, Any]:
        return self.ask("rotation_lease", txid=txid, sites=sites, **kw)

    def site_view(self, site: str = "shop") -> dict[str, Any]:
        resp = self.ask("sites", fresh=True)
        return next(s for s in resp["sites"] if s["site"] == site)

    def limiter_bytes(self) -> bytes:
        return (self.home / "limiter.json").read_bytes()

    def audit(self) -> str:
        return (self.home / "audit.log").read_text()


# ---------------------------------------------------------------------------
# S1: the fingerprint oracle is gone
# ---------------------------------------------------------------------------


class _BrokenPage:
    """A page every inspection of which fails (the report stays minimal)."""

    url = "https://login.shop.example/"

    def __getattr__(self, name: str) -> Any:
        raise RuntimeError(f"no {name}")


class _FailingRunner:
    """A login that submits, then fails — with the REAL failure report."""

    def __init__(self, home: Path) -> None:
        self.real = daemon.PlaywrightRunner(home, dev=True)
        self.last_diag = self.real.last_diag
        self.diag_dir = self.real.diag_dir

    def __call__(self, item: vault.SiteItem, get_secret: Any) -> dict[str, Any]:
        secret = get_secret()
        get_secret.attempt.entered()
        get_secret.attempt.mark_submitted()
        self.real._record_failure(_BrokenPage(), item, secret)
        raise recipes.LoginFailed("still on the login page", submitted=True)


def test_fingerprint_op_answers_removed(tmp_path: Path) -> None:
    env = _Env(tmp_path, [_login()])
    resp = env.ask("fingerprint", site="shop")
    assert resp == {"ok": False, "error": "removed", "detail": resp["detail"]}
    assert "credctl.py check -T" in resp["detail"]
    assert env.vault.reads == 0
    assert not hasattr(vault.BwVault, "fingerprint_secret")
    assert not hasattr(vault.FixtureVault, "fingerprint_secret")
    assert not hasattr(daemon, "secret_check")


def test_no_reply_report_or_audit_line_carries_a_length_or_hash(
    tmp_path: Path,
) -> None:
    home = tmp_path / "home"
    env = _Env(tmp_path, [_login()], runner=_FailingRunner(home))
    replies = [
        env.login(),
        env.ask("fingerprint", site="shop"),
        env.ask("sites", fresh=True),
        env.ask("secrets"),
    ]
    failed = replies[0]
    assert failed["ok"] is False and failed["submitted"] is True
    assert "password_check" not in json.dumps(failed)
    texts = [json.dumps(r) for r in replies] + [env.audit()]
    for path in home.rglob("*"):
        if path.is_file():
            texts.append(path.read_bytes().decode("utf-8", "replace"))
    for text in texts:
        assert not ORACLE.search(text), text[:200]
        assert PASSWORD not in text


def test_the_client_has_no_password_check_label() -> None:
    src = (REPO / "bin" / "browser.py").read_text(encoding="utf-8")
    assert "password_check" not in src
    agent = (REPO / "agent-login.py").read_text(encoding="utf-8")
    assert "--fingerprint" not in agent and "credctl.py check -T" in agent


# ---------------------------------------------------------------------------
# S2: one item, one collection
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("colls", "want"),
    [
        ([LOGIN], "ok"),
        ([SECRETS], "ok"),
        ([], "ok"),
        ([LOGIN, "other"], "ok"),
        ([LOGIN, SECRETS], "dual"),
        ([SECRETS, "x", LOGIN], "dual"),
        (..., "unreadable"),
        (None, "unreadable"),
        (LOGIN, "unreadable"),
        ([LOGIN, 3], "unreadable"),
        ([""], "unreadable"),
        ({"0": LOGIN}, "unreadable"),
    ],
)
def test_collection_membership(colls: Any, want: str) -> None:
    raw: dict[str, Any] = {"id": _id(), "name": "x"}
    if colls is not ...:
        raw["collectionIds"] = colls
    assert vault.collection_membership(raw, LOGIN, SECRETS) == want
    # no secrets collection configured: nothing is dual
    if want == "dual":
        assert vault.collection_membership(raw, LOGIN, None) == "ok"


@pytest.mark.parametrize(
    "variant",
    [
        {},
        {"agent_site": "other-site", "agent_secret_id": "different-id"},
        {"name": "Totally Unrelated Name", "agent_site": None},
    ],
)
def test_a_dual_item_is_refused_on_both_sides(
    tmp_path: Path, variant: dict[str, Any]
) -> None:
    """By the item's own collectionIds, whatever its fields or name say."""
    fields = {k: v for k, v in variant.items() if k != "name"}
    name = variant.get("name", "Shop")
    dual_id = _id()
    dual = _login(name, colls=(LOGIN, SECRETS), item_id=dual_id, **fields)
    if variant.get("agent_site", "") is None:
        dual = _login(name, site=None, colls=(LOGIN, SECRETS), item_id=dual_id)
    env = _Env(tmp_path, [dual], [dual])
    site = env.ask("sites")["sites"][0]
    assert site["refused"] and "split it" in site["reason"]
    assert site["item_id"] == dual_id
    login = env.login(site["site"])
    assert login["error"] == "refused" and env.vault.reads == 0
    listed = env.ask("secrets")["secrets"]
    assert len(listed) == 1 and listed[0]["refused"]
    assert "split it" in listed[0]["reason"] and listed[0]["item_id"] == dual_id
    with pytest.raises(vault.VaultError):
        env.vault.secret_values(listed[0]["id"])
    with pytest.raises(vault.VaultError, match="split it"):
        env.vault.secret(site["site"])
    assert PASSWORD not in json.dumps(env.ask("secrets"))


@pytest.mark.parametrize("colls", [..., None, "coll-login", [LOGIN, 7], [None]])
def test_unreadable_membership_is_refused_on_both_sides(
    tmp_path: Path, colls: Any
) -> None:
    env = _Env(tmp_path, [_login(colls=colls)], [_secret(colls=colls)])
    site = env.ask("sites")["sites"][0]
    assert site["refused"] and site["reason"] == "collection membership unreadable"
    listed = env.ask("secrets")["secrets"][0]
    assert listed["refused"]
    assert listed["reason"] == "collection membership unreadable"


def test_single_membership_items_are_served(tmp_path: Path) -> None:
    env = _Env(tmp_path, [_login()], [_secret()])
    assert not env.site_view()["refused"]
    assert env.login()["ok"] is True and env.vault.reads == 1
    listed = env.ask("secrets")["secrets"]
    assert [s["refused"] for s in listed] == [False]
    assert env.vault.secret_values("api").fields["password"] == TOKEN


def test_a_refused_dual_item_keeps_its_scope_in_the_conflict_check(
    tmp_path: Path,
) -> None:
    other = _login(
        "Shop Two", site="shop-two", agent_privilege="user", agent_instance="admin"
    )
    dual = _login("Dual", site="dual", colls=(LOGIN, SECRETS))
    env = _Env(tmp_path, [dual, other], [dual])
    by = {s["site"]: s for s in env.ask("sites")["sites"]}
    assert by["dual"]["refused"] and by["dual"]["multi_account"]
    assert by["shop-two"]["multi_account"] is True  # fail closed: it still counts
    (tmp_path / "alone").mkdir()
    alone = _Env(tmp_path / "alone", [other])
    assert alone.site_view("shop-two")["multi_account"] is False


def test_filter_org_keeps_an_unreadable_member_for_its_refusal() -> None:
    mine = {"organizationId": "org-1", "collectionIds": None, "id": "a"}
    listed = {"organizationId": "org-1", "collectionIds": [LOGIN], "id": "b"}
    elsewhere = {"organizationId": "org-1", "collectionIds": ["x"], "id": "c"}
    foreign = {"organizationId": "org-x", "collectionIds": None, "id": "d"}
    got = vault.filter_org([mine, listed, elsewhere, foreign], "org-1", LOGIN)
    assert [r["id"] for r in got] == ["a", "b"]


def test_onboarding_refuses_a_dual_member_with_the_brokers_rule(
    tmp_path: Path,
) -> None:
    env = _Env(tmp_path, [_login()])
    views = env.ask("sites")["sites"]
    planned = {
        "name": "New",
        "fields": {
            "agent_site": "new-site",
            "agent_fill_origins": "https://login.new.example",
            "agent_cookie_hosts": "new.example",
            "agent_logged_in_selector": "#me",
        },
    }
    colls = {"login": LOGIN, "secrets": SECRETS}
    dual = {
        "collections": colls,
        "items": [{**planned, "collectionIds": [LOGIN, SECRETS]}],
    }
    review = onboarding.review_planned(dual, views)
    refused = [f for f in review.findings if f.level == "refused"]
    assert refused and "split it" in refused[0].text and review.blocking
    unreadable = {"collections": colls, "items": [{**planned, "collectionIds": "x"}]}
    review = onboarding.review_planned(unreadable, views)
    assert any("membership unreadable" in f.text for f in review.findings)
    # a NEW item (no collectionIds) goes into the login collection only
    fresh = onboarding.review_planned({"collections": colls, **planned}, views)
    assert not [f for f in fresh.findings if f.level == "refused"]
    # collectionIds without the manifest's collection ids cannot be judged
    with pytest.raises(ValueError, match="collections"):
        onboarding.review_planned({**planned, "collectionIds": [LOGIN]}, views)
    # an old manifest (neither) is reviewed as before
    assert not [
        f for f in onboarding.review_planned(planned, views).findings if f.blocking
    ]


def test_membership_cli_lists_names_and_ids_only(tmp_path: Path, capsys) -> None:
    dual_id, bad_id = _id(), _id()
    dual = _login("Dual Item", colls=(LOGIN, SECRETS), item_id=dual_id)
    bad = _secret("Broken", colls=None, item_id=bad_id)
    path = _write(tmp_path / "v.json", [dual, _login("Ok", site="ok")], [dual, bad])
    home = tmp_path / "h"
    home.mkdir()
    rc = daemon.main(["-d", "-f", str(path), "-H", str(home), "-M"])
    out = capsys.readouterr()
    assert rc == 3
    assert out.out.splitlines() == [
        f"login\tdual\tDual Item\t{dual_id}",
        f"secrets\tdual\tDual Item\t{dual_id}",
        f"secrets\tunreadable\tBroken\t{bad_id}",
    ]
    assert PASSWORD not in out.out + out.err and TOKEN not in out.out + out.err
    assert '"listed": 3' in (home / "audit.log").read_text()
    clean = _write(tmp_path / "c.json", [_login()], [_secret()])
    assert daemon.main(["-d", "-f", str(clean), "-H", str(home), "-M"]) == 0
    assert "✅" in capsys.readouterr().out


def test_membership_cli_runs_as_the_broker_uid_only(tmp_path: Path) -> None:
    # not --dev, and the home is not this uid's: refused before any read
    args = daemon.parse_args(["-H", str(tmp_path / "missing"), "-M"])
    assert daemon._membership_cli(args, tmp_path / "missing") == 2


FAKE_BW = r"""#!/usr/bin/env python3
import json, sys
cmd = sys.argv[1]
if cmd == "status":
    print(json.dumps({"status": "locked"}))
elif cmd == "unlock":
    print("SESSIONKEY")
elif cmd == "list":
    coll = sys.argv[sys.argv.index("--collectionid") + 1]
    print(open("@DIR@/" + coll + ".json").read())
"""


def _bw(tmp_path: Path, logins: list, secrets_items: list) -> vault.BwVault:
    (tmp_path / f"{LOGIN}.json").write_text(json.dumps(logins))
    (tmp_path / f"{SECRETS}.json").write_text(json.dumps(secrets_items))
    fake = tmp_path / "bw"
    fake.write_text(FAKE_BW.replace("@DIR@", str(tmp_path)))
    fake.chmod(0o755)
    boot = vault.BwBootstrap(
        secrets.token_hex(8),
        secrets.token_hex(8),
        secrets.token_hex(8),
        LOGIN,
        organization_id="org-1",
        secrets_organization_id="org-1",
        secrets_collection_id=SECRETS,
    )
    return vault.BwVault(boot, tmp_path / "appdata", bw_bin=str(fake))


def test_bw_vault_refuses_a_dual_item_on_both_sides(tmp_path: Path) -> None:
    dual = _login("Dual", site="dual", host="dual.example", colls=(LOGIN, SECRETS))
    bw = _bw(tmp_path, [dual, _login()], [dual, _secret()])
    by = {it.site: it for it in bw.items()}
    assert "split it" in (by["dual"].refused or "") and by["shop"].refused is None
    sitems = {it.secret_id: it for it in bw.secret_items()}
    assert "split it" in (sitems["dual"].refused or "")
    assert sitems["api"].refused is None
    assert bw.secret("shop").password == PASSWORD
    with pytest.raises(vault.VaultError, match="split it"):
        bw.secret("dual")
    rows = bw.membership_problems()
    assert [(r[0], r[1]) for r in rows] == [("login", "dual"), ("secrets", "dual")]


# ---------------------------------------------------------------------------
# S3: rotation lease, drain and `held`
# ---------------------------------------------------------------------------


def _bg(fn: Any) -> tuple[threading.Thread, dict[str, Any]]:
    out: dict[str, Any] = {}

    def run() -> None:
        out["resp"] = fn()

    th = threading.Thread(target=run, daemon=True)
    th.start()
    return th, out


def test_a_lease_waits_for_the_login_in_flight(tmp_path: Path) -> None:
    env = _Env(tmp_path, [_login()])
    env.runner.proceed.clear()
    login_th, login = _bg(env.login)
    assert env.runner.at_submit.wait(10)  # past its secret read, before the submit
    lease_th, lease = _bg(lambda: env.lease(["shop"]))
    time.sleep(0.3)
    assert "resp" not in lease  # draining: waits for the login
    # a NEW login while the lease drains is held at once, nothing read
    late = env.login()
    assert late["error"] == "held" and late["txid"] == TX
    assert env.vault.reads == 1 and env.runner.calls == 1
    env.runner.proceed.set()
    login_th.join(10)
    lease_th.join(10)
    assert login["resp"]["ok"] is True
    assert lease["resp"]["ok"] is True and lease["resp"]["result"] == "leased"
    assert lease["resp"]["sites"] == ["shop"]


def test_a_login_after_the_lease_is_held_without_a_secret_read(
    tmp_path: Path,
) -> None:
    env = _Env(tmp_path, [_login(), _login("Other", site="other", host="o.example")])
    assert env.lease(["shop"])["result"] == "leased"
    variants: list[dict[str, Any]] = [{}, {"scheduled": True}, {"refresh_only": True}]
    for req in variants:
        resp = env.login("shop", **req)
        assert resp["ok"] is False and resp["error"] == "held"
        assert resp["phase"] == "precheck" and resp["submitted"] is False
        assert resp["txid"] == TX
    assert env.vault.reads == 0 and env.runner.calls == 0
    view = env.site_view()
    assert view["held"] is True and view["held_txid"] == TX
    assert env.site_view("other")["held"] is False
    assert env.login("other")["ok"] is True  # only the leased site is held
    assert '"result": "held"' in env.audit()


def test_held_never_touches_the_limiter(tmp_path: Path) -> None:
    env = _Env(tmp_path, [_login()])
    assert env.login()["ok"] is True  # the limiter state exists
    assert env.lease(["shop"])["result"] == "leased"
    before = env.limiter_bytes()
    assert env.login()["error"] == "held"
    assert env.login(scheduled=True)["error"] == "held"
    assert env.ask("sentinel_absent", site="shop", sentinel="#x")["error"] == "held"
    chal = env.ask("identity_challenge", site="shop", instance="")
    assert chal["error"] == "held"
    assert env.limiter_bytes() == before


def test_a_drain_timeout_drops_the_lease(tmp_path: Path) -> None:
    env = _Env(tmp_path, [_login()])
    env.broker.drain_s = 0.3
    env.runner.proceed.clear()
    login_th, login = _bg(env.login)
    assert env.runner.at_submit.wait(10)
    resp = env.lease(["shop"])
    assert resp["ok"] is False and resp["error"] == "busy"
    assert env.broker.leases.live() == {}
    assert env.site_view()["held"] is False
    env.runner.proceed.set()
    login_th.join(10)
    assert login["resp"]["ok"] is True
    assert env.login()["ok"] is True  # later logins proceed
    assert '"drained": false' in env.audit()


def test_a_lease_survives_a_broker_restart(tmp_path: Path) -> None:
    env = _Env(tmp_path, [_login()])
    assert env.lease(["shop"], ttl_s=600)["result"] == "leased"
    lease_file = env.home / daemon.LEASE_FILE
    assert oct(lease_file.stat().st_mode & 0o777) == "0o600"
    env.broker = env.new_broker()
    assert env.login()["error"] == "held"
    assert env.site_view()["held_txid"] == TX


def test_an_expired_lease_is_dropped(tmp_path: Path) -> None:
    env = _Env(tmp_path, [_login()])
    assert env.lease(["shop"], ttl_s=60)["result"] == "leased"
    assert env.login()["error"] == "held"
    env.clock[0] += 61
    assert env.login()["ok"] is True
    data = json.loads((env.home / daemon.LEASE_FILE).read_text())
    assert data["leases"] == {}


def test_release_reopens_the_site(tmp_path: Path) -> None:
    env = _Env(tmp_path, [_login()])
    assert env.lease(["shop"])["result"] == "leased"
    assert env.login()["error"] == "held"
    resp = env.ask("rotation_release", txid=TX)
    assert resp == {"ok": True, "result": "released", "released": True}
    assert env.login()["ok"] is True
    again = env.ask("rotation_release", txid=TX)
    assert again["ok"] is True and again["released"] is False


def test_lease_requests_are_validated(tmp_path: Path) -> None:
    env = _Env(tmp_path, [_login()])
    unknown = env.lease(["shop", "nope"])
    assert unknown["error"] == "unknown_site" and "nope" in unknown["detail"]
    assert env.broker.leases.live() == {}
    for uid in (UID + 1, None):
        assert env.ask("rotation_lease", uid=uid, txid=TX, sites=["shop"]) == {
            "ok": False,
            "error": "forbidden",
            "detail": "",
        }
        assert env.ask("rotation_release", uid=uid, txid=TX)["error"] == "forbidden"
    for bad in (
        {"txid": "x", "sites": ["shop"]},
        {"txid": TX, "sites": []},
        {"txid": TX, "sites": "shop"},
        {"txid": TX, "sites": ["Bad Site"]},
        {"txid": TX, "sites": ["shop"], "ttl_s": 0},
        {"txid": TX, "sites": ["shop"], "ttl_s": 99999},
        {"txid": TX, "sites": ["shop"], "ttl_s": True},
    ):
        assert env.ask("rotation_lease", **bad)["error"] == "bad_request", bad
    assert env.broker.leases.live() == {}
    assert env.login()["ok"] is True


def test_a_site_leased_by_another_rotation_is_refused(tmp_path: Path) -> None:
    env = _Env(tmp_path, [_login()])
    assert env.lease(["shop"])["result"] == "leased"
    other = env.lease(["shop"], txid=TX2)
    assert other["error"] == "busy"
    assert set(env.broker.leases.live()) == {TX}
    assert env.lease(["shop"])["result"] == "leased"  # the same txid renews


def test_an_unreadable_lease_file_holds_every_site(tmp_path: Path) -> None:
    env = _Env(tmp_path, [_login()])
    env.home.mkdir(parents=True, exist_ok=True)
    (env.home / daemon.LEASE_FILE).write_text("{not json")
    resp = env.login()
    assert resp["error"] == "held" and resp["txid"] is None
    assert env.vault.reads == 0


def test_agent_hold_alone_holds_the_item(tmp_path: Path) -> None:
    env = _Env(tmp_path, [_login(agent_hold=TX)])
    view = env.site_view()
    assert view["held"] is True and view["held_txid"] == TX
    resp = env.login()
    assert resp["error"] == "held" and resp["txid"] == TX
    assert env.vault.reads == 0 and env.runner.calls == 0
    with pytest.raises(vault.Held):
        env.vault.secret("shop")


def test_a_malformed_agent_hold_holds_too(tmp_path: Path) -> None:
    env = _Env(tmp_path, [_login(agent_hold="soon, maybe")])
    view = env.site_view()
    assert view["held"] is True and view["held_txid"] is None
    resp = env.login()
    assert resp["error"] == "held" and resp["txid"] is None
    assert "soon" not in json.dumps(resp) + json.dumps(view)


def test_agent_hold_found_by_the_fresh_secret_read_is_not_counted(
    tmp_path: Path,
) -> None:
    """The cached list predates the hold: the secret's fresh read finds it,
    the reservation is withdrawn — no attempt, no in-flight mark."""
    env = _Env(tmp_path, [_login()])
    assert not env.site_view()["held"]  # the item list is cached now
    _write(env.path, [_login(agent_hold=TX)])
    resp = env.login()
    assert resp["error"] == "held" and resp["txid"] == TX
    assert resp["submitted"] is False
    state = json.loads(env.limiter_bytes())
    entry = state["sites"].get("shop", {})
    assert entry.get("attempts", []) == [] and "inflight" not in entry


def test_limiter_withdraw_only_before_anything_was_typed(tmp_path: Path) -> None:
    lim = limiter.Limiter(tmp_path / "l.json", 0, 100, 100)
    grant = lim.reserve_site("shop", 10.0)
    assert isinstance(grant, limiter.AttemptGrant)
    lim.withdraw(grant)
    data = json.loads((tmp_path / "l.json").read_text())
    assert data["sites"]["shop"]["attempts"] == []
    assert "inflight" not in data["sites"]["shop"]
    typed = lim.reserve_site("shop", 11.0)
    assert isinstance(typed, limiter.AttemptGrant)
    lim.mark_entered(typed)
    with pytest.raises(limiter.LimiterStateError):
        lim.withdraw(typed)
    lim.finish(typed, "unknown", 12.0)
    after = json.loads((tmp_path / "l.json").read_text())["sites"]["shop"]
    assert [a[1] for a in after["attempts"]] == ["unknown"]


# -- the clients ---------------------------------------------------------------


def _load(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def browser() -> Any:
    return _load("browser_rotation_test", REPO / "bin" / "browser.py")


@pytest.fixture(scope="module")
def agent_login() -> Any:
    return _load("agent_login_rotation_test", REPO / "agent-login.py")


def test_browser_login_maps_held_to_busy(browser: Any, monkeypatch, capsys) -> None:
    def no_quarantine(*_a: Any, **_k: Any) -> None:
        raise AssertionError("held never quarantines")

    monkeypatch.setattr(browser._als, "quarantine", no_quarantine)
    browser._result_begin("login", "shop", None)
    rc = browser._broker_refused(
        "shop", {"ok": False, "error": "held", "txid": TX, "detail": "x"}
    )
    assert rc == browser.BUSY_RC == 75
    assert browser._RESULT["code"] == "held" and browser._RESULT["phase"] == "precheck"
    assert browser._RESULT["submitted"] is False and browser._RESULT["txid"] == TX
    assert f"held: rotation {TX} in progress" in capsys.readouterr().err
    # a malformed txid is never echoed
    assert browser._broker_held("shop", "evil\ntext") == 75
    assert "evil" not in capsys.readouterr().err


def test_agent_login_shows_held_and_never_logs_in(
    agent_login: Any, monkeypatch
) -> None:
    al = agent_login
    fields = al._broker_fields({"site": "shop", "held": True, "held_txid": TX})
    assert fields["held"] is True and fields["held_txid"] == TX
    bad = al._broker_fields({"site": "shop", "held": True, "held_txid": "x y"})
    assert bad["held"] is True and bad["held_txid"] is None
    row = {
        "site": "shop",
        "name": "shop",
        "status": "ready",
        "flow": "two-step",
        "sentinel": True,
        "in_bitwarden": True,
        **fields,
    }
    state, why = al.row_state(row, {})
    assert state == "held" and f"held (rotation {TX})" in why
    assert f"⏸ held (rotation {TX})" in al._row_flags(row)
    section, line = al._summary_line(row, {})
    assert section == "check" and "⏸" in line and TX in line and "❌" not in line

    def no_browser(*_a: Any, **_k: Any) -> Any:
        raise AssertionError("a held row runs no browser.py")

    monkeypatch.setattr(al, "ensure_logged_in", no_browser)
    monkeypatch.setattr(al, "run_browser", no_browser)
    recorded: list[tuple] = []
    monkeypatch.setattr(al, "record_check", lambda *a, **k: recorded.append(a))
    failed: list = []
    assert al._check_row(row, failed, lambda: True) is True
    assert not failed and recorded[0][1] is None
    assert recorded[0][3]["code"] == "held"


def test_agent_login_treats_a_held_login_like_busy(
    agent_login: Any, monkeypatch
) -> None:
    al = agent_login
    jobs = sys.modules["agent_login_jobs"]

    def no_probe(*_a: Any, **_k: Any) -> Any:
        raise AssertionError("no re-check of a held login")

    monkeypatch.setattr(al, "probe", no_probe)
    run = jobs.BrowserRun(
        rc=75,
        killed=False,
        stdout="",
        elapsed_s=0.1,
        result={"phase": "precheck", "code": "held", "txid": TX},
    )
    ok, how, res = al._after_login("shop", run, retry_left=True)
    assert ok is None and f"held (rotation {TX})" in how
    assert res["code"] == "held"


# ---------------------------------------------------------------------------
# S4: item id and revision in the metadata views
# ---------------------------------------------------------------------------


def test_views_carry_item_id_and_revision(tmp_path: Path) -> None:
    login_id, secret_id, refused_id = _id(), _id(), _id()
    refused = _login("Broken", site="broken", item_id=refused_id, rev=REV2)
    refused["fields"] = [
        f for f in refused["fields"] if f["name"] != "agent_fill_origins"
    ]
    env = _Env(
        tmp_path,
        [_login(item_id=login_id), refused],
        [_secret(item_id=secret_id, rev=REV2)],
    )
    by = {s["site"]: s for s in env.ask("sites")["sites"]}
    assert by["shop"]["item_id"] == login_id and by["shop"]["revision"] == REV1
    assert by["broken"]["refused"]
    assert by["broken"]["item_id"] == refused_id and by["broken"]["revision"] == REV2
    listed = env.ask("secrets")["secrets"][0]
    assert listed["item_id"] == secret_id and listed["revision"] == REV2
    blob = json.dumps(env.ask("sites")) + json.dumps(env.ask("secrets"))
    assert (
        PASSWORD not in blob
        and TOKEN not in blob
        and "password" not in json.dumps(env.ask("sites"))
    )
    for view in [*by.values(), listed]:
        assert re.fullmatch(r"[0-9a-f-]{36}", view["item_id"])
        assert re.fullmatch(r"[0-9T:.Z-]+", view["revision"])


def test_odd_ids_and_revisions_are_shown_empty(tmp_path: Path) -> None:
    odd = _login(item_id="id with spaces\n", rev="yesterday")
    env = _Env(tmp_path, [odd])
    view = env.site_view()
    assert view["item_id"] == "" and view["revision"] == ""


def test_a_bw_sync_that_changes_revision_date_changes_revision(
    tmp_path: Path,
) -> None:
    login_id, secret_id = _id(), _id()
    bw = _bw(
        tmp_path,
        [_login(item_id=login_id)],
        [_secret(item_id=secret_id)],
    )
    assert [it.revision for it in bw.items()] == [REV1]
    assert [it.revision for it in bw.secret_items()] == [REV1]
    (tmp_path / f"{LOGIN}.json").write_text(
        json.dumps([_login(item_id=login_id, rev=REV2)])
    )
    (tmp_path / f"{SECRETS}.json").write_text(
        json.dumps([_secret(item_id=secret_id, rev=REV2)])
    )
    # every read is unlock + sync + list: the login read sees it at once, and
    # its sync bumps the cache generation, so the secrets listing re-reads
    assert [it.public()["revision"] for it in bw.items()] == [REV2]
    assert [it.public()["revision"] for it in bw.secret_items()] == [REV2]


def test_secret_run_list_json_prints_ids_and_revisions(tmp_path: Path) -> None:
    secret_id = _id()
    path = _write(tmp_path / "v.json", [], [_secret(item_id=secret_id, rev=REV2)])
    brk = sf.make_broker(tmp_path / "home", path, allow_uid=UID, keeper_sock=None)
    with sf.sockdir() as d, sf.serving(brk, str(d / "b.sock"), UID) as sock:
        env = {**os.environ, "SECRET_RUN_SOCKET": sock}
        proc = subprocess.run(
            [sys.executable, str(REPO / "bin" / "secret_run.py"), "-l", "-j"],
            capture_output=True,
            env=env,
            timeout=30,
            check=False,
            stdin=subprocess.DEVNULL,
        )
        usage = subprocess.run(
            [sys.executable, str(REPO / "bin" / "secret_run.py"), "-j"],
            capture_output=True,
            env=env,
            timeout=30,
            check=False,
            stdin=subprocess.DEVNULL,
        )
    assert proc.returncode == 0, proc.stderr
    rows = [json.loads(line) for line in proc.stdout.decode().splitlines()]
    assert rows == [
        {
            # tp#991: the gate keys (kind, flag, what mode agent_script says)
            "agent_script": False,
            "gate_code": "no_agent_script",
            "kind": "secret",
            "fields": ["password"],
            "has_totp": False,
            "id": "api",
            "item_id": secret_id,
            "name": "Api",
            "reason": "",
            "refused": False,
            "revision": REV2,
            "short": False,
        }
    ]
    assert TOKEN not in proc.stdout.decode() + proc.stderr.decode()
    assert usage.returncode != 0
