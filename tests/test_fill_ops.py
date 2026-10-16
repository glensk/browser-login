"""The broker's ``safari_fill`` op (broker/fill_ops.py, tp#1082 B1), hermetic:
FixtureVault, a fake leak check, a fake attended gate, a fake clock, temp home.

Every fixture value and TOTP seed is a random sentinel; besides the success
answer's ``values`` / ``code``, no response, audit line or detail may carry one.

Run: uv run --no-sync pytest tests/test_fill_ops.py
"""

from __future__ import annotations

# pylint: disable=missing-function-docstring,redefined-outer-name,import-error
# pylint: disable=protected-access,wrong-import-position
import json
import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import secret_fixtures as sf  # noqa: E402

from broker import attended, daemon, fill_ops, leakcheck, limiter, vault  # noqa: E402

UID = 501
TXID = "20261013T120000Z-a1b2c3"
ORIGIN = "https://login.shop.example"


class Vals:
    """The random sentinels of one test."""

    def __init__(self) -> None:
        self.pw = sf.sentinel()
        self.user = sf.sentinel()
        self.ns_pw = sf.sentinel()
        self.acct = sf.sentinel()
        self.seed = sf.totp_seed()

    def all(self) -> list[str]:
        return [self.pw, self.user, self.ns_pw, self.acct, self.seed]


def _login(
    name: str,
    fields: dict[str, str],
    *,
    user: str = "",
    password: str | None = None,
    totp: str | None = None,
) -> dict[str, Any]:
    return {
        "id": f"id-{name}",
        "name": name,
        "login": {"username": user, "password": password, "totp": totp},
        "fields": [{"name": k, "value": v, "type": 0} for k, v in fields.items()],
    }


def _origin(site: str) -> str:
    """Each item its own origin (a shared one makes them one login scope)."""
    return f"https://login.{site}.example"


def _base(site: str, **extra: str) -> dict[str, str]:
    return {
        "agent_site": site,
        "agent_fill_origins": _origin(site),
        "agent_logged_in_selector": "#account",
        **extra,
    }


def _logins(v: Vals, *, hold: bool = False) -> list[dict[str, Any]]:
    shop = _base("shop", agent_safari_fill="true")
    if hold:
        shop["agent_hold"] = TXID
    return [
        _login("Shop", shop, user=v.user, password=v.pw, totp=v.seed),
        _login("Plain", _base("plain"), user=v.user, password=v.pw),
        _login(
            "Nosubmit",
            _base("nosubmit", agent_no_submit="true", agent_safari_fill="yes"),
            user=v.user,
            password=v.ns_pw,
        ),
        _login(
            "Account",
            _base(
                "account",
                agent_login_mode="username-only",
                agent_safari_fill="true",
            ),
            user=v.acct,
        ),
        _login(
            "Nopw",
            _base("nopw", agent_safari_fill="on"),
            user=v.user,
            password=None,
        ),
        _login("Badflag", _base("badflag", agent_safari_fill="maybe"), password=v.pw),
        _login("Twin", _base("twin1", agent_safari_fill="true"), password=v.pw),
        _login("Twin", _base("twin2", agent_safari_fill="true"), password=v.pw),
    ]


def _write(path: Path, v: Vals, **kw: Any) -> Path:
    path.write_text(json.dumps({"logins": _logins(v, **kw)}))
    return path


class CountingVault(vault.FixtureVault):
    """FixtureVault that counts every read."""

    def __init__(self, *a: Any, **kw: Any) -> None:
        super().__init__(*a, **kw)
        self.calls = 0

    def items(self) -> list[vault.SiteItem]:
        self.calls += 1
        return super().items()

    def fill_secret(self, site: str) -> vault.Secret:
        self.calls += 1
        return super().fill_secret(site)


class Events:
    """The order of the gates a request passed."""

    def __init__(self) -> None:
        self.log: list[str] = []
        self.attended: str | None = None
        self.leak_down = False
        self.registered: list[tuple[str, str, str]] = []


class FakeLeak:
    """A Registrar that records (or refuses) every push."""

    def __init__(self, ev: Events) -> None:
        self.ev = ev

    def register(self, entries: list[tuple[str, str, str]]) -> None:
        self.ev.log.append("leakcheck")
        if self.ev.leak_down:
            raise leakcheck.LeakCheckUnavailable("secretkeeper not reachable")
        self.ev.registered.extend(entries)

    def refresh(self, fetch: Any) -> int:
        del fetch
        return 0


class Clock:
    def __init__(self) -> None:
        self.now = 1_800_000_000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def vals() -> Vals:
    return Vals()


@pytest.fixture
def env(tmp_path, vals):
    """(broker, events, home, vault path, clock)."""
    ev = Events()
    home = tmp_path / "home"
    vpath = _write(tmp_path / "v.json", vals)
    clock = Clock()

    def gate(uid: int) -> str | None:
        assert uid == UID
        ev.log.append("attended")
        return ev.attended

    brk = daemon.Broker(
        CountingVault(vpath, dev=True),
        limiter.Limiter(home / "limiter.json", 0, 100, 100),
        home,
        runner=sf._NoRunner(),
        clock=clock,
        allow_uid=UID,
        leakcheck=FakeLeak(ev),
        attended=gate,
    )
    return brk, ev, home, vpath, clock


def _fill(brk, item="Shop", fields=("username", "password"), *, origin=None, uid=UID):
    origin = origin or _origin(item.lower())
    req = {"op": "safari_fill", "item": item, "origin": origin, "fields": list(fields)}
    return brk.handle(req, uid, 4242)


def _audit(home: Path) -> list[dict[str, Any]]:
    path = home / "audit.log"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines()]


def _charged(home: Path) -> set[str]:
    path = home / "secret-limiter.json"
    if not path.exists():
        return set()
    sites = json.loads(path.read_text())["sites"]
    return {k for k, e in sites.items() if e.get("attempts")}


def _assert_clean(text: str, v: Vals) -> None:
    for value in v.all():
        assert value not in text


# ---------------------------------------------------------------------------
# success
# ---------------------------------------------------------------------------


def test_fill_returns_requested_values_registers_and_audits_once(env, vals):
    brk, ev, home, _vpath, _clock = env
    resp = _fill(brk)
    assert resp == {
        "ok": True,
        "site": "shop",
        "values": {"username": vals.user, "password": vals.pw},
    }
    assert ev.log == ["leakcheck", "attended"]
    assert ev.registered == [
        ("fill.shop", "username", vals.user),
        ("fill.shop", "password", vals.pw),
    ]
    rows = _audit(home)
    assert len(rows) == 1
    row = rows[0]
    assert row["op"] == "safari_fill" and row["site"] == "shop"
    assert row["result"] == "ok" and row["uid"] == UID
    assert row["fields"] == ["username", "password"]
    assert row["origin"] == ORIGIN and row["pid"] == 4242
    _assert_clean((home / "audit.log").read_text(), vals)
    assert _charged(home) == {"fill:shop", "fill:*"}
    assert leakcheck.label_for("fill.shop", "password") == (
        "loginbroker:fill.shop:password"
    )


def test_only_requested_fields_and_site_id_lookup(env, vals):
    brk, _ev, _home, _vpath, _clock = env
    resp = _fill(brk, "shop", ["password"])
    assert resp["values"] == {"password": vals.pw}
    assert _fill(brk, "shop", ["password"], origin=ORIGIN + ":443")["ok"] is True
    assert _fill(brk, "Shop", ["username"])["values"] == {"username": vals.user}


def test_no_submit_item_with_the_flag_is_served(env, vals):
    brk, _ev, _home, _vpath, _clock = env
    resp = _fill(brk, "Nosubmit", ["password"])
    assert resp["ok"] is True and resp["values"] == {"password": vals.ns_pw}
    # the login path still refuses it
    with pytest.raises(vault.VaultError):
        brk.vault.secret("nosubmit")


def test_totp(env, vals):
    brk, ev, home, _vpath, _clock = env
    resp = _fill(brk, "Shop", ["totp"])
    assert resp["ok"] is True and resp["site"] == "shop"
    assert resp["code"].isdigit() and len(resp["code"]) == 6
    assert 0 < resp["valid_s"] <= 30
    assert "values" not in resp
    assert ev.registered == []  # a TOTP code is not registered
    assert _charged(home) == {"filltotp:shop", "fill:*"}
    _assert_clean(json.dumps(resp), vals)


def test_public_view_carries_the_flag(env):
    brk, _ev, _home, _vpath, _clock = env
    sites = {s["site"]: s for s in brk.handle({"op": "sites"}, UID)["sites"]}
    assert sites["shop"]["safari_fill"] is True
    assert sites["plain"]["safari_fill"] is False
    assert sites["badflag"]["refused"] is True
    assert "agent_safari_fill" in sites["badflag"]["reason"]


# ---------------------------------------------------------------------------
# refusals, in order
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("uid", [None, 0, UID + 1])
def test_wrong_uid_is_forbidden_before_any_vault_read(env, uid):
    brk, ev, home, _vpath, _clock = env
    resp = _fill(brk, uid=uid)
    assert resp == {"ok": False, "error": "forbidden", "detail": ""}
    assert brk.vault.calls == 0
    assert ev.log == []
    assert _charged(home) == set()


@pytest.mark.parametrize(
    "req",
    [
        {"item": "", "origin": ORIGIN, "fields": ["password"]},
        {"item": "x" * 201, "origin": ORIGIN, "fields": ["password"]},
        {"item": "Shop\n", "origin": ORIGIN, "fields": ["password"]},
        {"item": 5, "origin": ORIGIN, "fields": ["password"]},
        {"item": "Shop", "origin": "http://login.shop.example", "fields": ["password"]},
        {"item": "Shop", "origin": ORIGIN + "/login", "fields": ["password"]},
        {"item": "Shop", "origin": ORIGIN + "," + ORIGIN, "fields": ["password"]},
        {"item": "Shop", "origin": "https://u@login.shop.example", "fields": ["x"]},
        {"item": "Shop", "origin": ORIGIN, "fields": []},
        {"item": "Shop", "origin": ORIGIN, "fields": ["password", "password"]},
        {"item": "Shop", "origin": ORIGIN, "fields": ["totp", "password"]},
        {"item": "Shop", "origin": ORIGIN, "fields": ["notes"]},
        {"item": "Shop", "origin": ORIGIN, "fields": "password"},
    ],
)
def test_bad_shape(env, req):
    brk, ev, _home, _vpath, _clock = env
    resp = brk.handle({"op": "safari_fill", **req}, UID, 1)
    assert resp["error"] == "bad_request"
    assert brk.vault.calls == 0 and ev.log == []


def test_no_item_lists_the_sites_of_the_origin(env, vals):
    brk, ev, home, _vpath, _clock = env
    resp = _fill(brk, "Unknown Shop", origin=ORIGIN)
    assert resp["error"] == "no_item"
    assert resp["detail"].endswith(f"items for {ORIGIN}: shop")
    other = _fill(brk, "Unknown", origin="https://other.example")
    assert other["error"] == "no_item" and other["detail"].endswith("none")
    assert ev.log == []
    rows = _audit(home)
    assert rows[-1]["site"] is None and rows[-1]["result"] == "no_item"
    _assert_clean(json.dumps(resp), vals)


def test_ambiguous_name(env):
    brk, ev, _home, _vpath, _clock = env
    assert _fill(brk, "Twin", origin=_origin("twin1"))["error"] == "ambiguous"
    assert ev.log == []


@pytest.mark.parametrize(
    ("item", "code"),
    [
        ("Badflag", "refused"),
        ("Account", "refused"),
        ("Plain", "not_enabled"),
    ],
)
def test_item_checks(env, vals, item, code):
    brk, ev, home, _vpath, _clock = env
    resp = _fill(brk, item)
    assert resp["error"] == code
    assert ev.log == [] and _charged(home) == set()
    _assert_clean(json.dumps(resp) + (home / "audit.log").read_text(), vals)


def test_origin_violation(env):
    brk, ev, home, _vpath, _clock = env
    resp = _fill(brk, "Shop", origin="https://evil.example")
    assert resp["error"] == "origin_violation"
    assert ev.log == [] and _charged(home) == set()
    assert _audit(home)[-1]["origin"] == "https://evil.example"


def test_rotation_lease_is_held(env):
    brk, ev, home, _vpath, _clock = env
    brk.leases.grant(TXID, ["shop"], 600)
    resp = _fill(brk)
    assert resp["error"] == "held" and resp["txid"] == TXID
    assert ev.log == [] and _charged(home) == set()


def test_hold_after_the_listing_is_held_and_not_charged(env, vals):
    brk, ev, home, vpath, _clock = env
    assert _fill(brk, "Shop", ["password"])["ok"] is True  # warms the listing
    ev.log.clear()
    charged = json.loads((home / "secret-limiter.json").read_text())
    _write(vpath, vals, hold=True)  # the cached listing does not see it
    resp = _fill(brk, "Shop", ["password"])
    assert resp["error"] == "held" and resp["txid"] == TXID
    assert ev.log == []
    assert json.loads((home / "secret-limiter.json").read_text()) == charged


def test_no_password(env):
    brk, ev, home, _vpath, _clock = env
    assert _fill(brk, "Nopw", ["password"])["error"] == "no_password"
    assert ev.log == [] and _charged(home) == set()


def test_unknown_field_without_totp(env):
    brk, _ev, _home, vpath, _clock = env
    data = json.loads(vpath.read_text())
    data["logins"][0]["login"]["totp"] = None
    vpath.write_text(json.dumps(data))
    assert _fill(brk, "Shop", ["totp"])["error"] == "unknown_field"


def test_leakcheck_unavailable_is_not_charged(env):
    brk, ev, home, _vpath, _clock = env
    ev.leak_down = True
    resp = _fill(brk)
    assert resp["error"] == "leakcheck_unavailable"
    assert ev.log == ["leakcheck"]
    assert _charged(home) == set()


@pytest.mark.parametrize("why", sorted(attended.ATTENDED_REASONS))
def test_unattended_after_leakcheck_before_limiter(env, why):
    brk, ev, home, _vpath, _clock = env
    ev.attended = why
    resp = _fill(brk)
    assert resp == {"ok": False, "error": "unattended", "detail": why}
    assert ev.log == ["leakcheck", "attended"]
    assert _charged(home) == set()
    assert not (home / fill_ops.FILL_DISTINCT_FILE).exists()


def test_vault_error_on_unreadable_listing(env):
    brk, ev, _home, vpath, _clock = env
    vpath.write_text("not json")
    assert _fill(brk)["error"] == "vault_error"
    assert ev.log == []


# ---------------------------------------------------------------------------
# limiter caps, distinct-item cap, reset grammar
# ---------------------------------------------------------------------------


def test_per_item_hourly_cap(env, vals):
    brk, _ev, home, _vpath, clock = env
    for _ in range(10):
        assert _fill(brk, "Shop", ["password"])["ok"] is True
        clock.now += 1
    resp = _fill(brk, "Shop", ["password"])
    assert resp["error"] == "rate_limited"
    _assert_clean(json.dumps(resp), vals)
    assert _fill(brk, "Shop", ["totp"])["ok"] is True  # its own key
    clock.now += 3601
    assert _fill(brk, "Shop", ["password"])["ok"] is True
    rows = _audit(home)
    assert [r["result"] for r in rows].count("rate_limited") == 1


def test_global_hourly_cap(env):
    brk, _ev, _home, _vpath, clock = env
    sites = ["shop", "nosubmit"]
    for i in range(20):
        item = sites[i % 2]
        fields = ["password"] if i < 18 else ["totp"]
        if fields == ["totp"]:
            item = "shop"
        assert _fill(brk, item, fields)["ok"] is True, i
        clock.now += 1
    assert _fill(brk, "nosubmit", ["password"])["error"] == "rate_limited"


def test_distinct_item_cap(tmp_path, vals):
    ev = Events()
    home = tmp_path / "home"
    logins = [
        _login(f"S{i}", _base(f"s{i}", agent_safari_fill="true"), password=vals.pw)
        for i in range(17)
    ]
    vpath = tmp_path / "v.json"
    vpath.write_text(json.dumps({"logins": logins}))
    clock = Clock()
    brk = daemon.Broker(
        vault.FixtureVault(vpath, dev=True),
        limiter.Limiter(home / "limiter.json", 0, 100, 100),
        home,
        runner=sf._NoRunner(),
        clock=clock,
        allow_uid=UID,
        leakcheck=FakeLeak(ev),
        attended=lambda _uid: None,
    )
    for i in range(15):
        assert _fill(brk, f"s{i}", ["password"])["ok"] is True
        clock.now += 300
    resp = _fill(brk, "s15", ["password"])
    assert resp["error"] == "rate_limited" and "distinct" in resp["detail"]
    assert "fill:s15" not in _charged(home)
    assert _fill(brk, "s3", ["password"])["ok"] is True  # already counted
    state = home / fill_ops.FILL_DISTINCT_FILE
    assert oct(state.stat().st_mode & 0o777) == "0o600"
    clock.now += 24 * 3600
    assert _fill(brk, "s16", ["password"])["ok"] is True
    state.write_text("garbage")
    assert _fill(brk, "s16", ["password"])["error"] == "rate_limited"


def test_reset_accepts_fill_keys(tmp_path, capsys):
    home = tmp_path / "h"
    lim = daemon.build_secret_limiter(home)
    lim.reserve(["fill:github", "filltotp:github", "fill:*"], 0.0)
    for key in ("fill:github", "filltotp:github", "fill:*"):
        assert daemon.main(["-d", "-H", str(home), "-r", key]) == 0
    sites = json.loads(lim.state_path.read_text(encoding="utf-8"))["sites"]
    assert not {"fill:github", "filltotp:github", "fill:*"} & set(sites)
    assert daemon.main(["-d", "-H", str(home), "-r", "fills:x"]) == 2
    assert daemon.main(["-d", "-H", str(home), "-r", "fill:x", "-G"]) == 2
    assert "✅" in capsys.readouterr().out


def test_fill_caps():
    lim = daemon.build_secret_limiter(Path("/nonexistent"))
    assert lim.caps_for("fill:*") == (20, 60)
    assert lim.caps_for("fill:shop") == (10, 40)
    assert lim.caps_for("filltotp:shop") == (10, 0)


# ---------------------------------------------------------------------------
# resolution, leak-check re-push, reserved label prefix
# ---------------------------------------------------------------------------


def test_resolve_item_name_then_id_then_alias():
    a = vault.SiteItem(site="a", name="Beta")
    b = vault.SiteItem(site="beta", name="Other")
    c = vault.SiteItem(site="c", name="C", alias="gamma")
    d = vault.SiteItem(site="d", name="D", alias="gamma2")
    items = [a, b, c, d]
    assert fill_ops.resolve_item(items, "Beta") is a  # name before site id
    assert fill_ops.resolve_item(items, "beta") is b
    assert fill_ops.resolve_item(items, "GAMMA") is c
    assert fill_ops.resolve_item(items, "nope") == "no_item"
    assert fill_ops.resolve_item(items, "Not An Id!") == "no_item"
    twins = [vault.SiteItem(site="x", name="T"), vault.SiteItem(site="y", name="T")]
    assert fill_ops.resolve_item(twins, "T") == "ambiguous"


def test_refresh_repushes_fill_labels_through_fill_secret(tmp_path, vals):
    with sf.sockdir() as d:
        keeper = sf.FakeSecretkeeper(str(d / "keeper.sock"))
        try:
            home = tmp_path / "home"
            vpath = _write(tmp_path / "v.json", vals)
            brk = daemon.Broker(
                vault.FixtureVault(vpath, dev=True),
                limiter.Limiter(home / "limiter.json", 0, 100, 100),
                home,
                runner=sf._NoRunner(),
                allow_uid=UID,
                leakcheck=leakcheck.LeakCheck(
                    keeper.path, home / "leakcheck-labels.json"
                ),
                attended=lambda _uid: None,
            )
            assert _fill(brk, "Nosubmit")["ok"] is True
            assert set(keeper.labels) == {
                "loginbroker:fill.nosubmit:username",
                "loginbroker:fill.nosubmit:password",
            }
            keeper.restart()
            assert brk.refresh_leakcheck() == 2
            assert keeper.labels["loginbroker:fill.nosubmit:password"][0] == vals.ns_pw
            _assert_clean((home / "audit.log").read_text(), vals)
        finally:
            keeper.close()


def test_secret_ids_may_not_use_the_fill_prefix():
    raw = sf.secret_item("X", sf.sentinel(), fields={"agent_secret_id": "fill.shop"})
    it, values = vault.secret_item_from_json(raw, 0)
    assert it.refused and "reserved" in it.refused and values is None


def test_fill_secret_refuses_on_the_fresh_read(env, vals):
    brk, _ev, _home, _vpath, _clock = env
    with pytest.raises(vault.NotFillable) as exc:
        brk.vault.fill_secret("plain")
    assert exc.value.code == "not_enabled"
    with pytest.raises(vault.NotFillable) as exc:
        brk.vault.fill_secret("account")
    assert exc.value.code == "refused"
    assert brk.vault.fill_secret("shop").password == vals.pw


def test_attended_reads_the_given_uid():
    import plistlib  # pylint: disable=import-outside-toplevel
    import subprocess  # pylint: disable=import-outside-toplevel

    def run(argv: list[str], **_kw: Any) -> subprocess.CompletedProcess:
        if "Root" in argv:
            payload: Any = {
                "IOConsoleUsers": [
                    {"kCGSSessionUserIDKey": 777, "kCGSSessionOnConsoleKey": True}
                ]
            }
        else:
            payload = [{"HIDIdleTime": 10**9}]
        return subprocess.CompletedProcess(argv, 0, plistlib.dumps(payload), b"")

    assert attended.attended(777, run) is None
    assert attended.attended(778, run) == "not_on_console"
