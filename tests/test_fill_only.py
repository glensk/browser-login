"""Fill-only broker items (tp#1082 B2, ``agent_fill_only``): hermetic.

The vault parse (no check URL / sentinel / cookie scope, the flag fail
closed, fill origins required, ``public()``, ``fill_enabled``, no part in the
scope rules), every broker path that would log in, probe or challenge
(``fill_only`` before the limiter), the secret side (gate code ``fill_only``),
``safari_fill`` serving it, the onboarding digest, browser.py's
``_resolve_site`` / logout / try-sentinel, and agent-login.py's listing,
agents file line and ``-l``.

FixtureVault files in a temp dir, random sentinel values, fake leak check and
attended gate, no bw, no broker socket, no Chrome.

Run: uv run --no-sync pytest tests/test_fill_only.py
"""

from __future__ import annotations

# pylint: disable=missing-function-docstring,redefined-outer-name,import-error
# pylint: disable=protected-access,wrong-import-position
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import secret_fixtures as sf  # noqa: E402

from broker import daemon, identity, leakcheck, limiter, onboarding, vault  # noqa: E402

UID = 501
BANK = "https://login.bank.example"
SHOP = "https://login.shop.example"


def _script(rel: str) -> Any:
    """A repo script as a module of its own (registered: dataclasses
    resolve their module by name)."""
    name = "fill_only_" + Path(rel).stem.replace("-", "_")
    spec = importlib.util.spec_from_file_location(name, REPO / rel)
    assert spec and spec.loader
    sys.modules[name] = module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


browser = _script("bin/browser.py")
al = _script("agent-login.py")


class Vals:
    """The random sentinels of one test."""

    def __init__(self) -> None:
        self.pw = sf.sentinel()
        self.user = sf.sentinel()
        self.shop_pw = sf.sentinel()

    def all(self) -> list[str]:
        return [self.pw, self.user, self.shop_pw]


def _item(
    name: str, fields: dict[str, str], *, user: str = "", password: str | None = None
) -> dict[str, Any]:
    return {
        "id": f"id-{name.lower()}",
        "name": name,
        "login": {"username": user, "password": password, "totp": None},
        "fields": [{"name": k, "value": v, "type": 0} for k, v in fields.items()],
    }


def _bank(v: Vals, **extra: str) -> dict[str, Any]:
    fields = {
        "agent_site": "bank",
        "agent_fill_origins": BANK,
        "agent_fill_only": "true",
    }
    return _item("My Bank", {**fields, **extra}, user=v.user, password=v.pw)


def _shop(v: Vals, **extra: str) -> dict[str, Any]:
    fields = {
        "agent_site": "shop",
        "agent_fill_origins": SHOP,
        "agent_logged_in_selector": "#account",
        "agent_cookie_hosts": "shop.example",
    }
    return _item("Shop", {**fields, **extra}, user=v.user, password=v.shop_pw)


def _site(raw: dict[str, Any]) -> vault.SiteItem:
    return vault.site_item_from_json(raw, dev=True)


@pytest.fixture
def vals() -> Vals:
    return Vals()


# ---------------------------------------------------------------------------
# broker/vault.py: the parse
# ---------------------------------------------------------------------------


def test_parses_without_check_url_sentinel_or_cookie_hosts(vals):
    it = _site(_bank(vals))
    assert it.refused is None
    assert it.fill_only and not it.loginable
    assert it.fill_origins == [BANK]
    assert it.check_url == it.login_url == ""
    assert it.logged_in_selector is None
    assert it.cookie_hosts == [] and it.cookie_names is None
    assert it.storage_keys == {} and it.scopes == ()
    assert (it.identity, it.privilege, it.alias, it.instance) == ("", "", "", "")
    assert it.attempt_group is None and it.account_name == ""


def test_login_only_fields_are_ignored_not_refused(vals):
    it = _site(
        _bank(
            vals,
            agent_check_url="not a url",
            agent_logged_in_selector="text=Hello",
            agent_cookie_hosts="bank.example",
            agent_storage_keys="{not json",
            agent_identity="gitlab",
            agent_alias="bank-alias",
            agent_attempt_group="grp",
            agent_fresh_login="maybe",
        )
    )
    assert it.refused is None and it.fill_only
    view = it.public()
    for key in ("check_url", "login_url"):
        assert view[key] == ""
    for key in ("cookie_hosts", "cookie_scopes", "storage_origins", "proof_origins"):
        assert view[key] == []
    assert view["logged_in_selector"] is None and view["cookie_names"] is None
    assert view["storage_keys"] == {} and view["alias"] is None
    assert view["identity"] is None and view["privilege"] is None
    assert view["attempt_group"] is None


@pytest.mark.parametrize("raw", ["maybe", "2", "tru"])
def test_malformed_flag_refuses_the_item(vals, raw):
    it = _site(_bank(vals, agent_fill_only=raw))
    assert it.refused == "bad agent_fill_only (true or false)"
    assert not it.fill_only


@pytest.mark.parametrize("raw,want", [("1", True), ("YES", True), ("on", True)])
def test_flag_spellings(vals, raw, want):
    assert _site(_bank(vals, agent_fill_only=raw)).fill_only is want


@pytest.mark.parametrize("raw", ["false", "0", "no", "off"])
def test_false_spellings_need_the_login_fields(vals, raw):
    it = _site(_bank(vals, agent_fill_only=raw))
    assert not it.fill_only and it.loginable
    assert it.refused == "needs agent_check_url (or agent_logged_in_selector)"


def test_missing_fill_origins_refuses(vals):
    raw = _bank(vals)
    raw["fields"] = [f for f in raw["fields"] if f["name"] != "agent_fill_origins"]
    it = _site(raw)
    assert it.refused == "missing agent_fill_origins" and it.fill_only


def test_malformed_safari_fill_still_refuses(vals):
    assert _site(_bank(vals, agent_safari_fill="maybe")).refused == (
        "bad agent_safari_fill (true or false)"
    )


def test_public_flags_and_fill_enabled(vals):
    bank, shop = _site(_bank(vals)), _site(_shop(vals))
    assert bank.public()["fill_only"] is True
    assert bank.public()["safari_fill"] is False
    assert vault.fill_enabled(bank)
    assert shop.public()["fill_only"] is False and shop.loginable
    assert not vault.fill_enabled(shop)
    assert vault.fill_enabled(_site(_shop(vals, agent_safari_fill="true")))


def test_username_only_fill_only_parses(vals):
    it = _site(_bank(vals, agent_login_mode="username-only"))
    assert it.refused is None and it.login_mode == vault.USERNAME_ONLY


def test_never_part_of_the_scope_rules(vals):
    """A fill-only item on the login item's host makes it no multi-account
    item (it has no cookie scope), refused or not."""
    same_host = _bank(vals, agent_fill_origins=SHOP)
    broken = _bank(vals, agent_site="bank2", agent_fill_origins="ftp://x")
    raws = [_shop(vals), same_host, broken]
    items = {it.site: it for it in vault.build_items(raws, dev=True)}
    assert items["shop"].refused is None and not items["shop"].multi_account
    assert items["bank"].refused is None and not items["bank"].multi_account
    assert items["bank2"].refused and items["bank2"].cookie_hosts == []
    assert identity.item_scopes(items["bank"].public()) == frozenset()
    assert identity.scope_conflicts([i.public() for i in items.values()]) == {}


def test_secret_refuses_fill_secret_serves(tmp_path, vals):
    path = tmp_path / "v.json"
    path.write_text(json.dumps({"logins": [_bank(vals)]}))
    v = vault.FixtureVault(path, dev=True)
    with pytest.raises(vault.FillOnly) as exc:
        v.secret("bank")
    assert exc.value.code == "fill_only"
    for value in vals.all():
        assert value not in str(exc.value)
    got = v.fill_secret("bank")
    assert (got.username, got.password) == (vals.user, vals.pw)


# ---------------------------------------------------------------------------
# the broker: every login path answers fill_only, never charged
# ---------------------------------------------------------------------------


class FakeLeak:
    """A Registrar that records every push."""

    def __init__(self) -> None:
        self.registered: list[tuple[str, str, str]] = []

    def register(self, entries: list[tuple[str, str, str]]) -> None:
        self.registered.extend(entries)

    def refresh(self, fetch: Any) -> int:
        del fetch
        return 0


@pytest.fixture
def env(tmp_path, vals):
    """(broker, home, leak) on a fixture vault with bank (fill-only) and shop."""
    home = tmp_path / "home"
    home.mkdir()
    path = tmp_path / "v.json"
    path.write_text(json.dumps({"logins": [_bank(vals), _shop(vals)]}))
    leak = FakeLeak()
    brk = daemon.Broker(
        vault.FixtureVault(path, dev=True),
        limiter.Limiter(home / "limiter.json", 0, 100, 100),
        home,
        runner=sf._NoRunner(),
        allow_uid=UID,
        leakcheck=leak,
        attended=lambda _uid: None,
    )
    return brk, home, leak


def _limiter_state(home: Path) -> str:
    path = home / "limiter.json"
    return path.read_text() if path.exists() else ""


def _audit(home: Path) -> list[dict[str, Any]]:
    path = home / "audit.log"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines()]


@pytest.mark.parametrize(
    "req",
    [
        {"op": "login", "site": "bank"},
        {"op": "login", "site": "bank", "scheduled": True},
        {"op": "login", "site": "bank", "refresh_only": True},
        {"op": "login", "site": "bank", "candidate_sentinel": "#me"},
        {"op": "sentinel_absent", "site": "bank", "sentinel": "#me"},
        {"op": "identity_challenge", "site": "bank", "instance": ""},
    ],
)
def test_every_login_path_answers_fill_only_uncharged(env, vals, req):
    brk, home, _leak = env
    before = _limiter_state(home)
    resp = brk.handle(req, UID, 4242)
    assert resp["ok"] is False and resp["error"] == "fill_only"
    assert "fill-only item" in resp["detail"] and "safari.py -L" in resp["detail"]
    assert resp.get("submitted") in (None, False)
    assert _limiter_state(home) == before
    assert not (home / "profiles" / "bank").exists()
    rows = _audit(home)
    assert rows[-1]["result"] == "fill_only"
    text = json.dumps(resp) + (home / "audit.log").read_text()
    for value in vals.all():
        assert value not in text


def test_login_phase_is_precheck(env):
    brk, _home, _leak = env
    resp = brk.handle({"op": "login", "site": "bank"}, UID)
    assert resp["phase"] == "precheck"


def test_secret_gate_never_reserves_for_a_fill_only_item(env, vals):
    brk, home, _leak = env
    item = _site(_bank(vals))
    gate = daemon._SecretGate(brk, item, scheduled=True)
    with pytest.raises(vault.FillOnly):
        gate()
    assert gate.grant is None and _limiter_state(home) == ""


def test_sites_view_has_no_limit_for_a_fill_only_item(env):
    brk, _home, _leak = env
    resp = brk.handle({"op": "sites"}, UID)
    rows = {e["site"]: e for e in resp["sites"]}
    assert rows["bank"]["fill_only"] is True and "limit" not in rows["bank"]
    assert rows["shop"]["fill_only"] is False and "limit" in rows["shop"]


def test_forget_still_works_as_before(env):
    brk, _home, _leak = env
    resp = brk.handle({"op": "forget", "site": "bank"}, UID)
    assert resp["error"] == "still_listed"


def test_safari_fill_serves_a_fill_only_item(env, vals):
    brk, home, leak = env
    req = {
        "op": "safari_fill",
        "item": "My Bank",
        "origin": BANK,
        "fields": ["username", "password"],
    }
    resp = brk.handle(req, UID, 4242)
    assert resp == {
        "ok": True,
        "site": "bank",
        "values": {"username": vals.user, "password": vals.pw},
    }
    assert ("fill.bank", "password", vals.pw) in leak.registered
    assert _limiter_state(home) == ""  # the login limiter is untouched


def test_safari_fill_refuses_a_username_only_fill_only_item(tmp_path, vals):
    path = tmp_path / "v.json"
    path.write_text(
        json.dumps({"logins": [_bank(vals, agent_login_mode="username-only")]})
    )
    home = tmp_path / "home"
    brk = daemon.Broker(
        vault.FixtureVault(path, dev=True),
        limiter.Limiter(home / "limiter.json", 0, 100, 100),
        home,
        runner=sf._NoRunner(),
        allow_uid=UID,
        leakcheck=FakeLeak(),
        attended=lambda _uid: None,
    )
    req = {"op": "safari_fill", "item": "bank", "origin": BANK, "fields": ["password"]}
    assert brk.handle(req, UID, 1)["error"] == "refused"


def test_label_of_a_fill_value():
    assert leakcheck.label_for("fill.bank", "password") == (
        "loginbroker:fill.bank:password"
    )


# ---------------------------------------------------------------------------
# the secret side: gate code fill_only
# ---------------------------------------------------------------------------


def test_gate_codes_carry_fill_only():
    assert vault.GATE_FILL_ONLY == "fill_only" and "fill_only" in vault.GATE_CODES


def _secrets_vault(tmp_path: Path, logins: list, secrets_items: list, gate: str):
    path = tmp_path / f"s-{gate}.json"
    path.write_text(
        json.dumps(
            {
                "collection_id": "coll-login",
                "logins": logins,
                "secrets_collection_id": "coll-secrets",
                "secrets": secrets_items,
                "secret_gate": gate,
            }
        )
    )
    return vault.FixtureVault(path, dev=True)


@pytest.mark.parametrize("raw", ["true", "maybe"])
def test_secret_listing_refuses_with_gate_code_fill_only(tmp_path, vals, raw):
    login = _bank(vals, agent_script="true", agent_fill_only=raw)
    login["collectionIds"] = ["coll-login"]
    v = _secrets_vault(tmp_path, [login], [], vault.GATE_AGENT_SCRIPT)
    (it,) = v.secret_items()
    assert it.code == it.gate_code == vault.GATE_FILL_ONLY
    assert it.refused == vault.FILL_ONLY_SECRET
    assert it.fields == () and not it.has_totp
    with pytest.raises(vault.VaultError):
        v.secret_values(it.secret_id)
    text = json.dumps(it.public())
    for value in vals.all():
        assert value not in text


def test_a_secrets_collection_copy_is_refused_too(tmp_path, vals):
    copy = _item("Bank copy", {"agent_fill_only": "true", "agent_script": "true"})
    copy["login"]["password"] = vals.pw
    copy["collectionIds"] = ["coll-secrets"]
    v = _secrets_vault(tmp_path, [], [copy], vault.GATE_COLLECTIONS)
    (it,) = v.secret_items()
    assert it.code == it.gate_code == vault.GATE_FILL_ONLY


# ---------------------------------------------------------------------------
# broker/onboarding.py
# ---------------------------------------------------------------------------


def test_digest_changes_with_fill_only_and_safari_fill(vals):
    view = _site(_shop(vals)).public()
    digest = onboarding.config_digest(view)
    assert onboarding.config_digest({**view, "fill_only": True}) != digest
    assert onboarding.config_digest({**view, "safari_fill": True}) != digest
    assert onboarding.config_canon(view)["v"] == onboarding.CONFIG_V == 2


def test_review_has_no_login_findings_for_a_fill_only_item(vals):
    views = [_site(_bank(vals)).public(), _site(_shop(vals)).public()]
    assert onboarding.item_findings(views[0], views) == []
    stand_in = onboarding.item_from_view(views[0])
    assert stand_in.fill_only and not stand_in.loginable


# ---------------------------------------------------------------------------
# bin/browser.py: never a loginable Site
# ---------------------------------------------------------------------------


def _rows() -> list[dict[str, Any]]:
    return [
        {
            "site": "bank",
            "name": "My Bank",
            "refused": False,
            "fill_only": True,
            "fill_origins": [BANK],
            "alias": None,
        },
        {
            # an alias only an older or odd broker would publish
            "site": "bank-two",
            "name": 'Bad "name"',
            "refused": False,
            "fill_only": True,
            "fill_origins": ["https://two.bank.example"],
            "alias": "banking",
        },
    ]


@pytest.fixture
def client(monkeypatch):
    asked: list[str] = []

    def request(op: str, **_kw: Any) -> dict:
        asked.append(op)
        raise AssertionError("the broker must not be asked")

    monkeypatch.setattr(browser, "_broker_sites", lambda *_a, **_k: _rows())
    monkeypatch.setattr(browser, "_broker_request", request)
    return asked


@pytest.mark.parametrize("for_login", [False, True])
def test_resolve_site_refuses_a_dynamic_fill_only_row(client, capsys, for_login):
    with pytest.raises(SystemExit) as exc:
        browser._resolve_site("bank", for_login=for_login)
    assert exc.value.code == 2
    err = capsys.readouterr().err
    assert 'safari.py -L "My Bank" -u login.bank.example' in err
    assert not client


def test_resolve_site_refuses_a_fill_only_alias(client, capsys):
    with pytest.raises(SystemExit) as exc:
        browser._resolve_site("banking")
    assert exc.value.code == 2
    # an unsafe name is shown as the site id
    assert 'safari.py -L "bank-two" -u two.bank.example' in capsys.readouterr().err
    assert not client


def test_logout_and_try_sentinel_refuse(client, capsys):
    for call in (
        lambda: browser.cmd_broker_logout(9222, "bank"),
        lambda: browser.cmd_try_sentinel(9222, "bank", "#me"),
    ):
        with pytest.raises(SystemExit) as exc:
            call()
        assert exc.value.code == 2
        assert "safari.py -L" in capsys.readouterr().err
    assert not client


# ---------------------------------------------------------------------------
# agent-login.py: no row, one agents-file line, -l
# ---------------------------------------------------------------------------


def _listing() -> list[dict[str, Any]]:
    shop = {
        "site": "shopx",
        "name": "Shop X",
        "refused": False,
        "sentinel": True,
        "logged_in_selector": "#me",
        "cookie_hosts": ["shopx.example"],
        "fill_origins": ["https://shopx.example"],
        "storage_origins": [],
        "check_url": "https://shopx.example/me",
        "fill_only": False,
        "safari_fill": True,
    }
    return [shop, *_rows()]


def _overview(monkeypatch) -> dict:
    sites = _listing()
    monkeypatch.setattr(
        al, "broker_state", lambda **_k: ("running, Bitwarden readable", sites)
    )
    monkeypatch.setattr(al, "safari_state", lambda names: {})
    data: dict = al.overview()
    return data


def test_no_row_and_never_checked(monkeypatch):
    data = _overview(monkeypatch)
    sites = {r["site"] for r in data["rows"]}
    assert "shopx" in sites and not sites & {"bank", "bank-two"}
    assert {r["site"] for r in data["fillable"]} == {"shopx", "bank", "bank-two"}


def test_agents_file_gets_one_line(monkeypatch):
    data = _overview(monkeypatch)
    text = al.agent_summary(data, {})
    line = (
        "- 2 sites can be filled into Albert's Safari (login broker, fill-only): "
        '`safari.py -L "<item>" -u <host>`; list them with `agent-login.py -l`'
    )
    assert text.count(line) == 1
    assert "bank" not in text.replace(line, "")
    assert al.fill_only_lines({"fillable": []}) == []


def test_promotion_and_test_are_refused(monkeypatch, capsys):
    sites = _listing()
    monkeypatch.setattr(
        al, "broker_state", lambda **_k: ("running, Bitwarden readable", sites)
    )
    monkeypatch.setattr(al, "_snapshot_sites", lambda: sites)
    why = al.promote_refusal("bank")
    assert why and "fill-only" in why
    assert al.promote_action("bank") == 2
    assert al.run_test("bank") == 2
    assert 'safari.py -L "<item>" -u login.bank.example' in capsys.readouterr().out


def test_fillable_lists_names_and_origins(monkeypatch, capsys):
    sites = _listing()
    monkeypatch.setattr(
        al, "broker_state", lambda **_k: ("running, Bitwarden readable", sites)
    )
    assert al.fillable_action(as_json=False, fresh=False) == 0
    out = capsys.readouterr().out.splitlines()
    assert len(out) == 3
    bank = next(x for x in out if x.startswith("bank "))
    assert "My Bank" in bank and BANK in bank
    assert "agent_safari_fill" in next(x for x in out if x.startswith("shopx"))
    assert al.fillable_action(as_json=True, fresh=False) == 0
    rows = json.loads(capsys.readouterr().out)
    assert [r["site"] for r in rows] == ["bank", "bank-two", "shopx"]
    assert set(rows[0]) == {"site", "name", "fill_origins", "fill_only"}


def test_parser_has_l_without_collision():
    ap = al.build_parser()
    args = ap.parse_args(["-l"])
    assert args.fillable is True and not args.safari_login
    assert ap.parse_args(["--fillable", "-j"]).json is True
    assert ap.parse_args(["-L", "notion"]).fillable is False
