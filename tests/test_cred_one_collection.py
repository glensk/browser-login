"""tp#991 — one collection + the ``agent_script`` gate (PLAN_cred-one-collection.md).

B1: the vault's secret read per gate mode (collections | report |
agent_script), the closed ``gate_code`` enum, duplicate ids, the sites side,
the cache key, ``bootstrap_switch.py -W/-D`` and ``install.sh -W/-D/-g``.

Hermetic: FixtureVault files in a temp dir, random sentinel values, no bw,
no broker socket, no network.

Run: uv run pytest -q tests/test_cred_one_collection.py
"""

from __future__ import annotations

# pylint: disable=protected-access,missing-function-docstring,import-error
# pylint: disable=redefined-outer-name,wrong-import-position
import importlib.util
import json
import secrets
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from broker import bootstrap_switch, vault  # noqa: E402

LOGIN = "coll-login"
SECRETS = "coll-secrets"
PASSWORD = secrets.token_hex(16)
TOKEN = secrets.token_hex(16)
ACCOUNT = "acct" + secrets.token_hex(8)
SENTINELS = (PASSWORD, TOKEN, ACCOUNT)
MODES = vault.SECRET_GATES


def _id() -> str:
    return str(uuid.uuid4())


def _fields(**fields: str | None) -> list[dict[str, Any]]:
    return [
        {"name": k, "value": v, "type": 0} for k, v in fields.items() if v is not None
    ]


def _login(
    name: str = "Shop",
    *,
    site: str | None = "shop",
    colls: Any = (LOGIN,),
    item_id: str | None = None,
    flag: str | None = None,
    origins: str | None = "https://login.shop.example",
    username: str = "alice",
    password: str = PASSWORD,
    **extra: str,
) -> dict[str, Any]:
    """A login item (agent_site + fill origins) as `bw list items` lists it."""
    return {
        "id": item_id or _id(),
        "name": name,
        "revisionDate": "2026-10-14T08:00:00.000Z",
        "organizationId": "org-1",
        "collectionIds": list(colls),
        "login": {"username": username, "password": password, "totp": None},
        "fields": _fields(
            agent_site=site,
            agent_fill_origins=origins,
            agent_cookie_hosts="shop.example" if origins else None,
            agent_logged_in_selector="#account" if origins else None,
            agent_script=flag,
            **extra,
        ),
    }


def _secret(
    name: str = "Api",
    *,
    colls: Any = (SECRETS,),
    item_id: str | None = None,
    flag: str | None = None,
    value: str = TOKEN,
    **extra: str,
) -> dict[str, Any]:
    """A script item (no login fields)."""
    return {
        "id": item_id or _id(),
        "name": name,
        "revisionDate": "2026-10-14T08:00:00.000Z",
        "organizationId": "org-1",
        "collectionIds": list(colls),
        "login": {"username": "", "password": value, "totp": None},
        "fields": _fields(agent_script=flag, **extra),
    }


def _write(
    path: Path,
    logins: list | None = None,
    secrets_items: list | None = None,
    *,
    gate: str | None = None,
    with_secrets: bool = True,
) -> Path:
    data: dict[str, Any] = {"collection_id": LOGIN, "logins": logins or []}
    if with_secrets:
        data["secrets_collection_id"] = SECRETS
        data["secrets"] = secrets_items or []
    if gate is not None:
        data["secret_gate"] = gate
        data["secret_gate_since"] = "2026-10-14T10:00:00Z"
    path.write_text(json.dumps(data))
    return path


def _vault(tmp_path: Path, logins: list, secrets_items: list | None = None, **kw: Any):
    return vault.FixtureVault(
        _write(tmp_path / "vault.json", logins, secrets_items, **kw), dev=True
    )


def _rows(v: vault.FixtureVault) -> dict[str, dict[str, Any]]:
    return {it.secret_id: it.public() for it in v.secret_items()}


def _no_sentinel(text: str) -> None:
    for s in SENTINELS:
        assert s not in text


# ---------------------------------------------------------------------------
# the flag
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw,want",
    [
        ("true", True),
        ("TRUE", True),
        ("1", True),
        ("false", False),
        ("", False),
        ("maybe", None),
        ("tru", None),
    ],
)
def test_agent_script_flag(raw: str, want: bool | None) -> None:
    assert vault.agent_script_flag({"agent_script": raw}) is want


def test_absent_flag_is_false() -> None:
    assert vault.agent_script_flag({}) is False


# ---------------------------------------------------------------------------
# the mode x flag x location matrix
# ---------------------------------------------------------------------------

FLAGS = {"true": "true", "false": "false", "absent": None, "malformed": "maybe"}
PREVIEW = {
    "true": vault.GATE_OK,
    "false": vault.GATE_NO_FLAG,
    "absent": vault.GATE_NO_FLAG,
    "malformed": vault.GATE_BAD_FLAG,
}


def _place(where: str, flag: str | None) -> tuple[list, list, str]:
    if where == "secrets":
        return [], [_secret("Api", flag=flag)], "api"
    colls = (LOGIN,) if where == "login" else (LOGIN, SECRETS)
    item = _login("Shop", flag=flag, colls=colls)
    if where == "login":
        return [item], [], "shop"
    return [item], [item], "shop"


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("flag", list(FLAGS))
@pytest.mark.parametrize("where", ["login", "secrets", "both"])
def test_gate_matrix(tmp_path: Path, mode: str, flag: str, where: str) -> None:
    logins, secrets_items, _sid = _place(where, FLAGS[flag])
    v = _vault(tmp_path, logins, secrets_items, gate=mode)
    items = v.secret_items()
    _no_sentinel(json.dumps([it.public() for it in items]))
    if mode != vault.GATE_AGENT_SCRIPT:
        if where == "login":
            assert not items  # a login item is never read in these modes
            return
        (it,) = items
        if where == "secrets":
            # exactly today: served whatever the flag says
            assert it.refused is None
            assert it.gate_code == PREVIEW[flag]
            assert v.secret_values(it.secret_id).fields["password"] == TOKEN
        else:  # both: tp#965's dual refusal
            assert it.refused == vault.MEMBERSHIP_REASONS[vault.MEMBERSHIP_DUAL]
            assert it.gate_code == PREVIEW[flag]
        return
    (it,) = items
    assert it.kind == (vault.KIND_SECRET if where == "secrets" else vault.KIND_LOGIN)
    assert it.gate_code == PREVIEW[flag]
    if flag == "true":
        assert it.refused is None
        want = TOKEN if where == "secrets" else PASSWORD
        assert v.secret_values(it.secret_id).fields["password"] == want
    else:
        assert it.refused
        assert it.code == PREVIEW[flag]
        with pytest.raises(vault.VaultError):
            v.secret_values(it.secret_id)


def test_no_agent_script_reason_text(tmp_path: Path) -> None:
    v = _vault(tmp_path, [_login()], gate=vault.GATE_AGENT_SCRIPT)
    (it,) = v.secret_items()
    assert it.refused == vault.NO_AGENT_SCRIPT == "script read without agent_script"


def test_secret_items_need_no_secrets_collection_under_agent_script(
    tmp_path: Path,
) -> None:
    v = _vault(
        tmp_path,
        [_login(flag="true")],
        gate=vault.GATE_AGENT_SCRIPT,
        with_secrets=False,
    )
    assert v.secret_values("shop").fields["password"] == PASSWORD
    v2 = _vault(tmp_path, [_login(flag="true")], with_secrets=False)
    with pytest.raises(vault.SecretsNotConfigured):
        v2.secret_items()


# ---------------------------------------------------------------------------
# ids, duplicates, merging
# ---------------------------------------------------------------------------


def test_login_item_id_falls_back_to_agent_site(tmp_path: Path) -> None:
    item = _login("NPM nixos admin", site="npm-nixos", flag="true")
    v = _vault(tmp_path, [item], gate=vault.GATE_AGENT_SCRIPT)
    assert [it.secret_id for it in v.secret_items()] == ["npm-nixos"]


def test_agent_secret_id_wins(tmp_path: Path) -> None:
    item = _login("Shop", flag="true", agent_secret_id="shop-admin")
    v = _vault(tmp_path, [item], gate=vault.GATE_AGENT_SCRIPT)
    assert [it.secret_id for it in v.secret_items()] == ["shop-admin"]


def test_legacy_ids_never_change(tmp_path: Path) -> None:
    """O11: a legacy secrets item keeps agent_secret_id -> name slug in
    every mode, even when it carries an agent_site."""
    item = _secret("GitHub token", flag="true", agent_site="github")
    for mode in MODES:
        v = _vault(tmp_path, [], [item], gate=mode)
        assert [it.secret_id for it in v.secret_items()] == ["github-token"]


def test_pinned_id_is_stable_across_a_move(tmp_path: Path) -> None:
    """Codex r2 O4 (d): with agent_secret_id pinned, the id is the same
    before (legacy), during (both) and after (login only) a move."""
    iid = _id()
    base = {"agent_secret_id": "ecovacs"}
    before = _secret("Ecovacs", flag="true", item_id=iid, **base)
    during = _secret(
        "Ecovacs", flag="true", item_id=iid, colls=(LOGIN, SECRETS), **base
    )
    after = _secret("Ecovacs", flag="true", item_id=iid, colls=(LOGIN,), **base)
    ids = []
    for logins, sec in (([], [before]), ([during], [during]), ([after], [])):
        v = _vault(tmp_path, logins, sec, gate=vault.GATE_AGENT_SCRIPT)
        ids.append([it.secret_id for it in v.secret_items()])
    assert ids == [["ecovacs"], ["ecovacs"], ["ecovacs"]]


def test_an_item_in_both_reads_is_listed_once_as_login(tmp_path: Path) -> None:
    item = _login(flag="true", colls=(LOGIN, SECRETS))
    v = _vault(tmp_path, [item], [item], gate=vault.GATE_AGENT_SCRIPT)
    items = v.secret_items()
    assert len(items) == 1
    assert items[0].kind == vault.KIND_LOGIN


def test_items_without_an_item_id_are_never_merged(tmp_path: Path) -> None:
    a = _secret("Api", flag="true", item_id="")
    b = _secret("Api", flag="true", item_id="")
    b["collectionIds"] = [LOGIN]
    v = _vault(tmp_path, [b], [a], gate=vault.GATE_AGENT_SCRIPT)
    items = v.secret_items()
    assert len(items) == 2
    assert {it.gate_code for it in items} == {vault.GATE_DUPLICATE}
    assert all(it.refused for it in items)
    with pytest.raises(vault.VaultError):
        v.secret_values("api")


def test_two_flagged_owners_of_one_id_are_both_refused(tmp_path: Path) -> None:
    login = _login("GitHub", site="github", flag="true")
    sec = _secret("GitHub", flag="true")
    v = _vault(tmp_path, [login], [sec], gate=vault.GATE_AGENT_SCRIPT)
    items = v.secret_items()
    assert len(items) == 2
    assert all(it.code == vault.GATE_DUPLICATE for it in items)
    hit = vault.resolve_secret(items, "github")
    assert hit is not None and hit.refused == vault.DUPLICATE_SECRET_ID


def test_an_unflagged_login_does_not_claim_the_id(tmp_path: Path) -> None:
    """A browser-only login named like a script item does not block it."""
    login = _login("GitHub", site="github")
    sec = _secret("GitHub", flag="true")
    v = _vault(tmp_path, [login], [sec], gate=vault.GATE_AGENT_SCRIPT)
    items = v.secret_items()
    served = vault.resolve_secret(items, "github")
    assert served is not None and served.refused is None
    assert served.kind == vault.KIND_SECRET
    assert v.secret_values("github").fields["password"] == TOKEN


def test_collections_mode_duplicate_rule_is_todays(tmp_path: Path) -> None:
    a, b = _secret("Api", flag="true"), _secret("Api", flag="true")
    v = _vault(tmp_path, [], [a, b])
    first, second = v.secret_items()
    assert first.refused is None
    assert second.refused == "duplicate agent_secret_id"
    assert first.gate_code == second.gate_code == vault.GATE_DUPLICATE


# ---------------------------------------------------------------------------
# refusals the flag never lifts; username-only
# ---------------------------------------------------------------------------


def test_held_flagged_item_is_refused(tmp_path: Path) -> None:
    item = _login(flag="true", agent_hold="20261013T120000Z-a1b2c3")
    v = _vault(tmp_path, [item], gate=vault.GATE_AGENT_SCRIPT)
    (it,) = v.secret_items()
    assert it.code == vault.GATE_HELD and it.refused == vault.HELD_SECRET


def test_no_submit_flagged_item_is_refused(tmp_path: Path) -> None:
    item = _login(
        "Galaxus",
        site="galaxus",
        flag="true",
        origins="https://id.digitecgalaxus.ch",
    )
    v = _vault(tmp_path, [item], gate=vault.GATE_AGENT_SCRIPT)
    (it,) = v.secret_items()
    assert it.code == vault.GATE_NO_SUBMIT


def test_unreadable_membership_is_refused_in_every_mode(tmp_path: Path) -> None:
    item = _secret(flag="true")
    item["collectionIds"] = "not-a-list"
    for mode in MODES:
        v = _vault(tmp_path, [], [item], gate=mode)
        (it,) = v.secret_items()
        assert it.refused == vault.MEMBERSHIP_REASONS[vault.MEMBERSHIP_UNREADABLE]
        assert it.gate_code == vault.GATE_UNREADABLE


def test_flagged_username_only_injects_its_username(tmp_path: Path) -> None:
    """O3: R9 rewires vpn.sh to read the Mullvad account number this way."""
    item = _login(
        "Mullvad",
        site="mullvad",
        flag="true",
        username=ACCOUNT,
        password="",
        agent_login_mode="username-only",
    )
    v = _vault(tmp_path, [item], gate=vault.GATE_AGENT_SCRIPT)
    assert v.secret_values("mullvad").fields["password"] == ACCOUNT
    _no_sentinel(json.dumps([it.public() for it in v.secret_items()]))


def test_username_only_stays_refused_without_the_gate(tmp_path: Path) -> None:
    item = _secret("Mullvad", flag="true", value="", agent_login_mode="username-only")
    item["login"]["username"] = ACCOUNT
    v = _vault(tmp_path, [], [item])
    (it,) = v.secret_items()
    assert it.code == vault.GATE_USERNAME_ONLY
    assert it.gate_code == vault.GATE_OK  # what agent_script mode would do
    with pytest.raises(vault.VaultError):
        v.secret_values(it.secret_id)


# ---------------------------------------------------------------------------
# the gate itself, the cache, the sites side
# ---------------------------------------------------------------------------


def test_an_unknown_gate_refuses_secret_reads_not_logins(tmp_path: Path) -> None:
    v = _vault(tmp_path, [_login()], [_secret()], gate="enforce")
    with pytest.raises(vault.BadSecretGate):
        v.secret_items()
    with pytest.raises(vault.BadSecretGate):
        v.secret_values("api")
    assert [it.site for it in v.items()] == ["shop"]
    assert v.secret_gate()[0] == "enforce"


def test_a_mode_switch_never_serves_an_older_mode_value(tmp_path: Path) -> None:
    """O10: one vault/cache instance; the switch to agent_script refuses the
    unflagged item at once, though collections served it a moment ago."""
    path = tmp_path / "vault.json"
    sec = _secret()
    _write(path, [], [sec])
    v = vault.FixtureVault(path, dev=True)
    assert v.secret_values("api").fields["password"] == TOKEN
    _write(path, [], [sec], gate=vault.GATE_AGENT_SCRIPT)
    with pytest.raises(vault.VaultError):
        v.secret_values("api")
    _write(path, [], [sec], gate=vault.GATE_COLLECTIONS)
    assert v.secret_values("api").fields["password"] == TOKEN


def test_script_only_item_is_no_site_under_agent_script(tmp_path: Path) -> None:
    script = _secret("Api", flag="true", colls=(LOGIN,))
    v = _vault(tmp_path, [_login(), script], gate=vault.GATE_AGENT_SCRIPT)
    assert [it.site for it in v.items()] == ["shop"]
    v2 = _vault(tmp_path, [_login(), script])
    sites = {it.site: it for it in v2.items()}
    assert sites["api"].refused  # today: a refused site


def test_unflagged_siteless_item_is_no_site_and_not_injectable(
    tmp_path: Path,
) -> None:
    """tp#889: a legacy secrets item moved into the login collection without
    agent_script is no refused site, and secret-run still refuses it."""
    moved = _secret("Comicvine", colls=(LOGIN,))
    v = _vault(tmp_path, [_login(), moved], gate=vault.GATE_AGENT_SCRIPT)
    sites = v.items()
    assert [it.site for it in sites] == ["shop"]
    assert all(it.refused is None for it in sites)
    rows = _rows(v)
    assert rows["comicvine"]["gate_code"] == vault.GATE_NO_FLAG
    with pytest.raises(vault.VaultError):
        v.secret_values("comicvine")


def test_flagged_siteless_item_is_injectable(tmp_path: Path) -> None:
    script = _secret("Api", flag="true", colls=(LOGIN,))
    v = _vault(tmp_path, [_login(), script], gate=vault.GATE_AGENT_SCRIPT)
    assert [it.site for it in v.items()] == ["shop"]
    assert v.secret_values("api").fields["password"] == TOKEN


def test_item_with_agent_site_is_a_site_whatever_its_flag(tmp_path: Path) -> None:
    for flag in (None, "false", "true"):
        v = _vault(tmp_path, [_login(flag=flag)], gate=vault.GATE_AGENT_SCRIPT)
        sites = v.items()
        assert [(it.site, it.refused) for it in sites] == [("shop", None)]
        assert v.secret("shop").password == PASSWORD


def test_agent_site_without_origins_stays_a_refused_site(tmp_path: Path) -> None:
    broken = _login("Broken", site="broken", flag="true", origins=None)
    v = _vault(tmp_path, [_login(), broken], gate=vault.GATE_AGENT_SCRIPT)
    sites = {it.site: it for it in v.items()}
    assert sites["broken"].refused == "missing agent_fill_origins"


def test_dual_item_is_a_site_under_agent_script(tmp_path: Path) -> None:
    item = _login(flag="true", colls=(LOGIN, SECRETS))
    v = _vault(tmp_path, [item], [item], gate=vault.GATE_AGENT_SCRIPT)
    sites = v.items()
    assert len(sites) == 1 and sites[0].refused is None
    assert v.secret("shop").password == PASSWORD
    v2 = _vault(tmp_path, [item], [item])
    assert v2.items()[0].refused  # collections: tp#965 refusal


# ---------------------------------------------------------------------------
# compatibility: collections mode is today's output plus three keys
# ---------------------------------------------------------------------------


def _old_vault() -> Any:
    """broker/vault.py as committed on main before tp#991 (git show)."""
    src = subprocess.run(
        ["git", "-C", str(REPO), "show", "9d23e15:broker/vault.py"],
        capture_output=True,
        text=True,
        check=False,
    )
    if src.returncode != 0:
        pytest.skip("pre-tp#991 vault.py not reachable in this checkout")
    spec = importlib.util.spec_from_loader("vault_pre_991", loader=None)
    assert spec is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules["vault_pre_991"] = mod
    exec(compile(src.stdout, "vault_pre_991.py", "exec"), mod.__dict__)  # noqa: S102 # pylint: disable=exec-used
    return mod


def test_collections_mode_rows_equal_todays(tmp_path: Path) -> None:
    old = _old_vault()
    items = [
        _secret("Api", flag="true"),
        _secret("Other", agent_secret_fields="extra", extra="x" * 12),
        _secret("Api"),  # duplicate id
        _secret("Mullvad", value="", agent_login_mode="username-only"),
        _login("Shop", colls=(LOGIN, SECRETS)),
    ]
    path = _write(tmp_path / "vault.json", [], items)
    new_rows = [it.public() for it in vault.FixtureVault(path, dev=True).secret_items()]
    old_rows = [it.public() for it in old.FixtureVault(path, dev=True).secret_items()]
    added = {"kind", "agent_script", "gate_code"}
    assert [{k: r[k] for k in r if k not in added} for r in new_rows] == old_rows
    assert all(set(r) - set(o) == added for r, o in zip(new_rows, old_rows))


# ---------------------------------------------------------------------------
# the gate report rows (no value)
# ---------------------------------------------------------------------------


def test_script_gate_rows(tmp_path: Path) -> None:
    v = _vault(
        tmp_path,
        [_login(), _login("Bad", site="bad", flag="maybe")],
        [_secret("Api"), _secret("Ok", flag="true")],
    )
    rows = {r.secret_id: r for r in v.script_gate_report()}
    assert rows["api"].served_now and rows["api"].gate_code == vault.GATE_NO_FLAG
    assert rows["ok"].served_now and rows["ok"].gate_code == vault.GATE_OK
    assert not rows["shop"].served_now and rows["shop"].kind == vault.KIND_LOGIN
    assert rows["bad"].gate_code == vault.GATE_BAD_FLAG
    _no_sentinel(json.dumps([r.public() for r in rows.values()]))


# ---------------------------------------------------------------------------
# bootstrap_switch -W / -D and install.sh parsing
# ---------------------------------------------------------------------------


def _boot(home: Path, **extra: str) -> Path:
    home.mkdir(parents=True, exist_ok=True)
    data = {
        "client_id": "user.x",
        "client_secret": TOKEN,
        "master_password": PASSWORD,
        "collection_id": LOGIN,
        "organization_id": "org-1",
        "secrets_organization_id": "org-1",
        "secrets_collection_id": SECRETS,
        **extra,
    }
    (home / "bootstrap.json").write_text(json.dumps(data))
    return home


def _bs(home: Path, *args: str, stdin: str = "") -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            sys.executable,
            str(REPO / "broker/bootstrap_switch.py"),
            "-H",
            str(home),
            *args,
        ],
        input=stdin,
        capture_output=True,
        text=True,
        check=False,
    )


def test_bootstrap_load_reads_the_gate(tmp_path: Path) -> None:
    home = _boot(tmp_path / "h")
    assert vault.BwBootstrap.load(home / "bootstrap.json").secret_gate == "collections"
    home = _boot(tmp_path / "h2", secret_gate="report", secret_gate_since="x")
    boot = vault.BwBootstrap.load(home / "bootstrap.json")
    assert (boot.secret_gate, boot.secret_gate_since) == ("report", "x")


def test_switch_sets_the_gate_and_rolls_back(tmp_path: Path) -> None:
    home = _boot(tmp_path / "h")
    proc = _bs(home, "-W", "report")
    assert proc.returncode == 0, proc.stderr
    data = json.loads((home / "bootstrap.json").read_text())
    assert data["secret_gate"] == "report" and data["secret_gate_since"].endswith("Z")
    assert data["client_secret"] == TOKEN  # the secrets are kept
    _no_sentinel(proc.stdout + proc.stderr)
    assert _bs(home, "-W", "report").stdout.startswith("✅ bootstrap.json unchanged")
    assert _bs(home, "-B").returncode == 0
    assert "secret_gate" not in json.loads((home / "bootstrap.json").read_text())


def test_switch_refuses_an_unknown_gate(tmp_path: Path) -> None:
    home = _boot(tmp_path / "h")
    assert _bs(home, "-W", "enforce").returncode != 0


def test_a_collection_switch_keeps_the_gate(tmp_path: Path) -> None:
    home = _boot(tmp_path / "h", secret_gate="report", secret_gate_since="t")
    changed, _prev = bootstrap_switch.switch(
        home, {("org-2", "c2")}, ("org-2", "c2"), None
    )
    assert changed
    data = json.loads((home / "bootstrap.json").read_text())
    assert data["secret_gate"] == "report"


ROW_LOGIN = json.dumps({"kind": "login", "gate_code": "ok", "id": "shop"})
ROW_SECRET = json.dumps({"kind": "secret", "gate_code": "no_agent_script", "id": "api"})


@pytest.mark.parametrize(
    "gate,listing,why",
    [
        ("report", ROW_LOGIN, "not agent_script"),
        ("agent_script", f"{ROW_LOGIN}\n{ROW_SECRET}", "still in the legacy"),
        ("agent_script", "", "empty"),
        ("agent_script", "not json", "not JSON"),
        ("agent_script", json.dumps({"kind": "x"}), "no kind"),
    ],
)
def test_drop_secrets_refusals(
    tmp_path: Path, gate: str, listing: str, why: str
) -> None:
    home = _boot(tmp_path / "h", secret_gate=gate)
    before = (home / "bootstrap.json").read_bytes()
    proc = _bs(home, "-v", "-", "-D", stdin=listing)
    assert proc.returncode == 1
    assert why in proc.stderr
    assert (home / "bootstrap.json").read_bytes() == before


def test_drop_secrets_removes_the_legacy_ids(tmp_path: Path) -> None:
    home = _boot(tmp_path / "h", secret_gate="agent_script")
    proc = _bs(home, "-v", "-", "-D", stdin=ROW_LOGIN + "\n")
    assert proc.returncode == 0, proc.stderr
    data = json.loads((home / "bootstrap.json").read_text())
    assert "secrets_collection_id" not in data
    assert "secrets_organization_id" not in data
    assert data["secret_gate"] == "agent_script"
    assert _bs(home, "-B").returncode == 0
    assert json.loads((home / "bootstrap.json").read_text())["secrets_collection_id"]


def test_switch_modes_are_exclusive(tmp_path: Path) -> None:
    home = _boot(tmp_path / "h")
    assert _bs(home, "-W", "report", "-B").returncode == 1


def _install(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", str(REPO / "install/install.sh"), "-n", *args],
        capture_output=True,
        text=True,
        check=False,
    )


def test_install_parses_the_gate_options() -> None:
    proc = _install("-W", "agent_script")
    assert proc.returncode == 0, proc.stderr
    assert "-W agent_script" in proc.stdout
    assert _install("-W", "bogus").returncode != 0
    proc = _install("-D")
    assert proc.returncode == 0 and "-g -j" in proc.stdout and " -D" in proc.stdout
    assert " -g" in _install("-g").stdout


def test_install_with_group_still_parses() -> None:
    """O1: -G stays --with-group (the gate option is -W)."""
    proc = _install("-r", "galaxus", "-G")
    assert proc.returncode == 0, proc.stderr
    assert "-r galaxus -G" in proc.stdout


# ---------------------------------------------------------------------------
# B2: the broker ops (secrets / secret / totp under each gate, report events)
# ---------------------------------------------------------------------------

UID = 501


class _OpsEnv:
    """A broker on a fixture vault with a fake secretkeeper."""

    def __init__(self, tmp_path: Path, keeper_sock: str, **vault_kw: Any) -> None:
        import secret_fixtures as sf  # pylint: disable=import-outside-toplevel

        self.home = tmp_path / "home"
        self.path = _write(tmp_path / "vault.json", **vault_kw)
        self.broker = sf.make_broker(
            self.home, self.path, allow_uid=UID, keeper_sock=keeper_sock
        )

    def ask(self, op: str, **kw: Any) -> dict[str, Any]:
        resp: dict[str, Any] = self.broker.handle({"op": op, **kw}, UID)
        return resp

    def secret(self, *items: str) -> dict[str, Any]:
        return self.ask(
            "secret",
            items=[{"item": i, "field": "password"} for i in items],
            env=["X"],
            argv0="/bin/true",
        )

    def audit_lines(self) -> list[dict[str, Any]]:
        path = self.home / "audit.log"
        if not path.exists():
            return []
        return [json.loads(x) for x in path.read_text().splitlines() if x.strip()]

    def limiter_text(self) -> str:
        path = self.home / "secret-limiter.json"
        return path.read_text() if path.exists() else ""


@pytest.fixture
def keeper() -> Any:
    import secret_fixtures as sf  # pylint: disable=import-outside-toplevel

    with sf.sockdir() as d:
        k = sf.FakeSecretkeeper(str(d / "keeper.sock"))
        try:
            yield k
        finally:
            k.close()


def test_secrets_answer_carries_the_gate(tmp_path: Path, keeper: Any) -> None:
    env = _OpsEnv(
        tmp_path,
        keeper.path,
        logins=[_login(flag="true")],
        secrets_items=[_secret()],
        gate=vault.GATE_AGENT_SCRIPT,
    )
    resp = env.ask("secrets")
    assert resp["ok"] and resp["gate"] == "agent_script"
    assert resp["gate_since"] == "2026-10-14T10:00:00Z"
    rows = {r["id"]: r for r in resp["secrets"]}
    assert rows["shop"]["kind"] == "login" and rows["shop"]["gate_code"] == "ok"
    assert rows["api"]["gate_code"] == "no_agent_script" and rows["api"]["refused"]
    _no_sentinel(json.dumps(resp))


def test_collections_answer_reads_collections(tmp_path: Path, keeper: Any) -> None:
    env = _OpsEnv(tmp_path, keeper.path, logins=[], secrets_items=[_secret()])
    resp = env.ask("secrets")
    assert resp["gate"] == "collections"
    assert resp["secrets"][0]["gate_code"] == "no_agent_script"


def test_secret_injects_a_flagged_login_item(tmp_path: Path, keeper: Any) -> None:
    env = _OpsEnv(
        tmp_path,
        keeper.path,
        logins=[_login(flag="true")],
        gate=vault.GATE_AGENT_SCRIPT,
    )
    resp = env.secret("shop")
    assert resp["ok"] and resp["values"] == [PASSWORD]
    _no_sentinel(json.dumps(env.audit_lines()))


def test_a_gate_refusal_carries_its_code_and_is_not_charged(
    tmp_path: Path, keeper: Any
) -> None:
    env = _OpsEnv(
        tmp_path,
        keeper.path,
        logins=[_login()],
        secrets_items=[_secret(flag="maybe")],
        gate=vault.GATE_AGENT_SCRIPT,
    )
    before = env.limiter_text()
    resp = env.secret("shop")
    assert resp["error"] == "refused" and resp["gate_code"] == "no_agent_script"
    assert "script read without agent_script" in resp["detail"]
    resp = env.secret("api")
    assert resp["gate_code"] == "bad_agent_script"
    resp = env.ask("totp", item="shop")
    assert resp["gate_code"] == "no_agent_script"
    assert env.limiter_text() == before
    _no_sentinel(json.dumps(resp))


def test_a_bad_gate_fails_closed_for_the_reads_only(
    tmp_path: Path, keeper: Any
) -> None:
    env = _OpsEnv(
        tmp_path, keeper.path, logins=[], secrets_items=[_secret()], gate="enforce"
    )
    for resp in (env.ask("secrets"), env.secret("api"), env.ask("totp", item="api")):
        assert resp["ok"] is False and resp["error"] == "bad_secret_gate"
    assert env.ask("secrets")["gate"] == "bad_secret_gate"
    assert env.ask("audit", n=5)["ok"]
    assert env.ask("invalidate")["ok"]
    resp = env.ask("secret_done", nonce="0" * 64, exit=0)
    assert resp.get("error") != "bad_secret_gate"


def test_report_mode_writes_one_event_per_issued_item(
    tmp_path: Path, keeper: Any
) -> None:
    a, b = _secret("Api"), _secret("Ok", flag="true", value=secrets.token_hex(16))
    env = _OpsEnv(
        tmp_path, keeper.path, logins=[], secrets_items=[a, b], gate=vault.GATE_REPORT
    )
    resp = env.secret("api", "api", "ok")
    assert resp["ok"]  # report mode serves exactly like collections
    events = [r for r in env.audit_lines() if r.get("op") == "gate_would_refuse"]
    assert len(events) == 1
    assert events[0]["site"] == "api" and events[0]["gate_code"] == "no_agent_script"
    _no_sentinel(json.dumps(env.audit_lines()))


def test_report_mode_failed_issue_writes_no_event(tmp_path: Path) -> None:
    """No secretkeeper: leakcheck_unavailable, so nothing was issued."""
    import secret_fixtures as sf  # pylint: disable=import-outside-toplevel

    env = _OpsEnv(
        tmp_path,
        "",
        logins=[],
        secrets_items=[_secret("Api")],
        gate=vault.GATE_REPORT,
    )
    env.broker = sf.make_broker(env.home, env.path, allow_uid=UID, keeper_sock=None)
    resp = env.secret("api")
    assert resp["error"] == "leakcheck_unavailable"
    assert not [r for r in env.audit_lines() if r.get("op") == "gate_would_refuse"]


def test_collections_mode_writes_no_event(tmp_path: Path, keeper: Any) -> None:
    env = _OpsEnv(tmp_path, keeper.path, logins=[], secrets_items=[_secret("Api")])
    assert env.secret("api")["ok"]
    assert not [r for r in env.audit_lines() if r.get("op") == "gate_would_refuse"]


def test_daemon_script_gate_cli(tmp_path: Path, capsys: Any) -> None:
    from broker import daemon  # pylint: disable=import-outside-toplevel

    path = _write(
        tmp_path / "vault.json",
        [_login(), _login("Bad", site="bad", flag="maybe")],
        [_secret("Api"), _secret("Ok", flag="true")],
    )
    home = tmp_path / "home"
    home.mkdir()
    rc = daemon.main(["-H", str(home), "--dev", "-f", str(path), "-g"])
    out = capsys.readouterr()
    assert rc == 3
    lines = out.out.strip().splitlines()
    assert {ln.split("\t")[2] for ln in lines} == {"api", "bad"}
    _no_sentinel(out.out + out.err)
    rc = daemon.main(["-H", str(home), "--dev", "-f", str(path), "-g", "-j"])
    rows = [json.loads(x) for x in capsys.readouterr().out.splitlines()]
    assert rc == 0 and {r["id"] for r in rows} == {"shop", "bad", "api", "ok"}
    assert {r["kind"] for r in rows} == {"login", "secret"}
    assert daemon.main(["-H", str(home), "--dev", "-f", str(path), "-j"]) == 2


def test_daemon_script_gate_cli_clean(tmp_path: Path, capsys: Any) -> None:
    from broker import daemon  # pylint: disable=import-outside-toplevel

    path = _write(tmp_path / "vault.json", [_login()], [_secret("Ok", flag="true")])
    home = tmp_path / "home"
    home.mkdir()
    assert daemon.main(["-H", str(home), "--dev", "-f", str(path), "-g"]) == 0
    assert "✅" in capsys.readouterr().out


def test_a_secret_named_ok_is_served_not_mistaken_for_an_error(
    tmp_path: Path, keeper: Any
) -> None:
    """Incidental (tp#991): `"ok" in listing` took an item with id `ok` for an
    error answer and returned the whole listing."""
    env = _OpsEnv(tmp_path, keeper.path, logins=[], secrets_items=[_secret("Ok")])
    resp = env.secret("ok")
    assert resp["ok"] is True and resp["values"] == [TOKEN]
    assert env.ask("totp", item="ok")["error"] == "unknown_field"
