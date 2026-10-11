"""WS5 S1 (tp#833): the broker side of account identity.

Vault fields and their refusals (instance, privilege, identity recipe,
same-account, alias), the collection-wide rules (one account per scope per
instance, privilege on multi-account items, a refused item keeps its scope),
the account-tag key, the one-use identity challenge ops, the broker's own
identity proof (fake pages and a real headless Chromium against routed
fixture endpoints), and leaks.

Hermetic: no broker socket, no vault, no network — usernames and passwords
are generated per run, never literals.
"""

from __future__ import annotations

# pylint: disable=protected-access,missing-function-docstring,missing-class-docstring
# pylint: disable=too-many-lines
# pylint: disable=import-error,wrong-import-position,too-few-public-methods
import contextlib
import errno
import hashlib
import importlib.util
import json
import os
import secrets
import sys
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from broker import daemon, identity, identity_ops, limiter, recipes, vault  # noqa: E402

GITLAB = "gitlab.ws5.example"


def _user() -> str:
    """A fresh account name (never a literal in this file)."""
    return f"zz-{secrets.token_hex(5)}"


def _pw() -> str:
    return secrets.token_urlsafe(18)


def _raw(site: str, host: str = GITLAB, user: str | None = None, **fields: str) -> dict:
    """A Bitwarden-shaped login item of the agent-logins collection."""
    base = {
        "agent_site": site,
        "agent_fill_origins": f"https://{host}",
        "agent_check_url": f"https://{host}/dashboard",
        "agent_logged_in_selector": "#me",
        "agent_cookie_hosts": host,
    }
    base.update({f"agent_{k}": v for k, v in fields.items()})
    return {
        "id": f"id-{site}",
        "name": site,
        "login": {"username": user if user is not None else _user(), "password": _pw()},
        "fields": [{"name": k, "value": v} for k, v in base.items()],
    }


def _items(*raws: dict) -> dict[str, vault.SiteItem]:
    return {it.site: it for it in vault.build_items(list(raws))}


def _gitlab_trio(**over: dict[str, str]) -> list[dict]:
    """The tp#833 group, migrated as the plan proposes."""
    spec = {
        "gl-glensk": {"instance": "", "privilege": "user", "alias": "gl"},
        "gl-admin": {"instance": "admin", "privilege": "admin"},
        "gl-test": {"instance": "alt", "privilege": "user"},
    }
    out = []
    for site, fields in spec.items():
        merged = {"identity": "gitlab", **fields, **over.get(site, {})}
        out.append(_raw(site, **merged))
    return out


# ---------------------------------------------------------------------------
# identity.py: normalisation, digest, tag, static names
# ---------------------------------------------------------------------------


def test_normalisation_nfkc_ascii_lower_trim() -> None:
    name = _user()
    assert identity.normalize_identity(f"  {name.upper()}\t\n") == name
    fullwidth = "".join(chr(ord(c) + 0xFEE0) if "!" <= c <= "~" else c for c in name)
    assert identity.normalize_identity(fullwidth) == name  # NFKC folds it
    assert identity.normalize_identity(name + "é") is None  # non-ASCII
    assert identity.normalize_identity("   ") is None
    assert identity.normalize_identity(None) is None
    # \x1c is whitespace for Python's strip() but not for JS trim(): kept
    assert identity.normalize_identity("\x1c" + name) == "\x1c" + name


def test_challenge_digest_is_sha256_of_nonce_bytes_and_name() -> None:
    nonce, name = secrets.token_hex(32), _user()
    want = hashlib.sha256(bytes.fromhex(nonce) + name.encode()).hexdigest()
    assert identity.challenge_digest(nonce, name) == want
    with pytest.raises(ValueError):
        identity.challenge_digest(nonce[:-2], name)
    with pytest.raises(ValueError):
        identity.challenge_digest(nonce, name.upper())  # not normalised


def test_account_tag_is_normalised_and_keyed() -> None:
    key, name = secrets.token_bytes(32), _user()
    tag = identity.account_tag(key, name)
    assert tag and tag == identity.account_tag(key, f" {name.upper()} ")
    assert tag != identity.account_tag(secrets.token_bytes(32), name)
    assert identity.account_tag(key, name + "é") is None
    assert identity.account_tag(b"short", name) is None


def test_static_site_names_match_browser_registry() -> None:
    spec = importlib.util.spec_from_file_location(
        "ws5b_browser", REPO / "bin/browser.py"
    )
    assert spec and spec.loader
    sys.modules["ws5b_browser"] = browser = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(browser)
    names = set()
    for site in browser._sites():
        names |= {site.name, *site.aliases}
    assert names == set(identity.STATIC_SITE_NAMES)


def test_recipes_are_reviewed_and_unconfirmed_ones_absent() -> None:
    assert set(identity.IDENTITIES) == {
        "gitlab",
        "audiobookshelf",
        "navidrome",
        "dsm",
        "authentik",
        "runai",
    }
    for name, recipe in identity.IDENTITIES.items():
        assert recipe.name == name and recipe.path.startswith("/")
        assert recipe.auth in identity.AUTHS
        assert identity.recipe_problem(recipe) == ""
    abs_ = identity.IDENTITIES["audiobookshelf"]
    assert (
        identity.recipe_path(abs_, "https://a.example/audiobookshelf/library")
        == "/audiobookshelf/api/me"
    )
    assert identity.recipe_path(abs_, "https://a.example/other/x") == "/api/me"
    # usable = live-confirmed AND an admin bit: dsm / authentik wait for S4
    assert identity.usable_recipe("gitlab") is identity.IDENTITIES["gitlab"]
    assert identity.usable_recipe("audiobookshelf") is not None
    assert identity.usable_recipe("navidrome") is identity.IDENTITIES["navidrome"]
    # runai (S4c): usable; who may use it is `identity.item_recipe`
    assert identity.usable_recipe("runai") is identity.IDENTITIES["runai"]
    for name in ("dsm", "authentik", "nope", None):
        assert identity.usable_recipe(name) is None


# ---------------------------------------------------------------------------
# vault: per-item fields
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "fields, reason",
    [
        ({"instance": "private"}, "bad agent_instance"),
        ({"instance": "admin", "privilege": "root"}, "bad agent_privilege"),
        ({"identity": "nope", "privilege": "user"}, "bad agent_identity"),
        ({"identity": "gitlab"}, "agent_identity needs agent_privilege"),
        ({"identity": "dsm", "privilege": "readonly"}, "not live-confirmed"),
        ({"identity": "authentik", "privilege": "user"}, "not live-confirmed"),
        ({"same_account_as": "Bad Id!"}, "bad agent_same_account_as"),
        ({"same_account_as": "solo"}, "bad agent_same_account_as"),
        ({"alias": "cscs"}, "collides with a site name"),
        ({"alias": "solo"}, "collides with a site name"),
        ({"alias": "Not A Slug"}, "bad agent_alias"),
    ],
)
def test_field_refusals(fields: dict[str, str], reason: str) -> None:
    it = _items(_raw("solo", **fields))["solo"]
    assert it.refused and reason in it.refused
    assert it.cookie_hosts == [GITLAB]  # refused WITH its scope


def test_identity_needs_a_login_username() -> None:
    it = _items(_raw("solo", user="", identity="gitlab", privilege="user"))["solo"]
    assert it.refused and "needs the login's username" in it.refused


def test_identity_items_still_get_alias_and_same_account_checks() -> None:
    name = _user()
    gl = {"identity": "gitlab", "privilege": "user"}
    it = _items(_raw("idx", user=name, alias=f"x-{name}", **gl))["idx"]
    assert it.refused and "must not reveal" in it.refused
    it = _items(_raw("idx", alias="slack", **gl))["idx"]
    assert it.refused and "collides with a site name" in it.refused
    it = _items(_raw("idx", same_account_as="idx", **gl))["idx"]
    assert it.refused and "bad agent_same_account_as" in it.refused
    assert _items(_raw("idx", alias="gl", **gl))["idx"].refused is None


def test_alias_revealing_the_account_is_refused() -> None:
    name = _user()
    it = _items(_raw("solo", user=f"{name}@corp.example", alias=f"x-{name}"))["solo"]
    assert it.refused and "must not reveal" in it.refused


def test_fields_reach_the_public_view() -> None:
    items = _items(*_gitlab_trio())
    glensk = items["gl-glensk"]
    assert glensk.refused is None
    view = glensk.public()
    assert view["instance"] == "" and view["privilege"] == "user"
    assert view["identity"] == "gitlab" and view["alias"] == "gl"
    assert view["same_account_as"] == [] and view["identity_v"] == 1
    assert view["multi_account"] is True
    assert items["gl-admin"].public()["instance"] == "admin"


# ---------------------------------------------------------------------------
# vault: collection-wide rules
# ---------------------------------------------------------------------------


def test_tp833_trio_in_three_instances_is_accepted_and_multi_account() -> None:
    items = _items(*_gitlab_trio())
    assert all(it.refused is None for it in items.values())
    assert all(it.multi_account for it in items.values())
    # the client's own computation agrees (refused or not, every instance)
    views = [it.public() for it in items.values()]
    assert set(identity.scope_conflicts(views)) == set(items)


def test_in_instance_conflict_refuses_the_later_item() -> None:
    items = _items(*_gitlab_trio(**{"gl-test": {"instance": ""}}))
    assert items["gl-glensk"].refused is None
    late = items["gl-test"]
    assert late.refused and "scope conflict in instance default" in late.refused
    assert "gl-glensk" in late.refused and "agent_instance" in late.refused
    # the refused item keeps its scope and its flag: the client still sees
    # gl-glensk as multi-account
    assert late.cookie_hosts == [GITLAB] and late.multi_account
    views = [it.public() for it in items.values()]
    assert "gl-glensk" in identity.scope_conflicts(views)


def test_parent_domain_overlap_conflicts_inside_an_instance() -> None:
    items = _items(
        _raw("dock-a", host="docker.example", privilege="user"),
        _raw("dock-b", host="app.docker.example", privilege="user"),
    )
    assert items["dock-a"].refused is None
    assert items["dock-b"].refused and "scope conflict" in items["dock-b"].refused


def test_multi_account_item_needs_a_privilege() -> None:
    items = _items(
        _raw("mm-a", instance="", privilege="user"),
        _raw("mm-b", instance="admin"),
    )
    assert items["mm-a"].refused is None
    assert items["mm-b"].refused and "set agent_privilege" in items["mm-b"].refused


def test_single_account_items_need_nothing() -> None:
    items = _items(_raw("alone-a", host="a.example"), _raw("alone-b", host="b.example"))
    assert all(it.refused is None and not it.multi_account for it in items.values())


def test_same_account_must_be_symmetric() -> None:
    one_sided = _items(
        _raw("sa-a", same_account_as="sa-b", privilege="user"),
        _raw("sa-b", instance="alt", privilege="user"),
    )
    assert (
        one_sided["sa-a"].refused and "name this one back" in one_sided["sa-a"].refused
    )
    assert one_sided["sa-a"].same_account_as == ""  # dropped: fail closed
    name = _user()
    both = _items(
        _raw("sa-a", user=name, same_account_as="sa-b"),
        _raw("sa-b", user=name, same_account_as="sa-a"),
    )
    assert all(it.refused is None and not it.multi_account for it in both.values())


def test_alias_collisions_across_items() -> None:
    items = _items(
        _raw("al-a", host="a.example", alias="al-b"),
        _raw("al-b", host="b.example"),
        _raw("al-c", host="c.example", alias="dup"),
        _raw("al-d", host="d.example", alias="dup"),
    )
    assert items["al-a"].refused and "collides with a site id" in items["al-a"].refused
    assert items["al-c"].refused and items["al-d"].refused
    assert "used by another item" in str(items["al-c"].refused)


def test_item_refused_before_its_scope_still_makes_siblings_multi_account() -> None:
    items = _items(
        _raw("pre-a", privilege="user"),
        _raw("pre-b", check_url="ftp://nope", instance="alt"),  # refused at parse
    )
    assert items["pre-b"].refused and GITLAB in items["pre-b"].cookie_hosts
    assert items["pre-a"].multi_account and items["pre-a"].refused is None


def test_refused_scope_never_uses_check_or_login_url_hosts() -> None:
    idp = "idp.ws5.example"
    items = _items(
        _raw("on-idp", host=idp, privilege="user"),  # an item living on the IdP
        # refused at parse; its check/login URLs point at the IdP, its own
        # cookie host and fill origin do not
        _raw(
            "app",
            host="app.ws5.example",
            check_url=f"https://{idp}/x",
            login_url=f"https://{idp}/login",
            fresh_login="maybe",
        ),
    )
    assert items["app"].refused and items["app"].cookie_hosts == ["app.ws5.example"]
    assert not items["on-idp"].multi_account and items["on-idp"].refused is None


def test_find_refuses_a_secret_for_a_conflict_refused_item() -> None:
    raws = _gitlab_trio(**{"gl-test": {"instance": ""}})
    with pytest.raises(vault.VaultError, match="refused"):
        vault._find(raws, "gl-test", dev=False)


# ---------------------------------------------------------------------------
# account tag key and same-account tags
# ---------------------------------------------------------------------------


def test_tag_key_created_0600_and_kept(tmp_path: Path) -> None:
    path = tmp_path / "home" / identity_ops.TAG_KEY_NAME
    key = identity_ops.load_tag_key(path)
    st = path.stat()
    assert len(key) == 32 and st.st_mode & 0o777 == 0o600
    assert st.st_uid == os.geteuid()
    assert identity_ops.load_tag_key(path) == key
    assert [p.name for p in path.parent.iterdir()] == [path.name]  # no temp left


def test_tag_key_bad_mode_symlink_length(tmp_path: Path) -> None:
    path = tmp_path / identity_ops.TAG_KEY_NAME
    identity_ops.load_tag_key(path)
    path.chmod(0o640)
    with pytest.raises(identity_ops.TagKeyError, match="mode"):
        identity_ops.load_tag_key(path)
    path.unlink()
    path.write_bytes(b"x" * 8)
    path.chmod(0o600)
    with pytest.raises(identity_ops.TagKeyError, match="length"):
        identity_ops.load_tag_key(path)
    path.unlink()
    real = tmp_path / "real"
    real.write_bytes(secrets.token_bytes(32))
    real.chmod(0o600)
    path.symlink_to(real)
    with pytest.raises(identity_ops.TagKeyError):
        identity_ops.load_tag_key(path)


def _pair(user_a: str, user_b: str) -> list[vault.SiteItem]:
    return vault.build_items(
        [
            _raw("tp-a", user=user_a, same_account_as="tp-b"),
            _raw("tp-b", user=user_b, same_account_as="tp-a"),
        ]
    )


def test_apply_tags_keeps_equal_and_refuses_unequal_pairs(tmp_path: Path) -> None:
    ops = identity_ops.IdentityOps(tmp_path)
    name = _user()
    kept = ops.apply_tags(_pair(name, f" {name.upper()} "))
    assert all(it.refused is None for it in kept)
    bad = {it.site: it for it in ops.apply_tags(_pair(name, _user()))}
    for it in bad.values():
        assert it.refused and "same account name" in it.refused
        assert it.same_account_as == "" and it.multi_account  # now they conflict


def test_apply_tags_without_a_usable_key_refuses_pairs(tmp_path: Path) -> None:
    ops = identity_ops.IdentityOps(tmp_path)
    (tmp_path / identity_ops.TAG_KEY_NAME).write_bytes(b"short")
    name = _user()
    out = ops.apply_tags(_pair(name, name))
    assert all(it.refused and "tag key unavailable" in it.refused for it in out)


# ---------------------------------------------------------------------------
# the broker: ops over its handle()
# ---------------------------------------------------------------------------

PID = 4242


class _Vault:
    def __init__(self, items: list[vault.SiteItem]) -> None:
        self._items = items
        self.secret_calls = 0

    def items(self) -> list[vault.SiteItem]:
        return self._items

    def secret(self, site: str) -> vault.Secret:
        self.secret_calls += 1
        it = next(i for i in self._items if i.site == site)
        return vault.Secret(username=it.account_name, password=_pw())


class _Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


class _NoRunner:
    def __init__(self) -> None:
        self.calls = 0

    def __call__(self, item: Any, get_secret: Any) -> dict[str, Any]:
        self.calls += 1
        raise AssertionError("the runner must not be reached")


def _broker(
    tmp_path: Path, items: list[vault.SiteItem], runner: Any = None, clock: Any = None
) -> Any:
    clock = clock or _Clock()
    lim = limiter.Limiter(
        tmp_path / "l.json", cooldown_s=1800, min_interval_s=0, per_hour=50, per_day=100
    )
    brk = daemon.Broker(
        _Vault(items),  # type: ignore[arg-type]
        lim,
        tmp_path / "home",
        runner=runner or _NoRunner(),
        clock=clock,
    )
    brk.test_clock = clock  # type: ignore[attr-defined]
    return brk


def _trio(tmp_path: Path) -> tuple[list[vault.SiteItem], dict[str, str]]:
    users = {"gl-glensk": _user(), "gl-admin": _user(), "gl-test": _user()}
    raws = _gitlab_trio()
    for raw in raws:
        raw["login"]["username"] = users[raw["name"]]
    del tmp_path
    return vault.build_items(raws), users


@contextlib.contextmanager
def _trio_broker(tmp_path: Path) -> Iterator[tuple[Any, dict[str, str]]]:
    items, users = _trio(tmp_path)
    yield _broker(tmp_path, items), users


INSTANCE = {"gl-glensk": "", "gl-admin": "admin", "gl-test": "alt"}


def _ask(brk: Any, site: str, pid: int | None = PID, **extra: Any) -> Any:
    req = {"op": "identity_challenge", "site": site, "instance": INSTANCE.get(site, "")}
    req.update(extra)
    return brk.handle(req, 501, pid)


def _answer_digest(nonce: str, name: str) -> str:
    """What the page computes (independent of identity.challenge_digest)."""
    return hashlib.sha256(bytes.fromhex(nonce) + name.lower().encode()).hexdigest()


def _reply(brk: Any, ch: dict, name: str, pid: int = PID) -> Any:
    req = {
        "op": "identity_answer",
        "challenge_id": ch["challenge_id"],
        "digest": _answer_digest(ch["nonce"], name),
    }
    return brk.handle(req, 501, pid)


def _audit(tmp_path: Path) -> list[dict]:
    text = (tmp_path / "home" / "audit.log").read_text()
    return [json.loads(line) for line in text.splitlines()]


def test_sites_view_advertises_identity_v_and_no_username(tmp_path: Path) -> None:
    with _trio_broker(tmp_path) as (brk, users):
        resp = brk.handle({"op": "sites"}, 501)
        assert resp["ok"] and resp["identity_v"] == 1
        assert all(e["identity_v"] == 1 for e in resp["sites"])
        dumped = json.dumps(resp)
        assert not any(u in dumped for u in users.values())


def test_same_account_is_not_a_socket_op(tmp_path: Path) -> None:
    with _trio_broker(tmp_path) as (brk, _users):
        resp = brk.handle({"op": "same_account", "sites": ["gl-admin", "gl-test"]}, 501)
        assert resp["ok"] is False and resp["error"] == "bad_request"
    assert "same_account" not in identity_ops.IDENTITY_OPS


def test_challenge_match(tmp_path: Path) -> None:
    with _trio_broker(tmp_path) as (brk, users):
        ch = _ask(brk, "gl-glensk")
        assert ch["ok"] and ch["identity"] == "gitlab" and ch["privilege"] == "user"
        assert len(ch["nonce"]) == 64 and ch["ttl_s"] == 60
        assert _reply(brk, ch, users["gl-glensk"]) == {"ok": True, "result": "match"}


def test_challenge_expired_reused_wrong_pid(tmp_path: Path) -> None:
    with _trio_broker(tmp_path) as (brk, users):
        name = users["gl-test"]
        ch = _ask(brk, "gl-test")
        brk.test_clock.now += identity_ops.CHALLENGE_TTL_S + 1
        assert _reply(brk, ch, name)["result"] == "expired"
        ch = _ask(brk, "gl-test")
        assert _reply(brk, ch, name)["result"] == "match"
        assert _reply(brk, ch, name)["result"] == "expired"  # one use
        ch = _ask(brk, "gl-test")
        assert _reply(brk, ch, name, pid=PID + 1)["result"] == "expired"
        assert _reply(brk, ch, name)["result"] == "expired"  # consumed by the wrong pid


def test_challenge_caps_per_site_and_per_pid(tmp_path: Path) -> None:
    with _trio_broker(tmp_path) as (brk, _users):
        for _ in range(identity_ops.PER_SITE_PER_MIN):
            assert _ask(brk, "gl-test", pid=PID + _)["ok"]
        assert _ask(brk, "gl-test", pid=PID + 99)["error"] == "rate_limited"
        brk.test_clock.now += 61
        assert _ask(brk, "gl-test")["ok"]
    raws = [
        _raw(f"rc-{n}", host=f"h{n}.example", identity="gitlab", privilege="user")
        for n in range(identity_ops.PER_PID_PER_MIN + 1)
    ]
    brk = _broker(tmp_path / "b2", vault.build_items(raws))
    got = [_ask(brk, f"rc-{n}") for n in range(identity_ops.PER_PID_PER_MIN + 1)]
    assert all(r["ok"] for r in got[:-1]) and got[-1]["error"] == "rate_limited"
    assert _ask(brk, f"rc-{identity_ops.PER_PID_PER_MIN}", pid=PID + 1)["ok"]


def test_challenge_runs_the_login_gates(tmp_path: Path) -> None:
    items = vault.build_items(
        [
            *_gitlab_trio(),
            _raw("plain", host="plain.example"),
            _raw("nosent", host="nosent.example", logged_in_selector=""),
            # gl-glensk's scope in its instance; the later site id is refused
            _raw("zz-conflict", privilege="user"),
        ]
    )
    brk = _broker(tmp_path, items)
    assert _ask(brk, "nope")["error"] == "unknown_site"
    assert _ask(brk, "plain")["error"] == "identity_unproven"
    assert _ask(brk, "nosent")["error"] == "needs_sentinel"
    assert _ask(brk, "zz-conflict")["error"] == "refused"
    assert _ask(brk, "gl-glensk", pid=None)["error"] == "bad_request"
    assert _ask(brk, "gl-test", instance="")["error"] == "wrong_instance"
    assert _ask(brk, "gl-test", instance=None)["error"] == "wrong_instance"
    # a limiter block refuses like it refuses a login
    grant = brk.limiter.reserve_site("gl-admin", brk.test_clock())
    brk.limiter.mark_submitted(grant)
    brk.limiter.finish(grant, "unknown", brk.test_clock())
    resp = _ask(brk, "gl-admin")
    assert resp["error"] == "rate_limited" and resp["limit"]["state"] == "cooldown"
    brk.test_clock.now += 4000  # the cooldown is over, the streak is not
    resp = _ask(brk, "gl-admin")
    assert resp["error"] == "rate_limited" and resp["limit"]["state"] == "quarantined"
    ch = _ask(brk, "gl-glensk")
    for bad in (["a" * 64, "b" * 64], "A" * 64, "zz", None):
        resp = brk.handle(
            {
                "op": "identity_answer",
                "challenge_id": ch["challenge_id"],
                "digest": bad,
            },
            501,
            PID,
        )
        assert resp["ok"] is False and resp["error"] == "bad_request"
        ch = _ask(brk, "gl-glensk")


def test_non_ascii_account_name_is_refused_at_validation(tmp_path: Path) -> None:
    raw = _raw("na", user=_user() + "ü", identity="gitlab", privilege="user")
    items = vault.build_items([raw])
    assert items[0].refused and "plain-ASCII login username" in items[0].refused
    brk = _broker(tmp_path, items)
    assert _ask(brk, "na")["error"] == "refused"  # no per-challenge answer


def test_email_vault_username_is_refused_for_username_recipes() -> None:
    mail = f"{_user()}@corp.ws5.example"
    assert identity.identity_form(mail) == "email"
    assert identity.identity_form(_user()) == "username"
    assert identity.identity_form(_user() + "é") is None
    for name, recipe in identity.IDENTITIES.items():
        assert recipe.forms, name  # every recipe declares what it compares
    it = _items(_raw("gm", user=mail, identity="gitlab", privilege="user"))["gm"]
    assert it.refused == (
        "the vault holds an email; the gitlab identity proof compares the username"
    )
    assert mail not in json.dumps(it.public())


def test_ops_doc_names_no_same_account_op() -> None:
    text = Path(identity.__file__).read_text(encoding="utf-8")
    assert "`identity_answer` / `same_account`" not in text


def test_a_burst_of_open_challenges_yields_at_most_one_verdict(
    tmp_path: Path,
) -> None:
    with _trio_broker(tmp_path) as (brk, users):
        chs = [_ask(brk, "gl-glensk") for _ in range(identity_ops.PER_SITE_PER_MIN)]
        assert all(ch["ok"] for ch in chs)
        guesses = [_user() for _ in chs]
        guesses[3] = users["gl-glensk"]  # a later one would have matched
        results = [_reply(brk, ch, g)["result"] for ch, g in zip(chs, guesses)]
        verdicts = [r for r in results if r != "expired"]
        assert verdicts == ["mismatch"] and results[0] == "mismatch"


def test_no_verdict_while_the_guard_blocks(tmp_path: Path) -> None:
    with _trio_broker(tmp_path) as (brk, users):
        ch = _ask(brk, "gl-test")
        guard = brk.identity_ops.guard
        for n in range(identity_ops.GUARD_QUARANTINE_AFTER):
            guard.record_mismatch("gl-test", float(n))
        # even the RIGHT answer to a challenge issued before gets no verdict
        assert _reply(brk, ch, users["gl-test"])["result"] == "expired"


def _disk_full(*_a: Any, **_k: Any) -> None:
    raise OSError(errno.ENOSPC, "No space left on device")


def test_no_challenge_while_the_guard_cannot_be_written(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with _trio_broker(tmp_path) as (brk, _users):
        monkeypatch.setattr(identity_ops, "write_json_atomic", _disk_full)
        for site in ("gl-glensk", "gl-test", "gl-admin"):
            assert _ask(brk, site)["error"] == "identity_unwritable"
        monkeypatch.undo()
        assert _ask(brk, "gl-test")["ok"]
        assert not list((tmp_path / "home").glob("*.probe"))


def test_a_mismatch_that_cannot_be_recorded_blocks_the_site_in_memory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with _trio_broker(tmp_path) as (brk, users):
        first, second = _ask(brk, "gl-glensk"), _ask(brk, "gl-glensk")
        monkeypatch.setattr(identity_ops, "write_json_atomic", _disk_full)
        resp = _reply(brk, first, users["gl-admin"])  # a wrong guess
        assert resp["ok"] is False and resp["error"] == "internal"
        monkeypatch.undo()  # the disk is writable again
        # no verdict for the other open one, no new challenge, until a restart
        assert _reply(brk, second, users["gl-glensk"])["result"] == "expired"
        assert _ask(brk, "gl-glensk")["error"] == "identity_blocked"
        assert _ask(brk, "gl-test")["ok"]  # other sites unaffected
        guards = [r for r in _audit(tmp_path) if r["op"] == "identity_guard"]
        assert [(r["site"], r["result"]) for r in guards] == [
            ("gl-glensk", "unwritable")
        ]


def test_mismatch_cooldowns_escalate_then_quarantine(tmp_path: Path) -> None:
    with _trio_broker(tmp_path) as (brk, users):
        clock = brk.test_clock
        ch = _ask(brk, "gl-glensk")
        assert _reply(brk, ch, users["gl-admin"])["result"] == "mismatch"
        resp = _ask(brk, "gl-glensk")
        assert resp["error"] == "identity_cooldown"
        clock.now += 3599
        assert _ask(brk, "gl-glensk")["error"] == "identity_cooldown"
        clock.now += 2
        ch = _ask(brk, "gl-glensk")
        assert _reply(brk, ch, users["gl-test"])["result"] == "mismatch"
        clock.now += 3 * 3600
        assert _ask(brk, "gl-glensk")["error"] == "identity_cooldown"  # 6 h now
        clock.now += 3 * 3600 + 1
        # the guard is persisted: a restarted broker sees it too
        brk2 = _broker(tmp_path, brk.vault.items(), clock=clock)
        ch = _ask(brk2, "gl-glensk")
        assert _reply(brk2, ch, users["gl-admin"])["result"] == "mismatch"
        clock.now += 30 * 86400
        assert _ask(brk2, "gl-glensk")["error"] == "identity_quarantined"
        assert _ask(brk2, "gl-admin")["ok"]  # other sites unaffected
        guards = [r for r in _audit(tmp_path) if r["op"] == "identity_guard"]
        assert [r["result"] for r in guards] == ["cooldown", "cooldown", "quarantined"]
        assert all(r["site"] == "gl-glensk" for r in guards)
        # the root reset (install.sh -r SITE) lifts it
        home = str(tmp_path / "home")
        assert daemon.main(["-d", "-H", home, "-r", "gl-glensk"]) == 0
        assert _ask(brk2, "gl-glensk")["ok"]


def test_old_mismatches_leave_the_window(tmp_path: Path) -> None:
    guard = identity_ops.IdentityGuard(tmp_path)
    assert guard.record_mismatch("s", 0.0) == "cooldown"
    # the first left the 7-day window: this is again a FIRST mismatch (1 h)
    assert guard.record_mismatch("s", 8 * 86400.0) == "cooldown"
    assert guard.denial("s", 8 * 86400.0 + 3599) is not None
    assert guard.denial("s", 8 * 86400.0 + 3601) is None
    (tmp_path / identity_ops.GUARD_NAME).write_text("{not json")
    denied = guard.denial("s", 0.0)
    assert denied is not None and denied[0] == "identity_unreadable"  # fail closed


def test_audit_carries_no_nonce_digest_or_name(tmp_path: Path) -> None:
    with _trio_broker(tmp_path) as (brk, users):
        ch = _ask(brk, "gl-admin")
        digest = _answer_digest(ch["nonce"], users["gl-admin"])
        brk.handle(
            {
                "op": "identity_answer",
                "challenge_id": ch["challenge_id"],
                "digest": digest,
            },
            501,
            PID,
        )
        ch2 = _ask(brk, "gl-test")
        _reply(brk, ch2, users["gl-glensk"])  # a mismatch
        audit = (tmp_path / "home" / "audit.log").read_text()
        for secret in (ch["nonce"], digest, ch["challenge_id"], *users.values()):
            assert secret not in audit
        answers = [r for r in _audit(tmp_path) if r["op"] == "identity_answer"]
        assert [(r["site"], r["answer"]) for r in answers] == [
            ("gl-admin", "match"),
            ("gl-test", "mismatch"),
        ]


def test_login_of_a_multi_account_item_without_recipe_is_refused(
    tmp_path: Path,
) -> None:
    items = vault.build_items(
        [
            _raw("nr-a", privilege="user"),
            _raw("nr-b", instance="admin", privilege="admin"),
        ]
    )
    runner = _NoRunner()
    brk = _broker(tmp_path, items, runner)
    resp = brk.handle({"op": "login", "site": "nr-a"}, 501)
    assert resp["error"] == "identity_unproven" and resp["phase"] == "precheck"
    assert runner.calls == 0 and brk.vault.secret_calls == 0


def test_precheck_refuses_an_unusable_recipe_even_if_the_vault_let_it_through(
    tmp_path: Path,
) -> None:
    item = vault.replace(
        _items(_raw("solo", host="solo.example"))["solo"],
        identity="dsm",
        privilege="readonly",
    )
    runner = _NoRunner()
    brk = _broker(tmp_path, [item], runner)
    resp = brk.handle({"op": "login", "site": "solo"}, 501)
    assert resp["error"] == "identity_unproven" and runner.calls == 0
    assert _ask(brk, "solo")["error"] == "identity_unproven"


def test_identity_mismatch_after_a_password_is_its_own_outcome(tmp_path: Path) -> None:
    class _Wrong:
        last_diag: dict = {}

        def __call__(self, item: Any, get_secret: Any) -> dict:
            get_secret()
            get_secret.attempt.entered()
            get_secret.attempt.mark_submitted()
            raise daemon.IdentityMismatch(
                identity.WRONG_ACCOUNT, submitted=True, auth_proven=True
            )

    items, users = _trio(tmp_path)
    brk = _broker(tmp_path, items, _Wrong())
    # one unresolved earlier password failure: neither cleared nor escalated
    grant = brk.limiter.reserve_site("gl-glensk", 0.0)
    brk.limiter.mark_submitted(grant)
    brk.limiter.finish(grant, "unknown", 0.0)
    brk.test_clock.now = 5000.0  # past that cooldown
    resp = brk.handle({"op": "login", "site": "gl-glensk"}, 501)
    assert resp["ok"] is False and resp["error"] == "wrong_account"
    assert resp["phase"] == "broker-proof" and resp["submitted"] is True
    assert "bundle" not in resp
    assert not any(u in json.dumps(resp) for u in users.values())
    state = json.loads((tmp_path / "l.json").read_text())["sites"]["gl-glensk"]
    assert [a[1] for a in state["attempts"]] == ["unknown", "identity_mismatch"]
    assert state["consecutive"] == 1 and float(state["cooldown_until"]) < 5000.0


def test_three_identity_mismatches_a_day_set_a_cooldown(tmp_path: Path) -> None:
    class _Wrong:
        last_diag: dict = {}

        def __call__(self, item: Any, get_secret: Any) -> dict:
            get_secret()
            get_secret.attempt.entered()
            get_secret.attempt.mark_submitted()
            raise daemon.IdentityMismatch(
                identity.WRONG_ACCOUNT, submitted=True, auth_proven=True
            )

    items, _users = _trio(tmp_path)
    brk = _broker(tmp_path, items, _Wrong())
    for n in range(limiter.IDENTITY_MISMATCH_MAX):
        brk.test_clock.now = 1000.0 + n * 3600
        resp = brk.handle({"op": "login", "site": "gl-glensk"}, 501)
        assert resp["error"] == "wrong_account"
    state = json.loads((tmp_path / "l.json").read_text())["sites"]["gl-glensk"]
    assert state.get("consecutive", 0) == 0  # never the bad-password streak
    resp = brk.handle({"op": "login", "site": "gl-glensk"}, 501)
    assert resp["error"] == "rate_limited" and resp["limit"]["state"] == "cooldown"
    # two in a day (the third a day later) do not
    brk2 = _broker(tmp_path / "b2", items, _Wrong())
    for when in (0.0, 3600.0, 3600.0 + 86400.0 + 1):
        brk2.test_clock.now = when
        assert brk2.handle({"op": "login", "site": "gl-glensk"}, 501)["error"] == (
            "wrong_account"
        )


def test_five_identity_mismatches_in_a_week_hard_block(tmp_path: Path) -> None:
    class _Wrong:
        last_diag: dict = {}

        def __call__(self, item: Any, get_secret: Any) -> dict:
            get_secret()
            get_secret.attempt.entered()
            get_secret.attempt.mark_submitted()
            raise daemon.IdentityMismatch(
                identity.WRONG_ACCOUNT, submitted=True, auth_proven=True
            )

    items, _users = _trio(tmp_path)
    brk = _broker(tmp_path, items, _Wrong())
    day = 86400.0
    for n in range(limiter.IDENTITY_MISMATCH_BLOCK):
        brk.test_clock.now = 1000.0 + n * 1.2 * day  # never 3 within a day
        assert brk.handle({"op": "login", "site": "gl-glensk"}, 501)["error"] == (
            "wrong_account"
        )
    brk.test_clock.now += 30 * day  # long after any cooldown
    resp = brk.handle({"op": "login", "site": "gl-glensk"}, 501)
    assert resp["error"] == "rate_limited" and resp["limit"]["state"] == "locked"
    assert "another account" in resp["detail"]
    brk.limiter.reset("gl-glensk")  # what install.sh -r does
    assert brk.handle({"op": "login", "site": "gl-glensk"}, 501)["error"] == (
        "wrong_account"
    )


def test_same_account_cli(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    name = _user()
    fixture = tmp_path / "items.json"
    fixture.write_text(
        json.dumps(
            {
                "logins": [
                    _raw("sx-a", user=name, privilege="user"),
                    _raw("sx-b", user=name.upper(), instance="alt", privilege="user"),
                    _raw("sx-c", user=_user(), instance="admin", privilege="admin"),
                    _raw("sx-d", host="d.example", user=""),
                ]
            }
        )
    )
    home = tmp_path / "home"

    def cli(a: str, b: str) -> str:
        argv = ["-d", "-f", str(fixture), "-H", str(home), "-S", a, b]
        assert daemon.main(argv) == 0
        return capsys.readouterr().out.strip()

    assert cli("sx-a", "sx-b") == "same"
    assert cli("sx-a", "sx-c") == "different"
    assert cli("sx-a", "sx-d") == "unknown"  # no username
    assert cli("sx-a", "nope") == "unknown"
    assert daemon.main(["-d", "-f", str(fixture), "-H", str(home), "-S", "a", "a"]) == 2
    audit = (home / "audit.log").read_text()
    assert name not in audit and name.upper() not in audit
    lines = [json.loads(line) for line in audit.splitlines()]
    assert [r["result"] for r in lines] == ["same", "different", "unknown", "unknown"]
    assert all(r["op"] == "same_account_cli" for r in lines)


def test_home_problem(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    assert daemon._home_problem(home) == ""
    home.chmod(0o750)
    assert "want 0700" in daemon._home_problem(home)
    assert "not a directory" in daemon._home_problem(fixture_file(tmp_path))


def fixture_file(tmp_path: Path) -> Path:
    path = tmp_path / "plain-file"
    path.write_text("")
    return path


# ---------------------------------------------------------------------------
# the broker's own proof (fake pages over a fake CDP session)
# ---------------------------------------------------------------------------


class _Session:
    """The CDP calls ``daemon.evaluate_isolated`` makes, answered like the
    real recipe would answer in the isolated world."""

    def __init__(self, page: _Page) -> None:
        self.page = page

    def send(self, method: str, params: Any = None) -> Any:
        self.page.calls.append(method)
        if method == "Page.getFrameTree":
            return {"frameTree": {"frame": {"id": "F1"}}}
        if method == "Page.createIsolatedWorld":
            assert params["frameId"] == "F1"
            return {"executionContextId": 7}
        if method == "Runtime.evaluate":
            assert params["contextId"] == 7
            return {"result": {"objectId": "G7"}}
        if method == "Network.setBypassServiceWorker":
            self.page.bypass.append(params["bypass"])
            return {}
        if method == "Runtime.callFunctionOn":
            assert params["objectId"] == "G7"
            assert params["functionDeclaration"] == identity.RECIPE_JS
            return {
                "result": {"value": self.page.answer(params["arguments"][0]["value"])}
            }
        return {}

    def detach(self) -> None:
        self.page.calls.append("detach")


class _Page:  # pylint: disable=too-many-instance-attributes
    """Answers RECIPE_JS for the next of `names` (an account name, or a bare
    state) with `admin`; never through ``page.evaluate`` (the main world)."""

    def __init__(self, *names: str | None, admin: Any = False, state: str = "found"):
        self.names = list(names)
        self.admin, self.state = admin, state
        self.url = f"https://{GITLAB}/dashboard"
        self.args: list[dict] = []
        self.calls: list[str] = []
        self.bypass: list[bool] = []
        self.context = self

    def new_cdp_session(self, page: Any) -> _Session:
        assert page is self
        return _Session(self)

    def evaluate(self, *_a: Any) -> Any:
        raise AssertionError("the recipe never runs in the main world")

    def answer(self, arg: dict) -> dict:
        self.args.append(arg)
        name = self.names.pop(0) if len(self.names) > 1 else self.names[0]
        if self.state != "found" or name is None:
            return {"state": self.state}
        return {
            "state": "found",
            "digest": _answer_digest(arg["nonce"], name),
            "admin": self.admin,
        }


def _trio_item(site: str, name: str) -> vault.SiteItem:
    raws = _gitlab_trio()
    for raw in raws:
        if raw["name"] == site:
            raw["login"]["username"] = name
    return {it.site: it for it in vault.build_items(raws)}[site]


@pytest.mark.parametrize(
    "shown, admin, state, want",
    [
        ("self", False, "found", "ok"),
        ("other", False, "found", "reset"),
        ("self", None, "found", "identity_indeterminate"),  # no guess-login
        (None, None, "indeterminate", "identity_indeterminate"),
        (None, None, "logged_out", "login"),
        ("self", True, "found", "privilege_mismatch"),  # a login cannot fix it
    ],
)
def test_identity_reuse_verdicts(
    tmp_path: Path, shown: str | None, admin: Any, state: str, want: str
) -> None:
    name = _user()
    item = _trio_item("gl-glensk", name)
    runner = daemon.PlaywrightRunner(tmp_path, dev=True)
    page = _Page(
        {"self": name, "other": _user(), None: None}[shown], admin=admin, state=state
    )
    if want in ("ok", "reset", "login"):
        assert runner._identity_reuse(page, item) == want
    else:
        with pytest.raises(daemon.IdentityMismatch) as err:
            runner._identity_reuse(page, item)
        assert err.value.code == want and not err.value.auth_proven
        assert not err.value.submitted
    arg = page.args[0]
    assert arg["origin"] == f"https://{GITLAB}" and arg["path"] == "/api/v4/user"
    assert len(arg["nonce"]) == 64 and name not in json.dumps(arg)
    # the bypass is this session's own; never reset on a shared target
    assert page.bypass == [True] and page.calls[-1] == "detach"


@pytest.mark.parametrize(
    "shown, admin, state, code",
    [
        ("other", False, "found", "wrong_account"),
        ("self", True, "found", "privilege_mismatch"),
        ("self", None, "found", "identity_indeterminate"),
        (None, None, "logged_out", "login_failed"),
    ],
)
def test_identity_after_login_raises_auth_proven(
    tmp_path: Path, shown: str | None, admin: Any, state: str, code: str
) -> None:
    name = _user()
    item = _trio_item("gl-glensk", name)
    runner = daemon.PlaywrightRunner(tmp_path, dev=True)
    page = _Page(
        {"self": name, "other": _user(), None: None}[shown], admin=admin, state=state
    )
    attempt = recipes.AttemptController()
    attempt.mark_submitted()
    with pytest.raises(daemon.IdentityMismatch) as err:
        runner._identity_after_login(page, item, name, attempt)
    assert err.value.code == code and err.value.phase == "broker-proof"
    assert err.value.auth_proven and err.value.submitted
    assert name not in err.value.detail


def test_a_failing_isolated_world_is_indeterminate(tmp_path: Path) -> None:
    class _Broken(_Page):
        def new_cdp_session(self, page: Any) -> _Session:
            raise RuntimeError("no CDP")

    item = _trio_item("gl-glensk", _user())
    runner = daemon.PlaywrightRunner(tmp_path, dev=True)
    with pytest.raises(daemon.IdentityMismatch) as err:
        runner._identity_reuse(_Broken(item.account_name), item)
    assert err.value.code == "identity_indeterminate"


def test_identity_check_skips_items_without_a_recipe(tmp_path: Path) -> None:
    item = _items(_raw("plain", host="plain.example"))["plain"]
    page = _Page(None, state="indeterminate")
    runner = daemon.PlaywrightRunner(tmp_path, dev=True)
    assert runner._identity_reuse(page, item) == "ok" and not page.args


class _Ctx:
    def __init__(self, page: Any) -> None:
        self.pages = [page]
        self.cleared = 0

    def cookies(self) -> list:
        return []


class _Gate:
    """A get_secret: reserves (counts), hands the item's secret."""

    def __init__(self, name: str, *, refresh_only: bool = False) -> None:
        self.name = name
        self.calls = 0
        self.refresh_only = refresh_only
        self.attempt = recipes.AttemptController()
        self.deadline: float | None = None

    def __call__(self) -> vault.Secret:
        self.calls += 1
        if self.refresh_only:
            raise recipes.LoginFailed("refresh only", phase="profile-proof")
        return vault.Secret(username=self.name, password=_pw())


def _profile_runner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, proofs: list[str]
) -> tuple[daemon.PlaywrightRunner, list[str]]:
    runner = daemon.PlaywrightRunner(tmp_path, dev=True)
    events: list[str] = []
    seq = iter(proofs)
    monkeypatch.setattr(runner, "_profile_proof", lambda page, item: next(seq))
    monkeypatch.setattr(
        daemon.PlaywrightRunner, "_access_precheck", staticmethod(lambda *a: None)
    )
    monkeypatch.setattr(
        runner, "_export", lambda ctx, item, via, **kw: {"via": via, "cookies": [1]}
    )

    def cleared(_ctx: Any, _item: Any) -> int:
        events.append("cleared")
        return 0

    monkeypatch.setattr(runner, "clear_site_cookies", cleared)

    def reset(_ctx: Any, page: Any, _item: Any) -> Any:
        events.append("reset")
        return page

    monkeypatch.setattr(runner, "reset_site_profile", reset)

    def recipe(*_args: Any, attempt: Any, **_kw: Any) -> None:
        events.append("login")
        attempt.entered()
        attempt.mark_submitted()

    monkeypatch.setattr(daemon, "recipe_for", lambda site: recipe)
    return runner, events


def test_profile_reuse_of_the_right_account_exports(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    name = _user()
    item = _trio_item("gl-test", name)
    runner, events = _profile_runner(tmp_path, monkeypatch, [recipes.VALID])
    gate = _Gate(name)
    assert runner.run_in_context(_Ctx(_Page(name)), item, gate)["via"] == "profile"
    assert gate.calls == 0 and not events


def test_profile_reuse_of_another_account_resets_and_logs_in_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    name = _user()
    item = _trio_item("gl-test", name)
    runner, events = _profile_runner(
        tmp_path, monkeypatch, [recipes.VALID, recipes.VALID]
    )
    gate = _Gate(name)
    bundle = runner.run_in_context(_Ctx(_Page(_user(), name)), item, gate)
    assert bundle["via"] == "login" and gate.calls == 1
    # reserved, cookies + storage cleared, ONE login
    assert events == ["reset", "login"]


def test_undecided_reuse_fails_without_reset_or_submit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    name = _user()
    item = _trio_item("gl-test", name)
    runner, events = _profile_runner(tmp_path, monkeypatch, [recipes.VALID])
    gate = _Gate(name)
    with pytest.raises(daemon.IdentityMismatch) as err:
        runner.run_in_context(_Ctx(_UndecidedThenRight(name)), item, gate)
    assert err.value.code == "identity_indeterminate" and not err.value.submitted
    assert gate.calls == 0 and not events  # nothing reserved, cleared or typed


class _UndecidedThenRight(_Page):
    def __init__(self, name: str) -> None:
        super().__init__(name)
        self.round = 0

    def answer(self, arg: dict) -> dict:
        self.round += 1
        if self.round == 1:
            self.args.append(arg)
            return {"state": "indeterminate", "why": "status", "status": 502}
        return super().answer(arg)


def test_profile_reuse_wrong_then_login_wrong_fails_without_bundle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    name = _user()
    item = _trio_item("gl-test", name)
    runner, events = _profile_runner(
        tmp_path, monkeypatch, [recipes.VALID, recipes.VALID]
    )
    gate = _Gate(name)
    with pytest.raises(daemon.IdentityMismatch) as err:
        runner.run_in_context(_Ctx(_Page(_user())), item, gate)
    assert err.value.code == "wrong_account" and err.value.auth_proven
    assert events == ["reset", "login"] and gate.calls == 1


def test_refresh_only_with_another_account_never_clears_or_logs_in(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    name = _user()
    item = _trio_item("gl-test", name)
    runner, events = _profile_runner(tmp_path, monkeypatch, [recipes.VALID])
    gate = _Gate(name, refresh_only=True)
    with pytest.raises(recipes.LoginFailed):
        runner.run_in_context(_Ctx(_Page(_user())), item, gate)
    assert not events


def test_logged_out_reuse_logs_in_without_clearing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    name = _user()
    item = _trio_item("gl-test", name)
    runner, events = _profile_runner(
        tmp_path, monkeypatch, [recipes.VALID, recipes.VALID]
    )

    class _OutThenIn(_Page):
        def answer(self, arg: dict) -> dict:
            if not self.args:
                self.args.append(arg)
                return {"state": "logged_out", "status": 401}
            return super().answer(arg)

    bundle = runner.run_in_context(_Ctx(_OutThenIn(name)), item, _Gate(name))
    assert bundle["via"] == "login" and events == ["login"]


def test_deadline_wrapper_keeps_the_identity_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    item = _trio_item("gl-glensk", _user())
    runner = daemon.PlaywrightRunner(tmp_path, dev=True)
    monkeypatch.setattr(runner, "_launch", lambda *_a, **_k: _Ctx(_Page(None)))

    gate = _Gate(item.account_name)
    # after the Playwright driver started, before the run raises
    gate.deadline = deadline = time.monotonic() + 2.5

    def late(*_a: Any, **_k: Any) -> dict:
        while time.monotonic() <= deadline:
            time.sleep(0.05)  # the run deadline passes inside the run
        raise daemon.IdentityMismatch(
            identity.WRONG_ACCOUNT, submitted=True, auth_proven=True
        )

    monkeypatch.setattr(runner, "run_in_context", late)
    with pytest.raises(daemon.IdentityMismatch) as err:
        runner(item, gate)
    assert not isinstance(err.value, daemon.DeadlineError)
    assert err.value.code == "wrong_account"


def test_broker_reply_for_a_wrong_account_on_reuse(tmp_path: Path) -> None:
    class _Wrong:
        last_diag: dict = {}

        def __call__(self, item: Any, get_secret: Any) -> dict:
            raise daemon.IdentityMismatch(identity.PRIVILEGE_MISMATCH)

    items, users = _trio(tmp_path)
    brk = _broker(tmp_path, items, _Wrong())
    resp = brk.handle({"op": "login", "site": "gl-glensk"}, 501)
    assert resp["ok"] is False and resp["error"] == "privilege_mismatch"
    assert resp["phase"] == "broker-proof" and resp["submitted"] is False
    assert not any(u in json.dumps(resp) for u in users.values())


# ---------------------------------------------------------------------------
# RECIPE_JS in a real headless Chromium (routed fixture origins), run the
# way the broker runs it: in a CDP isolated world (daemon.evaluate_isolated)
# ---------------------------------------------------------------------------


def _chromium_installed() -> bool:
    try:
        from playwright.sync_api import (  # pylint: disable=import-outside-toplevel
            sync_playwright,
        )

        with sync_playwright() as pw:
            return Path(pw.chromium.executable_path).exists()
    except Exception:  # pylint: disable=broad-exception-caught
        return False


CHROME = pytest.mark.skipif(
    not _chromium_installed(), reason="Playwright Chromium missing"
)


class _Api:
    """Routes every request: the check page, the identity endpoint (`body`,
    `status`, `ctype` or a `redirect`), and a foreign origin."""

    def __init__(self) -> None:
        self.body: Any = {}
        self.status = 200
        self.ctype = "application/json; charset=utf-8"
        self.redirect: str | None = None
        self.seen_auth: list[str | None] = []

    def handle(self, route: Any) -> None:
        req = route.request
        if req.resource_type == "document":
            route.fulfill(status=200, content_type="text/html", body="<p id=me>hi</p>")
            return
        self.seen_auth.append(req.headers.get("authorization"))
        if self.redirect:
            route.fulfill(status=302, headers={"Location": self.redirect})
            return
        route.fulfill(
            status=self.status, content_type=self.ctype, body=json.dumps(self.body)
        )


@pytest.fixture(name="chrome")
def _chrome() -> Iterator[tuple[Any, _Api]]:
    from playwright.sync_api import (  # pylint: disable=import-outside-toplevel
        sync_playwright,
    )

    api = _Api()
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        try:
            ctx = browser.new_context()
            ctx.route("**/*", api.handle)
            yield ctx.new_page(), api
        finally:
            browser.close()


def _run(page: Any, recipe: str, check_url: str, *, goto: bool = True) -> dict:
    if goto:
        page.goto(check_url)
    nonce = secrets.token_hex(32)
    args = identity.recipe_args(identity.IDENTITIES[recipe], check_url, nonce)
    got = daemon.evaluate_isolated(page, identity.RECIPE_JS, args)
    got["_nonce"] = nonce
    return dict(got)


@pytest.mark.launches_chrome
@CHROME
def test_js_gitlab_match_and_admin_bit(chrome: tuple[Any, _Api]) -> None:
    page, api = chrome
    name = _user()
    check = f"https://{GITLAB}/dashboard"
    api.body = {"username": f" {name.upper()} ", "id": 7}  # no is_admin: not admin
    got = _run(page, "gitlab", check)
    assert got["state"] == "found" and got["admin"] is False
    assert identity.local_verdict(got, got["_nonce"], name, "user") == identity.MATCH
    assert (
        identity.local_verdict(got, got["_nonce"], _user(), "user")
        == identity.WRONG_ACCOUNT
    )
    api.body = {"username": name, "is_admin": True}
    got = _run(page, "gitlab", check)
    assert got["admin"] is True
    assert (
        identity.local_verdict(got, got["_nonce"], name, "user")
        == identity.PRIVILEGE_MISMATCH
    )
    assert identity.local_verdict(got, got["_nonce"], name, "admin") == identity.MATCH
    assert name not in json.dumps(got)


@pytest.mark.launches_chrome
@CHROME
def test_js_page_scripts_cannot_hook_the_isolated_recipe(
    chrome: tuple[Any, _Api],
) -> None:
    page, api = chrome
    real, fake = _user(), _user()
    check = f"https://{GITLAB}/dashboard"
    api.body = {"username": real}
    page.goto(check)
    # the page replaces the JSON parser and the hash in ITS world
    page.evaluate(
        """n => {
          Response.prototype.json = async function () { return {username: n}; };
          crypto.subtle.digest = async () => new ArrayBuffer(32);
        }""",
        fake,
    )
    hooked = page.evaluate(
        identity.RECIPE_JS,
        identity.recipe_args(
            identity.IDENTITIES["gitlab"], check, secrets.token_hex(32)
        ),
    )
    assert hooked["digest"] == "0" * 64  # the main world is hooked …
    got = _run(page, "gitlab", check, goto=False)
    assert identity.local_verdict(got, got["_nonce"], real, "user") == identity.MATCH


@pytest.mark.launches_chrome
@CHROME
def test_reset_site_profile_clears_every_store_in_a_fresh_tab(
    chrome: tuple[Any, _Api], tmp_path: Path
) -> None:
    page, _api = chrome
    ctx = page.context
    check = "https://abs.ws5.example/audiobookshelf/library"
    other = "https://elsewhere.ws5.example/"
    token = secrets.token_hex(16)
    page.goto(other)
    page.evaluate("t => localStorage.setItem('keep', t)", token)
    page.goto(check)
    page.evaluate(
        """t => new Promise(done => {
          localStorage.setItem('token', t); sessionStorage.setItem('s', t);
          const req = indexedDB.open('ws5db');
          req.onupgradeneeded = () => req.result.createObjectStore('o');
          req.onsuccess = () => { req.result.close(); done(); };
        })""",
        token,
    )
    ctx.add_cookies(
        [{"name": "sid", "value": token, "domain": "abs.ws5.example", "path": "/"}]
    )
    item = _items(
        _raw(
            "abs-x",
            host="abs.ws5.example",
            check_url=check,
            storage_keys=json.dumps({"https://abs.ws5.example": ["token"]}),
        )
    )["abs-x"]
    runner = daemon.PlaywrightRunner(tmp_path, dev=True)
    fresh = runner.reset_site_profile(ctx, page, item)
    assert fresh is not page and page.is_closed()
    fresh.goto(check)
    left = fresh.evaluate(
        """async () => [localStorage.length, sessionStorage.length,
          (await indexedDB.databases()).length]"""
    )
    assert left == [0, 0, 0]
    assert not [c for c in ctx.cookies() if c["domain"].endswith("abs.ws5.example")]
    fresh.goto(other)
    assert fresh.evaluate("() => localStorage.getItem('keep')") == token  # untouched


@pytest.mark.launches_chrome
@CHROME
def test_js_nfkc_parity_with_python(chrome: tuple[Any, _Api]) -> None:
    page, api = chrome
    name = _user()
    fullwidth = "".join(chr(ord(c) + 0xFEE0) if "!" <= c <= "~" else c for c in name)
    api.body = {"username": "\t" + fullwidth + " \n"}
    got = _run(page, "gitlab", f"https://{GITLAB}/x")
    assert got["digest"] == identity.challenge_digest(
        got["_nonce"], str(identity.normalize_identity(fullwidth))
    )
    api.body = {"username": name + "ü"}
    assert _run(page, "gitlab", f"https://{GITLAB}/x")["state"] == "indeterminate"


@pytest.mark.launches_chrome
@CHROME
def test_js_fails_closed(chrome: tuple[Any, _Api]) -> None:
    page, api = chrome
    check = f"https://{GITLAB}/x"
    api.body = {"username": _user()}
    api.status = 401
    assert _run(page, "gitlab", check)["state"] == "logged_out"
    api.status = 500
    assert _run(page, "gitlab", check)["state"] == "indeterminate"
    api.status, api.ctype = 200, "text/html"
    assert _run(page, "gitlab", check)["state"] == "indeterminate"
    api.ctype = "application/json"
    for target in (f"https://{GITLAB}/api/v4/other", "https://evil.ws5.example/u"):
        api.redirect = target  # same-origin or not: no redirect at all
        got = _run(page, "gitlab", check)
        assert got["state"] == "indeterminate" and got["why"] == "redirect"
    api.redirect = None
    api.body = ["not", "an", "object"]
    assert _run(page, "gitlab", check)["state"] == "indeterminate"
    # a page on another origin than the check URL's: the recipe refuses
    page.goto("https://other.ws5.example/")
    got = _run(page, "gitlab", check, goto=False)
    assert got["state"] == "indeterminate" and got["why"] == "origin"


@pytest.mark.launches_chrome
@CHROME
def test_js_audiobookshelf_bearer_from_local_storage(chrome: tuple[Any, _Api]) -> None:
    page, api = chrome
    name, token = _user(), secrets.token_hex(16)
    check = "https://abs.ws5.example/audiobookshelf/library"
    assert _run(page, "audiobookshelf", check)["state"] == "logged_out"  # no token
    page.evaluate("t => localStorage.setItem('token', t)", token)
    api.body = {"username": name, "type": "root"}
    got = _run(page, "audiobookshelf", check)
    assert got["state"] == "found" and got["admin"] is True
    assert api.seen_auth[-1] == f"Bearer {token}"
    assert identity.local_verdict(got, got["_nonce"], name, "admin") == identity.MATCH
    api.body = {"username": name, "type": "weird"}
    got = _run(page, "audiobookshelf", check)
    assert (
        identity.local_verdict(got, got["_nonce"], name, "user")
        == identity.INDETERMINATE
    )


@pytest.mark.launches_chrome
@CHROME
def test_js_authentik_impersonation_and_dsm_isolation(chrome: tuple[Any, _Api]) -> None:
    page, api = chrome
    name = _user()
    check = "https://auth.ws5.example/if/user/"
    api.body = {"user": {"username": name, "is_superuser": False}, "original": None}
    got = _run(page, "authentik", check)
    assert identity.local_verdict(got, got["_nonce"], name, "user") == identity.MATCH
    api.body = {
        "user": {"username": name, "is_superuser": False},
        "original": {"pk": 1},
    }
    assert _run(page, "authentik", check)["state"] == "indeterminate"
    api.body = {"user": {"username": name, "is_superuser": False}}  # no `original`
    assert _run(page, "authentik", check)["state"] == "indeterminate"
    # DSM's SynoToken is a page global: the isolated world does not see it,
    # so dsm stays indeterminate (and unusable) until S4 picks another source
    dsm = "https://nas.ws5.example/"
    page.goto(dsm)
    page.evaluate("t => { window.SYNO = {SDS: {Session: {SynoToken: t}}}; }", "tok")
    api.body = {"success": True, "data": {"username": name}}
    got = _run(page, "dsm", dsm, goto=False)
    assert got["state"] == "indeterminate" and got["why"] == "no token"
