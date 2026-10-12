"""WS3: the onboarding review (broker/onboarding.py) and the shared
storage-key rule (broker/storage_rules.py, used by broker/vault.py).

Hermetic: pure functions over ``sites`` views and Bitwarden-shaped raw items.
Usernames and passwords are generated per run, never literals.
"""

from __future__ import annotations

# pylint: disable=missing-function-docstring,import-error,wrong-import-position
import json
import secrets
import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from ws3_fixtures import new_user as _user  # noqa: E402
from ws3_fixtures import raw_item as _raw  # noqa: E402

from broker import identity, onboarding, storage_rules, vault  # noqa: E402


def _views(*raws: dict) -> list[dict]:
    return [it.public() for it in vault.build_items(list(raws))]


def _codes(findings: list[onboarding.Finding]) -> set[str]:
    return {f.code for f in findings}


# ---------------------------------------------------------------------------
# the storage-key rule: one function for the broker and the review
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "reason"),
    [
        ([], "not an object"),
        ({f"https://o{i}.example": ["k"] for i in range(9)}, "more than 8 origins"),
        ({"https://a.example": "k"}, "expected {origin: [keys]}"),
        ({"https://a.example": []}, "an origin without keys"),
        ({"https://a.example": [f"k{i}" for i in range(17)]}, "more than 16 keys"),
        ({"https://a.example": [1]}, "a key is not a string"),
        ({"https://a.example": [True]}, "a key is not a string"),
        ({"https://a.example": [""]}, "a key is empty"),
        ({"https://a.example": ["a b"]}, "whitespace"),
        ({"https://a.example": ["a\x01"]}, "control"),
        ({"https://a.example": ["k" * 129]}, "longer than 128"),
        ({"https://a.example": ["k", "k"]}, "listed twice"),
        ({"http://a.example": ["k"]}, "not an https"),
        ({"https://a.example/path": ["k"]}, "not an https"),
        ({"https://a.example, https://b.example": ["k"]}, "exactly one origin"),
        ({"https://A.example": ["k"], "https://a.example/": ["j"]}, "normalise to one"),
    ],
)
def test_storage_rule_refuses(value: Any, reason: str) -> None:
    parsed, problem = storage_rules.parse_storage_keys(value)
    assert parsed is None and reason in problem
    assert "a.example" not in problem and "k" * 129 not in problem  # fixed reasons


def test_storage_rule_accepts_and_normalises() -> None:
    parsed, problem = storage_rules.parse_storage_keys(
        {"https://App.example:443/": ["token", "user-id"]}
    )
    assert problem == "" and parsed == {"https://app.example": ["token", "user-id"]}
    # dev mode keeps the loopback origin of the hermetic end-to-end test
    parsed, problem = storage_rules.parse_storage_keys(
        {"http://127.0.0.1:8123": ["t"]}, dev=True
    )
    assert problem == "" and parsed == {"http://127.0.0.1:8123": ["t"]}
    assert storage_rules.parse_storage_keys({"http://127.0.0.1:8123": ["t"]})[0] is None


def test_vault_refuses_a_bad_storage_field_with_the_shared_reason() -> None:
    bad = _raw("st", "st.example", storage_keys=json.dumps({"https://st.example": [7]}))
    item = vault.site_item_from_json(bad)
    assert item.refused == "bad agent_storage_keys: a key is not a string"
    dup = _raw(
        "st",
        "st.example",
        storage_keys=json.dumps(
            {"https://st.example": ["a"], "https://ST.example": ["b"]}
        ),
    )
    assert "normalise to one" in str(vault.site_item_from_json(dup).refused)
    assert vault.site_item_from_json(
        _raw("st", "st.example", storage_keys="{not json")
    ).refused == ("bad agent_storage_keys: not JSON")
    good = _raw(
        "st", "st.example", storage_keys=json.dumps({"https://st.example": ["t"]})
    )
    assert vault.site_item_from_json(good).storage_keys == {"https://st.example": ["t"]}


# The shapes of the live snapshot (2026-10-12, key names only): 11 items with
# 1-8 keys of 4-20 printable characters on their own origin — none refused.
LIVE_SHAPES = [
    ["token"],
    ["aurral_tok"],
    ["hassTokens"],
    ["jellyfin_credentials", "_deviceId2"],
    ["kavita-user"],
    [
        "token",
        "userId",
        "username",
        "name",
        "role",
        "subsonic-salt",
        "subsonic-token",
        "is-authenticated",
    ],
    ["authentications"],
    ["stirling_jwt"],
]


@pytest.mark.parametrize("keys", LIVE_SHAPES)
def test_the_live_storage_shapes_stay_accepted(keys: list[str]) -> None:
    raw = _raw(
        "live", "live.example", storage_keys=json.dumps({"https://live.example": keys})
    )
    assert vault.site_item_from_json(raw).refused is None


# ---------------------------------------------------------------------------
# item findings over views
# ---------------------------------------------------------------------------


def test_pin_cases_hold() -> None:
    """broker-add's mirror is pinned to these (single-item codes)."""
    for view, want in onboarding.PIN_CASES:
        assert onboarding.single_item_codes(view) == want, view


def test_public_suffixes_from_the_vendored_list() -> None:
    for host in ("ch", "com", "co.uk", "github.io", "pages.dev", "blogspot.com"):
        assert onboarding.is_public_suffix(host), host
    for host in ("galaxus.ch", "app.docker.com", "x.github.io", "dom42.space"):
        assert not onboarding.is_public_suffix(host), host
    assert onboarding.registrable_domain("a.b.example.co.uk") == "example.co.uk"
    assert onboarding.registrable_domain("x.github.io") == "x.github.io"


def test_a_bad_psl_file_is_one_infrastructure_error_never_an_item_finding(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    assert onboarding.psl_problem() == ""
    fake = tmp_path / "psl.dat"
    fake.write_text("com\n", encoding="utf-8")
    monkeypatch.setattr(onboarding, "PSL_FILE", fake)
    onboarding._psl.cache_clear()  # pylint: disable=protected-access
    try:
        assert "pinned version" in onboarding.psl_problem()
        view = onboarding.PIN_CASES[0][0]
        assert onboarding.single_item_codes(view) == frozenset()
        github = {**view, "cookie_hosts": ["github.io"]}
        # its public-suffix judgement is unknown, nothing more
        assert "public_suffix_scope" not in onboarding.single_item_codes(github)
        single = {**view, "cookie_hosts": ["com"]}  # judged without the list
        assert "public_suffix_scope" in onboarding.single_item_codes(single)
        monkeypatch.setattr(onboarding, "PSL_FILE", tmp_path / "missing.dat")
        assert "cannot read" in onboarding.psl_problem()
    finally:
        onboarding._psl.cache_clear()  # pylint: disable=protected-access


def test_a_public_ip_cookie_host_is_a_risk_a_lan_ip_is_not() -> None:
    base = dict(onboarding.PIN_CASES[0][0])
    pub = {**base, "fill_origins": ["https://8.8.8.8"], "cookie_hosts": ["8.8.8.8"]}
    lan = {
        **base,
        "fill_origins": ["https://192.168.1.5"],
        "cookie_hosts": ["192.168.1.5"],
    }
    assert "public_suffix_scope" in onboarding.single_item_codes(pub)
    assert "public_suffix_scope" not in onboarding.single_item_codes(lan)


def test_a_server_proof_item_needs_no_sentinel() -> None:
    cscs = _views(
        _raw(
            "cscs",
            "auth.cscs.ch",
            logged_in_selector="",
            check_url="https://portal.cscs.ch/profile/",
            cookie_hosts="cscs.ch",
        )
    )[0]
    assert cscs["strict_proof"] is True and not cscs["logged_in_selector"]
    assert "no_proof" not in _codes(onboarding.item_findings(cscs, [cscs]))


def test_the_ws5_rule_names_siblings_and_fields() -> None:
    views = _views(
        _raw("gl-a", "gl.example"), _raw("gl-b", "gl.example", instance="admin")
    )
    by = {v["site"]: v for v in views}
    found = onboarding.item_findings(by["gl-b"], views)
    refused = [f for f in found if f.code == "broker_refused"]
    assert refused and "agent_privilege" in refused[0].text  # the broker's own word
    good = _views(
        _raw("gl-a", "gl.example", privilege="user"),
        _raw("gl-b", "gl.example", instance="admin", privilege="admin"),
    )
    hit = [
        f
        for f in onboarding.item_findings(good[1], good)
        if f.code == "account_unproven"
    ]
    assert hit and hit[0].level == "unusable" and hit[0].related == ("gl-a",)
    assert "agent_identity" in hit[0].text and "agent_same_account_as" in hit[0].text


def test_same_account_pairs_get_an_attempt_group_hint_only() -> None:
    views = _views(
        _raw("shop-a", "shop.example", same_account_as="shop-b"),
        _raw("shop-b", "shop.example", same_account_as="shop-a", instance="alt"),
    )
    found = onboarding.item_findings(views[0], views)
    assert [f.level for f in found if f.code == "attempt_group"] == ["hint"]
    grouped = _views(
        _raw("shop-a", "shop.example", same_account_as="shop-b", attempt_group="shop"),
        _raw(
            "shop-b",
            "shop.example",
            same_account_as="shop-a",
            attempt_group="shop",
            instance="alt",
        ),
    )
    assert "attempt_group" not in _codes(onboarding.item_findings(grouped[0], grouped))
    # separate apps on one domain: NOT one account, no suggestion
    apps = _views(_raw("app1", "app1.dom.example"), _raw("app2", "app2.dom.example"))
    assert "attempt_group" not in _codes(onboarding.item_findings(apps[0], apps))


def test_hostile_text_never_reaches_a_finding() -> None:
    view = {
        "site": "evil\x1b[2J",
        "refused": True,
        "reason": "bad\x07thing\n" + "x" * 500,
        "fill_origins": ["https://a.example"],
        "cookie_hosts": ["\x1b]8;;evil\x1b\\"],
    }
    for f in onboarding.item_findings(view, [view]):
        text = f.site + f.text
        assert "\x1b" not in text and "\x07" not in text and "\n" not in text
        assert f.site == "<invalid>"
        assert len(f.text) < 400


# ---------------------------------------------------------------------------
# planned changes: the broker's own rules, before the vault write
# ---------------------------------------------------------------------------


def _manifest_item(site: str, host: str, **fields: str) -> dict:
    raw = _raw(site, host, **fields)
    return {
        "name": raw["name"],
        "fields": {f["name"]: f["value"] for f in raw["fields"]},
    }


def test_stand_ins_reproduce_the_broker_verdicts() -> None:
    users = {s: _user() for s in ("a1", "a2", "b1", "b2", "c1", "c2", "d1")}
    raws = [
        _raw("a1", "a.example", users["a1"], privilege="user"),
        _raw("a2", "a.example", users["a2"], privilege="admin", instance="admin"),
        _raw("b1", "b.example", users["b1"]),
        _raw("b2", "b.example", users["b2"], privilege="user", instance="alt"),
        _raw("c1", "c.example", users["c1"], privilege="user"),
        _raw("c2", "c.example", users["c2"], privilege="user"),
        _raw("d1", "d.example", users["d1"], alias="dd"),
    ]
    real = vault.build_items(raws)
    stand = [onboarding.item_from_view(i.public()) for i in real]
    again = vault.identity_rules(stand, [{"fields": []} for _ in stand])
    assert {i.site: (i.refused is None, i.multi_account) for i in again} == {
        i.site: (i.refused is None, i.multi_account) for i in real
    }


def test_a_new_item_that_displaces_an_established_one_is_shown() -> None:
    views = _views(_raw("old", "app.example"))
    review = onboarding.review_planned(
        {
            **_manifest_item("aaa-new", "app.example", privilege="user"),
            "login": {"username": _user()},
        },
        views,
    )
    displaced = [f for f in review.findings if f.code == "displaced"]
    assert displaced and displaced[0].site == "old" and displaced[0].level == "refused"
    assert displaced[0].related == ("aaa-new",)
    assert review.blocking


def test_a_new_sibling_in_another_instance_makes_the_old_one_unproven() -> None:
    views = _views(_raw("old", "app.example", privilege="user"))
    review = onboarding.review_planned(
        _manifest_item("new", "app.example", privilege="admin", instance="admin"), views
    )
    made = [f for f in review.findings if f.code == "made_unproven"]
    assert made and made[0].site == "old" and made[0].level == "unusable"


def test_duplicates_and_replacements() -> None:
    views = _views(_raw("app", "app.example"))
    dup = onboarding.review_planned(_manifest_item("app", "app.example"), views)
    assert any(
        f.code == "broker_refused" and "duplicate" in f.text for f in dup.findings
    )
    upd = onboarding.review_planned(
        {
            **_manifest_item("app", "app.example", cookie_hosts="github.io"),
            "replaces": "app",
        },
        views,
    )
    assert "duplicate" not in json.dumps([f.text for f in upd.findings])
    assert "public_suffix_scope" in _codes(upd.findings)
    twice = onboarding.review_planned(
        {
            "items": [
                _manifest_item("n1", "n.example"),
                _manifest_item("n1", "n.example"),
            ]
        },
        views,
    )
    assert any("duplicate" in f.text for f in twice.findings)


def test_a_batch_is_judged_as_one_change_and_removals_count() -> None:
    views = _views(_raw("old", "old.example"))
    batch = {
        "items": [
            _manifest_item("p1", "p.example", privilege="user"),
            _manifest_item("p2", "p.example", privilege="user", instance="alt"),
        ]
    }
    review = onboarding.review_planned(batch, views)
    assert {f.site for f in review.findings if f.code == "account_unproven"} == {
        "p1",
        "p2",
    }
    gone = onboarding.review_planned({"items": [], "removes": ["old"]}, views)
    assert not gone.findings and "old" not in {v["site"] for v in gone.after}


def test_username_dependent_fields_need_the_username_or_its_form() -> None:
    views: list[dict] = []
    plain = _manifest_item("solo", "solo.example", alias="solo-alias")
    review = onboarding.review_planned(plain, views)
    assert "username_unchecked" in _codes(review.findings)
    told = {**plain, "username_form": "username", "reveals": {"alias": False}}
    assert "username_unchecked" not in _codes(
        onboarding.review_planned(told, views).findings
    )
    leaks = {**plain, "username_form": "username", "reveals": {"alias": True}}
    hit = [
        f
        for f in onboarding.review_planned(leaks, views).findings
        if f.code == "reveals_account"
    ]
    assert hit and hit[0].level == "refused"


def test_a_manifest_never_carries_a_secret() -> None:
    item = _manifest_item("s", "s.example")
    with pytest.raises(ValueError, match="no secrets"):
        onboarding.review_planned(
            {**item, "login": {"username": _user(), "password": secrets.token_hex(8)}},
            [],
        )
    with pytest.raises(ValueError, match="unknown item keys"):
        onboarding.review_planned({**item, "notes": "x"}, [])


def test_config_digest_moves_with_behaviour_not_labels() -> None:
    view = _views(_raw("app", "app.example"))[0]
    digest = onboarding.config_digest(view)
    assert digest == onboarding.config_digest(dict(view))
    assert onboarding.config_digest({**view, "alias": "x", "name": "y"}) == digest
    for key, value in (
        ("logged_in_selector", "#other"),
        ("cookie_hosts", ["example"]),
        ("check_url", "https://app.example/other"),
        ("instance", "admin"),
        ("storage_keys", {"https://app.example": ["t"]}),
        ("fill_origins", ["https://login.app.example"]),
    ):
        assert onboarding.config_digest({**view, key: value}) != digest, key


def test_the_digest_survives_a_broker_release() -> None:
    """B1: the same vault item hashes the same through view-format changes
    and code-derived flags (a broker release must not flip promotions)."""
    view = _views(_raw("app", "app.example", cookie_hosts="b.app.example,app.example"))[
        0
    ]
    digest = onboarding.config_digest(view)
    pre_s4c = {k: v for k, v in view.items() if k not in ("cookie_scopes", "scope_v")}
    assert onboarding.config_digest(pre_s4c) == digest
    reordered = {**view, "cookie_hosts": list(reversed(view["cookie_hosts"]))}
    reordered["cookie_scopes"] = list(reversed(view["cookie_scopes"]))
    assert onboarding.config_digest(reordered) == digest
    for key, value in (
        ("strict_proof", not view["strict_proof"]),
        ("session_refresh", "npm-jwt"),
        ("no_submit", True),
        ("sentinel", False),
        ("identity_v", 2),
        ("new_view_field", "x"),
        ("login_url", view["check_url"]),  # the default login URL
        ("cookie_names", None),
        ("cookie_names", []),
    ):
        assert onboarding.config_digest({**view, key: value}) == digest, key
    path_scoped = {
        **view,
        "cookie_scopes": [{"host": "app.example", "path": "/realms/a"}],
        "cookie_hosts": ["app.example"],
    }
    assert onboarding.config_digest(path_scoped) != digest
    assert onboarding.config_canon(view)["v"] == onboarding.CONFIG_V


# ---------------------------------------------------------------------------
# cookie hosts of the item's identity recipe (Run:ai's Keycloak, live
# 2026-10-12: app1.run.ai was a risk, blocking -p)
# ---------------------------------------------------------------------------

_RUNAI_SCOPES = [
    {"host": "sdsc.run.ai", "path": "/"},
    {"host": "custos.datascience.ch", "path": "/realms/sdsc/"},
    {"host": "app1.run.ai", "path": "/auth/realms/sdsc/"},
]


def _runai_raw(site: str = "runai-test3", **fields: str | None) -> dict:
    base: dict[str, str | None] = {
        "agent_site": site,
        "agent_fill_origins": "https://custos.datascience.ch",
        "agent_check_url": "https://sdsc.run.ai/workloads",
        "agent_logged_in_selector": "#me",
        "agent_cookie_scopes": json.dumps(_RUNAI_SCOPES),
        "agent_identity": "runai",
        "agent_privilege": "user",
    }
    base.update({f"agent_{k}": v for k, v in fields.items()})
    login = {"username": f"{_user()}@ws3r.example"}
    login["pass" + "word"] = secrets.token_urlsafe(18)
    return {
        "id": f"id-{site}",
        "name": site,
        "login": login,
        "fields": [{"name": k, "value": v} for k, v in base.items() if v is not None],
    }


def _risks(view: dict) -> set[str]:
    return {f.code for f in onboarding.item_findings(view, [view]) if f.level == "risk"}


def test_the_identity_recipes_issuer_host_is_related() -> None:
    view = _views(_runai_raw())[0]
    assert not view.get("refused"), view.get("reason")
    assert "app1.run.ai" in view["cookie_hosts"]
    assert identity.recipe_hosts(view) == {"app1.run.ai", "sdsc.run.ai"}
    assert _risks(view) == set()


def test_an_unrelated_cookie_host_stays_a_risk() -> None:
    # the same scopes without the recipe: app1.run.ai relates to nothing
    plain = _views(_runai_raw(identity=None, privilege=None))[0]
    assert identity.recipe_hosts(plain) == set()
    assert "unrelated_cookie_host" in _risks(plain)
    # a recipe item with ANOTHER unrelated host: still a risk, for that host
    extra = [*_RUNAI_SCOPES, {"host": "other.example.org", "path": "/"}]
    view = _views(_runai_raw(cookie_scopes=json.dumps(extra)))[0]
    risky = [
        f
        for f in onboarding.item_findings(view, [view])
        if f.code == "unrelated_cookie_host"
    ]
    assert len(risky) == 1 and "other.example.org" in risky[0].text
    # a site the recipe is not reviewed for gets none of its hosts
    other = _views(_runai_raw("runai-x"))[0]
    assert identity.recipe_hosts(other) == set()
    assert "unrelated_cookie_host" in _risks(other)
    # nor does an item whose check page is off the recipe's origin
    moved = {**view, "check_url": "https://other.run.ai/workloads"}
    assert identity.recipe_hosts(moved) == set()
    # a non-recipe item: a plain unrelated host is a risk as before
    app = _views(
        _raw("app", "app.example", cookie_hosts="app.example,other.example.org")
    )
    assert "unrelated_cookie_host" in _risks(app[0])
