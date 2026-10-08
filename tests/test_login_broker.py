"""Hermetic tests of the login broker (broker/) and its client in bin/browser.py.

No network, no shared Chromium on :9222, no keychain, no real Bitwarden: the
vault is a JSON fixture (or a fake `bw` script), the daemon serves a real Unix
socket in a temp dir with a stubbed login runner. The one browser test
(`-m browser`, opt-in via LOGIN_BROKER_E2E=1) logs into a local http.server
with a real headless Chromium.

Run: uv run --no-sync pytest tests/test_login_broker.py
"""

from __future__ import annotations

# pylint: disable=protected-access,import-outside-toplevel,too-few-public-methods
# pylint: disable=missing-function-docstring,missing-class-docstring,import-error
# pylint: disable=redefined-outer-name,unused-argument,wrong-import-position
# One module covers the whole broker package + client + installer (too-many-lines).
# pylint: disable=too-many-lines
import contextlib
import http.server
import importlib.util
import json
import os
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from broker import (  # noqa: E402
    bootstrap_switch,
    bundle,
    daemon,
    limiter,
    origins,
    page_state,
    peercred,
    recipes,
    runs,
    selfcheck,  # noqa: E402
    vault,
    vault_cache,
)

_BROWSER_PY = REPO / "bin" / "browser.py"


def _load_browser_module():
    spec = importlib.util.spec_from_file_location("browser_broker_test", _BROWSER_PY)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["browser_broker_test"] = mod
    spec.loader.exec_module(mod)
    return mod


browser = _load_browser_module()

PASSWORD = "pw-Sup3rSecret!"
TOTP_SEED = "JBSWY3DPEHPK3PXP"


def _item(name, fields, *, user="alice", password=PASSWORD, totp=TOTP_SEED):
    return {
        "id": f"id-{name}",
        "name": name,
        "login": {"username": user, "password": password, "totp": totp},
        "fields": [{"name": k, "value": v, "type": 0} for k, v in fields.items()],
    }


FIXTURE_ITEMS = [
    _item(
        "Ricardo",
        {
            "agent_site": "ricardo",
            "agent_fill_origins": "https://login.ricardo.ch",
            "agent_cookie_hosts": "ricardo.ch",
            "agent_logged_in_selector": "#account",
        },
    ),
    _item("No Origins", {"agent_site": "noorigins"}),
    _item(
        "CSCS",
        {
            "agent_site": "cscs",
            "agent_fill_origins": "https://auth.cscs.ch",
            "agent_cookie_hosts": "portal.cscs.ch",
            "agent_login_url": "https://portal.cscs.ch/profile/",
        },
    ),
]


# ---------------------------------------------------------------------------
# origins
# ---------------------------------------------------------------------------

CSCS = ["https://auth.cscs.ch"]


@pytest.mark.parametrize(
    "url",
    [
        "https://auth.cscs.ch/realms/cscs/login",
        "https://AUTH.cscs.ch/x",
        "https://auth.cscs.ch:443/x",
    ],
)
def test_origin_allowed_exact(url):
    assert origins.origin_allowed(url, CSCS)


@pytest.mark.parametrize(
    "url",
    [
        "https://evil.example/?auth.cscs.ch",
        "https://auth.cscs.ch.evil.example/",
        "https://evil.example/auth.cscs.ch",
        "https://auth.cscs.ch@evil.example/",
        "https://user:pw@auth.cscs.ch/",
        "http://auth.cscs.ch/",
        "https://auth.cscs.ch:8443/",
        "https://xauth.cscs.ch/",
        "https://cscs.ch/",
        "javascript:alert(1)",
        "data:text/html,auth.cscs.ch",
        "",
        "not a url",
    ],
)
def test_origin_rejected(url):
    assert not origins.origin_allowed(url, CSCS)


def test_origin_dev_loopback_only_in_dev():
    allowed = ["http://127.0.0.1:8080"]
    assert not origins.origin_allowed("http://127.0.0.1:8080/login", allowed)
    assert origins.origin_allowed("http://127.0.0.1:8080/login", allowed, dev=True)
    assert not origins.origin_allowed("http://127.0.0.1:9090/", allowed, dev=True)
    assert not origins.origin_allowed("http://localhost:8080/", allowed, dev=True)


def test_form_action():
    page = "https://auth.cscs.ch/realms/cscs/login"
    assert origins.form_action_allowed(page, None, CSCS)
    assert origins.form_action_allowed(page, "", CSCS)
    assert origins.form_action_allowed(page, "/realms/cscs/authenticate?x=1", CSCS)
    assert origins.form_action_allowed(page, "authenticate", CSCS)
    assert not origins.form_action_allowed(page, "https://evil.example/steal", CSCS)
    assert not origins.form_action_allowed(page, "//evil.example/steal", CSCS)
    assert not origins.form_action_allowed(page, "http://auth.cscs.ch/x", CSCS)


def test_parse_fill_origins_normalises():
    got = origins.parse_fill_origins(
        "https://Auth.CSCS.ch, https://portal.cscs.ch/\nhttps://x.example:8443"
    )
    assert got == [
        "https://auth.cscs.ch",
        "https://portal.cscs.ch",
        "https://x.example:8443",
    ]
    assert origins.parse_fill_origins("https://a.example:443") == ["https://a.example"]


@pytest.mark.parametrize(
    "field",
    [
        "",
        " , ",
        "https://auth.cscs.ch/login",
        "https://auth.cscs.ch/?q=1",
        "https://auth.cscs.ch/#f",
        "https://user@auth.cscs.ch",
        "http://auth.cscs.ch",
        "auth.cscs.ch",
        "https://*.cscs.ch",
        "ftp://auth.cscs.ch",
        "https://auth.cscs.ch, http://evil.example",
        "http://127.0.0.1:8080",
    ],
)
def test_parse_fill_origins_errors(field):
    with pytest.raises(ValueError):
        origins.parse_fill_origins(field)


def test_parse_fill_origins_dev_loopback():
    assert origins.parse_fill_origins("http://127.0.0.1:8080", dev=True) == [
        "http://127.0.0.1:8080"
    ]


# ---------------------------------------------------------------------------
# bundle
# ---------------------------------------------------------------------------


def _ck(domain, name="sid", value="v", **kw):
    return {"domain": domain, "name": name, "value": value, "path": "/", **kw}


def test_cookie_filter_hosts_and_subdomains():
    spec = bundle.SiteBundleSpec(cookie_hosts=["ricardo.ch"])
    got = bundle.filter_cookies(
        [
            _ck(".ricardo.ch"),
            _ck("www.ricardo.ch"),
            _ck("ricardo.ch.evil.example"),
            _ck("notricardo.ch"),
            _ck("example.com"),
        ],
        spec,
    )
    assert sorted(c["domain"] for c in got) == [".ricardo.ch", "www.ricardo.ch"]


def test_cookie_filter_parent_domain_not_included():
    spec = bundle.SiteBundleSpec(cookie_hosts=["portal.cscs.ch"])
    got = bundle.filter_cookies([_ck(".cscs.ch"), _ck("portal.cscs.ch")], spec)
    assert [c["domain"] for c in got] == ["portal.cscs.ch"]


def test_cookie_filter_excludes_idp_unless_named():
    cookies = [
        _ck("accounts.google.com"),
        _ck("sso.example.org"),
        _ck("keycloak.example.org"),
        _ck("www.example.org"),
    ]
    broad = bundle.SiteBundleSpec(cookie_hosts=["google.com", "example.org"])
    assert [c["domain"] for c in bundle.filter_cookies(cookies, broad)] == [
        "www.example.org"
    ]
    named = bundle.SiteBundleSpec(cookie_hosts=["accounts.google.com"])
    assert [c["domain"] for c in bundle.filter_cookies(cookies, named)] == [
        "accounts.google.com"
    ]
    cscs = bundle.SiteBundleSpec(cookie_hosts=["cscs.ch"])
    assert not bundle.filter_cookies([_ck("auth.cscs.ch")], cscs)


def test_cookie_filter_name_allowlist_and_shape():
    spec = bundle.SiteBundleSpec(cookie_hosts=["a.example"], cookie_names=["sid"])
    got = bundle.filter_cookies(
        [
            _ck("a.example", "sid", expires=-1, sameSite="Lax", httpOnly=True),
            _ck("a.example", "tracking"),
            _ck("a.example", "sid", expires=2_000_000_000.0, secure=True),
        ],
        spec,
    )
    assert [c["name"] for c in got] == ["sid", "sid"]
    assert "expires" not in got[0] and got[0]["sameSite"] == "Lax"
    assert got[0]["httpOnly"] is True
    assert got[1]["expires"] == 2_000_000_000.0 and got[1]["secure"] is True


def test_storage_filter():
    spec = bundle.SiteBundleSpec(
        cookie_hosts=["a.example"], storage_keys={"https://a.example": ["tok"]}
    )
    got = bundle.filter_storage(
        {
            "https://a.example": {"tok": "t1", "other": "x"},
            "https://b.example": {"tok": "t2"},
        },
        spec,
    )
    assert got == {"https://a.example": {"tok": "t1"}}


def test_client_scope_mirrors_broker():
    assert browser.BROKER_IDP_HOSTS == bundle.IDP_HOSTS
    assert browser.BROKER_IDP_LABELS == bundle.IDP_LABELS
    domains = [
        ".ricardo.ch",
        "ricardo.ch",
        "www.ricardo.ch",
        "accounts.google.com",
        "auth.cscs.ch",
        "portal.cscs.ch",
        "sso.ricardo.ch",
        "evilricardo.ch",
        "",
    ]
    for hosts in (["ricardo.ch"], ["google.com"], ["auth.cscs.ch", "cscs.ch"]):
        for names in (None, ["sid"]):
            spec = bundle.SiteBundleSpec(cookie_hosts=hosts, cookie_names=names)
            for d in domains:
                for n in ("sid", "other"):
                    assert bundle.cookie_in_scope(
                        d, n, spec
                    ) == browser._broker_cookie_in_scope(d, n, hosts, names), (
                        d,
                        n,
                        hosts,
                        names,
                    )


# ---------------------------------------------------------------------------
# limiter
# ---------------------------------------------------------------------------


def _limiter(path, **kw):
    args: dict[str, Any] = {"min_interval_s": 60, "per_hour": 3, "per_day": 5}
    args.update(kw)
    return limiter.Limiter(path, **args)


def test_limiter_persists_across_instances(tmp_path):
    state = tmp_path / "lim.json"
    a = _limiter(state)
    assert a.check("s", 1000.0) == (True, "")
    a.begin_attempt("s", 1000.0)
    a.record_attempt("s", 1001.0, "ok")
    b = _limiter(state)
    ok, reason = b.check("s", 1010.0)
    assert not ok and "interval" in reason
    assert b.check("s", 1100.0)[0]
    assert b.check("other", 1010.0)[0]


COOL = 12 * 3600.0


def test_limiter_post_submit_failure_cools_down(tmp_path):
    state = tmp_path / "lim.json"
    a = _limiter(state, cooldown_s=COOL)
    a.record_attempt("s", 1000.0, "unknown")
    for inst in (a, _limiter(state, cooldown_s=COOL)):  # persisted
        ok, reason = inst.check("s", 1000.0 + COOL - 60)
        assert not ok and "cooldown" in reason
    assert _limiter(state, cooldown_s=COOL).check("s", 1000.0 + COOL + 1)[0]


def test_limiter_three_post_submit_failures_hard_block(tmp_path):
    state = tmp_path / "lim.json"
    t = 0.0
    for _ in range(3):
        t += COOL + 10
        lim = _limiter(state, cooldown_s=COOL)
        assert lim.check("s", t)[0]
        lim.record_attempt("s", t, "unknown")
    ok, reason = _limiter(state, cooldown_s=COOL).check("s", t + 30 * 86400)
    assert not ok and "reset" in reason
    _limiter(state).reset("s")
    assert _limiter(state).check("s", t + 30 * 86400)[0]


def test_limiter_success_resets_streak(tmp_path):
    state = tmp_path / "lim.json"
    lim = _limiter(state, cooldown_s=COOL)
    t = 0.0
    for outcome in ("unknown", "unknown", "ok", "unknown", "unknown"):
        t += COOL + 10
        assert lim.check("s", t)[0], outcome
        lim.record_attempt("s", t, outcome)
    ok, reason = lim.check("s", t + COOL + 10)
    assert ok, reason  # streak is 2, not 4
    lim.record_attempt("s", t + COOL + 10, "failed")  # pre-submit: no streak
    assert lim.check("s", t + 2 * COOL)[0]


def test_limiter_crashed_inflight_counts_as_one_failure(tmp_path):
    state = tmp_path / "lim.json"
    _limiter(state, cooldown_s=COOL).begin_attempt("s", 1000.0)  # then dies
    ok, reason = _limiter(state, cooldown_s=COOL).check("s", 1000.0 + 60)
    assert not ok and "cooldown" in reason
    # Counted once: a later instance does not count the same marker again.
    assert _limiter(state, cooldown_s=COOL).check("s", 1000.0 + COOL + 1)[0]
    data = json.loads(state.read_text())["sites"]["s"]
    assert data["consecutive"] == 1 and "inflight" not in data
    t = 1000.0
    for _ in range(2):  # two more crashes -> hard block
        t += COOL + 10
        _limiter(state, cooldown_s=COOL).begin_attempt("s", t)
        _limiter(state, cooldown_s=COOL).check("s", t + 1)
    ok, reason = _limiter(state, cooldown_s=COOL).check("s", t + 30 * 86400)
    assert not ok and "reset" in reason


def test_limiter_cooldown_from_env(tmp_path, monkeypatch):
    monkeypatch.setenv("LOGIN_BROKER_COOLDOWN_S", "120")
    lim = _limiter(tmp_path / "lim.json", min_interval_s=0)
    assert lim.cooldown_s == 120
    lim.record_attempt("s", 0.0, "unknown")
    assert not lim.check("s", 100.0)[0] and lim.check("s", 121.0)[0]
    monkeypatch.setenv("LOGIN_BROKER_COOLDOWN_S", "nonsense")
    assert _limiter(tmp_path / "x.json").cooldown_s == 30 * 60


def test_limiter_hourly_and_daily_caps(tmp_path):
    lim = _limiter(tmp_path / "lim.json", min_interval_s=0, per_hour=2, per_day=3)
    lim.record_attempt("s", 0.0, "ok")
    lim.record_attempt("s", 10.0, "failed")
    ok, reason = lim.check("s", 20.0)
    assert not ok and "hourly" in reason
    assert lim.check("s", 3700.0)[0]
    lim.record_attempt("s", 3700.0, "ok")
    ok, reason = lim.check("s", 7400.0)
    assert not ok and "daily" in reason
    assert lim.check("s", 86500.0)[0]


def test_limiter_rejects_bad_outcome(tmp_path):
    with pytest.raises(ValueError):
        _limiter(tmp_path / "l.json").record_attempt("s", 0.0, "maybe")


def test_limiter_fsyncs_file_and_dir(tmp_path, monkeypatch):
    calls = []
    real = os.fsync

    def spy(fd):
        calls.append(os.fstat(fd).st_mode)
        real(fd)

    monkeypatch.setattr(os, "fsync", spy)
    state = tmp_path / "sub" / "lim.json"
    _limiter(state).record_attempt("s", 0.0, "ok")
    import stat as st

    assert any(st.S_ISREG(m) for m in calls) and any(st.S_ISDIR(m) for m in calls)
    assert json.loads(state.read_text())["sites"]["s"]["attempts"][0][1] == "ok"
    assert [p.name for p in state.parent.iterdir()] == ["lim.json"]


def test_limiter_corrupt_state_fails_closed(tmp_path):
    state = tmp_path / "lim.json"
    state.write_text("{not json")
    ok, reason = _limiter(state).check("s", 0.0)
    assert not ok and "unreadable" in reason


# ---------------------------------------------------------------------------
# peercred
# ---------------------------------------------------------------------------


def test_parse_xucred():
    blob = struct.pack("=IIh2x16I", 0, 501, 1, *([20] + [0] * 15))
    assert len(blob) == peercred.XUCRED_SIZE
    assert peercred.parse_xucred(blob) == 501
    with pytest.raises(ValueError):
        peercred.parse_xucred(struct.pack("=II", 7, 501))
    with pytest.raises(ValueError):
        peercred.parse_xucred(b"\x00\x00")


def test_peer_uid_real_socketpair():
    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    with a, b:
        assert peercred.peer_uid(a) == os.getuid()


# ---------------------------------------------------------------------------
# vault
# ---------------------------------------------------------------------------


def test_site_items_and_refusal():
    items = {it.site: it for it in vault.build_items(FIXTURE_ITEMS)}
    assert items["ricardo"].refused is None
    assert items["ricardo"].fill_origins == ["https://login.ricardo.ch"]
    # no agent_login_url: the flow starts at the (built-in) check URL
    ricardo_check = recipes.DEFAULT_CHECK_URLS["ricardo"]
    assert items["ricardo"].check_url == ricardo_check
    assert items["ricardo"].login_url == ricardo_check
    assert items["noorigins"].refused == "missing agent_fill_origins"
    assert items["cscs"].cookie_hosts == ["portal.cscs.ch"]
    assert items["cscs"].check_url == recipes.CSCS_LOGIN_URL


def test_item_without_check_url_or_sentinel_refused():
    bare = vault.site_item_from_json(
        _item("Shop", {"agent_fill_origins": "https://login.shop.example"})
    )
    assert bare.refused and "needs agent_check_url" in bare.refused
    with_check = vault.site_item_from_json(
        _item(
            "Shop",
            {
                "agent_fill_origins": "https://login.shop.example",
                "agent_check_url": "https://www.shop.example/account",
            },
        )
    )
    assert with_check.refused is None
    assert with_check.check_url == "https://www.shop.example/account"
    assert with_check.login_url == "https://www.shop.example/account"
    assert with_check.public()["check_url"] == "https://www.shop.example/account"
    explicit = vault.site_item_from_json(
        _item(
            "Shop",
            {
                "agent_fill_origins": "https://login.shop.example",
                "agent_check_url": "https://www.shop.example/account",
                "agent_login_url": "https://login.shop.example/start",
            },
        )
    )
    assert explicit.login_url == "https://login.shop.example/start"
    sentinel_only = vault.site_item_from_json(
        _item(
            "Shop",
            {
                "agent_fill_origins": "https://login.shop.example",
                "agent_logged_in_selector": "#me",
            },
        )
    )
    assert sentinel_only.refused is None and sentinel_only.check_url == ""
    for bad in ("http://www.shop.example/a", "javascript:alert(1)", "/account"):
        it = vault.site_item_from_json(
            _item(
                "Shop",
                {
                    "agent_fill_origins": "https://login.shop.example",
                    "agent_check_url": bad,
                },
            )
        )
        assert it.refused == "bad agent_check_url", bad


def test_default_cookie_hosts_skip_idp():
    it = vault.site_item_from_json(
        _item(
            "x",
            {
                "agent_fill_origins": "https://auth.cscs.ch, https://www.x.example",
                "agent_logged_in_selector": "#me",
            },
        )
    )
    assert it.site == "x" and it.cookie_hosts == ["www.x.example"]


def test_duplicate_site_refused():
    dup = [FIXTURE_ITEMS[0], FIXTURE_ITEMS[0]]
    items = vault.build_items(dup)
    assert items[0].refused is None and items[1].refused == "duplicate agent_site"


def test_secret_repr_redacted():
    s = vault.Secret("alice", PASSWORD, TOTP_SEED)
    assert PASSWORD not in repr(s) and TOTP_SEED not in repr(s)
    assert PASSWORD not in str(s)


def test_fixture_vault_requires_dev(tmp_path):
    with pytest.raises(vault.VaultError):
        vault.FixtureVault(tmp_path / "x.json", dev=False)


FAKE_BW = r"""#!/usr/bin/env python3
import json, os, sys
log = "@LOG@"  # baked in: BwVault passes no foreign env through
with open(log, "a") as fh:
    fh.write(json.dumps({"argv": sys.argv[1:],
                         "session": os.environ.get("BW_SESSION"),
                         "appdata": os.environ.get("BITWARDENCLI_APPDATA_DIR"),
                         "has_pw": "BW_PASSWORD" in os.environ}) + "\n")
cmd = sys.argv[1]
if cmd == "status":
    print(json.dumps({"status": "unauthenticated"}))
elif cmd == "login":
    assert os.environ.get("BW_CLIENTID") and os.environ.get("BW_CLIENTSECRET")
elif cmd == "unlock":
    assert os.environ["BW_PASSWORD"] == "master-pw"
    print("SESSIONKEY")
elif cmd == "list":
    assert os.environ["BW_SESSION"] == "SESSIONKEY"
    print(open("@ITEMS@").read())
"""


def test_bw_vault_env_only_secrets(tmp_path):
    items = tmp_path / "items.json"
    items.write_text(json.dumps(FIXTURE_ITEMS))
    log = tmp_path / "bw.log"
    fake = tmp_path / "bw"
    fake.write_text(FAKE_BW.replace("@LOG@", str(log)).replace("@ITEMS@", str(items)))
    fake.chmod(0o755)
    boot = vault.BwBootstrap("cid", "csecret", "master-pw", "coll-1")
    v = vault.BwVault(boot, tmp_path / "appdata", bw_bin=str(fake))
    assert [it.site for it in v.items()] == ["ricardo", "noorigins", "cscs"]
    sec = v.secret("ricardo")
    assert sec.password == PASSWORD and sec.totp_seed == TOTP_SEED
    with pytest.raises(vault.VaultError):
        v.secret("noorigins")
    calls = [json.loads(line) for line in log.read_text().splitlines()]
    flat = json.dumps([c["argv"] for c in calls])
    for secret_value in ("cid", "csecret", "master-pw", "SESSIONKEY", PASSWORD):
        assert secret_value not in flat
    verbs = [c["argv"][0] for c in calls]
    assert verbs.count("unlock") == verbs.count("lock") >= 2
    assert ["list", "items", "--collectionid", "coll-1"] in [c["argv"] for c in calls]
    assert all(c["appdata"] == str(tmp_path / "appdata") for c in calls)
    # bw defaults to the Bitwarden cloud: the server is set before every login.
    argvs = [c["argv"] for c in calls]
    server = ["config", "server", vault.DEFAULT_SERVER_URL]
    assert server in argvs
    assert argvs.index(server) < argvs.index(["login", "--apikey"])
    assert all(not c["has_pw"] for c in calls if c["argv"][0] != "unlock")


# ---------------------------------------------------------------------------
# recipes (pure parts)
# ---------------------------------------------------------------------------


def test_fresh_totp_waits_near_step_end():
    slept = []
    t = [29.0]  # 1 s left in the 30 s step

    def clock():
        return t[0]

    def sleep(s):
        slept.append(s)
        t[0] += s

    code = recipes.fresh_totp(TOTP_SEED, clock=clock, sleep=sleep)
    import pyotp

    assert slept and code == pyotp.TOTP(TOTP_SEED).at(int(t[0]))
    assert recipes.fresh_totp("not base32 !!") is None
    assert recipes.fresh_totp("") is None


def test_cscs_on_portal_exact():
    assert recipes.cscs_on_portal("https://portal.cscs.ch/profile/")
    assert not recipes.cscs_on_portal("https://portal.cscs.ch.evil.example/profile/")
    assert not recipes.cscs_on_portal("https://evil.example/?portal.cscs.ch")
    assert not recipes.cscs_on_portal("https://portal.cscs.ch/api-auth/keycloak/x")
    assert not recipes.cscs_on_portal("https://portal.cscs.ch/x?code=1")


class _SpaPage:
    """The HomePort SPA: renders on the portal, then (no token) moves to Keycloak."""

    def __init__(self, urls: list[str], tokens: list[bool]) -> None:
        self._urls, self._tokens = urls, tokens
        self.url = urls[0]

    def evaluate(self, _js: str) -> bool:
        return self._tokens.pop(0) if self._tokens else False

    def wait_for_timeout(self, _ms: float) -> None:
        if len(self._urls) > 1:
            self._urls.pop(0)
        self.url = self._urls[0]


def test_cscs_portal_ready_needs_the_token():
    """On the portal without a token is NOT logged in (the SPA redirects later)."""
    kc = "https://auth.cscs.ch/auth/realms/cscs/protocol/openid-connect/auth"
    stale = _SpaPage(["https://portal.cscs.ch/profile/", kc], [False])
    assert not recipes.cscs_portal_ready(stale, wait_s=5)
    late = _SpaPage(["https://portal.cscs.ch/profile/"] * 3, [False, False, True])
    assert recipes.cscs_portal_ready(late, wait_s=5)
    never = _SpaPage(["https://portal.cscs.ch/profile/"], [])
    assert not recipes.cscs_portal_ready(never, wait_s=0)
    assert recipes.recipe_for("cscs") is recipes.cscs_login
    assert recipes.recipe_for("ricardo") is recipes.generic_login


class _Frame:
    def __init__(self, url):
        self.url = url


class _Field:
    def __init__(self, frame_url, action=None, *, frame=True):
        self._frame = _Frame(frame_url) if frame else None
        self._action = action

    def owner_frame(self):
        return self._frame

    def evaluate(self, _js):
        return {"form": True, "action": self._action}


class _Page:
    def __init__(self, url):
        self.url = url


@pytest.mark.parametrize(
    "page_url, field, ok",
    [
        ("https://auth.cscs.ch/login", _Field("https://auth.cscs.ch/login"), True),
        ("https://auth.cscs.ch/login", _Field("https://auth.cscs.ch/x", "post"), True),
        # cross-origin iframe on an allowed top page
        ("https://auth.cscs.ch/login", _Field("https://evil.example/frame"), False),
        ("https://auth.cscs.ch/login", _Field("about:blank"), False),
        ("https://auth.cscs.ch/login", _Field("", frame=False), False),
        # same-origin frame, but its form posts elsewhere (relative to the FRAME)
        (
            "https://auth.cscs.ch/login",
            _Field("https://auth.cscs.ch/f", "https://evil.example/s"),
            False,
        ),
        # field on an allowed origin, top page elsewhere
        ("https://evil.example/", _Field("https://auth.cscs.ch/login"), False),
    ],
)
def test_guard_checks_page_frame_and_action(page_url, field, ok):
    if ok:
        recipes._guard(_Page(page_url), field, CSCS, dev=False)
    else:
        with pytest.raises(recipes.OriginViolation):
            recipes._guard(_Page(page_url), field, CSCS, dev=False)


def test_guard_resolves_action_against_frame_url():
    allowed = ["https://auth.cscs.ch", "https://a.example"]
    field = _Field("https://evil.example/frame", "/collect")
    with pytest.raises(recipes.OriginViolation):  # frame itself is foreign
        recipes._guard(_Page("https://auth.cscs.ch/"), field, allowed, dev=False)
    field = _Field("https://a.example/frame", "/collect")  # -> https://a.example
    recipes._guard(_Page("https://auth.cscs.ch/"), field, allowed, dev=False)


class _El:
    def __init__(self, visible=True):
        self._visible = visible

    def is_visible(self):
        return self._visible


class _CheckPage:
    """Just enough of a Playwright page for the positive check."""

    def __init__(self, url, *, password=False, sentinel=False, title="Account"):
        self.url = url
        self._password = password
        self._sentinel = sentinel
        self._title = title
        self.frames = []
        self.waited = []

    def title(self):
        return self._title

    def query_selector_all(self, selector):
        if selector == recipes.PASSWORD_SELECTOR or "password" in selector:
            return [_El(True)] if self._password else [_El(False)]
        return []

    def eval_on_selector_all(self, _sel, _js):
        return []

    def wait_for_selector(self, _sel, **_kw):
        if not self._sentinel:
            raise TimeoutError("no sentinel")
        return _El()

    def wait_for_timeout(self, ms):
        self.waited.append(ms)


SHOP_FILL = "https://login.shop.example"
SHOP_CHECK = "https://www.shop.example/account"


def _shop_item(**fields):
    base = {"agent_site": "shop", "agent_fill_origins": SHOP_FILL}
    return vault.site_item_from_json(_item("Shop", {**base, **fields}))


@pytest.mark.parametrize(
    "url, password, ok",
    [
        # regression (2026-10-02): page 2 of an identifier-first login has no
        # visible password field and a path other than the login URL's
        (SHOP_FILL + "/u/login/identifier?state=x", False, False),
        (SHOP_FILL + "/u/login/password?state=x", False, False),
        (SHOP_CHECK, True, False),  # inline login form on the site itself
        ("chrome-error://chromewebdata/", False, False),
        ("http://www.shop.example/account", False, False),  # not https
        (SHOP_CHECK, False, True),
    ],
)
def test_positive_check_rule(url, password, ok):
    item = _shop_item(agent_check_url=SHOP_CHECK)
    assert recipes.logged_in(_CheckPage(url, password=password), item, wait_s=0) is ok


def test_positive_check_challenge_and_sentinel():
    item = _shop_item(agent_check_url=SHOP_CHECK)
    page = _CheckPage(SHOP_CHECK, title="Just a moment...")
    assert not recipes.logged_in(page, item, wait_s=0)
    only_sentinel = _shop_item(agent_logged_in_selector="#me")
    assert not recipes.logged_in(_CheckPage(SHOP_CHECK), only_sentinel, wait_s=0)
    page = _CheckPage(SHOP_FILL + "/x", sentinel=True)
    assert recipes.logged_in(page, only_sentinel, wait_s=0)


def test_client_broker_logged_in_uses_check_url(monkeypatch, capsys):
    entry = {
        "site": "shop",
        "fill_origins": [SHOP_FILL],
        "login_url": SHOP_FILL + "/",
        "check_url": SHOP_CHECK,
        "logged_in_selector": None,
    }
    monkeypatch.setattr(browser, "_broker_entry_or_rc", lambda site: (entry, 0))
    opened = []
    final = {"url": ""}

    viewports = []

    class _SizedPage(_CheckPage):
        def set_viewport_size(self, size):
            viewports.append(size)

    def fake_bg(port, url, prepare, fn):
        opened.append(url)
        page = _SizedPage(final["url"])
        prepare(page)
        return fn(page)

    monkeypatch.setattr(browser, "_with_prepared_background_page", fake_bg)
    # still on the login (Auth0 page 2: no visible password) -> NOT logged in
    final["url"] = SHOP_FILL + "/u/login/password?state=x"
    assert browser._broker_logged_in(9222, "shop") == 2
    final["url"] = SHOP_CHECK
    assert browser._broker_logged_in(9222, "shop") == 0
    assert opened == [SHOP_CHECK, SHOP_CHECK]
    # the probe tab is sized like the broker's page before the check loads
    assert viewports == [browser.BROKER_PROBE_VIEWPORT] * 2
    # neither check URL nor sentinel: refuses to call it logged in, opens nothing
    entry["check_url"] = ""
    assert browser._broker_logged_in(9222, "shop") == 2
    assert len(opened) == 2
    assert "no check URL or sentinel" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# daemon over a real socket
# ---------------------------------------------------------------------------


@pytest.fixture
def sockdir():
    # AF_UNIX paths are capped at 104 bytes on macOS; pytest's tmp_path is longer.
    d = tempfile.mkdtemp(prefix="lb-")
    yield Path(d)
    shutil.rmtree(d, ignore_errors=True)


class StubRunner:
    """Counts invocations; optionally waits until a second caller is coalesced."""

    def __init__(self, *, wait_for_waiter=None, raise_exc=None):
        self.calls = 0
        self.wait_for_waiter = wait_for_waiter
        self.raise_exc = raise_exc
        self.lock = threading.Lock()

    def __call__(self, item, get_secret):
        with self.lock:
            self.calls += 1
        secret = get_secret()
        assert secret.password == PASSWORD
        if self.wait_for_waiter is not None:
            broker, site = self.wait_for_waiter
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                fl = broker._flights.get(site)
                if fl is not None and fl.waiters >= 1:
                    break
                time.sleep(0.01)
        if self.raise_exc is not None:
            raise self.raise_exc
        return {
            "site": item.site,
            "via": "login",
            "cookies": [
                {"name": "sid", "value": "cookie-value", "domain": "ricardo.ch"}
            ],
            "storage": {},
            "cookie_hosts": item.cookie_hosts,
            "cookie_names": item.cookie_names,
        }


def _start(sockdir, tmp_path, runner, *, allow_uid=None, items=None):
    fixture = tmp_path / "items.json"
    fixture.write_text(json.dumps(items if items is not None else FIXTURE_ITEMS))
    home = tmp_path / "home"
    lim = limiter.Limiter(home / "limiter.json", 0, 100, 100)
    brk = daemon.Broker(vault.FixtureVault(fixture, dev=True), lim, home, runner=runner)
    path = str(sockdir / "b.sock")
    srv = daemon.make_server(path, brk, os.getuid() if allow_uid is None else allow_uid)
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    return brk, srv, path


@contextlib.contextmanager
def running(sockdir, tmp_path, runner, **kw):
    brk, srv, path = _start(sockdir, tmp_path, runner, **kw)
    try:
        yield brk, path
    finally:
        srv.shutdown()
        srv.server_close()


def _ask(path, obj, raw=None):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(30)
        s.connect(path)
        s.sendall(raw if raw is not None else json.dumps(obj).encode() + b"\n")
        chunks: list[bytes] = []
        while not chunks or not chunks[-1].endswith(b"\n"):
            chunk = s.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
    return b"".join(chunks)


def test_daemon_forbidden_for_other_uid(sockdir, tmp_path):
    runner = StubRunner()
    with running(sockdir, tmp_path, runner, allow_uid=os.getuid() + 1) as (_brk, path):
        resp = json.loads(_ask(path, {"op": "login", "site": "ricardo"}))
    assert resp == {"ok": False, "error": "forbidden", "detail": ""}
    assert runner.calls == 0
    audit = (tmp_path / "home" / "audit.log").read_text()
    assert '"forbidden"' in audit


def test_daemon_ping_and_sites_without_secrets(sockdir, tmp_path):
    with running(sockdir, tmp_path, StubRunner()) as (_brk, path):
        assert json.loads(_ask(path, {"op": "ping"}))["ok"] is True
        raw = _ask(path, {"op": "sites"})
    text = raw.decode()
    for needle in (PASSWORD, TOTP_SEED, "alice", "password", "totp"):
        assert needle not in text
    sites = {s["site"]: s for s in json.loads(raw)["sites"]}
    assert sites["ricardo"]["refused"] is False
    assert sites["ricardo"]["fill_origins"] == ["https://login.ricardo.ch"]
    assert sites["ricardo"]["cookie_hosts"] == ["ricardo.ch"]
    assert sites["ricardo"]["check_url"] == recipes.DEFAULT_CHECK_URLS["ricardo"]
    assert sites["ricardo"]["logged_in_selector"] == "#account"
    assert sites["noorigins"]["refused"] is True
    assert "agent_fill_origins" in sites["noorigins"]["reason"]


def test_daemon_concurrent_login_coalesces(sockdir, tmp_path):
    runner = StubRunner()
    with running(sockdir, tmp_path, runner) as (brk, path):
        runner.wait_for_waiter = (brk, "ricardo")
        results = []

        def call():
            results.append(_ask(path, {"op": "login", "site": "ricardo"}))

        threads = [threading.Thread(target=call) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(30)
    assert runner.calls == 1
    assert len(results) == 2 and results[0] == results[1]
    resp = json.loads(results[0])
    assert resp["ok"] is True and resp["bundle"]["cookies"][0]["name"] == "sid"
    audit = (tmp_path / "home" / "audit.log").read_text()
    assert PASSWORD not in audit and "cookie-value" not in audit


def test_daemon_refused_unknown_and_bad_requests(sockdir, tmp_path):
    runner = StubRunner()
    with running(sockdir, tmp_path, runner) as (_brk, path):
        refused = json.loads(_ask(path, {"op": "login", "site": "noorigins"}))
        unknown = json.loads(_ask(path, {"op": "login", "site": "nope"}))
        traversal = json.loads(_ask(path, {"op": "logout", "site": "../etc"}))
        bad_op = json.loads(_ask(path, {"op": "reset", "site": "ricardo"}))
        too_big = json.loads(_ask(path, None, raw=b"x" * (70 * 1024) + b"\n"))
        not_json = json.loads(_ask(path, None, raw=b"hello\n"))
    assert refused["error"] == "refused" and "agent_fill_origins" in refused["detail"]
    assert unknown["error"] == "unknown_site"
    assert traversal["error"] == "bad_request"
    assert bad_op["error"] == "bad_request"
    assert too_big["error"] == "bad_request"
    assert not_json["error"] == "bad_request"
    assert runner.calls == 0


def test_daemon_post_submit_failure_cools_down(sockdir, tmp_path):
    runner = StubRunner(raise_exc=recipes.LoginFailed("timeout", submitted=True))
    with running(sockdir, tmp_path, runner) as (_brk, path):
        first = json.loads(_ask(path, {"op": "login", "site": "ricardo"}))
        second = json.loads(_ask(path, {"op": "login", "site": "ricardo"}))
    assert first["error"] == "login_failed"
    assert second["error"] == "rate_limited" and "cooldown" in second["detail"]
    assert runner.calls == 1


def test_daemon_needs_human_and_origin_violation_codes(sockdir, tmp_path):
    for exc, code in (
        (recipes.NeedsHuman("captcha"), "needs_human"),
        (recipes.OriginViolation("page is not on a fill origin"), "origin_violation"),
    ):
        runner = StubRunner(raise_exc=exc)
        sub = tmp_path / code
        sub.mkdir()
        with running(sockdir, sub, runner) as (_brk, path):
            resp = json.loads(_ask(path, {"op": "login", "site": "ricardo"}))
        assert resp["error"] == code


def test_daemon_logout_removes_profile(sockdir, tmp_path):
    with running(sockdir, tmp_path, StubRunner()) as (_brk, path):
        prof = tmp_path / "home" / "profiles" / "ricardo"
        prof.mkdir(parents=True)
        (prof / "Cookies").write_text("x")
        resp = json.loads(_ask(path, {"op": "logout", "site": "ricardo"}))
        again = json.loads(_ask(path, {"op": "logout", "site": "ricardo"}))
    assert resp == {"ok": True, "removed": True} and not prof.exists()
    assert again == {"ok": True, "removed": False}


def test_daemon_cli_guards(tmp_path):
    assert daemon.main(["-f", str(tmp_path / "x.json"), "-H", str(tmp_path)]) == 2
    assert daemon.main(["-d", "-r", "ricardo", "-H", str(tmp_path)]) == 0
    if os.geteuid() != 0:
        assert daemon.main(["-r", "ricardo", "-H", str(tmp_path)]) == 2


# ---------------------------------------------------------------------------
# client: name resolution against a fake broker socket
# ---------------------------------------------------------------------------


@pytest.fixture
def broker_env(sockdir, tmp_path, monkeypatch):
    with running(sockdir, tmp_path, StubRunner()) as (_brk, path):
        monkeypatch.setenv("LOGIN_BROKER_SOCKET", path)
        browser._BROKER_SITES_CACHE.clear()
        yield path
    browser._BROKER_SITES_CACHE.clear()


def test_resolve_site_broker_fallback(broker_env):
    site = browser._resolve_site("ricardo")
    assert site.name == "ricardo"
    assert site.login.func is browser._broker_login
    assert site.logged_in.func is browser._broker_logged_in
    assert browser._resolve_site("claude").name == "anthropic"  # static wins


def test_resolve_site_refused_and_unknown_exit_2(broker_env, capsys):
    for name in ("noorigins", "doesnotexist"):
        with pytest.raises(SystemExit) as exc:
            browser._resolve_site(name)
        assert exc.value.code == 2
    err = capsys.readouterr().err
    assert "not whitelisted in Bitwarden agent-logins or broker down" in err
    assert "refused" in err


def test_resolve_site_cscs_uses_broker_for_login_only(broker_env):
    login_site = browser._resolve_site("cscs", for_login=True)
    assert login_site.login.func is browser._broker_login
    assert login_site.logged_in is browser.cmd_token
    assert browser._resolve_site("cscs").login is browser.cmd_cscs_login


def test_resolve_site_broker_down(monkeypatch, sockdir, capsys):
    monkeypatch.setenv("LOGIN_BROKER_SOCKET", str(sockdir / "absent.sock"))
    browser._BROKER_SITES_CACHE.clear()
    with pytest.raises(SystemExit) as exc:
        browser._resolve_site("ricardo")
    assert exc.value.code == 2
    assert "broker down" in capsys.readouterr().err
    assert browser._resolve_site("cscs", for_login=True).login is browser.cmd_cscs_login
    with pytest.raises(browser.BrokerUnavailable):
        browser._broker_request("ping")


def test_cmd_broker_sites_table(broker_env, capsys):
    assert browser.cmd_broker_sites() == 0
    out = capsys.readouterr().out
    assert "ricardo" in out and "https://login.ricardo.ch" in out
    assert "refused: missing agent_fill_origins" in out


def test_make_server_replaces_own_stale_socket_only(sockdir, tmp_path):
    path = str(sockdir / "s.sock")
    stale = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    stale.bind(path)  # left behind by a "crashed" run
    stale.close()
    lim = limiter.Limiter(tmp_path / "l.json", 0, 9, 9)
    brk = daemon.Broker(
        vault.FixtureVault(tmp_path / "none.json", dev=True),
        lim,
        tmp_path,
        runner=StubRunner(),
    )
    srv = daemon.make_server(path, brk, os.getuid())
    srv.server_close()
    os.unlink(path)
    Path(path).write_text("not a socket", encoding="utf-8")
    with pytest.raises(OSError):
        daemon.make_server(path, brk, os.getuid())
    assert Path(path).read_text(encoding="utf-8") == "not a socket"


def test_socket_defaults_are_persistent():
    want = "/var/db/login-broker-run/broker.sock"
    assert daemon.DEFAULT_SOCKET == want
    assert selfcheck.DEFAULT_SOCKET == want
    assert browser.BROKER_SOCKET_DEFAULT == want
    text = (REPO / "install" / "install.sh").read_text()
    assert 'RUN_DIR="/var/db/login-broker-run"' in text
    assert "/var/run/login-broker" not in text


# ---------------------------------------------------------------------------
# install.sh: root executes only system binaries and its own pinned tools
# ---------------------------------------------------------------------------

INSTALL_SH = REPO / "install" / "install.sh"
SYSTEM_DIRS = ("/usr/bin/", "/bin/", "/usr/sbin/", "/sbin/")
LIBEXEC = "/usr/local/libexec/login-broker/"
# External commands that must never appear bare (i.e. resolved through PATH).
EXTERNALS = (
    "uv uvx git curl shasum tar unzip ditto install cp rm ln mv chown chmod find "
    "launchctl plutil dscl dseditgroup sysadminctl mktemp sed awk seq grep date "
    "sleep readlink cat sudo python python3 env mkdir uname xattr stat head tail "
    "sort tr id touch dirname bw node npm brew"
).split()


def _code_lines(text):
    """install.sh minus comments, heredoc bodies and quoted python snippets."""
    out, skip_until = [], None
    for line in text.splitlines():
        if skip_until is not None:
            if line.strip() == skip_until:
                skip_until = None
            continue
        m = re.search(r"<<'?(\w+)'?", line)
        if m:
            skip_until = m.group(1)
        if line.lstrip().startswith("#"):
            continue
        if "-c '" in line and not line.rstrip().endswith("'"):
            skip_until = '\' "$tmp"'
        out.append(line)
    return out


def test_install_sh_no_bare_externals():

    lines = _code_lines(INSTALL_SH.read_text())
    assert INSTALL_SH.read_text().startswith("#!/bin/bash\n")
    cmd_pos = r"(?:^\s*|[;&|(]\s*|\$\(\s*|\brun\s+|\bas_user\s+|\bthen\s+|\bdo\s+|!\s+)"
    bad = []
    for raw in lines:
        # Quoted strings are messages/arguments, not commands.
        line = re.sub(r"'[^']*'", "''", re.sub(r'"[^"]*"', '""', raw))
        for name in EXTERNALS:
            if re.search(cmd_pos + re.escape(name) + r"(?=\s|$)", line):
                bad.append((name, line.strip()))
    assert not bad, bad
    assert "UV_BIN" not in INSTALL_SH.read_text()
    assert "command -v" not in INSTALL_SH.read_text()


def test_install_sh_dry_run_executes_only_trusted_paths():
    proc = subprocess.run(
        [str(INSTALL_SH), "-n"],
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    cmds = [ln[2:] for ln in proc.stdout.splitlines() if ln.startswith("+ ")]
    assert len(cmds) > 20
    bad = []
    for cmd in cmds:
        if cmd.startswith(("audit:", "verify sha256")):
            continue
        tokens = cmd.split()
        for i, tok in enumerate(tokens):  # the root side of a pipeline counts too
            if i == 0 or tokens[i - 1] == "|":
                prog = tok
                j = i
                if prog.endswith("/env"):  # skip VAR=value assignments
                    j += 1
                    while (
                        j < len(tokens)
                        and "=" in tokens[j]
                        and not tokens[j].startswith("/")
                    ):
                        j += 1
                    prog = tokens[j] if j < len(tokens) else ""
                if not prog.startswith(SYSTEM_DIRS + (LIBEXEC,)):
                    bad.append(cmd)
    assert not bad, bad
    # The pinned downloads are verified before use. On a machine where the pinned
    # tools are already installed the dry run skips the download, so check the
    # script itself for the verify step and the dry run only for the rest.
    out = proc.stdout
    script = INSTALL_SH.read_text()
    assert 'fetch_verified "$UV_URL" "$UV_SHA256"' in script
    assert 'fetch_verified "$BW_URL" "$BW_SHA256"' in script
    assert "/usr/bin/shasum -a 256 -c" in script
    assert "--require-hashes" in out
    assert "/usr/bin/sudo -H -u" in out and "archive" in out


def test_install_sh_pins_look_real():

    text = INSTALL_SH.read_text()
    for var in ("UV_SHA256", "BW_SHA256"):
        m = re.search(var + r'="([0-9a-f]+)"', text)
        assert m and len(m.group(1)) == 64, var
    assert re.search(r'UV_VERSION="\d+\.\d+\.\d+"', text)
    assert re.search(r'BW_VERSION="\d{4}\.\d+\.\d+"', text)


# ---------------------------------------------------------------------------
# selfcheck
# ---------------------------------------------------------------------------


def test_selfcheck_skip_missing(tmp_path):
    args = ["-b", "-H", str(tmp_path / "no-home"), "-c", str(tmp_path / "no-code")]
    assert selfcheck.main([*args, "-s"]) == 0
    assert selfcheck.main(args) == 2
    proc = subprocess.run(
        [sys.executable, str(REPO / "broker" / "selfcheck.py"), *args, "-s"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0 and "SKIP not installed" in proc.stdout


def test_selfcheck_flags_bad_processes_and_own_dirs(tmp_path):
    bad = selfcheck.check_processes(
        [("1", "albert", "chrome --remote-debugging-port=9222 --user-data-dir=/p")],
        {"albert"},
    )
    assert [ok for ok, _ in bad] == [False, False]
    good = selfcheck.check_processes(
        [("2", "_loginbroker", "chrome --remote-debugging-pipe")], {"albert"}
    )
    assert all(ok for ok, _ in good)
    home, code = tmp_path / "home", tmp_path / "code"
    home.mkdir()
    code.mkdir()
    results = selfcheck.run_checks(home, code, tmp_path / "none.sock")
    assert not any(ok for ok, msg in results if msg[:2] in ("b)", "c)", "d)"))


# ---------------------------------------------------------------------------
# dev end-to-end: real headless Chromium against a local login form
# ---------------------------------------------------------------------------

E2E_USER = "alice"
E2E_SESSION = "sess-0123456789"
E2E_EMAIL = "alice@example.com"  # type=email fields validate the identifier


class _LoginApp(http.server.BaseHTTPRequestHandler):
    posts: list[str] = []  # every POST path this app received

    def log_message(self, *args):  # keep pytest output clean
        return

    def _send(self, code, body="", headers=()):
        self.send_response(code)
        for k, v in headers:
            self.send_header(k, v)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self):  # noqa: N802
        logged = f"session={E2E_SESSION}" in (self.headers.get("Cookie") or "")
        if self.path.startswith("/home"):
            if not logged:
                self._send(302, headers=[("Location", "/login")])
                return
            self._send(
                200,
                "<html><body><div id=welcome>hi</div>"
                "<script>localStorage.setItem('tok','t-123');"
                "localStorage.setItem('junk','j')</script></body></html>",
            )
            return
        if self.path.startswith("/evil-login"):  # posts the password off-origin
            self._send(
                200,
                "<html><body><form method=post action=http://localhost:9/steal>"
                "<input type=text name=user><input type=password name=pw>"
                "<button type=submit>Go</button></form></body></html>",
            )
            return
        if self.path.startswith("/login") and logged:
            self._send(302, headers=[("Location", "/home")])
            return
        self._send(
            200,
            "<html><head><title>Login</title></head><body>"
            "<form method=post action=/login>"
            "<input type=text name=user><input type=password name=pw>"
            "<button type=submit>Go</button></form></body></html>",
        )

    def do_POST(self):  # noqa: N802
        _LoginApp.posts.append(self.path)
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n).decode()
        from urllib.parse import parse_qs

        q = parse_qs(body)
        if q.get("user") == [E2E_USER] and q.get("pw") == [PASSWORD]:
            self._send(
                302,
                headers=[
                    # Persistent (Max-Age): Chromium drops SESSION cookies when the
                    # broker closes its profile, so the re-export path needs this.
                    (
                        "Set-Cookie",
                        f"session={E2E_SESSION}; Path=/; Max-Age=3600; HttpOnly",
                    ),
                    ("Location", "/home"),
                ],
            )
        else:
            self._send(302, headers=[("Location", "/login?err=1")])


@pytest.mark.browser
@pytest.mark.skipif(
    os.environ.get("LOGIN_BROKER_E2E") != "1", reason="set LOGIN_BROKER_E2E=1"
)
def test_e2e_dev_login_bundle(sockdir, tmp_path):
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _LoginApp)
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    origin = f"http://127.0.0.1:{port}"
    items = [
        _item(
            "Local",
            {
                "agent_site": "local",
                "agent_fill_origins": origin,
                "agent_login_url": origin + "/login",
                "agent_logged_in_selector": "#welcome",
                "agent_storage_keys": json.dumps({origin: ["tok"]}),
            },
            user=E2E_USER,
            totp=None,
        )
    ]
    home = tmp_path / "home"
    runner = daemon.PlaywrightRunner(home, dev=True)
    try:
        with running(sockdir, tmp_path, runner, items=items) as (_brk, path):
            first = json.loads(_ask(path, {"op": "login", "site": "local"}))
            second = json.loads(_ask(path, {"op": "login", "site": "local"}))
    finally:
        httpd.shutdown()
    assert first["ok"], first
    b = first["bundle"]
    assert b["via"] == "login"
    assert [(c["name"], c["value"]) for c in b["cookies"]] == [("session", E2E_SESSION)]
    assert b["storage"] == {origin: {"tok": "t-123"}}
    assert PASSWORD not in json.dumps(first)
    assert second["ok"] and second["bundle"]["via"] == "profile"
    if runner.channel_fallback:
        print("NOTE: channel='chromium' unavailable; used the default Chromium build")


@pytest.mark.browser
@pytest.mark.skipif(
    os.environ.get("LOGIN_BROKER_E2E") != "1", reason="set LOGIN_BROKER_E2E=1"
)
def test_e2e_dev_foreign_form_action_refused(sockdir, tmp_path):
    _LoginApp.posts.clear()
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _LoginApp)
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    origin = f"http://127.0.0.1:{port}"
    items = [
        _item(
            "Evil",
            {
                "agent_site": "evil",
                "agent_fill_origins": origin,
                "agent_login_url": origin + "/evil-login",
                "agent_check_url": origin + "/home",
            },
            user=E2E_USER,
            totp=None,
        )
    ]
    runner = daemon.PlaywrightRunner(tmp_path / "home", dev=True)
    try:
        with running(sockdir, tmp_path, runner, items=items) as (_brk, path):
            resp = json.loads(_ask(path, {"op": "login", "site": "evil"}))
    finally:
        httpd.shutdown()
    assert resp["error"] == "origin_violation", resp
    assert not _LoginApp.posts


# Static GET pages of `_TwoStepApp`, by path prefix.
_TWO_STEP_PAGES = (
    # no password field, no session
    ("/landing", "<html><body><p>Thanks!</p></body></html>"),
    (
        "/u/login/password",
        "<html><head><title>Password</title></head><body>"
        "<form method=post action=/u/login/password?state=s1>"
        f"<input type=email name=username value={E2E_EMAIL} readonly "
        "autocomplete=username>"
        "<input type=password name=password>"
        "<button type=submit>Log in</button></form></body></html>",
    ),
    (  # SWITCH edu-ID-like identifier page
        "/eduid/identifier",
        "<html><head><title>edu-ID</title></head><body>"
        "<form method=post action=/eduid/identifier>"
        "<input type=email name=username autocomplete=email>"
        "<button type=submit>Continue</button></form></body></html>",
    ),
    # No password field until "Use password" is pressed; the passkey button
    # (first in DOM order) reports any press to the server.
    (
        "/eduid/choose",
        "<html><head><title>edu-ID</title></head><body>"
        "<form method=post action=/u/login/password?state=s1>"
        f"<input type=email name=username value={E2E_EMAIL} readonly "
        "autocomplete=username>"
        "<button type=button id=pk onclick=\"fetch('/eduid/passkey',"
        "{method:'POST'})\">Use a passkey</button>"
        '<button type=button id=usepw onclick="document.getElementById('
        "'pwbox').style.display='block';this.style.display='none'\">"
        "Use password</button>"
        "<div id=pwbox style='display:none'>"
        "<input type=password name=password>"
        "<button type=submit>Log in</button></div>"
        "</form></body></html>",
    ),
    (  # one-page form that "vanishes"
        "/login2",
        "<html><body><form method=post action=/login2>"
        "<input type=text name=user><input type=password name=pw>"
        "<button type=submit>Go</button></form></body></html>",
    ),
)


class _TwoStepApp(http.server.BaseHTTPRequestHandler):
    """An Auth0-like identifier-first login on one origin (the fill origin)
    and the site with its check page on another (same host, other port)."""

    login_origin = ""
    site_origin = ""
    password_page_users: list[str] = []  # usernames posted on page 2
    passkey_clicks: list[str] = []  # edu-ID-like page: passkey button presses

    def log_message(self, *args):
        return

    def _send(self, code, body="", headers=()):
        self.send_response(code)
        for k, v in headers:
            self.send_header(k, v)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body.encode())

    def _form(self):
        n = int(self.headers.get("Content-Length") or 0)
        from urllib.parse import parse_qs

        return parse_qs(self.rfile.read(n).decode(), keep_blank_values=True)

    def do_GET(self):  # noqa: N802
        logged = f"session={E2E_SESSION}" in (self.headers.get("Cookie") or "")
        cls = type(self)
        if self.path.startswith("/account"):  # the check URL
            if logged:
                self._send(200, "<html><body><h1>My account</h1></body></html>")
            else:
                loc = cls.login_origin + "/u/login/identifier?state=s1"
                self._send(302, headers=[("Location", loc)])
            return
        if self.path.startswith("/u/login/identifier"):
            if "state=s1" not in self.path:  # Auth0 needs the site's state
                self._send(400, "<html><body>missing state</body></html>")
                return
            self._send(
                200,
                "<html><head><title>Log in</title></head><body>"
                "<form method=post action=/u/login/identifier?state=s1>"
                "<input type=email name=username autocomplete=email>"
                "<input type=password name=password style='display:none'>"
                "<button type=submit>Continue</button></form></body></html>",
            )
            return
        for prefix, body in _TWO_STEP_PAGES:
            if self.path.startswith(prefix):
                self._send(200, body)
                return
        self._send(404, "nope")

    def do_POST(self):  # noqa: N802
        q = self._form()
        cls = type(self)
        if self.path.startswith("/u/login/identifier"):
            if q.get("username") == [E2E_EMAIL]:
                loc = "/u/login/password?state=s1"
            else:
                loc = "/u/login/identifier?state=s1&err=1"
            self._send(302, headers=[("Location", loc)])
            return
        if self.path.startswith("/eduid/identifier"):
            ok = q.get("username") == [E2E_EMAIL]
            loc = "/eduid/choose" if ok else "/eduid/identifier?err=1"
            self._send(302, headers=[("Location", loc)])
            return
        if self.path.startswith("/eduid/passkey"):
            cls.passkey_clicks.append(self.path)
            self._send(204)
            return
        if self.path.startswith("/u/login/password"):
            cls.password_page_users.append((q.get("username") or [""])[0])
            if q.get("username") == [E2E_EMAIL] and q.get("password") == [PASSWORD]:
                cookie = f"session={E2E_SESSION}; Path=/; Max-Age=3600; HttpOnly"
                self._send(
                    302,
                    headers=[
                        ("Set-Cookie", cookie),
                        ("Location", cls.site_origin + "/account"),
                    ],
                )
            else:
                self._send(302, headers=[("Location", "/u/login/password?err=1")])
            return
        if self.path.startswith("/login2"):  # accepts anything, sets NO session
            self._send(302, headers=[("Location", cls.site_origin + "/landing")])
            return
        self._send(404, "nope")


@contextlib.contextmanager
def _two_step_servers():
    servers = [
        http.server.ThreadingHTTPServer(("127.0.0.1", 0), _TwoStepApp) for _ in range(2)
    ]
    for srv in servers:
        threading.Thread(target=srv.serve_forever, daemon=True).start()
    login, site = (f"http://127.0.0.1:{srv.server_address[1]}" for srv in servers)
    _TwoStepApp.login_origin, _TwoStepApp.site_origin = login, site
    _TwoStepApp.password_page_users = []
    _TwoStepApp.passkey_clicks = []
    try:
        yield login, site
    finally:
        for srv in servers:
            srv.shutdown()
            srv.server_close()


@pytest.mark.browser
@pytest.mark.skipif(
    os.environ.get("LOGIN_BROKER_E2E") != "1", reason="set LOGIN_BROKER_E2E=1"
)
def test_e2e_two_step_login_from_check_url(sockdir, tmp_path):
    with _two_step_servers() as (login, site):
        items = [
            _item(
                "TwoStep",
                {
                    "agent_site": "twostep",
                    "agent_fill_origins": login,
                    "agent_check_url": site + "/account",
                },
                user=E2E_EMAIL,
                totp=None,
            )
        ]
        runner = daemon.PlaywrightRunner(tmp_path / "home", dev=True)
        with running(sockdir, tmp_path, runner, items=items) as (_brk, path):
            first = json.loads(_ask(path, {"op": "login", "site": "twostep"}))
            second = json.loads(_ask(path, {"op": "login", "site": "twostep"}))
    assert first["ok"], first
    b = first["bundle"]
    assert b["via"] == "login"
    assert [(c["name"], c["value"]) for c in b["cookies"]] == [("session", E2E_SESSION)]
    assert PASSWORD not in json.dumps(first)
    # the read-only identifier on page 2 was submitted as shown, not refilled
    assert _TwoStepApp.password_page_users == [E2E_EMAIL]
    assert second["ok"] and second["bundle"]["via"] == "profile"


@pytest.mark.browser
@pytest.mark.skipif(
    os.environ.get("LOGIN_BROKER_E2E") != "1", reason="set LOGIN_BROKER_E2E=1"
)
def test_e2e_identifier_first_use_password_choice(sockdir, tmp_path):
    """Regression (2026-10-07, SWITCH edu-ID with a passkey): after the e-mail
    step the page offers "Use a passkey" / "Use password" and no password
    field. The recipe presses "Use password" and never the passkey button."""
    with _two_step_servers() as (login, site):
        items = [
            _item(
                "EduId",
                {
                    "agent_site": "eduidlike",
                    "agent_fill_origins": login,
                    "agent_login_url": login + "/eduid/identifier",
                    "agent_check_url": site + "/account",
                },
                user=E2E_EMAIL,
                totp=None,
            )
        ]
        runner = daemon.PlaywrightRunner(tmp_path / "home", dev=True)
        with running(sockdir, tmp_path, runner, items=items) as (_brk, path):
            resp = json.loads(_ask(path, {"op": "login", "site": "eduidlike"}))
        passkey_clicks = list(_TwoStepApp.passkey_clicks)
    assert resp["ok"], resp
    assert resp["bundle"]["via"] == "login"
    assert _TwoStepApp.password_page_users == [E2E_EMAIL]
    assert not passkey_clicks
    assert PASSWORD not in json.dumps(resp)


@pytest.mark.parametrize(
    ("name", "ok"),
    [
        ("Use password", True),
        ("  use   password ", True),
        ("Password", True),
        ("Sign in with password", True),
        ("Log in with your password", True),
        ("With password", True),
        ("Passwort verwenden", True),
        ("Mit Passwort anmelden", True),
        ("Passwort", True),
        ("Utiliser le mot de passe", True),
        ("Utiliser un mot de passe", True),
        ("Mot de passe", True),
        ("Use a passkey", False),
        ("Passkey verwenden", False),
        ("Utiliser une clé d'accès", False),
        ("Use a security key", False),
        ("Forgot password?", False),
        ("Reset password", False),
        ("Password forgotten", False),
        ("Use password or passkey", False),
        ("Sign in with WebAuthn", False),
    ],
)
def test_password_choice_name(name, ok):
    assert recipes.password_choice_name(name) is ok


@pytest.mark.browser
@pytest.mark.skipif(
    os.environ.get("LOGIN_BROKER_E2E") != "1", reason="set LOGIN_BROKER_E2E=1"
)
def test_e2e_vanished_password_page_is_not_success(sockdir, tmp_path):
    """Regression (2026-10-02): the password page disappears after submit, but
    the check URL still redirects to the login -> login_failed, never ok."""
    with _two_step_servers() as (login, site):
        items = [
            _item(
                "Vanish",
                {
                    "agent_site": "vanish",
                    "agent_fill_origins": login,
                    "agent_login_url": login + "/login2",
                    "agent_check_url": site + "/account",
                },
                user=E2E_EMAIL,
                totp=None,
            )
        ]
        runner = daemon.PlaywrightRunner(tmp_path / "home", dev=True)
        with running(sockdir, tmp_path, runner, items=items) as (_brk, path):
            resp = json.loads(_ask(path, {"op": "login", "site": "vanish"}))
    assert resp["ok"] is False and resp["error"] == "login_failed", resp
    assert "check URL" in resp["detail"] and "bundle" not in resp
    # The failure report says where it stopped, never the secrets.
    diag = resp.get("diag") or {}
    assert diag.get("url", "").startswith(login), diag
    assert PASSWORD not in json.dumps(diag)
    assert Path(diag["screenshot"]).is_file()


def test_install_role_account_uid_range_and_remnant_check() -> None:
    """macOS role accounts need a UID in 450-499; a record without UniqueID is repaired."""
    script = (
        Path(__file__).resolve().parent.parent / "install" / "install.sh"
    ).read_text()
    assert "/usr/bin/seq 450 499" in script
    assert "seq 200 400" not in script
    assert (
        "role_uid >/dev/null" in script
    )  # existence = has a UniqueID, not just a record


def test_bw_reason_is_fixed_text_never_the_message() -> None:
    msg = "Invalid master password. hunter2-secret"
    assert vault._bw_reason(msg) == ": wrong master password in bootstrap.json"
    assert "hunter2" not in vault._bw_reason(msg)
    assert vault._bw_reason("something odd") == ""


def test_default_cookie_hosts_cover_the_site_domain() -> None:
    hosts = vault._default_cookie_hosts(
        ["https://login.kleinanzeigen.de"],
        "https://www.kleinanzeigen.de/m-meine-anzeigen.html",
    )
    assert hosts == ["kleinanzeigen.de", "login.kleinanzeigen.de"]
    spec = bundle.SiteBundleSpec(cookie_hosts=hosts, cookie_names=None, storage_keys={})
    assert bundle.cookie_in_scope(".kleinanzeigen.de", "session", spec)
    assert bundle.cookie_in_scope("www.kleinanzeigen.de", "s", spec)
    assert not bundle.cookie_in_scope("evil.de", "s", spec)


def test_default_cookie_hosts_keep_idp_out() -> None:
    hosts = vault._default_cookie_hosts(
        ["https://auth.cscs.ch"], "https://portal.cscs.ch/profile/"
    )
    assert hosts == ["cscs.ch"]
    spec = bundle.SiteBundleSpec(cookie_hosts=hosts, cookie_names=None, storage_keys={})
    assert bundle.cookie_in_scope("portal.cscs.ch", "sid", spec)
    assert not bundle.cookie_in_scope("auth.cscs.ch", "KEYCLOAK_SESSION", spec)


def test_install_cleanliness_ignores_untracked_files() -> None:
    """The install is `git archive HEAD`; a stray untracked file must not block it."""
    script = (
        Path(__file__).resolve().parent.parent / "install" / "install.sh"
    ).read_text()
    assert "status --porcelain --untracked-files=no" in script


class _DiagPage:
    """Fake page for page_state.diagnose: echoes the username/password in its texts."""

    url = "https://login.example.ch/u/login/password?state=SECRETSTATE#x"

    def title(self) -> str:
        return f"Hello {USERNAME_FOR_DIAG}"

    def evaluate(self, _js: str) -> dict:
        return {
            "messages": [f"Wrong password {PASSWORD} for {USERNAME_FOR_DIAG}"],
            "buttons": ["Continue"],
            "inputs": ["email:username", "password:password"],
            "frames": ["challenges.cloudflare.com"],
        }

    frames: list = []

    def query_selector_all(self, _sel: str) -> list:
        return []

    def eval_on_selector_all(self, _sel: str, _js: str) -> list:
        return []


USERNAME_FOR_DIAG = "albert@example.ch"


def test_diagnose_masks_secrets_and_query() -> None:
    sec = vault.Secret(USERNAME_FOR_DIAG, PASSWORD, None)
    diag = page_state.diagnose(_DiagPage(), sec)
    flat = json.dumps(diag)
    assert PASSWORD not in flat and USERNAME_FOR_DIAG not in flat
    assert "SECRETSTATE" not in flat
    assert diag["url"] == "https://login.example.ch/u/login/password"
    assert diag["messages"] == ["Wrong password *** for ***"]
    assert diag["inputs"] == ["email:username", "password:password"]


def test_default_cooldown_is_30_minutes(monkeypatch) -> None:
    monkeypatch.delenv("LOGIN_BROKER_COOLDOWN_S", raising=False)
    assert limiter.default_cooldown_s() == 30 * 60


def test_install_has_reset_option() -> None:
    script = (
        Path(__file__).resolve().parent.parent / "install" / "install.sh"
    ).read_text()
    assert "-r | --reset)" in script and "do_reset" in script


def test_item_named_like_a_domain_maps_to_the_known_site() -> None:
    raw = _item("tutti.ch", {"agent_fill_origins": "https://auth.tutti.ch"})
    it = vault.site_item_from_json(raw)
    assert it.site == "tutti" and not it.refused
    assert it.check_url == recipes.DEFAULT_CHECK_URLS["tutti"]
    explicit = _item(
        "x", {"agent_fill_origins": "https://auth.tutti.ch", "agent_site": "mine"}
    )
    assert vault.site_item_from_json(explicit).site == "mine"


class _BlockedPage:
    """Fake page showing a fraud-protection block."""

    url = "https://login.example.de/u/login/password"
    frames: list = []

    def title(self) -> str:
        return "Anmelden"

    def eval_on_selector_all(self, _sel: str, _js: str) -> list:
        return []

    body = "IP-Bereich vorübergehend gesperrt. In deinem IP-Bereich kam es ..."

    def evaluate(self, _js: str) -> str:
        return self.body

    def wait_for_timeout(self, _ms: float) -> None:
        return None


def test_block_page_is_needs_human() -> None:
    reason = recipes.challenge_reason(_BlockedPage())
    assert reason and "blocked" in reason


class _DroppyField:
    """Password field that loses the first fill (page still hydrating)."""

    def __init__(self) -> None:
        self.value = ""
        self.fills = 0

    def fill(self, v: str) -> None:
        self.fills += 1
        self.value = "" if self.fills == 1 else v

    def press_sequentially(self, v: str, delay: int = 0) -> None:
        del delay
        self.value += v

    def input_value(self) -> str:
        return self.value


def test_fill_password_retries_when_value_is_dropped(monkeypatch) -> None:
    field = _DroppyField()
    page = _BlockedPage()
    page.body = ""  # no block text: the password step itself is tested
    monkeypatch.setattr(recipes, "_visible", lambda _p, _s: field)
    monkeypatch.setattr(recipes, "_guard", lambda *_a, **_k: None)
    sec = vault.Secret("u@example.com", PASSWORD, None)
    used = recipes._fill_password(
        page, field, sec, ["https://login.example.de"], dev=False
    )
    assert used is field and field.input_value() == PASSWORD


class _OtpChoicePage:
    """Fake page answering the authenticator-selection script."""

    def __init__(self, answer: str) -> None:
        self.answer = answer
        self.asked: list[str] = []

    def evaluate(self, _js: str, label: str = "") -> str:
        self.asked.append(label)
        return self.answer


def test_select_authenticator_rules() -> None:
    recipes._select_authenticator(_OtpChoicePage("single"), None)
    page = _OtpChoicePage("selected:Mac m1")
    recipes._select_authenticator(page, "Mac m1")
    assert page.asked == ["Mac m1"]
    with pytest.raises(recipes.NeedsHuman):
        recipes._select_authenticator(_OtpChoicePage("ambiguous:work|Mac m1"), None)
    with pytest.raises(recipes.LoginFailed):
        recipes._select_authenticator(_OtpChoicePage("nomatch:work|Mac m1"), "phone")


def test_item_reads_agent_otp_label() -> None:
    raw = _item(
        "cscs",
        {"agent_fill_origins": "https://auth.cscs.ch", "agent_otp_label": "Mac m1"},
    )
    assert vault.site_item_from_json(raw).otp_label == "Mac m1"


class _PortalPage:
    """Fake portal page for the CSCS token-key discovery."""

    url = "https://portal.cscs.ch/"

    def __init__(self, keys: list) -> None:
        self.keys = keys

    def goto(self, *_a, **_k) -> None:
        return None

    def wait_for_timeout(self, _ms: float) -> None:
        return None

    def evaluate(self, _js: str):
        return self.keys

    def close(self) -> None:
        return None


class _PortalCtx:
    def __init__(self, keys: list) -> None:
        self.keys = keys

    def new_page(self) -> _PortalPage:
        return _PortalPage(self.keys)


def _cscs_item() -> vault.SiteItem:
    return vault.site_item_from_json(
        _item("cscs", {"agent_fill_origins": "https://auth.cscs.ch"})
    )


def test_cscs_export_adds_the_portal_token_key(tmp_path) -> None:
    runner = daemon.PlaywrightRunner(tmp_path, dev=False)
    item = _cscs_item()
    spec = runner._with_portal_token_keys(
        _PortalCtx(["waldur/auth/token"]), item, item.bundle_spec
    )
    assert spec.storage_keys == {"https://portal.cscs.ch": ["waldur/auth/token"]}


def test_token_key_discovery_only_for_cscs(tmp_path) -> None:
    runner = daemon.PlaywrightRunner(tmp_path, dev=False)
    other = vault.site_item_from_json(
        _item(
            "x",
            {
                "agent_fill_origins": "https://login.x.example",
                "agent_check_url": "https://www.x.example/me",
            },
        )
    )
    assert (
        runner._with_portal_token_keys(_PortalCtx(["k"]), other, other.bundle_spec)
        == other.bundle_spec
    )
    item = _cscs_item()
    assert (
        runner._with_portal_token_keys(_PortalCtx([]), item, item.bundle_spec)
        == item.bundle_spec
    )


def test_password_fingerprint_is_short_and_stable() -> None:
    import hashlib

    fp = daemon.password_fingerprint("correct horse battery staple")
    want = hashlib.sha256(b"correct horse battery staple").hexdigest()[:4]
    assert fp == f"len=28 sha256:{want}"
    assert "horse" not in fp


def test_fingerprint_op_returns_only_the_check(sockdir, tmp_path) -> None:
    def runner(_item, _get_secret) -> dict:  # never called by this op
        return {}

    with running(sockdir, tmp_path, runner) as (_brk, path):
        resp = json.loads(_ask(path, {"op": "fingerprint", "site": "ricardo"}))
    assert resp["ok"] is True
    assert resp["password_check"] == daemon.password_fingerprint(PASSWORD)
    assert PASSWORD not in json.dumps(resp)


def test_empty_password_is_refused_before_any_login() -> None:
    """2026-10-04: a 'Can view, except passwords' collection hands the broker an
    item with an EMPTY password; typing it failed CSCS + Kleinanzeigen logins."""
    raw = _item("cscs", {"agent_fill_origins": "https://auth.cscs.ch"}, password="")
    with pytest.raises(vault.VaultError, match="Can view"):
        vault.secret_from_json(raw)


def test_sites_cached_until_fresh(tmp_path):
    """The site list is read from the vault once per SITES_TTL_S; `fresh` re-reads."""
    fixture = tmp_path / "items.json"
    fixture.write_text(json.dumps(FIXTURE_ITEMS))
    reads: list[int] = []
    fv = vault.FixtureVault(fixture, dev=True)
    real_items = fv.items

    def counting_items():
        reads.append(1)
        return real_items()

    fv.items = counting_items  # type: ignore[method-assign]
    now = [1000.0]
    lim = limiter.Limiter(tmp_path / "limiter.json", 0, 100, 100)
    brk = daemon.Broker(
        fv, lim, tmp_path / "home", runner=lambda *_a: {}, clock=lambda: now[0]
    )
    assert brk.handle({"op": "sites"}, os.getuid())["ok"]
    assert brk.handle({"op": "sites"}, os.getuid())["ok"]
    assert len(reads) == 1
    brk.handle({"op": "sites", "fresh": True}, os.getuid())
    assert len(reads) == 2
    now[0] += daemon.SITES_TTL_S + 1
    brk.handle({"op": "sites"}, os.getuid())
    assert len(reads) == 3


def test_smartsheet_item_gets_built_in_check_and_sentinel() -> None:
    """Smartsheet's check page stays on the fill origin when logged in, so the
    item needs a sentinel; the built-in one applies unless the item sets one."""
    raw = _item("Smartsheet", {"agent_fill_origins": "https://app.smartsheet.com"})
    it = vault.site_item_from_json(raw)
    assert it.site == "smartsheet" and not it.refused
    assert it.check_url == "https://app.smartsheet.com/b/home"
    assert it.logged_in_selector == recipes.DEFAULT_LOGGED_IN_SELECTORS["smartsheet"]
    assert it.cookie_hosts == ["smartsheet.com", "app.smartsheet.com"]
    assert recipes.recipe_for("smartsheet") is recipes.smartsheet_login
    own = _item(
        "Smartsheet",
        {
            "agent_fill_origins": "https://app.smartsheet.com",
            "agent_logged_in_selector": "#mine",
        },
    )
    assert vault.site_item_from_json(own).logged_in_selector == "#mine"


# ---------------------------------------------------------------------------
# agent_fresh_login (tp#803): a fresh IdP login per call, IdP cookie handed over
# ---------------------------------------------------------------------------

EDUID_FIELDS = {
    "agent_site": "eduid",
    "agent_fill_origins": "https://login.eduid.ch",
    "agent_check_url": "https://eduid.ch/account",
    "agent_cookie_hosts": "eduid.ch login.eduid.ch",
}


def test_item_reads_agent_fresh_login() -> None:
    def parse(value):
        fields = dict(EDUID_FIELDS)
        if value is not None:
            fields["agent_fresh_login"] = value
        return vault.site_item_from_json(_item("SWITCH edu-ID", fields))

    for value in ("true", "TRUE", " 1 ", "yes", "on"):
        assert parse(value).fresh_login is True, value
    for value in (None, "", "false", "0", "no", "Off"):
        it = parse(value)
        assert it.fresh_login is False and not it.refused, value
    bad = parse("maybe")
    assert bad.refused and "agent_fresh_login" in bad.refused
    assert parse("true").public()["fresh_login"] is True


def test_fresh_login_hosts_cover_cookie_hosts_fill_origins_and_parents() -> None:
    it = vault.site_item_from_json(
        _item(
            "x",
            {
                "agent_fill_origins": "https://login.x.example:8443",
                "agent_check_url": "https://www.x.example/me",
                "agent_cookie_hosts": ".www.x.example",
                "agent_fresh_login": "true",
            },
        )
    )
    hosts = daemon.fresh_login_hosts(it)
    assert hosts == ["www.x.example", "login.x.example"]
    reach = daemon.cookie_reaches_hosts
    assert reach(".x.example", hosts)  # parent domain: sent to both hosts
    assert reach("login.x.example", hosts)
    assert reach("a.www.x.example", hosts)  # set below a cookie host
    assert not reach("other.x.example", hosts)
    assert not reach("x.example.evil", hosts)
    assert not reach("", hosts)


def test_eduid_idp_session_cookie_exported_only_when_named() -> None:
    """The IdP's SSO cookie is session-only (no expiry): it leaves the broker,
    still without `expires`, only when the item names login.eduid.ch; the
    client's scope rule agrees in both cases."""
    cookies = [
        _ck("login.eduid.ch", "shib_idp_session", "sso", expires=-1, secure=True),
        _ck("login.eduid.ch", "__Host-JSESSIONID", "j", expires=-1, secure=True),
        _ck(".eduid.ch", "eduid_account", "acct", expires=2_000_000_000.0),
    ]
    named_hosts = ["eduid.ch", "login.eduid.ch"]
    named = bundle.filter_cookies(cookies, bundle.SiteBundleSpec(named_hosts))
    assert [c["name"] for c in named] == [
        "shib_idp_session",
        "__Host-JSESSIONID",
        "eduid_account",
    ]
    assert "expires" not in named[0] and named[0]["secure"] is True
    unnamed = bundle.filter_cookies(cookies, bundle.SiteBundleSpec(["eduid.ch"]))
    assert [c["name"] for c in unnamed] == ["eduid_account"]
    for hosts in (named_hosts, ["eduid.ch"]):
        spec = bundle.SiteBundleSpec(hosts)
        for c in cookies:
            assert bundle.cookie_in_scope(
                c["domain"], c["name"], spec
            ) == browser._broker_cookie_in_scope(c["domain"], c["name"], hosts, None)


class _JarCtx:
    """A cookie jar with Playwright's `cookies` / `clear_cookies` / `add_cookies`."""

    def __init__(self, cookies, log=None):
        self.jar = [dict(c) for c in cookies]
        self.log = log if log is not None else []
        self.pages = [object()]

    def cookies(self):
        return [dict(c) for c in self.jar]

    def clear_cookies(self, name=None, domain=None, path=None):
        self.log.append(("clear", name, domain))
        self.jar = [
            c
            for c in self.jar
            if not (c["name"] == name and c["domain"] == domain and c["path"] == path)
        ]

    def add_cookies(self, cookies):
        self.log.append(("add", tuple(c["name"] for c in cookies)))
        self.jar.extend(dict(c) for c in cookies)


class _JarBrowser:
    def __init__(self, ctx):
        self.contexts = [ctx]


def test_client_import_keeps_a_named_idp_cookie() -> None:
    """browser.py replaces the shared browser's login.eduid.ch cookies with the
    bundle's when the item names that host, and never touches them otherwise."""
    stale = _ck("login.eduid.ch", "shib_idp_session", "stale")
    other = _ck("accounts.google.com", "SID", "g")
    fresh = {**_ck("login.eduid.ch", "shib_idp_session", "sso"), "secure": True}
    named = {
        "cookie_hosts": ["eduid.ch", "login.eduid.ch"],
        "cookie_names": None,
        "cookies": [fresh],
    }
    ctx = _JarCtx([stale, other])
    assert browser._broker_replace_cookies(_JarBrowser(ctx), named) == 1
    assert sorted((c["domain"], c["value"]) for c in ctx.jar) == [
        ("accounts.google.com", "g"),
        ("login.eduid.ch", "sso"),
    ]
    unnamed = {**named, "cookie_hosts": ["eduid.ch"]}
    ctx = _JarCtx([stale])
    assert browser._broker_replace_cookies(_JarBrowser(ctx), unnamed) == 0
    assert [c["value"] for c in ctx.jar] == ["stale"]
    assert not ctx.log


def test_fresh_login_clears_profile_cookies_before_the_recipe(
    tmp_path, monkeypatch
) -> None:
    """With agent_fresh_login the runner wipes the site's cookies (account cookie
    and stale IdP cookie alike), skips the "already logged in" shortcut, and only
    then runs the recipe; unrelated cookies of the profile stay."""
    events: list = []
    ctx = _JarCtx(
        [
            _ck(".eduid.ch", "eduid_account", "acct"),
            _ck("login.eduid.ch", "shib_idp_session", "old"),
            _ck("example.org", "keep"),
        ],
        log=events,
    )
    runner = daemon.PlaywrightRunner(tmp_path, dev=False)
    checks: list = []

    def profile_logged_in(_page, _item):
        checks.append([c["name"] for c in ctx.jar])
        return True

    def recipe(_page, _item, secret, *, dev):
        events.append(("recipe", sorted(c["name"] for c in ctx.jar)))
        assert secret.password == PASSWORD

    monkeypatch.setattr(runner, "_profile_logged_in", profile_logged_in)
    monkeypatch.setattr(daemon, "recipe_for", lambda _site: recipe)
    monkeypatch.setattr(
        runner, "export_bundle", lambda _ctx, it, via: {"site": it.site, "via": via}
    )
    secret = vault.Secret(username="a@b.ch", password=PASSWORD)
    fresh = vault.site_item_from_json(
        _item("SWITCH edu-ID", {**EDUID_FIELDS, "agent_fresh_login": "true"})
    )
    assert runner.run_in_context(ctx, fresh, lambda: secret)["via"] == "login"
    assert events == [
        ("clear", "eduid_account", ".eduid.ch"),
        ("clear", "shib_idp_session", "login.eduid.ch"),
        ("recipe", ["keep"]),
    ]
    assert checks == [["keep"]]  # only the positive proof AFTER the recipe

    # Without the flag the profile's session is reused: no wipe, no recipe.
    events.clear()
    checks.clear()
    ctx.jar.append(_ck(".eduid.ch", "eduid_account", "acct"))
    plain = vault.site_item_from_json(_item("SWITCH edu-ID", EDUID_FIELDS))
    assert runner.run_in_context(ctx, plain, lambda: secret)["via"] == "profile"
    assert not events and len(checks) == 1


E2E_SSO = "sso-0123456789"
E2E_ACCOUNT = "acct-0123456789"


class _IdpApp(http.server.BaseHTTPRequestHandler):
    """An edu-ID-like pair: the site (check page /account, long-lived account
    cookie) logs in through an IdP on another origin whose SSO cookie is
    SESSION-ONLY. A live IdP session passes /idp/login and /idp/authorize
    without any form."""

    idp_origin = ""
    site_origin = ""
    idp_logins: list[str] = []  # one entry per password POST the IdP accepted

    def log_message(self, *args):
        return

    def _send(self, code, body="", headers=()):
        self.send_response(code)
        for k, v in headers:
            self.send_header(k, v)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self):  # noqa: N802
        cookies = self.headers.get("Cookie") or ""
        sso = f"idp_sso={E2E_SSO}" in cookies
        cls = type(self)
        form = (
            "<html><body><form method=post action=/idp/login>"
            "<input type=text name=user><input type=password name=pw>"
            "<button type=submit>Go</button></form></body></html>"
        )
        if self.path.startswith("/account"):
            if f"acct={E2E_ACCOUNT}" in cookies:
                self._send(200, "<html><body><h1>My account</h1></body></html>")
            else:
                self._send(302, headers=[("Location", cls.idp_origin + "/idp/login")])
        elif self.path.startswith("/callback"):
            acct = f"acct={E2E_ACCOUNT}; Path=/; Max-Age=3600; HttpOnly"
            self._send(302, headers=[("Set-Cookie", acct), ("Location", "/account")])
        elif self.path.startswith("/idp/login"):
            if sso:
                self._send(302, headers=[("Location", cls.site_origin + "/callback")])
            else:
                self._send(200, form)
        elif self.path.startswith("/idp/authorize"):
            self._send(
                200, "<html><body><div id=code>c</div></body></html>" if sso else form
            )
        else:
            self._send(404, "nope")

    def do_POST(self):  # noqa: N802
        n = int(self.headers.get("Content-Length") or 0)
        from urllib.parse import parse_qs

        q = parse_qs(self.rfile.read(n).decode())
        cls = type(self)
        if q.get("user") == [E2E_USER] and q.get("pw") == [PASSWORD]:
            cls.idp_logins.append(self.path)
            self._send(
                302,
                headers=[
                    # No Max-Age / Expires: a session cookie, like the real IdP's.
                    ("Set-Cookie", f"idp_sso={E2E_SSO}; Path=/; HttpOnly"),
                    ("Location", cls.site_origin + "/callback"),
                ],
            )
        else:
            self._send(302, headers=[("Location", "/idp/login?err=1")])


@contextlib.contextmanager
def _idp_servers():
    servers = [
        http.server.ThreadingHTTPServer(("127.0.0.1", 0), _IdpApp) for _ in range(2)
    ]
    for srv in servers:
        threading.Thread(target=srv.serve_forever, daemon=True).start()
    idp, site = (f"http://127.0.0.1:{srv.server_address[1]}" for srv in servers)
    _IdpApp.idp_origin, _IdpApp.site_origin = idp, site
    _IdpApp.idp_logins = []
    try:
        yield idp, site
    finally:
        for srv in servers:
            srv.shutdown()
            srv.server_close()


@pytest.mark.browser
@pytest.mark.skipif(
    os.environ.get("LOGIN_BROKER_E2E") != "1", reason="set LOGIN_BROKER_E2E=1"
)
def test_e2e_fresh_login_hands_over_the_session_only_idp_cookie(
    sockdir, tmp_path, monkeypatch
):
    """tp#803: without agent_fresh_login the second call reuses the profile's
    account cookie and carries NO IdP cookie (it was session-only); with it,
    every call logs in at the IdP again and the bundle carries the IdP's
    session cookie, which a fresh client browser then uses to pass the IdP
    without a form. The loopback host stands in for an IdP host here."""
    from playwright.sync_api import sync_playwright

    for mod in (bundle, browser):
        name = "IDP_HOSTS" if mod is bundle else "BROKER_IDP_HOSTS"
        monkeypatch.setattr(mod, name, frozenset({*bundle.IDP_HOSTS, "127.0.0.1"}))
    with _idp_servers() as (idp, site):

        def item(name, **extra):
            fields = {
                "agent_site": name,
                "agent_fill_origins": idp,
                "agent_check_url": site + "/account",
                "agent_cookie_hosts": "127.0.0.1",
                **extra,
            }
            return _item(name, fields, user=E2E_USER, totp=None)

        items = [item("plain"), item("fresh", agent_fresh_login="true")]
        runner = daemon.PlaywrightRunner(tmp_path / "home", dev=True)
        with running(sockdir, tmp_path, runner, items=items) as (_brk, path):
            got = {
                (site_id, n): json.loads(_ask(path, {"op": "login", "site": site_id}))
                for site_id in ("plain", "fresh")
                for n in (1, 2)
            }
        for resp in got.values():
            assert resp["ok"], resp
            assert PASSWORD not in json.dumps(resp)

        def names(key):
            return sorted(c["name"] for c in got[key]["bundle"]["cookies"])

        assert got["plain", 1]["bundle"]["via"] == "login"
        assert names(("plain", 1)) == ["acct", "idp_sso"]
        assert got["plain", 2]["bundle"]["via"] == "profile"
        assert names(("plain", 2)) == ["acct"]  # the bug: no IdP session left
        for n in (1, 2):
            assert got["fresh", n]["bundle"]["via"] == "login"
            assert names(("fresh", n)) == ["acct", "idp_sso"]
        sso = next(
            c for c in got["fresh", 2]["bundle"]["cookies"] if c["name"] == "idp_sso"
        )
        assert sso["value"] == E2E_SSO and "expires" not in sso
        assert len(_IdpApp.idp_logins) == 3  # plain once, fresh twice

        # Client import into a fresh browser holding a stale IdP cookie.
        with sync_playwright() as pw:
            client = pw.chromium.launch(headless=True)
            try:
                ctx = client.new_context()
                ctx.add_cookies(
                    [{"name": "idp_sso", "value": "stale", "url": idp + "/"}]
                )
                assert (
                    browser._broker_replace_cookies(client, got["fresh", 2]["bundle"])
                    == 2
                )
                page = ctx.new_page()
                page.goto(idp + "/idp/authorize")
                assert page.locator("#code").count() == 1
                assert page.locator("input[type=password]").count() == 0
            finally:
                client.close()


# ---------------------------------------------------------------------------
# tp#816 A1: org-keyed bootstrap, serialised + cached secrets collection
# ---------------------------------------------------------------------------


def _bootfile(path, **extra):
    data = {
        "client_id": "cid",
        "client_secret": "csecret",
        "master_password": "master-pw",
        "collection_id": "coll-login",
        **extra,
    }
    path.write_text(json.dumps(data))
    return path


def test_bootstrap_without_and_with_the_new_keys(tmp_path):
    old = vault.BwBootstrap.load(_bootfile(tmp_path / "a.json"))
    assert old.organization_id is None and old.secrets_collection_id is None
    new = vault.BwBootstrap.load(
        _bootfile(
            tmp_path / "b.json",
            organization_id="org-a",
            secrets_organization_id="org-s",
            secrets_collection_id="coll-s",
        )
    )
    assert (new.organization_id, new.secrets_organization_id) == ("org-a", "org-s")
    assert new.secrets_collection_id == "coll-s"
    assert "master-pw" not in repr(new) and "csecret" not in repr(new)
    with pytest.raises(vault.VaultError):
        vault.BwBootstrap.load(_bootfile(tmp_path / "c.json", organization_id=""))
    with pytest.raises(vault.SecretsNotConfigured):
        vault.BwVault(old, tmp_path / "appdata").secret_items()


FAKE_BW_SECRETS = r"""#!/usr/bin/env python3
import json, sys, time
log = "@LOG@"
cmd = sys.argv[1]
with open(log, "a") as fh:
    fh.write(json.dumps(sys.argv[1:]) + "\n")
if cmd == "status":
    print(json.dumps({"status": "locked"}))
elif cmd == "unlock":
    print("SESSIONKEY")
elif cmd == "list":
    time.sleep(@SLEEP@)
    print(open("@ITEMS@").read())
"""


def _fake_bw(tmp_path, items, *, sleep=0.0):
    items_file = tmp_path / "secret-items.json"
    items_file.write_text(json.dumps(items))
    log = tmp_path / "bw.log"
    fake = tmp_path / "bw"
    fake.write_text(
        FAKE_BW_SECRETS.replace("@LOG@", str(log))
        .replace("@ITEMS@", str(items_file))
        .replace("@SLEEP@", str(sleep))
    )
    fake.chmod(0o755)
    return fake, log, items_file


def _sitem(name, password, **kw):
    item = {
        "id": f"id-{name}",
        "name": name,
        "login": {"username": "u", "password": password, "totp": None},
        "fields": [],
    }
    item.update(kw)
    return item


def _bwv(tmp_path, fake, *, org="org-s", cache=None):
    boot = vault.BwBootstrap(
        "cid",
        "csecret",
        "master-pw",
        "coll-login",
        secrets_organization_id=org,
        secrets_collection_id="coll-s",
    )
    return vault.BwVault(boot, tmp_path / "appdata", bw_bin=str(fake), cache=cache)


def test_foreign_org_item_with_the_same_collection_id_is_dropped(tmp_path):
    pw_a, pw_b = os.urandom(12).hex(), os.urandom(12).hex()
    items = [
        _sitem("Mine", pw_a, organizationId="org-s", collectionIds=["coll-s"]),
        _sitem("Foreign", pw_b, organizationId="org-x", collectionIds=["coll-s"]),
        _sitem("Elsewhere", pw_b, organizationId="org-s", collectionIds=["coll-y"]),
    ]
    fake, log, _items = _fake_bw(tmp_path, items)
    v = _bwv(tmp_path, fake)
    assert [it.secret_id for it in v.secret_items()] == ["mine"]
    with pytest.raises(vault.VaultError):
        v.secret_values("foreign")
    argvs = [json.loads(line) for line in log.read_text().splitlines()]
    assert ["list", "items", "--collectionid", "coll-s"] in argvs
    # Without an org id the collection's items are kept as listed (old bootstrap).
    assert len(vault.filter_org(items, None, "coll-s")) == 3


def test_concurrent_misses_share_one_bw_read(tmp_path):
    fake, log, _items = _fake_bw(tmp_path, [_sitem("A", "a" * 20)], sleep=0.5)
    v = _bwv(tmp_path, fake, org=None)
    results, errors = [], []

    def worker():
        try:
            results.append(v.secret_values("a").fields["password"])
        except Exception as exc:  # noqa: BLE001  # pylint: disable=broad-exception-caught
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    assert not errors and results == ["a" * 20] * 8
    verbs = [json.loads(line)[0] for line in log.read_text().splitlines()]
    assert verbs.count("unlock") == 1
    assert verbs.count("sync") == 1
    assert verbs.count("list") == 1
    assert verbs.count("lock") == 1


def test_rotation_with_invalidate_never_serves_the_old_value(tmp_path):
    old, new = os.urandom(12).hex(), os.urandom(12).hex()
    fake, log, items_file = _fake_bw(tmp_path, [_sitem("A", old)])
    v = _bwv(tmp_path, fake, org=None)
    assert v.secret_values("a").fields["password"] == old
    items_file.write_text(json.dumps([_sitem("A", new)]))
    assert v.secret_values("a").fields["password"] == old  # cached (300 s)
    v.invalidate()
    for _ in range(3):
        assert v.secret_values("a").fields["password"] == new
    reads = [json.loads(line)[0] for line in log.read_text().splitlines()]
    assert reads.count("list") == 2


def test_cache_ttl_with_a_fake_clock(tmp_path):
    now = [100.0]
    cache = vault_cache.VaultCache(ttl_s=300, clock=lambda: now[0])
    fake, log, _items = _fake_bw(tmp_path, [_sitem("A", "a" * 20)])
    v = _bwv(tmp_path, fake, org=None, cache=cache)
    v.secret_values("a")
    now[0] += 299
    v.secret_values("a")
    now[0] += 2
    v.secret_values("a")
    lists = [json.loads(line)[0] for line in log.read_text().splitlines()]
    assert lists.count("list") == 2


def test_cache_caps_evict_oldest_and_stale_generations_are_refused():
    cache = vault_cache.VaultCache(max_items=3, max_bytes=100)
    gen = cache.generation
    for k in range(4):
        assert cache.put(("k", k), k, size=10, generation=gen)
    assert cache.get(("k", 0)) is None and cache.get(("k", 3)) == 3
    assert len(cache) == 3
    cache.put(("big", 1), "x", size=80, generation=gen)
    assert cache.nbytes <= 100 and cache.get(("k", 1)) is None
    assert not cache.put(("huge", 1), "x", size=101, generation=gen)
    new_gen = cache.bump()
    assert len(cache) == 0
    assert not cache.put(("k", 9), 9, size=1, generation=gen)  # read before bump
    assert cache.put(("k", 9), 9, size=1, generation=new_gen)


# ---------------------------------------------------------------------------
# tp#816 A2: SecretItem + field policy
# ---------------------------------------------------------------------------


def _secret_json(name, password, fields=None, **kw):
    item = _sitem(name, password, **kw)
    item["fields"] = [{"name": k, "value": v} for k, v in (fields or {}).items()]
    return item


def test_secret_item_default_exposes_password_only():
    seed = "JBSWY3DPEHPK3PXP"
    raw = _secret_json("My Item", "p" * 20, {"api_token": "t" * 20})
    raw["login"]["totp"] = seed
    item, values = vault.secret_item_from_json(raw, 1)
    assert item.secret_id == "my-item" and item.fields == ("password",)
    assert item.has_totp and values is not None
    assert dict(values.fields) == {"password": "p" * 20}
    pub = json.dumps(item.public())
    assert seed not in pub and "p" * 20 not in pub and "t" * 20 not in pub
    assert "<redacted>" in repr(values) and seed not in repr(values)


def test_secret_item_listed_fields():
    raw = _secret_json(
        "Svc",
        "p" * 20,
        {"agent_secret_fields": "username, api_token", "api_token": "t" * 20},
    )
    raw["login"]["username"] = "user-name-1"
    item, values = vault.secret_item_from_json(raw, 1)
    assert item.fields == ("password", "username", "api_token")
    assert values is not None and values.fields["api_token"] == "t" * 20
    raw2 = _secret_json(
        "Svc", "p" * 20, {"agent_secret_fields": "notes"}, notes="n" * 9
    )
    assert vault.secret_item_from_json(raw2, 1)[0].fields == ("password", "notes")


def test_secret_item_refusals():
    dup = _secret_json("Dup", "p" * 20)
    dup["fields"] = [{"name": "a", "value": "1"}, {"name": "a", "value": "2"}]
    assert "duplicate" in (vault.secret_item_from_json(dup, 1)[0].refused or "")
    seed = _secret_json("Seed", "p" * 20, {"agent_secret_fields": "totp"})
    assert "TOTP" in (vault.secret_item_from_json(seed, 1)[0].refused or "")
    cfg = _secret_json("Cfg", "p" * 20, {"agent_secret_fields": "agent_secret_id"})
    assert vault.secret_item_from_json(cfg, 1)[0].refused
    bad_id = _secret_json("X", "p" * 20, {"agent_secret_id": "Not Valid!"})
    item, vals = vault.secret_item_from_json(bad_id, 4)
    assert item.refused and item.secret_id == "item-4" and vals is None
    items, values = vault.build_secret_items(
        [_secret_json("Same", "p" * 20), _secret_json("same", "q" * 20)]
    )
    assert items[1].refused == "duplicate agent_secret_id"
    assert set(values) == {"same"} and values["same"].fields["password"] == "p" * 20


def test_secret_item_unsafe_names_are_replaced():
    raw = _secret_json(
        "x" * 70, "p" * 20, {"agent_secret_id": "ok-id", "agent_secret_fields": "a\tb"}
    )
    raw["fields"].append({"name": "a\tb", "value": "v" * 10})
    item, _vals = vault.secret_item_from_json(raw, 7)
    assert item.name == "item-7"
    assert item.fields == ("password", "field-1")
    assert vault.safe_name("ok name.1", 3) == "ok name.1"
    assert vault.safe_name("pw=hunter2!", 3) == "item-3"


def test_secret_item_short_values():
    refused, _ = vault.secret_item_from_json(_secret_json("S", "abc1234"), 1)
    assert "too short" in (refused.refused or "")
    assert "allow_short" in (refused.refused or "")
    ok, vals = vault.secret_item_from_json(
        _secret_json("S", "abc1234", {"agent_secret_allow_short": "true"}), 1
    )
    assert ok.refused is None and ok.short and vals is not None
    assert vals.fields["password"] == "abc1234"
    tiny, _ = vault.secret_item_from_json(
        _secret_json("T", "abc12", {"agent_secret_allow_short": "true"}), 1
    )
    assert "too short" in (tiny.refused or "")  # under 6 bytes: not even raw-only
    ws, _ = vault.secret_item_from_json(_secret_json("W", "        "), 1)
    assert "whitespace" in (ws.refused or "")
    eight, _ = vault.secret_item_from_json(_secret_json("S8", "abc12345"), 1)
    assert eight.refused is None and not eight.short


# ---------------------------------------------------------------------------
# tp#816 A3: atomic limiter reservation + issued-run table
# ---------------------------------------------------------------------------


def test_reserve_is_atomic_under_concurrency(tmp_path):
    lim = limiter.Limiter(tmp_path / "s.json", 0, 10, 100)
    granted: list[Any] = []
    denied: list[Any] = []

    def worker():
        res = lim.reserve(["secret:x"], 1000.0)
        (granted if isinstance(res, limiter.Reservation) else denied).append(res)

    threads = [threading.Thread(target=worker) for _ in range(50)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    assert len(granted) == 10 and len(denied) == 40
    again = limiter.Limiter(tmp_path / "s.json", 0, 10, 100)  # crash / restart
    assert isinstance(again.reserve(["secret:x"], 1001.0), limiter.Denied)
    assert oct((tmp_path / "s.json").stat().st_mode & 0o777) == "0o600"


def test_reserve_checks_item_and_global_caps_in_one_call(tmp_path):
    caps = {"secret:*": (3, 0), "secret:": (2, 0)}
    lim = limiter.Limiter(tmp_path / "s.json", 0, 99, 99, key_caps=caps)
    assert isinstance(lim.reserve(["secret:a", "secret:*"], 0.0), limiter.Reservation)
    assert isinstance(lim.reserve(["secret:a", "secret:*"], 1.0), limiter.Reservation)
    item = lim.reserve(["secret:a", "secret:*"], 2.0)
    assert isinstance(item, limiter.Denied) and item.key == "secret:a"
    assert isinstance(lim.reserve(["secret:b", "secret:*"], 3.0), limiter.Reservation)
    glob = lim.reserve(["secret:c", "secret:*"], 4.0)
    assert isinstance(glob, limiter.Denied) and glob.key == "secret:*"
    # a denied call recorded nothing for its other keys
    state = json.loads((tmp_path / "s.json").read_text())["sites"]
    assert "secret:c" not in state
    assert len(state["secret:*"]["attempts"]) == 3
    # an hour later the hourly caps have room again
    assert isinstance(
        lim.reserve(["secret:a", "secret:*"], 3700.0), limiter.Reservation
    )


def test_reserve_fails_closed_on_corrupt_state(tmp_path):
    (tmp_path / "s.json").write_text("{nope")
    lim = limiter.Limiter(tmp_path / "s.json", 0, 10, 10)
    res = lim.reserve(["secret:x"], 0.0)
    assert isinstance(res, limiter.Denied) and "unreadable" in res.reason


def test_run_table_nonce_once_expiry_and_crash(tmp_path):
    now = [1000.0]
    path = tmp_path / "runs.json"
    table = runs.RunTable(path, clock=lambda: now[0])
    nonce = table.issue(501, ["a:password"], ["X"], "kubectl")
    assert len(nonce) == 64 and int(nonce, 16) >= 0
    assert oct(path.stat().st_mode & 0o777) == "0o600"
    # a fresh instance (daemon restart) still knows the row
    reborn = runs.RunTable(path, clock=lambda: now[0])
    with pytest.raises(runs.RunError):
        reborn.close(nonce, 502, exit_code=0, masked=0)  # another uid
    row = reborn.close(nonce, 501, exit_code=0, masked=1)
    assert row["state"] == "done" and row["masked"] == 1
    with pytest.raises(runs.RunError):
        reborn.close(nonce, 501, exit_code=0, masked=0)
    stale = table.issue(501, ["a:password"], [], "sh")
    now[0] += 601
    abandoned = table.expire()
    assert [r["nonce"] for r in abandoned] == [stale[:8]]
    assert stale not in json.dumps(abandoned)
    with pytest.raises(runs.RunError):
        table.close(stale, 501, exit_code=0, masked=0)


# ---------------------------------------------------------------------------
# tp#816 A9: install + collection switch tooling
# ---------------------------------------------------------------------------


def _dry(*args):
    proc = subprocess.run(
        [str(INSTALL_SH), "-n", *args],
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    return proc.stdout


def test_install_sh_dry_run_ships_secret_run_and_links_it():
    out = _dry()
    assert "archive" in out and "bin/secret_run.py bin/secret-run" in out
    assert (
        "/bin/ln -sfn /usr/local/libexec/login-broker/current/bin/secret-run "
        "/usr/local/bin/secret-run" in out
    )
    assert "selfcheck.py -b" in out
    assert "/usr/bin/sudo -u nobody" in out and "selfcheck.py -F" in out
    assert "selfcheck.py -P" in out
    text = INSTALL_SH.read_text()
    assert '/usr/bin/stat -f %u "$LINK_DIR"' in text  # refuses a user-owned dir
    assert "/bin/rm -f /usr/local/bin/secret-run" in _dry("-U")


def test_install_sh_dry_run_collection_switch_and_rollback():
    listing = _dry("-c")
    assert "/usr/bin/sudo -u _loginbroker" in listing and "daemon.py -H" in listing
    assert listing.rstrip().endswith("-C")
    switch = _dry("-C", "org-1:coll-1", "-X", "org-2:coll-2")
    assert "bootstrap_switch.py -H /var/db/login-broker -v - -C org-1:coll-1" in switch
    assert "-X org-2:coll-2" in switch
    assert "/bin/launchctl kill SIGHUP system/com.albert.login-broker" in switch
    rollback = _dry("-B")
    assert "bootstrap_switch.py -H /var/db/login-broker -B" in rollback
    assert "SIGHUP" in rollback
    reset = _dry("-r", "secret:github")
    assert "daemon.py -H /var/db/login-broker -r secret:github" in reset
    for bad in (["-C", "no-colon"], ["-X", "a:b c"], ["-r", "secret:Bad!"]):
        proc = subprocess.run(
            [str(INSTALL_SH), "-n", *bad], capture_output=True, text=True, check=False
        )
        assert proc.returncode != 0 and "❌" in proc.stderr
    usage = subprocess.run(
        [str(INSTALL_SH), "-h"], capture_output=True, text=True, check=False
    ).stdout
    for flag in (
        "-c, --collections",
        "-C, --login-collection",
        "-X, --secrets-collection",
        "-B, --rollback-bootstrap",
    ):
        assert flag in usage


VISIBLE = (
    "org-new\tShared\tcoll-new\tagent-login\norg-new\tShared\tcoll-sec\tagent-secrets\n"
)


def test_bootstrap_switch_refuses_invisible_ids_and_keeps_the_file(tmp_path, capsys):
    home = tmp_path
    boot = _bootfile(home / "bootstrap.json")
    before = boot.read_bytes()
    visible = home / "visible.tsv"
    visible.write_text(VISIBLE)
    rc = bootstrap_switch.main(
        ["-H", str(home), "-v", str(visible), "-C", "org-other:coll-new"]
    )
    assert rc == 1 and boot.read_bytes() == before
    assert not list(home.glob("bootstrap.json.prev-*"))
    assert "❌" in capsys.readouterr().err


def test_bootstrap_switch_rewrites_and_rolls_back(tmp_path, capsys):
    home = tmp_path
    boot = _bootfile(home / "bootstrap.json")
    before = boot.read_bytes()
    visible = home / "visible.tsv"
    visible.write_text(VISIBLE)
    args = ["-H", str(home), "-v", str(visible)]
    assert (
        bootstrap_switch.main(
            [*args, "-C", "org-new:coll-new", "-X", "org-new:coll-sec"]
        )
        == 0
    )
    new = json.loads(boot.read_text())
    assert new["client_secret"] == "csecret" and new["master_password"] == "master-pw"
    assert new["organization_id"] == "org-new" and new["collection_id"] == "coll-new"
    assert new["secrets_collection_id"] == "coll-sec"
    assert oct(boot.stat().st_mode & 0o777) == "0o600"
    prevs = list(home.glob("bootstrap.json.prev-*"))
    assert len(prevs) == 1 and prevs[0].read_bytes() == before
    out = capsys.readouterr().out
    assert "✅" in out and "master-pw" not in out and "csecret" not in out
    # the same switch again: nothing to do
    assert bootstrap_switch.main([*args, "-C", "org-new:coll-new"]) == 0
    assert len(list(home.glob("bootstrap.json.prev-*"))) == 1
    # rollback restores the original; the switched file is kept
    assert bootstrap_switch.main(["-H", str(home), "-B"]) == 0
    assert boot.read_bytes() == before
    kept = list(home.glob("bootstrap.json.prev-*"))
    assert (
        len(kept) == 1
        and json.loads(kept[0].read_text())["collection_id"] == "coll-new"
    )


def test_selfcheck_secret_run_checks(tmp_path):
    code = tmp_path / "code"
    (code / "bin").mkdir(parents=True)
    (code / "bin" / "secret_run.py").write_text("")
    (code / "bin" / "secret-run").write_text("")
    link = tmp_path / "secret-run"
    ok, msg = selfcheck.check_link(link, code)
    assert not ok and "missing" in msg
    link.write_text("")
    ok, msg = selfcheck.check_link(link, code)
    assert not ok and "not a symlink" in msg
    link.unlink()
    link.symlink_to(code / "bin" / "secret-run")
    ok, msg = selfcheck.check_link(link, code)
    assert not ok and ("root" in msg or os.geteuid() == 0)
    ok, msg = selfcheck.check_client_writable(code, "me")
    assert not ok and "writable" in msg
    home = tmp_path / "home"
    home.mkdir()
    good = home / "secret-runs.json"
    good.write_text("{}")
    good.chmod(0o600)
    bad = home / "secret-limiter.json"
    bad.write_text("{}")
    bad.chmod(0o644)
    verdicts = dict(
        (m.split(" ", 2)[1], ok) for ok, m in selfcheck.check_state_perms(home)
    )
    assert verdicts["secret-runs.json"] is True
    assert verdicts["secret-limiter.json"] is False
    assert verdicts["leakcheck-labels.json"] is True  # not created yet


def test_selfcheck_forbidden_probe(sockdir, tmp_path):
    with running(sockdir, tmp_path, StubRunner(), allow_uid=os.getuid() + 1) as (
        _b,
        path,
    ):
        ok, msg = selfcheck.probe_forbidden(Path(path))
    assert ok and "forbidden" in msg
    sub = tmp_path / "served"
    sub.mkdir()
    with running(sockdir, sub, StubRunner()) as (brk, path):  # serves our uid
        brk.allow_uid = os.getuid()
        ok, _msg = selfcheck.probe_forbidden(Path(path))
    assert not ok
