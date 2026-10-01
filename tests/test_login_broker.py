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

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from broker import (  # noqa: E402
    bundle,
    daemon,
    limiter,
    origins,
    peercred,
    recipes,
    selfcheck,  # noqa: E402
    vault,
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
    args = {"min_interval_s": 60, "per_hour": 3, "per_day": 5}
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
    assert _limiter(tmp_path / "x.json").cooldown_s == 12 * 3600


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
    assert items["ricardo"].login_url == "https://login.ricardo.ch/"
    assert items["noorigins"].refused == "missing agent_fill_origins"
    assert items["cscs"].cookie_hosts == ["portal.cscs.ch"]


def test_default_cookie_hosts_skip_idp():
    it = vault.site_item_from_json(
        _item(
            "x", {"agent_fill_origins": "https://auth.cscs.ch, https://www.x.example"}
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

    assert slept and code == pyotp.TOTP(TOTP_SEED).at(t[0])
    assert recipes.fresh_totp("not base32 !!") is None
    assert recipes.fresh_totp("") is None


def test_cscs_on_portal_exact():
    assert recipes.cscs_on_portal("https://portal.cscs.ch/profile/")
    assert not recipes.cscs_on_portal("https://portal.cscs.ch.evil.example/profile/")
    assert not recipes.cscs_on_portal("https://evil.example/?portal.cscs.ch")
    assert not recipes.cscs_on_portal("https://portal.cscs.ch/api-auth/keycloak/x")
    assert not recipes.cscs_on_portal("https://portal.cscs.ch/x?code=1")
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
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
    return buf


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
    # The pinned downloads are verified before use.
    out = proc.stdout
    assert "verify sha256" in out and "--require-hashes" in out
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
