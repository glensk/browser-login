"""tp#1963: one vault read shared by the site and secret listings, skipped while
Vaultwarden's account revision is unchanged (fakes only: no bw, no network)."""

from __future__ import annotations

# pylint: disable=wrong-import-position
import json
import os
import sys
import urllib.request
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from broker import vault, vault_cache, vault_revision  # noqa: E402

SERVER = "https://vw.example"
CLIENT_SECRET = "csecret-" + os.urandom(6).hex()
TOKEN = "tok-" + os.urandom(6).hex()

FAKE_BW = r"""#!/usr/bin/env python3
import json, sys
with open("@LOG@", "a") as fh:
    fh.write(json.dumps(sys.argv[1:]) + "\n")
cmd = sys.argv[1]
if cmd == "status":
    print(json.dumps({"status": "locked"}))
elif cmd == "unlock":
    print("SESSIONKEY")
elif cmd == "list":
    print(open("@DIR@/items-" + sys.argv[-1] + ".json").read())
"""


def _login_item(site: str) -> dict:
    return {
        "id": f"id-{site}",
        "name": site,
        "login": {
            "username": "alice",
            "password": "p" * 20,
            "uris": [{"uri": f"https://{site}.example/login"}],
        },
        "fields": [
            {"name": "agent_site", "value": site},
            {"name": "agent_fill_origins", "value": f"https://{site}.example"},
            {"name": "agent_check_url", "value": f"https://{site}.example/home"},
            {"name": "agent_logged_in_selector", "value": "#me"},
        ],
        "collectionIds": ["coll-login"],
    }


def _secret_item(name: str, password: str) -> dict:
    return {
        "id": f"id-{name}",
        "name": name,
        "login": {"username": "u", "password": password, "totp": None},
        "fields": [],
        "collectionIds": ["coll-s"],
    }


class FakeProbe:
    """A RevisionProbe stand-in: answers `rev` (None = unreadable)."""

    def __init__(self, rev: str | None = "1000") -> None:
        self.rev = rev
        self.calls = 0

    def revision(
        self, server_url: str, client_id: str, client_secret: str
    ) -> str | None:
        assert server_url == SERVER and client_id == "cid"
        assert client_secret == CLIENT_SECRET
        self.calls += 1
        return self.rev


def _setup(tmp_path: Path, *, secrets: bool = True, gate: str = vault.GATE_COLLECTIONS):
    (tmp_path / "items-coll-login.json").write_text(
        json.dumps([_login_item("ricardo")])
    )
    (tmp_path / "items-coll-s.json").write_text(
        json.dumps([_secret_item("Svc", "s" * 20)])
    )
    log = tmp_path / "bw.log"
    fake = tmp_path / "bw"
    fake.write_text(FAKE_BW.replace("@LOG@", str(log)).replace("@DIR@", str(tmp_path)))
    fake.chmod(0o755)
    boot = vault.BwBootstrap(
        "cid",
        CLIENT_SECRET,
        "master-pw",
        "coll-login",
        server_url=SERVER,
        secrets_collection_id="coll-s" if secrets else None,
        secret_gate=gate,
    )
    return boot, fake, log


def _argvs(log: Path) -> list[list[str]]:
    if not log.exists():
        return []
    return [json.loads(line) for line in log.read_text().splitlines()]


def _verbs(log: Path) -> list[str]:
    return [a[0] for a in _argvs(log)]


def _bwv(tmp_path, boot, fake, probe, cache=None):
    return vault.BwVault(
        boot, tmp_path / "appdata", bw_bin=str(fake), cache=cache, revision=probe
    )


# --- BwVault -----------------------------------------------------------------


def test_items_read_both_collections_once_and_fill_the_secret_listing(tmp_path):
    boot, fake, log = _setup(tmp_path)
    v = _bwv(tmp_path, boot, fake, FakeProbe())
    assert [it.site for it in v.items()] == ["ricardo"]
    assert [it.secret_id for it in v.secret_items()] == ["svc"]
    verbs = _verbs(log)
    assert verbs.count("unlock") == 1 and verbs.count("sync") == 1
    assert verbs.count("lock") == 1 and verbs.count("list") == 2
    lists = [a for a in _argvs(log) if a[0] == "list"]
    assert lists == [
        ["list", "items", "--collectionid", "coll-login"],
        ["list", "items", "--collectionid", "coll-s"],
    ]


def test_unchanged_revision_skips_bw_after_the_ttls(tmp_path):
    now = [0.0]
    cache = vault_cache.VaultCache(clock=lambda: now[0])
    boot, fake, log = _setup(tmp_path)
    probe = FakeProbe("1000")
    v = _bwv(tmp_path, boot, fake, probe, cache)
    first = v.items()
    before = len(_argvs(log))
    now[0] += 1800  # the 300 s value TTL is long gone
    assert v.items() == first
    assert [it.secret_id for it in v.secret_items()] == ["svc"]
    assert len(_argvs(log)) == before  # no bw at all
    assert probe.calls == 3


def test_changed_revision_reads_in_full(tmp_path):
    boot, fake, log = _setup(tmp_path)
    probe = FakeProbe("1000")
    v = _bwv(tmp_path, boot, fake, probe)
    v.items()
    (tmp_path / "items-coll-login.json").write_text(
        json.dumps([_login_item("ricardo"), _login_item("galaxus")])
    )
    probe.rev = "2000"
    assert [it.site for it in v.items()] == ["ricardo", "galaxus"]
    assert _verbs(log).count("sync") == 2
    # the refusals of a full read stand in the memo too
    assert [it.no_submit for it in v.items()] == [False, True]
    assert _verbs(log).count("sync") == 2


def test_unreadable_revision_always_reads_in_full(tmp_path):
    boot, fake, log = _setup(tmp_path)
    v = _bwv(tmp_path, boot, fake, FakeProbe(None))
    v.items()
    v.items()
    assert _verbs(log).count("sync") == 2


def test_no_probe_keeps_the_old_behaviour(tmp_path):
    boot, fake, log = _setup(tmp_path)
    v = vault.BwVault(boot, tmp_path / "appdata", bw_bin=str(fake))
    v.items()
    v.items()
    assert _verbs(log).count("sync") == 2


def test_invalidate_and_a_login_read_drop_the_memo(tmp_path):
    boot, fake, log = _setup(tmp_path)
    v = _bwv(tmp_path, boot, fake, FakeProbe("1000"))
    v.items()
    v.invalidate()
    v.items()
    assert _verbs(log).count("sync") == 2
    v.secret("ricardo")  # a login always reads in full, and bumps
    assert _verbs(log).count("sync") == 3
    v.items()
    assert _verbs(log).count("sync") == 4


def test_memo_has_a_max_age(tmp_path):
    now = [0.0]
    cache = vault_cache.VaultCache(clock=lambda: now[0], revision_max_age_s=3600)
    boot, fake, log = _setup(tmp_path)
    v = _bwv(tmp_path, boot, fake, FakeProbe("1000"), cache)
    v.items()
    now[0] += 3599
    v.items()
    assert _verbs(log).count("sync") == 1
    now[0] += 2
    v.items()
    assert _verbs(log).count("sync") == 2


def test_secret_values_never_come_from_the_memo(tmp_path):
    now = [0.0]
    cache = vault_cache.VaultCache(clock=lambda: now[0])
    boot, fake, log = _setup(tmp_path)
    v = _bwv(tmp_path, boot, fake, FakeProbe("1000"), cache)
    v.items()
    assert _verbs(log).count("sync") == 1
    # items() cached the listing only, not a value
    assert v.secret_values("svc").fields["password"] == "s" * 20
    assert _verbs(log).count("sync") == 2
    now[0] += 1800
    v.secret_items()  # memo
    assert _verbs(log).count("sync") == 2
    v.secret_values("svc")  # values TTL expired: a full read
    assert _verbs(log).count("sync") == 3


def test_secret_listing_alone_uses_the_memo(tmp_path):
    now = [0.0]
    cache = vault_cache.VaultCache(clock=lambda: now[0])
    boot, fake, log = _setup(tmp_path)
    v = _bwv(tmp_path, boot, fake, FakeProbe("1000"), cache)
    v.secret_items()
    now[0] += 1800
    v.secret_items()
    assert _verbs(log).count("sync") == 1


def test_agent_script_gate_listing_from_the_shared_read(tmp_path):
    boot, fake, log = _setup(tmp_path, gate=vault.GATE_AGENT_SCRIPT)
    v = _bwv(tmp_path, boot, fake, FakeProbe("1000"))
    v.items()
    listing = v.secret_items()
    assert _verbs(log).count("sync") == 1
    fresh = vault.BwVault(boot, tmp_path / "appdata2", bw_bin=str(fake))
    assert [it.public() for it in listing] == [
        it.public() for it in fresh.secret_items()
    ]


def test_no_secrets_collection_reads_logins_only(tmp_path):
    boot, fake, log = _setup(tmp_path, secrets=False)
    v = _bwv(tmp_path, boot, fake, FakeProbe("1000"))
    v.items()
    assert [a for a in _argvs(log) if a[0] == "list"] == [
        ["list", "items", "--collectionid", "coll-login"]
    ]
    with pytest.raises(vault.SecretsNotConfigured):
        v.secret_items()


def test_memo_put_refuses_a_stale_generation():
    cache = vault_cache.VaultCache()
    gen = cache.generation
    cache.bump()
    assert not cache.memo_put(("k",), "1", "v", generation=gen)
    assert cache.memo_put(("k",), "1", "v", generation=cache.generation)
    assert cache.memo_get(("k",), "1") == "v"
    assert cache.memo_get(("k",), "2") is None
    assert cache.memo_get(("k",), "1") is None  # a mismatch drops the entry
    assert not cache.memo_put(("k",), "", "v", generation=cache.generation)


# --- RevisionProbe -----------------------------------------------------------


class FakeTransport:
    def __init__(self, answers: list[tuple[int, bytes]]) -> None:
        self.answers = answers
        self.requests: list[urllib.request.Request] = []

    def __call__(
        self, req: urllib.request.Request, timeout_s: float
    ) -> tuple[int, bytes]:
        assert timeout_s > 0
        self.requests.append(req)
        if not self.answers:
            raise OSError("no answer")
        return self.answers.pop(0)


def _token(expires: int = 7200) -> tuple[int, bytes]:
    return 200, json.dumps({"access_token": TOKEN, "expires_in": expires}).encode()


def test_probe_caches_the_token_and_reads_the_revision():
    now = [0.0]
    t = FakeTransport([_token(), (200, b"1700000000000"), (200, b"1700000000001")])
    probe = vault_revision.RevisionProbe(transport=t, clock=lambda: now[0])
    assert probe.revision(SERVER, "cid", CLIENT_SECRET) == "1700000000000"
    now[0] += 3600
    assert probe.revision(SERVER, "cid", CLIENT_SECRET) == "1700000000001"
    urls = [r.full_url for r in t.requests]
    assert urls == [
        f"{SERVER}/identity/connect/token",
        f"{SERVER}/api/accounts/revision-date",
        f"{SERVER}/api/accounts/revision-date",
    ]
    form = t.requests[0].data
    assert isinstance(form, bytes)
    assert b"grant_type=client_credentials" in form and b"scope=api" in form
    dev = vault_revision.device_id(SERVER, "cid")
    assert dev.encode() in form and CLIENT_SECRET not in dev
    assert t.requests[1].get_header("Authorization") == f"Bearer {TOKEN}"
    assert TOKEN not in t.requests[1].full_url


def test_probe_renews_an_expired_or_rejected_token():
    now = [0.0]
    t = FakeTransport(
        [
            _token(120),
            (200, b"1"),
            _token(),  # 120 s - margin passed: a new token
            (200, b"2"),
            (401, b""),  # the cached token is refused: renewed once
            _token(),
            (200, b"3"),
        ]
    )
    probe = vault_revision.RevisionProbe(transport=t, clock=lambda: now[0])
    assert probe.revision(SERVER, "cid", CLIENT_SECRET) == "1"
    now[0] += 61
    assert probe.revision(SERVER, "cid", CLIENT_SECRET) == "2"
    assert probe.revision(SERVER, "cid", CLIENT_SECRET) == "3"
    assert not t.answers


@pytest.mark.parametrize(
    "answers",
    [
        [],  # network down
        [(400, b"")],  # token refused
        [(200, b"not json")],
        [(200, b'{"expires_in": 60}')],
        [_token(), (500, b"")],
        [_token(), (200, b'"2024-01-01"')],
        [_token(), (200, b"true")],
        [_token(), (200, b"-5")],
    ],
)
def test_probe_answers_none_on_any_problem(answers):
    probe = vault_revision.RevisionProbe(transport=FakeTransport(list(answers)))
    assert probe.revision(SERVER, "cid", CLIENT_SECRET) is None


def test_probe_never_raises_a_secret_and_refuses_plain_http():
    def boom(req, timeout_s):
        raise OSError(f"failed {req.data!r}")

    probe = vault_revision.RevisionProbe(transport=boom)
    assert probe.revision(SERVER, "cid", CLIENT_SECRET) is None
    t = FakeTransport([_token(), (200, b"1")])
    probe = vault_revision.RevisionProbe(transport=t)
    assert probe.revision("http://vw.example", "cid", CLIENT_SECRET) is None
    assert not t.requests


def test_probe_token_is_per_server_and_client():
    t = FakeTransport([_token(), (200, b"1"), _token(), (200, b"2")])
    probe = vault_revision.RevisionProbe(transport=t)
    assert probe.revision(SERVER, "cid", CLIENT_SECRET) == "1"
    assert probe.revision(SERVER, "cid2", CLIENT_SECRET) == "2"
    assert len(t.requests) == 4


def test_agent_script_values_read_is_one_session_and_memoizes_the_sites(tmp_path):
    boot, fake, log = _setup(tmp_path, gate=vault.GATE_AGENT_SCRIPT)
    v = _bwv(tmp_path, boot, fake, FakeProbe("1000"))
    v.secret_items()  # a cold secret read (gate agent_script: both collections)
    verbs = _verbs(log)
    assert verbs.count("unlock") == 1 and verbs.count("list") == 2
    assert [it.site for it in v.items()] == ["ricardo"]
    assert _verbs(log).count("sync") == 1
    v.secret_items()
    assert _verbs(log).count("sync") == 1


def test_probe_logs_a_fixed_reason_once_per_change_and_never_a_secret():
    lines: list[str] = []

    def leaky(req, timeout_s):
        raise OSError(f"failed {req.data!r} {req.headers!r}")

    t = FakeTransport([(400, b""), (400, b""), _token(), (200, b"5")])
    probe = vault_revision.RevisionProbe(transport=t, log=lines.append)
    assert probe.revision(SERVER, "cid", CLIENT_SECRET) is None
    assert probe.revision(SERVER, "cid", CLIENT_SECRET) is None
    assert probe.revision(SERVER, "cid", CLIENT_SECRET) == "5"
    probe.transport = leaky
    probe.forget()
    assert probe.revision(SERVER, "cid", CLIENT_SECRET) is None
    assert lines == [
        "vault revision check unavailable (token_http_400): full vault reads",
        "vault revision check available again",
        "vault revision check unavailable (error:OSError): full vault reads",
    ]
    assert probe.problem == "error:OSError"
    for line in lines:
        assert CLIENT_SECRET not in line and TOKEN not in line
