"""A failed multi-item keychain write leaves no mixed old/new set (tp#491 D3).

`_keychain_set_all` used to stop at the first failed write, leaving earlier
items with NEW values and later ones with OLD values — a login then submits a
wrong username/password pair toward the Keycloak lockout. Now a failure after
anything may have changed deletes every item of the batch (best effort) and
reports what survived. `subprocess.run` is a stateful fake keychain; nothing
touches the real `security` binary. Values are dummies and must never appear
in the output.

Run: python3 -m pytest tests/test_keychain_batch.py -q     (from the repo root)
"""

from __future__ import annotations

# pylint: disable=protected-access,import-outside-toplevel,too-few-public-methods
# pylint: disable=missing-function-docstring,missing-class-docstring,import-error
# pylint: disable=redefined-outer-name
import importlib.util
import re
import subprocess
import sys
from pathlib import Path

import pytest

_BROWSER_PY = Path(__file__).resolve().parent.parent / "bin" / "browser.py"


def _load_browser_module():
    spec = importlib.util.spec_from_file_location("browser_kc_batch", _BROWSER_PY)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["browser_kc_batch"] = mod
    spec.loader.exec_module(mod)
    return mod


browser = _load_browser_module()

SEED = "JBSWY3DPEHPK3PXP"
NEW = {"svc.a": "NEW-VALUE-A", "svc.b": "NEW-VALUE-B", "svc.c": "NEW-VALUE-C"}
OLD = {"svc.a": "OLD-VALUE-A", "svc.b": "OLD-VALUE-B", "svc.c": "OLD-VALUE-C"}


class _Res:
    def __init__(self, returncode: int = 0, stdout: str = ""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = ""


def _token(line: str, flag: str) -> str:
    m = re.search(f' {flag} "([^"]*)"', line)
    assert m is not None
    return m.group(1)


class FakeKeychain:
    """`security` stand-in: add (via -i stdin), find -w, delete; per-service faults."""

    def __init__(self, items: dict[str, str] | None = None):
        self.items: dict[str, str] = dict(items or {})
        self.add_rc: dict[str, int] = {}  # service → non-zero exit, nothing written
        self.add_timeout: set[str] = set()  # written, THEN TimeoutExpired
        self.add_garble: set[str] = set()  # rc 0 but stores something else
        self.delete_fail: set[str] = set()  # delete exits 51 (locked)
        self.deletes: list[str] = []
        self.adds: list[str] = []

    def __call__(self, argv, **kwargs):
        if argv[:2] == ["security", "-i"]:
            line = kwargs["input"].decode()
            svc, value = _token(line, "-s"), _token(line, "-w")
            self.adds.append(svc)
            if svc in self.add_rc:
                return _Res(self.add_rc[svc])
            self.items[svc] = "garbled" if svc in self.add_garble else value
            if svc in self.add_timeout:
                raise subprocess.TimeoutExpired("security", 15)
            return _Res(0)
        svc = argv[argv.index("-s") + 1]
        if argv[1] == "find-generic-password":
            if svc not in self.items:
                return _Res(44)
            return _Res(0, self.items[svc] + "\n")
        if argv[1] == "delete-generic-password":
            self.deletes.append(svc)
            if svc in self.delete_fail:
                return _Res(51)
            return _Res(0) if self.items.pop(svc, None) is not None else _Res(44)
        raise AssertionError(f"unexpected security call {argv[:2]}")


@pytest.fixture
def kc(monkeypatch):
    fake = FakeKeychain(OLD)
    monkeypatch.setattr(browser.subprocess, "run", fake)
    monkeypatch.setattr(browser, "_kc_account", lambda: "tester")
    return fake


def _batch():
    return browser._keychain_set_all(list(NEW.items()), "d")


def test_all_written_is_ok(kc):
    res = _batch()
    assert res.ok and res.changed
    assert kc.items == NEW and not kc.deletes


def test_second_item_rejected_removes_the_whole_batch(kc):
    kc.add_rc["svc.b"] = 1
    res = _batch()
    assert (res.ok, res.changed) == (False, True)
    assert res.removed == tuple(NEW) and res.surviving == ()
    assert kc.deletes == list(NEW)  # every item, including the untouched OLD one
    assert not kc.items


def test_first_item_rejected_changes_nothing(kc):
    kc.add_rc["svc.a"] = 1
    res = _batch()
    assert (res.ok, res.changed) == (False, False)
    assert not kc.deletes and kc.items == OLD


def test_first_item_read_back_mismatch_is_cleaned_up(kc):
    kc.add_garble.add("svc.a")
    res = _batch()
    assert (res.ok, res.changed) == (False, True)
    assert kc.adds == ["svc.a"] and kc.deletes == list(NEW)
    assert not kc.items


def test_first_item_timeout_is_uncertain_and_cleaned_up(kc):
    kc.add_timeout.add("svc.a")  # it DID write before timing out
    res = _batch()
    assert (res.ok, res.changed) == (False, True)
    assert kc.deletes == list(NEW) and not kc.items


def test_one_failing_delete_is_reported_and_the_rest_still_attempted(kc):
    kc.add_rc["svc.c"] = 1
    kc.delete_fail.add("svc.a")
    res = _batch()
    assert res.surviving == ("svc.a",) and res.removed == ("svc.b", "svc.c")
    assert kc.deletes == list(NEW)


def test_all_deletes_failing_lists_every_item(kc):
    kc.add_rc["svc.b"] = 1
    kc.delete_fail.update(NEW)
    res = _batch()
    assert res.surviving == tuple(NEW) and res.removed == ()
    assert kc.deletes == list(NEW)


# --- the store commands' messages --------------------------------------------------


@pytest.fixture
def cscs_store(kc, monkeypatch):
    kc.items = {}
    monkeypatch.setattr(browser.shutil, "which", lambda name: "/usr/bin/op")
    monkeypatch.setattr(
        browser,
        "_op_creds",
        lambda item, acct: browser.CscsCreds("DUMMYUSER", "DUMMYPASS", lambda: "1"),
    )
    monkeypatch.setattr(browser, "_op_totp_uri", lambda item, acct: SEED)
    return kc


@pytest.fixture
def biopol_store(kc, monkeypatch):
    import getpass

    kc.items = {}
    monkeypatch.setattr("builtins.input", lambda _prompt="": "dummy@example.org")
    monkeypatch.setattr(getpass, "getpass", lambda _prompt="": "DUMMYPASS")
    return kc


def _run_store(which: str) -> int:
    cmd = browser.cmd_cscs_store_creds if which == "cscs" else None
    return int((cmd or browser.cmd_biopolwifi_store_creds)())


def _first_svc(which: str) -> str:
    return str(
        browser.KEYCHAIN_SVC_USER
        if which == "cscs"
        else browser.KEYCHAIN_SVC_BIOPOL_EMAIL
    )


def _second_svc(which: str) -> str:
    return str(
        browser.KEYCHAIN_SVC_PASS
        if which == "cscs"
        else browser.KEYCHAIN_SVC_BIOPOL_PASS
    )


def _no_values(capsys) -> str:
    out = capsys.readouterr()
    text = out.out + out.err
    for secret in ("DUMMYUSER", "DUMMYPASS", SEED, "dummy@example.org"):
        assert secret not in text
    return str(out.err)


@pytest.fixture(params=["cscs", "biopolwifi"])
def store(request):
    fixture = "cscs_store" if request.param == "cscs" else "biopol_store"
    return request.param, request.getfixturevalue(fixture)


def test_store_nothing_changed_message(store, capsys):
    which, kc = store
    kc.add_rc[_first_svc(which)] = 1
    assert _run_store(which) == 1
    err = _no_values(capsys)
    assert "nothing changed" in err


def test_store_partial_write_removed_message(store, capsys):
    which, kc = store
    kc.add_rc[_second_svc(which)] = 1
    assert _run_store(which) == 1
    err = _no_values(capsys)
    assert "no stored set remains" in err
    assert f"browser.py store-creds {which}" in err
    assert not kc.items


def test_store_cleanup_failed_message_names_the_survivors(store, capsys):
    which, kc = store
    kc.add_rc[_second_svc(which)] = 1
    kc.delete_fail.add(_first_svc(which))
    assert _run_store(which) == 1
    err = _no_values(capsys)
    assert "cleanup FAILED" in err and _first_svc(which) in err
    assert f"browser.py forget-creds {which}" in err
    assert "no stored set remains" not in err
