"""A failed multi-item keychain write leaves no mixed old/new set (tp#491 D3, tp#504).

`_keychain_set_all` used to stop at the first failed write, leaving earlier
items with NEW values and later ones with OLD values — a login then submits a
wrong username/password pair toward the Keycloak lockout. Now a failure after
anything may have changed deletes every item of the batch (best effort) and
reports what survived. Since tp#504 every item is replaced by delete-then-add
(no ``-U``) in the pinned default keychain, and ``security`` is never killed:
a Ctrl-C waits for the running child, cleans up if needed, then propagates.

`subprocess.Popen` is a stateful, INSERT-ONLY fake keychain (an add of an
existing item fails with 45, like ``errSecDuplicateItem``); nothing touches the
real `security` binary. Values are dummies and must never appear in the output.

Run: python3 -m pytest tests/test_keychain_batch.py -q     (from the repo root)
"""

from __future__ import annotations

# pylint: disable=protected-access,import-outside-toplevel,too-few-public-methods
# pylint: disable=missing-function-docstring,missing-class-docstring,import-error
# pylint: disable=redefined-outer-name,too-many-instance-attributes
import importlib.util
import re
import sys
from pathlib import Path

import pytest
from conftest import FakeSecurityPopen, _security_g, security_op

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


def _unquote(token: bytes) -> str:
    return re.sub(rb"\\(.)", rb"\1", token).decode()


class FakeKeychain:
    """`security` stand-in over several keychain files; answers ``FakeSecurityPopen``.

    ``search`` is the search list (unnamed finds take the first match),
    ``default`` the default keychain. Named deletes/adds only touch the named
    keychain. ``fault(op, svc, answer, nth)`` makes the *nth* (0-based) call of
    *op* for *svc* answer differently: an int rc (nothing done), ``"unknown"``
    (done, then the child dies by a signal), ``"not_started"``, ``"garble"``
    (add stores something else, rc 0) or ``"commit_then_fail"`` (add stores
    the value, then exits 45). ``interrupt_at(op, svc, nth)`` raises
    Ctrl-C in the parent while that call runs (the call itself completes).
    """

    def __init__(self, default: str, items: dict[str, str] | None = None):
        self.default = default
        self.search = [default]
        self.kcs: dict[str, dict[str, str]] = {default: dict(items or {})}
        self._faults: dict[tuple[str, str, int], object] = {}
        self._interrupts: set[tuple[str, str, int]] = set()
        self._seen: dict[tuple[str, str], int] = {}
        self.log: list[tuple[str, str]] = []  # (op, svc) of every started call
        self.popen = FakeSecurityPopen(
            self._handle, not_started=self._not_started, interrupt=self._interrupt
        )

    @property
    def items(self) -> dict[str, str]:
        return self.kcs[self.default]

    @items.setter
    def items(self, value: dict[str, str]) -> None:
        self.kcs[self.default] = dict(value)

    def fault(self, op: str, svc: str, answer, nth: int = 0) -> None:
        self._faults[(op, svc, nth)] = answer

    def interrupt_at(self, op: str, svc: str, nth: int = 0) -> None:
        self._interrupts.add((op, svc, nth))

    def ops(self, op: str) -> list[str]:
        return [s for o, s in self.log if o == op]

    @staticmethod
    def _parse(argv, data) -> tuple[str, str, str | None, str | None]:
        """``(op, service, keychain, value)`` of one call."""
        op = security_op(argv)
        if op == "add":
            fields = re.findall(rb'"((?:[^"\\]|\\.)*)"', data)
            assert len(fields) == 5, "add line must name account, svc, value, desc, kc"
            assert b" -U" not in data
            return op, _unquote(fields[1]), _unquote(fields[4]), _unquote(fields[2])
        if op == "default":
            return op, "", None, None
        svc = argv[argv.index("-s") + 1]
        tail = argv[argv.index("-s") + 2 :]
        keychain = next((a for a in tail if not a.startswith("-")), None)
        return op, svc, keychain, None

    def _key(self, argv, data=None, count=False) -> tuple[str, str, int]:
        op = security_op(argv)
        if op == "add":
            svc = self._parse(argv, data)[1]
        elif op == "default":
            svc = ""
        else:
            svc = argv[argv.index("-s") + 1]
        n = self._seen.get((op, svc), 0)
        if count:
            self._seen[(op, svc)] = n + 1
        return op, svc, n

    def _not_started(self, argv) -> bool:
        if security_op(argv) == "add":
            svc = self._pending_add_svc()  # the stdin is not known yet
            n = self._seen.get(("add", svc), 0)
            if self._faults.get(("add", svc, n)) == "not_started":
                self._seen[("add", svc)] = n + 1
                self.log.append(("add!", svc))
                return True
            return False
        op, svc, n = self._key(argv)
        if self._faults.get((op, svc, n)) == "not_started":
            self._seen[(op, svc)] = n + 1
            self.log.append((op + "!", svc))
            return True
        return False

    def _pending_add_svc(self) -> str:
        # the add always follows the delete of the same service
        deletes = [s for o, s in self.log if o in ("delete", "delete!")]
        return deletes[-1] if deletes else ""

    def _interrupt(self, argv) -> bool:
        call = self.popen.calls[-1]
        op, svc, _ = self._key(argv, call["input"])
        n = self._seen[(op, svc)] - 1
        return (op, svc, n) in self._interrupts

    def _handle(self, argv, data):
        op, svc, n = self._key(argv, data, count=True)
        self.log.append((op, svc))
        answer = self._faults.get((op, svc, n))
        if isinstance(answer, int):
            return answer, "", ""
        rc, out, err = self._apply(argv, data)
        if answer == "unknown":
            return -9, "", ""
        if answer == "commit_then_fail":
            return 45, "", ""  # it stored the item, yet exited non-zero
        if answer == "garble" and op == "add" and rc == 0:
            self.kcs[self._parse(argv, data)[2] or self.default][svc] = "garbled"
        return rc, out, err

    def _apply(self, argv, data) -> tuple[int, str, str]:
        op, svc, keychain, value = self._parse(argv, data)
        if op == "default":
            return 0, f'    "{self.default}"\n', ""
        if op == "find":
            assert keychain is None, "reads are unpinned"
            for kc in self.search:
                if svc in self.kcs.get(kc, {}):
                    return 0, "", _security_g(self.kcs[kc][svc])
            return 44, "", ""
        assert keychain is not None, f"{op} must name the keychain"
        store = self.kcs.setdefault(keychain, {})
        if op == "delete":
            return (0, "", "") if store.pop(svc, None) is not None else (44, "", "")
        if op == "add":
            if svc in store:
                return 45, "", ""  # insert-only: errSecDuplicateItem
            assert value is not None
            store[svc] = value
            return 0, "", ""
        raise AssertionError(f"unexpected security call {argv[:2]}")


@pytest.fixture
def default_kc(tmp_path):
    path = tmp_path / "login.keychain-db"
    path.write_bytes(b"")
    return str(path)


@pytest.fixture
def kc(monkeypatch, default_kc):
    fake = FakeKeychain(default_kc, OLD)
    monkeypatch.setattr(browser.subprocess, "Popen", fake.popen)
    monkeypatch.setattr(browser, "_kc_account", lambda: "tester")
    return fake


def _batch():
    return browser._keychain_set_all(list(NEW.items()), "d")


def test_all_written_is_ok(kc):
    res = _batch()
    assert res.ok and res.changed
    assert kc.items == NEW
    assert kc.ops("delete") == list(NEW) and kc.ops("add") == list(NEW)


def test_every_call_names_the_default_keychain(kc):
    _batch()
    for call in kc.popen.calls:
        op = security_op(call["argv"])
        if op == "delete":
            assert call["argv"][-1] == kc.default
        elif op == "add":
            quoted = browser._kc_quote(kc.default).encode()
            assert call["input"].endswith(b" -T /usr/bin/security " + quoted + b"\n")
        assert call["kwargs"]["start_new_session"] is True
        assert "timeout" not in call["kwargs"]


def test_second_item_rejected_removes_the_whole_batch(kc):
    kc.fault("add", "svc.b", 1)
    res = _batch()
    assert (res.ok, res.changed) == (False, True)
    assert res.removed == tuple(NEW) and res.surviving == ()
    # the write's own delete of svc.b, then the cleanup of every item
    assert kc.ops("delete") == ["svc.a", "svc.b", *NEW]
    assert not kc.items


def test_first_item_add_rejected_after_delete_is_lost_and_cleaned_up(kc):
    kc.fault("add", "svc.a", 1)  # OLD svc.a was deleted, NEW not added
    res = _batch()
    assert (res.ok, res.changed) == (False, True)
    assert kc.ops("delete") == ["svc.a", *NEW]
    assert not kc.items


@pytest.mark.parametrize("answer", [1, 51, "commit_then_fail"])
def test_first_item_absent_then_add_refused_is_cleaned_up(kc, answer):
    # tp#509: a refused add is no proof that nothing was stored; the old set
    # was already unusable without svc.a, so its leftovers go too
    kc.items = {"svc.b": "OLD-VALUE-B"}
    kc.fault("add", "svc.a", answer)
    res = _batch()
    assert (res.ok, res.changed) == (False, True)
    assert kc.ops("delete") == ["svc.a", *NEW]
    assert res.removed == tuple(NEW) and res.surviving == ()
    assert not kc.items


def test_first_item_absent_then_add_not_started_changes_nothing(kc):
    kc.items = {"svc.b": "OLD-VALUE-B"}
    kc.fault("add", "svc.a", "not_started")
    res = _batch()
    assert (res.ok, res.changed) == (False, False)
    assert kc.ops("delete") == ["svc.a"] and kc.items == {"svc.b": "OLD-VALUE-B"}


def test_locked_keychain_after_absent_first_item_names_every_survivor(kc):
    kc.items = {"svc.b": "OLD-VALUE-B"}
    kc.fault("add", "svc.a", 51)
    kc.fault("delete", "svc.a", 51, nth=1)
    kc.fault("delete", "svc.b", 51)
    kc.fault("delete", "svc.c", 51)
    res = _batch()
    assert (res.ok, res.changed) == (False, True)
    assert res.removed == () and res.surviving == tuple(NEW)


def test_first_item_delete_rejected_changes_nothing(kc):
    kc.fault("delete", "svc.a", 51)  # locked keychain
    res = _batch()
    assert (res.ok, res.changed) == (False, False)
    assert kc.ops("delete") == ["svc.a"] and not kc.ops("add")
    assert kc.items == OLD


def test_first_item_delete_not_started_changes_nothing(kc):
    kc.fault("delete", "svc.a", "not_started")
    res = _batch()
    assert (res.ok, res.changed) == (False, False)
    assert not kc.ops("add") and kc.items == OLD


def test_delete_unknown_starts_no_add_and_cleans_up(kc):
    kc.fault("delete", "svc.a", "unknown")
    res = _batch()
    assert (res.ok, res.changed) == (False, True)
    assert not kc.ops("add")
    assert kc.ops("delete") == ["svc.a", *NEW] and not kc.items


def test_add_unknown_is_uncertain_and_cleaned_up(kc):
    kc.fault("add", "svc.a", "unknown")  # it DID write, then died by a signal
    res = _batch()
    assert (res.ok, res.changed) == (False, True)
    assert kc.ops("add") == ["svc.a"]
    assert not kc.items


def test_add_not_started_after_delete_is_lost(kc):
    kc.fault("add", "svc.b", "not_started")
    res = _batch()
    assert (res.ok, res.changed) == (False, True)
    assert not kc.items


def test_first_item_read_back_mismatch_is_cleaned_up(kc):
    kc.fault("add", "svc.a", "garble")
    res = _batch()
    assert (res.ok, res.changed) == (False, True)
    assert kc.ops("add") == ["svc.a"] and kc.ops("delete") == ["svc.a", *NEW]
    assert not kc.items


def test_one_failing_delete_is_reported_and_the_rest_still_attempted(kc):
    kc.fault("add", "svc.c", 1)
    kc.fault("delete", "svc.a", 51, nth=1)  # the cleanup's delete of svc.a
    res = _batch()
    assert res.surviving == ("svc.a",) and res.removed == ("svc.b", "svc.c")
    assert kc.ops("delete")[3:] == list(NEW)


def test_all_deletes_failing_lists_every_item(kc):
    kc.fault("add", "svc.b", 1)
    kc.fault("delete", "svc.a", 51, nth=1)
    kc.fault("delete", "svc.b", 51, nth=1)
    kc.fault("delete", "svc.c", 51)
    res = _batch()
    assert res.surviving == tuple(NEW) and res.removed == ()


def test_unresolvable_default_keychain_runs_nothing(kc, default_kc):
    Path(default_kc).unlink()
    res = _batch()
    assert (res.ok, res.changed) == (False, False)
    assert [security_op(a) for a in kc.popen.argvs()] == ["default"]
    assert kc.items == OLD


def test_shadow_copy_earlier_in_the_search_list_is_a_mismatch(kc, tmp_path):
    shadow = str(tmp_path / "shadow.keychain-db")
    kc.kcs[shadow] = {"svc.a": "SHADOW-A"}
    kc.search = [shadow, kc.default]
    res = _batch()
    assert (res.ok, res.changed) == (False, True)
    assert kc.kcs[shadow] == {"svc.a": "SHADOW-A"}  # never touched: pinned
    assert not kc.items


# --- Ctrl-C: security is waited for, then cleanup, then the interrupt ---------


@pytest.mark.parametrize(
    "op, svc, nth",
    [
        ("delete", "svc.a", 0),  # the first mutation itself
        ("add", "svc.a", 0),
        ("find", "svc.a", 0),  # the read-back
        ("delete", "svc.b", 0),
    ],
)
def test_interrupt_after_a_mutation_cleans_up_then_propagates(kc, capsys, op, svc, nth):
    kc.interrupt_at(op, svc, nth)
    with pytest.raises(KeyboardInterrupt):
        _batch()
    assert kc.popen.interrupts == 1
    assert kc.ops("delete")[-3:] == list(NEW)  # the cleanup
    assert not kc.items
    assert "partially written keychain items were removed" in capsys.readouterr().err


@pytest.mark.parametrize("answer", [1, "commit_then_fail"])
def test_interrupt_during_a_refused_add_after_absent_cleans_up(kc, capsys, answer):
    kc.items = {"svc.b": "OLD-VALUE-B"}
    kc.fault("add", "svc.a", answer)
    kc.interrupt_at("add", "svc.a")
    with pytest.raises(KeyboardInterrupt):
        _batch()
    assert kc.ops("delete") == ["svc.a", *NEW]
    assert not kc.items
    assert "Interrupted — the partially written" in capsys.readouterr().err


def test_unexpected_exception_after_a_mutation_cleans_up_then_propagates(
    kc, capsys, monkeypatch
):
    def boom(_service):
        raise RuntimeError("read-back broke")

    monkeypatch.setattr(browser, "_keychain_get", boom)
    with pytest.raises(RuntimeError):
        _batch()
    assert kc.ops("delete") == ["svc.a", *NEW]
    assert not kc.items
    assert "Aborted — the partially written" in capsys.readouterr().err


def test_interrupt_during_a_rejected_first_delete_skips_cleanup(kc, capsys):
    kc.fault("delete", "svc.a", 51)
    kc.interrupt_at("delete", "svc.a")
    with pytest.raises(KeyboardInterrupt):
        _batch()
    assert kc.ops("delete") == ["svc.a"] and kc.items == OLD
    assert capsys.readouterr().err == ""


def test_interrupt_while_resolving_the_target_changes_nothing(kc):
    kc.interrupt_at("default", "")
    with pytest.raises(KeyboardInterrupt):
        _batch()
    assert [security_op(a) for a in kc.popen.argvs()] == ["default"]
    assert kc.items == OLD


def test_interrupt_during_cleanup_finishes_every_delete_then_propagates(kc, capsys):
    kc.fault("add", "svc.b", 1)
    kc.interrupt_at("delete", "svc.a", nth=1)  # the cleanup's first delete
    with pytest.raises(KeyboardInterrupt):
        _batch()
    assert kc.ops("delete")[2:] == list(NEW)
    assert not kc.items
    assert "cleanup FAILED" not in capsys.readouterr().err


def test_interrupt_with_a_failing_cleanup_names_the_survivors(kc, capsys):
    kc.interrupt_at("add", "svc.b")
    kc.fault("delete", "svc.a", 51, nth=1)
    with pytest.raises(KeyboardInterrupt):
        _batch()
    err = capsys.readouterr().err
    assert "cleanup FAILED for svc.a" in err
    for value in (*NEW.values(), *OLD.values()):
        assert value not in err


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


def test_store_prints_the_dialog_hint_without_values(store, capsys):
    which, kc = store
    assert _run_store(which) == 0
    err = _no_values(capsys)
    assert "If macOS shows a keychain dialog, answer it." in err
    assert len(kc.items) >= 2


def test_store_nothing_changed_message(store, capsys):
    which, kc = store
    kc.items = {_first_svc(which): "OLD"}
    kc.fault("delete", _first_svc(which), 51)
    assert _run_store(which) == 1
    err = _no_values(capsys)
    assert "nothing changed" in err
    assert kc.items == {_first_svc(which): "OLD"}


def test_store_refused_first_add_is_not_nothing_changed(store, capsys):
    which, kc = store  # the set is empty: the first item is absent
    kc.fault("add", _first_svc(which), "commit_then_fail")
    assert _run_store(which) == 1
    err = _no_values(capsys)
    assert "nothing changed" not in err
    assert "no stored set remains" in err
    assert not kc.items


def test_store_partial_write_removed_message(store, capsys):
    which, kc = store
    kc.fault("add", _second_svc(which), 1)
    assert _run_store(which) == 1
    err = _no_values(capsys)
    assert "no stored set remains" in err
    assert f"browser.py store-creds {which}" in err
    assert not kc.items


def test_store_cleanup_failed_message_names_the_survivors(store, capsys):
    which, kc = store
    kc.fault("add", _second_svc(which), 1)
    kc.fault("delete", _first_svc(which), 51, nth=1)
    assert _run_store(which) == 1
    err = _no_values(capsys)
    assert "cleanup FAILED" in err and _first_svc(which) in err
    assert f"browser.py forget-creds {which}" in err
    assert "no stored set remains" not in err
