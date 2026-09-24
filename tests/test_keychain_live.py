"""Live check of the keychain helpers against the real ``security`` binary.

The live test NEVER touches the login keychain. It creates its own temporary
keychain file (random password, held in memory only), names that file in every
``security`` call, never adds it to the search list, and deletes it afterwards.

The router sits BELOW ``browser._security_run``: it replaces
``subprocess.Popen`` for the live test body, so the production runner (new
session, no timeout, never kills) is what runs ``security``. It answers
``default-keychain -d user`` itself with the temp path (so ``browser.py``'s
delete and add already name the temp keychain), appends the temp path to the
unpinned ``find-generic-password``, checks that every delete and every
``security -i`` add line names exactly the temp keychain, and refuses every
other shape. The add line is checked when its stdin is sent; a refused line
never reaches ``security`` (it gets an empty stdin and exits). Other programs
go on to conftest's default-deny guard, which stays active. The fixture's own
lifecycle calls run through ``browser._security_run`` as well.

The live test is skipped unless ``BROWSER_LIVE_KEYCHAIN=1`` on macOS. The
offline tests of the router and of the keychain lifecycle always run; they use
fakes and never execute ``security``. Values are dummies, never printed.

Run: BROWSER_LIVE_KEYCHAIN=1 uv run pytest -q tests/test_keychain_live.py
"""

from __future__ import annotations

# pylint: disable=protected-access,import-error,missing-function-docstring
# pylint: disable=redefined-outer-name
import importlib.util
import os
import re
import secrets
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest
from conftest import DeniedSubprocess, FakeSecurityPopen, _executable, _security_g

# Captured at import, before conftest's guard wraps ``subprocess.Popen`` for a
# test. ``_exec_security`` and the live router are the only users.
_REAL_POPEN = subprocess.Popen

_BROWSER_PY = Path(__file__).resolve().parent.parent / "bin" / "browser.py"


def _load_browser_module():
    spec = importlib.util.spec_from_file_location("browser_live_kc", _BROWSER_PY)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["browser_live_kc"] = mod
    spec.loader.exec_module(mod)
    return mod


browser = _load_browser_module()

CASES = {
    "space": "dummy with spaces",
    "dquote": 'dummy"quote',
    "squote": "dummy'quote",
    "backslash": "dummy\\back",
    "trailing": "dummy-trailing\\",
    "shell": "dummy$;|&#`",
    "utf8": "dümmy-✓",
    "hexlike": "cafe",
    "hexutf8": "c3a4",
    "hexprefix": "0x41",
    "quote_end": 'ab"',
    "utf8_quote": 'ä"x',
    "only_utf8": "ä",
    "emoji": "😀",
    "lone_backslash": "\\",
}


class KeychainFixtureError(RuntimeError):
    """The temp keychain could not be set up, verified or removed."""


class RoutingRefused(BaseException):
    """The router refused a ``security`` call it cannot pin to the temp keychain.

    A ``BaseException``, so ``browser._security_run`` (which maps an
    ``Exception`` after launch to ``"unknown"``) does not swallow it: a refusal
    fails the test instead of looking like an uncertain write.
    """


def _exec_security(argv, data: bytes | None = None):
    """``browser._security_run`` on the real ``Popen`` (conftest's guard bypassed)."""
    if not argv or os.path.basename(argv[0]) != "security":
        raise RoutingRefused("_exec_security only runs `security`")
    with pytest.MonkeyPatch.context() as m:
        m.setattr(subprocess, "Popen", _REAL_POPEN)
        return browser._security_run(argv, data=data)


def _text(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")


# --- temp keychain lifecycle -------------------------------------------------


def _kc_lifecycle(runner, argv):
    """Run one lifecycle ``security`` call; raise (naming only the subcommand)."""
    r = runner(argv)
    if r.state != "done" or r.rc != 0:
        raise KeychainFixtureError(f"security {argv[1]} failed ({r.state}, rc {r.rc})")
    return r


def _search_list(runner) -> set[str]:
    """Realpath of every keychain on the user search list (read only)."""
    r = _kc_lifecycle(runner, ["security", "list-keychains", "-d", "user"])
    return {
        os.path.realpath(line.strip().strip('"'))
        for line in _text(r.stdout).splitlines()
        if line.strip()
    }


def _file_identity(path: Path) -> tuple[int, int]:
    """``(st_dev, st_ino)`` of a regular, non-symlink file the user owns."""
    try:
        st = os.lstat(path)
    except OSError as exc:
        raise KeychainFixtureError(f"temp keychain missing: {path}") from exc
    if not stat.S_ISREG(st.st_mode):
        raise KeychainFixtureError(f"temp keychain is not a regular file: {path}")
    if st.st_uid != os.getuid():
        raise KeychainFixtureError(f"temp keychain has a foreign owner: {path}")
    return (st.st_dev, st.st_ino)


def _create_temp_keychain(runner, tmpdir: Path | None = None):
    """Create, unlock and verify a private keychain; return ``(path, identity)``.

    Any failure from ``create-keychain`` on deletes the file again before the
    error propagates.
    """
    base = Path(tmpdir or tempfile.gettempdir()).resolve()
    path = base / f"tp504-{secrets.token_hex(6)}.keychain-db"
    password = secrets.token_urlsafe(24)
    try:
        _kc_lifecycle(
            runner, ["security", "create-keychain", "-p", password, str(path)]
        )
        _file_identity(path)  # a regular file we own, not a symlink
        _kc_lifecycle(
            runner, ["security", "unlock-keychain", "-p", password, str(path)]
        )
        # no -l/-u/-t: no lock on sleep, no idle timeout (a lock would prompt)
        _kc_lifecycle(runner, ["security", "set-keychain-settings", str(path)])
        info = _kc_lifecycle(runner, ["security", "show-keychain-info", str(path)])
        if "no-timeout" not in _text(info.stdout + info.stderr):
            raise KeychainFixtureError("temp keychain still has a lock timeout")
        if str(path) in _search_list(runner):
            raise KeychainFixtureError("temp keychain landed on the search list")
    except BaseException:
        _destroy_temp_keychain(runner, path)
        raise
    # securityd saves a keychain by atomic rename: the inode changes on every
    # write (measured 2026-09-24), so the identity is taken after the last one
    return path, _file_identity(path)


def _destroy_temp_keychain(runner, path: Path) -> None:
    """Exact-path ``delete-keychain``; raise (naming the path) unless it is gone."""
    r = runner(["security", "delete-keychain", str(path)])
    if r.state != "done" or r.rc != 0 or path.exists():
        raise KeychainFixtureError(
            f"could not delete the temp keychain {path} ({r.state}, rc {r.rc})"
            f" — remove it with: security delete-keychain {path}"
        )
    if str(path) in _search_list(runner):
        raise KeychainFixtureError(f"temp keychain still on the search list: {path}")


@pytest.fixture
def temp_keychain():
    path, identity = _create_temp_keychain(_exec_security)
    try:
        yield path, identity
    finally:
        _destroy_temp_keychain(_exec_security, path)


# --- router --------------------------------------------------------------------

_QUOTED = rb'"(?:[^"\\]|\\.)*"'
_ADD_LINE = re.compile(
    rb"add-generic-password -a "
    + _QUOTED
    + rb" -s "
    + _QUOTED
    + rb" -w "
    + _QUOTED
    + rb" -D "
    + _QUOTED
    + rb" -T /usr/bin/security ("
    + _QUOTED
    + rb")\n"
)

_DEFAULT_ARGV = ["default-keychain", "-d", "user"]
_FIND_SHAPE = ["find-generic-password", "-a", None, "-s", None, "-g"]
_DELETE_SHAPE = ["delete-generic-password", "-a", None, "-s", None, None]


def _check_identity(keychain: Path, identity: tuple[int, int]) -> None:
    if Path(os.path.realpath(keychain)) != keychain:
        raise RoutingRefused("temp keychain path is not its resolved path")
    try:
        current = _file_identity(keychain)
    except KeychainFixtureError as exc:
        raise RoutingRefused(str(exc)) from exc
    if current != identity:
        raise RoutingRefused("temp keychain file was replaced")


def _check_add_line(data, keychain: Path) -> None:
    """Refuse a ``security -i`` stdin that is not one add line for *keychain*."""
    if not isinstance(data, bytes):
        raise RoutingRefused("security -i stdin must be bytes")
    m = _ADD_LINE.fullmatch(data)
    if data.count(b"\n") != 1 or m is None:
        raise RoutingRefused("security -i stdin is not one insert-only add line")
    if any(b < 0x20 or b == 0x7F for b in data[:-1]):
        raise RoutingRefused("security -i stdin holds a control character")
    if m.group(1) != browser._kc_quote(str(keychain)).encode("utf-8"):
        raise RoutingRefused("security -i add line names another keychain")
    if len(data) - 1 > browser._KC_LINE_MAX:
        raise RoutingRefused("security -i line is too long")


def _route_security(args, keychain: Path) -> tuple[list[str] | None, bool]:
    """``(argv to run, is_add)``; ``(None, False)`` = answer default-keychain.

    Raises on any shape this router cannot pin to the temp keychain.
    """
    if not isinstance(args, (list, tuple)) or not all(isinstance(a, str) for a in args):
        raise RoutingRefused("security argv must be a list of str")
    head, rest = list(args[:1]), list(args[1:])
    if rest == ["-i"]:
        return head + rest, True
    if rest == _DEFAULT_ARGV:
        return None, False
    # the operands (account, service, keychain) are free in the shape itself
    shape = [None if i in (2, 4) else arg for i, arg in enumerate(rest)]
    if shape == _FIND_SHAPE:
        return head + rest + [str(keychain)], False
    if [None if i == 5 else a for i, a in enumerate(shape)] == _DELETE_SHAPE:
        if rest[5] != str(keychain):
            raise RoutingRefused("security delete names another keychain")
        return head + rest, False
    raise RoutingRefused(f"security {rest[:1]} is not a routable shape")


class _AnsweredProc:
    """``default-keychain -d user``, answered without running ``security``."""

    def __init__(self, keychain: Path):
        self.returncode = 0
        self._out = f'    "{keychain}"\n'.encode()

    def communicate(self, input=None):  # noqa: A002  # pylint: disable=redefined-builtin
        assert input is None
        return self._out, b""

    def wait(self):
        return self.returncode


class _TrackedProc:
    """A routed ``security`` process: checks an add line when its stdin is sent,
    re-takes the keychain identity once the child has exited."""

    def __init__(self, proc, keychain: Path, is_add: bool, on_exit):
        self._proc, self._keychain, self._on_exit = proc, keychain, on_exit
        self._unchecked = is_add

    @property
    def returncode(self):
        return self._proc.returncode

    def communicate(self, input=None):  # noqa: A002  # pylint: disable=redefined-builtin
        if self._unchecked:
            self._unchecked = False
            try:
                _check_add_line(input, self._keychain)
            except RoutingRefused:
                self._proc.communicate(None)  # empty stdin: `security -i` exits
                self._on_exit()
                raise
        try:
            return self._proc.communicate(input)
        finally:
            if self._proc.returncode is not None:
                self._on_exit()

    def wait(self):
        try:
            return self._proc.wait()
        finally:
            self._on_exit()


def _make_router(keychain: Path, identity, security_popen, fallback_popen):
    """A ``subprocess.Popen`` stand-in that pins every ``security`` call to *keychain*.

    *identity* is re-taken after each routed call exits (securityd renames the
    file on every write), so only a replacement BETWEEN two calls is refused.
    """
    current = [identity]

    def retake():
        current[0] = _file_identity(keychain)

    def popen(args, *a, **kw):
        exe = kw.get("executable")
        prog = _executable(args)
        if "security" in (prog, _executable([exe]) if exe is not None else ""):
            if exe is not None:
                raise RoutingRefused("executable= override on a security call")
            if a:
                raise RoutingRefused("positional Popen arguments on a security call")
            if kw.get("start_new_session") is not True or "timeout" in kw:
                raise RoutingRefused("security must run in a new session, untimed")
            _check_identity(keychain, current[0])
            argv, is_add = _route_security(args, keychain)
            if argv is None:
                return _AnsweredProc(keychain)
            return _TrackedProc(security_popen(argv, **kw), keychain, is_add, retake)
        return fallback_popen(args, *a, **kw)

    return popen


def _items_matching(prefix: str, keychain: Path, runner=_exec_security):
    """(account, service) of every temp-keychain item touching our namespace.

    ``dump-keychain`` without ``-d`` prints attributes only, never secrets;
    the output is parsed here and never echoed. A failed dump raises.
    """
    r = _kc_lifecycle(runner, ["security", "dump-keychain", str(keychain)])
    found = []
    for entry in _text(r.stdout).split("keychain: ")[1:]:
        acct = re.search(r'"acct"<blob>="(.*)"', entry)
        svce = re.search(r'"svce"<blob>="(.*)"', entry)
        a = acct.group(1) if acct else ""
        s = svce.group(1) if svce else ""
        if prefix in a or prefix in s:
            found.append((a, s))
    return found


# --- offline tests (always run, fakes only) ----------------------------------


def _unquote(token: bytes) -> str:
    return re.sub(rb"\\(.)", rb"\1", token).decode()


class _Recorder:
    """Fake ``security`` behind a ``FakeSecurityPopen``: a tiny insert-only keychain."""

    def __init__(self):
        self.items: dict[tuple[str, str, str], str] = {}
        self.popen = FakeSecurityPopen(self._handle)

    @property
    def calls(self) -> list[dict]:
        return self.popen.calls

    def _handle(self, argv, data):
        if argv[1:] == ["-i"]:
            if data is None:
                return 0, "", ""  # empty stdin: nothing ran
            acct, svc, value, _desc, kc = (
                _unquote(f) for f in re.findall(rb'"((?:[^"\\]|\\.)*)"', data)
            )
            if (kc, acct, svc) in self.items:
                return 45, "", ""
            self.items[(kc, acct, svc)] = value
            return 0, "", ""
        key = (argv[-1], argv[3], argv[5])
        if argv[1] == "find-generic-password":
            value = self.items.get(key)
            return (0, "", _security_g(value)) if value is not None else (44, "", "")
        if argv[1] == "delete-generic-password":
            return (
                (0, "", "") if self.items.pop(key, None) is not None else (44, "", "")
            )
        raise AssertionError(f"unexpected security call {argv[:2]}")


@pytest.fixture
def routed(tmp_path):
    keychain = tmp_path.resolve() / "fake.keychain-db"
    keychain.write_bytes(b"")
    identity = _file_identity(keychain)
    recorder = _Recorder()
    router = _make_router(keychain, identity, recorder.popen, subprocess.Popen)
    return keychain, recorder, router


_KW = {
    "stdin": subprocess.PIPE,
    "stdout": subprocess.PIPE,
    "stderr": subprocess.PIPE,
    "start_new_session": True,
}


def _add_line(keychain, service="svc", value='v a"l\\', description="d") -> bytes:
    line = browser._kc_add_line(service, value, description, str(keychain))
    assert isinstance(line, bytes)
    return line


def _send(router, line):
    return router(["security", "-i"], **_KW).communicate(line)


def test_add_line_names_the_temp_keychain_without_update_flag(routed, monkeypatch):
    keychain, recorder, router = routed
    monkeypatch.setattr(browser, "_kc_account", lambda: "acct")
    line = _add_line(keychain)
    _send(router, line)
    ((call),) = recorder.calls
    assert call["argv"] == ["security", "-i"] and call["input"] == line
    assert b" -U" not in line
    assert recorder.items == {(str(keychain), "acct", "svc"): 'v a"l\\'}


@pytest.mark.parametrize(
    "data",
    [
        b'add-generic-password -a "a" -s "s" -w "v" -D "d" -T /usr/bin/security "K"\n'
        b'add-generic-password -a "a" -s "t" -w "v" -D "d" -T /usr/bin/security "K"\n',
        b'delete-keychain "/Users/x/Library/Keychains/login.keychain-db"\n',
        b'add-generic-password -a "a" -s "s" -w "v" -D "d" -T /usr/bin/security -U\n',
        b'add-generic-password -a "a" -s "s" -w "v" -D "d" -T /usr/bin/security'
        b' -U "K"\n',
        b'add-generic-password -a "a" -s "s" -w "v" -D "d" -T /usr/bin/security\n',
        b'add-generic-password -a "a" -s "s" -w "v" -D "d" -T /usr/bin/security'
        b' "/Users/x/Library/Keychains/login.keychain-db"\n',
        b'add-generic-password -a "a" -s "s" -w "v" -D "d" -T /usr/bin/security "K"',
        'add-generic-password -a "a" -s "s" -w "v" -D "d" -T /usr/bin/security "K"\n',
        None,
    ],
    ids=[
        "two-lines",
        "wrong-command",
        "update-flag",
        "update-flag-and-keychain",
        "no-keychain",
        "other-keychain",
        "no-newline",
        "str",
        "no-input",
    ],
)
def test_bad_add_input_is_refused(routed, data):
    keychain, recorder, router = routed
    if isinstance(data, bytes):
        data = data.replace(b'"K"', browser._kc_quote(str(keychain)).encode())
    elif isinstance(data, str):
        data = data.replace('"K"', browser._kc_quote(str(keychain)))
    with pytest.raises(RoutingRefused):
        _send(router, data)
    assert [c["input"] for c in recorder.calls] == [None]  # empty stdin only
    assert not recorder.items


def test_find_gets_the_keychain_appended_and_delete_must_name_it(routed):
    keychain, recorder, router = routed
    router(["security", "find-generic-password", "-a", "A", "-s", "S", "-g"], **_KW)
    argv = ["/usr/bin/security", "delete-generic-password", "-a", "A", "-s", "S"]
    router([*argv, str(keychain)], **_KW)
    assert [c["argv"][-1] for c in recorder.calls] == [str(keychain)] * 2
    assert recorder.calls[1]["argv"][0] == "/usr/bin/security"


def test_default_keychain_is_answered_with_the_temp_path(routed):
    keychain, recorder, router = routed
    proc = router(["security", "default-keychain", "-d", "user"], **_KW)
    out, _ = proc.communicate()
    assert out.decode().strip() == f'"{keychain}"' and proc.returncode == 0
    assert not recorder.calls


@pytest.mark.parametrize(
    "argv",
    [
        ["security", "find-generic-password", "-a", "A", "-s", "S", "-g", "/k"],
        ["security", "find-generic-password", "-a", "A", "-s", "S"],
        ["security", "delete-generic-password", "-a", "A", "-s", "S"],
        ["security", "delete-generic-password", "-a", "A", "-s", "S", "/k"],
        ["security", "dump-keychain"],
        ["security", "list-keychains"],
        ["security", "default-keychain"],
        ["security", "default-keychain", "-s", "/k"],
        ["security", "delete-keychain", "/k"],
        "security find-generic-password -a A -s S -g",
        ["security", "find-generic-password", "-a", "A", "-s", "S", "-w"],
    ],
)
def test_other_security_shapes_are_refused(routed, argv):
    _, recorder, router = routed
    with pytest.raises(RoutingRefused):
        router(argv, **_KW)
    assert not recorder.calls


@pytest.mark.parametrize(
    "kw",
    [
        {"stdin": subprocess.PIPE},
        {"start_new_session": False},
        {"start_new_session": True, "timeout": 15},
    ],
    ids=["no-new-session", "new-session-false", "timeout"],
)
def test_security_outside_a_new_session_is_refused(routed, kw):
    _, recorder, router = routed
    with pytest.raises(RoutingRefused, match="new session"):
        router(["security", "find-generic-password", "-a", "A", "-s", "S", "-g"], **kw)
    assert not recorder.calls


def test_executable_override_is_refused(routed):
    _, recorder, router = routed
    argv = ["find", "find-generic-password", "-a", "A", "-s", "S", "-g"]
    with pytest.raises(RoutingRefused):
        router(argv, executable="/usr/bin/security", **_KW)
    with pytest.raises(RoutingRefused):
        router(["security", "dump-keychain"], executable="/usr/bin/security", **_KW)
    assert not recorder.calls


@pytest.mark.parametrize(
    "argv", [["op", "item", "get", "CSCS"], ["/opt/homebrew/bin/himalaya", "list"]]
)
def test_other_credential_tools_still_hit_the_guard(routed, argv):
    _, recorder, router = routed
    with pytest.raises(DeniedSubprocess):
        router(argv)
    assert not recorder.calls


def test_exec_security_only_runs_security():
    with pytest.raises(RoutingRefused):
        _exec_security(["/bin/echo", "hi"])


def _find(router):
    argv = ["security", "find-generic-password", "-a", "A", "-s", "S", "-g"]
    router(argv, **_KW).communicate()


def test_replaced_keychain_file_is_refused(routed):
    keychain, recorder, router = routed
    other = keychain.with_name("other.keychain-db")
    other.write_bytes(b"")  # exists alongside, so its inode differs
    os.replace(other, keychain)  # same path, same owner, new file
    with pytest.raises(RoutingRefused, match="replaced"):
        _find(router)
    assert not recorder.calls


def test_identity_follows_the_routers_own_writes(routed):
    keychain, _, _ = routed

    def renaming(_argv, _data):  # like securityd: every write is a rename
        other = keychain.with_name("saved.keychain-db")
        other.write_bytes(b"")
        os.replace(other, keychain)
        return 0, "", ""

    fake = FakeSecurityPopen(renaming)
    router = _make_router(keychain, _file_identity(keychain), fake, subprocess.Popen)
    _find(router)
    _find(router)  # the rename by the previous call is not a replacement
    other = keychain.with_name("other.keychain-db")
    other.write_bytes(b"")
    os.replace(other, keychain)  # a replacement between two calls
    with pytest.raises(RoutingRefused, match="replaced"):
        _find(router)


def test_symlinked_keychain_is_refused(tmp_path):
    target = tmp_path.resolve() / "real.keychain-db"
    target.write_bytes(b"")
    link = tmp_path.resolve() / "link.keychain-db"
    identity = _file_identity(target)
    link.symlink_to(target)
    recorder = _Recorder()
    with pytest.raises(RoutingRefused):
        _find(_make_router(link, identity, recorder.popen, subprocess.Popen))
    assert not recorder.calls
    with pytest.raises(KeychainFixtureError, match="not a regular file"):
        _file_identity(link)


def test_missing_keychain_is_refused(routed):
    keychain, recorder, router = routed
    keychain.unlink()
    with pytest.raises(RoutingRefused, match="missing"):
        _find(router)
    assert not recorder.calls


def test_foreign_owned_keychain_is_refused(routed, monkeypatch):
    _, recorder, router = routed
    uid = os.getuid()
    with monkeypatch.context() as m:
        m.setattr(os, "getuid", lambda: uid + 1)
        with pytest.raises(RoutingRefused, match="foreign owner"):
            _find(router)
    assert not recorder.calls


def test_browser_helpers_only_ever_name_the_temp_keychain(routed, monkeypatch):
    keychain, recorder, router = routed
    with monkeypatch.context() as m:
        m.setattr(browser, "_kc_account", lambda: "acct")
        m.setattr(subprocess, "Popen", router)
        assert browser._keychain_set("svc", 'dummy "v"\\', "desc")
        assert browser._keychain_set("svc", "dummy second", "desc")  # overwrite
        assert browser._keychain_get("svc") == "dummy second"
        assert browser._keychain_delete("svc")
    quoted = browser._kc_quote(str(keychain)).encode()
    # (delete, add, read-back) twice, get, delete
    assert len(recorder.calls) == 8
    for call in recorder.calls:
        if call["argv"][1:] == ["-i"]:
            assert call["input"].endswith(b" " + quoted + b"\n")
            assert b" -U" not in call["input"]
        else:
            assert call["argv"][-1] == str(keychain)
        assert call["kwargs"]["start_new_session"] is True
    assert not recorder.items


class _FakeLifecycle:
    """Fake runner for the keychain lifecycle (creates/removes real files)."""

    def __init__(self, fail_at=None, create_file=True, member=False, delete_rc=0):
        self.fail_at, self.create_file = fail_at, create_file
        self.member, self.delete_rc = member, delete_rc
        self.members: set[str] = set()
        self.calls: list[list[str]] = []

    def __call__(self, argv, data=None):
        assert data is None
        self.calls.append(list(argv))
        sub, out, err = argv[1], "", ""
        rc = 1 if sub == self.fail_at else 0
        if sub == "create-keychain" and rc == 0:
            if self.create_file:
                Path(argv[-1]).write_bytes(b"")
            if self.member:
                self.members.add(argv[-1])
        elif sub == "delete-keychain":
            rc = self.delete_rc
            if rc == 0:
                Path(argv[-1]).unlink(missing_ok=True)
                self.members.discard(argv[-1])
        elif sub == "list-keychains":
            out = "".join(f'    "{m}"\n' for m in sorted(self.members))
        elif sub == "show-keychain-info":
            err = f'Keychain "{argv[-1]}" no-timeout\n'
        return browser.SecurityResult("done", rc, out.encode(), err.encode())

    def deletes(self):
        return [c for c in self.calls if c[1] == "delete-keychain"]


def test_temp_keychain_create_and_destroy(tmp_path):
    fake = _FakeLifecycle()
    path, identity = _create_temp_keychain(fake, tmp_path)
    assert path.parent == tmp_path.resolve() and path.name.startswith("tp504-")
    assert identity == _file_identity(path)
    assert all(c[-1] == str(path) for c in fake.calls if c[1] != "list-keychains")
    assert not fake.deletes()
    _destroy_temp_keychain(fake, path)
    assert fake.deletes() == [["security", "delete-keychain", str(path)]]
    assert not path.exists()


def test_lifecycle_runs_through_the_production_runner(tmp_path, monkeypatch):
    seen: list[list[str]] = []

    def runner(argv, data=None):
        seen.append(list(argv))
        return _FakeLifecycle()(argv, data)

    monkeypatch.setattr(browser, "_security_run", runner)
    _destroy_temp_keychain(_exec_security, tmp_path / "gone.keychain-db")
    assert [a[1] for a in seen] == ["delete-keychain", "list-keychains"]


@pytest.mark.parametrize(
    "kwargs",
    [
        {"create_file": False},  # fails right after create-keychain
        {"fail_at": "create-keychain", "create_file": False},
        {"fail_at": "unlock-keychain"},
        {"fail_at": "set-keychain-settings"},
        {"fail_at": "show-keychain-info"},
        {"member": True},
    ],
    ids=["after-create", "create", "unlock", "settings", "info", "search-list"],
)
def test_failed_setup_deletes_the_temp_keychain_once(tmp_path, kwargs):
    fake = _FakeLifecycle(**kwargs)
    with pytest.raises(KeychainFixtureError):
        _create_temp_keychain(fake, tmp_path)
    path = fake.calls[0][-1]
    assert fake.deletes() == [["security", "delete-keychain", path]]
    assert not Path(path).exists()
    assert not fake.members


def test_failed_delete_names_the_path(tmp_path):
    fake = _FakeLifecycle(fail_at="unlock-keychain", delete_rc=1)
    with pytest.raises(KeychainFixtureError) as err:
        _create_temp_keychain(fake, tmp_path)
    path = fake.calls[0][-1]
    assert path in str(err.value)
    assert len(fake.deletes()) == 1
    Path(path).unlink()


def test_items_matching_raises_on_failed_dump(tmp_path):
    def failing(_argv):
        return browser.SecurityResult("done", 51)

    def empty(_argv):
        return browser.SecurityResult("done", 0)

    with pytest.raises(KeychainFixtureError, match="dump-keychain"):
        _items_matching("tp504", tmp_path / "k", failing)
    assert not _items_matching("tp504", tmp_path / "k", empty)


# --- live test (opt-in) ------------------------------------------------------


@pytest.mark.live_keychain
@pytest.mark.skipif(
    os.environ.get("BROWSER_LIVE_KEYCHAIN") != "1" or sys.platform != "darwin",
    reason="live keychain test: set BROWSER_LIVE_KEYCHAIN=1 on macOS",
)
def test_keychain_set_round_trips_through_security_stdin(temp_keychain, monkeypatch):
    keychain, identity = temp_keychain
    account = f"tp504-live-{secrets.token_hex(6)}"
    services = {case: f"{account}-{case}" for case in CASES}
    router = _make_router(keychain, identity, _REAL_POPEN, subprocess.Popen)
    with monkeypatch.context() as m:
        m.setattr(browser, "_kc_account", lambda: account)
        m.setattr(subprocess, "Popen", router)
        for case, value in CASES.items():
            assert browser._keychain_set(services[case], value, "tp504 live test"), case
            got = browser._keychain_get(services[case])
            assert got == value, f"read-back mismatch for case {case}"
        # ONE overwrite (delete-then-add, no -U, so no access-list prompt): once,
        # never a loop
        overwrite = f"{account}-overwrite"
        assert browser._keychain_set(overwrite, "dummy-first", "tp504 live test")
        assert browser._keychain_set(overwrite, "dummy-second", "tp504 live test")
        assert browser._keychain_get(overwrite) == "dummy-second"
        # an invalid value must not reach the keychain at all
        assert not browser._keychain_set(f"{account}-newline", "a\nb", "tp504")
        found = _items_matching(account, keychain)
        expected = [*services.values(), overwrite]
        assert sorted(found) == sorted((account, s) for s in expected), (
            "unexpected items under the throw-away account"
        )
        for svc in expected:
            assert browser._keychain_delete(svc), svc
    assert not _items_matching(account, keychain)
