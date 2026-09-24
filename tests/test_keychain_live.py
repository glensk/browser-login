"""Live check of the keychain helpers against the real ``security`` binary.

The live test NEVER touches the login keychain. It creates its own temporary
keychain file (random password, held in memory only), names that file in every
``security`` call, never adds it to the search list, and deletes it afterwards.

``browser.py``'s keychain helpers name no keychain, so for the live test body a
strict router replaces ``subprocess.run``: it appends the temp keychain path to
exactly the ``security`` shapes those helpers produce and rejects every other
``security`` call. The ``security -i`` add line loses its ``-U``: the update
branch of ``security`` falls back to the login keychain when the named path
cannot be opened, the plain insert fails instead. Other programs go on to
conftest's default-deny guard, which stays active. ``security`` runs with no
timeout — killing it mid-prompt made securityd abort (2026-09-24).

The live test is skipped unless ``BROWSER_LIVE_KEYCHAIN=1`` on macOS. The
offline tests of the router and of the keychain lifecycle always run; they use
fake runners and never execute ``security``. Values are dummies, never printed.

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
from conftest import DeniedSubprocess, _executable

# Captured at import, before conftest's guard wraps ``subprocess.Popen`` for a
# test: ``subprocess.run`` looks ``Popen`` up at call time, so the real run
# would hit the guard. ``_exec_security`` is the only caller.
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
}


class KeychainFixtureError(RuntimeError):
    """The temp keychain could not be set up, verified or removed."""


class RoutingRefused(RuntimeError):
    """The router refused a ``security`` call it cannot pin to the temp keychain.

    Not an ``OSError``/``SubprocessError``, so ``browser.py``'s helpers do not
    swallow it: a refusal fails the test instead of looking like a rejection.
    """


def _exec_security(argv, **kw):
    """``subprocess.run`` for ``security`` on the real ``Popen``, never timed out."""
    if not argv or os.path.basename(argv[0]) != "security":
        raise RoutingRefused("_exec_security only runs `security`")
    kw.pop("timeout", None)
    check = kw.pop("check", False)
    data = kw.pop("input", None)
    if kw.pop("capture_output", False):
        kw["stdout"] = kw["stderr"] = subprocess.PIPE
    kw["stdin"] = subprocess.PIPE if data is not None else subprocess.DEVNULL
    with _REAL_POPEN(argv, **kw) as proc:
        out, err = proc.communicate(data)
    done = subprocess.CompletedProcess(argv, proc.returncode, out, err)
    if check:
        done.check_returncode()
    return done


# --- temp keychain lifecycle -------------------------------------------------


def _kc_lifecycle(runner, argv):
    """Run one lifecycle ``security`` call; raise (naming only the subcommand)."""
    r = runner(argv, capture_output=True, text=True, errors="replace", check=False)
    if r.returncode != 0:
        raise KeychainFixtureError(f"security {argv[1]} failed (rc {r.returncode})")
    return r


def _search_list(runner) -> set[str]:
    """Realpath of every keychain on the user search list (read only)."""
    r = _kc_lifecycle(runner, ["security", "list-keychains", "-d", "user"])
    return {
        os.path.realpath(line.strip().strip('"'))
        for line in r.stdout.splitlines()
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
    path = base / f"tp506-{secrets.token_hex(6)}.keychain-db"
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
        if "no-timeout" not in f"{info.stdout or ''}{info.stderr or ''}":
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
    r = runner(
        ["security", "delete-keychain", str(path)],
        capture_output=True,
        text=True,
        errors="replace",
        check=False,
    )
    if r.returncode != 0 or path.exists():
        raise KeychainFixtureError(
            f"could not delete the temp keychain {path} (rc {r.returncode})"
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
    + rb" -T /usr/bin/security -U\n"
)


_ROUTABLE_ARGV = (
    ["find-generic-password", "-a", None, "-s", None, "-w"],
    ["delete-generic-password", "-a", None, "-s", None],
)


def _check_identity(keychain: Path, identity: tuple[int, int]) -> None:
    if Path(os.path.realpath(keychain)) != keychain:
        raise RoutingRefused("temp keychain path is not its resolved path")
    try:
        current = _file_identity(keychain)
    except KeychainFixtureError as exc:
        raise RoutingRefused(str(exc)) from exc
    if current != identity:
        raise RoutingRefused("temp keychain file was replaced")


def _route_add_line(data, keychain: Path) -> bytes:
    """The ``security -i`` stdin line, insert-only and naming the temp keychain."""
    if not isinstance(data, bytes):
        raise RoutingRefused("security -i stdin must be bytes")
    if data.count(b"\n") != 1 or not _ADD_LINE.fullmatch(data):
        raise RoutingRefused("security -i stdin is not one add-generic-password line")
    if any(b < 0x20 or b == 0x7F for b in data[:-1]):
        raise RoutingRefused("security -i stdin holds a control character")
    quoted: bytes = browser._kc_quote(str(keychain)).encode("utf-8")
    routed = data[: -len(b" -U\n")] + b" " + quoted
    if len(routed) > browser._KC_LINE_MAX:
        raise RoutingRefused("routed security -i line is too long")
    return routed + b"\n"


def _route_security(args, kw, keychain: Path):
    """``(argv, kwargs)`` with the temp keychain named; raise on any other shape."""
    if not isinstance(args, (list, tuple)) or not all(isinstance(a, str) for a in args):
        raise RoutingRefused("security argv must be a list of str")
    head, rest = list(args[:1]), list(args[1:])
    if rest == ["-i"]:
        routed = dict(kw)
        routed["input"] = _route_add_line(kw.get("input"), keychain)
        return head + rest, routed
    # the only argv shapes: <sub> -a A -s S [-w]; the operands A and S are free
    shape = [None if i in (2, 4) else arg for i, arg in enumerate(rest)]
    if shape in _ROUTABLE_ARGV:
        return head + rest + [str(keychain)], dict(kw)
    raise RoutingRefused(f"security {rest[:1]} is not a routable shape")


def _make_router(keychain: Path, identity, security_runner, fallback_run):
    """A ``subprocess.run`` stand-in that pins every ``security`` call to *keychain*.

    *identity* is re-taken after each routed call (securityd renames the file on
    every write), so only a replacement BETWEEN two calls is refused.
    """
    current = [identity]

    def run(args, *a, **kw):
        exe = kw.get("executable")
        prog = _executable(args)
        if "security" in (prog, _executable([exe]) if exe is not None else ""):
            if exe is not None:
                raise RoutingRefused("executable= override on a security call")
            if a:
                raise RoutingRefused("positional run() arguments on a security call")
            _check_identity(keychain, current[0])
            argv, routed = _route_security(args, kw, keychain)
            routed.pop("timeout", None)
            try:
                return security_runner(argv, **routed)
            finally:
                current[0] = _file_identity(keychain)
        return fallback_run(args, *a, **kw)

    return run


def _items_matching(prefix: str, keychain: Path, runner=_exec_security):
    """(account, service) of every temp-keychain item touching our namespace.

    ``dump-keychain`` without ``-d`` prints attributes only, never secrets;
    the output is parsed here and never echoed. A failed dump raises.
    """
    r = _kc_lifecycle(runner, ["security", "dump-keychain", str(keychain)])
    found = []
    for entry in r.stdout.split("keychain: ")[1:]:
        acct = re.search(r'"acct"<blob>="(.*)"', entry)
        svce = re.search(r'"svce"<blob>="(.*)"', entry)
        a = acct.group(1) if acct else ""
        s = svce.group(1) if svce else ""
        if prefix in a or prefix in s:
            found.append((a, s))
    return found


# --- offline tests (always run, fakes only) ----------------------------------


class _Recorder:
    """Fake ``security`` runner: records calls, emulates a tiny keychain."""

    def __init__(self):
        self.calls: list[tuple[list[str], dict]] = []
        self.items: dict[tuple[str, str], str] = {}

    def __call__(self, argv, **kw):
        self.calls.append((list(argv), dict(kw)))
        out, rc = "", 0
        if argv[1:] == ["-i"]:
            fields = re.findall(rb'"((?:[^"\\]|\\.)*)"', kw["input"])
            acct, svc, value = (
                re.sub(rb"\\(.)", rb"\1", f).decode() for f in fields[:3]
            )
            self.items[(acct, svc)] = value
        elif argv[1] == "find-generic-password":
            value = self.items.get((argv[3], argv[5]))
            out, rc = (value + "\n", 0) if value is not None else ("", 44)
        elif argv[1] == "delete-generic-password":
            rc = 0 if self.items.pop((argv[3], argv[5]), None) is not None else 44
        return subprocess.CompletedProcess(argv, rc, out, "")


@pytest.fixture
def routed(tmp_path):
    keychain = tmp_path.resolve() / "fake.keychain-db"
    keychain.write_bytes(b"")
    identity = _file_identity(keychain)
    recorder = _Recorder()
    router = _make_router(keychain, identity, recorder, subprocess.run)
    return keychain, recorder, router


def _add_line(service="svc", value='v a"l\\', description="d") -> bytes:
    line = browser._kc_add_line(service, value, description)
    assert isinstance(line, bytes)
    return line


def test_add_line_drops_update_flag_and_names_keychain(routed, monkeypatch):
    keychain, recorder, router = routed
    monkeypatch.setattr(browser, "_kc_account", lambda: "acct")
    line = _add_line()
    router(["security", "-i"], input=line, capture_output=True, timeout=15)
    ((argv, kw),) = recorder.calls
    assert argv == ["security", "-i"]
    quoted = browser._kc_quote(str(keychain)).encode()
    assert kw["input"] == line[: -len(b" -U\n")] + b" " + quoted + b"\n"
    assert b" -U" not in kw["input"]
    assert "timeout" not in kw


def test_add_line_too_long_after_routing_is_refused(routed, monkeypatch):
    keychain, recorder, router = routed
    monkeypatch.setattr(browser, "_kc_account", lambda: "acct")
    base = len(_add_line(value="")) - 1  # without the newline
    room = browser._KC_LINE_MAX - base
    line = _add_line(value="x" * room)  # fits unrouted, not with the path
    assert len(line) - 1 == browser._KC_LINE_MAX
    assert len(browser._kc_quote(str(keychain))) > 3
    with pytest.raises(RoutingRefused, match="too long"):
        router(["security", "-i"], input=line)
    assert not recorder.calls


@pytest.mark.parametrize(
    "data",
    [
        b'add-generic-password -a "a" -s "s" -w "v" -D "d" -T /usr/bin/security -U\n'
        b'add-generic-password -a "a" -s "t" -w "v" -D "d" -T /usr/bin/security -U\n',
        b'delete-keychain "/Users/x/Library/Keychains/login.keychain-db"\n',
        b'add-generic-password -a "a" -s "s" -w "v" -D "d" -T /usr/bin/security\n',
        b'add-generic-password -a "a" -s "s" -w "v" -D "d" -T /usr/bin/security -U',
        'add-generic-password -a "a" -s "s" -w "v" -D "d" -T /usr/bin/security -U\n',
        None,
    ],
    ids=["two-lines", "wrong-command", "no-U", "no-newline", "str", "no-input"],
)
def test_bad_add_input_is_refused(routed, data):
    _, recorder, router = routed
    with pytest.raises(RoutingRefused):
        router(["security", "-i"], input=data)
    assert not recorder.calls


def test_find_and_delete_get_keychain_as_last_argument(routed):
    keychain, recorder, router = routed
    router(["security", "find-generic-password", "-a", "A", "-s", "S", "-w"])
    router(["/usr/bin/security", "delete-generic-password", "-a", "A", "-s", "S"])
    assert [argv[-1] for argv, _ in recorder.calls] == [str(keychain)] * 2
    assert recorder.calls[1][0][0] == "/usr/bin/security"


@pytest.mark.parametrize(
    "argv",
    [
        ["security", "find-generic-password", "-a", "A", "-s", "S", "-w", "/k"],
        ["security", "find-generic-password", "-a", "A", "-s", "S"],
        ["security", "delete-generic-password", "-a", "A", "-s", "S", "/k"],
        ["security", "dump-keychain"],
        ["security", "list-keychains"],
        ["security", "default-keychain"],
        ["security", "delete-keychain", "/k"],
        "security find-generic-password -a A -s S -w",
    ],
)
def test_other_security_shapes_are_refused(routed, argv):
    _, recorder, router = routed
    with pytest.raises(RoutingRefused):
        router(argv)
    assert not recorder.calls


def test_executable_override_is_refused(routed):
    _, recorder, router = routed
    argv = ["find", "find-generic-password", "-a", "A", "-s", "S", "-w"]
    with pytest.raises(RoutingRefused):
        router(argv, executable="/usr/bin/security")
    with pytest.raises(RoutingRefused):
        router(["security", "dump-keychain"], executable="/usr/bin/security")
    assert not recorder.calls


def test_router_never_passes_timeout(routed):
    _, recorder, router = routed
    router(
        ["security", "find-generic-password", "-a", "A", "-s", "S", "-w"], timeout=15
    )
    assert "timeout" not in recorder.calls[0][1]


@pytest.mark.parametrize(
    "argv", [["op", "item", "get", "CSCS"], ["/opt/homebrew/bin/himalaya", "list"]]
)
def test_other_credential_tools_still_hit_the_guard(routed, argv):
    _, recorder, router = routed
    with pytest.raises(DeniedSubprocess):
        router(argv, check=False)
    assert not recorder.calls


def _find(router):
    router(["security", "find-generic-password", "-a", "A", "-s", "S", "-w"])


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

    def renaming(argv, **_kw):  # like securityd: every write is a rename
        other = keychain.with_name("saved.keychain-db")
        other.write_bytes(b"")
        os.replace(other, keychain)
        return subprocess.CompletedProcess(argv, 0, "", "")

    router = _make_router(keychain, _file_identity(keychain), renaming, subprocess.run)
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
        _find(_make_router(link, identity, recorder, subprocess.run))
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
        m.setattr(subprocess, "run", router)
        assert browser._keychain_set("svc", 'dummy "v"\\', "desc")
        assert browser._keychain_get("svc") == 'dummy "v"\\'
        assert browser._keychain_delete("svc")
    quoted = browser._kc_quote(str(keychain)).encode()
    assert len(recorder.calls) == 4  # add, read-back, get, delete
    for argv, kw in recorder.calls:
        if argv[1:] == ["-i"]:
            assert kw["input"].endswith(b" " + quoted + b"\n")
        else:
            assert argv[-1] == str(keychain)
        assert "timeout" not in kw


class _FakeLifecycle:
    """Fake ``security`` for the keychain lifecycle (creates/removes real files)."""

    def __init__(self, fail_at=None, create_file=True, member=False, delete_rc=0):
        self.fail_at, self.create_file = fail_at, create_file
        self.member, self.delete_rc = member, delete_rc
        self.members: set[str] = set()
        self.calls: list[list[str]] = []

    def __call__(self, argv, **kw):
        assert "timeout" not in kw
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
        return subprocess.CompletedProcess(argv, rc, out, err)

    def deletes(self):
        return [c for c in self.calls if c[1] == "delete-keychain"]


def test_temp_keychain_create_and_destroy(tmp_path):
    fake = _FakeLifecycle()
    path, identity = _create_temp_keychain(fake, tmp_path)
    assert path.parent == tmp_path.resolve() and path.name.startswith("tp506-")
    assert identity == _file_identity(path)
    assert all(c[-1] == str(path) for c in fake.calls if c[1] != "list-keychains")
    assert not fake.deletes()
    _destroy_temp_keychain(fake, path)
    assert fake.deletes() == [["security", "delete-keychain", str(path)]]
    assert not path.exists()


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
    def failing(argv, **_kw):
        return subprocess.CompletedProcess(argv, 51, "", "")

    def empty(argv, **_kw):
        return subprocess.CompletedProcess(argv, 0, "", "")

    with pytest.raises(KeychainFixtureError, match="dump-keychain"):
        _items_matching("tp506", tmp_path / "k", failing)
    assert not _items_matching("tp506", tmp_path / "k", empty)


# --- live test (opt-in) ------------------------------------------------------


@pytest.mark.live_keychain
@pytest.mark.skipif(
    os.environ.get("BROWSER_LIVE_KEYCHAIN") != "1" or sys.platform != "darwin",
    reason="live keychain test: set BROWSER_LIVE_KEYCHAIN=1 on macOS",
)
def test_keychain_set_round_trips_through_security_stdin(temp_keychain, monkeypatch):
    keychain, identity = temp_keychain
    account = f"tp506-live-{secrets.token_hex(6)}"
    services = {case: f"{account}-{case}" for case in CASES}
    with monkeypatch.context() as m:
        m.setattr(browser, "_kc_account", lambda: account)
        m.setattr(
            subprocess,
            "run",
            _make_router(keychain, identity, _exec_security, subprocess.run),
        )
        for case, value in CASES.items():
            assert browser._keychain_set(services[case], value, "tp506 live test"), case
            got = browser._keychain_get(services[case])
            expected = value if value.isascii() else value.encode().hex()
            assert got == expected, f"read-back mismatch for case {case}"
        # No -U UPDATE case on purpose: the router strips -U (insert-only),
        # and an update opened a SecurityAgent prompt on 2026-09-24.
        # an invalid value must not reach the keychain at all
        assert not browser._keychain_set(f"{account}-newline", "a\nb", "tp506")
        found = _items_matching(account, keychain)
        assert sorted(found) == sorted((account, s) for s in services.values()), (
            "unexpected items under the throw-away account"
        )
        for svc in services.values():
            assert browser._keychain_delete(svc), svc
    assert not _items_matching(account, keychain)
