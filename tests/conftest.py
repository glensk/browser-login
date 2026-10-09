"""Shared pytest guard: no test may reach the real keychain, 1Password or mailbox.

An autouse fixture wraps ``subprocess.run`` / ``subprocess.Popen`` with a
default-deny check: a call whose executable basename is ``security``, ``op`` or
``himalaya`` raises instead of running. Tests that mock ``subprocess.run``
themselves replace the wrapper for their own duration, so the guard only bites
when a mock is missing — exactly the case where a test would otherwise touch
Albert's real login keychain. The guard has NO opt-out: the ``live_keychain``
test in ``tests/test_keychain_live.py`` (opt-in via ``BROWSER_LIVE_KEYCHAIN=1``)
runs ``security`` only through its own router, against its own temporary
keychain file, while this guard keeps denying everything else.
"""

from __future__ import annotations

# pylint: disable=import-error
import os
import shlex
import subprocess
import sys

import pytest

_DENIED = frozenset({"security", "op", "himalaya"})


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "live_keychain: may run the real `security` binary against its own temp"
        " keychain through the test's router (opt-in)",
    )
    config.addinivalue_line(
        "markers",
        "browser: drives a real headless Chromium against a local fixture site"
        " (opt-in via LOGIN_BROKER_E2E=1)",
    )
    config.addinivalue_line(
        "markers",
        "launches_chrome: may launch a real (disposable, headless) Chrome through"
        " browser.py's _launch_browser — and must stop it again",
    )


def _executable(args) -> str:
    """Basename of the program an argv/str command would run ('' if unknown)."""
    if isinstance(args, (str, bytes)):
        text = args.decode() if isinstance(args, bytes) else args
        try:
            parts = shlex.split(text)
        except ValueError:
            parts = text.split()
        first = parts[0] if parts else ""
    else:
        seq = list(args)
        first = os.fspath(seq[0]) if seq else ""
        if isinstance(first, bytes):
            first = first.decode()
    return os.path.basename(str(first))


def _security_g(value: str) -> str:
    """Stderr of the keychain reader's labelled dump (``-g``) for ``value``.

    Mirrors Apple's formatter (SecurityTool keychain_utilities.c, tp#498):
    all bytes printable ASCII and none a backslash → quoted verbatim; else
    ``0x<UPPER HEX>`` followed by two spaces and an octal-escaped rendering
    when at least one byte is printable and not a backslash, or by a single
    trailing space when none is. An empty value gives the bare label.
    """
    data = value.encode("utf-8")
    label = "pass" + "word:"
    if not data:
        return label + "\n"

    def shown(b: int) -> bool:
        return 0x20 <= b < 0x7F and b != 0x5C

    if all(shown(b) for b in data):
        return f'{label} "{value}"\n'
    hexed = "0x" + data.hex().upper()
    if not any(shown(b) for b in data):
        return f"{label} {hexed} \n"
    rendered = "".join(chr(b) if shown(b) else f"\\{b:03o}" for b in data)
    return f'{label} {hexed}  "{rendered}"\n'


class DeniedSubprocess(RuntimeError):
    """Raised when a test would run a credential/mail tool for real."""


def _guard(real):
    def wrapper(args, *a, **kw):
        exe = _executable(kw.get("executable") or args)
        if exe in _DENIED:
            raise DeniedSubprocess(
                f"test tried to run `{exe}` for real — mock subprocess.run"
            )
        return real(args, *a, **kw)

    return wrapper


@pytest.fixture(autouse=True)
def _private_journal(tmp_path, monkeypatch):
    """Every test journals into its own tmp file, never the live cache's journal.

    browser.py appends to ``CACHE_DIR/journal.jsonl`` on up/switch/down/login,
    window raises and client (un)registration; many tests reach those paths
    without repointing CACHE_DIR, so the path override is set for all of them.

    The override lives in its OWN MonkeyPatch, so a test that calls
    ``monkeypatch.undo()`` mid-way cannot drop it; requesting ``monkeypatch``
    only orders teardown, so the after-check still sees the test's patches.
    """
    del monkeypatch  # requested for teardown ordering only
    with pytest.MonkeyPatch.context() as own:
        own.setenv("CLAUDE_BROWSER_JOURNAL_FILE", str(tmp_path / "journal.jsonl"))
        _assert_journal_not_live()
        yield
        _assert_journal_not_live()


@pytest.fixture(autouse=True)
def _private_mode_state(tmp_path, monkeypatch):
    """The headless-invariant state files of every loaded browser.py live in tmp.

    ``desired-mode.json``, ``maintenance.json`` (the guided-login record, + its
    lock), the client registry (+ its gate), the download dir and the proxy PAC
    copy are module constants computed from the live cache dir at import time;
    a test reaching `cmd_up`/`cmd_switch`/`_headed_lease` must never write the
    real ones. A guided login running on this Mac must not leak into a test
    either, hence the lease env var is cleared.
    """
    monkeypatch.delenv("CLAUDE_BROWSER_MAINTENANCE", raising=False)
    # A developer's host-map override must not change what a launch test sees.
    monkeypatch.delenv("CLAUDE_BROWSER_PAC_HOSTS", raising=False)
    state = tmp_path / "mode-state"
    for mod in list(sys.modules.values()):
        if getattr(mod, "MAINTENANCE_FILE", None) is None:
            continue
        monkeypatch.setattr(mod, "DESIRED_MODE_FILE", state / "desired-mode.json")
        monkeypatch.setattr(mod, "MAINTENANCE_FILE", state / "maintenance.json")
        monkeypatch.setattr(mod, "MAINTENANCE_LOCK", state / ".maintenance.lock")
        monkeypatch.setattr(mod, "DOWNLOAD_DIR", state / "downloads")
        # The client registry too: a revert transaction pauses (SIGUSR1) the
        # registered long-lived clients it finds — never the live ones.
        if getattr(mod, "CLIENTS_DIR", None) is not None:
            monkeypatch.setattr(mod, "CLIENTS_DIR", state / "clients")
            monkeypatch.setattr(
                mod, "REGISTRY_GATE", state / "clients" / ".registry.lock"
            )
        if getattr(mod, "PAC_FILE", None) is not None:
            monkeypatch.setattr(mod, "PAC_FILE", state / "proxy.pac")
    yield


_LIVE_CACHE_PREFIX = os.path.join(os.path.expanduser("~"), ".cache", "claude-browser")


def _assert_journal_not_live() -> None:
    """Abort the whole session if any loaded browser.py would journal live.

    Checks every imported copy of browser.py (each test file loads its own
    under its own module name) by asking it where it would write right now.
    """
    for name, mod in list(sys.modules.items()):
        resolve = getattr(mod, "_journal_path", None)
        if not callable(resolve):
            continue
        try:
            path = os.path.realpath(os.fspath(resolve()))
        except Exception:  # pylint: disable=broad-exception-caught
            continue
        live = os.path.realpath(_LIVE_CACHE_PREFIX)
        if path.startswith(live):
            pytest.exit(
                f"❌ {name}: journal path {path} is under the live browser cache "
                f"({live}*) — a test would write the real journal",
                returncode=3,
            )


@pytest.fixture(autouse=True)
def _no_real_chrome_launch(request, monkeypatch):
    """No test launches a real Chrome through browser.py unless it opts in.

    browser.py's `_launch_browser` exits (❌ test guard) while
    CLAUDE_BROWSER_TEST_NO_LAUNCH=1 — in this process and in every
    `browser.py` subprocess a test starts (they inherit the env). A test that
    really needs one (a disposable headless browser it also stops) carries
    the `launches_chrome` marker. Without this a fake CDP endpoint that looked
    headed made `_preflight` "revert" it, i.e. launch a Chrome nobody stopped.
    """
    if request.node.get_closest_marker("launches_chrome") is None:
        monkeypatch.setenv("CLAUDE_BROWSER_TEST_NO_LAUNCH", "1")
    else:
        monkeypatch.delenv("CLAUDE_BROWSER_TEST_NO_LAUNCH", raising=False)
    yield


@pytest.fixture(autouse=True)
def _deny_credential_subprocesses(monkeypatch):
    monkeypatch.setattr(subprocess, "run", _guard(subprocess.run))
    monkeypatch.setattr(subprocess, "Popen", _guard(subprocess.Popen))
    yield


class FakeSecurityPopen:
    """``subprocess.Popen`` stand-in for ``browser._security_run`` — runs nothing.

    ``handler(argv, input)`` answers each call with ``(rc, stdout, stderr)``
    (``str`` or ``bytes``); an exception it raises escapes ``communicate``.
    ``not_started(argv)`` → the constructor raises ``OSError``;
    ``interrupt(argv)`` → the first ``communicate`` runs the handler (the child
    finishes), then raises ``KeyboardInterrupt``; the retry returns the result
    and must not resend input. ``kill``/``terminate``/``send_signal`` raise:
    ``security`` is never signalled. ``calls`` holds every started call as
    ``{"argv", "kwargs", "input"}``.
    """

    def __init__(self, handler, *, not_started=None, interrupt=None):
        self.handler = handler
        self.not_started = not_started or (lambda argv: False)
        self.interrupt = interrupt or (lambda argv: False)
        self.calls: list[dict] = []
        self.interrupts = 0

    def __call__(self, argv, **kwargs):
        argv = list(argv)
        if self.not_started(argv):
            raise OSError("security not runnable (fake)")
        call = {"argv": argv, "kwargs": kwargs, "input": None}
        self.calls.append(call)
        return _FakeSecurityProc(self, call)

    def argvs(self) -> list[list[str]]:
        return [c["argv"] for c in self.calls]


def _as_bytes(value) -> bytes:
    return value.encode("utf-8") if isinstance(value, str) else bytes(value)


class _FakeSecurityProc:
    def __init__(self, owner: FakeSecurityPopen, call: dict):
        self._owner, self._call = owner, call
        self.args = call["argv"]
        self.returncode: int | None = None
        self._result: tuple[bytes, bytes] | None = None

    def communicate(self, input=None, timeout=None):  # noqa: A002  # pylint: disable=redefined-builtin
        assert timeout is None, "security must never be timed out"
        if self._result is not None:
            assert input is None, "a retried communicate must not resend input"
            return self._result
        self._call["input"] = input
        rc, out, err = self._owner.handler(self.args, input)
        self.returncode = rc
        self._result = (_as_bytes(out), _as_bytes(err))
        if self._owner.interrupt(self.args):
            self._owner.interrupts += 1
            raise KeyboardInterrupt
        return self._result

    def wait(self, timeout=None):
        assert timeout is None, "security must never be timed out"
        if self.returncode is None:
            self.returncode = 0
        return self.returncode

    def kill(self):
        raise AssertionError("security must never be killed")

    terminate = send_signal = kill


def security_op(argv) -> str:
    """``add`` / ``find`` / ``delete`` / ``default`` / the raw subcommand."""
    if list(argv[1:]) == ["-i"]:
        return "add"
    names = {
        "find-generic-password": "find",
        "delete-generic-password": "delete",
        "default-keychain": "default",
    }
    return str(names.get(argv[1], argv[1]))


@pytest.fixture(autouse=True)
def _agent_login_state(tmp_path, monkeypatch):
    """agent-login.py's last-check state goes to a temp file, never the real one."""
    monkeypatch.setenv("AGENT_LOGIN_STATE_FILE", str(tmp_path / "last-check.json"))
