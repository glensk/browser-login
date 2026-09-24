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

import pytest

_DENIED = frozenset({"security", "op", "himalaya"})


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "live_keychain: may run the real `security` binary against its own temp"
        " keychain through the test's router (opt-in)",
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
