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
