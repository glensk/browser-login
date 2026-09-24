"""Shared pytest guard: no test may reach the real keychain, 1Password or mailbox.

An autouse fixture wraps ``subprocess.run`` / ``subprocess.Popen`` with a
default-deny check: a call whose executable basename is ``security``, ``op`` or
``himalaya`` raises instead of running. Tests that mock ``subprocess.run``
themselves replace the wrapper for their own duration, so the guard only bites
when a mock is missing — exactly the case where a test would otherwise touch
Albert's real login keychain. ``tests/test_keychain_live.py`` opts out with the
``live_keychain`` marker (and is itself opt-in via ``BROWSER_LIVE_KEYCHAIN=1``).
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
        "markers", "live_keychain: may run the real `security` binary (opt-in)"
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
def _deny_credential_subprocesses(request, monkeypatch):
    if request.node.get_closest_marker("live_keychain"):
        yield
        return
    monkeypatch.setattr(subprocess, "run", _guard(subprocess.run))
    monkeypatch.setattr(subprocess, "Popen", _guard(subprocess.Popen))
    yield
