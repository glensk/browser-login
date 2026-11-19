"""Shared test helpers: a repo script loaded as a module, and a throwaway
headless Chromium whose every request goes to a routed fixture handler (no
network, never the shared browser)."""

from __future__ import annotations

# pylint: disable=import-outside-toplevel  # playwright only when a test needs it
import contextlib
import functools
import importlib.util
import json
import socket
import subprocess
import sys
import time
import urllib.request
from collections.abc import Callable, Collection, Iterator
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parent.parent

# A PWA's service worker: it answers every navigation of its origin with the
# app shell (which would run the app, send the token and write it back).
APP_SW = """
self.addEventListener('install', e => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(clients.claim()));
self.addEventListener('fetch', e => {
  if (e.request.mode === 'navigate')
    e.respondWith(new Response('<p id=shell>app shell</p>',
      {headers: {'content-type': 'text/html'}}));
});
"""


def load_script(rel: str, name: str) -> Any:
    """The repo script `rel` as a module registered under `name`
    (dataclasses resolve their module through sys.modules)."""
    path = REPO / rel
    spec = importlib.util.spec_from_file_location(name, path)
    if not (spec and spec.loader):
        raise ImportError(str(path))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@functools.cache
def chromium_executable() -> str:
    """Playwright's Chromium binary path ('' when unknown), asked once per
    run (one driver start)."""
    try:
        from playwright.sync_api import sync_playwright

        with sync_playwright() as pw:
            return str(pw.chromium.executable_path)
    except Exception:  # pylint: disable=broad-exception-caught
        return ""


def chromium_available() -> bool:
    """Playwright's Chromium binary is installed."""
    exe = chromium_executable()
    return bool(exe) and Path(exe).exists()


@contextlib.contextmanager
def routed_context(handler: Callable[[Any], None]) -> Iterator[Any]:
    """A fresh context of a throwaway headless Chromium; `handler(route)`
    answers every request. The browser is closed on exit."""
    from playwright.sync_api import sync_playwright

    with sync_playwright() as pw:
        chromium = pw.chromium.launch(headless=True)
        try:
            context = chromium.new_context()
            context.route("**/*", handler)
            yield context
        finally:
            chromium.close()


@contextlib.contextmanager
def disposable_chromium(
    profile: Path, start_s: float, avoid: Collection[int] = ()
) -> Iterator[tuple[int, dict[str, Any]]]:
    """A headless Chromium on a free DevTools port (never one of `avoid`, the
    shared instances) with its own `profile`; yields (port, its
    ``/json/version``) once the port answers, TimeoutError after `start_s`.
    Terminated (killed if it lingers) on exit."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = int(s.getsockname()[1])
    assert port not in avoid, port
    proc = subprocess.Popen(  # pylint: disable=consider-using-with
        [
            chromium_executable(),
            "--headless=new",
            f"--remote-debugging-port={port}",
            f"--user-data-dir={profile}",
            "--no-first-run",
            "--no-default-browser-check",
            "about:blank",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        deadline = time.monotonic() + start_s
        while True:
            try:
                with urllib.request.urlopen(
                    f"http://127.0.0.1:{port}/json/version", timeout=1
                ) as r:
                    version: dict[str, Any] = json.loads(r.read())
                break
            except OSError as exc:
                if time.monotonic() > deadline:
                    raise TimeoutError("disposable Chromium did not start") from exc
                time.sleep(0.1)
        yield port, version
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=10)
