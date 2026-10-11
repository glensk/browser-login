"""Shared test helpers: a repo script loaded as a module, and a throwaway
headless Chromium whose every request goes to a routed fixture handler (no
network, never the shared browser)."""

from __future__ import annotations

# pylint: disable=import-outside-toplevel  # playwright only when a test needs it
import contextlib
import functools
import importlib.util
import sys
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parent.parent


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
def chromium_available() -> bool:
    """Playwright's Chromium binary is installed (asked once per run)."""
    try:
        from playwright.sync_api import sync_playwright

        with sync_playwright() as pw:
            binary = Path(pw.chromium.executable_path)
    except Exception:  # pylint: disable=broad-exception-caught
        return False
    return binary.exists()


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
