"""WS5 S2 (tp#833): the foreign-storage clear in production shape — a
disposable Chromium attached over CDP (connect_over_cdp, its default
context), real owned tabs, registry, lease.

Split from tests/test_ws5_client_s2.py (tp#1655): the real `_connect` starts
its own `sync_playwright()`, which refuses while a module-wide instance is
alive. Here every Playwright instance is short-lived and tracked, under the
same bounded lifecycle (tests/pw_bound.py).
"""

from __future__ import annotations

# pylint: disable=protected-access,import-error,wrong-import-position
# pylint: disable=redefined-outer-name
import secrets
import socket
import subprocess
import sys
import time
import urllib.request
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from chromium_page import APP_SW, REPO, chromium_executable, load_script
from pw_bound import PwHolder, bound_test, chrome_mark, tracking

sys.path.insert(0, str(REPO))

browser = load_script("bin/browser.py", "ws5s2cdp_browser")

ND = "https://music.ws5c.example"
ELSEWHERE = "https://elsewhere.ws5c.example"
CDP_START_S = 60  # the disposable Chromium's DevTools port answers (load-tolerant)
# A test here starts six drivers (five seeding attaches and the real
# `_connect`) and one Chromium: ~47 s at load 20, so a wider bound than 90 s.
CDP_TEST_BOUND_S = 180
CHROME = chrome_mark()


@pytest.fixture(autouse=True)
def _playwright_bound(request: pytest.FixtureRequest) -> Iterator[None]:
    """The main-thread bound of every `launches_chrome` test here (no
    module-wide instance: each attach is its own tracked holder)."""
    yield from bound_test(request, CDP_TEST_BOUND_S)


@pytest.fixture
def cdp_chromium(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[tuple[int, Any]]:
    """A throwaway headless Chromium with a DevTools port (never 9222-9225)
    and every coordination file of browser.py in `tmp_path`; yields
    (port, a seeding helper that runs `fn(page)` on a routed page of the
    default context)."""
    files = {
        "CACHE_DIR": "",
        "LIFECYCLE_FILE": ".browser-lifecycle.json",
        "CLIENTS_DIR": "clients",
        "REGISTRY_GATE": "clients/.registry.lock",
        "INTERACTION_LOCK": "interaction.lock",
        "MAINTENANCE_FILE": "maintenance.json",
        "MAINTENANCE_LOCK": ".maintenance.lock",
    }
    for name, rel in files.items():
        monkeypatch.setattr(browser, name, tmp_path / rel if rel else tmp_path)
    monkeypatch.setenv("CLAUDE_BROWSER_CACHE_DIR", str(tmp_path))
    monkeypatch.delenv("CLAUDE_BROWSER_LEASE_HELD", raising=False)
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = int(s.getsockname()[1])
    assert port not in browser.INSTANCE_PORTS.values()
    proc = subprocess.Popen(  # pylint: disable=consider-using-with
        [
            chromium_executable(),
            "--headless=new",
            f"--remote-debugging-port={port}",
            f"--user-data-dir={tmp_path / 'profile'}",
            "--no-first-run",
            "--no-default-browser-check",
            "about:blank",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        deadline = time.monotonic() + CDP_START_S
        while True:
            try:
                with urllib.request.urlopen(
                    f"http://127.0.0.1:{port}/json/version", timeout=1
                ):
                    break
            except OSError:
                assert time.monotonic() < deadline, "disposable Chromium did not start"
                time.sleep(0.1)

        def seed_doc(route: Any) -> None:
            if route.request.url.endswith("/sw.js"):
                route.fulfill(status=200, content_type="text/javascript", body=APP_SW)
            else:
                route.fulfill(status=200, content_type="text/html", body="<p>seed</p>")

        def on_page(url: str, fn: Any) -> Any:
            """A short-lived, tracked driver attaches, seeds and detaches (a
            stall kills only its own driver; the browser keeps running)."""
            holder = PwHolder(launch=False)
            with tracking(holder):
                try:
                    holder.ensure()
                    attached = holder.pw.chromium.connect_over_cdp(
                        f"http://127.0.0.1:{port}", timeout=30_000
                    )
                    try:
                        ctx = attached.contexts[0]
                        ctx.route("**/*", seed_doc)
                        page = ctx.new_page()
                        try:
                            page.goto(url)
                            return fn(page)
                        finally:
                            if not holder.dead:
                                page.close()
                    finally:
                        if not holder.dead:
                            attached.close()  # disconnects only
                finally:
                    holder.stop("cdp detach")

        yield port, on_page
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=10)


@pytest.mark.launches_chrome
@CHROME
def test_the_clear_route_works_over_connect_over_cdp(
    cdp_chromium: tuple[int, Any],
) -> None:
    """The real `_broker_clear_foreign_storage` against a Chromium attached
    the way production attaches (connect_over_cdp, default context): it
    removes only the planned keys of the planned origin, through an owned
    tab that is gone afterwards."""
    port, on_page = cdp_chromium
    seed = (
        "kv => { for (const [k, v] of Object.entries(kv)) localStorage.setItem(k, v); }"
    )
    read = "() => Object.assign({}, localStorage)"
    token = secrets.token_hex(12)
    on_page(
        f"{ND}/x",
        lambda p: p.evaluate(seed, {"token": token, "userId": "u", "keep": "k"}),
    )
    on_page(f"{ELSEWHERE}/x", lambda p: p.evaluate(seed, {"token": token}))
    plan = {ND: ["token", "userId", "subsonic-token"]}
    assert browser._broker_clear_foreign_storage(port, "navidrome-user", plan) == 2
    assert on_page(f"{ND}/x", lambda p: p.evaluate(read)) == {"keep": "k"}
    assert on_page(f"{ELSEWHERE}/x", lambda p: p.evaluate(read)) == {"token": token}
    assert not [
        t
        for t in browser._page_targets(port)
        if str(t.get("url", "")).startswith(browser.OWNED_MARKER_PREFIX)
        or str(t.get("url", "")).startswith(ND)
    ]


@pytest.mark.launches_chrome
@CHROME
def test_over_cdp_a_service_worker_is_bypassed_or_nothing_is_cleared(
    cdp_chromium: tuple[int, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Production attach, a PWA worker installed on the origin: the real
    bypass keeps it out of the clear tab (cleared); a bypass that does not
    take effect lets the worker answer — the nonce is missing, nothing is
    cleared, and the clear says so."""
    port, on_page = cdp_chromium
    seed = (
        "kv => { for (const [k, v] of Object.entries(kv)) localStorage.setItem(k, v); }"
    )
    register = (
        "async () => { await navigator.serviceWorker.register('/sw.js');"
        " await navigator.serviceWorker.ready; }"
    )
    read = "() => Object.assign({}, localStorage)"
    on_page(f"{ND}/x", lambda p: p.evaluate(register))
    assert "app shell" in on_page(f"{ND}/x", lambda p: p.content())
    plan = {ND: ["token"]}
    on_page(f"{ND}/x", lambda p: p.evaluate(seed, {"token": "a"}))
    assert browser._broker_clear_foreign_storage(port, "navidrome-user", plan) == 1
    on_page(f"{ND}/x", lambda p: p.evaluate(seed, {"token": "b"}))
    monkeypatch.setattr(browser, "_broker_bypass_cache", lambda _p: True)
    with pytest.raises(browser.ForeignStorageError, match="not our document"):
        browser._broker_clear_foreign_storage(port, "navidrome-user", plan)
    assert on_page(f"{ND}/x", lambda p: p.evaluate(read)) == {"token": "b"}
