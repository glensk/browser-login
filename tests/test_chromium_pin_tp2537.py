"""The shared browser launches only the pinned Chromium revision (tp#2537).

Playwright's chromium-1254 (Chrome 158) cannot get its macOS Keychain cookie key,
so a profile launched on it keeps no cookies across a restart. Pinned here:

* `_chromium_binary` picks the pinned revision even when a newer one is on disk,
  and never falls back to another revision when the pinned one is missing;
* the revision override is honoured only for a disposable instance;
* the durable Playwright `.links` entry that keeps the pinned build safe from
  Playwright's install-time GC (exact link name, content and manifest).

Hermetic: every path lives in tmp_path, no browser is launched.

Run: uv run --no-sync pytest tests/test_chromium_pin_tp2537.py -q
"""

from __future__ import annotations

# pylint: disable=protected-access,missing-function-docstring,import-error
# pylint: disable=redefined-outer-name,unused-argument
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parent.parent


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


browser = _load("browser_chromium_pin_test", _REPO / "bin" / "browser.py")
PIN = browser.PINNED_CHROMIUM_REVISION


def _fake_build(cache: Path, revision: int, arch: str = "chrome-mac-arm64") -> str:
    exe = (
        cache
        / f"chromium-{revision}"
        / arch
        / "Google Chrome for Testing.app"
        / "Contents"
        / "MacOS"
        / "Google Chrome for Testing"
    )
    exe.parent.mkdir(parents=True)
    exe.write_text("#!/bin/sh\n")
    exe.chmod(0o755)
    return str(exe)


@pytest.fixture
def cache(tmp_path, monkeypatch):
    """A private Playwright cache + pin root; no override, live (non-test) mode."""
    root = tmp_path / "ms-playwright"
    root.mkdir()
    monkeypatch.setattr(browser, "_playwright_cache_root", lambda: root)
    monkeypatch.setattr(browser, "CHROMIUM_PIN_ROOT", tmp_path / "pin")
    monkeypatch.delenv(browser.CHROMIUM_REVISION_ENV, raising=False)
    monkeypatch.delenv("CLAUDE_BROWSER_CACHE_DIR", raising=False)
    return root


def test_pinned_revision_wins_over_newer(cache):
    pinned = _fake_build(cache, PIN)
    _fake_build(cache, PIN + 6)
    _fake_build(cache, PIN - 5)
    assert browser._chromium_binary() == pinned


def test_intel_layout_is_found(cache):
    pinned = _fake_build(cache, PIN, arch="chrome-mac")
    assert browser._chromium_binary() == pinned


def test_missing_pin_never_falls_back(cache):
    _fake_build(cache, PIN + 6)
    with pytest.raises(SystemExit) as exc:
        browser._chromium_binary()
    assert f"Chromium {PIN} is missing" in str(exc.value)
    assert not (cache / ".links").exists()


def test_override_ignored_for_live_instances(cache, monkeypatch):
    pinned = _fake_build(cache, PIN)
    _fake_build(cache, PIN + 6)
    monkeypatch.setenv(browser.CHROMIUM_REVISION_ENV, str(PIN + 6))
    assert browser._chromium_binary() == pinned


def test_override_honoured_for_disposable_instance(cache, tmp_path, monkeypatch):
    _fake_build(cache, PIN)
    newer = _fake_build(cache, PIN + 6)
    monkeypatch.setenv("CLAUDE_BROWSER_CACHE_DIR", str(tmp_path / "disposable"))
    monkeypatch.setenv(browser.CHROMIUM_REVISION_ENV, str(PIN + 6))
    assert browser._chromium_binary() == newer


def test_bad_override_exits(cache, tmp_path, monkeypatch):
    monkeypatch.setenv("CLAUDE_BROWSER_CACHE_DIR", str(tmp_path / "disposable"))
    monkeypatch.setenv(browser.CHROMIUM_REVISION_ENV, "latest")
    with pytest.raises(SystemExit):
        browser._chromium_revision()


def test_gc_link_registered_and_idempotent(cache, tmp_path):
    _fake_build(cache, PIN)
    browser._chromium_binary()
    pin_dir = tmp_path / "pin" / f"chromium-{PIN}"
    link = cache / ".links" / hashlib.sha1(str(pin_dir).encode()).hexdigest()
    # Playwright reads the link file as the package dir, then <dir>/browsers.json.
    assert link.read_text(encoding="utf-8") == str(pin_dir)
    manifest = json.loads((pin_dir / "browsers.json").read_text(encoding="utf-8"))
    assert manifest["browsers"] == [
        {"name": "chromium", "revision": str(PIN), "installByDefault": False}
    ]
    before = (link.stat().st_mtime_ns, (pin_dir / "browsers.json").stat().st_mtime_ns)
    browser._chromium_binary()
    after = (link.stat().st_mtime_ns, (pin_dir / "browsers.json").stat().st_mtime_ns)
    assert before == after
    assert sorted(p.name for p in (cache / ".links").iterdir()) == [link.name]
    assert sorted(p.name for p in pin_dir.iterdir()) == ["browsers.json"]


def test_gc_link_failure_only_warns(cache, tmp_path, capsys):
    pinned = _fake_build(cache, PIN)
    (tmp_path / "pin").write_text("not a dir")
    assert browser._chromium_binary() == pinned
    assert "could not register" in capsys.readouterr().err
