"""tp#1633 B5: `browser.py logout SITE` for a built-in (``SAFARI_BUILTIN``)
site deletes ONLY the site's session cookies from the shared browser.

Hermetic: `_connect` and the lease are fakes; Safari's cookie reader and the
broker raise when touched. Cookie values are per-test placeholders.
"""

from __future__ import annotations

# pylint: disable=missing-function-docstring,import-error,wrong-import-position
# pylint: disable=protected-access,unused-argument
import contextlib
import importlib.util
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

_BROWSER_PY = Path(__file__).resolve().parent.parent / "bin" / "browser.py"


def _load_browser() -> Any:
    spec = importlib.util.spec_from_file_location("browser_logout_test", _BROWSER_PY)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["browser_logout_test"] = mod
    spec.loader.exec_module(mod)
    return mod


browser = _load_browser()


def _ck(name: str, domain: str, path: str = "/") -> dict[str, Any]:
    return {"name": name, "domain": domain, "path": path, "value": "v-" + name}


class FakeJar:
    def __init__(self, cookies: list[dict[str, Any]], log: list[str]) -> None:
        self.jar = cookies
        self.log = log
        self.keep: set[str] = set()  # names whose delete silently fails

    def cookies(self) -> list[dict[str, Any]]:
        self.log.append("read")
        return [dict(c) for c in self.jar]

    def clear_cookies(self, *, name: str, domain: str, path: str) -> None:
        self.log.append(f"clear {name}")
        if name in self.keep:
            return
        self.jar = [
            c
            for c in self.jar
            if (c["name"], c["domain"], c["path"]) != (name, domain, path)
        ]


class _LogoutRig:
    def __init__(self, mp: pytest.MonkeyPatch, cookies: list[dict[str, Any]]) -> None:
        self.log: list[str] = []
        self.jar = FakeJar(cookies, self.log)
        self.contexts = [self.jar]
        mp.setattr(browser, "_connect", self._connect)
        mp.setattr(browser, "_interaction_lease", self._lease)

        def _never(*_a: Any, **_k: Any) -> Any:
            raise AssertionError("Safari or the broker was touched")

        for name in ("read_binarycookies", "session_summary", "default_path"):
            mp.setattr(browser._safari, name, _never)
        mp.setattr(browser, "_broker_request", _never)
        mp.setattr(browser, "_broker_site", _never)

    def _connect(self, port: int, purpose: str = "") -> tuple[Any, Any]:
        self.log.append("connect")
        return self, self

    @contextlib.contextmanager
    def _lease(self, purpose: str, *_a: Any, **_k: Any) -> Iterator[str]:
        self.log.append(f"lease {purpose}")
        yield "nonce"
        self.log.append("unlease")

    def close(self) -> None:
        self.log.append("close")

    def stop(self) -> None:
        self.log.append("stop")

    def names(self) -> set[tuple[str, str]]:
        return {(c["name"], c["domain"]) for c in self.jar.jar}


NOTION_JAR = [
    _ck("token_v2", ".www.notion.so"),
    _ck("notion_user_id", ".www.notion.so"),
    _ck("token_v2", ".notion.com"),
    _ck("notion_browser_id", ".www.notion.so"),
    _ck("device_id", ".notion.com"),
    _ck("token_v2", ".example.org"),  # another site's cookie of the same name
]


def test_logout_notion_clears_only_the_session_cookies(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    rig = _LogoutRig(monkeypatch, list(NOTION_JAR))
    assert browser.cmd_broker_logout(9222, "Notion") == 0
    assert rig.names() == {
        ("notion_browser_id", ".www.notion.so"),
        ("device_id", ".notion.com"),
        ("token_v2", ".example.org"),
    }
    # registration (connect) first, lease second, read back under the lease
    assert rig.log[:2] == ["connect", "lease logout notion"]
    assert rig.log.index("unlease") > max(
        i for i, e in enumerate(rig.log) if e == "read"
    )
    assert rig.log[-2:] == ["close", "stop"]
    out, err = capsys.readouterr()
    assert "deleted 3 notion session cookie(s)" in out
    assert "notion_user_id, token_v2" in out
    assert "Safari untouched" in out
    assert "v-" not in out + err  # names only, never a value


def test_logout_notion_with_no_session_deletes_nothing(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    rig = _LogoutRig(monkeypatch, [_ck("device_id", ".notion.com")])
    assert browser.cmd_broker_logout(9222, "notion") == 0
    assert rig.names() == {("device_id", ".notion.com")}
    assert "deleted 0 notion session cookie(s)" in capsys.readouterr().out


def test_logout_of_a_built_in_site_uses_its_session_cookie_rule(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rig = _LogoutRig(
        monkeypatch,
        [
            _ck("__Secure-next-auth.session-token.0", ".chatgpt.com"),
            _ck("__Secure-next-auth.session-token.1", ".chatgpt.com"),
            _ck("oai-did", ".chatgpt.com"),
            _ck("d", ".slack.com"),
        ],
    )
    assert browser.cmd_broker_logout(9222, "openai") == 0
    assert rig.names() == {("oai-did", ".chatgpt.com"), ("d", ".slack.com")}


def test_a_surviving_session_cookie_is_exit_2(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    rig = _LogoutRig(monkeypatch, list(NOTION_JAR))
    rig.jar.keep.add("notion_user_id")
    assert browser.cmd_broker_logout(9222, "notion") == 2
    assert "survived" in capsys.readouterr().err


def test_a_missing_shared_jar_is_exit_2(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    rig = _LogoutRig(monkeypatch, list(NOTION_JAR))
    rig.contexts = []
    monkeypatch.setattr(browser, "_journal_note", lambda **_k: None)
    assert browser.cmd_broker_logout(9222, "notion") == 2
    assert len(rig.jar.jar) == len(NOTION_JAR)
    assert "no session cookie was deleted" in capsys.readouterr().err
    assert rig.log[-2:] == ["close", "stop"]


def test_a_broker_site_still_takes_the_broker_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[str] = []

    def _site(site: str) -> None:
        seen.append(site)
        raise browser.BrokerUnavailable("no broker in tests")

    monkeypatch.setattr(browser, "_broker_site", _site)
    monkeypatch.setattr(browser, "cmd_builtin_logout", lambda *_a: 99)
    assert browser.cmd_broker_logout(9222, "tutti") == 3
    assert seen == ["tutti"]
