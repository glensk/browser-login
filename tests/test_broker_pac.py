"""The home-proxy PAC: the broker's constant copy, its launch, its parity with
the shared browser's map, and the self-check's PAC-route probe (tp#966).

The Cloudflare-Access-gated ``*.dom42.space`` hosts (= nixos
``accessGatedNames``) go through ``vpn.sh homeproxy`` (SOCKS5 127.0.0.1:1082)
in both browsers. Pinned here:

* ``broker/pac.py`` renders exactly those hosts, exact matches only, with the
  ``; DIRECT`` fallback; ``homeassistant`` / ``navidrome`` (and everything
  else) stay DIRECT — checked in Python and, when `node` exists, by running
  the PAC;
* the broker's launch carries that PAC (``launch_args`` / ``launch_kwargs`` /
  ``PlaywrightRunner._launch``) and never reads the agent-writable
  ``bin/pac_hosts.json``;
* parity: the broker constant == the ``:1082`` entries of ``bin/pac_hosts.json``
  (both port 1082), and both render the same PAC bytes for them;
* ``selfcheck.py -R``: routed / access_gated / unreachable, always exit 0 on
  its own, verdict printed before the browser closes, hard deadline.

Hermetic: no real browser (fakes), no network, never port 1082.

Run: uv run --no-sync pytest tests/test_broker_pac.py -q
"""

from __future__ import annotations

# pylint: disable=protected-access,missing-function-docstring,import-error
# pylint: disable=missing-class-docstring,wrong-import-position
# pylint: disable=too-few-public-methods
import base64
import importlib.util
import json
import shutil
import subprocess
import sys
import textwrap
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from broker import daemon, pac, selfcheck  # noqa: E402

GATED = {
    "music.dom42.space",
    "audiobookshelf.dom42.space",
    "booklore.dom42.space",
    "calibre.dom42.space",
    "books.dom42.space",
    "kavita.dom42.space",
    "komga.dom42.space",
    "homepage.dom42.space",
    "kindle-history.dom42.space",
    "jellyfin.dom42.space",
    "vaultwarden.dom42.space",
}
DIRECT_HOSTS = (
    "homeassistant.dom42.space",
    "navidrome.dom42.space",
    "dom42.space",
    "xkomga.dom42.space",
    "komga.dom42.space.evil.test",
    "groups.epfl.ch",
    "example.com",
)
ROUTE = "SOCKS5 127.0.0.1:1082; DIRECT"


def _load_browser():
    spec = importlib.util.spec_from_file_location(
        "browser_broker_pac_test", REPO / "bin" / "browser.py"
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


browser = _load_browser()


def _repo_map() -> dict[str, str]:
    data: dict[str, str] = json.loads(
        (REPO / "bin" / "pac_hosts.json").read_text(encoding="utf-8")
    )
    return data


# --- the broker's constant PAC -------------------------------------------------------


def test_constant_is_the_gated_list_on_1082():
    assert set(pac.HOMEPROXY_PAC_HOSTS) == GATED
    assert len(pac.HOMEPROXY_PAC_HOSTS) == len(GATED)  # no duplicates
    assert pac.HOMEPROXY_PROXY == "SOCKS5 127.0.0.1:1082"
    assert all(not h.startswith(".") for h in pac.HOMEPROXY_PAC_HOSTS)


def test_render_lists_each_exact_host_and_ends_direct():
    lines = pac.render_pac().splitlines()
    assert lines[:2] == [
        "function FindProxyForURL(url, host) {",
        "  host = host.toLowerCase();",
    ]
    rules = lines[2:-2]
    assert rules == [f'  if (host === "{h}") return "{ROUTE}";' for h in sorted(GATED)]
    assert lines[-2:] == ['  return "DIRECT";', "}"]
    assert "endsWith" not in pac.render_pac()  # no suffix rule


@pytest.mark.parametrize("host", sorted(GATED))
def test_route_for_gated_host(host):
    assert pac.route_for(host) == ROUTE
    assert pac.route_for(host.upper()) == ROUTE


@pytest.mark.parametrize("host", DIRECT_HOSTS)
def test_route_for_everything_else_is_direct(host):
    assert pac.route_for(host) == "DIRECT"


_NODE = shutil.which("node")


def _eval_pac(script: str, hosts: list[str]) -> list[str]:
    js = script + (
        "const hosts = " + json.dumps(hosts) + ";\n"
        "console.log(JSON.stringify(hosts.map("
        "h => FindProxyForURL('https://' + h + '/', h))));\n"
    )
    out = subprocess.run(
        [str(_NODE), "-e", js], capture_output=True, text=True, check=True
    ).stdout
    routes: list[str] = json.loads(out)
    return routes


@pytest.mark.skipif(_NODE is None, reason="node not installed")
def test_evaluated_broker_pac_routes_only_gated_hosts():
    hosts = [*sorted(GATED), "KOMGA.dom42.space", *DIRECT_HOSTS]
    got = dict(zip(hosts, _eval_pac(pac.render_pac(), hosts), strict=True))
    assert got == {h: pac.route_for(h) for h in hosts}
    assert got["homeassistant.dom42.space"] == "DIRECT"
    assert got["navidrome.dom42.space"] == "DIRECT"


@pytest.mark.skipif(_NODE is None, reason="node not installed")
def test_evaluated_shared_browser_pac_keeps_ha_and_navidrome_direct():
    script = browser._render_pac(browser._load_pac_hosts()[0])
    hosts = ["homeassistant.dom42.space", "navidrome.dom42.space", "komga.dom42.space"]
    assert _eval_pac(script, hosts) == ["DIRECT", "DIRECT", ROUTE]


def test_pac_url_and_flag_are_inline_data():
    url = pac.pac_url()
    assert url.startswith("data:application/x-ns-proxy-autoconfig;base64,")
    assert base64.b64decode(url.split(",", 1)[1]).decode() == pac.render_pac()
    assert " " not in url
    assert pac.pac_flag() == f"--proxy-pac-url={url}"
    assert pac.PAC_URL_PREFIX == browser.PAC_URL_PREFIX


# --- the broker's launch ---------------------------------------------------------------


def test_launch_args_carry_the_pac_and_no_global_proxy():
    args = daemon.launch_args()
    assert args == [*daemon.CHROME_ARGS, pac.pac_flag()]
    proxy = [a for a in args if a.startswith("--proxy") or "proxy-server" in a]
    assert proxy == [pac.pac_flag()]


def test_launch_args_follow_a_patched_chrome_args(monkeypatch):
    """Fixture tests extend CHROME_ARGS; the PAC is appended at call time."""
    monkeypatch.setattr(daemon, "CHROME_ARGS", ["--a", "--b"])
    assert daemon.launch_args() == ["--a", "--b", pac.pac_flag()]


def test_broker_never_reads_the_agent_writable_map(tmp_path, monkeypatch):
    other = tmp_path / "hosts.json"
    other.write_text(json.dumps({"evil.test": "SOCKS5 127.0.0.1:9"}))
    monkeypatch.setenv(browser.PAC_HOSTS_ENV, str(other))
    before = daemon.launch_args()
    assert pac.pac_flag() in before
    for path in (REPO / "broker" / "pac.py", REPO / "broker" / "daemon.py"):
        text = path.read_text(encoding="utf-8")
        assert "pac_hosts.json" not in text.replace("`bin/pac_hosts.json`", "")
        assert "CLAUDE_BROWSER_PAC_HOSTS" not in text
    assert "evil.test" not in base64.b64decode(pac.pac_url().split(",", 1)[1]).decode()


class _Ctx:
    def __init__(self) -> None:
        self.scripts: list[str] = []
        self.pages: list[Any] = []

    def add_init_script(self, script: str) -> None:
        self.scripts.append(script)


class _Chromium:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def launch_persistent_context(self, **kwargs: Any) -> _Ctx:
        self.calls.append(kwargs)
        return _Ctx()


def test_runner_launch_passes_the_pac(tmp_path, monkeypatch):
    monkeypatch.setattr(daemon, "broker_user_agent", lambda _pw: "UA")
    for name in (
        "clear_http_cache",
        "watch_script_mime",
        "watch_idp_responses",
    ):
        monkeypatch.setattr(daemon, name, lambda _ctx: None)
    chromium = _Chromium()
    runner = daemon.PlaywrightRunner(tmp_path, dev=False)
    runner._launch(SimpleNamespace(chromium=chromium), tmp_path / "profile")
    assert len(chromium.calls) == 1
    kwargs = chromium.calls[0]
    assert kwargs["channel"] == "chromium"
    assert kwargs["args"] == [*daemon.CHROME_ARGS, pac.pac_flag()]
    assert kwargs["headless"] is True and kwargs["chromium_sandbox"] is True
    assert "proxy" not in kwargs  # Playwright would add --proxy-server


# --- parity with the shared browser's map -------------------------------------------


def test_parity_broker_constant_and_pac_hosts_json():
    data = _repo_map()
    on_1082 = {h for h, p in data.items() if p.endswith(":1082")}
    assert on_1082 == set(pac.HOMEPROXY_PAC_HOSTS)
    assert {data[h] for h in on_1082} == {pac.HOMEPROXY_PROXY}
    assert pac.HOMEPROXY_PROXY.endswith(":1082")
    # The shared browser accepts every entry and renders the same bytes for them.
    hosts, problems = browser._load_pac_hosts()
    assert problems == []
    subset = {h: hosts[h] for h in on_1082}
    assert browser._render_pac(subset) == pac.render_pac()


def test_pac_hosts_json_keeps_the_epfl_entries():
    data = _repo_map()
    assert data["groups.epfl.ch"] == "SOCKS5 127.0.0.1:1081"
    assert data["api.epfl.ch"] == "SOCKS5 127.0.0.1:1081"
    assert "homeassistant.dom42.space" not in data
    assert "navidrome.dom42.space" not in data
    assert not any(h.startswith(".") and "dom42" in h for h in data)


# --- selfcheck -R: the PAC-route probe ----------------------------------------------

KOMGA = "https://komga.dom42.space/"
ACCESS = "https://albertha.cloudflareaccess.com/cdn-cgi/access/login/komga?x=1"


@pytest.mark.parametrize(
    "nav,want",
    [
        (([KOMGA, KOMGA + "login"], KOMGA + "login", ""), "routed"),
        (([KOMGA, ACCESS], ACCESS, ""), "access_gated"),
        (
            (["https://komga.dom42.space/cdn-cgi/access/login"],)
            + ("https://komga.dom42.space/cdn-cgi/access/login", ""),
            "access_gated",
        ),
        # single-IdP Access: an Access hop, then the IdP
        (([KOMGA, ACCESS, "https://github.com/login"], "https://github.com/login", ""),
         "access_gated"),
        (([], None, "Page.goto: net::ERR_NAME_NOT_RESOLVED"), "unreachable"),
        (([KOMGA], "https://elsewhere.test/", ""), "unreachable"),
    ],
)  # fmt: skip
def test_classify_route(nav, want):
    result, detail = selfcheck.classify_route(nav)
    assert result == want
    assert "?" not in detail and "/login/komga" not in detail  # origins only


def _navigator(nav, calls: list[str] | None = None):
    def navigate(url, seen):
        if calls is not None:
            calls.append(url)
        seen(nav)
        return nav

    return navigate


@pytest.mark.parametrize(
    "nav,mark,result",
    [
        (([KOMGA], KOMGA, ""), "✅", "routed"),
        (([KOMGA, ACCESS], ACCESS, ""), "ℹ️", "access_gated"),
        (([], None, "net::ERR_PROXY_CONNECTION_FAILED"), "ℹ️", "unreachable"),
    ],
)
def test_route_probe_never_fails(capsys, nav, mark, result):
    calls: list[str] = []
    assert selfcheck.main(["-R"], route_navigate=_navigator(nav, calls)) == 0
    out = capsys.readouterr().out.splitlines()
    assert calls == [selfcheck.ROUTE_PROBE_URL]
    assert len(out) == 1 and out[0].startswith(f"{mark} i) PAC route: {result}: ")
    assert "❌" not in out[0]


def test_route_probe_survives_a_raising_navigator(capsys):
    def boom(_url, _seen):
        raise RuntimeError("no browser")

    assert selfcheck.main(["-R"], route_navigate=boom) == 0
    out = capsys.readouterr().out
    assert "unreachable: probe could not run (RuntimeError)" in out


def test_route_probe_keeps_the_other_checks_verdict(tmp_path, capsys):
    """-R adds a line; the exit code is the other checks' own."""
    nav = ([KOMGA], KOMGA, "")
    rc = selfcheck.main(
        ["-P", "-H", str(tmp_path / "missing"), "-R"], route_navigate=_navigator(nav)
    )
    assert rc == 1
    out = capsys.readouterr().out.splitlines()
    assert out[0].startswith("❌ h)") and out[-1].startswith("✅ i) PAC route")


def test_report_comes_once_and_before_cleanup():
    order: list[str] = []
    nav = ([KOMGA], KOMGA, "")

    def navigate(_url, seen):
        seen(nav)
        order.append("cleanup")
        seen(nav)  # a second call never reports again
        return nav

    got = selfcheck.probe_pac_route(
        navigate, report=lambda r, d: order.append(f"report:{r}")
    )
    assert got[0] == "routed"
    assert order == ["report:routed", "cleanup"]


class _Req:
    def __init__(self, url: str, prev: _Req | None = None) -> None:
        self.url = url
        self.redirected_from = prev


class _Page:
    def __init__(self, final: str, hops: list[str], error: str = "") -> None:
        self.main_frame = object()
        self.url = final
        self._hops = hops
        self._error = error
        self.goto_calls: list[tuple[str, float]] = []

    def on(self, _event: str, _cb: Any) -> None:
        pass

    def goto(self, url: str, timeout: float) -> Any:
        self.goto_calls.append((url, timeout))
        if self._error:
            raise RuntimeError(self._error + " at " + url + "\nCall log: secret page")
        req = None
        for hop in self._hops:
            req = _Req(hop, req)
        return SimpleNamespace(request=req)


class _ProbeCtx:
    def __init__(self, page: _Page, log: list[str]) -> None:
        self.pages = [page]
        self._log = log

    def close(self) -> None:
        self._log.append("close")


class _ProbeChromium:
    def __init__(self, page: _Page, log: list[str]) -> None:
        self.page = page
        self.log = log
        self.kwargs: dict[str, Any] = {}

    def launch_persistent_context(self, **kwargs: Any) -> _ProbeCtx:
        self.kwargs = kwargs
        return _ProbeCtx(self.page, self.log)


def test_navigate_uses_the_broker_launch_and_reports_before_close(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(daemon, "broker_user_agent", lambda _pw: "UA")
    log: list[str] = []
    page = _Page(ACCESS, [KOMGA, ACCESS])
    chromium = _ProbeChromium(page, log)
    nav = selfcheck._navigate(
        SimpleNamespace(chromium=chromium),
        KOMGA,
        tmp_path / "profile",
        lambda n: log.append("seen"),
    )
    kw = chromium.kwargs
    assert kw["channel"] == "chromium"
    assert kw["args"] == daemon.launch_args() and pac.pac_flag() in kw["args"]
    assert kw["headless"] is True and kw["chromium_sandbox"] is True
    assert kw["user_data_dir"] == str(tmp_path / "profile")
    assert kw["timeout"] == selfcheck.ROUTE_PROBE_LAUNCH_S * 1000
    assert page.goto_calls == [(KOMGA, selfcheck.ROUTE_PROBE_GOTO_S * 1000)]
    assert log == ["seen", "close"]
    assert nav == ([KOMGA, ACCESS], ACCESS, "")
    assert selfcheck.classify_route(nav)[0] == "access_gated"


def test_navigate_error_keeps_only_the_first_line(tmp_path, monkeypatch):
    monkeypatch.setattr(daemon, "broker_user_agent", lambda _pw: "UA")
    log: list[str] = []
    page = _Page("", [], error="Page.goto: net::ERR_NAME_NOT_RESOLVED")
    nav = selfcheck._navigate(
        SimpleNamespace(chromium=_ProbeChromium(page, log)),
        KOMGA,
        tmp_path / "p",
        lambda n: None,
    )
    assert nav == ([], None, "Page.goto: net::ERR_NAME_NOT_RESOLVED")
    assert log == ["close"]


def test_probe_bounds_add_up_under_the_deadline():
    assert (
        selfcheck.ROUTE_PROBE_LAUNCH_S + selfcheck.ROUTE_PROBE_GOTO_S
        < selfcheck.ROUTE_PROBE_DEADLINE_S
        <= 20
    )


_DEADLINE_SCRIPT = textwrap.dedent(
    """
    import sys, time
    sys.path.insert(0, {repo!r})
    from broker import selfcheck
    selfcheck.ROUTE_PROBE_DEADLINE_S = 1
    nav = (["https://komga.dom42.space/"], "https://komga.dom42.space/", "")
    def navigate(url, seen):
        if {report_first!r}:
            seen(nav)
        time.sleep(30)
        return nav
    sys.exit(selfcheck.main(["-R"], route_navigate=navigate))
    """
)


@pytest.mark.parametrize("report_first", [False, True])
def test_route_probe_hard_deadline(report_first):
    script = _DEADLINE_SCRIPT.format(repo=str(REPO), report_first=report_first)
    start = time.monotonic()
    proc = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert time.monotonic() - start < 10
    assert proc.returncode == 0
    lines = proc.stdout.splitlines()
    if report_first:  # the verdict was in time: printed once, no "exceeded"
        assert lines == [
            selfcheck.route_line(
                "routed", f"{KOMGA[:-1]} answered through the home proxy"
            )
        ]
    else:
        assert len(lines) == 1 and "unreachable: probe exceeded 1 s" in lines[0]
