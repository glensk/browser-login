"""Unit tests for the shared browser's proxy auto-config (PAC).

Some hosts answer only from inside a campus network (groups.epfl.ch times out
from home). The shared browser routes ONLY the hosts in `bin/pac_hosts.json`
through their SOCKS5 proxy and everything else DIRECT. Pinned here:

* the committed host map, and the strict validation of every entry (the value
  is pasted into JavaScript: a host or proxy that is not plainly a host name /
  ``SOCKS5 HOST:PORT`` is skipped and named, never rendered);
* the rendered PAC — exact bytes, deterministic order, ``; DIRECT`` fallback
  on every proxied rule, ``DIRECT`` for the rest — and, when `node` exists, its
  behaviour when evaluated;
* the inline ``data:`` URL (Chrome for Testing 153 ignores ``file://``);
* the launch flags: one ``--proxy-pac-url=data:…`` and never a global
  ``--proxy-server``; no host → no proxy flag at all; the 0600 PAC copy;
* the one ``Proxy PAC:`` status line (down / active / not applied / unknown).

Hermetic: no browser is launched, `ps`/`pgrep` are stubbed, every file lives in
tmp_path.

Run: uv run --no-sync pytest tests/test_proxy_pac.py -q
"""

from __future__ import annotations

# Tests reach into browser.py's private helpers on purpose (it is a script, not
# a package, so there is no public API).
# pylint: disable=protected-access,missing-function-docstring,import-error
# pylint: disable=redefined-outer-name,unused-argument
import base64
import importlib.util
import json
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parent.parent
PORT = 59334
EPFL = {"groups.epfl.ch": "SOCKS5 127.0.0.1:1081"}


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


browser = _load("browser_proxy_pac_test", _REPO / "bin" / "browser.py")


@pytest.fixture
def cache(tmp_path, monkeypatch):
    """A private CACHE_DIR/PROFILE_DIR/PAC_FILE for launch tests."""
    monkeypatch.setattr(browser, "CACHE_DIR", tmp_path)
    monkeypatch.setattr(browser, "LIFECYCLE_FILE", tmp_path / "lifecycle.json")
    monkeypatch.setattr(browser, "PROFILE_DIR", tmp_path / "profile")
    monkeypatch.setattr(browser, "PID_FILE", tmp_path / "browser.pid")
    monkeypatch.setattr(browser, "PAC_FILE", tmp_path / "proxy.pac")
    return tmp_path


def _hosts_file(tmp_path: Path, monkeypatch, data) -> Path:
    path = tmp_path / "hosts.json"
    path.write_text(data if isinstance(data, str) else json.dumps(data))
    monkeypatch.setenv(browser.PAC_HOSTS_ENV, str(path))
    return path


# --- the host map -----------------------------------------------------------------


def test_committed_host_map_is_groups_epfl_only():
    assert browser.PAC_HOSTS_FILE == _REPO / "bin" / "pac_hosts.json"
    assert browser._load_pac_hosts() == (EPFL, [])


def test_env_override_replaces_the_committed_map(tmp_path, monkeypatch):
    _hosts_file(tmp_path, monkeypatch, {"intra.ethz.ch": "SOCKS5 127.0.0.1:1080"})
    assert browser._load_pac_hosts() == ({"intra.ethz.ch": "SOCKS5 127.0.0.1:1080"}, [])


def test_missing_override_file_is_a_problem(tmp_path, monkeypatch):
    monkeypatch.setenv(browser.PAC_HOSTS_ENV, str(tmp_path / "nope.json"))
    hosts, problems = browser._load_pac_hosts()
    assert hosts == {} and len(problems) == 1 and problems[0].endswith(": missing")


def test_missing_repo_file_is_silent(tmp_path, monkeypatch):
    monkeypatch.setattr(browser, "PAC_HOSTS_FILE", tmp_path / "pac_hosts.json")
    assert browser._load_pac_hosts() == ({}, [])


def test_unparseable_file_is_a_problem(tmp_path, monkeypatch):
    _hosts_file(tmp_path, monkeypatch, "{not json")
    hosts, problems = browser._load_pac_hosts()
    assert hosts == {} and len(problems) == 1


@pytest.mark.parametrize("data", [[], "x", 3, None])
def test_non_object_is_refused(data):
    assert browser._parse_pac_hosts(data) == (
        {},
        ["not a JSON object of host → proxy"],
    )


def test_entries_are_validated_one_by_one():
    hosts, problems = browser._parse_pac_hosts(
        {
            "Groups.EPFL.ch": " SOCKS5 127.0.0.1:1081 ",
            ".epfl.ch": "SOCKS5 127.0.0.1:1081",
            "proxy.test": "PROXY 10.0.0.1:3128",
            'a"); return "PROXY evil:1': "SOCKS5 127.0.0.1:1081",
            "bad host": "SOCKS5 127.0.0.1:1081",
            "-x.test": "SOCKS5 127.0.0.1:1081",
            "direct.test": "DIRECT",
            "port.test": "SOCKS5 127.0.0.1:99999",
            "zero.test": "SOCKS5 127.0.0.1:0",
            "inject.test": 'SOCKS5 127.0.0.1:1081"; x',
            "two.test": "SOCKS5 127.0.0.1:1081; DIRECT",
            "num.test": 1081,
        }
    )
    assert hosts == {
        "groups.epfl.ch": "SOCKS5 127.0.0.1:1081",
        ".epfl.ch": "SOCKS5 127.0.0.1:1081",
        "proxy.test": "PROXY 10.0.0.1:3128",
    }
    assert len(problems) == 9
    assert all(p.startswith("'") for p in problems)


# --- rendering ----------------------------------------------------------------------


def test_render_one_host_exact_bytes():
    assert browser._render_pac(EPFL) == (
        "function FindProxyForURL(url, host) {\n"
        "  host = host.toLowerCase();\n"
        '  if (host === "groups.epfl.ch") return "SOCKS5 127.0.0.1:1081; DIRECT";\n'
        '  return "DIRECT";\n'
        "}\n"
    )


def test_render_is_deterministic_exact_before_suffix():
    a = {
        ".b.test": "SOCKS5 127.0.0.1:2",
        "z.test": "SOCKS5 127.0.0.1:1",
        "a.test": "SOCKS5 127.0.0.1:1",
    }
    b = dict(reversed(list(a.items())))
    pac = browser._render_pac(a)
    assert pac == browser._render_pac(b)
    body = pac.splitlines()
    assert body[2].startswith('  if (host === "a.test")')
    assert body[3].startswith('  if (host === "z.test")')
    assert body[4] == (
        '  if (host === "b.test" || host.endsWith(".b.test")) '
        'return "SOCKS5 127.0.0.1:2; DIRECT";'
    )


def test_render_empty_map_is_all_direct():
    assert browser._render_pac({}).splitlines()[2] == '  return "DIRECT";'


_NODE = shutil.which("node")


@pytest.mark.skipif(_NODE is None, reason="node not installed")
def test_rendered_pac_routes_only_listed_hosts():
    pac = browser._render_pac({**EPFL, ".intra.test": "SOCKS5 127.0.0.1:1080"})
    cases = {
        "groups.epfl.ch": "SOCKS5 127.0.0.1:1081; DIRECT",
        "GROUPS.EPFL.CH": "SOCKS5 127.0.0.1:1081; DIRECT",
        "epfl.ch": "DIRECT",
        "xgroups.epfl.ch": "DIRECT",
        "www.epfl.ch": "DIRECT",
        "example.com": "DIRECT",
        "intra.test": "SOCKS5 127.0.0.1:1080; DIRECT",
        "a.b.intra.test": "SOCKS5 127.0.0.1:1080; DIRECT",
        "xintra.test": "DIRECT",
    }
    script = pac + (
        "const hosts = " + json.dumps(list(cases)) + ";\n"
        "console.log(JSON.stringify(hosts.map("
        "h => FindProxyForURL('https://' + h + '/', h))));\n"
    )
    out = subprocess.run(
        [str(_NODE), "-e", script], capture_output=True, text=True, check=True
    ).stdout
    assert dict(zip(cases, json.loads(out), strict=True)) == cases


def test_pac_url_is_inline_base64_data():
    pac = browser._render_pac(EPFL)
    url = browser._pac_url(pac)
    assert url.startswith("data:application/x-ns-proxy-autoconfig;base64,")
    assert base64.b64decode(url.split(",", 1)[1]).decode() == pac
    assert " " not in url  # one argv token, one `ps` word


def test_summary_line():
    assert browser._pac_summary({**EPFL, "a.test": "PROXY h:1"}) == (
        "a.test → PROXY h:1, groups.epfl.ch → SOCKS5 127.0.0.1:1081"
    )


# --- launch flags ------------------------------------------------------------------


def test_proxy_flags_write_the_0600_copy(cache, capsys):
    flags = browser._proxy_flags()
    pac = browser._render_pac(EPFL)
    assert flags == [f"--proxy-pac-url={browser._pac_url(pac)}"]
    assert browser.PAC_FILE.read_text() == pac
    assert stat.S_IMODE(browser.PAC_FILE.stat().st_mode) == 0o600
    assert capsys.readouterr().err == ""
    browser._proxy_flags()  # rewrite over an existing copy
    assert stat.S_IMODE(browser.PAC_FILE.stat().st_mode) == 0o600
    assert not list(cache.glob(".proxy.pac.*"))


def test_proxy_flags_without_hosts_add_nothing(cache, tmp_path, monkeypatch, capsys):
    _hosts_file(tmp_path, monkeypatch, {})
    assert browser._proxy_flags() == []
    assert not browser.PAC_FILE.exists()
    assert capsys.readouterr().err == ""


def test_proxy_flags_warn_and_skip_a_bad_entry(cache, tmp_path, monkeypatch, capsys):
    _hosts_file(tmp_path, monkeypatch, {**EPFL, "x y": "SOCKS5 127.0.0.1:1"})
    flags = browser._proxy_flags()
    assert flags == [f"--proxy-pac-url={browser._pac_url(browser._render_pac(EPFL))}"]
    assert "⚠ proxy PAC:" in capsys.readouterr().err


def test_unwritable_copy_still_passes_the_flag(cache, monkeypatch, capsys):
    monkeypatch.setattr(browser, "PAC_FILE", cache / "missing-dir-is-a-file" / "p.pac")
    (cache / "missing-dir-is-a-file").write_text("x")
    assert len(browser._proxy_flags()) == 1
    assert "copy not written" in capsys.readouterr().err


def _launch(monkeypatch) -> list[str]:
    seen: list[list[str]] = []
    monkeypatch.setattr(browser, "_launch_guard", lambda port: None)
    monkeypatch.setattr(browser, "_chromium_binary", lambda: "/x/Chrome")
    monkeypatch.setattr(browser, "_headless_user_agent", lambda binary: "UA/1")

    def launch(binary, flags, headless=False):
        seen.append(flags)
        return 4242

    monkeypatch.setattr(browser, "_launch_browser", launch)
    monkeypatch.setattr(browser, "_is_up", lambda port: True)
    monkeypatch.setattr(browser, "_record_running", lambda port, mode, pid, nonce: pid)
    assert browser._launch_and_record(PORT, True) == 0
    return seen[0]


def test_launch_passes_only_the_pac(cache, monkeypatch):
    flags = _launch(monkeypatch)
    pac_flags = [f for f in flags if f.startswith("--proxy")]
    assert pac_flags == [
        f"--proxy-pac-url={browser._pac_url(browser._render_pac(EPFL))}"
    ]
    assert not any("ALL_PROXY" in f or "socks" in f.lower() for f in flags)
    assert browser.PAC_FILE.exists()


def test_launch_without_hosts_has_no_proxy_flag(cache, tmp_path, monkeypatch):
    _hosts_file(tmp_path, monkeypatch, {})
    assert not any(f.startswith("--proxy") for f in _launch(monkeypatch))


# --- status line ---------------------------------------------------------------------


def _running(monkeypatch, up: bool, cmd: str | None, pids=(777,)):
    monkeypatch.setattr(browser, "_is_up", lambda port: up)
    monkeypatch.setattr(browser, "_find_root_pids", lambda port: list(pids))
    monkeypatch.setattr(browser, "_proc_command", lambda pid: cmd)


_SUMMARY = "Proxy PAC: groups.epfl.ch → SOCKS5 127.0.0.1:1081"


def test_status_line_when_down(monkeypatch):
    _running(monkeypatch, up=False, cmd=None)
    assert browser._pac_status_line(PORT) == (
        f"{_SUMMARY} (applied at the next `browser.py up`)"
    )


def test_status_line_active(monkeypatch):
    url = browser._pac_url(browser._render_pac(EPFL))
    _running(monkeypatch, up=True, cmd=f"/x/Chrome --a --proxy-pac-url={url} --b")
    assert browser._pac_status_line(PORT) == (
        f"{_SUMMARY} (active; DIRECT when the proxy is down)"
    )


@pytest.mark.parametrize(
    "cmd",
    ["/x/Chrome --remote-debugging-port=1", "/x/Chrome --proxy-pac-url=data:old"],
)
def test_status_line_not_applied(monkeypatch, cmd):
    _running(monkeypatch, up=True, cmd=cmd)
    line = browser._pac_status_line(PORT)
    assert line.startswith(f"{_SUMMARY} (NOT in the running browser")
    assert "`browser.py down` then `browser.py up`" in line


@pytest.mark.parametrize("pids,cmd", [((), "x"), ((1, 2), "x"), ((7,), None)])
def test_status_line_unknown(monkeypatch, pids, cmd):
    _running(monkeypatch, up=True, cmd=cmd, pids=pids)
    assert browser._pac_status_line(PORT) == f"{_SUMMARY} (running browser unknown)"


def test_status_line_none_and_problems(tmp_path, monkeypatch):
    _running(monkeypatch, up=False, cmd=None)
    _hosts_file(tmp_path, monkeypatch, {"bad host": "SOCKS5 127.0.0.1:1"})
    line = browser._pac_status_line(PORT)
    assert line.startswith("Proxy PAC: none configured ⚠ ignored: ")
    assert "\n" not in line


def test_print_lifecycle_prints_the_pac_line(cache, monkeypatch, capsys):
    _running(monkeypatch, up=False, cmd=None)
    monkeypatch.setattr(browser, "_lifecycle_problems", lambda port: [])
    browser._print_lifecycle(PORT)
    lines = capsys.readouterr().out.splitlines()
    assert lines[-1] == f"{_SUMMARY} (applied at the next `browser.py up`)"
