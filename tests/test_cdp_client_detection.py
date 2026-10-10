"""The unregistered-CDP-client check counts connections TO the CDP port only (tp#905).

``lsof -iTCP:<port>`` matches the port on either end of a connection, so an
unrelated outgoing connection that happened to get the CDP port as its local
(ephemeral) port used to count as an "unregistered CDP client" — which made
`switch` refuse and `down` warn. `_established_cdp_clients` now keeps only
connections whose REMOTE port is the CDP port.

Run: python3 -m pytest tests/ -q     (from the repo root)
"""

from __future__ import annotations

# pylint: disable=protected-access,missing-function-docstring,import-error
import importlib.util
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest
from ports import unused_port

_BROWSER_PY = Path(__file__).resolve().parent.parent / "bin" / "browser.py"


def _load_browser_module():
    spec = importlib.util.spec_from_file_location(
        "browser_cdp_clients_test", _BROWSER_PY
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["browser_cdp_clients_test"] = mod
    spec.loader.exec_module(mod)
    return mod


browser = _load_browser_module()
PORT = unused_port()


@pytest.mark.parametrize(
    ("name", "remote"),
    [
        ("127.0.0.1:52345->127.0.0.1:9222", 9222),
        ("[::1]:52345->[::1]:9222", 9222),
        ("192.168.1.2:9222->1.2.3.4:443", 443),
        ("127.0.0.1:9222", None),  # listening socket: no peer
        ("garbage", None),
    ],
)
def test_remote_port_of_an_lsof_name(name, remote):
    assert browser._remote_port(name) == remote


def test_only_connections_to_the_cdp_port_count(monkeypatch):
    """Client (remote = port) counts; outgoing (local = port) and accept side do not."""
    _fake_lsof(
        monkeypatch,
        [
            "p300",
            "cChromium",
            "f30",
            f"n127.0.0.1:{PORT}",  # the CDP listener
            "f40",
            f"n127.0.0.1:{PORT}->127.0.0.1:52345",  # the browser's accepting side
            "p100",
            "cclient",
            "f7",
            f"n127.0.0.1:52345->127.0.0.1:{PORT}",
            "p200",
            "cClaude",
            "f9",
            f"n192.168.178.28:{PORT}->160.79.104.10:443",  # the tp#905 flake
            "p400",
            "cnode",
            "f12",
            f"n[::1]:52346->[::1]:{PORT}",
        ],
    )
    assert browser._established_cdp_clients(PORT) == [(100, "client"), (400, "node")]


def test_no_listener_means_no_cdp_client(monkeypatch):
    """The tp#905 flake on loopback: an outgoing connection got the (unused)
    port as its LOCAL port, so its local peer's REMOTE port is that port."""
    _fake_lsof(
        monkeypatch,
        [
            "p200",
            "cClaude",
            "f9",
            f"n127.0.0.1:{PORT}->127.0.0.1:1081",
            "p500",
            "cssh",
            "f5",
            f"n127.0.0.1:1081->127.0.0.1:{PORT}",
        ],
    )
    assert browser._established_cdp_clients(PORT) == []


def _fake_lsof(monkeypatch, lines: list[str]) -> None:
    """`lsof -F` prints `lines`; `ps` knows no process (the `c` field is used)."""

    def fake_run(cmd, **_kw):
        assert cmd[0] == "lsof" and f"-iTCP:{PORT}" in cmd
        out = "\n".join(lines) + "\n"
        return subprocess.CompletedProcess(cmd, 0, stdout=out, stderr="")

    monkeypatch.setattr(browser.subprocess, "run", fake_run)
    monkeypatch.setattr(browser, "_proc_command", lambda _pid: None)


_CHILD = r"""
import socket, sys, time
cdp, local = int(sys.argv[1]), int(sys.argv[2])
srv = socket.create_server(("127.0.0.1", cdp))
client = socket.create_connection(("127.0.0.1", cdp))  # a real CDP client
other = socket.create_server(("127.0.0.1", 0))
out = socket.socket()
out.bind(("127.0.0.1", local))  # outgoing connection whose LOCAL port is `local`
out.connect(other.getsockname())
conns = [srv.accept()[0], other.accept()[0]]
print("ready", flush=True)
time.sleep(60)
"""


@pytest.mark.skipif(shutil.which("lsof") is None, reason="needs lsof")
def test_real_outgoing_local_port_is_not_a_cdp_client():
    """Real sockets: a connection FROM port X is not a client OF port X."""
    cdp, local = unused_port(), unused_port()
    while local == cdp:
        local = unused_port()
    with subprocess.Popen(
        [sys.executable, "-c", _CHILD, str(cdp), str(local)],
        stdout=subprocess.PIPE,
        text=True,
    ) as child:
        try:
            assert child.stdout is not None
            assert child.stdout.readline().strip() == "ready"
            deadline = time.monotonic() + 10
            while (
                child.pid not in dict(browser._established_cdp_clients(cdp))
                and time.monotonic() < deadline
            ):
                time.sleep(0.2)
            assert child.pid in dict(browser._established_cdp_clients(cdp))
            assert browser._established_cdp_clients(local) == []
        finally:
            child.kill()
