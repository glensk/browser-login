"""secret-run (bin/secret_run.py): CLI, process model and the hermetic E2E
against an in-process broker (FixtureVault) and a fake secretkeeper.

Every injected value is a random sentinel; the tests assert it never reaches
secret-run's output, stderr or the broker's audit log.

Run: uv run --no-sync pytest tests/test_secret_run.py
"""

from __future__ import annotations

# pylint: disable=missing-function-docstring,redefined-outer-name,import-error
# pylint: disable=protected-access,wrong-import-position,consider-using-with
import contextlib
import fcntl
import importlib.util
import json
import os
import re
import select
import signal
import struct
import subprocess
import sys
import termios
import time
from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parent
REPO = TESTS.parent
sys.path.insert(0, str(TESTS))
import secret_fixtures as sf  # noqa: E402

CLIENT = REPO / "bin" / "secret_run.py"
WRAPPER = REPO / "bin" / "secret-run"
_spec = importlib.util.spec_from_file_location("secret_run", CLIENT)
assert _spec and _spec.loader
sr = importlib.util.module_from_spec(_spec)
sys.modules["secret_run"] = sr
_spec.loader.exec_module(sr)


def _run(args, env_extra=None, *, timeout=30, stdin=None):
    # Never the installed broker's default socket: a test only talks to its own.
    env = {**os.environ, sr.SOCKET_ENV: "/nonexistent-secret-run-test.sock"}
    env.update(env_extra or {})
    return subprocess.run(
        [sys.executable, str(CLIENT), *args],
        capture_output=True,
        env=env,
        timeout=timeout,
        check=False,
        stdin=stdin if stdin is not None else subprocess.DEVNULL,
    )


# ---------------------------------------------------------------------------
# A7: CLI surface
# ---------------------------------------------------------------------------


def test_every_option_has_a_short_and_a_long_flag():
    parser = sr.build_parser()
    for action in parser._actions:
        shorts = [o for o in action.option_strings if re.fullmatch(r"-[A-Za-z]", o)]
        longs = [o for o in action.option_strings if o.startswith("--")]
        assert shorts and longs, action.option_strings
    flags = {o for a in parser._actions for o in a.option_strings}
    for want in (
        "-e",
        "-p",
        "-s",
        "-t",
        "-T",
        "-v",
        "-o",
        "-l",
        "-V",
        "-A",
        "-N",
        "-h",
    ):
        assert want in flags


def test_help_exits_zero():
    proc = _run(["-h"])
    assert proc.returncode == 0
    out = proc.stdout.decode()
    assert "secret-run -e NAME=ITEM[:FIELD]" in out and "Exit codes" in out
    shell = subprocess.run(["bash", "-n", str(WRAPPER)], check=False)
    assert shell.returncode == 0
    assert os.access(CLIENT, os.X_OK) and os.access(WRAPPER, os.X_OK)


@pytest.mark.parametrize(
    "spec",
    [
        "PATH=x",
        "HOME=x",
        "LD_PRELOAD=x",
        "DYLD_INSERT_LIBRARIES=x",
        "PYTHONPATH=x",
        "NODE_OPTIONS=x",
        "BASH_ENV=x",
        "lower=x",
        "1X=x",
        "X=Bad Item",
        "noequals",
    ],
)
def test_refused_names_exit_125_before_the_broker(spec):
    proc = _run(["-e", spec, "--", "true"], {sr.SOCKET_ENV: "/nonexistent.sock"})
    assert proc.returncode == 125
    err = proc.stderr.decode()
    assert "❌" in err and "not reachable" not in err


@pytest.mark.parametrize(
    "cmd",
    [
        ["printenv"],
        ["printenv", "X"],
        ["/usr/bin/env"],
        ["env", "-i"],
        ["env", "FOO=1"],
        ["env", "-u", "X"],
        ["set"],
        ["export", "-p"],
        ["declare", "-p"],
        ["typeset", "-x"],
        ["compgen", "-e"],
        ["sh", "-c", "env"],
        ["bash", "-c", " printenv "],
    ],
)
def test_environment_dumps_are_refused(cmd):
    assert sr.env_dump_reason(cmd)
    proc = _run(["-e", "X=item", "--", *cmd], {sr.SOCKET_ENV: "/nonexistent.sock"})
    assert (
        proc.returncode == 125 and "would print the environment" in proc.stderr.decode()
    )


@pytest.mark.parametrize(
    "cmd",
    [
        ["env", "FOO=1", "true"],
        ["env", "-u", "X", "make"],
        ["sh", "-c", "env | grep X"],  # a pipeline is not the obvious accident
        ["kubectl", "get", "pods"],
        ["declare", "-p", "X"],
    ],
)
def test_commands_that_are_not_dumps(cmd):
    assert sr.env_dump_reason(cmd) is None


def test_usage_errors_exit_125():
    assert _run(["-e", "X=item"]).returncode == 125  # no `-- CMD`
    assert _run(["--", "true"]).returncode == 125  # nothing to inject
    assert _run(["-l", "-o", "x"]).returncode == 125
    assert _run(["--bogus"]).returncode == 125
    assert _run(["-T", "0", "-e", "X=a", "--", "true"]).returncode == 125


# ---------------------------------------------------------------------------
# A6: process model (in-process, no broker)
# ---------------------------------------------------------------------------

VALUE = sf.sentinel()
PATTERNS = sr.variant_set(VALUE).patterns


def _pipes():
    r_out, w_out = os.pipe()
    r_err, w_err = os.pipe()
    return (r_out, w_out), (r_err, w_err)


def _drain(fd):
    os.set_blocking(fd, False)
    chunks = []
    while True:
        try:
            chunk = os.read(fd, 65536)
        except BlockingIOError:
            break
        if not chunk:
            break
        chunks.append(chunk)
    return b"".join(chunks)


def _run_pipe(cmd, **kw):
    (r_out, w_out), (r_err, w_err) = _pipes()
    env = {**os.environ, "X": VALUE}
    try:
        res = sr.run_pipe(
            cmd, env, list(PATTERNS), in_fd=None, out_fd=w_out, err_fd=w_err, **kw
        )
    finally:
        os.close(w_out)
        os.close(w_err)
    out, err = _drain(r_out), _drain(r_err)
    os.close(r_out)
    os.close(r_err)
    return res, out, err


def test_pipe_masks_both_streams_and_keeps_the_exit_code():
    script = 'echo "$X"; echo "pre-$X-post" >&2; printf %s "$X" | base64; exit 3'
    res, out, err = _run_pipe(["sh", "-c", script])
    assert res.exit_code == 3
    assert out == b"***\n***\n"
    assert err == b"pre-***-post\n"
    assert res.masked == 3
    assert VALUE.encode() not in out + err


def test_grandchild_holding_the_pipe_is_reaped_quickly():
    start = time.monotonic()
    res, out, _err = _run_pipe(["sh", "-c", "sleep 30 & echo $!"])
    assert time.monotonic() - start < 4.0
    assert res.exit_code == 0
    pid = int(out.split()[0])
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.05)
    else:
        pytest.fail(f"grandchild {pid} still alive")


def test_epipe_terminates_the_group_with_141():
    r_out, w_out = os.pipe()
    os.close(r_out)  # the agent stopped reading
    r_err, w_err = os.pipe()
    start = time.monotonic()
    try:
        res = sr.run_pipe(
            ["sh", "-c", "yes; echo done >&2"],
            dict(os.environ),
            list(PATTERNS),
            in_fd=None,
            out_fd=w_out,
            err_fd=w_err,
        )
    finally:
        os.close(w_out)
        os.close(w_err)
        os.close(r_err)
    assert res.exit_code == 141
    assert time.monotonic() - start < 6


def test_timeout_is_124():
    start = time.monotonic()
    res, _out, _err = _run_pipe(["sleep", "10"], timeout=0.5)
    assert res.exit_code == 124 and time.monotonic() - start < 4


def test_signal_death_is_128_plus_n_and_exec_failures():
    res, _o, _e = _run_pipe(["sh", "-c", "kill -TERM $$"])
    assert res.exit_code == 128 + signal.SIGTERM
    assert _run_pipe(["/nonexistent/cmd"])[0].exit_code == 127


def test_not_executable_is_126(tmp_path):
    script = tmp_path / "noexec.sh"
    script.write_text("#!/bin/sh\necho hi\n")
    script.chmod(0o644)
    assert _run_pipe([str(script)])[0].exit_code == 126


def test_stdin_value_then_eof():
    res, out, _err = _run_pipe(["cat"], stdin_data=VALUE.encode() + b"\n")
    assert res.exit_code == 0 and out == b"***\n"


# tp#853: kqueue (macOS) never reports EOF on a regular file, so the relay must
# read such a stdin directly. Every case is bounded by `timeout=` — a regression
# is exit 124, never a hung suite.


def _run_pipe_from(in_fd, cmd=("wc", "-c")):
    (r_out, w_out), (r_err, w_err) = _pipes()
    try:
        res = sr.run_pipe(
            list(cmd),
            dict(os.environ),
            list(PATTERNS),
            in_fd=in_fd,
            out_fd=w_out,
            err_fd=w_err,
            timeout=10,
        )
    finally:
        os.close(w_out)
        os.close(w_err)
    out = _drain(r_out)
    os.close(r_out)
    os.close(r_err)
    return res, out


@pytest.mark.parametrize("size", [0, 5, sr.MAX_PENDING_INPUT * 3 + 7])
def test_regular_file_stdin_reaches_eof(tmp_path, size):
    path = tmp_path / "in.bin"
    path.write_bytes(b"x" * size)
    with open(path, "rb") as fh:
        start = time.monotonic()
        res, out = _run_pipe_from(fh.fileno())
    assert res.exit_code == 0, "child stdin never closed (124 = timed out)"
    assert int(out.split()[0]) == size
    assert time.monotonic() - start < 8


def test_regular_file_stdin_from_its_current_offset(tmp_path):
    path = tmp_path / "in.txt"
    path.write_bytes(b"0123456789")
    with open(path, "rb") as fh:
        fh.seek(4)
        res, out = _run_pipe_from(fh.fileno())
    assert res.exit_code == 0 and int(out.split()[0]) == 6


def test_pipe_stdin_still_relayed():
    r, w = os.pipe()
    os.write(w, b"hello\n")
    os.close(w)
    try:
        res, out = _run_pipe_from(r)
    finally:
        os.close(r)
    assert res.exit_code == 0 and int(out.split()[0]) == 6


def test_dev_null_stdin_is_eof():
    with open(os.devnull, "rb") as fh:
        res, out = _run_pipe_from(fh.fileno())
    assert res.exit_code == 0 and int(out.split()[0]) == 0


def test_child_that_ignores_a_regular_file_stdin(tmp_path):
    path = tmp_path / "in.bin"
    path.write_bytes(b"y" * (sr.MAX_PENDING_INPUT * 2))
    with open(path, "rb") as fh:
        res, out = _run_pipe_from(fh.fileno(), cmd=("sh", "-c", "echo done"))
    assert res.exit_code == 0 and out == b"done\n"


def test_regular_file_stdin_backpressure_with_a_slow_child(tmp_path):
    size = sr.MAX_PENDING_INPUT * 3 + 11
    path = tmp_path / "in.bin"
    path.write_bytes(b"z" * size)
    with open(path, "rb") as fh:
        res, out = _run_pipe_from(fh.fileno(), cmd=("sh", "-c", "sleep 1; wc -c"))
    assert res.exit_code == 0 and int(out.split()[0]) == size


def test_direct_pump_buffer_stays_bounded(tmp_path):
    path = tmp_path / "in.bin"
    path.write_bytes(b"q" * (sr.MAX_PENDING_INPUT * 4))
    r, w = os.pipe()  # nobody reads r: every write soon fails with EAGAIN
    os.set_blocking(w, False)
    sel = sr.selectors.DefaultSelector()
    try:
        with open(path, "rb") as fh:
            pump = sr._InputPump(sel, fh.fileno(), None)
            assert pump.direct and not sel.get_map()
            for _ in range(200):
                assert pump.push(w)
                assert len(pump.pending) <= sr.MAX_PENDING_INPUT + sr.READ_CHUNK
            assert not pump.eof and pump.wait() > 0
    finally:
        sel.close()
        os.close(r)
        os.close(w)


def test_closed_stdin_fd_is_eof():
    fd = 4000  # far above anything the run opens, so it cannot be reused
    with pytest.raises(OSError):
        os.fstat(fd)
    res, out = _run_pipe_from(fd)  # fstat and register both fail: plain EOF
    assert res.exit_code == 0 and int(out.split()[0]) == 0


@pytest.mark.parametrize("content", [b"abc\n", b"abc", b"ab\ncd", b""])
def test_pty_regular_file_stdin_gets_eof(tmp_path, content):
    path = tmp_path / "in.txt"
    path.write_bytes(content)
    r, w = os.pipe()
    with open(path, "rb") as fh:
        try:
            res = sr.run_pty(
                ["wc", "-c"],
                dict(os.environ),
                [],
                in_fd=fh.fileno(),
                out_fd=w,
                timeout=10,
            )
        finally:
            os.close(w)
    out = _drain(r)
    os.close(r)
    assert res.exit_code == 0, "no ^D after the file (124 = timed out)"
    # the PTY echoes the input and the ^D(s); `wc`'s count is the last token
    assert out.split()[-1].endswith(str(len(content)).encode())


def test_pty_masks_crlf_output_and_multiline_values():
    multi = sf.sentinel() + "\n" + sf.sentinel()
    patterns = list(PATTERNS) + list(sr.variant_set(multi).patterns)
    r, w = os.pipe()
    env = {**os.environ, "X": VALUE, "M": multi}
    try:
        res = sr.run_pty(
            ["sh", "-c", 'printf "%s\\n" "$X"; printf "%s\\n" "$M"'],
            env,
            patterns,
            in_fd=None,
            out_fd=w,
        )
    finally:
        os.close(w)
    out = _drain(r)
    os.close(r)
    assert res.exit_code == 0
    assert out == b"***\r\n***\r\n"
    assert res.masked == 2


def test_terminal_attributes_restored_after_an_exception(monkeypatch):
    master, slave = os.openpty()
    try:
        before = termios.tcgetattr(slave)

        def boom(*_a, **_k):
            assert termios.tcgetattr(slave) != before  # raw while relaying
            raise RuntimeError("relay crashed")

        monkeypatch.setattr(sr, "_pty_loop", boom)
        with pytest.raises(RuntimeError):
            sr.run_pty(["sleep", "5"], dict(os.environ), [], in_fd=slave, out_fd=slave)
        assert termios.tcgetattr(slave) == before
    finally:
        os.close(master)
        os.close(slave)


# ---------------------------------------------------------------------------
# A10: hermetic E2E against the broker + fake secretkeeper
# ---------------------------------------------------------------------------


class World:  # pylint: disable=too-many-instance-attributes
    """Broker on a temp socket, fake secretkeeper, FixtureVault with sentinels."""

    def __init__(self, base: Path, sock_dir: Path) -> None:
        self.pw = sf.sentinel()
        self.token = sf.sentinel()
        self.seed = sf.totp_seed()
        self.home = base / "home"
        items = [
            sf.secret_item(
                "Item",
                self.pw,
                fields={"agent_secret_fields": "api_token", "api_token": self.token},
                totp=self.seed,
            )
        ]
        self.vault_path = sf.write_vault(base / "v.json", items)
        self.keeper = sf.FakeSecretkeeper(str(sock_dir / "k.sock"))
        self.broker = sf.make_broker(
            self.home,
            self.vault_path,
            allow_uid=os.getuid(),
            keeper_sock=self.keeper.path,
        )
        self.sock = str(sock_dir / "b.sock")
        self._serving = sf.serving(self.broker, self.sock, os.getuid())
        self._serving.__enter__()  # pylint: disable=unnecessary-dunder-call

    def env(self) -> dict[str, str]:
        return {sr.SOCKET_ENV: self.sock}

    def values(self) -> list[str]:
        return [self.pw, self.token, self.seed]

    def assert_clean(self, *blobs: bytes | str) -> None:
        for blob in blobs:
            text = blob.decode(errors="replace") if isinstance(blob, bytes) else blob
            for value in self.values():
                assert value not in text

    def audit(self) -> str:
        return (self.home / "audit.log").read_text()

    def close(self) -> None:
        self._serving.__exit__(None, None, None)
        self.keeper.close()


@pytest.fixture
def world(tmp_path):
    with sf.sockdir() as d:
        w = World(tmp_path, d)
        try:
            yield w
        finally:
            w.close()


def test_e2e_env_injection_masks_everything(world):
    script = 'echo "$X"; echo "$X" >&2; printf %s "$X" | base64; exit 3'
    proc = _run(["-v", "-e", "X=item", "--", "sh", "-c", script], world.env())
    assert proc.returncode == 3
    assert proc.stdout == b"***\n***\n"
    err = proc.stderr.decode()
    assert "***" in err and "✅ secret-run: X ← item:password" in err
    assert "⚠️ secret-run: masked 3 occurrence(s)" in err
    world.assert_clean(proc.stdout, proc.stderr, world.audit())
    recs = [json.loads(line) for line in world.audit().splitlines()]
    done = [r for r in recs if r["op"] == "secret_done"]
    assert done and done[-1]["exit"] == 3 and done[-1]["masked"] == 3
    assert any(r["op"] == "secret" and r["argv0"] == "sh" for r in recs)
    assert "loginbroker:item:password" in world.keeper.labels


def test_e2e_field_and_stdin(world):
    proc = _run(
        ["-e", "T=item:api_token", "--", "sh", "-c", 'echo "[$T]"'], world.env()
    )
    assert proc.returncode == 0 and proc.stdout == b"[***]\n"
    proc = _run(["-s", "item", "--", "cat"], world.env())
    assert proc.returncode == 0 and proc.stdout == b"***\n"
    world.assert_clean(proc.stdout, proc.stderr)


def test_e2e_regular_file_stdin_is_relayed_and_masked(world, tmp_path):
    path = tmp_path / "in.txt"
    path.write_bytes(b"line one\nline two\n")
    with open(path, "rb") as fh:
        proc = _run(
            ["-e", "X=item", "--", "sh", "-c", 'wc -c; echo "$X"'],
            world.env(),
            timeout=20,
            stdin=fh,
        )
    assert proc.returncode == 0
    assert proc.stdout.split() == [b"18", b"***"]
    with open(path, "rb") as fh:
        proc2 = _run(["-s", "item", "--", "cat"], world.env(), timeout=20, stdin=fh)
    assert proc2.returncode == 0 and proc2.stdout == b"***\n"
    world.assert_clean(proc.stdout, proc.stderr, proc2.stdout, proc2.stderr)
    world.assert_clean(world.audit())


def test_e2e_path_file_is_0600_and_removed_after_a_crash(world):
    script = '/usr/bin/stat -f %Lp "$F"; echo "$F"; cat "$F"; echo; kill -SEGV $$'
    proc = _run(["-p", "F=item", "--", "sh", "-c", script], world.env())
    assert proc.returncode == 128 + signal.SIGSEGV
    lines = proc.stdout.decode().splitlines()
    assert lines[0] == "600" and lines[2] == "***"
    path = Path(lines[1])
    assert not path.exists() and not path.parent.exists()
    world.assert_clean(proc.stdout, proc.stderr)


def test_e2e_timeout_totp_list_audit(world):
    start = time.monotonic()
    proc = _run(["-T", "1", "-e", "X=item", "--", "sleep", "10"], world.env())
    assert proc.returncode == 124 and time.monotonic() - start < 8
    assert "timed out" in proc.stderr.decode()
    code = _run(["-o", "item"], world.env())
    assert code.returncode == 0 and re.fullmatch(rb"\d{6}\n", code.stdout)
    listing = _run(["-l"], world.env())
    assert listing.returncode == 0
    assert listing.stdout.decode() == "✅ item: password, api_token  [TOTP (-o)]\n"
    audit = _run(["-A", "-N", "3"], world.env())
    assert audit.returncode == 0 and len(audit.stdout.splitlines()) == 3
    world.assert_clean(code.stderr, listing.stdout, audit.stdout, world.audit())


def test_e2e_broker_down_is_125(tmp_path):
    proc = _run(
        ["-e", "X=item", "--", "true"], {sr.SOCKET_ENV: str(tmp_path / "none.sock")}
    )
    assert proc.returncode == 125
    assert "❌ secret-run: login broker not reachable" in proc.stderr.decode()


def test_e2e_secretkeeper_down_is_125(world):
    world.keeper.close()
    proc = _run(["-e", "X=item", "--", "sh", "-c", 'echo "$X"'], world.env())
    assert proc.returncode == 125
    assert "leakcheck_unavailable" in proc.stderr.decode()
    assert proc.stdout == b""
    world.assert_clean(proc.stdout, proc.stderr, world.audit())
    world.keeper = sf.FakeSecretkeeper(world.keeper.path + "2")  # for close()


def test_e2e_printenv_refused_even_with_a_broker(world):
    proc = _run(["-e", "X=item", "--", "printenv"], world.env())
    assert proc.returncode == 125
    assert (
        '"op": "secret"' not in world.audit()
        if (world.home / "audit.log").exists()
        else True
    )


def _spawn_in_pty(args, env):
    master, slave = os.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))

    def ctty():
        os.setsid()
        fcntl.ioctl(0, termios.TIOCSCTTY, 0)

    proc = subprocess.Popen(  # pylint: disable=subprocess-popen-preexec-fn
        [sys.executable, str(CLIENT), *args],
        stdin=slave,
        stdout=slave,
        stderr=slave,
        env={**os.environ, **env},
        preexec_fn=ctty,
    )
    os.close(slave)
    return proc, master


def _read_until(master, pattern, timeout=10.0):
    buf = b""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        ready, _w, _x = select.select([master], [], [], 0.1)
        if ready:
            try:
                chunk = os.read(master, 4096)
            except OSError:
                break
            if not chunk:
                break
            buf += chunk
            if re.search(pattern, buf):
                return buf
    raise AssertionError(f"{pattern!r} not seen in {buf!r}")


def test_e2e_sigwinch_reaches_the_child(world):
    script = "stty size; sleep 2; stty size"
    proc, master = _spawn_in_pty(
        ["-t", "-e", "X=item", "--", "sh", "-c", script], world.env()
    )
    try:
        _read_until(master, rb"24 80")
        fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack("HHHH", 30, 100, 0, 0))
        out = _read_until(master, rb"30 100")
        assert proc.wait(15) == 0
        world.assert_clean(out)
    finally:
        os.close(master)
        if proc.poll() is None:
            proc.kill()


@pytest.mark.parametrize("sig,code", [(signal.SIGINT, 7), (signal.SIGTERM, 8)])
def test_e2e_signals_reach_the_child(world, sig, code):
    script = (
        'trap "echo got; exit 7" INT; trap "echo got; exit 8" TERM; '
        "echo ready; while :; do sleep 0.1; done"
    )
    proc = subprocess.Popen(
        [sys.executable, str(CLIENT), "-e", "X=item", "--", "sh", "-c", script],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.DEVNULL,
        env={**os.environ, **world.env()},
    )
    try:
        assert proc.stdout is not None
        assert proc.stdout.readline() == b"ready\n"
        proc.send_signal(sig)
        out, _err = proc.communicate(timeout=15)
    finally:
        if proc.poll() is None:
            proc.kill()
    assert proc.returncode == code
    assert out == b"got\n"


def _gone_within(pid, seconds):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        time.sleep(0.05)
    return False


@pytest.mark.parametrize(
    "script,code",
    [
        (  # the child itself ignores SIGTERM and holds the pipes
            'trap "" TERM; sleep 60 & echo $$ $!; echo ready; '
            "while :; do sleep 0.1; done",
            128 + signal.SIGKILL,
        ),
        (  # the child obeys; a detached grandchild ignores SIGTERM, pipes closed
            'trap "exit 5" TERM; '
            "sh -c 'trap \"\" TERM; exec sleep 60' </dev/null >/dev/null 2>&1 & "
            "echo $$ $!; echo ready; while :; do sleep 0.1; done",
            5,
        ),
    ],
    ids=["child-ignores-term", "grandchild-ignores-term"],
)
def test_e2e_sigterm_kills_a_term_ignoring_group_within_the_deadline(
    world, script, code
):
    proc = subprocess.Popen(
        [sys.executable, str(CLIENT), "-e", "X=item", "--", "sh", "-c", script],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.DEVNULL,
        env={**os.environ, **world.env()},
    )
    pids: list[int] = []
    try:
        assert proc.stdout is not None
        pids = [int(p) for p in proc.stdout.readline().split()]
        assert proc.stdout.readline() == b"ready\n"
        start = time.monotonic()
        proc.send_signal(signal.SIGTERM)
        proc.communicate(timeout=15)
        assert time.monotonic() - start < sr.SIGNAL_KILL_DEADLINE_S + 1.0
        for pid in pids:
            assert _gone_within(pid, 4.0 - (time.monotonic() - start)), pid
    finally:
        if proc.poll() is None:
            proc.kill()
        for pid in pids:
            with contextlib.suppress(ProcessLookupError):
                os.kill(pid, signal.SIGKILL)
    assert proc.returncode == code


# ---------------------------------------------------------------------------
# tp#991: -V capabilities, the agent_script gate in -l / -l -j, login items
# ---------------------------------------------------------------------------


def _gate_vault(world: World, gate: str | None) -> None:
    """Rewrite the world's vault: one flagged and one unflagged login item in
    the login collection, the legacy item in the secrets collection."""

    def login(name: str, site: str, flag: str | None) -> dict:
        fields = {
            "agent_site": site,
            "agent_fill_origins": f"https://login.{site}.example",
            "agent_cookie_hosts": f"{site}.example",
            "agent_logged_in_selector": "#me",
        }
        if flag is not None:
            fields["agent_script"] = flag
        item = sf.secret_item(name, world.pw, fields=fields, username="u")
        item["collectionIds"] = ["coll-login"]
        return item

    data = json.loads(world.vault_path.read_text())
    data["collection_id"] = "coll-login"
    data["logins"] = [login("Shop", "shop", "true"), login("Web", "web", None)]
    for item in data["secrets"]:
        item["collectionIds"] = ["coll-secrets"]
    data["secrets_collection_id"] = "coll-secrets"
    if gate is not None:
        data["secret_gate"] = gate
    world.vault_path.write_text(json.dumps(data))
    world.broker.invalidate()


def test_capabilities_reports_the_gate(world):
    proc = _run(["-V"], world.env())
    assert proc.returncode == 0
    caps = json.loads(proc.stdout)
    assert caps == {
        "v": 1,
        "gate": "collections",
        "features": ["capabilities", "agent-script-gate", "login-items", "gate-code"],
    }
    _gate_vault(world, "agent_script")
    assert json.loads(_run(["-V"], world.env()).stdout)["gate"] == "agent_script"


def test_capabilities_bad_gate_and_no_broker_exit_125(world, tmp_path):
    _gate_vault(world, "enforce")
    proc = _run(["-V"], world.env())
    assert proc.returncode == 125
    assert json.loads(proc.stdout)["gate"] == "bad_secret_gate"
    proc = _run(["-V"], {sr.SOCKET_ENV: str(tmp_path / "nope.sock")})
    assert proc.returncode == 125 and json.loads(proc.stdout)["gate"] == "unknown"


def test_list_json_carries_the_gate_keys(world):
    _gate_vault(world, "agent_script")
    proc = _run(["-l", "-j"], world.env())
    assert proc.returncode == 0
    rows = {r["id"]: r for r in map(json.loads, proc.stdout.splitlines())}
    assert rows["shop"]["kind"] == "login" and rows["shop"]["gate_code"] == "ok"
    assert rows["web"]["gate_code"] == "no_agent_script" and rows["web"]["refused"]
    assert rows["item"]["kind"] == "secret"
    assert rows["item"]["agent_script"] is False
    world.assert_clean(proc.stdout, proc.stderr)


def test_list_folds_browser_only_logins_into_one_line(world):
    _gate_vault(world, "agent_script")
    out = _run(["-l"], world.env()).stdout.decode()
    assert "✅ shop: password" in out
    assert "web" not in out
    assert "1 login item(s) not injectable: agent_script unset" in out
    assert "❌ item: refused" in out  # the legacy item lacks the flag


def test_a_flagged_login_item_is_injected_and_masked(world):
    _gate_vault(world, "agent_script")
    proc = _run(["-s", "shop", "--", "cat"], world.env())
    assert proc.returncode == 0 and proc.stdout == b"***\n"
    proc = _run(["-s", "web", "--", "cat"], world.env())
    assert proc.returncode == 125
    assert b"script read without agent_script" in proc.stderr
    world.assert_clean(proc.stdout, proc.stderr, world.audit())
