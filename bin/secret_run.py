#!/usr/bin/env python3
"""secret-run — run a command with vault secrets it can USE but you never SEE.

Asks the login broker (``secret`` op, peer uid checked) for the values, injects
them into a child it spawns (env var, 0600 temp file or stdin) and masks every
occurrence of a value — raw and encoded (base64, hex, percent, JSON, shell
quoting; see broker/variants.py) — in the child's stdout and stderr as ``***``.
This is output hygiene against accidents, not a security boundary: the child
holds the value, and so does anything that can read its memory or environment.

Every value is also registered with the secretkeeper by the broker, so the
out-of-session scanners catch it wherever it resurfaces later.

Process model: the child runs in its own session; stdin is a pipe fed from
secret-run's stdin (``-s``: the value + newline, then EOF); stdout/stderr are
pipes drained concurrently, one masker each. ``-t`` uses a pseudo-terminal
instead (window size and SIGWINCH passed through). SIGINT/SIGTERM/SIGHUP/
SIGQUIT are forwarded to the child's process group. A forwarded SIGINT/
SIGTERM/SIGHUP also arms a 3 s deadline: whatever of the group is still alive
then gets SIGKILL, and secret-run exits with the child's status (128+N when it
died of signal N) — so a runner's own TERM-then-KILL grace (5 s or more) never
leaves a child that ignores SIGTERM behind. When the child exits, output still
held open by a background grandchild is waited for <= 2 s, then the group gets
SIGTERM, 2 s later SIGKILL.

Residual risk: a direct SIGKILL of secret-run itself cannot be caught, so
nothing cleans up — the child's session keeps running (its stdout/stderr pipes
are gone, so it dies of SIGPIPE on its next write, or runs on if it is silent).
Callers stop secret-run with SIGTERM/SIGINT/SIGHUP and SIGKILL it only after
more than 3 s.

Exit codes: the child's; 128+N when it died of signal N; 124 timeout (-T);
125 secret-run's own failure (broker down, refused, rate limited, leak check
unavailable, bad usage); 126 cannot execute; 127 not found; 141 the reader of
secret-run's output went away (EPIPE).

Status lines go to stderr (✅ ❌ ⚠️); stdout belongs to the child. The broker
socket is /var/db/login-broker-run/broker.sock ($SECRET_RUN_SOCKET overrides).
"""

# too-many-lines: the broker client is deliberately ONE self-contained file (it
# is installed on its own as `secret-run`), like browser.py.
# pylint: disable=too-many-lines

from __future__ import annotations

import argparse
import contextlib
import fcntl
import json
import os
import re
import selectors
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import termios
import time
import tty
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from types import FrameType
from typing import Any, NoReturn

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# pylint: disable=wrong-import-position
from broker.masker import Masker  # noqa: E402
from broker.variants import variant_set  # noqa: E402

# pylint: enable=wrong-import-position

DEFAULT_SOCKET = "/var/db/login-broker-run/broker.sock"
SOCKET_ENV = "SECRET_RUN_SOCKET"
BROKER_TIMEOUT_S = 180.0
MAX_RESPONSE = 4 * 1024 * 1024
EXIT_TIMEOUT = 124
EXIT_OWN = 125
EXIT_NOEXEC = 126
EXIT_NOTFOUND = 127
EXIT_EPIPE = 141
EOF_GRACE_S = 2.0
TERM_GRACE_S = 2.0
TIMEOUT_TERM_GRACE_S = 5.0
KILL_GIVE_UP_S = 2.0
SIGNAL_KILL_DEADLINE_S = 3.0
TICK_S = 0.05
READ_CHUNK = 65536
MAX_PENDING_INPUT = 1024 * 1024
NAME_RE = re.compile(r"^[A-Z_][A-Z0-9_]*$")
ITEM_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
FIELD_RE = re.compile(r"^[A-Za-z0-9._ -]{1,64}$")
DENIED_NAMES = frozenset(
    {"PATH", "HOME", "SHELL", "IFS", "PS4", "BASH_ENV", "ENV", "NODE_OPTIONS"}
)
DENIED_PREFIXES = ("LD_", "DYLD_", "PYTHON")
SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ksh", "fish"})
FORWARDED_SIGNALS = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT)
# A forwarded one of these arms the SIGKILL deadline (SIGQUIT only forwards).
DEADLINE_SIGNALS = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)


class SecretRunError(Exception):
    """secret-run's own failure (exit 125 unless `code` says otherwise)."""

    def __init__(self, message: str, code: int = EXIT_OWN) -> None:
        super().__init__(message)
        self.code = code


def status(mark: str, text: str) -> None:
    """One status line on stderr."""
    print(f"{mark} secret-run: {text}", file=sys.stderr, flush=True)


# ---------------------------------------------------------------------------
# argument checks
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Spec:
    """One injection: kind env/path/stdin, NAME (None for stdin), item, field."""

    kind: str
    name: str | None
    item: str
    field: str

    @property
    def ref(self) -> str:
        """``item:field``."""
        return f"{self.item}:{self.field}"


def parse_ref(text: str) -> tuple[str, str]:
    """``ITEM[:FIELD]`` -> (item, field); FIELD defaults to ``password``."""
    item, _sep, fld = text.partition(":")
    fld = fld or "password"
    if not ITEM_RE.match(item):
        raise SecretRunError(f"invalid item id {item!r}")
    if not FIELD_RE.match(fld):
        raise SecretRunError(f"invalid field name {fld!r}")
    return item, fld


def check_name(name: str) -> None:
    """NAME must look like an env var and not steer the child's execution."""
    if not NAME_RE.match(name):
        raise SecretRunError(f"invalid NAME {name!r} (want ^[A-Z_][A-Z0-9_]*$)")
    if name in DENIED_NAMES or name.startswith(DENIED_PREFIXES):
        raise SecretRunError(f"refusing to set {name}: it changes how programs run")


def parse_spec(text: str, kind: str) -> Spec:
    """``NAME=ITEM[:FIELD]`` (env/path) or ``ITEM[:FIELD]`` (stdin)."""
    if kind == "stdin":
        item, fld = parse_ref(text)
        return Spec(kind, None, item, fld)
    name, sep, ref = text.partition("=")
    if not sep:
        raise SecretRunError(f"expected NAME=ITEM[:FIELD], got {text!r}")
    check_name(name)
    item, fld = parse_ref(ref)
    return Spec(kind, name, item, fld)


def _env_has_command(args: list[str]) -> bool:
    """Does an ``env`` argument list name a command to run?"""
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "--":
            return i + 1 < len(args)
        if arg in ("-S", "--split-string"):
            return True
        if arg in ("-u", "-C", "-P", "--unset", "--chdir"):
            i += 2
            continue
        if arg.startswith("-") or "=" in arg:
            i += 1
            continue
        return True
    return False


# One early return per environment-printing command form.
def env_dump_reason(cmd: list[str]) -> str | None:  # pylint: disable=too-many-return-statements
    """Why `cmd` would print the whole environment (None = it would not).
    Hygiene against the obvious accident, not a boundary."""
    if not cmd:
        return None
    base = os.path.basename(cmd[0])
    rest = cmd[1:]
    if base == "printenv":
        return "printenv"
    if base == "env" and not _env_has_command(rest):
        return "env without a command"
    if base == "set" and not rest:
        return "set"
    if base == "export" and (not rest or rest == ["-p"]):
        return "export -p"
    if base in ("declare", "typeset") and all(a.startswith("-") for a in rest):
        if not rest or any("p" in a or "x" in a for a in rest):
            return f"{base} -p/-x"
    if base == "compgen" and "-e" in rest:
        return "compgen -e"
    if base in SHELLS and "-c" in rest[:-1]:
        script = rest[rest.index("-c") + 1]
        if not re.search(r"[;&|`$()<>\n]", script):
            with contextlib.suppress(ValueError):
                return env_dump_reason(shlex.split(script))
    return None


# ---------------------------------------------------------------------------
# broker
# ---------------------------------------------------------------------------


def broker_socket() -> str:
    """$SECRET_RUN_SOCKET or the installed broker's socket."""
    return os.environ.get(SOCKET_ENV) or DEFAULT_SOCKET


def broker_request(op: str, timeout: float = BROKER_TIMEOUT_S, **kw: Any) -> dict:
    """One JSON request; SecretRunError when the broker does not answer."""
    path = broker_socket()
    buf = bytearray()
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect(path)
            sock.sendall(json.dumps({"op": op, **kw}).encode() + b"\n")
            while not buf.endswith(b"\n"):
                chunk = sock.recv(READ_CHUNK)
                if not chunk:
                    break
                buf += chunk
                if len(buf) > MAX_RESPONSE:
                    raise SecretRunError("login broker reply too large")
    except OSError as exc:
        raise SecretRunError(
            f"login broker not reachable at {path} ({exc.strerror or exc})"
        ) from None
    try:
        resp = json.loads(bytes(buf))
    except ValueError:
        raise SecretRunError("login broker sent no JSON") from None
    if not isinstance(resp, dict):
        raise SecretRunError("login broker sent no JSON object")
    return resp


def broker_ok(op: str, **kw: Any) -> dict:
    """``broker_request`` that turns an error answer into SecretRunError."""
    resp = broker_request(op, **kw)
    if resp.get("ok") is not True:
        detail = resp.get("detail") or ""
        raise SecretRunError(f"{resp.get('error') or 'error'}: {detail}".rstrip(": "))
    return resp


# ---------------------------------------------------------------------------
# process model
# ---------------------------------------------------------------------------


@dataclass
class RunResult:
    """Exit code (secret-run semantics) and masked occurrences."""

    exit_code: int
    masked: int


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        try:
            n = os.write(fd, view)
        except BlockingIOError:
            selectors.DefaultSelector().select(TICK_S)
            continue
        view = view[n:]


class _Group:  # pylint: disable=too-many-instance-attributes  # kill-phase clock
    """The child's process group: exit wait, timeout, TERM -> KILL phases."""

    def __init__(self, proc: subprocess.Popen[bytes], timeout: float | None) -> None:
        self.proc = proc
        self.pgid = proc.pid
        self.timeout = timeout
        self.start = time.monotonic()
        self.exited_at: float | None = None
        self.kill_at: float | None = None
        self.killed_at: float | None = None
        self.timed_out = False
        self.epipe = False
        self.signal_deadline: float | None = None

    def signal(self, sig: int) -> None:
        """Send `sig` to the whole group (gone = nothing to do)."""
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.killpg(self.pgid, sig)

    def terminate(self, grace: float) -> None:
        """SIGTERM now, SIGKILL after `grace` (once)."""
        if self.kill_at is None:
            self.signal(signal.SIGTERM)
            self.kill_at = time.monotonic() + grace

    def arm_signal_deadline(self, grace: float = SIGNAL_KILL_DEADLINE_S) -> None:
        """A termination signal was forwarded: SIGKILL the group after `grace`
        (sooner if a kill is already due earlier; never re-armed later)."""
        if self.signal_deadline is not None:
            return
        self.signal_deadline = time.monotonic() + grace
        if self.killed_at is None and (
            self.kill_at is None or self.signal_deadline < self.kill_at
        ):
            self.kill_at = self.signal_deadline

    def group_alive(self) -> bool:
        """True while any member of the child's process group exists."""
        try:
            os.killpg(self.pgid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        return True

    def _kill_rest_after_signal(self) -> None:
        """After a forwarded termination signal, members that outlived the
        child (detached grandchildren in the group) get SIGKILL at the deadline."""
        if self.signal_deadline is None:
            return
        while self.group_alive() and time.monotonic() < self.signal_deadline:
            time.sleep(TICK_S)
        if self.group_alive():
            self.signal(signal.SIGKILL)

    def child_exited(self) -> bool:
        """True once the direct child has exited (reaps it)."""
        return self.proc.poll() is not None

    def tick(self, streams_open: bool) -> None:
        """Advance the phases; call every loop iteration."""
        now = time.monotonic()
        if self.exited_at is None and self.child_exited():
            self.exited_at = now
        if (
            self.timeout is not None
            and not self.timed_out
            and self.exited_at is None
            and now - self.start >= self.timeout
        ):
            self.timed_out = True
            self.terminate(TIMEOUT_TERM_GRACE_S)
        if self.exited_at is not None and streams_open:
            if now - self.exited_at >= EOF_GRACE_S:
                self.terminate(TERM_GRACE_S)
        if self.kill_at is not None and self.killed_at is None and now >= self.kill_at:
            self.signal(signal.SIGKILL)
            self.killed_at = now

    def give_up(self) -> bool:
        """After SIGKILL, stop waiting for EOF (an escaped holder of the pipe)."""
        return (
            self.killed_at is not None
            and time.monotonic() - self.killed_at > KILL_GIVE_UP_S
        )

    def finish(self) -> int:
        """Reap the child and map its status to secret-run's exit code."""
        if self.proc.poll() is None:
            self.signal(signal.SIGKILL)
        rc = self.proc.wait()
        self._kill_rest_after_signal()
        if self.epipe:
            return EXIT_EPIPE
        if self.timed_out:
            return EXIT_TIMEOUT
        return 128 - rc if rc < 0 else rc


@contextlib.contextmanager
def _forwarding(
    group: _Group, enabled: bool, on_winch: Callable[[], None] | None = None
) -> Iterator[None]:
    """Forward SIGINT/SIGTERM/SIGHUP/SIGQUIT to the group (and SIGWINCH to
    `on_winch`) while the child runs; previous handlers restored after.
    SIGINT/SIGTERM/SIGHUP also arm the group's SIGKILL deadline."""
    if not enabled:
        yield
        return

    def forward(sig: int, _frame: FrameType | None) -> None:
        group.signal(sig)
        if sig in DEADLINE_SIGNALS:
            group.arm_signal_deadline()

    saved: dict[int, Any] = {}
    for sig in FORWARDED_SIGNALS:
        saved[sig] = signal.signal(sig, forward)
    if on_winch is not None:
        saved[signal.SIGWINCH] = signal.signal(
            signal.SIGWINCH, lambda _s, _f: on_winch()
        )
    try:
        yield
    finally:
        for sig, handler in saved.items():
            signal.signal(sig, handler)


def _spawn_error(exc: OSError) -> RunResult:
    if isinstance(exc, FileNotFoundError):
        status("❌", f"command not found: {exc.filename or ''}".rstrip())
        return RunResult(EXIT_NOTFOUND, 0)
    status("❌", f"cannot execute: {exc.strerror or exc}")
    return RunResult(EXIT_NOEXEC, 0)


class _InputPump:
    """Bytes for the child's stdin: preset data, or relayed from `in_fd`."""

    def __init__(
        self, sel: selectors.BaseSelector, in_fd: int | None, data: bytes | None
    ) -> None:
        self.sel = sel
        self.in_fd = in_fd
        self.pending = bytearray(data or b"")
        self.eof = data is not None or in_fd is None
        self.registered = False
        if not self.eof:
            self._register()

    def _register(self) -> None:
        assert self.in_fd is not None
        try:
            self.sel.register(self.in_fd, selectors.EVENT_READ, "agent")
            self.registered = True
        except (ValueError, OSError):
            self.eof = True  # not pollable (closed): the child gets EOF

    def stop(self) -> None:
        """No more input (the child exited)."""
        if self.registered and self.in_fd is not None:
            self.sel.unregister(self.in_fd)
            self.registered = False
        self.eof = True
        self.pending.clear()

    def on_readable(self, eof_byte: bytes = b"") -> None:
        """Read what `in_fd` has; at EOF optionally queue `eof_byte` (PTY ^D)."""
        assert self.in_fd is not None
        try:
            data = os.read(self.in_fd, READ_CHUNK)
        except BlockingIOError:
            return
        except OSError:
            data = b""
        if data:
            self.pending += data
            if len(self.pending) > MAX_PENDING_INPUT and self.registered:
                self.sel.unregister(self.in_fd)
                self.registered = False
            return
        self.pending += eof_byte
        if self.registered:
            self.sel.unregister(self.in_fd)
            self.registered = False
        self.eof = True

    def push(self, fd: int) -> bool:
        """Write pending bytes to `fd` (non-blocking); False when `fd` is gone."""
        if self.pending:
            try:
                n = os.write(fd, self.pending)
            except BlockingIOError:
                return True
            except OSError:
                self.stop()
                return False
            del self.pending[:n]
        if (
            not self.registered
            and not self.eof
            and len(self.pending) < MAX_PENDING_INPUT
        ):
            self._register()
        return True


# The pipe loop is one state machine; splitting it scatters its invariants.
# pylint: disable-next=too-many-locals,too-many-branches,too-many-statements,too-many-arguments
def run_pipe(
    cmd: list[str],
    env: dict[str, str],
    patterns: list[bytes],
    *,
    stdin_data: bytes | None = None,
    timeout: float | None = None,
    in_fd: int | None = 0,
    out_fd: int = 1,
    err_fd: int = 2,
    forward_signals: bool = False,
) -> RunResult:
    """Default mode: pipes for stdin/stdout/stderr, one masker per stream."""
    try:
        proc = subprocess.Popen(  # pylint: disable=consider-using-with
            cmd,
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
            close_fds=True,
        )
    except OSError as exc:
        return _spawn_error(exc)
    assert proc.stdin and proc.stdout and proc.stderr
    group = _Group(proc, timeout)
    sel = selectors.DefaultSelector()
    maskers = {
        proc.stdout.fileno(): (Masker(patterns), out_fd),
        proc.stderr.fileno(): (Masker(patterns), err_fd),
    }
    for fd in maskers:
        os.set_blocking(fd, False)
        sel.register(fd, selectors.EVENT_READ, "child")
    stdin_fd = proc.stdin.fileno()
    os.set_blocking(stdin_fd, False)
    child_in: int | None = stdin_fd
    pump = _InputPump(sel, in_fd, stdin_data)
    open_streams = len(maskers)
    try:
        with _forwarding(group, forward_signals):
            while open_streams and not group.give_up():
                wait = TICK_S / 10 if pump.pending else TICK_S
                for key, _ev in sel.select(wait):
                    if key.data == "agent":
                        pump.on_readable()
                        continue
                    masker, dest = maskers[key.fd]
                    try:
                        data = os.read(key.fd, READ_CHUNK)
                    except BlockingIOError:
                        continue
                    except OSError:
                        data = b""
                    if data:
                        out = masker.feed(data)
                    else:
                        out = masker.flush()
                        sel.unregister(key.fd)
                        open_streams -= 1
                    if out and not group.epipe:
                        try:
                            _write_all(dest, out)
                        except (BrokenPipeError, OSError):
                            group.epipe = True
                            group.terminate(TERM_GRACE_S)
                if child_in is not None:
                    if group.child_exited():
                        pump.stop()
                    elif not pump.push(child_in):
                        pump.stop()
                    if pump.eof and not pump.pending:
                        proc.stdin.close()
                        child_in = None
                group.tick(open_streams > 0)
            for fd, (masker, dest) in maskers.items():  # given up: release the rest
                if fd in sel.get_map():
                    out = masker.flush()
                    if out and not group.epipe:
                        with contextlib.suppress(OSError):
                            _write_all(dest, out)
    finally:
        pump.stop()
        sel.close()
        for stream in (proc.stdin, proc.stdout, proc.stderr):
            with contextlib.suppress(OSError):
                stream.close()
        code = group.finish()
    masked = sum(m.masked for m, _d in maskers.values())
    return RunResult(code, masked)


def _winsize(fd: int) -> bytes | None:
    try:
        return fcntl.ioctl(fd, termios.TIOCGWINSZ, b"\0" * 8)
    except OSError:
        return None


def _copy_winsize(src_fds: tuple[int | None, ...], dest: int) -> None:
    for fd in src_fds:
        if fd is not None and os.isatty(fd):
            size = _winsize(fd)
            if size is not None:
                with contextlib.suppress(OSError):
                    fcntl.ioctl(dest, termios.TIOCSWINSZ, size)
                return


@contextlib.contextmanager
def _raw_terminal(fd: int | None) -> Iterator[None]:
    """Our own terminal in raw mode while relaying (only when it IS one);
    the attributes are restored whatever happens."""
    if fd is None or not os.isatty(fd):
        yield
        return
    saved = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        yield
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, saved)


def _set_ctty() -> None:  # runs in the child between fork and exec
    fcntl.ioctl(0, termios.TIOCSCTTY, 0)


# One relay state machine, like run_pipe's loop.
# pylint: disable-next=too-many-arguments,too-many-positional-arguments,too-many-branches
def _pty_loop(
    master: int,
    group: _Group,
    masker: Masker,
    pump: _InputPump,
    sel: selectors.BaseSelector,
    out_fd: int,
) -> None:
    """Relay: agent -> child raw, child -> agent masked, until the PTY closes."""
    open_stream = True
    while open_stream and not group.give_up():
        wait = TICK_S / 10 if pump.pending else TICK_S
        for key, _ev in sel.select(wait):
            if key.data == "agent":
                pump.on_readable(eof_byte=b"\x04")
                continue
            try:
                data = os.read(master, READ_CHUNK)
            except BlockingIOError:
                continue
            except OSError:  # EIO: every slave fd is closed
                data = b""
            if data:
                out = masker.feed(data)
            else:
                out = masker.flush()
                sel.unregister(master)
                open_stream = False
            if out and not group.epipe:
                try:
                    _write_all(out_fd, out)
                except (BrokenPipeError, OSError):
                    group.epipe = True
                    group.terminate(TERM_GRACE_S)
        if group.child_exited():
            pump.stop()
        else:
            pump.push(master)
        group.tick(open_stream)
    if open_stream:
        out = masker.flush()
        if out and not group.epipe:
            with contextlib.suppress(OSError):
                _write_all(out_fd, out)


# pylint: disable-next=too-many-arguments,too-many-locals
def run_pty(
    cmd: list[str],
    env: dict[str, str],
    patterns: list[bytes],
    *,
    stdin_data: bytes | None = None,
    timeout: float | None = None,
    in_fd: int | None = 0,
    out_fd: int = 1,
    forward_signals: bool = False,
) -> RunResult:
    """``-t``: the child on a pseudo-terminal; its output masked in PTY mode."""
    master, slave = os.openpty()
    try:
        _copy_winsize((in_fd, out_fd), slave)
        if stdin_data is not None:  # the injected value must not be echoed
            attrs = termios.tcgetattr(slave)
            attrs[3] &= ~termios.ECHO
            termios.tcsetattr(slave, termios.TCSANOW, attrs)
        try:
            # pylint: disable-next=consider-using-with,subprocess-popen-preexec-fn
            proc = subprocess.Popen(
                cmd,
                env=env,
                stdin=slave,
                stdout=slave,
                stderr=slave,
                start_new_session=True,
                preexec_fn=_set_ctty,
                close_fds=True,
            )
        except OSError as exc:
            return _spawn_error(exc)
    finally:
        os.close(slave)
    group = _Group(proc, timeout)
    masker = Masker(patterns, pty=True)
    sel = selectors.DefaultSelector()
    os.set_blocking(master, False)
    sel.register(master, selectors.EVENT_READ, "child")
    data = stdin_data + b"\x04" if stdin_data is not None else None
    pump = _InputPump(sel, in_fd, data)

    def on_winch() -> None:
        _copy_winsize((in_fd, out_fd), master)

    try:
        with _raw_terminal(in_fd), _forwarding(group, forward_signals, on_winch):
            _pty_loop(master, group, masker, pump, sel, out_fd)
    finally:
        pump.stop()
        sel.close()
        code = group.finish()
        with contextlib.suppress(OSError):
            os.close(master)
    return RunResult(code, masked=masker.masked)


# ---------------------------------------------------------------------------
# commands
# ---------------------------------------------------------------------------


class _Parser(argparse.ArgumentParser):
    """Usage errors are secret-run's own failure: exit 125, not 2."""

    def error(self, message: str) -> NoReturn:
        self.print_usage(sys.stderr)
        status("❌", message)
        sys.exit(EXIT_OWN)


def build_parser() -> argparse.ArgumentParser:
    """The CLI (every option has a short and a long form)."""
    p = _Parser(
        prog="secret-run",
        description=(__doc__ or "").split("\n\n", 1)[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        usage=(
            "secret-run -e NAME=ITEM[:FIELD] [-e ...] [-p NAME=ITEM[:FIELD]] "
            "[-s ITEM[:FIELD]] [-t] [-T SEC] [-v] -- CMD [ARG...]\n"
            "       secret-run -o ITEM\n"
            "       secret-run -l\n"
            "       secret-run -A [-N N]"
        ),
        epilog=(
            "FIELD defaults to `password`; `secret-run -l` lists the items and "
            "exposed fields.\n\n"
            "Exit codes: the child's; 128+N on signal N; 124 timeout; 125 "
            "secret-run failed\n(broker down, refused, rate limited, leak check "
            "unavailable, bad usage);\n126 cannot execute; 127 not found; 141 "
            "EPIPE.\n\n"
            "Examples:\n"
            "  secret-run -e GH_TOKEN=github:api_token -- gh api user\n"
            "  secret-run -p KUBECONFIG=k8s-dev:kubeconfig -- kubectl get pods\n"
            "  secret-run -s vpn -- openconnect --passwd-on-stdin vpn.example.org\n"
            "  secret-run -t -e PW=db -- psql -h db.example.org\n"
            "  secret-run -T 60 -v -e T=svc -- ./deploy.sh\n"
            "  secret-run -o github        # the current TOTP code only\n"
            "  secret-run -l               # what can be injected\n"
            "  secret-run -A -N 20         # the broker's last 20 audit lines\n"
        ),
    )
    p.add_argument(
        "-e",
        "--env",
        action="append",
        default=[],
        metavar="NAME=ITEM[:FIELD]",
        help="value into env var NAME (repeatable)",
    )
    p.add_argument(
        "-p",
        "--path",
        action="append",
        default=[],
        metavar="NAME=ITEM[:FIELD]",
        help="value into a 0600 temp file, NAME = its path; removed afterwards "
        "(repeatable)",
    )
    p.add_argument(
        "-s",
        "--stdin",
        metavar="ITEM[:FIELD]",
        help="value + newline to the child's stdin, then EOF",
    )
    p.add_argument(
        "-t", "--tty", action="store_true", help="run the child on a pseudo-terminal"
    )
    p.add_argument(
        "-T",
        "--timeout",
        type=float,
        metavar="SEC",
        help="SIGTERM the child after SEC seconds (SIGKILL 5 s later); exit 124",
    )
    p.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="one ✅ per injected NAME, with pattern / dropped-variant counts",
    )
    p.add_argument(
        "-o", "--totp", metavar="ITEM", help="print ITEM's current TOTP code only"
    )
    p.add_argument(
        "-l",
        "--list",
        action="store_true",
        help="list injectable items and their exposed field names",
    )
    p.add_argument(
        "-A", "--audit", action="store_true", help="print the broker's last audit lines"
    )
    p.add_argument(
        "-N",
        "--lines",
        type=int,
        default=50,
        metavar="N",
        help="with -A: how many lines (default 50, max 500)",
    )
    return p


def cmd_totp(item: str) -> int:
    """``-o``: the code on stdout, nothing else."""
    if not ITEM_RE.match(item):
        raise SecretRunError(f"invalid item id {item!r}")
    resp = broker_ok("totp", item=item)
    code = str(resp.get("code") or "")
    if not re.fullmatch(r"\d{6,10}", code):
        raise SecretRunError("the broker sent no TOTP code")
    print(code)
    return 0


def cmd_list() -> int:
    """``-l``: ids and field NAMES (never values)."""
    resp = broker_ok("secrets")
    rows = resp.get("secrets") or []
    if not rows:
        status("⚠️", "the secrets collection holds no items")
        return 0
    for row in rows:
        if not isinstance(row, dict):
            continue
        sid = str(row.get("id") or "")
        if row.get("refused"):
            print(f"❌ {sid}: refused — {row.get('reason') or ''}")
            continue
        fields = ", ".join(str(f) for f in row.get("fields") or []) or "-"
        extras = []
        if row.get("has_totp"):
            extras.append("TOTP (-o)")
        if row.get("short"):
            extras.append("short value: masked raw-only")
        tail = f"  [{'; '.join(extras)}]" if extras else ""
        print(f"✅ {sid}: {fields}{tail}")
    return 0


def cmd_audit(lines: int) -> int:
    """``-A``: the broker's audit tail, one JSON object per line."""
    resp = broker_ok("audit", n=max(1, lines))
    for rec in resp.get("lines") or []:
        print(json.dumps(rec, sort_keys=True))
    return 0


def _collect_specs(args: argparse.Namespace) -> list[Spec]:
    specs = [parse_spec(t, "env") for t in args.env]
    specs += [parse_spec(t, "path") for t in args.path]
    if args.stdin:
        specs.append(parse_spec(args.stdin, "stdin"))
    names = [s.name for s in specs if s.name]
    dup = sorted({n for n in names if names.count(n) > 1})
    if dup:
        raise SecretRunError(f"NAME given twice: {', '.join(dup)}")
    return specs


def _patterns(
    specs: list[Spec], values: list[str], shorts: list[bool], verbose: bool
) -> list[bytes]:
    patterns: list[bytes] = []
    for spec, value, short in zip(specs, values, shorts):
        vs = variant_set(value, raw_only=short)
        patterns.extend(vs.patterns)
        if short:
            status("⚠️", f"{spec.ref} is a short value: masked raw-only")
        if verbose:
            target = spec.name or "stdin"
            dropped = f", {vs.dropped} variant(s) dropped" if vs.dropped else ""
            status(
                "✅", f"{target} ← {spec.ref} ({len(vs.patterns)} pattern(s){dropped})"
            )
    return patterns


def _fetch(specs: list[Spec], argv0: str) -> tuple[list[str], list[bool], str]:
    """Values (one per spec), short flags and the run nonce."""
    pairs = list(dict.fromkeys((s.item, s.field) for s in specs))
    resp = broker_ok(
        "secret",
        items=[{"item": i, "field": f} for i, f in pairs],
        env=[s.name for s in specs if s.name],
        argv0=os.path.basename(argv0),
    )
    values = resp.get("values")
    nonce = resp.get("nonce")
    if not isinstance(values, list) or len(values) != len(pairs):
        raise SecretRunError("the broker sent a malformed answer")
    if not all(isinstance(v, str) and v for v in values) or not isinstance(nonce, str):
        raise SecretRunError("the broker sent a malformed answer")
    short_raw = resp.get("short_values")
    shorts_by_pair = (
        [bool(x) for x in short_raw]
        if isinstance(short_raw, list) and len(short_raw) == len(pairs)
        else [False] * len(pairs)
    )
    by_pair = dict(zip(pairs, zip(values, shorts_by_pair)))
    out_values = [by_pair[(s.item, s.field)][0] for s in specs]
    out_shorts = [by_pair[(s.item, s.field)][1] for s in specs]
    return out_values, out_shorts, nonce


def _child_env(specs: list[Spec], values: list[str], tmpdir: str | None) -> dict:
    env = dict(os.environ)
    for spec, value in zip(specs, values):
        if spec.kind == "env" and spec.name:
            env[spec.name] = value
        elif spec.kind == "path" and spec.name and tmpdir:
            path = os.path.join(tmpdir, spec.name)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                _write_all(fd, value.encode("utf-8", "surrogateescape"))
            finally:
                os.close(fd)
            env[spec.name] = path
    return env


def cmd_run(args: argparse.Namespace, cmd: list[str]) -> int:
    """Inject, run, mask, report."""
    if not cmd:
        raise SecretRunError("no command: put it after `--`")
    specs = _collect_specs(args)
    if not specs:
        raise SecretRunError("nothing to inject: give -e, -p or -s")
    reason = env_dump_reason(cmd)
    if reason:
        raise SecretRunError(
            f"refusing `{reason}`: it would print the environment (all injected values)"
        )
    if args.timeout is not None and args.timeout <= 0:
        raise SecretRunError("-T needs a positive number of seconds")
    values, shorts, nonce = _fetch(specs, cmd[0])
    patterns = _patterns(specs, values, shorts, args.verbose)
    stdin_data = None
    for spec, value in zip(specs, values):
        if spec.kind == "stdin":
            stdin_data = value.encode("utf-8", "surrogateescape") + b"\n"
    tmpdir = (
        tempfile.mkdtemp(prefix="secret-run-")
        if any(s.kind == "path" for s in specs)
        else None
    )
    try:
        env = _child_env(specs, values, tmpdir)
        runner = run_pty if args.tty else run_pipe
        result = runner(
            cmd,
            env,
            patterns,
            stdin_data=stdin_data,
            timeout=args.timeout,
            forward_signals=True,
        )
    finally:
        if tmpdir:
            shutil.rmtree(tmpdir, ignore_errors=True)
    try:
        broker_ok(
            "secret_done", nonce=nonce, exit=result.exit_code, masked=result.masked
        )
    except SecretRunError as exc:
        status("⚠️", f"could not close the run with the broker ({exc})")
    if result.masked:
        status(
            "⚠️",
            f"masked {result.masked} occurrence(s) — the command printed an "
            "injected value",
        )
    if result.exit_code == EXIT_TIMEOUT and args.timeout is not None:
        status("❌", f"timed out after {args.timeout:g} s")
    return result.exit_code


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    argv = list(sys.argv[1:] if argv is None else argv)
    cmd: list[str] = []
    if "--" in argv:
        cut = argv.index("--")
        argv, cmd = argv[:cut], argv[cut + 1 :]
    parser = build_parser()
    args = parser.parse_args(argv)
    modes = [bool(args.totp), args.list, args.audit]
    run_mode = bool(cmd or args.env or args.path or args.stdin)
    if sum(modes) + run_mode > 1:
        parser.error("-o, -l, -A and running a command are mutually exclusive")
    try:
        if args.totp:
            return cmd_totp(args.totp)
        if args.list:
            return cmd_list()
        if args.audit:
            return cmd_audit(args.lines)
        return cmd_run(args, cmd)
    except SecretRunError as exc:
        status("❌", str(exc))
        return exc.code


if __name__ == "__main__":
    sys.exit(main())
