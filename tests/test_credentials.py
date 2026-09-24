#!/usr/bin/env python3
"""Keychain / 1Password credential access and the CSCS Keycloak login (browser.py).

Nothing here touches a real keychain, `op`, network or browser: `subprocess.run`
and ``subprocess.Popen`` are replaced by recorders, and pages are tiny
stand-ins. What is pinned down: secrets never reach argv or stdout on the READ
path, every ``op`` call has a timeout while ``security`` never has one and is
never killed (tp#504), a failing tool degrades to ``None``/``False`` (never a
crash, never a false success), and the Keycloak form flow fills the OTP
exactly once.

Run: python3 -m pytest tests/ -q     (from the repo root)
"""

from __future__ import annotations

# Tests reach into browser.py's private helpers on purpose (it is a script, not
# a package, so there is no public API), and build throwaway stub classes.
# pylint: disable=protected-access,import-outside-toplevel,too-few-public-methods
# pylint: disable=missing-function-docstring,missing-class-docstring,import-error
# pylint: disable=unused-argument,redefined-outer-name  # pytest fixtures
# pylint: disable=too-many-lines  # one module per credential surface
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pyotp
import pytest
from conftest import FakeSecurityPopen, _security_g, security_op

_BROWSER_PY = Path(__file__).resolve().parent.parent / "bin" / "browser.py"


def _load_browser_module():
    """Import bin/browser.py as a module (it has no module-level playwright import)."""
    spec = importlib.util.spec_from_file_location("browser_under_test", _BROWSER_PY)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["browser_under_test"] = mod
    spec.loader.exec_module(mod)
    return mod


browser = _load_browser_module()

SEED = "JBSWY3DPEHPK3PXP"


class _Res:
    def __init__(self, returncode: int = 0, stdout: str = "", stderr: str = ""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class _Run:
    """Records every subprocess.run call; answers from a queue or a callable."""

    def __init__(self, *answers):
        self.calls: list[tuple[list[str], dict]] = []
        self._answers = list(answers)

    def __call__(self, argv, **kwargs):
        self.calls.append((list(argv), kwargs))
        ans = self._answers.pop(0) if len(self._answers) > 1 else self._answers[0]
        if isinstance(ans, BaseException):
            raise ans
        return ans


@pytest.fixture
def run(monkeypatch):
    def install(*answers):
        rec = _Run(*answers)
        monkeypatch.setattr(browser.subprocess, "run", rec)
        return rec

    monkeypatch.setattr(browser, "_kc_account", lambda: "tester")
    return install


# --- keychain ------------------------------------------------------------------

NOT_STARTED = "not_started"  # the fake Popen raises OSError: nothing ran
UNKNOWN = (-9, "", "")  # the child died by a signal: effect unknown


class _Sec:
    """``security`` via ``_security_run``: answers from a queue, never runs it.

    ``default-keychain`` is answered with *keychain* (not from the queue).
    Queue entries: ``(rc, stdout, stderr)``, ``NOT_STARTED``, or an exception
    to raise from ``communicate``; the last entry repeats.
    """

    def __init__(self, keychain: str, answers):
        self.keychain = keychain
        self._answers = list(answers)
        self._next = None
        self.popen = FakeSecurityPopen(self._handle, not_started=self._not_started)

    def _pop(self):
        return self._answers.pop(0) if len(self._answers) > 1 else self._answers[0]

    def _not_started(self, argv) -> bool:
        if security_op(argv) == "default":
            return False
        self._next = self._pop()
        return self._next == NOT_STARTED

    def _handle(self, argv, _data):
        if security_op(argv) == "default":
            return 0, f'    "{self.keychain}"\n', ""
        ans, self._next = self._next, None
        if isinstance(ans, BaseException):
            raise ans
        return ans

    @property
    def calls(self) -> list[dict]:
        """Every started call except the target lookup."""
        return [c for c in self.popen.calls if security_op(c["argv"]) != "default"]


@pytest.fixture
def keychain_path(tmp_path) -> str:
    path = tmp_path / "login.keychain-db"
    path.write_bytes(b"")
    return str(path)


@pytest.fixture
def sec(monkeypatch, keychain_path):
    def install(*answers):
        rec = _Sec(keychain_path, answers or [(0, "", "")])
        monkeypatch.setattr(browser.subprocess, "Popen", rec.popen)
        return rec

    monkeypatch.setattr(browser, "_kc_account", lambda: "tester")
    return install


OK = (0, "", "")
ABSENT = (44, "", "The specified item could not be found in the keychain.")


def _found(value: str):
    return (0, "", _security_g(value))


# --- _security_run: never timed out, never killed, Ctrl-C deferred (tp#504) ---


@pytest.mark.parametrize(
    "argv, data, state, rc, out",
    [
        (["/bin/sh", "-c", "exit 3"], None, "done", 3, b""),
        (["/bin/cat"], b"stdin bytes\n", "done", 0, b"stdin bytes\n"),
        (["/bin/sh", "-c", "kill -9 $$"], None, "unknown", -9, b""),
        (["/nonexistent/security-tp504"], None, "not_started", None, b""),
    ],
    ids=["exit-code", "stdin", "signal", "not-started"],
)
def test_security_run_states_with_real_processes(argv, data, state, rc, out):
    r = browser._security_run(argv, data=data)
    assert (r.state, r.rc, r.stdout) == (state, rc, out)


def test_security_run_starts_a_new_session_and_never_times_out(monkeypatch):
    popen = FakeSecurityPopen(lambda argv, data: (0, "out", "err"))
    monkeypatch.setattr(browser.subprocess, "Popen", popen)
    r = browser._security_run(["security", "-i"], data=b"line\n")
    assert (r.state, r.rc, r.stdout, r.stderr) == ("done", 0, b"out", b"err")
    assert len(popen.calls) == 1
    call = popen.calls[0]
    kwargs = call["kwargs"]
    assert kwargs["start_new_session"] is True and "timeout" not in kwargs
    assert kwargs["stdin"] == subprocess.PIPE and call["input"] == b"line\n"
    browser._security_run(["security", "default-keychain", "-d", "user"])
    assert popen.calls[1]["kwargs"]["stdin"] == subprocess.DEVNULL


@pytest.mark.parametrize("rc, state", [(0, "done"), (44, "done"), (-2, "unknown")])
def test_security_run_defers_ctrl_c_until_the_child_exits(monkeypatch, rc, state):
    popen = FakeSecurityPopen(lambda argv, data: (rc, "o", "e"), interrupt=bool)
    monkeypatch.setattr(browser.subprocess, "Popen", popen)
    with pytest.raises(browser.SecurityInterrupted) as exc:
        browser._security_run(["security", "-i"], data=b"line\n")
    assert isinstance(exc.value, KeyboardInterrupt)
    assert popen.interrupts == 1  # the retry did not resend input (fake asserts)
    result = vars(exc.value)["result"]  # the finished call's outcome
    assert (result.state, result.rc, result.stdout) == (state, rc, b"o")


def test_security_run_reaps_after_a_broken_communicate(monkeypatch):
    def broken(argv, data):
        raise MemoryError

    popen = FakeSecurityPopen(broken)
    monkeypatch.setattr(browser.subprocess, "Popen", popen)
    assert browser._security_run(["security", "-i"], data=b"x\n").state == "unknown"


def test_keychain_code_never_times_out_or_signals_security():
    import inspect

    for name in (
        "_security_run",
        "_kc_target_keychain",
        "_keychain_get",
        "_kc_delete",
        "_keychain_write",
        "_keychain_set_all",
        "_kc_cleanup",
        "_keychain_delete",
    ):
        src = inspect.getsource(getattr(browser, name))
        code = "\n".join(
            line for line in src.splitlines() if not line.lstrip().startswith("#")
        )
        body = code.rsplit('"""', maxsplit=1)[-1]  # past the docstring
        for bad in (
            "timeout",
            ".kill(",
            ".terminate(",
            "send_signal",
            "subprocess.run",
        ):
            assert bad not in body, f"{name} uses {bad}"


def test_keychain_get_reads_the_labelled_dump_verbatim(sec):
    rec = sec((0, "keychain: ...\n", _security_g("  pw with spaces  ")))
    assert browser._keychain_get("svc") == "  pw with spaces  "
    (call,) = rec.popen.calls  # a read resolves no target: it is unpinned
    argv, kwargs = call["argv"], call["kwargs"]
    assert argv == ["security", "find-generic-password", "-a", "tester"] + [
        "-s",
        "svc",
        "-g",
    ]
    assert "-w" not in argv
    assert kwargs["start_new_session"] is True and "timeout" not in kwargs


@pytest.mark.parametrize(
    "answer",
    [
        ABSENT,
        _found(""),
        NOT_STARTED,
        UNKNOWN,
        RuntimeError("communicate broke"),
    ],
    ids=["absent", "empty", "not-started", "signal", "broken"],
)
def test_keychain_get_failure_is_none(sec, answer):
    sec(answer)
    assert browser._keychain_get("svc") is None


def test_keychain_set_reports_the_outcome(sec):
    sec(OK, OK, _found("v"))  # delete, add, read-back
    assert browser._keychain_set("svc", "v") is True
    sec(OK, (1, "", ""))
    assert browser._keychain_set("svc", "v") is False
    sec(NOT_STARTED)
    assert browser._keychain_set("svc", "v") is False
    sec(UNKNOWN)
    assert browser._keychain_set("svc", "v") is False


@pytest.mark.parametrize(
    "answers, outcome",
    [
        ([OK, OK, _found("v")], "ok"),
        ([ABSENT, OK, _found("v")], "ok"),
        ([(51, "", "")], "rejected"),
        ([NOT_STARTED], "rejected"),
        ([UNKNOWN], "uncertain"),
        ([ABSENT, (45, "", "")], "rejected"),
        ([ABSENT, NOT_STARTED], "rejected"),
        ([OK, (45, "", "")], "lost"),
        ([OK, NOT_STARTED], "lost"),
        ([OK, UNKNOWN], "uncertain"),
        ([OK, RuntimeError("broke")], "uncertain"),
        ([OK, OK, _found("other")], "mismatch"),
    ],
)
def test_keychain_write_outcomes(sec, keychain_path, answers, outcome):
    rec = sec(*answers)
    assert browser._keychain_write("svc", "v", "d", keychain_path) == outcome
    ops = [security_op(c["argv"]) for c in rec.calls]
    if answers[0] in (UNKNOWN, NOT_STARTED) or answers[0][0] == 51:
        assert ops in ([], ["delete"])  # no add after a failed/unknown delete


def test_keychain_set_passes_the_secret_on_stdin_never_argv(sec, keychain_path):
    secret = "s3cr3t-DUMMY"
    rec = sec(OK, OK, _found(secret))
    assert browser._keychain_set("svc", secret) is True
    assert [c["argv"] for c in rec.calls] == [
        ["security", "delete-generic-password", "-a", "tester", "-s", "svc"]
        + [keychain_path],
        ["security", "-i"],
        ["security", "find-generic-password", "-a", "tester", "-s", "svc", "-g"],
    ]
    for call in rec.popen.calls:
        assert all(secret not in a for a in call["argv"])
        assert call["kwargs"]["start_new_session"] is True
        assert "timeout" not in call["kwargs"]
    add = rec.calls[1]
    data = add["input"]
    assert isinstance(data, bytes) and data.endswith(b"\n")
    assert data.count(secret.encode()) == 1
    assert b' -w "' + secret.encode() + b'" ' in data
    quoted = browser._kc_quote(keychain_path).encode()
    assert data.endswith(b" -T /usr/bin/security " + quoted + b"\n")
    assert b" -U" not in data
    assert add["kwargs"]["stdin"] == subprocess.PIPE
    assert "text" not in add["kwargs"]  # bytes mode: exact UTF-8


def _unquote(token: str) -> str:
    """Reverse of the measured ``security -i`` rules: only \\\\ and \\" escape."""
    assert token[0] == token[-1] == '"'
    out, i, body = [], 0, token[1:-1]
    while i < len(body):
        if body[i] == "\\" and i + 1 < len(body) and body[i + 1] in '\\"':
            out.append(body[i + 1])
            i += 2
        else:
            assert body[i] != '"', "unescaped quote inside a token"
            out.append(body[i])
            i += 1
    return "".join(out)


@pytest.mark.parametrize(
    "value",
    [
        "with space",
        'dq"inside',
        "sq'inside",
        "back\\slash",
        "trailing\\",
        "$;|&#`",
        "päss✓",
    ],
)
def test_kc_quote_round_trips(value):
    quoted = browser._kc_quote(value)
    assert _unquote(quoted) == value


KC = "/Users/tester/Library/Keychains/login.keychain-db"


def test_kc_add_line_ends_with_the_named_keychain_and_no_update_flag(run):
    line = browser._kc_add_line("svc", "v", "d", '/k/a "b"')
    assert line is not None
    assert line.endswith(b' -T /usr/bin/security "/k/a \\"b\\""\n')
    assert b" -U" not in line


def test_kc_add_line_counts_the_keychain_toward_the_limit(run):
    short = browser._kc_add_line("svc", "v", "d", "/k")
    assert short is not None
    room = browser._KC_LINE_MAX - (len(short) - 1) + len("/k")
    assert browser._kc_add_line("svc", "v", "d", "/" + "k" * (room - 1)) is not None
    assert browser._kc_add_line("svc", "v", "d", "/" + "k" * room) is None


def _line_len(value: str) -> int:
    line = browser._kc_add_line("svc", value, "desc", KC)
    assert line is not None
    return len(line) - 1  # without the trailing newline


def test_kc_add_line_accepts_4000_bytes_and_rejects_4001(run):
    head = 'ä"\\'  # 2 + 2 + 2 bytes in the line: multibyte + escape expansion
    pad = 4000 - _line_len(head)
    exact = head + "x" * pad
    assert _line_len(exact) == 4000
    assert browser._kc_add_line("svc", exact + "x", "desc", KC) is None
    # the 4001st byte coming from escape expansion alone
    for tail in ('"', "ä"):
        line = browser._kc_add_line("svc", head + "x" * (pad - 1) + tail, "desc", KC)
        assert line is None


@pytest.mark.parametrize("bad", ["\n", "\r", "\0", "\t", "\x1b", "\x7f"])
@pytest.mark.parametrize(
    "field", ["account", "service", "value", "description", "keychain"]
)
def test_kc_add_line_rejects_control_chars_in_every_field(monkeypatch, field, bad):
    parts = {
        "account": "tester",
        "service": "svc",
        "value": "v",
        "description": "d",
        "keychain": KC,
    }
    parts[field] += bad
    monkeypatch.setattr(browser, "_kc_account", lambda: parts["account"])
    line = browser._kc_add_line(
        parts["service"], parts["value"], parts["description"], parts["keychain"]
    )
    assert line is None


def test_kc_add_line_rejects_a_lone_surrogate(run):
    assert browser._kc_add_line("svc", "a\ud800b", "d", KC) is None


def test_keychain_set_invalid_value_makes_no_mutating_call(sec):
    rec = sec(OK)
    assert browser._keychain_set("svc", "line1\nline2") is False
    assert not rec.calls


def test_keychain_set_read_back_mismatch_is_false(sec):
    sec(OK, OK, _found("something else"))
    assert browser._keychain_set("svc", "v") is False
    sec(OK, OK, ABSENT)
    assert browser._keychain_set("svc", "v") is False


def test_keychain_write_non_ascii_round_trips_via_the_hex_form(sec, keychain_path):
    sec(OK, OK, _found("päss"))
    assert browser._keychain_write("svc", "päss", "d", keychain_path) == "ok"


def test_keychain_write_non_ascii_rejects_a_hexlike_literal_read_back(
    sec, keychain_path
):
    sec(OK, OK, (0, "", f'{PW} "70c3a47373"\n'))
    assert browser._keychain_write("svc", "päss", "d", keychain_path) == "mismatch"


def test_keychain_write_all_hex_ascii_password_round_trips(sec, keychain_path):
    sec(OK, OK, _found("70c3a47373"))
    assert browser._keychain_write("svc", "70c3a47373", "d", keychain_path) == "ok"


@pytest.mark.parametrize(
    "stdout",
    ["", '    "/no/such/login.keychain-db"\n'],
    ids=["empty", "missing-file"],
)
def test_unresolvable_target_keychain_runs_nothing(monkeypatch, stdout):
    popen = FakeSecurityPopen(lambda argv, data: (0, stdout, ""))
    monkeypatch.setattr(browser.subprocess, "Popen", popen)
    monkeypatch.setattr(browser, "_kc_account", lambda: "tester")
    assert browser._kc_target_keychain() is None
    assert browser._keychain_set("svc", "v") is False
    assert browser._keychain_delete("svc") is False
    assert browser._keychain_set_all([("a", "x")], "d").ok is False
    assert {security_op(a) for a in popen.argvs()} == {"default"}


def test_target_keychain_strips_quotes_and_needs_a_file(monkeypatch, keychain_path):
    popen = FakeSecurityPopen(lambda argv, data: (0, f'  "{keychain_path}"  \n', ""))
    monkeypatch.setattr(browser.subprocess, "Popen", popen)
    assert browser._kc_target_keychain() == keychain_path
    assert popen.argvs() == [["security", "default-keychain", "-d", "user"]]
    popen.handler = lambda argv, data: (1, f'"{keychain_path}"', "")
    assert browser._kc_target_keychain() is None


PW = "pass" + "word:"  # split so the secret scanners do not flag the fixtures


@pytest.mark.parametrize(
    ("stderr", "expected"),
    [
        (f"{PW} 0x70C3A47373  " + '"p\\303\\244ss"\n', "päss"),
        (f'{PW} "cafe"\n', "cafe"),
        (f'{PW} "c3a4"\n', "c3a4"),
        (f'{PW} "a"b"\n', 'a"b'),
        (f"{PW} 0x615C62  " + '"a\\134b"\n', "a\\b"),
        (f'{PW} "sp "\n', "sp "),
        (f"{PW} 0x740962  " + '"t\\011b"\n', "t\tb"),
        (f"{PW} 0xC3A42278  " + '"\\303\\244"x"\n', 'ä"x'),
        (f'{PW} "0x41"\n', "0x41"),
        (f"{PW} 0xC3A4 \n", "ä"),
        (f"{PW} 0x5C \n", "\\"),
        (f"{PW} 0xc3a4 \n", "ä"),
        (f'{PW} "  both ends  "\n', "  both ends  "),
        (f'{PW} "crlf"\r\n', "crlf"),
        (f'noise\n{PW} "first"\nmore noise\n{PW} "last"\ntrailer\n', "last"),
        (f"{PW}\n", None),
        (f"{PW}   \n", None),
        (f'{PW} ""\n', None),
        (f"{PW} 0x70C3A4737\n", None),  # odd length
        (f"{PW} 0xFF \n", None),  # invalid UTF-8
        (f"{PW} 0x \n", None),  # empty payload
        (f"{PW} 0x70C3A47373Z\n", None),
        (f'{PW} "unterminated\n', None),
        (f'{PW} "\n', None),
        (f"{PW} bare\n", None),
        ("", None),
        ("keychain: nothing labelled\n", None),
    ],
)
def test_kc_parse_password(stderr, expected):
    assert browser._kc_parse_password(stderr) == expected


@pytest.mark.parametrize(
    "value", ["päss", "cafe", "a\\b", "t\tb", 'ä"x', "ä", "\\", "😀", "sp ", 'ab"']
)
def test_kc_parse_password_inverts_the_formatter(value):
    assert browser._kc_parse_password(_security_g(value)) == value


_DUMMY = "päss-DUMMY"
_DUMMY_FORMS = (
    _DUMMY,
    _DUMMY.encode().hex(),
    _DUMMY.encode().hex().upper(),
    "p\\303\\244ss-DUMMY",
)


def _assert_no_dummy(text: str) -> None:
    for form in _DUMMY_FORMS:
        assert form not in text


def test_keychain_get_unparsable_value_warns_with_the_label_only(sec, capsys):
    hexed = _DUMMY.encode().hex().upper()
    stderr = f'{PW} 0x{hexed}Z  "p\\303\\244ss-DUMMY" {_DUMMY}\n'
    sec((0, f"svce {_DUMMY}\n", stderr))
    assert browser._keychain_get("svc.label") is None
    out, err = capsys.readouterr()
    assert out == ""
    assert err == "Keychain item svc.label has an unreadable value — ignoring it.\n"
    _assert_no_dummy(err)


@pytest.mark.parametrize(
    "answer",
    [
        (1, _DUMMY, f"{PW} 0x{_DUMMY.encode().hex().upper()}  {_DUMMY}\n"),
        (-9, _DUMMY, f"{PW} {_DUMMY_FORMS[3]}\n"),
    ],
)
def test_keychain_get_failures_print_nothing(sec, capsys, answer):
    sec(answer)
    assert browser._keychain_get("svc") is None
    assert capsys.readouterr() == ("", "")


def test_keychain_set_all_validates_the_whole_batch_first(sec):
    rec = sec(OK)
    res = browser._keychain_set_all([("a", "fine"), ("b", "bad\n")], "d")
    assert res.ok is False and res.changed is False and not rec.calls


def test_keychain_set_all_stops_at_the_first_failure(sec):
    rec = sec((51, "", ""))
    res = browser._keychain_set_all([("a", "x"), ("b", "y")], "d")
    assert res.ok is False and res.changed is False
    assert len(rec.calls) == 1  # first delete refused: nothing to clean up


def test_keychain_set_all_resolves_the_target_once(sec, keychain_path):
    rec = sec(OK, OK, _found("x"), OK, OK, _found("y"))
    assert browser._keychain_set_all([("a", "x"), ("b", "y")], "my desc").ok is True
    ops = [security_op(c["argv"]) for c in rec.popen.calls]
    assert ops == ["default"] + ["delete", "add", "find"] * 2
    writes = [c["input"] for c in rec.calls if c["argv"] == ["security", "-i"]]
    assert len(writes) == 2
    assert all(b'-D "my desc"' in w for w in writes)
    deletes = [c["argv"] for c in rec.calls if security_op(c["argv"]) == "delete"]
    assert all(a[-1] == keychain_path for a in deletes)


def test_keychain_creds_generates_the_code_locally(monkeypatch):
    items = {
        browser.KEYCHAIN_SVC_USER: "user",
        browser.KEYCHAIN_SVC_PASS: "pw",
        browser.KEYCHAIN_SVC_TOTP: SEED,
    }
    monkeypatch.setattr(browser, "_keychain_get", items.get)
    creds = browser._keychain_creds()
    assert creds is not None and creds[:2] == ("user", "pw")
    assert pyotp.TOTP(SEED).verify(creds.otp(), valid_window=1)

    items[browser.KEYCHAIN_SVC_TOTP] = "not base32 !!"
    assert browser._keychain_creds() is None
    del items[browser.KEYCHAIN_SVC_PASS]
    assert browser._keychain_creds() is None


# --- TOTP ------------------------------------------------------------------------


def test_totp_now_accepts_seed_and_uri_forms():
    want = pyotp.TOTP(SEED).now()
    assert browser._totp_now(SEED) == want
    assert browser._totp_now(" jbsw y3dp ehpk 3pxp ") == want
    assert browser._totp_now(f"otpauth://totp/CSCS:u?secret={SEED}&issuer=CSCS") == want


@pytest.mark.parametrize(
    "bad",
    ["not base32 !!", "otpauth://totp/x?issuer=CSCS", "otpauth://totp/x?secret=!!!!"],
)
def test_totp_now_rejects_malformed_input(bad):
    assert browser._totp_now(bad) is None


def test_totp_now_changes_on_the_period_boundary(monkeypatch):
    # The code is a function of floor(t / 30): the last second of a window and
    # the first second of the next produce different codes.
    import datetime as _dt

    import pyotp.totp

    def frozen(epoch: float):
        class _Frozen(_dt.datetime):
            @classmethod
            def now(cls, tz=None):
                return _dt.datetime.fromtimestamp(epoch, tz)

        monkeypatch.setattr(pyotp.totp.datetime, "datetime", _Frozen)

    frozen(59.0)
    before = browser._totp_now(SEED)
    frozen(60.0)
    after = browser._totp_now(SEED)
    monkeypatch.undo()
    assert before == pyotp.TOTP(SEED).at(59)
    assert after == pyotp.TOTP(SEED).at(60)
    assert before != after


# --- 1Password -------------------------------------------------------------------


def test_op_creds_parses_fields_and_defers_the_otp(run):
    fields = [
        {"label": "username", "value": "user"},
        {"label": "password", "value": "pw"},
    ]
    rec = run(_Res(0, json.dumps(fields)), _Res(0, "123456\n"))
    creds = browser._op_creds("CSCS", "acct")
    assert creds is not None and creds[:2] == ("user", "pw")
    assert len(rec.calls) == 1 and "--otp" not in rec.calls[0][0]
    assert creds.otp() == "123456"  # the live code is fetched only now
    assert len(rec.calls) == 2 and rec.calls[1][0][-1] == "--otp"
    assert all(kwargs["timeout"] for _, kwargs in rec.calls)


@pytest.mark.parametrize(
    "creds_out, otp_out",
    [
        (_Res(1, "", "not signed in"), _Res(0, "123456")),
        (_Res(0, "{not json"), _Res(0, "123456")),
        (_Res(0, json.dumps([{"label": "username", "value": "u"}])), _Res(0, "1")),
        (_Res(0, json.dumps([{"label": "password", "value": "p"}])), _Res(1)),
    ],
)
def test_op_creds_failure_is_none(run, creds_out, otp_out):
    run(creds_out, otp_out)
    assert browser._op_creds("CSCS", "acct") is None


def test_op_totp_uri_finds_the_seed_uri(run):
    uri = f"otpauth://totp/CSCS?secret={SEED}"
    run(_Res(0, json.dumps([{"type": "OTP", "totp": "123456", "value": uri}])))
    assert browser._op_totp_uri("CSCS", "acct") == uri
    run(_Res(0, json.dumps({"type": "OTP", "totp": uri})))
    assert browser._op_totp_uri("CSCS", "acct") == uri


@pytest.mark.parametrize(
    "answer",
    [
        _Res(0, json.dumps([{"totp": "123456"}])),  # live code only, no seed
        _Res(0, "garbage"),
        _Res(1, ""),
        subprocess.TimeoutExpired("op", 60),
    ],
)
def test_op_totp_uri_without_seed_is_none(run, answer):
    run(answer)
    assert browser._op_totp_uri("CSCS", "acct") is None


# --- cscs-store-creds ------------------------------------------------------------


def _store_creds_env(monkeypatch, seed: str, password: str = "pw"):
    stored: dict[str, str] = {}
    monkeypatch.setattr(browser.shutil, "which", lambda name: "/usr/bin/op")
    monkeypatch.setattr(
        browser,
        "_op_creds",
        lambda item, acct: browser.CscsCreds("user", password, lambda: "1"),
    )
    monkeypatch.setattr(browser, "_op_totp_uri", lambda item, acct: seed)

    def fake_write(svc, v, description, keychain, touched=None):
        assert description == "cscs-api credential"
        stored[svc] = v
        return "ok"

    def fake_delete(svc):
        stored.pop(svc, None)
        return True

    monkeypatch.setattr(browser, "_keychain_write", fake_write)
    monkeypatch.setattr(browser, "_keychain_delete", fake_delete)
    monkeypatch.setattr(browser, "_kc_target_keychain", lambda: KC)
    return stored


def test_store_creds_writes_all_three_without_printing_secrets(monkeypatch, capsys):
    stored = _store_creds_env(monkeypatch, SEED)
    assert browser.cmd_cscs_store_creds() == 0
    assert stored == {
        browser.KEYCHAIN_SVC_USER: "user",
        browser.KEYCHAIN_SVC_PASS: "pw",
        browser.KEYCHAIN_SVC_TOTP: SEED,
    }
    out = capsys.readouterr()
    assert SEED not in out.out + out.err and "pw\n" not in out.out


def test_store_creds_refuses_a_seed_that_makes_no_code(monkeypatch):
    stored = _store_creds_env(monkeypatch, "not base32 !!")
    assert browser.cmd_cscs_store_creds() == 1
    assert not stored


def test_store_creds_invalid_last_field_writes_nothing(monkeypatch, sec):
    rec = sec(OK)
    real_write, real_delete = browser._keychain_write, browser._keychain_delete
    _store_creds_env(monkeypatch, SEED + "\n")  # still makes a code (stripped)
    monkeypatch.setattr(browser, "_keychain_write", real_write)
    monkeypatch.setattr(browser, "_keychain_delete", real_delete)
    assert browser.cmd_cscs_store_creds() == 1
    assert not rec.calls


def test_biopolwifi_store_creds_labels_and_validates(monkeypatch, sec):
    rec = sec(OK)
    answers = iter(["me@example.org"])
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(answers))
    import getpass

    monkeypatch.setattr(getpass, "getpass", lambda _prompt="": "pw\nrest")
    assert browser.cmd_biopolwifi_store_creds() == 1
    assert not rec.calls

    seen: list[tuple[str, str, str]] = []

    def fake_write(svc, v, description, keychain, touched=None):
        seen.append((svc, v, description))
        return "ok"

    monkeypatch.setattr(browser, "_keychain_write", fake_write)
    answers = iter(["me@example.org"])
    monkeypatch.setattr(getpass, "getpass", lambda _prompt="": "pw")
    assert browser.cmd_biopolwifi_store_creds() == 0
    assert seen == [
        (browser.KEYCHAIN_SVC_BIOPOL_EMAIL, "me@example.org", "biopol-wifi credential"),
        (browser.KEYCHAIN_SVC_BIOPOL_PASS, "pw", "biopol-wifi credential"),
    ]


# --- Keycloak form ---------------------------------------------------------------


class _El:
    def __init__(self, log: list, name: str):
        self._log, self._name = log, name

    def click(self):
        self._log.append(("click", self._name))

    def fill(self, value):
        self._log.append(("fill", self._name, value))


class _KcPage:
    """Keycloak: user/pass → OTP step → portal after the second submit."""

    def __init__(self, reach_portal: bool = True):
        self.url = "https://auth.cscs.ch/auth/realms/cscs/login-actions/authenticate"
        self.log: list = []
        self.submits = 0
        self._reach = reach_portal

    def fill(self, sel, value):
        self.log.append(("fill", sel, value))

    def query_selector(self, sel):
        if sel == "#kc-login":
            return self
        if sel == "#otp" and self.submits >= 1:
            return _El(self.log, sel)
        return None

    def click(self):
        self.submits += 1
        if self.submits >= 2 and self._reach:
            self.url = "https://portal.cscs.ch/profile/"

    def wait_for_timeout(self, _ms):
        pass


def test_submit_keycloak_login_fills_otp_once_and_lands_on_portal():
    page = _KcPage()
    creds = browser.CscsCreds("user", "pw", lambda: "654321")
    assert browser._submit_keycloak_login(page, creds) is True
    assert ("fill", "#username", "user") in page.log
    assert ("fill", "#password", "pw") in page.log
    assert page.log.count(("fill", "#otp", "654321")) == 1
    assert page.submits == 2


def test_submit_keycloak_login_that_never_reaches_portal_is_false():
    page = _KcPage(reach_portal=False)
    creds = browser.CscsCreds("user", "pw", lambda: "654321")
    assert browser._submit_keycloak_login(page, creds) is False
    assert page.log.count(("fill", "#otp", "654321")) == 1


def test_click_keycloak_submit_is_a_noop_without_a_button():
    class _Blank:
        def query_selector(self, sel):
            return None

    browser._click_keycloak_submit(_Blank())  # must not raise


@pytest.mark.parametrize(
    "url, on_portal",
    [
        ("https://portal.cscs.ch/profile/", True),
        ("https://auth.cscs.ch/auth/realms/cscs/protocol/openid-connect/auth", False),
        ("https://portal.cscs.ch/api-auth/keycloak/complete/?state=x", False),
        ("https://portal.cscs.ch/oauth_login_completed/", False),
        ("https://portal.cscs.ch/profile/?code=abc", False),
        ("https://example.com/portal.cscs.ch", True),
    ],
)
def test_on_portal(url, on_portal):
    class _P:
        def __init__(self, url):
            self.url = url

    p = _P(url)
    assert browser._on_portal(p) is on_portal


# --- DRF token scan ----------------------------------------------------------------

HEX = "0123456789abcdef0123456789abcdef01234567"


class _Ctx:
    def __init__(self, cookies):
        self._cookies = cookies

    def cookies(self, urls=None):
        return list(self._cookies)


class _TokPage:
    def __init__(self, token=None, exc=None):
        self._token, self._exc = token, exc

    def evaluate(self, _js):
        if self._exc:
            raise self._exc
        return self._token


def test_scan_token_prefers_local_storage():
    assert browser._scan_token(_Ctx([]), _TokPage(HEX)) == HEX


def test_scan_token_falls_back_to_portal_cookie():
    ctx = _Ctx([{"name": "token", "domain": "portal.cscs.ch", "value": HEX}])
    assert browser._scan_token(ctx, _TokPage(None)) == HEX


def test_scan_token_survives_a_navigation_mid_scan():
    from playwright.sync_api import Error as PlaywrightError

    page = _TokPage(exc=PlaywrightError("Execution context was destroyed"))
    assert browser._scan_token(_Ctx([]), page) is None


class _ScopedCtx:
    """Like a Playwright context: ``cookies(urls)`` filters by URL, ``cookies()``
    returns EVERY site's cookies."""

    def __init__(self, cookies):
        self._cookies = cookies
        self.asked: list = []

    def cookies(self, urls=None):
        self.asked.append(urls)
        if urls is None:
            return list(self._cookies)
        urls = [urls] if isinstance(urls, str) else urls
        return [c for c in self._cookies if any(c["domain"] in u for u in urls)]


def test_scan_token_ignores_other_sites_cookies():
    # Regression: the cookie fallback scanned ctx.cookies() — every site's
    # cookies in the shared profile — so a 40-hex session cookie from another
    # site was cached as the CSCS token and sent to portal.cscs.ch.
    other = "fedcba9876543210fedcba9876543210fedcba98"
    ctx = _ScopedCtx([{"name": "sid", "domain": "slack.com", "value": other}])
    assert browser._scan_token(ctx, _TokPage(None)) is None
    assert None not in ctx.asked


class _Resp:
    status_code = 200
    text = ""

    @staticmethod
    def json():
        return {"username": "user", "email": "u@x.ch"}


@pytest.fixture
def token_env(tmp_path, monkeypatch):
    import os

    import requests

    cache = tmp_path / "cscs-api" / "portal_token"
    monkeypatch.setattr(browser, "CSCS_TOKEN_CACHE", cache)
    monkeypatch.setattr(browser, "_scan_token", lambda ctx, page: HEX)
    monkeypatch.setattr(requests, "get", lambda *a, **k: _Resp())
    old = os.umask(0o022)
    yield cache
    os.umask(old)


def test_token_cache_is_never_readable_by_others(token_env, monkeypatch):
    # Regression: write_text() created the file 0644 and only a later chmod()
    # tightened it, leaving a window where any local user could read the token.
    # With the after-the-fact chmod neutralised, the file must still be 0600.
    import pathlib

    monkeypatch.setattr(pathlib.Path, "chmod", lambda self, mode: None)
    assert browser._capture_and_cache_token(None, None) == 0
    assert token_env.read_text() == HEX
    assert token_env.stat().st_mode & 0o777 == 0o600


def test_token_cache_tightens_a_preexisting_loose_file(token_env):
    token_env.parent.mkdir(parents=True)
    token_env.write_text("old-token-that-is-longer-than-the-new-one" * 2)
    token_env.chmod(0o644)
    assert browser._capture_and_cache_token(None, None) == 0
    assert token_env.read_text() == HEX
    assert token_env.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize(
    "answer, ok",
    [
        (OK, True),
        (ABSENT, True),
        ((51, "", "User interaction is not allowed."), False),
        (NOT_STARTED, False),
        (UNKNOWN, False),
    ],
)
def test_keychain_delete_reports_real_failures(sec, keychain_path, answer, ok):
    # Regression: the return code was ignored, so a locked keychain (51) was
    # reported as "deleted" and the secret silently stayed stored.
    rec = sec(answer)
    assert browser._keychain_delete("svc") is ok
    for call in rec.calls:
        assert call["argv"][-1] == keychain_path  # pinned to the default


@pytest.mark.parametrize(
    "answer, outcome",
    [
        (OK, "deleted"),
        (ABSENT, "absent"),
        ((51, "", ""), "rejected"),
        (NOT_STARTED, "rejected"),
        (UNKNOWN, "unknown"),
        (RuntimeError("broke"), "unknown"),
    ],
)
def test_kc_delete_outcomes(sec, keychain_path, answer, outcome):
    sec(answer)
    assert browser._kc_delete("svc", keychain_path) == outcome


@pytest.mark.parametrize(
    "cmd", ["cmd_cscs_forget_creds", "cmd_biopolwifi_forget_creds"]
)
def test_forget_creds_fails_loud_when_an_item_survives(monkeypatch, capsys, cmd):
    # Regression: forget-creds printed "✓ Removed" and exited 0 even when the
    # secrets were still in the keychain.
    monkeypatch.setattr(browser, "_keychain_delete", lambda svc: "pass" not in svc)
    assert getattr(browser, cmd)() == 1
    out = capsys.readouterr()
    assert "✓" not in out.out and "password" in out.err


@pytest.mark.parametrize(
    "cmd", ["cmd_cscs_forget_creds", "cmd_biopolwifi_forget_creds"]
)
def test_forget_creds_succeeds_when_all_items_are_gone(monkeypatch, capsys, cmd):
    deleted: list[str] = []

    def fake_delete(svc):
        deleted.append(svc)
        return True

    monkeypatch.setattr(browser, "_keychain_delete", fake_delete)
    assert getattr(browser, cmd)() == 0
    assert len(deleted) == (3 if "cscs" in cmd else 2)
    assert "✓ Removed" in capsys.readouterr().out


@pytest.mark.parametrize(
    "bad",
    [
        f"otpauth://hotp/CSCS?secret={SEED}&counter=1",  # AttributeError: no .now()
        f"otpauth://totp/CSCS?secret={SEED}&period=0",  # ZeroDivisionError
        "   ",  # empty key: pyotp happily makes a code from b""
    ],
)
def test_totp_now_rejects_unusable_secrets_without_crashing(bad):
    # Regression: these crashed cscs-store-creds with a traceback, or (blank
    # seed in the keychain) produced a code that is guaranteed wrong and burns a
    # Keycloak attempt toward the account lockout.
    assert browser._totp_now(bad) is None


class _LoginPage:
    def __init__(self, url: str, after_goto: str):
        self.url = url
        self._after = after_goto

    def goto(self, url, **kwargs):
        self.url = self._after

    def wait_for_timeout(self, _ms):
        pass


def _cscs_login_env(monkeypatch, page):
    import contextlib

    class _Closer:
        def close(self):
            pass

        def stop(self):
            pass

    monkeypatch.setattr(browser, "_connect", lambda port: (_Closer(), _Closer()))
    monkeypatch.setattr(
        browser, "_interaction_lease", lambda *a, **k: contextlib.nullcontext()
    )
    monkeypatch.setattr(browser, "_pick_portal_page", lambda b: (None, page))
    monkeypatch.setattr(browser, "_close_stale_cscs_tabs", lambda ctx, keep=None: 0)
    monkeypatch.setattr(browser, "_cscs_creds", lambda announce: (("u", "p", "1"), "k"))
    monkeypatch.setattr(browser, "_submit_keycloak_login", lambda pg, creds: False)
    monkeypatch.setattr(browser, "_keycloak_flow_expired", lambda pg: False)
    recorded: list = []
    monkeypatch.setattr(browser, "_record_login_event", lambda *a: recorded.append(a))
    return recorded


@pytest.mark.parametrize(
    "after_goto",
    [
        # OAuth callback carrying a live authorization code → "Unexpected page"
        "https://portal.cscs.ch/api-auth/keycloak/complete/?code=SECRETCODE&state=S",
        # Keycloak form with its session_code → "Login did not reach the portal"
        "https://auth.cscs.ch/auth/realms/cscs/login-actions/authenticate"
        "?session_code=SECRETCODE&execution=e&tab_id=t",
    ],
)
def test_cscs_login_errors_print_only_the_origin(monkeypatch, capsys, after_goto):
    # Regression: the failure lines interpolated the raw page URL, so an OAuth
    # authorization code / Keycloak session code landed in stderr, logs and LLM
    # transcripts (AGENTS.md: tab URLs in error lines go through _tab_hint).
    recorded = _cscs_login_env(monkeypatch, _LoginPage("about:blank", after_goto))
    assert browser.cmd_cscs_login(9222) == 1
    err = capsys.readouterr().err
    assert "SECRETCODE" not in err
    assert browser._tab_hint(after_goto) in err
    assert not recorded  # a failed login is never logged as a real login
