"""tp#2775 B3: agent_login_sms.py — reader, filter, child protocol, probe.

Hermetic: a fake Beeper Desktop API on a free loopback port; no real Beeper,
no real token, no real SMS. Codes are generated per run (no credential-shaped
literals). In-process runs use a fake clock whose sleep is a poll hook.
"""

from __future__ import annotations

# pylint: disable=missing-function-docstring,import-error,wrong-import-position
# pylint: disable=protected-access,redefined-outer-name,too-many-instance-attributes
import json
import os
import secrets
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Iterator
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlsplit

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import agent_login_sms as sms  # noqa: E402

MODULE = Path(__file__).resolve().parent.parent / "agent_login_sms.py"
TOKEN = "fake-" + secrets.token_hex(8)
GM = "gmessages_test"
SENDER = sms.SmsSender(
    senders=("Visana",),
    keyword_re=r"(?i)\bvisana\b",
    code_re=r"(?<!\d)(\d{6})(?!\d)",
)


def new_code() -> str:
    return str(100000 + secrets.randbelow(900000))


def iso(ts: float) -> str:
    return (
        datetime.fromtimestamp(ts, tz=timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


class FakeBeeper:
    """The subset of Beeper's /v1 API the reader uses."""

    def __init__(self) -> None:
        self.accounts: list[dict[str, Any]] = [
            {"accountID": GM, "status": "connected"},
            {"accountID": "whatsapp.x", "status": "connected"},
        ]
        self.messages: list[dict[str, Any]] = []
        self.chats: dict[str, dict[str, Any]] = {}
        self.requests: list[tuple[str, str, dict[str, str]]] = []
        self.page_size = 20
        self.honor_accounts = True
        self.redirect_to = ""
        self.lock = threading.Lock()
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_a: Any) -> None:
                return

            def _record(self) -> None:
                with fake.lock:
                    fake.requests.append(
                        (self.command, self.path, dict(self.headers.items()))
                    )

            def do_POST(self) -> None:  # noqa: N802
                self._record()
                self.send_response(405)
                self.end_headers()

            def do_GET(self) -> None:  # noqa: N802
                self._record()
                status, body, extra = fake.route(self)
                self.send_response(status)
                for k, v in extra.items():
                    self.send_header(k, v)
                data = json.dumps(body).encode()
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    # -- data ---------------------------------------------------------------
    def chat(self, cid: str, *, phone: str = "", name: str = "Visana") -> None:
        self.chats[cid] = {
            "id": cid,
            "accountID": GM,
            "type": "single",
            "participants": {
                "items": [
                    {"id": "@me", "isSelf": True},
                    {"id": "@sender-" + cid, "phoneNumber": phone, "fullName": name},
                ],
                "hasMore": False,
                "total": 2,
            },
        }

    def add(
        self,
        mid: str,
        text: str,
        *,
        at: float,
        chat: str = "!c1",
        sender: str = "Visana",
        account: str = GM,
        **extra: Any,
    ) -> dict[str, Any]:
        if chat not in self.chats:
            self.chat(chat, name=sender)
        msg = {
            "id": mid,
            "chatID": chat,
            "accountID": account,
            "senderID": "@sender-" + chat,
            "senderName": sender,
            "timestamp": iso(at),
            "sortKey": str(int(at * 1000)),
            "text": text,
            "isSender": False,
            "isDeleted": False,
            **extra,
        }
        with self.lock:
            self.messages.append(msg)
        return msg

    # -- routes -------------------------------------------------------------
    # pylint: disable-next=too-many-return-statements
    def route(self, req: BaseHTTPRequestHandler) -> tuple[int, Any, dict[str, str]]:
        url = urlsplit(req.path)
        q = parse_qs(url.query)
        if self.redirect_to:
            return 302, {}, {"Location": self.redirect_to}
        if url.path == "/v1/info":
            return 200, {"app": {"name": "Beeper"}, "server": {"status": "running"}}, {}
        if req.headers.get("Authorization") != "Bearer " + TOKEN:
            return 401, {"code": "unauthorized"}, {}
        if url.path == "/v1/accounts":
            return 200, self.accounts, {}
        with self.lock:
            msgs = sorted(self.messages, key=lambda m: m["timestamp"], reverse=True)
        if url.path == "/v1/messages/search":
            accs = q.get("accountIDs", [])
            after = sms.parse_time(q.get("dateAfter", [""])[0]) or 0.0
            msgs = [
                m
                for m in msgs
                if (not self.honor_accounts or m["accountID"] in accs)
                and (sms.parse_time(m["timestamp"]) or 0) > after
                and not m["isSender"]
            ]
            return 200, self._paged(msgs, q, with_chats=True), {}
        if url.path == "/v1/chats":
            accs = q.get("accountIDs", [])
            rows = []
            for cid, chat in self.chats.items():
                times = [m["timestamp"] for m in msgs if m["chatID"] == cid]
                if chat["accountID"] in accs and times:
                    rows.append({**chat, "lastActivity": max(times)})
            rows.sort(key=lambda c: c["lastActivity"], reverse=True)
            return 200, self._paged(rows, q), {}
        if url.path.startswith("/v1/chats/") and url.path.endswith("/messages"):
            cid = unquote(url.path[len("/v1/chats/") : -len("/messages")])
            return 200, self._paged([m for m in msgs if m["chatID"] == cid], q), {}
        return 404, {}, {}

    def _paged(
        self,
        rows: list[dict[str, Any]],
        q: dict[str, list[str]],
        with_chats: bool = False,
    ) -> dict[str, Any]:
        start = int(q.get("cursor", ["0"])[0])
        page = rows[start : start + self.page_size]
        more = start + self.page_size < len(rows)
        out: dict[str, Any] = {
            "items": page,
            "hasMore": more,
            "oldestCursor": str(start + self.page_size) if more else None,
            "newestCursor": None,
        }
        if with_chats:
            out["chats"] = {
                m["chatID"]: self.chats[m["chatID"]]
                for m in page
                if m["chatID"] in self.chats
            }
        return out


@pytest.fixture
def fake() -> Iterator[FakeBeeper]:
    server = FakeBeeper()
    yield server
    server.close()


class Clock:
    """A fake clock from real now; each sleep advances it and runs the hook
    for that poll number (1-based)."""

    def __init__(self, hooks: dict[int, Callable[[], object]] | None = None) -> None:
        self.now = time.time()
        self.polls = 0
        self.hooks = hooks or {}

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds
        self.polls += 1
        hook = self.hooks.get(self.polls)
        if hook:
            hook()


def run_wait(
    fake: FakeBeeper,
    clock: Clock,
    sender: sms.SmsSender = SENDER,
    wait_s: float = 40,
) -> list[dict[str, Any]]:
    lines: list[dict[str, Any]] = []
    sms.wait_code(
        sms.Beeper(fake.port, TOKEN),
        sender,
        wait_s,
        lines.append,
        clock=clock,
        sleep=clock.sleep,
    )
    return lines


def test_releases_one_new_code_from_the_allowlisted_sender(fake: FakeBeeper) -> None:
    code = new_code()
    clock = Clock()
    clock.hooks[1] = lambda: fake.add("m1", f"Ihr Visana Code: {code}", at=clock.now)
    lines = run_wait(fake, clock)
    assert lines == [{"armed": True}, {"ok": True, "code": code}]
    assert clock.polls == 2  # seen in poll 1, released on the repeat in poll 2


def test_baseline_code_is_never_released(fake: FakeBeeper) -> None:
    code = new_code()
    clock = Clock()
    fake.add("old", f"Visana Code {code}", at=clock.now - 10)
    clock.hooks[1] = lambda: fake.add("new", f"Visana Code {code}", at=clock.now)
    lines = run_wait(fake, clock, wait_s=20)
    assert lines == [{"armed": True}, {"ok": False, "why": "timeout"}]


def test_new_chat_id_per_sms_still_matches(fake: FakeBeeper) -> None:
    old, code = new_code(), new_code()
    clock = Clock()
    fake.add("old", f"Visana Code {old}", at=clock.now - 10, chat="!a")
    clock.hooks[1] = lambda: fake.add(
        "new", f"Visana Code {code}", at=clock.now, chat="!b"
    )
    lines = run_wait(fake, clock)
    assert "!b" not in {m["chatID"] for m in fake.messages[:1]}
    assert lines[-1] == {"ok": True, "code": code}


def test_backfilled_old_sms_with_fresh_id_is_ignored(fake: FakeBeeper) -> None:
    code = new_code()
    clock = Clock()
    sender = sms.SmsSender(
        senders=SENDER.senders,
        keyword_re=SENDER.keyword_re,
        code_re=SENDER.code_re,
        time_field="originalTimestamp",
    )
    # the bridge delivers it now, but the SMS itself is two minutes old
    clock.hooks[1] = lambda: fake.add(
        "bf",
        f"Visana Code {code}",
        at=clock.now,
        originalTimestamp=iso(clock.now - 120),
    )
    lines = run_wait(fake, clock, sender, wait_s=20)
    assert lines[-1] == {"ok": False, "why": "timeout"}


def test_search_pages_to_the_end(fake: FakeBeeper) -> None:
    code = new_code()
    clock = Clock()
    fake.page_size = 1

    def arrive() -> None:
        fake.add("sms", f"Visana Code {code}", at=clock.now - 1)
        fake.add("x1", "hello", at=clock.now, sender="Bob", chat="!bob")

    clock.hooks[1] = arrive
    lines = run_wait(fake, clock)
    assert lines[-1] == {"ok": True, "code": code}
    assert any("cursor=1" in p for _m, p, _h in fake.requests)


def test_other_network_same_text_is_ignored(fake: FakeBeeper) -> None:
    code = new_code()
    clock = Clock()
    fake.honor_accounts = False  # the reader's own filter must hold
    clock.hooks[1] = lambda: fake.add(
        "wa", f"Visana Code {code}", at=clock.now, account="whatsapp.x"
    )
    lines = run_wait(fake, clock, wait_s=20)
    assert lines[-1] == {"ok": False, "why": "timeout"}


def test_unlisted_sender_and_missing_keyword_are_ignored(fake: FakeBeeper) -> None:
    clock = Clock()

    def arrive() -> None:
        fake.add("u1", f"Visana Code {new_code()}", at=clock.now, sender="Mallory")
        fake.add("u2", f"Ihr Code {new_code()}", at=clock.now, chat="!c2")
        fake.add("u3", f"Visana {new_code()}", at=clock.now, sender="Visanax")

    clock.hooks[1] = arrive
    lines = run_wait(fake, clock, wait_s=20)
    assert lines[-1] == {"ok": False, "why": "timeout"}


def test_two_new_codes_is_several_no_code(fake: FakeBeeper) -> None:
    clock = Clock()

    def arrive() -> None:
        fake.add("n1", f"Visana Code {new_code()}", at=clock.now)
        fake.add("n2", f"Visana Code {new_code()}", at=clock.now)

    clock.hooks[1] = arrive
    lines = run_wait(fake, clock)
    assert lines == [{"armed": True}, {"ok": False, "why": "several"}]


def test_code_must_repeat_in_two_polls(fake: FakeBeeper) -> None:
    code = new_code()
    clock = Clock()
    msg: dict[str, Any] = {}
    clock.hooks[1] = lambda: msg.update(
        fake.add("m", f"Visana Code {code}", at=clock.now)
    )
    clock.hooks[2] = fake.messages.clear  # gone before the repeat
    lines = run_wait(fake, clock, wait_s=20)
    assert lines[-1] == {"ok": False, "why": "timeout"}
    assert code not in json.dumps(lines)


def test_no_gmessages_account_is_no_account_before_armed(fake: FakeBeeper) -> None:
    fake.accounts = [{"accountID": "whatsapp.x"}, {"accountID": "signal.y"}]
    lines = run_wait(fake, Clock())
    assert lines == [{"ok": False, "why": "no_account"}]


def test_missing_token_is_token_before_armed(fake: FakeBeeper) -> None:
    lines: list[dict[str, Any]] = []
    sms.wait_code(sms.Beeper(fake.port, "wrong"), SENDER, 10, lines.append)
    assert lines == [{"ok": False, "why": "token"}]


def test_only_get_to_loopback_and_no_redirect(fake: FakeBeeper) -> None:
    other = FakeBeeper()
    try:
        fake.redirect_to = f"http://127.0.0.1:{other.port}/v1/accounts"
        client = sms.Beeper(fake.port, TOKEN)
        assert client.base == f"http://127.0.0.1:{fake.port}"
        with pytest.raises(sms.BeeperError, match="redirect"):
            client.get("/v1/accounts")
        with pytest.raises(sms.BeeperError):
            client.get("https://example.invalid/v1/accounts")
        lines = run_wait(fake, Clock())
        assert lines == [{"ok": False, "why": "unreadable"}]
        assert not other.requests  # the token never followed the redirect
        assert fake.requests and {m for m, _p, _h in fake.requests} == {"GET"}
    finally:
        other.close()


def _env(fake: FakeBeeper, tmp_path: Path, token: str | None) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k != sms.TOKEN_ENV}
    env[sms.PORT_ENV] = str(fake.port)
    env["AGENT_LOGIN_STATE_FILE"] = str(tmp_path / "last-check.json")
    if token is not None:
        env[sms.TOKEN_ENV] = token
    return env


def test_check_never_reads_the_token(fake: FakeBeeper, tmp_path: Path) -> None:
    cmd = [sys.executable, "-I", str(MODULE), "-c"]
    res = subprocess.run(
        cmd,
        env=_env(fake, tmp_path, None),
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert res.returncode == 0, res.stderr
    assert res.stdout.strip() == "gmessages: unknown"
    (tmp_path / sms.LAST_NAME).write_text("filled\n", encoding="utf-8")
    # even with a token in the environment, -c sends none
    res = subprocess.run(
        cmd,
        env=_env(fake, tmp_path, TOKEN),
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert res.stdout.strip() == "gmessages: last:filled"
    assert [p for _m, p, _h in fake.requests] == ["/v1/info", "/v1/info"]
    assert all("Authorization" not in h for _m, _p, h in fake.requests)
    fake.close()
    res = subprocess.run(
        cmd,
        env=_env(fake, tmp_path, None),
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert (res.returncode, res.stdout.strip()) == (1, "gmessages: unreachable")
    fake.server.server_close()


def test_record_last_refuses_anything_but_an_outcome_word(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AGENT_LOGIN_STATE_FILE", str(tmp_path / "x.json"))
    sms.record_last("off:no_account")
    assert sms.read_last() == "off:no_account"
    assert (tmp_path / sms.LAST_NAME).stat().st_mode & 0o777 == 0o600
    with pytest.raises(ValueError):
        sms.record_last(new_code())


def run_probe(fake: FakeBeeper, clock: Clock, wait_s: float = 12) -> int:
    return sms.probe(
        sms.Beeper(fake.port, TOKEN),
        SENDER,
        wait_s,
        print,
        clock=clock,
        sleep=clock.sleep,
    )


def test_probe_never_prints_text_or_digits(
    fake: FakeBeeper, capsys: pytest.CaptureFixture[str]
) -> None:
    code = new_code()
    text = f"Ihr Visana Bestaetigungscode lautet {code}"
    clock = Clock()
    clock.hooks[1] = lambda: fake.add("v1", text, at=clock.now - 2, chat="!v")
    assert run_probe(fake, clock) == 0
    out, err = capsys.readouterr()
    for stream in (out, err):
        assert code not in stream and "Bestaetigungscode" not in stream
    rows = [json.loads(line) for line in out.splitlines()]
    hits = [r for r in rows if "via" in r]
    assert {r["via"] for r in hits} == {"search", "chats"}
    assert all(r["digit_runs"] == [6] and r["chatID"] == "!v" for r in hits)
    assert [r["chat_seen_before"] for r in hits] == [False, True]
    assert all(0 < r["times"]["timestamp"] <= 4 for r in hits)


def test_probe_prints_nothing_about_other_messages(
    fake: FakeBeeper, capsys: pytest.CaptureFixture[str]
) -> None:
    phone = "+4179" + str(1000000 + secrets.randbelow(8999999))
    chat = "!other-" + secrets.token_hex(4)
    clock = Clock()

    def arrive() -> None:
        fake.chat(chat, phone=phone, name="Friend")
        fake.add("o1", f"call me at {phone}", at=clock.now, chat=chat, sender="Friend")

    clock.hooks[1] = arrive
    assert run_probe(fake, clock) == 0
    out, err = capsys.readouterr()
    for stream in (out, err):
        assert phone not in stream and chat not in stream and "Friend" not in stream
    assert out.count("other message (ignored)") == 1


def test_child_prints_only_protocol_lines_and_exits_on_closed_pipe(
    fake: FakeBeeper, tmp_path: Path
) -> None:
    fake.add("old", f"Visana Code {new_code()}", at=time.time() - 5)
    cmd = [sys.executable, "-I", str(MODULE), "-w", "visana", "-t", "60"]
    env = _env(fake, tmp_path, TOKEN)
    for how in ("stdin", "sigterm"):
        start = time.monotonic()
        with subprocess.Popen(
            cmd,
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        ) as child:
            assert child.stdout is not None and child.stdin is not None
            assert json.loads(child.stdout.readline()) == {"armed": True}
            if how == "stdin":
                child.stdin.close()
            else:
                child.send_signal(signal.SIGTERM)
            rc = child.wait(timeout=15)
            rest = child.stdout.read()
            err = child.stderr.read() if child.stderr else ""
        assert (rc, rest, err) == (0, "", ""), how
        assert time.monotonic() - start < 15
    # no token: one protocol line, nothing else
    res = subprocess.run(
        cmd,
        env=_env(fake, tmp_path, None),
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert (res.stdout, res.stderr) == ('{"ok": false, "why": "token"}\n', "")


def test_help_and_bad_arguments() -> None:
    res = subprocess.run(
        [sys.executable, "-I", str(MODULE), "-h"],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert res.returncode == 0 and "-w visana" in res.stdout
    for argv in (["-w", "nosuch"], ["-w", "visana", "-t", "361"]):
        res = subprocess.run(
            [sys.executable, "-I", str(MODULE), *argv],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        assert res.returncode == 2
