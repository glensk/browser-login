#!/usr/bin/env python3
"""One SMS login code from Beeper's Google Messages bridge (tp#2775 B3).

agent-login never holds the Beeper token: for one attended ``-L`` run it
starts this file ONCE as a child under ``secret-run``::

    secret-run -e BEEPER_TOKEN=beeper-desktop-api -- python3 -I agent_login_sms.py -w visana -t 360

Child protocol (``-w SITE``, D1): one JSON line per event on stdout, nothing
else. First ``{"armed": true}`` once the baseline is read, or ``{"ok": false,
"why": "no_account" | "unreadable" | "token"}``. Then exactly one result:
``{"ok": true, "code": "<digits>"}`` or ``{"ok": false, "why": "no_sms" |
"several" | "unreadable" | "timeout"}``. stderr carries ``why`` words only.
The child exits on SIGTERM, on EOF of a piped stdin, or on a closed stdout.

The filter (D2) is functional, not a privacy boundary (Albert, Q1: agents may
read every SMS): it makes the reader release the ONE code meant for the ONE
site — a message of a ``gmessages*`` account, from an exact allowlisted
sender identity, carrying the site's keyword and exactly one code-shaped
match, with an id not seen at arm time, an original time after arm − 30 s,
and a code whose keyed digest is not in the baseline; that one new code must
repeat in two consecutive polls. Two new codes: ``several`` (Albert types).

Stdlib only; the child runs under ``python -I`` (no sibling imports). Only GET
requests, only to ``http://127.0.0.1:23373`` (``AGENT_LOGIN_SMS_PORT`` moves
the port, a test hook; the host is fixed), no proxies, no redirects, a 5-s
timeout per call. The token comes from ``BEEPER_TOKEN`` only, and ``-c``
never reads it. Nothing here writes a file except ``record_last`` (the
one-word ``sms-last`` state, called by the Safari machine, never with a code).
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import secrets
import select
import signal
import stat
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

BEEPER_HOST = "127.0.0.1"
BEEPER_PORT = 23373
PORT_ENV = "AGENT_LOGIN_SMS_PORT"  # test hook: the host stays 127.0.0.1
TOKEN_ENV = "BEEPER_TOKEN"
CALL_TIMEOUT_S = 5.0
POLL_S = 4.0
MAX_WAIT_S = 360  # open + login + the 240-s SMS wait (D3)
SKEW_S = 30.0  # clock skew allowed between the phone/bridge and this Mac
SEARCH_LIMIT = 20  # the API's maximum page size
MAX_PAGES = 50  # a window this busy is unreadable, never half-read
MAX_FAILED_POLLS = 3  # consecutive failed polls before `unreadable`
STATE_DIR = Path.home() / ".local/state/agent-login"
LAST_NAME = "sms-last"
_LAST_RE = re.compile(r"(filled|albert|off:[a-z_]{1,30})")
# Message fields that are text, never a time (the probe prints times only)
_TEXT_KEYS = frozenset({"text", "fullTitle", "id", "chatID", "senderID", "senderName"})

WHYS_ARM = ("no_account", "unreadable", "token")
WHYS_RESULT = ("no_sms", "several", "unreadable", "timeout")


@dataclass(frozen=True)
class SmsSender:
    """One site's SMS (D2). ``senders``: exact identities (``senderID``,
    ``senderName``, the sender participant's ``phoneNumber``/``fullName``/
    ``username``), case-folded, no substring; an empty tuple never matches.
    ``code_re`` has one capture group and must match exactly once.
    ``time_field``: the message field holding the SMS's original time.
    ``source``: ``search`` (account-wide ``/v1/messages/search``) or
    ``chats`` (the chat-list fallback, A8)."""

    senders: tuple[str, ...]
    keyword_re: str
    code_re: str
    account_prefix: str = "gmessages"
    time_field: str = "timestamp"
    source: str = "search"


# The allowlist: changed only by a reviewed commit. visana's senders come from
# B4's shadow run (until then it never matches, so Albert types).
SMS_SITES: dict[str, SmsSender] = {
    "visana": SmsSender(
        senders=(),
        keyword_re=r"(?i)\bvisana\b",
        code_re=r"(?<!\d)(\d{6})(?!\d)",
    ),
}


class BeeperError(Exception):
    """A failed Beeper call; ``str()`` is a why word, never a body."""


class _PipeClosed(Exception):
    """The parent went away (stdout closed or piped stdin at EOF)."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuses every redirect (the token never follows one anywhere)."""

    # urllib's own signature
    # pylint: disable-next=too-many-positional-arguments
    def redirect_request(  # type: ignore[override]
        self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str
    ) -> None:
        raise BeeperError("redirect")


class Beeper:
    """GET-only client for Beeper Desktop's local API on 127.0.0.1."""

    def __init__(self, port: int, token: str | None) -> None:
        self.base = f"http://{BEEPER_HOST}:{int(port)}"
        self._token = token
        self._opener = urllib.request.OpenerDirector()
        for handler in (
            urllib.request.ProxyHandler({}),  # never $http_proxy
            urllib.request.HTTPHandler(),
            urllib.request.HTTPDefaultErrorHandler(),
            urllib.request.HTTPErrorProcessor(),
            _NoRedirect(),
        ):
            self._opener.add_handler(handler)

    def get(self, path: str, params: Iterable[tuple[str, str]] = ()) -> Any:
        """The decoded JSON of one GET; BeeperError(``token`` | ``redirect``
        | ``unreachable`` | ``unreadable``) on any failure."""
        if not path.startswith("/v1/"):
            raise BeeperError("unreadable")
        query = urllib.parse.urlencode(list(params))
        url = self.base + path + ("?" + query if query else "")
        req = urllib.request.Request(url, method="GET")
        req.add_header("Accept", "application/json")
        if self._token:
            req.add_header("Authorization", "Bearer " + self._token)
        try:
            with self._opener.open(req, timeout=CALL_TIMEOUT_S) as resp:
                if resp.status != 200:
                    raise BeeperError("unreadable")
                body = resp.read()
        except urllib.error.HTTPError as exc:
            if 300 <= exc.code < 400:
                raise BeeperError("redirect") from None
            raise BeeperError(
                "token" if exc.code in (401, 403) else "unreadable"
            ) from None
        except (urllib.error.URLError, OSError):
            raise BeeperError("unreachable") from None
        try:
            return json.loads(body)
        except ValueError:
            raise BeeperError("unreadable") from None


def beeper_port() -> int:
    """The API port (``AGENT_LOGIN_SMS_PORT`` in tests, else 23373)."""
    raw = os.environ.get(PORT_ENV, "")
    return int(raw) if raw.isdigit() and 0 < int(raw) < 65536 else BEEPER_PORT


def _iso(ts: float) -> str:
    dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    return dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse_time(value: object) -> float | None:
    """Epoch seconds of an ISO 8601 string, None when it is not one."""
    if not isinstance(value, str) or not 10 <= len(value) <= 40 or "T" not in value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        return None
    return dt.timestamp()


def gm_accounts(client: Beeper, prefix: str) -> list[str]:
    """The ids of every account whose ``accountID`` starts with `prefix`."""
    data = client.get("/v1/accounts")
    if isinstance(data, dict):
        data = data.get("items", [])
    if not isinstance(data, list):
        raise BeeperError("unreadable")
    out = []
    for acc in data:
        aid = acc.get("accountID") if isinstance(acc, dict) else None
        if isinstance(aid, str) and aid.startswith(prefix):
            out.append(aid)
    return out


def _page(data: Any) -> tuple[list[dict[str, Any]], bool, str]:
    if not isinstance(data, dict) or not isinstance(data.get("items"), list):
        raise BeeperError("unreadable")
    items = [m for m in data["items"] if isinstance(m, dict)]
    cursor = data.get("oldestCursor")
    more = bool(data.get("hasMore")) and isinstance(cursor, str) and bool(cursor)
    return items, more, cursor if isinstance(cursor, str) else ""


Window = tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]


def search_window(client: Beeper, accounts: list[str], after: float) -> Window:
    """(messages, {chatID: chat}) of `accounts` after `after`, account-wide
    ``/v1/messages/search``, paged with the cursor to the end."""
    base = [("accountIDs", a) for a in accounts] + [
        ("dateAfter", _iso(after)),
        ("sender", "others"),
        ("limit", str(SEARCH_LIMIT)),
        ("excludeLowPriority", "false"),
        ("includeMuted", "true"),
    ]
    msgs: list[dict[str, Any]] = []
    chats: dict[str, dict[str, Any]] = {}
    params = list(base)
    for _ in range(MAX_PAGES):
        data = client.get("/v1/messages/search", params)
        items, more, cursor = _page(data)
        msgs += items
        raw_chats = data.get("chats")
        if isinstance(raw_chats, dict):
            chats.update({k: v for k, v in raw_chats.items() if isinstance(v, dict)})
        if not more:
            return msgs, chats
        params = base + [("cursor", cursor), ("direction", "before")]
    raise BeeperError("unreadable")


def chats_window(client: Beeper, accounts: list[str], after: float) -> Window:
    """The same window through the chat list (A8 fallback): every chat of
    `accounts` with activity after `after`, then its messages after `after`."""
    base = [("accountIDs", a) for a in accounts] + [("limit", "200")]
    chats: dict[str, dict[str, Any]] = {}
    params = list(base)
    for _ in range(MAX_PAGES):
        items, more, cursor = _page(client.get("/v1/chats", params))
        old = False
        for chat in items:
            last = parse_time(chat.get("lastActivity"))
            if last is not None and last <= after:
                old = True  # ordered by last activity, newest first
                continue
            if isinstance(chat.get("id"), str):
                chats[chat["id"]] = chat
        if old or not more:
            break
        params = base + [("cursor", cursor), ("direction", "before")]
    else:
        raise BeeperError("unreadable")
    msgs: list[dict[str, Any]] = []
    for cid in chats:
        path = "/v1/chats/" + urllib.parse.quote(cid, safe="") + "/messages"
        params = []
        for _ in range(MAX_PAGES):
            items, more, cursor = _page(client.get(path, params))
            fresh = [m for m in items if (parse_time(m.get("timestamp")) or 0) > after]
            msgs += fresh
            if len(fresh) < len(items) or not more:
                break
            params = [("cursor", cursor), ("direction", "before")]
        else:
            raise BeeperError("unreadable")
    return msgs, chats


def list_window(
    client: Beeper, accounts: list[str], after: float, source: str
) -> Window:
    """The window by the site's `source` (``search`` | ``chats``)."""
    if source == "chats":
        return chats_window(client, accounts, after)
    return search_window(client, accounts, after)


def sender_participant(msg: dict[str, Any], chat: dict[str, Any] | None) -> dict:
    """The chat participant that sent `msg` (by id; in a single chat the one
    participant that is not Albert), else {}."""
    if not isinstance(chat, dict):
        return {}
    parts = chat.get("participants")
    items = parts.get("items") if isinstance(parts, dict) else None
    if not isinstance(items, list):
        return {}
    users = [p for p in items if isinstance(p, dict)]
    for user in users:
        if user.get("id") == msg.get("senderID"):
            return user
    others = [u for u in users if not u.get("isSelf")]
    return others[0] if chat.get("type") == "single" and len(others) == 1 else {}


def identities(msg: dict[str, Any], chat: dict[str, Any] | None) -> set[str]:
    """Every case-folded identity of the message's sender."""
    user = sender_participant(msg, chat)
    raw = [msg.get("senderID"), msg.get("senderName")] + [
        user.get(k) for k in ("id", "phoneNumber", "fullName", "username")
    ]
    return {v.casefold() for v in raw if isinstance(v, str) and v}


@dataclass
class SmsBaseline:
    """What existed at arm time: the message ids, and keyed digests (per-run
    random key, memory only) of every code-shaped match in those messages."""

    key: bytes
    arm: float
    ids: set[str] = field(default_factory=set)
    digests: set[str] = field(default_factory=set)

    def digest(self, code: str) -> str:
        return hmac.new(self.key, code.encode(), hashlib.sha256).hexdigest()


def take_baseline(
    msgs: list[dict[str, Any]], sender: SmsSender, arm: float
) -> SmsBaseline:
    """The baseline of `msgs` (any sender: wider is safer)."""
    base = SmsBaseline(secrets.token_bytes(32), arm)
    for msg in msgs:
        if isinstance(msg.get("id"), str):
            base.ids.add(msg["id"])
        text = msg.get("text")
        if isinstance(text, str):
            base.digests |= {base.digest(c) for c in re.findall(sender.code_re, text)}
    return base


# A flat validator: one early return per rule.
# pylint: disable-next=too-many-return-statements
def candidate_code(
    msg: dict[str, Any],
    chat: dict[str, Any] | None,
    base: SmsBaseline,
    sender: SmsSender,
) -> str | None:
    """The code of one message when it passes every D2 rule, else None."""
    if msg.get("id") in base.ids or not isinstance(msg.get("id"), str):
        return None
    if not str(msg.get("accountID", "")).startswith(sender.account_prefix):
        return None
    if msg.get("isSender") is not False or msg.get("isDeleted"):
        return None
    sent = parse_time(msg.get(sender.time_field))
    if sent is None or sent <= base.arm - SKEW_S:
        return None
    allowed = {s.casefold() for s in sender.senders}
    if not allowed & identities(msg, chat):
        return None
    text = msg.get("text")
    if not isinstance(text, str) or not re.search(sender.keyword_re, text):
        return None
    found = re.findall(sender.code_re, text)
    if len(found) != 1 or not isinstance(found[0], str):
        return None
    code = found[0]
    return None if base.digest(code) in base.digests else code


def find_sms_code(
    msgs: list[dict[str, Any]],
    chats: dict[str, dict[str, Any]],
    base: SmsBaseline,
    sender: SmsSender,
) -> tuple[str | None, str]:
    """(code, '') when the new allowlisted messages hold exactly ONE distinct
    new code, else (None, ``no_sms`` | ``several``)."""
    new: set[str] = set()
    for msg in msgs:
        code = candidate_code(msg, chats.get(str(msg.get("chatID"))), base, sender)
        if code is not None:
            new.add(code)
    if len(new) == 1:
        return next(iter(new)), ""
    return None, "several" if new else "no_sms"


Emit = Callable[[dict[str, Any]], None]


def wait_code(
    client: Beeper,
    sender: SmsSender,
    wait_s: float,
    emit: Emit,
    *,
    clock: Callable[[], float] = time.time,
    sleep: Callable[[float], None] = time.sleep,
) -> bool:
    """The ``-w`` run: arm, then poll until one code repeats in two polls.
    Emits the protocol lines; True when a code was released."""
    start = clock()
    deadline = start + wait_s
    try:
        accounts = gm_accounts(client, sender.account_prefix)
        if not accounts:
            emit({"ok": False, "why": "no_account"})
            return False
        msgs, _chats = list_window(client, accounts, start - SKEW_S, sender.source)
    except BeeperError as exc:
        emit({"ok": False, "why": "token" if str(exc) == "token" else "unreadable"})
        return False
    base = take_baseline(msgs, sender, start)
    del msgs
    emit({"armed": True})
    last: str | None = None
    failed = 0
    while clock() < deadline:
        sleep(min(POLL_S, max(0.0, deadline - clock())))
        try:
            msgs, chats = list_window(client, accounts, start - SKEW_S, sender.source)
        except BeeperError:
            failed += 1
            if failed >= MAX_FAILED_POLLS:
                emit({"ok": False, "why": "unreadable"})
                return False
            continue
        failed = 0
        code, why = find_sms_code(msgs, chats, base, sender)
        del msgs, chats
        if why == "several":
            emit({"ok": False, "why": "several"})
            return False
        if code is not None and code == last:
            emit({"ok": True, "code": code})
            code = last = None
            return True
        last = code
    emit({"ok": False, "why": "timeout"})
    return False


def _rel(value: object, arm: float) -> float | None:
    ts = parse_time(value)
    return None if ts is None else round(ts - arm, 1)


def probe_line(
    msg: dict[str, Any],
    chat: dict[str, Any] | None,
    *,
    via: str,
    arm: float,
    now: float,
    chat_seen: bool,
) -> dict[str, Any]:
    """The metadata of one matching message (B4): never its text or digits."""
    user = sender_participant(msg, chat)
    times = {
        k: _rel(v, arm)
        for k, v in msg.items()
        if k not in _TEXT_KEYS and parse_time(v) is not None
    }
    sort_key = msg.get("sortKey")
    out: dict[str, Any] = {
        "via": via,
        "t": round(now - arm, 1),
        "chatID": msg.get("chatID"),
        "chat_seen_before": chat_seen,
        "senderID": msg.get("senderID"),
        "senderName": msg.get("senderName"),
        "phoneNumber": user.get("phoneNumber"),
        "fullName": user.get("fullName"),
        "times": times,
        "sortKey": sort_key,
    }
    if isinstance(sort_key, str) and sort_key.isdigit() and len(sort_key) == 13:
        out["sortKey_rel"] = round(int(sort_key) / 1000 - arm, 1)  # epoch ms?
    text = msg.get("text")
    out["digit_runs"] = (
        [len(r) for r in re.findall(r"\d+", text)] if isinstance(text, str) else []
    )
    return out


def probe(
    client: Beeper,
    sender: SmsSender,
    wait_s: float,
    out: Callable[[str], None],
    *,
    clock: Callable[[], float] = time.time,
    sleep: Callable[[float], None] = time.sleep,
) -> int:
    """The ``-p`` run (B4): arm like ``-w``, then for the whole `wait_s`
    report every new message: metadata for one that carries the site's
    keyword (first seen via search and via the chat list), else only
    ``other message (ignored)``. Never a text or a digit of it."""
    start = clock()
    deadline = start + wait_s
    after = start - SKEW_S
    try:
        accounts = gm_accounts(client, sender.account_prefix)
        if not accounts:
            out(json.dumps({"ok": False, "why": "no_account"}))
            return 1
        known = {
            str(m.get("id"))
            for via in ("search", "chats")
            for m in list_window(client, accounts, after, via)[0]
        }
    except BeeperError as exc:
        out(json.dumps({"ok": False, "why": str(exc)}))
        return 1
    out(json.dumps({"probe": "armed", "accounts": len(accounts)}))
    seen: dict[str, set[str]] = {"search": set(), "chats": set()}
    ignored: set[str] = set()
    chats_seen: set[str] = set()
    while clock() < deadline:
        sleep(min(POLL_S, max(0.0, deadline - clock())))
        for via in ("search", "chats"):
            try:
                msgs, chats = list_window(client, accounts, after, via)
            except BeeperError as exc:
                out(json.dumps({"via": via, "error": str(exc)}))
                continue
            for msg in msgs:
                mid = str(msg.get("id"))
                if mid in known or mid in seen[via] or mid in ignored:
                    continue
                text = msg.get("text")
                if not (
                    str(msg.get("accountID", "")).startswith(sender.account_prefix)
                    and isinstance(text, str)
                    and re.search(sender.keyword_re, text)
                ):
                    ignored.add(mid)
                    out("other message (ignored)")
                    continue
                seen[via].add(mid)
                cid = str(msg.get("chatID"))
                line = probe_line(
                    msg,
                    chats.get(cid),
                    via=via,
                    arm=start,
                    now=clock(),
                    chat_seen=cid in chats_seen,
                )
                chats_seen.add(cid)
                out(json.dumps(line))
    out(json.dumps({"probe": "done", "matched": len(seen["search"] | seen["chats"])}))
    return 0


def _state_dir() -> Path:
    env = os.environ.get("AGENT_LOGIN_STATE_FILE")
    return Path(env).parent if env else STATE_DIR


def read_last() -> str | None:
    """The last ``Outcome.sms`` word an attended run recorded, else None."""
    try:
        word = (_state_dir() / LAST_NAME).read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return word if _LAST_RE.fullmatch(word) else None


def record_last(word: str) -> None:
    """Record one ``Outcome.sms`` word (0600, atomic); anything that is not
    ``filled`` | ``albert`` | ``off:<why>`` is refused (never a code)."""
    if not _LAST_RE.fullmatch(word):
        raise ValueError("not an sms outcome word")
    path = _state_dir() / LAST_NAME
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(word + "\n")
    tmp.replace(path)


def check(client: Beeper) -> tuple[int, str]:
    """``-c`` (D5): never the token. Beeper's token-less ``/v1/info`` says
    whether the API runs (it names no account), so the line is
    ``unreachable``, else the last recorded run word, else ``unknown``."""
    try:
        info = client.get("/v1/info")
    except BeeperError:
        return 1, "gmessages: unreachable"
    server = info.get("server") if isinstance(info, dict) else None
    if not isinstance(server, dict) or server.get("status") != "running":
        return 1, "gmessages: unreachable"
    last = read_last()
    return 0, f"gmessages: last:{last}" if last else "gmessages: unknown"


def _emit_stdout(obj: dict[str, Any]) -> None:
    try:
        sys.stdout.write(json.dumps(obj) + "\n")
        sys.stdout.flush()
    except (BrokenPipeError, ValueError):
        raise _PipeClosed from None


def _sleep_watching_stdin(seconds: float) -> None:
    """Sleep; a piped stdin at EOF means the parent is gone."""
    try:
        piped = stat.S_ISFIFO(os.fstat(0).st_mode)
    except OSError:
        piped = False
    if not piped:
        time.sleep(seconds)
        return
    end = time.monotonic() + seconds
    while (left := end - time.monotonic()) > 0:
        ready, _w, _x = select.select([0], [], [], left)
        if ready and not os.read(0, 4096):
            raise _PipeClosed


def _on_sigterm(_signum: int, _frame: object) -> None:
    raise _PipeClosed


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agent_login_sms.py",
        description=(
            "Read ONE SMS login code from Beeper's Google Messages bridge "
            "(tp#2775). -w is agent-login's child; -p is the B4 shadow probe; "
            "-c is the token-less health check."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  secret-run -e BEEPER_TOKEN=beeper-desktop-api -- "
            "python3 -I agent_login_sms.py -w visana -t 360\n"
            "  secret-run -e BEEPER_TOKEN=beeper-desktop-api -- "
            "python3 -I agent_login_sms.py -p visana -t 360\n"
            "  agent_login_sms.py -c\n"
            f"sites: {', '.join(sorted(SMS_SITES))}"
        ),
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "-w", "--wait", metavar="SITE", help="child: one code for SITE (JSON lines)"
    )
    mode.add_argument(
        "-p", "--probe", metavar="SITE", help="print SMS metadata only (B4)"
    )
    mode.add_argument(
        "-c", "--check", action="store_true", help="health line, never the token"
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=MAX_WAIT_S,
        metavar="SECONDS",
        help=f"lifetime of -w/-p (1-{MAX_WAIT_S}, default {MAX_WAIT_S})",
    )
    return parser


# pylint: disable-next=too-many-return-statements
def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.check:
        rc, line = check(Beeper(beeper_port(), None))
        print(line)
        return rc
    site = args.wait or args.probe
    if site not in SMS_SITES:
        print("unknown_site", file=sys.stderr)
        return 2
    if not 1 <= args.timeout <= MAX_WAIT_S:
        print("bad_timeout", file=sys.stderr)
        return 2
    sender = SMS_SITES[site]
    token = os.environ.pop(TOKEN_ENV, "")
    signal.signal(signal.SIGTERM, _on_sigterm)
    try:
        if not token:
            _emit_stdout({"ok": False, "why": "token"})
            return 1
        client = Beeper(beeper_port(), token)
        del token
        if args.probe:
            return probe(
                client,
                sender,
                args.timeout,
                _emit_line,
                sleep=_sleep_watching_stdin,
            )
        released = wait_code(
            client, sender, args.timeout, _emit_stdout, sleep=_sleep_watching_stdin
        )
        return 0 if released else 1
    except _PipeClosed:
        _quiet_stdout()
        return 0
    except Exception as exc:  # pylint: disable=broad-exception-caught
        print(type(exc).__name__, file=sys.stderr)  # a class name, never a value
        try:
            _emit_stdout({"ok": False, "why": "unreadable"})
        except _PipeClosed:
            _quiet_stdout()
        return 1


def _emit_line(line: str) -> None:
    try:
        sys.stdout.write(line + "\n")
        sys.stdout.flush()
    except (BrokenPipeError, ValueError):
        raise _PipeClosed from None


def _quiet_stdout() -> None:
    """Point stdout at /dev/null so the exit flush cannot raise again."""
    try:
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
    except (OSError, ValueError):
        pass


if __name__ == "__main__":
    sys.exit(main())
