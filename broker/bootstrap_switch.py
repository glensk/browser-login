#!/usr/bin/env python3
"""Switch the broker's collections by ID, or roll the switch back.

Run by ``install.sh -C`` / ``-X`` / ``-B`` (as root). A switch names the login
collection (``-C ORG_ID:COLL_ID``) and/or the secrets collection
(``-X ORG_ID:COLL_ID``); each exact ID pair must appear in the broker account's
visible collections (``-v FILE``: the TSV ``daemon.py -C`` prints, ``-`` =
stdin), else nothing is written. The rewrite keeps the three secret fields,
goes through a 0600 temp file + fsync + rename, keeps the owner of the old file
and saves the previous file as ``bootstrap.json.prev-<UTC>``. ``-B`` restores
the newest ``.prev-*`` (the current file becomes a ``.prev-*`` itself, so
nothing is lost). Collections are always identified by IDs, never by name.
No secret value is ever printed.

tp#991: ``-W MODE`` sets the agent_script gate (``secret_gate``:
collections | report | agent_script) and stamps ``secret_gate_since`` (UTC);
``-D`` drops the legacy secrets collection (``secrets_organization_id`` +
``secrets_collection_id``) — only while the gate is ``agent_script`` and the
listing ``-v FILE`` (``daemon.py -g -j``, ``-`` = stdin) parses, is not empty
and holds ZERO rows of kind ``secret``, in any state.

Examples:
  bootstrap_switch.py -H /var/db/login-broker -v visible.tsv -C ORG:COLL
  daemon.py -C | bootstrap_switch.py -H /var/db/login-broker -v - -X ORG:COLL
  bootstrap_switch.py -H /var/db/login-broker -W report
  daemon.py -g -j | bootstrap_switch.py -H /var/db/login-broker -v - -D
  bootstrap_switch.py -H /var/db/login-broker -B
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

if __package__ in (None, ""):  # run as a script: make `broker` importable
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# pylint: disable=wrong-import-position
from broker.vault import (  # noqa: E402
    GATE_AGENT_SCRIPT,
    KIND_LOGIN,
    KIND_SECRET,
    SECRET_GATES,
    BwBootstrap,
    VaultError,
)

# pylint: enable=wrong-import-position

BOOTSTRAP = "bootstrap.json"
PREV_PREFIX = "bootstrap.json.prev-"
ID_RE = re.compile(r"^[A-Za-z0-9-]{1,64}$")
KEEP_KEYS = (
    "client_id",
    "client_secret",
    "master_password",
    "server_url",
    "collection_id",
    "organization_id",
    "secrets_organization_id",
    "secrets_collection_id",
    "secret_gate",
    "secret_gate_since",
)


class SwitchError(RuntimeError):
    """Refused; nothing was written."""


def parse_pair(text: str) -> tuple[str, str]:
    """``ORG_ID:COLL_ID`` -> (org, coll)."""
    org, sep, coll = text.partition(":")
    if not sep or not ID_RE.match(org) or not ID_RE.match(coll):
        raise SwitchError(f"expected ORG_ID:COLL_ID, got {text!r}")
    return org, coll


def visible_pairs(tsv: str) -> set[tuple[str, str]]:
    """(org_id, collection_id) pairs of ``daemon.py -C`` output."""
    pairs = set()
    for line in tsv.splitlines():
        cols = line.split("\t")
        if len(cols) >= 3 and cols[0] and cols[2]:
            pairs.add((cols[0], cols[2]))
    return pairs


def _utc_stamp() -> str:
    return time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())


def _write_like(path: Path, data: bytes, owner: os.stat_result) -> None:
    """Atomic 0600 write of `data` to `path`, owned like `owner`."""
    fd, tmp = tempfile.mkstemp(prefix=".bootstrap.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, 0o600)
        if os.geteuid() == 0:
            os.chown(tmp, owner.st_uid, owner.st_gid)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    dfd = os.open(str(path.parent), os.O_RDONLY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


def _keep_previous(home: Path, data: bytes, owner: os.stat_result) -> Path:
    stamp = _utc_stamp()
    prev = home / f"{PREV_PREFIX}{stamp}"
    n = 1
    while prev.exists():
        n += 1
        prev = home / f"{PREV_PREFIX}{stamp}-{n}"
    _write_like(prev, data, owner)
    return prev


def _load_raw(path: Path) -> tuple[dict[str, Any], bytes]:
    try:
        BwBootstrap.load(path)
        raw = path.read_bytes()
        data = json.loads(raw)
    except (VaultError, OSError, ValueError) as exc:
        raise SwitchError(f"{path} is not a valid bootstrap ({exc})") from None
    return data, raw


def switch(
    home: Path,
    visible: set[tuple[str, str]],
    login: tuple[str, str] | None,
    secrets: tuple[str, str] | None,
) -> tuple[bool, Path | None]:
    """Rewrite the bootstrap; (changed, previous file). Raises SwitchError."""
    for label, pair in (("login", login), ("secrets", secrets)):
        if pair is not None and pair not in visible:
            raise SwitchError(
                f"{label} collection {pair[0]}:{pair[1]} is not visible to the broker "
                "account (check `install.sh -c`)"
            )
    path = home / BOOTSTRAP
    old, raw = _load_raw(path)
    new = {k: old[k] for k in KEEP_KEYS if k in old}
    if login is not None:
        new["organization_id"], new["collection_id"] = login
    if secrets is not None:
        new["secrets_organization_id"], new["secrets_collection_id"] = secrets
    if new == old:
        return False, None
    owner = path.stat()
    prev = _keep_previous(home, raw, owner)
    _write_like(path, json.dumps(new).encode(), owner)
    return True, prev


def _utc_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _rewrite(home: Path, new: dict[str, Any], raw: bytes) -> Path:
    path = home / BOOTSTRAP
    owner = path.stat()
    prev = _keep_previous(home, raw, owner)
    _write_like(path, json.dumps(new).encode(), owner)
    return prev


def set_gate(home: Path, mode: str) -> tuple[bool, Path | None]:
    """Set ``secret_gate`` (+ ``secret_gate_since``); (changed, previous)."""
    if mode not in SECRET_GATES:
        raise SwitchError(f"unknown gate {mode!r} (one of {', '.join(SECRET_GATES)})")
    path = home / BOOTSTRAP
    old, raw = _load_raw(path)
    if old.get("secret_gate") == mode:
        return False, None
    new = {k: old[k] for k in KEEP_KEYS if k in old}
    new["secret_gate"] = mode
    new["secret_gate_since"] = _utc_iso()
    return True, _rewrite(home, new, raw)


def listing_kinds(text: str) -> tuple[int, int]:
    """(rows of kind login, rows of kind secret) of a ``daemon.py -g -j``
    listing; any line that is not such a row raises SwitchError (fail closed)."""
    login = secret = 0
    for n, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except ValueError:
            raise SwitchError(f"listing line {n} is not JSON") from None
        kind = row.get("kind") if isinstance(row, dict) else None
        if kind == KIND_LOGIN:
            login += 1
        elif kind == KIND_SECRET:
            secret += 1
        else:
            raise SwitchError(f"listing line {n} has no kind login|secret")
    return login, secret


def drop_secrets(home: Path, listing: str) -> tuple[bool, Path | None]:
    """Remove the legacy secrets collection ids; (changed, previous)."""
    path = home / BOOTSTRAP
    old, raw = _load_raw(path)
    if old.get("secret_gate") != GATE_AGENT_SCRIPT:
        raise SwitchError(
            "refused: the gate is not agent_script (install.sh -W agent_script first)"
        )
    login, secret = listing_kinds(listing)
    if login + secret == 0:
        raise SwitchError("refused: the listing is empty (is it `daemon.py -g -j`?)")
    if secret:
        raise SwitchError(
            f"refused: {secret} item(s) still in the legacy secrets collection — "
            "move or retire each first"
        )
    dropped = ("secrets_organization_id", "secrets_collection_id")
    if not any(k in old for k in dropped):
        return False, None
    new = {k: old[k] for k in KEEP_KEYS if k in old and k not in dropped}
    return True, _rewrite(home, new, raw)


def previous_files(home: Path) -> list[Path]:
    """``bootstrap.json.prev-*``, oldest first."""
    return sorted(home.glob(f"{PREV_PREFIX}*"))


def rollback(home: Path) -> tuple[Path, Path]:
    """Restore the newest ``.prev-*``; (restored file, where the current went)."""
    prevs = previous_files(home)
    if not prevs:
        raise SwitchError(f"no {PREV_PREFIX}* in {home} to roll back to")
    newest = prevs[-1]
    _data, prev_raw = _load_raw(newest)
    path = home / BOOTSTRAP
    _cur, cur_raw = _load_raw(path)
    owner = path.stat()
    saved = _keep_previous(home, cur_raw, owner)
    _write_like(path, prev_raw, owner)
    newest.unlink()
    return newest, saved


def describe(home: Path) -> str:
    """The IDs the bootstrap names now (no secret)."""
    boot = BwBootstrap.load(home / BOOTSTRAP)
    login = f"{boot.organization_id or '?'}:{boot.collection_id}"
    if boot.secrets_collection_id:
        secrets = f"{boot.secrets_organization_id or '?'}:{boot.secrets_collection_id}"
    else:
        secrets = "none"
    return f"login {login}, secrets {secrets}, gate {boot.secret_gate}"


def _gate_action(args: argparse.Namespace, home: Path) -> int:
    """``-W`` / ``-D`` (raises SwitchError)."""
    if args.secret_gate:
        changed, prev = set_gate(home, args.secret_gate)
    else:
        if not args.visible:
            raise SwitchError("-D needs -v FILE (the output of `daemon.py -g -j`)")
        text = (
            sys.stdin.read()
            if args.visible == "-"
            else Path(args.visible).read_text(encoding="utf-8")
        )
        changed, prev = drop_secrets(home, text)
    if not changed:
        print(f"✅ bootstrap.json unchanged ({describe(home)})")
        return 0
    assert prev is not None
    print(
        f"✅ bootstrap.json switched ({describe(home)}); previous kept as {prev.name}"
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    p = argparse.ArgumentParser(
        prog="bootstrap_switch.py",
        description=(__doc__ or "").split("\n\n", 1)[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  bootstrap_switch.py -H /var/db/login-broker -v visible.tsv -C ORG:COLL\n"
            "  bootstrap_switch.py -H /var/db/login-broker -v - -X ORG:COLL\n"
            "  bootstrap_switch.py -H /var/db/login-broker -W report\n"
            "  daemon.py -g -j | bootstrap_switch.py -H /var/db/login-broker -v - -D\n"
            "  bootstrap_switch.py -H /var/db/login-broker -B\n"
        ),
    )
    p.add_argument("-H", "--home", required=True, help="broker home directory")
    p.add_argument(
        "-v",
        "--visible",
        metavar="FILE",
        help="visible collections TSV from `daemon.py -C` (- = stdin)",
    )
    p.add_argument(
        "-C", "--login-collection", metavar="ORG_ID:COLL_ID", help="login collection"
    )
    p.add_argument(
        "-X",
        "--secrets-collection",
        metavar="ORG_ID:COLL_ID",
        help="secrets collection",
    )
    p.add_argument(
        "-W",
        "--secret-gate",
        metavar="MODE",
        choices=SECRET_GATES,
        help="set the agent_script gate: " + " | ".join(SECRET_GATES),
    )
    p.add_argument(
        "-D",
        "--drop-secrets-collection",
        action="store_true",
        help="drop the legacy secrets collection (gate agent_script, -v = the "
        "`daemon.py -g -j` listing with zero kind=secret rows)",
    )
    p.add_argument(
        "-B",
        "--rollback",
        action="store_true",
        help="restore the newest bootstrap.json.prev-*",
    )
    args = p.parse_args(argv)
    home = Path(args.home)
    try:
        modes = [
            bool(args.login_collection or args.secrets_collection),
            bool(args.secret_gate),
            args.drop_secrets_collection,
            args.rollback,
        ]
        if sum(modes) > 1:
            raise SwitchError("-C/-X, -W, -D and -B are mutually exclusive")
        if args.secret_gate or args.drop_secrets_collection:
            return _gate_action(args, home)
        if args.rollback:
            restored, saved = rollback(home)
            print(
                f"✅ restored {restored.name} ({describe(home)}); was kept as {saved.name}"
            )
            return 0
        if not (args.login_collection or args.secrets_collection):
            raise SwitchError("nothing to do: give -C, -X, -W, -D or -B")
        if not args.visible:
            raise SwitchError("-C/-X need -v FILE (the output of `daemon.py -C`)")
        tsv = (
            sys.stdin.read()
            if args.visible == "-"
            else Path(args.visible).read_text(encoding="utf-8")
        )
        login = parse_pair(args.login_collection) if args.login_collection else None
        secrets = (
            parse_pair(args.secrets_collection) if args.secrets_collection else None
        )
        changed, prev = switch(home, visible_pairs(tsv), login, secrets)
    except (SwitchError, OSError) as exc:
        print(f"❌ {exc}", file=sys.stderr)
        return 1
    if not changed:
        print(f"✅ bootstrap.json unchanged ({describe(home)})")
        return 0
    assert prev is not None
    print(
        f"✅ bootstrap.json switched ({describe(home)}); previous kept as {prev.name}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
