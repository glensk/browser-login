"""Login-keychain inventory for agent-login.py: which secrets could an agent read?

`security dump-keychain -a` lists every item's attributes and access list —
never a secret value (no ``-d``). An item is READABLE BY AGENTS when any process
running as Albert can print it with the security CLI without a prompt: its
decrypt entry trusts ``/usr/bin/security`` (or any application) and its
partition list admits ``apple-tool:``. Values are never read here.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
from collections.abc import Callable
from pathlib import Path

# Apple/system items nobody stores by hand (noise in the list).
_SYSTEM = re.compile(
    r"^(com\.apple\.|apple|ids:|airplay|bluetooth|icloud|handoff|continuity|"
    r"cloudkit|siri|safari|0x|[0-9A-F]{8}-[0-9A-F]{4}-)",
    re.IGNORECASE,
)
KEYCHAIN_MAX_AGE_S = 60 * 60  # the scan takes ~15 s: at most hourly


# Some items carry the SECRET in their service attribute (stored the wrong way
# round). Attributes are readable without any prompt, so only names that look
# like identifiers are shown: ENV_STYLE, plain words, or names with a separator.
_NAME_OK = re.compile(r"[A-Z][A-Z0-9_]*|[A-Za-z]+|.*[:./ @-].*")
MASKED = "‹name looks like a secret value — not shown›"


# Without the secret broker only these shapes are shown: ENV_STYLE or a
# structured name with a colon ("gh:github.com", "biopol-wifi: email").
_NAME_STRICT = re.compile(r"[A-Z][A-Z0-9_]*|.*:.*")


def safe_name(name: str) -> str:
    """`name`, or MASKED when its shape could be a credential itself."""
    return name if _NAME_OK.fullmatch(name) else MASKED


def _scrub_client() -> str | None:
    """mydotfiles' secret-broker client (the leak detector the hooks use)."""
    for cand in (
        os.environ.get("SECRET_BROKER_CLIENT"),
        shutil.which("secret-broker-client.py"),
        str(
            Path.home() / "obsidian/42-Git/home/mydotfiles/bin/secret-broker-client.py"
        ),
    ):
        if cand and os.access(cand, os.X_OK):
            return cand
    return None


def mask_known_secrets(names: list[str]) -> list[str]:
    """Each name, or MASKED when the secret broker knows it as a secret value.

    A shape check is not enough: a real password can look like a plain word.
    Without the broker (absent / exit 3) the strict shape rule decides.
    """
    client = _scrub_client()
    res = None
    if client and names:
        res = subprocess.run(
            [client, "scrub"],
            input="\n".join(n.replace("\n", " ") for n in names) + "\n",
            check=False,
            capture_output=True,
            text=True,
        )
    lines = res.stdout.split("\n") if res is not None and res.returncode == 0 else []
    if len(lines) < len(names):
        return [n if _NAME_STRICT.fullmatch(n) else MASKED for n in names]
    return [n if n == line else MASKED for n, line in zip(names, lines)]


def _attr(block: str, name: str) -> str:
    m = re.search(rf'"{name}"<blob>="((?:[^"\\]|\\.)*)"', block)
    return m.group(1) if m else ""


def _readable(block: str) -> bool:
    """Decrypt entry trusts the security CLI (or all apps) AND apple-tool: may read."""
    entries = re.split(r"\n\s+entry \d+:\n", block.split("\naccess:", 1)[-1])
    decrypt_apps: list[str] | None = []
    partition = ""
    for entry in entries:
        auth = re.search(r"authorizations \(\d+\): ([^\n]*)", entry)
        if not auth:
            continue
        if "decrypt" in auth.group(1).split():
            if re.search(r"applications: <null>", entry):
                decrypt_apps = None  # any application
            else:
                decrypt_apps = re.findall(r"\d+: (/\S+)", entry)
        elif "partition_id" in auth.group(1).split():
            desc = re.search(r"description: ([^\n]*)", entry)
            partition = desc.group(1) if desc else ""
    trusted = decrypt_apps is None or "/usr/bin/security" in decrypt_apps
    return trusted and (not partition or "apple-tool:" in partition)


def _blocks(text: str) -> list[tuple[str, str, str, str]]:
    """(kind, RAW service, RAW account, block) of every non-system item."""
    out: list[tuple[str, str, str, str]] = []
    for block in re.split(r"(?m)^keychain: ", text):
        cls = re.search(r'^class: "?(\w+)"?', block, re.MULTILINE)
        if not cls or cls.group(1) not in ("genp", "inet"):
            continue
        service = _attr(block, "svce") or _attr(block, "srvr")
        if not service or _SYSTEM.match(service) or "Safe Storage" in service:
            continue
        kind = "password" if cls.group(1) == "genp" else "internet"
        out.append((kind, service, _attr(block, "acct"), block))
    return out


def parse_dump(text: str) -> list[dict]:
    """Items of a ``dump-keychain -a`` text: kind, service, account, readable."""
    out: list[dict] = []
    for kind, service, account, block in _blocks(text):
        out.append(
            {
                "kind": kind,
                "service": safe_name(service),
                "account": safe_name(account),
                "readable": _readable(block),
            }
        )
    out.sort(key=lambda r: (not r["readable"], r["service"].lower()))
    return out


def scan() -> list[dict]:
    """The live login keychain (no values); [] when `security` fails."""
    res = subprocess.run(
        ["security", "dump-keychain", "-a"],
        check=False,
        capture_output=True,
        text=True,
        errors="replace",
    )
    if res.returncode != 0:
        return []
    items = parse_dump(res.stdout)
    flat = [x for i in items for x in (i["service"], i["account"])]
    masked = mask_known_secrets(flat)
    for n, item in enumerate(items):
        item["service"], item["account"] = masked[2 * n], masked[2 * n + 1]
    return items


def cached(path: Path) -> tuple[float, list[dict]]:
    """(scan time, items) from the last scan; (0, []) when there is none. Fast."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return float(data["at"]), list(data["items"])
    except (OSError, ValueError, KeyError, TypeError):
        return 0.0, []


def refresh(path: Path, *, force: bool = False) -> tuple[float, list[dict]]:
    """Rescan (~15 s) when forced or the last scan is over an hour old."""
    at, items = cached(path)
    if not force and items and time.time() - at < KEYCHAIN_MAX_AGE_S:
        return at, items
    items = scan()
    if not items:
        return at, cached(path)[1]
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    now = time.time()
    tmp.write_text(json.dumps({"at": now, "items": items}), "utf-8")
    tmp.chmod(0o600)
    tmp.replace(path)
    return now, items


def live_names() -> list[tuple[str, str, str]] | None:
    """(kind, RAW service, RAW account) of every item now — or None when unknown.

    ``dump-keychain`` WITHOUT ``-a`` reads attributes only (no access lists,
    never a value) and takes ~30 ms, against ~15 s with ``-a``. The raw names
    only ever feed `still_present`'s comparison; they are never printed (some
    items store the secret AS their name). Like every ``security`` call here:
    its own session, no timeout, never killed (AGENTS.md, tp#504).
    """
    try:
        res = subprocess.run(
            ["security", "dump-keychain"],
            check=False,
            capture_output=True,
            text=True,
            errors="replace",
            start_new_session=True,
        )
    except OSError:
        return None
    if res.returncode != 0:
        return None
    return [(k, s, a) for k, s, a, _block in _blocks(res.stdout)]


def _matches(item: dict, live: tuple[str, str, str]) -> bool:
    """A cached (masked) item names this live item; MASKED matches any name."""
    kind, service, account = live
    return (
        item["kind"] == kind
        and item["service"] in (MASKED, service)
        and item["account"] in (MASKED, account)
    )


def still_present(
    items: list[dict], live: list[tuple[str, str, str]]
) -> tuple[list[dict], int]:
    """(the cached items that still exist, how many live items the scan lacks)."""
    kept = [i for i in items if any(_matches(i, x) for x in live)]
    new = sum(1 for x in live if not any(_matches(i, x) for i in items))
    return kept, new


def print_list(
    path: Path, _c: Callable[[str, str], str], *, full: bool = False
) -> None:
    """The login-keychain list: names only, and whether agents can read it.

    The readability scan is cached (~15 s, at most hourly), but which items
    EXIST is re-read on every call (`live_names`, ~30 ms): an item deleted
    since the scan is never listed as present (tp#1059), and items added
    since are counted so the reader knows a rescan (-K) is due.
    """
    at, items = cached(path)
    print(_c("1", "Login keychain") + "  (names only, never values)")
    if not items:
        print(_c("2", "  not scanned yet — ./agent-login.py -K (takes ~15 s)"))
        return
    live = live_names()
    gone = new = 0
    if live is not None:
        kept, new = still_present(items, live)
        gone, items = len(items) - len(kept), kept
    readable = [i for i in items if i["readable"]]
    shown = items if full else readable
    when = time.strftime("%Y-%m-%d %H:%M", time.localtime(at))
    if live is None:
        state = f"scan {when}, NOT re-checked — names may be stale"
    else:
        changes = [f"{gone} deleted since"] if gone else []
        changes += [f"{new} new, readability unknown"] if new else []
        state = f"scan {when}, existence checked now" + "".join(
            f"; {c}" for c in changes
        )
    print(
        _c(
            "2",
            f"  {len(readable)} of {len(items)} items readable by any agent without "
            f"a prompt ({state}; -K rescans + lists all)",
        )
    )
    width = max(len(i["service"]) for i in shown) if shown else 10
    print(_c("2", f"     {'item'.ljust(width)}  account  ·  readable by agents"))
    for i in shown:
        icon = "🔓" if i["readable"] else "🔒"
        print(f"  {icon} {i['service'].ljust(width)}  {i['account'] or '-'}")
