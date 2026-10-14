"""The secrets agents can inject with ``secret-run`` — for agent-login.py's agents file.

Asks the login broker's ``secrets`` op (ids, exposed field NAMES, TOTP present —
never a value) and renders a short Markdown section for
``~/.local/state/agent-login/agents.md``. Every id and field name passes a
``safe_name`` check again here (``^[A-Za-z0-9._ -]{1,64}$``, else
``item-<n>`` / ``field-<n>``), so a name that is really a value can never reach
the file. The list is snapshotted to ``secrets.json`` next to ``sites.json``.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from broker.vault import safe_name

SNAPSHOT_NAME = "secrets.json"
SNAPSHOT_MAX_AGE_S = 30 * 60

Request = Callable[..., dict]


def clean_rows(rows: Any) -> list[dict[str, Any]]:
    """The broker's ``secrets`` rows reduced to safe names; refused rows dropped."""
    out: list[dict[str, Any]] = []
    for n, row in enumerate(rows if isinstance(rows, list) else [], 1):
        if not isinstance(row, dict) or row.get("refused"):
            continue
        fields = [
            safe_name(str(f), k, prefix="field")
            for k, f in enumerate(row.get("fields") or [], 1)
        ]
        out.append(
            {
                "id": safe_name(str(row.get("id") or ""), n),
                "fields": fields,
                "has_totp": bool(row.get("has_totp")),
            }
        )
    return out


GATES = ("collections", "report", "agent_script", "bad_secret_gate")


def _gate_of(resp: dict) -> str:
    """The broker's agent_script gate from a ``secrets`` answer (tp#991): a
    broker from before it sends none (= collections); anything else that
    cannot be read is ``unknown``."""
    if resp.get("ok"):
        gate = resp.get("gate", "collections")
    else:
        gate = resp.get("gate") or "unknown"
    return gate if gate in GATES else "unknown"


def live_secrets(request: Request) -> tuple[str, list[dict[str, Any]]]:
    """(note, rows) straight from the broker; rows empty when unavailable."""
    note, rows, _gate = _live(request)
    return note, rows


def _live(request: Request) -> tuple[str, list[dict[str, Any]], str]:
    try:
        resp = request("secrets")
    except (OSError, ValueError) as exc:
        return f"broker not reachable: {exc}", [], "unknown"
    if not resp.get("ok"):
        note = f"{resp.get('error')}: {resp.get('detail') or ''}".rstrip(": ")
        return note, [], _gate_of(resp)
    return "ok", clean_rows(resp.get("secrets")), _gate_of(resp)


def snapshot_secrets(state_dir: Path) -> list[dict[str, Any]]:
    """The snapshot's rows when it is recent (no broker call), else []."""
    try:
        data = json.loads((state_dir / SNAPSHOT_NAME).read_text(encoding="utf-8"))
        if 0 <= time.time() - float(data["at"]) < SNAPSHOT_MAX_AGE_S:
            return clean_rows(data["secrets"])
    except (OSError, ValueError, KeyError, TypeError):
        pass
    return []


def secrets_state(
    request: Request, state_dir: Path, *, fresh: bool = False
) -> tuple[str, list[dict[str, Any]]]:
    """(note, rows) — from the snapshot when it is recent, else live."""
    snap = state_dir / SNAPSHOT_NAME
    if not fresh:
        try:
            data = json.loads(snap.read_text(encoding="utf-8"))
            if 0 <= time.time() - float(data["at"]) < SNAPSHOT_MAX_AGE_S:
                return str(data["note"]), clean_rows(data["secrets"])
        except (OSError, ValueError, KeyError, TypeError):
            pass
    note, rows, gate = _live(request)
    try:
        state_dir.mkdir(parents=True, exist_ok=True)
        tmp = snap.with_suffix(".tmp")
        tmp.write_text(
            json.dumps(
                {"at": time.time(), "note": note, "secrets": rows, "gate": gate}
            ),
            encoding="utf-8",
        )
        tmp.replace(snap)
    except OSError:
        pass
    return note, rows


def gate_state(request: Request, state_dir: Path, *, fresh: bool = False) -> str:
    """The broker's agent_script gate: from a recent snapshot, else live
    (which refreshes the snapshot); ``unknown`` when neither can tell."""
    if not fresh:
        try:
            data = json.loads((state_dir / SNAPSHOT_NAME).read_text(encoding="utf-8"))
            if 0 <= time.time() - float(data["at"]) < SNAPSHOT_MAX_AGE_S:
                gate = data.get("gate")
                if gate in GATES:
                    return str(gate)
        except (OSError, ValueError, KeyError, TypeError):
            pass
    secrets_state(request, state_dir, fresh=True)
    try:
        data = json.loads((state_dir / SNAPSHOT_NAME).read_text(encoding="utf-8"))
        gate = data.get("gate")
        return str(gate) if gate in GATES else "unknown"
    except (OSError, ValueError, TypeError):
        return "unknown"


def summary_lines(rows: list[dict[str, Any]]) -> list[str]:
    """The agents-file section (empty when nothing can be injected)."""
    if not rows:
        return []
    out = [
        "",
        "## Secrets agents can inject (`secret-run`, values never shown)",
        "",
        "`secret-run -e NAME=ITEM[:FIELD] -- CMD` (also `-p` file, `-s` stdin; "
        "`secret-run -h`); TOTP code: `secret-run -o ITEM`. Never print, `env` "
        "or echo an injected value.",
        "",
    ]
    for row in sorted(clean_rows(rows), key=lambda r: r["id"]):
        fields = ", ".join(row["fields"]) or "-"
        totp = " (+ TOTP: `-o`)" if row["has_totp"] else ""
        out.append(f"- `{row['id']}`: {fields}{totp}")
    return out
