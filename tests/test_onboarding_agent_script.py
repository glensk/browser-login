"""tp#991 B4 — the onboarding review (``agent-login.py -V -i``) and the
``agent_script`` gate (PLAN_cred-one-collection.md).

The pure ``onboarding.review_planned(..., gate=)``: a malformed flag is
refused, a flag on an admin login is a risk (O1), an unknown gate blocks,
membership is judged per gate, a script-only item is no site under
``agent_script``; ``agent_login_secrets.gate_state`` reads the gate from the
broker's ``secrets`` answer and its snapshot. Hermetic: no broker, no vault.

Run: uv run pytest -q tests/test_onboarding_agent_script.py
"""

from __future__ import annotations

# pylint: disable=missing-function-docstring,import-error,wrong-import-position
import json
import sys
import time
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import agent_login_secrets as als  # noqa: E402
from broker import onboarding, vault  # noqa: E402

LOGIN, SECRETS = "coll-login", "coll-secrets"
COLLS = {"login": LOGIN, "secrets": SECRETS}


def _item(name: str = "Shop", site: str | None = "shop", **fields: str) -> dict:
    base = {
        "agent_site": site,
        "agent_fill_origins": "https://login.shop.example",
        "agent_cookie_hosts": "shop.example",
        "agent_logged_in_selector": "#me",
        **fields,
    }
    return {"name": name, "fields": {k: v for k, v in base.items() if v is not None}}


def _codes(review: onboarding.Review) -> set[str]:
    return {f.code for f in review.findings}


def test_a_malformed_flag_is_refused() -> None:
    review = onboarding.review_planned(_item(agent_script="yes please"), [])
    found = [f for f in review.findings if f.code == "bad_agent_script"]
    assert found and found[0].level == "refused" and review.blocking


def test_a_flag_on_an_admin_login_is_a_risk() -> None:
    review = onboarding.review_planned(
        _item(agent_script="true", agent_privilege="admin"),
        [],
        gate=vault.GATE_AGENT_SCRIPT,
    )
    found = [f for f in review.findings if f.code == "agent_script_admin"]
    assert found and found[0].level == "risk" and review.blocking


def test_a_flag_on_a_user_login_is_fine_under_the_gate() -> None:
    review = onboarding.review_planned(
        _item(agent_script="true"), [], gate=vault.GATE_AGENT_SCRIPT
    )
    assert not review.blocking
    assert "agent_script_not_enforced" not in _codes(review)


def test_a_flag_before_the_flip_is_a_hint() -> None:
    review = onboarding.review_planned(_item(agent_script="true"), [])
    hint = [f for f in review.findings if f.code == "agent_script_not_enforced"]
    assert hint and hint[0].level == "hint" and not review.blocking


@pytest.mark.parametrize("gate", ["unknown", "enforce", ""])
def test_an_unknown_gate_blocks(gate: str) -> None:
    review = onboarding.review_planned(_item(), [], gate=gate)
    assert "gate_unknown" in _codes(review) and review.blocking


def test_one_collection_manifest_is_accepted() -> None:
    manifest = {"collections": {"login": LOGIN}, **_item(agent_script="true")}
    review = onboarding.review_planned(manifest, [], gate=vault.GATE_AGENT_SCRIPT)
    assert not review.blocking, review.findings


def test_membership_is_judged_per_gate() -> None:
    dual = {
        "collections": COLLS,
        **_item(agent_script="true"),
        "collectionIds": [LOGIN, SECRETS],
    }
    old = onboarding.review_planned(dual, [])
    assert any(
        "in both agent-login and agent-secrets" in f.text for f in old.findings
    ), old.findings
    new = onboarding.review_planned(dual, [], gate=vault.GATE_AGENT_SCRIPT)
    assert not new.blocking, new.findings


def test_a_script_only_item_is_no_site_under_the_gate() -> None:
    script = {"name": "Ecovacs", "fields": {"agent_script": "true"}}
    review = onboarding.review_planned(script, [], gate=vault.GATE_AGENT_SCRIPT)
    assert review.planned == ["ecovacs"]
    assert not review.blocking, review.findings
    old = onboarding.review_planned(script, [])
    assert old.blocking  # without the gate it is a login item lacking origins


# ---------------------------------------------------------------------------
# agent_login_secrets.gate_state
# ---------------------------------------------------------------------------


def _req(resp: dict[str, Any] | Exception) -> Any:
    calls: list[str] = []

    def request(op: str, **_kw: Any) -> dict[str, Any]:
        calls.append(op)
        if isinstance(resp, Exception):
            raise resp
        return resp

    request.calls = calls  # type: ignore[attr-defined]
    return request


@pytest.mark.parametrize(
    "resp,want",
    [
        ({"ok": True, "secrets": [], "gate": "agent_script"}, "agent_script"),
        ({"ok": True, "secrets": []}, "collections"),  # a broker before tp#991
        (
            {"ok": False, "error": "bad_secret_gate", "gate": "bad_secret_gate"},
            "bad_secret_gate",
        ),
        ({"ok": False, "error": "vault_error"}, "unknown"),
        ({"ok": True, "secrets": [], "gate": "weird"}, "unknown"),
        (OSError("down"), "unknown"),
    ],
)
def test_gate_state_live(tmp_path: Path, resp: Any, want: str) -> None:
    assert als.gate_state(_req(resp), tmp_path, fresh=True) == want


def test_gate_state_uses_a_recent_snapshot(tmp_path: Path) -> None:
    (tmp_path / als.SNAPSHOT_NAME).write_text(
        json.dumps({"at": time.time(), "note": "ok", "secrets": [], "gate": "report"})
    )
    req = _req({"ok": True, "secrets": [], "gate": "agent_script"})
    assert als.gate_state(req, tmp_path) == "report"
    assert not req.calls
    assert als.gate_state(req, tmp_path, fresh=True) == "agent_script"


def test_gate_state_snapshot_without_gate_asks_the_broker(tmp_path: Path) -> None:
    (tmp_path / als.SNAPSHOT_NAME).write_text(
        json.dumps({"at": time.time(), "note": "ok", "secrets": []})
    )
    req = _req({"ok": True, "secrets": [], "gate": "collections"})
    assert als.gate_state(req, tmp_path) == "collections"
    assert req.calls == ["secrets"]


def test_secrets_state_still_returns_note_and_rows(tmp_path: Path) -> None:
    req = _req(
        {
            "ok": True,
            "gate": "agent_script",
            "secrets": [
                {"id": "shop", "fields": ["password"], "refused": False},
                {"id": "web", "fields": [], "refused": True},
            ],
        }
    )
    note, rows = als.secrets_state(req, tmp_path, fresh=True)
    assert note == "ok" and [r["id"] for r in rows] == ["shop"]
    snap = json.loads((tmp_path / als.SNAPSHOT_NAME).read_text())
    assert snap["gate"] == "agent_script"
