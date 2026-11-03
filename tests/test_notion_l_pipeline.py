"""tp#1633 B6: `agent-login.py -L notion` — free check → Safari import →
headless e-mail code (`browser.py login notion -M`) → attended Safari login.

Hermetic: the probe, Safari's jar, the import, the `-M` run and the Safari
drive are stubs; the state dir is a per-test temp dir (conftest).
"""

from __future__ import annotations

# pylint: disable=missing-function-docstring,import-error,wrong-import-position
# pylint: disable=protected-access,redefined-outer-name,unused-argument
import secrets
import sys
import time
from pathlib import Path
from typing import Any

import pytest

sys.path[:0] = [
    str(Path(__file__).resolve().parent.parent),
    str(Path(__file__).resolve().parent),
]

from ws3_fixtures import load_script  # noqa: E402

import agent_login_jobs as jobs  # noqa: E402
import agent_login_safari as alsafari  # noqa: E402
import agent_login_state as als  # noqa: E402
from broker import safari_cookies as sc  # noqa: E402

al = load_script("agent_login_tp1633_test", "agent-login.py")


def _run(rc: int | None, result: dict | None = None) -> jobs.BrowserRun:
    return jobs.BrowserRun(rc, rc is None, "", 0.1, result)


def _token(value: str | None = None) -> sc.Cookie:
    return sc.Cookie(
        domain=".notion.so",
        name="token_v2",
        value=value or secrets.token_hex(8),
        path="/",
        expires=time.time() + 86400,
        secure=True,
        http_only=True,
    )


@pytest.fixture
def pl(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    log: dict[str, Any] = {
        "order": [],
        "probe": (2, {"code": "logged_out"}),
        "jar": ([], None),
        "import": _run(2, {"phase": "client-proof", "code": "logged_out"}),
        "mail": _run(0, {"phase": "ok", "code": "ok", "route": "mail-code"}),
        "drive": alsafari.Outcome(0, "ok", credential=True, steps=["login"]),
        "gate": None,
        "lock_held_in_mail": None,
    }
    monkeypatch.delenv(alsafari.SCHEDULED_ENV, raising=False)
    monkeypatch.setattr(al, "configured_instance", lambda site: "")

    def probe(site: str, quiet: bool = True) -> Any:
        log["order"].append("probe")
        return log["probe"]

    def jar(site: str) -> tuple[list, str | None]:
        cookies, why = log["jar"]
        return list(cookies), why

    def imp(site: str, agent: bool) -> Any:
        log["order"].append("import-agent" if agent else "import")
        return log["import"]

    def mail(site: str) -> Any:
        log["order"].append("mail-code")
        with al.safari_login_lock(wait_s=0.0) as free:
            log["lock_held_in_mail"] = not free
        return log["mail"]

    def drive(site: str, recipe: alsafari.Recipe) -> Any:
        log["order"].append("safari")
        return log["drive"]

    def gate() -> Any:
        log["order"].append("gate")
        return log["gate"]

    monkeypatch.setattr(al, "probe", probe)
    monkeypatch.setattr(al, "_safari_jar", jar)
    monkeypatch.setattr(al, "_import_run", imp)
    monkeypatch.setattr(al, "_mail_code_run", mail)
    monkeypatch.setattr(al, "_drive_safari", drive)
    monkeypatch.setattr(al, "_wait_flush", lambda site, before: True)
    monkeypatch.setattr(alsafari, "interactive_gate", gate)
    return log


def test_logged_in_does_nothing(pl: dict) -> None:
    pl["probe"] = (0, {"phase": "ok", "code": "ok"})
    assert al.safari_login_action("notion") == 0
    assert pl["order"] == ["probe"]


def test_a_safari_session_is_imported_first(pl: dict) -> None:
    pl["jar"] = ([_token()], None)
    pl["import"] = _run(0, {"phase": "ok", "code": "ok"})
    assert al.safari_login_action("notion") == 0
    assert pl["order"] == ["probe", "import"]


def test_no_safari_session_goes_headless_on_a_locked_mac(pl: dict) -> None:
    pl["gate"] = "console_locked"
    assert al.safari_login_action("notion") == 0
    assert pl["order"] == ["probe", "mail-code"]  # the gate is never asked
    assert pl["lock_held_in_mail"] is False
    rec = al.last_checks()["notion"]
    assert (rec["state"], rec["route"]) == ("ok", "mail-code")


def test_a_failed_import_goes_headless(pl: dict) -> None:
    pl["jar"] = ([_token()], None)
    assert al.safari_login_action("notion") == 0
    assert pl["order"] == ["probe", "import", "mail-code"]


def test_an_unreadable_jar_goes_headless_and_says_why(pl: dict) -> None:
    pl["jar"] = ([], "Operation not permitted")
    assert al.safari_login_action("notion") == 0
    assert pl["order"] == ["probe", "mail-code"]
    assert al.last_checks()["notion"]["detail"] == "safari_jar: Operation not permitted"


@pytest.mark.parametrize(
    "code",
    [
        "mailbox_unreadable",
        "identity_unconfigured",
        "himalaya_missing",
        "state_unwritable",
        "recipe_stuck",
    ],
)
def test_a_stop_before_sending_falls_through_to_safari(pl: dict, code: str) -> None:
    pl["mail"] = _run(2, {"phase": "precheck", "code": code})
    pl["import"] = _run(0, {"phase": "ok", "code": "ok"})  # after the login
    assert al.safari_login_action("notion") == 0
    assert pl["order"] == [
        "probe",
        "mail-code",
        "gate",
        "probe",
        "safari",
        "import-agent",
    ]


def test_the_gate_blocks_only_the_safari_fallback(pl: dict) -> None:
    pl["mail"] = _run(2, {"phase": "precheck", "code": "mailbox_unreadable"})
    pl["gate"] = "albert_idle"
    assert al.safari_login_action("notion") == 3
    assert "safari" not in pl["order"]
    rec = al.last_checks()["notion"]
    assert (rec["code"], rec["route"]) == ("albert_idle", "mail-code")


def test_a_logged_in_recheck_skips_the_safari_fallback(
    pl: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    pl["mail"] = _run(2, {"phase": "precheck", "code": "recipe_stuck"})
    probes = iter([(2, {"code": "logged_out"}), (0, {"phase": "ok", "code": "ok"})])
    monkeypatch.setattr(al, "probe", lambda site, quiet=True: next(probes))
    assert al.safari_login_action("notion") == 0
    assert "safari" not in pl["order"]


@pytest.mark.parametrize(
    ("rc", "res"),
    [
        (2, {"phase": "recipe", "code": "recipe_stuck", "triggered": True}),
        (4, {"phase": "recipe", "code": "needs_albert_captcha"}),
        (2, {"phase": "precheck", "code": "cooldown"}),
        (2, {"phase": "precheck", "code": "quarantined"}),
        (2, {"phase": "precheck", "code": "wrong_account"}),
        (2, {"phase": "precheck", "code": "indeterminate"}),
        (2, {"phase": "mail", "code": "email_code", "triggered": True}),
        (75, {"phase": "precheck", "code": "busy"}),
        (124, {"phase": "recipe", "code": "timeout"}),
        (None, None),
    ],
)
def test_no_fall_through_after_a_real_stop(
    pl: dict, rc: int | None, res: dict | None
) -> None:
    pl["mail"] = _run(rc, res)
    got = al.safari_login_action("notion")
    assert got == (rc if rc in (4, 75) else 2)
    assert "safari" not in pl["order"] and "gate" not in pl["order"]
    rec = al.last_checks()["notion"]
    assert rec["route"] == "mail-code"
    assert als.quarantined("notion") is None


def test_a_credential_stop_quarantines_once(
    pl: dict, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    calls: list[str] = []
    monkeypatch.setattr(als, "quarantine", lambda *a, **k: calls.append(a[0]))
    pl["mail"] = _run(
        2,
        {
            "phase": "client-proof",
            "code": "logged_out",
            "credential": True,
            "quarantined": True,
        },
    )
    assert al.safari_login_action("notion") == 2
    assert not calls  # browser.py quarantined already
    assert "-Q notion" in capsys.readouterr().out
    pl["mail"] = _run(
        2, {"phase": "client-proof", "code": "logged_out", "credential": True}
    )
    assert al.safari_login_action("notion") == 2
    assert calls == ["notion"]  # the -R result did not say quarantined


def test_scheduled_still_refuses(pl: dict, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(alsafari.SCHEDULED_ENV, "1")
    assert al.safari_login_action("notion") == 2
    assert not pl["order"]


def test_other_recipes_keep_the_gate_on_top(pl: dict) -> None:
    pl["gate"] = "console_locked"
    assert al.safari_login_action("galaxus-de") == 3
    assert pl["order"] == ["gate"]


def test_dry_run_prints_the_fp_and_never_a_value(
    pl: dict, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    value = secrets.token_hex(12)
    pl["jar"] = ([_token(value)], None)
    monkeypatch.setattr(al.shutil, "which", lambda _n: None)
    assert al.safari_login_action("notion", dry_run=True) == 0
    out = capsys.readouterr().out
    fp = [ln for ln in out.splitlines() if "safari fp: " in ln]
    assert len(fp) == 1 and len(fp[0].rsplit(" ", 1)[1]) == 8
    assert value not in out
    assert "headless e-mail-code route NOT ready" in out
    assert "cooldown free" in out
    assert al.safari_login_action("notion", dry_run=True) == 0
    assert fp == [ln for ln in capsys.readouterr().out.splitlines() if "fp: " in ln]
    assert pl["order"] == ["gate", "gate"]  # read-only: no probe, import, -M


def test_rows_get_a_built_in_sentinel(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        al, "last_checks", lambda: {"notion": {"proof": "server+sentinel"}}
    )
    rows = [{"site": "notion", "sentinel": False}, {"site": "x", "sentinel": False}]
    al._builtin_sentinels(rows)
    assert rows[0]["sentinel"] == "built-in"
    assert rows[1]["sentinel"] is False
    monkeypatch.setattr(al, "last_checks", lambda: {"notion": {"proof": "server"}})
    rows = [{"site": "notion", "sentinel": False}]
    al._builtin_sentinels(rows)
    assert rows[0]["sentinel"] is False


def test_the_check_record_keeps_the_proof() -> None:
    al.record_check("notion", True, "ok", {"proof": "server+sentinel"})
    assert al.last_checks()["notion"]["proof"] == "server+sentinel"
    al.record_check("notion", True, "ok", {"proof": "<b>"})
    assert al.last_checks()["notion"]["proof"] == ""
