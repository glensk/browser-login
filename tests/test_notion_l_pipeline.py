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

    def drive(site: str, recipe: alsafari.Recipe, **_kw: Any) -> Any:
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
    assert pl["order"] == ["probe", "import", "probe"]  # the proof after it


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
        "probe",
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


def test_quarantined_still_imports_a_safari_session(
    pl: dict, capsys: pytest.CaptureFixture
) -> None:
    """D-c: the import sends nothing to Notion — it may restore the session
    while notion is quarantined; the quarantine stays."""
    als.quarantine("notion", "submit", "email_code")
    pl["jar"] = ([_token()], None)
    pl["import"] = _run(0, {"phase": "ok", "code": "ok"})
    assert al.safari_login_action("notion") == 0
    assert pl["order"] == ["probe", "import", "probe"]
    assert als.quarantined("notion") is not None
    assert "Safari session" in capsys.readouterr().out


@pytest.mark.parametrize(
    "jar",
    [
        ([], None),  # Safari holds no session
        ([], "Operation not permitted"),  # Safari's jar unreadable
        ("token", None),  # the import did not work
    ],
)
def test_quarantined_never_sends_a_code_nor_drives_safari(
    pl: dict, capsys: pytest.CaptureFixture, jar: tuple
) -> None:
    als.quarantine("notion", "submit", "email_code")
    pl["jar"] = ([_token()], None) if jar[0] == "token" else jar
    assert al.safari_login_action("notion") == 2
    assert "mail-code" not in pl["order"]
    assert "safari" not in pl["order"] and "gate" not in pl["order"]
    assert pl["order"][0] == "probe"
    assert als.quarantined("notion") is not None
    out = capsys.readouterr().out
    assert "-Q notion" in out
    assert "no e-mail code and no Safari login while quarantined" in out


def test_quarantined_and_logged_in_does_nothing(pl: dict) -> None:
    als.quarantine("notion", "submit", "email_code")
    pl["probe"] = (0, {"phase": "ok", "code": "ok"})
    assert al.safari_login_action("notion") == 0
    assert pl["order"] == ["probe"]


def test_quarantine_still_refuses_other_recipes(pl: dict) -> None:
    als.quarantine("galaxus-de", "submit", "login_failed")
    assert al.safari_login_action("galaxus-de") == 2
    assert pl["order"] == ["gate"]


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


def _notion_line(proof: str) -> str:
    """agents.md's Notion line after a passing check with `proof`."""
    al.record_check("notion", True, "ok", {"proof": proof})
    target = next(t for t in al.TARGETS if t.site == "notion")
    row = {
        **al.asdict(target),
        "status": "assisted",
        "detail": "",
        "sentinel": False,
        "instance": "",
    }
    al._builtin_sentinels([row])
    text = al.agent_summary({"rows": [row], "broker_ok": True}, al.last_checks())
    lines = [str(ln) for ln in str(text).splitlines() if "Notion (" in ln]
    assert len(lines) == 1
    return lines[0]


def test_the_agents_md_notion_line_has_no_weak_proof() -> None:
    line = _notion_line("server+sentinel")
    assert line.startswith("- ✅ Notion (")
    assert "weak proof" not in line
    # without the sidebar sentinel the old warning stays
    assert "weak proof" in _notion_line("server")


# ---------------------------------------------------------------------------
# tp#1633 canary 3: the import route records the proven check's proof
# ---------------------------------------------------------------------------

PROVEN = {
    "phase": "ok",
    "code": "ok",
    "server": "valid",
    "proof": "server+sentinel",
    "sentinel": True,
    "identity": "match",
    "cookie_days_left": 364,
}


def test_the_import_records_the_proof_of_the_check_after_it(
    pl: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    pl["jar"] = ([_token()], None)
    pl["import"] = _run(0, {"phase": "ok", "code": "ok", "proof": ""})
    probes = iter([(2, {"code": "logged_out"}), (0, dict(PROVEN))])

    def probe(site: str, quiet: bool = True) -> Any:
        pl["order"].append("probe")
        return next(probes)

    monkeypatch.setattr(al, "probe", probe)
    assert al.safari_login_action("notion") == 0
    assert pl["order"] == ["probe", "import", "probe"]
    rec = al.last_checks()["notion"]
    assert (rec["state"], rec["route"]) == ("ok", "safari-import")
    assert (rec["proof"], rec["server"]) == ("server+sentinel", "valid")
    assert "weak proof" not in _notion_line(rec["proof"])


def test_the_agent_import_records_the_proof_too(
    pl: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    pl["mail"] = _run(2, {"phase": "precheck", "code": "recipe_stuck"})
    pl["import"] = _run(0, {"phase": "ok", "code": "ok"})
    probes = iter(
        [(2, {"code": "logged_out"}), (2, {"code": "logged_out"}), (0, dict(PROVEN))]
    )
    monkeypatch.setattr(al, "probe", lambda site, quiet=True: next(probes))
    assert al.safari_login_action("notion") == 0
    rec = al.last_checks()["notion"]
    assert (rec["route"], rec["proof"]) == ("safari-login", "server+sentinel")


def test_a_failed_check_after_the_import_keeps_the_import(
    pl: dict, capsys: pytest.CaptureFixture
) -> None:
    pl["jar"] = ([_token()], None)
    pl["import"] = _run(0, {"phase": "ok", "code": "ok", "proof": ""})
    assert al.safari_login_action("notion") == 0  # the probe stub: logged_out
    rec = al.last_checks()["notion"]
    assert (rec["state"], rec["code"], rec["proof"]) == ("ok", "ok", "")
    assert "the import's own proof stands" in capsys.readouterr().out


def test_other_sites_import_without_a_second_check(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _never(site: str) -> Any:
        raise AssertionError("no check after another site's import")

    monkeypatch.setattr(al, "_free_check", _never)
    assert al._import_proof("galaxus-de", {"code": "ok"}) == {"code": "ok"}


def test_logged_in_records_the_proof_of_the_check(pl: dict) -> None:
    pl["probe"] = (0, dict(PROVEN))
    assert al.safari_login_action("notion") == 0
    assert pl["order"] == ["probe"]
    assert al.last_checks()["notion"]["proof"] == "server+sentinel"
