"""tp#1924: the overview prints one line per login on a terminal.

On a TTY every line is cut to the terminal width (a compact status: verdict,
date, short tags, then `…`); without a TTY or with `-w` the full text stays.
Hermetic: synthetic rows and check records, no broker, no network, no Chrome.
"""

from __future__ import annotations

# pylint: disable=missing-function-docstring,import-error,wrong-import-position
# pylint: disable=redefined-outer-name
import os
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

al = load_script("agent_login_tp1924_test", "agent-login.py")

NOW = time.time()
AT = time.strftime("%Y-%m-%d %H:%M", time.localtime(NOW))
SHORT_AT = AT[5:]  # the current year is dropped on a terminal


def _row(site: str, name: str, **extra: Any) -> dict[str, Any]:
    return {"site": site, "name": name, "status": "ready", "in_bitwarden": True} | (
        extra
    )


def _rows() -> list[dict[str, Any]]:
    return [
        _row("zz-ok", "zz ok"),
        _row("zz-down", "zz down", alias="zz"),
        _row(
            "zz-admin", "zz admin with a long name", privilege="admin", instance="admin"
        ),
        _row(
            "zz-quar",
            "zz quarantined",
            quarantine={"phase": "submit", "at_text": AT},
            stage="pending",
        ),
        _row("zz-failed", "zz failed"),
        _row("zz-shared", "zz shared", shares_login_with=["zz-down", "zz-admin"]),
        _row(
            "zz-refused", "zz refused", status="refused", detail="duplicate agent_site"
        ),
        _row("zz-new", "zz new"),
    ]


def _checks() -> dict[str, dict[str, Any]]:
    down = {
        "state": "unknown",
        "at": NOW,
        "at_text": AT,
        "phase": "precheck",
        "code": "browser_down",
    }
    return {
        "zz-ok": {"state": "ok", "at": NOW, "at_text": AT, "phase": "ok", "code": "ok"},
        "zz-down": down,
        "zz-admin": down | {"instance": "admin"},
        "zz-quar": down,
        "zz-failed": {
            "state": "failed",
            "at": NOW,
            "at_text": AT,
            "phase": "safari-source",
            "code": "needs_albert_captcha",
            "detail": "a long redacted detail " * 4,
            "screenshot": "/tmp/zz-failed.png",
        },
    }


@pytest.fixture
def data(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    monkeypatch.setattr(al, "USE", False)
    monkeypatch.setattr(al, "last_checks", _checks)
    return {"rows": _rows(), "broker_ok": True, "broker": "running, Bitwarden readable"}


def _lines_of(capsys: pytest.CaptureFixture[str]) -> list[str]:
    return capsys.readouterr().out.splitlines()


def _row_lines(lines: list[str]) -> dict[str, str]:
    """The one line of each synthetic login, by display name."""
    out = {}
    for row in _rows():
        hits = [x for x in lines if f" {row['name']} " in x]
        assert len(hits) == 1, (row["name"], hits)
        out[row["name"]] = hits[0]
    return out


@pytest.mark.parametrize("width", [160, 120])
def test_a_tty_row_fits_the_width(
    data: dict[str, Any], capsys: pytest.CaptureFixture[str], width: int
) -> None:
    al.print_overview(data, width)
    lines = _lines_of(capsys)
    assert all(al.text_width(x) <= width for x in lines), max(lines, key=al.text_width)
    rows = _row_lines(lines)
    assert "Safari: -L SITE -s" in "\n".join(lines)  # the short legend
    assert "full text: -w" in lines[-2]
    if width == 160:
        assert rows["zz ok"].endswith(f"ok {SHORT_AT}")
        assert rows["zz down"].endswith(
            f"could not tell {SHORT_AT}: shared Chromium is down  [alias zz]"
        )
        assert rows["zz admin with a long name"].endswith(
            "shared Chromium is down  [admin browser, ADMIN]"
        )
        assert rows["zz quarantined"].endswith("[quarantined, pending]")
        assert rows["zz failed"].endswith(
            f"failed {SHORT_AT}: needs Albert: a CAPTCHA in Safari"
        )
        assert (
            "account unproven (shares login with zz-down, zz-admin)"
            in (rows["zz shared"])
        )
        assert rows["zz new"].endswith("not checked yet")
    else:  # cut with …, the tags stay readable
        assert rows["zz admin with a long name"].endswith("…  [admin browser, ADMIN]")
    assert (
        rows["zz refused"]
        .split("True")[-1]
        .strip()
        .startswith("Bitwarden item refused")
    )


def test_full_text_without_a_tty(
    data: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    al.print_overview(data)  # width None: pipes, LaunchAgents, -w
    lines = _lines_of(capsys)
    rows = _row_lines(lines)
    assert lines[4].strip() == al.LOGIN_COLUMNS_LEGEND
    assert f"last check {AT} could not tell — before the login" in rows["zz down"]
    assert "[default — alias zz]" in rows["zz down"]
    assert "(release: ./agent-login.py -Q zz-quar)" in rows["zz quarantined"]
    assert "📷 /tmp/zz-failed.png" in rows["zz failed"]
    assert "…" not in "\n".join(lines)
    assert not any("full text: -w" in x for x in lines)
    assert max(al.text_width(x) for x in lines) > 160


def test_fit_width_follows_the_tty_and_wide(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        al.shutil,
        "get_terminal_size",
        lambda fallback=(80, 24): os.terminal_size((97, 30)),
    )
    assert al.fit_width(tty=True) == 97
    assert al.fit_width(tty=False) is None
    assert al.fit_width(wide=True, tty=True) is None


@pytest.mark.parametrize(
    ("argv", "want"), [([], 88), (["-w"], None), (["--wide"], None)]
)
def test_main_passes_the_width(
    monkeypatch: pytest.MonkeyPatch, argv: list[str], want: int | None
) -> None:
    seen: list[int | None] = []
    data = {"rows": _rows(), "broker_ok": True, "broker": "running"}
    monkeypatch.setattr(al, "overview", lambda **_k: data)
    monkeypatch.setattr(al, "write_agent_summary", lambda *_a: None)
    monkeypatch.setattr(al, "print_report", lambda _d, width: seen.append(width))
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr(
        al.shutil,
        "get_terminal_size",
        lambda fallback=(80, 24): os.terminal_size((88, 30)),
    )
    monkeypatch.setattr(sys, "argv", ["agent-login.py", *argv])
    assert al.main() == 0
    assert seen == [want]


def test_fit_counts_terminal_columns() -> None:
    assert al.fit("abc", None) == "abc"
    assert al.fit("abcdef", 6) == "abcdef"
    assert al.fit("abcdef", 4) == "abc…"
    assert al.text_width("✅⚠️a") == 5
    cut = al.fit("✅✅✅", 4)
    assert cut == "✅…" and al.text_width(cut) == 3
    assert al.fit("ab ⚠️ cd", 5) == "ab…"
