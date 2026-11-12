"""tp#1644 B19: the Safari keep-alive (`agent-login.py -k`).

Albert's exemption of 2026-11-13 from "`-L` is agent-invoked only", and its
limits: the keep-alive sites only; Albert active; a login only after this
run's `-O` proof said `safari_logged_out` (never on an unknown answer or an
error); never while quarantined or during a live guided login; one attempt
per site per 6 h (failures too); exit 4 → one notification; a logged-in
Safari is proven in a background tab that is closed again — nothing opened,
no window, no focus change. Hermetic: safari.py is a scripted fake (no real
Safari / Chrome / broker), the state dir is a per-test temp dir (conftest),
the notification is a recorder.
"""

from __future__ import annotations

# pylint: disable=missing-function-docstring,import-error,wrong-import-position
# pylint: disable=protected-access,redefined-outer-name,unused-argument
import json
import os
import stat
import sys
import time
from pathlib import Path
from typing import Any

import pytest

sys.path[:0] = [
    str(Path(__file__).resolve().parent.parent),
    str(Path(__file__).resolve().parent),
]

import test_safari_routes as r  # noqa: E402
import test_ws1b_safari as w  # noqa: E402

# pytest fixtures used by name
# pylint: disable-next=unused-import
from test_safari_routes import cscs, run, sso  # noqa: E402,F401

import agent_login_jobs as jobs  # noqa: E402
import agent_login_keepalive as kal  # noqa: E402
import agent_login_safari as alsafari  # noqa: E402
import agent_login_state as als  # noqa: E402

al = r.al
HOME = r.CSCS_HOME
LOGIN = r.CSCS_LOGIN
FORM = (LOGIN, w._page(user=True, password=True, steps=[[True, False], [False, False]]))
CODE = (LOGIN, w._page(code=True, steps=[[False, False], [True, False]]))
LIVE = (HOME, w._page(sentinel=True))
CAPTCHA = (LOGIN, w._page(captcha=True))


def _bg(rc: int, **data: Any) -> alsafari.Reply:
    return alsafari.Reply(rc, {"ok": rc == 0, **data})


def _seen(sentinel: bool, **extra: Any) -> alsafari.Reply:
    data: dict[str, Any] = {
        "result": json.dumps({"sentinel": sentinel}),
        "background": {"window_id": 3, "tab": 9, "closed": True},
        "focus_kept": True,
        **extra,
    }
    return _bg(0, **data)


SEEN = _seen(True)
REDIRECTED = _bg(
    2,
    reason="origin",
    background={"window_id": 3, "tab": 9, "closed": True},
)


class Keep(r.Safari):
    """The cscs fake plus the probe (`--background`), `--tabs` and
    `--close-tab`; the probe's eval file is checked (0600, the marker)."""

    def __init__(self, script: list, probe: alsafari.Reply) -> None:
        recipe = al.safari_recipe("cscs")
        assert recipe is not None
        super().__init__(recipe, script)
        self.probe = probe
        self.probe_files: list[tuple[int, str]] = []
        self.tab_rows: list[dict[str, Any]] = []

    def __call__(self, args: list[str]) -> alsafari.Reply:
        if args[0] == "--background":
            self.calls.append(list(args))
            path = Path(args[args.index("--eval") + 1])
            mode = stat.S_IMODE(os.stat(path).st_mode)
            self.probe_files.append((mode, path.read_text(encoding="utf-8")))
            return self.probe
        if args[0] == "--tabs" and self.tab_rows:
            self.calls.append(list(args))
            return alsafari.Reply(0, {"ok": True, "tabs": self.tab_rows})
        if args[0] == "--close-tab":
            self.calls.append(list(args))
            return alsafari.Reply(0, {"ok": True})
        return super().__call__(args)

    def windows(self) -> list[list[str]]:
        return [c for c in self.ops("--open") if "--new-window" in c]


@pytest.fixture
def keep(cscs: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:  # noqa: F811
    """A scheduled `-k` run (AGENT_LOGIN_SCHEDULED set), Albert active, no
    guided login, safari.py with the probe's features; notifications are
    recorded."""
    every = (
        w.ALL_FEATURES
        | frozenset(alsafari.STEP_FEATURES.values())
        | frozenset({"split_otp"})
        | kal.PROBE_FEATURES
    )
    monkeypatch.setattr(alsafari, "features", lambda _c: every)
    monkeypatch.setattr(alsafari, "scheduled", lambda: True)
    monkeypatch.setattr(
        alsafari, "interactive_gate", lambda *_a: "scheduled"
    )  # what a LaunchAgent gets
    monkeypatch.setattr(alsafari, "attended_gate", lambda *_a: None)
    monkeypatch.setattr(al, "guided_busy", lambda: None)
    cscs["notes"] = []

    def send(text: str) -> bool:
        cscs["notes"].append(text)
        return True

    cscs["mails"] = []

    def mail(subject: str, body: str) -> bool:
        cscs["mails"].append((subject, body))
        return True

    monkeypatch.setattr(kal, "desktop_notify", send)
    monkeypatch.setattr(al, "send_mail", mail)  # never a real gog mail
    real = kal.notify_once
    monkeypatch.setattr(
        kal,
        "notify_once",
        lambda site, text, now, send=send, fallback=None: real(
            site, text, now, send, fallback
        ),
    )
    return cscs


def _k(st: dict[str, Any], script: list, probe: alsafari.Reply) -> int:
    st["safari"] = Keep(script, probe)
    rc: int = al.keepalive_action()
    return rc


def _attempt_at() -> Any:
    return als.read(kal.STATE_FILE).get("sites", {}).get("cscs", {}).get("attempt_at")


# ---------------------------------------------------------------------------
# the config key and the LaunchAgent
# ---------------------------------------------------------------------------


def test_the_keepalive_sites_are_one_key_and_cscs_only() -> None:
    assert kal.KEEPALIVE_SITES == ("cscs",)
    assert kal.ATTEMPT_COOLDOWN_S == 6 * 3600
    route = al.SAFARI_ROUTES["cscs"]
    assert route.proof == "in_safari" and not route.then


def test_the_launchagent_runs_k_every_30_min_under_log_ts() -> None:
    labels = [label for label, _t, _w in jobs.agent_plists()]
    assert jobs.SAFARI_KEEPALIVE_LABEL in labels
    text = jobs.safari_keepalive_plist()
    assert "<string>-k</string>" in text
    assert "<integer>1800</integer>" in text
    assert f"<key>{jobs.SCHEDULED_ENV}</key>" in text
    assert "<false/>" in text  # not at load
    if jobs.LOG_TS.is_file():
        assert f"<string>{jobs.LOG_TS}</string>" in text


# ---------------------------------------------------------------------------
# logged in: nothing touched
# ---------------------------------------------------------------------------


def test_logged_in_touches_nothing(keep: dict[str, Any]) -> None:
    assert _k(keep, [LIVE], SEEN) == 0
    fake = keep["safari"]
    bg = fake.ops("--background")
    assert len(bg) == 1 and bg[0][1] == HOME
    mode, body = fake.probe_files[0]
    assert mode == 0o600 and body.startswith(kal.PROBE_MARK)
    assert json.dumps(alsafari.CSCS_SENTINEL) in body
    # no window, no tab, no fill, no close, no stamp, no notification
    assert not fake.ops("--open", "--close", "--close-tab", *r.FILLS)
    assert _attempt_at() is None and not keep["notes"]


def test_a_probe_tab_left_open_is_closed_only_when_provably_ours(
    keep: dict[str, Any],
) -> None:
    left = _seen(True, background={"window_id": 3, "tab": 9, "closed": False})
    fake = Keep([LIVE], left)
    fake.tab_rows = [
        {"window_id": 3, "tab": 1, "current": True, "url": "https://x.example/"},
        {"window_id": 3, "tab": 9, "current": False, "url": HOME},
    ]
    keep["safari"] = fake
    assert al.keepalive_action() == 0
    assert fake.ops("--close-tab") == [
        ["--close-tab", "3:9", "--expect-host", "portal.cscs.ch"]
    ]


@pytest.mark.parametrize(
    "rows",
    [
        # the current tab: Albert took it over
        [
            {"window_id": 3, "tab": 1, "current": False, "url": "https://x.example/"},
            {"window_id": 3, "tab": 9, "current": True, "url": HOME},
        ],
        # another host
        [
            {"window_id": 3, "tab": 1, "current": True, "url": "https://x.example/"},
            {"window_id": 3, "tab": 9, "current": False, "url": "https://x.example/"},
        ],
        # not the window's last tab
        [
            {"window_id": 3, "tab": 9, "current": False, "url": HOME},
            {"window_id": 3, "tab": 10, "current": True, "url": "https://x.example/"},
        ],
        # the window's only tab
        [{"window_id": 3, "tab": 9, "current": False, "url": HOME}],
    ],
)
def test_a_left_tab_that_may_be_alberts_is_never_closed(
    keep: dict[str, Any], rows: list[dict[str, Any]]
) -> None:
    left = _seen(True, background={"window_id": 3, "tab": 9, "closed": False})
    fake = Keep([LIVE], left)
    fake.tab_rows = rows
    keep["safari"] = fake
    assert al.keepalive_action() == 0
    assert not fake.ops("--close-tab")


# ---------------------------------------------------------------------------
# logged out: -O proof, then the login (scheduled — the exemption)
# ---------------------------------------------------------------------------


def test_logged_out_proves_then_logs_in_without_opening_a_page(
    keep: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    rc = _k(keep, [FORM, CODE, LIVE], REDIRECTED)
    assert rc == 0
    fake = keep["safari"]
    # two Machine windows: the -O proof (nothing typed), then the login
    assert len(fake.windows()) == 2
    fills = fake.ops(*r.FILLS)
    assert [c[0] for c in fills] == ["--login", "--otp"]
    first_fill = fake.calls.index(fills[0])
    second_window = [i for i, c in enumerate(fake.calls) if c in fake.windows()][1]
    assert second_window < first_fill  # nothing typed in the proof's window
    assert not fake.landing_opens()  # no page opened afterwards
    assert isinstance(_attempt_at(), float)
    out = capsys.readouterr().out
    assert "safari_logged_out" in out and "keep-alive: no page opened" in out


def test_the_proof_finding_a_session_logs_nothing_in(keep: dict[str, Any]) -> None:
    assert _k(keep, [LIVE], _seen(False)) == 0
    fake = keep["safari"]
    assert len(fake.windows()) == 1 and not fake.ops(*r.FILLS)
    assert not fake.landing_opens()


@pytest.mark.parametrize(
    "probe",
    [
        _bg(1, error="x"),  # osascript / JS error
        _bg(3, error="Safari is not running"),
        _bg(2, reason="disabled"),
        _bg(0, result="not json"),
        alsafari.Reply(1, {}, "timeout", killed=True),
    ],
)
def test_an_unknown_probe_never_proves_or_logs_in(
    keep: dict[str, Any], probe: alsafari.Reply
) -> None:
    assert _k(keep, [FORM], probe) == 0
    fake = keep["safari"]
    assert not fake.windows() and not fake.ops(*r.FILLS)
    assert _attempt_at() is None


@pytest.mark.parametrize("code", ["recipe_stuck", "safari_window_unknown"])
def test_a_proof_without_safari_logged_out_never_logs_in(
    keep: dict[str, Any], monkeypatch: pytest.MonkeyPatch, code: str
) -> None:
    monkeypatch.setattr(
        al, "_keepalive_prove", lambda _s, _r: alsafari.Outcome(2, code)
    )
    called: list[str] = []

    def login(*_a: Any, **_k: Any) -> int:
        called.append("login")
        return 0

    monkeypatch.setattr(al, "safari_target_action", login)
    assert _k(keep, [FORM], REDIRECTED) == 1
    assert not called


def test_needs_albert_notifies_once_then_cooldown(
    keep: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    assert _k(keep, [CAPTCHA], REDIRECTED) == 0
    assert len(keep["notes"]) == 1 and "cscs" in keep["notes"][0]
    assert not keep["safari"].ops(*r.FILLS)
    # the next run (30 min later): the attempt cooldown holds — no proof, no note
    assert _k(keep, [CAPTCHA], REDIRECTED) == 0
    assert not keep["safari"].windows() and len(keep["notes"]) == 1
    # after the attempt cooldown the notification cooldown still holds
    future = time.time() + kal.ATTEMPT_COOLDOWN_S + 1
    monkeypatch.setattr(al.time, "time", lambda: future)
    real_left = kal.cooldown_left
    monkeypatch.setattr(
        kal,
        "cooldown_left",
        lambda site, key, span, now: (
            real_left(site, key, span, now) if key == "attempt_at" else 1.0
        ),
    )
    assert _k(keep, [CAPTCHA], REDIRECTED) == 0
    assert len(keep["safari"].windows()) == 1 and len(keep["notes"]) == 1


def test_a_failed_login_counts_against_the_cooldown(
    keep: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    logins: list[str] = []

    def login(site: str, url: str, **kw: Any) -> int:
        assert kw == {"keepalive": True} and url == ""
        logins.append(site)
        return 2

    monkeypatch.setattr(al, "safari_target_action", login)
    assert _k(keep, [FORM], REDIRECTED) == 1
    assert logins == ["cscs"]
    # any failed re-login notifies (once)
    assert len(keep["notes"]) == 1 and "-L cscs -s" in keep["notes"][0]
    assert _k(keep, [FORM], REDIRECTED) == 0  # cooldown: skipped
    assert logins == ["cscs"] and not keep["safari"].windows()
    assert len(keep["notes"]) == 1 and not keep["mails"]


def test_a_busy_login_is_a_skip_without_a_notification(
    keep: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(al, "safari_target_action", lambda *_a, **_k: al.BUSY_RC)
    assert _k(keep, [FORM], REDIRECTED) == 0
    assert not keep["notes"] and not keep["mails"]


def test_a_failed_banner_falls_back_to_one_mail(
    keep: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    real = kal.notify_once
    monkeypatch.setattr(
        kal,
        "notify_once",
        lambda site, text, now, send=None, fallback=None: real(
            site, text, now, lambda _t: False, fallback
        ),
    )
    monkeypatch.setattr(al, "safari_target_action", lambda *_a, **_k: 2)
    assert _k(keep, [FORM], REDIRECTED) == 1
    assert len(keep["mails"]) == 1
    subject, body = keep["mails"][0]
    assert "cscs" in subject and "-L cscs -s" in body


def test_notify_once_mails_only_when_the_banner_failed() -> None:
    mails: list[str] = []

    def mail(text: str) -> bool:
        mails.append(text)
        return True

    now = time.time()
    assert kal.notify_once("a", "x", now, lambda _t: True, mail) == "sent"
    assert kal.notify_once("b", "x", now, lambda _t: False, mail) == "mailed"
    assert kal.notify_once("c", "x", now, lambda _t: False, None) == "failed"
    assert kal.notify_once("b", "x", now, lambda _t: False, mail) == "suppressed"
    assert mails == ["x"]


@pytest.mark.parametrize("why", ["idle", "quarantine", "guided", "unreadable"])
def test_the_stops_skip_before_any_window(
    keep: dict[str, Any], monkeypatch: pytest.MonkeyPatch, why: str
) -> None:
    if why == "idle":
        monkeypatch.setattr(alsafari, "attended_gate", lambda *_a: "albert_idle")
    elif why == "quarantine":
        als.quarantine("cscs", "submit", "unknown")
    elif why == "guided":
        monkeypatch.setattr(al, "guided_busy", lambda: "busy: guided login for x")
    else:
        (als.state_dir() / kal.STATE_FILE).write_text("{oops", encoding="utf-8")
    assert _k(keep, [FORM], REDIRECTED) == 0
    fake = keep["safari"]
    assert not fake.windows() and not fake.ops(*r.FILLS)
    if why == "idle":
        assert not fake.ops("--background")  # Safari not touched at all


def test_a_quarantine_written_by_the_login_stops_the_next_runs(
    keep: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    als.quarantine("cscs", "submit", "unknown")
    monkeypatch.setattr(kal, "cooldown_left", lambda *_a: 0.0)
    assert _k(keep, [FORM], REDIRECTED) == 0
    assert not keep["safari"].windows()


# ---------------------------------------------------------------------------
# the exemption is narrow
# ---------------------------------------------------------------------------


def test_plain_s_still_refuses_in_a_launchagent(
    keep: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    keep["safari"] = Keep([FORM], SEEN)
    assert al.safari_target_action("cscs", "") == 2
    assert al.safari_login_action("cscs") == 2
    assert "never from a LaunchAgent" in capsys.readouterr().out
    assert not keep["safari"].calls


def test_keepalive_refuses_a_site_outside_the_key(
    keep: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(alsafari.BROKER_SAFARI_LABELS, "cscs", r.CSCS_REAL)
    keep["safari"] = Keep([FORM], SEEN)
    monkeypatch.setattr(kal, "KEEPALIVE_SITES", ())
    assert al.safari_target_action("cscs", "", keepalive=True) == 2
    assert al.keepalive_site("cscs") == 2
    assert not keep["safari"].calls


def test_keepalive_refuses_a_url_or_dry_run(keep: dict[str, Any]) -> None:
    keep["safari"] = Keep([FORM], SEEN)
    assert al.safari_target_action("cscs", HOME, keepalive=True) == 2
    assert al.safari_target_action("cscs", "", keepalive=True, dry_run=True) == 2
    assert not keep["safari"].ops("--open", *r.FILLS)


def test_keepalive_login_uses_the_attended_gate(
    keep: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(alsafari, "attended_gate", lambda *_a: "console_locked")
    keep["safari"] = Keep([FORM], SEEN)
    assert al.safari_target_action("cscs", "", keepalive=True) == 3
    assert not keep["safari"].ops("--open", *r.FILLS)


def test_attended_gate_has_no_scheduled_refusal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(alsafari, "scheduled", lambda: True)
    monkeypatch.setattr(alsafari, "attended", lambda _uid, _run: None)
    assert alsafari.interactive_gate() == "scheduled"
    assert alsafari.attended_gate() is None
    monkeypatch.setattr(alsafari, "attended", lambda _uid, _run: "albert_idle")
    assert alsafari.attended_gate() == "albert_idle"


# ---------------------------------------------------------------------------
# the pure parts
# ---------------------------------------------------------------------------


def test_classify() -> None:
    assert kal.classify(SEEN).state == "logged_in"
    assert kal.classify(_seen(False)).state == "not_proven"
    assert kal.classify(REDIRECTED) == kal.Probe("not_proven", "left_origin")
    assert kal.classify(_bg(2, reason="lost")).state == "error"
    assert kal.classify(_bg(0, result=json.dumps({"x": 1}))).state == "error"
    left = kal.classify(
        _seen(True, background={"window_id": 3, "tab": 9, "closed": False})
    )
    assert left.tab_left == (3, 9) and left.focus_kept is True


def test_the_cooldown_fails_closed(tmp_path: Path) -> None:
    now = time.time()
    assert kal.cooldown_left("cscs", "attempt_at", 100.0, now) == 0.0
    assert kal.stamp("cscs", "attempt_at", now)
    left = kal.cooldown_left("cscs", "attempt_at", 100.0, now + 40)
    assert left is not None and 59 < left <= 60
    assert kal.cooldown_left("cscs", "attempt_at", 100.0, now - 10) == 100.0
    path = als.state_dir() / kal.STATE_FILE
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    path.write_text(json.dumps({"sites": {"cscs": {"attempt_at": "x"}}}))
    assert kal.cooldown_left("cscs", "attempt_at", 100.0, now) is None
    path.write_text("[]")
    assert kal.cooldown_left("cscs", "attempt_at", 100.0, now) is None
    assert not kal.stamp("cscs", "attempt_at", now)


def test_desktop_notify_passes_the_text_as_argv() -> None:
    seen: list[list[str]] = []

    class Res:  # pylint: disable=too-few-public-methods
        returncode = 0

    def fake_run(args: list[str], **_k: Any) -> Res:
        seen.append(args)
        return Res()

    assert kal.desktop_notify('say "hi"', run=fake_run)
    args = seen[0]
    assert args[0] == "/usr/bin/osascript" and args[-1] == 'say "hi"'
    assert all('say "hi"' not in a for a in args[:-1])


def test_the_cli_has_k_and_it_runs_alone() -> None:
    ap = al.build_parser()
    assert ap.parse_args(["-k"]).keep_alive
    assert ap.parse_args(["--keep-alive"]).keep_alive
