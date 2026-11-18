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
# What the live logged-out portal gives (tp#1644, 2026-11-17): the tab went
# to auth.cscs.ch, safari.py no longer finds it on its origin (`bg-lost`),
# cannot close it either.
LOST = _bg(
    2,
    reason="bg-lost",
    background={"window_id": 3, "tab": 9, "closed": False},
)
LOST_ROWS = [
    {"window_id": 3, "tab": 1, "current": True, "url": "https://x.example/"},
    {"window_id": 3, "tab": 9, "current": False, "url": LOGIN},
]


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
        self.rows_once = False  # the rows answer only the first --tabs

    def __call__(self, args: list[str]) -> alsafari.Reply:
        if args[0] == "--background":
            self.calls.append(list(args))
            path = Path(args[args.index("--eval") + 1])
            mode = stat.S_IMODE(os.stat(path).st_mode)
            self.probe_files.append((mode, path.read_text(encoding="utf-8")))
            return self.probe
        if args[0] == "--tabs" and self.tab_rows:
            self.calls.append(list(args))
            rows = self.tab_rows
            if self.rows_once:
                self.tab_rows = []
            return alsafari.Reply(0, {"ok": True, "tabs": rows})
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
        _bg(2, reason="disabled"),
        _bg(2, reason="bg-lost"),
        _bg(0, result="not json"),
        alsafari.Reply(1, {}, "timeout", killed=True),
    ],
)
def test_a_probe_that_cannot_tell_goes_on_to_the_proof(
    keep: dict[str, Any], probe: alsafari.Reply, capsys: pytest.CaptureFixture[str]
) -> None:
    """The background probe is never proof either way (tp#1644): "could not
    tell" runs the -O proof, and its safari_logged_out the login."""
    assert _k(keep, [FORM, CODE, LIVE], probe) == 0
    fake = keep["safari"]
    assert len(fake.windows()) == 2  # the -O proof, then the login
    assert [c[0] for c in fake.ops(*r.FILLS)] == ["--login", "--otp"]
    assert isinstance(_attempt_at(), float)
    out = capsys.readouterr().out
    assert "could not tell" not in out and "safari_logged_out" in out


def test_the_live_bg_lost_probe_closes_its_tab_and_logs_in(
    keep: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    fake = Keep([FORM, CODE, LIVE], LOST)
    fake.tab_rows, fake.rows_once = LOST_ROWS, True
    keep["safari"] = fake
    assert al.keepalive_action() == 0
    assert fake.ops("--close-tab") == [
        ["--close-tab", "3:9", "--expect-host", "auth.cscs.ch"]
    ]
    assert len(fake.windows()) == 2
    # one listing locates the tab AND checks it before the close
    first_window = fake.calls.index(fake.windows()[0])
    assert [c[0] for c in fake.calls[:first_window]].count("--tabs") == 1
    out = capsys.readouterr().out
    # tp#1644: the tab sits on CSCS's Keycloak — named, redacted (no query)
    assert "login_host" in out and "logged in again" in out
    assert "the probe tab was on auth.cscs.ch/auth/realms/cscs/protocol" in out
    assert not keep["notes"]


def test_a_lost_probe_tab_that_is_gone_still_goes_to_the_proof(
    keep: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    """tp#1644: no tab at the probe's place — `tab_gone`, never a reason to
    skip the renewal: the -O proof decides, its safari_logged_out logs in."""
    fake = Keep([FORM, CODE, LIVE], LOST)
    fake.tab_rows, fake.rows_once = LOST_ROWS[:1], True
    keep["safari"] = fake
    assert al.keepalive_action() == 0
    assert not fake.ops("--close-tab")
    assert len(fake.windows()) == 2
    assert [c[0] for c in fake.ops(*r.FILLS)] == ["--login", "--otp"]
    out = capsys.readouterr().out
    assert "tab_gone" in out and "logged in again" in out


def test_a_stuck_proof_says_where_it_stopped(
    keep: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """tp#1644 (2026-11-18 08:30): a `recipe_stuck` -O proof names its stuck
    reason, host and the page's shape — no login, the cooldown is spent."""
    stuck = alsafari.Outcome(2, "recipe_stuck")
    stuck.stuck, stuck.stuck_host = "step_conditions_unmet", "auth.cscs.ch"
    stuck.page = "path: /auth/realms/cscs/x; buttons: Go"
    monkeypatch.setattr(al, "_keepalive_prove", lambda _s, _r: stuck)
    assert _k(keep, [FORM], REDIRECTED) == 1
    got = capsys.readouterr()
    assert "found no step (step_conditions_unmet on auth.cscs.ch)" in got.out
    assert "the page showed — path: /auth/realms/cscs/x; buttons: Go" in got.err
    assert isinstance(_attempt_at(), float)
    assert not keep["safari"].ops(*r.FILLS)


def test_the_cooldown_left_rounds_up(
    keep: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    """tp#1644 (14:30 run): 18 s left read "0 min left" — now "1 min"
    (left = the window less the slack)."""
    at = time.time() - kal.ATTEMPT_COOLDOWN_S + kal.ATTEMPT_SLACK_S + 18
    assert kal.stamp("cscs", "attempt_at", at)
    assert _k(keep, [FORM], REDIRECTED) == 0
    assert "one attempt per 6 h — 1 min left" in capsys.readouterr().out
    assert not keep["safari"].windows()


def _kind() -> Any:
    sites = als.read(kal.STATE_FILE).get("sites", {})
    return sites.get("cscs", {}).get("attempt_kind")


def test_an_untyped_proof_stop_waits_1_h(
    keep: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Albert (2026-11-18): a -O proof that stopped with nothing typed
    (recipe_stuck, no credential step) → the next attempt after 1 h."""
    stuck = alsafari.Outcome(2, "recipe_stuck")
    proofs: list[str] = []

    def prove(_s: str, _r: Any) -> alsafari.Outcome:
        proofs.append("proof")
        return stuck

    monkeypatch.setattr(al, "_keepalive_prove", prove)
    t0 = 1_800_000_000.0
    monkeypatch.setattr(al.time, "time", lambda: t0)
    assert _k(keep, [FORM], REDIRECTED) == 1
    assert _attempt_at() == t0 and _kind() == kal.ATTEMPT_UNTYPED
    assert "typed nothing — next attempt in 1 h" in capsys.readouterr().out
    # 30 min later: held, the log says why (1 h, not 6 h)
    monkeypatch.setattr(al.time, "time", lambda: t0 + 1800)
    assert _k(keep, [FORM], REDIRECTED) == 0
    out = capsys.readouterr().out
    assert "one attempt per 1 h after a -O proof that typed nothing" in out
    assert proofs == ["proof"]
    # the next launchd run, a few seconds before the full hour: allowed
    monkeypatch.setattr(al.time, "time", lambda: t0 + 3600 - 5)
    assert _k(keep, [FORM], REDIRECTED) == 1
    assert proofs == ["proof", "proof"] and _attempt_at() == t0 + 3600 - 5


@pytest.mark.parametrize("how", ["credential_proof", "failed_login"])
def test_a_typed_run_keeps_6_h(
    keep: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    how: str,
) -> None:
    """A run in which a credential step ran keeps the full 6 h: a proof
    whose Outcome says credential, or the login after safari_logged_out."""
    if how == "credential_proof":
        typed = alsafari.Outcome(2, "recipe_stuck", credential=True)
        monkeypatch.setattr(al, "_keepalive_prove", lambda _s, _r: typed)
    else:
        monkeypatch.setattr(al, "safari_target_action", lambda *_a, **_k: 2)
    t0 = 1_800_000_000.0
    monkeypatch.setattr(al.time, "time", lambda: t0)
    assert _k(keep, [FORM], REDIRECTED) == 1
    assert _attempt_at() == t0 and _kind() == kal.ATTEMPT_TYPED
    assert "typed nothing" not in capsys.readouterr().out
    for later in (3600.0, 6 * 3600.0 - 121):
        monkeypatch.setattr(al.time, "time", lambda later=later: t0 + later)
        assert _k(keep, [FORM], REDIRECTED) == 0
        assert "one attempt per 6 h — " in capsys.readouterr().out
    assert _attempt_at() == t0


@pytest.mark.parametrize(
    ("untyped", "span"),
    [(False, kal.ATTEMPT_COOLDOWN_S), (True, kal.ATTEMPT_UNTYPED_COOLDOWN_S)],
)
def test_the_attempt_slack_on_both_sides(untyped: bool, span: float) -> None:
    """An attempt is allowed once span − 120 s have passed, not before."""
    t0 = 1_800_000_000.0
    assert kal.stamp_attempt("cscs", t0)
    if untyped:
        assert kal.mark_untyped("cscs", t0)
    kind = kal.ATTEMPT_UNTYPED if untyped else kal.ATTEMPT_TYPED
    assert kal.attempt_left("cscs", t0 + span - 121) == (1.0, kind)
    assert kal.attempt_left("cscs", t0 + span - 120) == (0.0, kind)
    assert kal.attempt_left("cscs", t0 + span - 119) == (0.0, kind)
    # a newer stamp is never re-marked by an older attempt
    assert kal.stamp_attempt("cscs", t0 + 10)
    assert not kal.mark_untyped("cscs", t0)
    assert kal.attempt_kind("cscs") == kal.ATTEMPT_TYPED


def test_an_old_format_stamp_counts_as_typed() -> None:
    """A stamp written before the kind existed (`attempt_at` only) = 6 h."""
    t0 = 1_800_000_000.0
    path = als.state_dir() / kal.STATE_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"sites": {"cscs": {"attempt_at": t0}}}))
    path.chmod(0o600)
    assert kal.attempt_kind("cscs") == kal.ATTEMPT_TYPED
    left, kind = kal.attempt_left("cscs", t0 + 3600)
    assert kind == kal.ATTEMPT_TYPED and left == 5 * 3600 - 120
    assert kal.attempt_left("cscs", t0 + 6 * 3600 - 120) == (0.0, kal.ATTEMPT_TYPED)
    # an unknown kind word counts as the longer window too
    path.write_text(
        json.dumps({"sites": {"cscs": {"attempt_at": t0, "attempt_kind": "x"}}})
    )
    assert kal.attempt_left("cscs", t0 + 3600)[1] == kal.ATTEMPT_TYPED
    # unreadable: fail closed
    path.write_text("[]")
    assert kal.attempt_left("cscs", t0) == (None, kal.ATTEMPT_TYPED)


def test_a_probe_that_cannot_tell_and_a_live_proof_logs_nothing_in(
    keep: dict[str, Any],
) -> None:
    assert _k(keep, [LIVE], _bg(1, error="x")) == 0
    fake = keep["safari"]
    assert len(fake.windows()) == 1 and not fake.ops(*r.FILLS)


def test_safari_not_answering_the_probe_is_a_skip(keep: dict[str, Any]) -> None:
    assert _k(keep, [FORM], _bg(3, error="Safari is not running")) == 0
    fake = keep["safari"]
    assert not fake.windows() and not fake.ops(*r.FILLS)
    assert _attempt_at() is None


def test_the_cooldown_still_holds_after_a_probe_that_cannot_tell(
    keep: dict[str, Any],
) -> None:
    assert kal.stamp("cscs", "attempt_at", time.time())
    assert _k(keep, [FORM], _bg(1, error="x")) == 0
    fake = keep["safari"]
    assert not fake.windows() and not fake.ops(*r.FILLS)


def _unproven() -> Any:
    sites = als.read(kal.STATE_FILE).get("sites", {})
    return sites.get("cscs", {}).get("unproven_runs")


def test_runs_without_a_proven_session_notify_once(
    keep: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    """N runs in a row without a proven session (here: the probe cannot
    tell, the attempt cooldown holds) → one notification, then its 6 h
    cooldown; never silent."""
    assert kal.stamp("cscs", "attempt_at", time.time())
    for n in range(1, kal.UNPROVEN_NOTIFY_AFTER):
        assert _k(keep, [FORM], LOST) == 0
        assert _unproven() == n and not keep["notes"]
    assert _k(keep, [FORM], LOST) == 0
    assert _unproven() == kal.UNPROVEN_NOTIFY_AFTER
    assert len(keep["notes"]) == 1
    assert "-L cscs -s -O" in keep["notes"][0]
    # the fake lists no tab at the probe's place: tp#1644 `kal.locate`
    assert "tab_gone" in keep["notes"][0]
    assert _k(keep, [FORM], LOST) == 0
    assert len(keep["notes"]) == 1  # the notification cooldown
    assert "without a proven session — notification suppressed" in (
        capsys.readouterr().out
    )


def test_a_proven_session_resets_the_count(keep: dict[str, Any]) -> None:
    assert kal.stamp("cscs", "attempt_at", time.time())
    assert _k(keep, [FORM], LOST) == 0
    assert _k(keep, [FORM], LOST) == 0
    assert _unproven() == 2
    assert _k(keep, [LIVE], SEEN) == 0
    assert _unproven() == 0
    assert _k(keep, [FORM], LOST) == 0
    assert _unproven() == 1 and not keep["notes"]


def test_a_working_proof_or_login_resets_the_count(keep: dict[str, Any]) -> None:
    assert kal.unproven_runs("cscs", proven=False) == 1
    assert _k(keep, [LIVE], LOST) == 0  # the -O proof finds the session
    assert _unproven() == 0
    assert kal.unproven_runs("cscs", proven=False) == 1
    # the next attempt only after the 6 h cooldown
    assert kal.stamp("cscs", "attempt_at", time.time() - kal.ATTEMPT_COOLDOWN_S - 1)
    assert _k(keep, [FORM, CODE, LIVE], LOST) == 0  # proof → login
    assert _unproven() == 0


def test_a_busy_guided_login_counts_neither_way(
    keep: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(al, "guided_busy", lambda: "busy: guided login for x")
    for _ in range(kal.UNPROVEN_NOTIFY_AFTER + 1):
        assert _k(keep, [FORM], LOST) == 0
    assert _unproven() is None and not keep["notes"]


def test_unproven_runs_fails_closed() -> None:
    (als.state_dir() / kal.STATE_FILE).write_text("[]", encoding="utf-8")
    assert kal.unproven_runs("cscs", proven=False) is None


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
    assert kal.classify(LOST) == kal.Probe(
        "error", "tab_lost_or_left_origin", (3, 9), None
    )
    assert kal.classify(_bg(0, result=json.dumps({"x": 1}))).state == "error"
    left = kal.classify(
        _seen(True, background={"window_id": 3, "tab": 9, "closed": False})
    )
    assert left.tab_left == (3, 9) and left.focus_kept is True
    # no_sentinel names where the page rendered (host + path, redacted)
    plain = kal.classify(_seen(False, url=HOME + "?next=x"))
    assert plain.why == "no_sentinel" and plain.hint == "portal.cscs.ch/profile"


def test_tab_hint_keeps_host_and_plain_path_words_only() -> None:
    url = (
        "https://auth.cscs.ch/auth/realms/cscs/login-actions/authenticate"
        "?execution=9d89&client_data=secret#frag"
    )
    assert (
        kal.tab_hint(url) == "auth.cscs.ch/auth/realms/cscs/login-actions/authenticate"
    )
    assert kal.tab_hint("https://x.example/reset/abc123def/9") == "x.example/reset/*/*"
    assert kal.tab_hint("http://x.example/a") == ""
    assert kal.tab_hint(None) == ""


def test_locate() -> None:
    hosts, home = ("portal.cscs.ch", "auth.cscs.ch"), "portal.cscs.ch"
    lost = kal.classify(LOST)
    got = kal.locate(lost, LOST_ROWS, hosts, home)
    assert got.state == "not_proven" and got.why == "login_host"
    assert got.hint == "auth.cscs.ch/auth/realms/cscs/protocol/openid-connect/auth"
    assert kal.locate(lost, LOST_ROWS[:1], hosts, home).why == "tab_gone"
    assert kal.locate(lost, None, hosts, home) == lost
    other = [{"window_id": 3, "tab": 9, "url": "https://x.example/a"}]
    moved = kal.locate(lost, other, hosts, home)
    assert moved.why == "tab_lost_or_left_origin" and moved.hint == "x.example/a"
    # only a bg-lost probe is located
    seen = kal.classify(SEEN)
    assert kal.locate(seen, LOST_ROWS, hosts, home) == seen


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
