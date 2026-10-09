"""Unit tests for scripts/tp871_gate.py's pure parts (no browser, no desktop).

The idle-guard parser and decision, the lsappinfo parser, the plan of runs and
resume, the per-variant pass rule, the 0d verdict, and focus_watch segment
counting with the off-display rule.

Run: uv run --no-sync pytest -q tests/test_tp871_gate.py
"""

from __future__ import annotations

# pylint: disable=missing-function-docstring,redefined-outer-name
import importlib.util
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod  # dataclasses resolve their module by name
    spec.loader.exec_module(mod)
    return mod


gate = _load("tp871_gate", _ROOT / "scripts" / "tp871_gate.py")
fw = _load("focus_watch", _ROOT / "bin" / "focus_watch.py")

IOREG = """
+-o IOHIDSystem  <class IOHIDSystem, id 0x100000abc, registered, matched>
    {
      "HIDIdleTime" = 812345678901
      "HIDParameters" = {"HIDClickTime"=500000000}
    }
"""


# -- idle guard --------------------------------------------------------------


def test_parse_hid_idle_s():
    assert gate.parse_hid_idle_s(IOREG) == pytest.approx(812.345678901)
    assert gate.parse_hid_idle_s("no such key") is None
    assert gate.parse_hid_idle_s("") is None


@pytest.mark.parametrize(
    ("idle", "since_synthetic", "active"),
    [
        (None, None, True),  # unknown fails closed
        (601.0, None, False),
        (600.0, None, False),
        (12.0, None, True),
        (12.0, 12.5, False),  # our own Cmd-` 12.5 s ago reset the counter
        (3.0, 12.5, True),  # input AFTER our event: Albert is back
    ],
)
def test_user_active(idle, since_synthetic, active):
    assert gate.user_active(idle, since_synthetic) is active


def test_parse_lsappinfo_pid():
    assert gate.parse_lsappinfo_pid('"pid"=4321\n') == 4321
    assert gate.parse_lsappinfo_pid('"pid" = 17') == 17
    assert gate.parse_lsappinfo_pid("") is None


def test_live_cache_is_refused(tmp_path):
    home = Path.home()
    assert gate.is_live_cache(home / ".cache" / "claude-browser")
    assert gate.is_live_cache(home / ".cache" / "claude-browser-private" / "x")
    assert not gate.is_live_cache(home / ".local" / "state" / "tp871" / "cache")
    assert not gate.is_live_cache(tmp_path / "cache")


def test_reserved_ports_are_refused(capsys):
    for port in ("9222", "9223"):
        with pytest.raises(SystemExit) as exc:
            gate.main(["-p", port, "-n"])
        assert exc.value.code == 2
    assert "shared browser's port" in capsys.readouterr().err


# -- plan of runs ------------------------------------------------------------


def test_plan_resumes_and_stops_after_a_control_that_did_not_freeze():
    names = [v.name for v in gate.pending_variants({}, with_0c=False)]
    assert names == ["V0", "V1", "V2", "V3"]
    assert [v.name for v in gate.pending_variants({}, with_0c=True)][-2:] == [
        "V1c",
        "V2c",
    ]
    results = {
        "V0": {"status": "done", "reproduced": True},
        "V1": {"status": "aborted", "reason": gate.ABORT_USER_ACTIVE},
        "V2": {"status": "done"},
    }
    assert [v.name for v in gate.pending_variants(results, False)] == ["V1", "V3"]
    assert (
        gate.pending_variants({"V0": {"status": "done", "reproduced": False}}, True)
        == []
    )


def test_variant_durations():
    v0, v3 = gate.VARIANT_BY_NAME["V0"], gate.VARIANT_BY_NAME["V3"]
    assert gate.variant_duration(v0, 900) == 900
    assert gate.variant_duration(v3, 900) == 300
    assert gate.variant_duration(v3, 60) == 60


def test_off_screen_payloads_match_the_plan():
    v1, v2 = gate.VARIANT_BY_NAME["V1"].params, gate.VARIANT_BY_NAME["V2"].params
    assert v1 == {
        "newWindow": True,
        "background": True,
        "left": -32000,
        "top": -32000,
        "width": 1280,
        "height": 900,
    }
    assert v2 == {**v1, "background": False, "focus": False}
    assert gate.VARIANT_BY_NAME["V0"].params == {"background": True}


# -- per-variant verdict -----------------------------------------------------


def _fw_ok():
    seg = {"counted": 0, "activations": 0, "window_raise": 0}
    return {"recorded": True, **{s: dict(seg) for s in gate.COUNTED_SEGMENTS}}


def _passing(**over):
    res = {
        "status": "done",
        "duration_s": 900,
        "evals": {"n": 900, "slow": 0, "unanswered": 0, "not_visible": 0},
        "page_events": {"freeze": 0},
        "connects": {"n": 180, "failures": 0},
        "human": {"n": 900, "not_visible": 0, "raf_stalls": 0, "unanswered": 0},
        "windows": {"bounds_exact": True},
        "cases": {"i": {"ok": True}, "ii": {"ok": True}},
        "fw": _fw_ok(),
    }
    res.update(over)
    return res


def test_reproduced_by_unanswered_freeze_or_connect():
    assert gate.reproduced(_passing()) == (False, [])
    hit, why = gate.reproduced(
        _passing(evals={"n": 10, "unanswered": 2}, connects={"failures": 1})
    )
    assert hit and len(why) == 2
    assert gate.reproduced(_passing(page_events={"freeze": 1}))[0]


def test_variant_pass_rule():
    v1 = gate.VARIANT_BY_NAME["V1"]
    assert gate.variant_pass(_passing(), v1) == (True, [])
    ok, why = gate.variant_pass(_passing(windows={"bounds_exact": False}), v1)
    assert not ok and "bounds differ" in why[0]
    ok, why = gate.variant_pass(_passing(cases={"i": {"ok": True}, "ii": {}}), v1)
    assert not ok and why == ["case (ii) did not land in H"]
    fw_bad = _fw_ok()
    fw_bad["steady"] = {"counted": 1, "activations": 0, "window_raise": 0}
    ok, why = gate.variant_pass(_passing(fw=fw_bad), v1)
    assert not ok and "focus_watch steady" in why[0]
    ok, why = gate.variant_pass(_passing(fw={}), v1)
    assert not ok and "focus_watch log missing" in why[0]
    ok, _why = gate.variant_pass(
        _passing(evals={"n": 900, "slow": 1, "unanswered": 0, "not_visible": 0}), v1
    )
    assert not ok
    # The control and the evidence-only variant are never judged.
    assert gate.variant_pass(_passing(), gate.VARIANT_BY_NAME["V0"]) == (None, [])
    assert gate.variant_pass(_passing(), gate.VARIANT_BY_NAME["V3"]) == (None, [])


def test_variant_pass_0c_needs_focus_and_every_character():
    v1c = gate.VARIANT_BY_NAME["V1c"]
    good = _passing(
        typing={"sent": 1500, "lost": 0},
        activation={"frontmost": True},
        human={"n": 300, "not_visible": 0, "raf_stalls": 0, "unanswered": 0},
    )
    assert gate.variant_pass(good, v1c) == (True, [])
    ok, why = gate.variant_pass({**good, "typing": {"sent": 1500, "lost": 3}}, v1c)
    assert not ok and "3 typed character(s) lost" in why
    ok, why = gate.variant_pass({**good, "activation": {"frontmost": False}}, v1c)
    assert not ok and "inconclusive" in why[0]


# -- 0d verdict --------------------------------------------------------------


def _done(**over):
    return {"status": "done", "duration_s": 900, **over}


def test_verdict_requires_a_reproduced_control():
    assert gate.overall_verdict({}, False)["state"] == "incomplete"
    out = gate.overall_verdict({"V0": _done(reproduced=False)}, False)
    assert out["state"] == "freeze not reproduced"
    assert out["valid"] is False and out["choice"] is None


def test_verdict_picks_v1_then_v2_then_fallback():
    base = {"V0": _done(reproduced=True), "V3": _done(duration_s=300, **{"pass": None})}
    out = gate.overall_verdict(
        {**base, "V1": _done(**{"pass": True}), "V2": _done(**{"pass": True})}, False
    )
    assert out["state"] == "complete" and out["choice"] == "V1"
    assert "explicit OK" in out["note"]  # 0c skipped: residual named
    assert out["smoke"] is False
    out = gate.overall_verdict(
        {**base, "V1": _done(**{"pass": False}), "V2": _done(**{"pass": True})}, False
    )
    assert out["choice"] is None and "without 0c" in out["note"]
    results = {
        **base,
        "V1": _done(**{"pass": False}),
        "V2": _done(**{"pass": True}),
        "V1c": _done(duration_s=300, **{"pass": False}),
        "V2c": _done(duration_s=300, **{"pass": True}),
    }
    assert gate.overall_verdict(results, True)["choice"] == "V2"
    # V1 passes 0b but fails 0c: V1 is out.
    results["V1"] = _done(**{"pass": True})
    assert gate.overall_verdict(results, True)["choice"] == "V2"
    out = gate.overall_verdict(
        {**base, "V1": _done(**{"pass": False}), "V2": _done(**{"pass": False})}, False
    )
    assert out["choice"] == "F1 -> (c)"


def test_verdict_flags_smoke_runs_and_missing_variants():
    out = gate.overall_verdict(
        {"V0": _done(duration_s=60, reproduced=True), "V1": _done(**{"pass": True})},
        False,
    )
    assert out["smoke"] is True
    assert out["state"] == "incomplete" and out["missing"] == ["V2", "V3"]


# -- focus_watch segments ----------------------------------------------------


def test_fw_segment_counts_only_the_disposable_inside_the_segment():
    def rec(ts, event, pid=7, **extra):
        return {
            "ts": ts,
            "event": event,
            "app": "CfT",
            "pid": pid,
            "chrome": True,
            **extra,
        }

    records = [
        rec("2026-10-09T10:00:00.000+02:00", "window_new", window=1, on_screen=True),
        rec(  # off-display check window: informational
            "2026-10-09T10:00:05.000+02:00",
            "window_new",
            window=2,
            on_screen=True,
            on_display=False,
        ),
        rec(  # a window on a display: counted
            "2026-10-09T10:00:06.000+02:00",
            "window_new",
            window=3,
            on_screen=True,
            on_display=True,
        ),
        rec("2026-10-09T10:00:07.000+02:00", "activate"),
        rec("2026-10-09T10:00:08.000+02:00", "activate", pid=99),  # another pid
        rec("2026-10-09T10:00:30.000+02:00", "window_raise", window=3),  # after end
    ]
    stats = gate.fw_segment_stats(
        fw,
        records,
        {7},
        "2026-10-09T10:00:04.000+02:00",
        "2026-10-09T10:00:20.000+02:00",
    )
    assert stats["records"] == 3
    assert stats["counted"] == 2
    assert stats["activations"] == 1
    assert stats["window_raise"] == 0
    assert stats["window_new_on_display"] == 1
    assert stats["window_new_off_display"] == 1
