"""Unit tests for bin/focus_watch.py's pure logic (no pyobjc, no desktop).

Rotation and rotated-log reading, summary aggregation (incl. self-test
bracketing), title redaction, Chrome / native-prompt classification, the
window tracker (new / shown / raise, seen-set across Spaces, state committed
before emitting), error rate-limiting and launchd std-log capping.

Run: uv run --no-sync pytest -q tests/test_focus_watch.py
"""

from __future__ import annotations

# pylint: disable=missing-function-docstring,import-error,redefined-outer-name
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

_PATH = Path(__file__).resolve().parent.parent / "bin" / "focus_watch.py"
_SPEC = importlib.util.spec_from_file_location("focus_watch", _PATH)
assert _SPEC is not None and _SPEC.loader is not None
fw = importlib.util.module_from_spec(_SPEC)
sys.modules["focus_watch"] = fw  # dataclasses resolve their module by name
_SPEC.loader.exec_module(fw)

CFT = "Google Chrome for Testing"


def info(number, owner, *, layer=0, pid=100, title=None, on_screen=True):
    rec = {
        "kCGWindowNumber": number,
        "kCGWindowOwnerName": owner,
        "kCGWindowOwnerPID": pid,
        "kCGWindowLayer": layer,
        "kCGWindowBounds": {"X": 1, "Y": 2, "Width": 300, "Height": 200},
        "kCGWindowName": title,
    }
    if on_screen:
        rec["kCGWindowIsOnscreen"] = True
    return rec


def snap(*infos):
    return fw.normalize_windows(list(infos), lambda _pid: None)


def tracker_with(on_screen, all_windows=()):
    tracker = fw.WindowTracker()
    tracker.baseline(snap(*all_windows), snap(*on_screen))
    return tracker


def names(events):
    return [(event, win.number) for event, win, _extra in events]


# -- redaction ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("title", "expected"),
    [
        (None, None),
        ("", None),
        ("Inbox — Mail", None),
        (
            "https://portal.example.org/callback?code=SECRET#tok",
            "https://portal.example.org",
        ),
        ("Login - https://User:Pw@Host.Example:8443/x", "https://host.example:8443"),
        ("see http://10.0.0.1/a and https://b.c/", "http://10.0.0.1"),
    ],
)
def test_redact_title(title, expected):
    assert fw.redact_title(title) == expected


def test_normalized_window_never_keeps_raw_title():
    (win,) = snap(info(1, CFT, title="https://x.example/path?token=abc"))
    assert win.title == "https://x.example"
    assert "token" not in json.dumps(win.fields())


def test_normalize_reads_on_screen_flag():
    on, off = snap(info(1, CFT), info(2, CFT, on_screen=False))
    assert on.on_screen and not off.on_screen


# -- classification ----------------------------------------------------------


def test_is_chrome_by_name_bundle_and_cache_path(tmp_path):
    assert fw.is_chrome(CFT, None, None)
    assert fw.is_chrome(None, "com.google.chrome.for.testing.helper", None)
    exe = str(tmp_path / "chromium-1243" / "x" / "Chromium")
    assert fw.is_chrome("Chromium", None, exe, cache=tmp_path)
    assert not fw.is_chrome("Google Chrome", "com.google.Chrome", "/Applications/x")
    assert not fw.is_chrome("Brave", None, str(tmp_path) + "-other/x", cache=tmp_path)


def test_is_native_prompt():
    assert fw.is_native_prompt("SecurityAgent", None)
    assert fw.is_native_prompt("coreautha", None)
    assert fw.is_native_prompt(None, "com.apple.LocalAuthentication.UIAgent")
    assert not fw.is_native_prompt("Keychain Access", "com.apple.keychainaccess")
    assert not fw.is_native_prompt("iTerm2", "com.googlecode.iterm2")


# -- window tracker ----------------------------------------------------------


def test_no_events_before_baseline():
    assert not fw.WindowTracker().on_screen(snap(info(1, CFT)))
    assert not fw.WindowTracker().all_windows({1}, snap(info(1, CFT)))


def test_new_chrome_window_and_new_native_prompt_window():
    tracker = tracker_with([info(1, "iTerm2")])
    cur = snap(
        info(5, "SecurityAgent", layer=1000),
        info(4, CFT),
        info(1, "iTerm2"),
        info(9, "Finder"),
    )
    events = tracker.on_screen(cur)
    assert names(events) == [("window_new", 5), ("window_new", 4)]
    assert events[0][1].native_prompt and not events[0][1].chrome
    assert events[1][1].chrome and events[1][1].on_screen


def test_space_round_trip_is_shown_not_new():
    # Chrome window 4 exists at start, on screen; the user switches Space away
    # and back: it must come back as window_shown, never window_new.
    tracker = tracker_with([info(4, CFT), info(1, "iTerm2")])
    assert not tracker.on_screen(snap(info(1, "iTerm2")))  # other Space
    assert names(tracker.on_screen(snap(info(4, CFT), info(1, "iTerm2")))) == [
        ("window_shown", 4)
    ]


def test_window_existing_off_screen_at_start_is_shown_not_new():
    tracker = tracker_with(
        [info(1, "iTerm2")], all_windows=[info(7, CFT, on_screen=False)]
    )
    assert names(tracker.on_screen(snap(info(7, CFT), info(1, "iTerm2")))) == [
        ("window_shown", 7)
    ]


def test_window_created_off_screen_is_new_once():
    tracker = tracker_with([info(1, "iTerm2")], all_windows=[info(1, "iTerm2")])
    hidden = snap(info(8, CFT, on_screen=False))
    events = tracker.all_windows({1, 8}, hidden)
    assert names(events) == [("window_new", 8)]
    assert events[0][1].fields()["on_screen"] is False
    # Later it appears on screen: shown, not new again.
    assert names(tracker.on_screen(snap(info(8, CFT), info(1, "iTerm2")))) == [
        ("window_shown", 8)
    ]
    # A later full scan listing it again is not new either.
    assert not tracker.all_windows({1, 8}, hidden)


def test_seen_set_is_pruned_to_existing_windows():
    tracker = tracker_with([info(4, CFT)])
    tracker.all_windows({1}, [])  # window 4 is gone
    assert tracker.seen == set()
    assert tracker.visible == set()


def test_empty_snapshots_are_skipped():
    tracker = tracker_with([info(4, CFT), info(1, "iTerm2")])
    assert not tracker.on_screen([])
    assert not tracker.all_windows(set(), [])
    assert tracker.seen == {4}
    assert tracker.visible == {4}
    # An empty poll did not reset `visible`, so nothing is "shown" afterwards.
    assert not tracker.on_screen(snap(info(4, CFT), info(1, "iTerm2")))


def test_state_is_committed_before_events_are_emitted():
    # The caller emits AFTER update returns; if that emit fails (disk full),
    # the next poll of the same snapshot must not re-report the window.
    tracker = tracker_with([info(1, "iTerm2")])
    cur = snap(info(4, CFT), info(1, "iTerm2"))

    def emit_all(events):
        for _ in events:
            raise OSError("disk full")

    with pytest.raises(OSError):
        emit_all(tracker.on_screen(cur))
    assert not tracker.on_screen(cur)


def test_chrome_rising_over_a_window_is_a_raise():
    tracker = tracker_with([info(1, "iTerm2"), info(2, "Finder"), info(3, CFT)])
    events = tracker.on_screen(snap(info(3, CFT), info(1, "iTerm2"), info(2, "Finder")))
    assert len(events) == 1
    event, win, extra = events[0]
    assert (event, win.number) == ("window_raise", 3)
    assert extra == {"z_from": 2, "z_to": 0, "overtaken": 2}


def test_index_drop_from_closed_window_is_not_a_raise():
    tracker = tracker_with([info(1, "iTerm2"), info(3, CFT)])
    assert not tracker.on_screen(snap(info(3, CFT)))


def test_other_window_rising_is_not_a_chrome_raise():
    tracker = tracker_with([info(1, "iTerm2"), info(3, CFT), info(2, "Finder")])
    cur = snap(info(2, "Finder"), info(1, "iTerm2"), info(3, CFT))
    assert not tracker.on_screen(cur)


def test_overlay_layers_ignored_for_raise():
    tracker = tracker_with([info(1, "iTerm2"), info(3, CFT)])
    cur = snap(info(7, "Dock", layer=20), info(1, "iTerm2"), info(3, CFT))
    assert not tracker.on_screen(cur)


# -- rotation ----------------------------------------------------------------


def test_log_rotates_and_keeps_three(tmp_path):
    path = tmp_path / "focus.jsonl"
    log = fw.JsonlLog(path, max_bytes=200, keep=3)
    for i in range(40):
        log.write({"i": i, "pad": "x" * 60})
    assert path.stat().st_size <= 200
    for idx in (1, 2, 3):
        assert fw.rotated_path(path, idx).exists()
    assert not fw.rotated_path(path, 4).exists()
    last = [json.loads(line) for line in path.read_text().splitlines()]
    assert last[-1]["i"] == 39
    newest_old = json.loads(fw.rotated_path(path, 1).read_text().splitlines()[-1])
    assert newest_old["i"] == last[0]["i"] - 1


def test_rotate_files_shift(tmp_path):
    path = tmp_path / "f.jsonl"
    path.write_text("cur")
    fw.rotated_path(path, 1).write_text("one")
    fw.rotated_path(path, 3).write_text("three")
    fw.rotate_files(path, keep=3)
    assert not path.exists()
    assert fw.rotated_path(path, 1).read_text() == "cur"
    assert fw.rotated_path(path, 2).read_text() == "one"
    assert not fw.rotated_path(path, 3).exists()  # nothing was at .2


def test_read_log_chain_oldest_first(tmp_path):
    path = tmp_path / "focus.jsonl"
    log = fw.JsonlLog(path, max_bytes=120, keep=3)
    for i in range(12):
        log.write({"i": i, "pad": "x" * 30})
    records, bad, files = fw.read_log_chain(path)
    assert bad == 0
    assert files[-1] == path
    assert files[0] == fw.rotated_path(path, 3)
    seq = [r["i"] for r in records]
    assert seq == sorted(seq)
    assert seq[-1] == 11


def test_read_log_chain_skips_missing_rotations(tmp_path):
    path = tmp_path / "f.jsonl"
    path.write_text(json.dumps({"i": 2}) + "\n")
    fw.rotated_path(path, 2).write_text(json.dumps({"i": 1}) + "\n")
    records, _bad, files = fw.read_log_chain(path)
    assert [r["i"] for r in records] == [1, 2]
    assert files == [fw.rotated_path(path, 2), path]


# -- summary -----------------------------------------------------------------


def test_summary_counts_and_flags(tmp_path):
    path = tmp_path / "f.jsonl"
    recs = [
        fw.make_record("start", app="iTerm2"),
        fw.make_record("activate", app="TextEdit", prev_app="iTerm2"),
        fw.make_record("activate", app="TextEdit", prev_app="iTerm2"),
        fw.make_record("window_new", app=CFT, pid=7, chrome=True, window=4),
        fw.make_record("window_shown", app=CFT, pid=7, chrome=True, window=4),
        fw.make_record("activate", app="SecurityAgent", native_prompt=True),
        fw.make_record("selftest", step="done", chrome=True),  # bookkeeping
    ]
    path.write_text(
        "\n".join(json.dumps(r) for r in recs) + "\nnot json\n", encoding="utf-8"
    )
    records, bad, files = fw.read_log_chain(path)
    assert bad == 1
    summary = fw.summarize(records)
    assert summary.counts[("TextEdit", "activate")] == 2
    assert summary.counts[(CFT, "window_new")] == 1
    assert summary.chrome_events == 1
    assert summary.chrome_shown == 1
    assert summary.native_events == 1
    assert [r["event"] for r in summary.flagged] == [
        "window_new",
        "window_shown",
        "activate",
    ]
    text = fw.format_summary(summary, files, bad)
    assert "❌ 1 Chrome-for-Testing" in text
    assert "window_shown events (informational" in text
    assert "chrome (shown, not counted)" in text
    assert "window=4" in text


def test_summary_ignores_selftest_chrome_between_markers():
    recs = [
        fw.make_record("selftest_begin", chrome_pid=55),
        fw.make_record("activate", app=CFT, pid=55, chrome=True),
        fw.make_record("window_new", app=CFT, pid=55, chrome=True, window=1),
        fw.make_record("selftest_end", chrome_pid=55),
        # Same pid after the end marker (pid reuse) counts again.
        fw.make_record("window_new", app=CFT, pid=55, chrome=True, window=2),
        # Another Chrome during a self-test is never ignored.
        fw.make_record("selftest_begin", chrome_pid=66),
        fw.make_record("window_new", app=CFT, pid=77, chrome=True, window=3),
        fw.make_record("selftest_end", chrome_pid=66),
    ]
    summary = fw.summarize(recs)
    assert summary.ignored_selftest == 2
    assert summary.chrome_events == 2
    assert [r["window"] for r in summary.flagged] == [2, 3]


def test_summary_clean_log_is_green(tmp_path):
    summary = fw.summarize(
        [
            fw.make_record("activate", app="Finder"),
            fw.make_record("window_shown", app=CFT, chrome=True),
        ]
    )
    text = fw.format_summary(summary, [tmp_path / "x.jsonl"])
    assert "✅ no Chrome-for-Testing activate/window_new/window_raise events" in text
    assert "✅ no native-prompt events" in text


def test_summary_off_display_window_is_not_counted(tmp_path):
    def new(window, **extra):
        return fw.make_record(
            "window_new", app=CFT, pid=9, chrome=True, window=window, **extra
        )

    recs = [
        # Created on screen but parked outside every display: informational.
        new(1, on_screen=True, on_display=False, bounds=[-32000, -32000, 1280, 900]),
        # On a display: counted.
        new(2, on_screen=True, on_display=True),
        # An old record without on_display keeps today's rule: counted.
        new(3, on_screen=True),
    ]
    summary = fw.summarize(recs)
    assert summary.chrome_events == 2
    assert summary.chrome_offdisplay == 1
    assert summary.chrome_offscreen == 0
    assert [r["window"] for r in summary.flagged] == [2, 3]
    text = fw.format_summary(summary, [tmp_path / "x.jsonl"])
    assert "created outside every display (informational, never shown): 1" in text
    # The off-display window's first window_shown counts, like an off-screen one.
    recs.append(fw.make_record("window_shown", app=CFT, pid=9, chrome=True, window=1))
    assert fw.summarize(recs).chrome_events == 3


def test_ns_to_cg_rect_flips_against_the_primary_height():
    # Primary 1440x900 at the Cocoa origin: identical in CG.
    assert fw.ns_to_cg_rect((0, 0, 1440, 900), 900) == (0, 900 - 900, 1440, 900)
    # A 1920x1080 display right of the primary, its bottom edge 100 pt above the
    # primary's bottom: its CG top is 900 - (100 + 1080) = -280.
    assert fw.ns_to_cg_rect((1440, 100, 1920, 1080), 900) == (1440, -280, 1920, 1080)
    # A display BELOW the primary (Cocoa y negative) sits at CG y = 900.
    assert fw.ns_to_cg_rect((0, -1080, 1920, 1080), 900) == (0, 900, 1920, 1080)
    displays = fw.display_rects_cg(
        [(0, 0, 1440, 900), (1440, 100, 1920, 1080)]  # primary first
    )
    assert displays == [(0, 0, 1440, 900), (1440, -280, 1920, 1080)]
    assert fw.on_any_display((100, 100, 500, 400), displays) is True
    assert fw.on_any_display((2000, -200, 300, 200), displays) is True  # secondary
    assert fw.on_any_display((1300, 850, 500, 400), displays) is True  # partial
    assert fw.on_any_display((-32000, -32000, 1280, 900), displays) is False
    assert fw.on_any_display((1440, 0, 10, 10), [(0, 0, 1440, 900)]) is False  # edge
    assert fw.on_any_display((0, 0, 10, 10), []) is None  # unknown


def test_normalize_sets_on_display_for_chrome_windows_only():
    calls = []

    def displays():
        calls.append(1)
        return [(0.0, 0.0, 1440.0, 900.0)]

    def at(number, owner, x, y):
        rec = info(number, owner)
        rec["kCGWindowBounds"] = {"X": x, "Y": y, "Width": 300, "Height": 200}
        return rec

    wins = fw.normalize_windows(
        [at(1, CFT, 10, 10), at(2, CFT, -32000, -32000), at(3, "iTerm2", 10, 10)],
        lambda _pid: None,
        displays,
    )
    assert [w.on_display for w in wins] == [True, False, None]
    assert calls == [1]  # display rects read once per snapshot
    assert wins[1].fields()["on_display"] is False
    assert "on_display" not in wins[2].fields()
    assert "on_display" not in snap(info(4, CFT))[0].fields()  # no displays given


def test_cmd_summary_exit_codes(tmp_path, capsys):
    path = tmp_path / "f.jsonl"
    path.write_text(json.dumps(fw.make_record("activate", app="Finder")) + "\n")
    assert fw.main(["-s", str(path)]) == 0
    path.write_text(json.dumps(fw.make_record("window_shown", app=CFT, chrome=True)))
    assert fw.main(["-s", str(path)]) == 0  # shown alone does not fail
    fw.rotated_path(path, 1).write_text(
        json.dumps(fw.make_record("window_raise", app=CFT, chrome=True))
    )
    assert fw.main(["-s", str(path)]) == 1  # found in the rotated file
    assert fw.main(["-s", str(tmp_path / "missing.jsonl")]) == 1
    capsys.readouterr()


# -- robustness --------------------------------------------------------------


def test_reporter_rate_limits_identical_messages():
    now = [0.0]
    out: list[str] = []
    rep = fw.RateLimitedReporter(interval=600, clock=lambda: now[0], sink=out.append)
    assert rep.report("boom")
    assert not rep.report("boom")
    assert rep.report("other")
    now[0] = 601
    assert rep.report("boom")
    assert len(out) == 3
    assert "repeated 1x" in out[-1]


def test_reporter_survives_failing_sink():
    def sink(_msg):
        raise OSError("disk full")

    assert fw.RateLimitedReporter(sink=sink).report("x")


def test_cap_file_truncates_in_place(tmp_path):
    path = tmp_path / "agent.err.log"
    path.write_bytes(b"x" * 100)
    inode = path.stat().st_ino
    assert not fw.cap_file(path, 200)
    assert fw.cap_file(path, 50)
    assert path.stat().st_size == 0
    assert path.stat().st_ino == inode
    assert fw.rotated_path(path, 1).stat().st_size == 100
    assert not fw.cap_file(tmp_path / "missing.log", 1)


def test_append_record(tmp_path):
    path = tmp_path / "f.jsonl"
    fw.append_record(path, {"a": 1})
    fw.append_record(path, {"a": 2})
    assert [json.loads(x)["a"] for x in path.read_text().splitlines()] == [1, 2]


def test_is_not_loaded():
    def res(code, err=""):
        return subprocess.CompletedProcess(["launchctl"], code, "", err)

    assert fw.is_not_loaded(res(3, "Boot-out failed: 3: No such process"))
    assert fw.is_not_loaded(res(113))
    assert not fw.is_not_loaded(res(5, "Boot-out failed: 5: Input/output error"))


# -- CLI / misc --------------------------------------------------------------


@pytest.mark.parametrize("argv", [["-m", "0"], ["-m", "-1"], ["-d", "-5"], ["-i", "5"]])
def test_cli_rejects_bad_values(argv, capsys):
    with pytest.raises(SystemExit) as exc:
        fw.build_parser().parse_args(argv)
    assert exc.value.code == 2
    capsys.readouterr()


def test_selftest_defaults_to_temp_log():
    log = fw.resolve_log(None, self_test=True)
    try:
        assert log != fw.DEFAULT_LOG
        assert log.name.startswith("focus-watch-selftest-")
    finally:
        log.unlink(missing_ok=True)
    assert fw.resolve_log(None, self_test=False) == fw.DEFAULT_LOG


def test_free_port_avoids_reserved():
    port = fw.free_port()
    assert port not in (9222, 9223)
    assert 0 < port < 65536


def test_agent_plist_shape(tmp_path):
    plist = fw.agent_plist(tmp_path / "py", tmp_path / "f.jsonl", 20)
    assert plist["Label"] == "com.albert.focus-watch"
    assert plist["LimitLoadToSessionType"] == "Aqua"
    assert plist["ProcessType"] == "Standard"
    assert plist["RunAtLoad"] and plist["KeepAlive"]
    assert plist["ProgramArguments"][1] == str(fw.SCRIPT)


def test_newest_chrome_binary_picks_highest_build(tmp_path):
    rel = "chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS"
    for build in ("1223", "1243", "1234"):
        exe = tmp_path / f"chromium-{build}" / rel / "Google Chrome for Testing"
        exe.parent.mkdir(parents=True)
        exe.write_text("")
        exe.chmod(0o755)
    (tmp_path / "chromium_headless_shell-9999").mkdir()
    found = fw.newest_chrome_binary(tmp_path)
    assert found is not None and "chromium-1243" in str(found)


def test_worktree_detection():
    # This test suite may run from a worktree or the main checkout; either way
    # the answer must be consistent with git's own view.
    res = subprocess.run(
        ["git", "-C", str(fw.REPO_ROOT), "rev-parse", "--git-dir", "--git-common-dir"],
        capture_output=True,
        text=True,
        check=False,
    )
    if res.returncode != 0:
        pytest.skip("not a git checkout")
    git_dir, common = (
        (fw.REPO_ROOT / p).resolve() if not Path(p).is_absolute() else Path(p).resolve()
        for p in res.stdout.split()
    )
    main = fw.worktree_main_checkout()
    assert (main is None) == (git_dir == common)


def test_summary_offscreen_window_is_informational_until_shown():
    recs = [
        # A headless Chrome's invisible window: never on screen → informational.
        fw.make_record(
            "window_new", app=CFT, pid=9, chrome=True, window=1, on_screen=False
        ),
        # Created off screen, later shown: its first appearance counts.
        fw.make_record(
            "window_new", app=CFT, pid=9, chrome=True, window=2, on_screen=False
        ),
        fw.make_record("window_shown", app=CFT, pid=9, chrome=True, window=2),
        # Shown again (Space round-trip) → informational.
        fw.make_record("window_shown", app=CFT, pid=9, chrome=True, window=2),
        # Created on screen → counts.
        fw.make_record(
            "window_new", app=CFT, pid=9, chrome=True, window=3, on_screen=True
        ),
    ]
    summary = fw.summarize(recs)
    assert summary.chrome_offscreen == 2
    assert summary.chrome_events == 2
    assert summary.chrome_shown == 1
    assert [r["window"] for r in summary.flagged] == [2, 2, 3]
