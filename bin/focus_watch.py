#!/usr/bin/env python3
"""focus_watch.py — log who takes focus on this Mac, and every Chrome-for-Testing window.

The acceptance instrument for "the shared Chrome for Testing never takes focus
or opens a window" (PLAN_focus-free-browser.md, Phase 0). It watches on one
Cocoa run loop and appends one JSON line per event:

  * activate      — an app became frontmost (NSWorkspace activation
                    notification; a poll of frontmostApplication every
                    --interval-ms is the fallback, marked source=poll).
  * window_new    — a Chrome-for-Testing window (owner name, bundle id, or an
                    executable under the Playwright cache) or a native-prompt
                    window (SecurityAgent, coreautha, …) that was never seen
                    before — on screen or not (field on_screen). Windows on
                    other Spaces / of hidden apps are found by a 1 s scan of
                    ALL windows; on-screen ones on every poll. Chrome windows
                    also carry on_display: whether their bounds intersect any
                    display at capture time (on_screen is also true for a
                    window parked far outside every display).
  * window_shown  — a known Chrome / native-prompt window came (back) on
                    screen: unhide, unminimise, Space switch.
  * window_raise  — a Chrome-for-Testing window climbed the z-order: a window
                    that was above it is still on screen but is now below it.
  * start / stop / selftest / selftest_begin / selftest_end — bookkeeping.

Window titles are never stored raw (they can carry URLs with tokens): a record
holds the owner, window number, layer, bounds and at most the ORIGIN of a URL
found in the title.

Usage:
  focus_watch.py                       watch forever (what the LaunchAgent runs)
  focus_watch.py -d 600                watch 10 minutes, then exit
  focus_watch.py -l /tmp/f.jsonl -d 5  log to another file
  focus_watch.py -s                    summarise the default log (+ rotations)
  focus_watch.py -s /tmp/f.jsonl       summarise another log
  focus_watch.py -t                    self-test (spawns a HEADED throwaway
                                       Chrome, activates TextEdit and back;
                                       logs to a temp file)
  focus_watch.py -P                    print the LaunchAgent plist
  focus_watch.py -I | -U               install / uninstall the LaunchAgent

Needs pyobjc (the `focus` dependency group, a default group here). Watch and
self-test modes run under the repo .venv via pyvenv_bootstrap (created on first use).
Exit codes: 0 ok, 1 self-test failed / summary found Chrome events, 2 usage,
3 pyobjc missing.
"""

# too-many-lines: like browser.py, this is deliberately ONE self-contained file
# that runs straight off PATH (and from launchd) with nothing to import from the
# repo; the pure helpers live here too so the tests can load them without pyobjc.
# pylint: disable=too-many-lines

from __future__ import annotations

import argparse
import ctypes
import dataclasses
import datetime as dt
import importlib
import json
import os
import plistlib
import queue
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from collections import Counter
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any

SCRIPT = Path(__file__).resolve()
REPO_ROOT = SCRIPT.parent.parent
VENV_PYTHON = REPO_ROOT / ".venv" / "bin" / "python"
STATE_DIR = Path.home() / ".local" / "state" / "focus-watch"
DEFAULT_LOG = STATE_DIR / "focus.jsonl"
AGENT_STD_LOGS = (STATE_DIR / "agent.out.log", STATE_DIR / "agent.err.log")
PLAYWRIGHT_CACHE = Path.home() / "Library" / "Caches" / "ms-playwright"
CHROME_OWNER = "google chrome for testing"
CHROME_BUNDLE_ID = "com.google.chrome.for.testing"
TEXTEDIT_BUNDLE_ID = "com.apple.TextEdit"
AGENT_LABEL = "com.albert.focus-watch"
AGENT_PLIST = Path.home() / "Library" / "LaunchAgents" / f"{AGENT_LABEL}.plist"
DEFAULT_INTERVAL_MS = 200
# How long the NSScreen display rects (for on_display) are reused.
DISPLAY_CACHE_S = 2.0
MIN_INTERVAL_MS = 20
ALL_WINDOWS_SCAN_S = 1.0
KEEP_ROTATED = 3
DEFAULT_MAX_MB = 20.0
STD_LOG_CAP_BYTES = 5 * 1024 * 1024
STD_LOG_CHECK_S = 600.0
ERROR_REPEAT_S = 600.0
EXE_CACHE_MAX = 512
RESERVED_CDP_PORTS = frozenset({9222, 9223})
SELFTEST_DEADLINE_S = 120.0
EXIT_FAIL = 1
EXIT_MISSING_DEP = 3
# launchctl: "Boot-out failed: 3: No such process" / 113 "Could not find service".
LAUNCHCTL_NOT_LOADED = frozenset({3, 113})

# Processes that put up native macOS prompts (password / Touch ID / TCC consent /
# Gatekeeper). Matched case-insensitively on app name or bundle id.
NATIVE_PROMPT_NAMES = frozenset(
    {
        "securityagent",
        "usernotificationcenter",
        "universalaccessauthwarn",
        "coreautha",
        "tccd",
        "localauthenticationremoteservice",
        "coreservicesuiagent",
    }
)
NATIVE_PROMPT_BUNDLES = frozenset(
    {
        "com.apple.securityagent",
        "com.apple.usernotificationcenter",
        "com.apple.universalaccessauthwarn",
        "com.apple.coreautha",
        "com.apple.tccd",
        "com.apple.localauthentication.uiagent",
        "com.apple.coreservicesuiagent",
    }
)

# Chrome events that fail a summary; window_shown is reported but not counted
# (a Space switch back to a Space holding a Chrome window looks the same).
COUNTED_CHROME_EVENTS = frozenset({"activate", "window_new", "window_raise"})
BOOKKEEPING_EVENTS = frozenset(
    {"start", "stop", "selftest", "selftest_begin", "selftest_end"}
)

# ---------------------------------------------------------------------------
# Pure helpers (no pyobjc) — importable by the tests.
# ---------------------------------------------------------------------------


def now_iso() -> str:
    """Local wall-clock time, ISO 8601 with the UTC offset, millisecond precision."""
    return dt.datetime.now().astimezone().isoformat(timespec="milliseconds")


def osc8(target: str, text: str) -> str:
    """`text` as an OSC 8 terminal hyperlink to `target` (invisible where unsupported)."""
    return f"\x1b]8;;{target}\x1b\\{text}\x1b]8;;\x1b\\"


def path_link(path: Path) -> str:
    """An absolute path, printed as a clickable file:// hyperlink."""
    absolute = path.expanduser().absolute()
    return osc8(absolute.as_uri(), str(absolute))


def safe_print(*parts: Any, err: bool = False) -> None:
    """print() that can never raise (closed stream, full disk under launchd)."""
    try:
        print(*parts, file=sys.stderr if err else sys.stdout, flush=True)
    except (OSError, ValueError):
        pass


class RateLimitedReporter:
    """Prints each distinct error message at most once per `interval` seconds."""

    def __init__(
        self,
        interval: float = ERROR_REPEAT_S,
        clock: Callable[[], float] = time.monotonic,
        sink: Callable[[str], None] | None = None,
    ) -> None:
        self.interval = interval
        self.clock = clock
        self.sink = sink or (lambda msg: safe_print(msg, err=True))
        self._last: dict[str, float] = {}
        self._suppressed: Counter[str] = Counter()

    def report(self, msg: str) -> bool:
        """Emit `msg` unless the same message went out < `interval` ago."""
        now = self.clock()
        last = self._last.get(msg)
        if last is not None and now - last < self.interval:
            self._suppressed[msg] += 1
            return False
        dropped = self._suppressed.pop(msg, 0)
        self._last[msg] = now
        suffix = f" (repeated {dropped}x since last report)" if dropped else ""
        try:
            self.sink(f"❌ focus_watch: {msg}{suffix}")
        except Exception:  # pylint: disable=broad-exception-caught
            pass
        return True


def is_native_prompt(app: str | None, bundle_id: str | None) -> bool:
    """True when the app name or bundle id belongs to a native-prompt process."""
    if app and app.strip().lower() in NATIVE_PROMPT_NAMES:
        return True
    return bool(bundle_id and bundle_id.strip().lower() in NATIVE_PROMPT_BUNDLES)


def is_chrome(
    app: str | None,
    bundle_id: str | None,
    exe_path: str | None,
    cache: Path = PLAYWRIGHT_CACHE,
) -> bool:
    """True for Chrome for Testing: owner name, bundle id, or a Playwright-cache binary."""
    if app and CHROME_OWNER in app.lower():
        return True
    if bundle_id and bundle_id.lower().startswith(CHROME_BUNDLE_ID):
        return True
    if exe_path:
        prefix = str(cache).rstrip("/") + "/"
        return exe_path.startswith(prefix)
    return False


_URL_RE = re.compile(r"\b([a-z][a-z0-9+.-]*)://([^/\s?#]+)", re.IGNORECASE)


def redact_title(title: str | None) -> str | None:
    """The origin (scheme://host[:port]) of the first URL in `title`, else None.

    Window titles are never logged raw — a tab title can be a URL carrying a
    token. Userinfo (``user:pass@``) is dropped from the host part.
    """
    if not title:
        return None
    match = _URL_RE.search(title)
    if match is None:
        return None
    host = match.group(2).rsplit("@", 1)[-1]
    if not host:
        return None
    return f"{match.group(1).lower()}://{host.lower()}"


def rotated_path(path: Path, index: int) -> Path:
    """`focus.jsonl` -> `focus.jsonl.<index>`."""
    return path.with_name(f"{path.name}.{index}")


def rotate_files(path: Path, keep: int = KEEP_ROTATED) -> None:
    """Shift `path` -> `.1` -> `.2` … keeping at most `keep` old files."""
    oldest = rotated_path(path, keep)
    if oldest.exists():
        oldest.unlink()
    for index in range(keep - 1, 0, -1):
        src = rotated_path(path, index)
        if src.exists():
            src.replace(rotated_path(path, index + 1))
    if path.exists():
        path.replace(rotated_path(path, 1))


def log_chain(path: Path, keep: int = KEEP_ROTATED) -> list[Path]:
    """`path`'s existing rotations oldest first (.keep … .1), then `path` itself."""
    chain = [rotated_path(path, i) for i in range(keep, 0, -1)]
    chain.append(path)
    return [p for p in chain if p.exists()]


def cap_file(path: Path, max_bytes: int) -> bool:
    """Keep a launchd stdout/stderr file small: copy to `.1` and truncate in place.

    launchd holds the file open (O_APPEND), so it cannot be renamed away — the
    descriptor would follow the rename. Truncating keeps the same inode.
    """
    try:
        if path.stat().st_size <= max_bytes:
            return False
        shutil.copyfile(path, rotated_path(path, 1))
        with path.open("r+b") as handle:
            handle.truncate(0)
    except OSError:
        return False
    return True


def append_record(path: Path, record: dict[str, Any]) -> None:
    """One unrotated O_APPEND line — for writing into another process's log."""
    line = (json.dumps(record, ensure_ascii=False, default=str) + "\n").encode()
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
    try:
        os.write(fd, line)
    finally:
        os.close(fd)


class JsonlLog:
    """Append-only JSON-lines log, rotated before a write would exceed `max_bytes`."""

    def __init__(self, path: Path, max_bytes: int, keep: int = KEEP_ROTATED) -> None:
        self.path = path
        self.max_bytes = max(1, max_bytes)
        self.keep = keep
        self._lock = threading.Lock()

    def write(self, record: dict[str, Any]) -> None:
        """Append one record as a single line (thread-safe; may raise OSError)."""
        line = json.dumps(record, ensure_ascii=False, default=str) + "\n"
        data = line.encode("utf-8")
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            try:
                size = self.path.stat().st_size
            except FileNotFoundError:
                size = 0
            if size and size + len(data) > self.max_bytes:
                rotate_files(self.path, self.keep)
            with self.path.open("ab") as handle:
                handle.write(data)


def make_record(
    event: str,
    *,
    app: str | None = None,
    bundle_id: str | None = None,
    pid: int | None = None,
    chrome: bool = False,
    native_prompt: bool = False,
    **extra: Any,
) -> dict[str, Any]:
    """One log record: the fixed fields first, then event-specific extras.

    Activations carry ``prev_app``; window events carry ``frontmost_app``.
    """
    record: dict[str, Any] = {
        "ts": now_iso(),
        "event": event,
        "app": app,
        "bundle_id": bundle_id,
        "pid": pid,
        "chrome": chrome,
        "native_prompt": native_prompt,
    }
    record.update(extra)
    return record


@dataclasses.dataclass(frozen=True)
class Win:  # pylint: disable=too-many-instance-attributes  # one field per datum
    """One window, reduced to what may be logged."""

    number: int
    owner: str
    pid: int | None
    layer: int
    bounds: tuple[int, int, int, int]
    title: str | None  # redacted: origin only, or None
    chrome: bool
    native_prompt: bool
    on_screen: bool = True
    on_display: bool | None = None  # Chrome only: bounds intersect a display

    @property
    def tracked(self) -> bool:
        """Chrome or native-prompt: the windows whose appearance is reported."""
        return self.chrome or self.native_prompt

    def fields(self) -> dict[str, Any]:
        """Log fields describing this window (``on_display`` only when known)."""
        out: dict[str, Any] = {
            "window": self.number,
            "layer": self.layer,
            "bounds": list(self.bounds),
            "title": self.title,
            "on_screen": self.on_screen,
        }
        if self.on_display is not None:
            out["on_display"] = self.on_display
        return out


def _bounds(raw: Any) -> tuple[int, int, int, int]:
    try:
        return (
            int(raw.get("X", 0)),
            int(raw.get("Y", 0)),
            int(raw.get("Width", 0)),
            int(raw.get("Height", 0)),
        )
    except (AttributeError, TypeError, ValueError):
        return (0, 0, 0, 0)


Rect = tuple[float, float, float, float]  # x, y, width, height


def ns_to_cg_rect(frame: Rect, primary_height: float) -> Rect:
    """An NSScreen frame (bottom-left origin, y up) in CG global coordinates.

    CGWindow bounds use the top-left corner of the PRIMARY display as origin with
    y growing downwards; Cocoa puts the origin at the primary display's
    bottom-left corner with y growing upwards. x is shared; the top edge of a
    Cocoa rect (``y + height``) is ``primary_height - (y + height)`` in CG.
    """
    x, y, width, height = frame
    return (x, primary_height - (y + height), width, height)


def rects_intersect(a: Rect, b: Rect) -> bool:
    """True when the two rects share a positive area (touching edges do not)."""
    ax, ay, aw, ah = a
    bx, by, bw, bh = b
    return ax < bx + bw and bx < ax + aw and ay < by + bh and by < ay + ah


def on_any_display(bounds: Rect, displays: list[Rect]) -> bool | None:
    """Whether CG `bounds` intersect any display rect (CG coords); None if unknown."""
    if not displays:
        return None
    return any(rects_intersect(bounds, d) for d in displays)


def display_rects_cg(ns_frames: list[Rect]) -> list[Rect]:
    """NSScreen frames (``NSScreen.screens()`` order, primary first) in CG coords."""
    if not ns_frames:
        return []
    primary_height = ns_frames[0][3]
    return [ns_to_cg_rect(frame, primary_height) for frame in ns_frames]


def normalize_windows(
    infos: Iterable[Any],
    exe_for_pid: Callable[[int], str | None],
    displays: Callable[[], list[Rect]] | None = None,
) -> list[Win]:
    """CGWindowList dicts (in the order given) -> `Win`s.

    `displays` (CG display rects, called at most once, and only when a Chrome
    window is present) sets each Chrome window's ``on_display``.
    """
    wins: list[Win] = []
    display_cache: list[list[Rect]] = []
    for info in infos or []:
        try:
            number = int(info.get("kCGWindowNumber") or 0)
            owner = str(info.get("kCGWindowOwnerName") or "?")
            raw_pid = info.get("kCGWindowOwnerPID")
            pid = int(raw_pid) if raw_pid is not None else None
            layer = int(info.get("kCGWindowLayer") or 0)
            title = info.get("kCGWindowName")
            on_screen = bool(info.get("kCGWindowIsOnscreen"))
        except (AttributeError, TypeError, ValueError):
            continue
        exe = exe_for_pid(pid) if pid else None
        bounds = _bounds(info.get("kCGWindowBounds"))
        chrome = is_chrome(owner, None, exe)
        on_display: bool | None = None
        if chrome and displays is not None:
            if not display_cache:
                display_cache.append(displays())
            on_display = on_any_display(bounds, display_cache[0])
        wins.append(
            Win(
                number=number,
                owner=owner,
                pid=pid,
                layer=layer,
                bounds=bounds,
                title=redact_title(str(title) if title else None),
                chrome=chrome,
                native_prompt=is_native_prompt(owner, None),
                on_screen=on_screen,
                on_display=on_display,
            )
        )
    return wins


Event = tuple[str, Win, dict[str, Any]]


class WindowTracker:
    """Turns window snapshots into window_new / window_shown / window_raise events.

    ``seen`` holds every Chrome / native-prompt window number ever observed that
    still exists, on screen or not — so a window coming back from another Space,
    from a hidden app or from the Dock is ``window_shown``, never ``window_new``.
    Every update changes the state BEFORE returning its events, so a caller whose
    emit fails half-way can never re-report the same window on the next poll.
    """

    def __init__(self) -> None:
        self.seen: set[int] | None = None  # None until the baseline
        self.visible: set[int] = set()  # tracked windows on screen at last poll
        self.z_order: list[int] = []  # on-screen layer-0 numbers, front to back

    def baseline(self, all_windows: list[Win], on_screen: list[Win]) -> None:
        """Adopt what exists at start as known (no events)."""
        self.seen = {w.number for w in all_windows if w.tracked}
        self.seen |= {w.number for w in on_screen if w.tracked}
        self.visible = {w.number for w in on_screen if w.tracked}
        self.z_order = [w.number for w in on_screen if w.layer == 0]

    def on_screen(self, cur: list[Win]) -> list[Event]:
        """Diff an on-screen-only snapshot (front to back) against the last one."""
        if self.seen is None or not cur:
            return []
        tracked = [w for w in cur if w.tracked]
        events: list[Event] = []
        for win in tracked:
            if win.number not in self.seen:
                events.append(("window_new", win, {}))
            elif win.number not in self.visible:
                events.append(("window_shown", win, {}))
        events.extend(_raises(self.z_order, cur))
        self.seen |= {w.number for w in tracked}
        self.visible = {w.number for w in tracked}
        self.z_order = [w.number for w in cur if w.layer == 0]
        return events

    def all_windows(self, existing: set[int], new_wins: list[Win]) -> list[Event]:
        """Fold in a scan of ALL windows: `existing` ids, `new_wins` described.

        `new_wins` are the windows not present in the previous full scan. A
        tracked one never seen before is ``window_new`` (usually off screen —
        another Space, a hidden app). ``seen`` is pruned to `existing`.
        """
        if self.seen is None or not existing:
            return []
        fresh = [w for w in new_wins if w.tracked and w.number not in self.seen]
        self.seen = (self.seen | {w.number for w in fresh}) & existing
        self.visible &= existing
        return [("window_new", w, {}) for w in fresh]


def _raises(prev_z: list[int], cur: list[Win]) -> list[Event]:
    """Layer-0 Chrome windows that overtook a window still on screen.

    An index drop caused only by a window above it closing (or leaving the
    screen) is not a raise.
    """
    cur_l0_wins = [w for w in cur if w.layer == 0]
    cur_l0 = [w.number for w in cur_l0_wins]
    still_on_screen = set(cur_l0)
    prev_index = {number: i for i, number in enumerate(prev_z)}
    events: list[Event] = []
    for index, win in enumerate(cur_l0_wins):
        if not win.chrome or win.number not in prev_index:
            continue
        old = prev_index[win.number]
        overtaken = (set(prev_z[:old]) - set(cur_l0[:index])) & still_on_screen
        if overtaken and index < old:
            events.append(
                (
                    "window_raise",
                    win,
                    {"z_from": old, "z_to": index, "overtaken": len(overtaken)},
                )
            )
    return events


def read_records(path: Path) -> tuple[list[dict[str, Any]], int]:
    """All JSON records in `path` and the number of unparsable lines."""
    records: list[dict[str, Any]] = []
    bad = 0
    with path.open(encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                bad += 1
                continue
            if isinstance(obj, dict):
                records.append(obj)
            else:
                bad += 1
    return records, bad


def read_log_chain(path: Path) -> tuple[list[dict[str, Any]], int, list[Path]]:
    """Records of `path`'s rotations (oldest first) and `path`; bad lines; files."""
    files = log_chain(path)
    records: list[dict[str, Any]] = []
    bad = 0
    for file in files:
        recs, file_bad = read_records(file)
        records.extend(recs)
        bad += file_bad
    return records, bad, files


@dataclasses.dataclass
class Summary:  # pylint: disable=too-many-instance-attributes
    """Aggregated view of a log."""

    counts: Counter[tuple[str, str]]
    flagged: list[dict[str, Any]]
    chrome_events: int  # counted: activate / window_new / window_raise
    chrome_shown: int  # informational: window_shown
    chrome_offscreen: int  # informational: window_new never on screen
    native_events: int
    ignored_selftest: int
    total: int
    first_ts: str | None
    last_ts: str | None
    chrome_offdisplay: int = 0  # informational: window_new outside every display


def summarize(records: list[dict[str, Any]]) -> Summary:
    """Counts by (app, event), plus every chrome / native-prompt event in order.

    Events of a self-test's Chrome (pid between ``selftest_begin`` and
    ``selftest_end`` records) are ignored: they are the watcher's own probe.

    A Chrome ``window_new`` created OFF screen (a headless or occluded Chrome's
    invisible window, a window on another Space) disturbs nobody and is only
    counted as informational; it fails the summary when that window first comes
    on screen (its first ``window_shown``). The same holds for a window created
    on screen but OUTSIDE every display (``on_screen: true, on_display: false``
    — a window parked at -32000,-32000); records without ``on_display`` (logs
    written before that field existed) keep the on_screen-only rule.
    """
    counts: Counter[tuple[str, str]] = Counter()
    flagged: list[dict[str, Any]] = []
    chrome_events = chrome_shown = chrome_offscreen = native_events = ignored = 0
    chrome_offdisplay = 0
    offscreen_windows: set[Any] = set()
    selftest_pids: set[int] = set()
    for rec in records:
        event = str(rec.get("event") or "?")
        if event == "selftest_begin" and rec.get("chrome_pid") is not None:
            selftest_pids.add(int(rec["chrome_pid"]))
        elif event == "selftest_end" and rec.get("chrome_pid") is not None:
            selftest_pids.discard(int(rec["chrome_pid"]))
        if rec.get("pid") is not None and rec.get("pid") in selftest_pids:
            ignored += 1
            continue
        counts[(str(rec.get("app") or "-"), event)] += 1
        if event in BOOKKEEPING_EVENTS:
            continue
        is_chrome_event = bool(rec.get("chrome"))
        is_native_event = bool(rec.get("native_prompt"))
        window = (rec.get("pid"), rec.get("window"))
        if is_chrome_event and event == "window_new" and rec.get("on_screen") is False:
            chrome_offscreen += 1
            offscreen_windows.add(window)
            continue
        if (
            is_chrome_event
            and event == "window_new"
            and rec.get("on_screen") is True
            and rec.get("on_display") is False
        ):
            chrome_offdisplay += 1
            offscreen_windows.add(window)
            continue
        if is_chrome_event and event == "window_shown" and window in offscreen_windows:
            offscreen_windows.discard(window)
            chrome_events += 1  # first appearance on screen of an off-screen window
        elif is_chrome_event and event in COUNTED_CHROME_EVENTS:
            chrome_events += 1
        elif is_chrome_event:
            chrome_shown += 1
        native_events += is_native_event
        if is_chrome_event or is_native_event:
            flagged.append(rec)
    stamps = [str(r["ts"]) for r in records if r.get("ts")]
    return Summary(
        counts=counts,
        flagged=flagged,
        chrome_events=chrome_events,
        chrome_shown=chrome_shown,
        chrome_offscreen=chrome_offscreen,
        native_events=native_events,
        ignored_selftest=ignored,
        total=len(records),
        first_ts=stamps[0] if stamps else None,
        last_ts=stamps[-1] if stamps else None,
        chrome_offdisplay=chrome_offdisplay,
    )


def md_table(header: list[str], rows: list[list[str]]) -> str:
    """A column-aligned Markdown table."""
    widths = [len(h) for h in header]
    for row in rows:
        widths = [max(w, len(cell)) for w, cell in zip(widths, row)]

    def fmt(cells: list[str]) -> str:
        return "| " + " | ".join(c.ljust(w) for c, w in zip(cells, widths)) + " |"

    sep = "| " + " | ".join(":" + "-" * (w - 1) for w in widths) + " |"
    return "\n".join([fmt(header), sep, *(fmt(r) for r in rows)])


def _flag_kind(rec: dict[str, Any]) -> str:
    if rec.get("chrome"):
        if rec.get("event") in COUNTED_CHROME_EVENTS:
            return "chrome"
        return "chrome (shown, not counted)"
    return "native_prompt"


def _flag_detail(rec: dict[str, Any]) -> str:
    parts = []
    for key in (
        "source",
        "window",
        "on_screen",
        "on_display",
        "layer",
        "bounds",
        "title",
        "z_from",
        "z_to",
    ):
        if rec.get(key) is not None:
            parts.append(f"{key}={rec[key]}")
    return " ".join(parts)


def format_summary(summary: Summary, files: list[Path], bad_lines: int = 0) -> str:
    """Human summary of a log (Markdown)."""
    lines = ["Log: " + ", ".join(path_link(p) for p in files)]
    lines.append(
        f"{summary.total} records, {summary.first_ts or '-'} .. {summary.last_ts or '-'}"
        + (f", {bad_lines} unparsable line(s)" if bad_lines else "")
        + (
            f", {summary.ignored_selftest} self-test Chrome record(s) ignored"
            if summary.ignored_selftest
            else ""
        )
    )
    lines.append("")
    rows = [
        [app, event, str(n)]
        for (app, event), n in sorted(
            summary.counts.items(), key=lambda kv: (-kv[1], kv[0])
        )
    ]
    lines.append(md_table(["app", "event", "count"], rows or [["-", "-", "0"]]))
    lines.append("")
    if summary.flagged:
        lines.append("Chrome-for-Testing / native-prompt events:")
        lines.append("")
        flag_rows = [
            [
                str(r.get("ts") or "-"),
                str(r.get("event") or "-"),
                str(r.get("app") or "-"),
                str(r.get("pid") or "-"),
                _flag_kind(r),
                str(r.get("prev_app") or r.get("frontmost_app") or "-"),
                _flag_detail(r),
            ]
            for r in summary.flagged
        ]
        lines.append(
            md_table(
                ["ts", "event", "app", "pid", "kind", "prev/frontmost", "detail"],
                flag_rows,
            )
        )
        lines.append("")
    if summary.chrome_events:
        lines.append(
            f"❌ {summary.chrome_events} Chrome-for-Testing activate/window_new/"
            "window_raise event(s)"
        )
    else:
        lines.append("✅ no Chrome-for-Testing activate/window_new/window_raise events")
    lines.append(
        f"Chrome window_shown events (informational, not counted — a Space switch "
        f"looks the same): {summary.chrome_shown}"
    )
    lines.append(
        "Chrome windows created off screen (informational, never shown): "
        f"{summary.chrome_offscreen}"
    )
    lines.append(
        "Chrome windows created outside every display (informational, never "
        f"shown): {summary.chrome_offdisplay}"
    )
    if summary.native_events:
        lines.append(f"❌ {summary.native_events} native-prompt event(s)")
    else:
        lines.append("✅ no native-prompt events")
    return "\n".join(lines)


def newest_chrome_binary(cache: Path = PLAYWRIGHT_CACHE) -> Path | None:
    """The Chrome-for-Testing binary of the highest-numbered chromium-* build."""

    def build(path: Path) -> int:
        try:
            return int(path.name.split("-", 1)[1])
        except (IndexError, ValueError):
            return -1

    for build_dir in sorted(cache.glob("chromium-*"), key=build, reverse=True):
        if build(build_dir) < 0:
            continue
        for exe in build_dir.glob(
            "chrome-mac*/Google Chrome for Testing.app/Contents/MacOS/"
            "Google Chrome for Testing"
        ):
            if os.access(exe, os.X_OK):
                return exe
    return None


def free_port(reserved: frozenset[int] = RESERVED_CDP_PORTS) -> int:
    """A currently free 127.0.0.1 TCP port that is not one of the shared browser's."""
    while True:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
            port = int(sock.getsockname()[1])
        if port not in reserved:
            return port


def agent_path() -> str:
    """PATH for the LaunchAgent: uv's directory first, then the system default."""
    dirs = []
    uv = shutil.which("uv")
    if uv:
        dirs.append(str(Path(uv).parent))
    dirs += [
        "/usr/local/bin",
        "/opt/homebrew/bin",
        "/usr/bin",
        "/bin",
        "/usr/sbin",
        "/sbin",
    ]
    return ":".join(dict.fromkeys(dirs))


def agent_plist(python: Path, log: Path, max_mb: float) -> dict[str, Any]:
    """The LaunchAgent definition (runs the watcher with the repo's .venv python)."""
    return {
        "Label": AGENT_LABEL,
        "ProgramArguments": [
            str(python),
            str(SCRIPT),
            "-l",
            str(log),
            "-m",
            f"{max_mb:g}",
        ],
        # launchd's PATH lacks ~/.local/bin; pyvenv_bootstrap needs uv to repair
        # the venv after a uv.lock change.
        "EnvironmentVariables": {"PATH": agent_path()},
        "LimitLoadToSessionType": "Aqua",
        "ProcessType": "Standard",
        "RunAtLoad": True,
        "KeepAlive": True,
        "ThrottleInterval": 30,
        "StandardOutPath": str(AGENT_STD_LOGS[0]),
        "StandardErrorPath": str(AGENT_STD_LOGS[1]),
    }


_LIBPROC: Any = None


def exe_path_for_pid(pid: int) -> str | None:
    """Executable path of `pid` via libproc's proc_pidpath, None if unavailable."""
    global _LIBPROC  # pylint: disable=global-statement
    if sys.platform != "darwin" or pid <= 0:
        return None
    try:
        if _LIBPROC is None:
            _LIBPROC = ctypes.CDLL("/usr/lib/libproc.dylib")
        buf = ctypes.create_string_buffer(4096)
        length = _LIBPROC.proc_pidpath(int(pid), buf, ctypes.sizeof(buf))
    except (OSError, AttributeError, ctypes.ArgumentError):
        return None
    if length <= 0:
        return None
    return buf.value.decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# pyobjc side
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class ObjC:
    """The pyobjc modules this script uses."""

    appkit: Any
    quartz: Any
    apphelper: Any
    objc: Any


PYOBJC_MODULES = ("AppKit", "Quartz", "PyObjCTools.AppHelper", "objc")


def bootstrap_venv() -> None:
    """Run under the repo's .venv (pyvenv_bootstrap; creates/repairs it, re-execs).

    Called from `main()` after argument parsing and only for the modes that need
    pyobjc, so `-h`, `-s`, `-P`, `-U` and `-I` work on a bare interpreter.
    """
    sys.path.insert(0, str(REPO_ROOT))
    from pyvenv_bootstrap import (  # pylint: disable=import-outside-toplevel
        ensure_venv,
    )

    try:
        ensure_venv(__file__, requires=PYOBJC_MODULES)
    except SystemExit as exc:
        if exc.code in (0, None):
            raise
        safe_print(
            f"❌ no usable venv with pyobjc; run: uv sync --project {REPO_ROOT}",
            err=True,
        )
        raise SystemExit(EXIT_MISSING_DEP) from exc


def load_pyobjc() -> ObjC:
    """Import pyobjc (after `bootstrap_venv`); exit 3 with a ❌ when missing."""
    try:
        return ObjC(
            appkit=importlib.import_module("AppKit"),
            quartz=importlib.import_module("Quartz"),
            apphelper=importlib.import_module("PyObjCTools.AppHelper"),
            objc=importlib.import_module("objc"),
        )
    except ImportError as exc:
        safe_print(
            f"❌ pyobjc is not importable ({exc}).\n"
            f"   Install it: uv sync --project {REPO_ROOT} --group focus",
            err=True,
        )
        sys.exit(EXIT_MISSING_DEP)


def ns_screen_frames(appkit: Any) -> list[Rect]:
    """Every ``NSScreen`` frame (Cocoa coordinates), primary display first."""
    frames: list[Rect] = []
    for screen in appkit.NSScreen.screens() or []:
        frame = screen.frame()
        frames.append(
            (
                float(frame.origin.x),
                float(frame.origin.y),
                float(frame.size.width),
                float(frame.size.height),
            )
        )
    return frames


def app_info(running_app: Any) -> dict[str, Any]:
    """Name / bundle id / pid / executable of an NSRunningApplication."""
    if running_app is None:
        return {"app": None, "bundle_id": None, "pid": None, "exe": None}
    exe_url = running_app.executableURL()
    pid = int(running_app.processIdentifier())
    name = running_app.localizedName()
    bundle = running_app.bundleIdentifier()
    return {
        "app": str(name) if name is not None else None,
        "bundle_id": str(bundle) if bundle is not None else None,
        "pid": pid,
        "exe": str(exe_url.path()) if exe_url is not None else None,
    }


@dataclasses.dataclass
class WatchOptions:
    """How a Watcher runs."""

    deadline: float | None = None  # time.monotonic() value, None = forever
    interval_s: float = DEFAULT_INTERVAL_MS / 1000
    keep_records: bool = False  # only the self-test needs wait_for()
    cap_std_logs: bool = False  # running as the LaunchAgent


class Watcher:  # pylint: disable=too-many-instance-attributes
    """State shared by the run-loop callbacks (main thread) and the self-test worker."""

    def __init__(self, log: JsonlLog, objc_mods: ObjC, opts: WatchOptions) -> None:
        self.log = log
        self.mods = objc_mods
        self.opts = opts
        self.workspace = objc_mods.appkit.NSWorkspace.sharedWorkspace()
        self.reporter = RateLimitedReporter()
        self.front_pid: int | None = None
        self.front_name: str | None = None
        self.tracker = WindowTracker()
        self.all_ids: set[int] = set()
        self.last_all_scan = 0.0
        self.last_std_check = 0.0
        self.exe_cache: dict[int, str | None] = {}
        self._displays: list[Rect] = []
        self._displays_at = -DISPLAY_CACHE_S
        self.records: list[dict[str, Any]] = []
        self.cond = threading.Condition()
        self.stop_requested = threading.Event()
        self.main_queue: queue.Queue[Callable[[], None]] = queue.Queue()

    # -- recording -----------------------------------------------------------
    def emit(self, record: dict[str, Any]) -> None:
        """Write a record (and keep it for `wait_for` when asked to)."""
        try:
            self.log.write(record)
        finally:
            if self.opts.keep_records:
                with self.cond:
                    self.records.append(record)
                    self.cond.notify_all()

    def mark(self) -> int:
        """Index of the next record (for `wait_for(start=...)`)."""
        with self.cond:
            return len(self.records)

    def wait_for(
        self, pred: Callable[[dict[str, Any]], bool], timeout: float, start: int = 0
    ) -> dict[str, Any] | None:
        """First record at index >= `start` matching `pred`, waiting up to `timeout`."""
        end = time.monotonic() + timeout
        with self.cond:
            while True:
                for rec in self.records[start:]:
                    if pred(rec):
                        return rec
                remaining = end - time.monotonic()
                if remaining <= 0:
                    return None
                self.cond.wait(remaining)

    # -- events --------------------------------------------------------------
    def on_activate(self, running_app: Any, source: str) -> None:
        """Record an activation unless that app is already the known frontmost."""
        info = app_info(running_app)
        if info["pid"] is None or info["pid"] == self.front_pid:
            return
        prev = self.front_name
        self.front_pid, self.front_name = info["pid"], info["app"]
        self.emit(
            make_record(
                "activate",
                app=info["app"],
                bundle_id=info["bundle_id"],
                pid=info["pid"],
                chrome=is_chrome(info["app"], info["bundle_id"], info["exe"]),
                native_prompt=is_native_prompt(info["app"], info["bundle_id"]),
                prev_app=prev,
                source=source,
            )
        )

    def _exe(self, pid: int) -> str | None:
        if pid not in self.exe_cache:
            if len(self.exe_cache) >= EXE_CACHE_MAX:
                self.exe_cache.clear()
            self.exe_cache[pid] = exe_path_for_pid(pid)
        return self.exe_cache[pid]

    def display_rects(self) -> list[Rect]:
        """Every display's frame in CG coordinates (cached for DISPLAY_CACHE_S)."""
        now = time.monotonic()
        if now - self._displays_at >= DISPLAY_CACHE_S:
            self._displays = display_rects_cg(ns_screen_frames(self.mods.appkit))
            self._displays_at = now
        return self._displays

    def on_screen_windows(self) -> list[Win]:
        """Every on-screen window, front to back."""
        quartz = self.mods.quartz
        infos = quartz.CGWindowListCopyWindowInfo(
            quartz.kCGWindowListOptionOnScreenOnly
            | quartz.kCGWindowListExcludeDesktopElements,
            quartz.kCGNullWindowID,
        )
        return normalize_windows(infos or [], self._exe, self.display_rects)

    def scan_all(self, describe_all: bool = False) -> tuple[set[int], list[Win]]:
        """Ids of ALL windows (any Space, hidden, minimised) + the new ones described."""
        quartz = self.mods.quartz
        ids = {
            int(i)
            for i in quartz.CGWindowListCreate(
                quartz.kCGWindowListOptionAll, quartz.kCGNullWindowID
            )
            or ()
        }
        new_ids = ids if describe_all else ids - self.all_ids
        new_wins: list[Win] = []
        if new_ids:
            infos = quartz.CGWindowListCreateDescriptionFromArray(sorted(new_ids))
            new_wins = normalize_windows(infos or [], self._exe, self.display_rects)
        if ids:
            self.all_ids = ids
        return ids, new_wins

    def _emit_window_events(self, events: list[Event]) -> None:
        for event, win, extra in events:
            self.emit(
                make_record(
                    event,
                    app=win.owner,
                    pid=win.pid,
                    chrome=win.chrome,
                    native_prompt=win.native_prompt,
                    frontmost_app=self.front_name,
                    **win.fields(),
                    **extra,
                )
            )

    def poll_windows(self) -> None:
        """On-screen diff every tick; full-window scan every ALL_WINDOWS_SCAN_S."""
        now = time.monotonic()
        if now - self.last_all_scan >= ALL_WINDOWS_SCAN_S:
            self.last_all_scan = now
            existing, new_wins = self.scan_all()
            self._emit_window_events(self.tracker.all_windows(existing, new_wins))
        self._emit_window_events(self.tracker.on_screen(self.on_screen_windows()))

    def tick(self) -> None:
        """The poll timer: main-thread jobs, frontmost poll, window poll, stop check."""
        while True:
            try:
                job = self.main_queue.get_nowait()
            except queue.Empty:
                break
            try:
                job()
            except Exception as exc:  # pylint: disable=broad-exception-caught
                self.reporter.report(f"main-thread job failed: {exc}")
        try:
            self.on_activate(self.workspace.frontmostApplication(), "poll")
        except Exception as exc:  # pylint: disable=broad-exception-caught
            self.reporter.report(f"frontmost poll failed: {exc}")
        try:
            self.poll_windows()
        except Exception as exc:  # pylint: disable=broad-exception-caught
            self.reporter.report(f"window poll failed: {exc}")
        now = time.monotonic()
        if self.opts.cap_std_logs and now - self.last_std_check >= STD_LOG_CHECK_S:
            self.last_std_check = now
            for path in AGENT_STD_LOGS:
                cap_file(path, STD_LOG_CAP_BYTES)
        if self.opts.deadline is not None and now >= self.opts.deadline:
            self.stop_requested.set()
        if self.stop_requested.is_set():
            self.mods.apphelper.stopEventLoop()

    def start(self) -> None:
        """Baseline: frontmost app and every window, recorded as one `start` event."""
        info = app_info(self.workspace.frontmostApplication())
        self.front_pid, self.front_name = info["pid"], info["app"]
        _ids, all_wins = self.scan_all(describe_all=True)
        self.last_all_scan = time.monotonic()
        on_screen = self.on_screen_windows()
        self.tracker.baseline(all_wins, on_screen)
        self.emit(
            make_record(
                "start",
                app=info["app"],
                bundle_id=info["bundle_id"],
                pid=info["pid"],
                chrome=is_chrome(info["app"], info["bundle_id"], info["exe"]),
                native_prompt=is_native_prompt(info["app"], info["bundle_id"]),
                watcher_pid=os.getpid(),
                interval_ms=round(self.opts.interval_s * 1000),
                chrome_windows=sum(1 for w in all_wins if w.chrome),
                chrome_windows_on_screen=sum(1 for w in on_screen if w.chrome),
            )
        )


_BRIDGE_CLASS: Any = None


def bridge_class(objc_mods: ObjC) -> Any:
    """The NSObject subclass that forwards notifications/timer ticks to a Watcher."""
    global _BRIDGE_CLASS  # pylint: disable=global-statement
    if _BRIDGE_CLASS is not None:
        return _BRIDGE_CLASS
    ns_object = objc_mods.appkit.NSObject
    user_info_key = objc_mods.appkit.NSWorkspaceApplicationKey

    class FocusWatchBridge(ns_object):  # type: ignore[misc,valid-type]
        """Forwards Cocoa callbacks to `self.watcher` (never raises into the run loop)."""

        watcher: Watcher

        def appActivated_(self, note: Any) -> None:  # pylint: disable=invalid-name
            """NSWorkspaceDidActivateApplicationNotification handler."""
            try:
                app = (note.userInfo() or {}).get(user_info_key)
                self.watcher.on_activate(app, "notify")
            except Exception as exc:  # pylint: disable=broad-exception-caught
                self.watcher.reporter.report(f"activation handler: {exc}")

        def tick_(self, _timer: Any) -> None:  # pylint: disable=invalid-name
            """NSTimer callback."""
            try:
                self.watcher.tick()
            except Exception as exc:  # pylint: disable=broad-exception-caught
                self.watcher.reporter.report(f"tick: {exc}")

    _BRIDGE_CLASS = FocusWatchBridge
    return _BRIDGE_CLASS


def run_loop(watcher: Watcher) -> None:
    """Register the observers and run the Cocoa loop until a stop is requested."""
    appkit = watcher.mods.appkit
    bridge = bridge_class(watcher.mods).alloc().init()
    bridge.watcher = watcher
    center = watcher.workspace.notificationCenter()
    center.addObserver_selector_name_object_(
        bridge,
        "appActivated:",
        appkit.NSWorkspaceDidActivateApplicationNotification,
        None,
    )
    timer = (
        appkit.NSTimer.scheduledTimerWithTimeInterval_target_selector_userInfo_repeats_(
            watcher.opts.interval_s, bridge, "tick:", None, True
        )
    )

    def request_stop(_signum: int, _frame: Any) -> None:
        watcher.stop_requested.set()

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    watcher.start()
    try:
        watcher.mods.apphelper.runConsoleEventLoop(installInterrupt=False)
    finally:
        timer.invalidate()
        center.removeObserver_(bridge)
        try:
            watcher.emit(make_record("stop", watcher_pid=os.getpid()))
        except OSError as exc:
            watcher.reporter.report(f"cannot write stop record: {exc}")


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class SelfTestContext:
    """What the self-test needs from the main thread before the loop starts."""

    prev_front: Any  # NSRunningApplication or None
    prev_name: str | None
    prev_bundle: str | None
    textedit_was_running: bool
    # (ok, message, counts_toward_exit)
    results: list[tuple[bool, str, bool]] = dataclasses.field(default_factory=list)


def _stop_chrome(proc: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        pass
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        proc.wait(timeout=5)


def _mark_agent_log(event: str, chrome_pid: int) -> None:
    """Bracket the self-test Chrome in the agent's log so `-s` ignores its events."""
    if not DEFAULT_LOG.exists():
        return
    try:
        append_record(
            DEFAULT_LOG,
            make_record(event, chrome_pid=chrome_pid, watcher_pid=os.getpid()),
        )
    except OSError as exc:
        safe_print(f"❌ could not mark {path_link(DEFAULT_LOG)}: {exc}", err=True)


def _selftest_chrome(watcher: Watcher, ctx: SelfTestContext) -> None:
    binary = newest_chrome_binary()
    if binary is None:
        ctx.results.append(
            (
                False,
                f"chrome window_new: no Chrome for Testing under {PLAYWRIGHT_CACHE}",
                True,
            )
        )
        return
    port = free_port()
    profile = tempfile.mkdtemp(prefix="focus-watch-selftest-")
    start = watcher.mark()
    proc = subprocess.Popen(  # pylint: disable=consider-using-with
        [
            str(binary),
            f"--user-data-dir={profile}",
            f"--remote-debugging-port={port}",
            "--no-first-run",
            "--no-default-browser-check",
            # No "Chrome Safe Storage" keychain prompt for a throwaway profile.
            "--use-mock-keychain",
            "--password-store=basic",
            "about:blank",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    _mark_agent_log("selftest_begin", proc.pid)
    watcher.emit(
        make_record("selftest", step="spawn_chrome", port=port, chrome_pid=proc.pid)
    )
    try:
        rec = watcher.wait_for(
            lambda r: (
                r.get("event") == "window_new"
                and bool(r.get("chrome"))
                and r.get("pid") == proc.pid
            ),
            timeout=30,
            start=start,
        )
    finally:
        _stop_chrome(proc)
        shutil.rmtree(profile, ignore_errors=True)
        _mark_agent_log("selftest_end", proc.pid)
        watcher.emit(
            make_record("selftest", step="chrome_stopped", chrome_pid=proc.pid)
        )
    ctx.results.append(
        (
            rec is not None,
            "chrome window_new logged"
            + (f" (window {rec.get('window')}, pid {rec.get('pid')})" if rec else ""),
            True,
        )
    )


def _restore_front(watcher: Watcher, ctx: SelfTestContext) -> None:
    """Hand focus back to whatever was frontmost before the self-test."""
    if ctx.prev_front is None or ctx.prev_bundle == TEXTEDIT_BUNDLE_ID:
        return
    appkit = watcher.mods.appkit
    prev_pid = int(ctx.prev_front.processIdentifier())
    start = watcher.mark()
    watcher.main_queue.put(
        lambda: ctx.prev_front.activateWithOptions_(
            appkit.NSApplicationActivateAllWindows
        )
    )

    def back(r: dict[str, Any]) -> bool:
        return r.get("event") == "activate" and r.get("pid") == prev_pid

    restored = watcher.wait_for(back, timeout=3, start=start)
    how = "activateWithOptions"
    if restored is None and ctx.prev_bundle:
        subprocess.run(["open", "-b", ctx.prev_bundle], check=False)
        restored = watcher.wait_for(back, timeout=5, start=start)
        how = "open -b"
    ctx.results.append(
        (
            restored is not None,
            f"focus restored to {ctx.prev_name} via {how} (informational)",
            False,
        )
    )


def _quit_textedit(watcher: Watcher, ctx: SelfTestContext) -> None:
    """Quit the TextEdit the self-test launched (terminate, then force)."""
    appkit = watcher.mods.appkit

    def running() -> list[Any]:
        return list(
            appkit.NSRunningApplication.runningApplicationsWithBundleIdentifier_(
                TEXTEDIT_BUNDLE_ID
            )
            or []
        )

    def terminate(force: bool) -> None:
        for app in running():
            if force:
                app.forceTerminate()
            else:
                app.terminate()

    watcher.main_queue.put(lambda: terminate(False))
    end = time.monotonic() + 4
    while running() and time.monotonic() < end:
        time.sleep(0.25)
    if running():
        watcher.main_queue.put(lambda: terminate(True))
        end = time.monotonic() + 4
        while running() and time.monotonic() < end:
            time.sleep(0.25)
    ctx.results.append((not running(), "TextEdit quit again (informational)", False))


def _selftest_textedit(watcher: Watcher, ctx: SelfTestContext) -> None:
    watcher.emit(make_record("selftest", step="open_textedit"))
    start = watcher.mark()
    doc_dir = tempfile.mkdtemp(prefix="focus-watch-selftest-")
    try:
        cmd = ["open", "-a", "TextEdit"]
        if not ctx.textedit_was_running:
            # A document instead of TextEdit's iCloud open panel, which made
            # the app ignore a later terminate.
            doc = Path(doc_dir) / "focus-watch-selftest.txt"
            doc.write_text("focus_watch self-test\n", encoding="utf-8")
            cmd.append(str(doc))
        subprocess.run(cmd, check=False)
        rec = watcher.wait_for(
            lambda r: (
                r.get("event") == "activate"
                and r.get("bundle_id") == TEXTEDIT_BUNDLE_ID
            ),
            timeout=20,
            start=start,
        )
        ctx.results.append(
            (
                rec is not None,
                "TextEdit activate logged"
                + (
                    f" (source {rec.get('source')})"
                    if rec
                    else f" (frontmost now: {watcher.front_name})"
                ),
                True,
            )
        )
        _restore_front(watcher, ctx)
        if not ctx.textedit_was_running:
            _quit_textedit(watcher, ctx)
    finally:
        shutil.rmtree(doc_dir, ignore_errors=True)


def selftest_worker(watcher: Watcher, ctx: SelfTestContext) -> None:
    """The self-test steps (worker thread); always ends the run loop."""
    try:
        time.sleep(1.0)  # let the baseline settle
        _selftest_chrome(watcher, ctx)
        time.sleep(1.0)
        _selftest_textedit(watcher, ctx)
    except Exception as exc:  # pylint: disable=broad-exception-caught
        ctx.results.append((False, f"self-test crashed: {exc}", True))
    finally:
        try:
            watcher.emit(
                make_record(
                    "selftest",
                    step="done",
                    ok=all(ok for ok, _msg, counts in ctx.results if counts),
                )
            )
        finally:
            watcher.stop_requested.set()


def run_selftest(log: JsonlLog, objc_mods: ObjC, interval_s: float) -> int:
    """Watch while spawning a headed throwaway Chrome and toggling TextEdit."""
    appkit = objc_mods.appkit
    watcher = Watcher(
        log,
        objc_mods,
        WatchOptions(
            deadline=time.monotonic() + SELFTEST_DEADLINE_S,
            interval_s=interval_s,
            keep_records=True,
        ),
    )
    front = watcher.workspace.frontmostApplication()
    info = app_info(front)
    ctx = SelfTestContext(
        prev_front=front,
        prev_name=info["app"],
        prev_bundle=info["bundle_id"],
        textedit_was_running=bool(
            appkit.NSRunningApplication.runningApplicationsWithBundleIdentifier_(
                TEXTEDIT_BUNDLE_ID
            )
        ),
    )
    worker = threading.Thread(target=selftest_worker, args=(watcher, ctx), daemon=True)
    worker.start()
    run_loop(watcher)
    worker.join(timeout=10)
    safe_print(f"Self-test log: {path_link(log.path)}")
    for ok, msg, _counts in ctx.results:
        safe_print(f"{'✅' if ok else '❌'} {msg}")
    passed = bool(ctx.results) and all(ok for ok, _m, counts in ctx.results if counts)
    safe_print("✅ self-test passed" if passed else "❌ self-test FAILED")
    return 0 if passed else EXIT_FAIL


# ---------------------------------------------------------------------------
# LaunchAgent
# ---------------------------------------------------------------------------


def _launchctl(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["launchctl", *args], capture_output=True, text=True, check=False
    )


def is_not_loaded(res: subprocess.CompletedProcess[str]) -> bool:
    """A bootout/print result that means "no such service" rather than an error."""
    text = f"{res.stdout}\n{res.stderr}".lower()
    return res.returncode in LAUNCHCTL_NOT_LOADED or (
        "no such process" in text or "could not find" in text
    )


def worktree_main_checkout(repo: Path = REPO_ROOT) -> Path | None:
    """The main checkout when `repo` is a linked git worktree, else None."""
    res = subprocess.run(
        [
            "git",
            "-C",
            str(repo),
            "rev-parse",
            "--path-format=absolute",
            "--git-dir",
            "--git-common-dir",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    lines = res.stdout.split()
    if res.returncode != 0 or len(lines) != 2:
        return None
    git_dir, common = (Path(p).resolve() for p in lines)
    return None if git_dir == common else common.parent


def install_agent(log: Path, max_mb: float) -> int:
    """Sync the focus group, write the plist and (re)load it into the GUI domain."""
    main_checkout = worktree_main_checkout()
    if main_checkout is not None:
        safe_print(
            f"❌ refusing -I from a git worktree ({path_link(REPO_ROOT)}): the agent "
            f"would run this worktree's copy. Run it from the main checkout: "
            f"{path_link(main_checkout / 'bin' / SCRIPT.name)} -I",
            err=True,
        )
        return EXIT_FAIL
    uv = shutil.which("uv")
    if uv is None:
        safe_print("❌ uv not found on PATH (needed to sync the focus group)", err=True)
        return EXIT_MISSING_DEP
    sync = subprocess.run(
        [uv, "sync", "--project", str(REPO_ROOT), "--group", "focus"], check=False
    )
    if sync.returncode != 0 or not VENV_PYTHON.exists():
        safe_print("❌ uv sync --group focus failed", err=True)
        return EXIT_FAIL
    safe_print(f"✅ venv ready: {path_link(VENV_PYTHON)}")
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    AGENT_PLIST.parent.mkdir(parents=True, exist_ok=True)
    AGENT_PLIST.write_bytes(plistlib.dumps(agent_plist(VENV_PYTHON, log, max_mb)))
    safe_print(f"✅ wrote {path_link(AGENT_PLIST)}")
    domain = f"gui/{os.getuid()}"
    service = f"{domain}/{AGENT_LABEL}"
    _launchctl("bootout", service)
    end = time.monotonic() + 5
    while time.monotonic() < end and _launchctl("print", service).returncode == 0:
        time.sleep(0.2)
    res = _launchctl("bootstrap", domain, str(AGENT_PLIST))
    for _attempt in range(3):
        if res.returncode == 0:
            break
        time.sleep(1)
        res = _launchctl("bootstrap", domain, str(AGENT_PLIST))
    if res.returncode != 0:
        safe_print(
            f"❌ launchctl bootstrap failed ({res.returncode}): {res.stderr.strip()}",
            err=True,
        )
        return EXIT_FAIL
    safe_print(f"✅ loaded {AGENT_LABEL}; logging to {path_link(log)}")
    return 0


def uninstall_agent() -> int:
    """Unload the agent and delete its plist."""
    res = _launchctl("bootout", f"gui/{os.getuid()}/{AGENT_LABEL}")
    status = 0
    if res.returncode == 0:
        safe_print(f"✅ unloaded {AGENT_LABEL}")
    elif is_not_loaded(res):
        safe_print(f"✅ {AGENT_LABEL} was not loaded")
    else:
        safe_print(
            f"❌ launchctl bootout failed ({res.returncode}): {res.stderr.strip()}",
            err=True,
        )
        status = EXIT_FAIL
    if AGENT_PLIST.exists():
        AGENT_PLIST.unlink()
        safe_print(f"✅ removed {path_link(AGENT_PLIST)}")
    return status


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _positive_float(text: str) -> float:
    value = float(text)
    if value <= 0:
        raise argparse.ArgumentTypeError(f"must be > 0, got {text}")
    return value


def _non_negative_float(text: str) -> float:
    value = float(text)
    if value < 0:
        raise argparse.ArgumentTypeError(f"must be >= 0, got {text}")
    return value


def _interval_ms(text: str) -> int:
    value = int(text)
    if value < MIN_INTERVAL_MS:
        raise argparse.ArgumentTypeError(f"must be >= {MIN_INTERVAL_MS}, got {text}")
    return value


def build_parser() -> argparse.ArgumentParser:
    """The argument parser."""
    parser = argparse.ArgumentParser(
        prog="focus_watch.py",
        description=(
            "Log app activations and Chrome-for-Testing windows on macOS as JSON lines "
            "(acceptance instrument for the focus-free shared browser)."
        ),
        epilog=(
            "examples:\n"
            "  focus_watch.py                      watch forever\n"
            "  focus_watch.py -d 600               watch 10 min\n"
            "  focus_watch.py -l /tmp/f.jsonl -d 5 log elsewhere\n"
            "  focus_watch.py -i 500               poll every 500 ms\n"
            "  focus_watch.py -s                   summarise the default log\n"
            "  focus_watch.py -t                   self-test (opens Chrome + TextEdit!)\n"
            "  focus_watch.py -P                   print the LaunchAgent plist\n"
            "  focus_watch.py -I / -U              install / uninstall the LaunchAgent\n"
            "\nexit: 0 ok, 1 self-test failed or summary saw Chrome "
            "activate/window_new/window_raise events, 3 pyobjc/uv missing"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-l",
        "--log",
        type=Path,
        default=None,
        help=f"JSON-lines log file (default: {DEFAULT_LOG}; with -t a new temp file)",
    )
    parser.add_argument(
        "-m",
        "--max-mb",
        type=_positive_float,
        default=DEFAULT_MAX_MB,
        help=f"rotate the log at this size in MB (> 0), keeping {KEEP_ROTATED} old "
        f"files (default: {DEFAULT_MAX_MB:g})",
    )
    parser.add_argument(
        "-d",
        "--duration",
        type=_non_negative_float,
        default=0.0,
        metavar="SECONDS",
        help="watch for SECONDS, then exit (default: 0 = forever)",
    )
    parser.add_argument(
        "-i",
        "--interval-ms",
        type=_interval_ms,
        default=DEFAULT_INTERVAL_MS,
        metavar="MS",
        help=f"poll interval for frontmost app + on-screen windows "
        f"(default: {DEFAULT_INTERVAL_MS}; all windows are scanned every "
        f"{ALL_WINDOWS_SCAN_S:g} s)",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "-s",
        "--summary",
        nargs="?",
        const="",
        metavar="PATH",
        help="summarise a log and its rotations, oldest first (default: the "
        "--log path) and exit",
    )
    mode.add_argument(
        "-t",
        "--self-test",
        action="store_true",
        help="spawn a headed throwaway Chrome for Testing and activate TextEdit "
        "and back; assert both were logged (ACTIVATES APPS)",
    )
    mode.add_argument(
        "-I",
        "--install-agent",
        action="store_true",
        help=f"write and load the LaunchAgent {AGENT_PLIST} (main checkout only)",
    )
    mode.add_argument(
        "-U",
        "--uninstall-agent",
        action="store_true",
        help="unload and delete the LaunchAgent",
    )
    mode.add_argument(
        "-P",
        "--print-agent",
        action="store_true",
        help="print the LaunchAgent plist and exit (writes nothing)",
    )
    return parser


def cmd_summary(path: Path) -> int:
    """`-s`: print the summary; exit 1 on counted Chrome events."""
    path = path.expanduser().absolute()
    records, bad, files = read_log_chain(path)
    if not files:
        safe_print(f"❌ no log at {path_link(path)}", err=True)
        return EXIT_FAIL
    summary = summarize(records)
    safe_print(format_summary(summary, files, bad))
    return EXIT_FAIL if summary.chrome_events else 0


def cmd_watch(log_path: Path, args: argparse.Namespace) -> int:
    """Default mode (watch, optionally for -d seconds) or the -t self-test."""
    if sys.platform != "darwin":
        safe_print("❌ focus_watch.py only runs on macOS", err=True)
        return EXIT_FAIL
    objc_mods = load_pyobjc()
    log = JsonlLog(log_path, int(args.max_mb * 1024 * 1024))
    interval_s = args.interval_ms / 1000
    if args.self_test:
        return run_selftest(log, objc_mods, interval_s)
    opts = WatchOptions(
        deadline=time.monotonic() + args.duration if args.duration else None,
        interval_s=interval_s,
        cap_std_logs=log_path.parent == STATE_DIR,
    )
    safe_print(f"✅ watching (pid {os.getpid()}), logging to {path_link(log_path)}")
    run_loop(Watcher(log, objc_mods, opts))
    safe_print("✅ stopped")
    return 0


def resolve_log(arg: Path | None, self_test: bool) -> Path:
    """-l if given; a fresh temp file for -t; else DEFAULT_LOG."""
    if arg is not None:
        return arg.expanduser().absolute()
    if self_test:
        fd, name = tempfile.mkstemp(prefix="focus-watch-selftest-", suffix=".jsonl")
        os.close(fd)
        return Path(name)
    return DEFAULT_LOG


def main(argv: list[str] | None = None) -> int:
    """Entry point."""
    args = build_parser().parse_args(argv)  # -h needs no venv
    watch_mode = not (
        args.summary is not None
        or args.print_agent
        or args.uninstall_agent
        or args.install_agent
    )
    if watch_mode and sys.platform == "darwin":
        bootstrap_venv()  # may re-exec under <repo>/.venv
    if args.summary is not None:
        default = args.log.expanduser() if args.log else DEFAULT_LOG
        return cmd_summary(Path(args.summary) if args.summary else default)
    log_path = resolve_log(args.log, args.self_test)
    if args.print_agent:
        sys.stdout.write(
            plistlib.dumps(agent_plist(VENV_PYTHON, log_path, args.max_mb)).decode()
        )
        return 0
    if args.uninstall_agent:
        return uninstall_agent()
    if args.install_agent:
        return install_agent(log_path, args.max_mb)
    return cmd_watch(log_path, args)


if __name__ == "__main__":
    sys.exit(main())
