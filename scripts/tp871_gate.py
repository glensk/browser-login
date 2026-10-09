#!/usr/bin/env python3
"""tp871_gate.py — Step 0 measurement gate of PLAN_headed-check-tabs.md (tp#871).

Measures whether a background check tab in a HEADED Chrome for Testing freezes
(0a, control V0) and whether an off-screen / minimised own window keeps it alive
without showing anything (0b: V1, V2, V3 plus cases i–iv); optionally (-c) the
focus behaviour with the disposable browser activated (0c). Writes the per-variant
results and the 0d verdict to ``$S/gate-step0.json``.

It launches a DISPOSABLE headed browser in-process (``browser._launch_and_record``)
with its own ``CLAUDE_BROWSER_CACHE_DIR=$S/cache`` on port 9371 — never the
shared browser on 9222/9223 — and runs ``bin/focus_watch.py -l $S/fw-step0.jsonl``
next to it. A headed window appears on the screen, so every variant runs only while
the Mac is idle: HIDIdleTime (``ioreg -c IOHIDSystem``) must be >= 600 s before
each variant and at every 30 s check during it; otherwise the variant is aborted,
the disposable browser torn down, ``aborted: user active`` recorded and the script
exits 75. A re-run skips every variant already done and resumes with the rest.

Usage:
  tp871_gate.py -n                 dry run: the plan of runs + prerequisites
  tp871_gate.py                    run the remaining variants (15 min each)
  tp871_gate.py -c                 … plus 0c (activates the disposable browser)
  tp871_gate.py -d 60 -S /tmp/g    a short smoke run in another state dir
  tp871_gate.py -p 9372            another disposable port (never 9222/9223)

Exit codes: 0 every planned variant done (verdict written), 1 error,
2 usage, 75 aborted because the user was active (re-run later to resume).
"""

# pylint: disable=too-many-lines  # one self-contained measurement tool

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import datetime as dt
import importlib
import importlib.util
import io
import json
import os
import re
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.parse
from collections.abc import Callable
from pathlib import Path
from typing import Any

SCRIPT = Path(__file__).resolve()
REPO_ROOT = SCRIPT.parent.parent
BIN_DIR = REPO_ROOT / "bin"
BROWSER_PY = BIN_DIR / "browser.py"
FOCUS_WATCH_PY = BIN_DIR / "focus_watch.py"
DEFAULT_STATE = Path.home() / ".local" / "state" / "tp871"
GATE_JSON = "gate-step0.json"
FW_LOG = "fw-step0.jsonl"
DEFAULT_PORT = 9371
RESERVED_PORTS = frozenset({9222, 9223})
DEFAULT_DURATION_S = 900.0
SHORT_VARIANT_S = 300.0  # V3 and the 0c re-runs: "5 min"
IDLE_MIN_S = 600.0
IDLE_CHECK_S = 30.0
# Our own synthetic key event (0c's Cmd-`) resets HIDIdleTime too; an idle time
# that matches the time since that event (within this) is ours, not Albert's.
SYNTHETIC_TOLERANCE_S = 2.0
EVAL_BUDGET_S = 5.0  # an evaluate unanswered within 5 s = the freeze reproduced
EVAL_PASS_S = 1.0  # a passing variant answers every evaluate under 1 s
SAMPLE_S = 1.0
CHURN_S = 5.0
CONNECT_S = 5.0
TYPE_S = 0.2
DOCTOR_WAIT_S = 120.0
FW_START_WAIT_S = 20.0
FW_FLUSH_S = 2.5
OFF = -32000
CHECK_WIDTH, CHECK_HEIGHT = 1280, 900
KVK_ANSI_GRAVE = 50
EXIT_FAIL = 1
EXIT_USAGE = 2
EXIT_ABORTED = 75
ABORT_USER_ACTIVE = "aborted: user active"
GATE_REQUIRES = ("playwright", "websockets", "AppKit", "Quartz")

_CHECK_HTML = (
    "<!doctype html><title>tp871 check</title><body>tp871 check tab<script>"
    "window.__raf=0;window.__ev=[];"
    "(function f(){window.__raf++;requestAnimationFrame(f);})();"
    "for(const t of ['freeze','resume','visibilitychange'])"
    "document.addEventListener(t,()=>window.__ev.push("
    "[t,document.visibilityState,Date.now()]));"
    "</script>"
)
_HUMAN_HTML = (
    "<!doctype html><title>tp871 human</title><body>tp871 human tab"
    "<textarea id=t rows=4 cols=40></textarea><script>"
    "window.__raf=0;window.__ev=[];"
    "(function f(){window.__raf++;requestAnimationFrame(f);})();"
    "for(const t of ['freeze','resume','visibilitychange'])"
    "document.addEventListener(t,()=>window.__ev.push("
    "[t,document.visibilityState,Date.now()]));"
    "</script>"
)
CHECK_URL = "data:text/html," + urllib.parse.quote(_CHECK_HTML)
HUMAN_URL = "data:text/html," + urllib.parse.quote(_HUMAN_HTML)
CASE_URL = "data:text/html," + urllib.parse.quote("<title>tp871 case</title>case")
PAGE_EXPR = (
    "({v:document.visibilityState,f:document.hasFocus(),r:window.__raf|0,"
    "ev:(window.__ev||[]).slice(-20)})"
)
POPUP_EXPR = (
    "(()=>{const w=window.open('about:blank','_blank','popup,width=500,height=400');"
    "if(w){w.document.write('<title>tp871 popup</title>tp871 popup');}"
    "return !!w;})()"
)

# fw segments that count towards a variant's pass (the popup segment and case
# iii, whose window placement is only recorded, are excluded).
COUNTED_SEGMENTS = ("steady", "case_i", "case_ii")


# ---------------------------------------------------------------------------
# Variants and the plan of runs (pure)
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class Variant:
    """One createTarget payload under test (without ``url``)."""

    name: str
    params: dict[str, Any]
    short: bool = False  # SHORT_VARIANT_S instead of the full duration
    evidence_only: bool = False  # V3: recorded, never selectable
    with_0c: bool = False  # activation + typing + Cmd-` instead of cases i–iv
    expect_bounds: tuple[int, int, int, int] | None = None
    note: str = ""


_V1_PARAMS: dict[str, Any] = {
    "newWindow": True,
    "background": True,
    "left": OFF,
    "top": OFF,
    "width": CHECK_WIDTH,
    "height": CHECK_HEIGHT,
}
_V2_PARAMS: dict[str, Any] = {**_V1_PARAMS, "background": False, "focus": False}
_OFF_BOUNDS = (OFF, OFF, CHECK_WIDTH, CHECK_HEIGHT)

VARIANTS: tuple[Variant, ...] = (
    Variant("V0", {"background": True}, note="0a control: today's headed payload"),
    Variant("V1", _V1_PARAMS, expect_bounds=_OFF_BOUNDS, note="0b off-screen window"),
    Variant(
        "V2",
        _V2_PARAMS,
        expect_bounds=_OFF_BOUNDS,
        note="0b off-screen window, background:false focus:false",
    ),
    Variant(
        "V3",
        {"newWindow": True, "background": True, "windowState": "minimized"},
        short=True,
        evidence_only=True,
        note="0b minimised window (evidence only)",
    ),
    Variant(
        "V1c",
        _V1_PARAMS,
        short=True,
        with_0c=True,
        expect_bounds=_OFF_BOUNDS,
        note="0c V1 while activated + typing + Cmd-`",
    ),
    Variant(
        "V2c",
        _V2_PARAMS,
        short=True,
        with_0c=True,
        expect_bounds=_OFF_BOUNDS,
        note="0c V2 while activated + typing + Cmd-`",
    ),
)
VARIANT_BY_NAME = {v.name: v for v in VARIANTS}


def variant_duration(variant: Variant, duration_s: float) -> float:
    """How long `variant` runs for a requested full `duration_s`."""
    return min(SHORT_VARIANT_S, duration_s) if variant.short else duration_s


def planned_variants(with_0c: bool) -> list[Variant]:
    """Every variant this invocation covers, in run order."""
    return [v for v in VARIANTS if with_0c or not v.with_0c]


def is_done(results: dict[str, Any], name: str) -> bool:
    """True when `name` has a completed result (aborted / error runs are redone)."""
    res = results.get(name)
    return isinstance(res, dict) and res.get("status") == "done"


def control_not_reproduced(results: dict[str, Any]) -> bool:
    """V0 completed and the freeze never showed: the gate stops there."""
    return is_done(results, "V0") and not results["V0"].get("reproduced")


def pending_variants(results: dict[str, Any], with_0c: bool) -> list[Variant]:
    """The variants still to run; none past a V0 that did not reproduce."""
    if control_not_reproduced(results):
        return []
    return [v for v in planned_variants(with_0c) if not is_done(results, v.name)]


# ---------------------------------------------------------------------------
# Idle guard, frontmost app (pure parsers + thin I/O)
# ---------------------------------------------------------------------------

_HID_IDLE_RE = re.compile(r'"HIDIdleTime"\s*=\s*(\d+)')
_LSAPPINFO_PID_RE = re.compile(r'"pid"\s*=\s*(\d+)')


def parse_hid_idle_s(text: str) -> float | None:
    """Seconds since the last HID input from ``ioreg -c IOHIDSystem`` output."""
    match = _HID_IDLE_RE.search(text or "")
    return int(match.group(1)) / 1e9 if match else None


def user_active(
    idle_s: float | None,
    since_synthetic_s: float | None = None,
    min_idle_s: float = IDLE_MIN_S,
    tolerance_s: float = SYNTHETIC_TOLERANCE_S,
) -> bool:
    """Whether Albert counts as present. Unknown idle time fails closed (True).

    An idle time below `min_idle_s` that equals the time since our own synthetic
    key event (0c's Cmd-`, within `tolerance_s`) was caused by that event.
    """
    if idle_s is None:
        return True
    if idle_s >= min_idle_s:
        return False
    return not (
        since_synthetic_s is not None and idle_s >= since_synthetic_s - tolerance_s
    )


def idle_seconds() -> float | None:
    """HIDIdleTime in seconds, None when ioreg is unavailable or unparsable."""
    try:
        res = subprocess.run(
            ["ioreg", "-c", "IOHIDSystem"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return parse_hid_idle_s(res.stdout)


def parse_lsappinfo_pid(text: str) -> int | None:
    """The pid from ``lsappinfo info -only pid <ASN>`` output."""
    match = _LSAPPINFO_PID_RE.search(text or "")
    return int(match.group(1)) if match else None


def frontmost_pid() -> int | None:
    """Pid of the frontmost app (lsappinfo; works without a Cocoa run loop)."""
    try:
        asn = subprocess.run(
            ["lsappinfo", "front"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        ).stdout.strip()
        if not asn:
            return None
        out = subprocess.run(
            ["lsappinfo", "info", "-only", "pid", asn],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        ).stdout
    except (OSError, subprocess.TimeoutExpired):
        return None
    return parse_lsappinfo_pid(out)


# ---------------------------------------------------------------------------
# Verdict (pure)
# ---------------------------------------------------------------------------


def _parse_ts(text: Any) -> dt.datetime | None:
    try:
        return dt.datetime.fromisoformat(str(text))
    except (TypeError, ValueError):
        return None


def fw_segment_stats(
    fw: Any, records: list[dict[str, Any]], pids: set[int], start: str, end: str
) -> dict[str, Any]:
    """focus_watch counts for the disposable's `pids` between two ISO stamps.

    ``counted`` is focus_watch's own ``summarize`` verdict (activations,
    window_raise, a window_new on a display or of unknown placement, the first
    window_shown of an off-display window); the breakdown names them.
    """
    lo, hi = _parse_ts(start), _parse_ts(end)
    sel = []
    for rec in records:
        stamp = _parse_ts(rec.get("ts"))
        if stamp is None or lo is None or hi is None or not lo <= stamp <= hi:
            continue
        if rec.get("pid") in pids:
            sel.append(rec)
    summary = fw.summarize(sel)
    new_on_display = [
        r
        for r in sel
        if r.get("event") == "window_new"
        and r.get("on_screen") is not False
        and r.get("on_display") is not False
    ]
    return {
        "records": len(sel),
        "counted": summary.chrome_events,
        "activations": sum(1 for r in sel if r.get("event") == "activate"),
        "window_raise": sum(1 for r in sel if r.get("event") == "window_raise"),
        "window_new_on_display": len(new_on_display),
        "window_new_off_display": summary.chrome_offdisplay,
        "window_new_off_screen": summary.chrome_offscreen,
        "flagged": [
            {
                k: r.get(k)
                for k in ("ts", "event", "window", "bounds", "on_screen", "on_display")
                if r.get(k) is not None
            }
            for r in summary.flagged[:20]
        ],
    }


def reproduced(res: dict[str, Any]) -> tuple[bool, list[str]]:
    """The 0a criterion: an evaluate unanswered within 5 s, a freeze, a failed connect."""
    why = []
    evals = res.get("evals") or {}
    if evals.get("unanswered"):
        why.append(f"{evals['unanswered']} evaluate(s) unanswered within 5 s")
    events = res.get("page_events") or {}
    if events.get("freeze"):
        why.append(f"{events['freeze']} freeze event(s)")
    connects = res.get("connects") or {}
    if connects.get("failures"):
        why.append(f"{connects['failures']} failed Playwright connect(s)")
    return bool(why), why


def _steady_failures(res: dict[str, Any], variant: Variant) -> list[str]:
    why = []
    evals = res.get("evals") or {}
    if not evals.get("n"):
        why.append("no evaluate sample")
    if evals.get("unanswered"):
        why.append(f"{evals['unanswered']} evaluate(s) unanswered")
    if evals.get("slow"):
        why.append(f"{evals['slow']} evaluate(s) took >= {EVAL_PASS_S:g} s")
    if evals.get("not_visible"):
        why.append(f"{evals['not_visible']} evaluate(s) not 'visible'")
    if (res.get("page_events") or {}).get("freeze"):
        why.append("freeze event")
    if (res.get("connects") or {}).get("failures"):
        why.append("failed Playwright connect")
    human = res.get("human") or {}
    if not human.get("n"):
        why.append("no human-tab sample")
    for key, label in (
        ("not_visible", "human tab not visible"),
        ("raf_stalls", "human tab rAF stalled"),
        ("unanswered", "human tab unanswered"),
    ):
        if human.get(key):
            why.append(f"{label} ({human[key]}x)")
    if variant.expect_bounds is not None:
        if (res.get("windows") or {}).get("bounds_exact") is not True:
            why.append("getWindowForTarget bounds differ from the requested ones")
    return why


def _fw_failures(res: dict[str, Any], segments: tuple[str, ...]) -> list[str]:
    fw_stats = res.get("fw")
    if not isinstance(fw_stats, dict) or not fw_stats.get("recorded"):
        return ["focus_watch log missing (no start record)"]
    why = []
    for seg in segments:
        stats = fw_stats.get(seg)
        if not isinstance(stats, dict):
            why.append(f"focus_watch segment {seg} missing")
        elif stats.get("counted"):
            why.append(
                f"focus_watch {seg}: {stats['counted']} counted event(s) "
                f"(activate {stats.get('activations', 0)}, raise "
                f"{stats.get('window_raise', 0)}, on-display window_new "
                f"{stats.get('window_new_on_display', 0)})"
            )
    return why


def variant_pass(
    res: dict[str, Any], variant: Variant
) -> tuple[bool | None, list[str]]:
    """The 0d pass rule for one completed variant; None for the control/evidence.

    0b variants: the steady criteria, cases i and ii in the human window ``H``,
    and no counted focus_watch event in the steady and case i/ii segments.
    0c variants: the human tab keeps hasFocus and loses no typed character.
    """
    if variant.name == "V0" or variant.evidence_only:
        return None, []
    why = _steady_failures(res, variant)
    if variant.with_0c:
        human = res.get("human") or {}
        if human.get("no_focus"):
            why.append(f"human tab lost hasFocus ({human['no_focus']}x)")
        typing = res.get("typing") or {}
        if not typing.get("sent"):
            why.append("nothing typed")
        elif typing.get("lost"):
            why.append(f"{typing['lost']} typed character(s) lost")
        if not (res.get("activation") or {}).get("frontmost"):
            why.append("the disposable browser never became frontmost (inconclusive)")
        return not why, why
    cases = res.get("cases") or {}
    for case in ("i", "ii"):
        if not (cases.get(case) or {}).get("ok"):
            why.append(f"case ({case}) did not land in H")
    why.extend(_fw_failures(res, COUNTED_SEGMENTS))
    return not why, why


def overall_verdict(results: dict[str, Any], with_0c: bool) -> dict[str, Any]:
    """0d: valid only if V0 reproduced; pick V1, else V2, else F1 → (c).

    ``smoke`` marks a verdict built from any variant shorter than the plan's
    durations (``-d`` below 900 s): a smoke run, never the verdict of record.
    """
    out: dict[str, Any] = {"computed": now_iso()}
    out["smoke"] = any(
        float(res.get("duration_s") or 0)
        < variant_duration(VARIANT_BY_NAME[name], DEFAULT_DURATION_S)
        for name, res in results.items()
        if name in VARIANT_BY_NAME and is_done(results, name)
    )
    if not is_done(results, "V0"):
        out.update(state="incomplete", valid=False, choice=None, note="V0 not run yet")
        return out
    if not results["V0"].get("reproduced"):
        out.update(
            state="freeze not reproduced",
            valid=False,
            choice=None,
            note="V0 never froze in this harness: record it in the plan and "
            "tp#871, tear down, stop; no code ships.",
        )
        return out
    passes = {
        name: results[name].get("pass")
        for name in ("V1", "V2", "V1c", "V2c")
        if is_done(results, name)
    }
    missing = [
        v.name for v in planned_variants(with_0c) if not is_done(results, v.name)
    ]
    out["passes"] = passes
    out["valid"] = True
    out["state"] = "incomplete" if missing else "complete"
    if missing:
        out["missing"] = missing
    ran_0c = {n: is_done(results, n) for n in ("V1c", "V2c")}
    if passes.get("V1") and (not ran_0c["V1c"] or passes.get("V1c")):
        out["choice"] = "V1"
        out["note"] = (
            "V1 passes 0b and 0c."
            if ran_0c["V1c"]
            else "V1 passes 0b; 0c skipped: key-focus theft while typing and Cmd-` "
            "landing in a check window stay unproven — shipping V1 needs Albert's "
            "explicit OK on that residual."
        )
    elif passes.get("V2") and ran_0c["V2c"] and passes.get("V2c"):
        out["choice"] = "V2"
        out["note"] = "V1 failed; V2 passes 0b and 0c."
    elif passes.get("V2") and not ran_0c["V2c"]:
        out["choice"] = None
        out["note"] = "V2 passes 0b but cannot be chosen without 0c (run with -c)."
    else:
        out["choice"] = "F1 -> (c)"
        out["note"] = "Neither V1 nor V2 passes: ship F1 → (c) (Step 7) instead."
    return out


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def now_iso() -> str:
    """Local time, ISO 8601 with offset, ms precision (focus_watch's format)."""
    return dt.datetime.now().astimezone().isoformat(timespec="milliseconds")


def osc8(target: str, text: str) -> str:
    """`text` as an OSC 8 terminal hyperlink to `target`."""
    return f"\x1b]8;;{target}\x1b\\{text}\x1b]8;;\x1b\\"


def path_link(path: Path) -> str:
    """An absolute path as a clickable file:// hyperlink."""
    absolute = path.expanduser().absolute()
    return osc8(absolute.as_uri(), str(absolute))


def say(msg: str) -> None:
    """One progress line, flushed."""
    print(msg, flush=True)


def load_module(name: str, path: Path) -> Any:
    """Import a repo script by path (bin/ is not a package)."""
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod  # dataclasses resolve their module by name
    spec.loader.exec_module(mod)
    return mod


def read_state(path: Path) -> dict[str, Any]:
    """The gate JSON (empty skeleton when absent or unreadable)."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        data = {}
    if not isinstance(data, dict):
        data = {}
    data.setdefault("results", {})
    return data


def write_state(path: Path, data: dict[str, Any]) -> None:
    """Atomic JSON write (tmp + rename)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    data["updated"] = now_iso()
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, default=str) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def is_live_cache(cache: Path) -> bool:
    """True when `cache` is (inside) a live shared browser's ~/.cache/claude-browser*."""
    live_root = (Path.home() / ".cache").resolve()
    try:
        rel = cache.expanduser().resolve().relative_to(live_root)
    except ValueError:
        return False
    return bool(rel.parts) and rel.parts[0].startswith("claude-browser")


def port_listening(port: int) -> bool:
    """True when something accepts TCP connections on 127.0.0.1:`port`."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.5)
        return sock.connect_ex(("127.0.0.1", port)) == 0


def _every(period_s: float, stop: threading.Event, fn: Callable[[], None]) -> None:
    """Call `fn` every `period_s` until `stop`; a slow call delays, never piles up."""
    nxt = time.monotonic()
    while not stop.is_set():
        fn()
        nxt += period_s
        delay = nxt - time.monotonic()
        if delay < 0:
            nxt, delay = time.monotonic(), 0.0
        stop.wait(delay)


# ---------------------------------------------------------------------------
# The disposable browser
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class Gate:  # pylint: disable=too-many-instance-attributes
    """Everything a variant run needs."""

    port: int
    state_dir: Path
    browser: Any  # bin/browser.py, imported with CLAUDE_BROWSER_CACHE_DIR set
    fw: Any  # bin/focus_watch.py
    fw_log: Path
    abort: threading.Event = dataclasses.field(default_factory=threading.Event)
    abort_reason: str = ""
    last_synthetic: float | None = None  # time.monotonic() of our own key event
    ws_url: str | None = None

    def user_active_now(self) -> tuple[bool, float | None]:
        """(active, idle seconds) — the idle guard."""
        idle = idle_seconds()
        since = (
            time.monotonic() - self.last_synthetic
            if self.last_synthetic is not None
            else None
        )
        return user_active(idle, since), idle

    def browser_call(
        self, method: str, params: dict[str, Any] | None = None, budget: float = 5.0
    ) -> Any:
        """One raw CDP command on the browser websocket."""
        if self.ws_url is None:
            self.ws_url = self.browser._browser_ws_url(self.port)  # pylint: disable=protected-access
        if self.ws_url is None:
            return self.browser.CdpResult("transport-error", error="no browser ws")
        return self.browser._cdp_ws_call(self.ws_url, method, params, budget)  # pylint: disable=protected-access

    def page_call(
        self,
        tid: str,
        method: str,
        params: dict[str, Any] | None = None,
        budget: float = 5.0,
    ) -> Any:
        """One raw CDP command on a page target's own websocket."""
        url = f"ws://127.0.0.1:{self.port}/devtools/page/{tid}"
        return self.browser._cdp_ws_call(url, method, params, budget)  # pylint: disable=protected-access

    def evaluate(
        self, tid: str, expr: str, budget: float, gesture: bool = False
    ) -> tuple[str, Any, float]:
        """(``ok``|``timeout``|``error``, value, seconds) of one Runtime.evaluate."""
        start = time.monotonic()
        params = {"expression": expr, "returnByValue": True, "userGesture": gesture}
        res = self.page_call(tid, "Runtime.evaluate", params, budget)
        took = time.monotonic() - start
        if res.status == "timeout":
            return "timeout", None, took
        result = res.result or {}
        if res.status != "ok" or res.error or result.get("exceptionDetails"):
            return "error", None, took
        return "ok", (result.get("result") or {}).get("value"), took

    def create(self, url: str, params: dict[str, Any]) -> str | None:
        """Target.createTarget with `params`; the new target id or None."""
        res = self.browser_call("Target.createTarget", {"url": url, **params})
        tid = (res.result or {}).get("targetId") if res.status == "ok" else None
        return tid if isinstance(tid, str) and tid and not res.error else None

    def close(self, tid: str) -> bool:
        """Target.closeTarget by id."""
        res = self.browser_call("Target.closeTarget", {"targetId": tid})
        return res.status == "ok" and not res.error

    def window_for(self, tid: str) -> dict[str, Any] | None:
        """``{windowId, bounds}`` of the window holding `tid`, None on failure."""
        res = self.browser_call("Browser.getWindowForTarget", {"targetId": tid}, 3.0)
        if res.status != "ok" or res.error or not res.result:
            return None
        return dict(res.result)

    def open_new_raw(self, url: str) -> str | None:
        """`open -N` in-process (``browser._open_new_raw``); the printed target id."""
        buf = io.StringIO()
        try:
            with contextlib.redirect_stdout(buf):
                rc = self.browser._open_new_raw(self.port, url)  # pylint: disable=protected-access
        except SystemExit:
            return None
        match = re.search(r"^target=(\S+)$", buf.getvalue(), re.MULTILINE)
        return match.group(1) if rc == 0 and match else None

    def root_pids(self) -> list[int]:
        """Root process(es) of the disposable browser (its profile, its port)."""
        profile = str(self.browser.PROFILE_DIR)
        return [
            pid
            for pid in self.browser._find_root_pids(self.port)  # pylint: disable=protected-access
            if profile in (self.browser._proc_command(pid) or "")  # pylint: disable=protected-access
        ]


def launch(gate: Gate) -> int | None:
    """Launch the disposable HEADED browser in-process; its root pid or None."""
    gate.ws_url = None
    rc = gate.browser._launch_and_record(gate.port, False)  # pylint: disable=protected-access
    if rc != 0:
        return None
    pids = gate.root_pids()
    return pids[0] if pids else None


def teardown(gate: Gate) -> bool:
    """``browser.py --cdp-port P down -f`` (same env); kill our roots if it fails."""
    if not gate.browser._is_up(gate.port) and not gate.root_pids():  # pylint: disable=protected-access
        return True
    try:
        subprocess.run(
            [
                sys.executable,
                str(BROWSER_PY),
                "--cdp-port",
                str(gate.port),
                "down",
                "-f",
            ],
            capture_output=True,
            text=True,
            timeout=90,
            check=False,
        )
    except subprocess.TimeoutExpired:
        pass
    for sig in (signal.SIGTERM, signal.SIGKILL):
        pids = gate.root_pids()  # only processes on OUR profile, never 9222/9223
        if not pids:
            break
        for pid in pids:
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.kill(pid, sig)
        time.sleep(3)
    gate.ws_url = None
    return not gate.root_pids()


def display_rects(fw: Any) -> list[tuple[float, float, float, float]]:
    """Every display in CG coordinates (NSScreen, via focus_watch's converter)."""
    appkit = importlib.import_module("AppKit")
    return list(fw.display_rects_cg(fw.ns_screen_frames(appkit)))


def _bounds_tuple(win: dict[str, Any] | None) -> tuple[int, int, int, int] | None:
    bounds = (win or {}).get("bounds") or {}
    try:
        return (
            int(bounds["left"]),
            int(bounds["top"]),
            int(bounds["width"]),
            int(bounds["height"]),
        )
    except (KeyError, TypeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# One variant
# ---------------------------------------------------------------------------


class Run:  # pylint: disable=too-many-instance-attributes
    """The samplers of one variant run and their aggregates (thread-safe)."""

    def __init__(self, gate: Gate, variant: Variant, samples_path: Path) -> None:
        self.gate = gate
        self.variant = variant
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.samples = samples_path.open("w", encoding="utf-8")
        self.check_tid = ""
        self.human_tid = ""
        self.evals: dict[str, Any] = {
            "n": 0,
            "slow": 0,
            "unanswered": 0,
            "not_visible": 0,
            "max_latency_s": 0.0,
            "first_unanswered": None,
        }
        self.page_events: set[tuple[Any, ...]] = set()
        self.human: dict[str, Any] = {
            "n": 0,
            "not_visible": 0,
            "raf_stalls": 0,
            "no_focus": 0,
            "unanswered": 0,
        }
        self._last_raf: int | None = None
        self.check_windows: set[Any] = set()
        self.check_bounds: set[tuple[int, int, int, int] | None] = set()
        self.human_windows: set[Any] = set()
        self.window_failures = 0
        self.connects: dict[str, Any] = {"n": 0, "failures": 0, "first_failure": None}
        self.churn = {
            "n": 0,
            "create_failures": 0,
            "unanswered": 0,
            "close_failures": 0,
        }
        self.typing = {"sent": 0, "failed": 0}

    def log(self, kind: str, **data: Any) -> None:
        """One raw sample line (evidence; $S/samples-<variant>.jsonl)."""
        line = json.dumps({"ts": now_iso(), "kind": kind, **data}, default=str)
        with self.lock:
            self.samples.write(line + "\n")

    # -- samplers --------------------------------------------------------
    def sample_check(self) -> None:
        """Runtime.evaluate on the long-lived check tab (5 s budget)."""
        status, val, took = self.gate.evaluate(self.check_tid, PAGE_EXPR, EVAL_BUDGET_S)
        val = val if isinstance(val, dict) else {}
        with self.lock:
            ev = self.evals
            ev["n"] += 1
            ev["max_latency_s"] = max(ev["max_latency_s"], round(took, 3))
            if status != "ok" or took >= EVAL_BUDGET_S:
                ev["unanswered"] += 1
                ev["first_unanswered"] = ev["first_unanswered"] or now_iso()
            else:
                if took >= EVAL_PASS_S:
                    ev["slow"] += 1
                if val.get("v") != "visible":
                    ev["not_visible"] += 1
                for item in val.get("ev") or []:
                    if isinstance(item, list):
                        self.page_events.add(tuple(item))
        self.log(
            "eval",
            status=status,
            took=round(took, 3),
            v=val.get("v"),
            f=val.get("f"),
            r=val.get("r"),
        )

    def sample_windows(self) -> None:
        """getWindowForTarget for both tabs + the human tab's state."""
        cwin = self.gate.window_for(self.check_tid)
        hwin = self.gate.window_for(self.human_tid)
        status, val, took = self.gate.evaluate(self.human_tid, PAGE_EXPR, 2.0)
        val = val if isinstance(val, dict) else {}
        with self.lock:
            if cwin is None or hwin is None:
                self.window_failures += 1
            if cwin is not None:
                self.check_windows.add(cwin.get("windowId"))
                self.check_bounds.add(_bounds_tuple(cwin))
            if hwin is not None:
                self.human_windows.add(hwin.get("windowId"))
            hum = self.human
            hum["n"] += 1
            if status != "ok":
                hum["unanswered"] += 1
            else:
                raf = int(val.get("r") or 0)
                if val.get("v") != "visible":
                    hum["not_visible"] += 1
                if not val.get("f"):
                    hum["no_focus"] += 1
                if self._last_raf is not None and raf <= self._last_raf:
                    hum["raf_stalls"] += 1
                self._last_raf = raf
        self.log(
            "windows",
            check=cwin,
            human=hwin,
            human_status=status,
            human_took=round(took, 3),
            v=val.get("v"),
            f=val.get("f"),
            r=val.get("r"),
        )

    def churn_once(self) -> None:
        """A fresh check tab (the variant's payload): create, evaluate, close."""
        tid = self.gate.create(CHECK_URL, self.variant.params)
        status, took, closed = "no-tab", 0.0, False
        if tid is not None:
            status, _val, took = self.gate.evaluate(tid, PAGE_EXPR, EVAL_BUDGET_S)
            closed = self.gate.close(tid)
        with self.lock:
            self.churn["n"] += 1
            if tid is None:
                self.churn["create_failures"] += 1
            elif status != "ok":
                self.churn["unanswered"] += 1
            if tid is not None and not closed:
                self.churn["close_failures"] += 1
        self.log(
            "churn",
            created=tid is not None,
            status=status,
            took=round(took, 3),
            closed=closed,
        )

    def connect_loop(self) -> None:
        """A real Playwright connect_over_cdp + close every 5 s (own thread)."""
        from playwright.sync_api import (  # pylint: disable=import-outside-toplevel
            sync_playwright,
        )

        endpoint = f"http://127.0.0.1:{self.gate.port}"
        timeout_ms = float(self.gate.browser.CONNECT_TIMEOUT_S) * 1000
        with sync_playwright() as pw:

            def once() -> None:
                start = time.monotonic()
                error = None
                try:
                    brw = pw.chromium.connect_over_cdp(endpoint, timeout=timeout_ms)
                    brw.close()
                except Exception as exc:  # pylint: disable=broad-exception-caught
                    error = f"{type(exc).__name__}: {str(exc).splitlines()[0][:160]}"
                with self.lock:
                    self.connects["n"] += 1
                    if error is not None:
                        self.connects["failures"] += 1
                        self.connects["first_failure"] = (
                            self.connects["first_failure"] or error
                        )
                self.log(
                    "connect",
                    ok=error is None,
                    took=round(time.monotonic() - start, 3),
                    error=error,
                )

            _every(CONNECT_S, self.stop, once)

    def idle_loop(self) -> None:
        """The idle guard: every 30 s; activity sets the gate's abort."""

        def once() -> None:
            active, idle = self.gate.user_active_now()
            self.log("idle", idle_s=idle, active=active)
            if active and not self.gate.abort.is_set():
                self.gate.abort_reason = ABORT_USER_ACTIVE
                self.gate.abort.set()

        self.stop.wait(IDLE_CHECK_S)
        _every(IDLE_CHECK_S, self.stop, once)

    def type_loop(self) -> None:
        """0c: one character into the human textarea every 200 ms."""

        def once() -> None:
            res = self.gate.page_call(
                self.human_tid, "Input.insertText", {"text": "a"}, 2.0
            )
            with self.lock:
                if res.status == "ok" and not res.error:
                    self.typing["sent"] += 1
                else:
                    self.typing["failed"] += 1

        _every(TYPE_S, self.stop, once)

    # -- aggregation -----------------------------------------------------
    def aggregate(self) -> dict[str, Any]:
        """The run's numbers as JSON-ready dicts."""
        with self.lock:
            kinds = [e[0] for e in self.page_events if e]
            expect = self.variant.expect_bounds
            bounds = sorted((b for b in self.check_bounds if b), key=str)
            return {
                "evals": dict(self.evals),
                "page_events": {
                    "freeze": kinds.count("freeze"),
                    "resume": kinds.count("resume"),
                    "visibilitychange": kinds.count("visibilitychange"),
                    "log": sorted(self.page_events, key=lambda e: e[-1])[:50],
                },
                "human": dict(self.human),
                "windows": {
                    "check_ids": sorted(self.check_windows, key=str),
                    "check_bounds": [list(b) for b in bounds],
                    "bounds_exact": (
                        None
                        if expect is None
                        else bool(self.check_bounds) and self.check_bounds == {expect}
                    ),
                    "human_ids": sorted(self.human_windows, key=str),
                    "failures": self.window_failures,
                },
                "connects": dict(self.connects),
                "churn": dict(self.churn),
            }


def _start(fn: Callable[[], None], name: str) -> threading.Thread:
    thread = threading.Thread(target=fn, name=name, daemon=True)
    thread.start()
    return thread


def _setup_human(gate: Gate, run: Run) -> int | None:
    """Navigate the first tab to the human page; its windowId (``H``)."""
    deadline = time.monotonic() + 15
    pages: list[dict[str, Any]] = []
    while time.monotonic() < deadline and not pages:
        pages = gate.browser._page_targets(gate.port)  # pylint: disable=protected-access
        if not pages:
            time.sleep(0.25)
    if not pages:
        return None
    run.human_tid = str(pages[0].get("id"))
    gate.page_call(run.human_tid, "Page.navigate", {"url": HUMAN_URL})
    time.sleep(2)
    win = gate.window_for(run.human_tid)
    return (win or {}).get("windowId")


def _doctor_start(gate: Gate, log_path: Path) -> subprocess.Popen[bytes]:
    with log_path.open("wb") as out:
        return subprocess.Popen(  # pylint: disable=consider-using-with
            [sys.executable, str(BROWSER_PY), "--cdp-port", str(gate.port), "doctor"],
            stdout=out,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )


def _doctor_finish(
    proc: subprocess.Popen[bytes] | None, log_path: Path
) -> dict[str, Any]:
    if proc is None:
        return {"rc": None, "note": "not started"}
    try:
        rc: int | None = proc.wait(timeout=DOCTOR_WAIT_S)
    except subprocess.TimeoutExpired:
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.killpg(proc.pid, signal.SIGKILL)
        proc.wait(timeout=10)
        rc = None
    tail = log_path.read_text(encoding="utf-8", errors="replace").splitlines()[-15:]
    return {"rc": rc, "timed_out": rc is None, "log": str(log_path), "tail": tail}


def _steady(
    gate: Gate, run: Run, duration_s: float, res: dict[str, Any], seg_start: str
) -> None:
    """The steady measurement period (from the check tab's creation, `seg_start`):
    samplers + doctor at half time."""
    threads = [
        _start(lambda: _every(SAMPLE_S, run.stop, run.sample_check), "eval"),
        _start(lambda: _every(SAMPLE_S, run.stop, run.sample_windows), "windows"),
        _start(lambda: _every(CHURN_S, run.stop, run.churn_once), "churn"),
        _start(run.connect_loop, "connect"),
        _start(run.idle_loop, "idle"),
    ]
    if run.variant.with_0c:
        threads.append(_start(run.type_loop, "type"))
    doctor_log = gate.state_dir / f"doctor-{run.variant.name}.log"
    doctor: subprocess.Popen[bytes] | None = None
    start = time.monotonic()
    end = start + duration_s
    last_up = start
    while time.monotonic() < end and not gate.abort.is_set():
        now = time.monotonic()
        if doctor is None and not run.variant.with_0c and now >= start + duration_s / 2:
            doctor = _doctor_start(gate, doctor_log)
        if now - last_up >= 5:
            last_up = now
            if not gate.browser._is_up(gate.port):  # pylint: disable=protected-access
                gate.abort_reason = "error: disposable browser died"
                gate.abort.set()
        gate.abort.wait(1.0)
    run.stop.set()
    hung = []
    join_s = float(gate.browser.CONNECT_TIMEOUT_S) + 15
    for thread in threads:
        thread.join(timeout=join_s)
        if thread.is_alive():
            hung.append(thread.name)
    if "connect" in hung:
        with run.lock:
            run.connects["failures"] += 1
            run.connects["first_failure"] = (
                run.connects["first_failure"] or "hung at stop"
            )
    res["hung_threads"] = hung
    res["segments"]["steady"] = [seg_start, now_iso()]
    if not run.variant.with_0c:
        res["doctor"] = _doctor_finish(doctor, doctor_log)


def _guard(gate: Gate) -> bool:
    """True when the run may go on (idle, not aborted)."""
    if gate.abort.is_set():
        return False
    active, _idle = gate.user_active_now()
    if active:
        gate.abort_reason = ABORT_USER_ACTIVE
        gate.abort.set()
    return not active


def _case_new_tab_in_h(gate: Gate, human_window: int) -> dict[str, Any]:
    tid = gate.open_new_raw(CASE_URL)
    win = gate.window_for(tid) if tid else None
    got = (win or {}).get("windowId")
    if tid:
        gate.close(tid)
    return {
        "created": tid is not None,
        "window": got,
        "H": human_window,
        "ok": got == human_window,
    }


def _cases(gate: Gate, run: Run, human_window: int, res: dict[str, Any]) -> None:
    """Cases i, iv, ii, iii (iii destroys H, so it comes last)."""
    cases: dict[str, Any] = {}
    res["cases"] = cases
    segs = res["segments"]
    if not _guard(gate):
        return
    seg = now_iso()
    cases["i"] = _case_new_tab_in_h(gate, human_window)
    segs["case_i"] = [seg, now_iso()]
    if not _guard(gate):
        return
    seg = now_iso()
    cases["iv"] = _case_popup(gate, run)
    segs["case_iv_popup"] = [seg, now_iso()]
    if not _guard(gate):
        return
    seg = now_iso()
    mini = gate.browser_call(
        "Browser.setWindowBounds",
        {"windowId": human_window, "bounds": {"windowState": "minimized"}},
    )
    time.sleep(1.5)
    cases["ii"] = {
        "minimized": mini.status == "ok" and not mini.error,
        **_case_new_tab_in_h(gate, human_window),
    }
    segs["case_ii"] = [seg, now_iso()]
    if not _guard(gate):
        return
    seg = now_iso()
    cases["iii"] = _case_close_h(gate, run, human_window)
    segs["case_iii"] = [seg, now_iso()]


def _case_popup(gate: Gate, run: Run) -> dict[str, Any]:
    """(iv) the check tab opens a popup; where does it land?"""
    status, val, _took = gate.evaluate(run.check_tid, POPUP_EXPR, 5.0, gesture=True)
    popup = None
    deadline = time.monotonic() + 5
    while popup is None and time.monotonic() < deadline:
        targets = (gate.browser_call("Target.getTargets").result or {}).get(
            "targetInfos"
        ) or []
        popup = next(
            (
                t
                for t in targets
                if t.get("openerId") == run.check_tid and t.get("type") == "page"
            ),
            None,
        )
        if popup is None:
            time.sleep(0.25)
    out: dict[str, Any] = {
        "opened": status == "ok" and bool(val),
        "found": popup is not None,
    }
    if popup is not None:
        tid = str(popup.get("targetId"))
        time.sleep(1)
        win = gate.window_for(tid)
        bounds = _bounds_tuple(win)
        out["window"] = (win or {}).get("windowId")
        out["bounds"] = list(bounds) if bounds else None
        out["on_display"] = (
            gate.fw.on_any_display(bounds, display_rects(gate.fw)) if bounds else None
        )
        out["closed"] = gate.close(tid)
    return out


def _case_close_h(gate: Gate, run: Run, human_window: int) -> dict[str, Any]:
    """(iii) close every tab in H, then `open -N`: record where it lands."""
    closed = 0
    for page in gate.browser._page_targets(gate.port):  # pylint: disable=protected-access
        tid = str(page.get("id"))
        if (gate.window_for(tid) or {}).get("windowId") == human_window:
            closed += gate.close(tid)
    time.sleep(1.5)
    tid = gate.open_new_raw(CASE_URL)
    win = gate.window_for(tid) if tid else None
    bounds = _bounds_tuple(win)
    got = (win or {}).get("windowId")
    check_win = (gate.window_for(run.check_tid) or {}).get("windowId")
    return {
        "closed_in_H": closed,
        "created": tid is not None,
        "window": got,
        "bounds": list(bounds) if bounds else None,
        "landed": (
            "H"
            if got == human_window
            else "check window"
            if got is not None and got == check_win
            else "other window"
            if got is not None
            else "unknown"
        ),
        "on_display": (
            gate.fw.on_any_display(bounds, display_rects(gate.fw)) if bounds else None
        ),
    }


def _activate(pid: int) -> dict[str, Any]:
    """0c: activate the DISPOSABLE browser by pid (never another app)."""
    appkit = importlib.import_module("AppKit")
    before = frontmost_pid()
    app = appkit.NSRunningApplication.runningApplicationWithProcessIdentifier_(pid)
    called = False
    if app is not None:
        called = bool(
            app.activateWithOptions_(
                getattr(appkit, "NSApplicationActivateAllWindows", 1)
                | getattr(appkit, "NSApplicationActivateIgnoringOtherApps", 2)
            )
        )
    time.sleep(1.5)
    after = frontmost_pid()
    return {"previous_pid": before, "called": called, "frontmost": after == pid}


def _restore_front(pid: int | None) -> None:
    if not pid:
        return
    appkit = importlib.import_module("AppKit")
    app = appkit.NSRunningApplication.runningApplicationWithProcessIdentifier_(pid)
    if app is not None:
        app.activateWithOptions_(getattr(appkit, "NSApplicationActivateAllWindows", 1))


def _cmd_backtick(gate: Gate, run: Run, pid: int) -> dict[str, Any]:
    """0c: Cmd-` posted to the disposable pid only, then who has focus."""
    if frontmost_pid() != pid:
        return {"posted": False, "note": "disposable not frontmost; Cmd-` skipped"}
    quartz = importlib.import_module("Quartz")
    for down in (True, False):
        event = quartz.CGEventCreateKeyboardEvent(None, KVK_ANSI_GRAVE, down)
        quartz.CGEventSetFlags(event, quartz.kCGEventFlagMaskCommand)
        quartz.CGEventPostToPid(pid, event)
    gate.last_synthetic = time.monotonic()
    time.sleep(1.5)
    _s1, check, _t1 = gate.evaluate(run.check_tid, PAGE_EXPR, 2.0)
    _s2, human, _t2 = gate.evaluate(run.human_tid, PAGE_EXPR, 2.0)
    return {
        "posted": True,
        "check_has_focus": (check or {}).get("f") if isinstance(check, dict) else None,
        "human_has_focus": (human or {}).get("f") if isinstance(human, dict) else None,
    }


def _run_0c_extras(gate: Gate, run: Run, pid: int, res: dict[str, Any]) -> None:
    status, length, _took = gate.evaluate(
        run.human_tid, "document.getElementById('t').value.length", 3.0
    )
    with run.lock:
        sent = run.typing["sent"]
    res["typing"] = {
        **run.typing,
        "textarea_length": length if status == "ok" else None,
        "lost": (sent - int(length)) if status == "ok" and length is not None else None,
    }
    if _guard(gate):
        seg = now_iso()
        res["cmd_backtick"] = _cmd_backtick(gate, run, pid)
        res["segments"]["cmd_backtick"] = [seg, now_iso()]


def _fw_analysis(gate: Gate, pid: int | None, res: dict[str, Any]) -> None:
    time.sleep(FW_FLUSH_S)
    try:
        records, _bad, _files = gate.fw.read_log_chain(gate.fw_log)
    except OSError:
        records = []
    recorded = any(r.get("event") == "start" for r in records)
    stats: dict[str, Any] = {"recorded": recorded, "log": str(gate.fw_log)}
    for name, (start, end) in res.get("segments", {}).items():
        stats[name] = fw_segment_stats(
            gate.fw, records, {pid} if pid else set(), start, end
        )
    res["fw"] = stats


def run_variant(gate: Gate, variant: Variant, duration_s: float) -> dict[str, Any]:
    """Launch, measure, tear down; the variant's result dict."""
    gate.abort.clear()
    gate.abort_reason = ""
    res: dict[str, Any] = {
        "status": "running",
        "variant": variant.name,
        "note": variant.note,
        "payload": {"url": "<check data: page>", **variant.params},
        "duration_s": duration_s,
        "started": now_iso(),
        "segments": {},
    }
    run = Run(gate, variant, gate.state_dir / f"samples-{variant.name}.jsonl")
    pid: int | None = None
    previous_front: int | None = None
    try:
        pid = launch(gate)
        if pid is None:
            res.update(status="error", reason="disposable browser did not launch")
            return res
        res["chrome_pid"] = pid
        human_window = _setup_human(gate, run)
        res["human_window"] = human_window
        # The steady segment starts BEFORE the check tab exists: a check window
        # that lands on a display must be counted, never hidden in "setup".
        steady_start = now_iso()
        res["segments"]["setup"] = [res["started"], steady_start]
        tid = gate.create(CHECK_URL, variant.params)
        if human_window is None or tid is None:
            res.update(status="error", reason="human tab or check tab not created")
            return res
        run.check_tid = tid
        if variant.with_0c:
            res["activation"] = _activate(pid)
            previous_front = res["activation"].get("previous_pid")
            gate.page_call(
                run.human_tid,
                "Runtime.evaluate",
                {"expression": "document.getElementById('t').focus()"},
            )
        _steady(gate, run, duration_s, res, steady_start)
        if not gate.abort.is_set():
            if variant.with_0c:
                _run_0c_extras(gate, run, pid, res)
            else:
                _cases(gate, run, human_window, res)
        res.update(run.aggregate())
    finally:
        run.samples.close()
        res["torn_down"] = teardown(gate)
        if previous_front and previous_front != pid:
            _restore_front(previous_front)
        res["ended"] = now_iso()
    if gate.abort.is_set():
        res["status"] = "aborted" if gate.abort_reason == ABORT_USER_ACTIVE else "error"
        res["reason"] = gate.abort_reason
        return res
    _fw_analysis(gate, pid, res)
    res["status"] = "done"
    res["reproduced"], res["reproduced_by"] = reproduced(res)
    res["pass"], res["fail_reasons"] = variant_pass(res, variant)
    return res


# ---------------------------------------------------------------------------
# focus_watch
# ---------------------------------------------------------------------------


def start_focus_watch(gate: Gate, duration_s: float) -> subprocess.Popen[bytes] | None:
    """`focus_watch.py -l $S/fw-step0.jsonl -d …`; None if it never logged a start."""
    before = gate.fw_log.stat().st_size if gate.fw_log.exists() else 0
    out = (gate.state_dir / "fw-step0.out.log").open("ab")
    proc = subprocess.Popen(  # pylint: disable=consider-using-with
        [
            sys.executable,
            str(FOCUS_WATCH_PY),
            "-l",
            str(gate.fw_log),
            "-d",
            f"{duration_s:.0f}",
        ],
        stdout=out,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    out.close()
    deadline = time.monotonic() + FW_START_WAIT_S
    while time.monotonic() < deadline and proc.poll() is None:
        if gate.fw_log.exists() and gate.fw_log.stat().st_size > before:
            time.sleep(1)  # baseline written; let the first polls settle
            return proc
        time.sleep(0.25)
    stop_focus_watch(proc)
    return None


def stop_focus_watch(proc: subprocess.Popen[bytes] | None) -> None:
    """SIGTERM (focus_watch writes its stop record), then SIGKILL."""
    if proc is None or proc.poll() is not None:
        return
    with contextlib.suppress(ProcessLookupError):
        proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        with contextlib.suppress(ProcessLookupError):
            proc.kill()
        proc.wait(timeout=5)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _port(text: str) -> int:
    value = int(text)
    if value in RESERVED_PORTS:
        raise argparse.ArgumentTypeError(
            f"{value} is the shared browser's port; use a disposable one (default "
            f"{DEFAULT_PORT})"
        )
    if not 1024 <= value <= 65535:
        raise argparse.ArgumentTypeError(f"port out of range: {text}")
    return value


def _duration(text: str) -> float:
    value = float(text)
    if value < 10:
        raise argparse.ArgumentTypeError(f"must be >= 10 s, got {text}")
    return value


def build_parser() -> argparse.ArgumentParser:
    """The argument parser."""
    parser = argparse.ArgumentParser(
        prog="tp871_gate.py",
        description=(
            "tp#871 Step 0 measurement gate: does a headed check tab freeze, and "
            "does an off-screen window fix it without showing anything? Puts a "
            "HEADED disposable Chrome window on the screen — runs only while the Mac "
            f"is idle (HIDIdleTime >= {IDLE_MIN_S:.0f} s)."
        ),
        epilog=(
            "examples:\n"
            "  tp871_gate.py -n              plan of runs + prerequisites, launch nothing\n"
            "  tp871_gate.py                 run the remaining variants\n"
            "  tp871_gate.py -c              … plus 0c (activates the disposable!)\n"
            "  tp871_gate.py -d 60 -S /tmp/g short smoke run, own state dir\n"
            "\nexit: 0 planned variants done (verdict written), 1 error, 2 usage, "
            f"{EXIT_ABORTED} aborted: user active (re-run later to resume)"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-S",
        "--state-dir",
        type=Path,
        default=DEFAULT_STATE,
        help=f"state dir: {GATE_JSON}, {FW_LOG}, cache/, samples (default: "
        f"{DEFAULT_STATE})",
    )
    parser.add_argument(
        "-p",
        "--port",
        type=_port,
        default=DEFAULT_PORT,
        help=f"CDP port of the disposable browser (default {DEFAULT_PORT}; "
        "9222/9223 refused)",
    )
    parser.add_argument(
        "-d",
        "--duration",
        type=_duration,
        default=DEFAULT_DURATION_S,
        metavar="SECONDS",
        help=f"length of V0/V1/V2 (default {DEFAULT_DURATION_S:.0f}); V3 and 0c "
        f"run min(this, {SHORT_VARIANT_S:.0f})",
    )
    parser.add_argument(
        "-c",
        "--with-0c",
        action="store_true",
        help="also run 0c: activate the disposable by pid, type into the human "
        "tab, Cmd-` (TAKES DESKTOP FOCUS — only while Albert is away)",
    )
    parser.add_argument(
        "-n",
        "--dry-run",
        action="store_true",
        help="print the plan of runs and check prerequisites; launch nothing",
    )
    return parser


def bootstrap_venv() -> None:
    """Run under the repo .venv (playwright, websockets, pyobjc)."""
    sys.path.insert(0, str(REPO_ROOT))
    from pyvenv_bootstrap import (  # pylint: disable=import-outside-toplevel
        ensure_venv,
    )

    ensure_venv(__file__, requires=GATE_REQUIRES)


def configure_env(state_dir: Path, port: int) -> None:
    """The disposable instance's env — BEFORE bin/browser.py is imported."""
    os.environ["CLAUDE_BROWSER_CACHE_DIR"] = str(state_dir / "cache")
    os.environ["CLAUDE_BROWSER_CDP_PORT"] = str(port)
    for name in (
        "CLAUDE_BROWSER_TEST_NO_LAUNCH",
        "CLAUDE_BROWSER_INSTANCE",
        "CLAUDE_BROWSER_OPEN_LAUNCH",
        "CLAUDE_BROWSER_MAINTENANCE",
    ):
        os.environ.pop(name, None)


def _plan_table(data: dict[str, Any], args: argparse.Namespace) -> tuple[str, float]:
    results = data["results"]
    pending = {v.name for v in pending_variants(results, args.with_0c)}
    rows = []
    total = 0.0
    for variant in planned_variants(args.with_0c):
        dur = variant_duration(variant, args.duration)
        if variant.name in pending:
            status = "pending"
            total += dur
        elif is_done(results, variant.name):
            status = "done (skipped)"
        else:
            status = "not run: V0 did not reproduce"
        payload = json.dumps(variant.params, separators=(",", ":"))
        rows.append([variant.name, f"{dur:.0f} s", status, payload])
    header = ["variant", "duration", "status", "createTarget params (+url)"]
    widths = [max(len(r[i]) for r in [header, *rows]) for i in range(len(header))]
    lines = ["| " + " | ".join(h.ljust(w) for h, w in zip(header, widths)) + " |"]
    lines.append("| " + " | ".join(":" + "-" * (w - 1) for w in widths) + " |")
    lines += [
        "| " + " | ".join(c.ljust(w) for c, w in zip(r, widths)) + " |" for r in rows
    ]
    return "\n".join(lines), total


def prerequisites(gate: Gate, args: argparse.Namespace) -> list[tuple[bool, str]]:
    """(ok, message) per prerequisite of a real run; idle is reported separately."""
    checks: list[tuple[bool, str]] = []
    cache = Path(os.environ["CLAUDE_BROWSER_CACHE_DIR"])
    checks.append(
        (
            not is_live_cache(cache),
            f"disposable cache dir {path_link(cache)} (not the live ~/.cache/claude-browser*)",
        )
    )
    checks.append(
        (args.port not in RESERVED_PORTS, f"port {args.port} is not 9222/9223")
    )
    busy = port_listening(args.port)
    roots = gate.root_pids()
    if busy and roots:
        port_state = f"is held by a leftover disposable browser (pid {roots[0]}; "
        port_state += "the run tears it down first)"
    else:
        port_state = "is in use by something else" if busy else "is free"
    checks.append((not busy or bool(roots), f"127.0.0.1:{args.port} {port_state}"))
    try:
        binary = gate.browser._chromium_binary()  # pylint: disable=protected-access
        checks.append((True, f"Chrome for Testing: {binary}"))
    except SystemExit as exc:
        checks.append((False, f"Chrome for Testing missing: {exc}"))
    for mod in GATE_REQUIRES:
        try:
            importlib.import_module(mod)
            checks.append((True, f"module {mod} importable"))
        except ImportError as exc:
            checks.append((False, f"module {mod} not importable: {exc}"))
    checks.append(
        (FOCUS_WATCH_PY.exists(), f"focus_watch: {path_link(FOCUS_WATCH_PY)}")
    )
    try:
        rects = display_rects(gate.fw)
        checks.append((bool(rects), f"{len(rects)} display(s) readable via NSScreen"))
    except Exception as exc:  # pylint: disable=broad-exception-caught
        checks.append((False, f"NSScreen displays unreadable: {exc}"))
    idle = idle_seconds()
    checks.append(
        (
            idle is not None,
            f"ioreg HIDIdleTime readable ({idle if idle is None else round(idle)} s)",
        )
    )
    try:
        args.state_dir.mkdir(parents=True, exist_ok=True)
        writable = os.access(args.state_dir, os.W_OK)
    except OSError:
        writable = False
    checks.append((writable, f"state dir writable: {path_link(args.state_dir)}"))
    return checks


def cmd_dry_run(gate: Gate, data: dict[str, Any], args: argparse.Namespace) -> int:
    """`-n`: the plan of runs and the prerequisites; launches nothing."""
    say("tp871 gate — dry run (nothing launched)")
    say(f"State: {path_link(args.state_dir / GATE_JSON)}")
    say(f"focus_watch log: {path_link(gate.fw_log)}")
    say(
        f"Disposable browser: port {args.port}, cache {path_link(args.state_dir / 'cache')}"
    )
    say("")
    table, total = _plan_table(data, args)
    say(table)
    say("")
    if control_not_reproduced(data["results"]):
        say("V0 completed without reproducing the freeze: the gate stops there.")
    say(
        f"Headed window on screen: ~{total / 60:.0f} min in total, only while idle "
        f">= {IDLE_MIN_S:.0f} s (checked before each variant and every "
        f"{IDLE_CHECK_S:.0f} s)."
    )
    if not args.with_0c:
        say(
            "0c skipped (-c not given): V2 cannot be chosen; V1 would need Albert's OK."
        )
    say("")
    checks = prerequisites(gate, args)
    for ok, msg in checks:
        say(f"{'✅' if ok else '❌'} {msg}")
    active, idle = gate.user_active_now()
    idle_txt = "unknown" if idle is None else f"{idle:.0f} s"
    say(
        f"{'⚠' if active else '✅'} idle now {idle_txt} — a real run would "
        + ("abort now (re-run when away)" if active else "start")
    )
    return 0 if all(ok for ok, _msg in checks) else EXIT_FAIL


def _print_verdict(verdict: dict[str, Any], path: Path) -> None:
    say("")
    say(f"Verdict ({verdict.get('state')}): choice = {verdict.get('choice')}")
    say(f"  {verdict.get('note', '')}")
    if verdict.get("smoke"):
        say(
            "  ⚠ shorter than the plan's durations: a smoke run, not the verdict of record"
        )
    say(f"✅ written: {path_link(path)}")


def _report_variant(res: dict[str, Any]) -> None:
    name = res.get("variant")
    if res.get("status") != "done":
        say(f"❌ {name}: {res.get('status')} — {res.get('reason')}")
        return
    rep = "reproduced" if res.get("reproduced") else "not reproduced"
    verdict = res.get("pass")
    mark = "❌" if verdict is False else "✅"
    detail = "; ".join(res.get("fail_reasons") or res.get("reproduced_by") or []) or "-"
    say(f"{mark} {name}: done, freeze {rep}, pass={verdict} ({detail})")


def cmd_run(gate: Gate, data: dict[str, Any], args: argparse.Namespace) -> int:
    """Run the pending variants; save after each; the 0d verdict at the end."""
    json_path = args.state_dir / GATE_JSON
    results: dict[str, Any] = data["results"]
    data.update(
        tp=871, port=args.port, state_dir=str(args.state_dir), fw_log=str(gate.fw_log)
    )
    todo = pending_variants(results, args.with_0c)
    code = _run_preflight(gate, data, args, todo) if todo else 0
    if todo and code is None:
        code = _run_variants(gate, data, args, todo)
    data["verdict"] = overall_verdict(results, args.with_0c)
    write_state(json_path, data)
    _print_verdict(data["verdict"], json_path)
    return int(code or 0)


def _run_preflight(
    gate: Gate, data: dict[str, Any], args: argparse.Namespace, todo: list[Variant]
) -> int | None:
    """Before anything launches: idle, leftovers, a free port; None = go."""
    json_path = args.state_dir / GATE_JSON
    active, idle = gate.user_active_now()
    if active:
        say(
            f"❌ {ABORT_USER_ACTIVE} (idle {idle} s < {IDLE_MIN_S:.0f} s); nothing launched"
        )
        data.setdefault("aborts", []).append(
            {"at": now_iso(), "idle_s": idle, "before": todo[0].name}
        )
        write_state(json_path, data)
        return EXIT_ABORTED
    if gate.root_pids() and not teardown(gate):
        say("❌ a leftover disposable browser could not be stopped")
        return EXIT_FAIL
    if port_listening(args.port):
        say(f"❌ 127.0.0.1:{args.port} is in use by something else")
        return EXIT_FAIL
    return None


def _run_variants(
    gate: Gate, data: dict[str, Any], args: argparse.Namespace, todo: list[Variant]
) -> int:
    """focus_watch around the pending variants; each saved as soon as it ends."""
    json_path = args.state_dir / GATE_JSON
    results: dict[str, Any] = data["results"]
    fw_total = sum(variant_duration(v, args.duration) for v in todo) + 900 * len(todo)
    # SIGTERM tears the disposable browser down too (the finally below).
    signal.signal(signal.SIGTERM, lambda _sig, _frm: sys.exit(128 + signal.SIGTERM))
    fw_proc = start_focus_watch(gate, max(7200.0, fw_total))
    if fw_proc is None:
        out_log = path_link(args.state_dir / "fw-step0.out.log")
        say(f"❌ focus_watch did not start; see {out_log}")
        return EXIT_FAIL
    say(f"✅ focus_watch running (pid {fw_proc.pid}) → {path_link(gate.fw_log)}")
    code = 0
    try:
        for variant in todo:
            if variant.name != "V0" and control_not_reproduced(results):
                break
            if not _guard(gate):
                results[variant.name] = {
                    "status": "aborted",
                    "variant": variant.name,
                    "reason": ABORT_USER_ACTIVE,
                    "at": now_iso(),
                }
                write_state(json_path, data)
                say(f"❌ {variant.name}: {ABORT_USER_ACTIVE} — re-run later to resume")
                code = EXIT_ABORTED
                break
            dur = variant_duration(variant, args.duration)
            say(f"▶ {variant.name} ({variant.note}), {dur:.0f} s …")
            res = run_variant(gate, variant, dur)
            results[variant.name] = res
            write_state(json_path, data)
            _report_variant(res)
            if res["status"] == "aborted":
                say("   re-run later to resume the remaining variants")
                code = EXIT_ABORTED
                break
            if res["status"] != "done":
                code = EXIT_FAIL
                break
    finally:
        stop_focus_watch(fw_proc)
        if gate.root_pids():
            teardown(gate)
    return code


def main(argv: list[str] | None = None) -> int:
    """Entry point."""
    args = build_parser().parse_args(argv)  # -h and usage errors need no venv
    if sys.platform != "darwin":
        say("❌ tp871_gate.py only runs on macOS")
        return EXIT_FAIL
    args.state_dir = args.state_dir.expanduser().absolute()
    if is_live_cache(args.state_dir / "cache"):
        say(
            f"❌ {args.state_dir / 'cache'} is the live browser's cache; pick another -S"
        )
        return EXIT_USAGE
    bootstrap_venv()  # may re-exec under <repo>/.venv
    configure_env(args.state_dir, args.port)
    browser = load_module("browser", BROWSER_PY)
    fw = load_module("focus_watch", FOCUS_WATCH_PY)
    gate = Gate(
        port=args.port,
        state_dir=args.state_dir,
        browser=browser,
        fw=fw,
        fw_log=args.state_dir / FW_LOG,
    )
    data = read_state(args.state_dir / GATE_JSON)
    if args.dry_run:
        return cmd_dry_run(gate, data, args)
    args.state_dir.mkdir(parents=True, exist_ok=True)
    return cmd_run(gate, data, args)


if __name__ == "__main__":
    sys.exit(main())
