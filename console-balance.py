#!/usr/bin/env python3
"""console-balance.py — read the Claude Console's credit balance and spend limit.

For each Console account (work: the shared Chromium; private: the private
browser instance, started headless for the run and stopped again), one fresh
tab of its own loads https://platform.claude.com/settings/spend-limits and,
from that page, reads what the billing and spend-limit pages render:

* every promotional-credit row (remaining, granted, expires, granted on) and
  the purchased credit balance (the page's own ``prepaid/credits`` data);
* the organisation's monthly spend limit: spent this month, the limit, when it
  resets (the page's "Organization limit" block, cross-checked with its data);
* the one-time Claude Code cloud-session credit from claude.ai (tp#1429): a second
  fresh tab on claude.ai reads ``/v1/code/promo/cloud_credit`` (state, expiry) and
  the org's ``/usage`` meter that ends at the same minute → ``cloud_credit``
  (``remaining_usd``, ``granted_usd``, ``expires_at``, ``measured_at``), ``null``
  when the account has none. A failed claude.ai read never fails the Console
  reading: the last good ``cloud_credit`` stays, ``cloud_error`` says why.

Read-only: GET requests from the page only — it never clicks buy, adjust,
auto-reload or notification controls. Each account's result goes to one JSON
file (0600, written atomically) that ccc reads as ``balance_json:<path>``
(its schema 1). A failed run keeps the last good figures and their
``measured_at`` and sets a typed ``status``: ``logged_out``, ``wrong_account``,
``browser_down``, ``busy``, ``timeout`` or ``page_error``. Nothing is guessed.

A logged-out (or wrong-account) account is not re-tried for
BACKOFF_S unless -f is given, so a scheduled run does not start the private
browser every hour for a session only Albert can restore
(``./agent-login.py -g console-private``).

Exit: 0 every account read, 2 some account logged out / wrong account,
1 any other failure (browser, page, file).
"""

from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import json
import os
import re
import sys
import tempfile
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
# pylint: disable=wrong-import-position
from agent_login_claude import CONSOLE_ACCOUNTS, SITE_INSTANCE, instance_users  # noqa: E402
from agent_login_jobs import (  # noqa: E402
    BUSY_RC,
    _browser,
    browser_mode,
    browser_timeout,
    run_browser,
)

# pylint: enable=wrong-import-position

SCHEMA = 1
PAGE_URL = "https://platform.claude.com/settings/spend-limits"
# The claude.ai side: the one-time Claude Code cloud-session credit (tp#1429).
CLOUD_URL = "https://claude.ai/new"
# The credit's `expires_at` (promo endpoint) and its meter's `resets_at` (org usage
# endpoint) name the same minute; the meter is found by that, never by its
# obfuscated key (which the page renames between releases).
CLOUD_MATCH_S = 120
# account label (ccc's) → agent-login site
ACCOUNTS = {"work": "console", "private": "console-private"}
DEFAULT_DIR = Path(
    os.environ.get("CONSOLE_BALANCE_DIR")
    or Path.home() / ".local" / "state" / "console-balance"
)
# The Console SPA needs 30-40 s in the headless browser (measured 2026-10-29).
EVAL_S = 100
BACKOFF_S = 6 * 3600
UP_WAIT_S = 60.0
# `browser.py down` of a busy Mac can outlast agent-login's 60 s budget (2026-10-29).
DOWN_S = 240.0
LOGGED_OUT = frozenset({"logged_out", "wrong_account"})

# Runs in the fresh tab. Waits (≤ 30 s) for the page to name its organisation
# (an /api/organizations/<uuid>/ request) or to land on /login, then GETs the
# account, the prepaid credits and the spend figures from the same origin.
# Returns ONE JSON string with only the fields parsed below — no ids, cookies
# or tokens leave the page.
PAGE_JS = r"""(async () => {
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const orgOf = () => {
    for (const e of performance.getEntriesByType("resource")) {
      const m = e.name.match(/\/api\/organizations\/([0-9a-f-]{36})\//);
      if (m) return m[1];
    }
    return "";
  };
  let org = "";
  for (let i = 0; i < 60; i++) {
    if (location.pathname.startsWith("/login")) break;
    org = orgOf();
    if (org && document.body.innerText.includes("Organization limit")) break;
    await sleep(500);
  }
  const get = async (path) => {
    try {
      const r = await fetch(path, { credentials: "include" });
      if (!r.ok) return { status: r.status };
      return { status: r.status, body: await r.json() };
    } catch (err) { return { status: 0 }; }
  };
  const acct = await get("/api/account");
  if (acct.status === 401 || acct.status === 403 || location.pathname.startsWith("/login"))
    return JSON.stringify({ state: "logged_out" });
  if (acct.status !== 200 || !acct.body) return JSON.stringify({ state: "page_error", why: "account " + acct.status });
  const a = acct.body;
  if (!org) {
    const api = (a.memberships || []).filter((m) => m.organization &&
      (m.organization.capabilities || []).includes("api"));
    if (api.length === 1) org = api[0].organization.uuid;
  }
  if (!org) return JSON.stringify({ state: "page_error", why: "no organization" });
  const member = (a.memberships || []).find((m) => m.organization && m.organization.uuid === org);
  const base = "/api/organizations/" + org + "/";
  const credits = await get(base + "prepaid/credits");
  const spend = await get(base + "current_spend");
  const limits = await get(base + "spend_limits");
  const c = credits.body || {};
  const tranche = (t) => ({
    remaining_minor: t.remaining_amount_minor_units,
    granted_minor: t.granted_amount_minor_units,
    remaining_credit: t.remaining && t.remaining.credits,
    granted_credit: t.granted && t.granted.credits,
    currency: t.currency, expires_at: t.expires_at, granted_at: t.granted_at,
    name: t.name, program: t.program_id,
  });
  const text = document.body.innerText;
  const i = text.indexOf("Organization limit");
  return JSON.stringify({
    state: "ok",
    email: a.email_address || "",
    org_name: (member && member.organization && member.organization.name) || "",
    credits_status: credits.status,
    currency: c.currency || "",
    purchased_minor: c.amount_without_scoped_credits,
    promo: (c.promo_tranches || []).map(tranche),
    spend_status: spend.status,
    spent_minor: spend.body && spend.body.amount,
    resets_at: spend.body && spend.body.resets_at,
    limits_status: limits.status,
    enforced_limit_minor: limits.body && limits.body.enforced_limit_usd,
    org_limit_text: i >= 0 ? text.slice(i, i + 400) : "",
  });
})()"""

# Runs in a fresh claude.ai tab. GETs the account's cloud-session promo
# (/v1/code/promo/cloud_credit) and, per chat organisation, the usage meters
# (/api/organizations/<uuid>/usage). Returns ONE JSON string with the promo's
# state/expiry and each meter's dollar figures only — no ids, names, cookies or
# conversation data leave the page.
CLOUD_JS = r"""(async () => {
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const get = async (path, headers) => {
    try {
      const r = await fetch(path, { credentials: "include", headers: headers || {} });
      if (!r.ok) return { status: r.status };
      return { status: r.status, body: await r.json() };
    } catch (err) { return { status: 0 }; }
  };
  let acct = { status: 0 };
  for (let i = 0; i < 40; i++) {
    acct = await get("/api/account");
    if (acct.status === 200 || acct.status === 401 || acct.status === 403) break;
    await sleep(500);
  }
  if (acct.status === 401 || acct.status === 403 || location.pathname.startsWith("/login"))
    return JSON.stringify({ state: "logged_out" });
  if (acct.status !== 200 || !acct.body) return JSON.stringify({ state: "page_error", why: "account " + acct.status });
  const promo = await get("/v1/code/promo/cloud_credit", { "anthropic-version": "2023-06-01" });
  const pb = promo.body || {};
  const meters = [];
  if (pb.state === "active") {
    for (const m of acct.body.memberships || []) {
      const o = m.organization || {};
      if (!(o.capabilities || []).includes("chat")) continue;
      const u = await get("/api/organizations/" + o.uuid + "/usage");
      for (const v of Object.values(u.body || {})) {
        if (v && typeof v === "object" && typeof v.limit_dollars === "number" &&
            typeof v.used_dollars === "number")
          meters.push({ limit: v.limit_dollars, used: v.used_dollars,
                        remaining: v.remaining_dollars, resets_at: v.resets_at });
      }
    }
  }
  return JSON.stringify({
    state: "ok", email: acct.body.email_address || "",
    promo_status: promo.status, promo_state: pb.state || "", expires_at: pb.expires_at || "",
    meters: meters,
  });
})()"""


def _now() -> int:
    return int(time.time())


def _iso(epoch: int) -> str:
    return dt.datetime.fromtimestamp(epoch, dt.UTC).isoformat().replace("+00:00", "Z")


def _money(minor: Any, credit: Any = None) -> float | None:
    """Dollars from a ``{"amount_minor", "exponent"}`` credit object, else from
    cents; None when neither is a number."""
    if isinstance(credit, dict):
        amount, exp = credit.get("amount_minor"), credit.get("exponent")
        if isinstance(amount, int) and isinstance(exp, int) and 0 <= exp <= 6:
            return float(amount) / float(10**exp)
    if isinstance(minor, (int, float)) and not isinstance(minor, bool):
        return float(minor) / 100.0
    return None


_DOLLARS = r"\$([\d,]+(?:\.\d+)?)"
_LIMIT_RE = re.compile(
    rf"{_DOLLARS} spent\s+Resets ([A-Z][a-z]{{2}} \d{{1,2}}, \d{{4}})[\s\S]*?"
    rf"Monthly spend limit\s+{_DOLLARS}"
)


def parse_limit_text(text: str) -> dict[str, Any] | None:
    """The page's "Organization limit" block → spent / limit / reset day (UTC);
    None when the block is not there in the expected words."""
    m = _LIMIT_RE.search(text or "")
    if m is None:
        return None
    try:
        resets = dt.datetime.strptime(m.group(2), "%b %d, %Y").replace(tzinfo=dt.UTC)
    except ValueError:
        return None
    return {
        "spent_usd": float(m.group(1).replace(",", "")),
        "limit_usd": float(m.group(3).replace(",", "")),
        "resets_at": _iso(int(resets.timestamp())),
    }


def parse_page(raw: dict[str, Any]) -> dict[str, Any]:
    """The page's answer (PAGE_JS) → the file's figures. Raises ValueError when
    the credits cannot be read: a half reading is never written as good."""
    if raw.get("credits_status") != 200:
        raise ValueError(f"prepaid/credits answered {raw.get('credits_status')}")
    promo = []
    for row in raw.get("promo") or []:
        remaining = _money(row.get("remaining_minor"), row.get("remaining_credit"))
        granted = _money(row.get("granted_minor"), row.get("granted_credit"))
        if remaining is None or granted is None or not row.get("expires_at"):
            raise ValueError("a promotional-credit row without amount or expiry")
        promo.append(
            {
                "remaining_usd": round(remaining, 4),
                "granted_usd": round(granted, 4),
                "expires_at": row["expires_at"],
                "granted_at": row.get("granted_at"),
                "name": row.get("name") or row.get("program") or "",
            }
        )
    out: dict[str, Any] = {
        "currency": str(raw.get("currency") or "USD").upper(),
        "purchased_usd": _money(raw.get("purchased_minor")),
        "promo": promo,
        "org_name": raw.get("org_name") or "",
        "cap": parse_cap(raw),
    }
    return out


def parse_cap(raw: dict[str, Any]) -> dict[str, Any] | None:
    """The monthly spend limit: the page's own words first (what Albert sees),
    the exact cents of its data for ``spent`` when both agree on the limit."""
    page = parse_limit_text(str(raw.get("org_limit_text") or ""))
    api_spent = (
        _money(raw.get("spent_minor")) if raw.get("spend_status") == 200 else None
    )
    api_limit = (
        _money(raw.get("enforced_limit_minor"))
        if raw.get("limits_status") == 200
        else None
    )
    if page is None and (api_spent is None or api_limit is None):
        return None
    cap: dict[str, Any] = (
        dict(page) if page else {"spent_usd": api_spent, "limit_usd": api_limit}
    )
    cap["source"] = "page" if page else "data"
    if page and api_spent is not None and abs(api_spent - page["spent_usd"]) < 0.01:
        cap["spent_usd"] = api_spent
    if raw.get("resets_at"):
        cap["resets_at"] = raw["resets_at"]
    if page and api_limit is not None and abs(api_limit - page["limit_usd"]) >= 0.01:
        cap["data_limit_usd"] = api_limit  # the page wins; the disagreement is kept
    return cap


def parse_cloud(raw: dict[str, Any], now: int) -> dict[str, Any] | None:
    """CLOUD_JS's answer → the ``cloud_credit`` figures, None when the account
    has no active credit. Raises ValueError when an active credit's meter cannot
    be found: a credit is never invented from the promo alone."""
    if raw.get("promo_status") != 200:
        raise ValueError(f"cloud_credit promo answered {raw.get('promo_status')}")
    if raw.get("promo_state") != "active":
        return None
    expires = str(raw.get("expires_at") or "")
    try:
        end = dt.datetime.fromisoformat(expires.replace("Z", "+00:00")).timestamp()
    except ValueError as exc:
        raise ValueError("the cloud credit has no readable expiry") from exc
    if end <= now:
        return None
    for meter in raw.get("meters") or []:
        try:
            at = dt.datetime.fromisoformat(
                str(meter["resets_at"]).replace("Z", "+00:00")
            ).timestamp()
            limit, used = float(meter["limit"]), float(meter["used"])
        except (KeyError, TypeError, ValueError):
            continue
        if abs(at - end) <= CLOUD_MATCH_S and limit > 0:
            return {
                "remaining_usd": round(max(limit - used, 0.0), 4),
                "granted_usd": round(limit, 4),
                "expires_at": expires,
                "measured_at": now,
            }
    raise ValueError("an active cloud credit without a usage meter ending with it")


def _run_problem(run: Any) -> str:
    """Why a browser.py run gave no answer ('' when it did)."""
    if run.rc == BUSY_RC:
        return "a guided login holds the browser"
    if run.killed or run.rc in (124, 125):
        return f"no answer within {EVAL_S} s"
    return f"browser.py eval-fresh exit {run.rc}" if run.rc != 0 else ""


def _cloud_problem(site: str, run: Any) -> tuple[dict[str, Any], str]:
    """(page answer, "") or ({}, why the claude.ai run gave no usable answer)."""
    why = _run_problem(run)
    raw: Any = None
    if not why:
        try:
            raw = json.loads(json.loads(run.stdout.strip().splitlines()[-1]))
        except (ValueError, IndexError, TypeError):
            pass
        raw = raw if isinstance(raw, dict) else {}
        state = raw.get("state")
        if not raw:
            why = "the page's answer is not a JSON object"
        elif state == "logged_out":
            why = "claude.ai is logged out"
        elif state != "ok":
            why = str(raw.get("why") or state)
        elif str(raw.get("email") or "").lower() != CONSOLE_ACCOUNTS[site].lower():
            why = "claude.ai holds another account"
    return ({}, why) if why else (raw, "")


def interpret_cloud(site: str, run: Any) -> dict[str, Any]:
    """The claude.ai run → ``{"cloud_credit": …}`` or ``{"cloud_error": why}``.
    Never raises and never fails the Console reading."""
    raw, why = _cloud_problem(site, run)
    if why:
        return {"cloud_error": why}
    try:
        return {"cloud_credit": parse_cloud(raw, _now())}
    except ValueError as exc:
        return {"cloud_error": str(exc)}


def read_previous(path: Path) -> dict[str, Any]:
    """The account's last file ({} when there is none or it is unreadable)."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def write_atomic(path: Path, data: dict[str, Any]) -> None:
    """Write `data` as JSON to `path`: a 0600 temp file in the same directory,
    fsynced, then renamed over the old one."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            os.fchmod(fh.fileno(), 0o600)
            json.dump(data, fh, indent=1, sort_keys=True)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def merge(
    previous: dict[str, Any], label: str, status: str, error: str, now: int
) -> dict[str, Any]:
    """A failed attempt's file: the last good figures kept, the status updated."""
    data = {k: v for k, v in previous.items() if k not in ("status", "error")}
    data.update(
        {
            "schema": SCHEMA,
            "account": label,
            "status": status,
            "error": error,
            "checked_at": now,
            "checked_at_iso": _iso(now),
        }
    )
    data.setdefault("measured_at", None)
    return data


@contextlib.contextmanager
def instance(inst: str) -> Iterator[bool]:
    """Point browser.py at instance `inst` ('' = the shared one). A named
    instance that is down is started for the run and ALWAYS stopped again
    afterwards (even when its start was slow), unless a client uses it then.
    Yields whether a browser answers."""
    old = os.environ.get("CLAUDE_BROWSER_INSTANCE")
    os.environ["CLAUDE_BROWSER_INSTANCE"] = inst
    started = False
    try:
        if inst and browser_mode() is None:
            started = True
            _browser("up", quiet=True, timeout_s=browser_timeout("up"))
            deadline = time.monotonic() + UP_WAIT_S
            while browser_mode() is None and time.monotonic() < deadline:
                time.sleep(1.0)
        yield browser_mode() is not None
    finally:
        if started:
            users = instance_users()
            if users is not None:
                print(f"⏸  the {inst} browser stays up — {users[1]}", file=sys.stderr)
            elif _browser("down", quiet=True, timeout_s=DOWN_S) != 0:
                print(
                    f"❌ the {inst} browser did not stop (browser.py down)",
                    file=sys.stderr,
                )
        if old is None:
            os.environ.pop("CLAUDE_BROWSER_INSTANCE", None)
        else:
            os.environ["CLAUDE_BROWSER_INSTANCE"] = old


def _eval(url: str, js: str) -> Any:
    """One fresh tab on `url` running `js`; the browser.py run."""
    return run_browser(
        "eval-fresh",
        "-t",
        str(EVAL_S),
        url,
        js,
        timeout_s=EVAL_S + 20,
        capture=True,
    )


def read_account(label: str) -> tuple[str, str, dict[str, Any] | None]:
    """(status, error, figures) for one account, from its browser. A readable
    Console page also carries the claude.ai cloud-credit reading (same browser
    run): ``cloud_credit`` (dict or None) or, when that read failed, only
    ``cloud_error`` — the Console figures are good either way."""
    site = ACCOUNTS[label]
    with instance(SITE_INSTANCE.get(site, "")) as up:
        if not up:
            return "browser_down", "the browser instance did not start", None
        run = _eval(PAGE_URL, PAGE_JS)
        cloud = _eval(CLOUD_URL, CLOUD_JS) if run.rc == 0 else None
    if run.rc == BUSY_RC:
        return "busy", "a guided login holds the browser", None
    if run.killed or run.rc in (124, 125):
        return "timeout", f"no answer within {EVAL_S} s", None
    if run.rc != 0:
        return "page_error", f"browser.py eval-fresh exit {run.rc}", None
    status, error, figures = interpret(site, run.stdout)
    if figures is not None and cloud is not None:
        figures.update(interpret_cloud(site, cloud))
    return status, error, figures


def interpret(site: str, stdout: str) -> tuple[str, str, dict[str, Any] | None]:
    """`read_account` for eval-fresh's output (the page's JSON string)."""
    try:
        raw = json.loads(json.loads(stdout.strip().splitlines()[-1]))
    except (ValueError, IndexError, TypeError):
        raw = None
    if not isinstance(raw, dict):
        return "page_error", "the page's answer is not a JSON object", None
    state = raw.get("state")
    want = CONSOLE_ACCOUNTS[site].lower()
    if state == "logged_out":
        status, error = "logged_out", f"log in once: ./agent-login.py -g {site}"
    elif state != "ok":
        status, error = "page_error", str(raw.get("why") or state)
    elif str(raw.get("email") or "").lower() != want:
        status, error = (
            "wrong_account",
            f"the browser holds another Console account, not {want}",
        )
    else:
        try:
            return "ok", "", parse_page(raw)
        except ValueError as exc:
            status, error = "page_error", str(exc)
    return status, error, None


def run_account(
    label: str, out_dir: Path, *, force: bool, dry_run: bool
) -> tuple[str, dict]:
    """Read one account and write its file; (status, file content)."""
    path = out_dir / f"{label}.json"
    previous = read_previous(path)
    now = _now()
    last = int(previous.get("checked_at") or 0)
    if not force and previous.get("status") in LOGGED_OUT and now - last < BACKOFF_S:
        return "skipped", previous
    status, error, figures = read_account(label)
    now = _now()
    if figures is not None:
        data = {
            "schema": SCHEMA,
            "account": label,
            "status": "ok",
            "error": "",
            "measured_at": now,
            "measured_at_iso": _iso(now),
            "checked_at": now,
            "checked_at_iso": _iso(now),
            "source": PAGE_URL,
            **figures,
        }
        if "cloud_credit" not in figures:  # its read failed: the last good one stays
            data["cloud_credit"] = previous.get("cloud_credit")
    else:
        data = merge(previous, label, status, error, now)
    if not dry_run:
        write_atomic(path, data)
    return status, data


def _summary(label: str, status: str, data: dict[str, Any]) -> str:
    if status == "skipped":
        ago = (_now() - int(data.get("checked_at") or 0)) // 60
        return (
            f"⏸  {label}: skipped — {data.get('status')} {ago} min ago "
            f"({data.get('error')}); -f retries now"
        )
    if status != "ok":
        return f"❌ {label}: {status} — {data.get('error')}"
    promo = ", ".join(
        f"${p['remaining_usd']:.2f} of ${p['granted_usd']:.2f} until {str(p['expires_at'])[:10]}"
        for p in data.get("promo") or []
    )
    cap = data.get("cap") or {}
    cap_txt = (
        f"; cap ${cap['spent_usd']:.2f} of ${cap['limit_usd']:,.2f}"
        if cap
        else "; cap n/a"
    )
    purchased = data.get("purchased_usd")
    bought = f"; purchased ${purchased:.2f}" if purchased is not None else ""
    cloud = data.get("cloud_credit")
    cloud_txt = (
        f"; cloud ${cloud['remaining_usd']:.2f} of ${cloud['granted_usd']:.2f} "
        f"until {str(cloud['expires_at'])[:10]}"
        if cloud
        else ""
    )
    if data.get("cloud_error"):
        cloud_txt += f"; cloud credit unread: {data['cloud_error']}"
    return f"✅ {label}: promo {promo or 'none'}{bought}{cap_txt}{cloud_txt}"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__.split("\n\n", 1)[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  ./console-balance.py                 # both accounts, write the files\n"
            "  ./console-balance.py -a work -n -j   # work only, print, write nothing\n"
            "  ./console-balance.py -a private -f   # retry a logged-out account now\n"
            f"\nfiles: {DEFAULT_DIR}/<account>.json (ccc: balance_json:<path>)"
        ),
    )
    ap.add_argument(
        "-a",
        "--account",
        action="append",
        choices=sorted(ACCOUNTS),
        help="account to read (repeatable; default: all)",
    )
    ap.add_argument(
        "-o", "--out-dir", type=Path, default=DEFAULT_DIR, help="where the files go"
    )
    ap.add_argument("-n", "--dry-run", action="store_true", help="write no file")
    ap.add_argument(
        "-f",
        "--force",
        action="store_true",
        help=f"read a logged-out account even within its {BACKOFF_S // 3600} h back-off",
    )
    ap.add_argument("-j", "--json", action="store_true", help="print each file's JSON")
    ap.add_argument("-q", "--quiet", action="store_true", help="print failures only")
    args = ap.parse_args(argv)
    rc = 0
    for label in args.account or sorted(ACCOUNTS):
        try:
            status, data = run_account(
                label, args.out_dir.expanduser(), force=args.force, dry_run=args.dry_run
            )
        except OSError as exc:
            print(f"❌ {label}: file error — {exc.strerror or exc}", file=sys.stderr)
            rc = max(rc, 1)
            continue
        if not args.quiet or status not in ("ok", "skipped"):
            print(_summary(label, status, data))
        if args.json:
            print(json.dumps(data, indent=1, sort_keys=True))
        if status in LOGGED_OUT:
            rc = 2 if rc == 0 else rc
        elif status not in ("ok", "skipped"):
            rc = 1
    return rc


if __name__ == "__main__":
    sys.exit(main())
