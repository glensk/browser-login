# PLAN: log Albert's Safari in to Notion and open a page (tp#1643)

> **Resume here.** Status: planned + debated (Opus), nothing built. Next box: B1.
> Overseer session: e060d2f3-356d-44b4-8a4f-9e4f6bca123b. Work in a worktree
> (`git -C /Users/albert/obsidian/42-Git/home/browser-login worktree add
> /Users/albert/obsidian/42-Git/home/browser-login/.worktrees.noindex/notion-safari -b
> notion-safari`) — `agent-login.py`, `bin/browser.py` and the `agent_login_*.py`
> modules are LIVE (consumers exec them). Install atomically at the end (B11). B12 is
> run with Albert present; B13 only when Safari is genuinely logged out.

## Session

Ticket: tp#1643
Session: e060d2f3-356d-44b4-8a4f-9e4f6bca123b (overseer; planned in
aafe7b3d-404e-4578-babf-520f38dca367)
Predecessor: tp#1633 (`PLAN_notion-headless-login.md`, done) — the headless
`browser.py login notion -M` route, its cooldown and quarantine.
Decision (Albert, 2026-11-03): build a supported Safari route for Notion.
Scope extension (Albert via overseer, 2026-11-03): "please log me into notion" → ONE
command an agent runs; overview columns Safari / Chromium from one capability table;
generalising the Safari route to other sites is a separate follow-up item (tp#1644).

## Goal

An agent told "please log me into notion" (or "open this Notion page in my Safari")
runs ONE command:

```
./agent-login.py -L notion -s                 # Safari logged in, left on the workspace home
./agent-login.py -L notion -s https://app.notion.com/p/renku/S3-Credentials-automation-40d0df2efafc8078835ad80c27f2f4d2
```

It (1) proves whether Albert's Safari already holds a working Notion session for the
expected account; (2) if not, logs Safari in with the existing Safari e-mail-code
recipe (attended gate, shared 15-min cooldown and quarantine); (3) imports the session
into the shared Chromium when that one is logged out (also after a `match` proof);
(4) opens the landing page (the workspace home `https://app.notion.com/`) or the given
URL in Safari via mydotfiles `safari.py -o URL`. Safari already logged in → no code
mail, it only opens the page.

Plus: the no-arg overview and `-j` gain `Safari` / `Chromium` columns, derived from one
per-site table (`login_columns()`, which reuses the existing `agent_route()`).

## Findings (read before building)

- **Today's `-L notion`** (`_mail_code_pipeline`, agent-login.py ~4097): free check
  of the shared Chromium (0 → done, Safari never looked at) → Safari import → headless
  `browser.py login notion -M` (stops on success) → attended Safari login only when
  `-M` stopped before sending anything (~4150-4178: gate → `safari_login_lock` →
  `_free_check_gate` → `_safari_drive_stage` ~3993 → `_drive_safari` ~4268). Safari
  stays logged out in the normal case.
- **Safari recipe** `RECIPES["notion"]` (agent_login_safari.py ~394): one `mail_code`
  step on `www.notion.so` (e-mail field, trigger "Continue", code from himalaya,
  submit "Continue with login code"), start `https://www.notion.so/login`, sentinel
  `.notion-sidebar, .notion-sidebar-switcher` on `app.notion.com`, hosts
  `www.notion.so`, `notion.so`, `app.notion.com`. `Machine.run` opens a NEW window
  (`--open … --new-window`), drives it by `--handle`/`--expect-host`, and CLOSES it in
  its `finally`. The code fill (`CODE_FILL_JS`, commit 1edd37d) is unit-tested only,
  never run live.
- **No Safari path honours the cooldown — including today's `-L notion` fallback.**
  The 15-min stamp (`<state>/notion-mail-code.json`, flock `notion-mail-code.lock`) is
  written only by browser.py's `-M` path (`_nmc_lock` / `_nmc_cooldown_left` /
  `_nmc_stamp`, browser.py ~16280-16335; constants `NOTION_MAIL_CODE_*` ~16168);
  agent-login.py only mirrors the read (`_mail_code_cooldown_left`, ~4191). The
  existing `-L notion` Safari fallback (`_safari_drive_stage` → `_drive_safari`)
  sends a code mail with NO cooldown check, NO stamp and without `NOTION_MAIL_ENV` —
  it can send a second code inside the cooldown today. B1/B2/B6 fix both the new
  `-s` route and that fallback with one shared implementation.
- **The Safari Machine's MailReader** (`_safari_plan`, ~4295) runs himalaya without
  `NOTION_MAIL_ENV` → a dead EPFL grant could open a browser (focus loss) mid-run.
  Both Safari mail-code paths pass the site's mail env (`dict(alsafari.NOTION_MAIL_ENV)`
  for notion; dead grant → `mailbox_unreadable` before any trigger).
- **"Is Safari logged in?"** Cookie presence (`safari_cookies.has_session`) is not a
  proof (an expired `token_v2` stays on disk). The server-side proof already exists:
  `_builtin_prove_isolated` (browser.py ~15547) proves Safari's cookies in a THROWAWAY
  Chromium context with `_notion_identity` (match / mismatch / logged_out / other) —
  but `import-safari` reaches it only when the shared Chromium is logged out
  (`_import_builtin_leased` returns 0 early on `valid`). B3 exposes it read-only.
- **`import-safari` always sweeps the shared jar.** `cmd_import_safari` (browser.py
  ~15245-15275) runs `_access_team_sweep` in a `finally` on every non-dry-run exit and
  `_access_team_verdict` (~13319-13333) turns a 0 into 1
  (`access_team_sweep_failed`) when the sweep fails. A read-only proof must not go
  through that path (B3).
- **An agent-route predicate already exists:** `agent_route(site, row)`
  (agent-login.py ~982-995: magic-link sites; recipe sites whose safari.py features
  are present, or whose live Safari session `-L` would import), consumed at ~942,
  ~959, ~1007, ~1081, ~1323, ~1544, ~2052, ~2394, ~2551. The new overview columns
  REUSE it; they do not add a second route predicate.
- **safari.py** (mydotfiles `bin/safari.py`): `-o/--open URL` opens a NEW tab in the
  front window and waits for `readyState == complete` (`-w`, default 20 s); exit 3
  when Safari is not running. Capability `open` is already in `BASE_FEATURES`.
  agent-login pins the path (`DEFAULT_SAFARI_PY`, agent_login_safari.py:88; env
  override only under pytest). **extdeps:** this repo declares NO `EXTERNAL_DEPS`
  registry by design (docs/AGENTS_REFERENCE.md:87, "a provider, not a consumer");
  safari.py is already a pinned, capability-checked dependency. The plan keeps that
  convention (README Requirements names safari.py `-o`) — decided, see below.
- **Gate:** `interactive_gate()` = not `scheduled()` + console unlocked + HID idle
  < 15 min; closed → `-L` exits 3 naming the code. `safari_login_action` refuses a
  LaunchAgent run (`AGENT_LOGIN_SCHEDULED`) at its top with exit 2 (before the gate);
  that stays as is for `-s` (the gate's own `scheduled` code would exit 3 — never
  reached).
- **Quarantine:** `_safari_fail` quarantines notion when `out.credential` (the Machine
  sets it once the code was filled) — the same `als.quarantine("notion", …)` the
  headless route writes and `-Q notion` releases. `als.quarantined("notion")` blocks
  any code mail in both routes.
- **Free short options** in agent-login.py today: a b d e f k o q s u v w y z, B C G
  J N O T W X Y Z (`-s` and `-o` are free). browser.py `import-safari` uses `-a -n -R`
  (`-P` free). Long `--safari` would be a prefix of the existing `--safari-login`
  (argparse prefix matching) → the long form is `--in-safari`.
- **No safe, value-free, Safari-only logout exists.** Safari has no CLI to delete one
  site's cookies (Website Data is GUI-only and not value-free to automate), and
  Notion's in-app "Log out" revokes the server session — when the shared Chromium
  holds the SAME `token_v2` (imported from Safari), Chromium is logged out too, and
  a misclick may hit "Log out of all devices". So the canary never logs Safari out
  (B12/B13).
- **Overview printer** `print_overview` (~1560): space-aligned columns
  `login  agent_fill_origins  status`; rows from `overview()` (~743); agents.md
  generator `agents_text` / `_route_header` route sentence ~951-979.

## CLI options considered

1. `-L notion -T safari` (+ `-o URL`): a target flag with values `shared|safari` plus a
   separate open flag — two new options for one intent; `-T shared` is today's
   default and never typed.
2. `-L notion -o URL` (open-after implies Safari): one flag, but "just log Safari in"
   has no form without a URL, and "-o" reads as an extra step, not a target.
3. New mode `-O URL` (site derived from the URL host): no `-L`; mixes site resolution
   into URL parsing, and "log me into notion" has no URL.
4. **Chosen: `-s/--in-safari [URL]` on `-L`** (argparse `nargs="?"`, `const=""`; long
   form `--in-safari`, not `--safari`, to avoid prefix ambiguity with `--safari-login`):
   `-L SITE -s` = "log Albert's SAFARI in to SITE and leave it on the site's landing
   page"; `-L SITE -s URL` = the same, then that page. One flag, one intent, reads as
   "log in, Safari". `-n` works with it. A second site with a NON-mail-code recipe is
   added by one entry in `SAFARI_ROUTES` (below) — the CLI shape does not change; a
   mail-code site additionally needs its mail env (the `NOTION_MAIL_ENV` equivalent)
   wired in. Without `-L`, or for a site with no Safari route → exit 2 naming the
   sites that have one.

## Design

### Login columns (one table, agent-login.py)

```python
# site -> landing URL a `-L SITE -s` run leaves Safari on (tp#1643). For a
# recipe without a mail_code step, adding a site here (with its RECIPES entry)
# is the whole of a new Safari route; a mail-code site also needs its mail env.
SAFARI_ROUTES: dict[str, str] = {"notion": "https://app.notion.com/"}

@dataclass(frozen=True)
class LoginColumns:
    safari: bool    # `-L SITE -s`: an agent logs Albert's Safari in AND leaves the landing page open
    chromium: bool  # an agent can get the shared Chromium logged in itself

def login_columns(site: str, row: dict | None = None) -> LoginColumns:
    safari = site in SAFARI_ROUTES and site in alsafari.RECIPES
    chromium = (
        agent_route(site, row)                # existing: Safari-recipe login + import, magic link
        or site in MAIL_CODE_SITES            # headless e-mail code (notion)
        or site in alsafari.MAGIC_LINK_SITES  # claude.ai / console magic link
        or _broker_logs_in(row)               # broker login item usable by agents
    )
    return LoginColumns(safari, chromium)
```

Legend (one line, printed under the overview header and in README): `Safari = -L SITE
-s logs Albert's Safari in and opens the page · Chromium = an agent gets the shared
Chromium logged in itself`.

`_broker_logs_in(row)`: a broker login row (not fill-only) whose state is usable by
agents today (the same predicate the overview already uses for "works for agents";
no new rule). `agent_route()` stays the one route predicate (unchanged); the printer
and agents.md read `login_columns()` — never strings of their own.

Expected today:

| site | Safari | Chromium | why |
|---|---|---|---|
| notion | ✅ | ✅ | in `SAFARI_ROUTES` + `RECIPES`; `MAIL_CODE_SITES` |
| claude.ai / console | ❌ | ✅ | `MAGIC_LINK_SITES` (`agent_route`) |
| anibis, galaxus, openai, slack (other `RECIPES` sites) | ❌ | ✅ when `agent_route` says so (safari.py has the recipe's features, or Safari holds a live importable session), else ❌ | not in `SAFARI_ROUTES` (tp#1644 extends it) |
| broker login sites | ❌ | ✅ when `_broker_logs_in` | broker item usable by agents |
| everything else | ❌ | ❌ | needs Albert |

### `-L SITE -s [URL]` pipeline (`safari_target_action`)

In order; every stop prints one line with a fixed code, nothing secret:

1. `scheduled()` → exit 2 (unchanged top check of `safari_login_action`).
2. Target: `site in SAFARI_ROUTES` (else exit 2 `no_safari_route`, naming the sites
   that have one). URL = the given one or `SAFARI_ROUTES[site]`; must be `https`, no
   userinfo, `port is None`, no backslash anywhere in the raw string, non-empty host,
   host ∈ `RECIPES[site].hosts` (exact match, else exit 2 `bad_url`, nothing touched).
   Printed only as its origin (`https://app.notion.com`) + "the given page".
3. `interactive_gate()` closed → exit 3 with the gate code (the whole route touches
   Safari — even an open-only run puts a tab in front of a person).
4. safari.py: `safari_py_bin()` + `features(call) ⊇ BASE_FEATURES | recipe.features()`
   and `--status` javascript true, else exit 3 (`safari_py_missing` /
   `safari_py_outdated` / `safari_unavailable`), nothing done.
5. `safari_login_lock()` (120 s) → else exit 75.
6. **Is Safari logged in?** `_safari_jar(site)`: unreadable or no session →
   "logged out" (why recorded). Else `browser.py import-safari notion -P -R <result>`
   (B3, under `site_session`):
   - `safari: match` → skip to step 8 (no code mail, no login), then step 9;
   - `safari: logged_out` → step 7;
   - `safari: mismatch` → exit 2 `wrong_account` (never add a second account);
   - anything else (indeterminate, 75, timeout) → exit 2 / 75, nothing done.
7. **Log Safari in** (only here may a code mail go out) — the shared helper
   `_mail_code_safari_drive(site, recipe, before)` (B6), also used by today's `-L
   notion` fallback:
   - `als.mail_code_lock(site)` (B1, non-blocking; busy → 75; state dir unwritable →
     exit 2 `state_unwritable`) held to the end of the drive;
   - `block` = `quarantined` when `als.quarantined(site)`, else `cooldown` when
     `als.mail_code_cooldown_left(site, now)` > 0 or unreadable (fail closed), else
     none;
   - `_drive_safari(site, recipe, env=<site mail env>, before_trigger=hook)` — the
     Machine (new window, closed in its `finally`) with B2's hook, called right BEFORE
     the "Continue" click: with a `block` it returns that code (`cooldown` /
     `quarantined`) → the Machine ends with that code and ZERO trigger clicks (no
     code mail while quarantined or inside the cooldown); without one it writes the
     stamp (`mail_code_stamp(site, now)`) and returns None (go); a failed write →
     `state_unwritable`, zero clicks;
   - Machine reaches the sentinel without the trigger (Safari's session was live but
     its on-disk cookie stale) → ok, even with a `block`;
   - stopped at the hook with `cooldown` / `quarantined` → exit 2 with that code
     ("N s left" / the `-Q` hint); `_safari_fail` must NOT quarantine on these codes
     (`out.credential` is false — assert it);
   - other not-ok → `_safari_fail(site, out, …, route="safari-target")` (quarantines
     after a credential step; `needs_albert_*` exit 4; `email_code`, `recipe_stuck`
     exit 2; no retry).
   - ok → `_wait_flush(site, before)` (⚠️ when Safari did not flush within 90 s).
8. **Import** (best effort, the goal is Safari; runs after a `match` proof AND after a
   login): `_free_check(site)` 0 → "shared Chromium already logged in, nothing
   imported"; definite logged_out / wrong_account → `_import_run(site, agent=True)` +
   `record_check` as today (route `safari-login`); an import failure prints ⚠️ with
   its code and is recorded, the run still goes on to step 9 (exit 0 — decided).
   Other check results → ⚠️ "not imported", go on.
9. **Open** `safari.py -o URL -w 20` (new tab in the front window; JSON reply only
   read for rc). rc 0 → `✅ notion: Albert's Safari is logged in — opened
   https://app.notion.com (the workspace home | the given page)`; else exit 2
   `safari_open_failed` (Safari's login state is unchanged by it).
   Exit 0 = Safari logged in AND the page opened.

Lock order: `safari_login_lock` → `mail_code_lock(site)` (both non-blocking past their
wait; the headless `-M` takes only `mail_code_lock` and today's `-L notion` releases
`safari_login_lock` before `-M` and re-takes it for the fallback, then
`mail_code_lock(site)` inside it) — no cycle.

`-L notion` WITHOUT `-s` keeps its order (headless first; Safari only as fallback),
but its Safari fallback now goes through `_mail_code_safari_drive` (lock, cooldown /
quarantine no-trigger mode, stamp before trigger, mail env) — B6.

### `-L SITE -s [URL] -n` (dry run, read-only)

Prints: the target origin (or `bad_url`), the gate, safari.py features incl. `open`,
whether Safari holds a session + `safari fp: <8 hex>`, quarantine, cooldown (shared
reader `mail_code_cooldown_left(site, now)`), the mailbox readiness
(`_mail_code_dry_run`), and the next step ("would prove Safari's session, import if
Chromium is logged out, then open" / "would log Safari in with the e-mail code, then
open" / "would try Safari without a code mail (cooldown|quarantined)").
No proof run, no lease, no mail, no Safari call except `--capabilities`/`--status`.

### `browser.py import-safari SITE -P/--prove-only` (B3)

`SAFARI_BUILTIN` sites only (else exit 2): read Safari's cookies (unreadable → exit 2
`no_safari_session`), expected account (`_builtin_expected`; missing → exit 2
`identity_unconfigured`), then under registration + `_interaction_lease("import-safari
SITE -P")` run `_builtin_prove_isolated` and stop. `-P` branches off in
`cmd_import_safari` BEFORE the try/finally that runs `_access_team_sweep` /
`_access_team_verdict` (own `_result_begin` / `_result_write`), so the shared jar is
never touched: no `_builtin_replace`, no storage clear, no login event, no team-cookie
sweep — a `match` stays exit 0. Result record:
`{"safari": "match|mismatch|logged_out|indeterminate", "phase", "code"}`; exit 0 on
match, else 2 with code `logged_out` / `wrong_account` / `indeterminate`. Output: one
line with the verdict, never a cookie name's value.

### Overview columns (B9)

`print_overview` gets two fixed-width columns after the login name: `Safari` and
`Chromium` (✅ / ❌ from `login_columns(r["site"], r)`; header and cells padded so the
columns stay aligned — emoji width handled like the status icon column) and the
legend line under the header. `-j`: each row gains
`"login_columns": {"safari": bool, "chromium": bool}`. agents.md: the route sentence
names `-L notion -s` ("Albert says 'log me into notion' → run
`agent-login.py -L notion -s`"), and the Safari-route site list comes from
`SAFARI_ROUTES` (no hard-coded "notion" in the text).

## Boxes

- [x] B1 `agent_login_state.py`: move the mail-code cooldown helpers out of browser.py,
  keyed by site: `mail_code_lock(site)` (context manager, True/False/None as
  `_nmc_lock`), `mail_code_cooldown_left(site, now)` (fail closed, future stamp = full
  cooldown) and `mail_code_stamp(site, now)` (atomic 0600); files
  `<site>-mail-code.json` / `<site>-mail-code.lock` (notion keeps its existing
  `notion-mail-code.json` / `notion-mail-code.lock`), `MAIL_CODE_COOLDOWN_S = 900`.
  browser.py keeps `NOTION_MAIL_CODE_FILE` / `NOTION_MAIL_CODE_LOCK` /
  `NOTION_MAIL_CODE_COOLDOWN_S` as aliases and its `_nmc_*` as thin calls with
  `site="notion"`; the `-M` flow keeps calling through `_nmc_*` (behaviour
  byte-identical) so `tests/test_notion_mail_code.py` (~739, ~895-948 monkeypatch
  `browser._nmc_stamp`) passes unchanged. agent-login.py drops its mirror
  (`MAIL_CODE_STAMP`, `MAIL_CODE_COOLDOWN_S`, `_mail_code_cooldown_left`) and reads
  the shared one.
- [x] B2 `agent_login_safari.py`: `Machine` gains `before_trigger: Callable[[], str |
  None] | None = None`, called in `_mail_code` after the e-mail fill and right before
  the trigger click; a returned code (`state_unwritable` / `cooldown` / `quarantined`)
  → `_end(2, code)`, no click; None → click. `_drive_safari` (agent-login.py) passes
  `before_trigger` and a MailReader `env` through (defaults unchanged for every other
  caller). `EMAIL_FILL_JS` / `CODE_FILL_JS` untouched.
- [x] B3 `bin/browser.py`: `import-safari SITE -P/--prove-only` as in Design (help
  text: "prove Safari's session in a throwaway context; the shared browser is not
  touched"); `-P` returns before the sweep try/finally. **Check first (unverified by
  the critique):** (a) does `_builtin_prove_isolated` / `_connect` start the shared
  Chromium when it is down, or traceback? — `-P` must either start it the way
  `import-safari` does today or exit 2 `indeterminate` with one line, never a
  traceback; (b) is agent-login's `browser_timeout("import-safari")` long enough for
  the proof plus the `_interaction_lease` wait? — if not, give `-P` its own timeout
  key. Record both answers in the B3 commit message.
- [x] B4 `agent-login.py`: `SAFARI_ROUTES`, `LoginColumns`, `login_columns()`
  (reusing `agent_route()` unchanged), `_broker_logs_in()`.
- [x] B5 `agent-login.py`: `-s/--in-safari [URL]` argument (`nargs="?"`, `const=""`,
  only with `-L`, else exit 2; conflicts handled like `-L`'s other-flag check ~4733)
  and the step-2 target validation (`no_safari_route`, `bad_url` incl. port,
  backslash, empty host).
- [x] B6 `agent-login.py`: `safari_target_action` steps 3-9 (gate, safari.py check,
  lock, `-P` proof, login, flush, best-effort import — after a `match` too —,
  `safari.py -o URL`), `_safari_fail(route="safari-target")`; the shared
  `_mail_code_safari_drive(site, recipe, before)` (step 7: `mail_code_lock(site)` →
  quarantine / cooldown → no-trigger mode with the `cooldown` / `quarantined` code,
  else stamp-before-trigger; site mail env) used by `-s` AND by today's `-L notion`
  Safari fallback for every `MAIL_CODE_SITES` site (`_safari_drive_stage` calls it
  instead of the bare `_drive_safari`; non-mail-code recipes unchanged). **Check first
  (unverified by the critique):** (a) the `-M` order of cooldown check vs. mailbox
  check — which "stopped before sending anything" codes reach the fallback, and does
  a `cooldown` stop from `-M` now lead to a no-trigger Safari run (it must not send);
  (b) does `https://www.notion.so/login` redirect to `app.notion.com` (sentinel
  visible) when Safari is logged in, so the no-trigger mode can succeed? If it does
  not, no-trigger mode with a stale on-disk cookie ends in `cooldown` /
  `quarantined` — note it in README; (c) as B3 (b) for the fallback's timeouts.
- [x] B7 `agent-login.py`: `-L SITE -s [URL] -n` dry run as in Design.
- [x] B8 tests (unit, no network, no real Safari / Chrome; fakes as in
  `test_ws1b_safari.py` / `test_notion_l_pipeline.py`) in new
  `tests/test_notion_safari_target.py`:
  Safari proof `match` → zero Machine calls, zero mail reads, cooldown file untouched,
  exactly one `safari.py -o <landing>` call, exit 0; with a URL → `-o <that URL>`;
  `match` + free check logged_out → import runs; `match` + free check 0 → no import;
  proof `logged_out` → Machine runs, stamp written before the trigger click (call
  order recorded), import runs when the free check says logged_out and is skipped when
  it says 0, then `-o` → exit 0; no Safari session / unreadable jar → login (why
  recorded); proof `mismatch` → exit 2 `wrong_account`, no Machine; cooldown active →
  Machine runs in no-trigger mode (zero trigger clicks, zero mail reads, stamp
  untouched): sentinel shown → exit 0 + `-o`, else exit 2 `cooldown`, no `-o`, no
  quarantine; quarantined → same no-trigger mode with code `quarantined` (zero
  clicks, no code mail ever), and a `match` proof still opens the page; unreadable
  cooldown → `cooldown` (fail closed); `mail_code_lock` busy → 75; stamp unwritable →
  `state_unwritable`, zero clicks; gate closed (each code) → exit 3, no safari.py
  call, no proof; `scheduled()` → exit 2; safari.py missing / lacking `open` → exit 3;
  Machine `needs_albert_captcha` → exit 4, no `-o`; code submitted then no sentinel →
  quarantine written once, exit 2, no `-o`; `-o` rc 3 → exit 2 `safari_open_failed`;
  `bad_url` cases (http, foreign host, userinfo, `notion.so.evil.com`,
  `https://app.notion.com:8443/x`, a backslash, empty host `https:///x`) → exit 2 with
  nothing called; `-s` without `-L` / on a site without a route → exit 2;
  `--in-safari` long form parses, `--safari-login` still parses as before;
  MailReader env carries `SDSC_EMAIL_NO_AUTO_AUTH=1`; the code and cookie values never
  appear in stdout/stderr/result/checks files (capsys + file scan); `-n` makes no
  `-P`/Machine/`-o` call. Fallback path (`-L notion` without `-s`, `-M` stopped
  before sending): cooldown active → no-trigger mode, zero trigger clicks; cooldown
  free → stamp written before the trigger; MailReader env carries `NOTION_MAIL_ENV`.
  browser.py `-P`: match → exit 0 and `_builtin_replace` / storage clear / login
  event / `_access_team_sweep` never called, rc stays 0 (a failing sweep fake is not
  reached); logged_out → 2; non-builtin site → 2.
  `login_columns`: notion (True, True); a claude.ai site (False, True); a recipe site
  not in `SAFARI_ROUTES` with `agent_route` True (False, True) and with it False
  (False, False); a broker login row (False, True); a fake second `SAFARI_ROUTES`
  entry (non-mail-code recipe) flips its Safari cell and `-s` accepts it without CLI
  changes. Overview: columns aligned (equal display width per line), the legend line
  present, `-j` rows carry `login_columns`. B1: browser.py and agent-login.py read the
  same stamp; `mail_code_*("notion")` uses the existing file names; B2:
  `before_trigger` returning a code → no click, `_end` code = that code.
- [x] B9 `agent-login.py`: overview `Safari` / `Chromium` columns + legend line + `-j`
  `login_columns` + agents.md route sentence from `SAFARI_ROUTES` (Design).
- [ ] B10 docs: README notion row (~586: "`-L notion -s [URL]` logs Albert's Safari in
  (attended) and opens the page"), §"Agents renew…" (~1075: a step "Safari target"
  after step 2 + Guards line "both Safari routes share the 15-min cooldown and the
  quarantine; inside them Safari is only tried without a code mail"), the `-L` row
  ~1644 and the `-s` row, Requirements (safari.py `-o`), the overview description
  (new columns + the one-line legend); `agent-login.py` `-h` example
  `./agent-login.py -L notion -s   # "log me into notion": Albert's Safari, left on the
  workspace home (-s URL: that page)`, the `-s/--in-safari` help text, the intro
  paragraph; regenerate agents.md (`agent-login.py -A`) and check the notion line
  names `-L notion -s`. Skill stow source (other repo, needs its own `[commit:
  /Users/albert/obsidian/42-Git/home/mydotfiles]` grant, else the overseer edits):
  `/Users/albert/obsidian/42-Git/home/mydotfiles/dotfiles/claude/.claude/skills/browser-login/SKILL.md`
  line 139 and line 169 — add "Albert says 'log me into notion' / 'open this page in my
  Safari' → `agent-login.py -L notion -s [URL]` (attended: Mac unlocked and in use)".
- [ ] B11 verify + install: `ruff format`, `ruff check`, `mypy`, `uv run pylint` on
  every touched file (incl. `agent-login.py` and the new test file); targeted pytest
  (the Verification block) in the foreground; `agent-login.py -h` and `browser.py
  import-safari -h` exit 0. Install into the live checkout atomically, in this order:
  `agent_login_state.py` → `agent_login_safari.py` → `bin/browser.py` →
  `agent-login.py`. Before the first: check every live file is unchanged since the
  worktree base (`git -C <live> diff --quiet <base> -- <file>` per file); stop if
  not. Per file: `cp <live> <live>.bak`, `cp <worktree file> <live dir>/.<name>.new`,
  `mv <live dir>/.<name>.new <live>` (mode kept: +x on the two scripts). After the
  last swap run the LIVE `bin/browser.py import-safari -h` and `./agent-login.py -h`
  (both exit 0). Rollback = `mv` the `.bak` files back in reverse order
  (`agent-login.py` → `bin/browser.py` → `agent_login_safari.py` →
  `agent_login_state.py`). Remove the `.bak` files only after B12 step 1 passed.
  Commit with the grant the brief carries.
- [ ] B12 LIVE CANARY A (Albert present at the Mac; no logout of anything). Result
  files in a fresh `mktemp -d` (0700).
  1. `agent-login.py -L notion -s -n` → target origin, gate open, Safari holds a
     session, cooldown, next step. Note `safari fp` and the mtime of
     `~/.local/state/agent-login/notion-mail-code.json` (`stat -f %m`, or "absent").
  2. `browser.py import-safari notion -P -R <dir>/prove.json` → expect exit 0,
     `safari: match`, and no `access_team_sweep` entry for this run. If `logged_out` →
     Safari is genuinely logged out: go to B13 now (Albert is present). `mismatch` /
     other → stop, report.
  3. `agent-login.py -L notion -s` → exit 0, Safari shows the workspace home; Albert
     confirms it is his workspace.
  4. `agent-login.py -L notion -s https://app.notion.com/p/renku/S3-Credentials-automation-40d0df2efafc8078835ad80c27f2f4d2`
     → exit 0, that page open in Safari.
  5. After 3 and 4: the cooldown file mtime unchanged (no code mail), no new mail from
     Notion, `browser.py logged-in notion` still 0, nothing quarantined
     (`agent-login.py -L notion -n` shows no quarantine).
  6. Negative, read-only: `agent-login.py -L notion -s http://app.notion.com/` and
     `-s https://example.com/` → exit 2 `bad_url`, Safari untouched.
- [ ] B13 LIVE CANARY B — the e-mail-code login in Safari (only when Safari is
  GENUINELY logged out of Notion — B12 step 2 said `logged_out`, or a later agent run
  meets it; never forced by a logout; Albert present; the cooldown free).
  `agent-login.py -L notion -s` → Safari login window opens, e-mail filled, "Continue",
  code filled once, window closes, import (or "already logged in"), workspace home
  opens; exit 0; the cooldown stamp is now fresh; the code mail archived
  (`mail_archived` in the check detail). Then `browser.py import-safari notion -P`
  → `match`. **Stop rules:** exit 4 (CAPTCHA, new-device check) → Albert solves it in
  that window by hand, no retry; `email_code` / `recipe_stuck` → no retry inside the
  cooldown, report (first live run of `CODE_FILL_JS` — a finding, not a bug hunt in
  place); a quarantine → report, never `-Q` it yourself. Until B13 ran, README /
  agents.md say "the Safari code fill is not proven live yet" (removed after B13).

## Verification

```
cd /Users/albert/obsidian/42-Git/home/browser-login && ruff format --check /Users/albert/obsidian/42-Git/home/browser-login/agent-login.py /Users/albert/obsidian/42-Git/home/browser-login/agent_login_safari.py /Users/albert/obsidian/42-Git/home/browser-login/agent_login_state.py /Users/albert/obsidian/42-Git/home/browser-login/bin/browser.py /Users/albert/obsidian/42-Git/home/browser-login/tests/test_notion_safari_target.py
cd /Users/albert/obsidian/42-Git/home/browser-login && ruff check /Users/albert/obsidian/42-Git/home/browser-login/agent-login.py /Users/albert/obsidian/42-Git/home/browser-login/agent_login_safari.py /Users/albert/obsidian/42-Git/home/browser-login/agent_login_state.py /Users/albert/obsidian/42-Git/home/browser-login/bin/browser.py /Users/albert/obsidian/42-Git/home/browser-login/tests/test_notion_safari_target.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run --project /Users/albert/obsidian/42-Git/home/browser-login mypy /Users/albert/obsidian/42-Git/home/browser-login/agent-login.py /Users/albert/obsidian/42-Git/home/browser-login/bin/browser.py /Users/albert/obsidian/42-Git/home/browser-login/agent_login_safari.py /Users/albert/obsidian/42-Git/home/browser-login/agent_login_state.py /Users/albert/obsidian/42-Git/home/browser-login/tests/test_notion_safari_target.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run --project /Users/albert/obsidian/42-Git/home/browser-login pylint /Users/albert/obsidian/42-Git/home/browser-login/agent-login.py /Users/albert/obsidian/42-Git/home/browser-login/bin/browser.py /Users/albert/obsidian/42-Git/home/browser-login/agent_login_safari.py /Users/albert/obsidian/42-Git/home/browser-login/agent_login_state.py /Users/albert/obsidian/42-Git/home/browser-login/tests/test_notion_safari_target.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run --project /Users/albert/obsidian/42-Git/home/browser-login pytest -q /Users/albert/obsidian/42-Git/home/browser-login/tests/test_notion_safari_target.py /Users/albert/obsidian/42-Git/home/browser-login/tests/test_notion_mail_code.py /Users/albert/obsidian/42-Git/home/browser-login/tests/test_notion_l_pipeline.py /Users/albert/obsidian/42-Git/home/browser-login/tests/test_ws1b_safari.py /Users/albert/obsidian/42-Git/home/browser-login/tests/test_ws1b_agent_login.py /Users/albert/obsidian/42-Git/home/browser-login/tests/test_agent_login.py /Users/albert/obsidian/42-Git/home/browser-login/tests/test_access_team_cookies.py /Users/albert/obsidian/42-Git/home/browser-login/tests/test_notion_logout.py
cd /Users/albert/obsidian/42-Git/home/browser-login && ./agent-login.py -h
cd /Users/albert/obsidian/42-Git/home/browser-login && bin/browser.py import-safari -h
cd /Users/albert/obsidian/42-Git/home/browser-login && grep -c "agent-login.py -L notion -s" README.md
```

Each line is `cd <repo> && <argv>` because `tp verify`'s grammar requires exactly that
prefix (`tp plan -f` refuses a block it cannot parse); no `;`, no pipes, no other `&&`,
absolute paths, no live login. mypy runs on the hyphenated `agent-login.py` and the
test file as plain paths (checked 2026-11-03: no `--explicit-package-bases` needed).
Read-only smoke (not in the block, run by B11): `agent-login.py -L notion -s -n`.
Full suite: skipped unless a touched file's neighbours fail (say so in the report).

## Risks

- **The Safari code fill was never run live** (1edd37d, unit-tested only): label drift,
  `_OTP_FIELD` not matching, a German UI. B13 is its first live run; a stop is a finding,
  cooldown blocks repeats; Albert is present and can finish by hand in the window.
- **No forced canary for the login path:** no safe Safari-only logout exists (Findings),
  so B13 waits for a genuine logout. B8's fakes cover the path; B12 covers the
  already-logged-in path live. Accepted by the brief.
- **Proof in a throwaway context** sends Safari's session cookies to Notion from
  Chromium (as every import already does). Notion could see a second client for the
  same token; no logout effect known. Same as today's import.
- **Safari cookies lag on disk:** a fresh Safari login may not be flushed when the proof
  runs → `logged_out` → a login attempt. Mitigation: inside the cooldown (or under
  quarantine) the Machine runs in no-trigger mode — a live session reaches the sentinel
  without any code mail; outside it at most one code mail per 15 min; `_wait_flush`
  after our own login.
- **Second account in Safari:** `mismatch` stops before any code (never adds an account).
- **Concurrency with headless `-M`:** shared `mail_code_lock("notion")` → one code mail
  at a time across all routes; busy → 75.
- **Opening a page in a tab of the front window** could land in a window Albert uses
  for something else — new tab only, never replaces a tab (safari.py rule).
- **Live-file edits:** worktree + ordered atomic install with `.bak` rollback (B11).

## Decided (overseer, 2026-11-03)

- extdeps: keep the repo's "no EXTERNAL_DEPS registry" convention (safari.py stays the
  pinned, capability-checked path; README Requirements names `-o`). Answer: yes.
- Overview `Chromium` column: count broker-login sites (usable for agents) as ✅.
  Answer: yes.
- `-L notion -s` when Safari is logged in but the import into Chromium failed: exit 0
  with ⚠️ (the asked-for Safari page is open). Answer: yes.
- Column semantics: `Safari` = "`-L SITE -s` supported: an agent logs Albert's Safari
  in AND leaves the landing page open" = site in `SAFARI_ROUTES` and in `RECIPES`
  (only notion today, per Albert's request; tp#1644 extends it). `Chromium` = an agent
  can get the shared Chromium logged in itself = existing `agent_route(site, row)` OR
  `MAIL_CODE_SITES` OR `MAGIC_LINK_SITES` OR the broker predicate.

## Debate outcome (Opus adversary)

Critic: fresh Opus subagent, 2026-11-03, 1 round. Verdict: sound-with-fixes.

1. [major] `-P` would still run the Access team-cookie sweep in `cmd_import_safari`'s
   finally and could turn a `match` 0 into 1 — accepted: Design `-P` and B3 branch off
   before the sweep try/finally; B8 asserts `_access_team_sweep` not called and rc 0;
   B12 step 2 checks no sweep entry.
2. [major] Today's `-L notion` Safari fallback also sends a code with no cooldown
   check/stamp and without `NOTION_MAIL_ENV` — accepted: Findings corrected; B6 routes
   the fallback through the shared `_mail_code_safari_drive` (lock → cooldown /
   quarantine → stamp-before-trigger + mail env); B8 fallback cases.
3. [major] `agent_routes()` would be a second route predicate next to `agent_route()`
   — accepted with modification: renamed to `login_columns()` → `LoginColumns(safari,
   chromium)`, Chromium reuses `agent_route()`; Safari = `SAFARI_ROUTES` ∩ `RECIPES`;
   "Expected today" table fixed (recipe sites ❌ / ✅ per `agent_route`); legend line
   in overview + README; `-j` key `login_columns`; B8 follows.
4. [major] On a `match` proof the import into a logged-out Chromium was skipped —
   accepted: step 6 `match` → step 8 → step 9; B8 "match + Chromium logged out →
   import; match + Chromium ok → no import".
5. [major] B11 install had no order, no rollback — accepted: order state → safari →
   browser.py → agent-login.py, unchanged-since-base check, `.bak` copies, live `-h`
   smoke after the swap, reverse-order rollback.
6. [minor] Moving `_nmc_*` would break `test_notion_mail_code.py`'s monkeypatches —
   accepted: B1 keeps `NOTION_MAIL_CODE_*` aliases and the `-M` flow through `_nmc_*`.
7. [minor] Refusing up front on cooldown/quarantine blocks a live session whose
   on-disk cookie is stale — accepted: step 7 / B2 / B6 no-trigger mode
   (`before_trigger` returns `cooldown` / `quarantined`, zero clicks; sentinel → ok,
   else exit 2 with that code); B8 cases.
8. [minor] Mail-code helpers were notion-global — accepted: B1 keys them by site
   (`mail_code_lock(site)` …; notion keeps its file names); "one `SAFARI_ROUTES` entry"
   claim limited to non-mail-code recipes, mail-code sites need their mail env.
9. [minor] `bad_url` let ports, backslashes and empty hosts through — accepted: step 2
   requires `port is None`, no backslash, non-empty host; B8 cases added.
10. [minor] Verification block incomplete — accepted: `git diff --stat` dropped;
    `agent-login.py` and the new test in mypy/pylint (plain paths suffice);
    `test_access_team_cookies.py`, `test_notion_logout.py` in pytest; `-h` smokes and
    the README grep added.
11. [minor] `--safari` is ambiguous with `--safari-login` by prefix — accepted: long
    option `--in-safari`, short `-s` unchanged; B8 parses both.

Critic's UNVERIFIED points are now "check first" items: B3 (a) Chromium-down
behaviour of `_builtin_prove_isolated` / `_connect`, B3 (b) / B6 (c)
`browser_timeout("import-safari")` vs. proof + lease wait, B6 (a) `-M` cooldown vs.
mailbox check order, B6 (b) `notion.so/login` redirect when logged in.
