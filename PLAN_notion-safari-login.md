# PLAN: log Albert's Safari in to Notion and open a page (tp#1643)

> **Resume here.** Status: planned, nothing built, no critique round yet. Next box: B1.
> Overseer session: aafe7b3d-404e-4578-babf-520f38dca367. Work in a worktree
> (`git -C /Users/albert/obsidian/42-Git/home/browser-login worktree add
> /Users/albert/obsidian/42-Git/home/browser-login/.worktrees.noindex/notion-safari -b
> notion-safari`) — `agent-login.py`, `bin/browser.py` and the `agent_login_*.py`
> modules are LIVE (consumers exec them). Install atomically at the end (B11). B12 is
> run with Albert present; B13 only when Safari is genuinely logged out.

## Session

Ticket: tp#1643
Session: aafe7b3d-404e-4578-babf-520f38dca367 (overseer)
Predecessor: tp#1633 (`PLAN_notion-headless-login.md`, done) — the headless
`browser.py login notion -M` route, its cooldown and quarantine.
Decision (Albert, 2026-11-03): build a supported Safari route for Notion.
Scope extension (Albert via overseer, 2026-11-03): "please log me into notion" → ONE
command an agent runs; overview columns Safari / Chromium from one capability table;
generalising the Safari route to other sites is a separate follow-up item.

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
into the shared Chromium when that one is logged out; (4) opens the landing page (the
workspace home `https://app.notion.com/`) or the given URL in Safari via mydotfiles
`safari.py -o URL`. Safari already logged in → no code mail, it only opens the page.

Plus: the no-arg overview and `-j` gain `Safari` / `Chromium` columns (where an agent
can log Albert in for that site), derived from one per-site route table.

## Findings (read before building)

- **Today's `-L notion`** (`_mail_code_pipeline`, agent-login.py ~4097): free check
  of the shared Chromium (0 → done, Safari never looked at) → Safari import → headless
  `browser.py login notion -M` (stops on success) → attended Safari login only when
  `-M` stopped before sending anything. Safari stays logged out in the normal case.
- **Safari recipe** `RECIPES["notion"]` (agent_login_safari.py ~394): one `mail_code`
  step on `www.notion.so` (e-mail field, trigger "Continue", code from himalaya,
  submit "Continue with login code"), start `https://www.notion.so/login`, sentinel
  `.notion-sidebar, .notion-sidebar-switcher` on `app.notion.com`, hosts
  `www.notion.so`, `notion.so`, `app.notion.com`. `Machine.run` opens a NEW window
  (`--open … --new-window`), drives it by `--handle`/`--expect-host`, and CLOSES it in
  its `finally`. The code fill (`CODE_FILL_JS`, commit 1edd37d) is unit-tested only,
  never run live.
- **The Safari Machine ignores the cooldown.** The 15-min stamp
  (`<state>/notion-mail-code.json`, flock `notion-mail-code.lock`) is written only by
  browser.py's `-M` path (`_nmc_lock` / `_nmc_cooldown_left` / `_nmc_stamp`,
  browser.py ~16280-16335); agent-login.py only mirrors the read
  (`_mail_code_cooldown_left`, ~4191). A Safari login today could send a second code
  mail inside the cooldown. B1/B2 fix that by sharing one implementation.
- **The Safari Machine's MailReader** (`_safari_plan`, ~4308) runs himalaya without
  `NOTION_MAIL_ENV` → a dead EPFL grant could open a browser (focus loss) mid-run.
  The Safari route passes `env=dict(alsafari.NOTION_MAIL_ENV)` (dead grant →
  `mailbox_unreadable` before any trigger).
- **"Is Safari logged in?"** Cookie presence (`safari_cookies.has_session`) is not a
  proof (an expired `token_v2` stays on disk). The server-side proof already exists:
  `_builtin_prove_isolated` (browser.py ~15547) proves Safari's cookies in a THROWAWAY
  Chromium context with `_notion_identity` (match / mismatch / logged_out / other) —
  but `import-safari` reaches it only when the shared Chromium is logged out
  (`_import_builtin_leased` returns 0 early on `valid`). B3 exposes it read-only.
- **safari.py** (mydotfiles `bin/safari.py`): `-o/--open URL` opens a NEW tab in the
  front window and waits for `readyState == complete` (`-w`, default 20 s); exit 3
  when Safari is not running. Capability `open` is already in `BASE_FEATURES`.
  agent-login pins the path (`DEFAULT_SAFARI_PY`, agent_login_safari.py:88; env
  override only under pytest). **extdeps:** this repo declares NO `EXTERNAL_DEPS`
  registry by design (docs/AGENTS_REFERENCE.md:87, "a provider, not a consumer");
  safari.py is already a pinned, capability-checked dependency. The plan keeps that
  convention (README Requirements names safari.py `-o`) — see Questions.
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
  (`-P` free).
- **No safe, value-free, Safari-only logout exists.** Safari has no CLI to delete one
  site's cookies (Website Data is GUI-only and not value-free to automate), and
  Notion's in-app "Log out" revokes the server session — when the shared Chromium
  holds the SAME `token_v2` (imported from Safari), Chromium is logged out too, and
  a misclick may hit "Log out of all devices". So the canary never logs Safari out
  (B12/B13).
- **Overview printer** `print_overview` (~1560): space-aligned columns
  `login  agent_fill_origins  status`; rows from `overview()` (~743); agents.md
  generator `agents_text` route sentence ~968.

## CLI options considered

1. `-L notion -T safari` (+ `-o URL`): a target flag with values `shared|safari` plus a
   separate open flag — two new options for one intent; `-T shared` is today's
   default and never typed.
2. `-L notion -o URL` (open-after implies Safari): one flag, but "just log Safari in"
   has no form without a URL, and "-o" reads as an extra step, not a target.
3. New mode `-O URL` (site derived from the URL host): no `-L`; mixes site resolution
   into URL parsing, and "log me into notion" has no URL.
4. **Chosen: `-s/--safari [URL]` on `-L`** (argparse `nargs="?"`, `const=""`): `-L
   SITE -s` = "log Albert's SAFARI in to SITE and leave it on the site's landing page";
   `-L SITE -s URL` = the same, then that page. One flag, one intent, reads as "log in,
   Safari". `-n` works with it. A second site is added by one entry in the route table
   (`SAFARI_ROUTES`, below) — the CLI shape does not change. Without `-L`, or for a
   site with no Safari route → exit 2 naming the sites that have one.

## Design

### Route table (one registry, agent-login.py)

```python
# site -> landing URL a `-L SITE -s` run leaves Safari on (tp#1643). Adding a
# site here (with its RECIPES entry) is the whole of a new Safari route.
SAFARI_ROUTES: dict[str, str] = {"notion": "https://app.notion.com/"}

@dataclass(frozen=True)
class AgentRoutes:
    safari: bool    # `-L SITE -s` can log Albert's Safari in
    chromium: bool  # an agent can log the shared Chromium in itself

def agent_routes(site: str, row: dict | None = None) -> AgentRoutes:
    safari = site in SAFARI_ROUTES and site in alsafari.RECIPES
    chromium = (
        site in MAIL_CODE_SITES               # headless e-mail code (notion)
        or site in alsafari.MAGIC_LINK_SITES  # claude.ai / console magic link
        or _broker_logs_in(row)               # broker login item usable by agents
    )
    return AgentRoutes(safari, chromium)
```

`_broker_logs_in(row)`: a broker login row (not fill-only) whose state is usable by
agents today (the same predicate the overview already uses for "works for agents";
no new rule). Only `SAFARI_ROUTES`, `MAIL_CODE_SITES`, `MAGIC_LINK_SITES` and the row
decide; the printer and agents.md read `agent_routes()` — never strings of their own.
Expected today: notion ✅ ✅; claude.ai sites ❌ ✅; broker login sites ❌ ✅; Safari-import
sites (anibis …) ❌ ❌ (an agent imports, it does not log in) — see Questions.

### `-L SITE -s [URL]` pipeline (`safari_target_action`)

In order; every stop prints one line with a fixed code, nothing secret:

1. `scheduled()` → exit 2 (unchanged top check of `safari_login_action`).
2. Target: `site in SAFARI_ROUTES` (else exit 2 `no_safari_route`, naming the sites
   that have one). URL = the given one or `SAFARI_ROUTES[site]`; must be `https`, no
   userinfo, host ∈ `RECIPES[site].hosts` (else exit 2 `bad_url`, nothing touched).
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
   - `safari: match` → skip to step 9 (no code mail, no login);
   - `safari: logged_out` → step 7;
   - `safari: mismatch` → exit 2 `wrong_account` (never add a second account);
   - anything else (indeterminate, 75, timeout) → exit 2 / 75, nothing done.
7. **Log Safari in** (only here may a code mail go out):
   - `als.quarantined(site)` → exit 2 (the `-Q` hint), nothing sent;
   - `als.mail_code_lock()` (B1, non-blocking; busy → 75; state dir unwritable → exit 2
     `state_unwritable`) held to the end of the drive;
   - `als.mail_code_cooldown_left()` > 0 → exit 2 `cooldown` ("N s left"); unreadable
     → exit 2 `cooldown` (fail closed);
   - `_drive_safari(site, recipe, env=NOTION_MAIL_ENV, before_trigger=stamp)` — the
     Machine (new window, closed in its `finally`) with B2's hook: the stamp is
     written right BEFORE the "Continue" click; a failed write → `state_unwritable`,
     zero clicks;
   - not ok → `_safari_fail(site, out, …, route="safari-target")` (quarantines after
     a credential step; `needs_albert_*` exit 4; `email_code`, `recipe_stuck` exit 2;
     no retry).
   - ok → `_wait_flush(site, before)` (⚠️ when Safari did not flush within 90 s).
8. **Import** (best effort, the goal is Safari): `_free_check(site)` 0 → "shared
   Chromium already logged in, nothing imported"; definite logged_out /
   wrong_account → `_import_run(site, agent=True)` + `record_check` as today (route
   `safari-login`); an import failure prints ⚠️ with its code and is recorded, the
   run still goes on to step 9. Other check results → ⚠️ "not imported", go on.
9. **Open** `safari.py -o URL -w 20` (new tab in the front window; JSON reply only
   read for rc). rc 0 → `✅ notion: Albert's Safari is logged in — opened
   https://app.notion.com (the workspace home | the given page)`; else exit 2
   `safari_open_failed` (Safari's login state is unchanged by it).
   Exit 0 = Safari logged in AND the page opened.

Lock order: `safari_login_lock` → `mail_code_lock` (both non-blocking past their wait;
the headless `-M` takes only `mail_code_lock` and today's `-L notion` releases
`safari_login_lock` before `-M`) — no cycle.

`-L notion` WITHOUT `-s` is unchanged (headless first; Safari only as fallback).

### `-L SITE -s [URL] -n` (dry run, read-only)

Prints: the target origin (or `bad_url`), the gate, safari.py features incl. `open`,
whether Safari holds a session + `safari fp: <8 hex>`, quarantine, cooldown (shared
reader), the mailbox readiness (`_mail_code_dry_run`), and the next step ("would prove
Safari's session, then open" / "would log Safari in with the e-mail code, then open").
No proof run, no lease, no mail, no Safari call except `--capabilities`/`--status`.

### `browser.py import-safari SITE -P/--prove-only` (B3)

`SAFARI_BUILTIN` sites only (else exit 2): read Safari's cookies (unreadable → exit 2
`no_safari_session`), expected account (`_builtin_expected`; missing → exit 2
`identity_unconfigured`), then under registration + `_interaction_lease("import-safari
SITE -P")` run `_builtin_prove_isolated` and stop. The shared jar is never written
(no `_builtin_replace`, no storage clear, no login event). Result record:
`{"safari": "match|mismatch|logged_out|indeterminate", "phase", "code"}`; exit 0 on
match, else 2 with code `logged_out` / `wrong_account` / `indeterminate`. Output: one
line with the verdict, never a cookie name's value.

### Overview columns (B9)

`print_overview` gets two fixed-width columns after the login name: `Safari` and
`Chromium` (✅ / ❌ from `agent_routes(r["site"], r)`; header and cells padded so the
columns stay aligned — emoji width handled like the status icon column). `-j`: each
row gains `"agent_routes": {"safari": bool, "chromium": bool}`. agents.md: the route
sentence names `-L notion -s` ("Albert says 'log me into notion' → run
`agent-login.py -L notion -s`"), and the Safari-route site list comes from
`SAFARI_ROUTES` (no hard-coded "notion" in the text).

## Boxes

- [ ] B1 `agent_login_state.py`: move the mail-code cooldown helpers out of browser.py
  as `mail_code_lock()` (context manager, True/False/None as `_nmc_lock`),
  `mail_code_cooldown_left(now)` (fail closed, future stamp = full cooldown) and
  `mail_code_stamp(now)` (atomic 0600), with `MAIL_CODE_FILE`, `MAIL_CODE_LOCK`,
  `MAIL_CODE_COOLDOWN_S = 900`; browser.py's `_nmc_*` become thin calls (behaviour
  byte-identical); agent-login.py drops its mirror (`MAIL_CODE_STAMP`,
  `MAIL_CODE_COOLDOWN_S`, `_mail_code_cooldown_left`) and reads the shared one.
  `tests/test_notion_mail_code.py` passes unchanged.
- [ ] B2 `agent_login_safari.py`: `Machine` gains `before_trigger: Callable[[], bool]
  | None = None`, called in `_mail_code` after the e-mail fill and right before the
  trigger click; False → `_end(2, "state_unwritable")`, no click. `_drive_safari`
  (agent-login.py) passes `before_trigger` and a MailReader `env` through (defaults
  unchanged for every other caller). `EMAIL_FILL_JS` / `CODE_FILL_JS` untouched.
- [ ] B3 `bin/browser.py`: `import-safari SITE -P/--prove-only` as in Design (help
  text: "prove Safari's session in a throwaway context; the shared browser is not
  touched").
- [ ] B4 `agent-login.py`: `SAFARI_ROUTES`, `AgentRoutes`, `agent_routes()`,
  `_broker_logs_in()`.
- [ ] B5 `agent-login.py`: `-s/--safari [URL]` argument (`nargs="?"`, `const=""`, only
  with `-L`, else exit 2; conflicts handled like `-L`'s other-flag check ~4733) and the
  step-2 target validation (`no_safari_route`, `bad_url`).
- [ ] B6 `agent-login.py`: `safari_target_action` steps 3-9 (gate, safari.py check,
  lock, `-P` proof, login with shared cooldown + quarantine + `NOTION_MAIL_ENV`,
  flush, best-effort import, `safari.py -o URL`), `_safari_fail(route="safari-target")`.
- [ ] B7 `agent-login.py`: `-L SITE -s [URL] -n` dry run as in Design.
- [ ] B8 tests (unit, no network, no real Safari / Chrome; fakes as in
  `test_ws1b_safari.py` / `test_notion_l_pipeline.py`) in new
  `tests/test_notion_safari_target.py`:
  Safari proof `match` → zero Machine calls, zero mail reads, cooldown file untouched,
  exactly one `safari.py -o <landing>` call, exit 0; with a URL → `-o <that URL>`;
  proof `logged_out` → Machine runs, stamp written before the trigger click (call
  order recorded), import runs when the free check says logged_out and is skipped when
  it says 0, then `-o` → exit 0; no Safari session / unreadable jar → login (why
  recorded); proof `mismatch` → exit 2 `wrong_account`, no Machine; cooldown active →
  exit 2 `cooldown`, no Machine; quarantined → exit 2, no Machine, but a `match` proof
  still opens the page; `mail_code_lock` busy → 75; stamp unwritable → `state_unwritable`,
  zero clicks; gate closed (each code) → exit 3, no safari.py call, no proof;
  `scheduled()` → exit 2; safari.py missing / lacking `open` → exit 3; Machine
  `needs_albert_captcha` → exit 4, no `-o`; code submitted then no sentinel →
  quarantine written once, exit 2, no `-o`; `-o` rc 3 → exit 2 `safari_open_failed`;
  `bad_url` cases (http, foreign host, userinfo, `notion.so.evil.com`) → exit 2 with
  nothing called; `-s` without `-L` / on a site without a route → exit 2;
  MailReader env carries `SDSC_EMAIL_NO_AUTO_AUTH=1`; the code and cookie values never
  appear in stdout/stderr/result/checks files (capsys + file scan); `-n` makes no
  `-P`/Machine/`-o` call. browser.py `-P`: match → exit 0 and `_builtin_replace` /
  storage clear / login event never called; logged_out → 2; non-builtin site → 2.
  `agent_routes`: notion (True, True), a claude.ai site (False, True), a Safari-import
  site (False, False); a fake second `SAFARI_ROUTES` entry flips its Safari cell and
  `-s` accepts it without CLI changes. Overview: columns aligned (equal display width
  per line), `-j` rows carry `agent_routes`. B1: browser.py and agent-login.py read
  the same stamp; B2: `before_trigger` False → no click.
- [ ] B9 `agent-login.py`: overview `Safari` / `Chromium` columns + `-j`
  `agent_routes` + agents.md route sentence from `SAFARI_ROUTES` (Design).
- [ ] B10 docs: README notion row (~586: "`-L notion -s [URL]` logs Albert's Safari in
  (attended) and opens the page"), §"Agents renew…" (~1075: a step "Safari target"
  after step 2 + Guards line "the Safari route shares the 15-min cooldown and the
  quarantine"), the `-L` row ~1644 and the `-s` row, Requirements (safari.py `-o`),
  the overview description (new columns); `agent-login.py` `-h` example
  `./agent-login.py -L notion -s   # "log me into notion": Albert's Safari, left on the
  workspace home (-s URL: that page)`, the `-s` help text, the intro paragraph;
  regenerate agents.md (`agent-login.py -A`) and check the notion line names
  `-L notion -s`. Skill stow source (other repo, needs its own `[commit:
  /Users/albert/obsidian/42-Git/home/mydotfiles]` grant, else the overseer edits):
  `/Users/albert/obsidian/42-Git/home/mydotfiles/dotfiles/claude/.claude/skills/browser-login/SKILL.md`
  line 139 and line 169 — add "Albert says 'log me into notion' / 'open this page in my
  Safari' → `agent-login.py -L notion -s [URL]` (attended: Mac unlocked and in use)".
- [ ] B11 verify + install: `ruff format`, `ruff check`, `mypy`, `uv run pylint` on
  every touched file; targeted pytest (new file + `test_notion_mail_code.py`,
  `test_notion_l_pipeline.py`, `test_ws1b_safari.py`, `test_ws1b_agent_login.py`,
  `test_agent_login.py`) in the foreground; `agent-login.py -h` and `browser.py
  import-safari -h` exit 0. Install into the live checkout atomically (cp to temp name
  - mv, after checking the live files are unchanged since the worktree base); commit
  with the grant the brief carries.
- [ ] B12 LIVE CANARY A (Albert present at the Mac; no logout of anything). Result
  files in a fresh `mktemp -d` (0700).
  1. `agent-login.py -L notion -s -n` → target origin, gate open, Safari holds a
     session, cooldown, next step. Note `safari fp` and the mtime of
     `~/.local/state/agent-login/notion-mail-code.json` (`stat -f %m`, or "absent").
  2. `browser.py import-safari notion -P -R <dir>/prove.json` → expect exit 0,
     `safari: match`. If `logged_out` → Safari is genuinely logged out: go to B13 now
     (Albert is present). `mismatch` / other → stop, report.
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
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run --project /Users/albert/obsidian/42-Git/home/browser-login mypy /Users/albert/obsidian/42-Git/home/browser-login/bin/browser.py /Users/albert/obsidian/42-Git/home/browser-login/agent_login_safari.py /Users/albert/obsidian/42-Git/home/browser-login/agent_login_state.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run --project /Users/albert/obsidian/42-Git/home/browser-login pylint /Users/albert/obsidian/42-Git/home/browser-login/bin/browser.py /Users/albert/obsidian/42-Git/home/browser-login/agent_login_safari.py /Users/albert/obsidian/42-Git/home/browser-login/agent_login_state.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run --project /Users/albert/obsidian/42-Git/home/browser-login pytest -q /Users/albert/obsidian/42-Git/home/browser-login/tests/test_notion_safari_target.py /Users/albert/obsidian/42-Git/home/browser-login/tests/test_notion_mail_code.py /Users/albert/obsidian/42-Git/home/browser-login/tests/test_notion_l_pipeline.py /Users/albert/obsidian/42-Git/home/browser-login/tests/test_ws1b_safari.py /Users/albert/obsidian/42-Git/home/browser-login/tests/test_ws1b_agent_login.py /Users/albert/obsidian/42-Git/home/browser-login/tests/test_agent_login.py
cd /Users/albert/obsidian/42-Git/home/browser-login && git diff --no-ext-diff --no-textconv --stat
```

Each line is `cd <repo> && <argv>` because `tp verify`'s grammar requires exactly that
prefix (`tp plan -f` refuses a block it cannot parse); no `;`, no pipes, no other `&&`,
absolute paths, no live login. Read-only smoke (not in the block, run by B11):
`agent-login.py -h`, `agent-login.py -L notion -s -n`, `browser.py import-safari -h`.
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
  runs → `logged_out` → an unneeded login attempt. Mitigation: the cooldown limits it to
  one code mail per 15 min; `_wait_flush` after our own login.
- **Second account in Safari:** `mismatch` stops before any code (never adds an account).
- **Concurrency with headless `-M`:** shared `mail_code_lock` → one code mail at a time
  across both routes; busy → 75.
- **Opening a page in a tab of the front window** could land in a window Albert uses
  for something else — new tab only, never replaces a tab (safari.py rule).
- **Live-file edits:** worktree + atomic install only (B11).

## Questions for Albert

- extdeps: keep the repo's "no EXTERNAL_DEPS registry" convention (safari.py stays the
  pinned, capability-checked path; README Requirements names `-o`)? Recommendation: yes.
- Overview `Chromium` column: count broker-login sites (usable for agents) as ✅?
  Recommendation: yes — it is a real agent route; Safari-import-only sites stay ❌.
- `-L notion -s` when the Safari login worked but the import into Chromium failed: exit
  0 with ⚠️ (the asked-for Safari page is open)? Recommendation: yes.
