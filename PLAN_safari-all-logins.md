# PLAN: log Albert's Safari in to every agent login on request (tp#1644)

> **Resume here.** Status: planned (Opus) and critiqued by Opus (Codex had no seat at
> round 0), nothing built yet. Next box: B1. Execution order: B1-B5, then B8-B9, B6-B7,
> B10-B11, B12-B13, B14-B15, B16-B17, B18 (overseer decision; the box ids stay).
> Planned against live `HEAD` 94bb6ae (2026-11-04). Work in a worktree
> (`git -C /Users/albert/obsidian/42-Git/home/browser-login worktree add
> /Users/albert/obsidian/42-Git/home/browser-login/.worktrees.noindex/safari-all -b
> safari-all`). `agent-login.py`, `bin/browser.py` and the `agent_login_*.py` /
> `broker/*.py` modules are LIVE (consumers exec them). Each batch installs
> atomically (the B4 path) before its canary. Boxes marked **[Albert]** run only
> with Albert at the Mac. Never open `/logout`, never log anything out.

Parent: PLAN_notion-safari-login.md (tp#1643, done) and PLAN_notion-safari-recipe-fix.md
(tp#1643, done): `SAFARI_ROUTES`, `login_columns()`, `-L SITE -s [URL]`,
`import-safari SITE -P`, the shared mail-code cooldown, the live canary rules.

## Session

Ticket: tp#1644 (depends on tp#1643, resolved)
Session: e46e0832-335c-455b-8cf3-2cc109b8f900 (overseer; ticket from
aafe7b3d-404e-4578-babf-520f38dca367)

## Goal

For every login `agent-login.py` lists, an agent told "log me into SITE" runs
`./agent-login.py -L SITE -s [URL]`. It proves Safari's session, logs Albert's Safari
in when needed (attended), and leaves the logged-in landing page (or URL) open in a
new Safari tab. The overview's Safari column says ✅ for every site that has the
route. A site that cannot have one shows ⛔ plus a fixed reason code, and `-s` on it
exits 2 naming that reason.

## Decisions (overseer, 2026-11-04; requirements, not open)

- Infeasible sites show ⛔ with the reason in `-L SITE -s -n` and in `-j`.
- Admin accounts (listing `privilege` = `admin`) stay ⛔ in Safari.
- mullvad stays ⛔ (no `safari_fill` opt-in). myfritz stays ⛔ while quarantined /
  on demand (no agent `-Q` release).
- edu-ID: every live canary is proof-only (`-O`) unless Albert says go for that run,
  each time. The same applies to the switch chain's edu-ID stage.
- DSM: route only the DSM account Safari already holds; the other one is ⛔.
- Execution order after B1-B5: B8 (SC) first, then B6 (BI), B10, B12, B14, B16.
- OPEN (Albert, B16 only): see `## Questions for Albert`.

## Findings (read before building)

- **Today only notion has the route.** `SAFARI_ROUTES = {"notion": …}`
  (agent-login.py ~1022). `login_columns()` ~1035: Safari = `SAFARI_ROUTES` ∩
  `alsafari.RECIPES`. `safari_target_action` ~4344 refuses everything else with
  `no_safari_route`.
- **The proof step is notion-shaped.** `_safari_proof` ~4434 runs `browser.py
  import-safari SITE -P` (`cmd_prove_safari`). `_prove_safari` (bin/browser.py
  ~16327) accepts only `SAFARI_BUILTIN` (broker/safari_cookies.py ~133: notion, slack,
  openai). The marketplace sites (`SAFARI_SITES` ~85) and the broker sites have no
  throwaway-context proof. A Chromium proof of Galaxus (Akamai) or Ricardo
  (Cloudflare) would read `indeterminate` or `logged_out` falsely.
- **The Safari Machine already proves in Safari (verified in the code).**
  `Machine._loop` (agent_login_safari.py ~1476) checks the sentinel on
  `sentinel_host` BEFORE `_next_step` (~1481). So a live session ends `ok` with zero
  steps. `run()` closes its window in `finally` (~1449). The same loop runs the first
  matching step at once (~1493), so today a proof and a login are ONE run. A
  proof-only mode (`proof_only`, below) is needed wherever a login needs Albert's go.
- **Recipes exist for 9 sites** (agent_login_safari.py ~292): galaxus-de, galaxus,
  anibis, tutti, kleinanzeigen, ricardo (password through the broker's
  `safari_fill`), openai (Google SSO), slack (Google SSO, else e-mail code), notion
  (e-mail code). Every label is UNVERIFIED except the galaxus-de one-page form, the
  tutti identifier page (with its Auth0 captcha) and notion. `Recipe.import_after`
  already exists (~238; read at agent-login.py ~4419; ricardo False).
- **Broker plan resolution exists.** `_safari_plan` (agent-login.py ~4779) takes
  `start_url` / `sentinel` / vault item from the broker listing (`login_url`,
  `logged_in_selector`, `name`) when the recipe leaves them empty. It returns None
  (→ `safari_no_recipe`) when there is no sentinel. What a broker site lacks is a
  `Recipe` entry: hosts, `sentinel_host` and steps.
- **The listing** (`~/.local/state/agent-login/sites.json`, `sites[]`) carries per
  site `login_url`, `check_url`, `logged_in_selector` / `sentinel`, `fill_origins`,
  `safari_fill`, `identity`, `instance`, `privilege`, `multi_account`,
  `same_account_as`, `pre_click`, `username_only`, `no_submit`, `fresh_login`,
  `refused`. It carries NO submit-button label and no "has TOTP" flag, so every
  broker site needs its labels (and whether a TOTP page follows) read once,
  read-only, in Albert's Safari (counts and labels only, no click, no fill).
- **cscs has no sentinel in the listing** (neither `logged_in_selector` nor
  `sentinel`). `_safari_plan` would return None, so its recipe must carry its own
  `sentinel`.
- **Privilege, from the listing (2026-11-04):** `admin`: abs-root, authentik-akadmin,
  **authentik-glensk**, custos-admin, dsm-albert, gitlab-sdsc-admin, navidrome-root,
  runai-admin. `readonly`: dsm-readonly. kavita-admin has no privilege and is the only
  kavita item, so it is routable despite its name.
- **Broker credentials reach Safari only under the broker's safari_fill gates.**
  The item must be opted in (`safari_fill` true) and the origin listed; the call is
  rate-limited and audited, and someone must be at the Mac. TOTP goes the same way
  (`safari.py -O ITEM`). Not opted in: mullvad, authentik-test3 and the refused
  second cloudflare item.
- **Identity proof protocol exists.** broker/identity.py holds the reviewed
  `IDENTITIES` recipes (one fixed same-origin endpoint each), the generic in-page
  `RECIPE_JS` and the challenge digest `sha256(nonce || name)`. The broker issues the
  nonce and judges the answer, so values never reach the client. The in-Safari
  identity read reuses that: `RECIPE_JS` through `safari.py --eval` on the Machine's
  window, with the broker's challenge. It is a broker call (no credential), so
  proof-first runs of multi-account sites DO call the broker.
- **Multi-account sites.** Safari is ONE cookie jar. "One cookie scope in one
  instance holds at most one account" applies to Safari too. `-s` proves WHICH account
  through the identity read, and never adds a second one (`wrong_account`).
- **`*.dom42.space` sites sit behind Cloudflare Access.** Albert's Safari may meet
  the Access interstitial first. Its login is Albert's. `Machine.tab_host` (~1409)
  ends `safari_tab_moved` for any host outside `recipe.hosts`, so the
  `cloudflareaccess.com` stop (`needs_albert_access`, exit 4) must sit in `tab_host`
  BEFORE that hosts check. UNVERIFIED whether Safari meets it: the B11 read decides.
- **Import into the shared Chromium.** `_safari_target_import` imports only when the
  shared Chromium check says definitely logged out (agent-login.py ~4486-4496).
  Broker sites, claude.ai / console and switch have their own Chromium login, so
  their recipes set `import_after=False`.
- **What exists only in the shared Chromium today**: every broker site,
  anthropic / console (magic link in the shared browser; `MAGIC_LINK_SITES`
  agent_login_safari.py ~444) and switch (SSO click on the browser's own edu-ID
  session). The marketplace sites, galaxus, openai and slack are the reverse: Safari
  is their source.

## Inventory (every login `agent-login.py` lists, 2026-11-04)

Kinds: **SC** = Safari-cookie site (recipe, password via broker `safari_fill`);
**BI** = built-in OAuth / mail code (recipe, throwaway proof); **BP** = broker
password (+TOTP when the read finds a TOTP page); **SSO** = IdP chain; **ML** = magic
link; **AO** = Albert-only. The landing URL is the logged-in page (`check_url` of the
listing unless named); the label read of each batch confirms it.

| site | kind | Safari route | landing URL | Chromium-only today | box |
|---|---|---|---|---|---|
| notion | mail code | ✅ done (tp#1643) | https://app.notion.com/ | no | — |
| anibis | SC | feasible; Auth0 captcha likely → exit 4 | https://www.anibis.ch/fr/myads/active | no | B8 |
| tutti | SC | feasible; Auth0 captcha seen (L2) → exit 4 | https://www.tutti.ch/de/myads/active | no | B8 |
| kleinanzeigen | SC | feasible | https://www.kleinanzeigen.de/m-meine-anzeigen.html | no | B8 |
| ricardo | SC, no import | feasible (Safari-only use) | https://www.ricardo.ch/de/my-ricardo/saved/articles/ | no | B8 |
| galaxus | SC, broker no_submit | feasible; reCAPTCHA possible → exit 4 | https://www.galaxus.ch/de/orders | no | B8 |
| galaxus-de | SC, broker no_submit | feasible (one-page form L2) | https://www.galaxus.de/de/orders | no | B8 |
| slack | BI (Google, else mail code) | feasible; Google push / passkey → exit 4 | https://swiss-data-science.slack.com/ | no | B6 |
| openai | BI (Google SSO) | feasible; Google push / passkey → exit 4 | https://chatgpt.com/ | no | B6 |
| abs-albert | BP, multi-account | feasible (identity read) | https://audiobookshelf.dom42.space/audiobookshelf/ | yes | B10 |
| aurral | BP | feasible once its check is green again | https://aurral.dom42.space/ | yes | B10 |
| calibre | BP (`fresh_login`) | feasible | https://calibre.dom42.space/me | yes | B10 |
| homeassistant | BP | feasible | https://ha.dom42.space/ | yes | B10 |
| immich | BP | feasible once its check is green again | https://immich.dom42.space/photos | yes | B10 |
| jellyfin | BP (`pre_click`) | feasible; pre-click as a click step | https://jellyfin.dom42.space/web/#/home | yes | B10 |
| kavita-admin | BP (no privilege, single item) | feasible | https://kavita.dom42.space/home | yes | B10 |
| komga | BP | feasible | https://komga.dom42.space/dashboard | yes | B10 |
| navidrome-albert | BP, multi-account | feasible (identity read) | https://music.dom42.space/app/ | yes | B10 |
| npm-nixos | BP (+TOTP) | feasible | https://nginx-nix.dom42.space/ | yes | B10 |
| npm-raspi | BP | feasible | https://nginx.dom42.space/ | yes | B10 |
| portainer-ds218 | BP | feasible | https://portainer.dom42.space/#!/home | yes | B10 |
| qbittorrent | BP | feasible | https://qbittorrent.dom42.space | yes | B10 |
| stirling | BP | feasible | https://stirling.dom42.space/ | yes | B10 |
| syncthing-nixos | BP | feasible | https://syncthing.dom42.space/ | yes | B10 |
| dsm-readonly / dsm-albert | BP, multi-account | the ONE Safari holds (B11 step 0 identity read); the other ⛔ `second_account`; none held → both ⛔ `not_held` | https://synology.dom42.space/ | yes | B10 |
| welib | BP | feasible | https://welib.org/account | yes | B10 |
| github | BP (+TOTP expected) | feasible; a passkey / push prompt → exit 4 | https://github.com/settings/profile | yes | B12 |
| gitlab-com | BP (+TOTP expected) | feasible | https://gitlab.com/-/user_settings/profile | yes | B12 |
| gitlab-ethz | BP (+TOTP expected) | feasible | https://gitlab.ethz.ch/-/user_settings/profile | yes | B12 |
| gitlab-sdsc-glensk | BP, multi-account | feasible (identity read) | https://gitlab.datascience.ch/-/user_settings/profile | yes | B12 |
| infomaniak | BP (+TOTP expected) | feasible; SMS / app push → exit 4 | https://manager.infomaniak.com | yes | B12 |
| zoho-desk | BP (+TOTP expected) | feasible; OneAuth push → exit 4 | https://desk.zoho.eu/agent | yes | B12 |
| smartsheet | BP | feasible; an e-mail code page → stop (not wired) | https://app.smartsheet.com/b/home | yes | B12 |
| eduid | BP (+TOTP) | feasible; canary `-O` only unless Albert says go | https://eduid.ch/account/organisations/ | yes | B14 |
| switch | SSO click on edu-ID | feasible as a chain: eduid's route, then the SSO click | https://cloud.switch.ch/ | yes | B14 |
| cscs | SSO (Keycloak + TOTP) | feasible; recipe carries its own sentinel; Safari keeps its own localStorage token | https://portal.cscs.ch/profile/ | yes | B14 |
| runai-test3 | SSO (Keycloak custos), multi-account | feasible (identity read) | https://sdsc.run.ai/ | yes | B14 |
| anthropic / console OR anthropic-private / console-private | ML | the pair Albert names (Question Q1); feasible only if the magic link logs in the browser that opens it | https://claude.ai/ , https://console.anthropic.com/ | yes | B16 |
| the other claude.ai / console pair | ML | ⛔ `second_account` (Safari holds one claude.ai account) | — | yes | B16 |
| abs-root, authentik-akadmin, authentik-glensk, custos-admin, gitlab-sdsc-admin, navidrome-root, runai-admin | `privilege` admin | ⛔ `admin_account` | — | yes | B2 |
| authentik-test3 | account unproven, not opted in | ⛔ `account_unproven` | — | yes | B2 |
| google-kindle | Google login (alt instance) | ⛔ `albert_only` (Google push / passkey / captcha; a second Google account) | — | yes | B2 |
| mullvad | account-number login, `safari_fill` false | ⛔ `not_opted_in` (final: no opt-in) | — | yes | B2 |
| cloudflare | item refused; Cloudflare dash = Access team account | ⛔ `refused` (never an Access team session through agents) | — | yes | B2 |
| myfritz | BP, on demand, quarantined | ⛔ `on_demand` (final while quarantined / on demand; no `-Q`) | — | yes | B2 |

Fill-only items are not logins: no row, no Safari route (`safari.py -L` fills them
already).

## Design

### Safari route table (agent-login.py; replaces the bare `SAFARI_ROUTES` dict)

```python
@dataclass(frozen=True)
class SafariRoute:
    landing: str                 # https URL `-s` leaves Safari on
    proof: str                   # "builtin" (import-safari -P) | "in_safari" (Machine sentinel run)
    then: str = ""               # chain: a second route run after this one (switch: eduid first)

SAFARI_ROUTES: dict[str, SafariRoute] = {"notion": SafariRoute("https://app.notion.com/", "builtin"), ...}
SAFARI_INFEASIBLE: dict[str, str] = {"google-kindle": "albert_only", ...}  # fixed reason codes
SAFARI_INFEASIBLE_TEXT: dict[str, str]  # one line per code, value-free
```

- The import decision stays `recipe.import_after` (no second flag). Broker,
  claude.ai / console, switch and cscs recipes set it False.
- The admin rule is DERIVED, not hand-listed: a listing row with
  `privilege == "admin"` is ⛔ `admin_account` unless it has a `SAFARI_ROUTES` entry.
  B2's test asserts that no admin row has one.
- `login_columns()` gains `safari_why: str` ('' when ✅ or simply not built yet;
  the code when ⛔). The overview cell is ✅ / ❌ (not built yet) / ⛔ (infeasible).
  The legend gains "⛔ = Albert's (reason: `-L SITE -s -n`, `-j`
  `login_columns.safari_why`)". `-j` rows carry `safari_why`. agents.md lists the ⛔
  sites in one line with their reasons, so agents never try them.
- `safari_target_action`: a ⛔ site → exit 2 `no_safari_route (<code>)` plus its
  text, `-n` included. A site with neither entry → exit 2 `no_safari_route`, as
  today.
- **`-O/--prove-only`** (new; `-O` is free in agent-login.py's parser), with `-L SITE
  -s`: prove only, never log in. `builtin` → `_safari_proof` alone. `in_safari` →
  `Machine(proof_only=True)`: the sentinel → ok (exit 0, the landing page opened); the
  first page where a recipe step's `when` matches → end `safari_logged_out` (exit 2,
  nothing typed, no broker fill, no code mail); an Albert stop → exit 4 as usual. For a
  chain, `-O` applies to every stage.
- Broker sites: `broker_recipe(row, labels)` builds a `Recipe` from the listing row
  plus a hand-written `BROKER_SAFARI_LABELS[site]` entry: hosts = `fill_origins` +
  `check_url` + `login_url` hosts, `sentinel_host` = the `check_url` host,
  `start_url` = `check_url` (so a live session lands on the sentinel at once),
  `import_after=False`, `identity` = the site when the listing row has one. Sentinel
  and item still come from `_safari_plan`'s listing lookup. The labels entry gives the
  submit labels, the one-page / two-step shape, an `otp` step with its submit label
  when the read found a TOTP page, `pre_click` as a `click` step, and, for a site
  without a listing sentinel (cscs), the `sentinel`. No labels entry → no route (❌),
  never a guessed label.
- Proof `in_safari`: `Machine.run` on `start_url`. A sentinel before any step → ok
  with `steps == 0` ("Safari was logged in, no login"). For rows with a listing
  `identity`, the identity read follows in the same window before it closes:
  `identity.RECIPE_JS` for the item's `IDENTITIES` recipe through `safari.py --eval`
  (an 0600 JS file, never argv), answering the broker's challenge, verdict
  `match / mismatch / unknown`. `mismatch` → exit 2 `wrong_account`; `unknown` → exit
  2 `indeterminate`; nothing typed in either case. A login form → the recipe steps
  (unless `-O`).
- Machine stops: `cloudflareaccess.com` in `tab_host` BEFORE the `recipe.hosts`
  check → `needs_albert_access` (exit 4); a passkey / WebAuthn prompt, an SMS page or
  a push page → the existing `needs_albert_*` codes; a captcha →
  `needs_albert_captcha`.
- Mail-code sites other than notion (slack's fallback, maybe smartsheet): the
  cooldown helpers are already keyed by site (tp#1643 B1). `MAIL_CODE_ENV` gains the
  site's entry, and `_mail_code_safari_drive` is chosen by "the recipe has a
  `mail_code` step", not by `MAIL_CODE_SITES` (which stays the headless `-M` set).
- Chains (`then`): `-L switch -s` runs eduid's route (proof, else login, subject
  to the edu-ID go rule in canaries), then the switch Machine (`start_url` =
  `https://cloud.switch.ch/auth/login`, one `click` step on the single edu-ID button,
  sentinel as browser.py's), then opens the landing page.
- Unchanged: the gate, the safari.py feature check, `safari_login_lock`, the one-run
  no-retry rule, quarantine after a credential step, `bad_url` validation against
  the recipe hosts, `-n` read-only.

## Boxes

- [x] B1 `agent-login.py` + `agent_login_safari.py` (worktree): `SafariRoute`,
  `SAFARI_INFEASIBLE` (+ texts, + the derived `admin_account` rule),
  `login_columns().safari_why`, the ⛔ cell + legend + `-j` + agents.md line, the
  `no_safari_route (<code>)` refusal; `-s` dispatch by `route.proof` (`builtin` →
  today's `_safari_proof`; `in_safari` → `Machine.run`); `-O/--prove-only` and
  `Machine.proof_only`; the in-Safari identity read (identity.RECIPE_JS + broker
  challenge); import only when `recipe.import_after`; mail-code choice by recipe step
  kind; the `needs_albert_access` stop in `tab_host`. notion's behaviour stays
  byte-identical (its tests unchanged). **Check first:** the broker's challenge call
  for an identity proof is reachable from agent-login.py without a browser lease
  (identity_ops / daemon); else the identity read is built in browser.py and B1 adds
  it to the lint lines.
- [x] B2 tests, new `tests/test_safari_routes.py` (no network, no real Safari / Chrome;
  fakes as in `test_notion_safari_target.py`): every listing row lands in exactly
  one of `SAFARI_ROUTES` / `SAFARI_INFEASIBLE` (incl. derived admin) / "not built
  yet" (a table-driven test over a listing snapshot fixture, so a new broker item
  fails the test until it is classified; no admin-privilege row has a route); the ⛔
  cell, the legend, `-j safari_why`, the agents.md ⛔ line; `-s` and `-s -n` on each ⛔
  code → exit 2 with that code, nothing called; `in_safari` proof: sentinel first →
  zero fills, zero broker fills, one `--open landing`, exit 0; login form → the recipe
  steps run, then `--open`; `-O` on a login form → exit 2 `safari_logged_out`, zero
  fills, zero mail reads; identity `mismatch` → exit 2 `wrong_account`, zero fills;
  identity JS goes through a file, never argv; `cloudflareaccess.com` tab → exit 4
  `needs_albert_access` (not `safari_tab_moved`), zero fills; `import_after` false →
  `_import_run` never called; notion's existing suite green.
- [x] B3 docs for the mechanism: README §"Agents renew…" (the `-s` sites now come
  from one table; the ⛔ reasons; `-O`), the `-s` / `-O` help text ("Sites:" from the
  table), the `-h` intro paragraph; regenerate agents.md (`agent-login.py -A`). Skill
  stow source (mydotfiles `dotfiles/claude/.claude/skills/browser-login/SKILL.md`:
  "log me into SITE" → `-L SITE -s`) needs its own `[commit: …/mydotfiles]` grant,
  else the overseer edits it.
- [x] B4 verify + install of B1-B3: ruff format / check, mypy, `uv run pylint` on
  every touched file, the Verification block against the worktree root; install
  as in PLAN_notion-safari-recipe-fix.md B3 (`<base>` = live HEAD at worktree
  creation; unchanged-since-base check; backups in
  `~/.local/state/agent-login/bak-1644/`; module → script order, `cp -p` + `mv`;
  live `-h` smokes; commit from live with explicit paths). Every later batch box
  (B5, B7, B9, B11, B13, B15, B17) reuses this install path for its own files.
  ↳ evidence 2026-11-04: B1-B3 installed into live at e53ec8c 2026-11-04 16:07 (unchanged-since-base 75b829a check, backups bak-1644, module->script cp -p + mv); live status clean; worktree ruff/mypy/pylint + 6 target test files green; live -h exit 0; live pytest test_safari_routes/notion_safari_target/ws1b_safari/notion_s…
- [x] B5 **[Albert]** LIVE CANARY of the mechanism (no login): `-L notion -s -O` and
  `-L notion -s` still exit 0 with no code mail (cooldown mtime unchanged);
  `-L google-kindle -s` and `-L abs-root -s` → exit 2 `no_safari_route (albert_only |
  admin_account)`; the overview shows ⛔ on every infeasible row and ✅ only on notion.
  ↳ evidence 2026-11-04: live canary 2026-11-04 at 73b249b: -L notion -s -O exit 0 and -L notion -s exit 0 (proof ok, no login, app.notion.com opened in Safari twice, landing on the logged-in renku page); notion-mail-code.json mtime 14:38:54 unchanged; google-kindle -s exit 2 no_safari_route (albert_only); abs-root and aut…

Execution order from here: B8-B9 first, then B6-B7 (overseer decision).

- [x] B8 batch SC (runs FIRST after B5): `SAFARI_ROUTES` entries for anibis, tutti,
  kleinanzeigen, galaxus, galaxus-de (`in_safari`; recipe `import_after` True) and
  ricardo (`in_safari`; recipe `import_after` False), landings as in the Inventory;
  `start_url` of each recipe → its landing page (a live session then shows the
  sentinel at once). Each recipe gains a sentinel (from the listing's
  `logged_in_selector`, the same one the broker proves with). Tests: proof-first
  sentinel → zero fills; `-O` on a login form → `safari_logged_out`; a login form →
  `safari.py -L ITEM -G auto` fills, `--expect-host` = the IdP host every time; tutti /
  anibis captcha page → exit 4 and no submit; galaxus `no_submit` is the broker's rule
  only (Safari submits; assert the broker headless path is untouched); ricardo → no
  `_import_run`.
- [ ] B9 **[Albert]** LIVE CANARY SC, then install (B4 path) before it. Read-only
  first: one label probe per IdP login page Safari shows (counts and labels only,
  as in the notion fix Findings 3); fix the labels in B8's worktree when a
  probe disagrees, then re-test. Then per site `-L SITE -s -O` (expect ok: Safari
  holds all six sessions today), then `-L SITE -s`. A password login only on a site
  where `-O` said `safari_logged_out`; one attempt; a captcha → Albert solves it, no
  retry; a quarantine → report, never `-Q` it yourself.
- [ ] B6 batch BI (after B9): `SAFARI_ROUTES` entries for slack (`builtin`, landing
  `https://swiss-data-science.slack.com/`; mail-code fallback with
  `MAIL_CODE_ENV["slack"]` and the shared per-site cooldown `slack-mail-code.json`)
  and openai (`builtin`, landing `https://chatgpt.com/`). Tests in
  `tests/test_safari_routes.py`: proof `match` → only `--open`; `logged_out` → the
  Google steps; `-O` + `logged_out` → exit 2, no steps; the Google chooser picks the
  expected account only (identity from `_builtin_expected`); slack's mail-code
  fallback stamps before the trigger, no-trigger mode inside the cooldown; a Google
  push / passkey page → exit 4. **Check first:** slack's `d` cookie proof works with
  `import-safari slack -P` (the `localConfig_v2` storage part of
  `SAFARI_BUILTIN_STORAGE` is needed by the import, not by the proof?).
- [ ] B7 **[Albert]** LIVE CANARY BI, then install (B4 path) before it. Per site:
  `-L SITE -s -n`; `-L SITE -s -O` (expect `match`); `-L SITE -s` → exit 0, the
  landing page open, Albert confirms the account. A login run only when `-O` said
  `logged_out`, never forced. Slack's e-mail code: one attempt per code mail, respect
  the 15-min cooldown, no retry. Exit 4 (Google push / passkey) → Albert approves in
  that window, no retry.
- [ ] B10 batch BP self-hosted (`*.dom42.space`, welib, the DSM account per B11
  step 0): `broker_recipe()` + `BROKER_SAFARI_LABELS` entries from a read-only probe
  of each login page in Albert's Safari (labels, one-page vs two-step, TOTP page). The
  probe runs ONLY with Albert present: it is a step of B11, and B10's code lands with
  an empty labels table until then. `SAFARI_ROUTES` entries (`in_safari`). Tests: a
  synthetic listing row + labels → the expected `Recipe` (hosts, start_url =
  check_url, sentinel_host, import_after False); no labels → no route; `pre_click` → a
  click step; an Access interstitial → exit 4; TOTP → `safari.py -O ITEM` after the
  password step, never before; multi-account rows (abs-albert, navidrome-albert, DSM)
  → identity `mismatch` → exit 2 `wrong_account`; the DSM pair: exactly one routed,
  the other ⛔ `second_account` (or both ⛔ `not_held`).
- [ ] B11 **[Albert]** label read + LIVE CANARY BP self-hosted: (0) DSM: one
  `-L dsm-readonly -s -O` style identity read of Safari's DSM session (no login),
  which decides which DSM item is routed (the other ⛔ `second_account`; no session →
  both ⛔ `not_held`, no DSM login; Safari holds dsm-albert → stop and ask Albert, see
  Q2); (1) the read-only label probe per site (no click, no fill); (2) the labels
  committed through the worktree + B4 install; (3) per site `-L SITE -s -O`, then
  `-L SITE -s`. Most are logged in in Safari already → proof-first ok. A real login
  only where `-O` said `safari_logged_out`; one attempt each; the broker rate limit
  and cooldowns are respected (a `rate_limited` → stop, no retry).
- [ ] B12 batch BP SaaS with TOTP: github, gitlab-com, gitlab-ethz,
  gitlab-sdsc-glensk, infomaniak, zoho-desk, smartsheet. Same mechanism as B10, plus
  the identity read for the multi-account gitlab-sdsc-glensk and per-site Albert
  stops (GitHub passkey / "GitHub Mobile" push, Infomaniak SMS / app, Zoho OneAuth
  push, a Smartsheet e-mail code page → stop `email_code_unwired`, exit 2: no code
  mail is sent by a route that does not know the sender). Tests as B10, plus the
  identity `mismatch` → exit 2 `wrong_account`.
- [ ] B13 **[Albert]** label read + LIVE CANARY BP SaaS (as B11). A TOTP code is used
  once (`safari.py -O` waits for a fresh window); a push / passkey prompt → exit 4,
  Albert approves in that window, no retry.
- [ ] B14 batch SSO: eduid (BP + TOTP on login.eduid.ch), switch (`then` chain
  eduid → SSO click), cscs (Keycloak + TOTP; its `BROKER_SAFARI_LABELS` entry carries
  the `sentinel` because the listing has none; Safari keeps its own localStorage
  token, no import), runai-test3 (custos Keycloak, identity read). authentik-glensk is
  NOT here (`privilege` admin → ⛔). Tests: the chain runs eduid's proof first and
  never types on `cloud.switch.ch`; `-O` on the chain stops at the first stage that
  needs a login; a live edu-ID session → zero fills on both; cscs: `_safari_plan`
  resolves a Plan (no `safari_no_recipe`) and `-s` never calls the broker's bundle /
  token path; identity `mismatch` on runai → exit 2.
- [ ] B15 **[Albert]** label read + LIVE CANARY SSO (as B11; the cscs sentinel is read
  here). edu-ID and the switch chain: `-O` only. A real `-L eduid -s` / `-L switch -s`
  runs only after `-O` said `safari_logged_out` AND Albert said go for that run.
- [ ] B16 batch ML (the claude.ai / console pair Albert names in Q1; the other pair ⛔
  `second_account`). Until Q1 is answered, B16 builds the mechanism with neither pair
  routed. **Check first, read-only:** does the claude.ai / console magic link log in
  whichever browser opens it, or only the one that requested it (a code page
  instead)? If the latter, the Safari route requests it in Safari (e-mail field +
  "Continue with email" in the Machine window) and opens the link in THAT window by an
  `-e` JS file (0600, `location.assign`), never on a command line (the link is a
  secret). If neither works → ⛔ `albert_only` with that reason. Proof `in_safari` with
  the identity read ("logged in as …"). No import (the shared Chromium has its own
  magic-link login). Mail: the shared per-site cooldown, `MAIL_CODE_ENV`, link mail
  archived after use. Tests as B6.
- [ ] B17 **[Albert]** LIVE CANARY ML (as B7): `-O` first; a link login only when `-O`
  said `safari_logged_out`; one link mail per attempt, the cooldown kept.
- [ ] B18 docs close-out: README's site rows (one sentence per batch: "`-L SITE -s`
  logs Albert's Safari in and opens <landing>"), the ⛔ list with reasons, the
  "not proven live yet" wording for any batch whose canary did not run a real login;
  regenerate agents.md; the overview shows ✅ on every built row and ⛔ on the rest.
  Then the Verification block, and the overseer ticks.

## Verification

```
cd /Users/albert/obsidian/42-Git/home/browser-login && ruff format --check /Users/albert/obsidian/42-Git/home/browser-login/agent-login.py /Users/albert/obsidian/42-Git/home/browser-login/agent_login_safari.py /Users/albert/obsidian/42-Git/home/browser-login/tests/test_safari_routes.py
cd /Users/albert/obsidian/42-Git/home/browser-login && ruff check /Users/albert/obsidian/42-Git/home/browser-login/agent-login.py /Users/albert/obsidian/42-Git/home/browser-login/agent_login_safari.py /Users/albert/obsidian/42-Git/home/browser-login/tests/test_safari_routes.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run --project /Users/albert/obsidian/42-Git/home/browser-login mypy /Users/albert/obsidian/42-Git/home/browser-login/agent-login.py /Users/albert/obsidian/42-Git/home/browser-login/agent_login_safari.py /Users/albert/obsidian/42-Git/home/browser-login/tests/test_safari_routes.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run --project /Users/albert/obsidian/42-Git/home/browser-login pylint /Users/albert/obsidian/42-Git/home/browser-login/agent-login.py /Users/albert/obsidian/42-Git/home/browser-login/agent_login_safari.py /Users/albert/obsidian/42-Git/home/browser-login/tests/test_safari_routes.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run --project /Users/albert/obsidian/42-Git/home/browser-login pytest -q /Users/albert/obsidian/42-Git/home/browser-login/tests/test_safari_routes.py /Users/albert/obsidian/42-Git/home/browser-login/tests/test_notion_safari_target.py /Users/albert/obsidian/42-Git/home/browser-login/tests/test_notion_safari_recipe.py /Users/albert/obsidian/42-Git/home/browser-login/tests/test_ws1b_safari.py /Users/albert/obsidian/42-Git/home/browser-login/tests/test_ws1b_agent_login.py /Users/albert/obsidian/42-Git/home/browser-login/tests/test_agent_login.py
cd /Users/albert/obsidian/42-Git/home/browser-login && ./agent-login.py -h
```

Each line is `cd <repo> && <argv>` (`tp verify` grammar); no live login. The block is
deliberately NOT strict-eligible: the claims it checks (the route table, `-O`, the
derived ⛔ rule, the identity read) are only provable by the new tests, mypy and
pylint, which the strict allowlist excludes. The block checks the LIVE files
(post-install); B4 and every batch box run the same commands against the worktree
root before their install. A batch that touches `bin/browser.py` or broker modules
(B1's identity check-first, B6 if the slack proof needs it) adds them to the lint
lines. Read-only smoke (not in the block): `./agent-login.py -L SITE -s -n` per site of
the batch. Full suite: skipped unless a touched file's neighbours fail.

## Live canary rules (every **[Albert]** box)

- Albert is at the Mac for the whole box; the gate is open; result files go in a
  fresh `mktemp -d` (0700).
- `-n` first, then `-O` (the proof), then `-s`. A real login only when `-O` says
  Safari is GENUINELY logged out. Never forced by a logout: the agent never opens
  `/logout`, never clicks a log-out control, and logs nothing out in Safari or the
  shared Chromium.
- edu-ID (and the switch chain): `-O` only, unless Albert says go for that one run.
- One attempt per code / link mail; the 15-min per-site cooldown is respected; no
  retry after phase `submit` / `unknown`; broker `rate_limited` / cooldown → stop.
- Exit 4 → Albert finishes in that window by hand, no retry. A quarantine → report,
  never `-Q` it yourself. `recipe_stuck` → read `stuck` / `stuck_host`, report (a
  finding, not a bug hunt in place).
- Label probes are read-only JS reads (counts and labels only; no click, no fill, no
  navigation), and run on a tab Albert has open or on one the probe opened with
  `-o -M` and closes with `-C`.

## Risks

- **Unverified labels on ~30 login pages:** each costs one read-only probe with Albert
  present; a wrong label only stops the run (`recipe_stuck`), nothing is typed.
- **Broker `safari_fill` rate limit:** a batch canary of 15 sites could hit it, so
  spread the logins. Proof-first runs make no broker FILL call; multi-account sites
  make one identity-challenge call each.
- **Cloudflare Access in Safari:** unknown until B11's read; the stop is exit 4.
- **Second-account risk:** identity reads on every multi-account row; admin
  (`privilege` admin) rows stay ⛔; the DSM pair routes only what Safari holds.
- **Live-file edits:** worktree + ordered atomic install with backups per batch (B4).

## Open points

- Q1 and Q2 below. B16 may end in ⛔ for claude.ai / console.

## Questions for Albert

- Q1 (B16 only, does not block B1-B15): which claude.ai / console account does
  Albert's Safari hold, work (`anthropic` / `console`) or private
  (`anthropic-private` / `console-private`)? The named pair gets the route; the other
  pair gets ⛔ `second_account`. Recommendation: the work pair, because the agent
  logins use it by default.
- Q2 (B11 step 0, only if it happens): if Safari's DSM session turns out to be
  `dsm-albert` (privilege admin), may it be routed as the one DSM account (the DSM
  decision), or does the admin rule win and both DSM rows stay ⛔? Recommendation:
  admin rule wins (both ⛔), the safer reading.

## Debate outcome (Opus adversary)

Critic: Opus (the debate subagent; Codex round 0 refused `debate_seat_unknown`),
2026-11-04, 1 round.

1. [blocker] The batch order contradicted the overseer's decision. Accepted: an
   execution-order line; B8/B9 are listed before B6/B7.
2. [blocker] An in_safari proof could not stop before the login, so the edu-ID go
   rule and the canary rule could not be carried out. Accepted: `-O/--prove-only` and
   `Machine.proof_only`; every canary runs `-O` first.
3. [major] Identity probes were invented per site, although the reviewed protocol
   exists (broker/identity.py), and it calls the broker. Accepted: reuse RECIPE_JS
   with the broker challenge; Risks corrected.
4. [major] Admin accounts were picked by name, not by `privilege`, and
   authentik-glensk is admin. Accepted: a derived `admin_account` rule;
   authentik-glensk is ⛔, kavita-admin is routed.
5. [major] The DSM row contradicted the decision. Accepted: B11 step 0's identity
   read decides; Q2 covers the admin edge.
6. [major] cscs has no listing sentinel, so `_safari_plan` returns None. Accepted:
   its labels entry carries the sentinel; a test checks it.
7. [major] Rows pointed to a missing Questions section, and the decisions are now
   taken. Accepted: final ⛔ for mullvad and myfritz; a Questions section with Q1/Q2.
8. [minor] `SafariRoute.import_after` duplicated `Recipe.import_after`. Accepted:
   the field is dropped.
9. [minor] B1's check (a) was already answered by the code (sentinel before
   `_next_step`; `_safari_plan` listing lookup). Accepted: written in as Findings.
10. [minor] A cloudflareaccess.com host would end `safari_tab_moved` in `tab_host`.
    Accepted: the stop goes in `tab_host` before the hosts check, with a test.
11. [minor] It was unstated why the Verification block is not strict. Accepted: one
    sentence.
