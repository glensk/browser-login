# PLAN: log Albert's Safari in to every agent login on request (tp#1644)

> **Resume here.** Status: planned (Opus), not debated, nothing built. Next box: B1.
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

## Findings (read before building)

- **Today only notion has the route.** `SAFARI_ROUTES = {"notion": …}`
  (agent-login.py ~1022). `login_columns()` ~1035: Safari = `SAFARI_ROUTES` ∩
  `alsafari.RECIPES`. `safari_target_action` ~4344 refuses everything else with
  `no_safari_route`.
- **The proof step is notion-shaped.** `_safari_proof` ~4434 runs `browser.py
  import-safari SITE -P` (`cmd_prove_safari`). That works only for `SAFARI_BUILTIN`
  (broker/safari_cookies.py ~133: notion, slack, openai, each with an identity
  probe: `_slack_identity` ~15988, `_openai_identity` ~15998, `_notion_identity`
  ~16017). The marketplace sites (`SAFARI_SITES` ~85) and the broker sites have no
  throwaway-context proof. A Chromium proof of Galaxus (Akamai) or Ricardo
  (Cloudflare blocks the automated browser) would read `indeterminate` or
  `logged_out` falsely.
- **The Safari Machine already proves in Safari.** `Machine.run` opens
  `recipe.start_url` in a new window, reads the detector each poll, and ends ok
  with zero steps when the sentinel shows before any step matches. That is the
  "Safari's session was live" case of tp#1643 step 7. A run with no credential step
  is therefore a value-free in-Safari proof. A run that meets the login form goes
  straight on into the login, which is what `-s` wants anyway.
- **Recipes exist for 9 sites** (agent_login_safari.py ~292): galaxus-de, galaxus,
  anibis, tutti, kleinanzeigen, ricardo (password through the broker's
  `safari_fill`, else the Vaultwarden tab), openai (Google SSO), slack (Google SSO,
  else e-mail code), notion (e-mail code). Every label is UNVERIFIED except the
  galaxus-de one-page form, the tutti identifier page (with its Auth0 captcha) and
  notion.
- **Broker sites have no recipe.** The `Recipe` docstring promises that a
  broker-backed site's start page, sentinel and item "come from the broker listing
  unless set here". No code synthesises one yet. The listing snapshot
  (`~/.local/state/agent-login/sites.json`) carries per site `login_url`,
  `check_url`, `logged_in_selector` / `sentinel`, `fill_origins`, `safari_fill`,
  `identity`, `instance`, `privilege`, `multi_account`, `pre_click`,
  `username_only`, `no_submit` and `fresh_login`. It carries NO submit-button
  label and no "has TOTP" flag. safari.py `-L/-O … -S TEXT` needs the label, and a
  submit is never a guess. So every broker site needs its labels (and whether a
  TOTP page follows) read once, read-only, in Albert's Safari, as the notion fix
  did (counts and labels only, no click, no fill).
- **Broker credentials reach Safari only under the broker's safari_fill gates.**
  The item must be opted in (`safari_fill` true), the origin must be listed, the
  call is rate-limited and audited, and someone must be at the Mac. TOTP goes the
  same way (`safari.py -O ITEM`). Opted in today: every broker login item except
  mullvad, authentik-test3 and the refused second cloudflare item.
- **Multi-account sites.** Safari is ONE cookie jar. The repo rule "one cookie scope
  in one instance holds at most one account" applies to Safari too: Safari can hold
  only one of abs-albert / abs-root, gitlab-sdsc-glensk / -admin, navidrome-albert /
  -root, dsm-albert / dsm-readonly, authentik-*, runai-test3 / runai-admin /
  custos-admin, and only one of anthropic / anthropic-private and console /
  console-private (the same claude.ai / console origins). `-s` must prove WHICH
  account (identity) and never add a second one (the notion rule `wrong_account`).
- **`*.dom42.space` sites sit behind Cloudflare Access** (the shared Chromium uses a
  per-host PAC and must never hold an Access team session). Albert's Safari may
  meet the Access interstitial first. Its login is Albert's: the Machine has to stop
  on `cloudflareaccess.com` with a fixed `needs_albert_access` code (exit 4), and
  never type anything there. This is UNVERIFIED: B10 reads it read-only.
- **Import into the shared Chromium.** `-s` imports (best effort) only for sites
  whose shared-Chromium session normally comes FROM Safari: `SAFARI_SITES` with
  `import_after`, plus `SAFARI_BUILTIN`. Broker sites, claude.ai / console and
  switch have their own Chromium login, so `-s` never imports for them. An import
  would replace a working broker session with Safari's copy.
- **What exists only in the shared Chromium today** (no Safari route, no recipe):
  every broker site, anthropic / console (magic link in the shared browser) and
  switch (SSO click on the browser's own edu-ID session). The marketplace sites,
  galaxus, openai and slack are the reverse: Safari is their source.

## Inventory (every login `agent-login.py` lists, 2026-11-04)

Kinds: **SC** = Safari-cookie site (recipe, password via broker `safari_fill`);
**BI** = built-in OAuth / mail code (recipe, throwaway proof); **BP** = broker
password (+TOTP when the read finds a TOTP page); **SSO** = IdP chain; **ML** = magic
link; **AO** = Albert-only. "Chromium-only" = the session exists only in the shared
Chromium today. The landing URL is the logged-in page (`check_url` of the listing
unless named); B10/B12/B14/B16 confirm each one by the read-only label read.

| site | kind | Safari route | landing URL | Chromium-only today | box |
|---|---|---|---|---|---|
| notion | mail code | ✅ done (tp#1643) | https://app.notion.com/ | no | — |
| slack | BI (Google, else mail code) | feasible; Google push / passkey → exit 4 | https://swiss-data-science.slack.com/ | no | B6 |
| openai | BI (Google SSO) | feasible; Google push / passkey → exit 4 | https://chatgpt.com/ | no | B6 |
| anibis | SC | feasible; Auth0 captcha likely → exit 4 | https://www.anibis.ch/fr/myads/active | no | B8 |
| tutti | SC | feasible; Auth0 captcha seen (L2) → exit 4 | https://www.tutti.ch/de/myads/active | no | B8 |
| kleinanzeigen | SC | feasible | https://www.kleinanzeigen.de/m-meine-anzeigen.html | no | B8 |
| ricardo | SC, no import | feasible (Safari-only use) | https://www.ricardo.ch/de/my-ricardo/saved/articles/ | no | B8 |
| galaxus | SC, broker no_submit | feasible; reCAPTCHA possible → exit 4 | https://www.galaxus.ch/de/orders | no | B8 |
| galaxus-de | SC, broker no_submit | feasible (one-page form L2) | https://www.galaxus.de/de/orders | no | B8 |
| abs-albert | BP | feasible (default account only) | https://audiobookshelf.dom42.space/audiobookshelf/ | yes | B10 |
| aurral | BP | feasible once its check is green again | https://aurral.dom42.space/ | yes | B10 |
| calibre | BP (`fresh_login`) | feasible | https://calibre.dom42.space/me | yes | B10 |
| homeassistant | BP | feasible | https://ha.dom42.space/ | yes | B10 |
| immich | BP | feasible once its check is green again | https://immich.dom42.space/photos | yes | B10 |
| jellyfin | BP (`pre_click`) | feasible; pre-click as a click step | https://jellyfin.dom42.space/web/#/home | yes | B10 |
| kavita-admin | BP | feasible | https://kavita.dom42.space/home | yes | B10 |
| komga | BP | feasible | https://komga.dom42.space/dashboard | yes | B10 |
| navidrome-albert | BP | feasible (default account only) | https://music.dom42.space/app/ | yes | B10 |
| npm-nixos | BP (+TOTP) | feasible | https://nginx-nix.dom42.space/ | yes | B10 |
| npm-raspi | BP | feasible | https://nginx.dom42.space/ | yes | B10 |
| portainer-ds218 | BP | feasible | https://portainer.dom42.space/#!/home | yes | B10 |
| qbittorrent | BP | feasible | https://qbittorrent.dom42.space | yes | B10 |
| stirling | BP | feasible | https://stirling.dom42.space/ | yes | B10 |
| syncthing-nixos | BP | feasible | https://syncthing.dom42.space/ | yes | B10 |
| dsm-readonly | BP, multi-account | see Questions (which DSM account Safari holds) | https://synology.dom42.space/ | yes | B10 or ⛔ |
| welib | BP | feasible | https://welib.org/account | yes | B10 |
| github | BP (+TOTP expected) | feasible; a passkey / push prompt → exit 4 | https://github.com/settings/profile | yes | B12 |
| gitlab-com | BP (+TOTP expected) | feasible | https://gitlab.com/-/user_settings/profile | yes | B12 |
| gitlab-ethz | BP (+TOTP expected) | feasible | https://gitlab.ethz.ch/-/user_settings/profile | yes | B12 |
| gitlab-sdsc-glensk | BP, multi-account | feasible (default account only) | https://gitlab.datascience.ch/-/user_settings/profile | yes | B12 |
| infomaniak | BP (+TOTP expected) | feasible; SMS / app push → exit 4 | https://manager.infomaniak.com | yes | B12 |
| zoho-desk | BP (+TOTP expected) | feasible; OneAuth push → exit 4 | https://desk.zoho.eu/agent | yes | B12 |
| smartsheet | BP | feasible; an e-mail code page → stop (not wired) | https://app.smartsheet.com/b/home | yes | B12 |
| eduid | BP (+TOTP) | feasible; Albert's primary federated identity | https://eduid.ch/account/organisations/ | yes | B14 |
| switch | SSO click on edu-ID | feasible as a chain: eduid's Safari route, then the SSO click | https://cloud.switch.ch/ | yes | B14 |
| cscs | SSO (Keycloak + TOTP) | feasible; the portal token is localStorage, Safari keeps its own | https://portal.cscs.ch/profile/ | yes | B14 |
| runai-test3 | SSO (Keycloak custos), multi-account | feasible (default account only) | https://sdsc.run.ai/ | yes | B14 |
| authentik-glensk | BP on authentik, multi-account | feasible once its check is green again | https://auth.dev.renku.ch/if/user/ | yes | B14 |
| anthropic / console | ML | feasible only if the magic link logs in the browser that opens it (check first) | https://claude.ai/ , https://console.anthropic.com/ | yes | B16 |
| anthropic-private / console-private | ML | ⛔ `second_account` (Safari holds one claude.ai account) | — | yes | B2 |
| abs-root, authentik-akadmin, custos-admin, dsm-albert, gitlab-sdsc-admin, navidrome-root, runai-admin | admin accounts | ⛔ `admin_account` (never a second account of the site in Albert's Safari; their own instances) | — | yes | B2 |
| authentik-test3 | account unproven, not opted in | ⛔ `account_unproven` | — | yes | B2 |
| google-kindle | Google login (alt instance) | ⛔ `albert_only` (Google push / passkey / captcha; a second Google account) | — | yes | B2 |
| mullvad | account-number login, `safari_fill` false | ⛔ `not_opted_in` (needs `broker-add.py mullvad -Y` first; see Questions) | — | yes | B2 |
| cloudflare | item refused; Cloudflare dash = Access team account | ⛔ `refused` (never an Access team session through agents) | — | yes | B2 |
| myfritz | BP, on demand, quarantined | ⛔ `on_demand` while quarantined (feasible after `-Q`, see Questions) | — | yes | B2 |

Fill-only items (219) are not logins: no row, no Safari route (`safari.py -L` fills
them already).

## Design

### Safari route table (agent-login.py; replaces the bare `SAFARI_ROUTES` dict)

```python
@dataclass(frozen=True)
class SafariRoute:
    landing: str                 # https URL `-s` leaves Safari on
    proof: str                   # "builtin" (import-safari -P) | "in_safari" (Machine sentinel run)
    import_after: bool           # best-effort import into the shared Chromium afterwards
    then: str = ""               # chain: a second route run after this one (switch: eduid first)

SAFARI_ROUTES: dict[str, SafariRoute] = {"notion": SafariRoute("https://app.notion.com/", "builtin", True), ...}
SAFARI_INFEASIBLE: dict[str, str] = {"google-kindle": "albert_only", ...}  # fixed reason codes
SAFARI_INFEASIBLE_TEXT: dict[str, str]  # one line per code, value-free
```

- `login_columns()` gains `safari_why: str` ('' when ✅ or simply not built yet;
  the code when ⛔). The overview cell is ✅ / ❌ (not built yet) / ⛔ (infeasible).
  The legend gains "⛔ = Albert's (reason: `-L SITE -s -n`, `-j`
  `login_columns.safari_why`)". `-j` rows carry `safari_why`. agents.md lists the ⛔
  sites in one line with their reasons, so agents never try them.
- `safari_target_action`: a ⛔ site → exit 2 `no_safari_route (<code>)` plus its
  text. A site without either entry → exit 2 `no_safari_route`, as today.
- Broker sites: `broker_recipe(row, labels)` builds a `Recipe` from the listing
  row (hosts = `fill_origins` + `check_url` + `login_url` hosts, `start_url` =
  `check_url`, so a live session lands on the sentinel at once, `sentinel` =
  `logged_in_selector`, `sentinel_host` = the `check_url` host) plus a hand-written
  `BROKER_SAFARI_LABELS[site]` entry. That entry gives the submit labels, the
  one-page / two-step shape, an `otp` step with its submit label when the read
  found a TOTP page, and `pre_click` as a `click` step. No labels entry → no route
  (❌), never a guessed label.
- Proof `in_safari`: `Machine.run` on `start_url` with a new `proof_first=True`. A
  sentinel before any step → ok with `steps == 0`, which is "Safari was logged in,
  no login". For sites with a listing `identity`, an identity read follows in the
  same window before it closes (a value-free `match / mismatch / unknown` from a
  per-site JS probe; `mismatch` → exit 2 `wrong_account`, `unknown` → exit 2
  `indeterminate`, nothing typed). A login form → the normal recipe steps.
- Machine stops (agent_login_safari.py detector): `cloudflareaccess.com` host →
  `needs_albert_access` (exit 4); a passkey / WebAuthn prompt, an SMS page or a
  push page → the existing `needs_albert_*` codes; a captcha → `needs_albert_captcha`.
- Mail-code sites other than notion (slack's fallback, maybe smartsheet): the
  cooldown helpers are already keyed by site (tp#1643 B1). `MAIL_CODE_ENV` gains the
  site's entry, and `_mail_code_safari_drive` is chosen by "the recipe has a
  `mail_code` step", not by `MAIL_CODE_SITES` (which stays the headless `-M` set).
- Chains (`then`): `-L switch -s` runs eduid's route (proof, else login), then
  the switch Machine (`start_url` = `https://cloud.switch.ch/auth/login`, one
  `click` step on the single edu-ID button, sentinel as browser.py's), then opens
  the landing page.
- Unchanged: the gate, the safari.py feature check, `safari_login_lock`, the one-run
  no-retry rule, quarantine after a credential step, `bad_url` validation against
  the recipe hosts, `-n` read-only.

## Boxes

- [ ] B1 `agent-login.py` + `agent_login_safari.py` (worktree): `SafariRoute`,
  `SAFARI_INFEASIBLE` (+ texts), `login_columns().safari_why`, the ⛔ cell + legend +
  `-j` + agents.md line, the `no_safari_route (<code>)` refusal; `-s` dispatch by
  `route.proof` (`builtin` → today's `_safari_proof`; `in_safari` → `Machine.run`
  with `proof_first`); import only when `route.import_after`; mail-code choice by
  recipe step kind; the `needs_albert_access` detector stop. notion's behaviour stays
  byte-identical (its tests unchanged). **Check first:** (a) does `Machine.run`
  already end ok on a sentinel with zero steps for a non-mail-code recipe
  (`_loop` order: sentinel before `_next_step`)? (b) safari.py's `--close` of the
  Machine window after a proof-only run leaves no stray tab.
- [ ] B2 tests, new `tests/test_safari_routes.py` (no network, no real Safari / Chrome;
  fakes as in `test_notion_safari_target.py`): every inventory row lands in exactly
  one of `SAFARI_ROUTES` / `SAFARI_INFEASIBLE` / "not built yet" (a table-driven test
  over the listing snapshot fixture, so a new broker item fails the test until it is
  classified); the ⛔ cell, the legend, `-j safari_why`, the agents.md ⛔ line; `-s` on
  each ⛔ code → exit 2 with that code, nothing called; `in_safari` proof: sentinel
  first → zero fills, zero broker calls, one `-o landing`, exit 0; login form → the
  recipe steps run, then `-o`; identity `mismatch` → exit 2 `wrong_account`, zero
  fills; `cloudflareaccess.com` → exit 4 `needs_albert_access`, zero fills;
  `import_after` false → `_import_run` never called; notion's existing suite green.
- [ ] B3 docs for the mechanism: README §"Agents renew…" (the `-s` sites now come
  from one table; the ⛔ reasons), the `-s` help text ("Sites:" from the table), the
  `-h` intro paragraph; regenerate agents.md (`agent-login.py -A`). Skill stow source
  (mydotfiles `dotfiles/claude/.claude/skills/browser-login/SKILL.md`: "log me into
  SITE" → `-L SITE -s`) needs its own `[commit: …/mydotfiles]` grant, else the
  overseer edits it.
- [ ] B4 verify + install of B1-B3: ruff format / check, mypy, `uv run pylint` on
  every touched file, the Verification block against the worktree root; install
  as in PLAN_notion-safari-recipe-fix.md B3 (`<base>` = live HEAD at worktree
  creation; unchanged-since-base check; backups in
  `~/.local/state/agent-login/bak-1644/`; module → script order, `cp -p` + `mv`;
  live `-h` smokes; commit from live with explicit paths). Every later batch box
  (B5, B7, B9, B11, B13, B15, B17) reuses this install path for its own files.
- [ ] B5 **[Albert]** LIVE CANARY of the mechanism (no login): `-L notion -s` still
  exits 0 with no code mail (cooldown mtime unchanged); `-L google-kindle -s` and
  `-L abs-root -s` → exit 2 `no_safari_route (albert_only | admin_account)`; the
  overview shows ⛔ on every infeasible row and ✅ only on notion.
- [ ] B6 batch BI: `SAFARI_ROUTES` entries for slack (`builtin`, import_after,
  landing `https://swiss-data-science.slack.com/`; mail-code fallback with
  `MAIL_CODE_ENV["slack"]` and the shared per-site cooldown
  `slack-mail-code.json`) and openai (`builtin`, import_after, landing
  `https://chatgpt.com/`). Tests in `tests/test_safari_routes.py`: proof `match` →
  only `-o`; `logged_out` → the Google steps; the Google chooser picks the expected
  account only (identity from `_builtin_expected`); slack's mail-code fallback stamps
  before the trigger, no-trigger mode inside the cooldown; a Google push / passkey
  page → exit 4. **Check first:** slack's `d` cookie proof works with
  `import-safari slack -P` (the `localConfig_v2` storage part of
  `SAFARI_BUILTIN_STORAGE` is needed by the import, not by the proof?).
- [ ] B7 **[Albert]** LIVE CANARY BI, then install (B4 path) before it. Per site:
  `-L SITE -s -n`; `import-safari SITE -P` (expect `match`); `-L SITE -s` → exit 0,
  the landing page open, Albert confirms the account. A login run only when Safari is
  GENUINELY logged out (the proof says `logged_out`), never forced. Slack's e-mail
  code: one attempt per code mail, respect the 15-min cooldown, no retry. Exit 4
  (Google push / passkey) → Albert approves in that window, no retry.
- [ ] B8 batch SC: `SAFARI_ROUTES` entries for anibis, tutti, kleinanzeigen,
  galaxus, galaxus-de (`in_safari`, import_after) and ricardo (`in_safari`, no
  import), landings as in the Inventory; `start_url` of each recipe → its landing
  page if the recipe has none (a live session then shows the sentinel at once).
  Each recipe gains a sentinel (from the listing's `logged_in_selector`, the same
  one the broker proves with). Tests: proof-first sentinel → zero fills; a login
  form → `safari.py -L ITEM -G auto` fills, `--expect-host` = the IdP host every
  time; tutti / anibis captcha page → exit 4 and no submit; galaxus `no_submit` is
  the broker's rule only (Safari submits; assert the broker headless path is
  untouched); ricardo → no `_import_run`.
- [ ] B9 **[Albert]** LIVE CANARY SC, then install (B4 path) before it. Read-only
  first: one label probe per IdP login page Safari shows (counts and labels only,
  as in the notion fix Findings 3); fix the labels in B8's worktree when a
  probe disagrees, then re-test. Then per site `-L SITE -s` (expect proof-first ok:
  Safari holds all six sessions today). A password login only on a genuinely
  logged-out site; one attempt; a captcha → Albert solves it, no retry; a quarantine
  → report, never `-Q` it yourself.
- [ ] B10 batch BP self-hosted (`*.dom42.space`, welib; dsm-readonly per the
  Question): `broker_recipe()` + `BROKER_SAFARI_LABELS` entries from a read-only
  probe of each login page in Albert's Safari (labels, one-page vs two-step, TOTP
  page). The probe runs ONLY with Albert present: it is a step of B11, and B10's
  code lands with an empty labels table until then. `SAFARI_ROUTES` entries
  (`in_safari`, no import). Tests: a synthetic listing row + labels → the expected
  `Recipe` (hosts, start_url = check_url, sentinel); no labels → no route; `pre_click`
  → a click step; an Access interstitial → exit 4; TOTP → `safari.py -O ITEM` after
  the password step, never before.
- [ ] B11 **[Albert]** label read + LIVE CANARY BP self-hosted: (1) the read-only
  label probe per site (no click, no fill); (2) the labels committed through the
  worktree + B4 install; (3) per site `-L SITE -s`. Most are logged in in Safari
  already → proof-first ok. A real login only where Safari is logged out; one
  attempt each; the broker rate limit and cooldowns are respected (a `rate_limited`
  → stop, no retry).
- [ ] B12 batch BP SaaS with TOTP: github, gitlab-com, gitlab-ethz,
  gitlab-sdsc-glensk, infomaniak, zoho-desk, smartsheet. Same mechanism as B10, plus
  identity proofs for the multi-account gitlab-sdsc-glensk (the profile page's
  username) and per-site Albert stops (GitHub passkey / "GitHub Mobile" push,
  Infomaniak SMS / app, Zoho OneAuth push, a Smartsheet e-mail code page → stop
  `email_code_unwired`, exit 2: no code mail is sent by a route that does not know
  the sender). Tests as B10, plus the identity `mismatch` → exit 2 `wrong_account`.
- [ ] B13 **[Albert]** label read + LIVE CANARY BP SaaS (as B11). A TOTP code is used
  once (`safari.py -O` waits for a fresh window); a push / passkey prompt → exit 4,
  Albert approves in that window, no retry.
- [ ] B14 batch SSO: eduid (BP + TOTP on login.eduid.ch), switch (`then` chain
  eduid → SSO click), cscs (Keycloak + TOTP; Safari keeps its own localStorage token,
  no import), runai-test3 (custos Keycloak, identity proof), authentik-glensk (when
  its check is green). Tests: the chain runs eduid's proof first and never types on
  `cloud.switch.ch`; a live edu-ID session → zero fills on both; cscs `-s` never
  calls the broker's bundle / token path; identity `mismatch` on runai → exit 2.
- [ ] B15 **[Albert]** label read + LIVE CANARY SSO (as B11). edu-ID is Albert's
  primary identity: only a proof-first run unless Safari is genuinely logged out of
  edu-ID, and then only with Albert's explicit go for that run.
- [ ] B16 batch ML (anthropic, console; one account, see Questions): **Check first,
  read-only:** does the claude.ai / console magic link log in whichever browser opens
  it, or only the one that requested it (a code page instead)? If the latter, the
  Safari route requests it in Safari (e-mail field + "Continue with email" in the
  Machine window) and opens the link in THAT window by an `-e` JS file (0600,
  `location.assign`), never on a command line (the link is a secret). If neither
  works → ⛔ `albert_only` with that reason. Proof `in_safari` with the identity
  read ("logged in as …"). No import (the shared Chromium has its own magic-link
  login). Mail: the shared per-site cooldown, `MAIL_CODE_ENV`, link mail archived
  after use. Tests as B6.
- [ ] B17 **[Albert]** LIVE CANARY ML (as B7): proof-first only unless Safari is
  genuinely logged out of claude.ai; one link mail per attempt, the cooldown kept.
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

Each line is `cd <repo> && <argv>` (`tp verify` grammar); no live login. The block
checks the LIVE files (post-install); B4 and every batch box run the same commands
against the worktree root before their install. A batch that touches `bin/browser.py`
(B6 if the slack proof needs it) adds it to the lint lines. Read-only smoke (not in
the block): `./agent-login.py -L SITE -s -n` per site of the batch. Full suite:
skipped unless a touched file's neighbours fail.

## Live canary rules (every **[Albert]** box)

- Albert is at the Mac for the whole box; the gate is open; result files in a fresh
  `mktemp -d` (0700).
- `-n` first, then the proof, then `-s`. A real login only when the proof says
  Safari is GENUINELY logged out. Never forced by a logout: the agent never opens
  `/logout`, never clicks a log-out control, and logs nothing out in Safari or the
  shared Chromium.
- One attempt per code / link mail; the 15-min per-site cooldown is respected; no
  retry after phase `submit` / `unknown`; broker `rate_limited` / cooldown → stop.
- Exit 4 → Albert finishes in that window by hand, no retry. A quarantine → report,
  never `-Q` it yourself. `recipe_stuck` → read `stuck` / `stuck_host`, report (a
  finding, not a bug hunt in place).
- Label probes are read-only JS reads (counts and labels only; no click, no fill, no
  navigation), and run on a tab Albert has open or one the probe opened with `-o -M`
  and closes with `-C`.

## Risks

- **Unverified labels on ~30 login pages:** each costs one read-only probe with Albert
  present; a wrong label only stops the run (`recipe_stuck`), nothing is typed.
- **Broker `safari_fill` rate limit:** a batch canary of 15 sites could hit it; spread
  the logins, proof-first runs call no broker.
- **Cloudflare Access in Safari:** unknown until B11's read; the stop is exit 4.
- **Second-account risk:** identity proofs only where the listing has `identity`;
  sites without one and with a sibling account stay ⛔ (`admin_account`).
- **Live-file edits:** worktree + ordered atomic install with backups per batch (B4).

## Open points

- The Questions below. B16 may end in ⛔ for claude.ai / console.
