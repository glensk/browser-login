## Session

Resume: `c --resume 3871ad21-0f16-4b68-828e-f9eb1f7a6847`

# WS5 — account identity for broker sites that share one cookie scope (tp#833)

## Context

**Problem (tp#833, hit 2026-10-10).** The shared Chromium has ONE cookie jar and ONE
localStorage per origin. Broker items that log into the same site with DIFFERENT accounts
overwrite each other (`_broker_replace_cookies`, bin/browser.py:11219, clears every cookie
on the scope hosts and adds the bundle's), but every sibling's `logged-in` still passes:
the DOM sentinel (`_broker_probe`, bin/browser.py:11074) proves "someone is logged in",
never WHICH account. Verified live: `browser.py logged-in` passes for gitlab-sdsc-admin,
-glensk and -test while the browser holds the admin account, so an agent that asks for
gitlab-sdsc-test acts as an instance ADMIN.

**Conflict groups (cookie-host overlap, `sites` snapshot 2026-10-11):**

| Scope (cookie hosts)                     | Items                                                    |
| :--------------------------------------- | :------------------------------------------------------- |
| `gitlab.datascience.ch`                  | gitlab-sdsc-admin, gitlab-sdsc-glensk, gitlab-sdsc-test  |
| `audiobookshelf.dom42.space` (+ storage) | abs-albert, abs-root                                     |
| `music.dom42.space` (+ storage)          | navidrome-albert, navidrome-root                         |
| `synology.dom42.space`                   | dsm-albert, dsm-readonly                                 |
| `auth.dev.renku.ch`                      | authentik-akadmin, authentik-glensk                      |
| `sdsc.run.ai`, `custos.datascience.ch`   | runai-admin, runai-test3, **custos-admin** (new finding) |
| `docker.com`                             | docker, docker-hub                                       |
| `www.myfritz.net`, `sso.myfritz.net`     | myfritz-alzenau, myfritz-prilly (Albert is merging them) |

custos-admin is not in the ticket. Its `cookie_hosts` (`custos.datascience.ch`) overlap the
runai items' Keycloak host, and `_broker_replace_cookies` clears host-wide (every path,
so every Keycloak realm). docker vs docker-hub: the broker's password fingerprints differ
(len 16 `fecd` vs len 19 `7bc2`), so they are two accounts, or one copy is stale.

**Design (reconciled with Codex, gpt-5.6-sol, converged in round 1, 13 objections
accepted):**

1. **Role instances instead of swapping.** A new vault field `agent_instance` puts an item
   into a browser instance: `""` = the shared 9222 browser (default, reachable by the
   Playwright MCP tools), `admin` (CDP 9224) or `alt` (CDP 9225). Both new instances use
   the existing `CLAUDE_BROWSER_INSTANCE` machinery of the `private` claude.ai instance:
   own profile, port and coordination files, started on demand. **Invariant:** inside
   ONE instance, a cookie-scope conflict group holds at most ONE item, unless the items
   are explicitly declared the same account. Nothing ever swaps accounts inside an
   instance. The proof-to-action race of a swap and the lease problem (MCP never calls
   browser.py) are gone, and MCP on 9222 only ever sees the least-privileged account.
2. **Server identity proof, fail closed.** Every item whose scope overlaps another item
   with a different account (in ANY instance) is *multi-account*. Its `logged-in` passes
   only when a reviewed, named recipe has asked one fixed same-origin server endpoint
   (`/me`-style) in the probe page, and a one-use broker challenge says the account
   matches. The admin bit must also match `agent_privilege`. A mismatch fails with phase
   `client-proof`, code `wrong_account` / `privilege_mismatch`. Anything unclear is
   `indeterminate`, never ✅. A multi-account item without a recipe is `identity_unproven`.
3. **Least privilege.** `agent_privilege` is mandatory on multi-account items. Admin
   members live only in the `admin` instance, which `-c` stops again after checking it.
   One default member per group answers to a group alias (`gitlab-sdsc`), and agents.md
   marks admin rows `ADMIN`.

**Rejected alternatives (with reasons):**

- *Swap on demand + per-scope lease* (the first draft): it serialises accounts instead of
  giving concurrency. The lease is a timestamp that Playwright MCP never takes, so a proof
  followed by an MCP action has an uncontrolled race. Cleanup is also incomplete:
  sibling-union cookies, storage that cannot be compare-and-swapped without the old
  values, and IndexedDB/sessionStorage.
- *Per-ACCOUNT instances*: the role split already gives ≤ 1 account per scope per instance
  for all 8 groups (table below), with 2 extra Chromiums instead of ~9.
- *CDP browser contexts*: AGENTS.md forbids `browserContextId`/`new_context()` for owned
  tabs, MCP cannot see them, and they die with the connection that created them.
- *An `account_tag` (HMAC of the username) as proof of "same account"*: the same username
  in two Keycloak realms is two accounts, and one account can log in with an e-mail in
  one item and a username in another. "Same account" is an explicit declaration; the tag
  is only a sanity check.
- *The broker fetching the identity itself*: it would need the shared browser's live
  session cookies exported INTO the broker, the reverse of today's trust direction.

**Cost of the instances.** Each running Chromium is roughly 300–500 MB RSS. `admin` and
`alt` run only while used. agents.md tells agents to `CLAUDE_BROWSER_INSTANCE=<x> browser.py
up` / `… down`, exactly like the private anthropic row, and `-c` starts and stops them
around its check. Session cookies lost on an instance restart are re-injected by the next
`login` (a broker profile re-export, normally no password submit).

**Why the Verification block is not strict-eligible (intended).** It runs pytest, mypy,
pylint and pre-commit, which execute repository code. Live steps are manual acceptance
steps under the parent plan's attempt policy (PLAN_agent-login-repair.md): broker install,
vault field edits (Albert's Touch ID via broker-add), instance launches, `browser.py
doctor` on a disposable instance, shared-browser probes, and one positive plus one
wrong-sibling proof per pair.

**Dependencies.** S0 (client guard) can land at once: it is client-only and fail-closed.
S1 (broker) waits for the WS1a broker release in the integration queue
(PLAN_agent-login-repair.md, "WS1a release order"). browser.py changes land only when
`browser.py clients` shows no registered exec client and no maintenance record is live.
WS3 (the onboarding guard) takes over S5's rule.

## Identity sources per group

Read-only inspection 2026-10-11: disposable owned tabs (`browser.py eval-fresh`). Only
HTTP status, JSON key names, element presence and value lengths were printed, never a
value.

| Group       | Instance plan (proposal)                                         | Recipe           | Fixed server endpoint → identity field, admin bit                                                        | Evidence                                                                                                  |
| :---------- | :--------------------------------------------------------------- | :--------------- | :------------------------------------------------------------------------------------------------------- | :-------------------------------------------------------------------------------------------------------- |
| gitlab-sdsc | glensk → `""`, admin → `admin`, test → `alt`                     | `gitlab`         | `GET /api/v4/user` (session cookie) → `username`; `is_admin`                                             | live: 200, keys `username`, `email`, `is_admin` present                                                   |
| abs         | albert → `""`, root → `admin`                                    | `audiobookshelf` | `GET <check-URL path>/api/me` with `Authorization: Bearer <localStorage token>` → `username`; `type` ∈ {root, admin} | live: 200, keys `username`, `type` present                                                                |
| navidrome   | albert → `""`, root → `admin`                                    | `navidrome`      | to confirm at the candidate login: `/api/user/<JWT uid>` or Subsonic `getUser` with the stored token; admin bit `isAdmin` / JWT `adm` | logged out now; unproven until a server-bound endpoint is confirmed                                       |
| dsm         | readonly → `""`, albert → `admin`                                | `dsm`            | `GET /webapi/entry.cgi?api=SYNO.Core.NormalUser&method=get&version=1` with `X-SYNO-TOKEN` → `data.username`; admin bit to confirm | logged out now: the unauthenticated call answers `success:false`, code 119 (fails closed)                 |
| authentik   | glensk → `""`, akadmin → `admin`                                 | `authentik`      | `GET /api/v3/core/users/me/` → `user.username`; `user.is_superuser`; non-null `original` (impersonation) → indeterminate | logged out now; authentik API docs                                                                        |
| runai       | test3 → `""`, admin → `admin`, custos-admin → `alt` unless declared the same account | — (discover)     | unknown; discover at the WS2 runai candidate login                                                       | both logged out, no sentinel yet; unproven until then                                                     |
| docker      | docker → `""`, docker-hub → `alt` (or merge)                     | — (none found)   | none found: `hub.docker.com/v2/user/` answers 401 to cookie auth, and the account menu shows no name     | live; stays `identity_unproven` (fail closed) while two accounts exist                                    |
| myfritz     | merge → one `myfritz` item, no group                             | —                | —                                                                                                        | Albert's decision 2026-10-11 (parent plan)                                                                |

## Steps

### S0 — client guard, fail closed (bin/browser.py only; ships first)

- [x] A pure function `scope_conflicts(sites)` (new module `broker/identity.py`, imported by
      browser.py like `broker.recipes`): items conflict when their `cookie_hosts`
      domain-match in either direction (parent domains included: `docker.com` covers
      `app.docker.com`) or they share a storage origin. Cookie names and paths are
      ignored, on purpose: over-inclusion only costs a refusal, never a wrong account.
      Instance = the entry's `instance` field, absent = `""`. Declared same-account
      pairs (`same_account_as`) do not conflict.
- [x] In `_broker_check_entry`: an item that conflicts with another item → `multi_account`.
      A multi-account item passes only through the identity proof (S2). Until then (and
      whenever the broker does not advertise `identity_v >= 1` in `sites`) → exit 2,
      phase `client-proof`, code `identity_unproven`. A rollback of the broker to a
      pre-WS5 release therefore keeps the client closed.
- [x] Tests (`tests/test_ws5_client.py`): the tp#833 regression (three gitlab entries, all
      sentinels visible → every one exits 2 `identity_unproven`); parent-domain overlap;
      storage-only overlap; disjoint hosts pass as before; a pre-WS5 `sites` view (no
      `identity_v`) stays closed.
- [x] Built 2026-10-11 (worktree, not yet released). Additions beyond the boxes above,
      per the overseer's S0 brief: fill-origin hosts join the scope too (conservative; no
      live difference); same-account needs BOTH items to name each other; refused items
      take part. `login` (broker, Safari import and Safari login) refuses at its start,
      before the free check, any broker request or injection; `logged-in -x CSS` (a
      DOM-only sentinel question) is not gated. agent-login: rows carry
      `shares_login_with`, state `unproven` (never ✅; agents.md `⚠ … account unproven
      (shares login with …)`, fixed text), `-x` column `shares_login`, `-p` refuses,
      `-c` neither checks nor logs them in (records `client-proof` · `identity_unproven`
      as "could not tell", no mail). Live snapshot: exactly the 8 groups of the table.

### S1 — broker (release via install.sh; after the WS1a broker release)

- [x] Vault fields in `broker/vault.py` `site_item_from_json` (validated, else `refused`):
  - `agent_instance`: `""` | a known instance slug (`admin`, `alt`);
  - `agent_privilege`: `admin` | `user` | `readonly`; mandatory for every item that
    overlaps another item's scope in any instance;
  - `agent_identity`: one name from `broker/identity.py` `IDENTITIES` (reviewed recipes
    only; no free-form endpoint, no DOM text);
  - `agent_same_account_as`: a site id, set on both items (symmetric, else refused);
  - `agent_alias`: a slug for the group's default member. Refused when it equals any
    static registry name, any broker site id or another alias, or reveals the account
    (reuse `_attempt_group`'s username check).
- [x] `sites` view: each entry gets `instance`, `privilege`, `identity`, `alias`,
      `same_account_as`, `multi_account`, `identity_v: 1`. Scope validation runs over all
      items: an overlap INSIDE one instance between items not declared same-account →
      the later item (by site id) is refused with `scope conflict in instance <x>: set
      agent_instance on one of them`. A multi-account item without `agent_privilege` →
      refused.
- [x] `account_tag` (sanity check only, never authorization): HMAC-SHA256 over the
      normalised username under a 32-byte key (0600, the broker uid, in its state
      directory, kept across releases). Declared same-account items with unequal tags →
      refused. It is not in the public view. **No socket op** (security review: an
      unlimited equality oracle over the collection): Albert's docker / custos questions
      go through the root-only CLI `sudo install/install.sh -S A B` (runs
      `daemon.py -S A B` as the broker uid), which prints only `same` / `different` /
      `unknown` and writes one audit line.
- [x] Challenge ops: `identity_challenge {site, instance}` → `{challenge_id, nonce}` (32
      random bytes, one use, TTL 60 s, bound to the site and the peer's pid);
      `identity_answer {challenge_id, digest}` with exactly ONE hex digest of
      `nonce || normalised value` → `match` | `mismatch` | `expired`. Audited without
      nonce or digest. **Online-guess oracle, bounded (security review M1):**
      - issued only when a `login` of the item would be served: known, not refused, a
        proof, a usable recipe, asked from the item's own instance (`wrong_instance`
        otherwise), and no limiter `locked` / `cooldown` / `quarantined` /
        `unreadable` on any of its keys (else `rate_limited` with the limit);
      - caps: 6 per site and 6 per peer pid per minute (no global cap, no open cap:
        the per-site cap bounds the open challenges);
      - every `mismatch` costs (`IdentityGuard`, `identity-guard.json` + flock, an
        `identity_guard` audit line each time): the site's challenges stop 1 h after
        the first, 6 h after the second, and the third within 7 days quarantines them
        until `sudo install/install.sh -r SITE` (which now resets the guard too);
        unreadable guard state → `identity_unreadable` (closed). So roughly 3 guesses
        per site per week instead of ~8.6k a day;
      - no burst past a mismatch (review round 2): a `mismatch` drops every open
        challenge of the site, answers are decided one at a time, and while the guard
        blocks the site every answer is `expired` — no verdict at all, even for the
        right digest;
      - the guard fails closed on a failed write (review round 3): a challenge is
        issued only after a probe write of the guard state succeeds
        (`identity_unwritable` otherwise, for every site — a full disk never reopens
        the oracle), and a mismatch that cannot be recorded (OSError included) blocks
        the site in memory for the life of the process (`identity_blocked`, checked by
        challenge and answer).
- [x] Normalisation, identical in Python and JS: NFKC, then reject non-ASCII
      (→ indeterminate), then ASCII lower-case, then trim (JS `trim` whitespace only).
- [x] Broker-side proof: after a login, and on profile / SSO reuse before export, the
      broker runs the same recipe in its OWN page and compares in-process against the
      vault username, together with the admin bit. No bundle unless `match`.
- [x] Tests (`tests/test_ws5_broker.py`, account names generated per run): field
      validation and refusals; in-instance conflict refusal; tag key ownership and tag
      equality; challenge match / mismatch / expired / reused / wrong pid / per-site and
      per-pid caps / login gates; the mismatch guard (1 h, 6 h, quarantine, 7-day
      window, persisted, root reset); the identity outcome in the limiter; reuse →
      reset → one login; the `-S` CLI; leak checks over audit lines, error texts and
      the `sites` view; RECIPE_JS in a real headless Chromium in an isolated world
      (incl. a page that hooks `Response.json` and `crypto.subtle`).
- [x] Built 2026-10-11, revised after the overseer's security review the same day
      (worktree, not yet released; needs `install.sh` + selfcheck). Decisions, each
      fail closed:
  - **Tag key created by the broker on first use**, not by `install.sh`
    (`<home>/account-tag.key`: temp file + link, `O_NOFOLLOW` read, a regular 0600 file
    of the broker's euid, exactly 32 bytes; else no key → declared pairs refused).
  - **Usable recipe = reviewed + `live_confirmed` + an admin bit**
    (`identity.usable_recipe`). The vault refuses `agent_identity` naming anything else
    and an `agent_identity` without a login username, with one that does not
    normalise (non-ASCII: refused at validation, never answered per challenge), or in
    a form the recipe cannot compare (each recipe declares `forms`; all compare the
    `username` today, so a vault holding an e-mail reads "the vault holds an email; the
    gitlab identity proof compares the username" — refused rather than compared with
    GitLab's `email`, one reviewed field per recipe); `login` and the challenge
    re-check usability at precheck. Today: `gitlab`, `audiobookshelf`. `dsm` (no admin bit in
    `SYNO.Core.NormalUser`; its SynoToken is a page global the isolated world cannot
    see) and `authentik` (docs only) stay in the table, unusable, until S4 confirms
    them live. navidrome and Run:ai are not in the table.
  - **RECIPE_JS** (`identity.py`, one generic in-page function driven by the reviewed
    spec): `redirect: 'manual'` (an opaqueredirect → `why: redirect`), the page must be
    on the check URL's origin, 200 + JSON + schema, 401/403 → `logged_out`. GitLab
    `is_admin` absent = not admin; ABS `type` root/admin vs user/guest; authentik
    `original` present and null.
  - **The broker runs it in a CDP isolated world** (`daemon.evaluate_isolated`:
    `Page.createIsolatedWorld` + `Runtime.callFunctionOn`, `Network.setBypassServiceWorker`
    on its OWN CDP session, dropped with it on detach — never reset on a shared target):
    page scripts cannot hook its `fetch`, `Response` or `crypto.subtle`.
    A CDP failure is `indeterminate`, never a main-world fallback. S2 should do the same
    over browser.py's raw CDP.
  - **Reuse** (`_identity_reuse`): `match` → export; `logged_out` → log in;
    `wrong_account` ONLY → the run reserves, then `reset_site_profile`: the tab goes
    to `about:blank` first (the app cannot write its token back), the site's cookies go,
    and for its fill / storage / check origins localStorage, IndexedDB, Cache Storage
    and service workers (`Storage.clearDataForOrigin`); a fresh tab replaces the old one
    (its sessionStorage dies with it); then ONE login (an attempt like any other,
    proven again);
    `indeterminate` and `privilege_mismatch` → fail before anything is reserved or
    submitted (no guess-login on a 5xx). A `refresh_only` request never clears or logs
    in.
  - **After a VALID login proof** (`_identity_after_login`): anything but `match` →
    `IdentityMismatch` with `auth_proven`, phase `broker-proof`, codes `wrong_account` /
    `privilege_mismatch` / `identity_indeterminate` / `login_failed`; the limiter
    records the new outcome `identity_mismatch` (counted for interval and caps, never
    for the bad-password streak; the 3rd within 24 h sets the site's limiter cooldown,
    so no password is submitted until it expires; the 5th within 7 days hard-blocks the
    site like the bad-password streak does, until `sudo install/install.sh -r SITE`, so a
    persistent wrong-account or logged-out misconfiguration never logs in every day). The run-deadline wrapper passes an
    `IdentityMismatch` through unchanged (never turned into a `timeout` that the
    limiter would count as `ok`). No failure screenshot (the page may show the other
    account's name).
  - A multi-account item (or one naming a recipe) without a usable recipe → `login`
    stops at `precheck` · `identity_unproven` before anything is reserved.
  - **A refused item keeps its scope**: a WS5 field refusal keeps the parsed scope; an
    item refused before its scope was parsed gets its `agent_cookie_hosts` and
    fill-origin hosts only (never check / login URL hosts: an IdP there would pull
    unrelated items in; never generic login URIs).
  - A refused same-account declarer loses its declaration; duplicate aliases refuse
    every item sharing one; the in-instance rule refuses the later site id (a NEW item
    can displace an established one: S5 must show it before install).
  - The broker refuses to start (non-dev) when its home is not a 0700 directory of its
    own uid; selfcheck now also checks `account-tag.key` and `identity-guard.json(.lock)`.
  - **Release effect**, replayed on the live `sites` snapshot (47 items, no WS5 field
    set yet): exactly the 16 items that were already multi-account under S0 change
    from `ok` to `refused` (no `agent_privilege`): abs-albert, abs-root,
    authentik-akadmin, authentik-glensk, custos-admin, docker, docker-hub, dsm-albert,
    dsm-readonly, gitlab-sdsc-admin, gitlab-sdsc-glensk, gitlab-sdsc-test,
    navidrome-albert, navidrome-root, runai-admin, runai-test3. No other item changes,
    and none becomes multi-account. They stay unusable, as under S0, but read
    `refused` in agent-login rows instead of `⚠ account unproven` until S4 sets the
    fields.

### S2 — client identity proof and instances (bin/browser.py, in a worktree)

- [x] Recipes in `broker/identity.py` (landed with S1, see there; S2 only calls
      `RECIPE_JS` + `recipe_args` in the probe page): `gitlab`, `audiobookshelf`, `dsm`, `authentik`
      first; `navidrome` and `runai` once their endpoints are confirmed. Each is one async
      in-page function: fetch ONE fixed path built from `location.origin`
      (`credentials: "same-origin"`); require the final URL on the same origin, status
      200, `content-type: application/json` and the expected schema; read the ONE declared
      identity field and the admin bit; normalise; hash `nonce || value` with
      `crypto.subtle`; return `{state: found | logged_out (401/403) | indeterminate,
      digest, admin}`. Raw values never cross CDP. No fallback source.
- [x] `_broker_probe` → for a multi-account entry, after a VALID sentinel or server proof:
      challenge → recipe in the SAME page → answer. `match` plus a matching admin bit →
      valid. `mismatch` → `wrong_account`. Admin-bit mismatch → `privilege_mismatch`.
      `logged_out` → invalid. Anything else, a broker error included → indeterminate.
- [x] Instances: `INSTANCE_PORTS` += `admin: 9224`, `alt: 9225`. `login`/`logged-in` of an
      item whose `instance` differs from `CLAUDE_BROWSER_INSTANCE` → exit 2, code
      `wrong_instance`, naming the exact prefix to use. Doctor and coordination files work
      per instance as for `private`.
- [x] Alias resolution in `_resolve_site`: static names first, as today; then broker site
      ids; then aliases. An alias never shadows either, and S1 refuses such an alias.
- [x] Tests (extend `tests/test_ws5_client.py`; one `launches_chrome` test runs each recipe
      against a local fixture page via `page.route`): match / mismatch / admin-bit
      mismatch / logged_out / wrong content type / cross-origin redirect / non-ASCII;
      an out-of-band account change (the fixture flips its identity between two probes);
      `wrong_instance`; alias resolution order; new client against a pre-WS5 broker
      (closed); leak test over stdout, stderr, the journal and `_RESULT`.

### S3 — agent-login.py, agents.md, scheduler

- [x] Rows carry `instance`. `checks.json` rows record the instance they were checked in,
      and `row_state` reads a row whose recorded instance differs from the item's current
      `instance` as stale (❓). There is no `displaced` state: the server proof at check
      time decides.
- [x] agents.md and the overview group multi-account members under their group:
      `✅ gitlab-sdsc-glensk (default; alias gitlab-sdsc; user)` and `✅ gitlab-sdsc-admin
      (ADMIN; own browser: CLAUDE_BROWSER_INSTANCE=admin browser.py up first, … down when
      done)`. `identity_unproven` rows read `⚠ account unproven` and are never ✅. Fixed
      vocabulary only.
- [x] `-c`: default-instance items as today. For each role instance: start it only if it
      was down, run the checks (logins only for promoted items, same gates as today), and
      stop it again if this run started it. An admin session is therefore not running in
      any browser between uses. `identity_unproven` items are never logged in by `-c`.
- [x] `-x` matrix: columns `instance`, `multi`, `identity`, `privilege`, `alias`,
      `same-account`.
- [ ] ~~`-s A B`~~ dropped (security review M2): the same-account question is the root-only `sudo install/install.sh -S A B`.
- [x] Tests in `tests/test_agent_login.py`: grouped rendering (no username, fixed
      vocabulary); instance prefix in agents.md; `-c` starts and stops only instances
      that were down; a stale row after an instance change; unproven rows never ✅ and
      never logged in.
- [x] S2 + S3 built 2026-10-11 (one worktree, not yet released; CLIENT-ONLY: no broker
      behaviour change, no `install.sh` needed — `broker/identity.py` gains the pure
      `proof_ready`, `connected_groups`, `ROLE_INSTANCE_PORTS`, `broker/phases.py` two code
      texts; the next broker install ships them unchanged in effect). Decisions:
  - **Proof-ready** (`identity.proof_ready`): not refused, `identity_v >= 1`, a usable
    recipe, a known privilege. A multi-account item that is not proof-ready stays
    `identity_unproven` (S0 behaviour, also against a rolled-back broker); a proof-ready one
    passes the gate and its check runs the proof.
  - **Client proof** (`_client_identity_proof`, bin/browser.py): only after a VALID
    sentinel/server proof, in the same probe page: `identity_challenge {site, instance}`
    → `RECIPE_JS(recipe_args(recipe, check URL, nonce))` in a fresh CDP isolated world
    (`_evaluate_isolated`, the client copy of the daemon's; a CDP failure is
    indeterminate, no main-world fallback) → `identity_answer` → `admin_verdict`. The
    challenge's `identity` / `privilege` must equal the entry's. Codes (phase
    `client-proof`): `wrong_account`, `privilege_mismatch`, `identity_indeterminate`,
    `identity_unproven`; broker refusals map to `wrong_instance`, `rate_limited` and the
    new `identity_blocked` (the guard's cooldown / quarantine / unreadable / unwritable).
    `_RESULT` records `identity` (+ a whitelisted `identity_why`, an int status, the
    broker's redacted detail) — never a nonce, digest or name.
  - **The verify after an injection claims the account** (`claims_account=True`), so a
    candidate-sentinel login (`login -x`) of a multi-account item is proven too;
    `logged-in -x CSS` stays a DOM-only question (no identity gate, no proof, "sentinel
    present" instead of "Logged into", no session-age note) — but never in another
    instance's browser (`_instance_gate`).
  - **The CHECK clears a foreign session** (review round 2; replaces round 1's `login
    -W`): no sibling may live in an instance (S1), so a `wrong_account` verdict of ANY
    `logged-in` (agents, `-c`, a login's free check) deletes at once, in this browser
    only, the item's cookies on its cookie hosts and their subdomains (never a parent
    domain; its `cookie_names` only when it has them, as `logout` does) — never storage,
    never the broker's profile — and exits 2 `client-proof` · `wrong_account`, "foreign
    session cleared". It is not a login: no gate applies (pending, quarantined rows are
    cleared too). The next check sees no sentinel → no challenge, no further mismatch, so
    the guard's 1 h → 6 h → quarantine escalation stops; a login's free check sees
    "logged out" and logs in normally (its verify is the second challenge, blocked by the
    guard's cooldown right after a mismatch → recorded as unknown).
    `privilege_mismatch`, `identity_indeterminate`, `identity_blocked`, `rate_limited`
    stop a login before any broker request (`IDENTITY_STOP_CODES`). The former gap (a
    foreign session held in localStorage, the audiobookshelf bearer token, survived the
    cookie clear) is closed by S4a below.
  - **Pinned runs** (review rounds 1–2, B1/SF3): ANY `--cdp-port` on the command line
    pins the run (`_self_run` always passes one); a routed re-run refuses a port that is
    not its instance's; `_instance_gate` compares the PORT too: a port of ANOTHER known
    instance is refused, also under a disposable cache dir or the test guard; only a port
    no instance owns (a disposable browser) passes. `logout` and `assisted-login` run the
    same gate; a guided login of a non-static name refuses an alias, an unlisted name and
    an unreachable broker (agent-login `-g` runs in the item's instance, `site_session`).
  - **agent-login identity verdicts**: `identity_indeterminate` / `rate_limited` /
    `identity_blocked` are "could not tell" (no login, no mail); `privilege_mismatch` /
    `wrong_instance` / `identity_unproven` ❌ without a login; `wrong_account` (already
    cleared by the probe) → a plain `login -s` when ungated, else ❌ `wrong_account`
    "(cleared)" without a login. ≤ 2 challenges a run. A login whose verify ran the
    proof is not re-probed. `checks.json` stores the
    verdict (`identity`); a multi-account ✅ without `identity: match` reads ❓ (an old ✅
    from before the siblings), and `-p` requires it.
  - **Instances**: `INSTANCE_PORTS` += `admin` 9224, `alt` 9225 (from
    `identity.ROLE_INSTANCE_PORTS`). The gate refuses an item of another instance
    (`precheck` · `wrong_instance`, naming `CLAUDE_BROWSER_INSTANCE=<x> browser.py <cmd>
    <site>` or `env -u CLAUDE_BROWSER_INSTANCE …`) for every broker item, Safari imports
    included. `main` re-executes `login` / `logged-in` of a role-instance item into its
    instance (`os.execve`, `CLAUDE_BROWSER_INSTANCE_ROUTED=1`) BEFORE any registration,
    preflight or journal entry — only when the run is not pinned (no explicit instance,
    no `--cdp-port` / `CLAUDE_BROWSER_CDP_PORT` / `CLAUDE_BROWSER_CACHE_DIR`, no guided-login
    child, not already routed); a pinned run is refused by the gate. "Browser down"
    hints name the instance prefix.
  - **Aliases**: static names, then broker site ids, then exactly one non-refused
    item's `alias` (ambiguous or refused → unknown). `browser.py` resolves against the
    live listing; `agent-login.py -t/-p/…` from the last `sites` snapshot only.
  - **agent-login rows** carry `instance`, `privilege`, `identity`, `alias`,
    `same_account_as`, `multi_account`, `proof_ready`. `checks.json` records `instance`
    (browser.py's `-R` word, else the row's / the site's configured instance — never the
    ambient env, review round 1 B2); a record without it (pre-S3) counts
    as the site's old instance (`""`, `private` for anthropic-private), so the release
    does not turn every ✅ into ❓. `-p` also refuses a check from another instance.
  - **agents.md**: each conflict group is one block (`- one site, several accounts (…)`)
    with every member indented — ✅ with `ADMIN account` / `user account` / `read-only
    account`, `the default — alias`…``, and for role instances the up/down prefix
    (admin: "Playwright MCP only through the opt-in `playwright-admin` config"); ❓ lines
    name the prefixed `logged-in`; refused members get fixed texts by kind
    (`refusal_text`: privilege missing, in-instance conflict, alias, same-account,
    identity) plus the sibling ids — never the broker's reason. Replayed on the live
    snapshot (copy): the 8 groups render as blocks of refused members with "needs
    agent_privilege".
  - **`-c`**: rows are split by role instance; a role instance is started (via
    `instance_session`, which `site_instance` now uses too) only when one of its rows
    needs a browser (`needs_browser`: a ready/extra/Safari row whose account is not
    unproven; refused or unproven rows are only recorded), checked
    with the same gates, and stopped only if this run started it AND `instance_users()`
    finds no registered (or unregistered) CDP client — read in-process from that
    instance's registry. An instance that does not start records `browser_down` for its
    rows (unknown, never "logged out") and fails the run. "Started here" = it was down
    and a browser answers within ~10 s after the `up` attempt (polled; an `up` timeout or
    a slow Chrome is still stopped); a failed stop or an unreadable client list goes into the run's failures
    (the mail). `-t` runs in the item's instance the same way. Group headers appear in
    each agents.md section their members land in.
  - **`-x`**: columns `instance`, `multi`, `identity` (`(unproven)` when not
    proof-ready), `alias`, `same_account`; `privilege` shows the item's `agent_privilege`.
  - Tests: `tests/test_ws5_client_s2.py` (the REAL `daemon.Broker` behind its socket
    server with a fake vault; the recipe in a throwaway headless Chromium with routed
    fixture endpoints; a page that hooks `Response.json` / `crypto.subtle`; leak checks
    over stdout, stderr, the journal and `-R`) and `tests/test_ws5_agent_login_s3.py`
    (a real registration in a throwaway registry blocks the stop).
  - **What S4 needs**: the vault fields (broker-add columns), then per pair one positive
    and one wrong-sibling proof in the item's own instance; `CLAUDE_BROWSER_INSTANCE=admin
    browser.py up` once to create its profile; the `playwright-admin` MCP config in
    mydotfiles (proposal from this slice); README "Accounts that share a site". The live
    default browser may still hold an admin session from before (tp#833): the first
    proof of the default member answers `wrong_account` and clears that session (cookies
    only); the 1 h guard cooldown then delays the positive proof — plan the acceptance
    proofs after it.
  - Incidental (review round 1): `broker/selfcheck.py` `probe_forbidden` tolerates the
    EPIPE of its send when the broker answered `forbidden` and closed first (the answer
    is still read) — the cause of the flaky `test_selfcheck_forbidden_probe`; the
    test helper `_ask` likewise. A deterministic regression test sends late; an empty
    reply (a broker that closes without a word) is "got no answer", never a pass
    (review round 2, tested).

### S4 — migration and live acceptance (main session; Albert's Touch ID for vault writes)

- [ ] mydotfiles `bin/broker-add.py`: add columns for `agent_instance`, `agent_privilege`,
      `agent_identity`, `agent_same_account_as` and `agent_alias` (short options without
      collisions), with validation reused from broker/vault.py. Separate commit in
      mydotfiles.
- [ ] `sudo install/install.sh -S docker docker-hub` and `-S custos-admin runai-admin`: same →
      Albert merges or declares same-account; different → separate instances.
- [ ] Set the fields per item (proposal in the table above, after Albert's answers), then
      `agent-login.py -x`: no in-instance conflict, no refusal.
- [ ] Disposable-instance doctor after the instance change:
      `CLAUDE_BROWSER_CACHE_DIR=<tmp> bin/browser.py --cdp-port <free port> up`, `doctor`,
      `down`.
- [ ] Per pair: one positive proof in the item's own instance, and one wrong-sibling proof
      (the recipe in instance A against item B's challenge must answer `mismatch`). Free
      probes otherwise; a login only under the attempt policy.
- [ ] runai / custos-admin endpoints: confirm at their WS2 candidate logins. Until then
      those groups stay `identity_unproven`. (navidrome: confirmed live 2026-10-11, S4a.)
- [x] **S4a** built 2026-10-11 (worktree, not yet released; BROKER + client:
      `broker/identity.py` changes what the broker accepts and proves, so `install.sh`):
  - **`navidrome` recipe** (`live_confirmed`): auth `jwt-local-storage` — localStorage
    `token` is a JWT; its payload (base64url, no signature check, the server validates)
    gives `uid`, which must be 1–128 of `[A-Za-z0-9_-]` (else indeterminate, nothing
    sent); `GET /api/user/<uid>` at the origin root with `x-nd-authorization: Bearer
    <token>`; the record's `id` must equal `uid` (an admin token reads any user →
    `why: claim`, indeterminate); `userName` compared, `isAdmin` boolean (any other
    type: no admin bit → indeterminate); no token / 401 / 403 → `logged_out`; a
    malformed token → `why: token`. Forms: username.
  - **RECIPE_JS generalised minimally**: `auth_header` + `auth_scheme` (ABS keeps
    `Authorization: Bearer …`), `path_claim` (one JWT claim as the last path segment),
    `claim_field` (the record's own id). The broker (`daemon.evaluate_isolated`) and the
    client (`browser._evaluate_isolated`) run the same function; the new test file runs
    every case through both.
  - **Reviewed-spec validation**: `IdentityRecipe.__post_init__` → `recipe_problem`
    (known auth, one absolute path, plain field keys, a token key and a settable header
    — not a forbidden / `Sec-` / `Proxy-` / Accept header — for localStorage auths, a
    claim only with jwt auth + `claim_field` + a path ending in `/`). A malformed
    table entry fails at import.
  - **Foreign clear covers storage** (`_broker_clear_foreign`): for an item whose
    recipe reads from localStorage (`identity.LOCAL_STORAGE_AUTHS`), also the item's
    declared `storage_keys` on its check / fill origins, and the recipe's `token_key`
    on the CHECK origin only (a fill origin may be a shared SSO provider;
    `identity.foreign_storage_keys`); registered first, then the interaction lease
    (gate before lease, as `reap-owned`); one fresh owned background tab per origin
    whose SW / cache bypass must apply (`_broker_bypass_cache` now returns whether it
    did; False → nothing loaded, not cleared) and whose own route serves a blank
    document of that origin carrying a per-call nonce (the app never runs, nothing
    reaches the site, every other request aborted); in an isolated world, removal by
    name only when the nonce is there and `navigator.serviceWorker.controller` is
    null (else nothing: a PWA worker answered — `not our document` / `a service worker
    controls the page`), confirmed by read-back. `_RESULT.foreign_storage_cleared`
    (count, None on failure), message "foreign session cleared (N cookie(s) and K
    storage key(s) in this browser; the broker's profile untouched)"; an unconfirmed
    origin → "could NOT be cleared (storage: … : <reason>)". Another open tab of the
    app may write its token back later: "cleared" holds at read-back time (fail
    safe). Cookie-auth items keep the old message and behaviour. (Review S4b fixes.)
  - Tests: `tests/test_ws5_navidrome.py` (spec validation, `foreign_storage_keys`,
    RECIPE_JS in a throwaway Chromium through both evaluators: match / mismatch / admin
    true-false-other / id≠uid / missing + garbage tokens and claims / 401 / 403 / 5xx /
    non-JSON / a page hooking fetch, Response.json, JSON.parse, atob, crypto.subtle /
    another origin) and `tests/test_ws5_client_s2.py` (ABS + Navidrome proven end to end
    through the real broker; a foreign session cleared by one check — cookies, declared
    keys, token — with an undeclared key and another origin's storage untouched, the
    clear tab never loading the site; the next check sends no challenge; a registered
    PWA service worker answering the clear tab → nothing cleared, reported; the real
    `_broker_clear_foreign_storage` against a disposable Chromium attached with
    `connect_over_cdp` (default context, owned tabs, registry, lease), with and
    without an installed worker).
- [ ] Update README (item fields, "Accounts that share a site", instances), AGENTS.md
      (invariant: one account per conflict group per instance; a multi-account item passes
      only with the server identity proof; values never leave page or broker) and the
      parent plan's WS5 box. Close tp#833 through the review flow.

- Live findings 2026-10-11 (main session, Albert's Safari, schema only, no values printed):
  - `install.sh -S docker docker-hub` → different; `-S custos-admin runai-admin` → different.
  - navidrome: `GET /api/user/<jwt.uid>` with `x-nd-authorization: Bearer <localStorage token>` →
    200 JSON `userName`, `isAdmin` (navidrome-albert: not admin). Recipe → S4b builder.
  - audiobookshelf albert: `type` = user.
  - Run:ai (sdsc.run.ai) and the Keycloak admin console keep their bearer token in page memory
    (no JS-readable cookie, no storage token; `/api/v1/*` answers 401 with cookies alone): no
    in-page server identity recipe is possible with RECIPE_JS. Decision for Albert: drop one
    member per group, or accept these groups as unproven.
  - runai-test3's vault password was stale (Keycloak "Invalid username or password"; the user
    exists, enabled, no required actions). Rotated 2026-10-11 (test fixture): new password set
    via the Keycloak admin API (keycloak-client-secret) and saved into the vault item through
    Safari; the Safari login with the vault item then reached the Run:ai dashboard.
  - dsm (two-step login, SynoToken page global), authentik (shadow-DOM flow), docker (two-step):
    not live-probed yet.

### S5 — onboarding rule (with WS3)

- [x] WS3's static validation uses `scope_conflicts`: a new item that conflicts with an
      existing one must declare `agent_instance`, `agent_privilege` and `agent_identity`
      (or `agent_same_account_as`). The broker's S1 refusal is the enforcement;
      `agent-login.py -V` shows it before install. Built in WS3 (`PLAN_ws3-onboarding.md`):
      `account_unproven` (unusable) plus `displaced` / `made_unproven` for the established
      items a planned item would knock out (`-V -i`).

## Open questions for Albert (with recommendations)

1. **Fail closed now (S0 before S1–S4).** Until migration, the 8 groups read `⚠ account
   unproven`, and agents cannot use gitlab-sdsc, abs, navidrome, dsm, authentik, runai or
   docker through the broker for a few days. Recommended: yes. Acting as the wrong account
   (e.g. ADMIN) is worse than a short outage.
2. **Default member and instance per group.** Recommended as in the table: gitlab-sdsc →
   glensk, abs → albert, navidrome → albert, dsm → readonly, authentik → glensk, runai →
   test3; admin members in `admin`; gitlab-sdsc-test, docker-hub and (if it conflicts)
   custos-admin in `alt`.
3. **docker vs docker-hub.** Recommended: decide after `sudo install/install.sh -S docker
   docker-hub`. Same → merge into one item. Different → docker-hub goes to `alt`, and both
   stay unproven until a Docker identity endpoint exists. Or keep only the one agents
   need.
4. **custos-admin vs runai-admin.** Recommended: keep the host-level conflict (conservative)
   and put custos-admin in `alt`, unless `-s` shows the same account. Realm-path cookie
   scopes stay deferred.
5. **Admin UI access via MCP.** DECIDED (Albert, 2026-10-11): the `admin` instance IS
   reachable through Playwright MCP too, not only through browser.py. This replaces the
   "admin not via MCP" rule above. How (S2/S4, mydotfiles): a second MCP config, e.g.
   `~/.claude/mcp/playwright-admin.json` with a server named `playwright-admin`, the same
   shape as `playwright.json` but `--cdp-endpoint http://127.0.0.1:9224`, its wrapper
   registered in the admin instance (`"env": {"CLAUDE_BROWSER_INSTANCE": "admin"}`, so
   `browser.py register-exec -t playwright-mcp-admin` writes the admin instance's
   coordination files and a guided login / switch there pauses it). A session opts in
   (`--mcp-config ~/.claude/mcp/playwright-admin.json`, like `cb`), never by default;
   the browser itself must be up (`CLAUDE_BROWSER_INSTANCE=admin browser.py up`), and
   `-c` must not stop the admin instance while a registered MCP client uses it (S3).
   Nothing in S1 blocks this: the broker only advertises `instance` per item.

## Implementation slicing

| Slice | Content                                                                   | Who                                  | Gate                                                   |
| :---- | :------------------------------------------------------------------------ | :----------------------------------- | :----------------------------------------------------- |
| S0    | client fail-closed guard (`scope_conflicts`, `identity_unproven`)         | opus-builder in a worktree           | Albert's Q1; no exec client registered                 |
| S1    | broker fields, scope validation, tag, challenge ops, broker-side proof    | opus-builder in a worktree           | after the WS1a broker release; install.sh + selfcheck  |
| S2    | recipes, client proof, instances `admin`/`alt`, alias resolution          | opus-builder in a worktree           | after S1 is deployed                                   |
| S3    | agent-login rows, agents.md, `-c` instance cycle, `-x`, `-s`              | opus-builder                         | after S2                                               |
| S4    | broker-add columns (mydotfiles), vault migration, doctor, live proofs     | main session + Albert (Touch ID)     | after S1 (fields), after S2/S3 (acceptance)            |
| S5    | onboarding rule                                                           | with WS3                             | after S4                                               |

## Verification

```commands
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run ruff format --check bin/ broker/ agent-login.py agent_login_jobs.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run ruff check bin/ broker/ agent-login.py agent_login_jobs.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run mypy bin/browser.py agent-login.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pylint bin/browser.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pytest -q tests/test_ws5_broker.py tests/test_ws5_client.py tests/test_ws5_client_s2.py tests/test_ws5_agent_login_s3.py tests/test_agent_login.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pytest -q tests
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pre-commit run --all-files
cd /Users/albert/obsidian/42-Git/home/browser-login && install/install.sh -n
cd /Users/albert/obsidian/42-Git/home/browser-login && bin/browser.py -h
```
