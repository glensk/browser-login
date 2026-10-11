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

- [ ] Vault fields in `broker/vault.py` `site_item_from_json` (validated, else `refused`):
  - `agent_instance`: `""` | a known instance slug (`admin`, `alt`);
  - `agent_privilege`: `admin` | `user` | `readonly`; mandatory for every item that
    overlaps another item's scope in any instance;
  - `agent_identity`: one name from `broker/identity.py` `IDENTITIES` (reviewed recipes
    only; no free-form endpoint, no DOM text);
  - `agent_same_account_as`: a site id, set on both items (symmetric, else refused);
  - `agent_alias`: a slug for the group's default member. Refused when it equals any
    static registry name, any broker site id or another alias, or reveals the account
    (reuse `_attempt_group`'s username check).
- [ ] `sites` view: each entry gets `instance`, `privilege`, `identity`, `alias`,
      `same_account_as`, `multi_account`, `identity_v: 1`. Scope validation runs over all
      items: an overlap INSIDE one instance between items not declared same-account →
      the later item (by site id) is refused with `scope conflict in instance <x>: set
      agent_instance on one of them`. A multi-account item without `agent_privilege` →
      refused.
- [ ] `account_tag` (sanity check only, never authorization): HMAC-SHA256 over the
      normalised username under a 32-byte key created by `install.sh`, owned by
      `_loginbroker:_loginbroker` 0600 in the broker's state directory and kept across
      releases. Declared same-account items with unequal tags → refused. It is not in the
      public view. Op `same_account {sites: [a, b]}` → `{ok, same: bool}` (enum only,
      audited) answers Albert's docker and custos questions (`agent-login.py -s A B`).
- [ ] Challenge ops: `identity_challenge {site}` → `{challenge_id, nonce}` (32 random
      bytes, one use, TTL 60 s, bound to the site and the peer's pid);
      `identity_answer {challenge_id, digest}` with exactly ONE hex digest of
      `nonce || normalised value` → `match` | `mismatch` | `expired`. Caps: 6 per site and
      20 in total per minute, then `rate_limited`. Audited without nonce or digest.
      Residual oracle risk accepted: the same uid can already fetch full session bundles
      (op `login`).
- [ ] Normalisation, identical in Python and JS: NFKC, then reject non-ASCII
      (→ indeterminate), then ASCII lower-case, then trim.
- [ ] Broker-side proof: after a login, and on profile reuse before export, the broker
      runs the same recipe in its OWN page and compares in-process against the vault
      username, together with the admin bit. A mismatch → phase `broker-proof`, code
      `wrong_account` / `privilege_mismatch`, no bundle. This catches an IdP SSO session
      that silently logs the broker profile into another account.
- [ ] Tests (`tests/test_ws5_broker.py`): field validation and refusals (alias collisions
      with static names, asymmetric same-account, unknown instance, missing privilege);
      in-instance conflict refusal; tag key ownership and tag equality; challenge
      match / mismatch / expired / reused / wrong pid / rate cap; broker-proof mismatch
      with a fake page; leak test (fixture username `zz-ws5-secret-user`, grepped over
      audit lines, error texts and the `sites` view).

### S2 — client identity proof and instances (bin/browser.py, in a worktree)

- [ ] Recipes in `broker/identity.py`: `gitlab`, `audiobookshelf`, `dsm`, `authentik`
      first; `navidrome` and `runai` once their endpoints are confirmed. Each is one async
      in-page function: fetch ONE fixed path built from `location.origin`
      (`credentials: "same-origin"`); require the final URL on the same origin, status
      200, `content-type: application/json` and the expected schema; read the ONE declared
      identity field and the admin bit; normalise; hash `nonce || value` with
      `crypto.subtle`; return `{state: found | logged_out (401/403) | indeterminate,
      digest, admin}`. Raw values never cross CDP. No fallback source.
- [ ] `_broker_probe` → for a multi-account entry, after a VALID sentinel or server proof:
      challenge → recipe in the SAME page → answer. `match` plus a matching admin bit →
      valid. `mismatch` → `wrong_account`. Admin-bit mismatch → `privilege_mismatch`.
      `logged_out` → invalid. Anything else, a broker error included → indeterminate.
- [ ] Instances: `INSTANCE_PORTS` += `admin: 9224`, `alt: 9225`. `login`/`logged-in` of an
      item whose `instance` differs from `CLAUDE_BROWSER_INSTANCE` → exit 2, code
      `wrong_instance`, naming the exact prefix to use. Doctor and coordination files work
      per instance as for `private`.
- [ ] Alias resolution in `_resolve_site`: static names first, as today; then broker site
      ids; then aliases. An alias never shadows either, and S1 refuses such an alias.
- [ ] Tests (extend `tests/test_ws5_client.py`; one `launches_chrome` test runs each recipe
      against a local fixture page via `page.route`): match / mismatch / admin-bit
      mismatch / logged_out / wrong content type / cross-origin redirect / non-ASCII;
      an out-of-band account change (the fixture flips its identity between two probes);
      `wrong_instance`; alias resolution order; new client against a pre-WS5 broker
      (closed); leak test over stdout, stderr, the journal and `_RESULT`.

### S3 — agent-login.py, agents.md, scheduler

- [ ] Rows carry `instance`. `checks.json` rows record the instance they were checked in,
      and `row_state` reads a row whose recorded instance differs from the item's current
      `instance` as stale (❓). There is no `displaced` state: the server proof at check
      time decides.
- [ ] agents.md and the overview group multi-account members under their group:
      `✅ gitlab-sdsc-glensk (default; alias gitlab-sdsc; user)` and `✅ gitlab-sdsc-admin
      (ADMIN; own browser: CLAUDE_BROWSER_INSTANCE=admin browser.py up first, … down when
      done)`. `identity_unproven` rows read `⚠ account unproven` and are never ✅. Fixed
      vocabulary only.
- [ ] `-c`: default-instance items as today. For each role instance: start it only if it
      was down, run the checks (logins only for promoted items, same gates as today), and
      stop it again if this run started it. An admin session is therefore not running in
      any browser between uses. `identity_unproven` items are never logged in by `-c`.
- [ ] `-x` matrix: columns `instance`, `multi`, `identity`, `privilege`, `alias`,
      `same-account`.
- [ ] `-s A B`: the broker's `same_account` answer, enum only.
- [ ] Tests in `tests/test_agent_login.py`: grouped rendering (no username, fixed
      vocabulary); instance prefix in agents.md; `-c` starts and stops only instances
      that were down; a stale row after an instance change; unproven rows never ✅ and
      never logged in.

### S4 — migration and live acceptance (main session; Albert's Touch ID for vault writes)

- [ ] mydotfiles `bin/broker-add.py`: add columns for `agent_instance`, `agent_privilege`,
      `agent_identity`, `agent_same_account_as` and `agent_alias` (short options without
      collisions), with validation reused from broker/vault.py. Separate commit in
      mydotfiles.
- [ ] `agent-login.py -s docker docker-hub` and `-s custos-admin runai-admin`: same →
      Albert merges or declares same-account; different → separate instances.
- [ ] Set the fields per item (proposal in the table above, after Albert's answers), then
      `agent-login.py -x`: no in-instance conflict, no refusal.
- [ ] Disposable-instance doctor after the instance change:
      `CLAUDE_BROWSER_CACHE_DIR=<tmp> bin/browser.py --cdp-port <free port> up`, `doctor`,
      `down`.
- [ ] Per pair: one positive proof in the item's own instance, and one wrong-sibling proof
      (the recipe in instance A against item B's challenge must answer `mismatch`). Free
      probes otherwise; a login only under the attempt policy.
- [ ] navidrome / runai / custos-admin endpoints: confirm at their WS2 candidate logins.
      Until then those groups stay `identity_unproven`.
- [ ] Update README (item fields, "Accounts that share a site", instances), AGENTS.md
      (invariant: one account per conflict group per instance; a multi-account item passes
      only with the server identity proof; values never leave page or broker) and the
      parent plan's WS5 box. Close tp#833 through the review flow.

### S5 — onboarding rule (with WS3)

- [ ] WS3's static validation uses `scope_conflicts`: a new item that conflicts with an
      existing one must declare `agent_instance`, `agent_privilege` and `agent_identity`
      (or `agent_same_account_as`). The broker's S1 refusal is the enforcement;
      `agent-login.py -V` shows it before install.

## Open questions for Albert (with recommendations)

1. **Fail closed now (S0 before S1–S4).** Until migration, the 8 groups read `⚠ account
   unproven`, and agents cannot use gitlab-sdsc, abs, navidrome, dsm, authentik, runai or
   docker through the broker for a few days. Recommended: yes. Acting as the wrong account
   (e.g. ADMIN) is worse than a short outage.
2. **Default member and instance per group.** Recommended as in the table: gitlab-sdsc →
   glensk, abs → albert, navidrome → albert, dsm → readonly, authentik → glensk, runai →
   test3; admin members in `admin`; gitlab-sdsc-test, docker-hub and (if it conflicts)
   custos-admin in `alt`.
3. **docker vs docker-hub.** Recommended: decide after `agent-login.py -s docker
   docker-hub`. Same → merge into one item. Different → docker-hub goes to `alt`, and both
   stay unproven until a Docker identity endpoint exists. Or keep only the one agents
   need.
4. **custos-admin vs runai-admin.** Recommended: keep the host-level conflict (conservative)
   and put custos-admin in `alt`, unless `-s` shows the same account. Realm-path cookie
   scopes stay deferred.
5. **Admin UI access via MCP.** The `admin` instance is reachable only through browser.py
   (`CLAUDE_BROWSER_INSTANCE=admin`), not through the default Playwright MCP. Recommended:
   keep it that way (least privilege). A `cb-admin` MCP config can be added later if a
   real need appears.

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
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pytest -q tests/test_ws5_broker.py tests/test_ws5_client.py tests/test_agent_login.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pytest -q tests
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pre-commit run --all-files
cd /Users/albert/obsidian/42-Git/home/browser-login && install/install.sh -n
cd /Users/albert/obsidian/42-Git/home/browser-login && bin/browser.py -h
```
