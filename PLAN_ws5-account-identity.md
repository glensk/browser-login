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

**Groups (cookie-host overlap, from the `sites` snapshot 2026-10-11):**

| Scope (cookie hosts)                       | Items                                                      |
| :----------------------------------------- | :--------------------------------------------------------- |
| `gitlab.datascience.ch`                    | gitlab-sdsc-admin, gitlab-sdsc-glensk, gitlab-sdsc-test    |
| `audiobookshelf.dom42.space` (+ storage)   | abs-albert, abs-root                                       |
| `music.dom42.space` (+ storage)            | navidrome-albert, navidrome-root                           |
| `synology.dom42.space`                     | dsm-albert, dsm-readonly                                   |
| `auth.dev.renku.ch`                        | authentik-akadmin, authentik-glensk                        |
| `sdsc.run.ai`, `custos.datascience.ch`     | runai-admin, runai-test3, **custos-admin** (new finding)   |
| `docker.com`                               | docker, docker-hub                                         |
| `www.myfritz.net`, `sso.myfritz.net`       | myfritz-alzenau, myfritz-prilly (being merged by Albert)   |

custos-admin is not in the ticket. Its `cookie_hosts` (`custos.datascience.ch`) overlap the
runai items' Keycloak host. Keycloak cookies are path-scoped per realm, so the two may
coexist in a browser, but `_broker_replace_cookies` clears host-wide (every path). Each
runai injection therefore deletes the custos-admin session, and the other way round.

docker vs docker-hub: the broker's password fingerprints differ (len 16 `fecd` vs len 19
`7bc2`), so they are two accounts, or one of the copies is stale. The `account_tag` below
answers this without printing a username.

**Design in one paragraph.** (1) The broker derives **scope groups** (cookie-scope
overlap) and an opaque **`account_tag`** per item (an HMAC of the normalised username under
a root-only broker key). (2) Every item in a group with two or more distinct tags is
**multi-account**. Its `logged-in` passes only after an **identity proof**: a reviewed,
named identity recipe runs in the probe page. It reads the account from a server-validated
same-origin API (or an exact-match DOM text), hashes every candidate value in-page with a
fresh client salt, and the broker's new `identity_verify` op answers match/mismatch. No
username ever leaves the broker or the page. A mismatch fails with phase `client-proof`,
code `wrong_account`. (3) A client-side **scope ledger** records which item was injected
last. Injecting one sibling marks the others `displaced` in the agent-login state. (4)
Concurrency: **swap on demand under a per-scope account lease**. `login SITE` re-injects
the right account (a broker profile re-export, normally no password submit). A swap to a
different account while another account's lease is live exits 75 (busy). (5) **Least
privilege**: `agent_privilege` per item, one default member per group reachable under a
group alias, `-c` restores the default when no lease is live, and agents.md shows `admin`.

**Why not per-account browser instances (now).** `CLAUDE_BROWSER_INSTANCE` (`INSTANCE_PORTS
= {"": 9222, "private": 9223}`, bin/browser.py:201) runs a whole second Chromium: its own
profile, port, coordination files and idle stop. That costs roughly 300–500 MB RSS each.
More importantly, the Playwright MCP `browser_*` tools are bound to 9222, so a second
instance serves browser.py consumers only, never MCP-driven agents. The anthropic
precedent (`login anthropic -e EMAIL`, private instance) exists because a claude.ai
session cannot be re-exported, whereas a broker swap is a cheap re-export of the broker's
own per-site profile. CDP browser contexts are rejected: AGENTS.md forbids
`browserContextId`/`new_context()` for owned tabs, MCP cannot see them, and they die with
the connection that created them. Revisit instances only if scope-lease contention shows
up (the journal counts busy exits per scope).

**Why the Verification block is not strict-eligible (intended).** It runs pytest, mypy and
pylint, which execute repository code. The live steps are manual acceptance steps under the
parent plan's attempt policy (PLAN_agent-login-repair.md): broker install, vault field
edits (Albert's Touch ID via broker-add), shared-browser probes and one swap canary per
group.

**Dependencies.** The broker slice (S1) goes after the WS1a broker release in the
integration queue (PLAN_agent-login-repair.md, "WS1a release order"). browser.py changes
land only when `browser.py clients` shows no registered exec client and no maintenance
record is live. WS3 (onboarding guard) consumes S5's rule.

## Identity sources per group

Read-only inspection 2026-10-11: disposable owned tabs (`browser.py eval-fresh`). Only
HTTP status, JSON key names, element presence and value lengths were printed, never a
value.

| Group       | Recipe (`agent_identity`) | Source                                                                                                                                                                     | Privilege signal                    | Evidence                                                                                                  |
| :---------- | :------------------------ | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :---------------------------------- | :-------------------------------------------------------------------------------------------------------- |
| gitlab-sdsc | `gitlab`                  | `GET /api/v4/user` (session cookie) → `username`, `email`; fallback `window.gon.current_username`                                                                          | `is_admin`                          | live: 200; keys `username`, `email`, `is_admin` present; `gon.current_username` is a string               |
| abs         | `audiobookshelf`          | `GET <base>/api/me` with `Authorization: Bearer localStorage.token` (`<base>` = check-URL path, `/audiobookshelf`) → `username`, `email`                                   | `type` (root/admin/user)            | live: 200; keys present; `/api/authorize` gives the same under `user.`                                   |
| navidrome   | `navidrome`               | server check `GET /api/keepalive/keepalive` with `x-nd-authorization: Bearer localStorage.token` must be 200; identity = the JWT payload's `sub` (+ localStorage `username`) | JWT `adm`                           | logged out now: from Navidrome's source, moderate confidence; confirm at the first candidate login        |
| dsm         | `dsm`                     | `GET /webapi/entry.cgi?api=SYNO.Core.NormalUser&method=get&version=1` with `X-SYNO-TOKEN: SYNO.SDS.Session.SynoToken` → `data.username`, `data.email`                      | `SYNO.SDS.Session.is_admin` (check) | logged out now: the unauthenticated call answers `success:false`, code 119 (fails closed); confirm keys   |
| authentik   | `authentik`               | `GET /api/v3/core/users/me/` → `user.username`, `user.email`; a non-null `original` (impersonation) → indeterminate                                                        | `user.is_superuser`                 | logged out now: authentik API docs, high confidence on path and keys                                     |
| runai       | — (discover)              | unknown; candidates: the Run:ai UI's OIDC token claims `preferred_username`/`email`, or a Run:ai `me` endpoint; custos-admin: Keycloak admin console `whoami`               | token roles                         | both logged out, no sentinel yet; discover at the WS2 runai candidate login (parent plan)                |
| docker      | — (discover)              | weak candidate: `/` redirects to `/accounts/<namespace>` (last account context, may be an org); `hub.docker.com/v2/user/` answers 401 to cookie auth                        | —                                   | live: account menu has no readable name (1-char avatar); needs a better source, or a merge                 |
| myfritz     | none (merge)              | Albert merges the Alzenau box into the gmail account → one `myfritz` item, no group                                                                                         | —                                   | Albert's decision 2026-10-11 (parent plan)                                                               |

A group without a recipe falls back to the **scope ledger** (weaker: it catches swaps done
through browser.py, not a human logging in by hand). Such items read `identity: ledger` in
the matrix and never pass when the ledger names another account.

## Steps

### S1 — broker (release via install.sh; after the WS1a broker release)

- [ ] Vault fields in `broker/vault.py` `site_item_from_json` (validated, else `refused`):
  - `agent_identity`: one name from a new registry `broker/identity.py` `IDENTITIES`
    (like `agent_session_refresh` / `SESSION_REFRESHERS`), or `text:<css>` (one plain CSS
    selector via `selector_ok`; the trimmed, casefolded text must EQUAL the username — never
    a substring: `albert` is a substring of `albertadmin`). No free-form fetch spec in the
    vault.
  - `agent_privilege`: `admin` | `user` | `readonly`; empty = `user`.
  - `agent_alias`: a slug the group's DEFAULT member answers to (e.g. `gitlab-sdsc`). It is
    unique across items, never equal to a site id, and must not reveal the account
    (reuse `_attempt_group`'s username check).
- [ ] `account_tag`: HMAC-SHA256 under a 32-byte key generated by `install.sh` (root 0600,
      `/var/db/login-broker/account-tag.key`, kept across releases), over the casefolded,
      trimmed username, truncated to 12 hex. It goes into `SiteItem.public()`. It is
      stable, means nothing without the key, and equal tags = the same account. It is never
      logged as a value next to a site in the audit.
- [ ] Scope groups in `BrokerDaemon._sites`: items whose cookie scopes intersect (domain
      match both ways: `docker.com` covers `app.docker.com`; the same storage origin also
      counts) form one group. It gets an opaque id (`scope-` + 8 hex of the sorted member
      site ids). Each entry gets `scope_group`, `scope_members`, `multi_account` (≥2 distinct
      tags in the group), `identity` (recipe name, `text`, or `none`), `privilege`,
      `alias`. A pure function, unit-tested apart from the daemon.
- [ ] Multi-account items without `agent_identity`: NOT refused in S1 (migration). Their
      entry gets `identity_required: true`, and the client treats them as unproven (S2).
      S5 turns this into a refusal once every existing item is migrated.
- [ ] New op `identity_verify {site, salt, digests[]}`: `salt` is 16–64 random bytes
      (base64) chosen by the client, `digests` is at most 4 hex SHA-256 values of
      `salt || normalised candidate`. The answer is `{ok, match: bool}`, nothing else. It is
      audited (op, site, result; never salt or digests), needs no limiter, and is capped per
      site (e.g. 30/min, then `rate_limited`) so it cannot serve as a fast username oracle.
- [ ] Broker-side proof: after a login (and on profile reuse before export) the broker
      runs the same recipe in its OWN page against the plain username (in-process, no
      hashing). A mismatch → phase `broker-proof`, code `wrong_account`, no bundle. This
      catches an IdP SSO session that silently logs the broker profile into another
      account.
- [ ] New op `same_account {sites: [a, b]}` → `{ok, same: bool}` for Albert's questions
      (docker/docker-hub, custos-admin/runai-admin). It is just a tag comparison, audited.
      Exposed as `agent-login.py -s A B`.
- [ ] Tests (`tests/test_ws5_broker.py`): field validation and refusals; tag stability,
      key dependence, equality for the same username, no username substring in the tag
      or the alias; group derivation (parent domain, disjoint hosts, storage-only overlap,
      three-member group, custos/runai); `identity_verify` match / mismatch / malformed
      salt / too many digests / rate cap; no username, salt or digest in the audit lines
      or error texts (fixture username `zz-ws5-secret-user`, grepped over every output);
      broker-proof `wrong_account` with a fake page.

### S2 — client `bin/browser.py` (in a worktree; lands when no exec client is registered)

- [ ] Identity recipes in `broker/identity.py` (shared JS strings, imported by browser.py
      like `broker.recipes`): `gitlab`, `audiobookshelf`, `navidrome`, `dsm`, `authentik`
      first. Each is one async in-page function `(salt, recipeArgs) → {state, digests,
      privileged}`: it fetches same-origin only (`credentials: "same-origin"`, the URL built
      from `location.origin`, never from vault data), extracts its fixed candidate fields,
      normalises (trim + casefold), hashes with `crypto.subtle.digest('SHA-256', salt||v)`,
      and returns `state` ∈ `found` / `logged_out` (401/403) / `absent` / `error`. Raw
      values never cross CDP.
- [ ] `_broker_probe` → after a VALID sentinel/server proof, for an entry with
      `multi_account`: run the recipe in the SAME page and call `identity_verify`.
      Match → valid. Mismatch → `_result_fail("client-proof", "wrong_account")`, exit 2.
      `logged_out` → invalid. `absent`/`error`/broker down → indeterminate (never valid).
      `text:` recipes compare in-page the same way. Without a recipe → the ledger
      (next step); an empty ledger → `identity_unproven` (indeterminate).
- [ ] Scope ledger `<cache>/scope-ledger.json` (per instance, flock, atomic write):
      `{scope_group: {site, account_tag, at, via: inject|proof}}`. It is written after
      every verified injection and every passing identity proof. A passing proof by a
      sibling with the same `account_tag` counts as the same holder (same-account
      siblings are not conflicts).
- [ ] Swap correctness: before injecting into a multi-account scope, clear every
      sibling's declared `storage_keys` on the shared origins too, not only the cookies
      (abs/navidrome keep their token in localStorage; a key the sibling has and the new
      bundle lacks would survive). Use the existing compare-and-swap storage helpers.
- [ ] Scope account lease `<cache>/scope-lease/<scope_group>.json` (flock; holder =
      `account_tag` + site + `until`; liveness = time only, because agents call browser.py
      as separate processes):
  - `login SITE` (or a passing `logged-in SITE`) for the holding account sets or extends
    `until = now + hold` (`-H/--hold MIN`, default 10, max 60);
  - `login SITE` for ANOTHER account while the lease is live: wait up to `-w/--wait S`
    (default 0), then exit 75 with `busy: <holder site> holds <alias> until ~HH:MM`
    (fixed vocabulary, the site id is public);
  - `browser.py release SITE` ends it early; `-F/--force-swap` overrides, journaled, for
    Albert and for `-c`'s restore only when the lease is expired;
  - `logout SITE` also releases.
- [ ] Alias resolution in `_broker_entry_or_rc`: `login gitlab-sdsc` / `logged-in
      gitlab-sdsc` resolve to the member whose `alias` matches. An alias never shadows a
      site id.
- [ ] Privilege cross-check: when the recipe reports `privileged` and the item is not
      `agent_privilege: admin`, record `privilege_mismatch` in `_RESULT` (a warning for
      `-x`, not a failure). The reverse (admin item, non-admin account) is a warning too.
- [ ] Tests (`tests/test_ws5_client.py`, fake CDP + fake pages; one `launches_chrome` test
      runs each recipe's JS against a local fixture page with `page.route`): the tp#833
      regression (three gitlab items, the browser holds admin → `logged-in
      gitlab-sdsc-test` exits 2, code `wrong_account`); match / mismatch / logged_out /
      absent; ledger with and without a recipe; same-tag siblings both pass; storage
      clearing on swap; lease busy (75), extension, expiry, `release`, `-F`; alias
      resolution and refusal of shadowing; leak test (fixture username never in stdout,
      stderr, the journal, `_RESULT`, the ledger or the lease file).

### S3 — `agent-login.py` + agents.md + scheduler

- [ ] State: after a verified injection of X, every sibling with another `account_tag`
      gets `displaced` in `site-state.json` (phase `client-proof`, code `wrong_account`,
      fixed text "the shared browser holds <sibling site>"). It is not a failure: no mail,
      no quarantine, no limiter.
- [ ] Overview and agents.md: one block per multi-account group, members indented:
      `✅ gitlab-sdsc-glensk (default, user) — in the browser`,
      `⇄ gitlab-sdsc-admin (ADMIN) — swap: browser.py login gitlab-sdsc-admin (logs the
      other account out for every agent; takes a 10-min lease)`. Admin members always
      carry `ADMIN`. An unproven group reads `⚠ account unproven` and is never ✅.
- [ ] `-c` (WS1a scheduler): a group is checked ONCE. Free identity probe of the current
      holder. If no lease is live and the holder is not the default member, log in the
      DEFAULT member (least privilege at rest; a re-export, normally no submit). If the
      holder is the default and valid, ✅ it and show the others as `⇄`. Never inject a
      non-default member, never swap during a live lease, never count `displaced` as a
      failure. Unproven groups (`identity_required`, no recipe, no ledger) are not logged
      in by `-c`.
- [ ] `-x` matrix: columns `scope group`, `multi`, `identity` (recipe/text/ledger/none),
      `privilege`, `default`, `holder`.
- [ ] `-s A B` (same account?) via the broker's `same_account` op.
- [ ] Tests in `tests/test_agent_login.py`: group rendering (no username, fixed
      vocabulary only), `-c` checking a group once, default restore, no swap under a lease,
      displaced ≠ failure, unproven groups skipped.

### S4 — migration and live acceptance (main session; Albert's Touch ID for vault writes)

- [ ] Extend mydotfiles `bin/broker-add.py` with the three fields (`-I/--identity`,
      `-R/--privilege`, `-D/--alias`) and reuse its value validation. This is a separate
      commit in mydotfiles.
- [ ] Run `agent-login.py -s docker docker-hub` and `-s custos-admin runai-admin`.
      Same → ask Albert to merge (delete one item). Different → keep both, identity
      required.
- [ ] Set the fields per item (defaults from Q1 below), check with `agent-login.py -x`.
- [ ] Per group, one swap canary under the attempt policy, free probes otherwise:
      `login <non-default>` → `logged-in <default>` must fail `wrong_account` → `login
      <default>` (lease expired or `release`) → ✅. Limiter counters unchanged for
      re-exports.
- [ ] runai / custos-admin / docker recipes: discovered at their WS2 candidate logins.
      Until then those groups run on the ledger and read `⚠ account unproven` until the
      first ledgered injection.
- [ ] Update README (broker item fields, "Accounts that share a site", lease, alias),
      AGENTS.md (an identity-proof invariant: a multi-account item never passes without
      the proof or the ledger; values never leave page or broker) and the parent plan's
      WS5 box. Close tp#833 through the review flow.

### S5 — WS3 onboarding rule (with WS3)

- [ ] A new item that joins a scope group with another `account_tag` must declare
      `agent_identity` and `agent_privilege`, and the group must have exactly one `alias`
      default. Otherwise the broker refuses it (`refused: multi-account scope needs
      agent_identity`). Enable the refusal only after S4 has migrated every existing item;
      until then it is a warning in `-x` / `-V`.

## Open questions for Albert (with recommendations)

1. **Default (alias) member per group.** Recommended: `gitlab-sdsc` → gitlab-sdsc-glensk,
   `abs` → abs-albert, `navidrome` → navidrome-albert, `dsm` → dsm-readonly, `authentik` →
   authentik-glensk, `runai` → runai-test3. Admin members are reachable only by their full
   site id.
2. **Swap semantics (tp#833's open question).** Recommended: swap on demand + identity
   proof + 10-minute lease. Separate instances only if lease contention appears.
3. **Least privilege at rest.** Recommended: `-c` restores the default member when no lease
   is live, so admin sessions do not linger in the shared browser.
4. **docker vs docker-hub.** Their password fingerprints differ. Recommended: decide after
   `agent-login.py -s docker docker-hub`. If they are the same account, merge into one item.
5. **custos-admin vs runai-*.** They share the Keycloak host. Recommended: keep the
   host-level group (conservative). Realm-path-aware cookie scopes (`agent_cookie_paths`)
   are deferred until a real need appears.

## Implementation slicing

| Slice | Content                                                         | Who                                    | Gate                                                   |
| :---- | :-------------------------------------------------------------- | :------------------------------------- | :----------------------------------------------------- |
| S1    | broker fields, tag, groups, `identity_verify`, broker-proof     | opus-builder in a worktree             | after the WS1a broker release; install.sh + selfcheck  |
| S2    | client recipes, proof, ledger, storage clearing, lease, alias   | opus-builder in a worktree             | after S1 is deployed; no exec client registered        |
| S3    | agent-login state, overview/agents.md, `-c`, `-x`, `-s`         | opus-builder (same or next worktree)   | after S2                                               |
| S4    | broker-add fields (mydotfiles), vault migration, live canaries  | main session + Albert (Touch ID)       | after S1 (fields), after S2/S3 (acceptance)            |
| S5    | onboarding refusal                                              | with WS3                               | after S4                                               |

## Verification

```commands
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run ruff format --check bin/ broker/ agent-login.py agent_login_jobs.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run ruff check bin/ broker/ agent-login.py agent_login_jobs.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run mypy bin/browser.py agent-login.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pylint bin/browser.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pytest -q tests/test_ws5_broker.py tests/test_ws5_client.py tests/test_agent_login.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pytest -q tests
cd /Users/albert/obsidian/42-Git/home/browser-login && bin/browser.py -h
```
