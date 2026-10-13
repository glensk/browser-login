## Session

Resume: `c --resume 3871ad21-0f16-4b68-828e-f9eb1f7a6847`

# WS3 — the onboarding guard: validate, promote on a budget, remove cleanly

## Context

Part of `plans-done/PLAN_agent-login-repair_DONE.md` (box WS3). Between 2026-10-09 and 2026-10-11 most broker
failures came from items that were added without a validated setup:

- batch-added items with no sentinel;
- stale vault passwords (npm, runai-test3);
- a check origin that was also a fill origin;
- same-scope siblings that silently overwrote each other (WS5);
- a NEW item that refuses an established one (WS5 S1: the in-instance rule refuses the later
  site id).

Removed items left state behind: zendesk's `last-check.json` row, and soon docker / docker-hub,
which leave the broker (Albert, 2026-10-11).

WS3 makes every future item pass four things:

1. a static review before it is usable;
2. ONE budgeted promotion transaction;
3. a removal path that leaves nothing behind;
4. a short onboarding checklist that names every failure mode learned so far.

**Debate:** Codex (gpt-5.6-sol), 2 rounds, converged by the judge. 15 + 2 objections, all
accepted (two parts of O6 were rejected with evidence and Codex agreed). The ledgers are in the
session scratchpad (`ws3/`).

**The Verification block is not strict-eligible, and that is intended.** It runs ruff, mypy,
pylint, pytest and pre-commit, which execute repository code. Live steps are NOT in the block:
`install.sh`, the raw-vault check after it, the docker removal and one promotion. They are manual
acceptance steps for the main session, under the parent plan's attempt policy.

Two parts change the broker and need a release (`sudo install/install.sh`): the storage-key rule
(D8) and the `forget` op (D7). mydotfiles is not edited here: `broker-add.py` gets a spec (below).

## Design

### D1 — one review, built on the broker's own rules (`broker/onboarding.py`)

`Finding(site, level, code, text, related)`. `code` is a fixed vocabulary, and `text` is built
from fixed words plus ids and hosts that went through `safe_id` / `safe_host` (anything else
reads `<invalid>`). The broker's refusal reason is the only free text: control characters are
stripped and it is capped at 200 characters. It reaches Albert's terminal only, never agents.md.
There are four levels:

| level      | meaning                                                                | enforced where                                  |
| :--------- | :--------------------------------------------------------------------- | :---------------------------------------------- |
| `refused`  | the broker refuses it: its OWN code decides                            | the broker                                      |
| `unusable` | accepted, but it can never become a proven ✅                           | `-p` refuses; `-V` exit 1                       |
| `risk`     | accepted and usable, but the config is dangerous                       | `-p` refuses; `-c` never logs it in; `-V` exit 1 |
| `hint`     | a suggestion                                                           | never                                           |

The broker's own code decides `refused`: `vault.site_item_from_json` and `vault.identity_rules`.

**Item findings** (`item_findings(view, views)`) are pure, over the broker's public `sites`
view:

- **`refused`**
  - `broker_refused`: the broker's reason.
- **`unusable`**
  - `no_proof`: no `strict_proof`. That is the broker's `SiteItem.has_proof`, a sentinel OR a
    server proof (CSCS).
  - `check_on_fill_origin`: the check origin is a fill origin AND there is no strict proof.
    Only the old proof reads fill origins (`recipes.check_proof_reason` does not). broker-add
    requires `-L` in this case, and ~25 working sentinel items have check origin == fill
    origin (debate O6, Codex agreed).
  - `account_unproven` (the WS5 S5 rule): `scope_conflicts` / `multi_account` and not
    `identity.proof_ready`. The text names the siblings and the fields to declare.
- **`risk`**
  - `public_suffix_scope`: the cookie host is a single label, a PUBLIC IP, or a public suffix.
    The check uses the vendored Public Suffix List (`broker/public_suffix_list.dat`, MPL-2.0,
    ICANN + PRIVATE; version and sha256 are pinned in the module, and the loader refuses a
    different file → `risk / psl_unavailable`).
  - `unrelated_cookie_host`: the cookie host is related to none of the item's fill, check,
    login, proof or storage hosts.
  - `storage_keys`: the shared storage rule (D8).
  - `storage_origin_unrelated`: a storage origin that is none of the item's fill, check, login
    or proof hosts.
- **`hint`**
  - `storage_no_refresher`: a storage token without a refresher (the NPM learning).
  - `identity_like_key`: a key named like an account claim (S4c O3: a page claim proves
    nothing).
  - `attempt_group`: a declared same-account pair whose groups differ. Never enforced (master
    plan O6). A registrable-domain heuristic was dropped: the replay suggested groups between
    every pair of `*.dom42.space` apps, which are separate accounts.
  - `wide_scope`: the cookie host is a strict parent of every own host, with no
    `cookie_names`. It is not blocking: a parent-domain session cookie is common (cloudflare,
    cscs, galaxus), and an overlap with ANOTHER item is already `account_unproven`.
  - `idp_cookie_host`: an identity-provider host is listed exactly.

**Planned review** (`review_planned(manifest, views, *, dev)`) covers a planned change BEFORE
the vault write.

- The MANIFEST is `{"items": [...], "removes": [site, …]}`, or one item.
- Each item is `{name, fields, login?: {username}, replaces?, username_form?, reveals?, id?}`.
  - `fields` is an object or Bitwarden's `[{name, value}]`.
  - A password, or any other `login` key, is refused.
- **Steps:**
  1. Planned items are built with the broker's own `site_item_from_json`.
  2. Every other listed item becomes a stand-in rebuilt from its view (`item_from_view`).
  3. The broker's `identity_rules` runs over the collection BEFORE and AFTER the change. The
     change is atomic: the rows of a batch can conflict with each other, and a same-account
     pair is judged together.
- **Results:**
  - A planned site id that is already listed (or twice in the manifest) is
    `refused / duplicate_site`, unless the item declares `"replaces": SITE` (an update).
  - Every established item the change refuses is `refused / displaced`.
  - Every item it turns multi-account and unprovable is `unusable / made_unproven`.
  - Then come the planned items' own item findings in the AFTER collection.
- **The username never leaves the vault.** A planned item with username-dependent fields
  (`agent_identity`, `agent_alias`, `agent_attempt_group`) and no username is
  `unusable / username_unchecked`, unless the manifest carries broker-add's NON-SECRET derived
  facts:
  - `username_form` (`username` | `email`): only then do the broker's rules run on a
    placeholder of that form;
  - `reveals: {alias, attempt_group}`: `true` → `refused / reveals_account`.
- **A test pins stand-in idempotence:** stand-ins from `public(build_items(raws))` give the
  same refusals and `multi_account` flags as `build_items(raws)`.

### D2 — `agent-login.py -V/--validate` (alias `--validate-selectors`)

- `-V`: the plain-CSS selector audit, then every listed item's findings, most severe first
  (`-r`: a fresh listing).
  - Read-only.
  - Exit 0 when nothing is at `refused` / `unusable` / `risk`, 1 otherwise, 3 when there is no
    list.
- `-V -i MANIFEST` (`-i -` = stdin): the planned review against the snapshot. The snapshot must
  be fresh (else `-r`). Same exit codes; exit 2 for a malformed manifest.

### D3 — config digest: a promotion holds for ONE configuration (debate O1)

- `onboarding.config_digest(view)`: sha256 over the view fields that change what a login does,
  where its session lives or how it is proven:
  - fill origins and cookie hosts / scopes / names;
  - storage keys and URLs;
  - sentinel, pre-click, fresh login, proof origins and attempt group;
  - refresher, no-submit, session days, username-only and strict proof;
  - instance, privilege, identity and same-account.
- `promote` stores it in `site-state.json` (`config`).
- `browser.py _broker_probe_page` records the digest of the entry it proved (`-R` field
  `config`), and `record_check` keeps it in checks.json.
- **Scheduled gate:** `als.scheduled_gate(site, config=…)` refuses the following (fail closed);
  `browser.py login -s` calls it with the listed entry's digest:
  - `changed`: a usable entry whose stored digest differs;
  - `config_unknown`: a usable entry without one.
- **Adoption:** a usable entry from before WS3 adopts the current digest ONCE, audited, only from
  a FRESH live listing (`-S` / `-r` / `-p`).
- agent-login's `-c` shows `changed — re-promote: ./agent-login.py -p SITE`.

### D4 — ONE promotion transaction `-p SITE` and its budget (debate O2–O5)

1. A fresh listing.
2. The item must:
   - be listed and not refused;
   - be a broker login (not assisted, no-submit or Safari);
   - have a strict proof (`strict_proof`, so a server-proof site like cscs counts);
   - have no blocking finding;
   - not be account-unproven;
   - not be quarantined.
3. Usable for its current digest → "already usable", exit 0.
4. The latest check is a fresh, strict ✅ of THIS digest (with `identity: match` for a
   multi-account item, from its own instance) → promote. No login.
5. Otherwise, the trial gate:
   - the limiter state of the fresh listing is not `locked` / `cooldown` / `quarantined` /
     `busy`;
   - `als.claim_trial(site)` succeeds.
6. Then EXACTLY ONE `browser.py login SITE -R`, non-scheduled, in the item's instance. Its
   built-in free check (`_broker_already`, route `already`) is the check-only probe, and its
   built-in verify (`_broker_check_entry`: strict proof, identity, digest) is the proof. There is
   no outer probe, no re-probe, no retry (also none after a 124).
7. The record is written, then `als.finish_trial(site, result)`. A strict ✅ with the matching
   digest promotes. A post-submit failure is quarantined by browser.py as today.

**Budget** (`site-state.json` → `trial`):

- `claim_trial` holds the site-state flock. It refuses when:
  - the site is usable for its digest;
  - it is quarantined;
  - its budget is spent;
  - a LIVE in-flight claim exists.
- Otherwise it writes `inflight {pid, pid_start, at}`. Liveness is pid + start time
  (`ps -o lstart`, LC_ALL=C TZ=UTC: the limiter's rule).
- A dead owner's claim turns into spent, outcome `unknown`.
- `finish_trial` refunds only when the result proves no broker request reached the password:
  - route `already`;
  - or `submitted` False in phase `precheck` / `limiter` / `vault` / `profile-proof`.
- Re-arm is its own audited action, `-E/--rearm SITE`. `-Q` releases only the quarantine.
- **`-t SITE`:**
  - for a broker site that is not usable for its digest, it takes the same claim (one login,
    refused when spent);
  - for a usable site, and for Safari / assisted sites, it is unchanged.

### D5 — `-c`

`schedule_gate` adds:

- `changed` / `config_unknown` (D3);
- `onboarding_risk`: a row with a `risk` finding is never logged in unattended. Its line names
  the finding.

`refused` / `unusable` rows were already skipped (status refused, needs-sentinel, unproven).

### D6 — `browser.py logout` clears storage too (debate O11)

- After the cookies, `logout` clears the item's declared `storage_keys` and the recipe's token
  key (`identity.foreign_storage_keys`).
- It uses the reviewed `_broker_clear_foreign_storage` machinery: an owned tab, the SW bypass, a
  nonce document and a read-back.
- Exit 2 when it cannot be confirmed.

### D7 — removal: `agent-login.py -D/--remove SITE`, two phases, audited (debate O10, O12)

- **Phase 1** (the site is still in a FRESH listing):
  1. Demote to `pending` (audited, "remove"), so `-c` never logs it in again.
  2. `browser.py logout SITE` in the item's instance: the broker profile, the scoped cookies and
     the declared storage. A non-zero exit stops here, and the site stays demoted.
  3. Print the vault step: `broker-add.py NAME -D` (spec), or the web vault, then `-D` again.
  - A static target (`TARGETS`) is refused.
- **Phase 2** (a fresh listing does NOT have it):
  1. The broker op `forget` (below).
  2. Delete the site from `checks.json`, `last-check.json` and `site-state.json`.
  3. In all four cache dirs (`~/.cache/claude-browser{,-private,-admin,-alt}`, or
     `$CLAUDE_BROWSER_CACHE_DIR`), delete `session-age/<site>.json` (+ its `.lock`) and
     `login-log/<site>.jsonl`.
     - Each data file is deleted under its lock. The lock path is unlinked last, while still
       held: every session-age writer runs only after a verified injection of a LISTED item.
  4. Rewrite agents.md.
  5. Append one line to `audit.jsonl` (action, site, time, argv). That line is the ONLY trace
     left, on purpose.
- No fresh listing → refused, nothing changed.
- A re-added item starts `pending` with a fresh budget, like any new item.
- **Broker op `forget {site}`**, run by the LIVE daemon (no root step, no separate process):
  1. It takes the daemon's own site lock (the lock every login of the site holds).
  2. `_items(fresh=True)` replaces the daemon's item cache, so a later login answers
     `unknown_site`. VaultError → refused. Any item with that site id (refused ones included) →
     `still_listed`, nothing touched.
  3. `Limiter.prune_site(site, keep_groups)` holds the limiter flock:
     - a live in-flight mark on the site or a bound group → `busy`;
     - otherwise it drops the site key and its bindings;
     - it drops a bound group key ONLY when no other limiter entry binds it AND no fresh vault
       item declares that group.
  4. `IdentityGuard.reset(site)`.
  5. It removes `profiles/<site>` (a symlink or non-directory is reported, not touched) and the
     regular file `last-failure-<site>.png`.
  6. One audit line: counts and flags only. It is idempotent.
- It may be served to the agent uid. It acts only on a site id that NO vault item carries after
  a fresh read under the site lock, and bringing that site back needs a vault write (Albert's
  Touch ID).
- **Automatic prune** (`-S` / `-r`): the rule is unchanged (entries with audit or quarantine
  survive), and it also deletes the session-age files of the sites it prunes.
- **docker / docker-hub (live):** `-D docker -F`, `-D docker-hub -F` (phase 1; `-F` because
  the two are each other's siblings in one scope and instance and both leave), then vault
  removal, then `-D` again for each (phase 2).

### D8 — the storage-key rule, shared by broker and client (debate O7, N1, N2)

- A leaf module `broker/storage_rules.py` (it imports only `broker.origins`) provides
  `parse_storage_keys(value, *, dev) -> (dict | None, problem)`:
  - every mapping key parses to EXACTLY one origin (`parse_fill_origins`, dev keeps
    `http://127.0.0.1`), and two keys that normalise to one origin are refused;
  - at most 8 origins, 1–16 distinct keys each;
  - every key is a string of 1–128 characters without whitespace or control characters.
- `vault.site_item_from_json` uses it in place of the `str(k)` coercion. A bad value refuses the
  item with `bad agent_storage_keys: <fixed reason>`.
- `onboarding` judges a view with the same function.
- Release: right after the install, `./agent-login.py -V -r` (a fresh RAW vault read through the
  new parser). Any item refused with `bad agent_storage_keys` → roll back at once to the previous
  release, then fix the item. The `sites.json` replay (11 storage items, 1–8 keys, 1–20
  printable characters) shows none, but cannot see raw non-string members.

### D9 — docs

- README "Adding a site to the broker":
  - the checklist and the commands (broker-add dry run → `-V -i` → write → `-S` →
    `browser.py logged-in -x` / one approved `login -x` → `broker-add -L` → `-p`);
  - removal (`-D` twice);
  - every failure mode with its symptom and fix.
- The `-V` / `-p` / `-E` / `-D` help, the READONLY help table, the agent-login docstring.
- An AGENTS.md convention bullet.
- The parent plan's WS3 box.

## broker-add spec (mydotfiles; not built here)

1. **Dry run, non-enforcing section** (also `-b`: one combined manifest for the whole batch).
   - **Single-item mirror:** `broker_add_fields.onboarding_findings(final_fields)` mirrors
     `onboarding`'s single-item checks:
     - `no_proof`, `check_on_fill_origin`;
     - `public_suffix_scope` (the same vendored PSL file and digest, copied into the vault-touchid
       snapshot), `unrelated_cookie_host`;
     - `storage_*`, `identity_like_key`, `wide_scope`, `idp_cookie_host`.
   - **Pin:** `test-broker-add.py case_onboarding_pins` loads `broker/onboarding.py` and compares
     codes over `onboarding.PIN_CASES` (`single_item_codes`).
   - **Collection checks:** the process that holds the final fields writes ONE sanitized manifest
     (0600, `~/.local/state/broker-add/planned/<run>.json`) with:
     - the agent_* fields, name and item id;
     - `replaces` (when the item already carries that agent_site);
     - `removes`;
     - `username_form` and `reveals` — never a username or a password.
   - Then it runs `agent-login.py -V -i <manifest>` itself (timeout 60 s) and prints its output
     under `>> onboarding review (not enforced)`. When it cannot run it, it prints the command.
2. **`-D` / `--remove`:**
   - `broker-add.py NAME -D [-n]` removes the item from `agent-login` and deletes ONLY the
     login-owned fields (every `agent_*` except `agent_secret_id` / `agent_secret_fields`).
   - `-D -x` removes it from `agent-secrets` and deletes only those two fields.
   - The item itself and its other collections stay. It runs the Touch ID window like every
     write, and is refused when the item is not in that collection.
   - Before the write it prints the phase-1 reminder (`agent-login.py -D SITE` first, while the
     item is listed). After it, it prints phase 2.

## Steps

- [x] S1 `broker/storage_rules.py` + `vault.py` use; `broker/onboarding.py` (findings, PSL,
      digest, stand-ins, manifest review, `PIN_CASES`); the vendored PSL.
- [x] S2 broker: `Limiter.prune_site`, the `forget` op in `daemon.py`, the docstring and help.
- [x] S3 `agent_login_state.py`:
  - config digest (store, adopt, scheduled gate);
  - `claim_trial` / `finish_trial` / `rearm`;
  - `remove_site` + `audit.jsonl`;
  - cache-file deletion (session-age under lock, login-log), and prune extended.
- [x] S4 `bin/browser.py`: the `config` field in the proof record, the scheduled config gate, and
      the storage clear in `logout`.
- [x] S5 `agent-login.py`: `-V` (+ `-i`), `-p` transaction, `-t` budget, `-E`, `-D`, `-c` gates,
      the adoption.
- [x] S6 Tests (`tests/test_ws3_onboarding.py`, `tests/test_ws3_broker.py`,
      `tests/test_ws3_agent_login.py`): every path named in debate O15. No credential-shaped
      literals.
- [x] S7 Replay on a copy of the live snapshot, recorded here: every finding per item; no
      promoted item gets a `risk`. If one does, it is a remediation item for the main session,
      not a rule change.
- [x] S8 Docs (D9) + parent plan box.
- [x] S9 Lint + the full suite + pre-commit + lint-gate on the changed files.

## Build notes (2026-10-12, worktree; not yet released)

- **S7 replay** (copy of `sites.json`, 45 items, and `site-state.json`; promoted: calibre,
  cscs, mullvad, portainer-ds218, smartsheet, stirling):
  - **No promoted item has a `risk`.** No item at all has a `risk`.
  - `refused`: the 15 WS5 items (privilege missing, as before; docker / docker-hub among
    them).
  - `unusable / no_proof`: eduid, kleinanzeigen.
  - Hints: `wide_scope` ×11, `storage_no_refresher` ×9, `identity_like_key` ×3,
    `idp_cookie_host` ×2.
- **Deviation:** the attempt-group hint is limited to declared same-account pairs. The
  registrable-domain variant suggested a group between every pair of `*.dom42.space` apps
  (separate accounts): noise, not signal. Fill-host sharing is a WS5 scope conflict anyway.
- **Deviation:** `-V` no longer echoes a refused selector's VALUE, only the site and the
  field (debate O14: vault text is never printed raw).
- **Pylint:** the Verification runs it in three groups. One run over `bin/browser.py` +
  `broker/daemon.py` reports a PRE-EXISTING `duplicate-code` (the isolated-world helper is
  copied in both on purpose, WS5 S1/S2). It is not on a changed line.
- **Flakes seen (pre-existing, not WS3):**
  - `tests/test_ws2_npm.py::test_launch_clears_the_items_service_workers`: a Chromium launch
    timed out after 180 s under load; it passes on a rerun.
  - `tests/test_ws2_calibre.py::test_an_old_session_is_renewed_with_a_fresh_login`: it fails
    when run alone, because `_broker_identity_gate` → `_broker_sites` is not stubbed, so it
    relies on an earlier test's cache. It passes in the file run.

## Review round 1 (overseer, 2026-10-12): applied

- [x] **B1 (blocker): the digest no longer drifts with broker releases.**
  - `onboarding.config_canon` hashes a defined canonical subset: the vault-authored
    configuration only, never code-derived or view-format fields.
    - The check URL, sentinel and cookie hosts are resolved values; a default login URL is
      dropped.
    - Host-wide `cookie_scopes` collapse to the sorted hosts form (a pre-S4c view without
      `cookie_scopes` hashes the same).
    - Order-free lists are sorted, empty values are normalised.
    - `strict_proof`, `session_refresh`, `no_submit` and any new view field are not hashed.
  - `CONFIG_V` = 1 is stored with the digest (`config_v`) and is part of the hashed JSON.
  - Re-adoption (`als.adopt_configs`) happens only for a promotion with an OLDER or no
    `config_v`, and only while the latest check is a fresh strict ✅ (`strict_fresh_ok`:
    `proof_v >= 1`, within the status-age limit). It is audited. The former "fill an empty
    config" adoption follows the same rule.
  - A current-version promotion is never re-adopted: a changed item stays `changed`.
  - An older `config_v` reads `config_unknown` in the scheduled gate and in `-c`.
- [x] **S1: `forget` is no limiter-bypass oracle.**
  - It never removes a limiter key that is locked, cooling down or quarantined
    (`Limiter.protected`). Such a site key stays whole, bindings included, so its groups
    stay too.
  - It never removes an identity-guard entry in a lockout, in quarantine or unreadable
    (`IdentityGuard.denial`).
  - Both are reported in `left`, and `-D` prints them with `sudo install/install.sh -r SITE`.
  - Refused (`vault_suspect`): an empty fresh read, or one smaller than half the cached item
    count.
  - Still listed: any item that resolves to the id (its `agent_site`, or the slug of its
    name), refused items included.
  - A refused item now keeps a valid (non-revealing) `agent_attempt_group`, so the keep set
    includes it.
- [x] **S2: phase 1 never logs out a sibling account.** A remaining item of another account
  in the same scope and the same instance (`sibling_in_instance`) → demote only, and say why.
  `-F` forces the logout.
  - docker / docker-hub are each other's siblings while both are listed: use `-D … -F` for
    them.
- [x] **S3: a bad or missing PSL is ONE infrastructure error** (`onboarding.psl_problem`).
  - `-V` reports it once (exit 1), `-c` reports it once into its failures and is not
    gated. (Review round 2: `-p` and `-V -i` now REFUSE while it lasts.)
  - It is never an item finding: only the public-suffix judgement is unknown. A single-label
    host is still judged without the list.
- [x] **S4: the trial budget is refunded** on exit 75 (`busy`) and when browser.py never
  started: an exception before the run (`not_started`), or an exec failure in `-t`.
- [x] **NITs:**
  - a claim whose owner start time is unknown is dead after `TRIAL_STALE_S` (15 min);
  - `_delete_session_age` deletes only the data file under the lock and leaves the empty
    lock file;
  - `_logout_storage_plan` uses `identity.str_list`;
  - the `-V` help says what `-r` does;
  - parentheses in `item_from_view`;
  - onboarding's `_list` reuses `identity.str_list` (was duplicate code).
- **Not a security boundary:** the client state (`site-state.json`, the trial budget,
  quarantine) is same-uid and every agent can write it. The broker limiter (root-owned
  state, `install.sh -r`) is the boundary; the client state is policy plus audit.

## Review round 2 (overseer, 2026-10-12): applied

- [x] **A bad PSL blocks new usable items.** While `psl_problem()` is non-empty, `-p` and
  `-V -i` refuse (exit 1, naming the infrastructure error); `-c` stays ungated. Tested: with
  a broken list, an item with `cookie_hosts=co.uk` cannot be promoted.
- [x] **A refund only for a child that provably never started.**
  - `run_browser` catches the OSError of `subprocess.run`'s Popen/exec and returns
    `BrowserRun(started=False)`. `run` raises OSError only there; a child that ran ends in a
    return code or TimeoutExpired.
  - `derived_result` maps that run to `precheck` · `not_started`, and `login_run_failure`
    names it.
  - The broad `except OSError` in `_budgeted_login` is gone, so an exception out of a run
    (e.g. the result tempdir's cleanup after the child ran) spends the budget.
  - `reap_owned_tabs` swallows OSError, as its docstring says.
- [x] **The broker kept a block → the client keeps the record.** When `forget` reports
  `left`, `als.remove_site(site, kept=left)` keeps the site-state entry:
  - demoted;
  - quarantined with that state (phase `limiter`, or `client-proof` for an identity
    lockout) when it had no quarantine;
  - an earlier quarantine kept as it was.

  Everything else goes. The next `-D`, after `install.sh -r`, removes it.
- [x] Plan text: the D7 docker bullet, release step 3, and the Deferred section below.

## Deferred (known limits, not built in WS3)

- `config_canon` sees only what the `sites` view publishes. It cannot see `agent_otp_label`,
  an explicit `agent_session_refresh` (the view shows the resolved refresher), an explicit
  `agent_no_submit` (merged with the built-in sites) or a username swap on the same item:
  such an edit does NOT read `changed`.
  - A later broker release could publish an opaque per-item config tag (an HMAC of every
    `agent_*` field plus the username, under the broker's tag key) for the client to hash
    instead.
- `vault_suspect` compares the fresh read with the daemon's CACHED count. Right after a
  broker restart (cold cache) there is no reference, so only an EMPTY read is refused there:
  a partial read on a cold cache is not caught.

## Release and live acceptance (main session; not in the Verification block)

1. Commit, push, `sudo install/install.sh` + selfcheck.
2. `./agent-login.py -V -r`: no `bad agent_storage_keys` refusal, else roll back (D8).
3. Digest adoption of the six promoted sites. The daily check LaunchAgent is loaded
   (reinstalled 2026-10-13), so its 09:15 run refreshes their checks.
   - The first `-S` after the install (the 10-minute snapshot) adopts each of the six whose
     current check is still a fresh strict ✅, i.e. at most 36 h old.
   - A site whose check is older than 36 h needs a manual `./agent-login.py -c`, `-t SITE`
     or `-p SITE` first (a fresh strict ✅), then the next `-S` adopts it.
   - Until then it reads `config_unknown`: no scheduled login, the free check still runs.
   - Check with `-x` / the site-state audit (`adopt_config`).
4. docker / docker-hub (each other's siblings in one scope and instance):
   - `-D docker -F` and `-D docker-hub -F` (phase 1, the logout forced: both leave);
   - vault removal (Safari / web vault until broker-add `-D` exists);
   - `-D` (phase 2) for each.
   - Then nothing about them in: checks.json, last-check.json, site-state.json, sites.json,
     agents.md, `-x`, `-j`, session-age / login-log in all four cache dirs, the shared browser's
     cookies for `docker.com`, `/var/db/login-broker/profiles/docker*`, `limiter.json` /
     `identity-guard.json` keys (`sudo` + key names only), the screenshots.
   - Expected and allowed: one line each in `audit.jsonl` and the broker's audit.log, and
     empty `session-age/docker*.lock` files.
   - If `-D` reports keys kept by the broker (locked / cooldown / quarantined / identity
     lockout): review, then `sudo install/install.sh -r docker` and `-D docker` again.
5. One `-p SITE` on a pending site with a strict proof, under the attempt policy.

## Verification

```commands
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run ruff format --check bin/ broker/ tests/ agent-login.py agent_login_jobs.py agent_login_state.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run ruff check bin/ broker/ tests/ agent-login.py agent_login_jobs.py agent_login_state.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run mypy bin/browser.py agent-login.py agent_login_state.py broker/onboarding.py broker/storage_rules.py broker/daemon.py broker/limiter.py broker/vault.py broker/identity.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pylint bin/browser.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pylint broker/daemon.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pylint agent-login.py agent_login_state.py agent_login_jobs.py broker/onboarding.py broker/storage_rules.py broker/limiter.py broker/vault.py broker/identity.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pytest -q tests/test_ws3_onboarding.py tests/test_ws3_broker.py tests/test_ws3_agent_login.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pytest -q tests
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pre-commit run --all-files
cd /Users/albert/obsidian/42-Git/home/browser-login && install/install.sh -n
cd /Users/albert/obsidian/42-Git/home/browser-login && bin/browser.py -h
```
