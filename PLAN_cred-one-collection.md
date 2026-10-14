## Session

Resume: `c --resume 2beb215f-de88-4679-b523-83db79427b36`
Parent: /Users/albert/obsidian/42-Git/home/mydotfiles/PLAN_credential-single-source.md

# Broker: one collection + `agent_script` gate, compare interface, agent-login credential section

> [!important] Status 2026-10-14 — B1–B6 landed (hermetic, full suite green); B7 install and B8 flip are the main session's
> tp#991 — tp#889 R4 (child plan), debated with Codex gpt-5.6-sol (2 rounds, converged; O1–O15
> folded in). The compare interface below was committed first for the mydotfiles R5 builder;
> the reconciliation added the closed `gate_code` enum (O6) — R5 maps codes, never reason
> texts. The live broker still runs the pre-tp#991 release until B7: `secret-run -V` answers
> "unrecognized arguments" (exit 125) there, which R5 treats as gate `collections`.
> Build note: B2's box was ticked by 8c03cf6, whose code landed one commit later (d2cb9c9).
> Incidental fixes in their own commits: an item with secret id `ok` was taken for an error
> answer by `secret`/`totp` (fixed in d2cb9c9 with a regression test); brew-mypy errors in
> `agent_login_state.py` / `agent_login_jobs.py` that blocked every commit touching
> `agent-login.py`; a pylint R0917 in `secret_ops.py`.

## Compare interface (for mydotfiles R5)

**Decision: there is no broker compare op.** tp#965 S1 removed the broker's `fingerprint`
oracle and the parent plan keeps "no broker oracle" (Opus debate O7, Codex O7). An
`agent_script = true` item may already be handed raw to any child `secret-run` starts (R0,
consequence O1), so the comparison runs where the copies are read: in credctl's existing
compare child, with the master injected by `secret-run`. What browser-login adds is (a) that
`secret-run` can inject an `agent_script` LOGIN item of the one collection, (b) a capability
probe, and (c) listing fields that tell credctl, without a value, whether an item can be
compared at all.

| Question                  | Answer                                                                                                                                                                                                                                                                                                                                          |
| :------------------------ | :---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Trusted child             | mydotfiles `credctl.py -m <manifest> -C <ID>` (`cred_lib/check.py` `compare_child`), unchanged. NOT the broker (it answers no equality question, ever) and NOT the vault-touchid helper (Touch ID; the daily run is unattended — vault-touchid stays the path for login items WITHOUT the flag, via `check -T`).                             |
| Who starts it             | `secret-run`, as today for `vault-secret` masters: `secret-run -s <sid>:<field> [-e CREDCTL_V<i>=<sid_i>:<field_i> …] -- <python ≥ 3.11> -I credctl.py -m <manifest> -C <ID>`                                                                                                                                                               |
| `<sid>`                   | login-collection item (mode `agent_script`): `agent_secret_id`, else `agent_site` (login items only), else the name slug (`npm-nixos`, `qbittorrent`). Legacy secrets-collection item, every mode: `agent_secret_id`, else the name slug — unchanged (O11). Two items claiming one id are BOTH refused (`duplicate_id`), never resolved by order. |
| Preconditions (broker)    | gate mode `agent_script` (see "Gate staging"); the item carries `agent_script = true`; not held (`agent_hold`), not no-submit; the field is listed (`password` + `agent_secret_fields`). A flagged username-only item lists `password` = its username (the credential, O3).                                                                 |
| Capability probe (new)    | `secret-run -V/--capabilities` prints ONE JSON object: `{"v": 1, "gate": "collections" \| "report" \| "agent_script" \| "bad_secret_gate" \| "unknown", "features": ["capabilities", "agent-script-gate", "login-items", "gate-code"]}`; exit 0 for the first three gates, 125 for `bad_secret_gate` / `unknown` (broker unreachable). A `secret-run` without `-V` exits 125 (usage) → treat as `collections`. |
| Listing (extended)        | `secret-run -l -j` rows keep every current key and gain `kind` (`secret` = legacy secrets collection, `login` = login collection), `agent_script` (`true` \| `false` \| `"malformed"`) and `gate_code` (closed enum below) — in `collections`/`report` mode `gate_code` is what `agent_script` mode WOULD answer. No value, length or hash. |
| Request to the child      | unchanged: the master value + `\n` on stdin then EOF; vault copies as `CREDCTL_V<i>` env vars; the child pops them before doing anything else.                                                                                                                                                                                               |
| Response from the child   | unchanged: `{"master": "read" \| "unreadable"}` then one `{"index": i, "status": "equal" \| "DRIFT" \| "missing" \| "unreadable", "detail": <one of check.DETAILS>}` per copy. `secret-run` masks every variant of the injected values in the child's output on top.                                                                     |
| Exit codes                | `secret-run`: the child's (0 = verdicts printed); 125 = its own failure (broker down, unknown item, refused, rate limited, leak check unavailable); 124 = `-T` timeout. credctl classifies BEFORE the run from `-V` + `-l -j` (`gate_code`), never from stderr text.                                                                       |
| Never leaves the child    | the value, its length, a hash or prefix of it. The broker never compares and never answers "equal?"; the child prints only the verdict words and fixed detail texts above.                                                                                                                                                                  |

**`gate_code` (closed enum, O6)** and credctl's classification of a `vault:` location
(mydotfiles R5, not built here; run once per `check` after `secret-run -V` and `-l -j`):

| `gate_code`             | Meaning                                                              | credctl verdict                                                       |
| :---------------------- | :------------------------------------------------------------------- | :-------------------------------------------------------------------- |
| `ok`                    | injectable (or would be)                                             | gate `agent_script` → run the compare child; a 125 = `unreadable`; other gate → `uncompared` "broker gate is not agent_script" |
| `no_agent_script`       | flag absent or `false`                                               | `uncompared` "no agent_script: compare with check -T"                 |
| `bad_agent_script`      | flag malformed                                                       | `unreadable` "agent_script malformed"                                 |
| `held`                  | `agent_hold` set (rotation)                                          | `uncompared` "held by rotation"                                       |
| `no_submit`             | a no-submit login (never a secret)                                   | `uncompared` "no-submit login: compare with check -T"                 |
| `username_only`         | username-only login (collections/report mode only)                   | `uncompared` "no agent_script: compare with check -T"                 |
| `duplicate_id`          | two items claim the id                                               | `unreadable` "duplicate secret id"                                    |
| `membership_unreadable` | `collectionIds` unreadable                                           | `unreadable` "collection membership unreadable"                       |
| `invalid_item`          | any other item validation refusal                                    | `unreadable` "item refused by the broker"                             |
| (row absent)            | not in either collection                                             | `missing`                                                             |
| gate `bad_secret_gate` / `unknown` / `-V` exit 125 | broker misconfigured or down              | every `vault:` location `unreadable` "broker gate unknown"            |

### mydotfiles part (for R5 / a mydotfiles writer — not edited by this plan)

- MD1 `cred_lib/check.py`: the classification above, keyed on `gate_code`; the new fixed
  detail texts in `check.DETAILS`; `state.py` already treats `unverified`/`uncompared` as
  never green.
- MD2 `bin/broker-add.py`: `-e/--agent-script` (`-a` is `--account`) sets `agent_script=true` (an explicit
  `-e ''` removes it, like the identity fields) on a login item AND, in place, on an item
  already in the legacy secrets collection (only that field, no move, no new item,
  collections kept — O2); `-x` writes `agent_script=true` on every NEW secrets item; the
  plan / Touch ID window shows the flag; the rule check calls browser-login's
  `vault.agent_script_flag` (exit 2 on a malformed value) and warns (O1) on
  `agent_privilege=admin`.
- MD3 `credctl lint` (R5 (a)) lists every `agent_script` item from `secret-run -l -j`
  (`agent_script: true`), names and ids only.

## Context

Parent R0 (option B, decided 2026-10-14): ONE Vaultwarden collection holds every
agent-usable item. The browser fill is unchanged (items with `agent_fill_origins` /
`agent_site`, origin binding, limiter). `secret-run` injects an item only when it carries
`agent_script = true`; a missing or malformed flag is a refusal (fail closed). Consequence
O1: the flag authorizes raw disclosure to an agent-chosen child, so it goes only on items a
script really reads; admin website logins never get it, and `credctl lint` lists every
flagged item (parent R5).

Today (tp#965 S2) the broker reads TWO collections: the login collection (`collection_id`)
for sites and the secrets collection (`secrets_collection_id`) for `secret-run`; an item in
both is refused on both sides (`MEMBERSHIP_DUAL`, "in both agent-login and agent-secrets:
split it"). No live item carries `agent_script` yet, and `secret-run` is used live by other
sessions right now — so the gate ships OFF and is flipped by a parent live step.

The Verification block runs pytest, mypy, pylint, pre-commit and `-h` smoke runs, which
need tools — it is not strict-eligible.

## Gate staging

New optional bootstrap keys `secret_gate` and `secret_gate_since` (UTC, written at every
switch, O14) in `/var/db/login-broker/bootstrap.json`, set by `install.sh -W/--secret-gate
MODE` through `bootstrap_switch.py -W/--secret-gate MODE` (`-G` is taken by
`--with-group`, O1) — same 0600 rewrite + `.prev-<UTC>` backup + `-B` rollback as `-C`/`-X`:

| Mode                                | `secret-run` injects                                                                                                                                                                                                                       | Sites side |
| :---------------------------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | :--------- |
| `collections` (DEFAULT, key absent) | exactly today: items of the secrets collection; dual membership refused on both sides; username-only and no-submit refused. Views gain `kind`, `agent_script`, `gate_code` (the preview); nothing else changes (compatibility fixture, O11). | today      |
| `report`                            | as `collections`; plus ONE `gate_would_refuse` audit event per unique item (id + `gate_code`) for a request that DID issue its value/code (after limiter, leak check and run issue, O14).                                                 | today      |
| `agent_script` (enforced)           | items of the login collection AND (until `-D` drops it) the legacy secrets collection whose `agent_script` is `true`, deduplicated by an id-shaped Bitwarden item id (items without one are never merged, O9); everything else refused with its `gate_code`. | an item in both collections is no longer refused; a script-only item (neither `agent_site` nor `agent_fill_origins`, O5) is left out of the sites view; an item with `agent_site` and no fill origins stays a visible refused site |

An unknown `secret_gate` value fails closed for `secrets`, `secret` and `totp` only
(`bad_secret_gate`); `secret_done`, `audit` and `invalidate` keep working (O7).
`MEMBERSHIP_UNREADABLE` stays a refusal in every mode. The secrets cache key is (gate,
login org, login collection, secrets org, secrets collection) — a switch never serves a
value cached under another mode (O10).

`daemon.py -M` keeps its meaning (membership defects). New `daemon.py -g/--script-gate`
(install.sh passes it through like `-M`): items INJECTABLE today (legacy secrets collection)
that `agent_script` mode would refuse, plus malformed flags; exit 0 none, 3 some (O8).

**Who flips it — never this plan's agent.** The main session, as live steps of the parent
plan BEFORE R7b (the first step that injects a login item, `npm-nixos` / `npm-raspi`).
Recommended new parent boxes:

- **R7g** (flip): (1) `install.sh -g` + `secret-run -l -j` list every current secrets item a
  consumer reads; (2) MD2's `broker-add.py NAME -e` writes `agent_script=true` on each, in
  place (attended vault writes, Albert's go per batch); (3) `install.sh -W report`, then a
  soak until one day of normal use after `secret_gate_since` shows no `gate_would_refuse`
  event for a live consumer AND the consumer canaries (env_profiles tokens, `credctl check
  -e`) pass; (4) `install.sh -W agent_script`; verify `secret-run -V` reads `agent_script`
  and the canaries still inject. Rollback: `install.sh -W collections` (or `-B`).
- **R7m** (migration, Codex r2 O4): after R7b, R8 and R9, for EVERY row of `secret-run -l
  -j` with `kind: secret` (refused ones included): pin its current id with `agent_secret_id`
  (MD2, `broker-add.py -x -s`), add the login collection to the same Bitwarden item and
  remove the legacy one, verify the row reads `kind: login` with the same id and run its
  consumer canary — or retire it (Albert's go). While an item sits in the legacy collection
  its id follows the legacy rule, so a move never renames it silently.
- **R7h** (one collection, O4): after R7m, `install.sh -D/--drop-secrets-collection`
  (refused unless the gate is `agent_script` and ZERO rows have `kind: secret`, in any
  state); proof: `secret-run -l -j` every row `kind: login`, canaries pass. Rollback: `-B`.

## Steps

- [x] B1 `broker/vault.py`: `agent_script_flag(fields) -> True | False | None` (None =
      malformed, via `_parse_flag`); `GATE_CODES`; `SECRET_GATES`; `BwBootstrap.secret_gate`
      / `secret_gate_since` (absent = `collections`; an unknown value kept and refused at the
      op); the secret source per mode (table above) with the cache key of O10; secret ids per
      O5/O11; a grouped index `{secret_id: [items]}` so duplicates are refused for requests
      and each owner keeps a diagnostic row (O9); `SecretItem` gains `kind`, `agent_script`,
      `gate_code` (in `public()`); `MEMBERSHIP_REASONS[MEMBERSHIP_DUAL]` in mode
      `agent_script` = `script read without agent_script` (code `no_agent_script`); flagged
      username-only → `password` = username (O3); no-submit and held stay refused for
      scripts whatever the flag; `build_items` in mode `agent_script` drops dual refusals
      and leaves script-only items out. `FixtureVault` honours `secret_gate`.
      `broker/bootstrap_switch.py -W/--secret-gate MODE` (writes `secret_gate_since`) and
      `-D/--drop-secrets-collection` (refused unless the gate is `agent_script` and zero
      `kind: secret` rows exist in any state); `install/install.sh -W MODE`, `-D` and `-g`
      pass-throughs; `-r SITE -G` still parses.
      Tests `tests/test_cred_one_collection.py`: every mode × flag {true, false, absent,
      malformed} × {login, secrets, both}; script-only vs login shapes; dedupe by item id,
      no merge without an id; duplicate id refused for requests, both rows listed; held /
      no-submit refused; flagged username-only injects its username; unknown gate; mode
      switch on ONE vault/cache instance (no collections-mode value served under
      `agent_script`); collections-mode compatibility fixture (today's rows unchanged but
      for the added keys); bootstrap switch round trip, `-D` refusals (a refused legacy row
      blocks it), `-B`; the id of an item with a pinned `agent_secret_id` identical before,
      during (both collections) and after a move; a sentinel value never in any `public()`
      view, exception text or `-g`/`-M` output.
- [x] B2 `broker/secret_ops.py` + `broker/daemon.py`: the `secrets` answer carries `gate`
      (and `gate_since`); `secret`/`totp` refuse with `gate_code` in the error; a gate
      refusal never charges the limiter; bad gate fails closed for the three verbs only;
      `report` mode writes the `gate_would_refuse` events (no value); `daemon.py -g`.
      Tests in `tests/test_cred_one_collection.py` (limiter untouched by refusals, audit
      event count/shape for a multi-item request, a failed leak check writes no event,
      `secret_done`/`audit`/`invalidate` under a bad gate, sentinel absent from responses
      and the audit file); `tests/test_cred_rotation.py` / `tests/test_secret_ops.py` green
      unchanged.
- [x] B3 `bin/secret_run.py`: `-V/--capabilities` (contract above); `-l -j` rows add
      `kind`, `agent_script`, `gate_code`; text `-l` folds unflagged login rows into ONE line
      (`N login item(s) not injectable: agent_script unset`); help + epilog. Tests in
      `tests/test_secret_run.py` against the fake broker.
- [x] B4 Onboarding review (`agent-login.py -V -i`, `broker/onboarding.py`): the gate from
      the `secrets` answer is saved with the site-list snapshot and passed explicitly into
      the pure `review_planned(..., gate=)` (O12); gate unknown → blocking finding "broker
      gate unknown"; a planned item's `agent_script` judged with `agent_script_flag`
      (malformed → `refused`; `true` with `agent_privilege=admin` → `risk` "agent_script on
      an admin login (raw disclosure, O1)"); the manifest's `collections` may be `{"login":
      ID}` alone; membership judged per the gate. Tests
      `tests/test_onboarding_agent_script.py`.
- [x] B5 `agent_login_cred.py` + its section in `./agent-login.py` (overview text after the
      keychain list; key `credentials` in `-j`): reads ONLY
      `~/.local/state/credctl/check-latest.json` (`$CREDCTL_STATE_FILE` overrides); closed
      schema (O13) — `v` must be 1, `attempt` in {started, completed, failed, timeout},
      timestamps ISO-8601 UTC, `exit` int or null, per result `id` matching
      `^[a-z0-9][a-z0-9._-]{0,63}$`, `verdict` in {equal, single, uncompared, unreadable,
      missing, DRIFT}, `location_count` int 0..64; an invalid result is ONE ⚠️ "N result(s)
      unreadable" line, an invalid envelope the file-level ⚠️. One line per valid result with
      `location_count >= 2`: ✅ `equal`; ❌ `DRIFT` / `missing` / `unreadable`; ⚠️
      `uncompared` with `credctl.py check -T <id>`. Attempt `failed` / `timeout`, or `started`
      older than 1 h → ONE ❌ line (attempt, exit); `started` younger → ONE ⚠️ "run in
      progress"; `completed_at` older than 36 h → ONE ⚠️ with `bin/credctl-daily.sh`; file
      absent, unreadable, not JSON or `v` ≠ 1 → ONE ⚠️ line. Prints only the validated
      fields. Tests `tests/test_agent_login_cred.py` (every branch; a sentinel in every
      displayable field and in unknown keys never printed).
- [x] B6 Docs: README "One item, one collection" rewritten (one collection, the gate and its
      modes, `gate_code`, the O1 consequence, `-M` vs `-g`, `-V`, the R7g/R7h recipes), the
      broker op table (`secrets` answer `gate`), `secret-run -h`, AGENTS.md one bullet,
      `repo_scope.md` lines that name two collections.
- [x] B7 (main session, live, no behavior change) install the reviewed commit:
      `sudo install/install.sh` (broker + clients, gate stays `collections`).
      Verify: `secret-run -V` → `gate: collections`; `secret-run -l` lists the same
      injectable items as before; `./agent-login.py` shows the credential section (⚠️ no
      state file until parent R3b) and no new ❌ site.
  ↳ evidence 2026-10-14: release b3226fa66469-20261014T135845Z installed by sudo install/install.sh; selfcheck all ✅; secret-run -V gate=collections; secret-run -l lists the same items; agent-login shows the credential section (no state file yet)
- [ ] B8 (main session, live — parent R7g, then R7m and R7h) the flip and the collection
      drop, per "Gate staging". Not this plan's agent.

**Order.** B1 → B2 → B3 → B4 → B5 → B6, each committed with its tests before the next; B7
after review; B8 belongs to the parent's live sequence.

## Verification

```commands
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pytest -q tests/test_cred_one_collection.py tests/test_onboarding_agent_script.py tests/test_agent_login_cred.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pytest -q tests
cd /Users/albert/obsidian/42-Git/home/browser-login && ruff format --check broker bin/secret_run.py agent-login.py agent_login_cred.py tests/test_cred_one_collection.py tests/test_onboarding_agent_script.py tests/test_agent_login_cred.py
cd /Users/albert/obsidian/42-Git/home/browser-login && ruff check broker bin/secret_run.py agent-login.py agent_login_cred.py tests/test_cred_one_collection.py tests/test_onboarding_agent_script.py tests/test_agent_login_cred.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run mypy broker/vault.py broker/secret_ops.py broker/onboarding.py broker/bootstrap_switch.py bin/secret_run.py agent_login_cred.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pylint broker/vault.py broker/secret_ops.py broker/onboarding.py broker/bootstrap_switch.py bin/secret_run.py agent_login_cred.py
cd /Users/albert/obsidian/42-Git/home/browser-login && shellcheck install/install.sh
cd /Users/albert/obsidian/42-Git/home/browser-login && pre-commit run --all-files
cd /Users/albert/obsidian/42-Git/home/browser-login && bin/secret-run -h
cd /Users/albert/obsidian/42-Git/home/browser-login && ./agent-login.py -h
```
