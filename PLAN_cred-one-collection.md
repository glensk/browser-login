## Session

Resume: `c --resume 2beb215f-de88-4679-b523-83db79427b36`
Parent: /Users/albert/obsidian/42-Git/home/mydotfiles/PLAN_credential-single-source.md

# Broker: one collection + `agent_script` gate, compare interface, agent-login credential section

> [!important] Status 2026-10-14 — interface section first
> tp#991 — tp#889 R4 (child plan). This section is committed BEFORE the rest of the plan because the
> mydotfiles R5 builder (`credctl check` comparing a `vault:` master's copies) reads it.

## Compare interface (for mydotfiles R5)

**Decision: there is no broker compare op.** tp#965 S1 removed the broker's `fingerprint`
oracle and the parent plan keeps "no broker oracle" (Opus debate O7, Codex O7). An
`agent_script = true` item may already be handed raw to any child `secret-run` starts (R0,
consequence O1), so the comparison runs where the copies are read: in credctl's existing
compare child, with the master injected by `secret-run`. What browser-login adds is (a) that
`secret-run` can inject an `agent_script` LOGIN item of the one collection, (b) a capability
probe, and (c) listing fields that tell credctl, without a value, whether an item can be
compared at all.

| Question                  | Answer                                                                                                                                                                                                                                                                                                                                                                    |
| :------------------------ | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Trusted child             | mydotfiles `credctl.py -m <manifest> -C <ID>` (`cred_lib/check.py` `compare_child`), unchanged. NOT the broker (it answers no equality question, ever) and NOT the vault-touchid helper (Touch ID; the daily run is unattended — vault-touchid stays the path for login items WITHOUT the flag, via `check -T`).                                                       |
| Who starts it             | `secret-run`, as today for `vault-secret` masters: `secret-run -s <sid>:<field> [-e CREDCTL_V<i>=<sid_i>:<field_i> …] -- <python ≥ 3.11> -I credctl.py -m <manifest> -C <ID>`                                                                                                                                                                                         |
| `<sid>` of a login item   | the secret id the broker assigns in the one collection: `agent_secret_id` if set, else `agent_site`, else the slug of the item name (`npm-nixos`, `qbittorrent`). Two items claiming one id are BOTH refused (`duplicate secret id`), never resolved by order.                                                                                                            |
| Preconditions (broker)    | gate mode `agent_script` (see "Gate staging"); the item carries `agent_script = true`; it is not held (`agent_hold`), not no-submit, not username-only; the field is listed (`password` + `agent_secret_fields`; `username` only when listed there).                                                                                                                     |
| Capability probe (new)    | `secret-run -V/--capabilities` prints ONE JSON object and exits 0: `{"v": 1, "gate": "collections" \| "report" \| "agent_script", "features": ["capabilities", "agent-script-gate", "login-items"]}` (`gate` from the broker's `secrets` answer; `"unknown"` when the broker is unreachable, exit 125). A `secret-run` without `-V` exits 125 (usage) → treat as `collections`. |
| Listing (extended)        | `secret-run -l -j` rows keep every current key and gain `kind` (`secret` = from the legacy secrets collection, `login` = an item of the login collection), `agent_script` (`true` \| `false` \| `"malformed"`) and `gate_reason` (a fixed text, `""` when the item is injectable or would be). No value, length or hash.                                               |
| Request to the child      | unchanged: the master value + `\n` on stdin then EOF; vault copies as `CREDCTL_V<i>` env vars; the child pops them before doing anything else.                                                                                                                                                                                                                             |
| Response from the child   | unchanged: `{"master": "read" \| "unreadable"}` then one `{"index": i, "status": "equal" \| "DRIFT" \| "missing" \| "unreadable", "detail": <one of check.DETAILS>}` per copy. `secret-run` masks every variant of the injected values in the child's output on top.                                                                                                   |
| Exit codes                | `secret-run`: the child's (0 = verdicts printed); 125 = its own failure — broker down, `unknown_item`, `refused` (stderr `❌ secret-run: refused — <sid>: <fixed reason>`), rate limited, leak check unavailable; 124 = `-T` timeout. The reason texts credctl may match are fixed: `script read without agent_script`, `bad agent_script (true or false)`, `held (rotation <txid>)`. |
| Never leaves the child    | the value, its length, a hash or prefix of it. The broker never compares and never answers "equal?"; the child prints only the verdict words and fixed detail texts above.                                                                                                                                                                                                |

**credctl's classification (mydotfiles R5, not built here).** Before the compare run, R5
reads `secret-run -V` and `secret-run -l -j` once per `check` run:

- gate is not `agent_script`, or `-V` is unsupported → every `vault:` LOGIN master and copy
  is `uncompared` with detail `broker gate is not agent_script` (never `missing`, never green);
- row present with `kind: login` and `agent_script` not `true`, or `gate_reason` = held →
  `uncompared`, detail `no agent_script: compare with check -T` / `held by rotation`;
- row present, not refused → run the compare child exactly as for a `vault-secret` master;
  a 125 from that run is `unreadable`;
- row absent → `missing` (the item is not in the collection).

### mydotfiles part (for R5 / a mydotfiles writer — not edited by this plan)

- MD1 `cred_lib/check.py`: the classification above; two new fixed detail texts in
  `check.DETAILS`; `state.py` already treats `unverified`/`uncompared` as never green.
- MD2 `bin/broker-add.py`: `-a/--agent-script` sets `agent_script=true` on the item (an
  explicit `-a ''` removes it, like the identity fields), in login mode only; `-x` (the
  legacy secrets collection) writes `agent_script=true` on every NEW secrets item it creates
  so items made before the flip stay injectable after it; the plan / Touch ID window shows
  the flag; the per-item rule check calls browser-login's `vault.agent_script_flag` (exit 2
  on a malformed value) and warns (O1) when the item has `agent_privilege=admin`.
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

## Gate staging

New optional bootstrap key `secret_gate` (`/var/db/login-broker/bootstrap.json`), set by
`install.sh -G MODE` through `bootstrap_switch.py -G MODE` (same 0600 rewrite +
`.prev-<UTC>` backup + `-B` rollback as `-C`/`-X`):

| Mode                     | `secret-run` injects                                                                                                                                                                                                              | Sites side                                                                     |
| :----------------------- | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :----------------------------------------------------------------------------- |
| `collections` (DEFAULT, key absent) | exactly today: items of the secrets collection; dual membership refused on both sides. The views carry the new metadata keys (`agent_script`, `gate_reason` = what `agent_script` mode WOULD say) and nothing else changes. | today                                                                          |
| `report`                 | as `collections`; in addition every `secret`/`totp` grant whose item `agent_script` mode would refuse writes one audit line `gate: would_refuse` (item id + fixed reason), and `daemon.py -M` lists those items.                 | today                                                                          |
| `agent_script` (enforced) | items of the login collection AND (while it is still configured) the legacy secrets collection whose `agent_script` is `true`, deduplicated by Bitwarden item id; anything else a script asks for is refused (fail closed).      | an item in both collections is no longer refused; a flagged item with neither `agent_fill_origins` nor `agent_site` is secret-only and left out of the sites view (not a refused site) |

An unknown `secret_gate` value refuses every secret op (`bad secret_gate`) while logins
keep working. `MEMBERSHIP_UNREADABLE` stays a refusal in every mode.

**Who flips it — never this plan's agent.** The main session, as a live step of the parent
plan BEFORE R7b (the first step that injects a login item, `npm-nixos` / `npm-raspi`):
recommended new parent box **R7g** — (1) `secret-run -l -j` + `daemon.py -M` list every
current secrets item consumers read; (2) MD2's `broker-add.py -a` writes `agent_script=true`
on each (attended vault writes, Albert's go per batch); (3) `sudo install/install.sh -G
report` and soak until a day of normal use shows no `gate: would_refuse` audit line for a
live consumer; (4) `sudo install/install.sh -G agent_script`; verify `secret-run -V` reads
`agent_script` and every consumer canary still injects. Rollback: `install.sh -G
collections` (or `-B`). R8b and R9 then rely on the enforced mode.

## Steps

- [ ] B1 `broker/vault.py`: `agent_script_flag(fields) -> True | False | None` (None =
      malformed; parsed with the existing `_parse_flag`); `SECRET_GATES`, `BwBootstrap.secret_gate`
      (default `collections`, unknown value kept as-is and refused at the op); the secret
      source per mode (table above), union + dedupe by item id, both owners of one secret id
      refused (`duplicate secret id`); a login item's secret id = `agent_secret_id` →
      `agent_site` → slug; `SecretItem` gains `kind`, `agent_script`, `gate_reason`
      (`public()` carries them); `MEMBERSHIP_REASONS[MEMBERSHIP_DUAL]` in `agent_script`
      mode = `script read without agent_script` (assigned to a script read that reaches an
      unflagged item); `build_items` in `agent_script` mode drops dual refusals and leaves
      secret-only items out; no-submit, username-only and held items stay refused for
      scripts whatever the flag. `FixtureVault` honours a `secret_gate` key.
      `broker/bootstrap_switch.py -G/--secret-gate MODE` (keeps `secret_gate` in
      `KEEP_KEYS`); `install/install.sh -G MODE`.
      Tests `tests/test_cred_one_collection.py` (vault part): every mode × {flag true,
      false, absent, malformed} × {login, secrets, both}; dedupe; duplicate id; held /
      no-submit / username-only stay refused; secret-only item not a refused site; unknown
      gate; bootstrap switch round trip + `-B`; a sentinel value in a fixture item never in
      any `public()` view or exception text.
- [ ] B2 `broker/secret_ops.py` + `broker/daemon.py`: the `secrets` answer carries
      `gate`; `secret`/`totp` refuse with the fixed reasons; `report` mode writes the
      `gate: would_refuse` audit line (no value); `daemon.py -M` adds rows side `script`,
      status `no_agent_script` / `malformed_agent_script` in `report` and `agent_script`
      modes. Tests: op-level cases in `tests/test_cred_one_collection.py` (limiter not
      charged for a gate refusal; audit line shape; sentinel absent from responses + audit
      file); `tests/test_cred_rotation.py` / `tests/test_secret_ops.py` stay green unchanged
      (collections mode is today).
- [ ] B3 `bin/secret_run.py`: `-V/--capabilities` (one JSON object, exit 0; broker down →
      `gate: "unknown"`, exit 125); `-l -j` rows add `kind`, `agent_script`, `gate_reason`;
      text `-l` prints unflagged login rows as ONE line (`N login item(s) not injectable:
      agent_script unset`) instead of N refused rows; help + epilog. Tests in
      `tests/test_secret_run.py` against the fake broker.
- [ ] B4 Onboarding review (`agent-login.py -V -i`, `broker/onboarding.py`): a planned
      item's `agent_script` is judged with `agent_script_flag` (malformed → `refused`;
      `true` on an item with `agent_privilege=admin` → `risk` "agent_script on an admin
      login (raw disclosure, O1)"); the manifest's `collections` may be `{"login": ID}`
      alone (one collection); membership judged per the live gate mode (read from the
      `secrets` answer, `collections` when unknown). Tests in `tests/test_agent_login.py`
      or a new `tests/test_onboarding_agent_script.py`.
- [ ] B5 `agent_login_cred.py` + its section in `./agent-login.py` (overview text after the
      keychain list, and key `credentials` in `-j`): reads ONLY
      `~/.local/state/credctl/check-latest.json` (`$CREDCTL_STATE_FILE` overrides, for
      tests); one line per result with `location_count >= 2`, derived from the file (no
      hand-written list): ✅ `equal`; ❌ `DRIFT` / `missing` / `unreadable`; ⚠️ `uncompared`
      with `credctl.py check -T <id>`; a run whose `attempt` is `failed` / `timeout` (or
      `started` older than 1 h) is ONE ❌ line naming the attempt and exit; `completed_at`
      older than 36 h is ONE ⚠️ line with `bin/credctl-daily.sh`; file absent, unreadable,
      not JSON or `v` ≠ 1 is ONE ⚠️ line. Shows only `id` (validated against the id
      pattern, else `?`), the verdict word, `location_count` and timestamps — never another
      key. Tests `tests/test_agent_login_cred.py` (every branch, a sentinel planted in an
      unknown key and in `master_detail` never printed, 0600 file not required).
- [ ] B6 Docs: README "One item, one collection" rewritten (one collection, the
      `agent_script` gate and its three modes, the O1 consequence, `-M`, `-V`, the flip
      recipe), the broker op table (`secrets` answer `gate`), `secret-run -h`, AGENTS.md
      one bullet; `repo_scope.md` lines that name two collections.
- [ ] B7 (main session, live, no behavior change) install the reviewed commit:
      `sudo install/install.sh` (broker + clients, gate stays `collections`).
      Verify: `secret-run -V` → `gate: collections`; `secret-run -l` lists the same
      injectable items as before; `./agent-login.py` shows the credential section (⚠️ no
      state file until parent R3b) and no new ❌ site.
- [ ] B8 (main session, live — parent R7g) the flip, per "Gate staging". Not this plan's
      agent.

**Order.** B1 → B2 → B3 → B4 → B5 → B6, each committed with its tests before the next; B7
after review; B8 belongs to the parent's live sequence.

## Verification

Pytest, mypy, pylint and the `-h` smoke runs need tools, so the block is not strict-eligible.

```commands
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pytest -q tests/test_cred_one_collection.py tests/test_agent_login_cred.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pytest -q tests/test_cred_rotation.py tests/test_secret_ops.py tests/test_secret_run.py tests/test_agent_login.py tests/test_login_broker.py tests/test_credentials.py
cd /Users/albert/obsidian/42-Git/home/browser-login && ruff format --check broker bin/secret_run.py agent-login.py agent_login_cred.py tests/test_cred_one_collection.py tests/test_agent_login_cred.py
cd /Users/albert/obsidian/42-Git/home/browser-login && ruff check broker bin/secret_run.py agent-login.py agent_login_cred.py tests/test_cred_one_collection.py tests/test_agent_login_cred.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run mypy broker/vault.py broker/secret_ops.py broker/onboarding.py broker/bootstrap_switch.py bin/secret_run.py agent_login_cred.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pylint broker/vault.py broker/secret_ops.py broker/onboarding.py broker/bootstrap_switch.py bin/secret_run.py agent_login_cred.py
cd /Users/albert/obsidian/42-Git/home/browser-login && shellcheck install/install.sh
cd /Users/albert/obsidian/42-Git/home/browser-login && bin/secret-run -h
cd /Users/albert/obsidian/42-Git/home/browser-login && ./agent-login.py -h
```
