## Session

Resume: `c --resume 2beb215f-de88-4679-b523-83db79427b36`
Parent: /Users/albert/obsidian/42-Git/home/mydotfiles/PLAN_credential-single-source.md

# Broker: one collection + `agent_script` gate, compare interface, agent-login credential section

> [!important] Status 2026-10-14 — interface section first
> tp#889 R4 (child plan). This section is committed BEFORE the rest of the plan because the
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
