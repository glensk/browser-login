## Session

Resume: `c --resume 3871ad21-0f16-4b68-828e-f9eb1f7a6847`
Parent: /Users/albert/obsidian/42-Git/home/mydotfiles/PLAN_credential-single-source.md

# Login broker: no password oracle, one item per collection, rotation lease

## Context

**Why.** tp#889 (parent plan above) makes every credential's master a Vaultwarden item and
rotates it with `credctl rotate` in mydotfiles. The 2026-10-13 Codex debate on that plan
(objections O3, O4, O7; dispositions binding) moved the broker's part into this child plan,
so it gets its own Verification block. The parent's execution order puts this plan FIRST:
no further `credctl check`, rotation or merge runs before steps S1–S4 here are installed.

**What is wrong today (read 2026-10-13).**

1. **Password oracle (O7).** `{"op": "fingerprint", "site": X}` (`broker/daemon.py:1896`)
   answers `len=<n> sha256:<4 hex>` of the vault password of any site, and every failed
   login's diagnostic carries the same as `password_check` (`daemon.py:823`, shown by
   `bin/browser.py:9912`). `agent-login.py -f SITE` prints it. That is an offline verifier
   (length + 16 bits filters a guess list without touching the site or the limiter) and
   reveals the length outright. mydotfiles `credctl check` uses it for `weak-equal`; the
   parent drops that use (its S5a) and moves every login comparison into the Touch ID
   child (`check -T`).
2. **Dual collection membership (O3).** The broker reads the login collection and the
   secrets collection with `bw list items --collectionid <id>` and `filter_org`
   (`broker/vault.py:643`). One Bitwarden item listed in BOTH collections is a login item
   AND a `secret-run` item, so `secret-run` hands a website password to agents. Nothing
   detects it: `secret_item_from_json` (`vault.py:528`) never looks at `collectionIds`,
   and a check on `agent_site` or on names misses items whose ids differ per side.
3. **No rotation lease (O4).** A login reads its secret at the start (`_login` →
   `_do_login` under `_site_lock(site)`, `daemon.py:2116`) and may submit it a minute
   later. A vault-only `agent_hold` blocks only FRESH reads; a login in flight when
   credctl changes the server (P4) still submits the old password and counts against the
   limiter — the 2026-07-17 lockout pattern.
4. **No ids or revisions in the metadata views.** The parent's guard index (design 8)
   needs the Bitwarden item id of every login and secret item, and its rotation tail
   (design 5, O5) needs the master's `revisionDate` to prove derive reads the value the
   Touch ID run wrote. Neither `sites` nor `secrets` carries them.

**Design.**

- **S1 removes the oracle, not restricts it.** A TTY- or uid-restricted variant would keep
  a second comparison path next to `credctl check -T` (window + Touch ID 2), which already
  answers "equal or not" for Albert. The op answers `{"ok": false, "error": "removed"}`
  (one release, so an old client gets a clear answer), then disappears.
- **S2 membership by item id.** For every raw item of either read: `collectionIds` must be
  a list of strings, else the item is refused on that side ("collection membership
  unreadable"). An item whose `collectionIds` names both the login collection and the
  configured secrets collection is refused on BOTH sides, keyed by its item id, whatever
  its fields or name say ("in both agent-login and agent-secrets: split it"). The login
  side keeps the item in the scope/conflict checks like any refused item (fail closed).
  The onboarding review (`broker/onboarding.py`) calls the same function, never a copy of
  the rule (AGENTS.md: never duplicate a broker refusal rule).
- **S3 lease, drain, `held`.** New socket ops (peer uid `--allow-uid` only, like every op):
  `rotation_lease {txid, sites[], ttl_s}` and `rotation_release {txid}`. The lease is
  recorded first (persisted 0600 under the broker home, so a broker restart keeps it until
  its TTL; default TTL 1200 s, above the Touch ID helper's 15-min deadline), so every NEW
  `login`, scheduled login, sentinel probe and identity challenge of a leased site answers
  `held` at once. Then the broker drains: for each site it waits (bounded, default 120 s)
  to acquire and release `_site_lock(site)`, so a login already past its secret read
  finishes or fails before the lease is granted. Drain timeout → the lease is dropped and
  the answer is `busy` (credctl stops before P3; nothing changed). Success → `leased`.
  `held` is never counted by the limiter, never quarantines, never triggers a failure
  mail; `browser.py login` maps it to exit 75 (`BUSY_RC`, "skip and re-check later"), and
  `agent-login.py` shows `⏸ held (rotation TXID)`. The persistent vault field `agent_hold
  = <txid>` (written by credctl at P3, removed at P6a) gives the same `held` answer from
  the item itself, so a lease lost with its TTL never reopens a site whose copy is still
  stale. An unknown site in a lease request is refused; an expired lease is dropped by the
  next request that reads it.
- **S4 metadata.** `sites` and `secrets` views gain `item_id` and `revision` (Bitwarden
  `revisionDate`, ISO string) per item — both non-secret. Leak canaries stay green.

**Not strict-eligible, intended.** The Verification block runs mypy, pylint and pytest,
which execute repository code; the broker install is a main-session step (root on the Mac).

## Steps

### S1 — remove the `fingerprint` oracle (first)

- [ ] `broker/daemon.py`: the `fingerprint` op answers `removed`; `secret_check` /
      `password_fingerprint` deleted; `_record_failure` no longer writes `password_check`
      (username-only length note removed too); module docstring updated.
- [ ] `broker/vault.py`: `fingerprint_secret` removed from `Vault`, `BwVault`, the dev
      fixture vault and the daemon's vault proxy.
- [ ] `agent-login.py -f/--fingerprint` removed (help text says: compare with
      `credctl.py check -T` in mydotfiles); `bin/browser.py` drops the `password_check`
      diagnostic label.
- [ ] Tests: the fingerprint cases in `tests/test_login_broker.py`,
      `tests/test_username_only.py` and `tests/test_ws2_galaxus.py` rewritten to assert
      `removed` and the absence of `password_check`; new leak test: no broker reply,
      diagnostic file or audit line matches `len=\d+` or `sha256:[0-9a-f]{4}`.

### S2 — one item, one collection (dual membership by item id)

- [ ] `broker/vault.py`: `collection_membership(raw, login_coll, secrets_coll)` → `ok` |
      `unreadable` | `dual`; applied in `items()`/`secret()` (login side) and in the
      secrets read (`build_secret_items` path), dev fixture vault included; `dual` and
      `unreadable` refused with fixed reasons on both sides, keyed by item id.
- [ ] `broker/onboarding.py` calls `collection_membership` for a new or changed item
      (refused level) instead of any name rule.
- [ ] Root-only CLI on `daemon.py` (letter chosen at build, documented in `-h`): list the
      dual-member and unreadable items of the live vault by safe name + item id, run as
      the broker uid; used once before the S5 install.
- [ ] `tests/test_cred_rotation.py`: dual item refused on both sides (also with different
      `agent_site`/`agent_secret_id`/names), missing / non-list / non-string
      `collectionIds` refused, a login-only and a secrets-only item served, the refused
      dual item still takes part in the scope conflict check, onboarding refuses it.

### S3 — rotation lease, drain and `held`

- [ ] `broker/daemon.py`: ops `rotation_lease` / `rotation_release` (design above),
      persisted lease file (0600, broker home, atomic write), TTL expiry, drain over
      `_site_lock` with a bounded wait, `busy` on drain timeout with the lease rolled
      back; `held` answered by login, scheduled login, sentinel probe and identity
      challenge of a leased site; limiter untouched by `held`.
- [ ] `broker/vault.py`: `SiteItem.hold` from `agent_hold` (txid shape checked; malformed
      = held, fail closed); `secret()` of a held item raises the `held` refusal; the
      `sites` view carries `held` + txid.
- [ ] Clients: `bin/browser.py login` maps `held` to exit 75 with
      `held: rotation TXID in progress`; `agent-login.py` shows `⏸ held (rotation TXID)`,
      treats it like busy in `-c` (no login, no failure mail, no quarantine) and in
      `agents.md`.
- [ ] `tests/test_cred_rotation.py`: a fake login paused right before its submit while
      `rotation_lease` arrives → the lease waits for it, then `leased`; a login started
      after the lease → `held` without a secret read; drain timeout → `busy`, lease gone,
      later logins proceed; `held` leaves limiter state byte-identical; broker restart
      with a live lease → still `held`; expired lease dropped; `agent_hold` alone → `held`;
      malformed `agent_hold` → `held`; `rotation_release` reopens the site; unknown site
      and foreign uid refused.

### S4 — item id and revision in the metadata views

- [ ] `sites` and `secrets` views: `item_id` + `revision` per item (refused items too);
      `bin/secret_run.py -l -j` prints them; the leak canaries stay green.
- [ ] Tests in `tests/test_cred_rotation.py`: both fields present, no value-shaped string
      added, a `bw sync` that changes `revisionDate` changes `revision`.

### S5 — docs and install

- [ ] README: broker op table (fingerprint removed, lease ops, `held`), the dual-membership
      refusal, `agent-login.py` options; AGENTS.md: one convention bullet (no password
      oracle; dual membership is refused by item id; `held` is a skip, never a failure).
- [ ] Main session, before the install: the S2 root-only listing against the live vault;
      no dual-member item → install, else the NOTE below first.

NOTE (albert, approve): only if the pre-install listing names a dual-member item (e.g. the `cloudflare` name pair): approve which collection it leaves; the agent splits it into a login item and a secrets item through `broker-add.py` before the install.

- [ ] Main session: `sudo install/install.sh` (broker + clients), then
      `browser.py logged-in` of every previously ✅ site still passes, `agent-login.py`
      shows no new ❌, and a `fingerprint` request answers `removed`.

## Verification

```commands
cd /Users/albert/obsidian/42-Git/home/browser-login && ruff format --check bin/ broker/ agent-login.py agent_login_jobs.py
cd /Users/albert/obsidian/42-Git/home/browser-login && ruff check bin/ broker/ agent-login.py agent_login_jobs.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run mypy bin/browser.py agent-login.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pylint bin/browser.py broker/daemon.py broker/vault.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pytest -q tests/test_cred_rotation.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pytest -q tests
cd /Users/albert/obsidian/42-Git/home/browser-login && bin/browser.py -h
```
