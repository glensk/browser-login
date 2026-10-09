## Session

Resume: `c --resume 3871ad21-0f16-4b68-828e-f9eb1f7a6847`

# Agent-login repair — every broker site ✅, and it stays ✅

## Context

Goal (Albert, 2026-10-09): agents can use **every** login in `./agent-login.py`. ❌ sites get
fixed at the root, durably. The overview always shows *exactly* where a login broke. The
scheduled check never locks a site again. New broker items cannot fall into the same holes. The
agent-login list reaches subagents, Codex and OpenCode.

Orchestration: this session oversees. Every workstream runs as a subagent: investigate, find
the root cause, run a codex-debate (fallback: opus-plan-critique), then implement in a git
worktree. This session reviews every diff, commits, pushes, deploys and re-verifies. Subagents
never commit. Plan debated with Codex 2026-10-09 (gpt-5.6-sol); the ledger lives in the
session scratchpad.

Albert's go (2026-10-09): resetting broker limiters, and `SECRET_RUN_GUARD_OFF=1` for broker
state work, are allowed for this repair. Zendesk is no longer used (SDSC moved to Zoho Desk):
remove the site, don't fix it.

**The Verification block is not strict-eligible, and that is intended.** It runs pytest,
mypy and pylint, which execute repository code. Live steps are NOT in the block: broker
installs, shared-browser checks, guided logins and limiter-consuming canaries. They are
manual acceptance steps under the attempt policy below.

### State at start (2026-10-09 21:30)

- Re-tested: github ✅, cloudflare ✅ (both ❌s were stale).
- Hard-locked by the limiter (3 post-submit failures in a row): calibre, galaxus, galaxus-de,
  npm-nixos, npm-raspi, myfritz-alzenau. **All 6 were reset 2026-10-09 21:35** (`sudo
  install/install.sh -r SITE`). The original failure reasons are unknown (masked by "rate
  limited").
- WS-Z found that most failing sites were batch-added on 2026-10-07/08 without a validated
  check (`1ec8c711`, `37758d65`), so they may never have worked.
- cscs: broker login `ok`, but the exported bundle carries 1 cookie and 0 storage keys, and the
  portal redirects to Keycloak. `cscs-api.py` / Waldur depend on it.
- Notion: needs Albert's guided login; why does its session expire?
- `com.albert.agent-login-check` (09:15, `-c -m`) is **unloaded** until the final acceptance.

## Rules for every subagent

- **Attempt policy.** A site gets at most ONE secret-submitting production login per
  diagnostic cycle, and only after the main session approves it. No automatic retry after
  phase `submitted`/`unknown`. Logged-in probes (no submit) are free and must not count as
  attempts. A site that fails after submit is **quarantined** until the main session releases
  it. A limiter reset does not reset a vendor-side lock.
- **Before WS1a is deployed, site work is read-only.** Allowed: screenshots
  `/var/db/login-broker-run/last-failure-*.png`, journal, broker log, recipes, site config,
  logged-in probes.
- **Integration queue.** One implementing worktree at a time per file set. It starts from the
  last accepted commit on `main`. The main session commits from it and fast-forwards `main`.
  Live `bin/browser.py` changes land only when `browser.py clients` shows no registered exec
  client and no maintenance record is live.
- **Release procedure (main session).** Hermetic checks (Verification block) → commit → `ai.py
  push`, then confirm `origin/main` contains the commit (`install.sh` refuses otherwise) → `sudo
  install/install.sh` + broker selfcheck → one bounded canary → rollback point is the previous
  release under `/usr/local/libexec/login-broker/releases`.
- **Debate.** Once the root cause is found: `codex-debate` mode=diagnose (no Codex seat →
  `opus-plan-critique`). Every root cause gets a sanitized fixture plus a regression test.
- **Never** page text in `agents.md` (prompt-injection surface). Show phase codes and fixed
  text only.

## Steps

- [x] WS0 — agent-login list for every agent kind (verified live 2026-10-09; mydotfiles
      commit "feat(agents): give subagents, Codex and OpenCode the agent-login list"):
      subagents through the SubagentStart hook `agent-login-subagent-context.py`
      (additionalContext); Codex through a trusted `[[hooks.SessionStart]]` in the shared
      `config.toml`, with a trust row per seat; OpenCode through `instructions` in
      `opencode.json`.
- [x] WS-Z — Zendesk: not needed (Albert, 2026-10-09). Remove it instead of fixing it.
- [x] Zendesk removal: Albert deleted the Vaultwarden item (2026-10-09). Verified: gone from
      the broker snapshot, the overview and agents.md. A stale `last-check.json` entry is left;
      WS1a pruning removes it.
- [ ] WS1a — diagnostics and scheduler safety. Hard gate: merged + deployed before any
      secret-submitting site retry. Plan → codex-debate → implement → review → release:
  - [ ] acceptance matrix generator (`agent-login.py -j` based): one row per item, static
        TARGETS + broker extras: consumer, privilege, check URL, authenticated sentinel,
        bundle scope, attempt group, refresh policy, last phase, state. With the broker down,
        extras show as `unknown`, never disappear.
  - [ ] versioned phase codes end to end: `precheck`, `limiter`, `vault`, `recipe`, `submit`,
        `broker-proof`, `bundle-export`, `cookie-inject`, `storage-inject`, `client-proof`,
        `consumer-followup`. Structured JSON from the broker through browser.py (a side
        channel, not the stderr that `agent_login_jobs.run_browser` discards) into
        `record_check`, written atomically under a lock, details redacted and length-capped.
        The overview shows phase + short reason + the screenshot path.
  - [ ] status freshness: last-attempt vs last-success timestamps; a maximum status age, after
        which a site reads `stale`; an offline run records `unknown`, never success; removed
        items are pruned
  - [ ] scheduler safety: `-c` never submits for locked / cooldown / quarantined / pending /
        assisted sites, and reports them as such (e.g. "locked — needs `sudo install.sh -r
        SITE`"). New or unplanned broker items start as `pending` and are excluded from
        scheduled logins until promoted. No inner retry after submit (agent-login.py:883).
  - [ ] mandatory authenticated DOM sentinel in the broker proof (`_broker_probe`,
        bin/browser.py:10616). "Off the fill origin, no password field" alone no longer
        passes. Every existing site is migrated to an explicit sentinel; a site without one
        cannot be `usable`.
  - [ ] attempt groups (debate O6, final design):
    - **Static group.** The group is an explicit opaque vault field `agent_attempt_group`
      (a validated slug), known before navigation. It is set on every known shared realm,
      and each WS2 investigation confirms or corrects it. Galaxus is an example: are
      id.digitecgalaxus.ch and id.galaxus.eu one account? No dynamic derivation at
      attempt time. WS3 may *suggest* a group, never enforce one.
    - **Keys.** Raw `SITE` keys stay unchanged (rollback-compatible, no migration). Only
      `group:<id>` keys are added.
    - **Outcome-aware API.** `reserve_attempt(keys) -> id`, `mark_submitted(id)`,
      `finish(id, outcome)`, each applied atomically to every key. Crash recovery turns
      an abandoned `submitted` into `unknown`, and an abandoned pre-submit into
      `not_submitted`. This replaces the use of `Limiter.reserve`, which records "ok"
      immediately.
    - **Both keys enforce everything:** minimum interval, `cooldown_until` (the multi-key
      deny path, limiter.py:227), hourly/daily caps and the hard block.
    - **Streak reset.** The streak clears only on a proven *fresh* password authentication
      (sentinel after submit), even when export fails later. A reused broker profile never
      clears it.
    - **Cross-process locking.** Every read-modify-write takes an exclusive `fcntl.flock` on
      a sidecar lock shared by the daemon and the reset process.
    - **Resets.** daemon.py gets a login-key parser that accepts `group:<id>` (separate
      from the `secret:`/`totp:` validator, daemon.py:865). `install.sh -r group:<id>`
      resets a group; `-r SITE` reports a group that still blocks; `-r SITE -G` resets
      both together. The site→group binding is persisted at reservation time.
    - **Tests:** pre- vs post-submit failure; group cooldown across members; crash recovery
      at every transition; concurrent reservations in one group; profile reuse not
      clearing a streak; auth success + export failure; old code reading new state; reset
      racing a live write; a malformed group field; group ids never revealing usernames.
- [ ] WS2 — per-site root-cause fixes, serial, each from the previous accepted + deployed
      base. Acceptance per site: logged-in probe ✅ in the shared Chromium, plus its consumer
      where one exists:
  - [ ] cscs: token discovery proven, exported storage keys > 0, injection read back before
        the SPA redirect, stable portal probe, `cscs-api.py` (Waldur) call succeeds.
    - [x] Root cause found (read-only, Codex diagnose debate converged in 3 rounds):
          `cscs_portal_ready` (recipes.py:791) passes on ANY 40-hex localStorage value, even
          an expired Waldur token (about 1 h lifetime). The broker therefore reuses a dead
          profile and skips the login. Discovery on `/` then loses the race against the
          portal's new `boot-redirect.js`, and `_with_portal_token_keys` (daemon.py:234)
          silently returns 0 keys. The audit still says `ok`.
          Second issue: a fresh login (188 s) exceeds the client's `BROKER_TIMEOUT_S` 180 s.
          `cscs-api.py:773` also kills the login after 180 s.
    - [ ] Fix (after WS1a deploys):
      - the check asks the server: `/api/users/me/` 200 + identity, returning
            valid/invalid/indeterminate;
      - export allowlist `waldur/auth/token` (+ expires_at, method), read on `/profile/`;
      - `BundleExportError` instead of the silent fallback;
      - client-side bundle check before touching cookies;
      - inject + read-back on `/profile/`;
      - `cmd_token` validates its token;
      - timeout ordering, incl. the sdsc `cscs-api.py` subprocess timeout;
      - hermetic portal fixture tests (stale/valid/503/export-fail).

      One live submit is needed.
  - [ ] npm-nixos
  - [ ] npm-raspi
  - [ ] calibre
  - [ ] galaxus
  - [ ] galaxus-de
  - [ ] myfritz-alzenau
  - [ ] notion: instrument why the session expires (vendor policy or lost profile state). No
        subagent runs a guided login. Albert does exactly one `-g notion`, observed over the
        interval. "Monitored + alert to Albert" is an acceptable durable outcome.
- [ ] WS1b — durability per flow, after WS2's root causes: broker re-export before expiry,
      credential-change handling, Safari-cookie expiry, monitoring of assisted sessions with
      an alert to Albert. Plan → codex-debate → implement.
- [ ] WS3 — onboarding guard (plan → codex-debate → implement): static validation of a new
      item (sentinel present, fill origins, cookie scope, attempt group), a budgeted
      promotion test (`pending` → `usable`), and a removal path (`broker-add.py` remove or
      documented) that also prunes agent-login state
- [ ] Final acceptance: a check-only inventory (logged-in probes only), then per-site canaries
      under the attempt policy. Re-enable the 09:15 job (`./agent-login.py -I`) only after
      locked / cooldown / pending / assisted / quarantined sites provably cannot trigger a
      login. Observe one real scheduled run: limiter counters must not move for green or
      quarantined sites.

## Learnings (carried to every subagent)

- The broker limiter hard-blocks a site after 3 post-submit failures in a row. Only root resets
  it (`sudo install/install.sh -r SITE`). Once locked, every attempt reports only "rate
  limited", which hides the original reason.
- `agent-login.py -t SITE` prints the broker's detailed failure: stop URL, page text, password
  fingerprint, and the screenshot at `/var/db/login-broker-run/last-failure-SITE.png`. The
  overview and `last-check.json` keep only the exit code (fixed by WS1a).
- `secret-run -A -N 500` prints the broker audit log: result per login, no reasons.
- The broker runs the INSTALLED code (`/usr/local/libexec/login-broker/current`, `git archive`
  of a commit on `origin/main`). `bin/browser.py` is live for every consumer immediately.
- The positive proof "ended off the fill origin, no password field" also passes on an "Access
  Denied" page (zendesk). Only a DOM sentinel proves a login.
- An audit `ok` does not prove a usable session. A check on a value's *shape* (a token-like
  string in storage) passes on expired tokens. Only a server-validated proof counts (CSCS:
  `/api/users/me/` 200). Look for the same pattern in every other site's check.
- Today the limiter is consulted before profile reuse, so a cooldown also blocks a reuse that
  needs no password. WS1a moves admission into `get_secret` (CSCS debate rule).
- Broker run times must stay inside the client timeouts. Required order: broker deadline <
  browser.py socket < `LOGIN_TIMEOUT_S` < runner / consumer subprocess timeouts.
- Subagents never see SessionStart output, only a SubagentStart hook's `additionalContext`. A
  Codex hook without a trust row is skipped silently in `codex exec`, and each seat needs its
  own row.

## Verification

```commands
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run ruff format --check bin/ broker/ agent-login.py agent_login_jobs.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run ruff check bin/ broker/ agent-login.py agent_login_jobs.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run mypy bin/browser.py agent-login.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pylint bin/browser.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pytest -q tests
cd /Users/albert/obsidian/42-Git/home/browser-login && bin/browser.py -h
```
