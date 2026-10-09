## Session

Resume: `c --resume 3871ad21-0f16-4b68-828e-f9eb1f7a6847`

# Agent-login repair — every broker site ✅, and it stays ✅

Goal (Albert, 2026-10-09): agents can use **every** login in `./agent-login.py`. ❌ sites get
fixed at the root, durably. The overview always shows *exactly* where a login broke. The daily
check never locks a site again. New broker items cannot fall into the same holes. The
agent-login list reaches subagents, Codex and OpenCode.

Orchestration: this session oversees. Every workstream runs as a subagent: investigate, find
the root cause, run a codex-debate (fallback: opus-plan-critique), then implement in a git
worktree. This session reviews every diff, commits, deploys the broker (`sudo
install/install.sh` — installs `git archive HEAD`) and re-verifies. Subagents never commit. Site
investigations run **one after another**, so the learnings below carry over.

Albert's go (2026-10-09): resetting broker limiters, and `SECRET_RUN_GUARD_OFF=1` for broker
state work, are allowed for this repair.

## State at start (2026-10-09 21:30)

- Re-tested: github ✅, cloudflare ✅ (both ❌s were stale).
- Locked by the limiter (3 failed logins in a row, root reset needed): calibre, galaxus,
  npm-nixos, myfritz-alzenau, and probably galaxus-de and npm-raspi. **All 6 were reset
  2026-10-09 21:35** (`sudo install/install.sh -r SITE`).
- zendesk: the broker logs in (help center shows "Albert Glensk"), but the check URL
  `/agent/dashboard` answers "Access Denied".
- cscs: broker login `ok`, but the injected session (1 cookie, 0 storage keys) does not stick;
  the portal redirects to Keycloak.
- Notion: needs Albert's guided login (`-g notion`); the investigation is about why the
  session expires.
- Daily check `com.albert.agent-login-check` (09:15, `-c -m`) is **unloaded** (`launchctl
  bootout`), so it cannot re-lock sites during the repair. Re-enable it with
  `./agent-login.py -I` once WS1 lands.

## Workstreams

- [ ] WS0 — the agent-login list reaches subagents (SubagentStart hook), Codex (`~/.codex`) and
      OpenCode; this lands before the first codex-debate
- [ ] WS-Z — does any agent need Zendesk *agent* access? (search the last 10 days of transcripts)
- [ ] WS1 — design fixes (plan → codex-debate → implement): the limiter is not burned by the
      daily check; granular failure reporting kept per site and shown in the overview; locked
      sites are reported as locked; ✅ stays green (proactive refresh, expiry tracking)
- [ ] WS2 — per-site root-cause fixes, one at a time:
  - [ ] npm-nixos
  - [ ] npm-raspi
  - [ ] calibre
  - [ ] cscs (important: cscs-api.py / Waldur still depend on it)
  - [ ] galaxus
  - [ ] galaxus-de
  - [ ] myfritz-alzenau
  - [ ] zendesk (after WS-Z)
  - [ ] notion (session lifetime; Albert does the `-g notion` login)
- [ ] WS3 — onboarding guard: a new broker item is validated before agents rely on it (plan →
      codex-debate → implement)
- [ ] Re-enable the daily check, run `./agent-login.py -c`, everything ✅

## Learnings (carried to every subagent)

- The broker limiter hard-blocks a site after 3 failed logins in a row; only root resets it
  (`sudo install/install.sh -r SITE`). Once locked, every attempt reports only
  "rate limited", which hides the original failure reason. **Count your attempts.**
- `agent-login.py -t SITE` prints the broker's detailed failure: stop URL, page text, password
  fingerprint, and the screenshot at `/var/db/login-broker-run/last-failure-SITE.png`. The
  overview and `last-check.json` keep only the exit code.
- `secret-run -A -N 500` prints the broker's audit log: result per login, no reasons.
- The broker runs the INSTALLED code (`/usr/local/libexec/login-broker/current`, from `git
  archive HEAD`). A broker-side fix is live only after commit + `sudo install/install.sh`.
  `bin/browser.py` is live for every consumer right away, so edit it only in a worktree.
