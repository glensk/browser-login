## Session

Resume: `c --resume 3871ad21-0f16-4b68-828e-f9eb1f7a6847`

# WS5 S4c: Run:ai page-claim identity + Keycloak realm-path scopes (tp#909)

## Context

WS5 (`PLAN_ws5-account-identity.md`, tp#909) refuses broker items that share one cookie
scope unless each carries a usable server identity recipe (`broker/identity.py`
`usable_recipe`: reviewed + `live_confirmed` + an admin bit). It runs in a CDP isolated world
on the broker side and the client side. Released: gitlab, audiobookshelf; navidrome is in review.

There are two groups no server recipe can serve. The live findings in Albert's Safari
(2026-10-11, schema only) are:

1. **Run:ai** (`sdsc.run.ai`; members runai-admin, runai-test3; login through Keycloak
   realm `sdsc` at `custos.datascience.ch`). The SPA keeps its bearer token in page memory:
   - there is no JS-readable cookie;
   - there is no storage token;
   - `/api/v1/*` with cookies alone answers 401.

   An isolated world cannot reach the token, so no `RECIPE_JS` fetch can prove the account.

   The page does persist the logged-in user's e-mail in localStorage, written by the app at
   login from the token (`logged-in-user-email`). It also renders the user in the top-right
   menu (initials; the e-mail after opening the menu). Albert (2026-10-11): "a runai web
   session has a logged in user on top right, so web session can be distinguished if its
   admin or test".
2. **Keycloak admin console** (custos-admin, realm `master`, `/admin/master/console/`). It
   has the same in-memory token, so it has no server recipe either.

   But it conflicts with Run:ai only because both name the HOST `custos.datascience.ch` in
   `agent_cookie_hosts`. Keycloak scopes its session cookies (`KEYCLOAK_IDENTITY`,
   `KEYCLOAK_SESSION`, `AUTH_SESSION_ID`) to the path `/realms/<realm>/`, so the master and
   sdsc sessions never overwrite each other. Albert chose realm-path scopes (2026-10-11).

`install.sh -S custos-admin runai-admin` → different accounts. Docker / docker-hub leave the
broker (Albert: neither), so they are out of scope.

## Steps

### A. Path-scoped cookie hosts (broker + client)

- [ ] An `agent_cookie_hosts` entry may carry a path prefix: `host/path/` (e.g.
      `custos.datascience.ch/realms/master/`). The path must start at a segment boundary
      and end with `/`; there are no wildcards.
- [ ] Scope semantics: the entry covers cookies whose domain matches the host (as today)
      AND whose cookie `path` starts with the prefix. A host-only entry keeps today's
      meaning: every path.
- [ ] Conflict detection (`scope_conflicts`, S0/S1 in-instance rule):
      - two entries on one host conflict unless both carry paths and neither path is a
        prefix of the other;
      - a host-only entry conflicts with every entry on that host.
- [ ] Every cookie operation that is scoped by `cookie_hosts` honours the path:
      - bundle export (broker);
      - injection / replace (`_broker_replace_cookies`);
      - `logout`;
      - the WS5 foreign-session clear;
      - session-age;
      - the Safari import.

      A cookie with path `/` on a path-scoped host is NOT in that scope. Keycloak sets
      `/realms/<realm>/` cookies; a stray `/` cookie stays the host's.
- [ ] Vault validation refuses malformed paths. `broker-add -k` accepts them.
- [ ] Vault change (Albert's Touch ID or Safari):
      - custos-admin → `custos.datascience.ch/realms/master/`;
      - runai-admin and runai-test3 → `sdsc.run.ai`, `custos.datascience.ch/realms/sdsc/`.
- [ ] Tests:
      - the conflict matrix;
      - injection/clear touching only the path's cookies;
      - a host-only entry unchanged;
      - a path cookie on a sibling path untouched.

### B. Page-claim identity recipes (`runai`)

- [ ] A new recipe class `page-claim`: no server call; the isolated world reads ONE
      declared localStorage key on the check origin (`runai`: `logged-in-user-email`),
      normalises it like the vault username (forms: email), and hashes it like
      `RECIPE_JS`. A missing key → `logged_out`, so there is no guess.
- [ ] It carries no admin bit. The verified identity implies the vault's declared
      privilege (an account's privilege is fixed per item): `admin_verdict` treats a
      page-claim recipe as "privilege = declared" after a `match`. The plan text says why
      this is acceptable here: the threat WS5 guards against is a mixed-up session (the
      wrong sibling's cookies), not a hostile page. A page-claim catches the sibling mix-up
      because the app rewrites the key at every login.
- [ ] `usable_recipe` accepts a page-claim recipe only when ALL hold:
      - it is listed by name in a reviewed allowlist (`PAGE_CLAIM_SITES`, only `runai`);
      - it is `live_confirmed`;
      - the item lives alone in its instance for its conflict group, which the in-instance
        rule already guarantees.

      agents.md and `-x` label such an item's proof `page claim` (weaker than `server`).
- [ ] Staleness guard: the key must be written AFTER the session's last login. The broker
      clears the key before each login (`reset_site_profile` already clears storage on a
      `wrong_account` reset; add: a fresh login clears it on the check origin first). The
      client's foreign-session clear removes it with the other storage keys.
- [ ] Live confirm (main session, Albert's Safari, equality only): the key equals the
      logged-in account after a login as runai-test3. Then log in as runai-admin and confirm
      the key flips.
- [ ] Vault fields:
      - runai-test3: `agent_privilege=user`, `agent_identity=runai`, `agent_alias=runai`
        (default instance);
      - runai-admin: `agent_privilege=admin`, `agent_identity=runai`, `agent_instance=admin`.

      custos-admin needs no identity: after A it shares no scope.
- [ ] Tests:
      - match / mismatch / missing key in a throwaway Chromium;
      - a page-claim recipe not on the allowlist is refused;
      - the privilege is implied only after a match;
      - leak checks (the e-mail is never printed).

## Verification

```commands
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run ruff check .
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pytest -q tests
```
