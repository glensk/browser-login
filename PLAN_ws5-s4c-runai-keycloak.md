## Session

Resume: `c --resume 3871ad21-0f16-4b68-828e-f9eb1f7a6847`

# WS5 S4c: Keycloak realm-path cookie scopes + a server-bound Run:ai identity (tp#909)

## Context

WS5 (`PLAN_ws5-account-identity.md`, tp#909) refuses broker items that share one cookie
scope unless each one carries a usable server identity recipe. `broker/identity.py`
`usable_recipe` requires a recipe that is reviewed, `live_confirmed`, and has an admin bit.
The recipe runs in a CDP isolated world on both the broker side and the client side.
Released: gitlab and audiobookshelf. In review: navidrome.

The live findings below come from Albert's Safari on 2026-10-11 (schema only):

- **Run:ai** (`sdsc.run.ai`; members runai-admin and runai-test3; login through the
  Keycloak realm `sdsc` at `custos.datascience.ch`): the SPA keeps its bearer token in page
  memory. There is no JS-readable cookie and no storage token, and `/api/v1/*` answers 401
  when called with cookies alone. The page stores the user's e-mail in localStorage
  `logged-in-user-email` and shows initials in the top-right menu. Albert (2026-10-11):
  "a runai web session has a logged in user on top right, so web session can be
  distinguished".
- **Keycloak admin console** (custos-admin, realm `master`): it has the same in-memory
  token. It conflicts with Run:ai only through the host `custos.datascience.ch`, and
  Keycloak scopes its session cookies to `/realms/<realm>/`. Albert chose realm-path scopes.
- `install.sh -S custos-admin runai-admin` → different accounts. Docker and docker-hub left
  the broker (Albert: neither).

Codex debate (round 1, gpt-5.6-sol, converged):

- A page-written claim such as localStorage, or the DOM, is forgeable and never
  authorizes.
- A vault-declared privilege is an expectation, not evidence.
- Cookie paths do not isolate origin-scoped storage.
- A new scope format needs versioning, one shared overlap implementation, and every
  cookie code path.

Verification is not strict-eligible on purpose: it needs the test suite, mypy and pylint
(security-relevant broker and client code).

## Steps

### A. Keycloak realm-path cookie scopes

- [ ] **A0 inventory (main session, value-free).** For both realms, through login,
      refresh, reload and logout, in a disposable profile and in Safari, record each
      cookie's name, domain, path, httpOnly flag and sameSite, plus the origin storage
      used (localStorage, IndexedDB, Cache Storage, service workers) on
      `https://custos.datascience.ch`.
      - Any authentication-relevant root, parent-domain or legacy cookie
        (`AUTH_SESSION_ID_LEGACY`, `KC_RESTART`, proxy cookies) keeps the items
        conflicting and stops Part A.
- [ ] **Meanwhile:** custos-admin moves to the `alt` instance. That already satisfies the
      in-instance rule, since runai-test3 is in the default instance and runai-admin in
      `admin`.
- [ ] **Structured field.** A new vault field `agent_cookie_scopes` holds a JSON list of
      `{host, path}`. `agent_cookie_hosts` is not overloaded. The sites view gets a
      protocol version `scope_v`.
      - Old clients ignore the new field and fail closed.
      - The code ships first; the vault migration comes after it.
      - Tests cover old-client/new-broker and new-client/old-broker.
- [ ] **Canonical `CookieScope(host, path)`** in `broker.identity`:
      - path matching follows RFC 6265, so the exact path without its trailing slash is
        included;
      - overlap is computed jointly over domain relations (parent and subdomains) and
        path intervals;
      - fill/storage-origin overlap stays a conflict (O11).
      - Both the multi-account check and the in-instance validation, refused items
        included, use this one implementation.
- [ ] **Every cookie operation** goes through the shared predicate, each with its own
      test:
      - broker export;
      - broker fresh login and the `wrong_account` reset (`reset_site_profile`, which must
        not clear the sibling realm's origin state; until A0 proves that state is
        irrelevant, conflicting items stay in separate instances);
      - client replace;
      - client rollback;
      - `logout`;
      - the WS5 foreign-session clear.

      The Safari import uses static `SafariSite` domains and is out of scope, because no
      Safari site is path-scoped.
- [ ] **Validation:** malformed scopes are refused, and `broker-add` gets a
      `--cookie-scopes` option.
- [ ] **Tests:**
      - the conflict matrix: `/`, exact path without slash, sibling, nested, parent
        domains;
      - injection and clearing touch only the cookies in the path;
      - a host-only scope behaves as before;
      - a sibling realm's cookies stay untouched;
      - mixed versions.

### B. Run:ai: a server-bound identity, or stay unproven

- [ ] **B1 discovery spike** (time-boxed; main session plus a builder; value-free). Try
      in order:
      1. Capture the SPA's own bearer token over CDP Network on an `/api/v1/*` request, in
         an owned tab. Validate its signature against the realm's JWKS
         (`/realms/sdsc/protocol/openid-connect/certs`, pinned issuer, audience/azp and
         exp). Read the identity from the validated claims.
      2. A silent OIDC `prompt=none`.
      3. The HttpOnly `KEYCLOAK_IDENTITY` `sub`, read over CDP and mapped through the
         Keycloak admin API.

      Also find a server-authenticated role artifact: a role claim in the token, or a
      fixed authenticated Run:ai roles endpoint. Write down why each approach that fails
      does so.
- [ ] **Rules for any resulting recipe:**
      - **Who may use it:** it declares `allowed_sites`, an exact https origin and a fixed
        source, enforced by both the broker validation and the client proof.
      - **Proof artifact:** a missing artifact is `indeterminate`
        (`IDENTITY_STOP_CODES`) and never starts a login. Broker reuse needs the same
        server-bound proof.
      - **Consequences:** only a server-bound mismatch charges `IdentityGuard` or clears
        a session.
      - **Storage keys:** identity-source keys are rejected in `agent_storage_keys`, so
        they are never exported or injected.
- [ ] **Privilege:** never implied from the vault.
      - Without a server role artifact, runai-admin stays unusable.
      - Whether a USER member may pass with its identity proven but its privilege
        unproven is put to Albert as an explicit choice.
      - If the spike finds no server-bound identity, both Run:ai members stay
        `identity_unproven`, and the weaker page-claim contract goes to Albert as an
        explicit choice, never as a default.
- [ ] **Live acceptance**, for both accounts: fresh login, profile reuse, restart, logout,
      a switch made outside the broker, a forged or stale artifact, and a role change
      where that can be tested.

## Verification

```commands
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run ruff format --check bin broker tests
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run ruff check .
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run mypy bin/browser.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pylint bin/browser.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pytest -q tests
cd /Users/albert/obsidian/42-Git/home/browser-login && bin/browser.py -h
```
