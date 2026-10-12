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

- [x] **A0 inventory (main session, value-free).** For both realms, through login,
      refresh, reload and logout, in a disposable profile and in Safari, record each
      cookie's name, domain, path, httpOnly flag and sameSite, plus the origin storage
      used (localStorage, IndexedDB, Cache Storage, service workers) on
      `https://custos.datascience.ch`.
      - Any authentication-relevant root, parent-domain or legacy cookie
        (`AUTH_SESSION_ID_LEGACY`, `KC_RESTART`, proxy cookies) keeps the items
        conflicting and stops Part A.
  - A0 logged out, 2026-10-11 (main session, value-free): every Keycloak cookie on custos
    is path-scoped per realm, in the shared Chromium and in Albert's Safari jar —
    `/realms/master/` and `/realms/sdsc/` each hold `AUTH_SESSION_ID`, `KC_RESTART`
    (httpOnly, session) and `KEYCLOAK_SESSION` (secure, persistent). No root-path cookie,
    no `.datascience.ch` cookie applies to custos.
  - [x] **A0 logged in (main session, still open):** repeat the inventory with a live
        session in each realm (login, refresh, reload, logout): `KEYCLOAK_IDENTITY` (not
        seen logged out) and every other cookie must carry the realm path; origin storage
        of `https://custos.datascience.ch` recorded. A root, parent-domain or legacy cookie
        keeps the items conflicting and stops Part A (the code still fails closed: a
        realm scope only narrows what an item's own cookie operations touch).
- [x] **Meanwhile:** custos-admin moves to the `alt` instance. That already satisfies the
      in-instance rule, since runai-test3 is in the default instance and runai-admin in
      `admin`.
- [x] **Structured field.** A new vault field `agent_cookie_scopes` holds a JSON list of
      `{host, path}`. `agent_cookie_hosts` is not overloaded. The sites view gets a
      protocol version `scope_v`.
      - Old clients ignore the new field and fail closed.
      - The code ships first; the vault migration comes after it.
      - Tests cover old-client/new-broker and new-client/old-broker.
- [x] **Canonical `CookieScope(host, path)`** in `broker.identity`:
      - path matching follows RFC 6265, so the exact path without its trailing slash is
        included;
      - overlap is computed jointly over domain relations (parent and subdomains) and
        path intervals;
      - fill/storage-origin overlap stays a conflict (O11).
      - Both the multi-account check and the in-instance validation, refused items
        included, use this one implementation.
- [x] **Every cookie operation** goes through the shared predicate, each with its own
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
- [x] **Validation:** malformed scopes are refused (broker side, built).
  - [x] `broker-add` gets a `--cookie-scopes` option (mydotfiles; spec in the build
        notes, delegated by the main session).
- [x] **Tests:**
      - the conflict matrix: `/`, exact path without slash, sibling, nested, parent
        domains;
      - injection and clearing touch only the cookies in the path;
      - a host-only scope behaves as before;
      - a sibling realm's cookies stay untouched;
      - mixed versions.

### B. Run:ai: a server-bound identity, or stay unproven

- [x] **B1 discovery spike** (time-boxed; main session plus a builder; value-free). Try
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
- B1 findings 2026-10-11 (main session, Albert's Safari as runai-test3, value-free):
  - The SPA's own refresh: `POST /api/v1/token` (same origin, JSON
    `{"grantType":"refresh_token","clientID":"runai-admin-ui"}`; the HttpOnly
    `refresh-token` cookie is path `/api/v1/token`) → 200 `{accessToken, idToken}`. The
    access token is a JWT issued by Run:ai's own Keycloak (`iss` path `/auth/realms/sdsc` on
    `app1.run.ai`, `azp` runai-admin-ui, `aud` [runai-dummy, runai]). Its `email`,
    `preferred_username` and `sub` all equal the vault username. Fetched fresh from the
    server in the isolated world, this is server-bound, like gitlab's `/api/v4/user`.
  - With that bearer: `/api/v1/authorization/permissions` → 200 (44 entries: resourceType,
    displayName, groupId, actions); `/api/v1/users/me` → 403; `/api/v1/authorization/access-rules`
    → 403 for test3. Admin-bit candidate: a fixed admin-only endpoint (200 vs 403), or a
    permission entry. Compare against runai-admin before fixing it.
  - localStorage `logged-in-user-email` did NOT equal test3: it was left over from an earlier
    login. This is live proof of Codex O3: the page claim was stale.
- Live acceptance finding 2026-10-12 (main session, runai-test3, value-free):
  - The admin probe answers the non-admin **403 with `content-type: text/plain;
    charset=utf-8`**; the body is Run:ai's JSON error object `{"code": <number>,
    "message": <string>}`. The same holds for `/api/v1/users` and
    `/api/v1/authorization/roles`. The JSON-content-type-only rule therefore gave
    `state: found, admin: null`, and `browser.py login runai-test3` ended
    `identity_indeterminate` at broker-proof.
  - Fixed (builder, worktree): recipe field `admin_probe_error_shape = ("code",
    "message")`. A status in `admin_probe_false` is "not admin" on a JSON content type, or
    — whatever the content type — on a body (≤ 64 KiB, UTF-8) that parses as a JSON object
    with exactly those two keys (`code` a finite number, `message` a string). HTML, another
    JSON shape, an oversized body: no bit. A 200 needs `application/json` AND a body that
    parses as JSON. `admin_true_confirmed` stayed False here (flipped after the admin
    confirmation below).
  - WS3 onboarding flagged the items' scope `app1.run.ai /auth/realms/sdsc/` as
    `risk unrelated_cookie_host` (blocks `-p`). Fixed: the cookie-host relation also counts
    the hosts of the item's reviewed identity recipe (`onboarding.recipe_hosts`: the
    pinned `issuer` and the `origin`), only when the item meets the recipe's
    `allowed_sites` and `origin` pins.
  - Both fixes need `install.sh` (`broker/identity.py` and `broker/onboarding.py` are
    shared by broker and client).
- [x] **Rules for any resulting recipe:**
      - **Who may use it:** it declares `allowed_sites`, an exact https origin and a fixed
        source, enforced by both the broker validation and the client proof.
      - **Proof artifact:** a missing artifact is `indeterminate`
        (`IDENTITY_STOP_CODES`) and never starts a login. Broker reuse needs the same
        server-bound proof.
      - **Consequences:** only a server-bound mismatch charges `IdentityGuard` or clears
        a session.
      - **Storage keys:** identity-source keys are rejected in `agent_storage_keys`, so
        they are never exported or injected.
- [x] **Privilege:** never implied from the vault.
      - Without a server role artifact, runai-admin stays unusable.
      - Whether a USER member may pass with its identity proven but its privilege
        unproven is put to Albert as an explicit choice.
      - If the spike finds no server-bound identity, both Run:ai members stay
        `identity_unproven`, and the weaker page-claim contract goes to Albert as an
        explicit choice, never as a default.
      - Built: the admin bit is a server artifact (the admin probe). Both answers are
        live-confirmed: "not admin" (403) for the user account, "admin" (200) for the
        admin account. A `user` member and the `admin` member each pass with identity
        AND privilege proven; no question for Albert arises.
  - [x] **Main session:** as runai-admin, confirm that the probe answers 200
        (status only), then set `admin_true_confirmed=True` in `IDENTITIES["runai"]`
        (and its test).
        - Live 2026-10-12 (main session, logged in as runai-admin in Albert's Safari,
          value-free): with the admin's own access token from `POST /api/v1/token`,
          `GET /api/v1/authorization/access-rules?subjectType=user`,
          `/api/v1/authorization/access-rules`, `/api/v1/users` and
          `/api/v1/authorization/roles` each answered `200 application/json;
          charset=UTF-8`; the broker's `RECIPE_JS` returned `{"state": "found",
          "admin": true}`.
        - A Run:ai application token (the manage-users client) gets 403 JSON on the
          probe: the bit tells user tokens apart (admin user vs non-admin user), not
          the roles of an application.
        - Built (builder, worktree): `admin_true_confirmed=True`; the unconfirmed-admin
          tests run on an explicit `admin_true_confirmed=False` variant, and new tests
          prove the admin item as `match` (both evaluators, and end to end).
  - [x] **Main session:** release the broker and the client again (`install.sh`) so
        runai-admin becomes usable.
- [ ] **Live acceptance**, for both accounts: fresh login, profile reuse, restart, logout,
      a switch made outside the broker, a forged or stale artifact, and a role change
      where that can be tested.

### C. Keycloak admin console (custos-admin): a server-bound identity

- [x] **C1 discovery** (main session, live 2026-10-12, Albert's Safari logged into the
      console, value-free; everything same-origin on `https://custos.datascience.ch`):
  - A silent `fetch` of `/realms/master/protocol/openid-connect/auth` (client
    `security-admin-console`, `redirect_uri` `/admin/master/console/`, `response_type
    code`, `response_mode query`, `scope openid`, `prompt none`, state, S256 challenge)
    ends on `/admin/master/console/` with a `code`, or with an `error`
    (`login_required`) when there is no session. A fetch never runs the console page,
    so nothing else spends the code.
  - The code exchange (form POST to `/realms/master/protocol/openid-connect/token`)
    answers 200 JSON with `access_token`, `id_token`, `refresh_token` (and other keys).
  - The access token is lightweight: exp, iat, jti, iss, typ, azp, sid, scope. It has
    no account name, and userinfo answers 401.
  - The ID token's claims include `preferred_username` (it contains `@`), `sub`,
    `email`, `azp` = `aud` = `security-admin-console`, and `iss` = `/realms/master`.
  - `GET /admin/realms` with the access token answers 200
    `application/json;charset=UTF-8` for the admin account; so do
    `/admin/realms/master/users/count` (one JSON integer; the recipe's probe since the
    review round) and `/admin/serverinfo`. A non-admin's 403 is expected, but not seen
    live: no such account exists.
- [x] **C2 recipe `keycloak-admin`** built (builder, worktree, 2026-10-12; build notes
      "Part C"). Not released.
- [x] **Main session:** the broker-add mirror (mydotfiles; spec in "Part C"), then
      release the broker and the client (`install.sh`), then set custos-admin's vault
      fields (table below).
- [x] **Live acceptance (custos-admin):** `browser.py logged-in custos-admin` in `alt`
      → `identity: match`. Record the one auth / token / probe run per check by status
      only. Also check that preferred_username equals the vault username after
      normalisation: a `wrong_account` on Albert's own session means they differ.
      Switching the recipe to the `email` claim would then also need `email_verified ===
      true`, and a master realm that forbids duplicate e-mails and does not let users
      edit their own e-mail. Otherwise an account could claim another's address.
- [ ] **403 side:** once a non-admin master-realm user exists, record the probe's
      status and content type. Then flip `admin_false_confirmed`, or adjust the
      false-side rule.

## Build notes (2026-10-11, worktree; BROKER + client: needs `install.sh` and the client release together)

### Part A — cookie scopes

- **`identity.CookieScope(host, path)`**: the host is normalised like a cookie host and the
  path is canonical (`/` stays; any other path loses its trailing slashes, so the RFC 6265
  path-match covers `/realms/sdsc` and `/realms/sdsc/…`).
  - `holds(domain, path)`: the cookie lies in the scope (host or subdomain, never a parent;
    path inside). Used for export and for the injection half of the client's replace:
    exact.
  - `clears(domain, path)`: what a DELETE in the shared browser takes. That is `holds`,
    plus a cookie on the host or a subdomain whose path is an ANCESTOR of the scope path:
    `/` and `/realms/` on custos, `/` and `/auth/` on app1.run.ai.
    - Never a parent domain, never a sibling path.
    - Used for the delete half of replace, rollback, logout and the foreign clear.
    - Why it is safe: such a cookie is sent into the realm and may carry a foreign
      session's state. A sibling realm's item can never share the instance, because the
      fill origin (the Keycloak host) keeps the two in conflict (O11).
  - `reaches(domain, path)`: the cookie lies in the scope or is sent into it. Used only
    by the broker's own wipe, with host-wide scopes.
  - `overlaps(other)`: related domains AND overlapping paths. Used for conflicts.
  - A `/` scope decides exactly as the old host lists did (tested against the old rule
    verbatim).
- **Conflicts** (`scope_conflicts`, the vault's in-instance rule): both use `item_scopes` =
  the cookie scopes plus the fill and storage origins' hosts at `/` (O11). Refused items
  take part as before. An item refused before its scope was parsed keeps its
  `agent_cookie_scopes` hosts host-wide.
- **Vault field `agent_cookie_scopes`**: a JSON list of 1–16 objects `{host, path?}` with
  exactly those keys.
  - `host`: a plain DNS name or IPv4 (no scheme, port or path).
  - `path`: absolute, plain printable ASCII: no whitespace, `%` (no percent-encoding:
    `%2e` would hide a dot segment), `;`, `,`, `?`, `#` or `\`. No `//`, no `.` or `..`
    segment, ≤ 256 characters. Duplicates fold.
  - Next to `agent_cookie_hosts`, both fields must name the same hosts (else refused). On
    its own, the field sets `cookie_hosts` to its hosts, which is what an old reader sees.
- **Views**: `sites` entries and session bundles carry `cookie_scopes` ([{host, path}],
  host-only items at `/`) and `scope_v: 1`.
  - Readers use `identity.entry_cookie_scopes`: the versioned field only when `scope_v`
    >= 1, the field is valid, and it names exactly `cookie_hosts`.
  - Anything else falls back to `cookie_hosts` at `/` (host-wide: more conflicts and a
    wider clear, never a narrower scope).
  - Old client with a new broker: host-wide. New client with an old broker: host-wide.
    Both are tested.
- **Broker fresh-login wipe and reset** (`fresh_login_scopes`): HOST-WIDE, as before S4c.
  - Every cookie host and fill-origin host at `/`: any path, the host, its subdomains and
    its parent domains.
  - `Storage.clearDataForOrigin` runs for every origin of the item.
  - A broker profile belongs to one site, so there is no sibling to spare. Path scopes
    apply only to the shared-browser operations (export, replace, rollback, logout,
    foreign clear).
  - Removed as dead code: `fresh_login_hosts`, `cookie_reaches_hosts`,
    `SiteItem.path_scoped_hosts`.
- **Status custos-admin vs runai-\*** (tested with the realistic fields): their cookie scopes
  no longer overlap (`/realms/master/` vs `/realms/sdsc/` + `sdsc.run.ai` +
  `app1.run.ai /auth/realms/sdsc/`). But all three
  type into `https://custos.datascience.ch` (fill origin), so they **still conflict** (O11).
  - In one instance, the later site id is refused.
  - custos-admin must go to `alt`, as planned. Part A changes no current conflict.

### Part B — the `runai` recipe

- **New auth `token-endpoint`**, with the reviewed spec fields:
  - `token_body` (a fixed JSON object), `token_field` (the JWT in the answer), `id_field`
    (a claim path);
  - `claim_pins` (`azp == runai-admin-ui`), `issuer` (`iss` must equal
    `https://app1.run.ai/auth/realms/sdsc` exactly), `exp` in the future (the isolated
    world's own `Date`);
  - `admin_probe` (a GET with the token as bearer): 200 with `application/json` and a JSON
    body → admin; 403 with `application/json`, or with a body that is exactly the
    `admin_probe_error_shape` object (`{code, message}`, any content type: Run:ai's 403 is
    text/plain, live 2026-10-12) → not admin. Anything else is no bit, including an HTML
    200 or 403 (an SPA fallback, a WAF page). `admin_true_confirmed` is True (the 200
    for the admin account seen live 2026-10-12);
  - `allowed_sites` (`runai-admin`, `runai-test3`), `origin` (`https://sdsc.run.ai`),
    `identity_storage_keys` (`logged-in-user-email`), `forms` (`email`).
  - `recipe_problem` validates all of it, and requires `allowed_sites` and `origin` for a
    token-endpoint recipe.
- **RECIPE_JS**: one new branch (`tokenWork`) entered only for `token-endpoint`, plus two
  helpers.
  - `call`: a same-origin fetch, `redirect: 'manual'`, the final URL's path and query
    pinned.
  - `digestOf`: the digest code moved into a helper, the same bytes.
  - gitlab, audiobookshelf and navidrome run the unchanged path, and their tests are
    unchanged.
  - The token lives only inside the function: never returned, exported or stored. No
    JWKS check: the token comes straight from the fixed endpoint in the isolated world
    (code comment in `IDENTITIES["runai"]`).
- **Who may use it**: one rule in `identity.recipe_refusal` / `item_recipe`.
  - `recipe_config_problem`: the recipe is usable, the site is in `allowed_sites`, and the
    check URL's https origin equals `origin`.
  - Plus the admin rule: `privilege admin` while `admin_true_confirmed` is False.
  - Enforced by the vault (config problems and identity-source storage keys → refused),
    `SiteItem.identity_recipe` (the broker's own proof, its login precheck, the challenge
    gate, `identity_ops`), `proof_ready` and the client proof.
- **Foreign clear**: a `wrong_account` check also removes the recipe's
  `identity_storage_keys` (`logged-in-user-email`) on the recipe's origin
  (`foreign_storage_keys`), so a foreign e-mail does not linger in the UI.
- **Service worker**: the recipe's world bypasses the origin's worker. Tested with a worker
  that answers `/api/v1/token` with another account's token: the main world is fooled,
  the recipe is not.
- **Side effect**: the POST is the SPA's own refresh, and may rotate the HttpOnly
  `refresh-token` cookie.
  - Each check runs the recipe once (tested: one POST and one probe per `logged-in`). A
    `login` runs it at most twice (free check, verify after injection); the broker runs
    it once per reuse or login.
  - Broker and client then hold different refresh tokens. Harmless unless Run:ai's
    Keycloak revokes reused refresh tokens.
- [x] **Release gate, refresh-token rotation (review SF2, main session, live).**
  - Run, all expected 200: a broker profile reuse of runai-test3, then a client
    `logged-in`, then a broker reuse again.
  - Record the token endpoint's status (only the status) for a REUSED refresh token and
    for a MISSING `refresh-token` cookie.
  - If rotation with reuse detection is enforced (the reused token is refused, or the
    session dies), the follow-up is to drop the broker profile's `refresh-token` cookie
    after the export, so the client's copy is the only live one.

### Deviations and interpretations

1. **Admin while unconfirmed = unproven, not a vault refusal.** It is valid in the vault,
   but `identity_recipe` is None everywhere, so the code is `identity_unproven`: never a
   login, never a pass. The brief said "refused as identity_unproven"; a vault refusal
   would have read `refused`. Config errors (another site, another origin, identity-source
   keys) are vault refusals.
2. **`identity_storage_keys`** is read as the page's OWN account claim
   (`logged-in-user-email`, seen stale in B1). The recipe reads nothing from storage. The
   refusal only adds a rule: no existing item changes.
3. ~~The `iss` host is not pinned~~: superseded in the review round. `iss` is pinned
   exactly to `https://app1.run.ai/auth/realms/sdsc`.
4. ~~The reset keeps a path-scoped host's origin storage~~: reverted in the review round.
   The broker's wipe and reset are host-wide again (see Part A).
5. `tests/test_ws5_broker.py`: the pinned recipe set gains `runai`. The "unknown recipe"
   cases use `nope` instead of `runai`. `tests/test_login_broker.py`: the fresh-login
   hosts test uses `fresh_login_scopes`.
6. Review round (2026-10-12): the admin bit only from JSON; Run:ai's own Keycloak scope
   `app1.run.ai /auth/realms/sdsc/` (live evidence 2026-10-11: Safari `KEYCLOAK_SESSION`,
   shared Chromium `AUTH_SESSION_ID` and `KC_RESTART` on that path); ancestor-path
   cookies in shared-browser deletes; no `%` in scope paths; the page claim key in the
   foreign clear; a service-worker test.

### Part C — the `keycloak-admin` recipe (custos-admin, 2026-10-12)

- **New auth `oidc-silent-pkce`** (`TOKEN_AUTHS` = token-endpoint + oidc-silent-pkce
  share the token rules: `token_field`, `claim_pins`, an exact `issuer`, the admin
  probe, `allowed_sites` + `origin`). Its own reviewed fields:
  - `client_id` (`security-admin-console`);
  - `auth_path` (`/realms/master/protocol/openid-connect/auth`);
  - `redirect_path` (`/admin/master/console/`);
  - `path`, the token endpoint (`/realms/master/protocol/openid-connect/token`);
  - `audience` (the `aud` pin: a string equal to it, or a list holding it);
  - `bearer_field` (`access_token`, the probe's bearer), with `token_field`
    (`id_token`) as the identity source.

  `_oidc_recipe_problem` requires the issuer on the recipe's origin, and both endpoints
  under the issuer's path. Fields of either token auth on any other auth are refused.
- **RECIPE_JS**: one new branch `silentWork`, entered only for `oidc-silent-pkce`.
  - The verifier (32 bytes), the state and the OIDC `nonce` (16 bytes each) come from
    the isolated world's `crypto.getRandomValues`, and the S256 challenge from its
    `crypto.subtle`.
  - The authorization fetch uses `redirect: 'follow'` and `mode: 'same-origin'`: a hop to
    another origin is a network error, never a request.
  - The final URL must have the same origin and the redirect path, and exactly one
    `state` equal to ours. Next, an `iss` that equals the issuer if present, checked
    BEFORE any error is believed (RFC 9207). Then exactly one `code` of safe
    characters.
  - Only a single `error=login_required` → `logged_out`. Every other error
    (`interaction_required`, i.e. a pending required action, `invalid_request`,
    `unauthorized_client`, `server_error`, `temporarily_unavailable`, …) →
    indeterminate (why `error`). A server fault or a required action must never
    trigger a password login that would then stall into quarantine. Anything else
    unexpected → indeterminate (`redirect`, `state`, `claim`, `code`).
  - The code exchange goes through the existing `call` (redirect manual, final URL
    pinned). Any non-200 is indeterminate: the auth step already proved a session.
  - The claim pins moved into a shared helper `found` (pins, audience, the OIDC nonce,
    iss, exp, identity, probe); runai's `tokenWork` calls it unchanged
    (`found(origin, t, t)`: no nonce, no leeway).
  - ID-token pins: `azp` and `typ` = `ID` (`claim_pins`), `aud`, `nonce` = this run's,
    the exact issuer, and `exp` with 30 s of leeway (`exp_leeway_s`, 0–60, default 0).
    The master realm's token lifespan is 60 s, so a few seconds of clock skew would
    otherwise fail a fresh token.
  - Tokens never leave the function, and the refresh token is never read.
- **Admin bit**: `GET /admin/realms/master/users/count` (review round: 200 JSON live,
  C1). It needs user rights IN the master realm, which only master administrators
  hold. `/admin/realms` would also say yes for an admin delegated for one other realm
  (its list is filtered).
  - 200 under a JSON content type whose body is ONE non-negative JSON integer, read
    with the capped reader (`admin_probe_true_integer`) → admin. Any other 200 body
    (a list, an object, a string, a negative or fractional number, > 64 KiB) → no bit.
  - 403 under a JSON content type → not admin. No error-object shape: Keycloak's is
    not confirmed, so a plain-text 403 is no bit.
  - HTML 200/403, 401, 404, 500 → no bit.
- **`admin_false_confirmed`** (new; default True, so all other recipes are unchanged):
  False for keycloak-admin. `recipe_refusal` then keeps every non-admin item unproven
  (`identity_unproven`, valid in the vault), mirroring `admin_true_confirmed`.
- **Side effects of one run**: Keycloak adds a client session of
  `security-admin-console` to the SSO session and may record LOGIN / CODE_TO_TOKEN
  events. Per check: exactly one authorization request, one code exchange and one
  probe (tested, also end to end through the real broker).
  - The check page IS the console: loading it also runs the console's own keycloak-js
    flow (its own authorization request, code exchange and API calls). One check
    therefore costs about twice the Keycloak calls of the recipe alone.
  - Every check refreshes the Single Sign-On (SSO) session's idle timer: a scheduled
    check keeps an otherwise idle custos session alive until its maximum lifespan.
- **Tests**: `tests/test_ws5_keycloak_admin.py`. It covers the spec and its refusals,
  who may use the recipe, the vault, and both evaluators.
  - Evaluator cases: match / mismatch / privilege; login_required vs every other
    error; the azp / typ / aud / nonce / iss / exp pins and the exp leeway; state /
    code / iss (also before an error) / path / off-origin redirects; token-endpoint
    statuses and shapes; the probe's count answers; page hooks of crypto (a
    predictable state and nonce) / Response.json / JSON / atob / fetch; another page
    origin; leak checks.
  - End to end: match, wrong_account (cookies cleared, no storage), and a user item
    unproven without a single request.
  - Playwright does NOT route the request that follows a fulfilled redirect: it goes to
    the network. The fixture therefore maps the fixture hosts to a local TLS server
    (`--host-resolver-rules`, a throwaway certificate) and every other host to
    `~NOTFOUND`. The test browser runs with `--no-proxy-server`, and the fixture's
    teardown asserts that every follow-up landed on a fixture host.
  - The first test runs of this build lacked that mapping. They sent the follow-up
    GETs of the console URL, with random fixture `state`/`code` values, from a
    cookie-less throwaway browser to the real custos host: no login, no credential.
  - `tests/test_ws5_broker.py`: the pinned recipe set gains `keycloak-admin`.
  - `bin/browser.py`: `_IDENTITY_WHY` gains `state` and `code`, so the result records
    them instead of `other`.
- **broker-add mirror** (mydotfiles `bin/broker_add_fields.py`, main session):
  - `IDENTITIES` gains `"keycloak-admin"`.
  - `USABLE_IDENTITY_FORMS` gains `"keycloak-admin": ("email",)`.
  - `RECIPE_RULES` gains `"keycloak-admin": RecipeRules(allowed_sites=("custos-admin",),
    origin="https://custos.datascience.ch")`.
  - (The probe, the pins and the leeway are broker-only; the mirror needs none of
    them.)
  - `RecipeRules` gains `admin_false_confirmed: bool = True` (False for
    keycloak-admin), with a `recipe_admin_note` twin for a non-admin privilege: "the
    item stays unproven until the not-admin answer is confirmed".
  - Separately, the mirror's `runai` still says `admin_true_confirmed=False`; the
    broker flipped it to True on 2026-10-12.

### Vault values (main session, after the broker-add change)

| Item         | `agent_cookie_scopes`                                                                                                                            | `agent_instance` | `agent_privilege` | `agent_identity` |
| :----------- | :----------------------------------------------------------------------------------------------------------------------------------------------- | :--------------- | :---------------- | :--------------- |
| runai-test3  | `[{"host":"sdsc.run.ai","path":"/"},{"host":"custos.datascience.ch","path":"/realms/sdsc/"},{"host":"app1.run.ai","path":"/auth/realms/sdsc/"}]` | (empty)          | `user`            | `runai`          |
| runai-admin  | the same                                                                                                                                         | `admin`          | `admin`           | `runai`          |
| custos-admin | `[{"host":"custos.datascience.ch","path":"/realms/master/"}]`                                                                                    | `alt`            | `admin`           | `keycloak-admin` |

- `agent_cookie_hosts`: either remove it, or set it to exactly the scope hosts
  (`sdsc.run.ai,custos.datascience.ch,app1.run.ai` for the Run:ai items).
- The check URL must be on `https://sdsc.run.ai`, and the username stays the e-mail.
- `logged-in-user-email` must not appear in `agent_storage_keys`.
- runai-admin is provable once the broker and client with `admin_true_confirmed=True`
  are released (flipped 2026-10-12).
- custos-admin (`-i keycloak-admin -p admin -I alt`): its check URL must be on
  `https://custos.datascience.ch` (the console, `/admin/master/console/`), and its
  username stays the e-mail (`forms=("email",)`). It is provable once the broker-add
  mirror and the broker + client with `keycloak-admin` are released. It still conflicts
  with the Run:ai items through the fill origin, so the proof is what makes it usable.

### Release order (cross-repo)

- mydotfiles `broker_add_fields.py` mirrors the recipe table. `test-broker-add.py`
  `case_identity_pins` fails until `IDENTITIES` gains `runai` and `USABLE_IDENTITY_FORMS`
  gains `"runai": ("email",)`.
- broker-add would also refuse `-i runai` today ("bad agent_identity"), so the broker-add
  change must land before the Run:ai vault fields are set.
- Old clients do not know `runai` and keep its items unproven (fail closed). Release the
  client with the broker.
- The same holds for `keycloak-admin`: the broker-add mirror (Part C) first, then the
  broker and client release, then `-i keycloak-admin` on custos-admin.

## Verification

```commands
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run ruff format --check bin broker tests
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run ruff check .
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run mypy bin/browser.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pylint bin/browser.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pytest -q tests
cd /Users/albert/obsidian/42-Git/home/browser-login && bin/browser.py -h
```

## Live acceptance 2026-10-12 (main session)

- A0 logged in: alt (custos-admin) holds `AUTH_SESSION_ID`, `KC_AUTH_SESSION_HASH`,
  `KEYCLOAK_IDENTITY`, `KEYCLOAK_REMEMBER_ME`, `KEYCLOAK_SESSION`, all on
  `custos.datascience.ch /realms/master/`; the shared browser (runai-test3) holds its
  Keycloak cookies on `/realms/sdsc/` and `app1.run.ai /auth/realms/sdsc/` only. No root-path or
  parent-domain cookie on either host.
- runai-test3 (default) and runai-admin (admin browser) ✅ side by side; custos-admin ✅ in `alt`.
  All three promoted (`-p`). Fresh login (`agent_fresh_login`) carries the session-only
  `KEYCLOAK_IDENTITY`; with it the broker never reuses a refresh token, so the rotation gate is
  moot on the broker side; two client checks in a row passed.
- Still open: the full live-acceptance matrix (restart, logout, out-of-band switch) runs with
  the daily job at final acceptance (PLAN_agent-login-repair.md); the 403 side of
  keycloak-admin waits for a non-admin master user.
