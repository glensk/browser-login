# PLAN: browser-login suite load fragility (tp#1672)

> **Resume here.** Status: root-caused and planned. Nothing is built yet. Next box: B1.
> B1 changes `broker/recipes.py`, which is broker code. The launchd broker runs from the
> installed copy (`${LIBEXEC}/current/broker/daemon.py`, `install/install.sh:448`), not from
> this checkout. That means the file is not live here, but the fix only reaches production
> after a reinstall, which Albert does as root. All other boxes are test-only. Work in a
> worktree anyway (`.worktrees.noindex/<name>`), because other agents build and run
> browser-login tests in this repo concurrently. Only one writer may work in the repo at a time.

## Session

Ticket: tp#1672 (follow-up of tp#1655)
Overseer session: 0f33deca-4332-40a7-8fe2-a03b66cfef7c (cause + plan)
Base: e1dbd52-era main. `tests/test_ws2_cscs.py`, `broker/recipes.py` and
`broker/daemon.py` are unchanged since 10-31.

## CSCS gate (Albert's rule: the CSCS Kubernetes cluster is out of use)

This gate does **not** apply. The `cscs` recipe (`broker/recipes.py:2421-3022`) and
`tests/test_ws2_cscs.py` log in to the **CSCS portal** (`https://portal.cscs.ch`, a Waldur
deployment behind Keycloak `https://auth.cscs.ch`). They do not touch the Kubernetes
cluster. The portal login is still in use:

- `sdsc/cscs-api/cscs-api.py` refreshes its Waldur token through `browser.py login cscs`.
  `repo_scope.md` names `sdsc-user-deactivation` as the primary consumer: it warns when a
  departing user still holds a CSCS project role.
- `sdsc/sdsc-automations/operations.yaml:2455-2595` uses it for Zoho workflows 37 and 38
  (join an existing CSCS project, project-member lookup) through `cscs-api.py` with
  `environment_contract: cscs-portal`.
- The "cscs cluster out of use since 2026-09-05" lines (`operations.yaml:258, 1034`) are
  about the department subvolume and cluster paths, not about the portal.
- `~/.local/state/agent-login/agents.md` lists `CSCS` (currently quarantined, so the
  main session has to release it with `agent-login.py -Q cscs`).

So we fix the 4 cscs failures instead of skipping them. Two of the three causes are real
races that can also hit the live login.

## Causes (evidence)

Measured on 2026-11-03, 22:25-22:45 Europe/Zurich, at load average 18-21. Each test was run
at most twice, in the foreground.

### C1. Keycloak combined form classified as "re-auth" (3 failures; high confidence)

`_cscs_form_or_portal` (`broker/recipes.py:2728-2770`) reads the two fields in **two
separate DOM queries**: `_visible(page, "#username")` at :2744, then
`_visible(page, "#password")` at :2745. `_visible` (`:560-568`) also returns None when
`query_selector_all` raises, for example "execution context destroyed" during a navigation.
The portal leaves for Keycloak by itself. The fixture app does it 300 ms after load
(`tests/test_ws2_cscs.py:102`, `away()`), and live HomePort does the same through its
redirect. If that navigation commits between the two queries, the first query sees the old
portal document (or raises, which also gives None) and the second sees the Keycloak form.
The result is `KeycloakForm(user=None, password=<el>)`. `_cscs_password_field` (:2946-2948)
treats `user is None` as the re-authentication page and calls `_cscs_reauth`. The combined
form has no `#kc-attempted-username` and no `#reset-login`, so `_cscs_reauth` raises
`LoginFailed("Keycloak asks for a password without naming this item's account")` (:2895-2899).

Evidence from the run: `test_a_fresh_login_exports_the_validated_token` failed at
`test_ws2_cscs.py:535` with exactly that detail. The page hint taken **at raise time** shows
the full combined form: `(on …/connect/auth; fields: text#username, password#password,
checkbox#rememberMe, submit#kc-login)`. The username field was there, and the
classification missed it by one query. The same test passed in the other run, and the
ticket's `:600`/`:764` failures (`test_a_stale_expiry_is_refreshed_before_export`,
`test_a_silent_sso_with_a_failed_export_keeps_the_streak`) passed in my run. That points to
a timing race, not a logic error. Load widens the gap between the two queries. This is a
production bug, not only a test bug: the same split read runs against live Keycloak. It
fails before anything is submitted, so no credential is sent.

### C2. `test_a_valid_token_under_another_key_proves_nothing` races the fixture's own redirect (1 failure; high confidence)

The test seeds **no** `waldur/auth/token` (`test_ws2_cscs.py:410`), so the fixture app
schedules `location.replace(KC_AUTH)` 300 ms after `/profile/` loads (`:101-103`). Then it
runs three in-page checks in sequence: `cscs_token_state` (:417), `cscs_token_proof`
(:418) and `cscs_export_storage` (:419). Each check makes 1 config fetch plus up to 2
`/api/users/me/` fetches through Python route handlers. Under load the redirect lands
somewhere inside that sequence. Each landing point gives a different symptom, and the
three runs showed three of them:

- in my run 1, :418 got `invalid`. The page was already on `auth.cscs.ch`, so
  `cscs_token_proof` returned INVALID at `recipes.py:2612-2613`.
- in my run 2, :417 got `indeterminate`. The navigation aborted the in-page fetch, which
  gives the `network` reason and then undecided.
- in the ticket, :419 got "the portal holds no token". The export read the Keycloak
  origin's empty localStorage, which gives `none`.

What this test is meant to prove (a valid token under a foreign key means `wrong_key`, then
indeterminate, then no export) has nothing to do with the redirect. The fixture's timer
makes the test non-deterministic. The production code is correct here: off the portal is
INVALID, which is right for a real redirect.

### C3. `test_login_timeout.py` 0.3 s step budget covers the whole setup (load-only; high confidence)

`test_stuck_evaluate_fires_closes_the_owned_tab_and_exits_124` (:206) and
`test_failed_close_still_listed_is_125_unconfirmed` (:246) set `BG_PAGE_STEP_S = 0.3`.
They expect the deadline to fire in the stuck `fn` (`step == "bg:fn"`) after a tab was
created (`fake.created[0]`). But `_background_page_run` pushes that budget **before** all
the setup work (`bin/browser.py:11463`, step label `bg:create` at :11464). Inside the
budget come `_is_up` (HTTP to FakeCdp), `_registry_register` (file lock + registry),
`ledger.pending` (`bg:ledger`, :11964), `_browser_ws_url` (HTTP), the raw
`Target.createTarget` over WebSocket (`bg:create`, :11969), and the attach (`bg:adopt`,
:11935). Under load that preamble alone takes more than 0.3 s, so the watcher fires in
`bg:create`/`bg:ledger`, before `fn`. The assertions on `step`, `fake.created[0]` and the
125 path then fail. `test_stalled_raw_create_fires_on_bg_create_and_leaks_no_target` (:227)
has the same exposure on its step label (`bg:ledger` instead of `bg:create`). At load ~20
the whole file passed for me (15 passed, 98.6 s), so the failure depends on the moment.

Side finding: `test_disarm_racing_the_expiry_never_exits_after_it_returned` (:295) took
**65.7 s** (200 iterations of arm/sleep/disarm at `DEADLINE_POLL_S = 0.0005`). The likely
causes are sleep granularity under load plus each fired iteration running `_fire`'s
real cleanup (`_close_owned_targets`, `_access_team_sweep_cdp` on port 1, journal,
`_result_write`, `bin/browser.py:11258-11330`). Medium-low confidence: B4 measures it
first.

### C4. `test_ws2_npm.py::test_a_stale_cached_build_does_not_blank_the_login` is slow, not hung (high confidence)

The test makes three full broker logins in sequence (`test_ws2_npm.py:391-420`). Each one
starts its own Node driver and a persistent-profile Chromium. The middle ("broken") login
must wait out its negative windows: `generic_login` settle (`settle_s=4.0`, `fast` fixture
:337-345) and the post-submit proof. Wall-clock timing per step, from an out-of-repo timing
plugin (one run, load ~20):

| step | login 1 (logged out) | login 2 (broken) | login 3 (reuse) |
| --- | --- | --- | --- |
| `sync_playwright` start | 2.1 s | 0.9 s | 1.0 s |
| `runner._launch` (persistent Chromium) | 6.6 s | 3.5 s | 5.1 s |
| `_profile_proof` | 6.1 s | 4.3 s + 6.5 s | 1.4 s |
| `generic_login` | — | 7.6 s | — |
| `ctx.close` | 1.7 s | 0.3 s | 0.3 s |
| total `runner.__call__` | 17.1 s | 24.1 s | 8.8 s |

That run took 55 s. The cProfile run before it took 138 s at the same load band, and the
ticket saw 181 s at load 20-38. Nothing blocks: every step scales with CPU contention from
concurrent Chromium-heavy work. The 120 s `faulthandler_timeout` (`pyproject.toml:37`)
fired a stack dump during the 138 s run, but the test passed. The dump showed the main
thread in Playwright's event loop and `RunWatchdog._run` (`broker/daemon.py:458`) idle in
its wait. A dump is noise, not a hang.

### C5. Full suite > 3600 s at load ~20 (high confidence on the mechanism, medium on the share)

About 180 tests carry `launches_chrome`. The largest groups are `test_ws2_cscs.py` 27,
`test_authentik.py` 26, `test_ws2_npm.py` 17, `test_ws5_runai.py` 15,
`test_ws5_client_s2.py` 14 and `test_ws5_keycloak_admin.py` 12. They run **serially**:
there is no xdist, and parallel runs would only add load. Almost every one starts a fresh
Node driver plus Chromium. At load 20 that costs 1-2 s for the driver and 3.5-6.6 s for the
launch, before any test work. Broker end-to-end tests then add fixed negative waits.
Measured at load ~20: cscs broker tests 20-66 s each, cscs page tests 3-12 s, npm stale
build 55-181 s, `test_disarm_racing` 66 s. At about 20 s average per Chromium test,
180 tests come to about 3600 s, and that is before the roughly 1000 hermetic tests. The
suite has no time budget and no per-file duration record, so we cannot tell a regression
from load.

## Fix design (tests made deterministic without loosening what they prove)

- **C1 (code):** classify the Keycloak page from **one stable observation**. A
  password-only shape (`user is None`, `password` visible) now has to be seen on **two
  polls in a row**, like the username-only shape already is (`user_only`, :2741-2751). The
  handles come from the second poll. On the second poll the combined form shows both fields
  and is taken as combined. A real re-auth page is stable and still classifies as re-auth
  after one more `CSCS_POLL_MS`. As a second safety net, `_cscs_reauth` re-checks
  `_visible(page, "#username")` before raising "without naming…". If the username field is
  visible, it returns the full form instead of failing. What stays true: a password is never
  typed for an account the page names differently, and the reauth tests (:656, :669) are
  unchanged.
- **C2 (test):** add a `Portal.leave_without_token: bool = True` fixture switch. `_APP_JS`
  gets `away()` only when it is true. The wrong-key test sets it to False and asserts at the
  end that `page.url` is still `PORTAL + "/profile/"`. That way the test provably runs all
  three checks on the portal. The redirect behaviour keeps its own coverage
  (`test_no_token_on_the_portal_is_invalid`, the broker login tests).
- **C3 (test):** separate "the bg step sits inside `BG_PAGE_STEP_S`" (a structural fact,
  checked deterministically) from "a stalled step fires" (timing):
  - Leave `BG_PAGE_STEP_S` at a value the setup cannot exhaust (e.g. 30).
  - The stuck call itself (`FakePage.evaluate`, and in :227 the stalled
    `_cdp_create_background_target` wrapper) opens the short budget with
    `browser._active_deadline().push(0.3, "background_page")` around its wait. That is the
    public `LoginDeadline.push`, the same API `_background_page_run` uses.
  - The watcher then fires inside the stuck step every time. Keep the `step`, `scope`,
    `owned` and rc assertions. Measure `exits.at[0]` from the start of the stall, still
    under 2.0 s.
  - Add one hermetic assertion, by spying `_deadline_push` and `_deadline_step`: the push
    of `(BG_PAGE_STEP_S, "background_page")` comes before `bg:create`, and its pop comes
    after `bg:close`. This keeps the claim that the step budget covers create and close.
- **C3 side (test):** measure `test_disarm_racing…`. If `_fire`'s side effects dominate, stub
  `_close_owned_targets` / `_access_team_sweep_cdp` / `_result_write` in that test only. It
  pins the lock protocol, not cleanup. Keep 200 iterations, `not late` and `fired > 0`.
- **C4 (test):** replace login 1, whose only job is "the broker profile caches build a",
  with a direct visit through `rig.brk.runner._launch(pw, profile_dir("npmfix"))` plus
  `goto(origin)` and `ctx.close()`. This is the pattern `test_a_stale_expiry_is_refreshed`
  already uses (`test_ws2_cscs.py:600-613`). It saves one proof window and one
  limiter round. The broken login and the reuse login stay as they are, because they are
  what the test proves. Expected saving is about 6-10 s at load 20. The rest is inherent.
- **C5 (suite):**
  1. One shared Chromium per module for the throwaway-browser fixtures in
     `test_ws2_cscs.py` (`_page`, `_client`). Each test keeps a **fresh context** (its own
     storage, its own routes), so isolation is unchanged. This saves driver start plus
     launch for about 15 tests. Do not touch `tests/test_ws5_client_s2.py`: tp#1655 owns
     it. Other files are listed as follow-ups, not done here.
  2. Make durations visible: `addopts = "--durations=25"` in `[tool.pytest.ini_options]`.
  3. Document a two-tier run in `README.md`'s test section: the quick tier is
     `-m "not launches_chrome"` and runs in minutes; the full tier runs at low load under
     `nice -n 15`, with the expected wall time recorded from one low-load run. This changes
     no test and gates nothing.

## Boxes

- [ ] B1 `broker/recipes.py`: in `_cscs_form_or_portal`, the password-only shape has to be
  seen on two consecutive polls, and the handles come from the confirming poll. In
  `_cscs_reauth`, a visible `#username` returns the combined form instead of raising.
  New hermetic test in `tests/test_ws2_cscs.py`: a scripted fake page whose first poll
  shows only `#password` (a navigation mid-poll) and whose second shows both. It must give
  a combined `KeycloakForm` with no `LoginFailed`. A stable password-only page must still
  give a re-auth form. Run the cscs reauth tests (:656, :669) plus the 3 ticket tests.
- [ ] B2 `tests/test_ws2_cscs.py`: add `Portal.leave_without_token` and make `_APP_JS`'s
  `away()` conditional on it. The wrong-key test sets it to False and asserts the page is
  still on `/profile/` at the end.
- [ ] B3 `tests/test_login_timeout.py`: move the short budget into the stalled call for
  :206, :227 and :246 (`push(0.3, "background_page")`), with `BG_PAGE_STEP_S = 30`. Add the
  hermetic push/step order assertion.
- [ ] B4 `tests/test_login_timeout.py`: time `test_disarm_racing…` per iteration (one run).
  If `_fire` side effects dominate, stub them in that test. Keep 200 iterations and both
  assertions. If the time is sleep granularity instead, report back and change nothing.
- [ ] B5 `tests/test_ws2_npm.py`: replace the stale-build test's first login with a direct
  profile visit through `runner._launch`, and keep the asserts on logins 2 and 3.
- [ ] B6 `tests/test_ws2_cscs.py`: a module-scoped Playwright + Chromium fixture shared by
  `_page`/`_client`, with a fresh context per test. The browser closes at module teardown,
  so no Chrome is left behind (conftest `launches_chrome` contract).
- [ ] B7 `pyproject.toml` `--durations=25`, plus a `README.md` two-tier test section with
  the low-load wall time from one full run done by the overseer at load < 8 (the overseer
  makes that run, not an agent under load).

## Verification

```commands
cd /Users/albert/obsidian/42-Git/home/browser-login && ruff format --check /Users/albert/obsidian/42-Git/home/browser-login/broker/recipes.py /Users/albert/obsidian/42-Git/home/browser-login/tests/test_ws2_cscs.py /Users/albert/obsidian/42-Git/home/browser-login/tests/test_login_timeout.py /Users/albert/obsidian/42-Git/home/browser-login/tests/test_ws2_npm.py
cd /Users/albert/obsidian/42-Git/home/browser-login && ruff check /Users/albert/obsidian/42-Git/home/browser-login/broker/recipes.py /Users/albert/obsidian/42-Git/home/browser-login/tests/test_ws2_cscs.py /Users/albert/obsidian/42-Git/home/browser-login/tests/test_login_timeout.py /Users/albert/obsidian/42-Git/home/browser-login/tests/test_ws2_npm.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run --project /Users/albert/obsidian/42-Git/home/browser-login mypy /Users/albert/obsidian/42-Git/home/browser-login/broker/recipes.py /Users/albert/obsidian/42-Git/home/browser-login/tests/test_ws2_cscs.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run --project /Users/albert/obsidian/42-Git/home/browser-login pylint /Users/albert/obsidian/42-Git/home/browser-login/broker/recipes.py /Users/albert/obsidian/42-Git/home/browser-login/tests/test_ws2_cscs.py /Users/albert/obsidian/42-Git/home/browser-login/tests/test_login_timeout.py /Users/albert/obsidian/42-Git/home/browser-login/tests/test_ws2_npm.py
cd /Users/albert/obsidian/42-Git/home/browser-login && timeout 600 uv run --project /Users/albert/obsidian/42-Git/home/browser-login pytest -q -rs -p no:cacheprovider /Users/albert/obsidian/42-Git/home/browser-login/tests/test_ws2_cscs.py
cd /Users/albert/obsidian/42-Git/home/browser-login && timeout 600 uv run --project /Users/albert/obsidian/42-Git/home/browser-login pytest -q -rs -p no:cacheprovider /Users/albert/obsidian/42-Git/home/browser-login/tests/test_login_timeout.py
cd /Users/albert/obsidian/42-Git/home/browser-login && timeout 600 uv run --project /Users/albert/obsidian/42-Git/home/browser-login pytest -q -rs -p no:cacheprovider /Users/albert/obsidian/42-Git/home/browser-login/tests/test_ws2_npm.py
```

Each file must pass at the current load (~20) on two normal runs. That is the "under load"
claim, and it uses no load generator. The timing bounds that stay in the tests (< 2.0 s
from the stall) are measured from the stall, not from the setup. The full-suite wall time
(B7) is one overseer run at low load and is not part of this block.

## Not in scope

- `tests/test_ws5_client_s2.py` (tp#1655, its own plan).
- Shared-Chromium fixtures for the other Chromium-heavy files (`test_authentik.py`,
  `test_ws5_runai.py`, `test_ws5_keycloak_admin.py`, …): follow-up ticket once B6 shows
  the saving.
- Releasing the live `cscs` quarantine (`agent-login.py -Q cscs`): the main session's call.
