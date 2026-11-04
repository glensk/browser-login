# PLAN: browser-login suite load fragility (tp#1672)

> **Resume here.** Status: root-caused, planned, debated (Opus adversary, 2026-11-03) and
> reconciled. Nothing is built yet. Next round: R1 (B1, B2, B6).
> B1 changes `broker/recipes.py`, which is broker code. The launchd broker runs from the
> installed copy (`${LIBEXEC}/current/broker/daemon.py`, `install/install.sh:448`), not from
> this checkout. That means the file is not live here, and the fix only reaches production
> through B6, which reinstalls with `sudo -n` (root is available, no ask) and keeps a
> rollback target. All other boxes are test-only. Work in a worktree anyway
> (`.worktrees.noindex/<name>`), because other agents build and run browser-login tests in
> this repo concurrently. Only one writer may work in the repo at a time. tp#1659 is
> changing `bin/browser.py` concurrently: cite browser.py by symbol and step label, never by
> line number, and start R2 (which depends on browser.py internals) only after tp#1659 has
> landed.

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

- **C1 (code):** classify the Keycloak page from **one stable observation**.
  1. Swap the query order: `#password` first, then `#username`, so a navigation that
     commits between the two queries reads the username from the settled Keycloak document
     (this removes the race direction that caused C1 without adding latency).
  2. Because `_visible` also returns None when the username query *raises* (execution
     context destroyed), the order swap alone is not enough. A password-only shape
     (`user is None`, `password` visible) must still be seen on **two polls in a row**,
     through a `pw_only` flag next to the existing `user_only` flag (:2741-2751). The
     handles come from the confirming poll. A real re-auth page is stable and still
     classifies as re-auth after one more `CSCS_POLL_MS`.
  3. Loop edge: a password-only shape first seen on the final tick (`tick >= ticks`) gets
     the same post-loop "one more look" that `user_only` has today (:2759-2763), so a
     late-rendering re-auth page still becomes a re-auth form, not "Keycloak login form not
     found".
  4. Safety net in `_cscs_reauth`: before raising "without naming…", **re-query both**
     `#username` and `#password`. Only when both are visible does it return
     `KeycloakForm(user, password)` with those fresh handles (never the stale `password`
     handle from the earlier poll). Otherwise it falls through to the existing
     restart/raise logic.
  What stays true: a password is never typed for an account the page names differently,
  and the reauth tests (:656, :669) are unchanged.
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
  - Add one hermetic test, by spying `_deadline_push` and `_deadline_step`. `_deadline_push`
    returns a `@contextmanager` (`LoginDeadline.push`), so the spy must **wrap the returned
    context manager** and record its enter and exit in the same event list as the
    `_deadline_step` labels. Assert the order
    `push(BG_PAGE_STEP_S, "background_page") enter < bg:create < bg:close < exit`. A spy
    on the call alone would not prove that the budget still covers close.
- **C3 side (test):** measure `test_disarm_racing…`. If `_fire`'s side effects dominate, stub
  `_close_owned_targets` / `_access_team_sweep_cdp` / `_result_write` in that test only. It
  pins the lock protocol, not cleanup. Keep 200 iterations, `not late` and `fired > 0`.
- **C4 (test):** replace login 1, whose only job is "the broker profile caches build a",
  with a direct visit through `rig.brk.runner._launch(pw, profile_dir("npmfix"))` plus
  `goto(origin)` and `ctx.close()`. This is the pattern `test_a_stale_expiry_is_refreshed`
  already uses (`test_ws2_cscs.py:600-613`). Chromium writes its disk cache
  asynchronously, so before `ctx.close()` the direct visit waits for `load` and checks
  in-page that `main-a.js` loaded (the same signal the broker visit relied on); otherwise the
  cache may be empty and the "broken" login would wrongly succeed. It saves one proof
  window and one limiter round. The broken login and the reuse login stay as they are,
  because they are what the test proves. Expected saving is about 6-10 s at load 20. The
  rest is inherent.
- **C5 (suite):**
  1. ~~One shared Chromium per module in `test_ws2_cscs.py`~~ **dropped after the
     debate**: the module mixes `_page`/`_client` tests with in-process broker tests that
     open their own `sync_playwright()` (`broker/daemon.py:1426`, :1511;
     `test_ws2_cscs.py:605`), and a nested `sync_playwright()` raises inside the outer
     one's event loop (`broker/daemon.py:1388-1389`). The saving (about 15 × 5-8 s out of
     more than 3600 s) does not justify splitting the module now. It becomes a follow-up
     together with the other Chromium-heavy files (see Not in scope).
  2. Make durations visible: `addopts = "--durations=25"` in `[tool.pytest.ini_options]`.
  3. Document a two-tier run in `README.md`'s test section: the quick tier is
     `-m "not launches_chrome"` and runs in minutes; the full tier runs at low load under
     `nice -n 15`, with the expected wall time recorded from one low-load run. This changes
     no test and gates nothing.
- **C6 (test, folded in from tp#1659):**
  `tests/test_connect_hang.py::test_real_connect_times_out_and_names_the_hung_tab_origin_only`
  asserts `took < 2 + PROBE_BUDGET_S + 12` (:127), where `took` is the wall time of the
  whole `subprocess.run` (`_run_cli`, :98-107). That includes interpreter start-up and the
  `bin/browser.py` import. Under load ~20 the test took 21-22 s with old and new browser.py
  alike, so this is start-up cost, not a regression. Fix (test-only, no browser.py change,
  so no conflict with tp#1659): in the same test, first time a start-up baseline with the
  same interpreter and env, a `browser.py` invocation that exits before any CDP work (for
  example `eval -t 0 1`, the early-reject path that
  `test_eval_rejects_a_non_positive_timeout` already uses). Then assert
  `took - startup < 2 + PROBE_BUDGET_S + 4`. The bound on the attach-plus-probe work gets
  tighter than today's 12 s slack, while start-up noise drops out. Apply the same baseline
  to `test_eval_watchdog_exits_at_its_deadline_while_the_attach_is_stuck` (:153,
  `took < 2 + 10`), which has the same exposure.

## Boxes

Build rounds (at most 3 boxes per round, one writer agent per round, rounds in order):

- **R1** = B1, B2, B6: the cscs fixes plus landing B1 in production. B1 and B2 both edit
  `tests/test_ws2_cscs.py`, so one agent builds them in that order. B6 runs after B1 is
  merged to `origin/main`, because `install.sh` installs `git archive HEAD` and refuses a
  HEAD that is not in `origin/main`.
- **R2** = B3, B4, B8: the timing and budget work. It starts only after tp#1659 has landed
  its `bin/browser.py` changes. The builder first rebases, then re-checks the `bg:*` step
  labels and the `_background_page_run` / `_deadline_push` symbols.
- **R3** = B5, B7: the npm stale-build test, durations and the README tiers. The B7
  low-load full run is the overseer's, after R1 and R2 have landed.

- [x] B1 `broker/recipes.py`: in `_cscs_form_or_portal`, query `#password` before
  `#username`. Add a `pw_only` flag next to `user_only`: a password-only shape must be
  seen on two consecutive polls, and the handles come from the confirming poll. The
  post-loop "one more look" also covers `pw_only` (first seen on the last tick). In
  `_cscs_reauth`, before raising "without naming…", re-query both `#username` and
  `#password`, and return `KeycloakForm(user, password)` with those fresh handles only when
  both are visible. New hermetic tests in `tests/test_ws2_cscs.py`, each on a scripted fake
  page (no Chromium):
  `test_a_navigation_between_keycloak_polls_is_not_reauth` (first poll password-only or
  username query raising, second poll both → combined form, no `LoginFailed`);
  `test_a_stable_password_only_page_is_reauth`; and
  `test_a_password_only_page_first_seen_on_the_last_tick_is_reauth`. Also run the cscs
  reauth tests (:656, :669) and the 3 ticket tests by name.
- [x] B2 `tests/test_ws2_cscs.py`: add `Portal.leave_without_token` and make `_APP_JS`'s
  `away()` conditional on it. The wrong-key test sets it to False and asserts that the page
  is still on `PORTAL + "/profile/"` at the end. That assertion is what tells the new test
  apart from the old one, which passes on a lucky run.
- [x] B6 Landing of B1 in production, after B1 and B2 are merged to `origin/main`. (1)
  Record the current release: `readlink /usr/local/libexec/login-broker/current`, in the
  report. (2) `sudo -n install/install.sh -n` (dry run), then
  `sudo -n install/install.sh` from a clean checkout at `origin/main`. It installs a new
  release, swaps `current` atomically, restarts the daemon and runs the boundary selfcheck,
  which rolls back on failure. (3) Confirm that the new release dir holds the B1
  `_cscs_form_or_portal`, that the daemon restarted (`sudo -n launchctl print
  system/com.albert.login-broker` shows a fresh pid), and the install line in
  `/var/log/login-broker.log`. (4) A live `browser.py login cscs` canary runs only after the
  main session has released the `cscs` quarantine (`agent-login.py -Q cscs`). Otherwise
  the box reports "canary pending: quarantine" and the main session runs the canary.
  Rollback: re-point `current` to the recorded release with `sudo -n ln -sfn <old>
  /usr/local/libexec/login-broker/current.tmp` plus `mv -h` over `current`, then
  `sudo -n launchctl kickstart -k system/com.albert.login-broker`.
- [x] B3 `tests/test_login_timeout.py`: move the short budget into the stalled call for
  the three tests `test_stuck_evaluate_fires_closes_the_owned_tab_and_exits_124`,
  `test_stalled_raw_create_fires_on_bg_create_and_leaks_no_target` and
  `test_failed_close_still_listed_is_125_unconfirmed`
  (`browser._active_deadline().push(0.3, "background_page")` around the wait), with
  `BG_PAGE_STEP_S = 30`. Add `test_bg_step_budget_covers_create_and_close`: the spy wraps
  the context manager that `_deadline_push` returns and asserts
  `push enter < bg:create < bg:close < push exit`.
- [ ] B4 `tests/test_login_timeout.py`: time `test_disarm_racing…` per iteration (one run).
  If `_fire` side effects dominate, stub them in that test. Keep 200 iterations and both
  assertions. If the time is sleep granularity instead, report back and change nothing.
- [x] B8 `tests/test_connect_hang.py` (C6, test-only): in
  `test_real_connect_times_out_and_names_the_hung_tab_origin_only` and
  `test_eval_watchdog_exits_at_its_deadline_while_the_attach_is_stuck`, time a start-up
  baseline first (same interpreter and env, `browser.py eval -t 0 1`, which exits before
  any CDP work). Assert `took - startup < 2 + PROBE_BUDGET_S + 4` and
  `took - startup < 2 + 4`. Every other assertion stays. No `bin/browser.py` change.
- [ ] B5 `tests/test_ws2_npm.py`: replace the stale-build test's first login with a direct
  profile visit through `runner._launch`. Before `ctx.close()`, wait for `load` and check
  in-page that `main-a.js` loaded. Keep the asserts on logins 2 and 3. If the "broken"
  login then stops failing (the cache was not populated), revert B5 and record the test as
  an inherently slow full-tier member.
- [ ] B7 `pyproject.toml` `--durations=25`, plus a `README.md` two-tier test section with
  the low-load wall time from one full run done by the overseer at load < 8 (the overseer
  makes that run, not an agent under load).
- [ ] B9 `tests/test_ws2_cscs.py` `test_the_deadline_itself_decides_not_only_the_watchdog`
  (~1656, found in R2, overseer 2026-11-04): it gives the gate 3 s including a real
  `sync_playwright()` start (only `_launch` stubbed), so it fails under load. Stub
  `sync_playwright` in that test, or start the deadline clock after Playwright is up;
  never just raise the 3 s. Keep what the test asserts about the deadline vs the watchdog.
  Verify with two normal `-k` runs.

## Verification

```commands
cd /Users/albert/obsidian/42-Git/home/browser-login && ruff format --check /Users/albert/obsidian/42-Git/home/browser-login/broker/recipes.py /Users/albert/obsidian/42-Git/home/browser-login/tests/test_ws2_cscs.py /Users/albert/obsidian/42-Git/home/browser-login/tests/test_login_timeout.py /Users/albert/obsidian/42-Git/home/browser-login/tests/test_ws2_npm.py /Users/albert/obsidian/42-Git/home/browser-login/tests/test_connect_hang.py
cd /Users/albert/obsidian/42-Git/home/browser-login && ruff check /Users/albert/obsidian/42-Git/home/browser-login/broker/recipes.py /Users/albert/obsidian/42-Git/home/browser-login/tests/test_ws2_cscs.py /Users/albert/obsidian/42-Git/home/browser-login/tests/test_login_timeout.py /Users/albert/obsidian/42-Git/home/browser-login/tests/test_ws2_npm.py /Users/albert/obsidian/42-Git/home/browser-login/tests/test_connect_hang.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run --project /Users/albert/obsidian/42-Git/home/browser-login mypy /Users/albert/obsidian/42-Git/home/browser-login/broker/recipes.py /Users/albert/obsidian/42-Git/home/browser-login/tests/test_ws2_cscs.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run --project /Users/albert/obsidian/42-Git/home/browser-login pylint /Users/albert/obsidian/42-Git/home/browser-login/broker/recipes.py /Users/albert/obsidian/42-Git/home/browser-login/tests/test_ws2_cscs.py /Users/albert/obsidian/42-Git/home/browser-login/tests/test_login_timeout.py /Users/albert/obsidian/42-Git/home/browser-login/tests/test_ws2_npm.py /Users/albert/obsidian/42-Git/home/browser-login/tests/test_connect_hang.py
cd /Users/albert/obsidian/42-Git/home/browser-login && grep -n leave_without_token /Users/albert/obsidian/42-Git/home/browser-login/tests/test_ws2_cscs.py
cd /Users/albert/obsidian/42-Git/home/browser-login && grep -n pw_only /Users/albert/obsidian/42-Git/home/browser-login/broker/recipes.py
cd /Users/albert/obsidian/42-Git/home/browser-login && grep -n durations=25 /Users/albert/obsidian/42-Git/home/browser-login/pyproject.toml
cd /Users/albert/obsidian/42-Git/home/browser-login && timeout 900 uv run --project /Users/albert/obsidian/42-Git/home/browser-login pytest -q -rs -p no:cacheprovider /Users/albert/obsidian/42-Git/home/browser-login/tests/test_ws2_cscs.py -k "keycloak_polls or password_only or another_key or fresh_login_exports or stale_expiry_is_refreshed or silent_sso_with_a_failed_export or reauth"
cd /Users/albert/obsidian/42-Git/home/browser-login && timeout 900 uv run --project /Users/albert/obsidian/42-Git/home/browser-login pytest -q -rs -p no:cacheprovider /Users/albert/obsidian/42-Git/home/browser-login/tests/test_login_timeout.py
cd /Users/albert/obsidian/42-Git/home/browser-login && timeout 900 uv run --project /Users/albert/obsidian/42-Git/home/browser-login pytest -q -rs -p no:cacheprovider /Users/albert/obsidian/42-Git/home/browser-login/tests/test_connect_hang.py -k "real_connect_times_out or eval_watchdog_exits"
cd /Users/albert/obsidian/42-Git/home/browser-login && timeout 900 uv run --project /Users/albert/obsidian/42-Git/home/browser-login pytest -q -rs -p no:cacheprovider /Users/albert/obsidian/42-Git/home/browser-login/tests/test_ws2_npm.py -k stale_cached_build
```

Why this block is not strict-eligible: every claim of this plan is about test behaviour
(races, budgets, timing), so it can only be shown by running pytest, mypy and pylint in the
project venv. A no-tools reviewer cannot discharge it. The permissioned reviewer session
runs it. The targeted runs must pass at the current load (~20) on two normal runs. That is the
"under load" claim, and it uses no load generator. The tests that tell old code from new
are named in the `-k` filters: the new hermetic C1 tests (they fail with exit 5, "no tests
collected", before B1, and on the old `_cscs_form_or_portal` the navigation case raises
`LoginFailed`), the wrong-key test with its `page.url` assertion (B2),
`test_bg_step_budget_covers_create_and_close` (B3), and the start-up baseline (B8). The
`grep` lines fail (exit 1) until B1, B2 and B7 have landed. Whole-file runs of
`test_ws2_cscs.py` and `test_ws2_npm.py` (about 600-1500 s at load 20) belong to B7's
low-load overseer run, not to this block. The timing bounds that stay in the tests (< 2.0 s
from the stall, the attach-plus-probe bound after start-up) are measured from the work they
bound, not from process or setup start. B6's live checks are in its box; they need root and
are not part of this read-only block.

## Not in scope

- `tests/test_ws5_client_s2.py` (tp#1655, its own plan).
- Shared-Chromium fixtures (dropped from this plan, see C5.1): for `test_ws2_cscs.py`
  this would mean splitting the `_page`/`_client` tests into their own module first; also
  for the other Chromium-heavy files (`test_authentik.py`, `test_ws5_runai.py`,
  `test_ws5_keycloak_admin.py`, …). This becomes a follow-up ticket once B7's durations show
  where the time goes.
- Releasing the live `cscs` quarantine (`agent-login.py -Q cscs`): the main session's call.

## Debate outcome (Opus adversary)

Critic: fresh Opus subagent, 2026-11-03, 1 round. Codex round 0 was refused three times
with `debate_seat_unknown` (no fresh five-hour reading for any seat), so the
`opus-plan-critique` stand-in ran. Verdict: sound-with-fixes.

1. [blocker] B6's module-scoped Chromium would coexist with the in-process broker tests'
   own `sync_playwright()`, and a nested one raises (`broker/daemon.py:1388-1389`).
   Accepted: the shared Chromium is dropped (C5.1, Not in scope). The B6 id now holds the
   production landing box.
2. [major] No box for the folded-in `test_connect_hang.py` 20 s limit. Accepted: new
   cause C6 and box B8 (start-up baseline subtracted, tighter attach-plus-probe bound, the
   same fix for the eval-watchdog test). It is in R2 with the other timing work.
3. [major] No landing/reinstall box for B1 and no rollback. Accepted: B6 records the old
   release, runs a dry run, then the real `sudo -n install/install.sh` from `origin/main`,
   checks the restart and the log, runs the canary after the quarantine is released, and
   names the rollback.
4. [major] Whole-file Verification runs cannot tell old code from new. Accepted:
   targeted `-k` runs on the discriminating tests, plus `grep` checks for the new symbols.
5. [major] `timeout 600` is below the measured whole-file cost at load 20. Accepted: the
   Chromium files run only the targeted tests (timeout 900); whole files go to B7's
   low-load run.
6. [minor] The two-poll rule misses the last-tick edge and the order-swap option.
   Accepted: B1 swaps the query order, adds `pw_only` with the post-loop confirm, and adds a
   last-tick hermetic test. The two-poll confirm stays, because a raising username query
   still returns None after the swap.
7. [minor] The `_cscs_reauth` safety net could fill a stale password handle. Accepted:
   it re-queries both fields and uses only the fresh handles.
8. [minor] The order spy must wrap the context manager to prove the pop comes after
   `bg:close`. Accepted: B3 spells this out.
9. [minor] browser.py line anchors are stale because of tp#1659 (35a7a79). Accepted:
   cite by symbol and label, and R2 starts after tp#1659 lands, with a rebase and a label
   re-check. The C3 line numbers in Causes are historical (pre-35a7a79).
10. [minor] B5's immediate `ctx.close()` may leave the disk cache empty. Accepted: wait
    for `load` plus an in-page `main-a.js` check before closing, and if it still flakes,
    revert and keep the test as slow full-tier.
11. [minor] No round grouping, and the landing order was unclear. Accepted: R1/R2/R3 are
    defined at the top of Boxes.

No rejections, so no round 2. Still unverified (the builder checks these): the C1 root
cause rests on one failing run's page hint (B1's hermetic tests pin the mechanism, not the
live occurrence); the B4 hypothesis is unmeasured (B4 measures it first).
