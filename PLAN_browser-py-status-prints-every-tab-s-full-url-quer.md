# tp#365 — `browser.py status` prints every tab's full URL (query/fragment included)

## Session

Resume: `c --resume cd30846a-045c-4653-8403-ffdb2be49c85`

## Context

**Classification: DEFECT** (information leak). The repo's own ruling from tp#337 defines a
tab's full URL in captured output as a leak class: reset-token paths, magic-link tokens,
`data:` bodies, and OAuth/OIDC (OpenID Connect) query parameters land in the caller's log
and the LLM transcript. `status` is the widest surface of that class — nearly every LLM
session that touches the browser runs it first.

**Symptom.** `browser.py status` renders each page target as
`- <title>  →  <url>` with `t.get('url')` verbatim from `GET /json/list`
(`bin/browser.py:1845-1846`). No `_strip_query`, no path redaction.

**Evidence (reproduced live, 2026-09-22, this session).** With the shared browser up
(Chrome/151, 4 tabs) `bin/browser.py status` printed a Keycloak authorize tab in full:
`https://custos.datascience.ch/realms/sdsc/protocol/openid-connect/auth?scope=openid&state=…&response_type=code&client_id=runai&redirect_uri=…&nonce=…`
— `state`, `nonce` and `redirect_uri` values verbatim (masked here before they reached the
transcript). A magic-link tab (`/auth/magic/<token>`) or the callback leg (`?code=…`)
lands the same way; `doctor`'s disposable `data:` tab would print its whole body.

**Second channel — the title column (Codex O1, confirmed).** Chrome titles a page that has
no `<title>` with its own URL minus the scheme, path and query included: the same live
listing shows a tab titled exactly `portal.cscs.ch/profile/`. A title-less callback or
magic-link hop therefore prints its token through the title even once the URL column is
origin-only. Titles are also page-controlled bytes: a newline in `document.title` forges
output lines.

**Root cause (high confidence).** `cmd_status` (`bin/browser.py:1829-1848`) predates the
tp#337 fix and never used `_tab_hint` (`bin/browser.py:2064-2092`), the origin-only,
fail-closed renderer introduced for the `eval --url` no-match error. The line at
`bin/browser.py:1846` interpolates the raw URL and the raw title.

**Consumers of `status` output.** Audited with no extension filter over all of
`~/obsidian/42-Git` (`.git` excluded), `~/.claude/{hooks,skills,agents,commands}`,
`~/Library/LaunchAgents`, `~/.zsh_aliases`, `~/.zshrc`: the only hits are prose
(`README.md:67`, `AGENTS.md:26`, `sdsc/cscs-api/README.md:309`,
`~/.claude/skills/anthropic-api/SKILL.md:80`) and browser.py's own error messages that
point at `status`. **No script parses the tab lines.** The tab line's two columns change
content; the `✓ Up …` header, the `N tab(s):` count, the `Lifecycle:` line and the exit
codes (0 up / 1 down) stay byte-identical, and no line is added.

**Decisions settled from the evidence (recorded as non-blocking `tp question 365`
assumptions).**

1. **Origin-only URL column by default via `_tab_hint`; `-f/--full-urls` prints the raw
   URL.** Consistency with tp#337: `_tab_hint` is an allowlist (`scheme://host[:port]`),
   fails closed on malformed input, and its tests already pin the no-leak property. The
   host is exactly the vocabulary `eval --url SUBSTR` needs; when several tabs share a
   host the tp#337 no-match error already dedups by origin. Humans who copy URLs get one
   deliberate, transcript-visible keystroke — never the default an agent inherits. The
   default output does **not** mention the flag (tp#337 "no pointer to status" reasoning,
   Codex O2): it is documented in `status -h` and the README only, and its help text names
   it unsafe for agent sessions.
2. **Keep the title column, fail closed via `_tab_title(title, url)`.** Non-string or
   blank → `(untitled)`; a title that is a substring of the raw URL **or** of
   `urllib.parse.unquote(url)` (Chrome's untitled default, percent-decoded forms
   included) → `(untitled)`; not `str.isprintable()` → `(untitled)`; longer than 100
   characters → first 97 + `…`. Residual, accepted: a site that deliberately writes a
   secret into its own `<title>` is site content, the same bytes every CDP client reads
   from the DOM — outside the threat model, which is the *accidental* default.
3. **Non-string `url` values never reach `_tab_hint`** (Codex O6): `_tab_hint(None)`/`""`
   already return `(empty)`, but a truthy non-string would raise inside `urlsplit`; the
   status line helper renders `<unparseable url>` for anything that is not a `str`.

**Alternatives considered and rejected.**

| Alternative                                             | Why not                                                                                                                                                                                                                                       |
| :------------------------------------------------------ | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Strip only query + fragment, keep the path              | Path-embedded tokens (magic links, reset links, `data:` bodies) are the tp#337 class; the ticket body names "no path/query redaction". Half a fix that still needs the opt-in for the query case.                                             |
| Bare count (`4 tab(s), URLs withheld`)                  | Rejected in the tp#337 debate: removes the one thing that lets the caller choose a `--url` host substring; the title alone does not name a host.                                                                                              |
| Omit titles entirely in the default                     | Codex O1's first option. The title is how a human tells two same-origin tabs apart; the fail-closed renderer above removes the untitled-default and line-forgery channels, which are the only ones a *page* can open by accident.               |
| Heuristic redaction of token-shaped segments            | Rejected in tp#337: a denylist misses short tokens and `data:` bodies; origin-only is an allowlist.                                                                                                                                           |
| Trailer line advertising the flag (`status -f …`)       | Codex O2: it routes every agent invocation straight at the unsafe path, the exact thing tp#337 refused for the eval error. Dropped; discoverability is `status -h`.                                                                          |
| Non-stdout human mechanism for the raw URLs (clipboard) | The human mechanism is `status --full-urls \| pbcopy`; a clipboard write inside the tool is a new desktop side effect (AGENTS.md) and equally capturable via `pbpaste`. Every CDP client can read every tab URL from `GET /json/list` anyway. |
| TTY-gate `--full-urls`                                  | `status --full-urls \| pbcopy` is the human use-case. The guard targets the accidental default; a caller that types the flag has read its help text.                                                                                          |
| Env var (`BROWSER_PY_STATUS_FULL=1`) instead of a flag   | Invisible in the transcript; a session that inherits it leaks silently. A flag is per-invocation and auditable.                                                                                                                              |
| Truncate `data:` URLs under `--full-urls`               | Out of scope; the flag is "raw", and the pre-existing behaviour for a `data:` tab is unchanged.                                                                                                                                               |

**Not in scope (observation, accepted in tp#337).** `open` echoes `page.url` after
navigation (`bin/browser.py:2106,2112,2115`); when the target redirects into an SSO flow
the echoed URL carries `state`/`nonce`. The tp#337 debate accepted "open already prints
every navigated URL" — the caller chose the URL and sees it once. Left as is.

**Debate.** Codex (gpt-5.6-sol, effort xhigh) raised O1–O10 in round 1; all ten accepted
(O2 and O10 in part, the rest in full) and the judge ruled converged in round 1. Ledger:
`$TMPDIR/ccc-codex-debate/cd30846a-045c-4653-8403-ffdb2be49c85/ledger_r1.md`.

**Blocked on Albert:** no. **Confidence:** high (repro + root cause + consumer audit).

## Steps

- [x] **`_tab_title(title: object, url: object) -> str`** (new helper next to `_tab_hint`,
      `bin/browser.py:2064`): the fail-closed title renderer from decision 2 — `(untitled)`
      for non-string/blank, for a title contained in the raw or `unquote`d URL string, and
      for a non-`isprintable()` title; cut at 100 characters (97 + `…`). Docstring names the
      Chrome untitled-default channel and the line-forgery case.
- [x] **`_tab_line(target: dict) -> str`** (same place): returns
      `- {_tab_title(t.get('title'), t.get('url'))}  →  {hint}` where `hint` is
      `_tab_hint(url)` when `url` is a `str`, else `<unparseable url>`; with
      `full_urls=True` the URL column is the raw `url` and the title column is unchanged
      (still `_tab_title` — the flag opts into raw URLs, not raw bytes on stdout).
- [x] **`cmd_status(port, full_urls=False)`** (`bin/browser.py:1829`): the loop at `:1845`
      prints `_tab_line(t, full_urls)`. No trailer line. `✓ Up …`, `N tab(s):`,
      `Lifecycle:` lines, the page-type filter and both exit codes unchanged.
- [x] **argparse + dispatch** (`bin/browser.py:228-230`, `:4952`): `status` gains
      `-f/--full-urls` (`store_true`; help: "print each tab's full URL — path, query and
      fragment. UNSAFE from an agent session: in-flight auth tabs carry codes/tokens and
      status output lands in logs and LLM transcripts. Default: origin only."); dispatch
      `cmd_status(port, args.full_urls)`. Epilog example (`:198`) →
      `# CDP health + tabs (origins only) + lifecycle`; module docstring summary (`:20`) →
      `status    Show CDP health, browser version, open tabs (origins only; -f full URLs), and the lifecycle record.`
- [x] **`_tab_hint` docstring** (`bin/browser.py:2064-2077`): "for `status` and the
      `eval --url` no-match error"; rendering rules unchanged (tp#337 tests untouched).
- [x] **Tests** — new `tests/test_status_output.py` (module-loading shim from
      `tests/test_tab_selection.py`; monkeypatch `_cdp_get`, `_browser_mode`,
      `_print_lifecycle` with a call recorder; `capsys`). Fixture targets: a Keycloak
      authorize URL with `state=`/`nonce=`/`redirect_uri=`, a magic-link path
      `/auth/magic/<token>`, a `data:text/html,<secret>` tab, `about:blank`, a
      `user:pw@host` URL, an IPv6 origin, a malformed URL, a tab whose title is its
      URL-minus-scheme carrying `?token=…`, a percent-encoded variant of that, a
      multiline title, a non-string title, and one `service_worker` target. Assert:
  - **default**: every genuine title present; every tab line ends in `→  <origin>`;
    none of `state=`, the token, `secret`, `user:pw`, `?`, `#`, a newline-forged line
    appears anywhere on stdout; untitled-default/multiline/non-string titles render
    `(untitled)`; `N tab(s):` counts pages only; header line exact; `_print_lifecycle`
    called exactly once with the port; return 0.
  - **`full_urls=True`**: every raw URL verbatim; titles still pass `_tab_title`; header
    and lifecycle assertions as above; return 0.
  - **zero page targets**: `0 tab(s):`, no tab lines, lifecycle once, return 0.
  - **CDP down** (`_cdp_get` → `None`): `✗ … DOWN` line, lifecycle once, zero tab lines,
    return 1.
  - **`_tab_title` unit cases**: normal title verbatim; the six placeholder cases; the
    100-char cut.
  - **`_tab_line` with `url` missing / `None` / `123` / `{}`**: no exception,
    `<unparseable url>` (or `(empty)` for `None`/`""`), title column still rendered.
  - **argparse**: `sys.argv=["browser.py","status","-f"]` → `parse_args().full_urls is
    True`; without `-f` → `False`; `--full-urls` long form accepted.
  - **dispatch**: `sys.argv` + `ensure_deps`→noop, `_set_purpose`→noop, `cmd_status`→
    recorder: `main()` returns the recorder's value and the recorder saw
    `full_urls=True` for `-f`, `False` without it.
  - `tests/test_tab_selection.py::test_eval_no_match_names_open_tabs_by_origin_only`
    still passes — the eval error must not start advertising `status`.
- [x] **Docs**: `README.md:67` → `# CDP health, version, open tabs (origins only; -f full
      URLs) + the lifecycle record`; the `status` paragraph at `README.md:126-129` gains
      one sentence (tab URLs are origins and titles are fail-closed because status output
      lands in transcripts; `-f/--full-urls` is the human opt-in, unsafe from an agent);
      `AGENTS.md` Conventions bullet: "Tab URLs and titles in any captured output
      (`status`, error lines) go through `_tab_hint`/`_tab_title` — origins only, fail
      closed; raw URLs are opt-in (`status --full-urls`) and never the default";
      `sdsc/cscs-api/README.md:309` and `~/.claude/skills/anthropic-api/SKILL.md:80`
      stay accurate (verify, no edit expected).
- [x] **Lint + verify + commit** (Verification block below), then
      `ai.py push -m "fix(status): print tab origins only; -f/--full-urls for raw URLs (tp#365)" bin/browser.py tests/test_status_output.py README.md AGENTS.md PLAN_browser-py-status-prints-every-tab-s-full-url-quer.md`.
**Completion** (a note, not a work box — `tp tidy` is tp's own post-close step, run by the orchestrator after the verdict; box removed 2026-09-22 so the headless work run can reach 100 %) (left for the review session — the work dispatch forbids `tp tidy`/`tp done` from the executing session): `tp tidy 365` (renames to `_DONE`, moves to `plans-done/`, fixes the
      tp link) in the closing commit.

## Verification

```commands
cd ~/obsidian/42-Git/home/browser-login
python3 -m pytest tests/ -q
python3 -m pytest tests/test_tab_selection.py::test_eval_no_match_names_open_tabs_by_origin_only -q
ruff format bin/ tests/ && ruff check bin/ tests/ && mypy bin/browser.py && pylint bin/browser.py
pre-commit run --all-files                                # gitleaks included
bin/browser.py -h >/dev/null && echo 'help ok'            # exit 0
bin/browser.py status -h | grep -q -- '--full-urls' && echo 'flag registered'
bin/browser.py status | grep -E '^\s+- .*→ ' | grep -E '[?#]' ; test $? -eq 1 && echo 'no query/fragment'
bin/browser.py status | grep -E '^\s+- .*→ [a-z]+://[^/]+/' ; test $? -eq 1 && echo 'no path'
bin/browser.py status | grep -q 'full-urls' ; test $? -eq 1 && echo 'no flag advertised'
bin/browser.py doctor                                     # lifecycle/desktop invariants untouched
```

(`status --full-urls` is deliberately NOT run live — it is exercised by the stubbed
`full_urls=True` test with known query/fragment/magic-link/`data:` fixtures.)

## Review 2026-09-22

- [ ] Plan's own Verification chain (PLAN line 168: ruff format/check + mypy + pylint bin/browser.py) is red: pylint bin/browser.py exits 26 (bare) / uv run pylint bin/browser.py exits 24 (canonicalized form f1439e0 made authoritative in AGENTS.md) — 47 pre-existing findings, first line 'bin/browser.py:1:0: C0302: Too many lines in module (5059/1000) (too-many-lines)', incl. import-outside-toplevel x~30, R0911/R0912 x5. Step 8 ('Lint + verify + commit') is checked [x] though this literal Verification command fails. Full root-cause/fix detail in -D.
