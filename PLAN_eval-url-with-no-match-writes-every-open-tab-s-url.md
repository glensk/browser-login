# eval --url no-match error leaks every open tab's URL path (tp#337)

## Session

Resume: `c --resume fec06787-4102-4af3-955e-6c959811b419`

## Context

**Classification: DEFECT** — a diagnostic message prints material it was meant to withhold.

**Symptom.** `browser.py eval --url SUBSTR '<js>'` with no matching tab exits 1 (correct
since tp#317) and appends `Open tabs: <url>, <url>, …` to the stderr line. Each entry keeps
the full URL *path*, so a password-reset tab, a magic-link tab or a `data:` page puts its
secret into the caller's log and, for LLM consumers, into the session transcript.

**Evidence (reproduced 2026-09-22, stub tabs only — the live shared browser was not
touched).** With `_connect` monkeypatched to return a fake browser holding three tabs:

```commands
❌ No tab matching 'epflch.sharepoint.com' — nothing evaluated. Open one first: browser.py open <url>. Open tabs: https://example.test/reset/SECRET-IN-PATH, data:text/html,<b>secret-body</b>, https://app.slack.com/client/T1/C1
exit 1
```

`SECRET-IN-PATH` (path) and the whole `data:` body survive; only `?code=HIDDEN` and the
`#frag` were removed. The same holds for `user:pw@host` userinfo and `blob:` / `file:` /
`javascript:` URLs, none of which have a `?` to cut at.

**Root cause (confidence: high).** `cmd_eval` (`bin/browser.py:2096-2105`) renders the
hint with `_strip_query` (`bin/browser.py:2058-2060`), a helper written for `open -r`'s
tab-REUSE matching: it cuts at the first `#` and `?` and strips a trailing `/`, nothing
else. The path, the userinfo and every non-hierarchical URL pass through verbatim. The
comment above the call (`bin/browser.py:2099-2100`) shows the only case considered was an
OAuth callback's *query* — the reviewer of tp#317 caught the gap and filed this ticket.

**Blocked on Albert: no.** No external, irreversible or paid decision; the three design
choices below are recorded as non-blocking assumptions (`tp question 337 …`).

### Design (settled)

- **Origin-only hint.** A new `_tab_hint(url)` renders each tab as
  `scheme://hostname[:port]` (lower-cased host via `urlsplit().hostname`, userinfo
  dropped, IPv6 re-bracketed) when the URL has a netloc — `https://`, `http://`,
  `chrome://newtab`; a URL without one (`data:`, `blob:`, `file:`, `javascript:`,
  `about:`) collapses to `<scheme>:…`, except the literal `about:blank`, which is printed
  as-is because it is the "you have only a blank tab — use `open`" signal. A host name is
  enough to choose a `--url` substring and carries no per-session secret.
- **Keep the list, deduplicated.** Same-origin tabs collapse to one entry with a `×N`
  suffix (three Slack tabs → `https://app.slack.com ×3`); the existing cap of 8 entries
  plus `… (+N more)` stays. Dropping the list altogether was rejected: it is the one thing
  that lets an unattended consumer fix its `--url` on the next call without a second
  round-trip. Token-shaped-segment heuristics (entropy, regex) were rejected: a denylist
  misses short magic-link tokens and `data:` bodies; origin-only is an allowlist.
- **Matching is unchanged.** `_pick_page` still tests `url_substr in pg.url` against the
  full URL, so `--url /sites/foo` keeps working; only what is *printed* shrinks. The
  message gains `(full URLs: browser.py status)` so a human at a terminal knows where the
  complete list is. `_strip_query` stays as it is — it is correct for `open -r`.
- **Out of scope: `status`.** `cmd_status` (`bin/browser.py:1844-1846`) prints every tab's
  full URL including the query — a wider surface of the same class, but it is the canonical
  "show me the tabs" command and humans copy URLs from it, so hiding anything there is a
  contract decision of its own: filed as **tp#365** (follow-up of this item). Once
  `_tab_hint` exists, that ticket can reuse it.

## Steps

- [ ] Add `_tab_hint(url: str) -> str` next to `_strip_query` (`bin/browser.py:~2058`)
      implementing the origin-only rules above (`urllib.parse.urlsplit`; the module already
      imports `urllib.error`/`urllib.request`). Docstring names tp#337 and says why the path
      is withheld.
- [ ] Rewrite the no-match branch of `cmd_eval` (`bin/browser.py:2096-2105`): hints from
      `_tab_hint`, order-preserving dedup with `×N` counts, cap 8 + `… (+N more)`, keep the
      `No tab matching … — nothing evaluated. Open one first: browser.py open <url>` wording,
      append `(full URLs: browser.py status)`; replace the "Listed without query/fragment"
      comment with one that states the origin-only rule.
- [ ] Tests in `tests/test_tab_selection.py` (module docstring: add the third pinned failure
      mode): a `_tab_hint` table — path+query+fragment, `user:pw@host:8443`, `http://[::1]:8080/p`,
      `data:`, `blob:`, `file:`, `javascript:`, `about:blank`, `chrome://newtab/`; an
      end-to-end `cmd_eval` no-match test with `_connect` monkeypatched to the stub browser
      (the reproduction above) asserting via `capsys` that `SECRET-IN-PATH`, `HIDDEN` and
      `secret-body` are absent from stderr while `https://example.test` and
      `https://app.slack.com` are present and the exit code is 1; a dedup/cap test (three
      Slack tabs → `×3`; ten distinct origins → 8 listed + `(+2 more)`).
- [ ] `README.md:75-76`: one clause — the error names the open tabs by origin only (no
      path/query); `browser.py status` shows the full URLs.
- [ ] Lint + tests green (`ruff format bin/ tests/ && ruff check bin/ tests/ && mypy bin/browser.py && pylint bin/browser.py`, `python3 -m pytest tests/ -q`), `browser.py eval -h` exits 0; commit with `ai.py push -m "fix(eval): name open tabs by origin only in the --url no-match error (tp#337)" bin/browser.py tests/test_tab_selection.py README.md PLAN_eval-url-with-no-match-writes-every-open-tab-s-url.md`.

## Verification

```commands
cd ~/obsidian/42-Git/home/browser-login
# 1. The reproduction from Context now prints origins only (stub browser, live browser untouched)
uv run --quiet python - <<'EOF'
import sys; sys.path.insert(0, "tests")
import test_tab_selection as t
class _PW:
    def stop(self): pass
class _Br(t._Browser):
    def close(self): pass
br = _Br(["https://user:pw@example.test/reset/SECRET-IN-PATH?code=HIDDEN",
          "data:text/html,<b>secret-body</b>#frag",
          "https://app.slack.com/client/T1/C1", "https://app.slack.com/client/T1/C2"])
t.browser._connect = lambda port: (_PW(), br)
sys.exit(t.browser.cmd_eval(9222, "1", "epflch.sharepoint.com"))
EOF
# expected on stderr: … Open tabs: https://example.test, data:…, https://app.slack.com ×2 (full URLs: browser.py status)   exit 1
# and none of SECRET-IN-PATH / HIDDEN / secret-body / user:pw
# 2. Regression tests + lint
python3 -m pytest tests/test_tab_selection.py -q
ruff format --check bin/ tests/ && ruff check bin/ tests/ && mypy bin/browser.py && pylint bin/browser.py
bin/browser.py eval -h >/dev/null && echo help-ok
# 3. Matching itself is untouched: a path substring still selects the tab (stub)
uv run --quiet python -c 'import sys; sys.path.insert(0,"tests"); import test_tab_selection as t; _c,p=t.browser._pick_page(t._Browser(["https://x.test/sites/foo/a"]),"/sites/foo",require_match=True); assert p and p.url.endswith("/a"); print("match-ok")'
```
