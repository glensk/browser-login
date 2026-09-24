# Claude magic-link login: sender allow-list, stale-mail exclusion, link↔email binding (tp#490)

## Session

Resume: `c --resume f9bfba63-863d-4040-b5cd-a51b9e9e75dd`

## Context

**Classification: DEFECT** (security — login Cross-Site Request Forgery (CSRF): the shared browser can be signed into an account that is not `ANTHROPIC_LOGIN_EMAIL`).

**Symptom.** `browser.py login anthropic` (full-auto path, `_claude_auto_login`) opens the first magic link it finds in a mail that merely *looks* like a Claude login mail. Two independent holes:

1. **Any sender.** `bin/browser.py:3780` — `_is_claude_login_mail` returns `True` as soon as the subject contains one of `_CLAUDE_SUBJECT_HINTS` ("secure link to Claude.ai", "log in to Claude.ai"), before the sender is looked at. A mail from `attacker@evil.example` carrying the attacker's own `https://claude.ai/magic-link#…` passes; `tests/test_login_mail_match.py:64` (`test_legacy_subject_still_matches`) asserts exactly this with an empty sender.
2. **Stale mail.** `bin/browser.py:3861` — a candidate is skipped only when `ts + 180 < since_ts`, so a link mail from a previous attempt up to 180 s *before* `trigger_ts` (`bin/browser.py:3920`) is accepted; the poll stops at the first hit and opens it. Failure mode is mostly fail-closed (a consumed/expired link → assisted fallback), but combined with hole 1 an attacker's mail sent shortly before the trigger is also in the window.

**Evidence (reproduced 2026-09-24, himalaya mocked, no real mailbox):**

- `_is_claude_login_mail({"subject": "Please log in to Claude.ai", "from": {"addr": "attacker@evil.example"}})` → `True`; same with the 2026 subject "Your secure link to Claude.ai is here | x" → `True`.
- `_himalaya_latest_login_mail("h", "", ts + 170)` with one `@mail.anthropic.com` envelope dated `ts` → `('INBOX', 'old')` — a mail 170 s older than the trigger is selected.

**Root cause.** (1) the subject short-circuit at `bin/browser.py:3780` ranks the subject — attacker-controlled — above the sender; (2) the freshness guard is a ±180 s date window (himalaya envelope dates have minute precision, `_himalaya_date_epoch` `%Y-%m-%d %H:%M%z`) instead of "not present before we triggered"; (3) nothing ties the link to the account we asked for — the link's `#<token>:<b64email>` fragment names the account, and it is never compared to `email`.

**Decisions.** Sender policy is Albert's assumption c4d0d1: explicit allow-list, default `mail.anthropic.com`, overridable via env, others rejected with a clear message naming the sender. The remaining design points are settled below and recorded as `tp question -d` defaults (non-blocking).

**Why `From` alone is not enough.** `From` is forgeable; the allow-list is the policy Albert asked for, but the load-bearing checks are (a) the link's embedded email must equal `ANTHROPIC_LOGIN_EMAIL` — an attacker's own link names the attacker's account, and a forged fragment email breaks the token/email pairing server-side (moderate confidence on the server-side binding, not verifiable without a live login; the client-side check stands regardless), and (b) the pre-trigger baseline removes every mail that existed before we asked for a link.

**Alternatives considered.** DKIM via `Authentication-Results` (`himalaya message read -H Authentication-Results`): trust depends on which MTA stamped the top header (Gmail vs EPFL Exchange differ) → provider-specific parsing, rejected for now (Observation for the work session). Post-login identity check via a claude.ai account API: needs undocumented endpoints in the live shared browser → rejected. Tightening the 180 s window alone: minute-precision dates make any window either leaky or flaky → replaced by the baseline, window kept only as a backstop.

**Confidence:** high on both holes and the fix shape; moderate that the server binds token to the fragment email.

**Blocked on Albert:** no.

**Verification strictness.** The block runs pytest, mypy and pylint (they execute repo code), so it is not strict-eligible; the allowlisted read-only checks come first. All tests mock himalaya and CDP completely — no real mailbox, keychain or browser profile is touched.

## Steps

- [ ] 1. **Sender allow-list.** Add `_ANTHROPIC_LOGIN_MAIL_SENDERS_DEFAULT = ("mail.anthropic.com",)` and `_login_mail_senders()` reading `ANTHROPIC_LOGIN_MAIL_SENDERS` (comma-separated; whitespace/empty entries ignored; lower-cased; an entry containing `@` before a localpart is an exact address, a bare domain or `@domain` is an exact-domain match — no subdomain or suffix match, so `evilmail.anthropic.com` and `mail.anthropic.com.evil` are rejected; an env value that parses to no entries falls back to the default, never to "allow all"). Add `_sender_allowed(addr, allow) -> bool`.
- [ ] 2. **Restructure `_is_claude_login_mail`** (`bin/browser.py:3770`) into `_looks_like_claude_login_mail(env)` (subject-only: a hint in `_CLAUDE_SUBJECT_HINTS`, or `"claude"` and `"link"` in the subject) and keep `_is_claude_login_mail(env, allow=None) -> bool` = looks-like AND sender allowed. Sender is now mandatory for every subject; the existing product-mail false-positive guard (same domain, non-link subject → rejected) stays.
- [ ] 3. **Clear rejection message.** In `_himalaya_latest_login_mail`, a mail that looks like a login mail but whose sender is not allowed is skipped with `_diag(diag, f"{folder}: rejected a Claude login-looking mail from {sender or '<no sender>'} — not in ANTHROPIC_LOGIN_MAIL_SENDERS ({', '.join(allow)})")`. Update the "no Anthropic login mail" diag to print the allow-list. Rejected mails do not count as `matched`.
- [ ] 4. **Pre-trigger baseline.** Add `_himalaya_login_mail_fingerprints(himalaya, email, account, diag) -> set[tuple[str, str, str]] | None` listing both folders with the same argv as the poll and returning `(from.addr.lower(), subject, date)` for every envelope that `_looks_like_claude_login_mail` (sender-independent, so a pre-planted forged mail is also excluded); `None` when either folder listing fails. Fingerprint, not himalaya `id`, because the server rule moves mails INBOX→Archive and ids are per-folder. Extract the shared "list one folder → list[dict] or diag" code into one helper used by both functions (no duplicated subprocess block).
- [ ] 5. **Use the baseline.** `_himalaya_latest_login_mail(..., exclude: set | None = None)` skips any envelope whose fingerprint is in `exclude` (diag: `"{folder}: skipped a login mail that predates this attempt"`). In `_claude_auto_login` take the baseline BEFORE `trigger_ts`/`_claude_fill_email_and_continue`; if it is `None`, print the diag lines plus "cannot tell old login mails from new ones — not auto-logging in" and return `False` (fail closed → assisted), without submitting the email form. Keep the `ts + 180 < since_ts` guard as a backstop.
- [ ] 6. **Bind link to the requested account.** Add `_magic_link_email(link) -> str | None` decoding the part after the last `:` of the fragment (standard and URL-safe base64, padding tolerated, UTF-8; `None` on any decode error). In `_claude_auto_login`, after `_himalaya_extract_magic_link` and before `page.goto`, require `_magic_link_email(link)` to equal `email` case-insensitively; on mismatch or `None`, `_diag` `"found a login mail ({folder} id {id}) whose link is for a different account — refusing to open it"` (never the link or the decoded email of a foreign account beyond its domain), keep polling for another new mail, and never open it.
- [ ] 7. **Tests** in `tests/test_login_mail_match.py` (himalaya fully mocked via `subprocess.run`): rewrite `test_legacy_subject_still_matches` to assert REJECTION with an empty/foreign sender, plus acceptance of the legacy subject from `no-reply-X@mail.anthropic.com`; foreign sender with the 2026 subject → rejected and the diag names the sender; `ANTHROPIC_LOGIN_MAIL_SENDERS` override (address entry, `@domain` entry, bare domain, lookalike domains `evilmail.anthropic.com` / `mail.anthropic.com.evil` rejected, empty value → default); baseline fingerprint excludes a pre-existing mail even after it moved INBOX→Archive with a new id; a new mail is still selected; baseline listing failure → `_claude_auto_login` returns `False` and never calls `_claude_fill_email_and_continue`; `_magic_link_email` round-trips `dXNlckBleGFtcGxlLmNvbQ==` → `user@example.com` and returns `None` on garbage; auto-login with a link for another account never calls `page.goto`. Adjust `tests/test_login_log_and_sites.py:271` (`test_auto_login_reads_the_link_from_the_configured_account`) for the new baseline call and the link-email binding (use `email="user@example.com"` to match `LINK`, and stub the baseline helper).
- [ ] 8. **Docs.** `.env.example`: add `ANTHROPIC_LOGIN_MAIL_SENDERS` (commented default, format, "must be EXPORTED") under the claude.ai section. `README.md:216` (`anthropic` row) and the auto-login section: sender allow-list, pre-trigger baseline, link must name `ANTHROPIC_LOGIN_EMAIL`; each rejection falls back to assisted login.
- [ ] 9. Lint (`ruff format`, `ruff check`, `mypy`, `pylint` per AGENTS.md), run the Verification block, commit via `ai.py push -m "fix(anthropic): allow-list login-mail senders, ignore pre-trigger mails, bind link to account" <files>`.

NOTE: the next real `browser.py login anthropic` after this lands is the live confirmation that the genuine Anthropic mail still passes all three checks — Albert's observation, not a box.

## Verification

```commands
cd /Users/albert/obsidian/42-Git/home/browser-login && ruff check bin/ tests/
cd /Users/albert/obsidian/42-Git/home/browser-login && ruff format --check bin/ tests/
cd /Users/albert/obsidian/42-Git/home/browser-login && git diff --no-ext-diff --no-textconv HEAD~1 --stat
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pytest -q tests/test_login_mail_match.py tests/test_login_log_and_sites.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pytest -q
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run mypy bin/browser.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pylint bin/browser.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run bin/browser.py -h
```
