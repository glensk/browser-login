# tp#489 — `_keychain_set` passes secrets on argv (visible in `ps`)

## Session

Resume: `c --resume e3bedcdc-4b55-43ad-bc70-5155d0298a76`

## Context

Classification: **DEFECT** (security; secret exposure to local process listings).

**Symptom.** `bin/browser.py:3158-3188` `_keychain_set` runs
`security add-generic-password -a <user> -s <svc> -w <value> …` — the secret is `argv[7]`.
Any same-user process (`ps -axww -o args`, Activity Monitor, a process-accounting or EDR agent)
can read it while `security` runs. Callers: `cmd_cscs_store_creds` (`bin/browser.py:3605-3608`,
CSCS username, password, TOTP seed) and the biopolwifi store (`bin/browser.py:4886-4887`, portal
email + password).

**Reproduced 2026-09-24** on this Mac with a throw-away keychain file (dummy value
`DUMMY489MARK<n>`, never a real secret): 200 `add-generic-password -w <dummy>` runs while polling
`ps -axww -o args=` → the dummy value was seen **120 times**. Root cause is established, not
guessed: the value is passed as a command-line argument, and argv of a macOS process is readable
by same-uid processes via `KERN_PROCARGS2`. Confidence: **high**.

**How `security` can take the secret without argv — measured (macOS 27, `/usr/bin/security`):**

| Mechanism                                       | No TTY (pipe, `start_new_session`)             | With TTY (parent on a pty)                            |
| ----------------------------------------------- | ---------------------------------------------- | ----------------------------------------------------- |
| `security -i`, one command line on stdin        | works, exit = that command's status (0 / 45)   | works identically (stdin is our pipe); `-D`/`-T` kept |
| `-w` as last arg (prompt, value twice on stdin) | works (falls back to stdin, prompts on stderr) | **blocks** — prompts on `/dev/tty`, ignores our pipe  |

`security -i` facts the implementation must respect (all measured):

- Quoting: a `"…"` token with `\\` and `\"` escaped round-trips spaces, `'`, `"`, `\`, a trailing
  `\`, `$`, `` ` ``, `;`, `|`, `&`, `#` and UTF-8 exactly.
- **Line limit: 4096 bytes** (+ newline). A 4098-byte line is split; the tail is parsed as a new
  (unknown) command.
- A newline inside the value ends the command line (value truncated).
- **Malformed input fails open into the default (login) keychain**: the split/truncated fragment
  of an over-long or newline-containing line — and a command naming a non-existent keychain path —
  was written to `login.keychain-db` under the given service. (The probe's stray dummy items were
  deleted; `dump-keychain` shows none left.) So the new code pre-validates every line, never
  names a keychain path, and reads back.
- `quit` is not a command (exit 1); send exactly one command, no trailer, and the exit code is that
  command's.
- `security create-keychain <tmp path>` did NOT add the file to the user search list here
  (`list-keychains -d user` showed only `login.keychain-db` afterwards) — moot, the plan creates
  no keychain file.

**Pre-existing, related (not this ticket's fix):** `find-generic-password -w` prints a non-ASCII
secret as hex (`päss` → `70c3a47373`) whichever way it was written, so `_keychain_get`
(`bin/browser.py:3125-3155`) returns hex for a non-ASCII password. The read-back below therefore
is a **consistency check** against `security -i` tokenizer divergence, not proof of byte-exact
storage; byte-exact reading is **tp#498**. The same argv defect exists in
`sdsc/biopol-wifi/biopol-wifi.py:392-418` (own repo) — filed as **tp#497**. Neither is fixed here.

**Alternatives considered.**

- `-w` last + stdin: rejected — TTY-dependent (blocks interactively, which is the normal
  `store-creds` case) unless detached with `start_new_session=True`; relies on `readpassphrase`'s
  stdin fallback.
- Security.framework via `ctypes`/`pyobjc`/`keyring`: rejected — the item's creator/ACL would
  become Python, so the prompt-free reads through `/usr/bin/security` (the whole point of
  `-T /usr/bin/security`) would start prompting; large blast radius on live infrastructure.
- An explicit test keychain file (`keychain=` parameter): rejected in the Codex debate — an
  invalid explicit path falls back to the default keychain, so the parameter would add a
  fail-open path to production code for the sake of a test.
- **Chosen: `security -i` with a single validated, quoted, UTF-8-encoded command on stdin,
  all items of a batch validated before the first write, then read-back.**

**Constraints.** `browser.py` is live infrastructure: implement in a git worktree, never on the
real keychain items; unit tests mock `subprocess.run` completely; the opt-in live test only
creates and deletes its own throw-away item (unique account + service). Never print a secret
(including in assertion messages). No public CLI change.

**Debate.** Codex (gpt-6-astra) round 1, judge converged: O1 no `keychain=` parameter (accepted),
O2 search-list isolation (refuted by measurement, moot), O3 single expected read-back form
(accepted), O4 validate the whole batch before writing (accepted), O5 exact UTF-8 bytes and every
field validated (accepted), O6 verify inside the worktree before integrating (accepted; the
block below stays the post-integration reviewer check on main).

**Verification strictness.** The block runs `pytest`, `mypy` and `pylint` because the fix changes
behaviour of a security helper, so it is not strict-eligible. The live keychain test is opt-in
via an env var and touches only its own throw-away item.

Blocked on Albert: **no**.

## Steps

- [x] Create a worktree (`git worktree add <scratchpad>/wt -b tp489-keychain-stdin`) and do all
      edits there — never edit the live `bin/browser.py` in place.
- [x] Add pure helper `_kc_quote(s: str) -> str` next to `_kc_account`: wrap in `"`, escape
      `\` → `\\` and `"` → `\"` (the measured `security -i` tokenizer rules).
- [x] Add pure helper `_kc_add_line(service: str, value: str, description: str) -> bytes | None`:
      returns `add-generic-password -a Q(account) -s Q(service) -w Q(value) -D Q(description) -T /usr/bin/security -U\n`
      encoded as UTF-8, or `None` when any of account, service, value, description contains a
      control character (`ord < 0x20` or `0x7f` — covers `\n`, `\r`, `\0`, `\t`), when encoding
      raises `UnicodeEncodeError` (lone surrogates), or when the encoded line (without the
      trailing newline) exceeds **4000 bytes** (measured hard limit 4096; margin kept). Never
      includes the value in any error text. No keychain positional, no `quit`. Decision recorded:
      `tp question 489 -d "reject control chars and lines > 4000 bytes" …`.
- [x] Rewrite `_keychain_set(service, value, description="cscs-api credential") -> bool`: build
      the line via `_kc_add_line` (`None` → `False`, no subprocess call), run
      `subprocess.run(["security", "-i"], input=<bytes>, capture_output=True, timeout=15, check=False)`
      (bytes mode), non-zero exit or `OSError`/`SubprocessError` → `False`. The secret appears in
      NO argv element.
- [x] Read-back in `_keychain_set` after exit 0: `_keychain_get(service)` must equal exactly ONE
      expected form — `value` if it is printable ASCII, else `value.encode("utf-8").hex()` (the
      measured `-w` output). Docstring states it is a consistency check, not byte-exact proof
      (tp#498). Decision recorded: `tp question 489 -d "read back after every write" …`.
- [x] Add `_keychain_set_all(items: Sequence[tuple[str, str]], description: str) -> bool`:
      serialize every item with `_kc_add_line` first and return `False` with **zero** subprocess
      calls if any is `None`; then write sequentially via `_keychain_set`, stopping at the first
      failure. Switch `cmd_cscs_store_creds` (`bin/browser.py:3605-3608`) and the biopolwifi store
      (`bin/browser.py:4886-4887`, with `description="biopol-wifi credential"`, matching what
      `sdsc/biopol-wifi` writes — today it is mislabelled "cscs-api credential") to it.
- [x] Unit tests in `tests/test_credentials.py` (fully mocked `subprocess.run`): argv is exactly
      `["security", "-i"]`; the secret is absent from every argv element and present exactly once,
      quoted, in `input`; quoting round-trip of `_kc_quote` for `space`, `"`, `'`, `\`, trailing
      `\`, `$;|&#`, UTF-8; a full line of exactly 4000 bytes accepted and 4001 rejected, built with
      multibyte chars and `"`/`\` escape expansion; control char in each of account, service,
      value, description → `None`; lone surrogate → `None`; non-zero exit → `False`; read-back
      mismatch → `False`; non-ASCII value with hex read-back → `True` and with plaintext read-back
      → `False`; `OSError`/`TimeoutExpired` → `False`. Update
      `test_keychain_set_reports_the_return_code` and the `_store_creds_env` fake (now patching
      `_keychain_set_all` or `subprocess.run`). Caller tests: an invalid LAST field (CSCS seed /
      biopol password with `\n`) → zero `security` calls.
- [x] Opt-in live test `tests/test_keychain_live.py`, skipped unless `BROWSER_LIVE_KEYCHAIN=1` and
      `sys.platform == "darwin"`: account `tp489-live-<token_hex>`, services
      `tp489-live-<token_hex>-<case>`; calls `_keychain_set` with the account monkeypatched via
      `_kc_account` and dummy values covering the quoting cases and one UTF-8 case; asserts the
      read-back form; before cleanup asserts no item exists under the unique account besides the
      expected services (no escaped fragments); `finally` deletes exactly those account/service
      pairs. Never prints values.
- [x] README: in the "Keychain note" section state that `store-creds` hands secrets to
      `security -i` on stdin (never argv) and the 4000-byte / no-control-char limit.
- [x] Run every Verification command from inside the worktree (`cd <scratchpad>/wt && …`) and
      fix until green; then fast-forward `main` to the branch, remove the worktree and branch, and
      commit/push with `ai.py push` listing every touched file.

Execution notes (2026-09-24): implemented in commit `269386a` (worktree
`tp489-keychain-stdin`, fast-forwarded to `main`). The new test module has no shebang and is
mode 644 like `test_credentials.py`: the global pre-commit hook treats an executable file with a
shebang and a `pytest` import as a script that needs a bootstrap shape. The live test only
exercises CREATE. **Incident:** an extra ps-probe (60 `_keychain_set` calls on ONE throw-away
item, i.e. 1 create + 59 `-U` updates) opened a SecurityAgent prompt on the first UPDATE
(14:15:06). The 15 s `subprocess.run` timeout killed the `security` client mid-prompt, and
`securityd` (up 3.4 days) aborted with SIGABRT at 14:15:21, then again at 14:25:04 (`log show`,
launchd "exited due to SIGABRT"). Afterwards every login-keychain access hung (500+ hung
`security find-generic-password` calls from other tools). Most likely the restarted `securityd`
re-locked the login keychain and is waiting for an unlock prompt only Albert can answer. The
probe was killed; its throw-away item (`tp489-probe-<hex>`, dummy value) could not be deleted
while the keychain hung and still has to be removed. Consequences: the live test deliberately has
NO update case; whether the old argv `-U` update prompted the same way is unmeasured (it runs the
same binary doing the same operation, so probably yes). The fixed 15 s timeout on a call that can
raise a GUI prompt is recorded as an observation, not fixed here.

NOTE: No redeploy is needed — `browser.py` is exec'd fresh per call. Albert's existing keychain
items stay as they are; they are only rewritten the next time he runs `store-creds`.

## Verification

```commands
cd /Users/albert/obsidian/42-Git/home/browser-login && ruff check bin/ tests/
cd /Users/albert/obsidian/42-Git/home/browser-login && ruff format --check bin/ tests/
cd /Users/albert/obsidian/42-Git/home/browser-login && git log --oneline -5
cd /Users/albert/obsidian/42-Git/home/browser-login && git status --short
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pytest -q tests/test_credentials.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pytest -q
cd /Users/albert/obsidian/42-Git/home/browser-login && env BROWSER_LIVE_KEYCHAIN=1 uv run pytest -q tests/test_keychain_live.py
cd /Users/albert/obsidian/42-Git/home/browser-login && mypy bin/browser.py
cd /Users/albert/obsidian/42-Git/home/browser-login && uv run pylint bin/browser.py
cd /Users/albert/obsidian/42-Git/home/browser-login && bin/browser.py -h
```
