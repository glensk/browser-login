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

| Mechanism                                         | No TTY (pipe, `start_new_session`)            | With TTY (parent on a pty)                           |
| ------------------------------------------------- | --------------------------------------------- | ---------------------------------------------------- |
| `security -i`, one command line on stdin          | works, exit = that command's status (0 / 45)  | works identically (stdin is our pipe); `-D`/`-T` kept |
| `-w` as last arg (prompt, value twice on stdin)   | works (falls back to stdin, prompts on stderr) | **blocks** — prompts on `/dev/tty`, ignores our pipe |

`security -i` facts the implementation must respect (all measured):

- Quoting: a `"…"` token with `\\` and `\"` escaped round-trips spaces, `'`, `"`, `\`, a trailing
  `\`, `$`, `` ` ``, `;`, `|`, `&`, `#` and UTF-8 exactly.
- **Line limit: 4096 bytes** (+ newline). A 4098-byte line is split; the tail is parsed as a new
  (unknown) command.
- A newline inside the value ends the command line (value truncated).
- **Malformed input fails open into the default (login) keychain**: the split/truncated fragment
  of an over-long or newline-containing line — and a command naming a non-existent keychain path —
  was written to `login.keychain-db` under the given service. (The probe's stray dummy items were
  deleted; `dump-keychain` shows none left.) So the new code must pre-validate and read back.
- `quit` is not a command (exit 1); send exactly one command, no trailer, and the exit code is that
  command's.

**Pre-existing, related (not this ticket's fix):** `find-generic-password -w` prints a non-ASCII
secret as hex (`päss` → `70c3a47373`) whichever way it was written, so `_keychain_get`
(`bin/browser.py:3125-3155`) returns hex for a non-ASCII password. The read-back check below
must accept that form; the decode fix is filed as **tp#498**. The same argv defect exists in
`sdsc/biopol-wifi/biopol-wifi.py:392-418` (own repo) — filed as **tp#497**. Neither is fixed here.

**Alternatives considered.**

- `-w` last + stdin: rejected — TTY-dependent (blocks interactively, which is the normal
  `store-creds` case) unless detached with `start_new_session=True`; relies on `readpassphrase`'s
  stdin fallback.
- Security.framework via `ctypes`/`pyobjc`/`keyring`: rejected — the item's creator/ACL would
  become Python, so the prompt-free reads through `/usr/bin/security` (the whole point of
  `-T /usr/bin/security`) would start prompting; large blast radius on live infrastructure.
- **Chosen: `security -i` with a single validated, quoted command on stdin, then read-back.**

**Constraints.** `browser.py` is live infrastructure: work in a worktree, never on the real
keychain items; unit tests mock `subprocess.run` completely; the opt-in live test uses its own
temporary keychain file and cleans up. Never print a secret (including in assertion messages).
No public CLI change.

**Verification strictness.** The block runs `pytest`, `mypy` and `pylint` because the fix changes
behaviour of a security helper, so it is not strict-eligible (not read-only-allowlist-only). The
live keychain test is opt-in via an env var and touches only a throw-away keychain.

Blocked on Albert: **no**.

## Steps

- [ ] Add `_kc_quote(s: str) -> str` next to `_kc_account` in `bin/browser.py`: wrap in `"`,
      escape `\` → `\\` and `"` → `\"` (the measured `security -i` tokenizer rules).
- [ ] Rewrite `_keychain_set(service, value)` to run `["security", "-i"]` with
      `input=<one line>` (`capture_output=True, text=True, timeout=15, check=False`); the line is
      `add-generic-password -a Q(account) -s Q(service) -w Q(value) -D Q(desc) -T /usr/bin/security -U`
      + `\n`, no `quit`, no keychain positional. The secret must appear in NO argv element.
- [ ] Fail closed before spawning (return `False`, no subprocess call) when any field contains a
      control character (`ord < 0x20` or `0x7f` — covers `\n`, `\r`, `\0`, `\t`) or the encoded
      line exceeds **4000 bytes** (measured hard limit 4096; margin kept). Decision recorded:
      `tp question 489 -d "reject control chars and lines > 4000 bytes" "What to do with secrets security -i cannot carry?"`.
- [ ] After exit 0, read back with `_keychain_get(service)` and return `True` only if it equals
      `value` or, for a non-ASCII value, `value.encode().hex()` (the measured `-w` output form).
      Decision recorded: `tp question 489 -d "read back after every write" "Verify each keychain write by reading it back?"`.
- [ ] Keep `-D` per caller: add a keyword `description: str = "cscs-api credential"` and pass
      `"biopol-wifi credential"` from the biopolwifi store (`bin/browser.py:4886-4887`) so its items
      match what `sdsc/biopol-wifi` writes (currently mislabelled "cscs-api credential"). Also add
      a keyword `keychain: str | None = None` (appended quoted as the positional keychain when set)
      used only by the live test; `_keychain_get` gets the same optional keyword for the read-back.
- [ ] Unit tests in `tests/test_credentials.py` (fully mocked `subprocess.run`): argv is exactly
      `["security", "-i"]`; the secret is absent from every argv element and present exactly once,
      quoted, in `input`; quoting round-trip cases (`space`, `"`, `'`, `\`, trailing `\`, `$;|&#`,
      UTF-8); control-char and over-length values return `False` with zero subprocess calls;
      non-zero exit → `False`; read-back mismatch → `False`; non-ASCII read-back in hex form →
      `True`; `OSError`/`TimeoutExpired` → `False`. Update `test_keychain_set_reports_the_return_code`.
- [ ] Opt-in live test `tests/test_keychain_live.py`, skipped unless `BROWSER_LIVE_KEYCHAIN=1` and
      `sys.platform == "darwin"`: creates a temp keychain file with `security create-keychain` in
      `tmp_path` (NOT added to the search list), unlocks it, calls `_keychain_set(..., keychain=path)`
      with dummy values covering the quoting cases, asserts round-trip via
      `_keychain_get(..., keychain=path)`, then `delete-keychain`; teardown also deletes any item
      with its unique test account from the default keychain (the measured fail-open path).
      Never prints values.
- [ ] README: in the "Keychain note" section state that `store-creds` hands secrets to
      `security -i` on stdin (never argv) and the 4000-byte / no-control-char limit.
- [ ] Lint + tests green (Verification block), commit with `ai.py push` listing every touched file.

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
