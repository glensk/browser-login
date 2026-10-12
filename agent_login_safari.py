"""An AGENT's login in Albert's own Safari (WS1b, PLAN_ws1b-durability.md D1–D3).

Albert, 2026-10-11: the assisted logins (galaxus-de, notion, openai, slack and
the Safari marketplace sites) are done by agents in his Safari — never a
`-g` to-do for him. `agent-login.py -L SITE` drives his Safari through
mydotfiles' ``safari.py`` (credentials come from his unlocked Vaultwarden
tab, never through this process's argv or output), then copies the session
into the shared Chromium (``browser.py import-safari``).

This module is the Safari side: the recipes (data), the page detector (a
fixed JS that returns booleans only), the step machine, the mail-code reader
and the interactive gate. Only four stops are Albert's: a CAPTCHA, an SMS
code, a push / security-key approval and a locked vault. Everything else is
the agent's.

Safety rules (each one tested):

* Explicit and attended only: `-L` refuses inside a LaunchAgent
  (``AGENT_LOGIN_SCHEDULED``), on a locked console and when nobody used the
  Mac for ``IDLE_MAX_S`` (`interactive_gate`) — a Safari login never runs on
  an unattended Mac.
* The login runs in a NEW Safari window addressed by its window id
  (``safari.py --new-window`` / ``--handle``); every fill, click and read also
  names the host the tab must be on (``--expect-host``, re-checked by
  safari.py in the page right before it acts). Without those safari.py
  features nothing is driven (``safari_py_outdated``).
* Every credential / SSO / code step runs at most once per run; a failure
  after one may have submitted something and quarantines the site.
* A safari.py run that overstays its budget gets SIGTERM (safari.py clears
  the clipboard on it, feature ``sigterm_clear``), then SIGKILL; after a
  killed credential step this process clears the clipboard itself.
* safari.py's free text (page text, candidates, error messages) is never
  stored or printed: only fixed codes, validated hosts and booleans leave.
"""

from __future__ import annotations

# One module for the whole Safari side (recipes, runner, gate, detector, mail
# codes, step machine): they share one contract and are tested together.
# pylint: disable=too-many-lines
import contextlib
import hashlib
import hmac
import json
import os
import plistlib
import re
import secrets
import shutil
import signal
import subprocess
import tempfile
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from email.utils import getaddresses
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

SAFARI_PY_ENV = "SAFARI_PY_BIN"
DEFAULT_SAFARI_PY = Path.home() / "obsidian/42-Git/home/mydotfiles/bin/safari.py"
# Local, private (0600, outside the public repo): per site the vault item when
# its name is ambiguous in Albert's own vault, the Google account to pick, the
# expected account an import must prove, the himalaya mailbox, and whether the
# Notion server probe was verified live (L0).
OVERRIDE_FILE = Path.home() / ".config" / "agent-login" / "safari-logins.json"
OVERRIDE_STR_KEYS = frozenset(
    {
        "item",
        "account",
        "expected_email",
        "expected_team_id",
        "expected_user_id",
        "expected_workspace_id",
        "mailbox",
    }
)
OVERRIDE_BOOL_KEYS = frozenset({"notion_probe_verified"})
SCHEDULED_ENV = "AGENT_LOGIN_SCHEDULED"
# Tests (conftest) pin the safari.py feature set: a comma list, or "none".
FEATURES_ENV = "AGENT_LOGIN_SAFARI_FEATURES"

# What any Safari-DRIVING run needs from safari.py (its `--capabilities`):
# a new window addressed by its id, the in-page host check, the clipboard
# clear on SIGTERM.
BASE_FEATURES = frozenset(
    {
        "open",
        "tabs",
        "eval",
        "handle",
        "new_window",
        "close",
        "expect_host",
        "sigterm_clear",
    }
)
STEP_FEATURES = {
    "user": "user_only",
    "login": "login",
    "otp": "otp",
    "click": "click",
    "account": "account_pick",
    "mail_code": "click",
}
# Steps that send a credential, an SSO choice or a code: at most once per run;
# a failure after one quarantines the site.
CREDENTIAL_KINDS = frozenset({"user", "login", "otp", "account", "mail_code"})
# Steps whose secret travels through the clipboard (safari.py -L / -O).
CLIPBOARD_KINDS = frozenset({"user", "login", "otp"})

POLL_S = 3.0
MAX_POLLS = 40  # ~2 min of page reads, plus the steps' own waits
IDLE_POLLS = 4  # this many reads with nothing to do = stuck
MAIL_WAIT_S = 180.0
MAIL_POLL_S = 5.0
# safari.py's worst case per call (its defaults): the vault lock (60 s), the
# vault search (10 s) and two copies (menu 3 s + clipboard 5 s each), the
# TOTP window (6 s), the page wait (`--wait`, 20 s), the submit enable (3 s)
# and its reaction (5 s) — about 125 s; the budget leaves room above it.
WAIT_S = 20
CREDENTIAL_TIMEOUT_S = 180.0
ACTION_TIMEOUT_S = 75.0  # open / click / eval / tabs / close
TERM_GRACE_S = 8.0  # SIGTERM → SIGKILL (safari.py's signal path takes ~6 s)

HOST_RE = re.compile(
    r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$"
)
_OTP_FIELD = (
    'input[autocomplete="one-time-code"],input[name="code"],input[name="otp"],'
    'input[inputmode="numeric"]'
)
_USER_FIELD = (
    'input[type="email"],input[autocomplete="username"],input[name="username"],'
    'input[name="email"]'
)
_PASSWORD = 'input[type="password"]'
# A form that shows BOTH fields (a one-page login; Safari supports `:has`).
ONE_PAGE_FORM = (
    'form:has(input[type="password"]):has(input[type="email"],'
    'input[autocomplete="username"],input[name="username"],input[name="email"])'
)
# The Google account chooser lists accounts as [data-identifier] rows; the
# password page shows the chosen account as a chip with the same attribute —
# never "pick" there.
GOOGLE_CHOOSER = "[data-identifier]"


@dataclass(frozen=True)
class Step:  # pylint: disable=too-many-instance-attributes
    """One step of a recipe; it runs when the tab is on `host` and `when` is
    visible and `unless` is not (empty `when` = always).

    `trigger` is the button that STARTS something (a click step's target, the
    mail-code step's "send me a code"); `submit` the button that SENDS what
    was filled (password, TOTP, the mail code)."""

    kind: str  # user | login | otp | click | account | mail_code
    host: str
    trigger: str = ""
    submit: str = ""
    when: str = ""
    unless: str = ""
    no_user: bool = False  # login: the page shows the password field only
    # mail_code: the e-mail field filled with the expected address (from the
    # override file) before the trigger; the mail's senders, subjects, code.
    email_field: str = ""
    senders: tuple[str, ...] = ()
    code_re: str = ""
    subjects: tuple[str, ...] = ()
    # A page that does not offer this step's element (safari.py refuses, exit
    # 2, before anything is copied) skips the step instead of stopping the run.
    optional: bool = False


@dataclass(frozen=True)
class Recipe:  # pylint: disable=too-many-instance-attributes
    """How an agent logs SITE in in Safari. For a broker-backed site the start
    page, the success sentinel and the vault item come from the broker
    listing (``login_url``, ``logged_in_selector``, ``name``) unless set here."""

    site: str
    hosts: tuple[str, ...]  # every host the login tab may be on
    sentinel_host: str
    steps: tuple[Step, ...] = ()
    start_url: str = ""
    sentinel: str = ""
    broker: bool = True
    import_after: bool = True  # False: Safari-only use (Ricardo)
    identity: str = ""  # built-in import's account proof (browser.py)

    def features(self) -> frozenset[str]:
        """safari.py features this recipe needs."""
        return BASE_FEATURES | {STEP_FEATURES[s.kind] for s in self.steps}


def _two_step(idp: str, *, user_submit: str, pass_submit: str) -> tuple[Step, ...]:
    """Username page, then password page (the IdP asks for the e-mail first)."""
    return (
        Step("user", idp, submit=user_submit, when=_USER_FIELD, unless=_PASSWORD),
        Step("login", idp, submit=pass_submit, when=_PASSWORD, no_user=True),
    )


def _one_or_two_step(
    idp: str, *, user_submit: str, pass_submit: str
) -> tuple[Step, ...]:
    """A page with both fields (one-page), else the two-step pages."""
    return (
        Step("login", idp, submit=pass_submit, when=ONE_PAGE_FORM),
        *_two_step(idp, user_submit=user_submit, pass_submit=pass_submit),
    )


def _google(host: str, trigger: str, *, optional: bool = False) -> tuple[Step, ...]:
    """ "Continue with Google" on `host`, then the account chooser (optional:
    Google skips it with one account; never on the password page, whose
    account chip carries the same attribute) and the consent "Continue"."""
    return (
        Step("click", host, trigger=trigger, optional=optional),
        Step(
            "account",
            "accounts.google.com",
            when=GOOGLE_CHOOSER,
            unless=_PASSWORD,
            optional=True,
        ),
        Step(
            "click",
            "accounts.google.com",
            trigger="Continue",
            when="button",
            unless=_PASSWORD,
            optional=True,
        ),
    )


# Every label below is UNVERIFIED until the main session's live step L2 has
# read the page in Albert's Safari; a wrong one only stops the run
# (`recipe_stuck`) — safari.py clicks exactly one visible match or nothing.
RECIPES: dict[str, Recipe] = {
    "galaxus-de": Recipe(
        "galaxus-de",
        ("www.galaxus.de", "id.galaxus.eu"),
        "www.galaxus.de",
        _two_step("id.galaxus.eu", user_submit="Weiter", pass_submit="Anmelden"),
    ),
    "galaxus": Recipe(
        "galaxus",
        ("www.galaxus.ch", "id.digitecgalaxus.ch"),
        "www.galaxus.ch",
        _two_step("id.digitecgalaxus.ch", user_submit="Weiter", pass_submit="Anmelden"),
    ),
    "anibis": Recipe(
        "anibis",
        ("www.anibis.ch", "auth.anibis.ch"),
        "www.anibis.ch",
        _one_or_two_step(
            "auth.anibis.ch", user_submit="Continuer", pass_submit="Se connecter"
        ),
    ),
    "tutti": Recipe(
        "tutti",
        ("www.tutti.ch", "auth.tutti.ch"),
        "www.tutti.ch",
        _one_or_two_step("auth.tutti.ch", user_submit="Weiter", pass_submit="Anmelden"),
    ),
    "kleinanzeigen": Recipe(
        "kleinanzeigen",
        ("www.kleinanzeigen.de", "login.kleinanzeigen.de"),
        "www.kleinanzeigen.de",
        _one_or_two_step(
            "login.kleinanzeigen.de", user_submit="Weiter", pass_submit="Einloggen"
        ),
    ),
    # Cloudflare blocks the automated browser on Ricardo: agents work in
    # Safari itself, so the recipe only logs Safari in (no import).
    "ricardo": Recipe(
        "ricardo",
        ("www.ricardo.ch", "login.ricardo.ch"),
        "www.ricardo.ch",
        _one_or_two_step(
            "login.ricardo.ch", user_submit="Weiter", pass_submit="Anmelden"
        ),
        import_after=False,
    ),
    "openai": Recipe(
        "openai",
        ("chatgpt.com", "auth.openai.com", "accounts.google.com"),
        "chatgpt.com",
        _google("auth.openai.com", "Continue with Google"),
        start_url="https://chatgpt.com/auth/login",
        sentinel='[data-testid="accounts-profile-button"]',
        broker=False,
        identity="openai",
    ),
    # Google first; a sign-in page without the Google button falls through to
    # the e-mail code (the optional click is refused: nothing was sent).
    "slack": Recipe(
        "slack",
        (
            "swiss-data-science.slack.com",
            "app.slack.com",
            "slack.com",
            "accounts.google.com",
        ),
        "app.slack.com",
        (
            *_google(
                "swiss-data-science.slack.com", "Sign In With Google", optional=True
            ),
            Step(
                "mail_code",
                "swiss-data-science.slack.com",
                trigger="Sign In With Email",
                when='input[type="email"]',
                email_field='input[type="email"]',
                senders=("no-reply@slack.com", "feedback@slack.com"),
                code_re=r"\b[A-Z0-9]{3}-[A-Z0-9]{3}\b",
                subjects=("confirmation code", "Bestätigungscode"),
            ),
        ),
        start_url="https://swiss-data-science.slack.com/",
        sentinel='[data-qa="channel_sidebar"]',
        broker=False,
        identity="slack",
    ),
    # The e-mail code: the expected address, "Continue" (trigger), the code
    # from the mailbox, "Continue with login code" (submit).
    "notion": Recipe(
        "notion",
        ("www.notion.so", "notion.so", "app.notion.com"),
        "app.notion.com",
        (
            Step(
                "mail_code",
                "www.notion.so",
                trigger="Continue",
                submit="Continue with login code",
                when='input[type="email"]',
                email_field='input[type="email"]',
                senders=("notify@mail.notion.so",),
                code_re=r"\b\d{6}\b",
                subjects=("login code", "Anmeldecode"),
            ),
        ),
        start_url="https://www.notion.so/login",
        sentinel=".notion-sidebar, .notion-sidebar-switcher",
        broker=False,
        identity="notion",
    ),
}
# claude.ai: no Safari — its login is the automated magic link in the shared
# browser (`browser.py login anthropic`, ANTHROPIC_LOGIN_EMAIL); agent-login
# routes to it.
MAGIC_LINK_SITES = frozenset({"anthropic", "anthropic-private"})


# ---------------------------------------------------------------------------
# results
# ---------------------------------------------------------------------------

NEEDS_ALBERT_RC = 4
BUSY_RC = 75
ENV_RC = 3


@dataclass
class Outcome:
    """How a Safari run ended: exit code, fixed phase/code, whether a
    credential step ran (→ quarantine on failure), the steps that ran."""

    rc: int
    code: str
    credential: bool = False
    steps: list[str] = field(default_factory=list)
    phase: str = "safari-source"
    # a window this run opened may still be open (its id was not returned)
    window_left: bool = False

    @property
    def ok(self) -> bool:
        return self.rc == 0


# ---------------------------------------------------------------------------
# the override file
# ---------------------------------------------------------------------------


class OverrideError(ValueError):
    """The override file exists but is not what it must be."""


def override_path() -> Path:
    """``$AGENT_LOGIN_SAFARI_OVERRIDES`` (tests), else ``OVERRIDE_FILE``."""
    env = os.environ.get("AGENT_LOGIN_SAFARI_OVERRIDES")
    return Path(env) if env else OVERRIDE_FILE


def load_overrides(path: Path | None = None) -> dict[str, dict[str, Any]]:
    """``{site: {key: value}}`` of the override file ({} when absent).

    Refused (OverrideError): not a regular 0600 file of this user, not a JSON
    object of objects, an unknown key, a value of the wrong type."""
    path = path or override_path()
    try:
        st = path.lstat()
    except FileNotFoundError:
        return {}
    except OSError as exc:
        raise OverrideError(f"{path}: unreadable") from exc
    if not path.is_file() or path.is_symlink():
        raise OverrideError(f"{path}: not a regular file")
    if st.st_mode & 0o077 or st.st_uid != os.getuid():
        raise OverrideError(f"{path}: must be 0600 and yours")
    data = json_object_text(path)
    if data is None:
        raise OverrideError(f"{path}: not a JSON object")
    return {str(site): _clean_entry(path, site, entry) for site, entry in data.items()}


def _clean_entry(path: Path, site: object, entry: object) -> dict[str, Any]:
    """One site's entry of the override file, validated (OverrideError)."""
    if not isinstance(entry, dict):
        raise OverrideError(f"{path}: {site!r} is not an object")
    bad = set(entry) - OVERRIDE_STR_KEYS - OVERRIDE_BOOL_KEYS
    if bad:
        raise OverrideError(f"{path}: unknown key(s) {sorted(bad)}")
    clean: dict[str, Any] = {}
    for key, value in entry.items():
        if key in OVERRIDE_BOOL_KEYS:
            if not isinstance(value, bool):
                raise OverrideError(f"{path}: {key} must be true or false")
            clean[key] = value
        elif isinstance(value, str) and value.strip():
            clean[key] = value.strip()
        else:
            raise OverrideError(f"{path}: {key} must be a non-empty string")
    return clean


def json_object_text(path: Path) -> dict | None:
    """The JSON object in `path` (None: unreadable or not an object)."""
    try:
        return json_object(path.read_text(encoding="utf-8"))
    except OSError:
        return None


# ---------------------------------------------------------------------------
# safari.py: the runner, its capabilities
# ---------------------------------------------------------------------------


def safari_py_bin() -> str | None:
    """safari.py: $SAFARI_PY_BIN, PATH, then mydotfiles' bin; None if absent."""
    for cand in (
        os.environ.get(SAFARI_PY_ENV),
        shutil.which("safari.py"),
        str(DEFAULT_SAFARI_PY),
    ):
        if cand and Path(cand).is_file() and os.access(cand, os.X_OK):
            return cand
    return None


@dataclass
class Reply:
    """One safari.py call: its exit code and the parsed JSON object (`data`;
    {} when there was none). `error` is safari.py's message — classified by
    `error_code`, NEVER stored or printed. `killed`: it overstayed its budget
    and was terminated."""

    rc: int
    data: dict[str, Any]
    error: str = ""
    killed: bool = False


Runner = Callable[[list[str]], Reply]


def call_timeout(args: list[str]) -> float:
    """The budget of one safari.py call (by its mode, the first argument)."""
    return (
        CREDENTIAL_TIMEOUT_S
        if args[:1] in (["--login"], ["--otp"])
        else ACTION_TIMEOUT_S
    )


def _terminate(proc: subprocess.Popen) -> None:
    """SIGTERM safari.py's process group (it clears the clipboard on it),
    then SIGKILL after ``TERM_GRACE_S``."""
    for sig, wait in ((signal.SIGTERM, TERM_GRACE_S), (signal.SIGKILL, TERM_GRACE_S)):
        with contextlib.suppress(OSError):
            os.killpg(proc.pid, sig)
        try:
            proc.wait(timeout=wait)
            return
        except subprocess.TimeoutExpired:
            continue


def run_safari_py(binary: str) -> Runner:
    """A Runner calling ``binary ARGS --json`` (stdout = one JSON object),
    in its own process group, bounded by `call_timeout`."""

    def call(args: list[str]) -> Reply:
        try:
            proc = subprocess.Popen(  # pylint: disable=consider-using-with
                [binary, *args, "--json"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                start_new_session=True,
            )
        except OSError:
            return Reply(ENV_RC, {}, "safari.py could not be run")
        try:
            out, _err = proc.communicate(timeout=call_timeout(args))
        except subprocess.TimeoutExpired:
            _terminate(proc)
            return Reply(1, {}, "timeout", killed=True)
        data = json_object(out or "{}") or {}
        return Reply(proc.returncode, data, str(data.get("error") or ""))

    return call


def clear_clipboard() -> None:
    """Empty the clipboard (`pbcopy` < nothing): after a killed safari.py
    whose credential step may have left a secret there."""
    with contextlib.suppress(OSError, subprocess.SubprocessError):
        subprocess.run(["pbcopy"], input="", text=True, timeout=10, check=False)


def interrupted(reply: Reply) -> bool:
    """safari.py did not end on its own terms: this process killed it, or it
    died of a signal nobody here sent (exit ≥ 128 through a shell, or a
    negative Popen code) — whatever it was doing MAY have been done."""
    return reply.killed or reply.rc >= 128 or reply.rc < 0


# One return per class of failure.
def error_code(reply: Reply) -> str:  # pylint: disable=too-many-return-statements
    """The fixed code of a failed safari.py call (by its exit code and the
    class of its message; the message itself is dropped)."""
    msg = reply.error.lower()
    if reply.killed:
        return "safari_timeout"
    if interrupted(reply):
        return "safari_signal"
    if reply.rc == ENV_RC:
        if "lock / login screen" in msg or "unlock" in msg:
            return "needs_albert_vault_locked"
        if "no safari tab url contains" in msg and "vault" in msg:
            return "needs_albert_vault_locked"
        if "vault tab busy" in msg:
            return "busy"
        return "safari_unavailable"
    return "recipe_stuck"


_FEATURE_CACHE: dict[tuple[str, str], frozenset[str]] = {}


def features(call: Runner) -> frozenset[str]:
    """safari.py's feature set (``--capabilities``); empty when it has none
    (an older safari.py: nothing is driven)."""
    reply = call(["--capabilities"])
    feats = reply.data.get("features") if reply.rc == 0 else None
    if isinstance(feats, list) and all(isinstance(f, str) for f in feats):
        return frozenset(feats)
    return frozenset()


def available_features() -> frozenset[str]:
    """What the installed safari.py can do (cached per binary); no safari.py =
    nothing. ``$AGENT_LOGIN_SAFARI_FEATURES`` (a comma list or ``none``) is
    honoured ONLY inside a pytest run (``PYTEST_CURRENT_TEST`` set): outside
    tests nobody can fake a capability."""
    env = os.environ.get(FEATURES_ENV)
    if env is not None and os.environ.get("PYTEST_CURRENT_TEST"):
        return frozenset(f for f in env.split(",") if f and f != "none")
    binary = safari_py_bin()
    if binary is None:
        return frozenset()
    key = (binary, str(Path(binary).stat().st_mtime) if Path(binary).exists() else "")
    if key not in _FEATURE_CACHE:
        _FEATURE_CACHE[key] = features(run_safari_py(binary))
    return _FEATURE_CACHE[key]


def missing_features(site: str, have: frozenset[str] | None = None) -> frozenset[str]:
    """The safari.py features `site`'s recipe needs and the installed one
    lacks (empty: `-L` can log Safari in for `site`)."""
    recipe = RECIPES.get(site)
    if recipe is None:
        return frozenset({"recipe"})
    have = available_features() if have is None else have
    return recipe.features() - have


# ---------------------------------------------------------------------------
# the interactive gate: never on an unattended Mac
# ---------------------------------------------------------------------------

IDLE_MAX_S = 15 * 60.0
_Run = Callable[..., subprocess.CompletedProcess]


def _ioreg(args: list[str], run: _Run) -> Any:
    """`ioreg ARGS -a` parsed (a plist), None on any failure."""
    try:
        res = run(
            ["/usr/sbin/ioreg", *args, "-a"],
            capture_output=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if res.returncode != 0 or not res.stdout:
        return None
    try:
        raw = res.stdout if isinstance(res.stdout, bytes) else res.stdout.encode()
        return plistlib.loads(raw)
    except (plistlib.InvalidFileException, ValueError):
        return None


def console_state(run: _Run = subprocess.run, uid: int | None = None) -> str:
    """``unlocked`` / ``locked`` / ``not_on_console`` / ``unknown`` for this
    user's console session (IORegistry root's ``IOConsoleUsers``). Locked =
    ``CGSSessionScreenIsLocked`` (the user's session) or ``IOConsoleLocked``
    (the root's or the session's) is true; either one present but not a
    boolean = unknown (fail closed). An absent key is "not locked"."""
    uid = os.getuid() if uid is None else uid
    root = _ioreg(["-n", "Root", "-d1"], run)
    users = root.get("IOConsoleUsers") if isinstance(root, dict) else None
    if not isinstance(users, list) or not isinstance(root, dict):
        return "unknown"
    mine = [
        u for u in users if isinstance(u, dict) and u.get("kCGSSessionUserIDKey") == uid
    ]
    if not mine or not any(u.get("kCGSSessionOnConsoleKey") is True for u in mine):
        return "not_on_console"
    flags = [root.get("IOConsoleLocked")]
    for u in mine:
        flags += [u.get("CGSSessionScreenIsLocked"), u.get("IOConsoleLocked")]
    present = [f for f in flags if f is not None]
    if any(not isinstance(f, bool) for f in present):
        return "unknown"
    return "locked" if any(present) else "unlocked"


def idle_seconds(run: _Run = subprocess.run) -> float | None:
    """Seconds since the last keyboard / mouse input (HIDIdleTime), None
    when it cannot be read."""
    data = _ioreg(["-c", "IOHIDSystem", "-r", "-d1"], run)
    entries = data if isinstance(data, list) else [data]
    for entry in entries:
        if isinstance(entry, dict):
            ns = entry.get("HIDIdleTime")
            if isinstance(ns, int) and not isinstance(ns, bool) and ns >= 0:
                return ns / 1e9
    return None


def interactive_gate(run: _Run = subprocess.run) -> str | None:
    """None when a Safari login may run now; else the fixed reason code:
    ``scheduled`` (a LaunchAgent), ``console_locked``, ``not_on_console``,
    ``console_unknown``, ``albert_idle`` (no input for ``IDLE_MAX_S``) or
    ``idle_unknown``. Fail closed: unreadable = refused.

    What it proves: SOMEONE is at this unlocked Mac and used it within
    ``IDLE_MAX_S`` — so a push, a CAPTCHA or a window in Safari meets a person
    who can see it. It does NOT prove that Albert started this run (an agent
    in his session does); the explicit invocation is that part."""
    if scheduled():
        return "scheduled"
    state = console_state(run)
    if state != "unlocked":
        return {"locked": "console_locked", "not_on_console": "not_on_console"}.get(
            state, "console_unknown"
        )
    idle = idle_seconds(run)
    if idle is None:
        return "idle_unknown"
    if idle > IDLE_MAX_S:
        return "albert_idle"
    return None


# ---------------------------------------------------------------------------
# the page detector (booleans only)
# ---------------------------------------------------------------------------

DETECTOR_JS = r"""// agent-login:detector
(() => {
  const P = __PARAMS__;
  const vis = (e) => !!e && e.getClientRects().length > 0 &&
    getComputedStyle(e).visibility !== "hidden";
  const any = (sel) => {
    if (!sel) return false;
    try { return [...document.querySelectorAll(sel)].some(vis); }
    catch (err) { return false; }
  };
  const text = (document.body ? document.body.innerText : "").slice(0, 20000);
  const path = location.pathname.toLowerCase();
  const frames = [...document.querySelectorAll("iframe")].filter(vis);
  const big = (f) => { const r = f.getBoundingClientRect(); return r.width > 2 && r.height > 2; };
  const src = (f) => String(f.src || "");
  const challengeFrame = (f) => big(f) && (
    /recaptcha\/(api2|enterprise)\/bframe/.test(src(f)) ||
    (/recaptcha\/(api2|enterprise)\/anchor/.test(src(f)) && !/size=invisible/.test(src(f))) ||
    /hcaptcha\.com/.test(src(f)) || /challenges\.cloudflare\.com/.test(src(f)) ||
    /arkoselabs|funcaptcha/.test(src(f)));
  const captcha = frames.some(challengeFrame) || any("#challenge-form,#cf-challenge-running");
  const password = any('input[type="password"]');
  const user = any(P.user);
  const code = any(P.otp);
  const fieldless = !password && !user && !code;
  // A second-factor page by its STRUCTURE (a challenge / verification route,
  // no form field), the text only names which kind: an offer on a login page
  // ("use a passkey") is never a stop.
  const challengePath = /challenge|mfa|2fa|two-?factor|verif|approv|webauthn|passkey/.test(path);
  const sms = code && /\bSMS\b|text message|Textnachricht|message texte/i.test(text);
  const push = fieldless && challengePath && /check your phone|approve (the )?sign.?in|tap yes|Pr(ü|ue)fe dein (Smartphone|Telefon|Handy)|Anmeldung best(ä|ae)tigen|v(é|e)rifiez votre t(é|e)l(é|e)phone/i.test(text);
  const hardware_key = fieldless && challengePath && /security key|Sicherheitsschl(ü|ue)ssel|cl(é|e) de s(é|e)curit(é|e)/i.test(text);
  const email_code = code && !sms && /e-?mail|inbox|Posteingang|courriel/i.test(text);
  const steps = (P.steps || []).map((s) => ({
    when: s.when ? any(s.when) : true,
    unless: s.unless ? any(s.unless) : false,
  }));
  return JSON.stringify({ captcha, sms, push, hardware_key, email_code,
    password, user, code, sentinel: any(P.sentinel), steps });
})()
"""

PAGE_FLAGS = (
    "captcha",
    "sms",
    "push",
    "hardware_key",
    "email_code",
    "password",
    "user",
    "code",
    "sentinel",
)
# The page stops that are Albert's, in the order they are checked.
ALBERT_STOPS = ("captcha", "sms", "push", "hardware_key")


def detector_js(recipe: Recipe, sentinel: str) -> str:
    """The detector for `recipe` (parameters as one JSON literal)."""
    params = {
        "sentinel": sentinel,
        "user": _USER_FIELD,
        "otp": _OTP_FIELD,
        "steps": [{"when": s.when, "unless": s.unless} for s in recipe.steps],
    }
    return DETECTOR_JS.replace("__PARAMS__", json.dumps(params))


def parse_page(raw: object, n_steps: int) -> dict[str, Any] | None:
    """The detector's answer, validated against its closed schema (None:
    anything else — counted as an unreadable page, never trusted)."""
    data = json_object(raw)
    steps = data.get("steps") if data else None
    if data is None or not isinstance(steps, list) or len(steps) != n_steps:
        return None
    if not all(isinstance(data.get(key), bool) for key in PAGE_FLAGS):
        return None
    pairs = [(s.get("when"), s.get("unless")) for s in steps if isinstance(s, dict)]
    if len(pairs) != n_steps or not all(
        isinstance(w, bool) and isinstance(u, bool) for w, u in pairs
    ):
        return None
    out: dict[str, Any] = {key: data[key] for key in PAGE_FLAGS}
    out["steps"] = pairs
    return out


def json_object(raw: object) -> dict | None:
    """`raw` parsed as ONE JSON object (None for anything else)."""
    with contextlib.suppress(TypeError, ValueError):
        data = json.loads(raw) if isinstance(raw, str) else None
        return data if isinstance(data, dict) else None
    return None


def safe_host(url: object) -> str:
    """The lower-case host of an https URL ('' for anything else)."""
    try:
        parts = urlsplit(str(url or ""))
    except ValueError:
        return ""
    host = (parts.hostname or "").lower()
    return host if parts.scheme == "https" and HOST_RE.match(host) else ""


# ---------------------------------------------------------------------------
# mail codes (himalaya, the pattern of browser.py's magic-link reader)
# ---------------------------------------------------------------------------

# Every folder a login mail can sit in (a server rule archives some; Gmail
# keeps everything in All Mail). A folder the account lacks is skipped — but
# only when it was already missing for the baseline: a folder that answered
# then must answer later, or old and new mail cannot be told apart.
MAIL_FOLDERS = ("INBOX", "Archive", "[Gmail]/All Mail")


def _addrs(raw: object) -> tuple[str, list[str]]:
    """(state, lower-cased addresses) of a himalaya address field; state
    ``absent`` / ``valid`` / ``malformed`` (odd input never accepts)."""
    if raw is None or raw in ("", [], {}):
        return "absent", []
    out: list[str] = []
    for item in raw if isinstance(raw, list) else [raw]:
        got = _item_addrs(item)
        if got is None:
            return "malformed", []
        out += got
    return "valid", out


def _item_addrs(item: object) -> list[str] | None:
    """The lower-cased addresses of ONE himalaya address entry (``{"addr"}``
    or a display string), None when it is anything else or malformed."""
    if isinstance(item, dict):
        addr = item.get("addr")
        parsed = [addr.strip()] if isinstance(addr, str) else []
    elif isinstance(item, str):
        parsed = [a.strip() for _n, a in getaddresses([item])]
    else:
        parsed = []
    ok = bool(parsed) and all(a.count("@") == 1 for a in parsed)
    return [a.lower() for a in parsed] if ok else None


def sender_allowed(addr: str, allow: tuple[str, ...]) -> bool:
    """Exact address or exact domain — never a suffix match."""
    addr = (addr or "").strip().lower()
    if addr.count("@") != 1:
        return False
    dom = addr.partition("@")[2]
    return any(addr == a if "@" in a else dom == a for a in allow)


def split_message(text: str) -> tuple[list[tuple[str, str]], str]:
    """(headers, body) of `himalaya message read --header …` output: header
    lines (folded continuations joined) up to the first blank line."""
    headers: list[tuple[str, str]] = []
    lines = text.splitlines()
    i = 0
    while i < len(lines) and lines[i].strip():
        line = lines[i]
        if line[:1] in (" ", "\t") and headers:
            name, value = headers[-1]
            headers[-1] = (name, f"{value} {line.strip()}")
        elif ":" in line:
            name, _sep, value = line.partition(":")
            headers.append((name.strip().lower(), value.strip()))
        i += 1
    return headers, "\n".join(lines[i + 1 :])


def dkim_pass(headers: list[tuple[str, str]], sender: str) -> bool:
    """The TOPMOST ``Authentication-Results`` (the receiving server's) says
    ``dkim=pass`` for the sender's domain (or a parent of it)."""
    results = [v for n, v in headers if n == "authentication-results"]
    if not results:
        return False
    domain = sender.rpartition("@")[2].lower()
    for part in results[0].split(";"):
        part = part.strip().lower()
        if not part.startswith("dkim=pass"):
            continue
        m = re.search(r"header\.(?:d|i)=@?([a-z0-9.-]+)", part)
        signed = m.group(1).strip(".") if m else ""
        if signed and (domain == signed or domain.endswith("." + signed)):
            return True
    return False


@dataclass
class MailReader:
    """Reads codes from Albert's mailbox through himalaya (no secret leaves:
    a code is returned to the caller only)."""

    himalaya: str
    account: str | None = None
    run: Callable[..., subprocess.CompletedProcess] = subprocess.run
    folders: tuple[str, ...] | None = None  # the baseline's readable folders

    def _cmd(self, *args: str) -> str | None:
        argv = [self.himalaya, *args]
        if self.account:
            argv += ["-a", self.account]
        try:
            res = self.run(
                argv, capture_output=True, text=True, timeout=30, check=False
            )
        except (OSError, subprocess.SubprocessError):
            return None
        return res.stdout if res.returncode == 0 else None

    def _folder(self, folder: str) -> list[dict] | None:
        raw = self._cmd(
            "envelope", "list", "--folder", folder, "--page-size", "30", "-o", "json"
        )
        data = None
        with contextlib.suppress(TypeError, ValueError):
            data = json.loads(raw) if raw is not None else None
        return (
            [e for e in data if isinstance(e, dict)] if isinstance(data, list) else None
        )

    def envelopes(self) -> list[tuple[str, str, dict]] | None:
        """(folder, id, envelope) of the newest mails; None when a folder
        that must answer did not (or, the first time, none answered)."""
        out: list[tuple[str, str, dict]] = []
        answered: list[str] = []
        for folder in self.folders or MAIL_FOLDERS:
            envs = self._folder(folder)
            if envs is None:
                if self.folders is not None:
                    return None
                continue
            answered.append(folder)
            out += [(folder, str(e.get("id")), e) for e in envs]
        if self.folders is None:
            if not answered:
                return None
            self.folders = tuple(answered)
        return out

    def message(self, folder: str, msg_id: str) -> str | None:
        """The message with its Authentication-Results header, read without
        marking it seen."""
        return self._cmd(
            "message",
            "read",
            msg_id,
            "--folder",
            folder,
            "--preview",
            "--header",
            "Authentication-Results",
        )


def is_login_mail(env: dict, step: Step, expected_to: str = "") -> bool:
    """A login-code mail of `step`: its subject holds one of the recipe's
    login subjects, ONE sender on the allow-list, and (with `expected_to`)
    addressed to that account. Product mail from the same sender fails the
    subject test; anything malformed fails."""
    subject = env.get("subject")
    if not isinstance(subject, str) or not any(
        s.lower() in subject.lower() for s in step.subjects
    ):
        return False
    state, frm = _addrs(env.get("from"))
    if state != "valid" or len(frm) != 1 or not sender_allowed(frm[0], step.senders):
        return False
    if not expected_to:
        return True
    to_state, to = _addrs(env.get("to"))
    return to_state == "valid" and expected_to.lower() in to


@dataclass
class Baseline:
    """Keyed digests (per-run random key, memory only) of every code already
    in the mailbox's login mails BEFORE the trigger: a mail moved to Archive
    under a new id still carries an old code and stays excluded."""

    key: bytes
    digests: set[str]

    def digest(self, code: str) -> str:
        return hmac.new(self.key, code.encode(), hashlib.sha256).hexdigest()


def _codes(
    reader: MailReader, step: Step, expected_to: str, *, signed: bool
) -> list[str] | None:
    """Every code in the login mails of `step` (None: a mail was unreadable).
    `signed`: only mails whose topmost Authentication-Results says dkim=pass
    for the sender's domain count."""
    envs = reader.envelopes()
    if envs is None:
        return None
    out: list[str] = []
    for folder, msg_id, env in envs:
        if not is_login_mail(env, step, expected_to):
            continue
        text = reader.message(folder, msg_id)
        if text is None:
            return None
        headers, body = split_message(text)
        sender = _addrs(env.get("from"))[1][0]
        if signed and not dkim_pass(headers, sender):
            continue
        out += re.findall(step.code_re, body)
    return out


def mail_baseline(reader: MailReader, step: Step) -> Baseline | None:
    """The baseline BEFORE the code is triggered (sender- and subject-based,
    any recipient, signed or not); None when unreadable — then no code is
    ever taken."""
    codes = _codes(reader, step, "", signed=False)
    if codes is None:
        return None
    base = Baseline(secrets.token_bytes(32), set())
    base.digests = {base.digest(c) for c in codes}
    return base


def find_code(
    reader: MailReader, baseline: Baseline, step: Step, expected_to: str
) -> tuple[str | None, str]:
    """(code, '') when the NEW, DKIM-signed login mails (not in the baseline)
    addressed to `expected_to` hold exactly ONE distinct code, else (None,
    why): ``no_mail`` (wait), ``email_code`` (several codes) or
    ``mailbox_unreadable``."""
    codes = _codes(reader, step, expected_to, signed=True)
    if codes is None:
        return None, "mailbox_unreadable"
    new = {c for c in codes if baseline.digest(c) not in baseline.digests}
    if len(new) == 1:
        return next(iter(new)), ""
    return None, "email_code" if new else "no_mail"


EMAIL_FILL_JS = r"""// agent-login:email
(() => {
  const P = __PARAMS__;
  const vis = (e) => !!e && e.getClientRects().length > 0;
  const field = [...document.querySelectorAll(P.field)].find(vis);
  if (!field) return JSON.stringify({ ok: false, why: "field" });
  const set = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set;
  set.call(field, P.email);
  for (const t of ["input", "change", "keyup"]) field.dispatchEvent(new Event(t, { bubbles: true }));
  return JSON.stringify({ ok: field.value === P.email });
})()
"""

CODE_FILL_JS = r"""// agent-login:code
(() => {
  const P = __PARAMS__;
  const vis = (e) => !!e && e.getClientRects().length > 0;
  const field = [...document.querySelectorAll(P.otp)].find(vis);
  if (!field) return JSON.stringify({ ok: false, why: "field" });
  const norm = (s) => String(s || "").replace(/\s+/g, " ").trim();
  const scope = field.form || document;
  const hits = P.submit ? [...scope.querySelectorAll('button,input[type="submit"]')]
    .filter((b) => vis(b) && (norm(b.innerText) === P.submit || norm(b.value) === P.submit)) : [];
  if (P.submit && hits.length !== 1) return JSON.stringify({ ok: false, why: "button" });
  const set = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set;
  set.call(field, P.code);
  for (const t of ["input", "change", "keyup"]) field.dispatchEvent(new Event(t, { bubbles: true }));
  if (field.value !== P.code) return JSON.stringify({ ok: false, why: "stick" });
  if (!P.submit) return JSON.stringify({ ok: true, clicked: false });
  hits[0].click();
  return JSON.stringify({ ok: true, clicked: true });
})()
"""


@contextlib.contextmanager
def private_js(body: str) -> Iterator[str]:
    """`body` in a 0600 temp file (created exclusively) for ``safari.py
    --eval FILE``, deleted in the `finally`."""
    fd, path = tempfile.mkstemp(prefix="agent-login-", suffix=".js")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(body)
        yield path
    finally:
        with contextlib.suppress(OSError):
            os.unlink(path)


# ---------------------------------------------------------------------------
# the step machine
# ---------------------------------------------------------------------------


@dataclass
class Plan:
    """What one run needs beyond the recipe: the resolved start page,
    sentinel and vault item, the overrides, a mail reader."""

    start_url: str
    sentinel: str
    item: str = ""
    account: str = ""
    expected_email: str = ""
    mail: MailReader | None = None


@dataclass
class Machine:  # pylint: disable=too-many-instance-attributes
    """One Safari login: open a new window, read the page, run steps."""

    recipe: Recipe
    plan: Plan
    call: Runner
    sleep: Callable[[float], None] = time.sleep
    clock: Callable[[], float] = time.monotonic
    clear_clip: Callable[[], None] = clear_clipboard
    handle: str = ""
    done: set[int] = field(default_factory=set)
    out: Outcome = field(default_factory=lambda: Outcome(2, "recipe_stuck"))
    baseline: Baseline | None = None

    # -- safari.py calls ---------------------------------------------------

    def _fail(self, reply: Reply) -> Outcome:
        code = error_code(reply)
        rc = (
            NEEDS_ALBERT_RC
            if code.startswith("needs_albert_")
            else BUSY_RC
            if code == "busy"
            else ENV_RC
            if code == "safari_unavailable"
            else 2
        )
        return self._end(rc, code)

    def _end(self, rc: int, code: str) -> Outcome:
        self.out.rc, self.out.code = rc, code
        return self.out

    def _on(self, host: str) -> list[str]:
        """The window handle + the host safari.py must find the tab on."""
        return ["--handle", self.handle, "--expect-host", host]

    def tab_host(self) -> tuple[str, str]:
        """(host of the login window's only tab, '' or a stop code)."""
        reply = self.call(["--tabs"])
        if reply.rc != 0:
            return "", error_code(reply)
        tabs = reply.data.get("tabs")
        if not isinstance(tabs, list):
            return "", "safari_tab_moved"
        mine = [
            t
            for t in tabs
            if isinstance(t, dict) and str(t.get("window_id")) == self.handle
        ]
        if len(mine) != 1:
            return "", "safari_tab_moved"
        url = str(mine[0].get("url") or "")
        if url in ("", "about:blank"):
            return "", ""  # still loading
        host = safe_host(url)
        if not host or host not in self.recipe.hosts:
            return "", "safari_tab_moved"
        return host, ""

    def read_page(self, host: str) -> dict[str, Any] | None:
        with private_js(detector_js(self.recipe, self.plan.sentinel)) as path:
            reply = self.call(["--eval", path, *self._on(host)])
        if reply.rc != 0:
            return None
        return parse_page(reply.data.get("result"), len(self.recipe.steps))

    # -- the run -------------------------------------------------------------

    def run(self) -> Outcome:
        """Open the login window, then read → stop / step / wait, bounded."""
        mail_steps = [s for s in self.recipe.steps if s.kind == "mail_code"]
        if mail_steps and self.plan.mail is not None:
            # BEFORE anything can trigger a code mail
            self.baseline = mail_baseline(self.plan.mail, mail_steps[0])
        reply = self.call(
            ["--open", self.plan.start_url, "--new-window", "--wait", str(WAIT_S)]
        )
        wid = reply.data.get("window_id")
        valid = isinstance(wid, int) and not isinstance(wid, bool) and wid > 0
        if valid:
            self.handle = str(wid)
        if reply.rc != 0:
            out = self._fail(reply)
            if valid:
                self.call(["--close", "--handle", self.handle])
            return out
        if not valid:
            # the window opened, but its id did not come back: it cannot be
            # addressed (or closed) safely — said so, nothing driven
            self.out.window_left = True
            return self._end(2, "safari_window_unknown")
        try:
            return self._loop()
        finally:
            self.call(["--close", "--handle", self.handle])

    def _loop(self) -> Outcome:  # pylint: disable=too-many-return-statements
        idle = 0
        for _ in range(MAX_POLLS):
            host, stop = self.tab_host()
            if stop:
                rc = (
                    NEEDS_ALBERT_RC
                    if stop.startswith("needs_albert_")
                    else ENV_RC
                    if stop == "safari_unavailable"
                    else BUSY_RC
                    if stop == "busy"
                    else 2
                )
                return self._end(rc, stop)
            page = self.read_page(host) if host else None
            if page is None:
                idle += 1
                if idle >= IDLE_POLLS + 2:
                    return self._end(2, "recipe_stuck")
                self.sleep(POLL_S)
                continue
            if page["sentinel"] and host == self.recipe.sentinel_host:
                return self._end(0, "ok")
            for flag in ALBERT_STOPS:
                if page[flag]:
                    return self._end(NEEDS_ALBERT_RC, f"needs_albert_{flag}")
            index = self._next_step(host, page)
            if index is None:
                if page["email_code"]:
                    return self._end(2, "email_code")
                idle += 1
                if idle >= IDLE_POLLS:
                    return self._end(2, "recipe_stuck")
                self.sleep(POLL_S)
                continue
            idle = 0
            stopped = self._run_step(index)
            if stopped is not None:
                return stopped
            self.sleep(POLL_S)
        return self._end(2, "recipe_stuck")

    def _next_step(self, host: str, page: dict[str, Any]) -> int | None:
        for i, step in enumerate(self.recipe.steps):
            if i in self.done or step.host != host:
                continue
            when, unless = page["steps"][i]
            if when and not unless:
                return i
        return None

    def _run_step(self, index: int) -> Outcome | None:
        """Run step `index` once; an Outcome when the run must stop."""
        step = self.recipe.steps[index]
        self.done.add(index)
        self.out.steps.append(step.kind)
        if step.kind == "mail_code":
            return self._mail_code(step)
        args = self._step_args(step)
        if args is None:
            return self._end(2, "identity_unconfigured")
        reply = self.call(args)
        if interrupted(reply) and step.kind in CLIPBOARD_KINDS:
            self.clear_clip()  # a secret may sit in the clipboard
        if step.kind in CREDENTIAL_KINDS and (reply.rc in (0, 1) or interrupted(reply)):
            # filled, maybe submitted: a later failure quarantines
            self.out.credential = True
        if reply.rc == 2 and step.optional and not interrupted(reply):
            return None  # refused before anything was copied: not offered here
        if reply.rc != 0:
            return self._fail(reply)
        return None

    def _step_args(self, step: Step) -> list[str] | None:
        on = self._on(step.host)
        if step.kind == "click":
            return ["--click", step.trigger, "--row", step.trigger, *on]
        if step.kind == "account":
            if not self.plan.account:
                return None
            return ["--click", self.plan.account, "--row", self.plan.account, *on]
        if step.kind == "otp":
            return ["--otp", self.plan.item, *on, "--submit", step.submit]
        if step.kind == "user":
            return [
                "--login",
                self.plan.item,
                *on,
                "--user-only",
                "--submit",
                step.submit,
            ]
        args = ["--login", self.plan.item, *on, "--submit", step.submit]  # login
        if step.no_user:
            args.append("--no-user")
        return args

    def _eval_ok(self, body: str, host: str) -> bool:
        """Run `body` in the login tab; True when it answered ``{"ok": true}``."""
        with private_js(body) as path:
            reply = self.call(["--eval", path, *self._on(host)])
        res = json_object(reply.data.get("result"))
        return reply.rc == 0 and res is not None and res.get("ok") is True

    # The mail-code step: one return per stage (e-mail, trigger, mail, code).
    def _mail_code(  # pylint: disable=too-many-return-statements
        self, step: Step
    ) -> Outcome | None:
        """E-mail → trigger → wait for ONE new signed code (the same in two
        consecutive polls) → fill it → submit."""
        reader = self.plan.mail
        if reader is None or self.baseline is None or not self.plan.expected_email:
            return self._end(2, "email_code")
        if step.email_field:
            params = {"field": step.email_field, "email": self.plan.expected_email}
            if not self._eval_ok(
                EMAIL_FILL_JS.replace("__PARAMS__", json.dumps(params)), step.host
            ):
                return self._end(2, "recipe_stuck")
        if step.trigger:
            reply = self.call(
                ["--click", step.trigger, "--row", step.trigger, *self._on(step.host)]
            )
            if reply.rc != 0:
                return self._fail(reply)
        code = self._wait_code(reader, step)
        if code is None:
            return self._end(2, "email_code")
        self.out.credential = True
        params = {"otp": _OTP_FIELD, "code": code, "submit": step.submit}
        body = CODE_FILL_JS.replace("__PARAMS__", json.dumps(params))
        try:
            # the RECIPE's host, never one read off the tab
            ok = self._eval_ok(body, step.host)
        finally:
            params.clear()
            del body
        return None if ok else self._end(2, "email_code")

    def _wait_code(self, reader: MailReader, step: Step) -> str | None:
        """The code once two consecutive polls agree on one new signed code."""
        assert self.baseline is not None
        deadline = self.clock() + MAIL_WAIT_S
        last: str | None = None
        while True:
            code, why = find_code(reader, self.baseline, step, self.plan.expected_email)
            if why not in ("", "no_mail"):
                return None
            if code is not None and code == last:
                return code
            last = code
            if self.clock() >= deadline:
                return None
            self.sleep(MAIL_POLL_S)


def scheduled() -> bool:
    """True inside an agent-login LaunchAgent (never drive Safari there)."""
    return bool(os.environ.get(SCHEDULED_ENV))  # any non-empty value


__all__ = [
    "MAGIC_LINK_SITES",
    "RECIPES",
    "Machine",
    "MailReader",
    "Outcome",
    "OverrideError",
    "Plan",
    "Recipe",
    "Reply",
    "Step",
    "available_features",
    "detector_js",
    "error_code",
    "features",
    "find_code",
    "interactive_gate",
    "load_overrides",
    "mail_baseline",
    "missing_features",
    "parse_page",
    "run_safari_py",
    "safari_py_bin",
    "safe_host",
    "scheduled",
]
