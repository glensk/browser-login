"""tp#1643: Albert's Safari as a Notion login target (`agent-login.py -L notion -s`).

B1 the shared per-site code-mail cooldown (agent_login_state), B2 the
Machine's `before_trigger` hook, B3 `browser.py import-safari SITE -P`.
Hermetic: safari.py, himalaya, the proof context and the shared browser are
fakes; the state dir is a per-test temp dir (conftest). No credential-shaped
literals: codes and cookie values are generated per run.
"""

from __future__ import annotations

# pylint: disable=missing-function-docstring,import-error,wrong-import-position
# pylint: disable=protected-access,redefined-outer-name,unused-argument
# pylint: disable=too-many-lines
import contextlib
import importlib.util
import io
import json
import os
import secrets
import sys
import time
import unicodedata
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

sys.path[:0] = [
    str(Path(__file__).resolve().parent.parent),
    str(Path(__file__).resolve().parent),
]

import test_ws1b_safari as w  # noqa: E402
from ws3_fixtures import load_script  # noqa: E402

import agent_login_safari as alsafari  # noqa: E402
import agent_login_state as als  # noqa: E402
from broker import safari_cookies as sc  # noqa: E402

_BROWSER_PY = Path(__file__).resolve().parent.parent / "bin" / "browser.py"


def _load_browser() -> Any:
    spec = importlib.util.spec_from_file_location("browser_tp1643_test", _BROWSER_PY)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["browser_tp1643_test"] = mod
    spec.loader.exec_module(mod)
    return mod


browser = _load_browser()
al = load_script("agent_login_tp1643_test", "agent-login.py")


# ---------------------------------------------------------------------------
# B1: one cooldown for every route
# ---------------------------------------------------------------------------


def test_notion_keeps_its_existing_file_names() -> None:
    assert als.mail_code_file("notion") == "notion-mail-code.json"
    assert als.mail_code_lock_file("notion") == "notion-mail-code.lock"
    assert browser.NOTION_MAIL_CODE_FILE == "notion-mail-code.json"
    assert browser.NOTION_MAIL_CODE_LOCK == "notion-mail-code.lock"
    assert browser.NOTION_MAIL_CODE_COOLDOWN_S == als.MAIL_CODE_COOLDOWN_S == 900.0


def test_agent_login_has_no_mirror_of_its_own() -> None:
    for name in ("MAIL_CODE_STAMP", "MAIL_CODE_COOLDOWN_S", "_mail_code_cooldown_left"):
        assert not hasattr(al, name)


def test_browser_and_the_shared_module_read_the_same_stamp() -> None:
    now = time.time()
    assert als.mail_code_cooldown_left("notion", now) == 0.0
    assert browser._nmc_stamp(now)
    path = als.state_dir() / "notion-mail-code.json"
    assert path.stat().st_mode & 0o777 == 0o600
    assert als.mail_code_cooldown_left("notion", now + 100) == pytest.approx(800.0)
    assert als.mail_code_stamp("notion", now + 200)
    assert browser._nmc_cooldown_left(now + 300) == pytest.approx(800.0)


def test_the_cooldown_fails_closed() -> None:
    now = time.time()
    path = als.state_dir() / als.mail_code_file("notion")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{not json", encoding="utf-8")
    assert als.mail_code_cooldown_left("notion", now) is None
    path.write_text(json.dumps({"at": True}), encoding="utf-8")
    assert als.mail_code_cooldown_left("notion", now) is None
    path.write_text(json.dumps({"at": now + 60}), encoding="utf-8")  # future
    assert als.mail_code_cooldown_left("notion", now) == als.MAIL_CODE_COOLDOWN_S


def test_other_sites_get_their_own_files_and_bad_ids_nothing() -> None:
    now = time.time()
    assert als.mail_code_stamp("example", now)
    assert (als.state_dir() / "example-mail-code.json").is_file()
    assert als.mail_code_cooldown_left("notion", now) == 0.0
    assert als.mail_code_cooldown_left("../x", now) is None
    assert not als.mail_code_stamp("../x", now)
    with als.mail_code_lock("../x") as held:
        assert held is None


def test_the_lock_is_shared_with_browsers_lock() -> None:
    with als.mail_code_lock("notion") as held:
        assert held is True
        with browser._nmc_lock() as other:
            assert other is False
    with browser._nmc_lock() as again:
        assert again is True


# ---------------------------------------------------------------------------
# B2: the Machine's before_trigger hook
# ---------------------------------------------------------------------------


def _mail_machine(hook: Any) -> tuple[alsafari.Outcome, w.MailSafari, w.FakeMailbox]:
    box = w.FakeMailbox()
    code = w._code()
    script = [
        ("https://www.example.org/login", w._page(user=True, steps=[[True, False]])),
        w.CODE_PAGE,
        ("https://www.example.org/", w._page(sentinel=True)),
    ]
    fake = w.MailSafari(w.NOTION_LIKE, script, code)

    def sleep(_s: float) -> None:
        if not box.mails:
            box.add("INBOX", "9", f"code {code}")

    plan = w._plan(expected_email="me@example.org", mail=w._reader(box))
    out = alsafari.Machine(
        w.NOTION_LIKE, plan, fake, sleep=sleep, before_trigger=hook
    ).run()
    return out, fake, box


@pytest.mark.parametrize("stop", ["cooldown", "quarantined", "state_unwritable"])
def test_a_hook_code_ends_the_run_without_a_click(stop: str) -> None:
    out, fake, box = _mail_machine(lambda: stop)
    assert (out.rc, out.code) == (2, stop)
    assert not out.credential
    assert fake.order == ["email"]  # filled, never clicked, never a code
    assert not any(c[0] == "--click" for c in fake.calls)
    assert not box.moves


def test_a_hook_none_clicks_once() -> None:
    order: list[str] = []

    def hook() -> None:
        order.append("hook")

    out, fake, _box = _mail_machine(hook)
    assert out.ok
    assert fake.order == ["email", "click:Continue", "code"]
    assert order == ["hook"]  # called exactly once


def test_the_hook_runs_after_the_email_and_before_the_click() -> None:
    seen: list[list[str]] = []
    holder: dict[str, w.MailSafari] = {}
    box = w.FakeMailbox()
    code = w._code()
    script = [
        ("https://www.example.org/login", w._page(user=True, steps=[[True, False]])),
        w.CODE_PAGE,
        ("https://www.example.org/", w._page(sentinel=True)),
    ]
    holder["fake"] = w.MailSafari(w.NOTION_LIKE, script, code)

    def hook() -> None:
        seen.append(list(holder["fake"].order))

    def sleep(_s: float) -> None:
        if not box.mails:
            box.add("INBOX", "9", f"code {code}")

    plan = w._plan(expected_email="me@example.org", mail=w._reader(box))
    out = alsafari.Machine(
        w.NOTION_LIKE, plan, holder["fake"], sleep=sleep, before_trigger=hook
    ).run()
    assert out.ok
    assert seen == [["email"]]


def test_without_a_hook_the_machine_is_unchanged() -> None:
    out, fake, _box = _mail_machine(None)
    assert out.ok and fake.order == ["email", "click:Continue", "code"]


def test_drive_safari_passes_the_hook_and_the_mail_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    got: dict[str, Any] = {}

    class FakeMachine:  # pylint: disable=too-few-public-methods
        def __init__(self, recipe: Any, plan: Any, call: Any, **kw: Any) -> None:
            got.update(plan=plan, kw=kw)

        def run(self) -> alsafari.Outcome:
            return alsafari.Outcome(0, "ok")

    recipe = alsafari.RECIPES["notion"]
    monkeypatch.setattr(alsafari, "safari_py_bin", lambda: "safari-fake")
    monkeypatch.setattr(
        alsafari,
        "run_safari_py",
        lambda _b: lambda args: alsafari.Reply(0, {"javascript": True}),
    )
    monkeypatch.setattr(alsafari, "features", lambda _c: recipe.features())
    monkeypatch.setattr(
        alsafari, "load_overrides", lambda: {"notion": {"expected_email": "a@b.c"}}
    )
    monkeypatch.setattr(alsafari, "Machine", FakeMachine)
    monkeypatch.setattr(al.shutil, "which", lambda _n: "himalaya-fake")

    def hook() -> str | None:
        return None

    env = dict(alsafari.NOTION_MAIL_ENV)
    out = al._drive_safari("notion", recipe, env=env, before_trigger=hook)
    assert out.ok
    assert got["kw"] == {"before_trigger": hook, "no_trigger": ""}
    assert got["plan"].mail.env == env
    assert got["plan"].mail.env.get("SDSC_EMAIL_NO_AUTO_AUTH") == "1"
    # defaults: today's behaviour (no hook, himalaya inherits the environment)
    out = al._drive_safari("notion", recipe)
    assert got["kw"] == {"before_trigger": None, "no_trigger": ""}
    assert got["plan"].mail.env is None


# ---------------------------------------------------------------------------
# B3: browser.py import-safari SITE -P
# ---------------------------------------------------------------------------


def _token() -> sc.Cookie:
    return sc.Cookie(
        domain=".notion.so",
        name="token_v2",
        value=secrets.token_hex(8),
        path="/",
        expires=time.time() + 86400,
        secure=True,
        http_only=True,
    )


@pytest.fixture
def prove(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> dict[str, Any]:
    st: dict[str, Any] = {
        "verdict": "match",
        "up": True,
        "cookie": _token(),
        "calls": [],
        "result": tmp_path / "prove.json",
    }

    def forbidden(name: str) -> Any:
        def call(*_a: Any, **_k: Any) -> Any:
            raise AssertionError(f"{name} must not run under -P")

        return call

    for name in (
        "_builtin_replace",
        "_builtin_clear_storage",
        "_builtin_clear",
        "_record_login_event",
        "_access_team_sweep",
        "_builtin_state",
    ):
        monkeypatch.setattr(browser, name, forbidden(name))
    monkeypatch.setattr(browser, "_safari_site_cookies", lambda _s: ([st["cookie"]], 0))
    monkeypatch.setattr(
        browser, "_builtin_expected", lambda _s: ({"expected_email": "a@b.c"}, "")
    )
    monkeypatch.setattr(browser, "_is_up", lambda _p: st["up"])

    def register(*a: Any, **_k: Any) -> Any:
        st["calls"].append("register")
        return lambda: st["calls"].append("unregister")

    @contextlib.contextmanager
    def lease(purpose: str, *_a: Any) -> Iterator[str]:
        st["calls"].append(f"lease:{purpose}")
        yield "nonce"

    def prover(_port: int, site: str, cookies: Any, expected: Any) -> str:
        st["calls"].append("prove")
        if st["verdict"] == "raise":
            raise RuntimeError("attach failed")
        return str(st["verdict"])

    monkeypatch.setattr(browser, "_registry_register", register)
    monkeypatch.setattr(browser, "_interaction_lease", lease)
    monkeypatch.setattr(browser, "_builtin_prove_isolated", prover)
    return st


def _prove_run(st: dict[str, Any], site: str = "notion") -> tuple[int, dict]:
    rc = browser.cmd_import_safari(
        9, site, prove_only=True, result_file=str(st["result"])
    )
    return rc, json.loads(st["result"].read_text(encoding="utf-8"))


def test_prove_match_exits_0_and_never_touches_the_shared_jar(
    prove: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    rc, res = _prove_run(prove)
    assert rc == 0
    assert res["safari"] == "match" and res["code"] == "ok" and res["ok"] is True
    assert prove["calls"] == [
        "register",
        "lease:import-safari notion -P",
        "prove",
        "unregister",
    ]
    out = capsys.readouterr()
    text = out.out + out.err + prove["result"].read_text(encoding="utf-8")
    assert prove["cookie"].value not in text
    assert "safari: match" in out.out


@pytest.mark.parametrize(
    ("verdict", "code"),
    [
        ("logged_out", "logged_out"),
        ("mismatch", "wrong_account"),
        ("indeterminate", "indeterminate"),
        ("weird", "indeterminate"),
    ],
)
def test_prove_other_verdicts_exit_2(
    prove: dict[str, Any], verdict: str, code: str
) -> None:
    prove["verdict"] = verdict
    rc, res = _prove_run(prove)
    assert rc == 2
    assert res["code"] == code
    assert res["safari"] == (verdict if verdict != "weird" else "indeterminate")


def test_prove_a_failing_proof_context_is_indeterminate(prove: dict[str, Any]) -> None:
    prove["verdict"] = "raise"
    rc, res = _prove_run(prove)
    assert (rc, res["code"], res["safari"]) == (2, "indeterminate", "indeterminate")
    assert prove["calls"][-1] == "unregister"


def test_prove_a_non_builtin_site_exits_2_untouched(prove: dict[str, Any]) -> None:
    rc, res = _prove_run(prove, "galaxus")
    assert rc == 2 and res["code"] == "unknown_site"
    assert not prove["calls"]


def test_prove_with_the_shared_browser_down_is_one_line_indeterminate(
    prove: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    prove["up"] = False
    rc, res = _prove_run(prove)
    assert (rc, res["code"], res["safari"]) == (2, "indeterminate", "indeterminate")
    assert not prove["calls"]
    assert len(capsys.readouterr().err.strip().splitlines()) == 1


def test_prove_without_a_safari_session_is_logged_out(
    prove: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(browser, "_safari_site_cookies", lambda _s: ([], 0))
    rc, res = _prove_run(prove)
    assert (rc, res["code"], res["safari"]) == (2, "no_safari_session", "logged_out")
    assert not prove["calls"]


def test_prove_a_busy_gate_keeps_its_exit_code(
    prove: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    def busy(*_a: Any, **_k: Any) -> Any:
        sys.exit(browser.BUSY_RC)

    monkeypatch.setattr(browser, "_registry_register", busy)
    with pytest.raises(SystemExit) as exc:
        _prove_run(prove)
    assert exc.value.code == browser.BUSY_RC
    res = json.loads(prove["result"].read_text(encoding="utf-8"))
    assert res["rc"] == browser.BUSY_RC and res["code"] == "busy"


def test_prove_refuses_dry_run_and_agent(prove: dict[str, Any]) -> None:
    assert browser.cmd_import_safari(9, "notion", prove_only=True, dry_run=True) == 2
    assert browser.cmd_import_safari(9, "notion", prove_only=True, agent=True) == 2
    assert not prove["calls"]


def test_prove_only_parses_short_and_long(monkeypatch: pytest.MonkeyPatch) -> None:
    for flag in ("-P", "--prove-only"):
        monkeypatch.setattr(
            sys, "argv", ["browser.py", "import-safari", "notion", flag]
        )
        assert browser.parse_args().prove_only is True
    monkeypatch.setattr(sys, "argv", ["browser.py", "import-safari", "notion"])
    assert browser.parse_args().prove_only is False


def test_state_dir_is_private_to_the_test() -> None:
    # conftest points the state at a temp dir: no test here touches the real one
    assert als.state_dir() != Path.home() / ".local/state/agent-login"
    assert os.environ.get("AGENT_LOGIN_STATE_FILE")


# ---------------------------------------------------------------------------
# B6: the Machine's no-trigger mode and the lazy mailbox baseline
# ---------------------------------------------------------------------------


def _counting_box() -> tuple[w.FakeMailbox, list[list[str]]]:
    box = w.FakeMailbox()
    reads: list[list[str]] = []
    real = box.run

    def run(argv: list[str], **kw: Any) -> Any:
        reads.append(list(argv))
        return real(argv, **kw)

    box.run = run  # type: ignore[method-assign]
    return box, reads


_LOGIN_PAGE = (
    "https://www.example.org/login",
    w._page(user=True, steps=[[True, False]]),
)


def test_no_trigger_mode_reads_no_mail_and_never_clicks() -> None:
    box, reads = _counting_box()
    fake = w.MailSafari(w.NOTION_LIKE, [_LOGIN_PAGE], w._code())
    plan = w._plan(expected_email="me@example.org", mail=w._reader(box))
    out = alsafari.Machine(
        w.NOTION_LIKE, plan, fake, sleep=lambda _s: None, no_trigger="cooldown"
    ).run()
    assert (out.rc, out.code, out.credential) == (2, "cooldown", False)
    assert not reads and not fake.order
    assert not any(c[0] == "--click" for c in fake.calls)


@pytest.mark.parametrize(
    "mode", [{"no_trigger": "quarantined"}, {"before_trigger": lambda: None}]
)
def test_a_live_session_reaches_the_sentinel_without_a_mail_read(mode: dict) -> None:
    box, reads = _counting_box()
    script = [("https://www.example.org/", w._page(sentinel=True))]
    fake = w.MailSafari(w.NOTION_LIKE, script, w._code())
    plan = w._plan(expected_email="me@example.org", mail=w._reader(box))
    machine = alsafari.Machine(w.NOTION_LIKE, plan, fake, sleep=lambda _s: None, **mode)
    assert machine.run().ok and not reads


def test_an_unreadable_mailbox_stops_before_the_hook_writes() -> None:
    box = w.FakeMailbox()
    box.unreadable = True
    hooked: list[int] = []

    def hook() -> None:
        hooked.append(1)

    fake = w.MailSafari(w.NOTION_LIKE, [_LOGIN_PAGE], w._code())
    plan = w._plan(expected_email="me@example.org", mail=w._reader(box))
    out = alsafari.Machine(
        w.NOTION_LIKE, plan, fake, sleep=lambda _s: None, before_trigger=hook
    ).run()
    assert out.code == "email_code" and not hooked and not fake.order


# ---------------------------------------------------------------------------
# B4: login_columns
# ---------------------------------------------------------------------------


def test_login_columns(monkeypatch: pytest.MonkeyPatch) -> None:
    assert al.login_columns("notion") == al.LoginColumns(True, True)
    assert al.login_columns("anthropic") == al.LoginColumns(False, True)
    monkeypatch.setattr(al, "agent_route", lambda _s, _r=None: True)
    assert al.login_columns("galaxus") == al.LoginColumns(False, True)
    monkeypatch.setattr(al, "agent_route", lambda _s, _r=None: False)
    assert al.login_columns("galaxus") == al.LoginColumns(False, False)
    row = {"site": "shop", "status": "ready"}
    assert al.login_columns("shop", row) == al.LoginColumns(False, True)
    assert not al.login_columns("shop", {**row, "fill_only": True}).chromium
    assert not al.login_columns("shop", {**row, "status": "refused"}).chromium
    # a second route (non-mail-code recipe) is one table entry
    monkeypatch.setitem(
        al.SAFARI_ROUTES,
        "galaxus",
        al.SafariRoute("https://www.galaxus.ch/", "in_safari"),
    )
    assert al.login_columns("galaxus").safari
    host = alsafari.RECIPES["galaxus"].hosts[0]
    assert al.safari_target_url("galaxus", f"https://{host}/x") is not None


# ---------------------------------------------------------------------------
# B5: -s parsing and the target URL
# ---------------------------------------------------------------------------


def _parse(monkeypatch: pytest.MonkeyPatch, *argv: str) -> Any:
    monkeypatch.setattr(sys, "argv", ["agent-login.py", *argv])
    return al.build_parser().parse_args()


def test_in_safari_parses_short_long_and_bare(monkeypatch: pytest.MonkeyPatch) -> None:
    assert _parse(monkeypatch, "-L", "notion", "-s").in_safari == ""
    page = "https://app.notion.com/p"
    assert _parse(monkeypatch, "-L", "notion", "--in-safari", page).in_safari == page
    assert _parse(monkeypatch, "-L", "notion", "-s", "-n").dry_run is True
    args = _parse(monkeypatch, "--safari-login", "notion")
    assert args.in_safari is None and args.safari_login == "notion"


def test_in_safari_without_l_exits_2(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "argv", ["agent-login.py", "-s"])
    with pytest.raises(SystemExit) as exc:
        al.main()
    assert exc.value.code == 2


@pytest.mark.parametrize(
    "url",
    [
        "http://app.notion.com/",
        "https://example.com/",
        "https://user@app.notion.com/",
        "https://notion.so.evil.com/",
        "https://app.notion.com:8443/x",
        "https://app.notion.com:/x",
        "https://app.notion.com\\@evil.com/",
        "https:///x",
        "https://APP.notion.com/",
        "https://app.notion.com/ x",
    ],
)
def test_bad_url_exits_2_with_nothing_called(
    url: str, pipe: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    assert al.safari_target_url("notion", url) is None
    assert al.safari_target_action("notion", url) == 2
    assert "bad_url" in capsys.readouterr().out
    assert not pipe["log"]


def test_good_urls() -> None:
    assert al.safari_target_url("notion", "") == "https://app.notion.com/"
    page = "https://app.notion.com/p/renku/S3-40d0df2efafc8078835ad80c27f2f4d2"
    assert al.safari_target_url("notion", page) == page


def test_a_site_without_a_route_exits_2(pipe: dict[str, Any]) -> None:
    assert al.safari_target_action("galaxus", "") == 2
    assert not pipe["log"]


# ---------------------------------------------------------------------------
# B6: the -s pipeline (fakes for safari.py, browser.py, the Machine)
# ---------------------------------------------------------------------------


class _PipeMachine:  # pylint: disable=too-few-public-methods
    """The Safari Machine: scripted by `st["machine"]`, logs into `st["log"]`."""

    st: dict[str, Any] = {}

    def __init__(self, _r: Any, plan: Any, _c: Any, **kw: Any) -> None:
        self.hook = kw.get("before_trigger")
        self.no_trigger = kw.get("no_trigger", "")
        self.st["env"] = plan.mail.env if plan.mail else None

    def run(self) -> alsafari.Outcome:
        st = self.st
        st["log"].append(("machine", self.no_trigger))
        if st["machine"] == "sentinel":
            return alsafari.Outcome(0, "ok")
        if st["machine"] == "captcha":
            return alsafari.Outcome(4, "needs_albert_captcha")
        if self.no_trigger:
            return alsafari.Outcome(2, self.no_trigger, steps=["mail_code"])
        stop = self.hook() if self.hook else None
        if stop:
            return alsafari.Outcome(2, stop, steps=["mail_code"])
        left = als.mail_code_cooldown_left("notion", time.time())
        st["log"].append(("click", left))
        if st["machine"] == "no_sentinel":
            return alsafari.Outcome(
                2, "recipe_stuck", credential=True, steps=["mail_code"]
            )
        return alsafari.Outcome(
            0, "ok", credential=True, steps=["mail_code"], mail_archived="ok"
        )


@pytest.fixture
def pipe(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    st: dict[str, Any] = {
        "log": [],
        "jar": [_token()],
        "proof": (0, "match"),
        "free": (0, ""),
        "import_rc": 0,
        "open_rc": 0,
        "machine": "login",  # login | sentinel | captcha | no_sentinel
        "gate": None,
        "records": [],
    }
    recipe = alsafari.RECIPES["notion"]

    def call(args: list[str]) -> alsafari.Reply:
        if args[0] == "--status":
            return alsafari.Reply(0, {"javascript": True})
        if args[0] == "--open":
            st["log"].append(("open", args[1]))
            return alsafari.Reply(st["open_rc"], {})
        return alsafari.Reply(0, {})

    def run_browser(*args: Any, **_k: Any) -> Any:
        st["log"].append(("browser", args))
        rc, said = st["proof"]
        return al.BrowserRun(rc, False, "", 0.0, {"safari": said, "code": said})

    def import_run(_site: str, agent: bool) -> Any:
        st["log"].append(("import", agent))
        return al.BrowserRun(st["import_rc"], False, "", 0.0, {"code": "x"})

    def features(_c: Any) -> frozenset[str]:
        return alsafari.BASE_FEATURES | recipe.features()

    def free(_s: str) -> tuple[int, dict]:
        return st["free"][0], {"code": st["free"][1]}

    monkeypatch.setattr(_PipeMachine, "st", st)
    monkeypatch.setattr(alsafari, "scheduled", lambda: False)
    monkeypatch.setattr(alsafari, "interactive_gate", lambda *_a: st["gate"])
    monkeypatch.setattr(alsafari, "safari_py_bin", lambda: "safari-fake")
    monkeypatch.setattr(alsafari, "run_safari_py", lambda _b: call)
    monkeypatch.setattr(alsafari, "features", features)
    monkeypatch.setattr(
        alsafari, "load_overrides", lambda: {"notion": {"expected_email": "a@b.c"}}
    )
    monkeypatch.setattr(alsafari, "Machine", _PipeMachine)
    monkeypatch.setattr(al.shutil, "which", lambda _n: "himalaya-fake")
    monkeypatch.setattr(al, "_safari_jar", lambda _s: (list(st["jar"]), None))
    monkeypatch.setattr(al, "run_browser", run_browser)
    monkeypatch.setattr(al, "site_session", lambda _s: contextlib.nullcontext())
    monkeypatch.setattr(al, "_free_check", free)
    monkeypatch.setattr(al, "_import_run", import_run)
    monkeypatch.setattr(al, "_import_proof", lambda _s, r: dict(r or {}))
    monkeypatch.setattr(al, "_wait_flush", lambda _s, _b: True)
    monkeypatch.setattr(al, "record_check", lambda *a, **_k: st["records"].append(a))
    monkeypatch.setattr(al, "resolve_site", lambda s: s)
    return st


def _kinds(st: dict[str, Any]) -> list[str]:
    return [e[0] for e in st["log"]]


def _stamp_path() -> Path:
    return als.state_dir() / "notion-mail-code.json"


def test_match_opens_without_machine_mail_or_stamp(pipe: dict[str, Any]) -> None:
    assert al.safari_target_action("notion", "") == 0
    assert _kinds(pipe) == ["browser", "open"]
    assert pipe["log"][0][1][:3] == ("import-safari", "notion", "-P")
    assert pipe["log"][-1] == ("open", "https://app.notion.com/")
    assert not _stamp_path().exists()


def test_match_with_a_page_and_chromium_logged_out_imports(
    pipe: dict[str, Any],
) -> None:
    pipe["free"] = (2, "logged_out")
    page = "https://app.notion.com/p/x-40d0df2efafc8078835ad80c27f2f4d2"
    assert al.safari_target_action("notion", page) == 0
    assert _kinds(pipe) == ["browser", "import", "open"]
    assert pipe["log"][-1] == ("open", page)


def test_logged_out_logs_in_stamp_before_click_then_imports(
    pipe: dict[str, Any],
) -> None:
    pipe["proof"] = (2, "logged_out")
    pipe["free"] = (2, "logged_out")
    assert al.safari_target_action("notion", "") == 0
    assert _kinds(pipe) == ["browser", "machine", "click", "import", "open"]
    click = next(e for e in pipe["log"] if e[0] == "click")
    assert click[1] == pytest.approx(als.MAIL_CODE_COOLDOWN_S, abs=5)  # stamped first
    assert pipe["env"] == {"SDSC_EMAIL_NO_AUTO_AUTH": "1"}
    assert ("import", True) in pipe["log"]


def test_no_safari_session_logs_in_without_a_proof(pipe: dict[str, Any]) -> None:
    pipe["jar"] = []
    assert al.safari_target_action("notion", "") == 0
    assert _kinds(pipe) == ["machine", "click", "open"]


@pytest.mark.parametrize("block", ["cooldown", "quarantined", "unreadable"])
def test_a_block_runs_without_a_code_mail(
    pipe: dict[str, Any], block: str, capsys: pytest.CaptureFixture[str]
) -> None:
    pipe["proof"] = (2, "logged_out")
    path = _stamp_path()
    if block == "cooldown":
        assert als.mail_code_stamp("notion", time.time())
    elif block == "unreadable":
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{bad", encoding="utf-8")
    else:
        als.quarantine("notion", "submit", "recipe_stuck")
    before = path.read_bytes() if path.exists() else None
    assert al.safari_target_action("notion", "") == 2
    want = "quarantined" if block == "quarantined" else "cooldown"
    assert _kinds(pipe) == ["browser", "machine"]
    assert pipe["log"][1] == ("machine", want)
    assert (path.read_bytes() if path.exists() else None) == before
    assert want in capsys.readouterr().out
    # never a new quarantine for a block
    assert (als.quarantined("notion") is not None) == (block == "quarantined")


def test_a_block_with_a_live_session_still_opens(pipe: dict[str, Any]) -> None:
    pipe["proof"] = (2, "logged_out")
    pipe["machine"] = "sentinel"
    assert als.mail_code_stamp("notion", time.time())
    assert al.safari_target_action("notion", "") == 0
    assert _kinds(pipe) == ["browser", "machine", "open"]


def test_the_mail_code_lock_busy_is_75(pipe: dict[str, Any]) -> None:
    pipe["proof"] = (2, "logged_out")
    with als.mail_code_lock("notion") as held:
        assert held
        assert al.safari_target_action("notion", "") == al.BUSY_RC
    assert "machine" not in _kinds(pipe)


def test_an_unwritable_stamp_never_clicks(
    pipe: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    pipe["proof"] = (2, "logged_out")
    monkeypatch.setattr(als, "mail_code_stamp", lambda *_a: False)
    assert al.safari_target_action("notion", "") == 2
    assert "click" not in _kinds(pipe) and "open" not in _kinds(pipe)


def test_mismatch_is_wrong_account(
    pipe: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    pipe["proof"] = (2, "mismatch")
    assert al.safari_target_action("notion", "") == 2
    assert "wrong_account" in capsys.readouterr().out
    assert _kinds(pipe) == ["browser"]


@pytest.mark.parametrize(("proof", "rc"), [((2, "indeterminate"), 2), ((75, ""), 75)])
def test_a_proof_that_cannot_tell_stops(
    pipe: dict[str, Any], proof: tuple, rc: int
) -> None:
    pipe["proof"] = proof
    assert al.safari_target_action("notion", "") == rc
    assert _kinds(pipe) == ["browser"]


@pytest.mark.parametrize("gate", ["console_locked", "albert_idle", "not_on_console"])
def test_a_closed_gate_is_3_with_nothing_called(
    pipe: dict[str, Any], gate: str
) -> None:
    pipe["gate"] = gate
    assert al.safari_target_action("notion", "") == 3
    assert not pipe["log"]


def test_scheduled_is_2(pipe: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(alsafari, "scheduled", lambda: True)
    assert al.safari_target_action("notion", "") == 2
    assert not pipe["log"]


def test_safari_py_missing_or_without_open_is_3(
    pipe: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(alsafari, "safari_py_bin", lambda: None)
    assert al.safari_target_action("notion", "") == 3
    monkeypatch.setattr(alsafari, "safari_py_bin", lambda: "safari-fake")
    lacking = alsafari.RECIPES["notion"].features() - {"open"}
    monkeypatch.setattr(alsafari, "features", lambda _c: lacking)
    assert al.safari_target_action("notion", "") == 3
    assert not pipe["log"]


def test_needs_albert_is_4_without_open(pipe: dict[str, Any]) -> None:
    pipe["proof"] = (2, "logged_out")
    pipe["machine"] = "captcha"
    assert al.safari_target_action("notion", "") == 4
    assert "open" not in _kinds(pipe)


def test_a_credential_then_no_sentinel_quarantines_once(pipe: dict[str, Any]) -> None:
    pipe["proof"] = (2, "logged_out")
    pipe["machine"] = "no_sentinel"
    assert al.safari_target_action("notion", "") == 2
    assert als.quarantined("notion") is not None
    assert "open" not in _kinds(pipe)
    assert pipe["records"][-1][3]["route"] == "safari-target"


def test_open_failure_is_safari_open_failed(
    pipe: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    pipe["open_rc"] = 3
    assert al.safari_target_action("notion", "") == 2
    assert "safari_open_failed" in capsys.readouterr().out


def test_an_import_failure_still_opens(pipe: dict[str, Any]) -> None:
    pipe["free"] = (2, "logged_out")
    pipe["import_rc"] = 2
    assert al.safari_target_action("notion", "") == 0
    assert _kinds(pipe) == ["browser", "import", "open"]


def _dry(
    pipe: dict[str, Any], monkeypatch: pytest.MonkeyPatch, site: str = "notion"
) -> tuple[str, list[str]]:
    """`-L SITE -s -n` with every safari.py argument recorded; (stdout, args)."""
    seen: list[str] = []
    inner = alsafari.run_safari_py("safari-fake")

    def call(args: list[str]) -> alsafari.Reply:
        seen.append(args[0])
        return inner(args)

    def features(c: Any) -> frozenset[str]:
        c(["--capabilities"])
        return alsafari.BASE_FEATURES | alsafari.RECIPES[site].features()

    monkeypatch.setattr(alsafari, "run_safari_py", lambda _b: call)
    monkeypatch.setattr(alsafari, "features", features)
    monkeypatch.setattr(al, "_mail_code_dry_run", lambda s: print(f"MAILBOX {s}"))
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        assert al.safari_target_action(site, "", dry_run=True) == 0
    return out.getvalue(), seen


def test_dry_run_calls_nothing(
    pipe: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    text, seen = _dry(pipe, monkeypatch)
    # no -P proof, no Machine, no -o, no import, no record, no stamp
    assert not pipe["log"] and not pipe["records"]
    assert set(seen) <= {"--capabilities", "--status"}
    assert not _stamp_path().exists()
    assert "▶ notion: Safari target https://app.notion.com (the landing page)" in text
    assert "interactive gate open" in text and "safari.py ready" in text
    assert "safari fp: " in text and "not quarantined" in text
    assert "MAILBOX notion" in text
    assert "-s would prove Safari's session" in text
    assert pipe["jar"][0].value not in text


@pytest.mark.parametrize(
    ("setup", "want"),
    [
        ("no_session", "-s would log Safari in with the e-mail code, then open"),
        ("cooldown", "-s would try Safari without a code mail (cooldown)"),
        ("quarantined", "-s would try Safari without a code mail (quarantined)"),
        ("gate", "-s would stop with exit 3 (console_locked)"),
        ("old_safari_py", "-s would stop with exit 3 (safari_py_outdated)"),
    ],
)
def test_dry_run_names_the_next_step(
    pipe: dict[str, Any], monkeypatch: pytest.MonkeyPatch, setup: str, want: str
) -> None:
    pipe["jar"] = []
    if setup == "cooldown":
        assert als.mail_code_stamp("notion", time.time())
    elif setup == "quarantined":
        als.quarantine("notion", "submit", "recipe_stuck")
    elif setup == "gate":
        pipe["gate"] = "console_locked"
    stamp = _stamp_path().read_bytes() if _stamp_path().exists() else None
    if setup == "old_safari_py":
        monkeypatch.setattr(alsafari, "features", lambda _c: frozenset())
        monkeypatch.setattr(al, "_mail_code_dry_run", lambda _s: None)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            assert al.safari_target_action("notion", "", dry_run=True) == 0
        text = out.getvalue()
    else:
        text, _seen = _dry(pipe, monkeypatch)
    assert want in text
    assert not pipe["log"]
    assert (_stamp_path().read_bytes() if _stamp_path().exists() else None) == stamp


def test_no_secret_in_output(
    pipe: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    pipe["proof"] = (2, "logged_out")
    cookie = pipe["jar"][0].value
    assert al.safari_target_action("notion", "") == 0
    out = capsys.readouterr()
    assert cookie not in out.out + out.err + repr(pipe["records"])
    for f in als.state_dir().rglob("*"):
        if f.is_file():
            assert cookie not in f.read_text(encoding="utf-8", errors="replace")


# the -L notion fallback goes through the same drive


def test_the_fallback_honours_the_cooldown(pipe: dict[str, Any]) -> None:
    assert als.mail_code_stamp("notion", time.time())
    assert al._safari_drive_stage("notion", alsafari.RECIPES["notion"], "fp") == 2
    assert ("machine", "cooldown") in pipe["log"] and "click" not in _kinds(pipe)


def test_the_fallback_stamps_before_the_trigger_with_the_mail_env(
    pipe: dict[str, Any],
) -> None:
    assert al._safari_drive_stage("notion", alsafari.RECIPES["notion"], "fp") == 0
    click = next(e for e in pipe["log"] if e[0] == "click")
    assert click[1] == pytest.approx(als.MAIL_CODE_COOLDOWN_S, abs=5)
    assert pipe["env"] == {"SDSC_EMAIL_NO_AUTO_AUTH": "1"}


# ---------------------------------------------------------------------------
# B7/B9: a second route is one SAFARI_ROUTES entry; overview, -j, agents.md
# ---------------------------------------------------------------------------


def test_a_second_route_is_one_table_entry(
    pipe: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    site = "galaxus"  # a recipe without a mail_code step
    assert not any(s.kind == "mail_code" for s in alsafari.RECIPES[site].steps)
    assert not al.login_columns(site).safari
    host = alsafari.RECIPES[site].hosts[0]
    monkeypatch.setitem(
        al.SAFARI_ROUTES, site, al.SafariRoute(f"https://{host}/", "in_safari")
    )
    assert al.login_columns(site).safari
    text, _seen = _dry(pipe, monkeypatch, site)
    assert f"▶ {site}: Safari target https://{host} (the landing page)" in text
    assert "no_safari_route" not in text and "MAILBOX" not in text
    assert not pipe["log"]
    assert f"`agent-login.py -L {site} -s`" in al.safari_route_sentence()


def _width(text: str) -> int:
    """Terminal columns of `text` (wide emoji 2, variation selectors 0)."""
    return sum(
        0
        if unicodedata.combining(ch) or ch == "️"
        else 2
        if unicodedata.east_asian_width(ch) in "WF"
        else 1
        for ch in text
    )


def _rows() -> list[dict[str, Any]]:
    return [
        {"site": "notion", "name": "Notion", "status": "assisted"},
        {"site": "anthropic", "name": "claude.ai", "status": "assisted"},
        {"site": "shop", "name": "A shop with a long name", "status": "ready"},
        {"site": "plain", "name": "Plain", "status": "refused"},
    ]


def test_overview_columns_align_with_a_legend(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(al, "USE", False)
    monkeypatch.setattr(al, "last_checks", dict)
    monkeypatch.setattr(al, "_row_flags", lambda _r: "")
    states = {"notion": "ok", "anthropic": "failed", "shop": "ok", "plain": "failed"}
    monkeypatch.setattr(al, "row_state", lambda r, _c: (states[r["site"]], "WHY"))
    data = {"rows": _rows(), "broker_ok": True, "broker": "running"}
    al.print_overview(data)
    lines = capsys.readouterr().out.splitlines()
    head = next(i for i, x in enumerate(lines) if "agent_fill_origins" in x)
    header = lines[head]
    assert "  Safari  Chromium  agent_fill_origins  status" in header
    assert lines[head + 1].strip() == al.LOGIN_COLUMNS_LEGEND
    body = lines[head + 2 : head + 2 + len(states)]
    # every column up to the status text ends at the same terminal column
    want = _width(header) - len("status")
    assert [_width(x) - len("WHY") for x in body] == [want] * len(states)
    cells = {x.split()[1]: x.split()[2:4] for x in body if x.split()[1] != "A"}
    assert cells == {
        "Notion": ["✅", "✅"],
        "claude.ai": ["❌", "✅"],
        "Plain": ["❌", "❌"],
    }
    shop = next(x for x in body if "A shop" in x)
    assert shop.split("A shop with a long name")[1].split()[:2] == ["❌", "✅"]


def test_json_rows_carry_login_columns(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    data = {"rows": _rows(), "broker_ok": True, "broker": "running"}
    monkeypatch.setattr(al, "overview", lambda **_k: data)
    monkeypatch.setattr(al, "write_agent_summary", lambda *_a: None)
    monkeypatch.setattr(al.agent_login_cred, "load", lambda: {})
    monkeypatch.setattr(al.agent_login_cred, "summary", lambda _c: {})
    monkeypatch.setattr(sys, "argv", ["agent-login.py", "-j"])
    assert al.main() == 0
    rows = {r["site"]: r for r in json.loads(capsys.readouterr().out)["rows"]}
    assert rows["notion"]["login_columns"] == {
        "safari": True,
        "chromium": True,
        "safari_why": "",
    }
    assert rows["anthropic"]["login_columns"] == {
        "safari": False,
        "chromium": True,
        "safari_why": "",
    }
    assert rows["shop"]["login_columns"] == {
        "safari": False,
        "chromium": True,
        "safari_why": "",
    }
    assert rows["plain"]["login_columns"] == {
        "safari": False,
        "chromium": False,
        "safari_why": "",
    }


def test_agents_md_names_the_safari_route_from_the_table(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data = {"rows": [], "broker_ok": True, "broker": "running"}
    text = al.agent_summary(data, {})
    assert (
        "Albert says 'log me into notion' → run `agent-login.py -L notion -s`" in text
    )
    # the site list is the table, not the text
    monkeypatch.setattr(al, "SAFARI_ROUTES", {})
    assert "-s`" not in al.agent_summary(data, {})
    assert al._route_header([]).startswith("for the other sites")
