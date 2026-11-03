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
import contextlib
import importlib.util
import json
import os
import secrets
import sys
import time
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
    assert got["kw"] == {"before_trigger": hook}
    assert got["plan"].mail.env == env
    assert got["plan"].mail.env.get("SDSC_EMAIL_NO_AUTO_AUTH") == "1"
    # defaults: today's behaviour (no hook, himalaya inherits the environment)
    out = al._drive_safari("notion", recipe)
    assert got["kw"] == {"before_trigger": None}
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
