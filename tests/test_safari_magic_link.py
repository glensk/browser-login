"""tp#1644 B16: claude.ai / the Claude Console in Albert's Safari — the
magic link requested and opened in the Safari login window, the account
read, the held-account group. Hermetic: no network, no real Safari, no
mailbox (fakes from test_ws1b_safari)."""

from __future__ import annotations

import base64
import json
import os
import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
# pylint: disable=wrong-import-position

import test_ws1b_safari as w  # noqa: E402
from ws3_fixtures import load_script  # noqa: E402

import agent_login_safari as s  # noqa: E402

al = load_script("agent_login_tp1644_b16_test", "agent-login.py")

ME = "me@example.org"
RECIPE = s.MAGIC_LINK_RECIPES["anthropic"]
STEP = RECIPE.steps[0]
LOGIN = ("https://claude.ai/login", w._page(user=True, steps=[[True, False]]))
LANDED = ("https://claude.ai/new", w._page(sentinel=True))


def _link(email: str = ME) -> str:
    tail = base64.urlsafe_b64encode(email.encode()).decode().rstrip("=")
    return f"https://claude.ai/magic-link#{os.urandom(8).hex()}:{tail}"


class LinkSafari(w.FakeSafari):
    """Records e-mail fill, trigger and link open; the link never on argv."""

    def __init__(self, script: list, link: str) -> None:
        super().__init__(RECIPE, script)
        self.order: list[str] = []
        self.link = link
        self.modes: list[int] = []

    def __call__(self, args: list[str]) -> s.Reply:
        assert self.link not in " ".join(args)  # never on argv
        if args[0] == "--eval":
            body = Path(args[1]).read_text(encoding="utf-8")
            if "agent-login:email" in body:
                self.order.append("email")
                return s.Reply(0, {"result": json.dumps({"ok": True})})
            if "agent-login:link" in body:
                assert args[args.index("--expect-host") + 1] == "claude.ai"
                assert json.dumps(self.link) in body and "location.assign" in body
                self.modes.append(os.stat(args[1]).st_mode & 0o777)
                self.order.append("link")
                self.pos += 1
                return s.Reply(0, {"result": json.dumps({"ok": True})})
        if args[0] == "--click":
            self.order.append(f"click:{args[1]}")
            self.calls.append(list(args))
            return s.Reply(0, {"ok": True})
        return super().__call__(args)


def _box() -> w.FakeMailbox:
    return w.FakeMailbox()


def _mail(box: w.FakeMailbox, link: str) -> None:
    box.add(
        "INBOX",
        "5",
        f"Sign in: {link}\n",
        auth="mx; dkim=pass header.d=mail.anthropic.com",
        **{
            "from": {"addr": "no-reply-x1@mail.anthropic.com"},
            "to": [{"addr": ME}],
            "subject": "Your secure link to Claude.ai is here | 12:00",
        },
    )


def _run(link: str, mailed: str, **kw: Any) -> tuple[s.Outcome, LinkSafari, Any]:
    box = _box()
    fake = LinkSafari([LOGIN, LANDED], link)

    def sleep(_s: float) -> None:
        if not box.mails:
            _mail(box, mailed)

    plan = s.Plan(
        RECIPE.start_url,
        RECIPE.sentinel,
        expected_email=ME,
        mail=s.MailReader("himalaya-fake", run=box.run),
    )
    out = s.Machine(RECIPE, plan, fake, sleep=sleep, **kw).run()
    return out, fake, box


def test_the_link_is_requested_and_opened_in_the_login_window() -> None:
    link = _link()
    out, fake, box = _run(link, link)
    assert out.ok and out.credential
    assert fake.order == ["email", "click:Continue with email", "link"]
    assert fake.modes == [0o600]
    assert box.moves == [["--folder", "INBOX", "Archive", "5"]]  # archived
    assert out.mail_archived == "ok"


def test_a_link_for_another_account_is_never_opened() -> None:
    other = _link("someone@example.net")
    out, fake, box = _run(other, other)
    assert out.code == "email_code" and "link" not in fake.order
    assert not box.moves


def test_prove_only_on_the_login_page_reads_no_mail_and_types_nothing() -> None:
    link = _link()
    out, fake, box = _run(link, link, proof_only=True)
    assert out.code == "safari_logged_out"
    assert not fake.order and not box.mails


@pytest.mark.parametrize(
    ("link", "want"),
    [
        (_link(), ME),
        (_link() + "!", ""),
        ("https://claude.ai/magic-link#abc", ""),
        ("https://evil.example/magic-link#a:" + "bWVAZXhhbXBsZS5vcmc", ""),
    ],
)
def test_magic_link_email(link: str, want: str) -> None:
    assert s.magic_link_email(link, s.CLAUDE_LINK_RE) == want


def test_the_magic_link_recipes_are_safe_and_mail_driven() -> None:
    for site, recipe in s.MAGIC_LINK_RECIPES.items():
        assert site in s.MAGIC_LINK_SITES and site not in s.RECIPES
        assert not recipe.import_after and not recipe.broker
        assert [st.kind for st in recipe.steps] == ["magic_link"]
        assert al.has_mail_code(recipe)
        assert al.MAIL_CODE_ENV[site] == s.NOTION_MAIL_ENV
        assert al.SAFARI_ROUTES[site].proof == "in_safari"


def test_the_plan_defaults_to_the_shared_browsers_account_and_mailbox(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(al.shutil, "which", lambda _b: "/bin/himalaya-fake")
    plan = al._safari_plan("anthropic-private", RECIPE, {})
    assert plan is not None and plan.mail is not None
    assert plan.expected_email == al.CLAUDE_ACCOUNTS["anthropic-private"]
    assert plan.mail.account == al.MAGIC_LINK_MAILBOX["anthropic-private"][0]


def test_undecided_groups_route_nothing_and_only_prove(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(al, "SAFARI_HELD", {})
    monkeypatch.setattr(al, "resolve_site", lambda x: x)
    monkeypatch.setattr(s, "scheduled", lambda: False)
    for site in s.MAGIC_LINK_RECIPES:
        cols = al.login_columns(site)
        assert not cols.safari and not cols.safari_why  # ❌, not ⛔
        assert al.safari_target_action(site, "") == 2
    assert "not decided yet" in capsys.readouterr().out


def test_a_decided_group_routes_the_held_account_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(al, "SAFARI_HELD", {"claude": "anthropic"})
    assert al.safari_routed("anthropic")
    assert not al.safari_routed("anthropic-private")
    assert al.safari_why("anthropic-private", {}) == "second_account"
    assert not al.safari_routed("console")  # its own group: still undecided


@pytest.mark.parametrize(
    ("state", "stop"),
    [
        ("match", ""),
        ("other", "second_account"),
        ("mismatch", "wrong_account"),
        ("unknown", "indeterminate"),
        ("logged_out", "indeterminate"),
    ],
)
def test_the_account_read_names_the_held_account(
    state: str, stop: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(al, "IDENTITY_READ_POLL_S", 0)
    seen: list[str] = []

    def call(args: list[str]) -> s.Reply:
        body = Path(args[1]).read_text(encoding="utf-8")
        seen.append(" ".join(args))
        if "identity-start" in body:
            assert "/api/account" in body and json.dumps(ME) not in " ".join(args)
            return s.Reply(0, {"result": json.dumps({"ok": True})})
        return s.Reply(0, {"result": json.dumps({"state": state})})

    monkeypatch.setitem(al.MAGIC_LINK_ACCOUNTS, "anthropic", ME)
    read = al._claude_identity_reader("anthropic")
    assert read(call, ["--handle", "41", "--expect-host", "claude.ai"]) == stop
    assert all(a.startswith("--eval ") for a in seen)
