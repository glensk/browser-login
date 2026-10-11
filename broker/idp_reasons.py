"""Reason codes from an identity provider's own answer to a submitted password.

Some IdPs show ONE text for several server answers: Galaxus' "Deine
Anmeldedaten sind nicht korrekt" stands for ``InvalidCredentials`` AND for
``Unknown`` (its bot check). Its JSON answer tells them apart, so the broker
records WHICH one (``diag["idp_reason"]``) and reports it as the failure code.

DORMANT while these hosts are no-submit (``vault.NO_SUBMIT_DOMAINS``): the broker
never submits a Galaxus password, so no answer to classify ever arrives. Kept as
diagnostics for the day a no-submit site is lifted (a code change, by design).

Allowlist only: a rule names the endpoint (https, exact hosts, path suffix, POST),
the JSON field and the enum values it knows; anything else is ignored. The value
is mapped to a fixed code (``broker/phases.py``) — the response itself never
leaves this module, and a body larger than ``MAX_BODY`` is not parsed.

Pure: no I/O, no Playwright (the runner hands over method, URL, status, body;
it keeps only FINISHED requests, so reading a body never waits for the network).
"""

from __future__ import annotations

import json
import urllib.parse
from dataclasses import dataclass

MAX_BODY = 64 * 1024
# How many matching responses a run keeps (the last one decides).
MAX_KEPT = 8


@dataclass(frozen=True)
class IdpReasonRule:
    """One IdP endpoint whose JSON answer names why a password was refused."""

    hosts: tuple[str, ...]  # exact https hosts (no subdomains)
    path_suffix: str  # the URL path ends with this (query ignored)
    field: str  # the top-level JSON key holding the enum
    codes: tuple[tuple[str, str], ...]  # (enum value, phase code)


RULES: tuple[IdpReasonRule, ...] = (
    # Digitec Galaxus IdPs (id.digitecgalaxus.ch, id.galaxus.eu): the password
    # page's POST; 2xx with {"error": ...} on a refused password.
    IdpReasonRule(
        hosts=("id.digitecgalaxus.ch", "id.galaxus.eu"),
        path_suffix="/api/v1/login/_actions/submit-password",
        field="error",
        codes=(
            ("InvalidCredentials", "idp_invalid_credentials"),
            ("Unknown", "idp_unknown"),
            ("CaptchaRequired", "captcha_required"),
        ),
    ),
)
CODES = frozenset(code for rule in RULES for _value, code in rule.codes)


def rule_for(method: str, url: str) -> IdpReasonRule | None:
    """The rule a request matches (POST to a known https endpoint), else None."""
    if str(method).upper() != "POST":
        return None
    try:
        parts = urllib.parse.urlsplit(str(url))
    except ValueError:
        return None
    if parts.scheme != "https":
        return None
    host = (parts.hostname or "").lower()
    return next(
        (r for r in RULES if host in r.hosts and parts.path.endswith(r.path_suffix)),
        None,
    )


def body_too_large(headers: object) -> bool:
    """True when a response's ``content-length`` says it exceeds ``MAX_BODY``
    (its body is then never fetched)."""
    try:
        raw = headers.get("content-length")  # type: ignore[attr-defined]
        return raw is not None and int(raw) > MAX_BODY
    except (AttributeError, TypeError, ValueError):
        return False


def classify(method: str, url: str, status: int, body: bytes | str) -> str | None:
    """The phase code of one IdP answer, or None (no rule, not 2xx, too large,
    not JSON, or a value outside the allowlist)."""
    rule = rule_for(method, url)
    if rule is None or not isinstance(status, int) or not 200 <= status < 300:
        return None
    if len(body) > MAX_BODY:
        return None
    try:
        data = json.loads(body)
    except (ValueError, TypeError):
        return None
    if not isinstance(data, dict):
        return None
    value = data.get(rule.field)
    if not isinstance(value, str):
        return None
    return dict(rule.codes).get(value)
