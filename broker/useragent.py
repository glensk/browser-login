"""Desktop-Chrome User-Agent that matches the installed Chromium engine.

Shared by the login broker (``broker/daemon.py``) and the shared-browser
driver (``bin/browser.py``): a UA whose version lags the engine is what bot
checks key on (Anubis raises its proof-of-work difficulty, Cloudflare answers
``HeadlessChrome`` with its challenge page).
"""

from __future__ import annotations

import plistlib
from pathlib import Path

CHROME_UA_TEMPLATE = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/{major}.0.0.0 Safari/537.36"
)


def engine_user_agent(executable: str) -> str | None:
    """The desktop-Chrome User-Agent for the Chromium at `executable` (its
    app bundle's ``CFBundleShortVersionString``), or None when unreadable."""
    plist = Path(executable).parent.parent / "Info.plist"
    try:
        with plist.open("rb") as fh:
            version = str(plistlib.load(fh).get("CFBundleShortVersionString") or "")
    except (OSError, ValueError, plistlib.InvalidFileException):
        return None
    major = version.split(".", 1)[0]
    if not major.isdigit():
        return None
    return CHROME_UA_TEMPLATE.format(major=major)
