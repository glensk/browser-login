"""The conftest guard refuses `security`/`op`/`himalaya`, lets anything else run."""

from __future__ import annotations

# pylint: disable=import-error,missing-function-docstring
import subprocess
import sys

import pytest
from conftest import DeniedSubprocess


@pytest.mark.parametrize(
    "argv",
    [
        ["security", "find-generic-password", "-s", "x"],
        ["/usr/bin/security", "-i"],
        ["op", "item", "get", "CSCS"],
        ["/opt/homebrew/bin/himalaya", "envelope", "list"],
        "security dump-keychain",
    ],
)
def test_credential_tools_are_denied(argv):
    with pytest.raises(DeniedSubprocess):
        subprocess.run(argv, check=False)
    with pytest.raises(DeniedSubprocess):
        subprocess.Popen(argv)  # pylint: disable=consider-using-with


def test_other_programs_still_run():
    res = subprocess.run(
        [sys.executable, "-c", "print('ok')"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert res.stdout.strip() == "ok"
