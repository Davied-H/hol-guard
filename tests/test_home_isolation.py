"""The test session must never resolve the developer's real home."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def test_session_home_is_private():
    private_home = os.environ["HOL_GUARD_TEST_PRIVATE_HOME"]

    assert str(Path.home()) == private_home
    assert Path("~").expanduser() == Path(private_home)
    assert "CODEX_HOME" not in os.environ
    assert "HOL_GUARD_HOME" not in os.environ


def test_spawned_helpers_inherit_private_home():
    completed = subprocess.run(
        [sys.executable, "-c", "from pathlib import Path; print(Path.home())"],
        capture_output=True,
        text=True,
        check=True,
    )

    assert completed.stdout.strip() == os.environ["HOL_GUARD_TEST_PRIVATE_HOME"]
