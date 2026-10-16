"""The Windows CI capture helper must return when its deadline expires."""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from tests.support.bounded_subprocess import run_bounded


def test_bounded_run_returns_both_streams(tmp_path: Path) -> None:
    completed = run_bounded(
        [sys.executable, "-c", "import sys; sys.stdout.write('out'); sys.stderr.write('err')"],
        cwd=tmp_path,
        env=os.environ,
        timeout=10,
        text=True,
    )

    assert completed.returncode == 0
    assert completed.stdout == "out"
    assert completed.stderr == "err"


def test_bounded_run_timeout_returns_without_waiting_out_a_descendant(tmp_path: Path) -> None:
    """A grandchild holding the parent's stdout must not keep the wait open.

    ``capture_output=True`` on Windows drains pipes again after kill, with no
    deadline. This child exits immediately after spawning that grandchild.
    """

    script = """
import subprocess, sys, time
# Inherit stdout and outlive the parent. A pipe capture would stay open.
subprocess.Popen([sys.executable, "-c", "import time; time.sleep(8)"])
time.sleep(30)
"""
    started = time.monotonic()
    with pytest.raises(subprocess.TimeoutExpired):
        run_bounded(
            [sys.executable, "-c", script],
            cwd=tmp_path,
            env=os.environ,
            timeout=1,
        )

    assert time.monotonic() - started < 10
