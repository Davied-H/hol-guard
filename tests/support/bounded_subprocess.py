"""Capture a child without a timed-out wait that can block forever.

On Windows, ``subprocess.run(..., capture_output=True, timeout=...)`` kills
the direct child and then drains its pipes with no second deadline. A
detached descendant that inherited those pipes never closes them, so the
caller never returns. Writing the child to files means the wait ends when
the direct child dies.
"""

from __future__ import annotations

import subprocess
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Literal, overload


@overload
def run_bounded(
    argv: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
    timeout: float,
    input: bytes | None = None,
    stdin: int | None = None,
    text: Literal[False] = False,
) -> subprocess.CompletedProcess[bytes]: ...


@overload
def run_bounded(
    argv: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
    timeout: float,
    input: bytes | None = None,
    stdin: int | None = None,
    text: Literal[True],
) -> subprocess.CompletedProcess[str]: ...


def run_bounded(
    argv: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
    timeout: float,
    input: bytes | None = None,
    stdin: int | None = None,
    text: bool = False,
) -> subprocess.CompletedProcess[str] | subprocess.CompletedProcess[bytes]:
    """Run ``argv`` and return its output. ``timeout`` is a hard deadline."""

    if input is not None and stdin is not None:
        raise ValueError("input and stdin are mutually exclusive")
    command = list(argv)
    with tempfile.TemporaryDirectory(prefix="bounded-stdio-") as directory:
        root = Path(directory)
        stdout_path = root / "stdout"
        stderr_path = root / "stderr"
        with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
            kwargs: dict[str, object] = {
                "env": dict(env),
                "cwd": cwd,
                "stdout": stdout,
                "stderr": stderr,
                "timeout": timeout,
                "check": False,
            }
            if input is not None:
                kwargs["input"] = input
            elif stdin is not None:
                kwargs["stdin"] = stdin
            completed = subprocess.run(command, **kwargs)
        captured_out = stdout_path.read_bytes()
        captured_err = stderr_path.read_bytes()
    if text:
        return subprocess.CompletedProcess(
            command,
            completed.returncode,
            captured_out.decode("utf-8", errors="replace"),
            captured_err.decode("utf-8", errors="replace"),
        )
    return subprocess.CompletedProcess(command, completed.returncode, captured_out, captured_err)
