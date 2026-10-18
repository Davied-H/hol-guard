"""Declarative shape of a false-positive regression case: staged files, PATH stubs and output checks.

Each case replays shell commands that earlier Guard fixes stopped reviewing. The workspace and
HOME files give those commands something real to touch, a stub stands in for any toolchain or
service the host may not carry (it prints fixed text and never opens a socket), and the output
and filesystem checks bind the pass to what the commands produced, not to an exit status.
"""

from __future__ import annotations

import os
import re
import shlex
import subprocess
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

# One stub answer: the exact argument string it recognizes and the exact text it prints.
Rule = tuple[str, str]
# Expected command output: exact text, a pattern that must occur, a predicate, or None for
# commands that print nothing worth binding (their effects are checked on disk instead).
Output = str | re.Pattern[str] | Callable[[str], bool] | None
Check = Callable[[Path, Path], bool]


@dataclass(frozen=True)
class FpCase:
    outputs: tuple[Output, ...]
    files: Mapping[str, str] = field(default_factory=dict)
    executables: Mapping[str, str] = field(default_factory=dict)
    home_files: Mapping[str, str] = field(default_factory=dict)
    stubs: Mapping[str, Sequence[Rule]] = field(default_factory=dict)
    repositories: tuple[str, ...] = ()
    environment: Mapping[str, str] = field(default_factory=dict)
    checks: Mapping[str, Check] = field(default_factory=dict)
    # Commands that exit non-zero by design, such as probing a path that does not exist.
    expected_failures: frozenset[str] = frozenset()
    # Extra setup the plain files cannot express, run last with the workspace and HOME.
    setup: Callable[[Path, Path], None] | None = None


def stub_script(rules: Sequence[Rule]) -> str:
    """A POSIX program that answers each listed argument string and rejects every other call."""
    lines = ["#!/bin/sh", 'case "$*" in']
    for arguments, output in rules:
        if not output.endswith("\n"):
            raise ValueError("stub output must end with a newline: " + arguments)
        lines.append(f"{shlex.quote(arguments)})\ncat <<'STUB_OUTPUT'\n{output}STUB_OUTPUT\n;;")
    lines.extend(["*)", 'printf "stub: unexpected arguments: %s\\n" "$*" >&2', "exit 64", ";;", "esac"])
    return "\n".join(lines) + "\n"


def write_text(path: Path, text: str, *, executable: bool = False) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")
    if executable:
        path.chmod(0o700)


def init_repository(path: Path, environment: Mapping[str, str]) -> None:
    """Make an existing directory a Git working tree without committing anything."""
    subprocess.run(
        ["git", "-C", str(path), "init", "--quiet"],
        env=dict(environment),
        check=True,
        capture_output=True,
        timeout=15,
    )


def stage_case(case: FpCase, workspace: Path, home: Path, bin_dir: Path) -> None:
    """Write one case's files, executables, stubs and repositories under the disposable fixture."""
    for relative, text in case.files.items():
        write_text(workspace / relative, text)
    for relative, text in case.executables.items():
        write_text(workspace / relative, text, executable=True)
    for relative, text in case.home_files.items():
        write_text(home / relative, text)
    for name, rules in case.stubs.items():
        write_text(bin_dir / name, stub_script(rules), executable=True)
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(home),
        "GIT_CONFIG_NOSYSTEM": "1",
    }
    for relative in case.repositories:
        init_repository(home / relative, environment)
    if case.setup is not None:
        case.setup(workspace, home)


def output_matches(expected: Output, text: str | None) -> bool:
    if expected is None:
        return True
    if text is None:
        return False
    if isinstance(expected, str):
        return text == expected
    if isinstance(expected, re.Pattern):
        return expected.search(text) is not None
    return bool(expected(text))


def exact_file(path: Path, expected: str) -> bool:
    """A regular, non-symlink file holding exactly the expected text."""
    try:
        return path.is_file() and not path.is_symlink() and path.read_text(encoding="utf-8") == expected
    except (OSError, UnicodeError):
        return False


def absent(path: Path) -> bool:
    return not path.exists() and not path.is_symlink()
