"""Inline analysis runs in the same credential-filtered, read-only OS boundary."""

from __future__ import annotations

import os
import sys
import tempfile
from collections.abc import Callable, Sequence
from pathlib import Path

from ..native_restricted_pytest import native_launch_plan, restricted_native
from .restricted_node_capabilities import linux_node_environment
from .restricted_pytest_model import (
    NODE_EVAL_READ_ONLY_PROFILE_VERSION,
    PYTHON_EVAL_READ_ONLY_PROFILE_VERSION,
    RestrictedPytestError,
    RestrictedPytestPlan,
)
from .restricted_pytest_sandbox import _backend_argv, _restricted_environment, _run_backend_process


def _test_script(script: str, *, node: bool = False) -> bool:
    return restricted_native("test_script", {"value": script, "node": node}, bool)


def _python_runtime_args(command: Sequence[str]) -> tuple[str, ...] | None:
    value = restricted_native("python_runtime_args", {"command": list(command)}, (list, type(None)))
    return tuple(value) if value is not None else None
