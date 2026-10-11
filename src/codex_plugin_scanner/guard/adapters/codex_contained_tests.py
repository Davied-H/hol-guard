"""Route Codex contained-test receipts through the PreToolUse ``updatedInput`` rewrite.

Codex applies ``permissionDecision: "allow"`` with ``updatedInput`` from 0.131.0.
Older releases treat that output as an unsupported hook result and run the
original command, so the bridge rewrites only after it has confirmed the Codex
process that launched it is new enough. Otherwise the denial stands.
"""

from __future__ import annotations

import ctypes
import json
import os
import re
import subprocess
import sys
from pathlib import Path

from .zcode_contained_tests import contained_zcode_response

_MIN_VERSION = (0, 131, 0)
_MAX_ANCESTORS = 6
_PROC_PIDTBSDINFO = 3
_PROC_BSDINFO_SIZE = 136
_PPID_OFFSET = 16
_VERSION = re.compile(r"^codex-cli (\d+)\.(\d+)\.(\d+)(-[0-9A-Za-z.-]+)?\s*$")
UPDATE_HINT = "Update Codex to 0.131 or later so HOL Guard can run this test inside its contained runner."


def route_codex_containment(
    response: dict[str, object],
    *,
    hook_input: str,
    guard_home: Path | None,
) -> dict[str, object]:
    """Rewrite a containment receipt into the contained sink, or keep the denial."""

    if (
        sys.platform != "darwin"
        or guard_home is None
        or response.get("policy_action") != "sandbox-required"
        or response.get("decision") != "deny"
    ):
        return response
    try:
        payload = json.loads(hook_input)
    except ValueError:
        return response
    if not isinstance(payload, dict) or payload.get("guard_containment_receipt_only") is True:
        return response
    executable = launching_codex_executable()
    if executable is None or not codex_applies_updated_input(executable):
        return _with_update_hint(response)
    routed = contained_zcode_response(
        response,
        input_text=json.dumps(payload),
        config={
            "harness": "codex",
            "guard_home": str(guard_home),
            "python_executable": sys.executable,
            "package_root": str(Path(__file__).resolve().parents[3]),
        },
        cli_args=["--home", str(Path.home())],
    )
    return routed if routed is not None else response


def launching_codex_executable() -> Path | None:
    """Path of the nearest ``codex`` ancestor process, read from the kernel."""

    try:
        libproc = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
    except OSError:
        return None
    pid = os.getppid()
    for _ in range(_MAX_ANCESTORS):
        if pid <= 1:
            return None
        path_buffer = ctypes.create_string_buffer(4096)
        if libproc.proc_pidpath(pid, path_buffer, len(path_buffer)) <= 0:
            return None
        path = Path(os.fsdecode(path_buffer.value))
        if path.name == "codex":
            return path
        info = ctypes.create_string_buffer(_PROC_BSDINFO_SIZE)
        size = libproc.proc_pidinfo(pid, _PROC_PIDTBSDINFO, ctypes.c_uint64(0), info, _PROC_BSDINFO_SIZE)
        if size != _PROC_BSDINFO_SIZE:
            return None
        pid = int.from_bytes(info.raw[_PPID_OFFSET : _PPID_OFFSET + 4], sys.byteorder)
    return None


def codex_applies_updated_input(executable: Path) -> bool:
    """True when ``codex --version`` reports a release that applies ``updatedInput``."""

    try:
        result = subprocess.run(
            [os.fspath(executable), "--version"],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
            stdin=subprocess.DEVNULL,
            env={"PATH": "/usr/bin:/bin", "HOME": str(Path.home())},
        )
    except (OSError, subprocess.SubprocessError):
        return False
    match = _VERSION.match(result.stdout.strip()) if result.returncode == 0 else None
    if match is None:
        return False
    version = tuple(int(part) for part in match.group(1, 2, 3))
    # A 0.131.0 pre-release may predate the rewrite support.
    return version > _MIN_VERSION or (version == _MIN_VERSION and match.group(4) is None)


def _with_update_hint(response: dict[str, object]) -> dict[str, object]:
    hook_output = response.get("hookSpecificOutput")
    if not isinstance(hook_output, dict):
        return response
    reason = hook_output.get("permissionDecisionReason")
    text = f"{reason} {UPDATE_HINT}" if isinstance(reason, str) and reason else UPDATE_HINT
    return {**response, "hookSpecificOutput": {**hook_output, "permissionDecisionReason": text}}


__all__ = [
    "UPDATE_HINT",
    "codex_applies_updated_input",
    "launching_codex_executable",
    "route_codex_containment",
]
