"""Privacy-safe native availability diagnostics, separate from hook readiness."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Literal, TypedDict

from ..adapters.diagnostic_probes import skipped_command_probe
from ..native_policy_snapshot_constants import NATIVE_RUNTIME_STATE_DIRECTORY
from ..resident_state_prune import pid_is_alive, probe_owner_lock


class _NativeAvailabilityFields(TypedDict):
    mode: Literal["off", "shadow", "auto", "force", "unknown"]
    available: bool | None
    compatible: bool | None
    reason_code: str
    evaluation_verified: Literal[False]


class NativeAvailabilityResult(_NativeAvailabilityFields, total=False):
    message: str


_MAX_STATE_BYTES = 64 * 1024

# Two Guard installs (for example a desktop app and a package-manager CLI) share
# one home-wide resident. Only one owns it; the other is healthy, not broken.
_REASON_MESSAGES = {
    "native_resident_owner_busy": (
        "Another Guard install on this account owns the native resident runtime, so this "
        "install cannot start its own. Nothing crashed and no restarts were used. Keep one "
        "Guard install per user, or keep both on the same version so they share one runtime."
    ),
}


def _resident_owned_elsewhere(state_base: Path, runtime_sha256: str) -> bool:
    """True when a process holds the home-wide owner lock and no live resident runs this runtime.

    Reads only the lock and the resident state files; it never takes the lock
    for longer than the probe and never starts or stops a resident.
    """

    if probe_owner_lock(state_base) is not False:
        return False
    for state_path in state_base.glob("resident-v3-*/generation-*.json"):
        try:
            with state_path.open("rb") as handle:
                state = json.loads(handle.read(_MAX_STATE_BYTES))
        except (OSError, ValueError):
            continue
        if not isinstance(state, dict) or state.get("runtime_sha256") != runtime_sha256:
            continue
        process_id = state.get("process_id")
        if isinstance(process_id, int) and pid_is_alive(process_id):
            return False
    return True


def doctor_native_availability(guard_home: Path | None = None) -> NativeAvailabilityResult:
    """Use null availability for an unperformed probe, never a false failure."""
    # This only queries the passive scope; its command metadata is not emitted.
    if skipped_command_probe(["hol-guard-runtime", "capabilities", "--json"]) is not None:
        return {
            "mode": "unknown",
            "available": None,
            "compatible": None,
            "reason_code": "native_status_probe_skipped",
            "evaluation_verified": False,
        }

    from ..native_runtime import native_runtime_status

    try:
        status = native_runtime_status()
    except (OSError, RuntimeError, ValueError):
        return {
            "mode": "unknown",
            "available": False,
            "compatible": False,
            "reason_code": "native_status_probe_failed",
            "evaluation_verified": False,
        }
    reason = status.reason
    # Native status reasons are fixed lowercase codes, not arbitrary probe text.
    if not re.fullmatch(r"[a-z0-9_.-]{1,96}", reason):
        reason = "native_status_reason_unavailable"
    result: NativeAvailabilityResult = {
        "mode": status.mode,
        "available": status.available,
        "compatible": status.compatible,
        "reason_code": reason,
        "evaluation_verified": False,
    }
    identity = status.identity
    if (
        guard_home is not None
        and identity is not None
        and _resident_owned_elsewhere(guard_home / NATIVE_RUNTIME_STATE_DIRECTORY, identity.sha256)
    ):
        reason = "native_resident_owner_busy"
        result["reason_code"] = reason
    message = _REASON_MESSAGES.get(reason)
    if message is not None:
        result["message"] = message
    return result
