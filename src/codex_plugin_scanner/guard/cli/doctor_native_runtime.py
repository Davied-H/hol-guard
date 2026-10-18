"""Privacy-safe native availability diagnostics, separate from hook readiness."""

from __future__ import annotations

import re
from typing import Literal, TypedDict

from ..adapters.diagnostic_probes import skipped_command_probe


class _NativeAvailabilityFields(TypedDict):
    mode: Literal["off", "shadow", "auto", "force", "unknown"]
    available: bool | None
    compatible: bool | None
    reason_code: str
    evaluation_verified: Literal[False]


class NativeAvailabilityResult(_NativeAvailabilityFields, total=False):
    message: str


# Two Guard installs (for example a desktop app and a package-manager CLI) share
# one home-wide resident. Only one owns it; the other is healthy, not broken.
_REASON_MESSAGES = {
    "native_resident_owner_busy": (
        "Another Guard install on this account owns the native resident runtime, so this "
        "install cannot start its own. Nothing crashed and no restarts were used. Keep one "
        "Guard install per user, or keep both on the same version so they share one runtime."
    ),
}


def doctor_native_availability() -> NativeAvailabilityResult:
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
    message = _REASON_MESSAGES.get(reason)
    if message is not None:
        result["message"] = message
    return result
