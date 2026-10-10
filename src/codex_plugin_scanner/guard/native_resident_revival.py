"""Fast failure and revival for a native resident that is down and not restarting.

The Rust client respawns a dead resident on demand, but paces respawns with a
bounded exponential backoff once a crash loop is detected. While that backoff
refuses a respawn, every further resident call would spawn a short-lived client
process only to be refused again, and a single hook makes many such calls. This
module lets the Python pool remember the refusal for a moment and answer the
same bounded failure frame immediately, and it gives ``hol-guard repair`` a way
to lift the pacing and bring the resident back before it checks the approval
gate. Nothing here can approve anything: a refused respawn still means the
caller fails closed.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Mapping
from pathlib import Path

from .codex_hook_launch_runtime import run_isolated_hook_process
from .fork_safety import forget_in_child

RESTART_BLOCKED_CODE = "native_resident_restart_circuit_open"
# Longer than a refused spawn attempt (a few hundred milliseconds) and shorter
# than the first backoff step, so the pool re-probes about as soon as the Rust
# pacing would allow a respawn.
RESTART_HOLD_SECONDS = 1.5
_REVIVE_TIMEOUT_SECONDS = 3.0
_RESTART_BLOCKED_FRAME = b'{"error":"native_resident_restart_circuit_open","retryable":false}'
DEAD_RUNTIME_REASON = (
    "HOL Guard's native runtime is not running and could not be restarted. "
    "Run `hol-guard repair` in a terminal, then retry."
)

_HOLD_LOCK = threading.Lock()
_HOLDS: dict[str, float] = {}
forget_in_child(_HOLDS)


def _hold_key(state_dir: Path) -> str:
    try:
        return str(state_dir.expanduser().resolve())
    except (OSError, RuntimeError):
        return str(state_dir)


def restart_blocked_frame() -> bytes:
    """The same bounded failure frame the Rust client writes for a refused respawn."""

    return _RESTART_BLOCKED_FRAME


def is_restart_blocked_frame(response: bytes) -> bool:
    return response == _RESTART_BLOCKED_FRAME


def arm_restart_hold(state_dir: Path, *, now: float | None = None) -> None:
    current = time.monotonic() if now is None else now
    with _HOLD_LOCK:
        _HOLDS[_hold_key(state_dir)] = current + RESTART_HOLD_SECONDS


def restart_hold_active(state_dir: Path, *, now: float | None = None) -> bool:
    current = time.monotonic() if now is None else now
    with _HOLD_LOCK:
        key = _hold_key(state_dir)
        until = _HOLDS.get(key)
        if until is None:
            return False
        if until <= current:
            del _HOLDS[key]
            return False
        return True


def clear_restart_hold(state_dir: Path) -> None:
    with _HOLD_LOCK:
        _HOLDS.pop(_hold_key(state_dir), None)


def native_unavailable_reason(failure_code: str | None, default: str) -> str:
    """Name the repair command when the resident is down and not being restarted."""

    return DEAD_RUNTIME_REASON if failure_code == RESTART_BLOCKED_CODE else default


def reset_native_resident_restart_pacing(
    *,
    executable: Path,
    guard_home: Path,
    environment: Mapping[str, str],
    timeout_seconds: float = _REVIVE_TIMEOUT_SECONDS,
) -> bool:
    """Lift the respawn pacing so the next resident request may start it at once.

    Only the crash-loop history is cleared; the resident is still started by the
    authenticated Rust client path on the next request, and approval and policy
    state are untouched.
    """

    state_dir = guard_home / "native-runtime"
    clear_restart_hold(state_dir)
    try:
        result = run_isolated_hook_process(
            (str(executable), "resident-reset-restart-budget", "--state-dir", str(state_dir)),
            input_text="",
            cwd=executable.parent,
            environment=dict(environment),
            timeout_seconds=timeout_seconds,
            output_limit=64 * 1024,
        )
    except (OSError, RuntimeError, ValueError):
        return False
    return result.returncode == 0 and not result.timed_out and not result.containment_failed


def revive_native_resident(guard_home: Path) -> bool:
    """Reset respawn pacing for this Guard home when a native runtime is provisioned.

    Returns False when no compatible runtime is provisioned or the reset failed;
    callers continue, because the approval gate then fails closed on its own.
    """

    from .native_runtime import _isolated_environment, native_runtime_status

    status = native_runtime_status()
    if status.mode == "off" or not status.available or not status.compatible or status.identity is None:
        return False
    return reset_native_resident_restart_pacing(
        executable=status.identity.path,
        guard_home=guard_home,
        environment=_isolated_environment(),
    )


__all__ = [
    "DEAD_RUNTIME_REASON",
    "RESTART_BLOCKED_CODE",
    "RESTART_HOLD_SECONDS",
    "arm_restart_hold",
    "clear_restart_hold",
    "is_restart_blocked_frame",
    "native_unavailable_reason",
    "reset_native_resident_restart_pacing",
    "restart_blocked_frame",
    "restart_hold_active",
    "revive_native_resident",
]
