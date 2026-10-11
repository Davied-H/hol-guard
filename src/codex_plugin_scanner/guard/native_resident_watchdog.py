"""Respawn a native resident that died while this process was using it.

The Rust client already restarts a dead resident the next time a request
arrives. A daemon that has seen its resident die does not have to wait for a
hook to pay for that restart: this watchdog notices that every published
resident process is gone without a clean stop and issues one cheap read-only request, which makes the
client respawn it. The Rust restart pacing still bounds a crash loop, and the
request carries no approval authority, so a refused or failed respawn changes
nothing about fail-closed decisions.

Windows is left to the on-demand path because probing a pid there is not a
side-effect-free operation.
"""

from __future__ import annotations

import json
import os
import threading
from collections.abc import Callable
from pathlib import Path

from .native_resident_client import resident_state_files, tracked_native_resident_state_dirs

WATCHDOG_INTERVAL_SECONDS = 5.0
_MAX_STATE_BYTES = 64 * 1024


def _state_process_id(path: Path) -> int | None:
    try:
        with path.open("rb") as handle:
            payload = json.loads(handle.read(_MAX_STATE_BYTES + 1)[:_MAX_STATE_BYTES])
    except (OSError, ValueError):
        return None
    if not isinstance(payload, dict):
        return None
    pid = payload.get("process_id")
    return pid if isinstance(pid, int) and not isinstance(pid, bool) and pid > 0 else None


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except OSError:
        return True
    return True


def resident_provably_dead(state_dir: Path) -> bool:
    """True when this state root still publishes residents and none of their processes exist.

    A clean stop or an update retirement removes the published state, so a root
    with no state is never treated as a crash and is left for the next request.
    """

    if os.name == "nt":
        return False
    files = resident_state_files(state_dir)
    if not files:
        return False
    for path in files:
        pid = _state_process_id(path)
        if pid is None or _pid_alive(pid):
            return False
    return True


def respawn_dead_resident(guard_home: Path) -> bool:
    """Issue one read-only request when a tracked resident is provably dead."""

    if not any(resident_provably_dead(state_dir) for state_dir in tracked_native_resident_state_dirs(guard_home)):
        return False
    from .approval_gate import public_config
    from .approval_gate_types import ApprovalGateError

    try:
        public_config(guard_home)
    except ApprovalGateError:
        # The resident did not come back (respawn paced or failed). The next tick retries.
        return False
    return True


def start_native_resident_watchdog(
    guard_home: Path,
    *,
    stop: threading.Event,
    on_error: Callable[[str], object],
    interval: float = WATCHDOG_INTERVAL_SECONDS,
    respawn: Callable[[Path], bool] = respawn_dead_resident,
) -> threading.Thread:
    """Poll for a dead resident on a daemon thread until ``stop`` is set."""

    def loop() -> None:
        while not stop.wait(interval):
            try:
                _ = respawn(guard_home)
            except Exception:
                on_error("native_resident_watchdog_failed")

    thread = threading.Thread(target=loop, name="guard-native-resident-watchdog", daemon=True)
    thread.start()
    return thread


__all__ = [
    "WATCHDOG_INTERVAL_SECONDS",
    "resident_provably_dead",
    "respawn_dead_resident",
    "start_native_resident_watchdog",
]
