"""Early "starting" heartbeat from a freshly spawned Guard daemon.

A cold daemon on a slow machine spends tens of seconds importing Python before
it can journal ``start_requested`` or take the owner lock. Without any signal
in that window the launcher cannot tell a slow child from a stuck one and
terminates both. The launcher therefore hands the child a heartbeat path in its
environment; the child writes one tiny record before importing anything heavy.

The record only extends the launcher's patience. It is bounded by
``SLOW_START_MAX_SECONDS`` after spawn, must name a pid inside the spawned
process tree, and is never read as proof that the daemon is ready or trusted.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from ..private_file_io import read_private_regular_text

START_HEARTBEAT_ENV = "HOL_GUARD_DAEMON_START_HEARTBEAT"
START_HEARTBEAT_FILE = "daemon-start-heartbeat.json"
START_HEARTBEAT_MAX_BYTES = 256
# Hard ceiling on how long a child that has only emitted this heartbeat is
# treated as starting. Past it the child is classified like any silent one.
SLOW_START_MAX_SECONDS = 180.0

# Run by the child before it imports Guard. Stdlib only, never raises.
START_HEARTBEAT_CODE = f"""\
try:
    import os, time
    _path = os.environ.pop({START_HEARTBEAT_ENV!r}, "")
    if _path:
        _flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
        _fd = os.open(_path, _flags, 0o600)
        try:
            os.write(_fd, ('{{"pid":%d,"ns":%d}}' % (os.getpid(), time.time_ns())).encode())
        finally:
            os.close(_fd)
except BaseException:
    pass
"""


def start_heartbeat_path(guard_home: Path) -> Path:
    return guard_home / START_HEARTBEAT_FILE


def load_start_heartbeat(guard_home: Path) -> tuple[int, int] | None:
    """Return ``(pid, recorded_at_ns)`` from a well-formed heartbeat record."""

    try:
        raw = read_private_regular_text(
            start_heartbeat_path(guard_home),
            max_bytes=START_HEARTBEAT_MAX_BYTES,
            require_private_parent=True,
        )
        payload = json.loads(raw) if raw else None
    except (OSError, ValueError):
        return None
    if not isinstance(payload, dict):
        return None
    pid = payload.get("pid")
    recorded_at_ns = payload.get("ns")
    if type(pid) is not int or pid <= 0 or type(recorded_at_ns) is not int or recorded_at_ns <= 0:
        return None
    return pid, recorded_at_ns


def clear_start_heartbeat(guard_home: Path) -> None:
    try:
        start_heartbeat_path(guard_home).unlink()
    except OSError:
        return


def heartbeat_is_within_window(recorded_at_ns: int, *, spawned_at_ns: int, now_ns: int | None = None) -> bool:
    now = time.time_ns() if now_ns is None else now_ns
    if recorded_at_ns <= spawned_at_ns:
        return False
    return now - spawned_at_ns < int(SLOW_START_MAX_SECONDS * 1_000_000_000)


__all__ = [
    "SLOW_START_MAX_SECONDS",
    "START_HEARTBEAT_CODE",
    "START_HEARTBEAT_ENV",
    "clear_start_heartbeat",
    "heartbeat_is_within_window",
    "load_start_heartbeat",
    "start_heartbeat_path",
]
