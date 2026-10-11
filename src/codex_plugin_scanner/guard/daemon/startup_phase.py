"""Bounded startup phase timing for the local Guard daemon.

A slow daemon start on a cold host is otherwise a single opaque interval. Each
phase records one ``startup_phase`` diagnostic carrying its elapsed milliseconds
so the frozen packaging tests and operators can see which phase was slow. The
records are diagnostic only; no decision reads them.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Final

_MAX_PENDING: Final = 32
_FIRST_IMPORT_MONOTONIC: Final = time.monotonic()
_lock = threading.Lock()
_pending: list[tuple[str, int]] = []

PhaseSink = Callable[[str, str], object]


def _elapsed_ms(started: float) -> int:
    return max(0, int((time.monotonic() - started) * 1000))


def _detail(name: str, elapsed_ms: int) -> str:
    return f"phase={name} elapsed_ms={elapsed_ms} since_first_import_ms={_elapsed_ms(_FIRST_IMPORT_MONOTONIC)}"


@contextmanager
def timed_phase(name: str, sink: PhaseSink | None = None) -> Iterator[None]:
    """Time the enclosed block; buffer the record until a sink exists."""

    started = time.monotonic()
    try:
        yield
    finally:
        elapsed = _elapsed_ms(started)
        if sink is not None:
            sink("startup_phase", _detail(name, elapsed))
        else:
            with _lock:
                if len(_pending) < _MAX_PENDING:
                    _pending.append((_detail(name, elapsed), elapsed))


def flush_pending_phases(sink: PhaseSink) -> None:
    """Emit the phases buffered before the daemon diagnostics existed."""

    with _lock:
        pending = list(_pending)
        _pending.clear()
    for detail, _elapsed in pending:
        sink("startup_phase", detail)


__all__ = ["PhaseSink", "flush_pending_phases", "timed_phase"]
