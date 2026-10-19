"""A hook review that cannot read the authority lease still reviews.

A reader holds the lease for the whole of its review, so one publication commit
can hold the next hook out for longer than its budget. The snapshot is bound
before the fence and handed to the review either way, so an unleased review
reads the policy a leased one would read. Refusing it would turn an ordinary
command issued during a publication into an approval row.
"""

from __future__ import annotations

import threading
import time
from pathlib import Path

from codex_plugin_scanner.guard.daemon.hook_native_review_fence import native_review_fence
from codex_plugin_scanner.guard.native_command_control_authority_io import (
    hold_command_control_authority_lock,
)

_SNAPSHOT = {"command_extensions_bound": True, "generation": 1}


def _fence(guard_home: Path, *, budget: float) -> bool | None:
    with native_review_fence(
        policy_snapshot=_SNAPSHOT,
        event_name="PreToolUse",
        recording_only=False,
        guard_home=guard_home,
        deadline=time.monotonic() + budget,
    ) as fenced:
        return fenced


def test_an_uncontended_review_holds_the_lease(tmp_path):
    assert _fence(tmp_path, budget=5.0) is True


def test_a_review_behind_a_held_mutation_is_not_refused(tmp_path):
    held = threading.Event()
    release = threading.Event()

    def mutate() -> None:
        with hold_command_control_authority_lock(tmp_path):
            held.set()
            release.wait(5.0)

    writer = threading.Thread(target=mutate, daemon=True)
    writer.start()
    try:
        assert held.wait(5.0)
        started = time.monotonic()
        fenced = _fence(tmp_path, budget=0.2)
        waited = time.monotonic() - started
    finally:
        release.set()
        writer.join(5.0)
    assert fenced is None
    assert waited < 2.0
