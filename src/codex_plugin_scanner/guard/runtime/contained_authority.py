"""Settle the live native decision a contained run re-asks for."""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from typing import cast

# A contained run re-asks native authority from its own short-lived process.
# That process starts its own policy publisher and waits for the resident to
# acknowledge the snapshot, so a loaded host can leave it without an answer
# for a moment. These reason codes say the runtime never reached a decision;
# they are not a verdict on the command. A missing resident edge answers
# PreToolUse with native_pre_tool_unavailable.
AUTHORITY_UNAVAILABLE_REASONS = frozenset(
    {
        "native_hook_worker_exception",
        "native_hook_worker_unavailable",
        "native_hook_render_unavailable",
        "native_pre_tool_unavailable",
    }
)
_SETTLE_ATTEMPTS = 3
_SETTLE_PAUSE_SECONDS = 0.75
# An ask that came back unavailable within this window found the runtime
# between states, so asking again is cheap and usually lands. An ask that
# already spent longer than this waited out the whole publisher readiness
# window with no acknowledgement, and asking twice more only turns a 27 second
# failure into a minute and a half of a backgrounded job that has nothing to
# report. That time is not "a moment".
_SETTLE_RETRY_WITHIN_SECONDS = 5.0

_last_unavailable_reason: str | None = None


def authority_unavailable(response: object) -> bool:
    """Whether the runtime failed to decide rather than deciding against the run."""
    return isinstance(response, Mapping) and response.get("reason_code") in AUTHORITY_UNAVAILABLE_REASONS


def settled_authority(
    authorize: Callable[[dict[str, object]], object],
    payload: dict[str, object],
    *,
    pause: Callable[[float], None] | None = None,
) -> object:
    """The live decision for `payload`, re-asked while the runtime cannot answer.

    The command reaching here already carries a PreToolUse decision that sent
    it to a contained profile, so a missing answer here cancels work Guard
    itself asked to run contained. A real decision is deterministic and
    arrives on the first ask; only an unavailable runtime is asked again.
    """
    global _last_unavailable_reason
    wait = time.sleep if pause is None else pause
    _last_unavailable_reason = None
    started = time.monotonic()
    response = authorize(payload)
    for _ in range(_SETTLE_ATTEMPTS - 1):
        if not authority_unavailable(response) or time.monotonic() - started > _SETTLE_RETRY_WITHIN_SECONDS:
            break
        wait(_SETTLE_PAUSE_SECONDS)
        started = time.monotonic()
        response = authorize(payload)
    if authority_unavailable(response):
        _last_unavailable_reason = str(cast("Mapping[str, object]", response).get("reason_code"))
    return response


def last_unavailable_reason() -> str | None:
    """The reason code of the latest ask that ended with no runtime decision.

    The sink runs one command per short-lived process, so the latest ask is the
    one whose failure the operator is about to be told about.
    """
    return _last_unavailable_reason
