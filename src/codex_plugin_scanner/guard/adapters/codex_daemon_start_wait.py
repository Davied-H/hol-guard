"""Keep a Codex hook asking a daemon that is still starting.

A cold start on a busy Windows machine can take tens of seconds. Denying the
tool call after one retry turns that start into a string of failed actions.
While a launch marker says the start has not settled, the hook keeps asking
the daemon instead. Only an authenticated daemon reply comes back from here;
the wait never produces a decision of its own.
"""

from __future__ import annotations

import http.client
import time
import urllib.error
from collections.abc import Callable
from pathlib import Path

from .codex_daemon_dead_fastpath import daemon_start_in_progress

FIRST_POLL_SECONDS = 0.25
MAX_POLL_SECONDS = 1.0
# Failures that mean "not up yet": no state, a stopped state, nothing
# listening, or a new daemon replacing the state mid-request.
RETRYABLE_REASONS = frozenset(
    {
        "daemon_connection_refused",
        "daemon_generation_changed",
        "daemon_state_missing",
        "daemon_state_stopped",
        "daemon_state_unreadable",
        "daemon_transport_unavailable",
    }
)


def await_started_daemon(
    *,
    state_path: str | Path,
    stop_at: float,
    request: Callable[[], dict[str, object] | None],
    started: bool,
    failure_reason: Callable[[BaseException], str],
) -> dict[str, object] | None:
    """Ask the daemon until it answers, the start settles or ``stop_at`` passes.

    ``started`` means the start command succeeded, so one request is made even
    without a launch marker. A failed request is retried only for a retryable
    reason while a marker is fresh; any other failure, including an
    authenticated refusal, is raised unchanged.
    """

    poll = FIRST_POLL_SECONDS
    attempt_now = started
    while True:
        if time.monotonic() >= stop_at:
            # A request started with no time left would run against the hook
            # deadline and spend the slice reserved for the local fallback.
            return None
        if attempt_now:
            try:
                return request()
            except (OSError, ValueError, http.client.HTTPException, urllib.error.URLError) as error:
                if (
                    failure_reason(error) not in RETRYABLE_REASONS
                    or time.monotonic() + poll >= stop_at
                    or not daemon_start_in_progress(state_path)
                ):
                    raise
        elif time.monotonic() + poll >= stop_at or not daemon_start_in_progress(state_path):
            return None
        time.sleep(poll)
        poll = min(poll * 2, MAX_POLL_SECONDS)
        attempt_now = True


__all__ = ["await_started_daemon"]
