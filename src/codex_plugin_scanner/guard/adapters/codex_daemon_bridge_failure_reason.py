"""Choose the denial text for a Codex hook the local daemon could not review.

The bridge records one fixed reason code per failed daemon attempt. Only an
authentication failure should tell the user to repair the daemon; a daemon that
is restarting, slow, or briefly unreachable needs a retry, not a repair.

Stdlib only: the bridge imports this module before any heavy Guard code loads.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from .codex_daemon_dead_fastpath import NATIVE_RUNTIME_DEAD_REASON, NATIVE_RUNTIME_DEAD_REASON_CODE

AUTHENTICATION_FAILED_REASON = (
    "HOL Guard could not authenticate the local daemon. Run `hol-guard daemon repair` from a terminal, then retry."
)
DAEMON_UNAVAILABLE_REASON = (
    "HOL Guard's local daemon did not answer before the hook deadline and kept this action blocked. "
    "No approval was requested; retry the action. "
    "If this keeps happening, run `hol-guard daemon repair` from a terminal."
)
DAEMON_DEAD_REASON = (
    "HOL Guard's local daemon is not running and could not be restarted. "
    "Run `hol-guard repair` in a terminal, then retry."
)
OVERLOAD_REASON = (
    "HOL Guard is temporarily saturated and kept this action blocked. No approval was requested; retry the action."
)

# Codes from ``_daemon_failure_reason`` that mean the daemon's identity, state
# or token could not be verified, rather than that it did not answer in time.
AUTHENTICATION_FAILURE_CODES = frozenset(
    {
        "daemon_response_unauthenticated",
        "daemon_state_unreadable",
        "daemon_discovery_key_unreadable",
        "daemon_token_unreadable",
        "daemon_state_authentication_failed",
        "daemon_challenge_authentication_failed",
        "daemon_challenge_expired",
        "daemon_challenge_identity_mismatch",
        "daemon_token_binding_mismatch",
        "daemon_state_or_response_invalid",
    }
)


def daemon_failure_reason(causes: Sequence[object], *, daemon_overloaded: bool) -> str:
    """Return the denial text that names the actual daemon failure."""

    records = [cause for cause in causes if isinstance(cause, Mapping)]
    if any(cause.get("stage") == "daemon_dead_fast" for cause in records):
        if any(cause.get("reason_code") == NATIVE_RUNTIME_DEAD_REASON_CODE for cause in records):
            return NATIVE_RUNTIME_DEAD_REASON
        return DAEMON_DEAD_REASON
    if daemon_overloaded:
        return OVERLOAD_REASON
    if any(cause.get("reason_code") in AUTHENTICATION_FAILURE_CODES for cause in records):
        return AUTHENTICATION_FAILED_REASON
    return DAEMON_UNAVAILABLE_REASON
