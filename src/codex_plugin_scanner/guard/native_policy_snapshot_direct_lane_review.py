"""Daemon facts the resident needs to queue a reviewed ``PreToolUse`` itself.

When the daemon pauses a reviewed ``PreToolUse`` for approval it reads the
blocked-request mode from Guard config, links the approval center from its
runtime state, binds the queued request to its store's connection source, and
rebuilds the action envelope with its own working directory. A resident that
queues such a request without the daemon needs those same four facts, as the
daemon had them when it published. A fact the resident cannot accept is left
out, so such a hook defers to this daemon.
"""

from __future__ import annotations

import os
from collections.abc import Iterable, Mapping

# The resident accepts the review facts below in its direct-lane binding.
DIRECT_HOOK_REVIEW_FACTS_FEATURE = "hook-direct-review-facts-v1"

# Mirrors the resident limits in guard-policy-snapshot's direct_lane module.
_MAX_REVIEW_FACT_BYTES = 256
_MAX_PATH_BYTES = 4096
_BLOCKED_REQUEST_MODES = frozenset({"ask", "safe-alternative"})


def review_facts_bound(features: Iterable[str]) -> bool:
    return DIRECT_HOOK_REVIEW_FACTS_FEATURE in set(features)


def _text_fact(value: object, limit: int) -> str | None:
    if not isinstance(value, str) or not value or "\0" in value:
        return None
    try:
        length = len(value.encode("utf-8"))
    except UnicodeEncodeError:
        return None
    return value if length <= limit else None


def uniform_blocked_request_mode(configs: Iterable[object]) -> str | None:
    """The blocked-request mode every compiled config resolves to.

    The daemon reads the mode for the hook's own workspace. A binding covers
    the home and every settled workspace, so it carries a mode only when they
    all agree; otherwise such a hook defers to this daemon.
    """

    modes = {getattr(config, "blocked_request_mode", None) for config in configs}
    if len(modes) != 1:
        return None
    (mode,) = modes
    return mode if isinstance(mode, str) and mode in _BLOCKED_REQUEST_MODES else None


def approval_center_origin(store: object) -> str | None:
    """The approval center origin the daemon links a queued review to."""

    from .daemon.hook_native_review_approval import _native_review_approval_center_url

    return _text_fact(_native_review_approval_center_url(store), _MAX_REVIEW_FACT_BYTES)


def review_host_cwd() -> str | None:
    """The working directory the daemon rebuilds the action envelope with."""

    try:
        cwd = os.getcwd()
    except OSError:
        return None
    return _text_fact(cwd, _MAX_PATH_BYTES)


def _review_oauth_source(store: object) -> str | None:
    # ``add_approval_request`` binds a queued request to this source.
    return _text_fact(getattr(store, "_guard_source", None), _MAX_REVIEW_FACT_BYTES)


def recheckable_review_facts(store: object) -> tuple[str | None, str | None]:
    """The review facts that no watched policy input covers."""

    return approval_center_origin(store), review_host_cwd()


def with_review_facts(
    binding: Mapping[str, object] | None,
    *,
    store: object,
    features: Iterable[str],
    blocked_request_mode: str | None,
) -> dict[str, object] | None:
    """Add the review facts, for a resident that accepts them."""

    if binding is None:
        return None
    bound = dict(binding)
    if not review_facts_bound(features):
        return bound
    facts = {
        "blocked_request_mode": blocked_request_mode if blocked_request_mode in _BLOCKED_REQUEST_MODES else None,
        "approval_center_origin": approval_center_origin(store),
        "review_oauth_source": _review_oauth_source(store),
        "review_host_cwd": review_host_cwd(),
    }
    bound.update({name: value for name, value in facts.items() if value is not None})
    return bound
