"""Retain the command mutation lease through native review and local reuse."""

from __future__ import annotations

import time
from collections.abc import Iterator, Mapping
from contextlib import ExitStack, contextmanager
from pathlib import Path

from ..native_command_control_authority_io import (
    NativeCommandControlAuthorityUnavailableError,
    hold_command_control_authority_lock,
)

# The lease only keeps a control mutation from committing while the review
# runs, so it is not worth the review's own budget. Every acquirer takes the
# authority turnstile exclusively and a writer holds it for the whole of its
# wait, so an uncapped wait here spends the hook's entire deadline and leaves
# the native evaluator none: the evaluator then reports an expired deadline and
# the command is held for approval. Wait a short moment for the lease, then
# review without it.
LEASE_WAIT_SECONDS = 0.25


def published_binding_token(publisher: object) -> tuple[object, object, object] | None:
    """Read *committed* control inputs, not the cached publisher snapshot.

    An external CLI can commit to SQLite while this process's in-memory
    generation stays unchanged. If durable control inputs cannot be read,
    an unleased review must fail closed rather than treat two None values
    as proof of unchanged authority.
    """

    import hashlib
    import json

    compiled = getattr(publisher, "_compiled_command_extensions", None)
    business = getattr(publisher, "_compiled_business_source", None)
    revision = getattr(publisher, "_current_local_cli_revision", None)
    if not all(callable(fn) for fn in (compiled, business, revision)):
        return None
    try:
        controls = compiled()
        business_source = business()
        cli_revision = revision()
        business_bytes = (
            getattr(business_source, "retained_identity_bytes", None)
            if business_source is not None
            else b""
        )
        if not isinstance(controls, Mapping) or not isinstance(business_bytes, bytes):
            return None
        controls_data = json.dumps(controls, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return (
            hashlib.sha256(controls_data.encode("utf-8")).hexdigest(),
            hashlib.sha256(business_bytes).hexdigest(),
            cli_revision,
        )
    except (OSError, RuntimeError, TypeError, ValueError, KeyError):
        return None


@contextmanager
def native_review_fence(
    *,
    policy_snapshot: Mapping[str, object] | None,
    event_name: str,
    recording_only: bool,
    guard_home: Path,
    deadline: float | None,
) -> Iterator[bool | None]:
    """Yield True while the lease is held, False when it does not apply.

    None means the lease was wanted and was not free within its short wait.
    The review still runs, on the snapshot that was bound before this fence,
    and the caller compares committed control state across it. An external
    mutation can leave the publisher's cached generation unchanged, so the
    comparison must read the durable source. An unavailable reading fails
    closed; the read does not grant permission to an uncertain response.
    """

    bound = policy_snapshot is not None and (
        policy_snapshot.get("command_extensions_bound") is True
        or isinstance(policy_snapshot.get("command_extensions"), Mapping)
    )
    if not bound or event_name not in {"PreToolUse", "UserPromptSubmit"} or recording_only:
        yield False
        return
    # A missing deadline grants no lock wait at all. Normal HTTP callers supply
    # their original absolute deadline; it is never reset here.
    remaining = 0.0 if deadline is None else max(0.0, deadline - time.monotonic())
    with ExitStack() as resources:
        try:
            resources.enter_context(
                hold_command_control_authority_lock(
                    guard_home, timeout_seconds=min(LEASE_WAIT_SECONDS, remaining), shared=True
                )
            )
        except NativeCommandControlAuthorityUnavailableError:
            # Refusing this hook would turn an ordinary command issued during a
            # publication into an approval row, and would add no protection:
            # the review still runs, and still denies. It needs budget to run,
            # so a hook that is already out of time is still refused here.
            if deadline is None or time.monotonic() >= deadline:
                raise TimeoutError("native_review_fence_deadline") from None
            yield None
            return
        if deadline is not None and time.monotonic() >= deadline:
            raise TimeoutError("native_review_fence_deadline")
        yield True
