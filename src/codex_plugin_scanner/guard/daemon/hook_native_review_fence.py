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


def published_binding_token(publisher: object) -> tuple[object, object] | None:
    """Identify the published snapshot without taking the authority lease."""

    reader = getattr(publisher, "current_snapshot_binding", None)
    if not callable(reader):
        return None
    binding = reader()
    if not isinstance(binding, Mapping):
        return None
    return (binding.get("generation"), binding.get("policy_digest"))


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
    and the caller compares the published binding across it: a mutation that
    commits while the lease is unheld moves that binding, and the caller then
    reports the fence unavailable rather than honouring an answer reached
    against the policy the user is replacing.
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
