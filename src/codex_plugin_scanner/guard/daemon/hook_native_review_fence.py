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

    None means the lease was wanted and could not be read in time. The review
    still runs: it is handed the snapshot that was bound before this fence, so
    it reads the policy a leased review would read. The lease only keeps a
    control mutation from committing while the review runs.
    """

    bound = policy_snapshot is not None and (
        policy_snapshot.get("command_extensions_bound") is True
        or isinstance(policy_snapshot.get("command_extensions"), Mapping)
    )
    if not bound or event_name not in {"PreToolUse", "UserPromptSubmit"} or recording_only:
        yield False
        return
    # A missing deadline grants no additional lock wait. Normal HTTP callers
    # supply their original absolute deadline; it is never reset here.
    timeout = 0.0 if deadline is None else max(0.0, deadline - time.monotonic())
    with ExitStack() as resources:
        try:
            resources.enter_context(
                hold_command_control_authority_lock(guard_home, timeout_seconds=timeout, shared=True)
            )
        except NativeCommandControlAuthorityUnavailableError:
            # A reader holds this lease for the whole of its review, so one
            # publication commit can hold the next hook out for longer than
            # its budget. Refusing that hook would turn an ordinary command
            # issued during a publication into an approval row, and would add
            # no protection: the review still runs, and still denies.
            yield None
            return
        if deadline is not None and time.monotonic() >= deadline:
            raise TimeoutError("native_review_fence_deadline")
        yield True
