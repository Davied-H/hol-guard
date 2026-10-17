"""The local CLI grant a contained workspace run is widened by.

The sink never trusts a grant it was handed. It asks this device's store when
it prepares the plan, admits only a plan widened by exactly that grant, and
asks again after the second receipt: a blocked CLI stops the run, and a grant
that changed in between, in any field, stops it too. Without a store, or
without a bound resident answer, the run keeps the base sandbox.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path
from typing import TYPE_CHECKING

from .restricted_pytest_model import PYTEST_INVALID_COMMAND_REASON_CODE, RestrictedPytestError
from .restricted_workspace_grants import ExpectedGrant

if TYPE_CHECKING:
    from ..local_cli_hook import ContainedGrant
    from ..store import GuardStore

GRANT_CHANGED = "The local CLI grant changed before launch."
GRANT_BLOCKED = "This device blocked the local CLI this command launches."
_WORKSPACE_REASON = "native_workspace_containment_required"
_STATE_CAPABILITIES = frozenset({"state-dir-read", "state-dir-write"})
_STORE: ContextVar[GuardStore | None] = ContextVar("restricted_workspace_grant_store", default=None)


@contextmanager
def grant_store(store: GuardStore) -> Iterator[None]:
    """Let contained runs inside this block look grants up in `store`."""
    token = _STORE.set(store)
    try:
        yield
    finally:
        _STORE.reset(token)


def decided_grant(command: str, *, workspace: Path, home: Path) -> ContainedGrant | None:
    """The grant the store decides for a sandbox-required `command` now."""
    store = _STORE.get()
    if store is None:
        return None
    from ..local_cli_hook import ALLOW_CONTAINED_WITH_GRANT, local_cli_contained_grant

    decision = local_cli_contained_grant(
        store,
        command=command,
        cwd=workspace,
        home_dir=home,
        current_action="sandbox-required",
        reason_code=_WORKSPACE_REASON,
    )
    if decision is None:
        return None
    action, grant = decision
    if action == "block":
        raise RestrictedPytestError("contained_test_authorization_failed", GRANT_BLOCKED)
    return grant if action == ALLOW_CONTAINED_WITH_GRANT else None


def expected_grant(grant: ContainedGrant, home: Path) -> ExpectedGrant:
    """What the plan must carry: the state directory is `<canonical home>/.<name>`."""
    state_dir = None
    if _STATE_CAPABILITIES.intersection(grant.capabilities):
        state_dir = str(home.resolve() / f".{grant.name}")
    return ExpectedGrant(grant.identity_hash, grant.capabilities, state_dir)


def require_unchanged(first: ContainedGrant | None, command: str, *, workspace: Path, home: Path) -> None:
    """Fail unless the store still decides `first` for the command."""
    try:
        now = decided_grant(command, workspace=workspace, home=home)
    except RestrictedPytestError:
        # Blocked since the plan was prepared.
        raise RestrictedPytestError(PYTEST_INVALID_COMMAND_REASON_CODE, GRANT_CHANGED) from None
    if now != first:
        raise RestrictedPytestError(PYTEST_INVALID_COMMAND_REASON_CODE, GRANT_CHANGED)
