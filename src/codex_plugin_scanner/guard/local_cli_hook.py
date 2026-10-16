"""Unlisted CLI observation and grants: one resident call records and decides, Python presents."""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path
from typing import TYPE_CHECKING, cast
from uuid import uuid4

from . import store_storage_gate
from .models import GuardAction
from .native_context import _canonical_request_sha256, ensure_resident_prerequisite
from .native_execution import _resident_request
from .sqlite_tuning import sqlite_connect_timeout_seconds

if TYPE_CHECKING:
    from .store import GuardStore

LOCAL_CLI_HOOK_FEATURE = "local-cli-hook-v1"
_RESULT_SCHEMA = "guard-local-cli-hook-result.v1"
_STORE_FAILED = "native_local_cli_hook_store_failed"
_GRANT_ACTIONS = frozenset({"allow", "block", "review"})


def local_cli_grant_action(
    *,
    store: GuardStore,
    command: str | None,
    cwd: Path,
    home_dir: Path | None,
    current_action: GuardAction,
    grant_allowed: bool,
) -> GuardAction:
    """Record the CLI the command launches and refine the action with its grant."""

    if command is None:
        return current_action
    action = native_local_cli_hook(
        store, command=command, cwd=cwd, home_dir=home_dir, current_action=current_action, grant_allowed=grant_allowed
    )
    if action is not None:
        return action
    return unverified_local_cli_action(store, current_action) if grant_allowed else current_action


def observe_unlisted_cli(*, store: GuardStore, command: str, cwd: Path, home_dir: Path | None) -> None:
    """Record the CLIs a command launches without consulting any grant."""

    native_local_cli_hook(
        store, command=command, cwd=cwd, home_dir=home_dir, current_action="allow", grant_allowed=False
    )


def native_local_cli_hook(
    store: GuardStore,
    *,
    command: str,
    cwd: Path,
    home_dir: Path | None,
    current_action: GuardAction,
    grant_allowed: bool,
) -> GuardAction | None:
    """Return the resident's action, or ``None`` without a bound answer; a store failure raises."""

    request: dict[str, object] = {
        "schema": "guard-local-cli-hook-request.v1",
        "request_id": f"local-cli-hook-{uuid4().hex}",
        "store_path": str(store.path),
        "guard_home": str(store.guard_home),
        "source": store.guard_source,
        "busy_timeout_ms": max(1, int(sqlite_connect_timeout_seconds() * 1000)),
        "command": command,
        "cwd": str(cwd),
        "home_dir": None if home_dir is None else str(home_dir),
        "user_home": str(Path.home()),
        "env": dict(os.environ),
        "current_action": current_action,
        "grant_allowed": grant_allowed,
    }
    digest = "sha256:" + _canonical_request_sha256(request)
    if not ensure_resident_prerequisite(store.guard_home):
        return None
    with store_storage_gate.hold_storage_gate(store.guard_home, exclusive=False):
        response = _resident_request(
            operation="local_cli_hook",
            request=request,
            guard_home=store.guard_home,
            timeout_seconds=10.0,
            required_feature=LOCAL_CLI_HOOK_FEATURE,
            response_schema=_RESULT_SCHEMA,
        )
    # The resident may have written the store, as a store call would.
    store._repair_store_permissions()
    if (
        response is None
        or response.get("schema") != _RESULT_SCHEMA
        or response.get("request_id") != request["request_id"]
        or response.get("request_sha256") != digest
    ):
        return None
    status, code, payload = response.get("status"), response.get("code"), response.get("payload")
    if status == "error" and code == _STORE_FAILED:
        raise sqlite3.DatabaseError(_STORE_FAILED)
    if status != "ok" or code != "ok" or not isinstance(payload, dict) or set(payload) != {"action"}:
        return None
    action = payload["action"]
    # Only a grant can change the action, and only to allow, block or review.
    if action != current_action and action not in _GRANT_ACTIONS:
        return None
    return cast(GuardAction, action)


def unverified_local_cli_action(store: object, current_action: GuardAction) -> GuardAction:
    """Hold an otherwise allowed command for review while a block rule might apply."""

    if current_action not in {"allow", "warn"}:
        return current_action
    probe = getattr(store, "has_local_cli_block_rules", None)
    try:
        has_blocks = bool(probe()) if callable(probe) else False
    except Exception:
        has_blocks = True
    return "review" if has_blocks else current_action
