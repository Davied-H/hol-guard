"""What an operator's single approval buys the agent's next shell attempt.

The approve-then-retry path is the Gauntlet's ``approved-retry`` lane at
product level: a reviewed command, one grant through the approval UI's own
resolution code, then the agent's retry. The grant is fenced to the reviewed
request, so what the retry may change decides whether it gets through.

Three retries, all after a grant the operator just gave:

* the identical request, same transport id: allowed, the approval is reused;
* the identical command under a fresh ``tool_use_id``, which is what a real
  Claude Code retry sends, since the model emits a new tool-use block:
  reviewed again (hashgraph-online/hol-guard#3837);
* a reworded command: reviewed again.

The last two are recorded here as today's behaviour, not as behaviour this
test endorses. ``request_payload_identity`` drops the transport call id from
the review anchor only for the ``pi`` and ``omp`` harnesses, so every other
harness binds its approval to an id its own retry will not repeat.

Under the default ``blocked_request_mode = "safe-alternative"`` a review is
rendered to the agent as a plain block with ``prompted`` false, so the queued
inbox row, not the response, says whether an attempt was reviewed.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

GRANT_REASON = "Approved for the approve-then-retry contract"
REVIEW_ACTIONS = {"review", "require-reapproval"}


def _payload(command: str, use_id: str, workspace: Path) -> dict[str, object]:
    return {
        "hook_event_name": "PreToolUse",
        "tool_name": "bash",
        "tool_input": {"command": command},
        "session_id": "approved-retry",
        "tool_use_id": use_id,
        "cwd": str(workspace),
    }


def _grant(store: Any, request_id: str, workspace: Path) -> None:
    """Resolve exactly as the approval UI's "Allow just this once" control does."""
    from codex_plugin_scanner.guard.approvals import apply_approval_resolution

    apply_approval_resolution(
        store=store,
        request_id=request_id,
        action="allow",
        scope="artifact",
        workspace=str(workspace),
        reason=GRANT_REASON,
        return_queue_result=True,
        resolve_scope_matches=True,
    )


def _queued(store: Any, seen: set[str]) -> list[dict[str, Any]]:
    """Rows this attempt queued, so earlier rounds' rows are not counted twice."""
    rows = [row for row in store.list_approval_requests(status="pending") if row["request_id"] not in seen]
    seen.update(row["request_id"] for row in rows)
    return rows


def _approve_then_retry(
    worker: Any,
    store: Any,
    kwargs: dict[str, Any],
    workspace: Path,
    seen: set[str],
    *,
    command: str,
    use_id: str,
    retry_command: str | None = None,
    retry_use_id: str | None = None,
) -> dict[str, Any]:
    """Review one command, grant that row, and report what its retry got.

    Each round uses its own command, so a grant left over from an earlier
    round cannot be the one a later retry matches.
    """
    first = worker.review_http_payload(payload=_payload(command, use_id, workspace), **kwargs)
    queued = _queued(store, seen)
    assert first["policy_action"] != "allow", first
    assert len(queued) == 1, queued
    assert queued[0]["policy_action"] in REVIEW_ACTIONS, queued[0]
    _grant(store, queued[0]["request_id"], workspace)

    retry_payload = _payload(retry_command or command, retry_use_id or use_id, workspace)
    retry = worker.review_http_payload(payload=retry_payload, **kwargs)
    requeued = _queued(store, seen)
    return {
        "policy_action": retry["policy_action"],
        "reason_code": retry.get("reason_code"),
        "granted_binding": queued[0]["artifact_hash"],
        "requeued_bindings": [row["artifact_hash"] for row in requeued],
    }


def test_one_approval_carries_the_identical_retry_but_not_a_new_call_id_or_rewording(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, native_approval_reuse_runtime: Path
) -> None:
    from codex_plugin_scanner.guard.config import update_guard_settings
    from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker
    from codex_plugin_scanner.guard.store import GuardStore

    home = tmp_path / "home"
    workspace = home / "workspace"
    workspace.mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    store = GuardStore(home / ".hol-guard")
    # ``subprocess_action`` is the only configured floor that reaches an ordinary shell
    # command, and only "review" or "require-reapproval" queue an approval row at all.
    update_guard_settings(store.guard_home, {"mode": "enforce", "subprocess_action": "review"})
    worker = HookWorker(store=store, workspace=workspace)
    kwargs = dict(
        params={},
        default_harness="claude-code",
        home_dir=home,
        guard_home=store.guard_home,
        workspace=workspace,
    )
    seen: set[str] = set()
    try:
        same_id = _approve_then_retry(
            worker, store, kwargs, workspace, seen, command="git status --short", use_id="toolu_status"
        )
        new_id = _approve_then_retry(
            worker,
            store,
            kwargs,
            workspace,
            seen,
            command="git diff --stat",
            use_id="toolu_diff_first",
            retry_use_id="toolu_diff_retry",
        )
        reworded = _approve_then_retry(
            worker,
            store,
            kwargs,
            workspace,
            seen,
            command="git log --oneline -1",
            use_id="toolu_log",
            retry_command="git log --format=%h -1",
        )
    finally:
        worker.close()

    outcomes = {"same_call_id": same_id, "new_call_id": new_id, "reworded": reworded}
    # The whole point of the grant: the request it was queued for runs.
    assert same_id["policy_action"] == "allow", outcomes
    assert same_id["requeued_bindings"] == [], outcomes
    # #3837: the retry the model actually sends carries a new tool-use id, and
    # the review anchor keeps that id for every harness but pi and omp, so the
    # approval the operator just gave does not cover it.
    assert new_id["policy_action"] != "allow", outcomes
    assert len(new_id["requeued_bindings"]) == 1, outcomes
    assert new_id["requeued_bindings"] != [same_id["granted_binding"]], outcomes
    # Same intent, the model's own wording: a different action, so a new review.
    assert reworded["policy_action"] != "allow", outcomes
    assert len(reworded["requeued_bindings"]) == 1, outcomes
