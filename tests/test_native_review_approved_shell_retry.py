"""What an operator's single approval buys the agent's next shell attempt.

The approve-then-retry path is the Gauntlet's ``approved-retry`` lane at product
level: a reviewed command, one grant through the approval UI's own resolution
code, then the agent's retry. The identical retry reuses the grant. A reworded
retry does not, which is hashgraph-online/hol-guard#3837 — this test records that
behaviour rather than asserting it is desirable.

Under the default ``blocked_request_mode = "safe-alternative"`` a review is
rendered to the agent as a plain block with ``prompted`` false, so the response's
``policy_action`` cannot tell a review from a hard block. The queued inbox row
is the signal, and these assertions use it.
"""

from __future__ import annotations

from pathlib import Path

import pytest

GRANT_REASON = "Approved for the approve-then-retry contract"
REVIEW_ACTIONS = {"review", "require-reapproval"}


def _payload(command: str, call_id: str, workspace: Path) -> dict[str, object]:
    return {
        "hook_event_name": "PreToolUse",
        "tool_name": "bash",
        "tool_input": {"command": command},
        "session_id": "approved-retry",
        "tool_call_id": call_id,
        "cwd": str(workspace),
    }


def _grant(store: object, request_id: str, workspace: Path) -> None:
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


def _reviewed(response: dict[str, object], pending: list[dict[str, object]]) -> None:
    """The attempt was stopped for review and left exactly one row to approve."""
    assert response["policy_action"] != "allow", response
    assert len(pending) == 1, pending
    assert pending[0]["policy_action"] in REVIEW_ACTIONS, pending[0]


def test_one_approval_carries_the_identical_shell_retry_but_not_a_reworded_one(
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
    try:
        first = worker.review_http_payload(payload=_payload("git status --short", "first", workspace), **kwargs)
        pending = store.list_approval_requests(status="pending")
        _reviewed(first, pending)
        _grant(store, pending[0]["request_id"], workspace)

        identical = worker.review_http_payload(payload=_payload("git status --short", "retry", workspace), **kwargs)
        requeued = store.list_approval_requests(status="pending")
        # A retry can only reuse the grant when it binds the same contract the
        # granted row was queued for, so report that binding before the verdict.
        assert [row["artifact_hash"] for row in requeued] == [], {
            "granted_binding": pending[0]["artifact_hash"],
            "retry_binding": [row["artifact_hash"] for row in requeued],
            "retry_reason": identical.get("reason_code"),
        }
        assert identical["policy_action"] == "allow", identical

        # Same intent, the model's own wording. Today this needs a second approval.
        reworded = worker.review_http_payload(payload=_payload("git status --porcelain", "reword", workspace), **kwargs)
        _reviewed(reworded, store.list_approval_requests(status="pending"))
    finally:
        worker.close()
