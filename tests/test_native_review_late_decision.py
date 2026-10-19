"""A native decision reached under the lease survives a deadline that passed.

The fence refuses to *start* a review that is already out of time. Once the
review has answered, the answer was read from the snapshot the lease holds, so
discarding it only turns ordinary work into an approval row — and would drop a
deny the runtime had already reached.
"""

from __future__ import annotations

import time
from typing import Any

from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker
from codex_plugin_scanner.guard.store import GuardStore

_PAYLOAD = {
    "hook_event_name": "PreToolUse",
    "tool_name": "Bash",
    "tool_input": {"command": "git status --short"},
}


def _edge(action: str) -> dict[str, object]:
    return {
        "result": {"policy_action": action, "reason_code": f"native_{action}_fixture"},
        "receipt": None,
        "event_name": "PreToolUse",
        "harness": "codex",
    }


def _worker(tmp_path: Any, monkeypatch: Any, action: str) -> HookWorker:
    worker = HookWorker(
        store=GuardStore(tmp_path / "guard-home"),
        wait_for_native_policy=False,
        publish_native_policy=False,
    )
    monkeypatch.setattr(worker, "_native_policy_snapshot", lambda *_a, **_k: {"generation": 1})

    def slow_review(**kwargs: object) -> dict[str, object]:
        deadline = kwargs.get("deadline")
        if isinstance(deadline, float):
            time.sleep(max(0.0, deadline - time.monotonic()) + 0.05)
        return _edge(action)

    monkeypatch.setattr(worker, "_review_raw_hook_native", slow_review)
    return worker


def _review(worker: HookWorker, tmp_path: Any) -> dict[str, object]:
    return worker.review_native_edge_decision(
        payload=dict(_PAYLOAD),
        harness="codex",
        default_harness="codex",
        home_dir=tmp_path / "home",
        guard_home=tmp_path / "guard-home",
        workspace=tmp_path / "workspace",
        edge_budget_seconds=0.2,
    )


def test_an_allow_reached_after_the_deadline_is_still_delivered(tmp_path, monkeypatch):
    worker = _worker(tmp_path, monkeypatch, "allow")
    try:
        edge = _review(worker, tmp_path)
    finally:
        worker.close()
    assert edge["failure_reason_code"] is None
    result = edge["result"]
    assert isinstance(result, dict)
    assert result["policy_action"] == "allow"


def test_a_deny_reached_after_the_deadline_is_not_downgraded(tmp_path, monkeypatch):
    worker = _worker(tmp_path, monkeypatch, "deny")
    try:
        edge = _review(worker, tmp_path)
    finally:
        worker.close()
    assert edge["failure_reason_code"] is None
    result = edge["result"]
    assert isinstance(result, dict)
    assert result["policy_action"] == "deny"
