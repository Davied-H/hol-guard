"""A one-shot CLI hook must hand the native edge a real bounded deadline."""

from __future__ import annotations

import time

import pytest

from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker
from codex_plugin_scanner.guard.daemon.runtime_hook_deadline import RuntimeHookDeadline
from codex_plugin_scanner.guard.store import GuardStore


def _worker(tmp_path, monkeypatch, seen: dict[str, object]) -> HookWorker:
    worker = HookWorker(
        store=GuardStore(tmp_path / "guard-home"),
        wait_for_native_policy=False,
        publish_native_policy=False,
    )
    monkeypatch.setattr(worker, "_native_policy_snapshot", lambda *_a, **_k: {"generation": 1})

    def capture(**kwargs: object) -> None:
        seen["deadline"] = kwargs.get("deadline")
        seen["at"] = time.monotonic()

    monkeypatch.setattr(worker, "_review_raw_hook_native", capture)
    return worker


def test_cli_edge_budget_reaches_native_edge_and_unavailable_stays_fail_closed(tmp_path, monkeypatch):
    seen: dict[str, object] = {}
    worker = _worker(tmp_path, monkeypatch, seen)
    try:
        edge = worker.review_native_edge_decision(
            payload={"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "git status"}},
            harness="codex",
            default_harness="codex",
            home_dir=tmp_path / "home",
            guard_home=tmp_path / "guard-home",
            workspace=tmp_path / "workspace",
            edge_budget_seconds=9.0,
        )
    finally:
        worker.close()
    deadline = seen["deadline"]
    assert isinstance(deadline, float)
    assert 8.0 < deadline - float(seen["at"]) <= 9.0
    assert edge["result"] is None
    assert edge["failure_reason_code"] == "native_pre_tool_unavailable"


def test_cli_hook_budget_exceeds_the_native_default_but_stays_bounded():
    deadline = RuntimeHookDeadline.for_cli_hook({}, monotonic=lambda: 100.0)
    assert 0.75 < deadline.expires_at - 100.0 <= 10.0
    hinted = RuntimeHookDeadline.for_cli_hook({"guard_remaining_ms": 1500}, monotonic=lambda: 100.0)
    assert hinted.expires_at - 100.0 == pytest.approx(1.25)
    huge = RuntimeHookDeadline.for_cli_hook({"guard_remaining_seconds": 600}, monotonic=lambda: 100.0)
    assert huge.expires_at - 100.0 <= 10.0
