"""A safe-alternative block resumes the Oh My Pi agent after the user approves."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.pi_extension_previous_source import previous_managed_extension_source
from codex_plugin_scanner.guard.adapters.pi_extension_source import managed_extension_source
from codex_plugin_scanner.guard.adapters.pi_extension_tool_resume_source import TOOL_APPROVAL_RESUME_SOURCE
from tests.pi_continuation_support import _decode_json_object, _node_executable, _run_child


def _source(tmp_path: Path, harness: str, *, previous: bool = False) -> str:
    render = previous_managed_extension_source if previous else managed_extension_source
    return render(
        guard_home=tmp_path / "guard-home",
        home_dir=tmp_path,
        settings_path=tmp_path / "settings.json",
        harness=harness,
        display_name="fixture",
    )


def test_only_the_active_omp_extension_resumes_after_a_safe_alternative_approval(tmp_path: Path) -> None:
    active = _source(tmp_path, "omp")
    assert "function scheduleToolApprovalResume" in active
    assert active.count("scheduleToolApprovalResume(response, ctx, snapshot);") == 1
    for source in (
        _source(tmp_path, "pi"),
        _source(tmp_path, "omp", previous=True),
        _source(tmp_path, "pi", previous=True),
    ):
        assert "scheduleToolApprovalResume" not in source


def test_an_approval_starts_one_turn_that_asks_for_the_identical_call(tmp_path: Path) -> None:
    node = _node_executable()
    if node is None:
        pytest.skip("Node is required to execute the generated helper")
    script = (
        """
const sent = [];
const notices = [];
let generation = 0;
const pendingApprovalResumes = new Map();
const pi = { sendMessage: (...args) => sent.push(args) };
let pollQueue = [];
let polls = 0;
type GuardResponse = Record<string, unknown>;
function canonicalJson(value: unknown): string | null { return JSON.stringify(value); }
function ompInteractiveContext(ctx: any): boolean { return ctx.mode === 'tui'; }
function captureInputApprovalResumeBinding(ctx: any) {
  return { generation, sessionId: ctx.sessionId, cwd: ctx.cwd };
}
function inputApprovalResumeBindingIsActive(ctx: any, binding: any): boolean {
  return binding !== null && binding.generation === generation && ctx.sessionId === binding.sessionId;
}
async function pollApprovalResolution(_id: string, _path: string, _signal: unknown, isActive: () => boolean) {
  polls += 1;
  await new Promise((resolve) => setTimeout(resolve, 5));
  if (!isActive()) return 'aborted';
  return pollQueue.shift() ?? 'timeout';
}
"""
        + TOOL_APPROVAL_RESUME_SOURCE
        + """
const ctx = (mode = 'tui') => ({
  mode,
  sessionId: 's1',
  cwd: '/w',
  ui: { notify: (m: string, k: string) => notices.push([k, m]) },
});
const snapshot = (input: unknown) => ({ payload: { tool_name: 'learn', tool_input: input } });
const blocked = (id: string) => ({
  decision: 'deny',
  approval_resume: { request_id: id, poll_path: `/v1/requests/${id}` },
});
const settle = () => new Promise((resolve) => setTimeout(resolve, 40));
const results: Record<string, unknown> = {};
async function run() {
  pollQueue = ['allow'];
  scheduleToolApprovalResume(blocked('a'), ctx(), snapshot({ memory: 'tests run with uv', context: 'repo' }));
  scheduleToolApprovalResume(blocked('a'), ctx(), snapshot({ memory: 'tests run with uv', context: 'repo' }));
  await settle();
  results.approved = { sent: sent.splice(0), polls, notices: notices.splice(0) };
  polls = 0; pollQueue = ['block'];
  scheduleToolApprovalResume(blocked('b'), ctx(), snapshot({ memory: 'x' }));
  await settle();
  results.kept_blocked = { sent: sent.splice(0), notices: notices.splice(0) };
  polls = 0; pollQueue = ['allow'];
  scheduleToolApprovalResume({ decision: 'deny' }, ctx(), snapshot({ memory: 'x' }));
  scheduleToolApprovalResume(blocked('c'), ctx('print'), snapshot({ memory: 'x' }));
  await settle();
  results.not_scheduled = { sent: sent.splice(0), polls };
  polls = 0; pollQueue = ['allow'];
  scheduleToolApprovalResume(blocked('d'), ctx(), snapshot({ memory: 'x' }));
  generation += 1;
  await settle();
  results.moved_on = { sent: sent.splice(0) };
  pollQueue = ['allow'];
  scheduleToolApprovalResume(blocked('e'), ctx(), snapshot({ memory: 'y'.repeat(9000) }));
  await settle();
  results.oversized = { sent: sent.splice(0) };
  console.log(JSON.stringify(results));
}
run();
"""
    )
    harness = tmp_path / "resume.mts"
    harness.write_text(script, encoding="utf-8")
    completed = _run_child([node, "--experimental-strip-types", str(harness)], timeout=30)
    results = _decode_json_object(completed.stdout)

    approved = results["approved"]
    assert isinstance(approved, dict)
    assert approved["polls"] == 1, "the same request is only watched once"
    ((message, options),) = approved["sent"]
    assert options == {"triggerTurn": True, "deliverAs": "nextTurn"}
    assert message["customType"] == "hol_guard_approval_resume"
    assert message["details"] == {"requestId": "a", "toolName": "learn"}
    content = message["content"]
    assert "approved the learn call" in content
    assert json.dumps({"memory": "tests run with uv", "context": "repo"}, separators=(",", ":")) in content
    assert "with exactly these arguments, unchanged" in content
    assert approved["notices"] == [["info", "HOL Guard approved this request. Oh My Pi is running it again."]]

    kept_blocked = results["kept_blocked"]
    assert isinstance(kept_blocked, dict)
    assert kept_blocked["sent"] == []
    assert kept_blocked["notices"] == [["warning", "HOL Guard kept this request blocked. Oh My Pi will not run it."]]

    assert results["not_scheduled"] == {"sent": [], "polls": 0}
    assert results["moved_on"] == {"sent": []}, "a new prompt or session drops the pending resume"

    oversized = results["oversized"]
    assert isinstance(oversized, dict)
    ((oversized_message, _),) = oversized["sent"]
    assert "with exactly the same arguments, unchanged" in oversized_message["content"]
    assert "y" * 100 not in oversized_message["content"]
