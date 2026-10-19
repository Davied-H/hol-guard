"""A frozen Guard never starts a cold `hol-guard hook` evaluator from a hook bridge."""

from __future__ import annotations

import io
import json
import subprocess
import sys
import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import frozen_codex_runtime
from codex_plugin_scanner.guard.adapters import claude_daemon_hook_bridge
from codex_plugin_scanner.guard.adapters import codex_daemon_hook_bridge as codex_bridge

_PRE_TOOL_USE = json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "ls"}})
_FALLBACK_COMMAND = ["/app/hol-guard", "hook", "--harness", "codex"]
_NATIVE = Path("/app/guard-home/native/hol-guard-runtime")
# The argument the frozen launch contract authenticated, carried verbatim.
_BRIDGE_CONFIG = json.dumps(
    {
        "state_path": "/app/guard-home/daemon-state.json",
        "manifest_path": "/app/guard-home/managed/codex/hooks.manifest.json",
        "fallback_command": _FALLBACK_COMMAND,
        "start_command": ["/app/hol-guard", "--hol-guard-frozen-daemon-recover", "{}"],
        "query": "",
        "hook_timeouts": {"PreToolUse": 10},
    },
    separators=(",", ":"),
)


def _forbidden(*args: object, **kwargs: object) -> object:
    del args, kwargs
    raise AssertionError("a frozen Guard must not start a cold evaluator")


def test_frozen_claude_bridge_denies_without_a_daemon_answer(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(claude_daemon_hook_bridge, "run_isolated_hook_process", _forbidden)

    output = claude_daemon_hook_bridge._run_local_fallback(
        "daemon unavailable",
        _PRE_TOOL_USE,
        ("/app/hol-guard", "hook", "--harness", "claude"),
        deadline=time.monotonic() + 10,
    )

    decision = json.loads(output)["hookSpecificOutput"]
    assert decision["permissionDecision"] == "deny"
    assert "no daemon answered" in decision["permissionDecisionReason"]


def test_frozen_codex_bridge_has_no_fallback_response(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.delenv("HOL_GUARD_DESKTOP", raising=False)
    children: list[tuple[str, ...]] = []

    def record(argv, **kwargs):
        del kwargs
        children.append(tuple(str(part) for part in argv))
        return subprocess.CompletedProcess(list(argv), 0)

    monkeypatch.setattr(subprocess, "run", record)
    monkeypatch.setattr(codex_bridge, "native_hook_bridge_executable", lambda *_args, **_kwargs: _NATIVE)
    monkeypatch.setattr("sys.stdin", io.StringIO(_PRE_TOOL_USE))

    argv = ("hol-guard", frozen_codex_runtime._FROZEN_BRIDGE_ARG, _BRIDGE_CONFIG)
    assert frozen_codex_runtime.run_frozen_internal_command(argv) == 0

    assert children == [(str(_NATIVE), "codex-hook-bridge", _BRIDGE_CONFIG)]
    capsys.readouterr()

    monkeypatch.setattr(codex_bridge, "native_hook_bridge_executable", lambda *_args, **_kwargs: None)
    monkeypatch.setattr("sys.stdin", io.StringIO(_PRE_TOOL_USE))
    children.clear()

    assert frozen_codex_runtime.run_frozen_internal_command(argv) == 0

    assert children == []
    decision = json.loads(capsys.readouterr().out)["hookSpecificOutput"]
    assert decision["permissionDecision"] == "deny"
    assert decision["permissionDecisionReason"] == codex_bridge._NATIVE_RUNTIME_UNAVAILABLE
