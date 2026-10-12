"""The workspace sandbox sink runs only a receipt-bound, natively planned command."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_restricted_pytest as native
from codex_plugin_scanner.guard.adapters import zcode_contained_tests
from codex_plugin_scanner.guard.runtime import contained_test_hook as sink
from codex_plugin_scanner.guard.runtime import restricted_workspace as workspace_sink
from codex_plugin_scanner.guard.runtime.restricted_pytest import RestrictedPytestError

COMMAND = "./todo.py add x"


def payload(command: str = COMMAND) -> dict[str, object]:
    return {"hook_event_name": "PreToolUse", "tool_name": "bash", "tool_input": {"command": command}}


def receipt(**changes: object) -> dict[str, object]:
    value: dict[str, object] = {
        "decision": "deny",
        "policy_action": "sandbox-required",
        "reason_code": "native_workspace_containment_required",
        "required_execution_profile": "workspace-contained-v1",
        "command_binding_digest": "a" * 64,
    }
    return value | changes


def plan(workspace: Path, text: str = COMMAND, **changes: object) -> dict[str, object]:
    value: dict[str, object] = {
        "profile_version": "workspace-contained-v1",
        "backend": "macos-seatbelt",
        "backend_executable": "/usr/bin/sandbox-exec",
        "workspace": str(workspace.resolve()),
        "cwd": str(workspace.resolve()),
        "executable": "/bin/sh",
        "command": ["/bin/sh", "-c", text],
        "command_sha256": hashlib.sha256(text.encode()).hexdigest(),
        "allowed_executables": [],
        "read_only_roots": [],
        "exec_roots": [],
        "write_denials": [],
        "sandbox_path": "/usr/bin:/bin",
        "bootstrap_git": None,
        "denied_capabilities": [],
    }
    return value | changes


@pytest.mark.parametrize(
    "changes",
    [
        {"observe_mode": True},
        {"decision": "allow"},
        {"policy_action": "review"},
        {"reason_code": "native_pytest_readonly_containment_required"},
        {"required_execution_profile": "pytest-readonly-v2"},
        {"command_binding_digest": None},
    ],
)
def test_only_a_live_workspace_receipt_matches(changes: dict[str, object]) -> None:
    assert workspace_sink.receipt_matches(receipt())
    assert not workspace_sink.receipt_matches(receipt(**changes))
    assert not workspace_sink.receipt_matches(None)


def test_hook_falls_back_to_the_workspace_sink_only_with_a_receipt(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def reject(*args: object, **kwargs: object) -> None:
        raise RestrictedPytestError("pytest_restricted_invalid_command", "not pytest")

    ran: list[object] = []
    monkeypatch.setattr(
        native,
        "restricted_native",
        lambda *args, **kwargs: dict.fromkeys(("inline_eval", "node_test", "vitest", "git", "node_tool"), False),
    )
    monkeypatch.setattr(sink, "prepare_restricted_pytest", reject)
    monkeypatch.setattr(sink, "run_workspace_contained", lambda *args, **kwargs: ran.append(kwargs) or 0)
    assert (
        sink.run_authorized_contained_test(
            payload(), workspace=tmp_path, timeout_seconds=20, authorize=lambda original: receipt()
        )
        == 0
    )
    assert len(ran) == 1
    for denied in (None, receipt(observe_mode=True), receipt(reason_code="native_policy_sandbox_required")):
        with pytest.raises(RestrictedPytestError):
            sink.run_authorized_contained_test(
                payload(), workspace=tmp_path, timeout_seconds=20, authorize=lambda original, denied=denied: denied
            )
    assert len(ran) == 1


def test_changed_evidence_before_launch_never_starts(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(workspace_sink, "restricted_native", lambda *args, **kwargs: plan(tmp_path))
    started: list[object] = []
    monkeypatch.setattr(workspace_sink, "_run_backend_process", lambda *args, **kwargs: started.append(args) or 0)
    with pytest.raises(RestrictedPytestError):
        workspace_sink.run_workspace_contained(
            payload(),
            workspace=tmp_path,
            cwd=tmp_path,
            authorize=lambda original: receipt(command_binding_digest="b" * 64),
            first_receipt=receipt(),
        )
    assert started == []


@pytest.mark.parametrize(
    "changes",
    [
        {"command": ["/bin/sh", "-c", "rm -rf x"]},
        {"backend": "linux-bubblewrap"},
        {"allowed_executables": ["/bin/sh"]},
        {"profile_version": "pytest-readonly-v2"},
        {"command_sha256": "0" * 64},
    ],
)
def test_a_plan_that_differs_from_the_authorized_command_is_rejected(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, changes: dict[str, object]
) -> None:
    monkeypatch.setattr(workspace_sink, "restricted_native", lambda *args, **kwargs: plan(tmp_path, **changes))
    started: list[object] = []
    monkeypatch.setattr(workspace_sink, "_run_backend_process", lambda *args, **kwargs: started.append(args) or 0)
    with pytest.raises(RestrictedPytestError):
        workspace_sink.run_workspace_contained(
            payload(), workspace=tmp_path, cwd=tmp_path, authorize=lambda original: receipt(), first_receipt=receipt()
        )
    assert started == []


def test_matching_plan_launches_in_the_sandbox_backend(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    calls: list[str] = []

    def fake_native(operation: str, fields: object, expected: object) -> object:
        calls.append(operation)
        return "(version 1)" if operation == "macos_profile" else plan(tmp_path)

    launched: list[tuple[list[str], dict[str, str]]] = []
    monkeypatch.setattr(workspace_sink, "restricted_native", fake_native)
    monkeypatch.setattr(workspace_sink, "trusted_git_binary_for_cwd", lambda cwd: None)
    monkeypatch.setattr(
        workspace_sink,
        "_restricted_environment",
        lambda source, **kwargs: {"HOME": str(kwargs["private_home"]), "PATH": "/host/bin"},
    )
    monkeypatch.setattr(
        workspace_sink,
        "_run_backend_process",
        lambda argv, **kwargs: launched.append((list(argv), kwargs["env"])) or 0,
    )
    assert (
        workspace_sink.run_workspace_contained(
            payload(), workspace=tmp_path, cwd=tmp_path, authorize=lambda original: receipt(), first_receipt=receipt()
        )
        == 0
    )
    argv, env = launched[0]
    assert argv[:2] == ["/usr/bin/sandbox-exec", "-p"]
    assert argv[-3:] == ["/bin/sh", "-c", COMMAND]
    assert env["PATH"] == "/usr/bin:/bin"
    assert env["GIT_CONFIG_NOSYSTEM"] == "1"
    assert env["GIT_TERMINAL_PROMPT"] == "0"
    assert calls == ["prepare_workspace_contained", "macos_profile"]


def test_adapters_map_the_workspace_reason_to_its_profile() -> None:
    assert zcode_contained_tests._PROFILES["native_workspace_containment_required"] == "workspace-contained-v1"
