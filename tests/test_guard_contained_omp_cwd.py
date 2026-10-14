"""Contained runs of Oh My Pi `bash` calls that name a `cwd` argument."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime import contained_test_hook as sink
from codex_plugin_scanner.guard.runtime.restricted_pytest import RestrictedPytestError

pytestmark = pytest.mark.skipif(os.name != "posix", reason="POSIX-only execution sink")

COMMAND = "python3 -m pytest -q"


def required_profile() -> dict[str, object]:
    return {
        "decision": "deny",
        "policy_action": "sandbox-required",
        "reason_code": "native_pytest_readonly_containment_required",
        "required_execution_profile": "pytest-readonly-v2",
    }


def call(cwd: object, **extra: object) -> dict[str, object]:
    return {
        "hook_event_name": "PreToolUse",
        "tool_name": "bash",
        "tool_input": {"command": COMMAND, "cwd": cwd},
        **extra,
    }


def session(tmp_path: Path) -> tuple[Path, Path, Path]:
    """A session folder holding a checkout, and a linked worktree beside it."""
    home = tmp_path / "home"
    workspace = home / "org"
    (workspace / "app" / ".git").mkdir(parents=True)
    worktree = home / "app-fix"
    worktree.mkdir()
    (worktree / ".git").write_text("gitdir: /nonexistent\n")
    return home.resolve(), workspace.resolve(), worktree.resolve()


def run(monkeypatch: pytest.MonkeyPatch, original: dict[str, object], workspace: Path, home: Path, response=None):
    """Run the sink and return the commands it authorized and where it prepared the test."""
    authorized: list[str] = []
    prepared: list[tuple[Path, Path]] = []
    monkeypatch.setattr(
        sink,
        "prepare_restricted_pytest",
        lambda argv, *, workspace, cwd, read_only_workspace: prepared.append((workspace, cwd)),
    )
    monkeypatch.setattr(sink, "run_restricted_pytest", lambda *args, **kwargs: 0)

    def authorize(payload: dict[str, object]) -> dict[str, object]:
        authorized.append(payload["tool_input"]["command"])
        assert "cwd" not in payload["tool_input"] or len(authorized) == 1
        return response or required_profile()

    exit_code = sink.run_authorized_contained_test(
        original, workspace=workspace, timeout_seconds=20, authorize=authorize, home_dir=home
    )
    return exit_code, authorized, prepared


def test_a_worktree_beside_the_session_folder_becomes_the_run_root(monkeypatch, tmp_path) -> None:
    home, workspace, worktree = session(tmp_path)
    for spelled in (str(worktree), "../app-fix", "~/app-fix"):
        exit_code, authorized, prepared = run(monkeypatch, call(spelled), workspace, home)
        assert exit_code == 0
        # The call as issued, then the explicit cd form, then the test in the worktree.
        assert authorized == [COMMAND, f"cd {worktree} && {COMMAND}", COMMAND]
        assert prepared == [(worktree, worktree)]


def test_a_folder_inside_the_session_runs_there(monkeypatch, tmp_path) -> None:
    home, workspace, _worktree = session(tmp_path)
    exit_code, authorized, prepared = run(monkeypatch, call("app"), workspace, home)
    assert exit_code == 0
    assert authorized[1] == f"cd {workspace / 'app'} && {COMMAND}"
    assert prepared == [(workspace, workspace / "app")]


@pytest.mark.parametrize("spelled", ["", ".", "/", "//", "./"])
def test_the_session_folder_itself_needs_no_directory_change(monkeypatch, tmp_path, spelled: str) -> None:
    home, workspace, _worktree = session(tmp_path)
    exit_code, authorized, prepared = run(monkeypatch, call(spelled), workspace, home)
    assert exit_code == 0
    assert authorized == [COMMAND, COMMAND]
    assert prepared == [(workspace, workspace)]


@pytest.mark.parametrize(
    "spelled",
    [
        "missing",
        "~other/app",
        "@app",
        ":app",
        "file:app",
        "https://example.com/app",
        "app\\x",
        "app\N{NO-BREAK SPACE}x",
        3,
        None,
    ],
)
def test_forms_the_host_rewrites_or_cannot_run_never_start(monkeypatch, tmp_path, spelled: object) -> None:
    home, workspace, _worktree = session(tmp_path)
    with pytest.raises(RestrictedPytestError):
        run(monkeypatch, call(spelled), workspace, home)


def test_a_file_named_as_the_directory_never_starts(monkeypatch, tmp_path) -> None:
    home, workspace, _worktree = session(tmp_path)
    (workspace / "notes.txt").write_text("x\n")
    with pytest.raises(RestrictedPytestError):
        run(monkeypatch, call("notes.txt"), workspace, home)


def test_the_call_as_issued_must_carry_the_receipt(monkeypatch, tmp_path) -> None:
    home, workspace, worktree = session(tmp_path)
    blocked = {**required_profile(), "policy_action": "review"}
    with pytest.raises(RestrictedPytestError):
        run(monkeypatch, call(str(worktree)), workspace, home, response=blocked)


def test_a_second_copy_of_the_input_is_rejected(monkeypatch, tmp_path) -> None:
    home, workspace, worktree = session(tmp_path)
    original = call(str(worktree), arguments={"command": COMMAND, "cwd": str(workspace)})
    with pytest.raises(RestrictedPytestError):
        run(monkeypatch, original, workspace, home)
