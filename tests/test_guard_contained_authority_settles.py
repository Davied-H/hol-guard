"""A contained run waits for a decision instead of cancelling ordinary work."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime import contained_test_hook as sink
from codex_plugin_scanner.guard.runtime.contained_authority import authority_unavailable, settled_authority
from codex_plugin_scanner.guard.runtime.restricted_pytest import RestrictedPytestError
from codex_plugin_scanner.guard.runtime.restricted_pytest_model import PYTEST_INVALID_COMMAND_REASON_CODE

UNAVAILABLE = {
    "decision": "block",
    "policy_action": "block",
    "reason_code": "native_hook_worker_exception",
}
ALLOW = {"decision": "allow", "policy_action": "allow"}


def test_an_undecided_runtime_is_asked_again() -> None:
    answers = [UNAVAILABLE, UNAVAILABLE, ALLOW]
    asked: list[dict[str, object]] = []
    slept: list[float] = []

    def authorize(payload: dict[str, object]) -> object:
        asked.append(payload)
        return answers[len(asked) - 1]

    assert settled_authority(authorize, {"tool_input": {}}, pause=slept.append) == ALLOW
    assert len(asked) == 3
    assert slept == [0.75, 0.75]


def test_a_decision_is_taken_as_it_stands() -> None:
    asked: list[dict[str, object]] = []

    def authorize(payload: dict[str, object]) -> object:
        asked.append(payload)
        return ALLOW

    def never(_seconds: float) -> None:
        raise AssertionError("a settled decision must not be re-asked")

    assert settled_authority(authorize, {"tool_input": {}}, pause=never) == ALLOW
    assert len(asked) == 1


def test_an_unreachable_runtime_is_not_mistaken_for_a_verdict() -> None:
    assert authority_unavailable(UNAVAILABLE)
    assert not authority_unavailable(ALLOW)
    assert not authority_unavailable({"reason_code": "native_workspace_containment_required"})
    assert not authority_unavailable("native_hook_worker_exception")


def test_a_script_that_is_not_pytest_reports_the_authorization_that_failed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`python3 scripts/report.py` has no pytest invocation to correct.

    The read-only pytest planner is the last shape the dispatcher tries, so
    its "accepts only a pytest executable" message would send the user after
    an invocation that was never in their command.
    """
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    _ = (scripts / "report.py").write_text("print('report')\n", encoding="utf-8")

    def not_a_pytest(*_args: object, **_kwargs: object) -> object:
        raise RestrictedPytestError(
            PYTEST_INVALID_COMMAND_REASON_CODE,
            "Restricted pytest accepts only a pytest executable or a Python `-m pytest` invocation.",
        )

    from codex_plugin_scanner.guard import native_restricted_pytest

    monkeypatch.setattr(
        native_restricted_pytest,
        "restricted_native",
        lambda *_args, **_kwargs: {
            "inline_eval": False,
            "node_test": False,
            "vitest": False,
            "git": False,
            "node_tool": False,
        },
    )
    monkeypatch.setattr(sink, "prepare_restricted_pytest", not_a_pytest)
    with pytest.raises(RestrictedPytestError) as failure:
        _ = sink.run_authorized_contained_test(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "bash",
                "tool_input": {"command": "python3 scripts/report.py"},
            },
            workspace=tmp_path,
            authorize=lambda _payload: UNAVAILABLE,
            timeout_seconds=30,
        )
    assert failure.value.reason_code == "contained_test_authorization_failed"
