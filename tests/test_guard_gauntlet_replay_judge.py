"""The replay lane's strict judge, without the native runtime."""

from __future__ import annotations

from tests.gauntlet_replay import ReplayCase, expand, judge


def _case(expect: str, harness: str = "claude-code") -> ReplayCase:
    return ReplayCase(f"x@{harness}", "x", harness, "shell", {"command": "ls"}, "worktree", expect)


_QUIET = {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow"}}


def test_quiet_allow_passes() -> None:
    assert judge(_case("quiet"), _QUIET, []) is None


def test_warn_with_rendered_text_fails_ordinary_work() -> None:
    warned = {**_QUIET, "policy_action": "warn", "systemMessage": "Guard warning"}
    assert judge(_case("quiet"), warned, []) is not None


def test_warn_without_text_is_quiet() -> None:
    assert (
        judge(_case("quiet"), {**_QUIET, "policy_action": "warn", "reason_code": "native_policy_warning"}, []) is None
    )


def test_approval_row_fails_ordinary_work() -> None:
    assert judge(_case("quiet"), _QUIET, [{"tool_name": "Bash", "reason_code": "r"}]) is not None


def test_ask_fails_ordinary_work() -> None:
    asked = {"hookSpecificOutput": {"permissionDecision": "ask", "permissionDecisionReason": "review"}}
    assert judge(_case("quiet"), asked, []) is not None


def test_always_needs_an_exact_action_token() -> None:
    asked = {"hookSpecificOutput": {"permissionDecision": "ask"}}
    plain = {"tool_name": "Bash", "always_available": False, "exact_context_token_present": False}
    offered = {"tool_name": "Bash", "always_available": False, "exact_context_token_present": True}
    assert judge(_case("always"), asked, [plain]) is not None
    assert judge(_case("always"), asked, [offered]) is None


def test_attack_must_not_be_allowed() -> None:
    denied = {"hookSpecificOutput": {"permissionDecision": "deny"}}
    assert judge(_case("block"), _QUIET, []) is not None
    assert judge(_case("block"), denied, []) is None


def test_expansion_covers_pi_and_every_harness() -> None:
    cases = expand()
    assert {c.harness for c in cases} == {"codex", "zcode", "claude-code", "omp", "pi"}
    assert next(c for c in cases if c.case_id == "omp-todo-phases@pi").tool_name == "todo"
