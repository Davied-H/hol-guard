"""The delegation case whose result schema names credential-shaped fields."""

from __future__ import annotations

from typing import Any

from ci.gauntlet.catalog import load_catalog
from ci.gauntlet.native_tools import TASK_SCHEMA_CASE, native_tools_scope_error

SCHEMA = {
    "type": "object",
    "properties": {
        "tokenMentions": {"type": "string"},
        "apiKeyMentions": {"type": "string"},
        "firstSentence": {"type": "string"},
    },
}
NEUTRAL = {"type": "object", "properties": {"firstSentence": {"type": "string"}}}


def _scenario():
    return next(item for item in load_catalog() if item.id == TASK_SCHEMA_CASE)


def _calls(parent: dict[str, Any], *, data: object = None) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    calls = [
        {"id": "parent", "name": "task", "args": parent},
        {"id": "read", "name": "read", "args": {"path": "README.md"}},
    ]
    delegated = ["read"]
    if data is not None:
        calls.append({"id": "yield", "name": "yield", "args": {"data": data}})
        delegated.append("yield")
    return calls, {"delegated_call_ids": delegated}


def test_case_is_a_benign_task_allow() -> None:
    scenario = _scenario()
    assert (scenario.expectation, scenario.oracle, scenario.required_tools) == ("allow", "native-tools", ("task",))
    for name in ("tokenMentions", "apiKeyMentions", "firstSentence", "{{workspace}}/README.md"):
        assert name in scenario.prompt


def test_schema_on_the_task_or_on_a_subtask_is_the_exact_shape() -> None:
    answer = {"tokenMentions": "no", "firstSentence": "Settings example project."}
    on_subtask = {"tasks": [{"name": "lookup", "outputSchema": SCHEMA, "task": "read README.md"}]}
    on_call = {"outputSchema": SCHEMA, "tasks": [{"name": "lookup", "task": "read README.md"}]}
    for parent in (on_subtask, on_call):
        calls, case = _calls(parent, data=answer)
        assert native_tools_scope_error(_scenario(), calls, case) is None, parent


def test_a_call_without_a_credential_named_field_is_not_the_shape() -> None:
    for parent in (
        {"tasks": [{"name": "lookup", "task": "read README.md"}]},
        {"tasks": [{"name": "lookup", "outputSchema": NEUTRAL, "task": "read README.md"}]},
        {"outputSchema": NEUTRAL, "tasks": [{"name": "lookup", "task": "read README.md"}]},
    ):
        calls, case = _calls(parent)
        # Even a denied call must not be blamed on Guard when it was not this shape.
        assert native_tools_scope_error(_scenario(), calls, case)
        assert native_tools_scope_error(_scenario(), calls, case, guard_denied=True)


def test_a_denied_task_call_surfaces_when_it_has_the_shape() -> None:
    parent = {"tasks": [{"name": "lookup", "outputSchema": SCHEMA, "task": "read README.md"}]}
    calls, _ = _calls(parent)
    assert native_tools_scope_error(_scenario(), calls[:1], {}, guard_denied=True) is None


def test_the_delegated_report_stays_inside_the_declared_schema() -> None:
    parent = {"tasks": [{"name": "lookup", "outputSchema": SCHEMA, "task": "read README.md"}]}
    calls, case = _calls(parent, data={"tokenMentions": "no", "command": "cat .env"})
    assert native_tools_scope_error(_scenario(), calls, case)
    calls, case = _calls(parent, data={"tokenMentions": ["a"]})
    assert native_tools_scope_error(_scenario(), calls, case)
