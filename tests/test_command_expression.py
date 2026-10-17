from __future__ import annotations

from typing import Literal

import pytest

from codex_plugin_scanner.guard.runtime.command_expression import (
    CommandCondition,
    CommandExpression,
    CommandExpressionError,
    command_expression_from_mapping,
    validate_command_expression,
)


def _expression(combinator: Literal["all", "any"], *conditions: CommandCondition) -> CommandExpression:
    return CommandExpression(combinator=combinator, conditions=tuple(conditions))


def test_a_condition_keeps_its_spelling_and_loses_only_its_spacing() -> None:
    condition = CommandCondition("command", "startsWith", "  docker   compose  ")

    assert condition.value == "docker compose"


def test_a_valid_regex_compiles_while_the_document_is_validated() -> None:
    expression = _expression(
        "all",
        CommandCondition("command", "regex", r"^docker\s+compose\s+(up|down)$"),
    )

    validate_command_expression(expression)


def test_invalid_regex_is_rejected_before_evaluation() -> None:
    expression = _expression("all", CommandCondition("command", "regex", "[unclosed"))

    with pytest.raises(CommandExpressionError, match="invalid_command_regex"):
        validate_command_expression(expression)


def test_an_unclosed_glob_class_is_rejected_before_evaluation() -> None:
    expression = _expression("all", CommandCondition("command", "glob", "docker [compose"))

    with pytest.raises(CommandExpressionError, match="glob_class_unclosed"):
        validate_command_expression(expression)


def test_an_operator_outside_the_dialect_is_refused() -> None:
    with pytest.raises(CommandExpressionError, match="unsupported_command_pattern_operator"):
        CommandCondition("command", "matches", "git push")  # type: ignore[arg-type]


def test_omitted_case_flag_parses_as_case_insensitive() -> None:
    expression = command_expression_from_mapping(
        {
            "combinator": "all",
            "conditions": [{"field": "command", "operator": "exact", "value": "git push"}],
        }
    )

    assert expression.conditions[0].case_sensitive is False


def test_mapping_requires_explicit_boolean_combinator() -> None:
    with pytest.raises(CommandExpressionError, match="command_expression_combinator_required"):
        command_expression_from_mapping(
            {"conditions": [{"field": "command", "operator": "exact", "value": "git push"}]}
        )
