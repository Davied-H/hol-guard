from __future__ import annotations

import copy
import json
from dataclasses import asdict
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator

from codex_plugin_scanner.guard.policy_document import (
    canonical_policy_document_bytes,
    policy_document_digest,
)
from codex_plugin_scanner.guard.policy_document_compile import compile_policy_document
from codex_plugin_scanner.guard.policy_document_yaml import parse_policy_document_yaml

ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "spec" / "guard-policy" / "v1alpha1"
EXTENSION_SCHEMA = SPEC / "extensions" / "x-hol.tests.schema.json"
FIXTURE = SPEC / "fixtures" / "valid" / "with-tests.yaml"


def _validator() -> Draft202012Validator:
    schema = json.loads(EXTENSION_SCHEMA.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def _fixture_mapping() -> dict[str, object]:
    document = parse_policy_document_yaml(FIXTURE.read_bytes())
    return json.loads(canonical_policy_document_bytes(document))


def _rows(document_mapping: dict[str, object]) -> list[tuple[str, dict[str, object], str]]:
    source = yaml.safe_dump(document_mapping, allow_unicode=True, sort_keys=False)
    rows = compile_policy_document(parse_policy_document_yaml(source))
    return [(row.rule_id, asdict(row.decision), row.provenance_json) for row in rows]


def test_fixture_extension_value_matches_registered_schema() -> None:
    mapping = _fixture_mapping()
    tests = mapping["spec"]["x-hol.tests"]

    assert [test["id"] for test in tests] == [
        "mcp-blocked",
        "trusted-plugin-allowed",
        "unknown-plugin-falls-through",
    ]
    assert list(_validator().iter_errors(tests)) == []


def test_fixture_expectations_reference_rules_in_the_document() -> None:
    mapping = _fixture_mapping()
    rule_ids = {rule["id"] for rule in mapping["spec"]["rules"]}

    for test in mapping["spec"]["x-hol.tests"]:
        expected_rule = test["expect"].get("ruleId")
        if expected_rule is not None:
            assert expected_rule in rule_ids


def test_extension_changes_digest_but_not_compiled_rows() -> None:
    with_tests = _fixture_mapping()
    without_tests = copy.deepcopy(with_tests)
    del without_tests["spec"]["x-hol.tests"]

    with_digest = policy_document_digest(parse_policy_document_yaml(FIXTURE.read_bytes()))
    without_digest = policy_document_digest(
        parse_policy_document_yaml(yaml.safe_dump(without_tests, allow_unicode=True, sort_keys=False))
    )

    assert with_digest != without_digest
    assert _rows(with_tests) == _rows(without_tests)
    assert {rule_id for rule_id, _, _ in _rows(with_tests)} == {"block-mcp", "allow-trusted-plugin"}


@pytest.mark.parametrize(
    "value",
    [
        {"id": "not-a-list"},
        [{"id": "missing-event", "expect": {"effect": "allow"}}],
        [{"id": "no-harness", "event": {"tool": "mcp"}, "expect": {"effect": "allow"}}],
        [{"id": "bad-tool", "event": {"harness": "codex", "tool": "browser"}, "expect": {"effect": "block"}}],
        [{"id": "review", "event": {"harness": "codex"}, "expect": {"effect": "review"}}],
        [
            {
                "id": "local-time",
                "event": {"harness": "codex", "at": "2026-11-01T00:00:00+02:00"},
                "expect": {"effect": "allow"},
            }
        ],
        [{"id": "raw-command", "event": {"harness": "codex", "command": "rm -rf /"}, "expect": {"effect": "block"}}],
        [{"id": "-leading-dash", "event": {"harness": "codex"}, "expect": {"effect": "default"}}],
        [{"id": f"t{index}", "event": {"harness": "codex"}, "expect": {"effect": "default"}} for index in range(257)],
    ],
    ids=[
        "not-an-array",
        "missing-event",
        "missing-harness",
        "unknown-tool-family",
        "unsupported-effect",
        "non-utc-timestamp",
        "raw-command-field",
        "invalid-identifier",
        "too-many-tests",
    ],
)
def test_invalid_extension_values_are_rejected(value: object) -> None:
    assert list(_validator().iter_errors(value)) != []
