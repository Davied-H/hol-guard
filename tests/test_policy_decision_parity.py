"""The Decision shape and the recorded parity fixtures shared with the Policy Studio Explain engine."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from codex_plugin_scanner.guard.policy_document_compile import compile_policy_document
from codex_plugin_scanner.guard.policy_document_yaml import parse_policy_document_yaml
from codex_plugin_scanner.guard.policy_tests_runner import run_policy_tests
from codex_plugin_scanner.guard.store import GuardStore

ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "spec" / "guard-policy" / "v1alpha1"
PARITY = SPEC / "fixtures" / "parity"
SCHEMAS = ROOT / "src" / "codex_plugin_scanner" / "guard" / "schemas"
CASES = json.loads((PARITY / "cases.json").read_text(encoding="utf-8"))
DECISIONS = json.loads((PARITY / "decisions.json").read_text(encoding="utf-8"))
DECISION_SCHEMA = json.loads((SPEC / "decision.schema.json").read_text(encoding="utf-8"))
EVENT_CASES = [case for case in CASES["cases"] if "event" in case]


def _recorder():
    spec = importlib.util.spec_from_file_location("record_policy_parity", ROOT / "scripts" / "record_policy_parity.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    ("shared", "packaged"),
    [
        (SPEC / "decision.schema.json", SCHEMAS / "guard-policy-decision-v1alpha1.schema.json"),
        (SPEC / "extensions" / "x-hol.tests.schema.json", SCHEMAS / "guard-policy-x-hol-tests-v1alpha1.schema.json"),
        (SPEC / "schema.json", SCHEMAS / "guard-policy-v1alpha1.schema.json"),
    ],
)
def test_packaged_schemas_are_byte_identical_to_the_shared_spec(shared: Path, packaged: Path) -> None:
    assert packaged.read_bytes() == shared.read_bytes()


def test_decision_schema_is_a_valid_draft_2020_12_schema() -> None:
    Draft202012Validator.check_schema(DECISION_SCHEMA)


def test_parity_corpus_has_ten_events_and_a_decision_for_each() -> None:
    assert len(CASES["cases"]) == 10
    assert sorted(case["id"] for case in CASES["cases"]) == sorted(DECISIONS["decisions"])
    assert DECISIONS["now"] == CASES["now"]


@pytest.mark.parametrize("case_id", sorted(DECISIONS["decisions"]))
def test_recorded_decisions_satisfy_the_decision_schema(case_id: str) -> None:
    decision = DECISIONS["decisions"][case_id]

    assert list(Draft202012Validator(DECISION_SCHEMA).iter_errors(decision)) == []


def test_recorded_decisions_are_exactly_what_the_engine_produces() -> None:
    recorder = _recorder()

    assert recorder.render(recorder.record_decisions()) == (PARITY / "decisions.json").read_text(encoding="utf-8")
    assert recorder.main(["--check"]) == 0


@pytest.mark.parametrize(
    "decision",
    [
        {"effect": "maybe"},
        {"effect": "allow", "ruleId": None, "ambiguous": False, "matchLimitExceeded": False, "tiedRuleIds": []},
    ],
)
def test_decision_schema_rejects_malformed_decisions(decision: dict[str, object]) -> None:
    assert list(Draft202012Validator(DECISION_SCHEMA).iter_errors(decision)) != []


def test_decision_schema_rejects_extra_fields_and_bad_digests() -> None:
    decision = json.loads(json.dumps(next(iter(DECISIONS["decisions"].values()))))
    decision["extra"] = True
    assert list(Draft202012Validator(DECISION_SCHEMA).iter_errors(decision)) != []
    del decision["extra"]
    decision["document"]["digest"] = "sha256:" + "0" * 64
    assert list(Draft202012Validator(DECISION_SCHEMA).iter_errors(decision)) != []


@pytest.mark.parametrize("case", EVENT_CASES, ids=[case["id"] for case in EVENT_CASES])
def test_engine_agrees_with_the_runtime_lookup(tmp_path: Path, case: dict[str, object]) -> None:
    document = parse_policy_document_yaml((PARITY / CASES["documents"][case["document"]]).read_bytes())
    store = GuardStore(tmp_path / "guard")
    store.import_policy_document(
        document,
        compile_policy_document(document),
        mode="replace",
        now="2026-01-01T00:00:00Z",
        approval_gate_grant=None,
    )
    event = case["event"]
    tool = event.get("tool")
    artifact_id = event.get("artifact") or (f"family:{'tool-action' if tool == 'shell' else tool}" if tool else None)

    lookup = store.resolve_policy_decision_lookup(
        event["harness"],
        artifact_id,
        workspace=event.get("workspace"),
        publisher=event.get("publisher"),
        now=event.get("at", CASES["now"]),
        consume_one_shot=False,
    )

    recorded = DECISIONS["decisions"][case["id"]]
    decision = lookup["decision"]
    if recorded["effect"] == "default":
        assert decision is None
        return
    assert decision is not None
    assert decision["action"] == recorded["effect"]
    with store._connect() as connection:
        row = connection.execute(
            "select policy_rule_id from policy_decisions where decision_id = ?", (decision["decision_id"],)
        ).fetchone()
    assert row[0] == recorded["ruleId"]


@pytest.mark.parametrize("relative", ["valid/with-tests.yaml", "valid/enforceable-scopes.yaml"])
def test_fixture_x_hol_tests_all_pass_in_the_engine(relative: str) -> None:
    document = parse_policy_document_yaml((SPEC / "fixtures" / relative).read_bytes())

    run = run_policy_tests(document, now=CASES["now"])

    assert run.results
    assert [result.id for result in run.results if result.status != "pass"] == []
