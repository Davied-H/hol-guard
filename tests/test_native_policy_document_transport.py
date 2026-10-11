"""Transport, DTO, and paging boundaries; algorithms replay in compiled Rust."""

from __future__ import annotations

import json
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_policy_document as client
from codex_plugin_scanner.guard import policy_document as document
from codex_plugin_scanner.guard import policy_document_compile as compiler


def _resident(monkeypatch, mutation=None, result=None):
    identity = SimpleNamespace(path=Path("document-runtime"), sha256="a" * 64)
    status = SimpleNamespace(
        available=True,
        compatible=True,
        identity=identity,
        capabilities=SimpleNamespace(features=("request-context-v1", "resident-protocol-v2")),
    )
    monkeypatch.setattr(client, "native_runtime_status", lambda **kwargs: status)
    monkeypatch.setattr(client, "validate_native_binary", lambda _: identity)
    monkeypatch.setattr(client, "_resolve_digest_home", lambda _: Path("document-home").absolute())
    monkeypatch.setattr(client, "_isolated_environment", lambda: {})
    calls = []

    def reply(**kwargs):
        calls.append(kwargs)
        request = json.loads(kwargs["payload"])["request"]
        response = {
            "schema": "guard-request-context-result.v1",
            "request_id": request["request_id"],
            "request_sha256": "sha256:" + client._canonical_request_sha256(request),
            "status": "ok",
            "code": "ok",
            "payload": {
                "kind": "policy_document",
                "query": request["action"]["body"]["query"],
                "result": {"ok": {}} if result is None else result,
            },
        }
        if mutation in {"request_id", "request_sha256"}:
            response[mutation] = "wrong"
        elif mutation in {"kind", "query"}:
            response["payload"][mutation] = "wrong"
        elif mutation == "extra":
            response["allow"] = True
        elif mutation == "missing":
            return None
        elif mutation == "duplicates":
            return b'{"schema":"first","schema":"second"}'
        elif mutation == "error":
            response["status"] = "error"
        return json.dumps(response).encode()

    monkeypatch.setattr(client, "native_resident_client_request", reply)
    return calls, status


@pytest.mark.parametrize(
    "mutation", ["request_id", "request_sha256", "kind", "query", "extra", "missing", "duplicates", "error"]
)
def test_document_rejects_unavailable_unbound_or_malformed_native_authority(monkeypatch, mutation):
    _resident(monkeypatch, mutation)
    with pytest.raises(client.NativePolicyDocumentError):
        client.policy_query("canonical", {"value": {}})


def test_document_preserves_one_absolute_deadline_and_expected_runtime_identity(monkeypatch):
    calls, status = _resident(monkeypatch)
    deadline = time.monotonic() + 1
    assert (
        client.policy_query(
            "canonical", {"value": {}}, deadline_monotonic=deadline, runtime_sha256=status.identity.sha256
        )
        == {}
    )
    assert len(calls) == 1
    assert calls[0]["deadline_monotonic"] == deadline
    request = json.loads(calls[0]["payload"])["request"]
    assert 0 < request["budget_ms"] <= 1000
    assert request["action"] == {"kind": "policy_document", "body": {"query": "canonical", "input": {"value": {}}}}


@pytest.mark.parametrize("case", ["deadline", "runtime_change", "missing_binary", "nonfinite"])
def test_document_rejects_before_transport_without_native_authority(monkeypatch, case):
    calls, _ = _resident(monkeypatch)
    kwargs = {}
    body = {"value": {}}
    if case == "deadline":
        kwargs["deadline_monotonic"] = 0.0
    elif case == "runtime_change":
        kwargs["runtime_sha256"] = "b" * 64
    elif case == "missing_binary":
        monkeypatch.setattr(client, "validate_native_binary", lambda _: None)
    else:
        body = {"value": float("nan")}
    with pytest.raises(client.NativePolicyDocumentError):
        client.policy_query("canonical", body, **kwargs)
    assert not calls


@pytest.mark.parametrize(
    "kind,exception", [("TypeError", TypeError), ("ValueError", ValueError), ("CommandExpressionError", ValueError)]
)
def test_document_preserves_native_semantic_error_types(monkeypatch, kind, exception):
    _resident(monkeypatch, result={"error": {"type": kind, "message": "fixture_error"}})
    with pytest.raises(exception, match="fixture_error"):
        client.policy_query("from_mapping", {})


def test_document_preserves_compilation_error_code_and_rule_id(monkeypatch):
    _resident(
        monkeypatch,
        result={
            "error": {
                "type": "PolicyCompilationError",
                "message": "unsupported:fixture",
                "code": "unsupported",
                "rule_id": "fixture",
            }
        },
    )
    with pytest.raises(compiler.PolicyCompilationError) as caught:
        client.policy_query("compile", {})
    assert (caught.value.code, caught.value.rule_id) == ("unsupported", "fixture")


def _compile_transport(monkeypatch, mutation=None):
    source = SimpleNamespace(to_mapping=lambda: {"native-source": "fixture"})
    monkeypatch.setattr(
        compiler, "native_runtime_status", lambda **kwargs: SimpleNamespace(identity=SimpleNamespace(sha256="a" * 64))
    )
    calls = []

    def page(query, body, **kwargs):
        calls.append((query, body.copy(), kwargs.copy()))
        offset = body["offset"]
        item = {
            "rule_id": "native-rule",
            "provenance_json": "{}",
            "decision": {"harness": "pi", "scope": "harness", "action": "block"},
        }
        result = {"items": [item.copy() for _ in range(min(32, 65 - offset))], "offset": offset, "total": 65}
        if mutation == "offset":
            result["offset"] += 1
        elif mutation == "short":
            result["items"].pop()
        elif mutation == "total" and offset:
            result["total"] = 64
        elif mutation == "action":
            result["items"][0]["decision"] = {"harness": "pi", "scope": "harness", "action": "claimed_allow"}
        elif mutation == "type":
            result["items"][0]["decision"] = {"harness": [], "scope": "harness", "action": "block"}
        elif mutation == "scope":
            result["items"][0]["decision"] = {"harness": "pi", "scope": "claimed-global", "action": "block"}
        return result

    monkeypatch.setattr(compiler, "policy_query", page)
    return source, calls


def test_compiled_rows_present_native_pages_without_recomputing_actions(monkeypatch):
    source, calls = _compile_transport(monkeypatch)
    rows = compiler.compile_policy_document(source)
    assert len(rows) == 65
    assert {row.decision.action for row in rows} == {"block"}
    assert [body["offset"] for _, body, _ in calls] == [0, 32, 64]
    assert len({kwargs["deadline_monotonic"] for _, _, kwargs in calls}) == 1
    assert {kwargs["runtime_sha256"] for _, _, kwargs in calls} == {"a" * 64}


@pytest.mark.parametrize("mutation", ["offset", "short", "total", "action", "type", "scope"])
def test_compiled_rows_reject_unbound_pages_and_invalid_dto_fields(monkeypatch, mutation):
    source, _ = _compile_transport(monkeypatch, mutation)
    with pytest.raises(client.NativePolicyDocumentError):
        compiler.compile_policy_document(source)


def test_native_document_dto_never_runs_python_command_normalization(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Python normalization called")

    monkeypatch.setattr(document.CommandCondition, "__post_init__", forbidden)
    expression = {
        "combinator": "all",
        "conditions": [{"field": "command", "operator": "exact", "value": "native value", "case_sensitive": False}],
    }
    value = document._decode_dto(document.CommandExpression, expression)
    assert value.conditions[0].value == "native value"
    assert isinstance(value.conditions, tuple)


@pytest.mark.parametrize(
    "value",
    [{}, {"combinator": "all", "conditions": []}, {"combinator": "all", "conditions": [], "claimed_allow": True}],
)
def test_native_document_dto_rejects_missing_or_extra_fields(monkeypatch, value):
    if set(value) == {"combinator", "conditions"}:
        value["conditions"] = False
    with pytest.raises(client.NativePolicyDocumentError):
        document._decode_dto(document.CommandExpression, value)


def test_canonical_projection_rejects_non_string_native_output(monkeypatch):
    monkeypatch.setattr(document, "policy_query", lambda *args, **kwargs: {"claimed_allow": True})
    with pytest.raises(client.NativePolicyDocumentError):
        document.canonical_json_bytes({})
