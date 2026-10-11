"""Native sensitivity outage, binding, deadline and privacy boundary tests."""

from __future__ import annotations

import base64
import gzip
import json
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_content_sensitivity as client


def _resident(monkeypatch: pytest.MonkeyPatch, mutation: str | None = None) -> list[dict[str, object]]:
    identity = SimpleNamespace(path=Path("fixture-runtime"), sha256="a" * 64)
    status = SimpleNamespace(
        available=True,
        compatible=True,
        identity=identity,
        capabilities=SimpleNamespace(features=("resident-protocol-v2", "request-context-v1")),
    )
    monkeypatch.setattr(client, "native_runtime_status", lambda **kwargs: status)
    monkeypatch.setattr(client, "_resolve_digest_home", lambda _: Path("fixture-home").absolute())
    monkeypatch.setattr(client, "_isolated_environment", lambda: {})
    monkeypatch.setattr(client, "native_record_resident_failure", lambda *args, **kwargs: None)
    monkeypatch.setattr(client, "native_record_resident_success", lambda *args, **kwargs: None)
    calls: list[dict[str, object]] = []

    def reply(**kwargs):
        calls.append(kwargs)
        envelope = json.loads(kwargs["payload"])
        request = envelope["request"]
        response = {
            "schema": "guard-request-context-result.v1",
            "request_id": request["request_id"],
            "request_sha256": "sha256:" + client._canonical_request_sha256(request),
            "status": "ok",
            "code": "ok",
            "payload": {
                "kind": "content_sensitivity",
                "query": request["action"]["body"]["query"],
                "result": {"ok": [] if request["action"]["body"]["query"] == "content" else "b" * 64},
            },
        }
        if mutation == "request":
            response["request_id"] = "different-request"
        elif mutation == "digest":
            response["request_sha256"] = "sha256:" + "0" * 64
        elif mutation == "query":
            response["payload"]["query"] = "other"
        elif mutation == "kind":
            response["payload"]["kind"] = "other"
        elif mutation == "extra":
            response["payload"]["allow"] = True
        elif mutation == "error":
            response["status"] = "error"
        elif mutation == "rejected":
            response.update(status="error", code="native_request_context_content_input_invalid", payload=None)
        elif mutation == "missing":
            return None
        elif mutation == "duplicates":
            return b'{"schema":"first","schema":"second"}'
        return json.dumps(response).encode()

    monkeypatch.setattr(client, "native_resident_client_request", reply)
    return calls


@pytest.mark.parametrize("mutation", ["request", "digest", "query", "kind", "extra", "error", "missing", "duplicates"])
def test_sensitivity_rejects_unavailable_malformed_or_unbound_authority(monkeypatch, mutation):
    _resident(monkeypatch, mutation)
    with pytest.raises(client.NativeContentSensitivityError):
        client.content_query("content_version", {})


def test_sensitivity_uses_one_absolute_deadline_for_the_persistent_client(monkeypatch):
    calls = _resident(monkeypatch)
    deadline = time.monotonic() + 0.1
    assert client.content_query("content_version", {}, deadline_monotonic=deadline) == "b" * 64
    assert len(calls) == 1
    assert calls[0]["deadline_monotonic"] == deadline
    envelope = json.loads(calls[0]["payload"])
    assert 0 < envelope["request"]["budget_ms"] <= 100
    assert envelope["request"]["action"] == {
        "kind": "content_sensitivity",
        "body": {"query": "content_version", "input": {}},
    }


def test_expired_sensitivity_deadline_never_opens_a_client(monkeypatch):
    calls = _resident(monkeypatch)
    with pytest.raises(client.NativeContentSensitivityError):
        client.content_query("content_version", {}, deadline_monotonic=0.0)
    assert not calls


def test_sensitivity_outage_obeys_existing_value_error_rejection_contract(monkeypatch):
    _resident(monkeypatch, "missing")
    with pytest.raises(ValueError):
        client.content_query("content_version", {})


@pytest.mark.parametrize("case", ["oversize", "nonfinite", "rejected", "expired_reply"])
def test_caller_rejections_do_not_quarantine_the_shared_resident(monkeypatch, case):
    calls = _resident(monkeypatch, "rejected" if case == "rejected" else None)
    failures = []
    monkeypatch.setattr(client, "native_record_resident_failure", lambda *args, **kwargs: failures.append(kwargs))
    body = {"unused": "x" * (12 * 1024 * 1024)} if case == "oversize" else {}
    if case == "nonfinite":
        body = {"unused": float("nan")}
    if case == "expired_reply":
        now = time.monotonic()
        monkeypatch.setattr(client.time, "monotonic", lambda: now + (1 if calls else 0))
    with pytest.raises(client.NativeContentSensitivityError):
        client.content_query("content_version", body)
    assert not failures
    if case in {"oversize", "nonfinite"}:
        assert not calls


@pytest.mark.parametrize("mutation", ["request", "digest", "missing", "duplicates"])
def test_resident_faults_still_update_shared_health(monkeypatch, mutation):
    _resident(monkeypatch, mutation)
    failures = []
    monkeypatch.setattr(client, "native_record_resident_failure", lambda *args, **kwargs: failures.append(kwargs))
    with pytest.raises(client.NativeContentSensitivityError):
        client.content_query("content_version", {})
    assert len(failures) == 1


def test_state_only_snapshot_never_requires_native_classification(monkeypatch, tmp_path):
    from codex_plugin_scanner.guard.runtime import workspace_snapshot_inputs as snapshots

    entries = [SimpleNamespace(name=".git"), SimpleNamespace(name=".guard")]

    def bounded(*args):
        yield from entries

    def unavailable(*args, **kwargs):
        raise client.NativeContentSensitivityError("offline")

    monkeypatch.setattr(snapshots, "_bounded_entries", bounded)
    monkeypatch.setattr(snapshots, "classify_secret_paths_batch", unavailable)
    monkeypatch.setattr(snapshots, "_check_discovery_budget", lambda *args: None)
    assert list(snapshots._classified_entries(tmp_path, (0, 0), tmp_path, time.monotonic(), [0])) == [
        (entry, False) for entry in entries
    ]


def test_mixed_snapshot_classifies_only_eligible_entries_in_original_order(monkeypatch, tmp_path):
    from codex_plugin_scanner.guard.runtime import workspace_snapshot_inputs as snapshots

    entries = [SimpleNamespace(name=name) for name in [".GIT", "ordinary", ".env", ".guard"]]

    def bounded(*args):
        yield from entries

    calls = []

    def classify(paths, **kwargs):
        calls.append(paths)
        return [None, object()]

    monkeypatch.setattr(snapshots, "_bounded_entries", bounded)
    monkeypatch.setattr(snapshots, "classify_secret_paths_batch", classify)
    monkeypatch.setattr(snapshots, "_check_discovery_budget", lambda *args: None)
    assert list(snapshots._classified_entries(tmp_path, (0, 0), tmp_path, time.monotonic(), [0])) == list(
        zip(entries, [False, False, True, False], strict=True)
    )
    assert calls == [["ordinary", ".env"]]


@pytest.mark.parametrize("text", ["x" * (5 * 1024 * 1024), '\\"' * (5 * 512 * 1024), "界" * (5 * 1024 * 1024 // 3)])
def test_large_output_wire_encoding_is_lossless_and_keeps_the_callers_deadline(monkeypatch, text):
    calls = _resident(monkeypatch)
    body = {"text": text, "suppress_samples": True, "documentation_sample_context": False}
    deadline = time.monotonic() + 30
    assert client.content_query("content", body, deadline_monotonic=deadline) == []
    assert len(calls) == 1
    assert calls[0]["deadline_monotonic"] == deadline
    assert len(calls[0]["payload"]) <= 6 * 1024 * 1024
    packed = json.loads(calls[0]["payload"])["request"]["action"]["body"]["input"]
    decoded = gzip.decompress(base64.b64decode(packed["packed_json_gzip_v1"]))
    assert len(decoded) == packed["decoded_bytes"]
    assert json.loads(decoded) == body


def test_unexpected_binding_recheck_logs_only_exception_class(monkeypatch, caplog):
    from codex_plugin_scanner.guard.runtime import structured_output_mediation as mediation

    calls = []

    def query(query, body, **kwargs):
        calls.append((query, body.copy()))
        return {"recheck_required": True} if query == "mediate_prepare" else None

    def recheck():
        raise LookupError("private payload must never be logged")

    monkeypatch.setattr(mediation, "content_query", query)
    mediation.mediate_native_post_tool_content(
        harness="pi",
        event_name="PostToolUse",
        native_result={},
        validated_receipt=None,
        structured_output_json=None,
        binding=None,
        recheck_binding=recheck,
    )
    assert calls[-1][1]["recheck_error"] is True
    assert "LookupError" in caplog.text
    assert "private payload" not in caplog.text


def test_harness_presentation_is_available_without_native_runtime(monkeypatch):
    from codex_plugin_scanner.guard.runtime import structured_output_mediation as mediation

    def unavailable(*args, **kwargs):
        raise client.NativeContentSensitivityError("offline")

    monkeypatch.setattr(mediation, "content_query", unavailable)
    assert mediation.canonical_harness_name(" Pi_Coding_Agent ") == "pi"
    assert mediation.canonical_harness_name("oh-my-pi") == "omp"


def test_path_batch_requires_exact_result_count(monkeypatch):
    from codex_plugin_scanner.guard.runtime import secret_sensitivity as sensitivity

    monkeypatch.setattr(sensitivity, "content_query", lambda *args, **kwargs: [None])
    with pytest.raises(client.NativeContentSensitivityError):
        sensitivity.classify_secret_paths_batch(["ordinary.txt", ".env"])


def test_path_batch_presents_each_native_dto_in_order(monkeypatch):
    from codex_plugin_scanner.guard.runtime import secret_sensitivity as sensitivity

    calls = []

    def native(query, body, **kwargs):
        calls.append((query, body, kwargs))
        return [
            None,
            {
                "family": "local .env file",
                "path": ".env",
                "sensitivity": "critical",
                "reason": "native fixture",
                "requested_path": ".env",
            },
        ]

    monkeypatch.setattr(sensitivity, "content_query", native)
    result = sensitivity.classify_secret_paths_batch(["ordinary.txt", ".env"], deadline_monotonic=42)
    assert result[0] is None
    assert result[1].family == "local .env file"
    assert len(calls) == 1
    assert calls[0][0] == "path_batch"
    assert calls[0][2] == {"deadline_monotonic": 42}


def test_status_probe_has_request_deadline_and_memo_expires_on_binary_or_manifest_change(monkeypatch, tmp_path):
    _resident(monkeypatch)
    status = client.native_runtime_status()
    binary = tmp_path / "runtime-fixture"
    binary.write_bytes(b"original")
    status.identity.path = binary
    probes = []
    client._status_memo = None

    def probe(*, deadline_monotonic):
        probes.append(deadline_monotonic)
        return status

    monkeypatch.setattr(client, "native_runtime_status", probe)
    monkeypatch.setattr(client, "_scoped_manifest_still_valid", lambda _: True)
    deadline = time.monotonic() + 0.1
    client.content_query("content_version", {}, deadline_monotonic=deadline)
    client.content_query("content_version", {}, deadline_monotonic=deadline)
    assert probes == [deadline]
    binary.write_bytes(b"replacement-with-new-identity")
    client.content_query("content_version", {}, deadline_monotonic=deadline)
    assert len(probes) == 2
    monkeypatch.setattr(client, "_scoped_manifest_still_valid", lambda _: False)
    client.content_query("content_version", {}, deadline_monotonic=deadline)
    assert len(probes) == 3
