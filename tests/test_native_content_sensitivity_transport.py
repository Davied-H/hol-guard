"""Native sensitivity outage, binding, deadline and privacy boundary tests."""

from __future__ import annotations

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
                "result": {"ok": "b" * 64},
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
