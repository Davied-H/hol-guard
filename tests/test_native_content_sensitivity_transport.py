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
    monkeypatch.setattr(client, "native_runtime_status", lambda: status)
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
