"""Strict request-bound sensitivity DTOs through the existing persistent client."""

from __future__ import annotations

import json
import os
import sys
import time
from typing import Any
from uuid import uuid4

from .native_context import _canonical_request_sha256, _resolve_digest_home
from .native_resident_client import native_resident_client_request
from .native_runtime import _isolated_environment, native_runtime_status
from .native_runtime_resilience import native_record_resident_failure, native_record_resident_success
from .strict_json_pairs import unique_json_object

_RESULT_SCHEMA = "guard-request-context-result.v1"


class NativeContentSensitivityError(RuntimeError):
    """Missing, expired or unbound native authority; callers must fail closed."""


def content_query(query: str, body: dict[str, Any], *, deadline_monotonic: float | None = None) -> Any:
    deadline = min(time.monotonic() + 0.5, deadline_monotonic if deadline_monotonic is not None else float("inf"))
    status = native_runtime_status()
    if (
        time.monotonic() >= deadline
        or not status.available
        or not status.compatible
        or status.identity is None
        or status.capabilities is None
        or not {"resident-protocol-v2", "request-context-v1"} <= set(status.capabilities.features)
    ):
        raise NativeContentSensitivityError("native_content_sensitivity_unavailable")
    home = _resolve_digest_home(None)
    request: dict[str, Any] = {
        "schema": "guard-request-context-request.v1",
        "request_id": f"content-sensitivity-{uuid4().hex}",
        "guard_home": str(home),
        "source": "hook",
        "budget_ms": max(1, int((deadline - time.monotonic()) * 1000)),
        "owner_uid": None if sys.platform == "win32" else os.geteuid(),
        "action": {"kind": "content_sensitivity", "body": {"query": query, "input": body}},
    }
    try:
        digest = "sha256:" + _canonical_request_sha256(request)
        encoded = json.dumps(
            {"operation": "request_context_build", "request": request, "deadline_budget_ms": request["budget_ms"]}
        ).encode("utf-8")
        if len(encoded) > 256 * 1024 or time.monotonic() >= deadline:
            raise NativeContentSensitivityError("native_content_sensitivity_request_invalid")
        raw = native_resident_client_request(
            executable=status.identity.path,
            guard_home=home,
            environment=_isolated_environment(),
            payload=encoded,
            deadline_monotonic=deadline,
        )
        if raw is None or len(raw) > 256 * 1024:
            raise NativeContentSensitivityError("native_content_sensitivity_unavailable")
        response = json.loads(raw, object_pairs_hook=unique_json_object)
        if (
            not isinstance(response, dict)
            or set(response) != {"schema", "request_id", "request_sha256", "status", "code", "payload"}
            or response["schema"] != _RESULT_SCHEMA
            or response["request_id"] != request["request_id"]
            or response["request_sha256"] != digest
        ):
            raise NativeContentSensitivityError("native_content_sensitivity_unbound")
        payload = response["payload"]
        if (
            response["status"] != "ok"
            or response["code"] != "ok"
            or not isinstance(payload, dict)
            or set(payload) != {"kind", "query", "result"}
        ):
            raise NativeContentSensitivityError("native_content_sensitivity_unavailable")
        if payload["kind"] != "content_sensitivity" or payload["query"] != query or time.monotonic() >= deadline:
            raise NativeContentSensitivityError("native_content_sensitivity_unbound")
        result = payload["result"]
        if not isinstance(result, dict) or set(result) not in ({"ok"}, {"error", "type"}):
            raise NativeContentSensitivityError("native_content_sensitivity_malformed")
        if "error" in result and (
            result["type"] != "ValueError" or not isinstance(result["error"], str) or len(result["error"]) > 512
        ):
            raise NativeContentSensitivityError("native_content_sensitivity_malformed")
        if "ok" in result and not _dto_shape(query, result["ok"]):
            raise NativeContentSensitivityError("native_content_sensitivity_malformed")
    except (KeyError, OSError, RuntimeError, TypeError, ValueError) as exc:
        native_record_resident_failure(status.identity.sha256, home, reason="native_content_sensitivity_unavailable")
        raise NativeContentSensitivityError("native_content_sensitivity_unavailable") from exc
    native_record_resident_success(status.identity.sha256, home)
    if "error" in result:
        raise ValueError(result["error"])
    return result["ok"]


def _record(value: Any, keys: set[str], strings: set[str] | frozenset[str] = frozenset()) -> bool:
    return (
        isinstance(value, dict)
        and set(value) == keys
        and all(isinstance(value[key], str) and len(value[key]) <= 4096 for key in strings)
    )


def _digest(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(ch in "0123456789abcdef" for ch in value)


def _fields(value: Any) -> bool:
    return (
        isinstance(value, list)
        and 0 < len(value) <= 64
        and all(
            _record(field, {"path", "role", "value_type", "category"}, {"role", "value_type"})
            and isinstance(field["path"], list)
            and 0 < len(field["path"]) <= 8
            and all(isinstance(part, str) and len(part) <= 64 for part in field["path"])
            and (field["category"] is None or isinstance(field["category"], str))
            for field in value
        )
    )


def _policy(value: Any) -> bool:
    return (
        _record(value, {"harnesses", "schema"})
        and isinstance(value["harnesses"], list)
        and all(isinstance(harness, str) for harness in value["harnesses"])
        and _record(value["schema"], {"fields"})
        and _fields(value["schema"]["fields"])
    )


def _binding(value: Any) -> bool:
    return value is None or (
        _record(value, {"harness", "managed_policy_hash", "policy", "rule_version"}, {"harness"})
        and (_digest(value["managed_policy_hash"]) and _digest(value["rule_version"]) and _policy(value["policy"]))
    )


def _dto_shape(query: str, value: Any) -> bool:
    if query in {"content_version", "classifier_version"}:
        return _digest(value)
    if query in {"canonical", "harness"}:
        return isinstance(value, str) or (query == "canonical" and value is None)
    if query == "path":
        return value is None or (
            _record(
                value,
                {"family", "path", "sensitivity", "reason", "requested_path"},
                {"family", "path", "sensitivity", "reason", "requested_path"},
            )
            and value["sensitivity"] in {"high", "critical"}
        )
    if query == "legacy":
        return isinstance(value, list) and len(value) <= 9 and all(isinstance(item, str) for item in value)
    if query == "content":
        return (
            isinstance(value, list)
            and len(value) <= 10
            and all(
                _record(
                    item,
                    {"classifier", "family", "sensitivity", "reason"},
                    {"classifier", "family", "sensitivity", "reason"},
                )
                and item["sensitivity"] in {"medium", "high", "critical"}
                for item in value
            )
        )
    if query == "fields":
        return _fields(value)
    if query == "policy":
        return _policy(value)
    if query == "resolution":
        return (
            _record(value, {"binding", "required", "reason_code"})
            and type(value["required"]) is bool
            and (value["reason_code"] is None or isinstance(value["reason_code"], str))
            and _binding(value["binding"])
        )
    if query in {"declared", "declared_bytes"}:
        return (
            _record(
                value,
                {"status", "matches", "complete", "reason_code", "bytes_scanned", "fields_scanned", "rule_version"},
                {"status", "reason_code"},
            )
            and value["status"] in {"matched", "no_declared_match", "unsupported"}
            and (
                type(value["complete"]) is bool
                and _digest(value["rule_version"])
                and all(
                    type(value[key]) is int and 0 <= value[key] <= 65536 for key in ("bytes_scanned", "fields_scanned")
                )
                and (
                    isinstance(value["matches"], list)
                    and len(value["matches"]) <= 16
                    and all(
                        _record(
                            item,
                            {"category", "sensitivity", "field_path", "reason"},
                            {"category", "sensitivity", "reason"},
                        )
                        and (
                            isinstance(item["field_path"], list)
                            and all(isinstance(part, str) for part in item["field_path"])
                        )
                        for item in value["matches"]
                    )
                )
            )
        )
    if query in {"mediate_prepare", "mediate_finish"}:
        return (
            value is None
            or (_record(value, {"recheck_required"}) and value["recheck_required"] is True)
            or (
                _record(
                    value, {"action", "reason_code", "native_decision_id", "content_sha256"}, {"action", "reason_code"}
                )
                and value["action"] in {"forward", "withhold"}
                and (value["native_decision_id"] is None or isinstance(value["native_decision_id"], str))
                and (
                    _digest(value["content_sha256"])
                    if value["action"] == "forward"
                    else value["content_sha256"] is None
                )
            )
        )
    return False
