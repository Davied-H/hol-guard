"""Request-bound portable policy DTOs through the existing persistent client."""

from __future__ import annotations

import json
import os
import sys
import time
from typing import Any
from uuid import uuid4

from .native_binary_identity import validate_native_binary
from .native_context import _canonical_request_sha256, _resolve_digest_home
from .native_resident_client import native_resident_client_request
from .native_runtime import _isolated_environment, native_runtime_status
from .strict_json_pairs import unique_json_object


class NativePolicyDocumentError(ValueError, RuntimeError):
    """Unavailable or unbound native authority cannot compile a policy."""


def policy_query(
    query: str,
    body: dict[str, Any],
    *,
    deadline_monotonic: float | None = None,
    runtime_sha256: str | None = None,
) -> Any:
    deadline = deadline_monotonic if deadline_monotonic is not None else time.monotonic() + 30.0
    if time.monotonic() >= deadline:
        raise NativePolicyDocumentError("native_policy_document_unavailable")
    status = native_runtime_status(deadline_monotonic=deadline)
    if (
        not status.available
        or not status.compatible
        or status.identity is None
        or status.capabilities is None
        or "request-context-v1" not in status.capabilities.features
        or "resident-protocol-v2" not in status.capabilities.features
    ):
        raise NativePolicyDocumentError("native_policy_document_unavailable")
    identity = validate_native_binary(status.identity.path)
    if (
        identity is None
        or identity != status.identity
        or (runtime_sha256 is not None and identity.sha256 != runtime_sha256)
    ):
        raise NativePolicyDocumentError("native_policy_document_runtime_changed")
    home = _resolve_digest_home(None)
    request = {
        "schema": "guard-request-context-request.v1",
        "request_id": f"policy-document-{uuid4().hex}",
        "guard_home": str(home),
        "source": "direct_command",
        "owner_uid": None if sys.platform == "win32" else os.geteuid(),
        "budget_ms": max(1, int((deadline - time.monotonic()) * 1000)),
        "action": {"kind": "policy_document", "body": {"query": query, "input": body}},
    }
    try:
        digest = "sha256:" + _canonical_request_sha256(request)
        wire = json.dumps(
            {"operation": "request_context_build", "request": request, "deadline_budget_ms": request["budget_ms"]},
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
        if len(wire) > 6 * 1024 * 1024 or time.monotonic() >= deadline:
            raise NativePolicyDocumentError("native_policy_document_request_invalid")
        raw = native_resident_client_request(
            executable=identity.path,
            guard_home=home,
            environment=_isolated_environment(),
            payload=wire,
            deadline_monotonic=deadline,
        )
        if raw is None or len(raw) > 2 * 1024 * 1024:
            raise NativePolicyDocumentError("native_policy_document_unavailable")
        response = json.loads(raw, object_pairs_hook=unique_json_object)
        if (
            not isinstance(response, dict)
            or set(response) != {"schema", "request_id", "request_sha256", "status", "code", "payload"}
            or response["schema"] != "guard-request-context-result.v1"
            or response["request_id"] != request["request_id"]
            or response["request_sha256"] != digest
            or response["status"] != "ok"
            or response["code"] != "ok"
        ):
            raise NativePolicyDocumentError("native_policy_document_unbound")
        payload = response["payload"]
        if (
            not isinstance(payload, dict)
            or set(payload) != {"kind", "query", "result"}
            or payload["kind"] != "policy_document"
            or payload["query"] != query
            or time.monotonic() >= deadline
        ):
            raise NativePolicyDocumentError("native_policy_document_unbound")
        result = payload["result"]
        if not isinstance(result, dict) or set(result) not in ({"ok"}, {"error"}):
            raise NativePolicyDocumentError("native_policy_document_malformed")
        if "error" in result:
            error = result["error"]
            if (
                not isinstance(error, dict)
                or set(error) not in ({"type", "message"}, {"type", "message", "code", "rule_id"})
                or not all(isinstance(value, str) and len(value) <= 512 for value in error.values())
            ):
                raise NativePolicyDocumentError("native_policy_document_malformed")
    except (KeyError, OSError, RuntimeError, TypeError, ValueError) as exc:
        raise NativePolicyDocumentError("native_policy_document_unavailable") from exc
    if "error" in result:
        error = result["error"]
        if error["type"] == "PolicyCompilationError" and set(error) == {"type", "message", "code", "rule_id"}:
            from .policy_document_types import PolicyCompilationError

            raise PolicyCompilationError(error["code"], error["rule_id"])
        if error["type"] == "CommandExpressionError":
            from .runtime.command_expression import CommandExpressionError

            raise CommandExpressionError(error["message"])
        if error["type"] == "KeyError":
            raise KeyError(error["message"].strip("'"))
        if error["type"] == "TypeError":
            raise TypeError(error["message"])
        if error["type"] == "ValueError":
            raise ValueError(error["message"])
        raise NativePolicyDocumentError("native_policy_document_malformed")
    return result["ok"]
