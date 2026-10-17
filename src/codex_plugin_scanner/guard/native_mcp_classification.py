"""Resident bridge for the ``mcp_classify`` op.

Rust describes what an MCP tool's declared schema and the provider's own
annotation claims suggest. Python ships the declarations as data, binds the
reply by ``request_id`` plus ``request_sha256`` and decodes it. Nothing is
described in Python, so an unavailable resident yields no classification at
all rather than a locally invented one.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from uuid import uuid4

from .native_context import ensure_resident_prerequisite
from .native_execution import _resident_request
from .native_store_policy import _payload

MCP_CLASSIFICATION_FEATURE = "mcp-classification-v1"
_OPERATION = "mcp_classify"
_REQUEST_SCHEMA = "guard-mcp-classification-request.v1"
_RESULT_SCHEMA = "guard-mcp-classification-result.v1"
_TIMEOUT_SECONDS = 10.0
_MAX_REQUEST_BYTES = 8 * 1024 * 1024
_MAX_ITEMS = 1024
UNAVAILABLE = "native_mcp_classification_unavailable"


class McpClassificationUnavailableError(ValueError):
    """The resident could not describe the tools; nothing was described here."""

    def __init__(self) -> None:
        super().__init__(UNAVAILABLE)


def _item(definition: Mapping[str, object]) -> dict[str, object]:
    full_schema = definition.get("full_schema", True)
    return {
        "name": str(definition.get("name") or ""),
        "schema": definition.get("schema"),
        "provider": definition.get("provider"),
        "annotations": definition.get("annotations"),
        "full_schema": bool(full_schema),
    }


def _envelope(items: Sequence[Mapping[str, object]], *, request_id: str) -> dict[str, object]:
    return {
        "operation": _OPERATION,
        "request": {
            "schema": _REQUEST_SCHEMA,
            "request_id": request_id,
            "items": [dict(item) for item in items],
        },
        "deadline_budget_ms": max(1, int(_TIMEOUT_SECONDS * 1000)),
    }


def _wire_bytes(items: Sequence[Mapping[str, object]]) -> int:
    """Byte length of the envelope ``_resident_request`` actually sends."""

    probe = "mcp-classification-" + ("0" * 32)
    try:
        return len(json.dumps(_envelope(items, request_id=probe)).encode("utf-8"))
    except (TypeError, ValueError):
        raise McpClassificationUnavailableError from None


# json.dumps joins array elements with ", " (comma, space).
_ARRAY_SEPARATOR_BYTES = 2


def _chunks(items: Sequence[Mapping[str, object]]) -> list[list[int]]:
    """Pack the declarations under the count and byte caps.

    A declaration too large to travel on its own cannot be described; the
    caller hears that rather than receiving a guess for it.
    """

    base = _wire_bytes([])
    sizes = [_wire_bytes([item]) - base for item in items]
    chunks: list[list[int]] = []
    current: list[int] = []
    current_bytes = base
    for index, size in enumerate(sizes):
        if base + size > _MAX_REQUEST_BYTES:
            raise McpClassificationUnavailableError
        added = size if not current else size + _ARRAY_SEPARATOR_BYTES
        if current and (len(current) + 1 > _MAX_ITEMS or current_bytes + added > _MAX_REQUEST_BYTES):
            chunks.append(current)
            current = [index]
            current_bytes = base + size
            continue
        current.append(index)
        current_bytes += added
    if current:
        chunks.append(current)
    return chunks


def native_mcp_classifications(
    definitions: Sequence[Mapping[str, object]],
    *,
    guard_home: Path,
) -> list[dict[str, object]]:
    """Describe tool declarations in the resident; raise when it cannot."""

    if not definitions:
        return []
    home = Path(guard_home)
    if not ensure_resident_prerequisite(home):
        raise McpClassificationUnavailableError
    prepared = [_item(definition) for definition in definitions]
    described: list[dict[str, object] | None] = [None] * len(prepared)
    for chunk in _chunks(prepared):
        wire: dict[str, object] = {
            "schema": _REQUEST_SCHEMA,
            "request_id": f"mcp-classification-{uuid4().hex}",
            "items": [dict(prepared[index]) for index in chunk],
        }
        try:
            response = _resident_request(
                operation=_OPERATION,
                request=wire,
                guard_home=home,
                timeout_seconds=_TIMEOUT_SECONDS,
                required_feature=MCP_CLASSIFICATION_FEATURE,
                response_schema=_RESULT_SCHEMA,
                max_request_bytes=_MAX_REQUEST_BYTES,
                record_success=False,
            )
        except (TypeError, ValueError, OSError, RuntimeError):
            raise McpClassificationUnavailableError from None
        payload = _payload(response, wire, home)
        reply = payload.get("classifications") if payload is not None else None
        if not isinstance(reply, list) or len(reply) != len(chunk):
            raise McpClassificationUnavailableError
        for index, entry in zip(chunk, reply, strict=True):
            if not isinstance(entry, dict):
                raise McpClassificationUnavailableError
            described[index] = entry
    if any(entry is None for entry in described):
        raise McpClassificationUnavailableError
    return [entry for entry in described if entry is not None]
