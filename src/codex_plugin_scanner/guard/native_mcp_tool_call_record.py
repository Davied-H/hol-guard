"""Client for the native MCP tool-call record owner.

Rust builds the receipt, inventory row and runtime event of one decided tool
call and writes them in a single store transaction. Python ships the call facts
plus the process-local ids and instants, and keeps the process-local concerns
around the write: the storage-access gate, permission repair and the Review
outbox wake. The same request rides the fused stdio exchange so the evidence is
stored before the call is written to the child.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Mapping
from contextlib import AbstractContextManager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from .models import GuardArtifact, GuardReceipt
from .native_context import ensure_resident_prerequisite
from .native_execution import _resident_request
from .native_guard_store import NativeGuardStoreUnavailable, raise_for_store_code
from .native_mcp_runtime_evidence import argument_entries
from .native_mcp_tool_evidence import NativeMcpToolEvidenceError
from .native_resident_prerequisite_reason import prerequisite_unavailable_code
from .runtime.mcp_skill_firewall import enrich_artifact_with_mcp_skill_firewall
from .sqlite_tuning import sqlite_connect_timeout_seconds
from .store_base import _canonical_utc_timestamp
from .store_review_event_outbox_schema import notify_review_event_wake

if TYPE_CHECKING:
    from .store import GuardStore

NATIVE_MCP_TOOL_CALL_RECORD_FEATURE = "mcp-tool-call-record-v1"
REQUEST_SCHEMA = "guard-mcp-tool-call-record-request.v1"
_RESULT_SCHEMA = "guard-mcp-tool-call-record-result.v1"
_OPERATION = "mcp_tool_call_record"
_MAX_REQUEST_BYTES = 8 * 1024 * 1024
_LOGGER = logging.getLogger(__name__)


class ToolCallRecordError(RuntimeError):
    """The evidence for a tool call could not be recorded, so the call must not run."""


@dataclass(slots=True)
class PreparedToolCallRecord:
    """One decided tool call's evidence, ready to be written exactly once."""

    store: GuardStore
    request: dict[str, object]
    recorded: bool = field(default=False)

    def gate(self) -> AbstractContextManager[None]:
        """The shared storage gate the write must run under."""
        return self.store._hold_storage_gate(exclusive=False)  # pyright: ignore[reportPrivateUsage]

    def finish(self, outbox_generation: int | None) -> None:
        """Process-local follow-up after the resident committed the write."""
        self.recorded = True
        self.store._repair_store_permissions()  # pyright: ignore[reportPrivateUsage]
        notify_review_event_wake(self.store.path, outbox_generation)

    def commit(self) -> GuardReceipt:
        """Write the evidence in its own resident round trip."""
        if self.recorded:
            raise ToolCallRecordError("native_mcp_tool_call_record_already_recorded")
        request_id = self.request["request_id"]
        # The resident refuses a home without its runtime state; the old store call provisioned it.
        if not ensure_resident_prerequisite(self.store.guard_home):
            reason = prerequisite_unavailable_code(
                "native_mcp_tool_call_record_prerequisite_unavailable", self.store.guard_home
            )
            raise NativeGuardStoreUnavailable(f"Guard store native runtime unavailable ({reason}).")
        with self.gate():
            response = _resident_request(
                operation=_OPERATION,
                request=self.request,
                guard_home=self.store.guard_home,
                timeout_seconds=max(1.0, sqlite_connect_timeout_seconds()) + 5.0,
                required_feature=NATIVE_MCP_TOOL_CALL_RECORD_FEATURE,
                response_schema=_RESULT_SCHEMA,
                max_request_bytes=_MAX_REQUEST_BYTES,
            )
        if response is None or response.get("request_id") != request_id:
            raise NativeGuardStoreUnavailable("Guard store native runtime unavailable (native_mcp_tool_call_record).")
        if response.get("status") != "ok":
            raise_for_store_code(response.get("code"), None)
        receipt = response.get("receipt")
        generation = response.get("outbox_generation")
        if not isinstance(receipt, dict) or (generation is not None and type(generation) is not int):
            raise ToolCallRecordError("native_mcp_tool_call_record_response_invalid")
        self.finish(generation)
        return receipt_from_wire(receipt)


def receipt_from_wire(receipt: Mapping[str, Any]) -> GuardReceipt:
    return GuardReceipt(
        receipt_id=receipt["receipt_id"],
        timestamp=receipt["timestamp"],
        harness=receipt["harness"],
        artifact_id=receipt["artifact_id"],
        artifact_hash=receipt["artifact_hash"],
        policy_decision=receipt["policy_decision"],
        capabilities_summary=receipt["capabilities_summary"],
        changed_capabilities=tuple(receipt["changed_capabilities"]),
        provenance_summary=receipt["provenance_summary"],
        user_override=receipt["user_override"],
        artifact_name=receipt["artifact_name"],
        source_scope=receipt["source_scope"],
        diff_summary=receipt["diff_summary"],
        approval_source=receipt["approval_source"],
        approval_request_id=receipt["approval_request_id"],
        scanner_evidence=tuple(dict(item) for item in receipt["scanner_evidence"]),
        raw_command_text=receipt["raw_command_text"],
    )


def _firewall(artifact: GuardArtifact) -> tuple[object, bool]:
    """The artifact's firewall evidence, and whether recomputing it failed."""
    firewall = artifact.metadata.get("mcpSkillFirewall")
    if isinstance(firewall, dict):
        return firewall, False
    try:
        enriched = enrich_artifact_with_mcp_skill_firewall(artifact)
    except NativeMcpToolEvidenceError:
        _LOGGER.warning("native MCP firewall evidence unavailable; recording receipt without it", exc_info=True)
        return None, True
    firewall = enriched.metadata.get("mcpSkillFirewall")
    return (firewall if isinstance(firewall, dict) else None), False


def prepare_tool_call_record(
    *,
    store: GuardStore,
    kind: str,
    artifact: GuardArtifact,
    artifact_hash: str,
    decision_source: str,
    now: str,
    signals: tuple[str, ...],
    risk_categories: tuple[str, ...],
    policy_action: str,
    arguments: object,
    additional_scanner_evidence: tuple[dict[str, object], ...],
) -> PreparedToolCallRecord:
    """Package one decided call's facts for the resident to record."""
    firewall, firewall_unavailable = _firewall(artifact)
    description = artifact.metadata.get("tool_description")
    stamp = datetime.now(timezone.utc)
    request: dict[str, object] = {
        "schema": REQUEST_SCHEMA,
        "request_id": f"mcp-tool-call-record-{uuid.uuid4().hex}",
        "kind": kind,
        "store_path": str(store.path),
        "guard_home": str(store.guard_home),
        "source": store._guard_source,  # pyright: ignore[reportPrivateUsage]
        "busy_timeout_ms": max(1, int(sqlite_connect_timeout_seconds() * 1000)),
        "event_queue_limit": store._guard_event_queue_limit,  # pyright: ignore[reportPrivateUsage]
        "receipt_id": f"guard-receipt-{uuid.uuid4()}",
        "receipt_timestamp": stamp.isoformat(),
        "store_now": _canonical_utc_timestamp(stamp.isoformat()),
        "new_device_id": uuid.uuid4().hex,
        "now": now,
        "artifact": {
            "artifact_id": artifact.artifact_id,
            "name": artifact.name,
            "harness": artifact.harness,
            "artifact_type": artifact.artifact_type,
            "source_scope": artifact.source_scope,
            "config_path": artifact.config_path,
            "command": artifact.command,
            "args": list(artifact.args),
            "url": artifact.url,
            "transport": artifact.transport,
            "publisher": artifact.publisher,
        },
        "artifact_hash": artifact_hash,
        "decision_source": decision_source,
        "policy_action": policy_action,
        "signals": list(signals),
        "risk_categories": list(risk_categories),
        "firewall": firewall,
        "firewall_unavailable": firewall_unavailable,
        "tool_description": description if isinstance(description, str) else None,
        "arguments": argument_entries(arguments, mapping_type=Mapping),
        "additional_scanner_evidence": [dict(item) for item in additional_scanner_evidence],
    }
    return PreparedToolCallRecord(store=store, request=request)


__all__ = [
    "NATIVE_MCP_TOOL_CALL_RECORD_FEATURE",
    "PreparedToolCallRecord",
    "ToolCallRecordError",
    "prepare_tool_call_record",
    "receipt_from_wire",
]
