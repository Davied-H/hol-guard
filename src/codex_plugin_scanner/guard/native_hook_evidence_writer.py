"""The hook evidence writer owned by the native resident.

``daemon.runtime_hook_evidence_writer.RuntimeHookEvidenceWriter`` keeps a
queue, a journal and a draining thread per Guard home. All of that now lives in
the resident, which builds one writer per Guard home from its own store,
correlation, receipt, Composio and journal seams. This module is the client:
it shapes the same calls Python made on the writer object, sends them to the
resident, and keeps the two concerns the resident has no handle on.

The first is waking the in-process snapshot publishers after a write that moved
provider policy. The resident counts those mutations and reports them; the
caller wakes its own publishers.

The second is fatal-store recovery. ``GuardStore._recover_fatal_sqlite_store``
quarantines a store a probe has proven unusable, writes the forensics beside it
and rebuilds the database. That belongs to the ``GuardStore`` object this
process owns, so the resident reports the failure code instead and the recovery
runs here, once per reported failure.

A resident that is unavailable, replies unbound, or violates the contract never
yields a silent default: the call raises ``NativeHookEvidenceWriterUnavailableError``
rather than reporting evidence as queued when nothing was.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final
from uuid import uuid4

from .native_context import _canonical_request_sha256, ensure_resident_prerequisite
from .native_execution import _resident_request
from .native_guard_store import _raise_for_code
from .native_resident_prerequisite_reason import prerequisite_unavailable_code
from .native_runtime import native_runtime_status
from .native_runtime_resilience import native_record_resident_failure, native_record_resident_success

if TYPE_CHECKING:
    from .store_connection_schema import GuardStore

HOOK_EVIDENCE_WRITER_FEATURE: Final = "hook-evidence-writer-v1"
_REQUEST_SCHEMA: Final = "guard-hook-evidence-writer-request.v1"
_RESULT_SCHEMA: Final = "guard-hook-evidence-writer-result.v1"
# The writer queues bounded records; the resident's own submission bound plus
# envelope slack is the only transport limit that matters here.
_MAX_REQUEST_BYTES: Final = 4 * 1024 * 1024 + 4096
# One round trip queues a record onto an in-process queue. A wait longer than
# this means the resident is not answering, not that the writer is busy.
_TIMEOUT_SECONDS: Final = 5.0
# `RuntimeHookEvidenceWriter.stop` waited for its own thread; the resident
# waits for the writer it owns and this bounds the transport around that wait.
_STOP_TRANSPORT_SLACK_SECONDS: Final = 5.0

_FATAL_STORE_CODES: Final = frozenset({"native_guard_store_sqlite_corrupt", "native_guard_store_sqlite_io"})


class NativeHookEvidenceWriterUnavailableError(RuntimeError):
    """The resident gave no authoritative answer; the evidence was not queued."""

    reason: str = "native_hook_evidence_writer_unavailable"


def _unavailable(reason: str) -> NativeHookEvidenceWriterUnavailableError:
    error = NativeHookEvidenceWriterUnavailableError(f"Guard hook evidence writer unavailable ({reason}).")
    error.reason = reason
    return error


class NativeHookEvidenceWriter:
    """The resident's writer for one Guard home, shaped like the Python one.

    Holds the ``GuardStore`` only to recover it: no evidence is written through
    it, and no verdict is recalculated here.
    """

    def __init__(self, *, store: GuardStore) -> None:
        self._store = store
        self._guard_home = Path(store.guard_home)
        self._source = store.guard_source
        self._policy_mutations = 0

    @property
    def guard_home(self) -> Path:
        return self._guard_home

    def _call(self, action: Mapping[str, object], *, timeout_seconds: float) -> dict[str, object]:
        if not ensure_resident_prerequisite(self._guard_home):
            raise _unavailable(
                prerequisite_unavailable_code("native_hook_evidence_writer_prerequisite_unavailable", self._guard_home)
            )
        request: dict[str, object] = {
            "schema": _REQUEST_SCHEMA,
            "request_id": f"hook-evidence-writer-{uuid4().hex}",
            "guard_home": str(self._guard_home),
            "source": self._source,
            **dict(action),
        }
        try:
            digest = "sha256:" + _canonical_request_sha256(request)
        except (TypeError, ValueError):
            raise _unavailable("native_hook_evidence_writer_request_invalid") from None
        response = _resident_request(
            operation="hook_evidence_writer",
            request=request,
            guard_home=self._guard_home,
            timeout_seconds=timeout_seconds,
            required_feature=HOOK_EVIDENCE_WRITER_FEATURE,
            response_schema=_RESULT_SCHEMA,
            max_request_bytes=_MAX_REQUEST_BYTES,
            record_success=False,
        )
        identity = native_runtime_status().identity
        if (
            response is None
            or response.get("request_id") != request["request_id"]
            or response.get("request_sha256") != digest
        ):
            if response is not None and identity is not None:
                native_record_resident_failure(
                    identity.sha256, self._guard_home, reason="native_hook_evidence_writer_binding"
                )
            raise _unavailable("native_hook_evidence_writer_unavailable")
        if identity is not None:
            native_record_resident_success(identity.sha256, self._guard_home)
        status, code, payload = response.get("status"), response.get("code"), response.get("payload")
        if status == "error":
            _raise_for_code(code, payload)
        if status != "ok" or code != "ok" or not isinstance(payload, dict):
            raise _unavailable("native_hook_evidence_writer_response_invalid")
        return payload

    def _queued(self, action: Mapping[str, object]) -> bool:
        payload = self._call(action, timeout_seconds=_TIMEOUT_SECONDS)
        queued = payload.get("queued")
        if not isinstance(queued, bool):
            raise _unavailable("native_hook_evidence_writer_response_invalid")
        return queued

    def submit_command_activity(
        self,
        *,
        harness: str,
        event: str,
        payload: Mapping[str, object],
        succeeded: bool,
        policy_action: str | None = None,
        receipt_id: str | None = None,
        prompted: bool = False,
        approval_reuse_status: str = "not-applicable",
    ) -> bool:
        return self._queued(
            {
                "action": "submit_command_activity",
                "harness": harness,
                "event": event,
                "payload": dict(payload),
                "succeeded": succeeded,
                "policy_action": policy_action,
                "receipt_id": receipt_id,
                "prompted": prompted,
                "approval_reuse_status": approval_reuse_status,
            }
        )

    def submit_composio_discovery(
        self,
        *,
        harness: str,
        payload: Mapping[str, object],
        succeeded: bool,
    ) -> bool:
        return self._queued(
            {
                "action": "submit_composio_discovery",
                "harness": harness,
                "payload": dict(payload),
                "succeeded": succeeded,
            }
        )

    def submit_native_decision_receipt(self, receipt: Mapping[str, object]) -> bool:
        return self._queued({"action": "submit_native_decision_receipt", "receipt": dict(receipt)})

    def stats(self) -> dict[str, Any]:
        """The writer's counters, with the two signals the resident hands back.

        ``policy_mutations`` and ``store_fatal`` are read-and-clear in the
        resident. Both are consumed here so a second reader cannot repeat the
        publisher wake or the store recovery, and neither is reported as a
        counter.
        """

        payload = self._call({"action": "stats"}, timeout_seconds=_TIMEOUT_SECONDS)
        self._consume_signals(payload)
        return payload

    def stop(self, *, timeout_seconds: float = 1.0) -> bool:
        """Drain the resident's writer for this home and drop it.

        The Python writer defaulted to one second of draining and the resident
        to two, so the value is always sent rather than left to either default.
        """

        payload = self._call(
            {"action": "stop", "timeout_seconds": max(0.0, timeout_seconds)},
            timeout_seconds=max(0.0, timeout_seconds) + _STOP_TRANSPORT_SLACK_SECONDS,
        )
        self._consume_signals(payload)
        drained = payload.get("drained")
        if not isinstance(drained, bool):
            raise _unavailable("native_hook_evidence_writer_response_invalid")
        return drained

    def take_policy_mutations(self) -> int:
        """The mutations observed since the last read, for the caller's publishers."""

        mutations, self._policy_mutations = self._policy_mutations, 0
        return mutations

    def _consume_signals(self, payload: Mapping[str, object]) -> None:
        mutations = payload.pop("policy_mutations", 0) if isinstance(payload, dict) else 0
        if isinstance(mutations, int) and not isinstance(mutations, bool) and mutations > 0:
            self._policy_mutations += mutations
        fatal = payload.pop("store_fatal", None) if isinstance(payload, dict) else None
        if isinstance(fatal, str):
            self._recover_store(fatal)

    def _recover_store(self, code: str) -> None:
        """Run the store's own recovery for a failure the resident reported.

        The resident names the failure in the ``native_guard_store_*`` codes the
        store client already maps, so the exception the recovery inspects is
        built by that same mapping rather than a second classifier here.
        """

        if code not in _FATAL_STORE_CODES:
            return
        try:
            _raise_for_code(code, None)
        except sqlite3.DatabaseError as error:
            self._store._recover_fatal_sqlite_store(error)


__all__ = [
    "HOOK_EVIDENCE_WRITER_FEATURE",
    "NativeHookEvidenceWriter",
    "NativeHookEvidenceWriterUnavailableError",
]
