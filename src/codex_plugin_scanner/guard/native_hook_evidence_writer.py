"""The hook evidence writer owned by the native resident.

The writer keeps a queue, a journal and a draining thread per Guard home, and
all of that lives in the resident, which builds one writer per Guard home from
its own store, correlation, receipt, Composio and journal seams. This module is
the client: it shapes the calls a caller makes on the writer object, sends them
to the resident, and keeps the two concerns the resident has no handle on.

The first is waking the in-process snapshot publishers after a write that moved
provider policy. The resident counts those mutations and reports them; the
caller wakes its own publishers.

The second is fatal-store recovery. ``GuardStore._recover_fatal_sqlite_store``
quarantines a store a probe has proven unusable, writes the forensics beside it
and rebuilds the database. That belongs to the ``GuardStore`` object this
process owns, so the resident reports the failure code instead and the recovery
runs here, once per reported failure.

A resident that is unavailable, replies unbound, or violates the contract never
reports evidence as queued when nothing was. Submitting is best-effort, as it
was in the writer this replaces: a hook has already decided by the time it
records what it did, and a resident that cannot take the record must not turn
that decision into an exception. The failure is counted instead, and ``stats``
reports it.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Mapping
from contextlib import suppress
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
# A stop waits for the writer's own drain; the resident performs that wait and
# this bounds the transport around it.
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
        self._submit_failures = 0
        self._last_submit_failure: str | None = None
        self._final_stats: dict[str, Any] | None = None

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
        """Submit one record, and report rather than raise when that fails.

        The writer this replaces returned ``False`` for every failure and
        counted a drop. Its callers were written for that: ``HookWorker``
        records a command's activity after the native edge has already decided
        and before it shapes the harness response, so an evidence transport
        that raised here would replace a finished decision with an error.
        """

        try:
            payload = self._call(action, timeout_seconds=_TIMEOUT_SECONDS)
        except Exception as error:
            self._record_submit_failure(error)
            return False
        self._consume_signals(payload)
        queued = payload.get("queued")
        if not isinstance(queued, bool):
            self._record_submit_failure(_unavailable("native_hook_evidence_writer_response_invalid"))
            return False
        return queued

    def _record_submit_failure(self, error: BaseException) -> None:
        """Count a submission the resident did not take, and name it once.

        A dropped record stays observable: ``stats`` reports the count and the
        last reason, which is what a caller that no longer sees an exception
        has to go on. A failure that names a fatal store runs the recovery the
        reported signal would have run.
        """

        self._submit_failures += 1
        self._last_submit_failure = getattr(error, "reason", None) or type(error).__name__
        if isinstance(error, sqlite3.DatabaseError):
            with suppress(Exception):
                self._store._recover_fatal_sqlite_store(error)

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

    def start(self) -> bool:
        """Build the resident's writer for this home before any hook needs it.

        Construction replays the journal, and the writer this replaces paid
        that cost when the daemon built it at startup. Warming it here keeps
        the replay off the first hook's decision path. Best-effort like every
        other call: a resident that cannot build the writer now builds it on
        the first submission instead.
        """

        try:
            payload = self._call({"action": "start"}, timeout_seconds=_TIMEOUT_SECONDS)
        except Exception as error:
            self._record_submit_failure(error)
            return False
        self._consume_signals(payload)
        return payload.get("running") is True

    def stats(self) -> dict[str, Any]:
        """The writer's counters, with the two signals the resident hands back.

        ``policy_mutations`` and ``store_fatal`` are read-and-clear in the
        resident. Both are consumed here so a second reader cannot repeat the
        publisher wake or the store recovery, and neither is reported as a
        counter.
        """

        try:
            payload = self._call({"action": "stats"}, timeout_seconds=_TIMEOUT_SECONDS)
        except Exception as error:
            return self._unavailable_stats(error)
        self._consume_signals(payload)
        # A writer this process stopped is gone from the resident, which
        # answers for it with the counters of a writer that never ran. The
        # drain is where a store failure surfaces, so the counters the stop
        # reported are the ones a reader asking afterwards wants.
        if payload.get("started") is False and self._final_stats is not None:
            payload = dict(self._final_stats)
        payload["submit_failures"] = self._submit_failures
        payload["last_submit_failure"] = self._last_submit_failure
        return payload

    def _unavailable_stats(self, error: BaseException) -> dict[str, Any]:
        """What the counters look like when the resident did not answer.

        The detailed health page and the operator dashboard both read these
        counters, and both are opened precisely when something is wrong. A
        resident outage has to show as a degraded writer there, not as a page
        that fails to render.
        """

        return {
            "queued": 0,
            "queued_bytes": 0,
            "accepted": 0,
            "processed": 0,
            "dropped": 0,
            "failures": self._submit_failures,
            "recovered": 0,
            "durable_pending": 0,
            "degraded": True,
            "running": False,
            "started": True,
            "receipt_accepted": 0,
            "receipt_processed": 0,
            "receipt_deduped": 0,
            "receipt_dropped": 0,
            "receipt_failures": 0,
            "receipt_durable_pending": 0,
            "submit_failures": self._submit_failures,
            "last_submit_failure": self._last_submit_failure,
            "unavailable_reason": getattr(error, "reason", None) or type(error).__name__,
        }

    def stop(self, *, timeout_seconds: float = 1.0) -> bool:
        """Drain the resident's writer for this home and drop it.

        The Python writer defaulted to one second of draining and the resident
        to two, so the value is always sent rather than left to either default.
        """

        # The resident re-serializes the request to check the digest it binds
        # its reply to, and it holds the budget as a float. An int sent here
        # would canonicalise as `2` on this side and `2.0` on that one, so the
        # reply would arrive unbound after the writer has already been drained.
        budget = float(max(0.0, timeout_seconds))
        try:
            payload = self._call(
                {"action": "stop", "timeout_seconds": budget},
                timeout_seconds=budget + _STOP_TRANSPORT_SLACK_SECONDS,
            )
        except Exception as error:
            self._record_submit_failure(error)
            return False
        self._consume_signals(payload)
        final = payload.get("final_stats")
        if isinstance(final, dict):
            self._final_stats = dict(final)
        drained = payload.get("drained")
        return drained if isinstance(drained, bool) else False

    def take_policy_mutations(self) -> int:
        """The mutations observed since the last read, for the caller's publishers."""

        mutations, self._policy_mutations = self._policy_mutations, 0
        return mutations

    def _consume_signals(self, payload: Mapping[str, object]) -> None:
        mutations = payload.pop("policy_mutations", 0) if isinstance(payload, dict) else 0
        if isinstance(mutations, int) and not isinstance(mutations, bool) and mutations > 0:
            self._policy_mutations += mutations
            self._wake_policy_publishers()
        fatal = payload.pop("store_fatal", None) if isinstance(payload, dict) else None
        if isinstance(fatal, str):
            self._recover_store(fatal)

    def _wake_policy_publishers(self) -> None:
        """Republish the policy snapshot a resident write moved.

        A Composio discovery used to reach provider policy through
        ``GuardStore.record_composio_discovery``, which woke the in-process
        publishers itself. The resident counts the write instead, so the wake
        happens here, on the reply that reports it. Without it a hook keeps
        evaluating the snapshot the discovery invalidated until some unrelated
        mutation republishes it.
        """

        from .native_policy_snapshot import notify_native_policy_mutation

        with suppress(Exception):
            notify_native_policy_mutation(self._guard_home)

    def _recover_store(self, code: str) -> None:
        """Run the store's own recovery for a failure the resident reported.

        The resident names the failure in the ``native_guard_store_*`` codes the
        store client already maps, so the exception the recovery inspects is
        built by that same mapping rather than a second classifier here. The
        signal rides every reply, so a one-shot hook that submits once and
        exits repairs the store it broke rather than leaving it for whoever
        opens a health page next.
        """

        if code not in _FATAL_STORE_CODES:
            return
        try:
            _raise_for_code(code, None)
        except sqlite3.DatabaseError as error:
            with suppress(Exception):
                self._store._recover_fatal_sqlite_store(error)


__all__ = [
    "HOOK_EVIDENCE_WRITER_FEATURE",
    "NativeHookEvidenceWriter",
    "NativeHookEvidenceWriterUnavailableError",
]
