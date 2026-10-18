"""The resident client for the hook evidence writer: wire shape and the two signals it consumes."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard import native_hook_evidence_writer
from codex_plugin_scanner.guard.native_hook_evidence_writer import (
    NativeHookEvidenceWriter,
    NativeHookEvidenceWriterUnavailableError,
)

# pyright: reportAny=false, reportPrivateUsage=false, reportUnknownMemberType=false
# pyright: reportUnknownVariableType=false, reportUnknownArgumentType=false


class _Identity:
    sha256 = "b" * 64


class _Status:
    identity = _Identity()


class _Store:
    """The parts of ``GuardStore`` the client holds: a home, a source, recovery."""

    def __init__(self, guard_home: Path) -> None:
        self.guard_home = guard_home
        self.guard_source = "oauth"
        self.recovered: list[BaseException] = []

    def _recover_fatal_sqlite_store(self, error: BaseException, **_kwargs: Any) -> bool:
        self.recovered.append(error)
        return True


def _answer(payload: dict[str, Any], *, status: str = "ok", code: str = "ok") -> Any:
    """A resident reply bound to whatever request the client just sent."""

    sent: list[dict[str, Any]] = []

    def respond(*, request: dict[str, Any], **_kwargs: Any) -> dict[str, Any]:
        sent.append(request)
        digest = "sha256:" + native_hook_evidence_writer._canonical_request_sha256(request)
        return {
            "schema": "guard-hook-evidence-writer-result.v1",
            "request_id": request["request_id"],
            "request_sha256": digest,
            "status": status,
            "code": code,
            "payload": payload,
        }

    respond.sent = sent  # pyright: ignore[reportFunctionMemberAccess]
    return respond


@pytest.fixture
def writer(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> NativeHookEvidenceWriter:
    monkeypatch.setattr(native_hook_evidence_writer, "ensure_resident_prerequisite", lambda _home: True)
    monkeypatch.setattr(native_hook_evidence_writer, "native_runtime_status", lambda: _Status())
    monkeypatch.setattr(native_hook_evidence_writer, "native_record_resident_success", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(native_hook_evidence_writer, "native_record_resident_failure", lambda *_args, **_kwargs: None)
    return NativeHookEvidenceWriter(store=_Store(tmp_path / "guard-home"))


def _install(monkeypatch: pytest.MonkeyPatch, respond: Any) -> None:
    monkeypatch.setattr(native_hook_evidence_writer, "_resident_request", respond)


def test_a_command_activity_submission_sends_the_flat_writer_request(
    writer: NativeHookEvidenceWriter, monkeypatch: pytest.MonkeyPatch
) -> None:
    respond = _answer({"queued": True})
    _install(monkeypatch, respond)

    queued = writer.submit_command_activity(
        harness="claude-code",
        event="PreToolUse",
        payload={"tool_name": "Bash"},
        succeeded=True,
        policy_action="allow",
    )

    assert queued is True
    request = respond.sent[0]
    assert request["schema"] == "guard-hook-evidence-writer-request.v1"
    assert request["action"] == "submit_command_activity"
    assert request["guard_home"] == str(writer.guard_home)
    assert request["harness"] == "claude-code"
    assert request["payload"] == {"tool_name": "Bash"}
    assert request["approval_reuse_status"] == "not-applicable"
    # The action fields are flat beside the envelope, not nested under a query.
    assert "query" not in request


def test_a_reply_bound_to_another_request_is_never_read_as_queued(
    writer: NativeHookEvidenceWriter, monkeypatch: pytest.MonkeyPatch
) -> None:
    def respond(*, request: dict[str, Any], **_kwargs: Any) -> dict[str, Any]:
        return {
            "request_id": request["request_id"],
            "request_sha256": "sha256:" + "0" * 64,
            "status": "ok",
            "code": "ok",
            "payload": {"queued": True},
        }

    _install(monkeypatch, respond)

    with pytest.raises(NativeHookEvidenceWriterUnavailableError):
        writer.submit_native_decision_receipt({"receipt": "shaped"})


def test_a_resident_error_raises_the_store_exception_its_code_names(
    writer: NativeHookEvidenceWriter, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install(
        monkeypatch,
        _answer({"message": "bad evidence"}, status="error", code="native_guard_store_value_error"),
    )

    with pytest.raises(ValueError, match="bad evidence"):
        writer.submit_composio_discovery(
            harness="claude-code",
            payload={"tool_name": "mcp__composio__composio_search_tools"},
            succeeded=True,
        )


def test_reading_counters_consumes_the_mutation_count_once(
    writer: NativeHookEvidenceWriter, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install(monkeypatch, _answer({"running": True, "policy_mutations": 2, "store_fatal": None}))

    stats = writer.stats()

    # The signals are not counters; the caller takes them deliberately.
    assert "policy_mutations" not in stats
    assert "store_fatal" not in stats
    assert stats["running"] is True
    assert writer.take_policy_mutations() == 2
    assert writer.take_policy_mutations() == 0


def test_a_reported_fatal_store_runs_the_store_recovery_once(
    writer: NativeHookEvidenceWriter, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install(
        monkeypatch,
        _answer({"running": True, "policy_mutations": 0, "store_fatal": "native_guard_store_sqlite_corrupt"}),
    )

    writer.stats()

    recovered = writer._store.recovered
    assert len(recovered) == 1
    error = recovered[0]
    assert isinstance(error, sqlite3.DatabaseError)
    assert getattr(error, "sqlite_errorcode", None) == 11


def test_an_ordinary_counter_read_never_recovers_the_store(
    writer: NativeHookEvidenceWriter, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install(monkeypatch, _answer({"running": True, "policy_mutations": 0, "store_fatal": None}))

    writer.stats()

    assert writer._store.recovered == []


def test_stopping_sends_its_own_drain_budget_rather_than_either_default(
    writer: NativeHookEvidenceWriter, monkeypatch: pytest.MonkeyPatch
) -> None:
    respond = _answer({"drained": True, "policy_mutations": 1, "store_fatal": None})
    _install(monkeypatch, respond)

    assert writer.stop(timeout_seconds=0.5) is True
    assert respond.sent[0]["timeout_seconds"] == 0.5
    assert writer.take_policy_mutations() == 1
