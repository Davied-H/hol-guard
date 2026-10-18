"""The resident client for the hook evidence writer: wire shape and the two signals it consumes."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard import native_hook_evidence_writer
from codex_plugin_scanner.guard.native_hook_evidence_writer import (
    NativeHookEvidenceWriter,
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

    # The record was not queued, and the writer says so rather than raising:
    # a hook records what it did after it has already decided.
    assert writer.submit_native_decision_receipt({"receipt": "shaped"}) is False


def test_a_refused_submission_is_counted_rather_than_raised(
    writer: NativeHookEvidenceWriter, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install(
        monkeypatch,
        _answer({"message": "bad evidence"}, status="error", code="native_guard_store_value_error"),
    )

    queued = writer.submit_composio_discovery(
        harness="claude-code",
        payload={"tool_name": "mcp__composio__composio_search_tools"},
        succeeded=True,
    )

    assert queued is False
    # A dropped record stays visible to whoever reads the counters.
    _install(monkeypatch, _answer({"running": True}))
    stats = writer.stats()
    assert stats["submit_failures"] == 1
    assert stats["last_submit_failure"] == "ValueError"


def test_a_submission_that_reports_a_mutation_wakes_the_publishers(
    writer: NativeHookEvidenceWriter, monkeypatch: pytest.MonkeyPatch
) -> None:
    woken: list[Path] = []
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.native_policy_snapshot.notify_native_policy_mutation",
        lambda guard_home: woken.append(guard_home),
    )
    _install(monkeypatch, _answer({"queued": True, "policy_mutations": 1, "store_fatal": None}))

    assert (
        writer.submit_composio_discovery(
            harness="claude-code",
            payload={"tool_name": "mcp__composio__composio_search_tools"},
            succeeded=True,
        )
        is True
    )

    # A discovery that moved provider policy republishes the snapshot on the
    # reply that reports it, not whenever someone next opens a health page.
    assert woken == [writer.guard_home]


def test_a_submission_that_reports_a_fatal_store_recovers_it(
    writer: NativeHookEvidenceWriter, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install(
        monkeypatch,
        _answer({"queued": False, "policy_mutations": 0, "store_fatal": "native_guard_store_sqlite_corrupt"}),
    )

    assert writer.submit_native_decision_receipt({"receipt": "shaped"}) is False

    # A one-shot hook submits once and exits; it never reads the counters, so
    # a store only a counter read repairs would stay broken.
    assert len(writer._store.recovered) == 1


def test_counters_stay_readable_when_the_resident_is_gone(
    writer: NativeHookEvidenceWriter, monkeypatch: pytest.MonkeyPatch
) -> None:
    def refuse(**_kwargs: Any) -> dict[str, Any] | None:
        return None

    _install(monkeypatch, refuse)

    stats = writer.stats()

    # The health page and the dashboard read these, and both are opened when
    # something is wrong. A degraded writer has to render.
    assert stats["running"] is False
    assert stats["degraded"] is True
    assert stats["unavailable_reason"] == "native_hook_evidence_writer_unavailable"


def test_reading_counters_consumes_the_mutation_count_once(
    writer: NativeHookEvidenceWriter, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.native_policy_snapshot.notify_native_policy_mutation",
        lambda guard_home: None,
    )
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


def test_counters_read_after_a_stop_are_the_ones_the_drain_reported(
    writer: NativeHookEvidenceWriter, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install(
        monkeypatch,
        _answer({"drained": True, "final_stats": {"failures": 2, "running": False, "started": True}}),
    )
    assert writer.stop(timeout_seconds=0.5) is True

    _install(monkeypatch, _answer({"started": False, "running": False, "failures": 0}))
    stats = writer.stats()

    # The resident answers for a writer it no longer holds with the counters of
    # one that never ran. A failure the drain hit must not read as none.
    assert stats["failures"] == 2


def test_stopping_sends_its_own_drain_budget_rather_than_either_default(
    writer: NativeHookEvidenceWriter, monkeypatch: pytest.MonkeyPatch
) -> None:
    respond = _answer({"drained": True, "policy_mutations": 1, "store_fatal": None})
    _install(monkeypatch, respond)

    assert writer.stop(timeout_seconds=0.5) is True
    assert respond.sent[0]["timeout_seconds"] == 0.5
    assert writer.take_policy_mutations() == 1


def test_a_start_builds_the_writer_before_any_hook_submits(
    writer: NativeHookEvidenceWriter, monkeypatch: pytest.MonkeyPatch
) -> None:
    respond = _answer({"running": True, "started": True, "policy_mutations": 0, "store_fatal": None})
    monkeypatch.setattr(native_hook_evidence_writer, "_resident_request", respond)

    assert writer.start() is True
    assert respond.sent[0]["action"] == "start"


def test_a_start_the_resident_refuses_is_counted_rather_than_raised(
    writer: NativeHookEvidenceWriter, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(native_hook_evidence_writer, "_resident_request", lambda **_kwargs: None)

    # The daemon warms the writer on a path that must not fail to start a
    # daemon; the first submission builds the writer instead.
    assert writer.start() is False
    assert writer.stats()["submit_failures"] == 1
