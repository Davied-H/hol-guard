from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_decision_receipt
from codex_plugin_scanner.guard.daemon import hook_native_cli_observer
from codex_plugin_scanner.guard.daemon.hook_direct_evidence_drain import (
    DirectHookEvidenceDrain,
    record_direct_hook_evidence,
)

RECEIPT = {"decision_id": "e" * 64, "policy_action": "allow"}
PAYLOAD = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "ls"}}
RESPONSE = {"continue": True, "policy_action": "allow", "reason_code": "native_allow"}


class _Writer:
    def __init__(self) -> None:
        self.receipts: list[Mapping[str, object]] = []
        self.activity: list[dict[str, object]] = []

    def submit_native_decision_receipt(self, *, receipt: Mapping[str, object]) -> None:
        self.receipts.append(receipt)

    def submit_command_activity(self, **values: object) -> None:
        self.activity.append(values)


@dataclass
class _Host:
    guard_home: Path
    store: object = field(default_factory=object)
    activity_writer: _Writer = field(default_factory=_Writer)
    policy_snapshot_publisher: object = field(default_factory=object)


def _host(tmp_path: Path) -> _Host:
    return _Host(tmp_path)


def _record(**overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "harness": "codex",
        "workspace": "/work",
        "home_dir": "/home/user",
        "payload": dict(PAYLOAD),
        "receipt": dict(RECEIPT),
        "harness_response": dict(RESPONSE),
    }
    value.update(overrides)
    return value


@pytest.fixture
def observed(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, object]]:
    calls: list[dict[str, object]] = []
    monkeypatch.setattr(native_decision_receipt, "validate_native_decision_receipt", lambda receipt: receipt)
    monkeypatch.setattr(
        hook_native_cli_observer,
        "observe_native_pre_tool_cli",
        lambda store, **values: calls.append(values),
    )
    return calls


def test_a_drained_answer_is_recorded_like_a_daemon_allow(tmp_path: Path, observed: list[dict[str, object]]) -> None:
    host = _host(tmp_path)
    assert record_direct_hook_evidence(host, _record())

    assert host.activity_writer.receipts == [RECEIPT]
    assert observed == [{"payload": PAYLOAD, "workspace": Path("/work"), "home_dir": Path("/home/user")}]
    [activity] = host.activity_writer.activity
    assert activity["harness"] == "codex"
    assert activity["event"] == "PreToolUse"
    assert activity["policy_action"] == "allow"
    assert activity["receipt_id"] == RECEIPT["decision_id"]


def test_a_drained_claude_code_answer_is_recorded_for_claude_code(
    tmp_path: Path, observed: list[dict[str, object]]
) -> None:
    host = _host(tmp_path)
    assert record_direct_hook_evidence(host, _record(harness="claude-code"))

    [activity] = host.activity_writer.activity
    assert activity["harness"] == "claude-code"
    assert activity["policy_action"] == "allow"


@pytest.mark.parametrize(
    "record",
    [
        "not a record",
        _record(harness="cursor"),
        _record(payload="ls"),
        _record(workspace=None),
        _record(harness_response=None),
    ],
)
def test_a_malformed_record_is_not_recorded(tmp_path: Path, observed: list[dict[str, object]], record: object) -> None:
    host = _host(tmp_path)
    assert not record_direct_hook_evidence(host, record)
    assert host.activity_writer.receipts == []
    assert host.activity_writer.activity == []
    assert observed == []


def test_an_unmanaged_harness_is_passed_through_without_recording(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, observed: list[dict[str, object]]
) -> None:
    from codex_plugin_scanner.guard.daemon import hook_managed_install_state

    harnesses: list[str] = []

    def unmanaged(host: object, harness: str) -> bool:
        harnesses.append(harness)
        return True

    monkeypatch.setattr(hook_managed_install_state, "_hook_harness_is_unmanaged", unmanaged)
    host = _host(tmp_path)
    assert record_direct_hook_evidence(host, _record())
    assert harnesses == ["codex"]
    assert host.activity_writer.receipts == []
    assert host.activity_writer.activity == []
    assert observed == []


def test_an_invalid_receipt_is_not_submitted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, observed: list[dict[str, object]]
) -> None:
    monkeypatch.setattr(native_decision_receipt, "validate_native_decision_receipt", lambda receipt: None)
    host = _host(tmp_path)
    assert record_direct_hook_evidence(host, _record())
    assert host.activity_writer.receipts == []
    assert host.activity_writer.activity[0]["receipt_id"] is None


def _page(records: list[object], remaining: int) -> bytes:
    return json.dumps({"schema": "guard-hook-direct-evidence.v1", "records": records, "remaining": remaining}).encode()


def test_drain_pulls_pages_until_the_queue_is_empty(tmp_path: Path, observed: list[dict[str, object]]) -> None:
    host = _host(tmp_path)
    pages = [_page([_record(), "junk"], 1), _page([_record()], 0)]
    requests: list[dict[str, object]] = []

    def client(**values: object) -> bytes:
        requests.append(values)
        return pages.pop(0)

    drain = DirectHookEvidenceDrain(host, transport=lambda: (tmp_path / "guard-runtime", client))
    assert drain.drain_once() is False
    assert (drain.recorded, drain.rejected, drain.failures) == (2, 1, 0)
    assert len(requests) == 2
    assert requests[0]["executable"] == tmp_path / "guard-runtime"
    assert json.loads(requests[0]["payload"]) == {  # pyright: ignore[reportArgumentType]
        "operation": "hook_direct_evidence_drain",
        "request": {"guard_home": str(tmp_path)},
    }


@pytest.mark.parametrize("output", [None, b"", b"not json", b'{"schema":"other","records":[],"remaining":0}'])
def test_drain_counts_a_bad_page_as_a_failure(tmp_path: Path, output: bytes | None) -> None:
    drain = DirectHookEvidenceDrain(_host(tmp_path), transport=lambda: (tmp_path, lambda **_: output))
    assert drain.drain_once() is False
    assert drain.failures == 1


def test_drain_without_a_resident_does_nothing(tmp_path: Path) -> None:
    drain = DirectHookEvidenceDrain(_host(tmp_path), transport=lambda: None)
    assert drain.drain_once() is False
    assert drain.failures == 0


def test_stop_collects_what_the_resident_still_holds(tmp_path: Path, observed: list[dict[str, object]]) -> None:
    host = _host(tmp_path)
    drain = DirectHookEvidenceDrain(host, transport=lambda: (tmp_path, lambda **_: _page([_record()], 0)))
    drain.stop()
    assert drain.recorded == 1
