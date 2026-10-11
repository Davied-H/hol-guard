"""Copilot tool-call settlement is answered by the native runtime.

The vectors were recorded from the retired Python settle logic. The Rust suite
replays them against the op; this suite replays them through the real
resident and the Python transport, and checks the Copilot response shaping.
"""

from __future__ import annotations

import gzip
import io
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from codex_plugin_scanner.guard import native_hook_decision as decision
from codex_plugin_scanner.guard import native_resident_decision as shared
from codex_plugin_scanner.guard.cli import commands_hook_native_copilot as copilot

_VECTORS: list[dict[str, Any]] = json.loads(
    gzip.decompress(
        (
            Path(__file__).resolve().parent.parent
            / "rust/crates/guard-runtime/tests/fixtures/hook_copilot_settle_vectors.json.gz"
        ).read_bytes()
    )
)["vectors"]
_PLAN_KEYS = ("effects", "exit_code", "approval_reuse", "scanner_evidence")
_INPUTS = {key: value for key, value in _VECTORS[0]["inputs"].items() if key != "acked_recording_only"}


@pytest.mark.usefixtures("native_approval_reuse_runtime")
def test_resident_matches_recorded_vectors() -> None:
    failures: list[str] = []
    for vector in _VECTORS:
        inputs = dict(vector["inputs"])
        acked = inputs.pop("acked_recording_only", None)
        asked: list[bool] = []

        def acked_fact(acked: object = acked, asked: list[bool] = asked) -> bool:
            asked.append(True)
            return bool(acked)

        plan = decision.native_copilot_settle(inputs, acked_fact)
        if bool(asked) != vector["needs_acked_snapshot"]:
            failures.append(f"{vector['name']}: acked snapshot asked={bool(asked)}")
        failures.extend(f"{vector['name']}: {key}" for key in _PLAN_KEYS if plan[key] != vector["expected"][key])
    assert failures == []


def test_pretool_response_matches_recorded_documents() -> None:
    checked = 0
    for vector in _VECTORS:
        effects = [effect for effect in vector["expected"]["effects"] if effect["effect"] == "pretool_response"]
        if not effects:
            continue
        stream = io.StringIO()
        copilot._emit_copilot_pretool_response(
            SimpleNamespace(json=vector["json_requested"]),
            permission_decision=effects[0]["permission_decision"],
            reason=effects[0]["reason"],
            approval_reuse=vector["expected"]["approval_reuse"],
            scanner_evidence=tuple(vector["expected"]["scanner_evidence"]),
            output_stream=stream,
        )
        assert [json.loads(line) for line in stream.getvalue().splitlines()] == vector["pretool_documents"]
        checked += 1
    assert checked > 100


def _resident_returning(monkeypatch: pytest.MonkeyPatch, payloads: list[dict[str, Any]]) -> None:
    monkeypatch.setattr(shared, "_resolve_digest_home", lambda _home: Path("/tmp/hook-decision-home"))
    monkeypatch.setattr(shared, "ensure_resident_prerequisite", lambda _home: True)

    def reply(*, request: dict[str, Any], **_kwargs: object) -> dict[str, Any]:
        return {
            "schema": "guard-hook-decision-result.v1",
            "request_id": request["request_id"],
            "request_sha256": "sha256:" + shared._canonical_request_sha256(request),
            "status": "ok",
            "code": "ok",
            "payload": payloads.pop(0),
        }

    monkeypatch.setattr(decision, "_resident_request", reply)


_ASK = {"kind": "copilot_settle", "needs_facts": ["acked_recording_only"], "plan": None}
_PLAN = {
    "policy_action": "allow",
    "approval_reuse": None,
    "scanner_evidence": [],
    "effects": [{"effect": "usage", "policy_action": "allow"}],
    "exit_code": 0,
}


@pytest.mark.parametrize(
    "payloads",
    [
        [{"kind": "copilot_settle", "needs_facts": ["other"], "plan": None}],
        [_ASK, _ASK],
        [{"kind": "copilot_settle", "needs_facts": [], "plan": {**_PLAN, "exit_code": "0"}}],
        [{"kind": "copilot_settle", "needs_facts": [], "plan": {**_PLAN, "effects": [{"effect": "shell"}]}}],
        [{"kind": "copilot_settle", "needs_facts": [], "plan": {**_PLAN, "effects": [{"effect": "usage"}]}}],
        [{"kind": "copilot_settle", "needs_facts": [], "plan": {**_PLAN, "policy_action": "bogus"}}],
    ],
)
def test_malformed_answers_raise(monkeypatch: pytest.MonkeyPatch, payloads: list[dict[str, Any]]) -> None:
    _resident_returning(monkeypatch, payloads)
    with pytest.raises(decision.NativeHookDecisionError):
        decision.native_copilot_settle(_INPUTS, lambda: False)


def test_acked_fact_is_asked_once(monkeypatch: pytest.MonkeyPatch) -> None:
    _resident_returning(monkeypatch, [_ASK, {"kind": "copilot_settle", "needs_facts": [], "plan": _PLAN}])
    calls: list[bool] = []
    assert decision.native_copilot_settle(_INPUTS, lambda: calls.append(True) or True) == _PLAN
    assert calls == [True]
