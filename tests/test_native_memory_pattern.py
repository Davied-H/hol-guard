from __future__ import annotations

import gzip
import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import memory_decision_event, native_memory_pattern, store_policy
from codex_plugin_scanner.guard.memory_decision_event import build_memory_decision_event
from codex_plugin_scanner.guard.native_memory_pattern import NativeMemoryPatternError, memory_pattern_verdict
from codex_plugin_scanner.guard.store_policy import memory_lookup_candidates

_VECTORS = (
    Path(__file__).resolve().parents[1] / "rust/crates/guard-runtime/tests/fixtures/memory_pattern_vectors.json.gz"
)
_CASES = json.loads(gzip.decompress(_VECTORS.read_bytes()))["cases"]


def _as_wire(verdict: native_memory_pattern.MemoryPatternVerdict) -> dict[str, object]:
    pattern = verdict.pattern
    return {
        "pattern": None
        if pattern is None
        else {
            "fingerprint": pattern.fingerprint,
            "kind": pattern.kind,
            "components": [[name, value] for name, value in pattern.components.items()],
        },
        "exact_artifact_ids": list(verdict.exact_artifact_ids),
        "memory_artifact_id": verdict.memory_artifact_id,
    }


def test_native_verdicts_match_the_recorded_python() -> None:
    assert len(_CASES) == 146
    for case in _CASES:
        verdict = memory_pattern_verdict(**case["request"])

        assert _as_wire(verdict) == case["expected"], case["name"]


def test_lookup_candidates_come_from_the_resident() -> None:
    command = "git status"
    exact_ids, memory_id = memory_lookup_candidates(
        "codex",
        None,
        memory_command=command,
        memory_artifact_type="shell",
        memory_artifact_name=None,
    )

    assert [identifier.rsplit(":", 1)[0] for identifier in exact_ids] == [
        "memory:exact-shell-command",
        "memory:exact-command",
    ]
    assert memory_id == "memory:codex:command_pattern:command_pattern:git:codex:status"


_MALFORMED = [
    None,
    {"status": "error", "code": "native_context_digest_unsupported"},
    {"status": "ok"},
    {"status": "ok", "memory_pattern": {"pattern": None, "exact_artifact_ids": []}},
    {"status": "ok", "memory_pattern": {"pattern": None, "exact_artifact_ids": ["x"], "memory_artifact_id": None}},
    {
        "status": "ok",
        "memory_pattern": {"pattern": None, "exact_artifact_ids": [], "memory_artifact_id": "memory:codex:x:y"},
    },
    {
        "status": "ok",
        "memory_pattern": {
            "pattern": {"fingerprint": "other:x", "kind": "command_pattern", "components": []},
            "exact_artifact_ids": [],
            "memory_artifact_id": None,
        },
    },
    {
        "status": "ok",
        "memory_pattern": {
            "pattern": {"fingerprint": "command_pattern:x", "kind": ["command_pattern"], "components": []},
            "exact_artifact_ids": [],
            "memory_artifact_id": None,
        },
    },
    {
        "status": "ok",
        "memory_pattern": {
            "pattern": {"fingerprint": "command_pattern:x", "kind": "command_pattern", "components": [["a", "b", "c"]]},
            "exact_artifact_ids": [],
            "memory_artifact_id": None,
        },
    },
]


@pytest.mark.parametrize("answer", _MALFORMED)
def test_policy_lookup_fails_closed_without_the_resident(monkeypatch: pytest.MonkeyPatch, answer: object) -> None:
    monkeypatch.setattr(native_memory_pattern, "native_context_digest", lambda *_args, **_kwargs: answer)

    with pytest.raises(NativeMemoryPatternError):
        memory_lookup_candidates(
            "codex",
            None,
            memory_command="git status",
            memory_artifact_type="shell",
            memory_artifact_name=None,
        )


def test_decision_event_omits_the_fingerprint_without_the_resident(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(native_memory_pattern, "native_context_digest", lambda *_args, **_kwargs: None)

    event = build_memory_decision_event(
        request={
            "request_id": "req-1",
            "raw_command_text": "npm install lodash",
            "harness": "codex",
        },
        action="allow",
        scope="harness",
        resolved_at="2026-10-12T00:00:00Z",
    )

    assert event is not None
    assert event.memory_pattern_fingerprint is None
    assert event.memory_pattern_kind is None
    assert event.memory_pattern_components == {}


def test_callers_share_the_native_client() -> None:
    assert store_policy.memory_pattern_verdict is memory_pattern_verdict
    assert memory_decision_event.memory_pattern_verdict is memory_pattern_verdict
