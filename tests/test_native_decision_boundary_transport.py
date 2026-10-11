from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_runner_authority, native_signal_projection
from codex_plugin_scanner.guard.decision_boundaries import (
    canonical_approval_decision,
    canonical_approval_surfaces,
    canonical_approval_surfaces_batch,
    canonical_receipt_decision,
)
from codex_plugin_scanner.guard.native_signal_projection import NativeSignalProjectionUnavailableError


@pytest.mark.parametrize("operation", ("approval", "receipt", "surfaces", "batch"))
def test_boundary_native_outage_has_no_local_verdict(monkeypatch: pytest.MonkeyPatch, operation: str) -> None:
    def unavailable(*args: object) -> object:
        raise native_runner_authority.NativeRunnerAuthorityError("native_runtime_unavailable")

    monkeypatch.setattr(native_runner_authority, "native_runner_authority", unavailable)
    with pytest.raises(NativeSignalProjectionUnavailableError, match="native_runtime_unavailable") as caught:
        if operation == "approval":
            canonical_approval_decision("allow", None, reject_contradiction=False)
        elif operation == "receipt":
            canonical_receipt_decision("allow", None, reject_contradiction=False)
        elif operation == "surfaces":
            canonical_approval_surfaces("allow", None, None, reject_contradiction=False)
        else:
            canonical_approval_surfaces_batch([("allow", None, None)])
    assert not isinstance(caught.value, ValueError)
    assert isinstance(caught.value.__cause__, native_runner_authority.NativeRunnerAuthorityError)


@pytest.mark.usefixtures("native_prompt_runtime")
@pytest.mark.parametrize("count,expected_calls", ((0, 0), (25, 1), (129, 2)))
def test_queue_projection_uses_one_native_call_per_bounded_page(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    count: int,
    expected_calls: int,
) -> None:
    from codex_plugin_scanner.guard.native_context import bind_context_digest_home, reset_context_digest_home

    original = native_signal_projection._request
    calls: list[str] = []

    def tracked(kind: str, args: dict[str, object]) -> dict[str, object]:
        calls.append(kind)
        return original(kind, args)

    monkeypatch.setattr(native_signal_projection, "_request", tracked)
    token = bind_context_digest_home(tmp_path)
    try:
        result = canonical_approval_surfaces_batch([("review", None, None)] * count)
    finally:
        reset_context_digest_home(token)
    assert len(result) == count
    assert calls == ["projection_surfaces_batch"] * expected_calls
    assert all(item.policy_action == "review" and item.contract_error is None for item in result)
