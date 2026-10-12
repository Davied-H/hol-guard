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
    def unavailable(*args: object, **kwargs: object) -> object:
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

    def tracked(kind: str, args: dict[str, object], *, guard_home: Path | None = None) -> dict[str, object]:
        calls.append(kind)
        return original(kind, args, guard_home=guard_home)

    monkeypatch.setattr(native_signal_projection, "_request", tracked)
    token = bind_context_digest_home(tmp_path)
    try:
        result = canonical_approval_surfaces_batch([("review", None, None)] * count)
    finally:
        reset_context_digest_home(token)
    assert len(result) == count
    assert calls == ["projection_surfaces_batch"] * expected_calls
    assert all(item.policy_action == "review" and item.contract_error is None for item in result)


@pytest.mark.usefixtures("native_prompt_runtime")
def test_store_read_projections_use_the_connection_home(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.models import GuardApprovalRequest
    from codex_plugin_scanner.guard.store import GuardStore

    home = tmp_path / "custom-guard-home"
    store = GuardStore(home)
    request = GuardApprovalRequest(
        request_id="custom-home-request",
        harness="codex",
        artifact_id="artifact-1",
        artifact_name="fixture",
        artifact_hash="sha256:" + "a" * 64,
        policy_action="review",
        recommended_scope="artifact",
        changed_fields=(),
        source_scope="project",
        config_path="config.toml",
        review_command="review",
        approval_url="",
    )
    store.add_approval_request(request, "2026-01-01T00:00:00+00:00")
    original = native_runner_authority.native_runner_authority
    homes: list[Path] = []

    def bound(kind: str, args: object, guard_home: Path | None = None):
        if kind.startswith("projection_"):
            if guard_home is None:
                raise native_runner_authority.NativeRunnerAuthorityError("default_home_unavailable")
            assert guard_home == home
            homes.append(guard_home)
        return original(kind, args, guard_home=guard_home)

    monkeypatch.setattr(native_runner_authority, "native_runner_authority", bound)
    page = store.list_approval_request_page(include_totals=False)
    detail = store.get_approval_request(request.request_id, derive_scope=False)
    assert page["items"][0]["request_id"] == request.request_id
    assert detail is not None and detail["policy_action"] == "review"
    assert homes == [home, home]


def test_boundary_healthy_refusal_is_validation(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*args: object, **kwargs: object) -> object:
        raise native_runner_authority.NativeRunnerAuthorityRefusalError("native_runner_authority_request_too_large")

    monkeypatch.setattr(native_runner_authority, "native_runner_authority", refuse)
    with pytest.raises(native_signal_projection.NativeSignalProjectionError, match="too_large") as caught:
        canonical_approval_surfaces_batch([("review", None, None)])
    assert not isinstance(caught.value, NativeSignalProjectionUnavailableError)


@pytest.mark.usefixtures("native_prompt_runtime")
def test_large_readable_rows_split_without_reordering(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    home = tmp_path / "large-page-home"
    source = canonical_approval_decision("review", None, reject_contradiction=False, guard_home=home).decision_v2_json
    inputs = [("review", {**source, "user_body": str(index) + ":" + "x" * 30_000}, None) for index in range(100)]
    original = native_signal_projection._request
    batches: list[int] = []

    def tracked(kind: str, args: dict[str, object], *, guard_home: Path | None = None):
        if kind == "projection_surfaces_batch":
            batches.append(len(args["rows"]))
        return original(kind, args, guard_home=guard_home)

    monkeypatch.setattr(native_signal_projection, "_request", tracked)
    results = canonical_approval_surfaces_batch(inputs, guard_home=home)
    assert [row.decision_v2_json["user_body"] for row in results] == [row[1]["user_body"] for row in inputs]
    assert batches == [100, 50, 50]
    oversized = [("review", {**source, "user_body": "x" * (2 * 1024 * 1024)}, None)]
    with pytest.raises(native_signal_projection.NativeSignalProjectionError, match="response_too_large"):
        canonical_approval_surfaces_batch(oversized, guard_home=home)
    assert canonical_approval_surfaces_batch([("review", None, None)], guard_home=home)[0].policy_action == "review"


def test_batch_request_bytes_are_bounded_even_below_the_row_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    batches: list[int] = []

    def request(kind: str, args: dict[str, object], *, guard_home: Path | None = None):
        rows = args["rows"]
        batches.append(len(rows))
        return {
            "status": "ok",
            "value": [
                {
                    "policy_action": "review",
                    "decision_v2_json": {},
                    "action_envelope_json": None,
                    "contract_error": None,
                }
                for _ in rows
            ],
        }

    monkeypatch.setattr(native_signal_projection, "_request", request)
    results = canonical_approval_surfaces_batch([("review", {"user_body": "x" * 100_000}, None)] * 40)
    assert len(results) == 40
    assert len(batches) == 2 and sum(batches) == 40 and max(batches) < 40
