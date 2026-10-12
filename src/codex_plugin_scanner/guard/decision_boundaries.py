"""Native action projections for untyped persistence and API boundaries."""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from .decision_projection_boundaries import CanonicalApprovalDecision as CanonicalApprovalDecision
from .decision_projection_boundaries import canonical_approval_decision as canonical_approval_decision
from .models import GuardAction
from .native_signal_projection import NativeSignalProjectionError, signal_projection

# Leave framing and home-path headroom below the resident's 4 MiB request cap.
# ASCII encoding also bounds the canonical digest representation of Unicode.
_PROJECTION_BATCH_BYTES = 3 * 1024 * 1024
_PROJECTION_SIZE_REFUSALS = frozenset(
    {
        "native_runner_authority_request_too_large",
        "native_runner_authority_response_too_large",
        "native_runner_authority_projection_batch_too_large",
    }
)


@dataclass(frozen=True, slots=True)
class CanonicalReceiptDecision:
    """One native receipt action and synchronized envelope fields."""

    policy_decision: GuardAction
    action_envelope_json: dict[str, object] | None
    contract_error: str | None = None


@dataclass(frozen=True, slots=True)
class CanonicalApprovalSurfaces:
    """Approval fields synchronized by a single native evaluation."""

    policy_action: GuardAction
    decision_v2_json: dict[str, object]
    action_envelope_json: dict[str, object] | None
    contract_error: str | None = None


def canonical_receipt_decision(
    policy_decision: object,
    action_envelope_json: object,
    *,
    reject_contradiction: bool,
    guard_home: Path | None = None,
) -> CanonicalReceiptDecision:
    return CanonicalReceiptDecision(
        **signal_projection(
            "projection_receipt",
            {"action": policy_decision, "envelope": action_envelope_json, "reject": reject_contradiction},
            guard_home=guard_home,
        )
    )


def canonical_approval_surfaces(
    policy_action: object,
    decision_v2_json: object,
    action_envelope_json: object,
    *,
    reject_contradiction: bool,
    guard_home: Path | None = None,
) -> CanonicalApprovalSurfaces:
    return CanonicalApprovalSurfaces(
        **signal_projection(
            "projection_surfaces",
            {
                "action": policy_action,
                "decision": decision_v2_json,
                "envelope": action_envelope_json,
                "reject": reject_contradiction,
            },
            guard_home=guard_home,
        )
    )


def canonical_approval_surfaces_batch(
    inputs: Sequence[tuple[object, object, object]],
    *,
    guard_home: Path | None = None,
) -> list[CanonicalApprovalSurfaces]:
    """Project ordered rows within request, response and row-count limits."""

    result: list[CanonicalApprovalSurfaces] = []
    rows: list[dict[str, object]] = []
    size = 0
    for action, decision, envelope in inputs:
        row = {"action": action, "decision": decision, "envelope": envelope}
        try:
            row_size = len(json.dumps(row, separators=(",", ":"), allow_nan=False).encode("utf-8")) + 1
        except (TypeError, ValueError, UnicodeEncodeError) as error:
            raise NativeSignalProjectionError("native_runner_authority_component_unencodable") from error
        if rows and (len(rows) == 128 or size + row_size > _PROJECTION_BATCH_BYTES):
            result.extend(_project_approval_rows(rows, guard_home=guard_home))
            rows, size = [], 0
        rows.append(row)
        size += row_size
    if rows:
        result.extend(_project_approval_rows(rows, guard_home=guard_home))
    return result


def _project_approval_rows(
    rows: list[dict[str, object]], *, guard_home: Path | None
) -> list[CanonicalApprovalSurfaces]:
    try:
        projected = signal_projection(
            "projection_surfaces_batch", {"rows": rows, "reject": False}, guard_home=guard_home
        )
    except NativeSignalProjectionError as error:
        # A bound size refusal proves availability. Split aggregates only;
        # a single unreadable row retains the native refusal and no partial page.
        if str(error) not in _PROJECTION_SIZE_REFUSALS or len(rows) == 1:
            raise
        midpoint = len(rows) // 2
        return _project_approval_rows(rows[:midpoint], guard_home=guard_home) + _project_approval_rows(
            rows[midpoint:], guard_home=guard_home
        )
    return [CanonicalApprovalSurfaces(**row) for row in projected]
