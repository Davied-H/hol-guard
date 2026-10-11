"""Native action projections for untyped persistence and API boundaries."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from .decision_projection_boundaries import CanonicalApprovalDecision as CanonicalApprovalDecision
from .decision_projection_boundaries import canonical_approval_decision as canonical_approval_decision
from .models import GuardAction
from .native_signal_projection import signal_projection


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
) -> CanonicalReceiptDecision:
    return CanonicalReceiptDecision(
        **signal_projection(
            "projection_receipt",
            {"action": policy_decision, "envelope": action_envelope_json, "reject": reject_contradiction},
        )
    )


def canonical_approval_surfaces(
    policy_action: object,
    decision_v2_json: object,
    action_envelope_json: object,
    *,
    reject_contradiction: bool,
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
        )
    )


def canonical_approval_surfaces_batch(
    inputs: Sequence[tuple[object, object, object]],
) -> list[CanonicalApprovalSurfaces]:
    """Project a queue page once per bounded transport batch."""

    result: list[CanonicalApprovalSurfaces] = []
    for offset in range(0, len(inputs), 128):
        rows = [
            {"action": action, "decision": decision, "envelope": envelope}
            for action, decision, envelope in inputs[offset : offset + 128]
        ]
        projected = signal_projection("projection_surfaces_batch", {"rows": rows, "reject": False})
        result.extend(CanonicalApprovalSurfaces(**row) for row in projected)
    return result
