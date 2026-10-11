"""Native canonical approval projections for persistence boundaries."""

from __future__ import annotations

from dataclasses import dataclass

from .models import GuardAction
from .native_signal_projection import signal_projection


@dataclass(frozen=True, slots=True)
class CanonicalApprovalDecision:
    """One native queue action and its product-facing projection."""

    policy_action: GuardAction
    decision_v2_json: dict[str, object]
    contract_error: str | None = None


def canonical_approval_decision(
    policy_action: object,
    decision_v2_json: object,
    *,
    reject_contradiction: bool,
) -> CanonicalApprovalDecision:
    return CanonicalApprovalDecision(
        **signal_projection(
            "projection_approval",
            {"action": policy_action, "decision": decision_v2_json, "reject": reject_contradiction},
        )
    )
