"""Consumer artifact decision composition answered by the native runtime.

The consumer evaluation gathers evidence (detected artifacts, capability
deltas, store history, provenance, saved-decision lookups, context tokens);
the resident scores the artifact, composes the current policy action,
validates and composes saved/claimed approval reuse and the trusted-request
override, and applies runtime-detector authority. There is no Python
evaluator: ``native_consumer_compose`` raises ``NativeConsumerComposeError``
for anything but a bound, strictly decoded ``ok`` answer, so a missing
resident fails the evaluation closed.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from pathlib import Path
from uuid import uuid4

from .models import GUARD_ACTION_VALUES
from .native_context import _canonical_request_sha256, _resolve_digest_home, ensure_resident_prerequisite
from .native_execution import _resident_request

CONSUMER_ARTIFACT_COMPOSE_FEATURE = "consumer-artifact-compose-v1"
_REQUEST_SCHEMA = "guard-consumer-artifact-compose-request.v1"
_RESULT_SCHEMA = "guard-consumer-artifact-compose-result.v1"
_RESIDENT_CODE = re.compile(r"^native_consumer_artifact_compose_[a-z_]{1,64}$")
_UNAVAILABLE = "native_consumer_artifact_compose_unavailable"
_TIMEOUT_SECONDS = 5.0
# Every field is sent explicitly (nulls included) so the digest bound here
# equals the resident's digest of its decoded request.
_FIELDS: dict[str, frozenset[str]] = {
    "current_action": frozenset(
        {
            "removed",
            "artifact_type",
            "configured_action",
            "guard_default_action",
            "first_seen",
            "changed",
            "effective_default_action",
            "config_changed_hash_action",
            "config_default_action",
            "skill_directory_identity_reusable",
            "signals",
            "deltas",
            "provenance_source_kind",
            "publisher_trust",
            "prior_approvals",
            "prior_incidents",
        }
    ),
    "runtime_decision": frozenset(
        {
            "current_action",
            "configured_action",
            "scanner_action",
            "raw_scoring_recommendation",
            "skill_directory_identity_reusable",
            "approval_context_hash",
            "saved_decision",
            "ignored_local_integrity",
            "diagnosed_reason",
            "trusted_request_override_hash",
            "claimed_saved_approval_hash",
            "retained_saved_approval_hash",
            "saved_approval_qualification",
            "runtime_detector_composition",
            "runtime_detector_block_reason",
            "runtime_signals",
        }
    ),
}

# The exact answer shape of each query kind. Spec letters: a action,
# A action or null, b bool, s string, d dict, D dict or null, l list.
_ANSWERS: dict[str, dict[str, str]] = {
    "current_action": {"current_action": "a", "scanner_action": "A", "verdict": "D"},
    "runtime_decision": {
        "approval_claim": "D",
        "approval_reuse": "d",
        "approval_source": "s",
        "append_pending_claim": "b",
        "authority_finalized": "b",
        "decision_reason": "s",
        "policy_action": "a",
        "policy_composition": "d",
        "saved_state_present": "b",
        "scanner_evidence": "l",
        "trusted_request_override": "b",
    },
}


def _field_valid(spec: str, value: object) -> bool:
    if spec.isupper() and value is None:
        return True
    match spec.lower():
        case "a":
            return isinstance(value, str) and value in GUARD_ACTION_VALUES
        case "b":
            return isinstance(value, bool)
        case "s":
            return isinstance(value, str)
        case "d":
            return isinstance(value, dict)
        case "l":
            return isinstance(value, list)
    return False


def _answer_valid(kind: str, payload: dict[str, object]) -> bool:
    shape = _ANSWERS[kind]
    return set(payload) == set(shape) and all(_field_valid(spec, payload[name]) for name, spec in shape.items())


class NativeConsumerComposeError(RuntimeError):
    """No authoritative composition answer; ``code`` says why, for diagnostics."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def native_consumer_compose(kind: str, fields: Mapping[str, object], *, guard_home: Path | None) -> dict[str, object]:
    """Return the resident's answer to one composition query, or raise."""

    expected = _FIELDS.get(kind)
    if expected is None or set(fields) != expected:
        raise NativeConsumerComposeError("native_consumer_artifact_compose_request_invalid")
    try:
        home = _resolve_digest_home(guard_home)
    except (OSError, RuntimeError, ValueError):
        raise NativeConsumerComposeError("native_consumer_artifact_compose_home_unbound") from None
    request: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": f"consumer-artifact-compose-{uuid4().hex}",
        "query": {"kind": kind, **fields},
    }
    try:
        digest = "sha256:" + _canonical_request_sha256(request)
    except (TypeError, ValueError):
        raise NativeConsumerComposeError("native_consumer_artifact_compose_request_invalid") from None
    if not ensure_resident_prerequisite(home):
        raise NativeConsumerComposeError(_UNAVAILABLE)
    response = _resident_request(
        operation="consumer_artifact_compose",
        request=request,
        guard_home=home,
        timeout_seconds=_TIMEOUT_SECONDS,
        required_feature=CONSUMER_ARTIFACT_COMPOSE_FEATURE,
        response_schema=_RESULT_SCHEMA,
    )
    if (
        response is None
        or response.get("schema") != _RESULT_SCHEMA
        or response.get("request_id") != request["request_id"]
        or response.get("request_sha256") != digest
    ):
        raise NativeConsumerComposeError(_UNAVAILABLE)
    status, code = response.get("status"), response.get("code")
    if status == "error":
        reason = code if isinstance(code, str) and _RESIDENT_CODE.fullmatch(code) else _UNAVAILABLE
        raise NativeConsumerComposeError(reason)
    payload = response.get("payload")
    if status != "ok" or code != "ok" or not isinstance(payload, dict):
        raise NativeConsumerComposeError("native_consumer_artifact_compose_payload_invalid")
    if not _answer_valid(kind, payload):
        raise NativeConsumerComposeError("native_consumer_artifact_compose_payload_invalid")
    return payload


__all__ = ["CONSUMER_ARTIFACT_COMPOSE_FEATURE", "NativeConsumerComposeError", "native_consumer_compose"]
