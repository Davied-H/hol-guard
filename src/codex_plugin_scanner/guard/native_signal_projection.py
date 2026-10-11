"""Bound transport for native persistence projections."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


class NativeSignalProjectionError(ValueError):
    """The native owner returned an incomplete projection."""


def _request(kind: str, args: Mapping[str, object]) -> dict[str, Any]:
    from .native_runner_authority import native_runner_authority

    return native_runner_authority(kind, args)


def signal_projection(kind: str, args: Mapping[str, object]) -> Any:
    result = _request(kind, args)
    if (
        result.get("status") == "error"
        and result.get("error_type") == "ValueError"
        and isinstance(result.get("message"), str)
    ):
        raise ValueError(result["message"])
    value = result.get("value")
    batch = kind == "projection_surfaces_batch"
    rows = value if batch and isinstance(value, list) else [value]
    valid = result.get("status") == "ok" and (not batch or isinstance(value, list))
    if batch:
        inputs = args.get("rows")
        valid = valid and isinstance(inputs, list) and len(rows) == len(inputs)
    action_key = "policy_decision" if kind == "projection_receipt" else "policy_action"
    keys = {"contract_error", action_key}
    if kind != "projection_receipt":
        keys.add("decision_v2_json")
    if kind != "projection_approval":
        keys.add("action_envelope_json")
    for row in rows:
        if not isinstance(row, dict) or set(row) != keys or not isinstance(row.get(action_key), str):
            raise NativeSignalProjectionError("native_signal_projection_result_invalid")
        valid = valid and (row["contract_error"] is None or isinstance(row["contract_error"], str))
        valid = valid and (kind == "projection_receipt" or isinstance(row.get("decision_v2_json"), dict))
        valid = valid and (row.get("action_envelope_json") is None or isinstance(row["action_envelope_json"], dict))
    if not valid:
        raise NativeSignalProjectionError("native_signal_projection_result_invalid")
    return value
