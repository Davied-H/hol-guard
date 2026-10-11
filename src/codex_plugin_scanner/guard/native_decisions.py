"""Bound resident transport for decision construction and validation."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


class NativeDecisionAuthorityError(ValueError):
    """The native owner returned an incomplete decision projection."""


def _invalid() -> NativeDecisionAuthorityError:
    return NativeDecisionAuthorityError("native_decision_authority_result_invalid")


def _request(kind: str, args: Mapping[str, object]) -> dict[str, Any]:
    from .native_runner_authority import native_runner_authority

    return native_runner_authority(kind, args)


def _fields(payload: object, fields: Mapping[str, type], nullable: tuple[str, ...] = ()) -> dict[str, Any]:
    if not isinstance(payload, dict) or set(payload) != set(fields):
        raise _invalid()
    for key, kind in fields.items():
        value = payload[key]
        if value is None and key in nullable:
            continue
        if not isinstance(value, kind) or (kind is int and isinstance(value, bool)):
            raise _invalid()
    return payload


def _shape(payload: dict[str, Any], kind: str) -> None:
    if kind == "enforcement":
        _fields(
            payload,
            dict.fromkeys(
                (
                    "blocking",
                    "authority_finalized",
                    "launch_permitted",
                    "prompt_required",
                    "sandbox_required",
                    "snapshot_permitted",
                ),
                bool,
            ),
        )
        return
    if kind == "authoritative":
        _fields(
            payload,
            {
                "schema_version": int,
                "action": str,
                "source": str,
                "reason": str,
                "composition_trace": dict,
                "signals": list,
                "enforcement": dict,
                "decision_v2": dict,
            },
        )
        _shape(payload["enforcement"], "enforcement")
        _shape(payload["decision_v2"], "v2")
    else:
        fields: dict[str, type] = dict.fromkeys(
            (
                "guard_action",
                "action",
                "reason",
                "user_title",
                "user_body",
                "harness_message",
                "dashboard_primary_detail",
                "retry_instruction",
                "confidence",
            ),
            str,
        )
        fields.update({"approval_scopes": list, "signals": list})
        if "package_review_cloud_reason_code" in payload:
            fields["package_review_cloud_reason_code"] = str
        _fields(payload, fields, ("retry_instruction", "package_review_cloud_reason_code"))
        if any(not isinstance(scope, str) for scope in payload["approval_scopes"]):
            raise _invalid()
    signal_fields: dict[str, type] = dict.fromkeys(
        (
            "signal_id",
            "category",
            "severity",
            "confidence",
            "detector",
            "title",
            "plain_reason",
            "technical_detail",
            "evidence_ref",
            "redaction_level",
            "false_positive_hint",
            "advisory_id",
        ),
        str,
    )
    for signal in payload["signals"]:
        _fields(signal, signal_fields, ("technical_detail", "evidence_ref", "false_positive_hint", "advisory_id"))


def decision_authority(kind: str, args: Mapping[str, object]) -> dict[str, Any]:
    result = _request(kind, args)
    if result.get("status") == "error":
        message = result.get("message")
        error_type = result.get("error_type")
        if not isinstance(message, str) or error_type != "ValueError":
            raise _invalid()
        raise ValueError(message)
    value = result.get("value")
    if result.get("status") != "ok" or not isinstance(value, dict):
        raise _invalid()
    shape = (
        "enforcement"
        if kind == "decision_enforcement_decode"
        else ("v2" if kind in {"decision_v2_decode", "decision_legacy"} else "authoritative")
    )
    _shape(value, shape)
    return value
