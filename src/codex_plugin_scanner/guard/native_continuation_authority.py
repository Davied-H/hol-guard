"""Bound transport for fused native continuation authority."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from .native_runner_authority import native_runner_authority

if TYPE_CHECKING:
    from .continuation_contract import ContinuationOffer, ContinuationResult


def _wire(value: object) -> object:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Mapping):
        return {key: _wire(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_wire(item) for item in value]
    return value


def offer_wire(offer: ContinuationOffer) -> dict[str, Any]:
    return cast(dict[str, Any], _wire(asdict(offer)))


def result_wire(result: ContinuationResult) -> dict[str, Any]:
    return cast(dict[str, Any], _wire(asdict(result)))


def result_dto(value: object) -> ContinuationResult | None:
    from .continuation_contract import ContinuationResult

    if value is None:
        return None
    fields = dict(cast(Mapping[str, Any], value))
    fields["completed_at"] = datetime.fromisoformat(fields["completed_at"])
    return ContinuationResult(**fields)


def continuation_authority(call: str, *, guard_home: Path | None = None, **args: Any) -> dict[str, Any]:
    carrier = {"call": call, **args}
    if call.startswith("store_") and guard_home is not None:
        carrier["guard_home"] = str(guard_home)
    result = native_runner_authority("continuation_authority", carrier, guard_home)
    if result.get("exception") == "RuntimeError":
        raise RuntimeError(result["error"])
    if result.get("exception") == "ValueError":
        raise ValueError(result["error"])
    return result


def project(
    offer: ContinuationOffer,
    result: ContinuationResult,
    *,
    operation: Mapping[str, object] | None = None,
    request_id: str = "",
    action: str = "allow_once",
    now: str = "",
    guard_home: Path | None = None,
) -> dict[str, Any]:
    return continuation_authority(
        "project",
        offer=offer_wire(offer),
        result=result_wire(result),
        operation=operation,
        request_id=request_id,
        action=action,
        now=now,
        guard_home=guard_home,
    )
