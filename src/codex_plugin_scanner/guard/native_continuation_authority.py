"""Bound transport for fused native continuation authority."""

from __future__ import annotations

import json
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import asdict
from datetime import datetime
from functools import lru_cache
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
    if operation is None and not request_id and action == "allow_once" and not now and guard_home is None:
        carrier = json.dumps(
            {"offer": offer_wire(offer), "result": result_wire(result)},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        return deepcopy(_public_projection(carrier))
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


@lru_cache(maxsize=128)
def _public_projection(carrier: str) -> dict[str, Any]:
    """Reuse one bound pure projection for the immutable public carrier pair."""
    return continuation_authority(
        "project",
        **json.loads(carrier),
        operation=None,
        request_id="",
        action="allow_once",
        now="",
    )
