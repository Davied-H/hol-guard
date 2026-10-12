"""Typed client for the native settings/hook-copy owner; no Python evaluator."""

from __future__ import annotations

import json
import math
from collections.abc import Mapping, Sequence
from pathlib import Path

from . import native_execution

_UNSERIALIZABLE = "<unserializable>"
_NON_FINITE_TAG = "\0float"


UNAVAILABLE_MESSAGE = "HOL Guard's native runtime is unavailable, so this request could not be completed."


class NativeGuardSupportError(ValueError):
    """The native owner could not supply a complete, typed support result.

    A `ValueError` so CLI entry points print the message instead of a traceback.
    """


def _home(guard_home: Path | None) -> Path:
    if guard_home is not None:
        return guard_home
    from .config import resolve_guard_home

    return resolve_guard_home()


def _call(subop: str, payload: Mapping[str, object], guard_home: Path | None) -> object:
    try:
        result = native_execution.guard_support_native(subop, payload, guard_home=_home(guard_home))
    except (OSError, ValueError) as error:
        raise NativeGuardSupportError(UNAVAILABLE_MESSAGE) from error
    if result is None:
        raise NativeGuardSupportError(UNAVAILABLE_MESSAGE)
    return result


def _jsonable(value: object) -> object:
    try:
        json.dumps(value, allow_nan=False)
    except (TypeError, ValueError):
        return _UNSERIALIZABLE
    return value


def _string(result: object) -> str:
    if not isinstance(result, str):
        raise NativeGuardSupportError("HOL Guard received an invalid reply from its native runtime.")
    return result


def _optional_string(result: object) -> str | None:
    if result is not None and not isinstance(result, str):
        raise NativeGuardSupportError("HOL Guard received an invalid reply from its native runtime.")
    return result


def _toml_value(value: object) -> object:
    """Shape a parsed config value the way the previous Python writer rendered it."""
    if isinstance(value, float) and not math.isfinite(value):
        return {_NON_FINITE_TAG: repr(value)}
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, list):
        return [_toml_value(item) for item in value]
    if isinstance(value, dict):
        return {key: _toml_value(item) for key, item in value.items() if isinstance(key, str)}
    return str(value)


def render_toml(config: Mapping[str, object], *, guard_home: Path | None = None) -> str:
    return _string(_call("toml_render", {"config": _toml_value(dict(config))}, guard_home))


def coerce_setting(key: str, value: object, *, max_wait_seconds: int, guard_home: Path | None = None) -> object:
    """Validate one editable setting; raise ValueError with the user-facing message."""
    result = _call(
        "coerce_setting",
        {"key": key, "value": _jsonable(value), "max_wait_seconds": max_wait_seconds},
        guard_home,
    )
    if not isinstance(result, dict):
        raise NativeGuardSupportError("HOL Guard received an invalid reply from its native runtime.")
    if "ok" in result:
        return result["ok"]
    message = result.get("error")
    if not isinstance(message, str):
        raise NativeGuardSupportError("HOL Guard received an invalid reply from its native runtime.")
    raise ValueError(f"{message}: {value!r}" if result.get("repr") else message)


def coerce_loaded(items: Sequence[Mapping[str, object]], *, guard_home: Path | None = None) -> list[object]:
    result = _call("coerce_loaded", {"items": [dict(item) for item in items]}, guard_home)
    if not isinstance(result, list) or len(result) != len(items):
        raise NativeGuardSupportError("HOL Guard received an invalid reply from its native runtime.")
    return result


def _artifact(artifact: object) -> dict[str, object]:
    return {
        "artifact_type": getattr(artifact, "artifact_type", ""),
        "metadata": dict(getattr(artifact, "metadata", None) or {}),
    }


def native_reason(artifact: object, response: Mapping[str, object], *, guard_home: Path | None = None) -> str:
    return _string(_call("native_reason", {"artifact": _artifact(artifact), "response": dict(response)}, guard_home))


def claude_additional_context(
    *,
    harness: str,
    event_name: str,
    policy_action: str,
    artifact: object,
    native_reason: str,
    guard_home: Path | None = None,
) -> str | None:
    payload = {
        "artifact": _artifact(artifact),
        "event_name": event_name,
        "policy_action": policy_action,
        "native_reason": native_reason,
        "claude_harness": harness == "claude-code",
    }
    return _optional_string(_call("claude_additional_context", payload, guard_home))


def claude_system_message(
    *,
    event_name: str,
    policy_action: str,
    artifact: object,
    native_reason: str,
    guard_home: Path | None = None,
) -> str | None:
    payload = {
        "artifact": _artifact(artifact),
        "event_name": event_name,
        "policy_action": policy_action,
        "native_reason": native_reason,
    }
    return _optional_string(_call("claude_system_message", payload, guard_home))


def codex_block_message(*, policy_action: str, native_reason: str, guard_home: Path | None = None) -> str | None:
    payload = {"policy_action": policy_action, "native_reason": native_reason}
    return _optional_string(_call("codex_block_message", payload, guard_home))
