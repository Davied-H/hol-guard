"""Typed client for the native settings/hook-copy owner; no Python evaluator."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path

from . import native_execution

_UNSERIALIZABLE = "<unserializable>"


class NativeGuardSupportError(RuntimeError):
    """The native owner could not supply a complete, typed support result."""


def _home(guard_home: Path | None) -> Path:
    if guard_home is not None:
        return guard_home
    from .config import resolve_guard_home

    return resolve_guard_home()


def _call(subop: str, payload: Mapping[str, object], guard_home: Path | None) -> object:
    try:
        result = native_execution.guard_support_native(subop, payload, guard_home=_home(guard_home))
    except (OSError, ValueError) as error:
        raise NativeGuardSupportError("native_guard_support_unavailable") from error
    if result is None:
        raise NativeGuardSupportError("native_guard_support_unavailable")
    return result


def _jsonable(value: object) -> object:
    try:
        json.dumps(value, allow_nan=False)
    except (TypeError, ValueError):
        return _UNSERIALIZABLE
    return value


def _string(result: object) -> str:
    if not isinstance(result, str):
        raise NativeGuardSupportError("native_guard_support_invalid")
    return result


def _optional_string(result: object) -> str | None:
    if result is not None and not isinstance(result, str):
        raise NativeGuardSupportError("native_guard_support_invalid")
    return result


def render_toml(config: Mapping[str, object], *, guard_home: Path | None = None) -> str:
    try:
        json.dumps(config, allow_nan=False)
    except (TypeError, ValueError) as error:
        raise ValueError("Guard config contains a value that cannot be written.") from error
    return _string(_call("toml_render", {"config": config}, guard_home))


def coerce_setting(key: str, value: object, *, max_wait_seconds: int, guard_home: Path | None = None) -> object:
    """Validate one editable setting; raise ValueError with the user-facing message."""
    result = _call(
        "coerce_setting",
        {"key": key, "value": _jsonable(value), "max_wait_seconds": max_wait_seconds},
        guard_home,
    )
    if not isinstance(result, dict):
        raise NativeGuardSupportError("native_guard_support_invalid")
    if "ok" in result:
        return result["ok"]
    message = result.get("error")
    if not isinstance(message, str):
        raise NativeGuardSupportError("native_guard_support_invalid")
    raise ValueError(f"{message}: {value!r}" if result.get("repr") else message)


def coerce_loaded(items: Sequence[Mapping[str, object]], *, guard_home: Path | None = None) -> list[object]:
    result = _call("coerce_loaded", {"items": [dict(item) for item in items]}, guard_home)
    if not isinstance(result, list) or len(result) != len(items):
        raise NativeGuardSupportError("native_guard_support_invalid")
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
