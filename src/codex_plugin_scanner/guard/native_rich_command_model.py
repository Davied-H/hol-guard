"""Request-bound transport for the native rich command parser."""

from __future__ import annotations

import json
import time
from typing import Any
from uuid import uuid4

from .native_context import (
    _canonical_request_sha256,
    _resolve_digest_home,
    ensure_resident_prerequisite,
)
from .native_context import (
    _native_runtime_status_memo as native_runtime_status,
)
from .native_resident_client import native_resident_client_request
from .native_runtime import _isolated_environment

FEATURE = "rich-command-model-v1"
SCHEMA = "guard-rich-command-model-request.v1"
RESULT_SCHEMA = "guard-rich-command-model-result.v1"
_MAX_BYTES = 2 * 1024 * 1024


class NativeCommandModelError(RuntimeError, ValueError):
    """The native parser did not return an authoritative, bound result."""


def _shape(value: Any, spec: Any) -> bool:
    if isinstance(spec, tuple):
        return any(_shape(value, option) for option in spec)
    if isinstance(spec, dict):
        return (
            isinstance(value, dict)
            and set(value) == set(spec)
            and all(_shape(value[key], kind) for key, kind in spec.items())
        )
    if isinstance(spec, list):
        if not isinstance(value, list):
            return False
        if len(spec) == 1:
            return all(_shape(item, spec[0]) for item in value)
        return len(value) == len(spec) and all(_shape(item, kind) for item, kind in zip(value, spec, strict=True))
    return type(value) is spec


def _valid_result(action: str, value: Any) -> bool:
    nullable = (str, type(None))
    span = {"source": str, "start": int, "end": int}
    redirect = {"operator": str, "target": str, "start": int, "end": int}
    specs = {
        "parse": {
            "raw_text": str,
            "normalized_text": str,
            "dialect": str,
            "transport": str,
            "extraction_provenance": str,
            "wrapper_chain": [str],
            "confidence": str,
            "uncertainty_reason": nullable,
            "security_identity": str,
            "path_overridden": bool,
            "segments": [
                {
                    "text": str,
                    "tokens": [str],
                    "executable": nullable,
                    "arguments": [str],
                    "environment_names": [str],
                    "wrapper_chain": [str],
                    "path_overridden": bool,
                    "execution_context": str,
                    "pipeline_index": int,
                    "span": span,
                }
            ],
            "redirects": [{"operator": str, "target": str, "span": span}],
            "embedded_commands": [{"kind": str, "text": str, "execution_context": str, "span": span}],
        },
        "tokens": [[str], bool],
        "windows_tokens": [[str], bool],
        "leading_environment": [[str], int, [str]],
        "executable": nullable,
        "sudo_options": int,
        "segment_tokens": [str],
        "redirects": [redirect],
        "identity": str,
        "env": {
            "complete": bool,
            "error": nullable,
            "original_tokens": [str],
            "expanded_tokens": [str],
            "option_effects": {
                "ignore_environment": bool,
                "unset_names": [str],
                "chdir": nullable,
                "search_path": nullable,
                "verbose": bool,
                "null_output": bool,
            },
            "environment_delta": {"clear": bool, "unset_names": [str], "assignments": [[str, str]]},
            "effective_environment": ([[str, str]], type(None)),
            "effective_cwd": nullable,
            "command_index": (int, type(None)),
            "executable_argv": [str],
            "split_expansions": [{"payload": str, "source_index": int, "tokens": [str]}],
        },
    }
    return action in specs and _shape(value, specs[action])


def request(action: str, args: dict[str, Any], *, timeout_seconds: float = 10.0) -> Any:
    deadline = time.monotonic() + timeout_seconds
    try:
        home = _resolve_digest_home(None)
        if not ensure_resident_prerequisite(home):
            raise NativeCommandModelError("native_rich_command_model_unavailable")
        status = native_runtime_status()
        if (
            not status.available
            or not status.compatible
            or status.identity is None
            or status.capabilities is None
            or FEATURE not in status.capabilities.features
            or "resident-protocol-v2" not in status.capabilities.features
        ):
            raise NativeCommandModelError("native_rich_command_model_unavailable")
        material = {
            "schema": SCHEMA,
            "request_id": uuid4().hex,
            "guard_home": str(home),
            "action": action,
            "args": args,
        }
        digest = _canonical_request_sha256(material)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise NativeCommandModelError("native_rich_command_model_deadline")
        payload = json.dumps(
            {
                "operation": "rich_command_model",
                "request": material,
                "deadline_budget_ms": max(1, int(remaining * 1000)),
            },
            ensure_ascii=False,
        ).encode("utf-8")
        if len(payload) > _MAX_BYTES:
            raise NativeCommandModelError("native_rich_command_model_bounds")
        response = native_resident_client_request(
            executable=status.identity.path,
            guard_home=home,
            environment=_isolated_environment(),
            payload=payload,
            deadline_monotonic=deadline,
        )
        if response is None or len(response) > _MAX_BYTES or time.monotonic() > deadline:
            raise NativeCommandModelError("native_rich_command_model_unavailable")
        decoded = json.loads(response)
        if (
            not isinstance(decoded, dict)
            or set(decoded) != {"schema", "request_id", "request_sha256", "status", "result", "error"}
            or decoded["schema"] != RESULT_SCHEMA
            or decoded["request_id"] != material["request_id"]
            or decoded["request_sha256"] != digest
        ):
            raise NativeCommandModelError("native_rich_command_model_invalid_result")
        if decoded["status"] == "invalid_input" and decoded["error"] == "Command text cannot be empty":
            raise ValueError(decoded["error"])
        if decoded["status"] != "ok" or decoded["error"] is not None:
            raise NativeCommandModelError("native_rich_command_model_invalid_result")
        if not _valid_result(action, decoded["result"]):
            raise NativeCommandModelError("native_rich_command_model_invalid_result")
        return decoded["result"]
    except UnicodeEncodeError as error:
        raise NativeCommandModelError("native_rich_command_model_invalid_input") from error
    except (OSError, TypeError, UnicodeError, json.JSONDecodeError) as error:
        raise NativeCommandModelError("native_rich_command_model_unavailable") from error


def string_tuple(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise NativeCommandModelError("native_rich_command_model_invalid_result")
    return tuple(value)
