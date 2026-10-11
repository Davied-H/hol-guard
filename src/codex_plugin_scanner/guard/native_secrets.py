"""Typed client for the native ``hol-guard-secrets`` command surface.

Rust owns leaked-secret detection, the repository, history and staged scans,
the pre-commit hook install/uninstall and the public detector rule catalog.
Python parses the command line, absolutizes the target, binds the answer to the
request by ``request_id`` and canonical ``request_sha256`` and renders text.
A refusal the owner reports (a missing target, an unusable Git worktree)
raises ``SecretsRefusedError``; every other outcome that is not a well-formed,
request-bound ``ok`` reply raises ``NativeSecretsError``. Callers must fail
closed and never substitute a Python computation.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Final

from . import native_execution
from .native_context import _canonical_request_sha256, _resolve_digest_home, ensure_resident_prerequisite

_FEATURE: Final = "secrets-scan-v1"
_REQUEST_SCHEMA: Final = "guard-secrets-scan-request.v1"
_RESULT_SCHEMA: Final = "guard-secrets-scan-result.v1"
_RESULT_KEYS: Final = frozenset({"schema", "request_id", "request_sha256", "status", "code", "payload", "message"})
# The resident bounds the canonical request at 64 KiB; the wire envelope adds
# only the operation name and deadline.
_MAX_WIRE_BYTES: Final = 96 * 1024
# Below the resident's two-minute ceiling for this operation.
_TRANSPORT_TIMEOUT_SECONDS: Final = 115.0
_INVALID: Final = "native_secrets_scan_invalid_result"
_REFUSED: Final = "secrets_scan_refused"
_SCAN_BOUND_KEYS: Final = (
    "include_history",
    "max_commits",
    "max_files",
    "max_file_bytes",
    "max_total_bytes",
    "max_findings",
)


class NativeSecretsError(RuntimeError):
    """The native owner could not supply a complete, request-bound answer."""


class SecretsRefusedError(ValueError):
    """The native owner refused the command; the text is safe to show the user."""


def native_secrets_scan(target: str, *, staged: bool, bounds: dict[str, Any]) -> dict[str, Any]:
    """Return the public scan result for a repository, history or staged scan."""

    return _call("staged" if staged else "scan", target=_absolute(target), bounds=_scan_bounds(bounds, staged=staged))


def native_secrets_hook(target: str, *, install: bool) -> dict[str, Any]:
    """Install or uninstall the Guard-managed pre-commit hook; return the public result."""

    return _call("install_hook" if install else "uninstall_hook", target=_absolute(target), bounds=None)


def native_secrets_rules() -> tuple[str, str]:
    """Return ``(json_text, plain_text)`` renderings of the public detector catalog."""

    payload = _call("rules", target="", bounds=None)
    json_text, plain_text = payload.get("json"), payload.get("text")
    if set(payload) != {"json", "text"} or not isinstance(json_text, str) or not isinstance(plain_text, str):
        raise NativeSecretsError(_INVALID)
    return json_text, plain_text


def _absolute(target: str) -> str:
    return os.path.abspath(Path(target).expanduser())


def _scan_bounds(bounds: dict[str, Any], *, staged: bool) -> dict[str, Any]:
    # A staged scan has no history; the wire still carries every bound.
    return {key: (False if staged and key == "include_history" else bounds[key]) for key in _SCAN_BOUND_KEYS}


def _call(action: str, *, target: str, bounds: dict[str, Any] | None) -> dict[str, Any]:
    request: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": native_execution._request_id("secrets_scan"),
        "guard_home": "",
        "action": action,
        "target": target,
        "bounds": bounds,
    }
    try:
        home = _resolve_digest_home(None)
        request["guard_home"] = str(home)
        if not ensure_resident_prerequisite(home):
            raise NativeSecretsError("native_secrets_scan_unavailable")
        request_sha256 = _canonical_request_sha256(request)
        decoded = native_execution._resident_request(
            operation="secrets_scan",
            request=request,
            guard_home=home,
            timeout_seconds=_TRANSPORT_TIMEOUT_SECONDS,
            required_feature=_FEATURE,
            response_schema=_RESULT_SCHEMA,
            max_request_bytes=_MAX_WIRE_BYTES,
        )
    except (OSError, TypeError, ValueError) as error:
        raise NativeSecretsError("native_secrets_scan_unavailable") from error
    if decoded is None:
        raise NativeSecretsError("native_secrets_scan_unavailable")
    if not set(decoded) <= _RESULT_KEYS:
        raise NativeSecretsError(_INVALID)
    if decoded.get("request_id") != request["request_id"] or decoded.get("request_sha256") != request_sha256:
        raise NativeSecretsError("native_secrets_scan_request_mismatch")
    code = decoded.get("code")
    if code == _REFUSED and decoded.get("status") == "error":
        message = decoded.get("message")
        if not isinstance(message, str) or decoded.get("payload") is not None:
            raise NativeSecretsError(_INVALID)
        raise SecretsRefusedError(message)
    if decoded.get("status") != "ok" or code != "ok" or decoded.get("message") is not None:
        raise NativeSecretsError(_INVALID)
    payload = decoded.get("payload")
    if not isinstance(payload, dict):
        raise NativeSecretsError(_INVALID)
    return payload
