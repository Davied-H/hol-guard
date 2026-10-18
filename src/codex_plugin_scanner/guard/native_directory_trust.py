"""Typed client for the native directory-trust owner; no Python evaluator.

Whether a request may name a directory is a Guard verdict, not transport, so
Rust decides it. Python frames what it read -- the Guard home it is serving,
its own home and temporary directory, and the candidate paths a hook sent --
binds the answer by ``request_id`` and canonical ``request_sha256``, and reads
the verdicts back in the order it asked.

Nothing here resolves a path or compares it against a root. A transport,
capability, or binding failure raises ``NativeDirectoryTrustError``; the hook
routes turn that into the same rejection an untrusted path gets, so an
unreachable runtime refuses a directory instead of trusting it.
"""

from __future__ import annotations

import json
import tempfile
import time
import uuid
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from .native_context import (
    _canonical_request_sha256,
    _native_error,
    _native_runtime_status_memo,
    _resolve_digest_home,
    ensure_resident_prerequisite,
)
from .native_resident_client import native_resident_client_request
from .native_resident_prerequisite_reason import prerequisite_unavailable_code
from .native_runtime import _isolated_environment
from .native_runtime_resilience import (
    native_record_overload,
    native_record_resident_failure,
    native_record_resident_success,
)

_FEATURE = "directory-trust-v1"
_RESIDENT_PROTOCOL_FEATURE = "resident-protocol-v2"
_REQUEST_SCHEMA = "guard-directory-trust-request.v1"
_RESULT_SCHEMA = "guard-directory-trust-result.v1"
_MAX_REQUEST_BYTES = 64 * 1024
_TIMEOUT_SECONDS = 5.0
_INVALID_RESULT = "native_directory_trust_result_invalid"

#: The reason a caller records when the runtime could not answer at all. It is
#: not one of the runtime's own verdicts: those name what was wrong with the
#: path, and this names what was wrong with the runtime.
UNAVAILABLE_REASON = "native_directory_trust_unavailable"


class NativeDirectoryTrustError(ValueError):
    """The native owner could not supply a bound directory-trust answer."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class DirectoryTrustVerdict:
    """One candidate's answer: the path to use, or why it may not be used."""

    __slots__ = ("parameter", "path", "reason")

    def __init__(self, parameter: str, path: str | None, reason: str | None) -> None:
        self.parameter = parameter
        self.path = path
        self.reason = reason

    @property
    def trusted(self) -> bool:
        return self.path is not None


def native_directory_trust(
    candidates: Sequence[tuple[str, str]],
    *,
    guard_home: Path | str,
    home_dir: Path | str | None = None,
    deadline_monotonic: float | None = None,
) -> list[DirectoryTrustVerdict]:
    """Settle every ``(parameter, value)`` candidate in one resident call.

    ``parameter`` names the rule: ``guard-home`` has to resolve to the store
    this process is serving, ``workspace`` may also name a scratch directory
    the caller owns under a temporary root, and anything else has to sit under
    a trusted root. The verdicts come back in the order they were asked for.

    ``deadline_monotonic`` caps the wait. A caller working to a deadline of
    its own — a hook with a host budget to keep — passes it so a slow resident
    cannot spend the whole budget settling paths; without one the call waits
    the module's own timeout.
    """

    if not candidates:
        return []
    home = Path.home() if home_dir is None else Path(home_dir)
    request: dict[str, Any] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": uuid.uuid4().hex,
        "guard_home": str(guard_home),
        "home_dir": str(home),
        # The resident has its own `TMPDIR`, which an isolated environment may
        # not share; the temporary-root rules follow this process's.
        "temp_dir": tempfile.gettempdir(),
        "candidates": [{"parameter": parameter, "value": value} for parameter, value in candidates],
    }
    result = _round_trip(
        request,
        _resolve_digest_home(Path(guard_home)),
        deadline_monotonic=deadline_monotonic,
    )
    verdicts = result.get("results")
    if not isinstance(verdicts, list) or len(verdicts) != len(candidates):
        raise NativeDirectoryTrustError(_INVALID_RESULT)
    answers: list[DirectoryTrustVerdict] = []
    for (parameter, _value), verdict in zip(candidates, verdicts, strict=True):
        if not isinstance(verdict, dict) or verdict.get("parameter") != parameter:
            raise NativeDirectoryTrustError(_INVALID_RESULT)
        path = verdict.get("path")
        reason = verdict.get("reason")
        if verdict.get("trusted") is True:
            if not isinstance(path, str) or not path:
                raise NativeDirectoryTrustError(_INVALID_RESULT)
            answers.append(DirectoryTrustVerdict(parameter, path, None))
            continue
        if not isinstance(reason, str) or not reason:
            raise NativeDirectoryTrustError(_INVALID_RESULT)
        answers.append(DirectoryTrustVerdict(parameter, None, reason))
    return answers


def _round_trip(
    request: dict[str, Any],
    guard_home: Path,
    *,
    deadline_monotonic: float | None = None,
) -> dict[str, object]:
    """One bound resident round trip; returns the verified result document."""

    status = _native_runtime_status_memo()
    if (
        not status.available
        or not status.compatible
        or status.identity is None
        or status.capabilities is None
        or _FEATURE not in status.capabilities.features
        or _RESIDENT_PROTOCOL_FEATURE not in status.capabilities.features
    ):
        raise NativeDirectoryTrustError(UNAVAILABLE_REASON)
    try:
        prerequisite = ensure_resident_prerequisite(guard_home)
    except Exception as error:
        raise NativeDirectoryTrustError("native_directory_trust_prerequisite_unavailable") from error
    if not prerequisite:
        raise NativeDirectoryTrustError(
            prerequisite_unavailable_code("native_directory_trust_prerequisite_unavailable", guard_home)
        )
    deadline = time.monotonic() + _TIMEOUT_SECONDS
    if deadline_monotonic is not None:
        deadline = min(deadline, deadline_monotonic)
    budget_ms = max(1, int((deadline - time.monotonic()) * 1000))
    try:
        request_sha256 = "sha256:" + _canonical_request_sha256(request)
        envelope = json.dumps(
            {"operation": "directory_trust", "deadline_budget_ms": budget_ms, "request": request},
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        # A path carrying lone surrogates cannot cross a strict JSON
        # transport. It is not a path this runtime may trust either.
        raise NativeDirectoryTrustError("native_directory_trust_component_unencodable") from error
    if len(envelope) > _MAX_REQUEST_BYTES:
        raise NativeDirectoryTrustError("native_directory_trust_request_too_large")
    try:
        output = native_resident_client_request(
            executable=status.identity.path,
            guard_home=guard_home,
            environment=_isolated_environment(),
            payload=envelope,
            deadline_monotonic=deadline,
        )
    except Exception:
        output = None
    if output is None:
        native_record_resident_failure(status.identity.sha256, guard_home, reason=UNAVAILABLE_REASON)
        raise NativeDirectoryTrustError(UNAVAILABLE_REASON)
    try:
        result = json.loads(output)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        native_record_resident_failure(status.identity.sha256, guard_home, reason=_INVALID_RESULT)
        raise NativeDirectoryTrustError(_INVALID_RESULT) from error
    error_code = _native_error(result)
    if error_code is not None:
        if error_code == "native_overloaded":
            native_record_overload(status.identity.sha256, guard_home)
        else:
            native_record_resident_failure(status.identity.sha256, guard_home, reason=error_code)
        raise NativeDirectoryTrustError(error_code)
    if (
        not isinstance(result, dict)
        or result.get("schema") != _RESULT_SCHEMA
        or result.get("request_id") != request["request_id"]
        or result.get("request_sha256") != request_sha256
        or result.get("status") != "ok"
        or result.get("code") != "ok"
    ):
        native_record_resident_failure(status.identity.sha256, guard_home, reason=_INVALID_RESULT)
        raise NativeDirectoryTrustError(_INVALID_RESULT)
    native_record_resident_success(status.identity.sha256, guard_home)
    return result


__all__ = [
    "UNAVAILABLE_REASON",
    "DirectoryTrustVerdict",
    "NativeDirectoryTrustError",
    "native_directory_trust",
]
