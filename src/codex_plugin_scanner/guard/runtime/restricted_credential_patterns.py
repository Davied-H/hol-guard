"""Native credential-path expressions for contained operating-system profiles."""

from __future__ import annotations

from pathlib import Path

from ..native_restricted_pytest import restricted_native


def _read_only_credential_patterns() -> tuple[str, ...]:
    return tuple(restricted_native("credential_patterns", {}, list))


def _seatbelt_string(path: Path | str) -> str:
    return restricted_native("seatbelt_string", {"value": str(path)}, str)


def _read_only_credential_denials(*, hide_metadata: bool = False) -> tuple[str, ...]:
    return tuple(restricted_native("credential_denials", {"hide_metadata": hide_metadata}, list))
