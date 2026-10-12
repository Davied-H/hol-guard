"""Package shim audit proof persistence (the manifest write is the resident's ``shim_admin``)."""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

from .native_shim_admin import NativeShimAdminError
from .native_shim_admin import record_package_shim_audit_result as _record_audit


class HarnessContextLike(Protocol):
    @property
    def guard_home(self) -> Path: ...


PACKAGE_SHIM_STATUS_FD_ENV_VAR = "HOL_GUARD_PACKAGE_SHIM_STATUS_FD"


def record_package_shim_audit_result(
    context: HarnessContextLike,
    *,
    audited_at: str | None = None,
) -> None:
    """Stamp the audit time; a refused or failed write is a ``ValueError``."""

    try:
        _record_audit(context.guard_home, audited_at=audited_at)
    except NativeShimAdminError as error:
        raise ValueError(error.detail or error.code) from error
