"""Process-wide reuse of a verified native runtime status.

``native_runtime_status`` outside a daemon request scope re-stats the binary,
re-reads the bundled manifest and, for a runtime younger than the identity
cache window or on non-POSIX hosts, re-hashes the whole binary. This cache keeps
one verified ``ready`` status per process and trusts it only while a stat-only
check proves nothing moved: the resolved candidate path, the binary's full stat
identity and owner, and the manifest's full stat identity and owner must all be
unchanged. Any difference, stat error or disappearance drops the entry so the
caller recomputes and fails closed. Files changed within the identity cache age
window, and every non-POSIX host, never enter the cache.
"""

from __future__ import annotations

import os
import threading
import time
from pathlib import Path

from .file_identity import full_stat_identity
from .native_runtime_request_scope import _RequestKey, _resolved_candidate_path
from .native_runtime_values import NativeRuntimeStatus

_MIN_AGE_NS = 2_000_000_000
_MAX_ENTRIES = 8
_ENABLED = os.name == "posix" and hasattr(os, "O_NOFOLLOW")
_LOCK = threading.Lock()
_Fingerprint = tuple[int, ...]
_STATUSES: dict[_RequestKey, tuple[NativeRuntimeStatus, _Fingerprint, _Fingerprint | None]] = {}


def _fingerprint(path: Path, *, follow: bool) -> _Fingerprint | None:
    """Return a stat-only identity for ``path`` when it is old enough to trust."""

    try:
        metadata = path.stat() if follow else path.lstat()
    except OSError:
        return None
    changed_at = int(getattr(metadata, "st_ctime_ns", 0))
    if changed_at <= 0 or time.time_ns() - changed_at < _MIN_AGE_NS:
        return None
    return (*full_stat_identity(metadata), int(metadata.st_uid), int(metadata.st_gid))


def _manifest_path(status: NativeRuntimeStatus) -> Path | None:
    identity = status.identity
    if identity is None or status.manifest is None:
        return None
    return identity.path.with_name("runtime-manifest.json")


def remember_process_status(key: _RequestKey, status: NativeRuntimeStatus) -> None:
    """Keep a ready status that is old enough to have a stable stat identity."""

    identity = status.identity
    if not _ENABLED or identity is None or not status.available or not status.compatible:
        return
    binary = _fingerprint(identity.path, follow=True)
    if binary is None:
        return
    manifest_path = _manifest_path(status)
    manifest = None
    if manifest_path is not None:
        manifest = _fingerprint(manifest_path, follow=False)
        if manifest is None:
            return
    with _LOCK:
        if key not in _STATUSES and len(_STATUSES) >= _MAX_ENTRIES:
            _STATUSES.pop(next(iter(_STATUSES)))
        _STATUSES[key] = (status, binary, manifest)


def process_status(key: _RequestKey, candidates: tuple[Path, ...]) -> NativeRuntimeStatus | None:
    """Return the cached status while stat metadata proves the runtime is unchanged."""

    with _LOCK:
        entry = _STATUSES.get(key)
    if entry is None:
        return None
    status, binary, manifest = entry
    identity = status.identity
    resolved = {_resolved_candidate_path(candidate) for candidate in candidates}
    manifest_path = _manifest_path(status)
    if (
        identity is None
        or identity.path not in resolved
        or _fingerprint(identity.path, follow=True) != binary
        or (manifest_path is not None and _fingerprint(manifest_path, follow=False) != manifest)
    ):
        forget_process_status(key)
        return None
    return status


def forget_process_status(key: _RequestKey | None = None) -> None:
    """Drop one entry, or every entry when ``key`` is omitted."""

    with _LOCK:
        if key is None:
            _STATUSES.clear()
        else:
            _STATUSES.pop(key, None)
