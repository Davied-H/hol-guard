"""Capability, health and catalog route handlers for the daemon control plane."""

# pyright: reportAttributeAccessIssue=false, reportUnknownMemberType=false

from __future__ import annotations

import platform
import threading
import time
from collections.abc import Callable
from typing import TYPE_CHECKING
from urllib.parse import parse_qs

from ...version import __version__
from ..cli.install_commands import (
    list_harness_setup_items,
)
from ..native_daemon_handler import (
    NativeDaemonHandlerError,
    native_detection_app_statuses,
)
from .manager import (
    GUARD_DAEMON_COMPATIBILITY_VERSION,
    current_guard_daemon_runtime_fingerprint,
)
from .server_common import (
    _NATIVE_HANDLER_UNAVAILABLE,
    _build_local_url,
)

if TYPE_CHECKING:
    from .server import _GuardDaemonHTTPServer as _GuardDaemonHttpServer


_HEADLESS_OPERATIONS = ("install", "repair", "remove", "status", "scan", "policy_sync")


def _headless_safe_failure_reasons() -> dict[str, str]:
    return {
        "offline": "Local Guard daemon is unavailable.",
        "timeout": "Local Guard daemon did not answer before the browser timeout.",
        "unauthorized": "Dashboard session is missing or stale.",
        "unsupported": "Harness is not supported by this daemon.",
        "confirmation_required": "Remove actions need the harness confirmation phrase.",
    }


_CONTAINMENT_HEALTH_CACHE_SECONDS = 10.0


def cached_containment_health(
    server: _GuardDaemonHttpServer,
    *,
    force_refresh: bool,
    probe: Callable[[], dict[str, object]],
) -> dict[str, object] | None:
    """Return containment health without holding the cache lock across the probe.

    A fresh cache is shared. When the cache is due, one caller runs the probe
    and everyone else keeps the previous payload. Callers only wait together
    when no payload exists yet.
    """

    arrived_generation: int | None = None
    probe_generation = 0
    while True:
        with server.containment_health_cache_lock:
            if arrived_generation is None:
                arrived_generation = server.containment_health_generation
            cached = server.containment_health_cache
            age = time.monotonic() - server.containment_health_cache_monotonic
            if cached is not None and age <= _CONTAINMENT_HEALTH_CACHE_SECONDS and not force_refresh:
                return dict(cached)
            if server.containment_health_refreshing:
                if cached is not None and not force_refresh:
                    return dict(cached)
                event = server.containment_health_refresh_event
                run_probe = False
            else:
                event = threading.Event()
                server.containment_health_refresh_event = event
                server.containment_health_refreshing = True
                server.containment_health_generation += 1
                probe_generation = server.containment_health_generation
                run_probe = True
        if not run_probe:
            event.wait()
            with server.containment_health_cache_lock:
                done = server.containment_health_completed_generation
                if force_refresh and arrived_generation is not None and done <= arrived_generation:
                    continue
                return None if server.containment_health_cache is None else dict(server.containment_health_cache)
        break
    payload: dict[str, object] | None = None
    failed = False
    try:
        payload = probe()
    except (OSError, RuntimeError, TypeError, ValueError):
        payload = None
        failed = True
    except BaseException:
        failed = True
        raise
    finally:
        with server.containment_health_cache_lock:
            if failed or payload is not None:
                server.containment_health_cache = None if payload is None else dict(payload)
                server.containment_health_cache_monotonic = time.monotonic()
            server.containment_health_refreshing = False
            server.containment_health_completed_generation = probe_generation
            event.set()
    return None if payload is None else dict(payload)


class _ControlHealthRoutes:
    """Handler methods for control-plane routes."""

    def _local_queue_url(self) -> str:
        host = self._daemon_server().daemon_host()
        port = self._daemon_server().daemon_port()
        return _build_local_url(host, port, "/#/inbox")

    def _handle_capabilities(self) -> None:
        context = self._harness_context({})
        items = list_harness_setup_items(context, self.server.store)  # type: ignore[attr-defined]
        supported = []
        failure_reasons = _headless_safe_failure_reasons()
        listed = [item for item in items if isinstance(item.get("harness"), str)]
        try:
            app_statuses = native_detection_app_statuses(
                [item.get("status") for item in listed],
                guard_home=self.server.store.guard_home,  # type: ignore[attr-defined]
            )
        except NativeDaemonHandlerError:
            self._write_json(_NATIVE_HANDLER_UNAVAILABLE[1], status=_NATIVE_HANDLER_UNAVAILABLE[0])
            return
        for item, app_status in zip(listed, app_statuses, strict=True):
            harness = item["harness"]
            supported.append(
                {
                    "display_name": item.get("display_name"),
                    "harness": harness,
                    "status": app_status,
                    "command_available": bool(item.get("command_available")),
                    "headless_actions": list(_HEADLESS_OPERATIONS[:-1]),
                    "safe_failure_reasons": failure_reasons,
                }
            )
        self._write_json(
            {
                "auth_state": "dashboard_session" if self._dashboard_session_token_is_valid() else "local_token",
                "command_available": any(bool(item.get("command_available")) for item in items),
                "daemon": {
                    "compatibility_version": GUARD_DAEMON_COMPATIBILITY_VERSION,
                    "package_version": __version__,
                    "platform": platform.system().lower() or "unknown",
                },
                "headless_api": {
                    "execution_mode": "guard_cloud_command_queue",
                    "operations": list(_HEADLESS_OPERATIONS),
                },
                "package_firewall_api": {
                    "execution_mode": "guard_cloud_command_queue",
                    "operations": ["status", "connect", "install", "repair", "test", "audit", "sync", "remove"],
                },
                "safe_failure_reasons": _headless_safe_failure_reasons(),
                "supported_harnesses": sorted(item["harness"] for item in supported),
                "items": supported,
            }
        )

    @staticmethod
    def _optional_bool(value: object, *, default: bool) -> bool:
        if value is None:
            return default
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            normalized = value.strip().lower()
            if normalized in {"true", "1", "yes", "on"}:
                return True
            if normalized in {"false", "0", "no", "off", ""}:
                return False
        raise ValueError("invalid boolean value")

    @staticmethod
    def _optional_int(value: object) -> int | None:
        if isinstance(value, int):
            return value
        if isinstance(value, str) and value.strip():
            try:
                return int(value.strip())
            except ValueError:
                return None
        return None

    def _containment_health_payload(self, *, force_refresh: bool = False) -> dict[str, object] | None:
        from ..runtime.containment_health import probe_containment_health

        def probe() -> dict[str, object]:
            return probe_containment_health(
                daemon_fingerprint=current_guard_daemon_runtime_fingerprint(),
            ).to_dict()

        return cached_containment_health(self._daemon_server(), force_refresh=force_refresh, probe=probe)

    def _operator_health_payload(self) -> dict[str, object]:
        daemon_server = self._daemon_server()
        scheduler = daemon_server.runtime_hook_scheduler.stats()
        evidence_writer = daemon_server.runtime_hook_evidence_writer.stats()
        activity_health = daemon_server.store.get_command_activity_persistence_health()
        evidence_fault = not evidence_writer["running"]
        store_busy = (
            activity_health.persistence_error_count > 0
            and activity_health.last_error_code is not None
            and activity_health.last_error_code.startswith("sqlite.")
        )
        saturated = scheduler["queued_limit"] > 0 and scheduler["queued"] >= scheduler["queued_limit"]

        if evidence_fault:
            state = "saturated"
            cause = "A local processing component stopped and needs repair."
        elif store_busy:
            state = "store-contended"
            cause = "The local evidence store is busy; queued writes are retrying automatically."
        elif saturated:
            state = "saturated"
            cause = "Local review capacity is full; new work waits or receives a typed retry."
        elif scheduler["queued"] > 0:
            state = "backlogged"
            cause = "A short local backlog is waiting behind active reviews."
        else:
            state = "healthy"
            cause = "Local reviews are processing within available capacity."

        repairable = evidence_fault
        return {
            "state": state,
            "cause": cause,
            "automatic_recovery": (
                "Repair restores the stopped local component."
                if repairable
                else "Guard drains queued work and adjusts ready workers automatically."
            ),
            "repairable": repairable,
            "queue_depth": scheduler["queued"],
            "queue_limit": scheduler["queued_limit"],
            "oldest_wait_ms": scheduler["oldest_queued_ms"],
            "workers_busy": scheduler["active"],
            "workers_ready": max(0, scheduler["active_limit"] - scheduler["active"]),
            "workers_configured": scheduler["active_limit"],
        }

    def _coalesce_string(self, mapping: dict[str, object], *keys: str) -> str | None:
        for key in keys:
            value = self._optional_string(mapping.get(key))
            if value is not None:
                return value
        return None

    @staticmethod
    def _query_string(query_string: str, key: str) -> str | None:
        value = parse_qs(query_string).get(key, [None])[-1]
        if isinstance(value, str) and value.strip():
            return value.strip()
        return None

    @staticmethod
    def _query_bool(query_string: str, key: str, *, default: bool) -> bool:
        value = parse_qs(query_string).get(key, [None])[-1]
        if not isinstance(value, str):
            return default
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "on"}:
            return True
        if normalized in {"0", "false", "no", "off"}:
            return False
        return default

    def write_catalog_v2_body(self, body: bytes, *, status: int, headers: dict[str, str]) -> None:
        self._write_json_bytes(body, status=status, extra_headers=headers)

    def write_catalog_v2_empty(self, *, status: int, headers: dict[str, str]) -> None:
        cors_headers = self._cors_headers_for_request(allow_methods="GET, POST, OPTIONS") or {}
        self._write_empty(status=status, extra_headers={**cors_headers, **headers})

    def write_catalog_v2_error(self, error_code: str, *, status: int) -> None:
        self._write_json({"error": error_code}, status=status, extra_headers={"Cache-Control": "no-store"})
