"""Build the ``fleet-posture/v1`` object that rides in ``syncContext.fleetPosture``.

The contract lives in ``contracts/fleet-posture/v1`` and is documented in
``docs/guard/fleet-posture.md``. This module collects the machine, AI-tool,
inventory and policy sections, derives each tool's protection state, and decides
whether the inventory goes out as ``full``, ``delta`` or ``digest_only``.

Building never writes to the store. ``build_fleet_posture_state`` returns the
payload together with the next "last sent" snapshot, and the caller commits that
snapshot with ``commit_fleet_posture_sent`` only after Guard Cloud accepted the
request.
"""

from __future__ import annotations

import hashlib
import json
import logging
import platform
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any

from ...version import __version__
from ..harness_tool_version import tool_version_from_artifacts

AUTO_UPDATE_STATE_KEY = "guard_auto_update_state"

if TYPE_CHECKING:
    from ..adapters.base import HarnessContext
    from ..config import GuardConfig
    from ..store import GuardStore

_LOGGER = logging.getLogger(__name__)

SCHEMA_VERSION = "fleet-posture/v1"
CAPABILITY = "fleet-posture/v1"
MAX_PAYLOAD_BYTES = 65536
MAX_ITEMS_PER_SYNC = 250
MAX_TOOLS = 32
MAX_BLIND_SPOTS = 8
MAX_BLIND_SPOT_LENGTH = 80
STALE_AFTER = timedelta(days=7)
FULL_REFRESH_AFTER = timedelta(days=7)
MAX_TRACKED_ITEMS = 5000

LAST_SENT_STATE_KEY = "fleet_posture_last"
SETTINGS_STATE_KEY = "fleet_posture_settings"
FORCE_FULL_STATE_KEY = "fleet_posture_force_full"
FOLLOWUP_STATE_KEY = "fleet_posture_bundle_followup"

HARNESS_IDS = frozenset(
    {
        "antigravity",
        "claude-code",
        "cline",
        "codex",
        "copilot",
        "cursor",
        "devin",
        "gemini",
        "grok",
        "hermes",
        "kimi",
        "omp",
        "openclaw",
        "opencode",
        "paseo",
        "pi",
        "zcode",
    }
)
_SETUP_STATUSES = frozenset({"active", "broken", "partial", "not_found"})
_ITEM_KINDS = {
    "skill": "skill",
    "skill_file": "skill",
    "mcp_server": "mcp_server",
    "plugin": "plugin",
    "plugin-file": "plugin",
    "extension": "plugin",
    "package": "package",
    "hook": "hook",
    "guard_hook": "hook",
}
_ITEM_SOURCES = {
    "marketplace": "marketplace",
    "project": "project",
    "workspace": "project",
    "global": "user",
    "user": "user",
    "lockfile": "lockfile",
    "config": "config",
}
_SHA256_HEX = re.compile(r"^[a-f0-9]{64}$")
_VERSION_PATTERN = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+[0-9A-Za-z.+-]*$")
_PRERELEASE_PATTERN = re.compile(r"[0-9](a|b|rc|dev|alpha|beta)[0-9]*", re.IGNORECASE)


@dataclass(frozen=True)
class FleetPostureSettings:
    """Inputs the builder needs besides the store and the adapter list."""

    context: HarnessContext
    guard_config: GuardConfig | None = None
    now: datetime | None = None
    runtime: str = "python"
    # ``None`` reads the persisted opt-out from the store.
    reporting_enabled: bool | None = None
    force_full: bool | None = None
    extra: Mapping[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class FleetPostureBuild:
    """A built payload plus the snapshot to record once Guard Cloud accepts it."""

    payload: dict[str, object]
    next_state: dict[str, object]
    mode: str
    payload_bytes: int
    advanced_inventory: bool


# --------------------------------------------------------------------------- settings


def fleet_posture_managed(config: GuardConfig | None) -> bool:
    """MDM-managed installs always report; the opt-out is ignored for them."""

    return config is not None and getattr(config, "install_owner", "user") == "mdm"


def fleet_posture_opted_out(store: GuardStore) -> bool:
    """Whether the user ran ``hol-guard settings set fleet-posture off``."""

    raw = store.get_sync_payload(SETTINGS_STATE_KEY)
    return isinstance(raw, dict) and raw.get("enabled") is False


def set_fleet_posture_reporting(store: GuardStore, *, enabled: bool, now: str) -> dict[str, object]:
    """Persist the opt-out choice and return the new settings record."""

    record: dict[str, object] = {"enabled": enabled, "updatedAt": now}
    store.set_sync_payload(SETTINGS_STATE_KEY, record, now)
    return record


def fleet_posture_reporting_enabled(store: GuardStore, config: GuardConfig | None) -> bool:
    """Effective detail level: managed installs ignore the opt-out."""

    return fleet_posture_managed(config) or not fleet_posture_opted_out(store)


def request_full_inventory(store: GuardStore, *, source: str, now: str) -> None:
    """Make the next posture go out with ``inventory.mode = "full"``."""

    store.set_sync_payload(FORCE_FULL_STATE_KEY, {"requestedAt": now, "source": source}, now)


def full_inventory_requested(store: GuardStore) -> bool:
    raw = store.get_sync_payload(FORCE_FULL_STATE_KEY)
    return isinstance(raw, dict) and bool(raw)


def _clear_full_inventory_request(store: GuardStore, now: str) -> None:
    if full_inventory_requested(store):
        store.set_sync_payload(FORCE_FULL_STATE_KEY, {}, now)


# --------------------------------------------------------------------------- helpers


def _utc(value: datetime | None) -> datetime:
    resolved = value or datetime.now(timezone.utc)
    if resolved.tzinfo is None:
        resolved = resolved.replace(tzinfo=timezone.utc)
    return resolved.astimezone(timezone.utc)


def _iso(value: datetime) -> str:
    return _utc(value).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_timestamp(value: object) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return _utc(parsed)


def _normalized_timestamp(value: object) -> str | None:
    parsed = _parse_timestamp(value)
    return _iso(parsed) if parsed is not None else None


def _sha256_text(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def _digest_rows(rows: Iterable[Iterable[object]]) -> str:
    """Digest of rows sorted lexicographically, serialized as compact JSON."""

    ordered = sorted(
        ([("" if cell is None else str(cell)) for cell in row] for row in rows),
    )
    return _sha256_text(json.dumps(ordered, separators=(",", ":"), ensure_ascii=False))


def _normalized_hash(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip().lower()
    if text.startswith("sha256:"):
        text = text[len("sha256:") :]
    return f"sha256:{text}" if _SHA256_HEX.match(text) else None


def _clip(value: str, limit: int) -> str:
    return value if len(value) <= limit else value[:limit]


def _json_size(payload: object) -> int:
    return len(json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))


# --------------------------------------------------------------------------- machine and client


def _os_name() -> str:
    return {"darwin": "macos", "linux": "linux", "windows": "windows"}.get(platform.system().lower(), "unknown")


def _os_version(os_name: str) -> str | None:
    version: str | None = None
    if os_name == "macos":
        version = platform.mac_ver()[0] or None
    elif os_name == "linux":
        try:
            with open("/etc/os-release", encoding="utf-8") as handle:
                for line in handle:
                    if line.startswith("VERSION_ID="):
                        version = line.split("=", 1)[1].strip().strip("\"'") or None
                        break
        except OSError:
            version = None
    elif os_name == "windows":
        version = platform.version() or None
    return _clip(version, 32) if version else None


def _arch() -> str:
    machine = platform.machine().lower()
    if machine in {"arm64", "aarch64"}:
        return "arm64"
    if machine in {"x86_64", "amd64", "x64"}:
        return "x86_64"
    return "unknown"


def _machine_section(*, include_os_version: bool) -> dict[str, object]:
    os_name = _os_name()
    hostname = platform.node().strip().lower()
    return {
        "osName": os_name,
        "osVersion": _os_version(os_name) if include_os_version else None,
        "arch": _arch(),
        "hostnameHash": _sha256_text(hostname) if hostname else None,
    }


def _auto_update_state(store: GuardStore) -> tuple[dict[str, object], str | None]:
    raw = store.get_sync_payload(AUTO_UPDATE_STATE_KEY)
    state: dict[str, Any] = raw if isinstance(raw, dict) else {}
    last_status = state.get("last_status")
    status: dict[str, Any] = last_status if isinstance(last_status, dict) else {}
    channel = status.get("release_channel")
    last_checked = _normalized_timestamp(state.get("last_check_at"))
    result: str | None = None
    if status:
        last_update_at = _parse_timestamp(state.get("last_update_at"))
        checked_at = _parse_timestamp(state.get("last_check_at"))
        if (
            state.get("last_update_exit_code") == 0
            and last_update_at is not None
            and checked_at is not None
            and last_update_at >= checked_at
        ):
            result = "updated"
        elif status.get("update_available") is True:
            result = "update_available"
        else:
            result = "up_to_date"
    elif state.get("last_check_error") is True or state.get("last_update_error") is True:
        result = "failed"
    section: dict[str, object] = {
        "enabled": bool(status.get("auto_updatable")) if status else False,
        "lastCheckedAt": last_checked,
        "lastResult": result,
    }
    return section, channel if channel in {"stable", "alpha"} else None


def _client_section(store: GuardStore, runtime: str) -> dict[str, object]:
    auto_update, stored_channel = _auto_update_state(store)
    channel = stored_channel or ("alpha" if _PRERELEASE_PATTERN.search(__version__) else "stable")
    version = __version__ if _VERSION_PATTERN.match(__version__) else "0.0.0"
    return {
        "version": _clip(version, 32),
        "channel": channel,
        "runtime": runtime if runtime in {"python", "native"} else "python",
        "autoUpdate": auto_update,
    }


# --------------------------------------------------------------------------- AI tools


def _posture_override(config: GuardConfig | None, harness: str) -> str | None:
    """Map Guard's per-app posture to the contract's override vocabulary.

    Guard's "watch" posture records but never blocks, which is protection off, so
    it is reported as ``off``. ``observe`` is reserved and never emitted.
    """

    if config is None:
        return None
    from ..harness_posture import harness_posture_override

    override = harness_posture_override(config, harness)
    if override is None:
        return "default"
    return "off" if override == "watch" else "enforce"


def _effectively_paused(config: GuardConfig | None, harness: str) -> bool:
    if config is None:
        return False
    from ..harness_posture import effective_harness_posture

    try:
        return effective_harness_posture(config, harness) == "watch"
    except Exception:  # pragma: no cover - defensive, config shape is owned elsewhere
        return False


def derive_protection_state(
    *,
    setup_status: str,
    has_config_paths: bool,
    paused: bool,
    last_activity_at: datetime | None,
    now: datetime,
) -> str:
    """Per-tool protection state (see docs/guard/fleet-posture.md)."""

    if setup_status == "not_found":
        return "needs_setup" if has_config_paths else "not_detected"
    if setup_status in {"partial", "broken"}:
        return "broken"
    if paused:
        return "paused"
    if last_activity_at is None or now - last_activity_at > STALE_AFTER:
        return "stale"
    return "protected"


def _latest_activity(store: GuardStore, harness: str) -> datetime | None:
    try:
        rows = store.list_receipts(limit=1, harness=harness)
    except Exception:
        _LOGGER.debug("fleet posture: receipt lookup failed for %s", harness, exc_info=True)
        return None
    if not rows:
        return None
    return _parse_timestamp(rows[0].get("timestamp"))


def _coverage(adapter: Any) -> dict[str, object]:
    try:
        coverage = adapter.setup_contract().coverage
    except Exception:
        return {}
    return {
        "nativeHooks": bool(getattr(coverage, "native_hooks", False)),
        "browserFallback": bool(getattr(coverage, "browser_fallback", False)),
        "mcpProxy": bool(getattr(coverage, "mcp_proxy", False)),
        "promptHooks": bool(getattr(coverage, "prompt_hooks", False)),
        "blindSpots": [str(item) for item in getattr(coverage, "blind_spots", ()) if str(item).strip()],
    }


def _tool_row(
    *,
    adapter: Any,
    diagnostics: Mapping[str, object],
    store: GuardStore,
    config: GuardConfig | None,
    now: datetime,
    include_blind_spots: bool,
    inventory: Mapping[str, list[dict[str, object]]],
) -> dict[str, object]:
    harness = str(adapter.harness)
    setup_status = str(diagnostics.get("setup_status"))
    config_paths = diagnostics.get("config_paths")
    artifacts = diagnostics.get("artifacts")
    coverage = _coverage(adapter)
    last_activity = _latest_activity(store, harness)
    items = inventory.get(harness, [])
    blind_spots: list[str] = []
    if include_blind_spots:
        raw_spots = coverage.get("blindSpots")
        spot_list = list(raw_spots) if isinstance(raw_spots, (list, tuple)) else []
        blind_spots = [_clip(str(spot), MAX_BLIND_SPOT_LENGTH) for spot in spot_list[:MAX_BLIND_SPOTS]]
    version = tool_version_from_artifacts(artifacts if isinstance(artifacts, list) else ())
    return {
        "harness": harness,
        "toolVersion": version,
        "setupStatus": setup_status,
        "protectionState": derive_protection_state(
            setup_status=setup_status,
            has_config_paths=bool(config_paths),
            paused=_effectively_paused(config, harness),
            last_activity_at=last_activity,
            now=now,
        ),
        "hooks": {
            "nativeHooks": bool(coverage.get("nativeHooks", False)),
            "browserFallback": bool(coverage.get("browserFallback", False)),
            "mcpProxy": bool(coverage.get("mcpProxy", False)),
            "promptHooks": bool(coverage.get("promptHooks", False)),
        },
        "blindSpots": blind_spots,
        "postureOverride": _posture_override(config, harness),
        "artifactCount": min(len(items), 100000),
        "lastActivityAt": _iso(last_activity) if last_activity is not None else None,
        "inventoryDigest": _item_digest(items),
    }


# --------------------------------------------------------------------------- inventory


def _inventory_items(store: GuardStore) -> list[dict[str, object]]:
    """Installed items from the local inventory table, in contract shape."""

    try:
        rows = store.list_inventory()
    except Exception:
        _LOGGER.debug("fleet posture: inventory read failed", exc_info=True)
        return []
    items: dict[str, dict[str, object]] = {}
    for row in rows:
        if row.get("removed_at"):
            continue
        if row.get("present") in (0, False, "0"):
            continue
        kind = _ITEM_KINDS.get(str(row.get("artifact_type") or ""))
        harness = str(row.get("harness") or "")
        name = str(row.get("artifact_name") or "").strip()
        if kind is None or harness not in HARNESS_IDS or not name:
            continue
        first_seen = _normalized_timestamp(row.get("first_seen_at"))
        last_seen = _normalized_timestamp(row.get("last_seen_at"))
        if first_seen is None or last_seen is None:
            continue
        config_path = row.get("config_path")
        item: dict[str, object] = {
            "kind": kind,
            "name": _clip(name, 200),
            "version": None,
            "hash": _normalized_hash(row.get("artifact_hash")),
            "harness": harness,
            "source": _ITEM_SOURCES.get(str(row.get("source_scope") or ""), "unknown"),
            "pathHash": _sha256_text(str(config_path)) if isinstance(config_path, str) and config_path else None,
            "firstSeenAt": first_seen,
            "lastSeenAt": last_seen,
        }
        items.setdefault(_item_key(item), item)
    ordered = [items[key] for key in sorted(items)]
    return ordered[:MAX_TRACKED_ITEMS]


def _item_key(item: Mapping[str, object]) -> str:
    identity = "\0".join(str(item.get(part) or "") for part in ("kind", "harness", "name", "pathHash"))
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()[:32]


def _item_fingerprint(item: Mapping[str, object]) -> str:
    material = "\0".join(str(item.get(part) or "") for part in ("version", "hash", "source"))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


def _item_digest(items: Iterable[Mapping[str, object]]) -> str:
    return _digest_rows(
        (item.get("kind"), item.get("name"), item.get("version"), item.get("hash"), item.get("harness"))
        for item in items
    )


def _group_by_harness(items: Iterable[dict[str, object]]) -> dict[str, list[dict[str, object]]]:
    grouped: dict[str, list[dict[str, object]]] = {}
    for item in items:
        grouped.setdefault(str(item["harness"]), []).append(item)
    return grouped


def _previous_items(last: Mapping[str, object] | None) -> dict[str, dict[str, Any]] | None:
    if not isinstance(last, Mapping):
        return None
    raw = last.get("items")
    if not isinstance(raw, dict):
        return None
    return {str(key): dict(value) for key, value in raw.items() if isinstance(value, dict)}


def _tracked(item: Mapping[str, object]) -> dict[str, object]:
    return {
        "k": item["kind"],
        "n": item["name"],
        "h": item["harness"],
        "x": item["hash"],
        "f": _item_fingerprint(item),
    }


def _removed_entry(tracked: Mapping[str, object]) -> dict[str, object]:
    return {"kind": tracked["k"], "name": tracked["n"], "harness": tracked["h"], "hash": tracked["x"]}


def _needs_full(
    *,
    previous: Mapping[str, object] | None,
    last: Mapping[str, object] | None,
    force_full: bool,
    now: datetime,
) -> bool:
    """A full inventory is due on first send, on request, or after a week."""

    full_sent_at = _parse_timestamp(last.get("fullSentAt")) if isinstance(last, Mapping) else None
    return force_full or previous is None or full_sent_at is None or now - full_sent_at > FULL_REFRESH_AFTER


def _plan_inventory(
    *,
    current: list[dict[str, object]],
    previous: dict[str, dict[str, Any]] | None,
    last: Mapping[str, object] | None,
    force_full: bool,
    detail: bool,
    now: datetime,
    limit: int = MAX_ITEMS_PER_SYNC,
) -> tuple[str, list[dict[str, object]], list[dict[str, object]], dict[str, dict[str, Any]]]:
    """Choose mode, items, removed and the next tracked-item snapshot."""

    by_key = {_item_key(item): item for item in current}
    if not detail:
        return "digest_only", [], [], dict(previous or {})
    need_full = _needs_full(previous=previous, last=last, force_full=force_full, now=now)
    if need_full:
        stale_keys = sorted(key for key in (previous or {}) if key not in by_key)
        if len(current) <= limit:
            return "full", list(current), [], {key: _tracked(item) for key, item in by_key.items()}
        # Too many for one request: stream the inventory as successive deltas.
        sent = sorted(by_key)[:limit]
        prior = previous or {}
        removed = [_removed_entry(prior[key]) for key in stale_keys[:limit]]
        return "delta", [by_key[key] for key in sent], removed, {key: _tracked(by_key[key]) for key in sent}
    assert previous is not None
    changed = sorted(
        key for key, item in by_key.items() if key not in previous or previous[key].get("f") != _item_fingerprint(item)
    )
    gone = sorted(key for key in previous if key not in by_key)
    sent_changed = changed[:limit]
    sent_gone = gone[:limit]
    next_items: dict[str, dict[str, Any]] = {key: dict(value) for key, value in previous.items()}
    for key in sent_gone:
        next_items.pop(key, None)
    for key in sent_changed:
        next_items[key] = _tracked(by_key[key])
    return (
        "delta",
        [by_key[key] for key in sent_changed],
        [_removed_entry(previous[key]) for key in sent_gone],
        next_items,
    )


# --------------------------------------------------------------------------- policy


def _int_or_none(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int) and value >= 1:
        return value
    return None


def policy_section(store: GuardStore, acknowledgement: Mapping[str, object] | None) -> dict[str, object]:
    """Mirror the acknowledgement Guard is sending in the same request."""

    section: dict[str, object] = {
        "appliedBundleVersion": None,
        "appliedBundleHash": None,
        "appliedPolicyVersionNumber": None,
        "status": "none",
        "errorCode": None,
        "appliedAt": None,
    }
    if isinstance(acknowledgement, Mapping) and acknowledgement:
        bundle_hash = acknowledgement.get("bundleHash")
        status = str(acknowledgement.get("status") or "")
        mapped = {"applied": "applied", "synced": "applied", "validated": "validated", "failed": "rejected"}.get(
            status, "none"
        )
        error_code = acknowledgement.get("errorCode") or acknowledgement.get("reason")
        section.update(
            {
                "appliedBundleVersion": _int_or_none(acknowledgement.get("bundleVersion")),
                "appliedBundleHash": _clip(bundle_hash, 80) if isinstance(bundle_hash, str) else None,
                "appliedPolicyVersionNumber": _int_or_none(acknowledgement.get("policyRevision")),
                "status": mapped,
                "errorCode": _clip(error_code, 80) if mapped == "rejected" and isinstance(error_code, str) else None,
                "appliedAt": _normalized_timestamp(
                    acknowledgement.get("appliedAt") or acknowledgement.get("observedAt")
                ),
            }
        )
        return section
    last_error = store.get_sync_payload("policy_bundle_last_error")
    if isinstance(last_error, dict) and isinstance(last_error.get("reason"), str):
        section["status"] = "rejected"
        section["errorCode"] = _clip(str(last_error["reason"]), 80)
    return section


# --------------------------------------------------------------------------- build


def build_fleet_posture_state(
    store: GuardStore,
    adapters: Iterable[Any],
    settings: FleetPostureSettings,
    *,
    acknowledgement: Mapping[str, object] | None = None,
) -> FleetPostureBuild:
    """Collect the posture and plan the inventory transmission."""

    now = _utc(settings.now)
    config = settings.guard_config
    detail = (
        settings.reporting_enabled
        if settings.reporting_enabled is not None
        else fleet_posture_reporting_enabled(store, config)
    )
    if settings.reporting_enabled is not None:
        detail = bool(settings.reporting_enabled) or fleet_posture_managed(config)
    force_full = settings.force_full if settings.force_full is not None else full_inventory_requested(store)
    last_raw = store.get_sync_payload(LAST_SENT_STATE_KEY)
    last = last_raw if isinstance(last_raw, dict) else None
    previous_tool_states: dict[str, Any] = {}
    last_tools = last.get("tools") if last is not None else None
    if isinstance(last_tools, dict):
        previous_tool_states = last_tools

    current_items = _inventory_items(store)
    grouped = _group_by_harness(current_items)
    tools: list[dict[str, object]] = []
    for adapter in adapters:
        harness = getattr(adapter, "harness", "")
        if harness not in HARNESS_IDS:
            continue
        try:
            diagnostics = adapter.diagnostics(settings.context)
        except Exception:
            _LOGGER.debug("fleet posture: diagnostics failed for %s", harness, exc_info=True)
            continue
        if not isinstance(diagnostics, Mapping) or diagnostics.get("setup_status") not in _SETUP_STATUSES:
            continue
        row = _tool_row(
            adapter=adapter,
            diagnostics=diagnostics,
            store=store,
            config=config,
            now=now,
            include_blind_spots=detail,
            inventory=grouped,
        )
        absent = row["protectionState"] == "not_detected"
        if absent and previous_tool_states.get(harness) in (None, "not_detected"):
            continue
        tools.append(row)
    tools = tools[:MAX_TOOLS]

    previous = _previous_items(last)

    def plan_and_assemble(
        limit: int,
    ) -> tuple[str, list[dict[str, object]], list[dict[str, object]], dict[str, dict[str, Any]], dict[str, Any]]:
        planned_mode, planned_items, planned_removed, planned_next = _plan_inventory(
            current=current_items,
            previous=previous,
            last=last,
            force_full=force_full,
            detail=detail,
            now=now,
            limit=limit,
        )
        assembled = _assemble(
            store,
            settings,
            now,
            detail,
            tools,
            current_items,
            planned_mode,
            planned_items,
            planned_removed,
            acknowledgement,
        )
        return planned_mode, planned_items, planned_removed, planned_next, assembled

    mode, items, removed, next_items, payload = plan_and_assemble(MAX_ITEMS_PER_SYNC)
    payload_bytes = _json_size(payload)
    if payload_bytes > MAX_PAYLOAD_BYTES and mode != "digest_only":
        # Send as many items as fit, in successive deltas; digest_only only when
        # not even one item fits next to the machine and tool sections.
        low, high, best = 1, MAX_ITEMS_PER_SYNC - 1, None
        while low <= high:
            middle = (low + high) // 2
            candidate = plan_and_assemble(middle)
            if _json_size(candidate[4]) <= MAX_PAYLOAD_BYTES:
                best, low = candidate, middle + 1
            else:
                high = middle - 1
        if best is not None:
            mode, items, removed, next_items, payload = best
        else:
            mode, items, removed, next_items = "digest_only", [], [], dict(previous or {})
            payload = _assemble(
                store, settings, now, detail, tools, current_items, mode, items, removed, acknowledgement
            )
        payload_bytes = _json_size(payload)
    if payload_bytes > MAX_PAYLOAD_BYTES:
        for tool in payload["aiTools"]:
            tool["blindSpots"] = []
        payload_bytes = _json_size(payload)

    advanced = mode != "digest_only"
    full_sent_at = last.get("fullSentAt") if isinstance(last, dict) else None
    if detail and mode != "digest_only" and _needs_full(previous=previous, last=last, force_full=force_full, now=now):
        full_sent_at = _iso(now)
    summary = json.loads(json.dumps(payload))
    summary["inventory"]["items"] = []
    summary["inventory"]["removed"] = []
    next_state: dict[str, object] = {
        "sentAt": _iso(now),
        "collectedAt": payload["collectedAt"],
        "mode": mode,
        "inventoryDigest": payload["inventory"]["digest"],
        "inventoryItemsTracked": len(current_items),
        "fullSentAt": full_sent_at,
        "payloadBytes": payload_bytes,
        "items": next_items,
        "tools": {str(tool["harness"]): tool["protectionState"] for tool in tools},
        "summary": summary,
    }
    return FleetPostureBuild(
        payload=payload,
        next_state=next_state,
        mode=mode,
        payload_bytes=payload_bytes,
        advanced_inventory=advanced,
    )


def _assemble(
    store: GuardStore,
    settings: FleetPostureSettings,
    now: datetime,
    detail: bool,
    tools: list[dict[str, object]],
    current_items: list[dict[str, object]],
    mode: str,
    items: list[dict[str, object]],
    removed: list[dict[str, object]],
    acknowledgement: Mapping[str, object] | None,
) -> dict[str, Any]:
    return {
        "schemaVersion": SCHEMA_VERSION,
        "collectedAt": _iso(now),
        "client": _client_section(store, settings.runtime),
        "machine": _machine_section(include_os_version=detail),
        "aiTools": [dict(tool) for tool in tools],
        "inventory": {
            "digest": _item_digest(current_items),
            "mode": mode,
            "items": items,
            "removed": removed,
        },
        "policy": policy_section(store, acknowledgement),
    }


def build_fleet_posture(
    store: GuardStore,
    adapters: Iterable[Any],
    settings: FleetPostureSettings,
    *,
    acknowledgement: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Return the ``fleet-posture/v1`` object for ``syncContext.fleetPosture``."""

    return build_fleet_posture_state(store, adapters, settings, acknowledgement=acknowledgement).payload


def commit_fleet_posture_sent(store: GuardStore, built: FleetPostureBuild, *, now: str) -> None:
    """Record what Guard Cloud accepted so the next build can send a delta."""

    store.set_sync_payload(LAST_SENT_STATE_KEY, built.next_state, now)
    if built.advanced_inventory:
        _clear_full_inventory_request(store, now)


def last_sent_fleet_posture(store: GuardStore) -> dict[str, object] | None:
    raw = store.get_sync_payload(LAST_SENT_STATE_KEY)
    return raw if isinstance(raw, dict) and raw else None


__all__ = [
    "CAPABILITY",
    "MAX_PAYLOAD_BYTES",
    "SCHEMA_VERSION",
    "FleetPostureBuild",
    "FleetPostureSettings",
    "build_fleet_posture",
    "build_fleet_posture_state",
    "commit_fleet_posture_sent",
    "derive_protection_state",
    "fleet_posture_managed",
    "fleet_posture_opted_out",
    "fleet_posture_reporting_enabled",
    "full_inventory_requested",
    "last_sent_fleet_posture",
    "policy_section",
    "request_full_inventory",
    "set_fleet_posture_reporting",
]
