"""Live "set up this connector" recommendation for one pending approval request.

A review held only because Guard does not know the connector it launches
records a connector hint at queue time. This module re-checks that hint on
every read against the stored connector (still ``unset``, same identity), the
extension-control authority and the approval gate, so the Inbox never offers a
setup that no longer applies. It is read-only: setting the connector up still
goes through the local-CLI preview, one-use proof and apply flow.
"""

from __future__ import annotations

import logging
import sqlite3
from collections.abc import Callable, Mapping

from ..runtime.connector_setup_items import listed_public_items
from ..runtime.extension_allow_hint import validated_connector_setup_hint
from ..runtime.extension_control_authority import AuthorityHealth
from ..runtime.extension_control_runtime import ExtensionControlRuntimeSnapshot
from .approval_extension_recommendation import CAUTION_RISK_CLASSES

CONNECTOR_RECOMMENDATION_SCHEMA = "guard.approval-connector-recommendation.v1"
# Sibling rows read for the caution check; a group past this is still cautioned
# from what was read, never cleared.
_MAX_GROUP_ROWS = 200

_LOGGER = logging.getLogger(__name__)


def _strings(value: object) -> list[str]:
    return [item for item in value if isinstance(item, str)] if isinstance(value, list) else []


def _stored_connector(store: object, cli_id: str, identity_hash: str) -> Mapping[str, object] | None:
    for item in listed_public_items(store):  # pyright: ignore[reportArgumentType]
        if item.get("cli_id") == cli_id:
            return item if item.get("identity_hash") == identity_hash else None
    return None


def _group_risk_classes(
    store: object,
    identity_hash: str,
    current: list[str],
    read_hint: Callable[[str], object],
) -> set[str]:
    classes = set(current)
    lister = getattr(store, "list_approval_requests", None)
    if not callable(lister):
        return classes
    prefix = f"connector:{identity_hash}:"
    rows = lister(status="pending", limit=_MAX_GROUP_ROWS)
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, Mapping) or not str(row.get("queue_group_id") or "").startswith(prefix):
            continue
        hint = validated_connector_setup_hint(read_hint(str(row.get("request_id", ""))))
        if hint is not None and hint["identity_hash"] == identity_hash:
            classes.update(_strings(hint["risk_classes"]))
    return classes


def build_approval_connector_recommendation(
    approval: Mapping[str, object],
    *,
    store: object,
    snapshot: ExtensionControlRuntimeSnapshot,
    approval_gate_configured: bool,
) -> dict[str, object] | None:
    """Return the setup recommendation for a pending request, or None when it no longer applies."""

    if approval.get("status") != "pending":
        return None
    hint = validated_connector_setup_hint(approval.get("extension_allow_hint"))
    if hint is None:
        return None
    identity_hash, cli_id = str(hint["identity_hash"]), str(hint["cli_id"])
    if not str(approval.get("queue_group_id") or "").startswith(f"connector:{identity_hash}:"):
        return None
    if any(layer.global_lockdown for layer in snapshot.layers):
        return None
    item = _stored_connector(store, cli_id, identity_hash)
    # Only a connector this device still has no decision for is a setup.
    if item is None or item.get("state") != "unset":
        return None
    surface = item.get("surface")
    if surface != hint["surface"]:
        return None
    reader = getattr(store, "get_approval_extension_allow_hint", None)
    risk_classes = _group_risk_classes(
        store,
        identity_hash,
        _strings(hint["risk_classes"]),
        reader if callable(reader) else (lambda _request_id: None),
    )
    caution_classes = sorted(risk_classes & CAUTION_RISK_CLASSES)
    if snapshot.health is not AuthorityHealth.PROTECTED:
        status = "authority_unavailable"
    elif not approval_gate_configured:
        status = "approval_gate_required"
    else:
        status = "available"
    return {
        "schema": CONNECTOR_RECOMMENDATION_SCHEMA,
        "status": status,
        "identity_hash": identity_hash,
        "cli_id": cli_id,
        "surface": surface,
        "display_name": hint["display_name"],
        "deep_link": hint["deep_link"],
        # Recomputed from the stored connector, never trusted from the queue time.
        "card_recommendation": {"state": "allowed", "capabilities": []},
        "approval_gate_configured": approval_gate_configured,
        "caution": bool(caution_classes),
        "caution_risk_classes": caution_classes,
        "revision": snapshot.revision,
    }


def safe_connector_recommendation(
    approval: Mapping[str, object],
    *,
    store: object,
    snapshot: ExtensionControlRuntimeSnapshot,
    approval_gate_configured: Callable[[], bool],
) -> dict[str, object] | None:
    """The recommendation, or None when any input cannot be read; never fails the approval read."""

    if validated_connector_setup_hint(approval.get("extension_allow_hint")) is None:
        return None
    try:
        return build_approval_connector_recommendation(
            approval, store=store, snapshot=snapshot, approval_gate_configured=approval_gate_configured()
        )
    except (AttributeError, KeyError, OSError, RuntimeError, TypeError, ValueError, sqlite3.Error) as error:
        _LOGGER.warning("Connector recommendation unavailable (%s)", type(error).__name__)
        return None


__all__ = [
    "CONNECTOR_RECOMMENDATION_SCHEMA",
    "build_approval_connector_recommendation",
    "safe_connector_recommendation",
]
