"""``hol-guard extensions list`` and ``hol-guard mcp list``: read the local inventory.

Both commands read the same local inventory table that fleet posture reports from, so what
they print is what Guard can send to Guard Cloud. Nothing is written and nothing is sent.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from ..runtime.fleet_posture_common import HARNESS_IDS
from ..runtime.fleet_posture_inventory import inventory_item_kind

if TYPE_CHECKING:
    from ..store import GuardStore

# Guard command name -> (parser attribute naming the subcommand, inventory kind, kinds listed).
_LIST_COMMANDS: dict[str, tuple[str, str, frozenset[str]]] = {
    "extensions": ("extension_builder_command", "extensions", frozenset({"plugin"})),
    "mcp": ("mcp_command", "mcp", frozenset({"mcp_server"})),
}


def configure_inventory_list_parser(parser: argparse.ArgumentParser) -> None:
    """Arguments shared by ``extensions list`` and ``mcp list``."""

    from .commands_parser_helpers import _add_guard_common_args

    _add_guard_common_args(parser)
    parser.add_argument("--json", action="store_true")


def is_inventory_list_command(args: argparse.Namespace) -> bool:
    spec = _LIST_COMMANDS.get(str(getattr(args, "guard_command", "")))
    return spec is not None and getattr(args, spec[0], None) == "list"


def _text(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _is_installed(row: dict[str, object]) -> bool:
    return not row.get("removed_at") and row.get("present") not in (0, False, "0")


def inventory_list_payload(
    store: GuardStore,
    *,
    command: str,
    generated_at: str,
) -> dict[str, object]:
    """Installed inventory items for ``command`` (``extensions`` or ``mcp``), sorted by harness and name."""

    _, kind, reported_kinds = _LIST_COMMANDS[command]
    items: list[dict[str, object]] = []
    for row in store.list_inventory():
        if not _is_installed(row) or inventory_item_kind(row.get("artifact_type")) not in reported_kinds:
            continue
        if str(row.get("harness") or "") not in HARNESS_IDS or not str(row.get("artifact_name") or "").strip():
            continue
        items.append(
            {
                "name": str(row.get("artifact_name") or row.get("artifact_id") or ""),
                "harness": str(row.get("harness") or ""),
                "artifact_type": str(row.get("artifact_type") or ""),
                "source_scope": _text(row.get("source_scope")),
                "config_path": _text(row.get("config_path")),
                "artifact_hash": _text(row.get("artifact_hash")),
                "policy_action": _text(row.get("last_policy_action")),
                "first_seen_at": _text(row.get("first_seen_at")),
                "last_seen_at": _text(row.get("last_seen_at")),
            }
        )
    items.sort(key=lambda item: (str(item["harness"]), str(item["name"]), str(item["config_path"] or "")))
    return {"generated_at": generated_at, "kind": kind, "count": len(items), "items": items}


def run_inventory_list_command(args: argparse.Namespace, *, store: GuardStore) -> int:
    from .render import emit_guard_payload

    command = str(args.guard_command)
    payload = inventory_list_payload(
        store,
        command=command,
        generated_at=datetime.now(timezone.utc).isoformat(),
    )
    emit_guard_payload(f"{command}.list", payload, bool(getattr(args, "json", False)))
    return 0


__all__ = [
    "configure_inventory_list_parser",
    "inventory_list_payload",
    "is_inventory_list_command",
    "run_inventory_list_command",
]
