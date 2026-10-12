#!/usr/bin/env python3
"""Record schema-prefix vectors from the original Python store.

Run from a checkout whose `GuardStore._initialize_schema` still creates the
schema prefix in Python (core tables, receipt binding, resume columns and the
five command-activity families), with `PYTHONPATH=<checkout>/src` and
`HOL_GUARD_NATIVE=off`. Each scenario seeds `guard.db` with legacy or
incompatible objects, runs the real store startup, and captures the schema
the moment the prefix ends (just before the evidence schema), or the
`RuntimeError` a family validator raised.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import sys
import tempfile
from pathlib import Path

from codex_plugin_scanner.guard import store_connection_schema as schema_module
from codex_plugin_scanner.guard import store_native_decision_receipts as receipts
from codex_plugin_scanner.guard import store_resume
from codex_plugin_scanner.guard.store import GuardStore

try:
    from codex_plugin_scanner.guard import store_command_activity_health_schema as health
    from codex_plugin_scanner.guard import store_command_activity_maintenance_schema as maintenance
    from codex_plugin_scanner.guard import store_command_activity_schema as activity
except ImportError as error:  # pragma: no cover - guard against recording from the port
    raise SystemExit(f"original Python schema prefix is gone: {error}") from error

TARGET = Path(__file__).resolve().parent / "schema_prefix_vectors.json"


class _PrefixDoneSignal(Exception):  # noqa: N818 - control-flow signal, not an error
    pass


def _rows(connection: sqlite3.Connection, sql: str) -> list[list[object]]:
    return [list(row) for row in connection.execute(sql).fetchall()]


def _snapshot(connection: sqlite3.Connection) -> dict[str, object]:
    return {
        "objects": _rows(connection, "select type, name, tbl_name, sql from sqlite_schema order by type, name"),
        "migrations": [row[0] for row in _rows(connection, "select version from schema_migrations order by version")],
        "journal_mode": connection.execute("pragma journal_mode").fetchone()[0],
        "auto_vacuum": connection.execute("pragma auto_vacuum").fetchone()[0],
        "health": _rows(connection, "select * from command_activity_health"),
        "health_active": _rows(connection, "select * from command_activity_health_active"),
        "maintenance": _rows(connection, "select * from command_activity_maintenance"),
    }


def _record(setup: list[str] | None) -> dict[str, object]:
    home = Path(tempfile.mkdtemp())
    if setup is not None:
        connection = sqlite3.connect(home / "guard.db", isolation_level=None)
        for statement in setup:
            connection.execute(statement)
        connection.close()
    captured: dict[str, object] = {}
    original = schema_module.ensure_evidence_schema

    def capture(connection: sqlite3.Connection, *args: object, **kwargs: object) -> None:
        captured.update(_snapshot(connection))
        raise _PrefixDoneSignal

    schema_module.ensure_evidence_schema = capture
    try:
        GuardStore(home)
    except _PrefixDoneSignal:
        return {"state": captured}
    except RuntimeError as error:
        return {"error": str(error)}
    except sqlite3.OperationalError as error:
        return {"sqlite_error": str(error)}
    finally:
        schema_module.ensure_evidence_schema = original
    raise AssertionError("store startup never reached the evidence schema")


def _without_lines(statement: str, *prefixes: str) -> str:
    kept = [line for line in statement.splitlines() if not line.strip().startswith(prefixes)]
    return re.sub(r",(\s*\)\s*)$", r"\1", "\n".join(kept))


def _scenarios() -> dict[str, list[str] | None]:
    activity_statements = activity.command_activity_schema_statements()
    daily_totals = next(s for s in activity_statements if "command_activity_daily_totals (" in s)
    command_activity = activity_statements[0]
    shouted = daily_totals.replace("if not exists ", "").upper().replace(" ", "  \n ")
    return {
        "fresh": None,
        "existing_file": ["create table legacy_marker (id integer)"],
        "legacy_columns": [
            _without_lines(store_resume.resume_schema_statement(), "continuation_"),
            "create table guard_continuation_claims (request_id text not null, offer_hash text not null, "
            "action text not null, state text not null, claimed_at text not null, evidence_id text, "
            "primary key (request_id, offer_hash, action))",
            receipts.native_decision_receipt_schema_statement().replace(receipts._COMMAND_BINDING_COLUMN + ",", ""),
        ],
        "activity_missing_columns": ["create table command_activity (activity_id text primary key, occurred_at text)"],
        "activity_columns": [
            command_activity.replace("activity_id text primary key,", "activity_id text primary key, extra text,", 1)
        ],
        "activity_primary_key": [
            "create table command_activity_daily_totals (day text, total integer, primary key (total, day))"
        ],
        "activity_index": [
            command_activity,
            "create index idx_command_activity_occurred_at on command_activity(occurred_at)",
        ],
        "activity_object_sql": [
            "create table command_activity_daily_totals (day text primary key, total integer not null)"
        ],
        "activity_canonical_sql": [shouted],
        "health_columns": ["create table command_activity_health (singleton integer primary key, extra text)"],
        "health_singleton": [
            health._HEALTH_TABLE_SQL,
            "insert into command_activity_health values (1, 0, 0, null, null, '0.9.0')",
        ],
        "health_active_object_sql": [
            "create table command_activity_health_active (singleton integer primary key, "
            "command_error_active integer not null, shadow_error_active integer not null, "
            "maintenance_error_active integer not null)"
        ],
        "maintenance_singleton": [
            *activity_statements,
            *maintenance.command_activity_maintenance_schema_statements(),
            "insert into command_activity_maintenance (singleton, rollup_backfill_complete, "
            "last_backfilled_rows, last_detail_rows_deleted, last_correlation_rows_deleted, "
            "last_aggregate_rows_deleted, schema_version) values (1, 0, 0, 0, 0, 0, 'old')",
        ],
        "api_object_sql": [
            "create table command_activity_invalidations (sequence integer primary key, activity_id text)"
        ],
        "display_primary_key": ["create table command_activity_invocation (activity_id text, invocation_preview text)"],
    }


def main() -> int:
    if os.environ.get("HOL_GUARD_NATIVE") != "off":
        raise SystemExit("set HOL_GUARD_NATIVE=off so the original Python path records")
    cases = [{"name": name, "setup": setup, **_record(setup)} for name, setup in _scenarios().items()]
    TARGET.write_text(json.dumps({"cases": cases}, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    print(f"recorded {len(cases)} cases", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
