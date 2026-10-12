//! The five command-activity schema families. Each one creates its objects,
//! checks the live columns, primary keys, indexes and stored SQL against the
//! statements it owns, then records its migration version.

use rusqlite::Connection;
use serde_json::Value;

use super::record_migration;
use super::sql_families as sql;
use crate::guard_store_db::{int, query_all, query_one, runtime_error, text, StoreResult};

const ACTIVITY_MIGRATION_VERSION: i64 = 10;
const HEALTH_MIGRATION_VERSION: i64 = 11;
const HEALTH_ACTIVE_MIGRATION_VERSION: i64 = 19;
const HEALTH_SCHEMA_VERSION: &str = "1.0.0";
const MAINTENANCE_MIGRATION_VERSION: i64 = 12;
const MAINTENANCE_SCHEMA_VERSION: &str = "guard.command-activity-maintenance.v1";
const API_MIGRATION_VERSION: i64 = 13;
const DISPLAY_MIGRATION_VERSION: i64 = 27;

/// Expected column set and primary key (in key order) of one table.
type TableShape = (
    &'static str,
    &'static [&'static str],
    &'static [&'static str],
);

const ACTIVITY_TABLES: [TableShape; 6] = [
    (
        "command_activity",
        &[
            "activity_id",
            "occurred_at",
            "harness",
            "hook_phase",
            "execution_status",
            "proof_level",
            "policy_action",
            "decision_reason_code",
            "controlling_rule_id",
            "parse_confidence",
            "uncertainty_class",
            "match_count",
            "prompted",
            "approval_reuse_status",
            "receipt_link_status",
            "receipt_id",
            "evaluation_latency_bucket",
            "persistence_latency_bucket",
            "schema_version",
        ],
        &["activity_id"],
    ),
    (
        "command_activity_matches",
        &[
            "activity_id",
            "ordinal",
            "extension_id",
            "extension_version",
            "rule_id",
            "rule_version",
            "match_class",
            "severity",
            "default_floor",
            "safe_variant_id",
            "schema_version",
        ],
        &["activity_id", "ordinal"],
    ),
    (
        "command_activity_match_effects",
        &["activity_id", "ordinal", "effect_class"],
        &["activity_id", "ordinal", "effect_class"],
    ),
    (
        "command_activity_correlations",
        &["activity_id", "kind", "harness", "key_id", "digest"],
        &["activity_id", "kind"],
    ),
    ("command_activity_daily_totals", &["day", "total"], &["day"]),
    (
        "command_activity_daily_rollups",
        &["day", "dimension", "dimension_value", "count"],
        &["day", "dimension", "dimension_value"],
    ),
];

/// Index name, table, columns, unique, partial.
type IndexShape = (
    &'static str,
    &'static str,
    &'static [&'static str],
    i64,
    i64,
);

const ACTIVITY_INDEXES: [IndexShape; 6] = [
    (
        "idx_command_activity_occurred_at",
        "command_activity",
        &["occurred_at", "activity_id"],
        0,
        0,
    ),
    (
        "idx_command_activity_harness_occurred_at",
        "command_activity",
        &["harness", "occurred_at", "activity_id"],
        0,
        0,
    ),
    (
        "idx_command_activity_match_rule",
        "command_activity_matches",
        &["rule_id", "activity_id"],
        0,
        0,
    ),
    (
        "idx_command_activity_match_extension",
        "command_activity_matches",
        &["extension_id", "activity_id"],
        0,
        0,
    ),
    (
        "idx_command_activity_correlation_lookup",
        "command_activity_correlations",
        &["kind", "harness", "key_id", "digest"],
        0,
        0,
    ),
    (
        "idx_command_activity_request_correlation_unique",
        "command_activity_correlations",
        &["harness", "key_id", "digest"],
        1,
        1,
    ),
];
const INDEXED_TABLES: [&str; 3] = [
    "command_activity",
    "command_activity_matches",
    "command_activity_correlations",
];

const HEALTH_TABLES: [TableShape; 2] = [
    (
        "command_activity_health",
        &[
            "singleton",
            "dropped_event_count",
            "persistence_error_count",
            "last_error_code",
            "last_error_at",
            "schema_version",
        ],
        &["singleton"],
    ),
    (
        "command_activity_health_active",
        &[
            "singleton",
            "command_error_active",
            "shadow_error_active",
            "maintenance_error_active",
        ],
        &["singleton"],
    ),
];

const MAINTENANCE_TABLES: [TableShape; 3] = [
    (
        "command_activity_rollup_membership",
        &[
            "activity_id",
            "day",
            "occurred_at",
            "rolled_at",
            "detail_present",
        ],
        &["activity_id"],
    ),
    (
        "command_activity_maintenance",
        &[
            "singleton",
            "last_completed_day",
            "last_run_at",
            "detail_compaction_started_at",
            "rollup_backfill_cursor_occurred_at",
            "rollup_backfill_cursor_activity_id",
            "rollup_backfill_complete",
            "last_backfilled_rows",
            "last_detail_rows_deleted",
            "last_correlation_rows_deleted",
            "last_aggregate_rows_deleted",
            "schema_version",
        ],
        &["singleton"],
    ),
    (
        "command_activity_rollup_pending",
        &["activity_id", "occurred_at"],
        &["activity_id"],
    ),
];

const API_TABLES: [TableShape; 2] = [
    (
        "command_activity_feedback",
        &[
            "activity_id",
            "label",
            "created_at",
            "updated_at",
            "schema_version",
        ],
        &["activity_id"],
    ),
    (
        "command_activity_invalidations",
        &["sequence", "activity_id"],
        &["sequence"],
    ),
];

const DISPLAY_TABLES: [TableShape; 1] = [(
    "command_activity_invocation",
    &["activity_id", "invocation_preview"],
    &["activity_id"],
)];

pub(super) fn ensure_activity(connection: &Connection, applied_at: &str) -> StoreResult<()> {
    run(connection, &sql::ACTIVITY)?;
    for shape in &ACTIVITY_TABLES {
        check_table(connection, shape)?;
    }
    check_activity_indexes(connection)?;
    check_object_sql(connection, &sql::ACTIVITY, "", true)?;
    record_migration(connection, ACTIVITY_MIGRATION_VERSION, applied_at)
}

pub(super) fn ensure_health(connection: &Connection, applied_at: &str) -> StoreResult<()> {
    connection.execute_batch(sql::HEALTH_TABLE)?;
    check_single_table(connection, &HEALTH_TABLES[0], sql::HEALTH_TABLE)?;
    connection.execute(
        "insert or ignore into command_activity_health (\
           singleton, dropped_event_count, persistence_error_count, \
           last_error_code, last_error_at, schema_version\
         ) values (1, 0, 0, null, null, ?)",
        [HEALTH_SCHEMA_VERSION],
    )?;
    if singleton_schema_version(connection, "command_activity_health")?.as_deref()
        != Some(HEALTH_SCHEMA_VERSION)
    {
        return runtime_error("incompatible command_activity_health singleton");
    }
    connection.execute_batch(sql::HEALTH_ACTIVE_TABLE)?;
    check_single_table(connection, &HEALTH_TABLES[1], sql::HEALTH_ACTIVE_TABLE)?;
    connection.execute_batch(
        "insert or ignore into command_activity_health_active (\
           singleton, command_error_active, shadow_error_active, maintenance_error_active\
         ) \
         select singleton, \
           case when last_error_code is null then 0 else 1 end, \
           case when last_error_code is null then 0 else 1 end, \
           case when last_error_code is null then 0 else 1 end \
         from command_activity_health where singleton = 1",
    )?;
    if query_one(
        connection,
        "select singleton from command_activity_health_active where singleton = 1",
        &[],
    )?
    .is_none()
    {
        return runtime_error("incompatible command_activity_health_active singleton");
    }
    record_migration(connection, HEALTH_MIGRATION_VERSION, applied_at)?;
    record_migration(connection, HEALTH_ACTIVE_MIGRATION_VERSION, applied_at)
}

pub(super) fn ensure_maintenance(connection: &Connection, applied_at: &str) -> StoreResult<()> {
    run(connection, &sql::MAINTENANCE)?;
    connection.execute(
        "insert or ignore into command_activity_maintenance (\
           singleton, last_completed_day, last_run_at, detail_compaction_started_at, \
           rollup_backfill_cursor_occurred_at, rollup_backfill_cursor_activity_id, \
           rollup_backfill_complete, last_backfilled_rows, \
           last_detail_rows_deleted, last_correlation_rows_deleted, \
           last_aggregate_rows_deleted, schema_version\
         ) values (1, null, null, null, null, null, 0, 0, 0, 0, 0, ?)",
        [MAINTENANCE_SCHEMA_VERSION],
    )?;
    for shape in &MAINTENANCE_TABLES {
        check_table(connection, shape)?;
    }
    check_object_sql(connection, &sql::MAINTENANCE, "maintenance ", false)?;
    if singleton_schema_version(connection, "command_activity_maintenance")?.as_deref()
        != Some(MAINTENANCE_SCHEMA_VERSION)
    {
        return runtime_error("incompatible command_activity_maintenance singleton");
    }
    record_migration(connection, MAINTENANCE_MIGRATION_VERSION, applied_at)
}

pub(super) fn ensure_api(connection: &Connection, applied_at: &str) -> StoreResult<()> {
    run(connection, &sql::API)?;
    for shape in &API_TABLES {
        check_table(connection, shape)?;
    }
    check_object_sql(connection, &sql::API, "API ", false)?;
    record_migration(connection, API_MIGRATION_VERSION, applied_at)
}

pub(super) fn ensure_display(connection: &Connection, applied_at: &str) -> StoreResult<()> {
    run(connection, &sql::DISPLAY)?;
    for shape in &DISPLAY_TABLES {
        check_table(connection, shape)?;
    }
    check_object_sql(connection, &sql::DISPLAY, "display ", false)?;
    record_migration(connection, DISPLAY_MIGRATION_VERSION, applied_at)
}

fn run(connection: &Connection, statements: &[&str]) -> StoreResult<()> {
    for statement in statements {
        connection.execute_batch(statement)?;
    }
    Ok(())
}

/// Column set, then the primary key in key order.
fn check_table(
    connection: &Connection,
    (table, columns, primary_key): &TableShape,
) -> StoreResult<()> {
    let rows = query_all(connection, &format!("pragma table_info({table})"), &[])?;
    let mut actual: Vec<&str> = rows.iter().map(|row| text(row, "name")).collect();
    let mut expected = columns.to_vec();
    actual.sort_unstable();
    actual.dedup();
    expected.sort_unstable();
    if actual != expected {
        return runtime_error(&format!("incompatible {table} schema"));
    }
    let mut keyed: Vec<(i64, &str)> = rows
        .iter()
        .filter(|row| int(row, "pk") > 0)
        .map(|row| (int(row, "pk"), text(row, "name")))
        .collect();
    keyed.sort_by_key(|(position, _)| *position);
    if !keyed
        .iter()
        .map(|(_, name)| *name)
        .eq(primary_key.iter().copied())
    {
        return runtime_error(&format!("incompatible {table} primary key"));
    }
    Ok(())
}

/// A health table: its shape, then its stored SQL against the one statement.
fn check_single_table(
    connection: &Connection,
    shape: &TableShape,
    statement: &str,
) -> StoreResult<()> {
    check_table(connection, shape)?;
    let table = shape.0;
    let stored = query_one(
        connection,
        "select sql from sqlite_schema where type = 'table' and name = ?",
        &[Value::from(table)],
    )?;
    let expected = canonical_sql(statement).replacen(" if not exists", "", 1);
    match stored
        .as_ref()
        .and_then(|row| row.get("sql"))
        .and_then(Value::as_str)
    {
        Some(sql) if canonical_sql(sql) == expected => Ok(()),
        _ => runtime_error(&format!("incompatible {table} schema object")),
    }
}

fn singleton_schema_version(connection: &Connection, table: &str) -> StoreResult<Option<String>> {
    Ok(query_one(
        connection,
        &format!("select schema_version from {table} where singleton = 1"),
        &[],
    )?
    .and_then(|row| {
        row.get("schema_version")
            .and_then(Value::as_str)
            .map(str::to_owned)
    }))
}

fn check_activity_indexes(connection: &Connection) -> StoreResult<()> {
    let mut actual: Vec<(String, &str, Vec<String>, i64, i64)> = Vec::new();
    for table in INDEXED_TABLES {
        for row in query_all(connection, &format!("pragma index_list({table})"), &[])? {
            let name = text(&row, "name").to_owned();
            let columns = query_all(connection, &format!("pragma index_info({name})"), &[])?
                .iter()
                .map(|column| text(column, "name").to_owned())
                .collect();
            actual.retain(|entry| entry.0 != name);
            actual.push((
                name,
                table,
                columns,
                int(&row, "unique"),
                int(&row, "partial"),
            ));
        }
    }
    for (name, table, columns, unique, partial) in ACTIVITY_INDEXES {
        let matches = actual.iter().any(|entry| {
            entry.0 == name
                && entry.1 == table
                && entry
                    .2
                    .iter()
                    .map(String::as_str)
                    .eq(columns.iter().copied())
                && entry.3 == unique
                && entry.4 == partial
        });
        if !matches {
            return runtime_error(&format!("incompatible command activity index: {name}"));
        }
    }
    Ok(())
}

/// Every owned object's stored SQL must equal its statement without the
/// first `if not exists`, compared after lowercasing and collapsing spaces.
fn check_object_sql(
    connection: &Connection,
    statements: &[&str],
    family_label: &str,
    allow_unique: bool,
) -> StoreResult<()> {
    let mut expected: Vec<(String, String)> = Vec::new();
    for statement in statements {
        let canonical = canonical_sql(statement);
        let Some(name) = owned_object_name(&canonical, allow_unique) else {
            return runtime_error(&format!(
                "unrecognized command activity {family_label}schema statement"
            ));
        };
        let sql = canonical.replacen(" if not exists", "", 1);
        match expected.iter_mut().find(|(known, _)| *known == name) {
            Some(entry) => entry.1 = sql,
            None => expected.push((name, sql)),
        }
    }
    let names: Vec<Value> = expected
        .iter()
        .map(|(name, _)| Value::from(name.as_str()))
        .collect();
    let rows = query_all(
        connection,
        &format!(
            "select name, sql from sqlite_schema where name in ({})",
            crate::guard_store_db::placeholders(names.len())
        ),
        &names,
    )?;
    for (name, sql) in &expected {
        let stored = rows
            .iter()
            .filter(|row| text(row, "name") == name)
            .filter_map(|row| row.get("sql").and_then(Value::as_str))
            .next_back()
            .map(canonical_sql);
        if stored.as_deref() != Some(sql.as_str()) {
            return runtime_error(&format!(
                "incompatible command activity {family_label}schema object: {name}"
            ));
        }
    }
    Ok(())
}

/// `create [unique ](table|index|trigger) if not exists <name>` at the start.
fn owned_object_name(canonical: &str, allow_unique: bool) -> Option<String> {
    let rest = canonical.strip_prefix("create ")?;
    let rest = match rest.strip_prefix("unique ") {
        Some(after) if allow_unique => after,
        _ => rest,
    };
    let rest = ["table ", "index ", "trigger "]
        .iter()
        .find_map(|kind| rest.strip_prefix(kind))?
        .strip_prefix("if not exists ")?;
    let name: String = rest
        .chars()
        .take_while(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '_')
        .collect();
    (!name.is_empty()).then_some(name)
}

/// Python `" ".join(value.strip().lower().split())`.
pub(super) fn canonical_sql(value: &str) -> String {
    value
        .to_lowercase()
        .split(is_python_space)
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

fn is_python_space(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}
