//! Schema prefix for `guard.db`: the core tables, native receipt binding,
//! continuation resume columns and the five command-activity families that
//! the Python store used to create and validate on every startup.
//!
//! The prefix runs in one immediate transaction after WAL is enabled, so an
//! incompatible family rolls the whole prefix back instead of leaving the
//! earlier families applied. Every validation failure keeps the original
//! `RuntimeError` message. The remaining schema steps stay with the Python
//! caller, which runs them after this method returns.

mod families;
mod sql_core;
mod sql_core_tail;
mod sql_families;
#[cfg(test)]
mod tests;

use std::path::Path;
use std::time::{Duration, Instant};

use rusqlite::{Connection, ErrorCode, OpenFlags};
use serde_json::{json, Map, Value};

use crate::guard_store_db::{exec, query_all, text, StoreError, StoreResult};

pub(crate) const METHOD: &str = "initialize_schema_prefix";
const WAL_BUSY_TIMEOUT_MS: u64 = 1_000;
const LOCK_RETRY_DELAY: Duration = Duration::from_millis(100);
const NATIVE_COMMAND_RECEIPT_BINDING_MIGRATION_VERSION: i64 = 28;
const RESUME_ADDITIONS: [(&str, &str); 9] = [
    ("continuation_contract_version", "text"),
    ("continuation_capability", "text"),
    ("continuation_status", "text"),
    ("continuation_reason", "text"),
    ("continuation_evidence_json", "text not null default '[]'"),
    ("continuation_offer_hash", "text"),
    ("continuation_action", "text"),
    ("continuation_completed_at", "text"),
    ("continuation_cancelled_at", "text"),
];

/// Create or upgrade the schema prefix. The store file is created here when
/// it does not exist yet; this is the only guard-store method allowed to.
pub(crate) fn initialize(
    path: &Path,
    busy_timeout_ms: u64,
    args: &Map<String, Value>,
    apply_pragmas: fn(&Connection) -> StoreResult<()>,
) -> StoreResult<Value> {
    let applied_at = args
        .get("applied_at")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or(StoreError::Invalid("native_guard_store_invalid"))?;
    let incremental_vacuum = !path.exists();
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    connection.busy_timeout(Duration::from_millis(busy_timeout_ms))?;
    apply_pragmas(&connection)?;
    if incremental_vacuum {
        connection.execute_batch("pragma auto_vacuum=incremental")?;
    }
    // WAL must be enabled before the schema transaction starts: SQLite
    // cannot change journal modes inside one.
    enable_wal(&connection, busy_timeout_ms)?;
    connection.execute_batch("BEGIN IMMEDIATE")?;
    if let Err(error) = apply(&connection, applied_at) {
        let _ = connection.execute_batch("ROLLBACK");
        return Err(error);
    }
    connection.execute_batch("COMMIT")?;
    Ok(json!({}))
}

/// Retry `journal_mode=WAL` in short busy slices until the caller's busy
/// budget runs out, then restore the caller's busy timeout.
fn enable_wal(connection: &Connection, busy_timeout_ms: u64) -> StoreResult<()> {
    let deadline = Instant::now() + Duration::from_millis(busy_timeout_ms);
    let result = (|| -> StoreResult<()> {
        let mut lock_error: Option<rusqlite::Error> = None;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if let Some(error) = lock_error.take().filter(|_| remaining.is_zero()) {
                return Err(error.into());
            }
            connection.busy_timeout(remaining.min(Duration::from_millis(WAL_BUSY_TIMEOUT_MS)))?;
            match connection.query_row("pragma journal_mode=WAL", [], |_| Ok(())) {
                Ok(()) => return Ok(()),
                Err(error) if error.sqlite_error_code() == Some(ErrorCode::DatabaseBusy) => {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        return Err(error.into());
                    }
                    lock_error = Some(error);
                    std::thread::sleep(LOCK_RETRY_DELAY.min(remaining));
                }
                Err(error) => return Err(error.into()),
            }
        }
    })();
    connection.busy_timeout(Duration::from_millis(busy_timeout_ms))?;
    result
}

fn apply(connection: &Connection, applied_at: &str) -> StoreResult<()> {
    for statement in sql_core::CORE_HEAD.iter().chain(&sql_core_tail::CORE_TAIL) {
        connection.execute_batch(statement)?;
    }
    if !column_names(connection, "native_hook_decision_receipts")?
        .iter()
        .any(|name| name == "command_extensions_json")
    {
        connection.execute_batch(&format!(
            "alter table native_hook_decision_receipts add column {}",
            sql_families::COMMAND_BINDING_COLUMN
        ))?;
    }
    record_migration(
        connection,
        NATIVE_COMMAND_RECEIPT_BINDING_MIGRATION_VERSION,
        applied_at,
    )?;
    ensure_resume(connection)?;
    families::ensure_activity(connection, applied_at)?;
    families::ensure_health(connection, applied_at)?;
    families::ensure_maintenance(connection, applied_at)?;
    families::ensure_api(connection, applied_at)?;
    families::ensure_display(connection, applied_at)
}

/// Backfill continuation columns for stores created before they existed.
fn ensure_resume(connection: &Connection) -> StoreResult<()> {
    let columns = column_names(connection, "guard_request_resumes")?;
    for (name, definition) in RESUME_ADDITIONS {
        if !columns.iter().any(|column| column == name) {
            connection.execute_batch(&format!(
                "alter table guard_request_resumes add column {name} {definition}"
            ))?;
        }
    }
    connection.execute_batch(sql_families::RESUME_CLAIMS)?;
    let claim_columns = column_names(connection, "guard_continuation_claims")?;
    for name in ["lease_expires_at", "claim_id"] {
        if !claim_columns.iter().any(|column| column == name) {
            connection.execute_batch(&format!(
                "alter table guard_continuation_claims add column {name} text"
            ))?;
        }
    }
    Ok(connection.execute_batch(sql_families::RESUME_EFFECTS)?)
}

fn column_names(connection: &Connection, table: &str) -> StoreResult<Vec<String>> {
    Ok(
        query_all(connection, &format!("pragma table_info({table})"), &[])?
            .iter()
            .map(|row| text(row, "name").to_owned())
            .collect(),
    )
}

fn record_migration(connection: &Connection, version: i64, applied_at: &str) -> StoreResult<()> {
    exec(
        connection,
        "insert or ignore into schema_migrations (version, applied_at) values (?, ?)",
        &[Value::from(version), Value::from(applied_at)],
    )
    .map(|_| ())
}
