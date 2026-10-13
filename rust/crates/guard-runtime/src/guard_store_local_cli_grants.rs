//! This-device custom-extension grant reads: the device grant, the authority
//! revision, whether any rule exists, and one extension's command catalog and
//! per-command states.

use std::collections::HashMap;

use rusqlite::Connection;
use serde_json::{Map, Value};

use crate::guard_store_args::Args;
use crate::guard_store_db::{query_all, query_one, value_error, Row, StoreResult};
use crate::guard_store_observed_mcp::is_local_cli_id;

const COMMAND_STATES: [&str; 4] = ["inherit", "allow", "review", "block"];

/// The grant row, or `None` for an invalid id or no grant.
pub(crate) fn read_grant(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let cli_id = args.str("cli_id")?;
    if !is_local_cli_id(cli_id) {
        return Ok(Value::Null);
    }
    let row = query_one(
        connection,
        "select cli_id, identity_hash, state, revision, updated_at from local_cli_grant where cli_id = ?",
        &[Value::from(cli_id)],
    )?;
    Ok(row.map_or(Value::Null, Value::Object))
}

/// Whether a device grant or per-command state exists; only blocks if asked.
pub(crate) fn rules_exist(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let sql = if args.flag("blocks_only")? {
        "select exists(select 1 from local_cli_grant where state = 'blocked') \
         or exists(select 1 from local_cli_command_grant where state = 'block') as present"
    } else {
        "select exists(select 1 from local_cli_grant) \
         or exists(select 1 from local_cli_command_grant) as present"
    };
    let row = query_one(connection, sql, &[])?;
    let present = row
        .and_then(|row| row.get("present").and_then(Value::as_i64))
        .is_some_and(|value| value != 0);
    Ok(Value::Bool(present))
}

/// The authority revision; a non-integer stored value is a corrupt row.
pub(crate) fn read_revision(connection: &Connection) -> StoreResult<Value> {
    // Read the type first so a corrupt blob cell is the same row error.
    let row = query_one(
        connection,
        "select case when typeof(revision) = 'integer' then revision end as revision \
         from local_cli_authority where singleton = 1",
        &[],
    )?;
    let Some(row) = row else {
        return Ok(Value::from(0));
    };
    match row.get("revision") {
        Some(revision) if revision.is_i64() => Ok(revision.clone()),
        _ => value_error("invalid local CLI row"),
    }
}

/// Catalog rows in display order, skipping rows with non-text cells.
pub(crate) fn read_command_catalog(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let cli_id = args.str("cli_id")?;
    if !is_local_cli_id(cli_id) {
        return Ok(Value::Array(Vec::new()));
    }
    let rows = command_catalog(connection, cli_id)?;
    Ok(Value::Array(rows.into_iter().map(Value::Object).collect()))
}

/// Per-command states, skipping unknown states and non-text ids.
pub(crate) fn read_command_states(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let cli_id = args.str("cli_id")?;
    if !is_local_cli_id(cli_id) {
        return Ok(Value::Object(Map::new()));
    }
    let states = command_states(connection, cli_id)?
        .into_iter()
        .map(|(command_id, state)| (command_id, Value::from(state)))
        .collect();
    Ok(Value::Object(states))
}

/// One extension's well-formed catalog rows in display order. Rows with a
/// non-text cell are skipped in SQL, never decoded.
pub(crate) fn command_catalog(connection: &Connection, cli_id: &str) -> StoreResult<Vec<Row>> {
    query_all(
        connection,
        "select command_id, name, usage, description, parent_id from local_cli_command \
         where cli_id = ? and typeof(command_id) = 'text' and typeof(name) = 'text' \
         and typeof(usage) = 'text' and typeof(description) = 'text' \
         and typeof(parent_id) in ('text', 'null') \
         order by sort_index asc, command_id asc",
        &[Value::from(cli_id)],
    )
}

/// One extension's per-command states, recognised states only.
pub(crate) fn command_states(
    connection: &Connection,
    cli_id: &str,
) -> StoreResult<HashMap<String, String>> {
    let rows = query_all(
        connection,
        "select command_id, state from local_cli_command_grant \
         where cli_id = ? and typeof(command_id) = 'text' and typeof(state) = 'text'",
        &[Value::from(cli_id)],
    )?;
    Ok(rows
        .iter()
        .filter_map(|row| {
            let command_id = row.get("command_id")?.as_str()?;
            let state = row.get("state")?.as_str()?;
            COMMAND_STATES
                .contains(&state)
                .then(|| (command_id.to_owned(), state.to_owned()))
        })
        .collect())
}
