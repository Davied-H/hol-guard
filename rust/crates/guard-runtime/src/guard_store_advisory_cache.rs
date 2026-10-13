//! Cloud advisory cache: the `publisher_cache` writes from a sync and the
//! newest-first reads behind the advisory CLI, product view and projection.

use rusqlite::Connection;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::guard_store_args::Args;
use crate::guard_store_db::{exec, query_all, StoreError, StoreResult};
use crate::guard_store_json::{dumps_sorted, py_strip};

const INVALID_PAYLOAD: StoreError = StoreError::Invalid("native_advisory_payload_invalid");

/// The advisory's stripped `id`, or a digest of its canonical JSON.
fn cache_key(advisory: &Value) -> StoreResult<String> {
    if let Some(id) = advisory.get("id").and_then(Value::as_str) {
        let id = py_strip(id);
        if !id.is_empty() {
            return Ok(id.to_owned());
        }
    }
    let canonical = dumps_sorted(advisory).ok_or(INVALID_PAYLOAD)?;
    Ok(format!(
        "anonymous:{}",
        hex::encode(Sha256::digest(canonical.as_bytes()))
    ))
}

/// Upsert every payload (the caller's `json.dumps` text, stored verbatim)
/// under its cache key and return how many were written.
pub(crate) fn cache(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let now = args.str("now")?;
    let payloads = args
        .strings("payloads")?
        .ok_or(StoreError::Invalid("native_guard_store_args_invalid"))?;
    for payload in &payloads {
        let advisory: Value = serde_json::from_str(payload).map_err(|_| INVALID_PAYLOAD)?;
        exec(
            connection,
            "insert into publisher_cache (publisher_key, payload_json, updated_at) values (?, ?, ?) \
             on conflict(publisher_key) do update set \
             payload_json = excluded.payload_json, updated_at = excluded.updated_at",
            &[
                Value::from(cache_key(&advisory)?),
                Value::from(*payload),
                Value::from(now),
            ],
        )?;
    }
    Ok(Value::from(payloads.len()))
}

/// Cached rows newest first, at most `limit` unless it is null. The payload
/// text is returned as stored so the caller decodes it exactly as before.
pub(crate) fn list(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let rows = match args.raw("limit") {
        None => query_all(
            connection,
            "select publisher_key, payload_json, updated_at from publisher_cache \
             order by updated_at desc",
            &[],
        )?,
        Some(_) => query_all(
            connection,
            "select publisher_key, payload_json, updated_at from publisher_cache \
             order by updated_at desc limit ?",
            &[Value::from(args.int("limit")?)],
        )?,
    };
    Ok(Value::Array(rows.into_iter().map(Value::Object).collect()))
}
