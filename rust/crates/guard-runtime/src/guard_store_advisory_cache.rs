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

/// Serialized row bytes one `list` reply carries before it stops early, well
/// under the resident's reply frame limit.
const LIST_REPLY_BUDGET: usize = 1024 * 1024;

/// One page of cached rows newest first: at most `limit` (unbounded when it
/// is null or negative) after skipping `offset`. The payload text is returned
/// as stored so the caller decodes it exactly as before. A page that would
/// pass the reply budget stops early (always keeping its first row) and sets
/// `more`, so the caller asks again from where it ended.
pub(crate) fn list(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let limit = match args.raw("limit") {
        None => -1,
        Some(_) => args.int("limit")?,
    };
    let offset = match args.raw("offset") {
        None => 0,
        Some(_) => args.int("offset")?,
    };
    let rows = query_all(
        connection,
        "select publisher_key, payload_json, updated_at from publisher_cache \
         order by updated_at desc limit ? offset ?",
        &[Value::from(limit), Value::from(offset)],
    )?;
    let mut page = Vec::with_capacity(rows.len());
    let mut used = 0;
    let mut more = false;
    for row in rows {
        let row = Value::Object(row);
        used += serde_json::to_string(&row).map_or(0, |text| text.len());
        if used > LIST_REPLY_BUDGET && !page.is_empty() {
            more = true;
            break;
        }
        page.push(row);
    }
    Ok(serde_json::json!({"rows": page, "more": more}))
}
