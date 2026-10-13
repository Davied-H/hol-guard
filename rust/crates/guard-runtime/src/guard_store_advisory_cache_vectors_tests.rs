//! Replays advisory cache vectors recorded from the original Python store
//! (see `testdata/guard_store/record_advisory_cache_vectors.py`). Seeds, SQL
//! steps, results and table states all come from Python, never from Rust
//! output.

use std::path::Path;

use guard_contracts::{GuardStoreRequestV1, GUARD_STORE_REQUEST_SCHEMA};
use rusqlite::Connection;
use serde_json::{Map, Value};

use crate::guard_store_cmd_vectors_tests::{apply_sql, assert_rows, dump, insert_rows, temp_home};
use crate::guard_store_op::evaluate_guard_store_request;

const VECTORS: &str = include_str!("../testdata/guard_store/advisory_cache_vectors.json");

fn build_database(path: &Path, vectors: &Value, scenario: &Value) {
    let connection = Connection::open(path).unwrap();
    connection.execute_batch("pragma journal_mode=wal").ok();
    connection
        .execute_batch("create table guard_review_outbox_events (stream_sequence integer primary key, payload_hash text not null default '')")
        .unwrap();
    for statement in vectors["schema_sql"].as_array().unwrap() {
        connection
            .execute_batch(statement.as_str().unwrap())
            .unwrap();
    }
    for (table, rows) in scenario["seed"].as_object().unwrap() {
        insert_rows(&connection, table, rows);
    }
}

fn run_step(home: &Path, source: &str, step: &Value) -> Value {
    let request = GuardStoreRequestV1 {
        schema: GUARD_STORE_REQUEST_SCHEMA.to_owned(),
        request_id: "vector".to_owned(),
        store_path: home.join("guard.db").to_string_lossy().into_owned(),
        guard_home: home.to_string_lossy().into_owned(),
        method: step["method"].as_str().unwrap().to_owned(),
        source: source.to_owned(),
        busy_timeout_ms: 5000,
        args: step["wire_args"].as_object().unwrap().clone(),
    };
    let bytes = evaluate_guard_store_request(&request).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// What the Python caller builds from the returned rows: dict payloads only,
/// with the payload's own keys winning over the row's.
fn decoded(rows: &Value) -> Value {
    let items = rows.as_array().unwrap().iter().filter_map(|row| {
        let payload: Value = serde_json::from_str(row["payload_json"].as_str()?).ok()?;
        let mut item = Map::new();
        item.insert("cache_key".to_owned(), row["publisher_key"].clone());
        item.insert("updated_at".to_owned(), row["updated_at"].clone());
        item.extend(payload.as_object()?.clone());
        Some(Value::Object(item))
    });
    Value::Array(items.collect())
}

#[test]
fn replays_every_recorded_advisory_cache_step() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    assert_eq!(vectors["schema"], "guard-store-advisory-cache-vectors.v1");
    let source = vectors["source"].as_str().unwrap();
    let mut compared_steps = 0;
    for scenario in vectors["scenarios"].as_array().unwrap() {
        let name = scenario["name"].as_str().unwrap();
        let home = temp_home(name);
        build_database(&home.join("guard.db"), &vectors, scenario);
        for (index, step) in scenario["steps"].as_array().unwrap().iter().enumerate() {
            let label = format!("{name}#{index} {} {}", step["method"], step["label"]);
            if step["method"] == "sql" {
                apply_sql(&home, step);
                continue;
            }
            let reply = run_step(&home, source, step);
            assert_eq!(reply["status"], "ok", "{label}: {reply}");
            if step["method"] == "list_cached_advisories" {
                assert_eq!(decoded(&reply["payload"]), step["result"], "{label}");
            } else {
                assert_eq!(reply["payload"], step["result"], "{label}");
            }
            let connection = Connection::open(home.join("guard.db")).unwrap();
            for (table, order_by) in vectors["order_by"].as_object().unwrap() {
                let actual = dump(&connection, table, order_by.as_str().unwrap());
                assert_rows(&actual, &step["after"][table], &label);
            }
            compared_steps += 1;
        }
        let _ = std::fs::remove_dir_all(&home);
    }
    assert!(compared_steps >= 11, "only {compared_steps} recorded steps");
}
