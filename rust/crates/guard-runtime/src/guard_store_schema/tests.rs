//! Replays schema-prefix vectors recorded from the original Python store
//! (see `testdata/guard_store/record_schema_prefix_vectors.py`): each case
//! seeds `guard.db` with legacy or incompatible objects, and the expected
//! schema, migrations, pragmas, singleton rows or validator error all come
//! from Python.

use std::path::Path;

use guard_contracts::{GuardStoreRequestV1, GUARD_STORE_REQUEST_SCHEMA};
use rusqlite::types::ValueRef;
use rusqlite::Connection;
use serde_json::{json, Map, Value};

use crate::guard_store_cmd_vectors_tests::temp_home;
use crate::guard_store_op::evaluate_guard_store_request;

const VECTORS: &str = include_str!("../../testdata/guard_store/schema_prefix_vectors.json");

fn initialize(home: &Path) -> Value {
    let mut args = Map::new();
    args.insert("applied_at".to_owned(), json!("2026-10-12T00:00:00+00:00"));
    let request = GuardStoreRequestV1 {
        schema: GUARD_STORE_REQUEST_SCHEMA.to_owned(),
        request_id: "schema-vector".to_owned(),
        store_path: home.join("guard.db").to_string_lossy().into_owned(),
        guard_home: home.to_string_lossy().into_owned(),
        method: super::METHOD.to_owned(),
        source: "local".to_owned(),
        busy_timeout_ms: 5000,
        args,
    };
    serde_json::from_slice(&evaluate_guard_store_request(&request).unwrap()).unwrap()
}

fn rows(connection: &Connection, sql: &str) -> Value {
    let mut statement = connection.prepare(sql).unwrap();
    let width = statement.column_count();
    let mut out = Vec::new();
    let mut cursor = statement.query([]).unwrap();
    while let Some(row) = cursor.next().unwrap() {
        let cells = (0..width)
            .map(|index| match row.get_ref(index).unwrap() {
                ValueRef::Null => Value::Null,
                ValueRef::Integer(number) => json!(number),
                ValueRef::Real(number) => json!(number),
                ValueRef::Text(text) => json!(String::from_utf8_lossy(text)),
                ValueRef::Blob(_) => panic!("unexpected blob in schema snapshot"),
            })
            .collect();
        out.push(Value::Array(cells));
    }
    Value::Array(out)
}

fn snapshot(home: &Path) -> Value {
    let connection = Connection::open(home.join("guard.db")).unwrap();
    let pragma = |name: &str| rows(&connection, &format!("pragma {name}"))[0][0].clone();
    let migrations: Vec<Value> = rows(
        &connection,
        "select version from schema_migrations order by version",
    )
    .as_array()
    .unwrap()
    .iter()
    .map(|row| row[0].clone())
    .collect();
    json!({
        "objects": rows(&connection, "select type, name, tbl_name, sql from sqlite_schema order by type, name"),
        "migrations": migrations,
        "journal_mode": pragma("journal_mode"),
        "auto_vacuum": pragma("auto_vacuum"),
        "health": rows(&connection, "select * from command_activity_health"),
        "health_active": rows(&connection, "select * from command_activity_health_active"),
        "maintenance": rows(&connection, "select * from command_activity_maintenance"),
    })
}

fn seed(home: &Path, setup: &Value) {
    let Some(statements) = setup.as_array() else {
        return;
    };
    let connection = Connection::open(home.join("guard.db")).unwrap();
    for statement in statements {
        connection
            .execute_batch(statement.as_str().unwrap())
            .unwrap();
    }
}

#[test]
fn replays_every_recorded_schema_prefix_case() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    let cases = vectors["cases"].as_array().unwrap();
    assert!(cases.len() >= 15);
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let home = temp_home(&format!("schema-{name}"));
        seed(&home, &case["setup"]);
        let reply = initialize(&home);
        if let Some(message) = case["error"].as_str() {
            assert_eq!(reply["status"], "error", "{name}: {reply}");
            assert_eq!(reply["code"], "native_guard_store_runtime_error", "{name}");
            assert_eq!(reply["payload"]["message"], message, "{name}");
        } else if let Some(message) = case["sqlite_error"].as_str() {
            assert_eq!(reply["status"], "error", "{name}: {reply}");
            assert_eq!(reply["code"], "native_guard_store_sqlite_error", "{name}");
            let actual = reply["payload"]["message"].as_str().unwrap();
            assert!(actual.contains(message), "{name}: {actual}");
        } else {
            assert_eq!(reply["status"], "ok", "{name}: {reply}");
            assert_eq!(snapshot(&home), case["state"], "{name}");
        }
        let _ = std::fs::remove_dir_all(&home);
    }
}

#[test]
fn rerunning_the_prefix_leaves_a_fresh_store_unchanged() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    let fresh = vectors["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == "fresh")
        .unwrap();
    let home = temp_home("schema-rerun");
    for _ in 0..2 {
        assert_eq!(initialize(&home)["status"], "ok");
    }
    assert_eq!(snapshot(&home), fresh["state"]);
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn a_failed_family_rolls_back_the_whole_prefix() {
    let home = temp_home("schema-rollback");
    seed(
        &home,
        &json!([
            "create table command_activity_invocation (activity_id text, invocation_preview text)"
        ]),
    );
    assert_eq!(initialize(&home)["status"], "error");
    let connection = Connection::open(home.join("guard.db")).unwrap();
    let tables = rows(
        &connection,
        "select name from sqlite_schema where type = 'table' order by name",
    );
    assert_eq!(tables, json!([["command_activity_invocation"]]));
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn rejects_a_missing_applied_at() {
    let home = temp_home("schema-invalid");
    let request = GuardStoreRequestV1 {
        schema: GUARD_STORE_REQUEST_SCHEMA.to_owned(),
        request_id: "schema-invalid".to_owned(),
        store_path: home.join("guard.db").to_string_lossy().into_owned(),
        guard_home: home.to_string_lossy().into_owned(),
        method: super::METHOD.to_owned(),
        source: "local".to_owned(),
        busy_timeout_ms: 5000,
        args: Map::new(),
    };
    let reply: Value =
        serde_json::from_slice(&evaluate_guard_store_request(&request).unwrap()).unwrap();
    assert_eq!(reply["code"], "native_guard_store_invalid");
    assert!(!home.join("guard.db").exists());
    let _ = std::fs::remove_dir_all(&home);
}
