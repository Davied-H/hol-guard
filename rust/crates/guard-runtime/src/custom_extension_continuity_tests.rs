//! Replays continuity vectors recorded from the reference Python
//! (`scripts/record_custom_extension_continuity_vectors.py`).

use serde_json::{json, Value};

use super::*;

const VECTORS: &str = include_str!("../tests/fixtures/custom_extension_continuity_vectors.json");

#[test]
fn continuity_matches_python_vectors() {
    let vectors: Vec<Value> = serde_json::from_str(VECTORS).expect("vectors");
    assert!(vectors.len() >= 300);
    for vector in &vectors {
        let got = evaluate(&vector["request"]).expect("answer");
        assert_eq!(got, vector["expected"], "vector {}", vector["name"]);
    }
}

#[test]
fn malformed_requests_are_errors_not_refusals() {
    for request in [
        json!({}),
        json!({"operation": "other"}),
        json!({"operation": "plan", "continuity": {}, "now": "x"}),
        json!({"operation": "local_mutation", "cli_id": "local-cli.a"}),
        json!({"operation": "public_state"}),
    ] {
        assert_eq!(evaluate(&request), Err(ERR_REQUEST), "{request}");
    }
}
