use super::*;
use serde_json::json;

const VECTORS: &str =
    include_str!("../../../../tests/fixtures/mcp_tool_call_identity/parity_vectors.json");

fn vectors() -> Value {
    serde_json::from_str(VECTORS).expect("parity vectors parse")
}

fn parse(raw: &Value) -> McpToolCallIdentityRequestV1 {
    let mut raw = raw.clone();
    raw["schema"] = json!(MCP_TOOL_CALL_IDENTITY_REQUEST_SCHEMA);
    raw["request_id"] = json!("vector");
    serde_json::from_value(raw).expect("request parses")
}

fn run(request: &McpToolCallIdentityRequestV1) -> Value {
    let bytes = evaluate_mcp_tool_call_identity_request(request).expect("encodes");
    serde_json::from_slice(&bytes).expect("result json")
}

#[test]
fn every_python_recorded_vector_replays_exactly() {
    let doc = vectors();
    let all = doc["vectors"].as_object().expect("vectors");
    assert!(all.len() >= 20);
    for (name, vector) in all {
        let request = parse(&vector["request"]);
        let reply = run(&request);
        if let Some(code) = vector.get("error") {
            assert_eq!(reply["status"], "error", "{name}: {reply}");
            assert_eq!(&reply["code"], code, "{name}");
            assert!(reply["payload"].is_null(), "{name}");
            continue;
        }
        assert_eq!(reply["status"], "ok", "{name}: {reply}");
        let payload = &reply["payload"];
        let expected = &vector["expected"];
        assert_eq!(payload["artifact"], expected["artifact"], "{name} artifact");
        assert_eq!(
            payload["runtime_private_metadata"], expected["runtime_private_metadata"],
            "{name} private"
        );
        assert_eq!(
            payload["artifact_hash"], expected["artifact_hash"],
            "{name} hash"
        );
    }
}

#[test]
fn result_echoes_the_canonical_request_digest() {
    let doc = vectors();
    let request = parse(&doc["vectors"]["catalog_token"]["request"]);
    let reply = run(&request);
    assert_eq!(
        reply["request_sha256"].as_str().expect("digest"),
        request_digest(&request).expect("digest")
    );
}

#[test]
fn rejects_wrong_schema_and_ambiguous_source() {
    let doc = vectors();
    let mut request = parse(&doc["vectors"]["catalog_token"]["request"]);
    request.schema = "other".to_owned();
    assert_eq!(
        run(&request)["code"],
        "native_mcp_tool_call_identity_schema_mismatch"
    );
    let mut request = parse(&doc["vectors"]["catalog_token"]["request"]);
    request.artifact = request
        .build
        .as_ref()
        .map(|build| build_artifact(build).expect("builds").0);
    assert_eq!(
        run(&request)["code"],
        "native_mcp_tool_call_identity_request_invalid"
    );
    request.build = None;
    request.artifact = None;
    assert_eq!(
        run(&request)["code"],
        "native_mcp_tool_call_identity_request_invalid"
    );
}

#[test]
fn risky_tool_reports_risk_categories() {
    let doc = vectors();
    let reply = run(&parse(&doc["vectors"]["risky_shell"]["request"]));
    assert!(reply["payload"]["risk_categories"]
        .as_array()
        .is_some_and(|items| !items.is_empty()));
}
