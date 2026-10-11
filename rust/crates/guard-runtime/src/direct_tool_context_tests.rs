//! Direct-tool actions stay request-bound and reject malformed caller facts.
use guard_contracts::RequestContextRequestV1;
use serde_json::{json, Value};

fn request(kind: &str, command: Value) -> Value {
    let root = std::env::temp_dir()
        .canonicalize()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    let owner = if cfg!(unix) { owner() } else { None };
    let mut body = json!({"facts": {"cwd": root, "home_dir": root, "caller_home": root, "temp_dir": root, "environment": {}, "groups": []}});
    if kind == "direct_tool" {
        body["tool"] = json!("vitest");
        body["script"] = command;
    } else {
        body["command"] = command;
    }
    json!({"schema": "guard-request-context-request.v1", "request_id": "synthetic-direct-tool", "guard_home": root, "source": "direct_command", "budget_ms": 9000, "owner_uid": owner, "action": {"kind": kind, "body": body}})
}

#[cfg(unix)]
fn owner() -> Option<u32> {
    Some(nix::unistd::geteuid().as_raw())
}
#[cfg(not(unix))]
fn owner() -> Option<u32> {
    None
}

fn evaluate(wire: Value) -> Value {
    let request: RequestContextRequestV1 = serde_json::from_value(wire).unwrap();
    let bytes = crate::request_context_op::evaluate_request_context_request(&request).unwrap();
    let response: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        response["request_sha256"],
        crate::request_context_op::request_digest(&request).unwrap()
    );
    assert_eq!(response["request_id"], request.request_id);
    response
}

#[test]
fn direct_tool_refusals_are_bound_without_a_context() {
    let response = evaluate(request("direct_tool", json!("echo synthetic")));
    assert_eq!(response["status"], "ok");
    assert_eq!(
        response["payload"],
        json!({"kind": "direct_tool", "accepted": false, "context": null})
    );
    let response = evaluate(request("trusted_tool", json!("missing-synthetic-command")));
    assert_eq!(
        response["payload"],
        json!({"kind": "trusted_tool", "trusted": false})
    );
}

#[test]
fn direct_tool_admission_refuses_paths_environment_and_budgets() {
    let mut wire = request("direct_tool", json!("echo synthetic"));
    wire["action"]["body"]["facts"]["cwd"] = json!("relative");
    assert_eq!(
        evaluate(wire)["code"],
        "native_request_context_direct_path_invalid"
    );
    let mut wire = request("trusted_tool", json!("node"));
    wire["action"]["body"]["facts"]["environment"]["PATH"] = json!("x".repeat(65537));
    assert_eq!(
        evaluate(wire)["code"],
        "native_request_context_direct_environment_invalid"
    );
    let mut wire = request("direct_tool", json!("echo synthetic"));
    wire["budget_ms"] = json!(0);
    assert_eq!(
        evaluate(wire)["code"],
        "native_request_context_budget_invalid"
    );
}

#[test]
fn direct_tool_contract_has_no_trust_override_or_unknown_fields() {
    for kind in ["direct_tool", "trusted_tool"] {
        let mut wire = request(kind, json!("node"));
        wire["action"]["body"]["facts"]["trusted_tree_sha256"] = json!("unreviewed");
        assert!(serde_json::from_value::<RequestContextRequestV1>(wire).is_err());
        let mut wire = request(kind, json!("node"));
        wire["action"]["body"]["trusted"] = json!(true);
        assert!(serde_json::from_value::<RequestContextRequestV1>(wire).is_err());
    }
}
