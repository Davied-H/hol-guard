use super::*;
use guard_contracts::{McpToolCallRecordArtifactV1, MCP_TOOL_CALL_RECORD_REQUEST_SCHEMA};

fn request(kind: &str, decision_source: &str, policy_action: &str) -> McpToolCallRecordRequestV1 {
    McpToolCallRecordRequestV1 {
        schema: MCP_TOOL_CALL_RECORD_REQUEST_SCHEMA.to_owned(),
        request_id: "r1".to_owned(),
        kind: kind.to_owned(),
        store_path: "/tmp/guard.db".to_owned(),
        guard_home: "/tmp".to_owned(),
        source: "local".to_owned(),
        busy_timeout_ms: 1000,
        event_queue_limit: 100,
        receipt_id: "rc1".to_owned(),
        receipt_timestamp: "2026-01-01T00:00:00+00:00".to_owned(),
        store_now: "2026-01-01T00:00:00+00:00".to_owned(),
        new_device_id: "dev1".to_owned(),
        now: "2026-01-01T00:00:00+00:00".to_owned(),
        artifact: McpToolCallRecordArtifactV1 {
            artifact_id: "codex:project:srv".to_owned(),
            name: "srv".to_owned(),
            harness: "codex".to_owned(),
            artifact_type: "mcp_server".to_owned(),
            source_scope: "project".to_owned(),
            config_path: "/p/.mcp.json".to_owned(),
            command: Some("npx".to_owned()),
            args: vec!["-y".to_owned(), "srv".to_owned()],
            url: None,
            transport: Some("stdio".to_owned()),
            publisher: None,
        },
        artifact_hash: "h1".to_owned(),
        decision_source: decision_source.to_owned(),
        policy_action: policy_action.to_owned(),
        signals: vec!["s1".to_owned()],
        risk_categories: Vec::new(),
        firewall: None,
        firewall_unavailable: false,
        tool_description: None,
        arguments: None,
        additional_scanner_evidence: Vec::new(),
    }
}

#[test]
fn allow_rows_mark_the_call_approved() {
    let rows = build_rows(&request("allow", "policy", "allow")).unwrap();
    assert_eq!(rows.event_name, "runtime_tool_call_allowed");
    assert_eq!(rows.inventory["approved"], json!(true));
    assert_eq!(rows.inventory["launch_command"], json!("npx -y srv"));
    assert_eq!(rows.receipt["approval_source"], json!("policy"));
    assert_eq!(
        rows.receipt["provenance_summary"],
        json!("runtime tool call allowed from /p/.mcp.json")
    );
    assert_eq!(
        rows.receipt["changed_capabilities"],
        json!(["runtime_tool_call", "policy", "s1"])
    );
    assert_eq!(
        rows.receipt["diff_summary"],
        json!("3 change(s): runtime_tool_call, policy, s1")
    );
    let payload: Value = serde_json::from_str(&rows.event_payload_json).unwrap();
    assert!(payload.get("execution_outcome").is_none());
}

#[test]
fn block_rows_name_the_verdict_and_mark_not_executed() {
    let rows = build_rows(&request("block", "inline-denied", "block")).unwrap();
    assert_eq!(rows.event_name, "runtime_tool_call_blocked");
    assert_eq!(rows.inventory["approved"], json!(false));
    assert_eq!(rows.receipt["user_override"], json!("inline-deny"));
    assert_eq!(rows.receipt["approval_source"], json!("inline"));
    let payload: Value = serde_json::from_str(&rows.event_payload_json).unwrap();
    assert_eq!(payload["execution_outcome"], json!("not-executed"));
}

#[test]
fn unknown_kind_and_block_action_fail_closed() {
    assert_eq!(
        build_rows(&request("other", "policy", "allow")).err(),
        Some(ERR_KIND)
    );
    assert_eq!(
        build_rows(&request("block", "policy", "allow")).err(),
        Some(ERR_ACTION)
    );
}

#[test]
fn diff_summary_truncates_after_three_changes() {
    let changed: Vec<String> = ["a", "b", "c", "d"]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
    assert_eq!(diff_summary(&changed), "4 change(s): a, b, c ...");
}

#[test]
fn decision_sources_map_to_approval_sources() {
    let cases = [
        ("inline-approved", "inline"),
        ("inline-denied", "inline"),
        ("native-approved", "inline"),
        ("claude-native-approved", "inline"),
        ("policy-allow", "policy"),
        ("policy-block", "policy"),
        ("policy_allow", "policy"),
        ("heuristic-allow", "policy"),
        ("heuristic_block", "policy"),
        ("auto-allow", "policy"),
        ("heuristic", "policy"),
        ("policy", "policy"),
        ("auto", "policy"),
        ("pre-tool-hook", "policy"),
        ("permission-request-hook", "policy"),
        ("policy-custom", "policy"),
        ("pending-approval", "approval_center"),
        ("approval-center-allow", "approval_center"),
        ("unknown-source", "approval_center"),
    ];
    for (decision_source, expected) in cases {
        assert_eq!(
            approval_source(decision_source),
            expected,
            "{decision_source}"
        );
    }
}
