//! Pure builders for `mcp_tool_call_record`: the receipt, inventory row and
//! event payload of one decided MCP tool call. They mirror what the Python
//! `allow_tool_call` / `block_tool_call` assembled before the store write, so
//! the store sees the same rows.

use guard_command::mcp_runtime_evidence::{extract_command_text, runtime_action_record};
use guard_contracts::McpToolCallRecordRequestV1;
use serde_json::{json, Map, Value};

use crate::guard_store_json::{dumps_default, py_strip};

const ERR_KIND: &str = "native_mcp_tool_call_record_kind_invalid";
const ERR_ACTION: &str = "native_mcp_tool_call_record_action_invalid";
const ERR_EVENT: &str = "native_mcp_tool_call_record_event_unencodable";

const INLINE_SOURCES: [&str; 4] = [
    "inline-approved",
    "inline-denied",
    "native-approved",
    "claude-native-approved",
];
const POLICY_SOURCES: [&str; 15] = [
    "heuristic",
    "policy",
    "auto",
    "pre-tool-hook",
    "permission-request-hook",
    "policy-allow",
    "policy-block",
    "policy_allow",
    "policy_block",
    "heuristic-allow",
    "heuristic-block",
    "heuristic_allow",
    "heuristic_block",
    "auto-allow",
    "auto-block",
];

/// The rows one decided call writes.
pub(crate) struct Rows {
    pub(crate) receipt: Map<String, Value>,
    pub(crate) inventory: Map<String, Value>,
    pub(crate) event_name: String,
    pub(crate) event_payload_json: String,
}

fn approval_source(decision_source: &str) -> &'static str {
    if INLINE_SOURCES.contains(&decision_source) {
        "inline"
    } else if POLICY_SOURCES.contains(&decision_source) || decision_source.starts_with("policy") {
        "policy"
    } else {
        "approval_center"
    }
}

/// `normalize_guard_action(value, unknown_action="require-reapproval")`.
fn normalize_action(action: &str) -> &str {
    match action {
        "allow" | "warn" | "review" | "require-reapproval" | "sandbox-required" | "block" => action,
        "ask" => "review",
        _ => "require-reapproval",
    }
}

/// Event name and provenance wording for a verdict that did not execute.
fn non_executed(action: &str) -> Option<(&'static str, &'static str)> {
    match action {
        "review" => Some((
            "runtime_tool_call_review_required",
            "runtime tool call awaiting review",
        )),
        "require-reapproval" => Some((
            "runtime_tool_call_reapproval_required",
            "runtime tool call awaiting fresh approval",
        )),
        "sandbox-required" => Some((
            "runtime_tool_call_sandbox_required",
            "runtime tool call requires an enforceable sandbox",
        )),
        "block" => Some(("runtime_tool_call_blocked", "runtime tool call blocked")),
        _ => None,
    }
}

/// `receipt_evidence_for_mcp_tool_call`: the display text and the scanner
/// evidence item built from the firewall result and the runtime action.
fn display_evidence(request: &McpToolCallRecordRequestV1) -> (Option<String>, Value) {
    let mut evidence = Map::new();
    if request.firewall_unavailable {
        evidence.insert("firewallEvidence".into(), json!("native_unavailable"));
    }
    if let Some(firewall) = request.firewall.as_ref().filter(|value| value.is_object()) {
        evidence.insert("mcpSkillFirewall".into(), firewall.clone());
    }
    let text = extract_command_text(&request.artifact.name, request.arguments.as_deref());
    if let Some(action) = runtime_action_record(
        request.tool_description.as_deref(),
        None,
        &request.risk_categories,
        None,
    ) {
        evidence.insert("runtimeAction".into(), action);
    }
    (text, Value::Object(evidence))
}

/// `_auto_diff_summary`.
fn diff_summary(changed: &[String]) -> String {
    let sample = changed
        .iter()
        .take(3)
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    let suffix = if changed.len() > 3 { " ..." } else { "" };
    format!("{} change(s): {sample}{suffix}", changed.len())
}

fn launch_command(request: &McpToolCallRecordRequestV1) -> Value {
    let artifact = &request.artifact;
    match artifact
        .command
        .as_deref()
        .filter(|command| !command.is_empty())
    {
        None => Value::Null,
        Some(command) => {
            let mut parts = vec![command.to_owned()];
            parts.extend(artifact.args.iter().cloned());
            Value::String(py_strip(&parts.join(" ")).to_owned())
        }
    }
}

pub(crate) fn build_rows(request: &McpToolCallRecordRequestV1) -> Result<Rows, &'static str> {
    let allow = match request.kind.as_str() {
        "allow" => true,
        "block" => false,
        _ => return Err(ERR_KIND),
    };
    let artifact = &request.artifact;
    let policy_action = request.policy_action.as_str();
    let (event_name, provenance) = if allow {
        (
            "runtime_tool_call_allowed",
            "runtime tool call allowed".to_owned(),
        )
    } else {
        let (name, wording) = non_executed(policy_action).ok_or(ERR_ACTION)?;
        (name, wording.to_owned())
    };
    let (raw_command_text, firewall_evidence) = display_evidence(request);
    let mut changed = vec![
        "runtime_tool_call".to_owned(),
        request.decision_source.clone(),
    ];
    changed.extend(request.signals.iter().cloned());
    let mut scanner_evidence = vec![firewall_evidence];
    scanner_evidence.extend(request.additional_scanner_evidence.iter().cloned());
    let inline_override = if allow {
        "inline-approved"
    } else {
        "inline-denied"
    };
    let user_override = (request.decision_source == inline_override).then_some(if allow {
        "inline-approve"
    } else {
        "inline-deny"
    });
    let mut receipt = Map::new();
    receipt.insert("receipt_id".into(), json!(request.receipt_id));
    receipt.insert("timestamp".into(), json!(request.receipt_timestamp));
    receipt.insert("harness".into(), json!(artifact.harness));
    receipt.insert("artifact_id".into(), json!(artifact.artifact_id));
    receipt.insert("artifact_hash".into(), json!(request.artifact_hash));
    receipt.insert(
        "policy_decision".into(),
        json!(normalize_action(policy_action)),
    );
    receipt.insert(
        "capabilities_summary".into(),
        json!(format!("mcp tool call \u{2022} {}", artifact.name)),
    );
    receipt.insert("changed_capabilities".into(), json!(changed));
    receipt.insert(
        "provenance_summary".into(),
        json!(format!("{provenance} from {}", artifact.config_path)),
    );
    receipt.insert("user_override".into(), json!(user_override));
    receipt.insert("artifact_name".into(), json!(artifact.name));
    receipt.insert("source_scope".into(), json!(artifact.source_scope));
    receipt.insert("diff_summary".into(), json!(diff_summary(&changed)));
    receipt.insert(
        "approval_source".into(),
        json!(approval_source(&request.decision_source)),
    );
    receipt.insert("approval_request_id".into(), Value::Null);
    receipt.insert("scanner_evidence".into(), Value::Array(scanner_evidence));
    receipt.insert("raw_command_text".into(), json!(raw_command_text));

    let approved = allow && matches!(policy_action, "allow" | "warn");
    let mut inventory = Map::new();
    inventory.insert("artifact_id".into(), json!(artifact.artifact_id));
    inventory.insert("harness".into(), json!(artifact.harness));
    inventory.insert("artifact_name".into(), json!(artifact.name));
    inventory.insert("artifact_type".into(), json!(artifact.artifact_type));
    inventory.insert("source_scope".into(), json!(artifact.source_scope));
    inventory.insert("config_path".into(), json!(artifact.config_path));
    inventory.insert("publisher".into(), json!(artifact.publisher));
    inventory.insert("origin_url".into(), json!(artifact.url));
    inventory.insert("launch_command".into(), launch_command(request));
    inventory.insert("transport".into(), json!(artifact.transport));
    inventory.insert("artifact_hash".into(), json!(request.artifact_hash));
    inventory.insert("policy_action".into(), json!(policy_action));
    inventory.insert("changed".into(), json!(false));
    inventory.insert("approved".into(), json!(approved));
    inventory.insert("now".into(), json!(request.now));

    let mut payload = Map::new();
    payload.insert("artifact_id".into(), json!(artifact.artifact_id));
    payload.insert("artifact_hash".into(), json!(request.artifact_hash));
    payload.insert("decision_source".into(), json!(request.decision_source));
    payload.insert("policy_action".into(), json!(policy_action));
    payload.insert("risk_categories".into(), json!(request.risk_categories));
    payload.insert("signals".into(), json!(request.signals));
    if !allow {
        payload.insert("execution_outcome".into(), json!("not-executed"));
    }
    let event_payload_json = dumps_default(&Value::Object(payload)).ok_or(ERR_EVENT)?;
    Ok(Rows {
        receipt,
        inventory,
        event_name: event_name.to_owned(),
        event_payload_json,
    })
}

#[cfg(test)]
#[path = "mcp_tool_call_record_build_tests.rs"]
mod tests;
