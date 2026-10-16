//! The approval-center block the queue route takes under
//! `blocked_request_mode = "ask"`.
//!
//! `_queue_approval_center_response` answers the queue route by the bound
//! blocked-request mode. Under `ask` the proxy writes the call's approval
//! request, raises the desktop notice and the approval center, and blocks the
//! call on that request; the agent is told which request to approve and that
//! retrying the same action is what resumes it. This ports that branch for
//! the harnesses whose native prompt is a pure function of the decision, so
//! the resident answers such a call without the Python proxy in the byte path.
//!
//! Only opencode qualifies. `_allow_after_native_prompt` is the one fact the
//! route still needs under `ask`, and the opencode proxy answers it from the
//! decision alone (`decision.source != "policy"`); every other relay harness
//! answers it from its base class, whose `False` leaves the route to the
//! client's inline elicitation, which the resident cannot raise.
//!
//! The row is written before the block is answered, through the daemon's own
//! `queue_blocked_approvals` store operation under the shared storage gate,
//! and read back through `get_approval_request` with the cwd a queued row is
//! derived against. The call's `temporary_mcp_approval` hint, which Python
//! attaches to every queue read, is attached here for the same reason: a
//! browser MCP call whose approval carried no bounded-grant hint would lose
//! the 15m/1h/5h choices in the approval center. The read's other hint,
//! `local_tool_approval`, reads a trusted-local-tool scanner evidence entry,
//! which a tool call's evidence never holds.
//!
//! What the resident cannot reproduce defers, and a defer blocks the call, so
//! each one costs the user a stopped tool call:
//!
//! - any relay harness other than opencode, until its inline elicitation is
//!   ported;
//! - a binding with no approval-center origin, no review OAuth source or no
//!   bound receipt redaction level, which the daemon publishes together;
//! - a decision whose signals, projected risk summary or launch target are
//!   empty, since the queued row would then fall back to the artifact's own
//!   risk facts, which the Python proxy derives and the relay does not carry;
//! - a read-back row whose `approval_url` is not this center's link for the
//!   written request, which `canonical_local_approval_url` would rewrite.
//!
//! One gap is accepted rather than deferred: the row is written before the
//! block's evidence is offered, so an evidence buffer that is full after the
//! write leaves a queued request the agent never hears about. The user still
//! sees it in the approval center, and the call is blocked either way.

use std::path::Path;

use guard_command::effect_decision::GuardAction;
use guard_contracts::{
    BrowserMcpArtifactV1, GuardStoreRequestV1, McpCallProjectionQueryV1, McpToolCallArtifactV1,
    McpToolRiskInputV1, GUARD_STORE_REQUEST_SCHEMA,
};
use serde_json::{json, Map, Value};

use super::{Admitted, McpRelayDecideRequestV1, Resolved, Routed};
use crate::hook_direct::saved_decision::consume::{repair_store_permissions, storage_gate};
use crate::local_store_read::STORE_FILE_NAME;
use crate::mcp_tool_policy_decision::Decision;

/// The decision source `_queue_approval_center_response` records for a call
/// it blocks on a queued approval request.
pub(super) const APPROVAL_PENDING_SOURCE: &str = "approval-center-pending";
/// The one relay harness whose `_allow_after_native_prompt` is a pure
/// function of the decision.
pub(super) const OPENCODE: &str = "opencode";
/// The busy timeout the daemon's own store calls take.
const BUSY_TIMEOUT_MS: u64 = 250;
/// The artifact type a tool call is built with.
const ARTIFACT_TYPE: &str = "tool_call";
/// The actions `_needs_review` queues; any other item is dropped unwritten.
const REVIEWABLE: [&str; 2] = ["review", "require-reapproval"];
/// `_QUEUE_METADATA_KEYS`, which a tool-call artifact never carries.
const QUEUE_METADATA_KEYS: [&str; 4] = [
    "raw_command_text",
    "command_text",
    "command_rule_matches",
    "extension_allow_hint",
];
/// `TEMPORARY_MCP_GRANT_TARGETS`.
const GRANT_TARGETS: [&str; 3] = ["exact", "category", "server"];
/// `["once", *TEMPORARY_MCP_GRANT_DURATIONS]`.
const GRANT_DURATIONS: [&str; 4] = ["once", "15m", "1h", "5h"];
/// `_HARD_RISK_EXCLUSIONS`.
const HARD_RISK_EXCLUSIONS: [&str; 10] = [
    "browser_transfer",
    "browser_privileged",
    "browser_sensitive_surface",
    "browser_shared_profile",
    "secret_access",
    "filesystem_access",
    "command_execution",
    "destructive_mutation",
    "privileged_system_mutation",
    "tool_schema_mismatch",
];
/// `_INTENT_CATEGORIES`.
const INTENT_CATEGORIES: [(&str, &str); 3] = [
    ("browser.navigation", "browser_navigation"),
    ("browser.inspect", "browser_inspection"),
    ("browser.interact", "browser_interaction"),
];
/// The one `_INFORMATIONAL_CATEGORIES` entry.
const INFORMATIONAL_CATEGORY: &str = "browser_external_domain";

const ASK_UNSUPPORTED: &str = "mcp_relay_ask_unsupported";
const ASK_PROJECTION: &str = "mcp_relay_ask_projection";
const ASK_QUEUE_FAILED: &str = "mcp_relay_ask_queue_failed";
const ASK_STALE_CENTER: &str = "mcp_relay_ask_stale_center";

/// `_allow_after_native_prompt` for a relay harness, when the decision it
/// reads carries no pending saved approval. The saved-allow gate replaces a
/// pending decision before the route runs, so the pre-gate answer would be
/// the wrong one and the route asks for the fact itself.
pub(super) fn native_prompt_allows(harness: &str, decision: &Decision) -> Option<bool> {
    if decision.pending.is_some() {
        return None;
    }
    (harness == OPENCODE).then(|| decision.source != "policy")
}

/// Write this call's approval request and block on it, as the `ask` branch of
/// `_queue_approval_center_response` does.
pub(super) fn queue(
    request: &McpRelayDecideRequestV1,
    admitted: &Admitted,
    resolved: &Resolved,
    policy_action: String,
) -> Result<Routed, &'static str> {
    if request.build.harness != OPENCODE || !REVIEWABLE.contains(&policy_action.as_str()) {
        return Err(ASK_UNSUPPORTED);
    }
    let review = &admitted.binding.review;
    let (Some(center), Some(oauth_source), Some(redaction_level)) = (
        review.approval_center_origin.as_deref(),
        review.review_oauth_source.as_deref(),
        resolved.redaction_level.as_deref(),
    ) else {
        return Err(ASK_UNSUPPORTED);
    };
    let artifact = &resolved.identity.artifact;
    let artifact_hash = resolved
        .identity
        .artifact_hash
        .as_deref()
        .ok_or(ASK_UNSUPPORTED)?;
    let signals = &resolved.decision.signals;
    if !signals.iter().any(|signal| !signal.is_empty()) {
        return Err(ASK_UNSUPPORTED);
    }
    let projection = project(request, artifact)?;
    let item = review_item(
        artifact,
        artifact_hash,
        signals,
        &projection,
        &policy_action,
        &resolved.decision,
    );
    let now = now_isoformat().ok_or(ASK_QUEUE_FAILED)?;
    let args = args(request, item, artifact, center, &now, redaction_level);
    let (request_id, notice) = write(request, oauth_source, args)?;
    let row = read_back(request, &request_id)?;
    let review_url = format!("{}/requests/{request_id}", center.trim_end_matches('/'));
    // `canonical_local_approval_url` leaves this center's own link alone; a
    // row carrying any other link is one Python would have rewritten.
    if row.get("approval_url").and_then(Value::as_str) != Some(review_url.as_str()) {
        return Err(ASK_STALE_CENTER);
    }
    let message = format!(
        "HOL Guard stopped tool call {} from {}. Approve request {request_id} at {review_url}, \
         then retry the same action.",
        request.build.tool_name, request.build.server_name
    );
    let data = json!({
        "approvalCenterUrl": center,
        "approvalRequests": [Value::Object(row)],
        "guardPolicyAction": policy_action,
        "reviewUrl": review_url,
    });
    Ok(Routed::Asked {
        policy_action,
        message,
        data,
        // What `_notify_pending_approval` and `_maybe_open_approval_center`
        // raise once the row is written, which the drain owns.
        approval: json!({
            "approval_center_url": center,
            "review_url": review_url,
            "request_id": request_id,
            "workspace": admitted.workspace,
            "notices": [notice],
        }),
    })
}

/// The `McpCallProjection` fields the queued item reads.
struct Projection {
    /// `display_launch_target`.
    launch_target: String,
    risk_summary: String,
    browser_intent: Option<Value>,
}

/// `self._call_projector.project(tool_name, params, artifact)`.
fn project(
    request: &McpRelayDecideRequestV1,
    artifact: &McpToolCallArtifactV1,
) -> Result<Projection, &'static str> {
    let projected = crate::mcp_proxy_projection::call_projection(&McpCallProjectionQueryV1 {
        tool_name: request.build.tool_name.clone(),
        params: request.params.clone(),
        // `risk_input(artifact, params["arguments"])`, taken from the
        // arguments in the order the host sent them; the decoded params lost
        // that order, and the risk evidence reads it.
        risk: Some(McpToolRiskInputV1 {
            artifact: BrowserMcpArtifactV1 {
                name: artifact.name.clone(),
                command: artifact.command.clone(),
                metadata: artifact.metadata.clone(),
            },
            arguments: request.arguments.clone(),
            risk_categories: None,
            summary_code: None,
        }),
    })
    .map_err(|_| ASK_PROJECTION)?;
    let browser = projected.get("browser").filter(|value| !value.is_null());
    // `display_launch_target`: the browser label for a browser navigation,
    // else the plain target.
    let launch_target = match browser {
        Some(browser) => browser.get("launch_target"),
        None => projected.get("launch_target"),
    }
    .and_then(Value::as_str)
    .unwrap_or_default()
    .to_owned();
    let risk_summary = projected
        .get("risk")
        .and_then(|risk| risk.get("summary"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    if launch_target.is_empty() || risk_summary.is_empty() {
        return Err(ASK_PROJECTION);
    }
    Ok(Projection {
        launch_target,
        risk_summary,
        browser_intent: browser.and_then(|browser| browser.get("intent")).cloned(),
    })
}

/// `review_artifact_payload`: the evaluation item a queued `tools/call` is
/// written to the inbox with.
fn review_item(
    artifact: &McpToolCallArtifactV1,
    artifact_hash: &str,
    signals: &[String],
    projection: &Projection,
    policy_action: &str,
    decision: &Decision,
) -> Map<String, Value> {
    let mut changed_fields = vec![json!("runtime_tool_call")];
    if projection.browser_intent.is_some() {
        changed_fields.push(json!("runtime_browser_tool_call"));
    }
    let mut item = Map::new();
    item.insert("artifact_id".to_owned(), json!(artifact.artifact_id));
    item.insert("artifact_name".to_owned(), json!(artifact.name));
    item.insert("artifact_hash".to_owned(), json!(artifact_hash));
    item.insert("artifact_type".to_owned(), json!(ARTIFACT_TYPE));
    item.insert("source_scope".to_owned(), json!(artifact.source_scope));
    item.insert("config_path".to_owned(), json!(artifact.config_path));
    item.insert("changed_fields".to_owned(), Value::Array(changed_fields));
    item.insert("policy_action".to_owned(), json!(policy_action));
    item.insert("launch_target".to_owned(), json!(projection.launch_target));
    item.insert("risk_summary".to_owned(), json!(projection.risk_summary));
    item.insert(
        "risk_signals".to_owned(),
        Value::Array(signals.iter().map(|signal| json!(signal)).collect()),
    );
    if let Some(intent) = &projection.browser_intent {
        item.insert("browser_intent".to_owned(), intent.clone());
    }
    let evidence = scanner_evidence(decision);
    if !evidence.is_empty() {
        item.insert("scanner_evidence".to_owned(), Value::Array(evidence));
    }
    item
}

/// `tool_decision_scanner_evidence`: how the decision's action was reached,
/// without any of the call's payload.
fn scanner_evidence(decision: &Decision) -> Vec<Value> {
    let facts = crate::mcp_tool_policy_proxy::facts(decision);
    let effective = crate::mcp_proxy_actions::enforcement(&facts.action, &facts);
    let mut evidence = Vec::new();
    if let Some(reason_code) = &decision.normalization_reason_code {
        evidence.push(json!({
            "source": "guard_action_normalizer",
            "input_source": "stored_tool_policy",
            "reason_code": reason_code,
            "original_action": decision.original_action,
            "normalized_action": effective.as_str(),
        }));
    }
    if let Some(reason_code) = &decision.approval_reuse_reason_code {
        evidence.push(json!({
            "source": "approval_reuse",
            "status": decision.approval_reuse_status,
            "reason_code": reason_code,
            "current_action": decision.current_action.map(GuardAction::as_str),
            "saved_action": decision.saved_action.map(GuardAction::as_str),
            "effective_action": effective.as_str(),
        }));
    }
    evidence
}

/// The `queue_blocked_approvals` arguments for this one item.
fn args(
    request: &McpRelayDecideRequestV1,
    item: Map<String, Value>,
    artifact: &McpToolCallArtifactV1,
    center: &str,
    now: &str,
    redaction_level: &str,
) -> Map<String, Value> {
    let mut artifacts = Map::new();
    artifacts.insert(
        artifact.artifact_id.clone(),
        Value::Object(queue_artifact(artifact)),
    );
    let mut args = Map::new();
    args.insert("harness".to_owned(), json!(request.build.harness));
    args.insert("items".to_owned(), json!([Value::Object(item)]));
    args.insert("artifacts".to_owned(), Value::Object(artifacts));
    args.insert("approval_center_url".to_owned(), json!(center));
    args.insert("now".to_owned(), json!(now));
    args.insert("prompt_shown".to_owned(), json!(true));
    args.insert("redaction_level".to_owned(), json!(redaction_level));
    args.insert("guard_version".to_owned(), json!(crate::PACKAGE_VERSION));
    args.insert("cwd".to_owned(), json!(request.cwd));
    // `continuation_offer_facts` for an operation the proxy offers no
    // continuation for: every fact is its default and the metadata is empty.
    args.insert(
        "continuation".to_owned(),
        json!({
            "harness": request.build.harness,
            "original_hook_attached": false,
            "wait_deadline": Value::Null,
            "opaque_target_id": Value::Null,
            "session_target_verified": false,
            "now": now,
            "correlation_candidates": [Value::Null, Value::Null],
        }),
    );
    args
}

/// `_queue_artifact`: the artifact facts the decision owner reads beside the
/// item. A tool-call artifact carries none of the command metadata, and the
/// item's own risk facts are non-empty, so the artifact's are never read.
fn queue_artifact(artifact: &McpToolCallArtifactV1) -> Map<String, Value> {
    let mut queued = Map::new();
    queued.insert("wire".to_owned(), wire_artifact(artifact));
    for key in QUEUE_METADATA_KEYS {
        queued.insert(key.to_owned(), Value::Null);
    }
    queued.insert("risk_summary".to_owned(), Value::Null);
    queued.insert("risk_signals".to_owned(), Value::Array(Vec::new()));
    queued
}

/// `wire_artifact`: none of the `_METADATA_KEYS` are ever set on a tool-call
/// artifact, so the wire metadata is the identity mark alone.
fn wire_artifact(artifact: &McpToolCallArtifactV1) -> Value {
    json!({
        "artifact_id": artifact.artifact_id,
        "name": artifact.name,
        "harness": artifact.harness,
        "artifact_type": ARTIFACT_TYPE,
        "source_scope": artifact.source_scope,
        "config_path": artifact.config_path,
        "command": artifact.command,
        "args": [],
        "url": Value::Null,
        "transport": artifact.transport,
        "publisher": artifact.publisher,
        "metadata": {"mcp_tool_identity": true},
    })
}

/// Write the request through the daemon's own store operation, under the
/// storage gate every writer of this store holds.
fn write(
    request: &McpRelayDecideRequestV1,
    oauth_source: &str,
    args: Map<String, Value>,
) -> Result<(String, Value), &'static str> {
    let guard_home = Path::new(&request.guard_home);
    let _gate = storage_gate(guard_home).map_err(|_| ASK_QUEUE_FAILED)?;
    let written = store(
        request,
        "mcp-relay-ask-queue",
        "queue_blocked_approvals",
        oauth_source,
        args,
    );
    repair_store_permissions(guard_home);
    let written = written?;
    // Python raises what the queue loop stopped on after naming what it had
    // already written; a relayed call has no later step to raise into, so an
    // error defers whether or not a row was written.
    if !written["error"].is_null() {
        return Err(ASK_QUEUE_FAILED);
    }
    let entry = written["queued"]
        .as_array()
        .and_then(|queued| queued.first())
        .ok_or(ASK_QUEUE_FAILED)?;
    let request_id = entry["request_id"]
        .as_str()
        .filter(|id| !id.is_empty())
        .ok_or(ASK_QUEUE_FAILED)?
        .to_owned();
    Ok((request_id, entry["notice"].clone()))
}

/// `store.get_approval_request(request_id)`, with the queue hints Python
/// attaches to every approval read.
fn read_back(
    request: &McpRelayDecideRequestV1,
    request_id: &str,
) -> Result<Map<String, Value>, &'static str> {
    let mut args = Map::new();
    args.insert("request_id".to_owned(), json!(request_id));
    args.insert("derive_scope".to_owned(), json!(true));
    args.insert("cwd".to_owned(), json!(request.cwd));
    // `RuntimeError("Persisted approval request not found")`: the row was
    // written, so a read that cannot find it leaves a store the resident
    // cannot reason about.
    let Value::Object(mut row) = store(
        request,
        "mcp-relay-ask-read",
        "get_approval_request",
        "mcp-relay",
        args,
    )?
    else {
        return Err(ASK_QUEUE_FAILED);
    };
    if let Some(hint) = temporary_mcp_approval(&row) {
        row.insert("temporary_mcp_approval".to_owned(), hint);
    }
    Ok(row)
}

/// One store call against this home's `guard.db`.
fn store(
    request: &McpRelayDecideRequestV1,
    request_id: &str,
    method: &str,
    source: &str,
    args: Map<String, Value>,
) -> Result<Value, &'static str> {
    crate::guard_store_op::evaluate(&GuardStoreRequestV1 {
        schema: GUARD_STORE_REQUEST_SCHEMA.to_owned(),
        request_id: request_id.to_owned(),
        store_path: Path::new(&request.guard_home)
            .join(STORE_FILE_NAME)
            .to_string_lossy()
            .into_owned(),
        guard_home: request.guard_home.clone(),
        method: method.to_owned(),
        source: source.to_owned(),
        busy_timeout_ms: BUSY_TIMEOUT_MS,
        args,
    })
    .map(|(payload, _)| payload)
    .map_err(|_| ASK_QUEUE_FAILED)
}

/// `temporary_mcp_approval_payload`: the bounded-grant choices a routine
/// browser capability offers in the approval center.
fn temporary_mcp_approval(row: &Map<String, Value>) -> Option<Value> {
    let intent = row.get("browser_intent")?.as_object()?;
    let identity_hash = nonempty(intent.get("mcp_server_identity_hash"))?;
    let server_name = nonempty(intent.get("mcp_server_name"))?;
    let named = nonempty(intent.get("intent"))?;
    let category = INTENT_CATEGORIES
        .iter()
        .find(|(name, _)| *name == named)
        .map(|(_, category)| *category)?;
    let risk_categories: Vec<&str> = intent
        .get("risk_categories")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    if !risk_categories.contains(&category) {
        return None;
    }
    if !risk_categories
        .iter()
        .all(|item| *item == category || *item == INFORMATIONAL_CATEGORY)
    {
        return None;
    }
    let target_label =
        nonempty(intent.get("target_domain")).or_else(|| nonempty(intent.get("target_origin")));
    Some(json!({
        "version": 1,
        "eligible": true,
        "server_name": server_name,
        "server_identity_hash": identity_hash,
        "category": category,
        "target_label": target_label,
        "allowed_targets": GRANT_TARGETS,
        "allowed_durations": GRANT_DURATIONS,
        "hard_risk_exclusions": HARD_RISK_EXCLUSIONS,
    }))
}

/// `_nonempty_string`.
fn nonempty(value: Option<&Value>) -> Option<String> {
    let text = value?.as_str()?.trim();
    (!text.is_empty()).then(|| text.to_owned())
}

/// `_now()`: `datetime.now(timezone.utc).isoformat()`, which leaves the
/// fraction out at exactly zero microseconds.
fn now_isoformat() -> Option<String> {
    let micros = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_micros();
    crate::policy_bundle_time::micros_to_utc_isoformat(i64::try_from(micros).ok()?, "+00:00")
}

#[cfg(test)]
#[path = "mcp_relay_decide_ask_tests.rs"]
mod tests;
