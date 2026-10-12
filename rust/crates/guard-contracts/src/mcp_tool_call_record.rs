//! `McpToolCallRecord` - wire contract for the resident op that records one
//! decided MCP tool call: the receipt, the inventory row and the runtime event
//! in a single store transaction.
//!
//! The resident builds the receipt (summary text, diff summary, approval
//! source, display evidence) and the event payload from the call facts; the
//! caller supplies only the process-local instants and ids. The same request
//! rides the fused stdio exchange so the evidence lands before the call is
//! written to the child.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// Schema discriminator for the request.
pub const MCP_TOOL_CALL_RECORD_REQUEST_SCHEMA: &str = "guard-mcp-tool-call-record-request.v1";
/// Schema discriminator for the result.
pub const MCP_TOOL_CALL_RECORD_RESULT_SCHEMA: &str = "guard-mcp-tool-call-record-result.v1";
/// Capability advertised by the runtime when this operation is available.
pub const MCP_TOOL_CALL_RECORD_FEATURE: &str = "mcp-tool-call-record-v1";

/// The artifact fields the receipt and inventory row read.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct McpToolCallRecordArtifactV1 {
    pub artifact_id: String,
    pub name: String,
    pub harness: String,
    pub artifact_type: String,
    pub source_scope: String,
    pub config_path: String,
    pub command: Option<String>,
    pub args: Vec<String>,
    pub url: Option<String>,
    pub transport: Option<String>,
    pub publisher: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct McpToolCallRecordRequestV1 {
    pub schema: String,
    /// Caller correlation id; echoed in the result.
    pub request_id: String,
    /// `allow` (executing verdict) or `block` (non-executed verdict).
    pub kind: String,
    pub store_path: String,
    pub guard_home: String,
    /// OAuth source the store instance is bound to.
    pub source: String,
    pub busy_timeout_ms: u64,
    pub event_queue_limit: i64,
    /// Caller-generated receipt id.
    pub receipt_id: String,
    /// Receipt instant (UTC ISO-8601).
    pub receipt_timestamp: String,
    /// Canonical store instant for the receipt write.
    pub store_now: String,
    /// Caller-generated device id for a first receipt.
    pub new_device_id: String,
    /// Decision instant for the inventory row and the event.
    pub now: String,
    pub artifact: McpToolCallRecordArtifactV1,
    pub artifact_hash: String,
    pub decision_source: String,
    pub policy_action: String,
    pub signals: Vec<String>,
    pub risk_categories: Vec<String>,
    /// `artifact.metadata["mcpSkillFirewall"]` when it is an object.
    pub firewall: Option<Value>,
    /// The firewall enrichment failed, so `firewall` is absent.
    pub firewall_unavailable: bool,
    /// `artifact.metadata["tool_description"]` when it is a string.
    pub tool_description: Option<String>,
    /// Call arguments as ordered `[key, value]` entries; `None` when not a mapping.
    pub arguments: Option<Vec<(String, Option<String>)>>,
    pub additional_scanner_evidence: Vec<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct McpToolCallRecordResultV1 {
    pub schema: String,
    pub request_id: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, or a `native_mcp_tool_call_record_*` / `native_guard_store_*` failure code.
    pub code: String,
    /// The receipt that was written (before the store canonicalizes its action).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt: Option<Map<String, Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outbox_generation: Option<i64>,
}
