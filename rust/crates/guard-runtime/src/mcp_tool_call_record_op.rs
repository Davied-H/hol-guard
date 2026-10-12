//! `McpToolCallRecord` - resident op that records one decided MCP tool call
//! (inventory row, receipt and runtime event) in a single store transaction.
//!
//! The same recording also runs inside the fused stdio exchange, ahead of the
//! write to the child. Process-local concerns (storage gate, permission
//! repair, wake notification) stay with the Python caller, which receives the
//! outbox generation.

use guard_contracts::{
    GuardStoreRequestV1, McpToolCallRecordRequestV1, McpToolCallRecordResultV1,
    GUARD_STORE_REQUEST_SCHEMA, MCP_TOOL_CALL_RECORD_REQUEST_SCHEMA,
    MCP_TOOL_CALL_RECORD_RESULT_SCHEMA,
};
use serde_json::{json, Map, Value};

use crate::mcp_tool_call_record_build::build_rows;

const ERR_SCHEMA: &str = "native_mcp_tool_call_record_schema_mismatch";
const ERR_INVALID: &str = "native_mcp_tool_call_record_request_invalid";

/// A recorded call: the receipt that was written and the outbox generation.
pub(crate) struct Recorded {
    pub(crate) receipt: Map<String, Value>,
    pub(crate) outbox_generation: Option<i64>,
}

fn store_request(
    request: &McpToolCallRecordRequestV1,
    args: Map<String, Value>,
) -> GuardStoreRequestV1 {
    GuardStoreRequestV1 {
        schema: GUARD_STORE_REQUEST_SCHEMA.to_owned(),
        request_id: format!("guard-store-{}", request.request_id),
        store_path: request.store_path.clone(),
        guard_home: request.guard_home.clone(),
        method: "record_tool_call_evidence".to_owned(),
        source: request.source.clone(),
        busy_timeout_ms: request.busy_timeout_ms,
        args,
    }
}

/// Build the rows and write them in one store transaction. The error is a
/// stable failure code; nothing was written when it is returned.
pub(crate) fn record_tool_call(request: &McpToolCallRecordRequestV1) -> Result<Recorded, String> {
    if request.schema != MCP_TOOL_CALL_RECORD_REQUEST_SCHEMA {
        return Err(ERR_SCHEMA.to_owned());
    }
    if request.request_id.is_empty() {
        return Err(ERR_INVALID.to_owned());
    }
    let rows = build_rows(request).map_err(str::to_owned)?;
    let args = json!({
        "inventory": rows.inventory,
        "receipt": rows.receipt,
        "action_envelope": Value::Null,
        "now": request.store_now,
        "new_device_id": request.new_device_id,
        "event_queue_limit": request.event_queue_limit,
        "event_name": rows.event_name,
        "event_payload_json": rows.event_payload_json,
        "event_occurred_at": request.now,
    });
    let Value::Object(args) = args else {
        return Err(ERR_INVALID.to_owned());
    };
    let outbox_generation =
        crate::guard_store_op::run_store_request(&store_request(request, args))?;
    Ok(Recorded {
        receipt: rows.receipt,
        outbox_generation,
    })
}

fn result(
    request: &McpToolCallRecordRequestV1,
    outcome: Result<Recorded, String>,
) -> Result<Vec<u8>, String> {
    let (status, code, receipt, outbox_generation) = match outcome {
        Ok(done) => (
            "ok",
            "ok".to_owned(),
            Some(done.receipt),
            done.outbox_generation,
        ),
        Err(code) => ("error", code, None, None),
    };
    crate::resident_protocol::encode_response(&McpToolCallRecordResultV1 {
        schema: MCP_TOOL_CALL_RECORD_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        status: status.to_owned(),
        code,
        receipt,
        outbox_generation,
    })
}

pub(crate) fn evaluate_mcp_tool_call_record_request(
    request: &McpToolCallRecordRequestV1,
) -> Result<Vec<u8>, String> {
    result(request, record_tool_call(request))
}
