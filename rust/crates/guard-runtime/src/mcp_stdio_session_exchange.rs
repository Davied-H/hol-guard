//! Fused `send` exchange of the MCP stdio session op: quiet edge, optional
//! evidence record, write and correlated response under one session lock.

use std::process::Child;
use std::time::Duration;

use guard_command::mcp_stdio_session::{QuietEdge, SessionEvent};
use guard_contracts::McpStdioSessionResultV1;
use serde_json::Value;

use super::{child_exit_code, encode, err_result, SessionEntry};

const MAX_QUIET_MS: u64 = 1_000;
const MAX_RESPONSE_MS: u64 = 120_000;

/// What the exchange recorded before the write: `None` when it had no
/// evidence to record, otherwise the outbox generation the write produced.
type Recorded = Option<Option<i64>>;

fn exchange_outcome(
    outcome: &str,
    written: bool,
    recorded: Recorded,
    kind: Option<&str>,
    frame: Option<Value>,
    exit_code: Option<i32>,
) -> Result<Vec<u8>, String> {
    let mut r = McpStdioSessionResultV1::status("sent");
    r.payload = Some(serde_json::json!({
        "outcome": outcome,
        "written": written,
        "recorded": recorded.is_some(),
        "outbox_generation": recorded.flatten(),
        "event_kind": kind,
        "frame": frame,
        "exit_code": exit_code,
    }));
    encode(r)
}

/// The evidence write failed, so the message was not written.
fn record_failed(code: &str) -> Result<Vec<u8>, String> {
    let mut r = McpStdioSessionResultV1::status("sent");
    r.payload = Some(serde_json::json!({
        "outcome": "record_failed",
        "written": false,
        "recorded": false,
        "record_error": code,
    }));
    encode(r)
}

fn event_parts(event: SessionEvent) -> (&'static str, Value) {
    match event {
        SessionEvent::ChildResponse(frame) => ("child_response", frame),
        SessionEvent::ChildRequest(frame) => ("child_request", frame),
        SessionEvent::ChildNotification(frame) => ("child_notification", frame),
    }
}

/// Fused `send`: quiet edge, write, correlated response. The quiet edge is the
/// pre-write drain the proxy performs so a catalog change announced by the
/// child is seen before a guarded call is written; any frame seen first is
/// handed back unwritten (`boundary`) and the caller re-validates. Frames other
/// than the awaited response are returned, never buffered here, because the
/// proxy owns correlation of everything but its own response.
pub(super) fn exchange_locked(
    entry: &mut SessionEntry,
    message: &Value,
    exchange: &guard_contracts::McpStdioSessionExchangeV1,
) -> Result<Vec<u8>, String> {
    let Some(request_id) = message.get("id").filter(|id| !id.is_null()) else {
        return err_result("mcp_exchange_requires_request_id");
    };
    let quiet = Duration::from_millis(exchange.quiet_ms.min(MAX_QUIET_MS));
    match entry.session.next_event_quiet(quiet) {
        Ok(QuietEdge::Silent) => {}
        Ok(QuietEdge::Event(event)) => {
            let (kind, frame) = event_parts(event);
            return exchange_outcome("boundary", false, None, Some(kind), Some(frame), None);
        }
        Ok(QuietEdge::Busy) => {
            return err_result("mcp_exchange_quiet_edge_busy");
        }
        Err(guard_command::mcp_stdio_session::SessionReadError::Eof) => {
            return exchange_eof(&mut entry.child, false, None);
        }
    }
    let recorded: Recorded = match exchange.record.as_ref() {
        None => None,
        Some(record) => match crate::mcp_tool_call_record_op::record_tool_call(record) {
            Ok(done) => Some(done.outbox_generation),
            Err(code) => return record_failed(&code),
        },
    };
    if let Err(code) = entry.session.write(message) {
        return err_result(&code);
    }
    let remaining = Duration::from_millis(exchange.response_timeout_ms.min(MAX_RESPONSE_MS));
    match entry.session.next_event(remaining) {
        Ok(None) => exchange_outcome("timeout", true, recorded, None, None, None),
        Err(guard_command::mcp_stdio_session::SessionReadError::Eof) => {
            exchange_eof(&mut entry.child, true, recorded)
        }
        Ok(Some(SessionEvent::ChildResponse(frame))) if frame.get("id") == Some(request_id) => {
            exchange_outcome(
                "response",
                true,
                recorded,
                Some("child_response"),
                Some(frame),
                None,
            )
        }
        Ok(Some(event)) => {
            let (kind, frame) = event_parts(event);
            exchange_outcome("event", true, recorded, Some(kind), Some(frame), None)
        }
    }
}

fn exchange_eof(child: &mut Child, written: bool, recorded: Recorded) -> Result<Vec<u8>, String> {
    match child_exit_code(child) {
        Ok(code) => exchange_outcome("eof", written, recorded, None, None, code),
        Err(code) => err_result(&code),
    }
}
