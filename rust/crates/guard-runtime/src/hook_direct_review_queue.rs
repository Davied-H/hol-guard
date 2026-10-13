//! The daemon's approval request for a reviewed `PreToolUse` it pauses.
//!
//! When neither a saved exact-action decision nor an approve-once answers a
//! review, `pause_native_pre_tool_for_approval`
//! (`hook_native_review_approval.py`) queues the action in the approval inbox
//! and pauses the hook with a link to it. This ports that last step for a
//! home whose blocked-request mode is `ask`:
//!
//! - `queue_native_pre_tool_review`, with the request the review-request
//!   builder derives from the facts the daemon published, written by the same
//!   `add_native_review_approval_request` store operation under the shared
//!   storage gate;
//! - `render_pre_tool_review` (`hook_fail_closed.py`), with the approval link
//!   `native_review_reason` (`approval_link_output.py`) signs;
//! - the `prompted` and `approval_center_url` marks the daemon records the
//!   activity with.
//!
//! Every other shape defers, so the daemon still pauses the hook: a
//! safe-alternative home, a missing fact, Claude Code (whose permission
//! notice the daemon records), a package review the daemon may settle, and
//! any request or write the resident could not reproduce.

use super::consume::{repair_store_permissions, storage_gate};
use super::review_request::{build, ExactKeys, RequestInput};
use super::{Context, HookDirectDefer, ENVELOPE_BYTES, ESCAPE_FACTOR};
use crate::guard_store_approval_request::rewrite_approval_url;
use crate::local_store_read::STORE_FILE_NAME;
use guard_command::hook_responses::{pre_tool_review, Object};
use guard_contracts::{
    GuardStoreRequestV1, NativeExactActionQueryV1, GUARD_STORE_REQUEST_SCHEMA,
    HOOK_RENDER_MAX_BYTES,
};
use serde_json::{json, Map, Value};
use std::path::Path;

const WRITE_METHOD: &str = "add_native_review_approval_request";
/// `asks_for_approval`: the mode that pauses the hook for the inbox.
const ASK_MODE: &str = "ask";
/// `PACKAGE_REVIEW_REASON`: a review `native_package_review_response` may
/// settle before anything is queued.
const PACKAGE_REVIEW_REASON: &str = "native_package_review";
/// The harness whose paused review also records a permission notice.
const CLAUDE_CODE: &str = "claude-code";
/// `_REVIEW_DEFAULT_REASON` (`hook_fail_closed.py`).
const DEFAULT_REASON: &str = "HOL Guard requires review before this action can execute.";
/// A hook waits this long for a busy store before the daemon takes over.
const BUSY_TIMEOUT_MS: u64 = 250;

/// The facts a queued review needs, or `None` when the daemon pauses it.
struct Facts<'a> {
    origin: &'a str,
    oauth_source: &'a str,
    host_cwd: &'a str,
    environment: &'a std::collections::BTreeMap<String, String>,
}

/// The paused review response for an action the resident queued itself.
pub(super) fn answer(
    context: &Context<'_>,
    result: &Object,
    receipt: Option<&Value>,
    exact: &NativeExactActionQueryV1,
    token: &Result<String, &'static str>,
) -> Result<Value, HookDirectDefer> {
    let facts = facts(context, result).ok_or(HookDirectDefer::ReviewQueue)?;
    let review_binding = crate::native_exact_action_op::review_binding_for(exact, receipt);
    let request_id = request_id().ok_or(HookDirectDefer::ReviewQueue)?;
    let input = RequestInput {
        harness: context.harness,
        payload: context.recorded_payload,
        workspace: context.workspace,
        home_dir: context.home_dir,
        environment: facts.environment,
        host_cwd: Some(facts.host_cwd),
        request_id: &request_id,
        approval_center_url: facts.origin,
        review_binding: review_binding.as_deref(),
        exact: match token {
            Ok(token) => ExactKeys::Token(token),
            Err(reason) => ExactKeys::OnceOnly(reason),
        },
    };
    let request = build(&input, result, receipt).ok_or(HookDirectDefer::ReviewQueue)?;
    let approval_url = request
        .get("approval_url")
        .and_then(Value::as_str)
        .ok_or(HookDirectDefer::ReviewQueue)?
        .to_owned();
    let reason = match result.get("reason") {
        Some(Value::String(text)) if !text.is_empty() => text.as_str(),
        _ => DEFAULT_REASON,
    };
    let stored_id = write(context, facts.oauth_source, request)?;
    // A pending request for the same action keeps its id, so a pause the
    // resident cannot render leaves the daemon to queue the same request.
    let approval_url = rewrite_approval_url(&approval_url, &stored_id);
    let auth_token =
        crate::daemon_policy_authority::load_guard_daemon_auth_token(Path::new(context.guard_home));
    let linked = crate::native_review_link::native_review_reason(
        &canonical_harness(context.harness),
        reason,
        &approval_url,
        auth_token.as_deref(),
        now_micros().ok_or(HookDirectDefer::ReviewQueue)?,
    )
    .ok_or(HookDirectDefer::ReviewQueue)?;
    respond(
        context.harness,
        result,
        &stored_id,
        &approval_url,
        &linked,
        facts.origin,
    )
    .ok_or(HookDirectDefer::ReviewQueue)
}

/// The published facts for an `ask` review the resident may queue.
fn facts<'a>(context: &Context<'a>, result: &Object) -> Option<Facts<'a>> {
    let binding = context.binding;
    let review = &binding.review;
    if review.blocked_request_mode.as_deref() != Some(ASK_MODE)
        || context.harness == CLAUDE_CODE
        || result.get("reason_code").and_then(Value::as_str) == Some(PACKAGE_REVIEW_REASON)
    {
        return None;
    }
    Some(Facts {
        origin: review.approval_center_origin.as_deref()?,
        oauth_source: review.review_oauth_source.as_deref()?,
        host_cwd: review.review_host_cwd.as_deref()?,
        environment: &binding.exact_action_environment.as_ref()?.0,
    })
}

/// `add_approval_request` through the daemon's store operation: the stored
/// request id, which is an earlier pending request's for the same action.
fn write(
    context: &Context<'_>,
    oauth_source: &str,
    request: Value,
) -> Result<String, HookDirectDefer> {
    let now = super::super::lifecycle::utc_now_isoformat().ok_or(HookDirectDefer::ReviewQueue)?;
    let guard_home = Path::new(context.guard_home);
    let _gate = storage_gate(guard_home).map_err(|_| HookDirectDefer::ReviewQueue)?;
    let mut args = Map::new();
    args.insert("request".to_owned(), request);
    args.insert("now".to_owned(), json!(now));
    let store_request = GuardStoreRequestV1 {
        schema: GUARD_STORE_REQUEST_SCHEMA.to_owned(),
        request_id: "direct-hook-review-queue".to_owned(),
        store_path: guard_home
            .join(STORE_FILE_NAME)
            .to_string_lossy()
            .into_owned(),
        guard_home: context.guard_home.to_owned(),
        method: WRITE_METHOD.to_owned(),
        source: oauth_source.to_owned(),
        busy_timeout_ms: BUSY_TIMEOUT_MS,
        args,
    };
    let written = crate::guard_store_op::evaluate(&store_request).map(|(payload, _)| payload);
    repair_store_permissions(guard_home);
    match written {
        Ok(Value::String(request_id)) if !request_id.is_empty() => Ok(request_id),
        _ => Err(HookDirectDefer::ReviewQueue),
    }
}

/// `render_pre_tool_review` for the queued request, marked as the daemon
/// marks a paused review, or `None` when the daemon's render request could
/// exceed its size limit.
fn respond(
    harness: &str,
    result: &Object,
    request_id: &str,
    approval_url: &str,
    linked_reason: &str,
    approval_center_url: &str,
) -> Option<Value> {
    let mut approval = Object::new();
    approval.insert("request_id".to_owned(), json!(request_id));
    approval.insert("approval_url".to_owned(), json!(approval_url));
    let encoded = serde_json::to_vec(result).ok()?.len()
        + serde_json::to_vec(&approval).ok()?.len()
        + linked_reason.len()
        + harness.len();
    if encoded * ESCAPE_FACTOR + ENVELOPE_BYTES > HOOK_RENDER_MAX_BYTES {
        return None;
    }
    let mut response = pre_tool_review(harness, result, Some(&approval), Some(linked_reason));
    response.insert("prompted".to_owned(), json!(true));
    response.insert("approval_center_url".to_owned(), json!(approval_center_url));
    Some(Value::Object(response))
}

/// `canonical_harness` (`hook_fail_closed.py`).
fn canonical_harness(harness: &str) -> String {
    crate::guard_store_json::py_strip(harness)
        .to_lowercase()
        .replace('_', "-")
}

/// `uuid.uuid4().hex`.
fn request_id() -> Option<String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).ok()?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Some(hex::encode(bytes))
}

fn now_micros() -> Option<i64> {
    let micros = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_micros();
    i64::try_from(micros).ok()
}

#[cfg(test)]
#[path = "hook_direct_review_queue_tests.rs"]
mod tests;
