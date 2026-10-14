//! The Cursor client's own answer for a resident's harness response.
//!
//! This reproduces `_emit_cursor_response` and `_cursor_reason` for the
//! allows, denials and reviews a resident answers, byte for byte as the
//! client's `print(json.dumps(response))` writes them. `_cursor_reason`
//! rewrites a review link through `live_approval_review_url`, which signs a
//! loopback link with the daemon auth token only when the client's
//! interpreter can import Guard; a response whose link the client may sign
//! is left to the client.
//!
//! A lone surrogate escape CPython's `json.loads` keeps is read as the
//! character [`pyjson::parse_mapping_lone_surrogates`] maps it onto and
//! written back as the `\udXXX` escape `json.dumps` writes.

use std::path::Path;

use guard_command::hook_adapter_value::{parse_python_json, OMap, OValue};
use guard_contracts::write_json_string;

use crate::claude_hook_bridge_render::py_strip;
use crate::hook_env_stamp::{dumps, json_string};
use crate::native_review_link::{review_url_stays_unsigned, OPEN_GUARD};
use crate::pyjson::{self, in_surrogate_plane};

/// `print(json.dumps({"permission": "allow"}))`.
pub(crate) const ALLOW_STDOUT: &str = "{\"permission\": \"allow\"}\n";
/// `_cursor_reason` when the response names no reason and no review link.
const DEFAULT_BLOCK_REASON: &str = "HOL Guard blocked this Cursor action.";
/// `_cursor_reason`'s lead when the response names a link but no reason.
const NEEDS_APPROVAL: &str = "HOL Guard needs approval for this Cursor action.";
const REVIEW_URL_KEYS: [&str; 3] = ["primary_approval_url", "approval_url", "guardApprovalUrl"];
const REASON_KEYS: [&str; 7] = [
    "reason",
    "stopReason",
    "systemMessage",
    "review_hint",
    "risk_summary",
    "why_now",
    "risk_headline",
];
const DECISION_REASON_KEYS: [&str; 4] = [
    "harness_message",
    "retry_instruction",
    "user_body",
    "user_title",
];

/// `json.loads(text)` as the bridge reads it, and whether the text held a
/// lone surrogate escape, which the value holds as its mapped character.
/// `None` when the port cannot read the text alike, or when a lone
/// surrogate sits beside a genuine character of the mapped range and the
/// two could no longer be told apart.
pub(crate) fn python_document(text: &str) -> Option<(OValue, bool)> {
    if let Ok(value) = parse_python_json(text) {
        return Some((value, false));
    }
    let parsed = pyjson::parse_mapping_lone_surrogates(text).ok()?;
    if !parsed.mapped || parsed.collision {
        return None;
    }
    let mut literal = String::new();
    dumps(&parsed.value, false, false, &mut literal);
    parse_python_json(&literal).ok().map(|value| (value, true))
}

/// `text`, compact `ensure_ascii` JSON of a value read by
/// [`python_document`], with each mapped character written back as the
/// lone `\udXXX` escape `json.dumps` writes for the surrogate.
pub(crate) fn unmapped_json(text: &str) -> Option<String> {
    let value = pyjson::parse(text).ok()?;
    let mut out = String::new();
    dumps(&value, true, true, &mut out);
    Some(out)
}

/// `value.strip()` for a non-blank string value.
fn stripped(value: Option<&OValue>) -> Option<&str> {
    let text = py_strip(value?.as_str()?);
    (!text.is_empty()).then_some(text)
}

/// `_cursor_review_url`: the first link the response names.
fn review_url(response: &OMap) -> Option<&str> {
    if let Some(url) = REVIEW_URL_KEYS
        .iter()
        .find_map(|key| stripped(response.get(key)))
    {
        return Some(url);
    }
    response
        .get("approval_requests")
        .and_then(OValue::as_list)?
        .iter()
        .find_map(|item| stripped(item.as_map()?.get("approval_url")))
}

/// `_cursor_reason`, or `None` when the client would show a link it signs
/// with Guard's Python only if its interpreter can import it, or when the
/// link holds a lone surrogate (`unmap`) the bridge cannot sign alike.
fn reason(response: &OMap, guard_home: &Path, unmap: bool) -> Option<String> {
    let hook_output = response.get("hookSpecificOutput").and_then(OValue::as_map);
    let decision = response.get("decision_v2_json").and_then(OValue::as_map);
    let reason = REASON_KEYS
        .iter()
        .map(|key| response.get(key))
        .chain(hook_output.map(|output| output.get("permissionDecisionReason")))
        .chain(
            DECISION_REASON_KEYS
                .iter()
                .filter_map(|key| decision.map(|decision| decision.get(key))),
        )
        .find_map(stripped);
    let Some(review_url) = review_url(response) else {
        return Some(reason.unwrap_or(DEFAULT_BLOCK_REASON).to_owned());
    };
    // `live_approval_review_url` then hands the link back unchanged.
    if (unmap && review_url.chars().any(in_surrogate_plane))
        || !review_url_stays_unsigned(review_url, guard_home)
    {
        return None;
    }
    let suffix = format!("{OPEN_GUARD} {review_url}.");
    Some(match reason {
        None => format!("{NEEDS_APPROVAL} {suffix}"),
        Some(reason) if reason.contains(review_url) => reason.to_owned(),
        Some(reason) => format!("{reason} {suffix}"),
    })
}

/// `print(json.dumps(response))` for the client's string-valued answer,
/// with mapped surrogates written back when `unmap` is set.
fn printed(fields: &[(&str, &str)], unmap: bool) -> String {
    let mut out = vec![b'{'];
    for (index, (name, value)) in fields.iter().enumerate() {
        if index > 0 {
            out.extend_from_slice(b", ");
        }
        write_json_string(name, &mut out);
        out.extend_from_slice(b": ");
        if unmap {
            out.extend_from_slice(json_string(value, true, true).as_bytes());
        } else {
            write_json_string(value, &mut out);
        }
    }
    out.extend_from_slice(b"}\n");
    String::from_utf8(out).expect("ensure_ascii output is ASCII")
}

/// The client's stdout and exit code for `response`, the harness response
/// the daemon would return for a hook the client names `event`, with
/// `guard_home` its `GUARD_HOME` and `unmap` whether `response` held a lone
/// surrogate, or `None` when the bridge cannot reproduce
/// the client's answer. This is `_emit_cursor_response` with
/// `_cursor_permission`: a review asks, which `beforeReadFile` and
/// `preToolUse` turn into a denial.
pub(crate) fn rendered(
    event: &str,
    response: &OMap,
    guard_home: &Path,
    unmap: bool,
) -> Option<(String, i32)> {
    let permission = match response.get_str("policy_action")? {
        "allow" | "warn" => return Some((ALLOW_STDOUT.to_owned(), 0)),
        "block" | "sandbox-required" => "deny",
        "review" | "require-reapproval" => "ask",
        _ => return None,
    };
    let reason = reason(response, guard_home, unmap)?;
    let event = py_strip(event).to_lowercase();
    if event == "beforereadfile" {
        let fields = [("permission", "deny"), ("user_message", reason.as_str())];
        return Some((printed(&fields, unmap), 2));
    }
    let permission = if event == "pretooluse" {
        "deny"
    } else {
        permission
    };
    let fields = [
        ("permission", permission),
        ("user_message", reason.as_str()),
        ("agent_message", reason.as_str()),
    ];
    Some((
        printed(&fields, unmap),
        if permission == "deny" { 2 } else { 0 },
    ))
}
