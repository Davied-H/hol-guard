//! `GuardSupport` resident op: subop-multiplexed pure helpers for settings
//! writes and hook copy. The caller must not substitute a Python evaluator.

use guard_contracts::{
    GuardSupportRequestV1, GuardSupportResultV1, GUARD_SUPPORT_REQUEST_SCHEMA,
    GUARD_SUPPORT_RESULT_SCHEMA,
};
use serde_json::{json, Map, Value};

use crate::guard_support_coerce::{coerce_loaded, coerce_setting};
use crate::guard_support_reason::{
    claude_additional_context, claude_system_message, codex_block_message, native_reason, Artifact,
};
use crate::guard_support_text::str_field;
use crate::guard_support_toml::render_config;

fn object<'a>(payload: &'a Value, key: &str) -> Result<&'a Map<String, Value>, String> {
    payload
        .get(key)
        .and_then(Value::as_object)
        .ok_or_else(|| format!("missing_{key}"))
}

fn text<'a>(payload: &'a Value, key: &str) -> Result<&'a str, String> {
    payload
        .as_object()
        .and_then(|map| str_field(map, key))
        .ok_or_else(|| format!("missing_{key}"))
}

fn optional_text(value: Option<String>) -> Value {
    value.map_or(Value::Null, Value::String)
}

pub(crate) fn run_subop(subop: &str, payload: &Value) -> Result<Value, String> {
    Ok(match subop {
        "toml_render" => Value::String(render_config(
            payload.get("config").ok_or("missing_config")?,
        )?),
        "coerce_setting" => {
            let max_wait = payload
                .get("max_wait_seconds")
                .and_then(Value::as_i64)
                .ok_or("missing_max_wait_seconds")?;
            match coerce_setting(
                text(payload, "key")?,
                payload.get("value").unwrap_or(&Value::Null),
                max_wait,
            ) {
                Ok(value) => json!({"ok": value}),
                Err((message, with_repr)) => json!({"error": message, "repr": with_repr}),
            }
        }
        "coerce_loaded" => {
            let items = payload
                .get("items")
                .and_then(Value::as_array)
                .ok_or("missing_items")?;
            let coerced: Result<Vec<Value>, String> = items
                .iter()
                .map(|item| coerce_loaded(item.as_object().ok_or("invalid_item")?))
                .collect();
            Value::Array(coerced?)
        }
        "native_reason" => {
            let artifact =
                Artifact::from_value(payload.get("artifact").ok_or("missing_artifact")?)?;
            Value::String(native_reason(&artifact, object(payload, "response")?))
        }
        "claude_additional_context" | "claude_system_message" | "codex_block_message" => {
            harness_copy(subop, payload)?
        }
        other => return Err(format!("unknown_guard_support_subop:{other}")),
    })
}

fn harness_copy(subop: &str, payload: &Value) -> Result<Value, String> {
    let policy_action = text(payload, "policy_action")?;
    let reason = text(payload, "native_reason")?;
    if subop == "codex_block_message" {
        return Ok(optional_text(codex_block_message(policy_action, reason)));
    }
    let artifact = Artifact::from_value(payload.get("artifact").ok_or("missing_artifact")?)?;
    let event_name = text(payload, "event_name")?;
    Ok(optional_text(if subop == "claude_system_message" {
        claude_system_message(event_name, policy_action, &artifact, reason)
    } else {
        let claude = payload
            .get("claude_harness")
            .and_then(Value::as_bool)
            .ok_or("missing_claude_harness")?;
        claude_additional_context(claude, event_name, policy_action, &artifact, reason)
    }))
}

pub(crate) fn evaluate_guard_support(request: &GuardSupportRequestV1) -> Result<Vec<u8>, String> {
    if request.schema != GUARD_SUPPORT_REQUEST_SCHEMA {
        return Err(format!("schema_mismatch:{}", request.schema));
    }
    let result = run_subop(&request.subop, &request.payload)?;
    crate::encode_response(&GuardSupportResultV1 {
        schema: GUARD_SUPPORT_RESULT_SCHEMA.to_owned(),
        result: Some(result),
    })
}
