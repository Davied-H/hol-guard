//! CLI hook input compatibility normalization in one native request.

use serde_json::{json, Value};

const INVALID: &str = "native_runner_authority_cli_support_invalid";

fn strip(value: &str) -> &str {
    value.trim_matches(|character: char| {
        character.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&character)
    })
}

fn argument(value: &Value) -> Value {
    if let Some(value) = value.as_str() {
        let stripped = strip(value);
        if stripped.is_empty() {
            return Value::Null;
        }
        if let Ok(parsed) = serde_json::from_str::<Value>(stripped) {
            if parsed.is_object() || parsed.is_array() || parsed.is_string() {
                return parsed;
            }
        }
        return json!(stripped);
    }
    value.clone()
}

fn arguments(values: &Value) -> Result<Value, &'static str> {
    let values = values.as_array().ok_or(INVALID)?;
    Ok(values
        .iter()
        .map(argument)
        .find(|value| !value.is_null())
        .unwrap_or(Value::Null))
}

fn first(value: &Value, expected: &Value) -> Value {
    let expected = expected.as_str().map(strip);
    let Some(calls) = value.as_array() else {
        return json!([null, null]);
    };
    let mut fallback = None;
    for call in calls {
        let Some(name) = call
            .get("name")
            .and_then(Value::as_str)
            .filter(|v| !strip(v).is_empty())
        else {
            continue;
        };
        let name = strip(name);
        let result = json!([name, argument(call.get("args").unwrap_or(&Value::Null))]);
        if expected.is_none_or(|expected| expected == name) {
            return result;
        }
        if fallback.is_none() {
            fallback = Some(result);
        }
    }
    fallback.unwrap_or_else(|| json!([null, null]))
}

pub(crate) fn evaluate(operation: &str, params: &Value) -> Result<Value, &'static str> {
    match operation {
        "normalize_argument" => Ok(argument(params.get("value").ok_or(INVALID)?)),
        "normalize_arguments" => arguments(params.get("values").ok_or(INVALID)?),
        "first_tool_call" => Ok(first(
            params.get("value").ok_or(INVALID)?,
            params.get("expected").unwrap_or(&Value::Null),
        )),
        "normalize_payload" => {
            let payload = params
                .get("payload")
                .and_then(Value::as_object)
                .ok_or(INVALID)?;
            let mut normalized = payload.clone();
            for (source, target) in [
                ("artifactId", "artifact_id"),
                ("artifactHash", "artifact_hash"),
                ("artifactName", "artifact_name"),
                ("changedCapabilities", "changed_capabilities"),
                ("hookEventName", "hook_event_name"),
                ("hookName", "hook_name"),
                ("preExecutionResult", "pre_execution_result"),
                ("policyAction", "policy_action"),
                ("sourceScope", "source_scope"),
                ("toolName", "tool_name"),
                ("userOverride", "user_override"),
            ] {
                if !normalized.contains_key(target) {
                    if let Some(value) = payload.get(source) {
                        normalized.insert(target.to_owned(), value.clone());
                    }
                }
            }
            if !normalized.contains_key("tool_name") || !normalized.contains_key("tool_input") {
                let call = first(
                    payload.get("toolCalls").unwrap_or(&Value::Null),
                    normalized.get("tool_name").unwrap_or(&Value::Null),
                );
                for (index, key) in [(0, "tool_name"), (1, "tool_input")] {
                    if !normalized.contains_key(key) && !call[index].is_null() {
                        normalized.insert(key.to_owned(), call[index].clone());
                    }
                }
            }
            let value = arguments(&json!([
                normalized.get("tool_input"),
                normalized.get("arguments"),
                payload.get("toolArgs"),
                payload.get("toolInput")
            ]))?;
            if !value.is_null() {
                normalized.insert("tool_input".to_owned(), value.clone());
                normalized.insert("arguments".to_owned(), value);
            }
            if params.get("harness").and_then(Value::as_str) == Some("kimi") {
                if let Some(parts) = normalized.get("prompt").and_then(Value::as_array) {
                    let texts: Vec<&str> = parts
                        .iter()
                        .filter_map(|part| part.get("text").and_then(Value::as_str))
                        .collect();
                    if !texts.is_empty() {
                        normalized.insert("prompt".to_owned(), json!(texts.join("\n")));
                    }
                } else {
                    normalized.entry("prompt").or_insert(Value::Null);
                }
            }
            Ok(Value::Object(normalized))
        }
        _ => Err(INVALID),
    }
}
