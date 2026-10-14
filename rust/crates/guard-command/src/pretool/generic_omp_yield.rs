//! Typed OMP result reports: file references describe work, never execute it.
use super::{strict_tool_input, OmpContext};
use serde_json::{json, Map, Value};

const MAX_TASK_DATA_DEPTH: usize = 8;

pub(super) fn signal_payload(payload: &Value) -> Option<Value> {
    if payload.get("tool_name")?.as_str()? != "yield"
        || serde_json::to_string(payload).ok()?.len() > 16 * 1024
    {
        return None;
    }
    let input = strict_tool_input(payload)?;
    if input.is_empty()
        || !input
            .keys()
            .all(|key| matches!(key.as_str(), "data" | "error" | "type"))
    {
        return None;
    }
    if input.get("error").is_some_and(|value| !value.is_string())
        || input.get("type").is_some_and(|value| {
            !value.is_string()
                && !value.as_array().is_some_and(|items| {
                    !items.is_empty() && items.len() <= 16 && items.iter().all(Value::is_string)
                })
        })
    {
        return None;
    }
    let mut projected_input = input.clone();
    if let Some(data) = input.get("data") {
        if let Some(report) = data.as_object() {
            let (typed, task): (Map<String, Value>, Map<String, Value>) =
                report.clone().into_iter().partition(|(key, _)| {
                    matches!(
                        key.as_str(),
                        "summary" | "report" | "architecture" | "contents" | "files"
                    )
                });
            if !task.is_empty() && !plain_task_data(&Value::Object(task)) {
                return None;
            }
            if !typed.iter().all(|(key, value)| match key.as_str() {
                "summary" | "report" | "architecture" | "contents" => value.is_string(),
                "files" => value.as_array().is_some_and(|files| {
                    files.len() <= 24
                        && files.iter().all(|file| {
                            file.as_object().is_some_and(|record| {
                                record
                                    .get("path")
                                    .and_then(Value::as_str)
                                    .is_some_and(|path| !path.is_empty())
                                    && record.iter().all(|(key, value)| {
                                        matches!(key.as_str(), "path" | "description")
                                            && value.is_string()
                                    })
                            })
                        })
                }),
                _ => false,
            }) {
                return None;
            }
            if let Some(files) = report.get("files").and_then(Value::as_array) {
                // Preserve every referenced path for the ordinary sensitive-file
                // and symlink proof. The raw report still reaches output scanning.
                projected_input.get_mut("data")?["files"] =
                    Value::Array(files.iter().map(|file| file["path"].clone()).collect());
            }
        } else if !data.is_string() && !plain_task_data(data) {
            return None;
        }
    } else if !input.contains_key("error") {
        return None;
    }
    let mut projected = payload.clone();
    for alias in super::super::extract::EMBEDDED_ARGUMENT_KEYS {
        if projected.get(alias).is_some() {
            projected[alias] = Value::Object(projected_input.clone());
        }
    }
    Some(projected)
}

/// Result fields a task names for itself, such as those a parent's output
/// schema asks for, are data handed back to the parent agent; Oh My Pi runs
/// nothing from them. They are accepted only when no key at any depth names
/// tool arguments and the ordinary signal extractor finds no command, path,
/// URL, package, prompt, request or environment reference in them.
fn plain_task_data(value: &Value) -> bool {
    fn keys_are_plain(value: &Value, depth: usize) -> bool {
        match value {
            Value::Object(record) => {
                depth < MAX_TASK_DATA_DEPTH
                    && record.iter().all(|(key, value)| {
                        !super::super::extract::EMBEDDED_ARGUMENT_KEYS.contains(&key.as_str())
                            && !matches!(key.as_str(), "tool_name" | "toolName")
                            && keys_are_plain(value, depth + 1)
                    })
            }
            Value::Array(items) => {
                depth < MAX_TASK_DATA_DEPTH
                    && items.iter().all(|item| keys_are_plain(item, depth + 1))
            }
            _ => true,
        }
    }
    if !keys_are_plain(value, 0) {
        return false;
    }
    // `data` itself reads as a request body, so the probe wraps the fields
    // under a neutral key.
    let probe = json!({"tool_name": "yield", "tool_input": {"result": value}});
    super::super::extract::extract_generic_signals(&probe).is_ok_and(|signals| {
        signals.command.is_none()
            && !signals.package_present
            && signals.path_values.is_empty()
            && signals.url_values.is_empty()
            && !signals.request_body_or_method
            && !signals.business_action_present
            && !signals.prompt_present
            && !signals.env_reference
    })
}

pub(super) fn references_are_readable(paths: &[String], context: &OmpContext<'_>) -> bool {
    paths.iter().all(|path| {
        if path.contains("://") || path.trim() != path || path.chars().any(char::is_control) {
            return false;
        }
        let result = crate::pretool::generic::evaluate_envelope(
            context.harness,
            context.event,
            &json!({"tool_name":"read", "tool_input":{"path":path}}),
            context.controls,
            context.deadline,
            context.path,
            context.execution_environment,
            true,
        );
        result.minimum_action == "allow" && !result.action.sensitive_target
    })
}
