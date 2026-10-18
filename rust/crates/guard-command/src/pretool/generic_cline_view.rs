//! Cline 4.1 sends each tool call twice, a typed `tool_call` and a
//! compatibility `preToolUse`, under its own event label (`tool_call`).
//! Prepare reconciles both onto `tool_name` and `tool_input` and refuses
//! copies that disagree, but keeps them so the receipt records the call as
//! sent. The generic extractor reads every name and event key, so Cline's
//! spellings (`read_files` beside `read_file`, `tool_call` beside
//! `PreToolUse`) would read as two calls. Evaluation judges a view without
//! the copies prepare has already reconciled.

use crate::hook_adapter_cline_tables::EVENT_NAMES;
use serde_json::Value;

const EVENT_KEYS: [&str; 6] = [
    "hook_event_name",
    "hookEventName",
    "hook_name",
    "hookName",
    "event",
    "eventName",
];
const WIRE_COPIES: [(&str, &str); 4] = [
    ("tool_call", "name"),
    ("preToolUse", "toolName"),
    ("tool_result", "name"),
    ("postToolUse", "toolName"),
];

/// The prepared payload without Cline's reconciled duplicates, or `None`
/// when nothing needs to change.
pub(super) fn evaluated_view(payload: &Value) -> Option<Value> {
    let root = payload.as_object()?;
    // Prepare always writes the canonical `hook_event_name`; without it the
    // payload was not prepared and stays as sent, so conflicts fail closed.
    let event = root.get("hook_event_name")?.as_str()?;
    let mut view = root.clone();
    for key in EVENT_KEYS {
        let Some(label) = root.get(key).and_then(Value::as_str) else {
            continue;
        };
        if label != event && cline_event(label) == Some(event) {
            view.insert(key.to_owned(), Value::from(event));
        }
    }
    // Prepare records the name it reconciled as `cline_tool_name`. Only a
    // copy naming that same tool is dropped; any other copy stays and the
    // extractor still refuses the conflict.
    let reconciled = root
        .get("tool_input")
        .and_then(Value::as_object)
        .and_then(|input| input.get("cline_tool_name"))
        .and_then(Value::as_str);
    if let Some(reconciled) = reconciled {
        for (key, name_key) in WIRE_COPIES {
            let named = root
                .get(key)
                .and_then(Value::as_object)
                .and_then(|copy| copy.get(name_key))
                .and_then(Value::as_str)
                .map(str::trim);
            if named == Some(reconciled) {
                view.remove(key);
            }
        }
    }
    if view == *root {
        None
    } else {
        Some(Value::Object(view))
    }
}

fn cline_event(label: &str) -> Option<&'static str> {
    let lookup = label.to_ascii_lowercase().replace('-', "_");
    EVENT_NAMES
        .iter()
        .find(|(alias, _)| *alias == lookup)
        .map(|(_, canonical)| *canonical)
}
