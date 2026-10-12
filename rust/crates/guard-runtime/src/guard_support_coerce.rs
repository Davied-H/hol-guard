//! Editable-setting validation and loaded-value coercion. Ports the former
//! `guard/config.py` write-path coercers; messages are shown to users and are
//! pinned by vectors recorded from that Python.

use guard_command::action_lattice::normalize_guard_action_result;
use guard_command::effect_decision::GuardAction;
use guard_command::local_supply_chain::VALID_RISK_ACTION_KEYS;
use serde_json::{json, Map, Value};

use crate::guard_config_coerce as coerce;
use crate::guard_support_text::py_strip;
use crate::package_authority_config::{
    coerce_harness_risk_actions, coerce_security_level, VALID_SECURITY_LEVELS,
};

const MODES: [&str; 3] = ["observe", "prompt", "enforce"];
const SURFACE_POLICIES: [&str; 4] = [
    "attention-aware",
    "auto-open-once",
    "native-only",
    "approval-center",
];
const SEVERITIES: [&str; 5] = ["info", "low", "medium", "high", "critical"];
const REDACTION_LEVELS: [&str; 3] = ["full", "partial", "none"];
const BOOLEAN_KEYS: [&str; 4] = ["desktop_notifications", "telemetry", "sync", "billing"];

type Outcome = Result<Value, (String, bool)>;

fn fail(message: &str) -> Outcome {
    Err((message.to_owned(), false))
}

fn is_action(value: &Value) -> bool {
    normalize_guard_action_result(value, GuardAction::Review).recognized()
}

fn choice(value: &Value, allowed: &[&str]) -> bool {
    value.as_str().is_some_and(|text| allowed.contains(&text))
}

/// A JSON integer (not a boolean or float) inside `0..=maximum`.
fn bounded(value: &Value, maximum: i64) -> bool {
    value
        .as_i64()
        .is_some_and(|number| (0..=maximum).contains(&number))
}

fn flag(value: &Value, message: &str) -> Outcome {
    if value.is_boolean() {
        Ok(value.clone())
    } else {
        fail(message)
    }
}

fn risk_actions(value: &Value) -> Outcome {
    let Some(table) = value.as_object() else {
        return fail("Risk actions must be a table.");
    };
    for (name, action) in table {
        if !VALID_RISK_ACTION_KEYS.contains(&name.as_str()) || !is_action(action) {
            return fail("Invalid Guard risk action.");
        }
    }
    Ok(value.clone())
}

fn harness_risk_actions(value: &Value) -> Outcome {
    let Some(table) = value.as_object() else {
        return fail("Harness risk actions must be a table.");
    };
    for (harness, actions) in table {
        if py_strip(harness).is_empty() {
            return fail("Invalid Guard harness.");
        }
        risk_actions(actions)?;
    }
    Ok(value.clone())
}

pub(crate) fn coerce_setting(key: &str, value: &Value, max_wait_seconds: i64) -> Outcome {
    let valid = |ok: bool, message: &str| if ok { Ok(value.clone()) } else { fail(message) };
    match key {
        "presentation_mode_explicit" => {
            flag(value, "presentation_mode_explicit must be true or false.")
        }
        "presentation_schema_version" => valid(
            value == &Value::Bool(true) || value.as_f64() == Some(1.0),
            "Unsupported presentation schema version.",
        ),
        "mode" => valid(choice(value, &MODES), "Invalid Guard mode."),
        "protection_posture_explicit" => {
            flag(value, "protection_posture_explicit must be true or false.")
        }
        "watch_auto_revert_hours" => valid(
            bounded(value, 168),
            "Watch auto-revert hours must be between 0 and 168.",
        ),
        "security_level" => valid(
            choice(value, &VALID_SECURITY_LEVELS),
            "Invalid Guard security level.",
        ),
        "risk_actions" => risk_actions(value),
        "harness_risk_actions" => harness_risk_actions(value),
        _ if key.ends_with("_action") => valid(is_action(value), "Invalid Guard action."),
        "approval_surface_policy" if choice(value, &SURFACE_POLICIES) => {
            let policy = value.as_str().unwrap_or_default();
            Ok(Value::String(
                if policy == "auto-open-once" {
                    "attention-aware"
                } else {
                    policy
                }
                .to_owned(),
            ))
        }
        "approval_surface_policy" => fail("Invalid approval surface policy."),
        "blocked_request_mode" => valid(
            choice(value, &["safe-alternative", "ask"]),
            "Choose safe-alternative or ask for blocked requests.",
        ),
        "approval_browser_delay_seconds" => valid(
            bounded(value, 300),
            "Browser attention delay must be between 0 and 300 seconds.",
        ),
        "approval_browser_immediate_severity" => valid(
            choice(value, &SEVERITIES),
            "Invalid immediate browser attention severity.",
        ),
        "approval_wait_timeout_seconds" => valid(
            bounded(value, max_wait_seconds),
            &format!("Approval wait timeout must be between 0 and {max_wait_seconds} seconds."),
        ),
        _ if BOOLEAN_KEYS.contains(&key) => flag(value, &format!("{key} must be true or false.")),
        "update_channel" => valid(
            choice(value, &["stable", "alpha"]),
            "Update channel must be stable or alpha.",
        ),
        "receipt_redaction_level" if !choice(value, &REDACTION_LEVELS) => {
            // The caller appends the Python repr of the rejected value.
            Err(("Invalid receipt redaction level".to_owned(), true))
        }
        "receipt_redaction_level" => Ok(value.clone()),
        _ => Err((format!("Unsupported Guard setting: {key}"), false)),
    }
}

fn static_mode(value: &str) -> &'static str {
    MODES
        .iter()
        .find(|mode| **mode == value)
        .copied()
        .unwrap_or("observe")
}

fn action_fallback(value: Option<&Value>) -> GuardAction {
    value.map_or(GuardAction::RequireReapproval, |fallback| {
        normalize_guard_action_result(fallback, GuardAction::RequireReapproval).action
    })
}

/// One loaded value: `{kind, value, fallback}` -> its coerced form.
pub(crate) fn coerce_loaded(item: &Map<String, Value>) -> Result<Value, String> {
    let value = item.get("value").filter(|value| !value.is_null());
    let fallback = item.get("fallback");
    let kind = item
        .get("kind")
        .and_then(Value::as_str)
        .ok_or("missing_kind")?;
    Ok(match kind {
        "mode" => json!(coerce::loaded_mode(
            value,
            static_mode(fallback.and_then(Value::as_str).unwrap_or(""))
        )),
        "security_level" => json!(coerce_security_level(value)),
        "action" => json!(coerce::action_or_default(value, action_fallback(fallback)).as_str()),
        "bool" => json!(coerce::loaded_bool(value)),
        "receipt_redaction_level" => json!(coerce::receipt_redaction_level(value)),
        "risk_actions" => json!(coerce::risk_action_map(value)),
        "harness_risk_actions" => json!(coerce_harness_risk_actions(value)),
        other => return Err(format!("unknown_loaded_kind:{other}")),
    })
}
