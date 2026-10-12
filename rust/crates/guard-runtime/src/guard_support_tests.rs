//! Parity vectors recorded from the legacy Python (`guard/config.py` writers and
//! coercers, `cli/commands_support_prompts.py` copy builders) before deletion.

use crate::guard_support_op::run_subop;
use flate2::read::GzDecoder;
use serde_json::{json, Value};
use std::io::Read;

const VECTORS: &[u8] = include_bytes!("../tests/fixtures/guard_support_vectors.json.gz");

fn vectors() -> Value {
    let mut text = String::new();
    GzDecoder::new(VECTORS)
        .read_to_string(&mut text)
        .expect("gunzip vectors");
    serde_json::from_str(&text).expect("vector json")
}

fn items<'a>(vectors: &'a Value, key: &str) -> &'a Vec<Value> {
    vectors[key]
        .as_array()
        .unwrap_or_else(|| panic!("{key} vectors"))
}

#[test]
fn toml_render_matches_recorded_python() {
    let vectors = vectors();
    let cases = items(&vectors, "toml");
    assert!(cases.len() >= 15);
    for case in cases {
        let actual = run_subop("toml_render", &json!({"config": case["config"]})).unwrap();
        assert_eq!(actual, case["expected"], "config {}", case["config"]);
    }
}

#[test]
fn toml_render_escapes_astral_characters_as_valid_toml() {
    let actual = run_subop(
        "toml_render",
        &json!({"config": {"k": "a\u{1F600}b", "\u{1F600}": 1}}),
    )
    .unwrap();
    assert_eq!(actual, "k = \"a\\U0001f600b\"\n\"\\U0001f600\" = 1\n");
}

#[test]
fn coerce_setting_matches_recorded_python() {
    let vectors = vectors();
    let max_wait = &vectors["coerce_setting"]["max_wait_seconds"];
    let cases = vectors["coerce_setting"]["cases"]
        .as_array()
        .expect("cases");
    assert!(cases.len() >= 1000);
    for case in cases {
        let actual = run_subop(
            "coerce_setting",
            &json!({"key": case["key"], "value": case["value"], "max_wait_seconds": max_wait}),
        )
        .unwrap();
        assert_eq!(
            actual, case["expected"],
            "{} = {}",
            case["key"], case["value"]
        );
    }
}

#[test]
fn coerce_loaded_matches_recorded_python() {
    let vectors = vectors();
    let cases = items(&vectors, "coerce_loaded");
    assert!(cases.len() >= 200);
    let batch: Vec<&Value> = cases.iter().map(|case| &case["item"]).collect();
    let actual = run_subop("coerce_loaded", &json!({"items": batch})).unwrap();
    let actual = actual.as_array().expect("batch");
    assert_eq!(actual.len(), cases.len());
    for (case, actual) in cases.iter().zip(actual) {
        assert_eq!(actual, &case["expected"], "item {}", case["item"]);
    }
}

#[test]
fn native_reason_matches_recorded_python() {
    let vectors = vectors();
    let cases = items(&vectors, "native_reason");
    assert!(cases.len() >= 1000);
    for case in cases {
        let actual = run_subop(
            "native_reason",
            &json!({"artifact": case["artifact"], "response": case["response"]}),
        )
        .unwrap();
        assert_eq!(
            actual, case["expected"],
            "{} / {}",
            case["artifact"], case["response"]
        );
    }
}

#[test]
fn harness_copy_matches_recorded_python() {
    let vectors = vectors();
    let cases = items(&vectors, "harness_copy");
    assert!(cases.len() >= 800);
    for case in cases {
        let base = |extra: Value| {
            let mut payload = json!({
                "artifact": case["artifact"],
                "event_name": case["event_name"],
                "policy_action": case["policy_action"],
                "native_reason": case["native_reason"],
            });
            payload
                .as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            payload
        };
        let label = format!(
            "{} {} {}",
            case["artifact"], case["event_name"], case["policy_action"]
        );
        assert_eq!(
            run_subop("claude_system_message", &base(json!({}))).unwrap(),
            case["claude_system_message"],
            "system {label}"
        );
        for (name, claude) in [("claude", true), ("other", false)] {
            assert_eq!(
                run_subop(
                    "claude_additional_context",
                    &base(json!({"claude_harness": claude}))
                )
                .unwrap(),
                case["claude_additional_context"][name],
                "context {name} {label}"
            );
        }
        assert_eq!(
            run_subop(
                "codex_block_message",
                &json!({"policy_action": case["policy_action"], "native_reason": case["native_reason"]})
            )
            .unwrap(),
            case["codex_block_message"],
            "codex {label}"
        );
    }
}

#[test]
fn unknown_subop_is_rejected() {
    assert_eq!(
        run_subop("nope", &json!({})).unwrap_err(),
        "unknown_guard_support_subop:nope"
    );
}
