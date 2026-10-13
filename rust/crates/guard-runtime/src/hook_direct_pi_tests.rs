use super::{
    allowed_payload, allowing_lane, deferred, drain, lane, post_tool_payload, prompt_payload,
    run_as, HOME,
};
use crate::hook_direct::pi::{source_ref_external_allowed, structured_mediation};
use serde_json::{json, Value};

const VECTORS: &str = include_str!("../testdata/hook_direct_pi/pi_vectors.json");

fn vectors(group: &str) -> Vec<Value> {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    let group = vectors[group].as_array().unwrap().clone();
    assert!(!group.is_empty());
    group
}

#[test]
fn the_source_ref_flag_follows_the_recorded_daemon_rule() {
    for vector in vectors("source_ref_external_allowed") {
        let harness = vector["harness"].as_str().unwrap();
        assert_eq!(
            source_ref_external_allowed(harness),
            vector["allowed"].as_bool().unwrap(),
            "{harness:?}"
        );
    }
}

#[test]
fn structured_mediation_follows_the_recorded_daemon_rule() {
    for vector in vectors("structured_mediation") {
        let harness = vector["harness"].as_str().unwrap();
        let event = vector["event"].as_str().unwrap();
        assert_eq!(
            structured_mediation(harness, event),
            vector["mediated"].as_bool().unwrap(),
            "{harness:?} {event}"
        );
    }
}

#[test]
fn a_pi_lifecycle_hook_gets_the_recorded_daemon_constant() {
    let lane = lane("pi-lifecycle", json!({}));
    for vector in vectors("lifecycle") {
        let harness = vector["harness"].as_str().unwrap();
        let event = vector["event"].as_str().unwrap();
        let payload = json!({ "hook_event_name": event, "session_id": "synthetic" });
        let result = run_as(&lane, harness, Some(HOME), payload);
        assert_eq!(result["outcome"], "answer", "{harness} {event}: {result}");
        assert_eq!(
            result["edge"],
            json!({ "harness_response": vector["response"] }),
            "{harness} {event}"
        );
    }
    assert_eq!(drain(&lane, None)["records"], json!([]));
}

#[test]
fn a_pi_tool_hook_is_answered_with_the_daemon_source_flag() {
    for harness in ["pi", "omp"] {
        let lane = allowing_lane(&format!("pi-pre-{harness}"), json!({}));
        // The extension names no event for a tool call, and sends its budget.
        let payload = json!({
            "tool_name": "bash",
            "tool_input": { "command": "pwd" },
            "cwd": lane.workspace,
            "guard_remaining_ms": 4_000,
        });
        let result = run_as(&lane, harness, Some(HOME), payload);
        assert_eq!(result["outcome"], "answer", "{harness}: {result}");
        let edge = &result["edge"];
        assert_eq!(
            edge["receipt"]["source_ref_external_allowed"], true,
            "{harness}"
        );
        let page = drain(&lane, None);
        let record = &page["records"][0];
        assert_eq!(record["harness"], harness);
        assert_eq!(record["event"], "PreToolUse");
        assert_eq!(record["harness_response"], edge["harness_response"]);
        assert_eq!(record["receipt"], edge["receipt"]);
    }
    let codex = allowing_lane("pi-pre-codex", json!({}));
    let result = run_as(&codex, "codex", Some(HOME), allowed_payload(&codex));
    assert_eq!(
        result["edge"]["receipt"]["source_ref_external_allowed"],
        false
    );
}

#[test]
fn a_pi_prompt_is_answered_with_the_daemon_source_flag() {
    for harness in ["pi", "omp"] {
        let lane = lane(&format!("pi-prompt-{harness}"), json!({}));
        let result = run_as(&lane, harness, Some(HOME), prompt_payload(&lane));
        assert_eq!(result["outcome"], "answer", "{harness}: {result}");
        assert_eq!(
            result["edge"]["receipt"]["source_ref_external_allowed"],
            true
        );
        let page = drain(&lane, None);
        assert_eq!(page["records"][0]["harness"], harness);
        assert_eq!(page["records"][0]["event"], "UserPromptSubmit");
    }
}

#[test]
fn a_pi_post_tool_use_and_its_source_ref_take_the_daemon_path() {
    for harness in ["pi", "omp"] {
        let lane = lane(&format!("pi-post-{harness}"), json!({}));
        let result = run_as(&lane, harness, Some(HOME), post_tool_payload(&lane));
        assert_eq!(deferred(&result), "direct_hook_event_unsupported");
        let mut referenced = post_tool_payload(&lane);
        referenced["guard_source_ref"] = json!({ "path": "/tmp/output.txt" });
        let result = run_as(&lane, harness, Some(HOME), referenced);
        assert_eq!(deferred(&result), "direct_hook_payload_unsupported");
        assert_eq!(drain(&lane, None)["records"], json!([]), "{harness}");
    }
}
