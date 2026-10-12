use serde_json::{json, Value};

use super::{evaluate, QUERIES};
use crate::codex_output_env::{Ctx, GitCheck, GitRun, InspectionHost};

/// A host with no resident services: every trust probe fails closed.
struct Host;

impl InspectionHost for Host {
    fn env(&self, _: &str) -> Option<String> {
        None
    }
    fn git_executable(&self) -> Option<String> {
        None
    }
    fn git_safety(&self, _: GitCheck, _: Option<&str>, _: &[String]) -> bool {
        false
    }
    fn git_binary_trusted(&self, _: &str, _: &str) -> bool {
        false
    }
    fn run_git(&self, _: &str, _: &[String], _: &str) -> GitRun {
        GitRun::Failed("unavailable")
    }
}

fn ask(query: &str, input: &Value) -> Result<Value, &'static str> {
    let host = Host;
    let ctx = Ctx::new(&host, "/work", "/home/user");
    evaluate(query, input, &ctx, None)
}

#[test]
fn unknown_queries_and_non_object_inputs_are_rejected() {
    assert_eq!(
        ask("verdict", &json!({})),
        Err("native_sensitive_request_query_unknown")
    );
    assert_eq!(
        ask("classify_path", &json!([])),
        Err("native_sensitive_request_input_invalid")
    );
    assert_eq!(
        ask("classify_path", &json!({"path": "x", "cwd": 3})),
        Err("native_sensitive_request_input_invalid")
    );
}

#[test]
fn every_listed_query_is_answered() {
    for query in QUERIES {
        assert_ne!(
            ask(query, &json!({})),
            Err("native_sensitive_request_query_unknown"),
            "{query}"
        );
    }
}

#[test]
fn ssh_private_key_path_is_classified() {
    let found = ask(
        "classify_path",
        &json!({"path": "~/.ssh/id_rsa", "cwd": "/work", "home_dir": "/home/user"}),
    )
    .expect("classified");
    assert!(found.is_object(), "{found}");
    assert!(found["family"].is_string(), "{found}");
    assert_eq!(found["requested_path"], json!("~/.ssh/id_rsa"));
}

#[test]
fn ordinary_source_path_is_not_sensitive() {
    let found = ask(
        "classify_path",
        &json!({"path": "src/main.rs", "cwd": "/work", "home_dir": "/home/user"}),
    );
    assert_eq!(found, Ok(Value::Null));
}

#[test]
fn canonical_claim_must_match_the_resident_parse() {
    let input = json!({
        "tool_name": "Bash",
        "arguments": {"command": "cat ~/.ssh/id_rsa"},
        "cwd": "/work",
        "home_dir": "/home/user",
        "canonical": {"raw_text": "cat ~/.ssh/id_rsa", "security_identity": "forged"},
    });
    assert_eq!(
        ask("tool_action", &input),
        Err("native_sensitive_request_canonical_unbound")
    );
}

#[test]
fn malformed_evaluation_is_rejected() {
    let input = json!({
        "tool_name": "Bash",
        "arguments": {"command": "ls"},
        "evaluation": {"security_identity": "x", "minimum_action": "maybe"},
    });
    assert_eq!(
        ask("tool_action", &input),
        Err("native_sensitive_request_input_invalid")
    );
}

#[test]
fn command_list_texts_require_a_list_and_flag() {
    assert_eq!(
        ask("command_list_candidate_texts", &json!({"values": "ls"})),
        Err("native_sensitive_request_input_invalid")
    );
    let texts = ask(
        "command_list_candidate_texts",
        &json!({"values": ["cat", "README.md"], "preserve_items": false}),
    )
    .expect("texts");
    assert!(texts.is_array(), "{texts}");
}

#[test]
fn canonical_claim_parse_settings_must_be_known() {
    let input = json!({
        "tool_name": "Bash",
        "arguments": {"command": "ls"},
        "canonical": {"raw_text": "ls", "security_identity": "x", "dialect": "fish"},
    });
    assert_eq!(
        ask("tool_action", &input),
        Err("native_sensitive_request_input_invalid")
    );
}
