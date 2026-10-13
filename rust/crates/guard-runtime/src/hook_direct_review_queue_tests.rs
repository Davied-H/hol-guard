use super::*;
use crate::policy_store::policy_store_direct_lane::{DirectLaneBinding, DirectLaneReviewFacts};

fn ask_binding() -> DirectLaneBinding {
    let mut binding = super::super::tests::binding();
    binding.review = DirectLaneReviewFacts {
        blocked_request_mode: Some("ask".to_owned()),
        approval_center_origin: Some("http://127.0.0.1:4781".to_owned()),
        review_oauth_source: Some("default".to_owned()),
        review_host_cwd: Some("/work".to_owned()),
    };
    binding
}

fn queued(harness: &str, binding: &DirectLaneBinding, result: &Value) -> bool {
    let payload = Map::new();
    let context = Context {
        harness,
        payload: &payload,
        recorded_payload: &payload,
        workspace: "/work",
        home_dir: "/home/user",
        guard_home: "/home/user/.hol-guard",
        binding,
    };
    facts(&context, result.as_object().unwrap()).is_some()
}

#[test]
fn only_a_fully_published_ask_home_queues() {
    let review = json!({"reason_code": "native_review", "reason": "Review this."});
    let binding = ask_binding();
    assert!(queued("codex", &binding, &review));
    // Claude Code's paused review also records a permission notice.
    assert!(!queued(CLAUDE_CODE, &binding, &review));
    // The daemon may settle a package review before it queues anything.
    let package = json!({"reason_code": PACKAGE_REVIEW_REASON});
    assert!(!queued("codex", &binding, &package));
    let mut safe_alternative = ask_binding();
    safe_alternative.review.blocked_request_mode = Some("safe-alternative".to_owned());
    assert!(!queued("codex", &safe_alternative, &review));
    for strip in [
        (|facts: &mut DirectLaneReviewFacts| facts.blocked_request_mode = None)
            as fn(&mut DirectLaneReviewFacts),
        |facts: &mut DirectLaneReviewFacts| facts.approval_center_origin = None,
        |facts: &mut DirectLaneReviewFacts| facts.review_oauth_source = None,
        |facts: &mut DirectLaneReviewFacts| facts.review_host_cwd = None,
    ] {
        let mut partial = ask_binding();
        strip(&mut partial.review);
        assert!(!queued("codex", &partial, &review));
    }
    let mut no_environment = ask_binding();
    no_environment.exact_action_environment = None;
    assert!(!queued("codex", &no_environment, &review));
}

#[test]
fn request_ids_are_uuid4_hex() {
    let first = request_id().unwrap();
    let second = request_id().unwrap();
    assert_ne!(first, second);
    for id in [first, second] {
        assert_eq!(id.len(), 32);
        assert!(id
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f')));
        assert_eq!(&id[12..13], "4");
        assert!(matches!(&id[16..17], "8" | "9" | "a" | "b"));
    }
}

#[test]
fn harness_names_canonicalize_as_the_daemon_does() {
    assert_eq!(canonical_harness(" Gemini_CLI \n"), "gemini-cli");
    assert_eq!(canonical_harness("codex"), "codex");
}

#[test]
fn the_pause_carries_the_queued_request() {
    let result = json!({"decision": "review", "reason": "Review this."});
    let response = respond(
        "codex",
        result.as_object().unwrap(),
        "abc123",
        "http://127.0.0.1:4781/requests/abc123",
        "Review this. Approve at http://127.0.0.1:4781/requests/abc123",
        "http://127.0.0.1:4781",
    )
    .unwrap();
    assert_eq!(response["prompted"], json!(true));
    assert_eq!(
        response["approval_center_url"],
        json!("http://127.0.0.1:4781")
    );
    let mut approval = Object::new();
    approval.insert("request_id".to_owned(), json!("abc123"));
    approval.insert(
        "approval_url".to_owned(),
        json!("http://127.0.0.1:4781/requests/abc123"),
    );
    let mut expected = pre_tool_review(
        "codex",
        result.as_object().unwrap(),
        Some(&approval),
        Some("Review this. Approve at http://127.0.0.1:4781/requests/abc123"),
    );
    expected.insert("prompted".to_owned(), json!(true));
    expected.insert(
        "approval_center_url".to_owned(),
        json!("http://127.0.0.1:4781"),
    );
    assert_eq!(response, Value::Object(expected));
}

#[test]
fn an_oversized_pause_defers() {
    let result = json!({"reason": "x".repeat(HOOK_RENDER_MAX_BYTES)});
    assert!(respond(
        "codex",
        result.as_object().unwrap(),
        "abc123",
        "http://127.0.0.1:4781/requests/abc123",
        "linked",
        "http://127.0.0.1:4781",
    )
    .is_none());
}
