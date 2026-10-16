//! What one relayed package call answers with, and when the lane asks for the
//! second resolution at all.

use std::cell::Cell;

use guard_command::effect_decision::GuardAction;
use guard_command::package_execution_context::PackageExecutionContext;
use serde_json::json;

use super::*;
use crate::mcp_tool_policy_decision::Current;

const TOOL: &str = "install_package";
const SERVER: &str = "registry";

/// A resolved package policy whose evaluation settled on `policy_action` and
/// reported `reasons`.
fn policy(policy_action: &str, reasons: Value) -> PackagePolicy {
    let mut evaluation = Map::new();
    evaluation.insert("policy_action".to_owned(), json!(policy_action));
    evaluation.insert("decision".to_owned(), json!(policy_action));
    evaluation.insert("reasons".to_owned(), reasons);
    PackagePolicy {
        evaluation,
        current_action: GuardAction::Review,
        artifact_hash: "guard-approval-context:v1:abc".to_owned(),
        policy_workspace: Some("package-request-workspace:v2:abc".to_owned()),
        execution_context: PackageExecutionContext {
            digest: "ctx".to_owned(),
            portable: true,
            components: Vec::new(),
            non_portable_reason: None,
        },
        reused_decision: None,
        claim_disposition: None,
    }
}

fn tool(action: GuardAction) -> Decision {
    Decision::plain(Current {
        action,
        source: "policy".to_owned(),
        signals: Vec::new(),
        summary: "installs a package".to_owned(),
        risk_categories: Vec::new(),
    })
}

#[test]
fn a_call_the_precheck_stops_is_never_re_resolved() {
    let asked = Cell::new(false);
    let saved_block = policy("allow", json!([{"code": "saved_package_block"}]));
    let answer = decide_package("enforce", TOOL, SERVER, &saved_block, || {
        asked.set(true);
        Ok((tool(GuardAction::Allow), policy("allow", json!([]))))
    })
    .expect("the precheck answers the call");
    assert!(
        !asked.get(),
        "the proxy re-resolves nothing for a stopped call"
    );
    let (message, data) = answer.block.expect("a stopped call answers with a block");
    assert!(
        message.contains("already blocked by stored policy"),
        "{message}"
    );
    assert_eq!(data["guardPolicyAction"], json!("block"));
    assert_eq!(answer.decision, "package-block-stored");
    assert_eq!(answer.decision_source, package_answer::BLOCK_SOURCE);
    assert_eq!(answer.policy_action, "block");
    // The receipt binds the decision to the request the precheck read.
    assert_eq!(answer.artifact_hash, saved_block.artifact_hash);
    assert_eq!(answer.policy_workspace, saved_block.policy_workspace);
    assert_eq!(answer.signals, vec!["saved_package_block".to_owned()]);
}

#[test]
fn a_forwarded_call_answers_from_the_re_resolved_policy() {
    let answer = decide_package("enforce", TOOL, SERVER, &policy("allow", json!([])), || {
        Ok((
            tool(GuardAction::Warn),
            policy("allow", json!([{"message": "left-pad is newly published"}])),
        ))
    })
    .expect("neither policy stops the call");
    assert_eq!(answer.block, None);
    assert_eq!(answer.policy_action, "warn");
    assert_eq!(answer.decision_source, "policy-warn");
    assert_eq!(answer.decision, "package-warn");
    // The reasons are the second resolution's, not the precheck's.
    assert_eq!(
        answer.signals,
        vec!["left-pad is newly published".to_owned()],
    );
}

#[test]
fn a_composed_terminal_answers_as_the_package_response() {
    let answer = decide_package("enforce", TOOL, SERVER, &policy("allow", json!([])), || {
        Ok((tool(GuardAction::Block), policy("allow", json!([]))))
    })
    .expect("the composition stops the call");
    let (message, data) = answer.block.expect("a stopped call answers with a block");
    assert_eq!(
        message,
        "HOL Guard blocked package install request install_package from registry."
    );
    assert_eq!(data["supplyChainEvaluation"]["decision"], json!("allow"));
    assert_eq!(answer.decision, "terminal-package-block");
}

#[test]
fn a_leg_the_relay_cannot_answer_defers_from_either_resolution() {
    // The precheck's queue: the proxy writes the approval request for it.
    assert_eq!(
        decide_package(
            "enforce",
            TOOL,
            SERVER,
            &policy("review", json!([])),
            || { panic!("a queued precheck re-resolves nothing") }
        )
        .err(),
        Some(package_route::PACKAGE_QUEUE),
    );
    // The composition's, once the fresh tool authority asks for approval.
    assert_eq!(
        decide_package("enforce", TOOL, SERVER, &policy("allow", json!([])), || Ok(
            (tool(GuardAction::Review), policy("allow", json!([])),)
        ))
        .err(),
        Some(package_route::PACKAGE_QUEUE),
    );
}

#[test]
fn a_second_resolution_the_caller_could_not_read_defers_the_call() {
    assert_eq!(
        decide_package(
            "enforce",
            TOOL,
            SERVER,
            &policy("allow", json!([])),
            || Err("mcp_relay_store_unreadable")
        )
        .err(),
        Some("mcp_relay_store_unreadable"),
    );
}
