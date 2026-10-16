//! What the relay answers for a decided package call, and what it hands back
//! to the proxy because answering it would write.

use guard_command::effect_decision::GuardAction;
use guard_command::package_execution_context::PackageExecutionContext;
use serde_json::{json, Map};

use super::*;
use crate::mcp_tool_policy_decision::{Current, Decision};

/// A resolved package policy whose evaluation settled on `policy_action`.
fn policy(policy_action: &str) -> PackagePolicy {
    let mut evaluation = Map::new();
    evaluation.insert("policy_action".to_owned(), json!(policy_action));
    evaluation.insert("decision".to_owned(), json!(policy_action));
    evaluation.insert("reasons".to_owned(), json!([]));
    PackagePolicy {
        evaluation,
        current_action: GuardAction::Review,
        artifact_hash: "deadbeef".to_owned(),
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

/// `_has_saved_package_block`: the reason an authenticated saved block leaves.
fn with_saved_block(mut policy: PackagePolicy) -> PackagePolicy {
    policy.evaluation.insert(
        "reasons".to_owned(),
        json!([{"code": "saved_package_block", "message": "already blocked"}]),
    );
    policy
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
fn the_precheck_stops_a_saved_block_before_the_tool_is_re_resolved() {
    assert_eq!(
        precheck("enforce", &with_saved_block(policy("allow"))),
        Ok(Some(PackageRoute::StoredPackageBlock)),
    );
}

#[test]
fn the_precheck_stops_a_terminal_package_policy() {
    for action in ["block", "sandbox-required"] {
        assert_eq!(
            precheck("enforce", &policy(action)),
            Ok(Some(PackageRoute::TerminalPackage {
                policy_action: action.to_owned(),
            })),
            "{action}",
        );
    }
}

#[test]
fn the_precheck_hands_back_a_call_that_needs_an_approval_request() {
    // `_queue_package_approval_response` either writes the request row or
    // answers with the approval-center block naming one, so the relay cannot
    // answer this leg at all.
    for action in ["review", "require-reapproval"] {
        assert_eq!(precheck("enforce", &policy(action)), Err(PACKAGE_QUEUE));
    }
}

#[test]
fn the_precheck_lets_a_permitted_or_observed_call_reach_the_composition() {
    for action in ["allow", "warn"] {
        assert_eq!(precheck("enforce", &policy(action)), Ok(None), "{action}");
    }
    // Under observe the precheck never queues; the composition decides what
    // the call does and what it records.
    assert_eq!(precheck("observe", &policy("review")), Ok(None));
}

#[test]
fn the_composition_stops_a_saved_block_on_either_policy() {
    let mut blocked = tool(GuardAction::Allow);
    blocked.saved_action = Some(GuardAction::Block);
    assert_eq!(
        compose("enforce", &blocked, &policy("allow")),
        Ok(PackageRoute::StoredToolBlock),
    );
    assert_eq!(
        compose(
            "enforce",
            &tool(GuardAction::Allow),
            &with_saved_block(policy("allow")),
        ),
        Ok(PackageRoute::StoredPackageBlock),
    );
}

#[test]
fn the_composition_stops_the_call_under_the_most_restrictive_terminal_action() {
    // The composed terminal is answered as the package response either way,
    // as the proxy renders one response for the call that carries the request.
    assert_eq!(
        compose("enforce", &tool(GuardAction::Block), &policy("allow")),
        Ok(PackageRoute::TerminalPackage {
            policy_action: "block".to_owned(),
        }),
    );
    assert_eq!(
        compose("enforce", &tool(GuardAction::Allow), &policy("block")),
        Ok(PackageRoute::TerminalPackage {
            policy_action: "block".to_owned(),
        }),
    );
}

#[test]
fn the_composition_hands_back_either_queue() {
    assert_eq!(
        compose("enforce", &tool(GuardAction::Review), &policy("allow")),
        Err(PACKAGE_QUEUE),
    );
    assert_eq!(
        compose("enforce", &tool(GuardAction::Allow), &policy("review")),
        Err(PACKAGE_QUEUE),
    );
}

#[test]
fn the_composition_hands_back_an_observed_forward() {
    // The forward comes with the observed requests the proxy queues first.
    assert_eq!(
        compose("observe", &tool(GuardAction::Allow), &policy("review")),
        Err(PACKAGE_OBSERVE),
    );
}

#[test]
fn the_composition_forwards_a_call_neither_policy_stops() {
    assert_eq!(
        compose("enforce", &tool(GuardAction::Warn), &policy("allow")),
        Ok(PackageRoute::Forward {
            policy_action: "warn".to_owned(),
        }),
    );
}

#[test]
fn a_forward_with_a_saved_approval_still_to_spend_is_the_claim_lanes() {
    let mut pending_tool = tool(GuardAction::Allow);
    pending_tool.pending = Some(Map::new());
    assert_eq!(
        compose("enforce", &pending_tool, &policy("allow")),
        Err(PACKAGE_PENDING_CLAIM),
    );
    let mut pending_package = policy("allow");
    pending_package.reused_decision = Some(json!({"decision_id": 7}));
    assert_eq!(
        compose("enforce", &tool(GuardAction::Allow), &pending_package),
        Err(PACKAGE_PENDING_CLAIM),
    );
}

#[test]
fn an_evaluation_with_no_policy_action_decides_nothing() {
    let mut empty = policy("allow");
    empty.evaluation.remove("policy_action");
    assert_eq!(precheck("enforce", &empty), Err(PACKAGE_ACTION_MISSING));
    assert_eq!(
        compose("enforce", &tool(GuardAction::Allow), &empty),
        Err(PACKAGE_ACTION_MISSING),
    );
}

#[test]
fn an_answer_naming_an_unknown_kind_defers() {
    // The proxy raises `native_mcp_proxy_decision_*_unknown` here; the relay
    // hands the call back rather than inventing a route for it.
    assert_eq!(kind(&json!({})), Err(PACKAGE_ROUTE_UNKNOWN));
    assert_eq!(kind(&json!({"kind": 7})), Err(PACKAGE_ROUTE_UNKNOWN));
    assert_eq!(
        answered_action(&json!({"kind": "terminal"})),
        Err(PACKAGE_ROUTE_UNKNOWN),
    );
}
