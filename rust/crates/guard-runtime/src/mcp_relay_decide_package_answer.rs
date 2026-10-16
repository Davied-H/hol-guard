//! What a relayed package call answers with once its route is decided.
//!
//! Port of the package lane's response renderers in `runtime_mcp.py`:
//! `_stored_package_block_response` (:2450), `_terminal_package_response`
//! (:2352), `_stored_tool_block_response` with `package_request = True`
//! (:2400), `_terminal_tool_response` (:2276) and the receipt side of
//! `_record_package_forward` (:2025).
//!
//! Only the text and the payload belong here. The block receipt, the allow
//! receipt and the forwarded message itself stay with the caller: the relay
//! holds its evidence for the drain to record, which is how every other route
//! in this lane already answers.

// The decide path reads this with the rest of the native package lane; until
// it does, only the tests below render a package answer.
#![allow(dead_code)]

use serde_json::{json, Value};

use super::package_policy::PackagePolicy;
use super::package_route::PackageRoute;

/// `block_tool_call(decision_source="policy-block")`, which every stopped
/// package call records under.
pub(super) const BLOCK_SOURCE: &str = "policy-block";

/// The message and payload a stopped call answers with. The package legs carry
/// the evaluation the lane settled on, as the proxy's `supplyChainEvaluation`;
/// the tool legs carry what a plain blocked tool call does, because the policy
/// that stopped them is the tool's.
pub(super) fn block(
    route: &PackageRoute,
    tool: &str,
    server: &str,
    policy: &PackagePolicy,
) -> Option<(String, Value)> {
    let message = match route {
        PackageRoute::StoredPackageBlock => format!(
            "HOL Guard blocked package install request {tool} from {server}. This exact request \
             is already blocked by stored policy with authenticated local integrity."
        ),
        PackageRoute::TerminalPackage { policy_action } => {
            if policy_action == "block" {
                format!("HOL Guard blocked package install request {tool} from {server}.")
            } else {
                format!(
                    "HOL Guard requires an enforceable sandbox for package install request \
                     {tool} from {server}; this runtime cannot provide one."
                )
            }
        }
        PackageRoute::StoredToolBlock => format!(
            "HOL Guard blocked package tool call {tool} from {server}. This exact request is \
             already blocked by authenticated saved policy."
        ),
        PackageRoute::TerminalTool { policy_action } => {
            if policy_action == "block" {
                format!("HOL Guard blocked tool call {tool} from {server}.")
            } else {
                format!(
                    "HOL Guard requires an enforceable sandbox for tool call {tool} from \
                     {server}; this runtime cannot provide one."
                )
            }
        }
        PackageRoute::Forward { .. } => return None,
    };
    let mut data = json!({
        "approvalRequests": [],
        "guardPolicyAction": policy_action(route),
    });
    if carries_evaluation(route) {
        data["supplyChainEvaluation"] = Value::Object(policy.evaluation.clone());
    }
    Some((message, data))
}

/// The action the answer reports, which a stored block always states as
/// `block` and a terminal leg takes from the composed policy.
pub(super) fn policy_action(route: &PackageRoute) -> &str {
    match route {
        PackageRoute::StoredPackageBlock | PackageRoute::StoredToolBlock => "block",
        PackageRoute::TerminalPackage { policy_action }
        | PackageRoute::TerminalTool { policy_action }
        | PackageRoute::Forward { policy_action } => policy_action,
    }
}

/// `decision_source` the receipt records: a stopped call is a policy block, a
/// forwarded one is the action it was permitted under. The relay never spends
/// a saved approval, so the remembered source a claimed forward would carry is
/// not one of these.
pub(super) fn decision_source(route: &PackageRoute) -> String {
    match route {
        PackageRoute::Forward { policy_action } => format!("policy-{policy_action}"),
        _ => BLOCK_SOURCE.to_owned(),
    }
}

/// The `decision` the proxy's own event names, which the drain records for the
/// answered call.
pub(super) fn decision_label(route: &PackageRoute) -> String {
    match route {
        PackageRoute::StoredPackageBlock => "package-block-stored".to_owned(),
        PackageRoute::StoredToolBlock => "block-stored-policy".to_owned(),
        PackageRoute::TerminalPackage { policy_action } => {
            format!("terminal-package-{policy_action}")
        }
        PackageRoute::TerminalTool { policy_action } => format!("terminal-{policy_action}"),
        PackageRoute::Forward { policy_action } => format!("package-{policy_action}"),
    }
}

/// The receipt signals both the block and the allow record: each reason's
/// message, its code when it carries no message, and an empty string when it
/// carries neither, in the order the evaluation reported them.
pub(super) fn reason_signals(policy: &PackagePolicy) -> Vec<String> {
    policy
        .evaluation
        .get("reasons")
        .and_then(Value::as_array)
        .map(|reasons| {
            reasons
                .iter()
                .map(|reason| {
                    reason
                        .get("message")
                        .and_then(Value::as_str)
                        .filter(|text| !text.is_empty())
                        .or_else(|| reason.get("code").and_then(Value::as_str))
                        .unwrap_or("")
                        .to_owned()
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Whether the answer reports the package evaluation to the caller. The tool
/// legs do not: the proxy renders them as the tool-policy responses they are.
fn carries_evaluation(route: &PackageRoute) -> bool {
    matches!(
        route,
        PackageRoute::StoredPackageBlock | PackageRoute::TerminalPackage { .. }
    )
}

#[cfg(test)]
#[path = "mcp_relay_decide_package_answer_tests.rs"]
mod tests;
