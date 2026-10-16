//! What a relayed package call answers with once its route is decided.
//!
//! Port of the package lane's own response renderers in `runtime_mcp.py`:
//! `_stored_package_block_response` (:2450), `_terminal_package_response`
//! (:2352) and the receipt side of `_record_package_forward` (:2025). The legs
//! the tool policy decides are rendered by the plain tool-policy responses, so
//! they are a `ToolLeg` the caller answers through the tool lane and never
//! reach this module.
//!
//! Only the text and the payload belong here. The block receipt, the allow
//! receipt and the forwarded message itself stay with the caller: the relay
//! holds its evidence for the drain to record, which is how every other route
//! in this lane already answers.

use serde_json::{json, Value};

use super::package_policy::PackagePolicy;
use super::package_route::PackageRoute;

/// `block_tool_call(decision_source="policy-block")`, which every stopped
/// package call records under.
pub(super) const BLOCK_SOURCE: &str = "policy-block";

/// The message and payload a stopped call answers with, carrying the
/// evaluation the lane settled on as the proxy's `supplyChainEvaluation`.
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
        PackageRoute::Forward { .. } => return None,
    };
    Some((
        message,
        json!({
            "approvalRequests": [],
            "guardPolicyAction": policy_action(route),
            "supplyChainEvaluation": Value::Object(policy.evaluation.clone()),
        }),
    ))
}

/// The action the answer reports, which a stored block always states as
/// `block` and a terminal leg takes from the composed policy.
pub(super) fn policy_action(route: &PackageRoute) -> &str {
    match route {
        PackageRoute::StoredPackageBlock => "block",
        PackageRoute::TerminalPackage { policy_action }
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
        PackageRoute::TerminalPackage { policy_action } => {
            format!("terminal-package-{policy_action}")
        }
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

#[cfg(test)]
#[path = "mcp_relay_decide_package_answer_tests.rs"]
mod tests;
