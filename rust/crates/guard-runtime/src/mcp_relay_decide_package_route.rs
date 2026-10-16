//! The route a relayed package call takes once its stored policy is resolved.
//!
//! Port of `_handle_package_request`'s two decide legs (`runtime_mcp.py:1486`,
//! `:1543`): the precheck on the policy resolved before the tool is
//! re-resolved, and the composition of the freshly re-resolved tool and
//! package policies. Both answers are the resident's own
//! (`mcp_proxy_package.rs`), asked here with the facts the proxy sends
//! (`native_mcp_proxy_decision.py` `tool_facts`, `package_facts`), so the
//! relay and the proxy decide a package call by one algorithm rather than two.
//!
//! The relay answers only the legs that stop or forward a call on what it has
//! already read. Three defer:
//!
//! * a queue, because the proxy either writes an approval request for it
//!   (`_queue_package_approval_response` under `ask`) or answers it with the
//!   approval-center block, which names a row the relay does not write;
//! * an observed forward, because the proxy queues the observed requests it
//!   would have blocked before it forwards;
//! * a forward whose policies left a saved approval pending, which is the
//!   claim lane's call to spend.
//!
//! A kind neither answer names is the proxy's `NativeMcpProxyDecisionError`;
//! here it defers, because a relayed call never guesses at a verdict.

use guard_contracts::{McpPackageComposeQueryV1, McpPackageFactsV1, McpPackagePrecheckQueryV1};
use serde_json::Value;

use super::package_policy::PackagePolicy;
use crate::mcp_tool_policy_decision::Decision;

/// The call needs an approval request written or an approval-center block
/// rendered from a row the relay does not write.
pub(super) const PACKAGE_QUEUE: &str = "mcp_relay_package_queue";
/// `mode = "observe"`: the forward comes with the observed approval requests
/// the proxy queues first.
pub(super) const PACKAGE_OBSERVE: &str = "mcp_relay_package_observe";
/// The tool or the package policy holds a saved approval the forward spends.
pub(super) const PACKAGE_PENDING_CLAIM: &str = "mcp_relay_package_pending_claim";
/// An answer naming a kind this port does not know, which the proxy raises
/// `native_mcp_proxy_decision_{precheck,compose}_unknown` for.
pub(super) const PACKAGE_ROUTE_UNKNOWN: &str = "mcp_relay_package_route_unknown";
/// The resolved evaluation carries no policy action to decide on.
pub(super) const PACKAGE_ACTION_MISSING: &str = "mcp_relay_package_action_missing";

/// `_has_saved_package_block`: the reason code a saved block leaves.
const SAVED_PACKAGE_BLOCK: &str = "saved_package_block";

/// What the relay does with a decided package call. Each variant names the
/// proxy response it answers with, which renders the package evaluation.
#[derive(Debug, Clone, PartialEq)]
pub(super) enum PackageRoute {
    /// `_stored_package_block_response`: authenticated saved policy already
    /// blocks this exact request.
    StoredPackageBlock,
    /// `_terminal_package_response`: the package policy itself stops the call.
    TerminalPackage { policy_action: String },
    /// `_stored_tool_block_response` with `package_request = True`.
    StoredToolBlock,
    /// `_terminal_tool_response`: the tool policy stops the call carrying the
    /// package request.
    TerminalTool { policy_action: String },
    /// `_record_package_forward`: neither policy stops the call and no saved
    /// approval is pending.
    Forward { policy_action: String },
}

/// `package_precheck`. `None` is the proxy's `proceed`: the call goes on to
/// the fresh tool authority and the fresh package policy.
pub(super) fn precheck(
    mode: &str,
    policy: &PackagePolicy,
) -> Result<Option<PackageRoute>, &'static str> {
    let answer = crate::mcp_proxy_package::package_precheck(&McpPackagePrecheckQueryV1 {
        mode: mode.to_owned(),
        saved_policy_blocks: saved_policy_blocks(policy),
        policy_action: policy_action(policy)?.to_owned(),
    });
    match kind(&answer)? {
        "proceed" => Ok(None),
        "stored_package_block" => Ok(Some(PackageRoute::StoredPackageBlock)),
        "terminal" => Ok(Some(PackageRoute::TerminalPackage {
            policy_action: answered_action(&answer)?,
        })),
        "queue" => Err(PACKAGE_QUEUE),
        _ => Err(PACKAGE_ROUTE_UNKNOWN),
    }
}

/// `package_compose` over the freshly re-resolved tool and package policies.
pub(super) fn compose(
    mode: &str,
    tool: &Decision,
    policy: &PackagePolicy,
) -> Result<PackageRoute, &'static str> {
    let answer = crate::mcp_proxy_package::package_compose(&McpPackageComposeQueryV1 {
        mode: mode.to_owned(),
        tool: crate::mcp_tool_policy_proxy::facts(tool),
        package: package_facts(policy)?,
    });
    match kind(&answer)? {
        "stored_tool_block" => Ok(PackageRoute::StoredToolBlock),
        "stored_package_block" => Ok(PackageRoute::StoredPackageBlock),
        "terminal_tool" => Ok(PackageRoute::TerminalTool {
            policy_action: answered_action(&answer)?,
        }),
        "terminal_package" => Ok(PackageRoute::TerminalPackage {
            policy_action: answered_action(&answer)?,
        }),
        "queue_tool" | "queue_package" => Err(PACKAGE_QUEUE),
        "observe_forward" => Err(PACKAGE_OBSERVE),
        "proceed" => match answer.get("pending_claims").and_then(Value::as_bool) {
            Some(false) => Ok(PackageRoute::Forward {
                policy_action: answer
                    .get("authoritative_action")
                    .and_then(Value::as_str)
                    .ok_or(PACKAGE_ROUTE_UNKNOWN)?
                    .to_owned(),
            }),
            Some(true) => Err(PACKAGE_PENDING_CLAIM),
            None => Err(PACKAGE_ROUTE_UNKNOWN),
        },
        _ => Err(PACKAGE_ROUTE_UNKNOWN),
    }
}

/// `package_facts`: the decision-relevant facts of one resolved package
/// policy.
fn package_facts(policy: &PackagePolicy) -> Result<McpPackageFactsV1, &'static str> {
    Ok(McpPackageFactsV1 {
        saved_policy_blocks: saved_policy_blocks(policy),
        current_action: Some(policy.current_action.as_str().to_owned()),
        policy_action: policy_action(policy)?.to_owned(),
        // The saved row the resolution reported without consuming, which is
        // the claim a forward would spend.
        has_pending: policy.reused_decision.is_some(),
    })
}

/// `_has_saved_package_block(evaluation.reasons)`.
fn saved_policy_blocks(policy: &PackagePolicy) -> bool {
    policy
        .evaluation
        .get("reasons")
        .and_then(Value::as_array)
        .is_some_and(|reasons| {
            reasons.iter().any(|reason| {
                reason.get("code").and_then(Value::as_str) == Some(SAVED_PACKAGE_BLOCK)
            })
        })
}

/// `evaluation.policy_action`, which both answers read.
fn policy_action(policy: &PackagePolicy) -> Result<&str, &'static str> {
    policy
        .evaluation
        .get("policy_action")
        .and_then(Value::as_str)
        .ok_or(PACKAGE_ACTION_MISSING)
}

fn kind(answer: &Value) -> Result<&str, &'static str> {
    answer
        .get("kind")
        .and_then(Value::as_str)
        .ok_or(PACKAGE_ROUTE_UNKNOWN)
}

/// The action a terminal answer carries, which the proxy passes to the
/// response it renders. Both answers compose it from a `GuardAction`, so the
/// text is one of that enum's.
fn answered_action(answer: &Value) -> Result<String, &'static str> {
    answer
        .get("policy_action")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or(PACKAGE_ROUTE_UNKNOWN)
}

#[cfg(test)]
#[path = "mcp_relay_decide_package_route_tests.rs"]
mod tests;
