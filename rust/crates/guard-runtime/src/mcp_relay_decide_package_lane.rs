//! The package lane of one relayed `tools/call`, from the resolved policies to
//! the answer and the facts its receipt records.
//!
//! Port of `_handle_package_request`'s own order (`runtime_mcp.py:1486`): the
//! precheck answers on the policy the lane resolved first, and only a call it
//! lets through re-resolves the tool authority and the package policy and is
//! composed from both (`:1543`). The route is `mcp_relay_decide_package_route.rs`
//! and the text and payload are `mcp_relay_decide_package_answer.rs`; this
//! module is the order they are asked in, and what one answered call leaves for
//! the drain to record.
//!
//! The re-resolution is the caller's, because it reads the store and the policy
//! view the decide path already holds. The lane asks for it only once the
//! precheck did not answer, exactly as the proxy re-resolves nothing for a call
//! its precheck stopped.
//!
//! A queued package request is answered by the blocked-request mode the
//! call's configs bound. Under `safe-alternative` the proxy blocks it in place
//! and leaves the silent inbox row, so the lane answers it and carries the
//! bound receipt redaction level for the drain to write that row with. Under
//! `ask` it defers, because the package-shaped approval row the proxy then
//! writes is not one the relay shapes.
//!
//! Not every leg of this lane is a package answer. The three the tool policy
//! decides — `_stored_tool_block_response`, `_terminal_tool_response` and
//! `_queue_approval_center_response` — are the plain tool-policy responses the
//! proxy renders for any other call, and each records the tool call's own
//! receipt against the tool artifact rather than the package request's. The
//! lane names them apart so the caller routes them through the tool lane it
//! already has, and only the package legs leave the `mcp_package_call` record.

use serde_json::{Map, Value};

use super::package_answer;
use super::package_policy::PackagePolicy;
use super::package_receipt;
use super::package_route::{self, Decided, PackageRoute, ToolLeg};
use super::queue;
use crate::mcp_tool_policy_decision::Decision;

/// What one decided package call leaves the caller: the lane's own answer, or
/// a leg the tool policy decided, which the tool lane answers and records.
#[derive(Debug, Clone, PartialEq)]
pub(super) enum PackageOutcome {
    Answered(PackageAnswer),
    ToolLeg(ToolLeg),
}

/// One answered package call: what the client is told, and what the receipt the
/// drain writes records for it.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct PackageAnswer {
    /// The message and payload a stopped call is answered with; `None`
    /// forwards it.
    pub(super) block: Option<(String, Value)>,
    /// `guardPolicyAction`, which the receipt records as the policy action.
    pub(super) policy_action: String,
    /// `decision_source` the receipt records.
    pub(super) decision_source: String,
    /// The `decision` the proxy's event names. The receipt records the tool
    /// decision itself, so only the event the relay does not emit reads this.
    #[allow(dead_code)]
    pub(super) decision: String,
    /// The receipt signals, one per reason the evaluation reported.
    pub(super) signals: Vec<String>,
    /// The one workspace identity the package lookup was valid for, which the
    /// receipt binds the decision to.
    pub(super) policy_workspace: Option<String>,
    /// The approval-context token the answered request hashes to.
    pub(super) artifact_hash: String,
    /// The evaluation the lane settled on, as the answer reported it.
    pub(super) evaluation: Map<String, Value>,
    /// The package half of the receipt's scanner evidence.
    pub(super) evidence: Vec<Value>,
    /// The receipt redaction level the silent inbox row is written with,
    /// which only the queued leg leaves.
    pub(super) redaction_level: Option<String>,
}

/// The review binding one queued package request is answered under: the
/// blocked-request mode the call's configs agree on, and the receipt
/// redaction level bound with it.
#[derive(Debug, Clone, Copy)]
pub(super) struct QueueBinding<'a> {
    pub(super) blocked_request_mode: Option<&'a str>,
    pub(super) redaction_level: Option<&'a str>,
}

/// Decide one relayed package call. `re_resolve` is the proxy's second
/// resolution: the fresh tool authority and the fresh package policy, read by
/// the caller that holds the store.
pub(super) fn decide_package<F>(
    mode: &str,
    tool: &str,
    server: &str,
    resolved: &PackagePolicy,
    binding: QueueBinding<'_>,
    re_resolve: F,
) -> Result<PackageOutcome, &'static str>
where
    F: FnOnce() -> Result<(Decision, PackagePolicy), &'static str>,
{
    if let Some(route) = package_route::precheck(mode, resolved)? {
        // The precheck answers on the package policy alone, so every leg it
        // decides is this lane's own.
        return Ok(PackageOutcome::Answered(answered(
            &route, tool, server, resolved, binding,
        )?));
    }
    let (authority, policy) = re_resolve()?;
    Ok(match package_route::compose(mode, &authority, &policy)? {
        Decided::Package(route) => {
            PackageOutcome::Answered(answered(&route, tool, server, &policy, binding)?)
        }
        Decided::Tool(leg) => PackageOutcome::ToolLeg(leg),
    })
}

/// The answer and the receipt facts of one decided package route.
fn answered(
    route: &PackageRoute,
    tool: &str,
    server: &str,
    policy: &PackagePolicy,
    binding: QueueBinding<'_>,
) -> Result<PackageAnswer, &'static str> {
    let redaction_level = match route {
        PackageRoute::QueuePackage { .. } => Some(queued_redaction_level(binding)?),
        _ => None,
    };
    let signals = package_answer::signals(route, policy);
    Ok(PackageAnswer {
        block: package_answer::block(route, tool, server, policy, &signals),
        policy_action: package_answer::policy_action(route).to_owned(),
        decision_source: package_answer::decision_source(route),
        decision: package_answer::decision_label(route),
        signals,
        policy_workspace: policy.policy_workspace.clone(),
        artifact_hash: policy.artifact_hash.clone(),
        evaluation: policy.evaluation.clone(),
        evidence: package_receipt::evidence(policy),
        redaction_level,
    })
}

/// `_queue_package_approval_response` by the bound blocked-request mode. Under
/// `safe-alternative` the request is blocked in place and the inbox row is
/// written with the bound receipt redaction level; `ask` defers, because the
/// package-shaped approval row it writes instead is not one the relay shapes.
fn queued_redaction_level(binding: QueueBinding<'_>) -> Result<String, &'static str> {
    match (binding.blocked_request_mode, binding.redaction_level) {
        (Some(queue::SAFE_ALTERNATIVE_MODE), Some(level)) => Ok(level.to_owned()),
        _ => Err(package_route::PACKAGE_QUEUE),
    }
}

#[cfg(test)]
#[path = "mcp_relay_decide_package_lane_tests.rs"]
mod tests;
