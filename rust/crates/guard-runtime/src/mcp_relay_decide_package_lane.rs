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

// The decide path reads this with the rest of the native package lane; until
// it does, only the tests below decide a package call.
#![allow(dead_code)]

use serde_json::{Map, Value};

use super::package_answer;
use super::package_policy::PackagePolicy;
use super::package_receipt;
use super::package_route::{self, PackageRoute};
use crate::mcp_tool_policy_decision::Decision;

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
    /// The `decision` the proxy's event names.
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
}

/// Decide one relayed package call. `re_resolve` is the proxy's second
/// resolution: the fresh tool authority and the fresh package policy, read by
/// the caller that holds the store.
pub(super) fn decide_package<F>(
    mode: &str,
    tool: &str,
    server: &str,
    resolved: &PackagePolicy,
    re_resolve: F,
) -> Result<PackageAnswer, &'static str>
where
    F: FnOnce() -> Result<(Decision, PackagePolicy), &'static str>,
{
    if let Some(route) = package_route::precheck(mode, resolved)? {
        return Ok(answered(&route, tool, server, resolved));
    }
    let (authority, policy) = re_resolve()?;
    let route = package_route::compose(mode, &authority, &policy)?;
    Ok(answered(&route, tool, server, &policy))
}

/// The answer and the receipt facts of one decided route.
fn answered(
    route: &PackageRoute,
    tool: &str,
    server: &str,
    policy: &PackagePolicy,
) -> PackageAnswer {
    PackageAnswer {
        block: package_answer::block(route, tool, server, policy),
        policy_action: package_answer::policy_action(route).to_owned(),
        decision_source: package_answer::decision_source(route),
        decision: package_answer::decision_label(route),
        signals: package_answer::reason_signals(policy),
        policy_workspace: policy.policy_workspace.clone(),
        artifact_hash: policy.artifact_hash.clone(),
        evaluation: policy.evaluation.clone(),
        evidence: package_receipt::evidence(policy),
    }
}

#[cfg(test)]
#[path = "mcp_relay_decide_package_lane_tests.rs"]
mod tests;
