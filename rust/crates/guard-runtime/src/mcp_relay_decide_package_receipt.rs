//! The receipt one answered package call leaves for the drain to write.
//!
//! A relayed package call is recorded against the package request's own
//! artifact, not the tool's: `_record_package_block` (`runtime_mcp.py:2327`)
//! and `_record_package_forward` (:2025) write `block_tool_call` and
//! `allow_tool_call` with the package artifact, the approval-context token the
//! request hashed to, the evaluation's reason signals, and the package scanner
//! evidence `_package_scanner_evidence` (:2009) composed. The tool legs of the
//! same lane are recorded as the plain tool-policy blocks they are, so they
//! keep the `mcp_tool_call` record the rest of the decide path leaves.
//!
//! So a package leg carries its own record kind. It names the package artifact
//! by id and the workspace the proxy parsed it from, rather than shipping the
//! artifact itself: `to_dict` redacts args, url and metadata, and a receipt
//! written from redacted fields is not the receipt the proxy writes. The drain
//! rebuilds the artifact from the call the record carries — the same parser
//! input the resident read — and drops the record when the rebuilt artifact is
//! not the one this decided.
//!
//! The evidence is the package half only. The tool half is
//! `tool_decision_scanner_evidence` of the decision the record already carries,
//! which the drain derives for every relayed call.

use serde_json::{json, Map, Value};

use super::package_lane::PackageAnswer;
use super::package_policy::PackagePolicy;
use super::{McpRelayDecideRequestV1, IDENTITY_FAILED};
use crate::mcp_tool_policy_decision::Decision;
use guard_command::package_intent_common::GuardArtifact;

/// The evidence kind the drain records a relayed package call under.
pub(super) const PACKAGE_CALL_EVIDENCE_KIND: &str = "mcp_package_call";

/// The package half of `_package_scanner_evidence`: the execution context the
/// approval identity is bound to, then one entry per reason that carries an
/// approval reuse, in the order the evaluation reported them.
pub(super) fn evidence(policy: &PackagePolicy) -> Vec<Value> {
    let mut evidence = vec![policy.execution_context.to_evidence()];
    let reasons = policy
        .evaluation
        .get("reasons")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    for reason in reasons {
        let Some(reuse) = reason.get("approval_reuse").and_then(Value::as_object) else {
            continue;
        };
        let mut entry = Map::new();
        entry.insert("source".to_owned(), json!("approval_reuse"));
        entry.extend(reuse.clone());
        evidence.push(Value::Object(entry));
    }
    evidence
}

/// The record the drain writes one answered package call's receipt from.
///
/// `artifact` is the package request's artifact and `workspace` the directory
/// its intent was parsed against, which is what the drain rebuilds it from.
pub(super) fn record(
    request: &McpRelayDecideRequestV1,
    identity: &Value,
    decision: &Decision,
    artifact: &GuardArtifact,
    workspace: &str,
    answer: &PackageAnswer,
) -> Result<Value, &'static str> {
    // A forward is the only route whose receipt binds the policy workspace,
    // because only `allow_tool_call` is given one.
    let forwarded = answer.block.is_none();
    let mut package = json!({
        "artifact_id": artifact.artifact_id,
        "artifact_hash": answer.artifact_hash,
        "workspace": workspace,
        "evaluation": Value::Object(answer.evaluation.clone()),
        "evidence": Value::Array(answer.evidence.clone()),
        "signals": answer.signals.clone(),
    });
    if forwarded {
        package["policy_workspace"] = json!(answer.policy_workspace);
    }
    Ok(json!({
        "kind": PACKAGE_CALL_EVIDENCE_KIND,
        "harness": request.build.harness,
        "outcome": if forwarded { "forward" } else { "block" },
        "decision_source": answer.decision_source,
        "policy_action": answer.policy_action,
        "tool_name": request.build.tool_name,
        "params": request.params,
        // The arguments in host key order, which the decoded params lost.
        "arguments": serde_json::to_value(&request.arguments).map_err(|_| IDENTITY_FAILED)?,
        "identity": identity,
        "decision": decision.to_value(),
        "package": package,
    }))
}

#[cfg(test)]
#[path = "mcp_relay_decide_package_receipt_tests.rs"]
mod tests;
