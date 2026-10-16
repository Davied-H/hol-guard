//! The package leg of one relayed `tools/call`: the artifact, the stored
//! policy and the answer the lane settles, read on the decide path's own
//! snapshot.
//!
//! The proxy evaluates a package request before it resolves any policy for it
//! (`runtime_mcp.py:1365`), and that evaluation is a conversation: the
//! resident asks for archive and registry rounds the caller performs. A
//! `tools/call` decide cannot hold one, so the first decide of a package call
//! answers `evaluate` and the relay sends the same call again with the
//! evaluation attached. This module is what the second decide runs: the
//! package request's artifact, rebuilt from the intent the gate parsed, the
//! stored policy resolved against it, and the lane's answer over both.
//!
//! Everything the evaluation and the execution context are bound to belongs to
//! the relaying process, not the resident: its environment, its working
//! directory and its home (`_resident_environment`). They travel with the
//! request, and a call that is missing any of them defers rather than binding
//! the resident's own.
//!
//! The workspace is the one the policy lookup is valid for, so a call without
//! one defers as well. The proxy would resolve the policy under its working
//! directory, but it parses the intent under its `--workspace` alone, and the
//! drain rebuilds the artifact from the workspace the receipt names. A
//! substituted directory would rebuild another artifact, and the receipt the
//! drain cannot match is dropped rather than recorded.

use guard_command::package_intent_common::{
    build_package_request_artifact, GuardArtifact, PackageIntent,
};
use guard_contracts::{McpToolCallIdentityPayloadV1, McpToolPolicySubjectV1};

use super::package_lane::{self, PackageAnswer};
use super::package_policy::{self, ProcessFacts};
use super::store::Saved;
use super::view::HarnessView;
use super::{run_policy, McpRelayDecideRequestV1};

/// A package call sent without the evaluation the lane decides from.
const EVALUATION_ABSENT: &str = "mcp_relay_package_evaluation_absent";
/// A package call without the relaying process's own facts: the workspace the
/// policy lookup is valid for, its working directory or its environment.
const FACTS_ABSENT: &str = "mcp_relay_package_facts_absent";
/// No store to resolve the saved package policy against.
const STORE_ABSENT: &str = "mcp_relay_package_store_absent";

/// One decided package call, and what its receipt is written against.
pub(super) struct Packaged {
    /// The package request's own artifact, which the receipt names by id.
    pub(super) artifact: GuardArtifact,
    /// The workspace the intent was parsed against, which the drain rebuilds
    /// the artifact from.
    pub(super) workspace: String,
    pub(super) answer: PackageAnswer,
}

/// Decide the package call the gate found an intent in.
pub(super) fn decide_package_leg(
    request: &McpRelayDecideRequestV1,
    view: &HarnessView,
    saved: Option<&Saved<'_>>,
    control_digest: &str,
    identity: &McpToolCallIdentityPayloadV1,
    intent: &PackageIntent,
    subject: &McpToolPolicySubjectV1,
) -> Result<Packaged, &'static str> {
    let evaluation = request
        .package_evaluation
        .as_ref()
        .ok_or(EVALUATION_ABSENT)?;
    let workspace = present(request.workspace.as_deref())?;
    let cwd = present(request.cwd.as_deref())?;
    if request.environment.is_empty() {
        return Err(FACTS_ABSENT);
    }
    // `package_policy` reads the saved rows the resolution is composed from,
    // so a call the store is unreadable for has no package policy at all.
    let saved = saved.ok_or(STORE_ABSENT)?;
    // The package request's artifact carries the tool call's own scope and
    // config path, as `_package_request_artifact` builds it.
    let artifact = build_package_request_artifact(
        &identity.artifact.harness,
        intent,
        &identity.artifact.config_path,
        &identity.artifact.source_scope,
    );
    let process = ProcessFacts {
        environment: &request.environment,
        cwd,
        home: &request.launcher_home,
    };
    let resolve = || {
        package_policy::package_policy(
            saved,
            view,
            &artifact,
            evaluation,
            control_digest,
            workspace,
            &process,
        )
    };
    let resolved = resolve()?;
    let answer = package_lane::decide_package(
        &view.mode,
        &request.build.tool_name,
        &request.build.server_name,
        &resolved,
        // The proxy's second resolution, which reads the store the decide
        // path still holds open: the fresh tool authority, then the fresh
        // package policy.
        || Ok((run_policy(subject, Some(saved))?, resolve()?)),
    )?;
    Ok(Packaged {
        artifact,
        workspace: workspace.to_owned(),
        answer,
    })
}

/// A request field the proxy sends for every package call, which a call
/// without it is not decided from.
fn present(field: Option<&str>) -> Result<&str, &'static str> {
    field.filter(|value| !value.is_empty()).ok_or(FACTS_ABSENT)
}

#[cfg(test)]
#[path = "mcp_relay_decide_package_leg_tests.rs"]
mod tests;
