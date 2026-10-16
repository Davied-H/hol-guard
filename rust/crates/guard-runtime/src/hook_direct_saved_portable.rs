//! The portable Git identity the daemon composes a saved lookup with.
//!
//! `resolve_policy_decision_lookup` (`store_portable_project_memory.py`)
//! reads the workspace's portable identity (`_portable_project_workspace`)
//! and composes the local lookup most restrictive with the lookup under that
//! identity, stripped of any permission it would grant
//! (`_portable_lookup_without_permission_elevation`). The resident derives
//! the identity itself (`project_identity`) and composes it the same way,
//! and reads whenever that identity resolves exactly. A row bound to another
//! project's identity is read by no lookup of this workspace: every
//! workspace selector the lookup binds is this workspace's own.

use super::HookDirectDefer;
use crate::context_digest::python_strip;
use crate::mcp_tool_policy_lookup::{most_restrictive, without_permission_elevation};
use crate::project_identity::{portable_workspace, PortableIdentity};
use serde_json::Value;

/// `_portable_project_workspace(workspace)` for the daemon's absolute
/// workspace. A workspace that already names a portable identity is its own,
/// and one whose identity the resident does not resolve exactly defers.
pub(super) fn identity(workspace: &str) -> Result<Option<String>, HookDirectDefer> {
    match portable_workspace(workspace) {
        PortableIdentity::Absent => Ok(None),
        PortableIdentity::Identity(identity) => Ok(Some(identity)),
        PortableIdentity::Unknown => Err(HookDirectDefer::SavedDecision),
    }
}

/// The local lookup composed most restrictive with the restrictive-only
/// lookup under the workspace's portable identity; that lookup alone for a
/// workspace that already names the identity, as
/// `resolve_policy_decision_lookup` returns it.
pub(super) fn compose(
    workspace: &str,
    identity: &str,
    local: Value,
    portable: Value,
) -> Result<Value, HookDirectDefer> {
    let preview = without_permission_elevation(portable);
    if python_strip(workspace) == identity {
        return Ok(preview);
    }
    most_restrictive(&[local, preview]).ok_or(HookDirectDefer::SavedDecision)
}

#[cfg(all(test, unix))]
#[path = "hook_direct_saved_portable_tests.rs"]
mod tests;
