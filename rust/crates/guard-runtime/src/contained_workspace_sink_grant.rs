//! The local CLI grant a contained run is widened by.
//!
//! The sink never trusts a grant it was handed: it asks this device's store
//! itself when it prepares the plan, admits only a plan widened by exactly
//! that grant, and asks again after the second receipt. A blocked CLI stops
//! the run; a grant that changed in between, in any field, stops it too.
//!
//! The direct lane needs no grant routing: it sends a sandbox requirement here
//! as before, and an outside-roots review with grant rows defers to the
//! daemon, which routes a granted one here. Linux plans carry no capability.

use std::collections::BTreeMap;

use guard_contracts::{LocalCliHookRequestV1, LOCAL_CLI_HOOK_REQUEST_SCHEMA};

use super::*;
use crate::contained_workspace_grant_plan::ExpectedGrant;
use crate::local_cli_hook_contained::{grant_capabilities, ALLOW_CONTAINED_WITH_GRANT};

pub(super) const GRANT_CHANGED: &str = "The local CLI grant changed before launch.";
const GRANT_BLOCKED: &str = "This device blocked the local CLI this command launches.";
const STORE_BUSY_MILLISECONDS: u64 = 2_000;

/// The store question the hook asked, asked again for a sandbox requirement.
pub(super) fn request(
    guard_home: &Path,
    home: &str,
    workspace: &str,
    command: &str,
) -> Outcome<LocalCliHookRequestV1> {
    let guard_home = path_text(guard_home)?;
    let env: BTreeMap<String, String> = environment().into_iter().collect();
    Ok(LocalCliHookRequestV1 {
        schema: LOCAL_CLI_HOOK_REQUEST_SCHEMA.to_owned(),
        request_id: SINK_COMMAND.to_owned(),
        store_path: format!("{}/guard.db", guard_home.trim_end_matches('/')),
        guard_home,
        // Nothing is recorded here, so the store's source is never read.
        source: String::new(),
        busy_timeout_ms: STORE_BUSY_MILLISECONDS,
        command: command.to_owned(),
        cwd: workspace.to_owned(),
        home_dir: Some(home.to_owned()),
        user_home: home.to_owned(),
        env,
        current_action: "sandbox-required".to_owned(),
        current_reason_code: Some(WORKSPACE_REASON.to_owned()),
        grant_allowed: true,
    })
}

/// The grant the store decides for `request` now: `None` runs the base
/// sandbox; a blocked CLI or a store that cannot answer stops the run.
pub(super) fn decided(request: &LocalCliHookRequestV1) -> Outcome<Option<Value>> {
    let refined =
        crate::local_cli_hook_op::decide_refined(request).map_err(|_| Failure::unauthorized())?;
    match (refined.action.as_str(), refined.contained_grant) {
        (ALLOW_CONTAINED_WITH_GRANT, Some(grant)) => Ok(Some(grant)),
        ("block", _) => Err(Failure::new(AUTHORIZATION_FAILED, GRANT_BLOCKED)),
        ("sandbox-required", None) => Ok(None),
        _ => Err(Failure::unauthorized()),
    }
}

/// The `grant` field of the prepare input: `GrantInput`.
pub(super) fn prepare_input(grant: &Value) -> Value {
    json!({
        "identity_hash": grant["identity_hash"],
        "name": grant["name"],
        "capabilities": grant["capabilities"],
    })
}

/// What the plan must carry for `grant`; the state directory is the one the
/// command crate derives, `<canonical home>/.<name>`.
pub(super) fn expected(grant: &Value, home: &str) -> Outcome<ExpectedGrant> {
    let invalid = || Failure::invalid(INVALID_PLAN);
    let identity_hash = grant["identity_hash"]
        .as_str()
        .ok_or_else(invalid)?
        .to_owned();
    let capabilities = grant_capabilities(&grant["capabilities"]).map_err(|()| invalid())?;
    let stateful = capabilities
        .iter()
        .any(|name| name.starts_with("state-dir-"));
    let state_dir = match (stateful, grant["name"].as_str()) {
        (false, _) => None,
        (true, Some(name)) => std::fs::canonicalize(home)
            .ok()
            .and_then(|home| home.join(format!(".{name}")).to_str().map(str::to_owned)),
        (true, None) => return Err(invalid()),
    };
    Ok(ExpectedGrant {
        identity_hash,
        capabilities,
        state_dir,
    })
}

/// Fails unless the store still decides `first` for the command.
pub(super) fn unchanged(first: &Option<Value>, now: Outcome<Option<Value>>) -> Outcome<()> {
    match now {
        Ok(now) if now == *first => Ok(()),
        _ => Err(Failure::invalid(GRANT_CHANGED)),
    }
}

#[cfg(test)]
#[path = "contained_workspace_sink_grant_tests.rs"]
mod tests;
