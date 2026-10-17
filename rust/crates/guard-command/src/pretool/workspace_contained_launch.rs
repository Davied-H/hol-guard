//! Programs the workspace sandbox could not run.
use super::PathContext;
use crate::CanonicalCommandV1;
use guard_contracts::GuardExecutionEnvironmentV1;
use std::path::Path;

/// Whether the sandbox could not run a program the command launches, as the
/// agent's shell would resolve it from the session `PATH`. Without that
/// `PATH` the launch cannot be compared, and the sandbox decides.
#[cfg(unix)]
pub(super) fn outside(
    model: &CanonicalCommandV1,
    workspace: &Path,
    context: PathContext<'_>,
    execution_environment: Option<&GuardExecutionEnvironmentV1>,
) -> bool {
    let (Some(environment), Some(cwd)) = (execution_environment, context.cwd) else {
        return false;
    };
    crate::restricted_pytest::launches_outside_exec_roots(
        model
            .segments
            .iter()
            .filter_map(|segment| segment.executable.as_deref()),
        &environment.path,
        context.home_dir.map(Path::new),
        workspace,
        Path::new(cwd),
    )
}

#[cfg(not(unix))]
pub(super) fn outside(
    _model: &CanonicalCommandV1,
    _workspace: &Path,
    _context: PathContext<'_>,
    _execution_environment: Option<&GuardExecutionEnvironmentV1>,
) -> bool {
    false
}
