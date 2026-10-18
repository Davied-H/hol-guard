//! Close out one supervised resident run.
//!
//! The client that asked for a resident is a one-shot process and is usually
//! gone before the resident it spawned has finished. The supervisor is the
//! only process that outlives that client and reaps the serving child, so it
//! is the one place that can say whether a run was an orderly
//! start-serve-exit cycle or a failure, and the only place that can keep the
//! child's stderr.

use std::path::Path;
use std::time::Duration;

use super::resident_failure_log::ResidentFailureLog;
use super::restart_budget;

/// Drain the serving child's stderr into this scope's record on a thread of
/// its own, handing the record back over a channel rather than a join: a
/// grandchild that inherited the pipe can hold it open after the resident
/// itself is gone, and the supervisor must still finish.
#[cfg(not(windows))]
pub(super) fn capture_resident_stderr(
    child: &mut std::process::Child,
    scope: &Path,
) -> Option<std::sync::mpsc::Receiver<ResidentFailureLog>> {
    let stderr = child.stderr.take()?;
    let (sender, receiver) = std::sync::mpsc::channel();
    let scope = scope.to_owned();
    let _pump = std::thread::spawn(move || {
        let mut record = ResidentFailureLog::for_scope(&scope);
        record.drain(stderr);
        let _ = sender.send(record);
    });
    Some(receiver)
}

/// Hand the restart budget the classification of this exit, and leave the
/// user a record of the runs that were not healthy. A broken record or a
/// busy budget must not change the supervised result, so both are best
/// effort here.
pub(super) fn record_supervised_exit(
    scope: &Path,
    record: Option<ResidentFailureLog>,
    success: bool,
    exit_code: Option<i32>,
    ran_for: Duration,
) {
    // No record means the stderr pump still owns the file. Leave it to the
    // pump rather than truncating a record that is still being written.
    if let Some(mut record) = record {
        let code = exit_code.map_or_else(|| "none".to_owned(), |code| code.to_string());
        let ran_for_ms = ran_for.as_millis();
        if !success {
            record.note(&format!(
                "native_resident_managed_exit_failed exit_code={code} ran_for_ms={ran_for_ms}"
            ));
        } else if !restart_budget::healthy_exit(success, ran_for) {
            // A resident that reports success before it can have served
            // anything keeps its restart charge; say so where it can be seen.
            record.note(&format!(
                "native_resident_managed_exit_premature exit_code={code} ran_for_ms={ran_for_ms}"
            ));
        }
    }
    let _ = restart_budget::release_after_exit(scope, success, ran_for);
}
