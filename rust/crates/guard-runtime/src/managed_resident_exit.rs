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

use super::resident_failure_log;
use super::restart_budget;

/// Read the serving child's stderr on a thread of its own, handing the bytes
/// back over a channel rather than a join: a grandchild that inherited the
/// pipe can hold it open after the resident itself is gone, and the
/// supervisor must still finish. The pump never touches the record file, so
/// one left behind by an earlier run cannot overwrite a later run's record.
#[cfg(not(windows))]
pub(super) fn capture_resident_stderr(
    child: &mut std::process::Child,
) -> Option<std::sync::mpsc::Receiver<Vec<u8>>> {
    let stderr = child.stderr.take()?;
    let (sender, receiver) = std::sync::mpsc::channel();
    let _pump = std::thread::spawn(move || {
        let _ = sender.send(resident_failure_log::collect_resident_stderr(stderr));
    });
    Some(receiver)
}

/// Hand the restart budget the classification of this exit, and leave the
/// user a record of the runs that were not healthy. A broken record or a
/// busy budget must not change the supervised result, so both are best
/// effort here.
pub(super) fn record_supervised_exit(
    scope: &Path,
    stderr: Option<Vec<u8>>,
    success: bool,
    exit_code: Option<i32>,
    ran_for: Duration,
) {
    let code = exit_code.map_or_else(|| "none".to_owned(), |code| code.to_string());
    let ran_for_ms = ran_for.as_millis();
    let note = if !success {
        Some(format!(
            "native_resident_managed_exit_failed exit_code={code} ran_for_ms={ran_for_ms}"
        ))
    } else if restart_budget::healthy_exit(success, ran_for) {
        None
    } else {
        // A resident that reports success before it can have served anything
        // keeps its restart charge; say so where it can be seen.
        Some(format!(
            "native_resident_managed_exit_premature exit_code={code} ran_for_ms={ran_for_ms}"
        ))
    };
    // Stderr the pump has not handed over yet is lost rather than waited for,
    // but the exit note is still written: a pipe held open by a descendant
    // must not cost the user the reason the run ended.
    let stderr = stderr.unwrap_or_default();
    resident_failure_log::write_run(scope, &stderr, note.as_deref());
    let _ = restart_budget::release_after_exit(scope, success, ran_for);
}
