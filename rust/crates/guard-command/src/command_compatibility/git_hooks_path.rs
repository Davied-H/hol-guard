//! Hooks paths that leave an inspection read with no hook to run.

/// Hooks never run for an inspection read, and a path with no hook files adds
/// none. `/dev/null` is the conventional way to disable hooks entirely.
const GIT_HOOK_NAMES: &[&str] = &[
    "applypatch-msg",
    "pre-applypatch",
    "post-applypatch",
    "pre-commit",
    "pre-merge-commit",
    "prepare-commit-msg",
    "commit-msg",
    "post-commit",
    "pre-rebase",
    "post-checkout",
    "post-merge",
    "pre-push",
    "pre-receive",
    "update",
    "proc-receive",
    "post-receive",
    "post-update",
    "reference-transaction",
    "push-to-checkout",
    "pre-auto-gc",
    "post-rewrite",
    "sendemail-validate",
    "fsmonitor-watchman",
    "p4-changelist",
    "p4-prepare-changelist",
    "p4-post-changelist",
    "p4-pre-submit",
    "post-index-change",
];

/// `/dev/null`, which switches hooks off. Git for Windows does not map it to
/// the null device here but resolves it below the current drive, so there it
/// switches hooks off only while no drive holds hooks below it.
pub(super) fn null_hooks_path(value: &str) -> bool {
    value == "/dev/null" && (!cfg!(windows) || hooks_path_names_no_hooks(value))
}

pub(super) fn hooks_path_names_no_hooks(value: &str) -> bool {
    // Windows resolves a rooted path without a drive (`/dev/null`,
    // `/tmp/no-hooks`) against whichever drive is current when a hook would
    // run, so it names no hooks only when it names none below any drive.
    let path = std::path::Path::new(value);
    if cfg!(windows) && path.has_root() && !path.is_absolute() {
        return (b'A'..=b'Z')
            .all(|drive| hooks_path_names_no_hooks(&format!("{}:{value}", drive as char)));
    }
    if value == "/dev/null" {
        return true;
    }
    // Git joins an empty hooks path as `/<hook>`, so it names the filesystem root.
    if value.is_empty() {
        return GIT_HOOK_NAMES.iter().all(|name| {
            std::fs::symlink_metadata(std::path::Path::new("/").join(name))
                .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
        });
    }
    if !path.is_absolute() || value.starts_with('~') {
        return false;
    }
    match std::fs::symlink_metadata(path) {
        Err(error) => {
            error.kind() == std::io::ErrorKind::NotFound
                // No such drive, or no media in the drive.
                || cfg!(windows) && matches!(error.raw_os_error(), Some(15 | 21))
        }
        Ok(metadata) => {
            metadata.is_dir()
                && std::fs::read_dir(path).is_ok_and(|mut entries| entries.next().is_none())
        }
    }
}
