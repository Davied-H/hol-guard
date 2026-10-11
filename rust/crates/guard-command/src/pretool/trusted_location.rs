//! Location trust shared by the Git binary lookup and loader search paths.
//!
//! A path is trusted when it sits outside the home directory, the working
//! directory and the temporary directories, and no ancestor can be written by
//! another user. The agent can write the excluded trees, so a binary or library
//! there could be planted by an earlier tool call.
use std::fs;
use std::path::Path;

pub(super) fn trusted_location(path: &Path, home: &Path, cwd: &Path) -> bool {
    let canonical_temp = fs::canonicalize(std::env::temp_dir()).ok();
    if path.starts_with(home)
        || path.starts_with(cwd)
        || path.starts_with(std::env::temp_dir())
        || canonical_temp
            .as_deref()
            .is_some_and(|directory| path.starts_with(directory))
        || path.starts_with("/tmp")
        || path.starts_with("/private/tmp")
    {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let Ok(home_metadata) = fs::metadata(home) else {
            return false;
        };
        let owner = home_metadata.uid();
        for ancestor in std::iter::once(path).chain(path.ancestors().skip(1)) {
            let Ok(metadata) = fs::metadata(ancestor) else {
                return false;
            };
            if metadata.mode() & 0o002 != 0
                || (metadata.mode() & 0o020 != 0
                    && metadata.uid() != owner
                    && metadata.gid() != home_metadata.gid())
                || !matches!(metadata.uid(), uid if uid == 0 || uid == owner)
            {
                return false;
            }
        }
    }
    #[cfg(windows)]
    {
        // The system's own folder locations, not the caller-controlled and
        // runtime-filtered ProgramFiles/SystemRoot environment variables.
        if !guard_runtime_windows_process::trusted_install_roots()
            .into_iter()
            .filter_map(|root| fs::canonicalize(root).ok())
            .any(|root| path.starts_with(root))
        {
            return false;
        }
    }
    true
}

/// A stamped loader search path keeps a Git read proven only when every entry
/// is a non-empty absolute path whose directory is a trusted location. An
/// empty entry or `.` means the working directory, and a relative entry
/// follows it, so either could load a library from the repository.
pub(super) fn trusted_library_search_path(value: &str, home: &Path, cwd: &Path) -> bool {
    !value.is_empty()
        && value.split(':').all(|entry| {
            let entry = Path::new(entry);
            entry.is_absolute()
                && fs::canonicalize(entry).is_ok_and(|directory| {
                    directory.is_dir() && trusted_location(&directory, home, cwd)
                })
        })
}
