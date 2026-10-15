//! Where a proven `git worktree add` creates its checkout, and the directory
//! its `-C` enters.

use std::path::{Path, PathBuf};

/// The directory `git -C <dir>` enters: absolute or relative to the context
/// cwd, an existing directory, canonical.
pub(super) fn resolve_chdir(value: &str, context: super::super::PathContext<'_>) -> Option<String> {
    let cwd = std::fs::canonicalize(Path::new(context.cwd?)).ok()?;
    let supplied = Path::new(value);
    let target = if supplied.is_absolute() {
        supplied.to_path_buf()
    } else {
        cwd.join(supplied)
    };
    let canonical = std::fs::canonicalize(target).ok()?;
    canonical
        .is_dir()
        .then(|| canonical.to_str().map(str::to_owned))?
}

pub(super) fn fresh_destination(
    value: &str,
    context: super::super::PathContext<'_>,
) -> Option<PathBuf> {
    let home = std::fs::canonicalize(Path::new(context.home_dir?)).ok()?;
    let cwd = std::fs::canonicalize(Path::new(context.cwd?)).ok()?;
    if !home.is_dir() || !home.is_absolute() || !cwd.is_dir() || !cwd.is_absolute() {
        return None;
    }
    // The shell expands an unquoted `~/` from its own HOME, so the spelling
    // is proved only when that HOME is the declared one.
    let expanded;
    let value = if value.starts_with("~/") {
        if cfg!(windows) || !context.shell_home_matches {
            return None;
        }
        expanded = super::super::read_paths::expand_home_read_path(value, context.home_dir)?;
        expanded.as_str()
    } else {
        value
    };
    let supplied = Path::new(value);
    let target = if supplied.is_absolute() {
        supplied.to_path_buf()
    } else {
        cwd.join(supplied)
    };
    let parent = target.parent()?;
    match std::fs::symlink_metadata(&target) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        _ => return None,
    }
    // The parent may be reached through a symlink, as `/tmp` is on macOS.
    // Everything below judges the canonical directory exactly as if it had
    // been spelled, so a link cannot lead anywhere the spelling could not;
    // a link someone else could swap before Git runs is never followed.
    if !fixed_symlinks(parent, &home) {
        return None;
    }
    let canonical_parent = std::fs::canonicalize(parent).ok()?;
    // A checkout below the shared temporary directory, where the user owns
    // every directory on the way, is as private as one below home. Directly
    // in the sticky root or the user's own temporary directory, the leaf
    // must not exist yet, which the check above already proves.
    let temporary = super::super::git_routes::temporary_checkout_parent(&canonical_parent, context);
    if !canonical_parent.is_dir() {
        return None;
    }
    if !canonical_parent.starts_with(&home) && !temporary {
        return None;
    }
    let leaf = target.file_name()?.to_str()?;
    if leaf.starts_with('.') || leaf == ".." {
        return None;
    }
    let destination = canonical_parent.join(leaf);
    if protected_worktree_destination(&destination)
        || !(temporary
            || super::super::safe_writes::bounded_native_file_write_target(
                destination.to_str()?,
                context.home_dir,
                context.cwd,
            ))
    {
        return None;
    }
    Some(destination)
}

/// Whether every symlink on the way to `path` sits where only root or the
/// home owner could replace it: a directory one of them owns that no one
/// else can write, or a sticky one when the link is theirs too. Such a link
/// (`/tmp` on macOS, or one the user made) leads where it led when checked.
#[cfg(unix)]
fn fixed_symlinks(path: &Path, home: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Ok(owner) = std::fs::metadata(home).map(|metadata| metadata.uid()) else {
        return false;
    };
    let trusted = |uid: u32| uid == 0 || uid == owner;
    path.ancestors().all(|ancestor| {
        let Ok(link) = std::fs::symlink_metadata(ancestor) else {
            return false;
        };
        if !link.file_type().is_symlink() {
            return true;
        }
        let Some(directory) = ancestor.parent() else {
            return false;
        };
        std::fs::metadata(directory).is_ok_and(|metadata| {
            trusted(metadata.uid())
                && (metadata.mode() & 0o022 == 0
                    || (metadata.mode() & 0o1000 != 0 && trusted(link.uid())))
        })
    })
}

/// Off Unix there is no owner to check, so a symlinked parent stays reviewed.
#[cfg(not(unix))]
fn fixed_symlinks(path: &Path, _home: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|metadata| !metadata.file_type().is_symlink())
}

/// A checkout in a workflow directory or an autostart location (a login
/// item directory, a systemd unit tree) is reviewed whatever its parent, so
/// the owned temporary carve-out above cannot place one there either.
fn protected_worktree_destination(path: &Path) -> bool {
    if super::super::safe_writes::autostart_write_target(path) {
        return true;
    }
    let parts: Vec<String> = path
        .components()
        .filter_map(|component| match component {
            std::path::Component::Normal(value) => {
                Some(value.to_string_lossy().to_ascii_lowercase())
            }
            _ => None,
        })
        .collect();
    parts
        .windows(2)
        .any(|pair| pair == [".github", "workflows"])
}
