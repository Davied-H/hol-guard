//! Sibling checkouts below the shared temporary directory. Anyone can write
//! there, so a checkout counts only when every directory down to it belongs
//! to the home owner and no one else can write it.

/// Whether canonical `path` is a non-hidden directory strictly below the
/// shared temporary directory whose every directory down from that root
/// belongs to the home owner and is writable by no one else.
pub(in crate::pretool) fn owned_temporary_directory(
    path: &std::path::Path,
    context: super::super::PathContext<'_>,
) -> bool {
    let Some(home) = context
        .home_dir
        .and_then(|home| std::fs::canonicalize(home).ok())
    else {
        return false;
    };
    owned_temporary_roots().iter().any(|root| {
        path.strip_prefix(root).is_ok_and(|relative| {
            !relative.as_os_str().is_empty()
                && relative.components().all(|part| {
                    matches!(part, std::path::Component::Normal(name) if !name.to_string_lossy().starts_with('.'))
                })
        }) && owned_below(root, path, &home)
    })
}

/// Whether canonical `parent` may hold a fresh checkout `git worktree add`
/// creates: an owned directory below the shared temporary root, or the root
/// itself, or the home owner's private macOS temporary directory.
///
/// Directly in the sticky shared root, another user could pre-create the
/// leaf only by winning a race against the existence check, the same race
/// the native file-write proof already accepts there. A planted directory
/// still fails that check, and the hook, configuration and filter proofs
/// apply wherever the checkout lands.
pub(in crate::pretool) fn temporary_checkout_parent(
    parent: &std::path::Path,
    context: super::super::PathContext<'_>,
) -> bool {
    owned_temporary_directory(parent, context)
        || owned_temporary_roots()
            .iter()
            .any(|root| root == parent && sticky_shared_root(root, context))
        || private_temporary_root(parent, context)
}

/// A sticky shared root owned by root or the home owner, so entries another
/// user creates there can never be renamed or removed out from under ours.
#[cfg(unix)]
fn sticky_shared_root(root: &std::path::Path, context: super::super::PathContext<'_>) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Some(owner) = home_owner(context) else {
        return false;
    };
    std::fs::symlink_metadata(root).is_ok_and(|metadata| {
        metadata.is_dir()
            && metadata.mode() & 0o1000 != 0
            && (metadata.uid() == 0 || metadata.uid() == owner)
    })
}

#[cfg(not(unix))]
fn sticky_shared_root(_root: &std::path::Path, _context: super::super::PathContext<'_>) -> bool {
    false
}

/// The home owner's own macOS temporary directory
/// (`/private/var/folders/<a>/<b>/T`), or an owned directory below it. No
/// other user can create an entry there.
#[cfg(target_os = "macos")]
fn private_temporary_root(
    parent: &std::path::Path,
    context: super::super::PathContext<'_>,
) -> bool {
    use std::os::unix::fs::MetadataExt;
    let (Some(owner), Some(home)) = (
        home_owner(context),
        context
            .home_dir
            .and_then(|home| std::fs::canonicalize(home).ok()),
    ) else {
        return false;
    };
    let names: Vec<&std::ffi::OsStr> = parent
        .components()
        .skip(1)
        .map(|part| part.as_os_str())
        .collect();
    if names.len() < 6 || names[..3] != ["private", "var", "folders"] || names[5] != "T" {
        return false;
    }
    let root = std::path::Path::new("/").join(names[..6].iter().collect::<std::path::PathBuf>());
    std::fs::symlink_metadata(&root).is_ok_and(|metadata| {
        metadata.is_dir() && metadata.uid() == owner && metadata.mode() & 0o077 == 0
    }) && parent
        .strip_prefix(&root)
        .is_ok_and(|relative| {
            relative.components().all(|part| {
                matches!(part, std::path::Component::Normal(name) if !name.to_string_lossy().starts_with('.'))
            })
        })
        && owned_below(&root, parent, &home)
}

#[cfg(not(target_os = "macos"))]
fn private_temporary_root(
    _parent: &std::path::Path,
    _context: super::super::PathContext<'_>,
) -> bool {
    false
}

#[cfg(unix)]
fn home_owner(context: super::super::PathContext<'_>) -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    context
        .home_dir
        .and_then(|home| std::fs::metadata(home).ok())
        .map(|metadata| metadata.uid())
}

/// The canonical shared temporary roots (`/tmp`, which is `/private/tmp` on
/// macOS) that sibling checkouts may sit below; none off Unix.
pub(in crate::pretool) fn owned_temporary_roots() -> Vec<std::path::PathBuf> {
    if cfg!(not(unix)) {
        return Vec::new();
    }
    let mut roots: Vec<std::path::PathBuf> = ["/tmp", "/private/tmp"]
        .iter()
        .filter_map(|root| std::fs::canonicalize(root).ok())
        .collect();
    roots.dedup();
    roots
}

/// `path` with a leading root-owned system alias such as macOS `/tmp`
/// (a link to `/private/tmp`) replaced by the directory it names. Only root
/// can create or retarget an entry directly in `/`, so the alias names the
/// same directory for Git, for the shell's `cd` and for this proof. Any
/// other link keeps the path unchanged and fails the checks that follow.
#[cfg(unix)]
pub(in crate::pretool) fn system_alias_resolved(path: &std::path::Path) -> std::path::PathBuf {
    use std::os::unix::fs::MetadataExt;
    let mut components = path.components();
    let (Some(std::path::Component::RootDir), Some(std::path::Component::Normal(first))) =
        (components.next(), components.next())
    else {
        return path.to_path_buf();
    };
    let alias = std::path::Path::new("/").join(first);
    let root_owned = |metadata: &std::fs::Metadata| metadata.uid() == 0;
    let trusted = std::fs::symlink_metadata("/")
        .is_ok_and(|root| root_owned(&root) && root.mode() & 0o022 == 0)
        && std::fs::symlink_metadata(&alias)
            .is_ok_and(|link| link.file_type().is_symlink() && root_owned(&link));
    match trusted
        .then(|| std::fs::canonicalize(&alias).ok())
        .flatten()
    {
        Some(resolved) if components.as_path().as_os_str().is_empty() => resolved,
        Some(resolved) => resolved.join(components.as_path()),
        None => path.to_path_buf(),
    }
}

#[cfg(not(unix))]
pub(in crate::pretool) fn system_alias_resolved(path: &std::path::Path) -> std::path::PathBuf {
    path.to_path_buf()
}

/// Whether every directory strictly below `root` down to `path` belongs to
/// the owner of `home` and grants no group or other write access.
#[cfg(unix)]
pub(super) fn owned_below(
    root: &std::path::Path,
    path: &std::path::Path,
    home: &std::path::Path,
) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Ok(owner) = std::fs::metadata(home).map(|metadata| metadata.uid()) else {
        return false;
    };
    path.ancestors()
        .take_while(|directory| *directory != root)
        .all(|directory| {
            std::fs::symlink_metadata(directory).is_ok_and(|metadata| {
                metadata.is_dir() && metadata.uid() == owner && metadata.mode() & 0o022 == 0
            })
        })
}

#[cfg(not(unix))]
pub(super) fn owned_below(
    _root: &std::path::Path,
    _path: &std::path::Path,
    _home: &std::path::Path,
) -> bool {
    false
}

#[cfg(all(test, unix))]
mod tests {
    use super::system_alias_resolved;
    use std::path::{Path, PathBuf};

    #[test]
    fn only_a_root_owned_top_level_alias_resolves() {
        // `/tmp` is a root-owned link on macOS and a plain directory on
        // Linux; either way the proof and the shell land in the same place.
        let shared = std::fs::canonicalize("/tmp").unwrap();
        assert_eq!(
            system_alias_resolved(Path::new("/tmp/hg-alias-leaf")),
            shared.join("hg-alias-leaf")
        );
        assert_eq!(system_alias_resolved(Path::new("/tmp")), shared);
        assert_eq!(
            system_alias_resolved(Path::new("relative/leaf")),
            PathBuf::from("relative/leaf")
        );
        // A link the user owns keeps its spelling, so the symlinked-parent
        // check that follows still refuses it.
        let base = std::fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!("hg-alias-{}", std::process::id()));
        std::fs::create_dir_all(base.join("real")).unwrap();
        let link = base.join("link");
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(base.join("real"), &link).unwrap();
        let through_link = link.join("leaf");
        assert_eq!(system_alias_resolved(&through_link), through_link);
        let _ = std::fs::remove_dir_all(&base);
    }
}
