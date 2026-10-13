//! Metadata-only `ls` operands that the general read screens reject.
//!
//! `ls` prints names, sizes, modes and times, never file content. Two shapes
//! qualify here:
//!
//! * one existing regular file whose name marks it as a credential, such as
//!   `~/kubeconfig.yaml`. Reading it stays reviewed; confirming it exists
//!   does not expose it. Symlinks, directories (whose entries could name
//!   further secrets) and paths inside credential stores stay guarded.
//! * a global package tree below a node version manager or runtime in the
//!   home directory, such as `~/.bun/install/global/node_modules` or
//!   `~/.nvm/versions/node/<v>/lib/node_modules`. The path must pass through
//!   a `node_modules` component, so the tool's caches, settings and
//!   credential files beside it stay guarded.

use std::path::{Component, Path, PathBuf};

const PACKAGE_ROOTS: [&str; 6] = [".bun", ".nvm", ".volta", ".fnm", ".npm-global", ".asdf"];

fn plain_operand(value: &str, context: crate::pretool::PathContext<'_>) -> Option<PathBuf> {
    if value.is_empty()
        || value.len() > 4096
        || value.starts_with('-')
        || value.contains([
            '$', '`', '|', ';', '&', '<', '>', '\n', '\r', '\0', '\\', '*', '?', '[', ']', '{', '}',
        ])
        || value.split('/').any(|part| part == "..")
        || !crate::pretool::safe_reads::verified_path_context(context.home_dir, context.cwd)
    {
        return None;
    }
    let expanded = crate::pretool::read_paths::expand_home_read_path(value, context.home_dir)
        .unwrap_or_else(|| value.to_owned());
    let expanded = Path::new(&expanded);
    if expanded.is_absolute() {
        return Some(expanded.to_path_buf());
    }
    if value.starts_with('~') {
        return None;
    }
    let cwd = context.cwd?;
    let cwd = crate::pretool::read_paths::expand_home_read_path(cwd, context.home_dir)
        .unwrap_or_else(|| cwd.to_owned());
    Some(Path::new(&cwd).join(expanded))
}

/// `ls -la ~/kubeconfig.yaml`: one regular, non-symlink file whose only
/// screen failure is its credential-like name.
pub(in crate::pretool) fn credential_file_metadata_operand(
    value: &str,
    context: crate::pretool::PathContext<'_>,
) -> bool {
    let Some(path) = plain_operand(value, context) else {
        return false;
    };
    if !std::fs::symlink_metadata(&path).is_ok_and(|metadata| metadata.file_type().is_file()) {
        return false;
    }
    let Ok(canonical) = std::fs::canonicalize(&path) else {
        return false;
    };
    let Some(parent) = canonical.parent() else {
        return false;
    };
    canonical.is_file()
        && guard_secure_fs::sensitive_path_family(&canonical).is_none()
        && crate::pretool::read_paths::resolved_path_allowed_for_operation(
            parent,
            context.home_dir,
            context.cwd,
            false,
            true,
        )
}

/// `ls ~/.bun/install/global/node_modules`: a listing inside a global
/// `node_modules` tree of a home-level runtime or version manager.
pub(in crate::pretool) fn global_package_listing_operand(
    value: &str,
    context: crate::pretool::PathContext<'_>,
) -> bool {
    let (Some(path), Some(home_dir)) = (plain_operand(value, context), context.home_dir) else {
        return false;
    };
    let Ok(relative) = path.strip_prefix(home_dir) else {
        return false;
    };
    let mut names = Vec::new();
    for component in relative.components() {
        let Component::Normal(name) = component else {
            return false;
        };
        let Some(name) = name.to_str() else {
            return false;
        };
        names.push(name);
    }
    let Some((root, rest)) = names.split_first() else {
        return false;
    };
    let Some(modules) = rest.iter().position(|name| *name == "node_modules") else {
        return false;
    };
    if !PACKAGE_ROOTS.contains(root)
        || rest[..modules].iter().any(|name| name.starts_with('.'))
        || rest.iter().any(|name| {
            guard_secure_fs::sensitive_external_filename(Path::new(name))
                || guard_secure_fs::credential_named_path(Path::new(name))
        })
    {
        return false;
    }
    let Ok(canonical) = std::fs::canonicalize(&path) else {
        return false;
    };
    let Ok(tool_root) = std::fs::canonicalize(Path::new(home_dir).join(root)) else {
        return false;
    };
    if guard_secure_fs::sensitive_path_family(&canonical).is_some()
        || guard_secure_fs::credential_named_path(&canonical)
    {
        return false;
    }
    canonical.starts_with(&tool_root)
        || crate::pretool::read_paths::resolved_path_allowed_for_operation(
            &canonical,
            context.home_dir,
            context.cwd,
            false,
            true,
        )
}
