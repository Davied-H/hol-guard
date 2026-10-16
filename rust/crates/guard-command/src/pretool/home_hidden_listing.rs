//! Name-only listing of a hidden directory in the home directory
//! (`ls ~/.config/`, `ls ~/.agents/skills/`, `find ~/.config -maxdepth 1`).
//!
//! A listing prints entry names and metadata, never file content, so a
//! dot-directory that stores no credentials, and its visible subdirectories,
//! are as safe to list as the home directory itself. `~/.codex` and
//! `~/.claude` keep their logins in known files that content reads still
//! refuse, so their names list too. Credential, key, wallet, browser-profile,
//! other agent-login and Guard state stores keep their review at any depth, and so do the stores that live below `~/.config` and
//! `~/.local/share` (`~/.config/gh`). Callers must bound the listing to the
//! directory's own entries: a recursive listing of `~/.config` prints the
//! names inside `~/.config/gh` and keeps its review.
//!
//! The store lists themselves live in [`crate::credential_store_names`], so the
//! content screen that `cat` and `rg` go through refuses the same directories.

use std::path::{Path, PathBuf};

use crate::credential_store_names::clears_store_screen;
pub(super) use crate::credential_store_names::{CREDENTIAL_STORE_NAMES, HARNESS_HOME_NAMES};

/// Whether `value` names an existing directory below a hidden component of
/// the home directory that is not, and is not inside, a credential store.
pub(in crate::pretool) fn home_hidden_directory(
    value: &str,
    home_dir: Option<&str>,
    cwd: Option<&str>,
) -> bool {
    if value.is_empty()
        || value.len() > 4096
        || value.starts_with('-')
        || value.contains(|c: char| {
            // Windows spells the home path with `\`, so there it is a separator.
            (c == '\\' && !cfg!(windows))
                || [
                    '$', '`', '|', ';', '&', '<', '>', '\n', '\r', '\0', '*', '?', '[', ']', '{',
                    '}',
                ]
                .contains(&c)
        })
        || value.split(['/', '\\']).any(|part| part == "..")
        || !super::super::verified_path_context(home_dir, cwd)
    {
        return false;
    }
    let (Some(raw_home), Some(expanded)) = (home_dir, expanded(value, home_dir, cwd)) else {
        return false;
    };
    let Ok(home) = std::fs::canonicalize(raw_home) else {
        return false;
    };
    let Ok(canonical) = std::fs::canonicalize(&expanded) else {
        return false;
    };
    // The spelled path must be the resolved one: a link anywhere below the
    // home directory could dress another store, or the home directory
    // itself, as an ordinary dot-directory.
    let Some(relative) = expanded
        .strip_prefix(raw_home)
        .or_else(|_| expanded.strip_prefix(&home))
        .ok()
        .filter(|relative| home.join(relative) == canonical)
    else {
        return false;
    };
    let Some(first) = relative.components().next() else {
        return false;
    };
    // Only the home entry itself is hidden: a dot-directory nested deeper
    // (`~/.nvm/.cache`) is private state of the tool that owns it.
    let mut names = relative.components().skip(1);
    canonical.is_dir()
        && first.as_os_str().to_string_lossy().starts_with('.')
        && !names.any(|name| name.as_os_str().to_string_lossy().starts_with('.'))
        && clears_store_screen(relative)
        && super::super::resolved_location_allowed(&canonical, home_dir, cwd, false)
}

fn expanded(value: &str, home_dir: Option<&str>, cwd: Option<&str>) -> Option<PathBuf> {
    let path = if value == "~" || value.starts_with("~/") || value.starts_with("~\\") {
        PathBuf::from(super::super::expand_home_read_path(value, home_dir)?)
    } else if Path::new(value).is_absolute() {
        PathBuf::from(value)
    } else {
        let cwd = cwd?;
        let root =
            super::super::expand_home_read_path(cwd, home_dir).unwrap_or_else(|| cwd.to_owned());
        Path::new(&root).join(value)
    };
    Some(path.components().collect())
}
