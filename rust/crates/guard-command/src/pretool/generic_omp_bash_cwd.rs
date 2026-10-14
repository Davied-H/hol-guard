//! Oh My Pi's `bash` tool runs its command in the optional `cwd` argument.
//!
//! The host resolves that argument against the session directory, so a
//! command such as `cat config` with `cwd: "~/.ssh"` reads `~/.ssh/config`.
//! Evaluating the command against the session directory instead judged the
//! wrong files, and a Git command in a repository below the session
//! directory could not prove its configuration.

use serde_json::Value;
use std::path::{Component, Path, PathBuf};

const INPUT_KEYS: [&str; 3] = ["tool_input", "toolInput", "arguments"];

pub(super) enum BashCwd {
    /// No `cwd` argument, or one naming the session directory.
    Session,
    /// A directory below the session directory, spelled from it.
    Within(String),
    /// A directory outside the session directory, canonicalized.
    Outside(String),
    /// A plain path naming no existing directory, so nothing would run.
    Missing,
    /// A form the host resolves in a way Guard does not model.
    Unresolved,
}

pub(super) fn resolve(payload: &Value, home_dir: Option<&str>, session: Option<&str>) -> BashCwd {
    let mut values = INPUT_KEYS
        .iter()
        .filter_map(|key| payload.get(*key)?.as_object()?.get("cwd"));
    let Some(first) = values.next() else {
        return BashCwd::Session;
    };
    if values.any(|value| value != first) {
        return BashCwd::Unresolved;
    }
    let Some(text) = first.as_str() else {
        return BashCwd::Unresolved;
    };
    // The host treats an empty value as absent and a root of only slashes
    // as the session directory.
    if text.is_empty() || text.bytes().all(|byte| byte == b'/') {
        return BashCwd::Session;
    }
    let Some(session) = session.filter(|session| Path::new(session).is_absolute()) else {
        return BashCwd::Unresolved;
    };
    let Some(target) = literal_target(text, home_dir, session) else {
        return BashCwd::Unresolved;
    };
    let Ok(root) = Path::new(session).canonicalize() else {
        return BashCwd::Unresolved;
    };
    let target = match target.canonicalize() {
        Ok(target) => target,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return BashCwd::Missing,
        Err(_) => return BashCwd::Unresolved,
    };
    if !target.is_dir() {
        return BashCwd::Unresolved;
    }
    match target.strip_prefix(&root) {
        Ok(suffix) if suffix.as_os_str().is_empty() => BashCwd::Session,
        Ok(suffix) => match suffix.to_str() {
            Some(suffix) => BashCwd::Within(format!("{}/{suffix}", session.trim_end_matches('/'))),
            None => BashCwd::Unresolved,
        },
        Err(_) => match target.to_str() {
            Some(text) if !text.contains('\'') => BashCwd::Outside(text.to_owned()),
            _ => BashCwd::Unresolved,
        },
    }
}

/// The directory a plain path names. The host also rewrites `@`, `:` and
/// `file:` prefixes, Unicode spaces and internal URLs before resolving, so
/// those forms stay unresolved rather than guessed.
fn literal_target(text: &str, home_dir: Option<&str>, session: &str) -> Option<PathBuf> {
    if !text.is_ascii()
        || text
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b'\\')
        || text.starts_with(['@', ':'])
        || text.starts_with("file:")
        || text.contains("://")
    {
        return None;
    }
    let path = if text == "~" || text.starts_with("~/") {
        let home = home_dir.filter(|home| Path::new(home).is_absolute())?;
        Path::new(home).join(text.trim_start_matches('~').trim_start_matches('/'))
    } else if text.starts_with('~') {
        return None;
    } else {
        Path::new(session).join(text)
    };
    path.components()
        .all(|component| !matches!(component, Component::Prefix(_)))
        .then_some(path)
}
