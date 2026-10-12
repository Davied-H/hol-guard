//! Bounded read of a workspace repository's configuration for the workspace
//! sandbox: helper paths inside the workspace become write-denied so a
//! sandboxed command cannot plant code a later, unsandboxed Git would run.
use std::fs;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

const MAX_CONFIG_BYTES: u64 = 64 * 1024;
const MAX_DENIALS: usize = 64;

/// `Ok(None)` when the workspace has no repository, `Ok(Some(text))` for a
/// plain, bounded `.git/config`, and `Err` for anything the sandbox cannot
/// reason about (symlinked or file-form `.git`, oversized or binary config).
pub(crate) fn repository_config(workspace: &Path) -> Result<Option<String>, ()> {
    let git = workspace.join(".git");
    match fs::symlink_metadata(&git) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(()),
        Ok(metadata) if !metadata.is_dir() => return Err(()),
        Ok(_) => {}
    }
    let config = git.join("config");
    match fs::symlink_metadata(&config) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Some(String::new()))
        }
        Err(_) => return Err(()),
        Ok(metadata) if !metadata.is_file() || metadata.len() > MAX_CONFIG_BYTES => return Err(()),
        Ok(_) => {}
    }
    let mut bytes = Vec::new();
    fs::File::open(&config)
        .map_err(|_| ())?
        .take(MAX_CONFIG_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ())?;
    if bytes.len() as u64 > MAX_CONFIG_BYTES || bytes.contains(&0) {
        return Err(());
    }
    String::from_utf8(bytes).map(Some).map_err(|_| ())
}

fn normalize(path: &Path) -> PathBuf {
    let mut result = PathBuf::new();
    for component in path.components() {
        match component {
            Component::ParentDir => {
                result.pop();
            }
            Component::CurDir => {}
            other => result.push(other.as_os_str()),
        }
    }
    result
}

fn inside(workspace: &Path, value: &str) -> Option<PathBuf> {
    let value = value.trim().trim_matches('"');
    if value.is_empty() || value.starts_with('~') || value.contains("://") {
        return None;
    }
    let path = Path::new(value);
    let joined = if path.is_absolute() {
        path.to_path_buf()
    } else {
        workspace.join(path)
    };
    let normal = normalize(&joined);
    (normal.starts_with(workspace) && normal != workspace).then_some(normal)
}

/// Workspace paths a configured hook directory, include or helper command
/// names. Every one becomes write-denied inside the sandbox; `None` when the
/// list exceeds its bound.
pub(crate) fn helper_write_denials(config: &str, workspace: &Path) -> Option<Vec<PathBuf>> {
    let mut denials: Vec<PathBuf> = Vec::new();
    let mut section = String::new();
    for line in config.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(header) = line.strip_prefix('[') {
            let name = header.trim_end_matches(']').trim();
            section = name
                .split(|c: char| c.is_whitespace() || c == '"')
                .next()
                .unwrap_or_default()
                .to_ascii_lowercase();
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim().to_ascii_lowercase();
        let value = value.trim();
        let candidate = if key == "hookspath" || (section.starts_with("include") && key == "path") {
            inside(workspace, value)
        } else {
            let head = value.trim_start_matches('!').trim_start_matches('"');
            let token = head.split_whitespace().next().unwrap_or_default();
            if token.contains('/') {
                inside(workspace, token)
            } else {
                None
            }
        };
        if let Some(path) = candidate {
            if !denials.contains(&path) {
                if denials.len() >= MAX_DENIALS {
                    // An unbounded list cannot be proven; keep the command at review.
                    return None;
                }
                denials.push(path);
            }
        }
    }
    Some(denials)
}
