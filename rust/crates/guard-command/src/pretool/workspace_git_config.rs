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

/// `value` as a path under `workspace`, resolving a relative value against
/// `base`; `None` when it leaves the workspace or is not a plain path.
fn inside(base: &Path, workspace: &Path, value: &str) -> Option<PathBuf> {
    let value = value.trim().trim_matches('"');
    if value.is_empty() || value.starts_with('~') || value.contains("://") {
        return None;
    }
    let normal = normalize(&base.join(value));
    (normal.starts_with(workspace) && normal != workspace).then_some(normal)
}

/// Workspace paths a configured hook directory or helper command names. Every
/// one becomes write-denied inside the sandbox. `None` keeps the command at
/// review: an include of workspace configuration this reader never parses, a
/// hook directory outside the workspace, or a list beyond its bound.
pub(crate) fn helper_write_denials(config: &str, workspace: &Path) -> Option<Vec<PathBuf>> {
    let git_dir = workspace.join(".git");
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
        let mut candidates: Vec<PathBuf> = Vec::new();
        if section.starts_with("include") && key == "path" {
            // Git resolves a relative include against the including file's
            // directory, `.git/`. Included workspace configuration could name
            // its own helpers, and this reader does not follow it.
            if inside(&git_dir, workspace, value).is_some() {
                return None;
            }
        } else if key == "hookspath" {
            // Relative hook directories resolve against the work tree.
            candidates.push(inside(workspace, workspace, value)?);
        } else if section != "branch" && section != "user" {
            // The first word is a program Git finds on PATH unless it has a
            // slash. Later words are arguments a shell resolves in the
            // repository, so a workspace file there is a helper too.
            let words = value.trim_start_matches('!').split_whitespace();
            for (index, word) in words.enumerate() {
                let word = word.trim_matches(|c| c == '"' || c == '\'');
                if word.contains('/') || (index > 0 && workspace.join(word).exists()) {
                    candidates.extend(inside(workspace, workspace, word));
                }
            }
        }
        for path in candidates {
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

#[cfg(test)]
mod tests {
    use super::helper_write_denials;
    use std::path::{Path, PathBuf};

    fn denials(config: &str, workspace: &Path) -> Option<Vec<PathBuf>> {
        helper_write_denials(config, workspace)
    }

    #[test]
    fn workspace_includes_and_outside_hooks_keep_the_command_at_review() {
        let ws = Path::new("/w/repo");
        // Relative includes resolve against `.git/`, so both name workspace files.
        assert_eq!(denials("[include]\n\tpath = ../.gitconfig\n", ws), None);
        assert_eq!(denials("[include]\n\tpath = extra\n", ws), None);
        assert_eq!(
            denials("[includeIf \"gitdir:/w/\"]\n\tpath = /w/repo/cfg\n", ws),
            None
        );
        assert_eq!(denials("[core]\n\thooksPath = /outside/hooks\n", ws), None);
        assert_eq!(denials("[core]\n\thooksPath = ~/hooks\n", ws), None);
        // An include outside the workspace is not writable from the sandbox.
        assert_eq!(
            denials("[include]\n\tpath = /etc/gitconfig.d/team\n", ws),
            Some(vec![])
        );
    }

    #[test]
    fn helper_paths_in_any_word_are_write_denied() {
        let ws = std::env::temp_dir().join(format!("hol-git-config-{}", std::process::id()));
        std::fs::create_dir_all(ws.join("tools")).unwrap();
        std::fs::write(ws.join("x.sh"), "").unwrap();
        let config = "[core]\n\thooksPath = .githooks\n\tfsmonitor = ./tools/mon\n\
             [alias]\n\tx = !sh tools/x\n\ty = !sh x.sh\n\tst = status -s\n\
             [branch \"main\"]\n\tmerge = refs/heads/main\n";
        let got = denials(config, &ws).unwrap();
        assert_eq!(
            got,
            vec![
                ws.join(".githooks"),
                ws.join("tools/mon"),
                ws.join("tools/x"),
                ws.join("x.sh"),
            ]
        );
        std::fs::remove_dir_all(&ws).unwrap();
    }
}
