//! Repository metadata reached by a recursive `grep`.
//!
//! `grep -r` has no notion of a repository, so a search rooted at a checkout
//! also reads its `.git` entry. Refusing that entry outright sends nearly every
//! repository-wide search to review. What `.git` holds is mostly history the
//! agent can already print with `git log` or `git show`; the parts that can
//! carry a credential are the configuration files, where remote URLs,
//! `http.extraHeader` values and credential sections live, and add-on key
//! stores such as git-crypt's.
//!
//! A `.git` file (a linked worktree or submodule pointer) holds one `gitdir:`
//! line and is allowed when it is small. A `.git` directory is walked by
//! metadata like any tree, never following links. Every configuration file in
//! it is read, bounded, and must carry no credential marker; any key store,
//! hidden name, secret extension or credential name sends the search to review.
use std::io::Read;
use std::path::Path;

const MAX_ENTRIES: usize = 20_000;
const MAX_DEPTH: usize = 16;
const MAX_POINTER_BYTES: u64 = 4 * 1024;
const MAX_CONFIG_BYTES: u64 = 64 * 1024;
const CONFIG_NAMES: &[&str] = &["config", "config.worktree"];
const KEY_STORES: &[&str] = &["git-crypt", "credentials", "credential"];
/// Lowercase substrings that mark a credential in Git configuration.
const CREDENTIAL_MARKERS: &[&str] = &[
    "extraheader",
    "[credential",
    "password",
    "passwd",
    "token",
    "oauth",
    "authorization",
    "bearer",
    "secret",
];

/// True when a recursive `grep` may read the `.git` entry at `path`.
pub(super) fn safe_git_entry(path: &Path, metadata: &std::fs::Metadata) -> bool {
    if metadata.is_file() {
        return metadata.len() <= MAX_POINTER_BYTES;
    }
    metadata.is_dir() && safe_git_directory(path)
}

fn safe_git_directory(root: &Path) -> bool {
    let mut pending = vec![(root.to_path_buf(), 0_usize)];
    let mut inspected = 0_usize;
    while let Some((path, depth)) = pending.pop() {
        inspected += 1;
        if inspected > MAX_ENTRIES || depth > MAX_DEPTH {
            return false;
        }
        let Ok(metadata) = std::fs::symlink_metadata(&path) else {
            return false;
        };
        if depth > 0 && !safe_git_descendant(&path, root, &metadata) {
            return false;
        }
        if metadata.is_dir() {
            let Ok(entries) = std::fs::read_dir(&path) else {
                return false;
            };
            for entry in entries {
                let Ok(entry) = entry else { return false };
                if pending.len() + inspected >= MAX_ENTRIES {
                    return false;
                }
                pending.push((entry.path(), depth + 1));
            }
        }
    }
    true
}

fn safe_git_descendant(path: &Path, root: &Path, metadata: &std::fs::Metadata) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    let lowered = name.to_ascii_lowercase();
    if KEY_STORES.contains(&lowered.as_str()) {
        return false;
    }
    if metadata.is_dir() {
        return super::tree::descendant_allowed(path, root, false);
    }
    if !metadata.is_file() {
        return false;
    }
    if CONFIG_NAMES.contains(&lowered.as_str()) {
        return config_without_credentials(path, metadata);
    }
    super::tree::descendant_allowed(path, root, true)
}

fn config_without_credentials(path: &Path, metadata: &std::fs::Metadata) -> bool {
    if metadata.len() > MAX_CONFIG_BYTES {
        return false;
    }
    let Ok(file) = std::fs::File::open(path) else {
        return false;
    };
    let mut text = String::new();
    if file
        .take(MAX_CONFIG_BYTES + 1)
        .read_to_string(&mut text)
        .is_err()
        || text.len() as u64 > MAX_CONFIG_BYTES
    {
        return false;
    }
    let text = text.to_ascii_lowercase();
    !CREDENTIAL_MARKERS
        .iter()
        .any(|marker| text.contains(marker))
        && !text.contains("[include")
        && !text.contains("[includeif")
        && !url_with_userinfo(&text)
}

/// A remote URL that embeds a secret: any password (`user:pw@`), or any
/// user name over HTTP, where a token is commonly passed as the user name.
/// `ssh://git@host` names only the SSH login and is not a credential.
fn url_with_userinfo(text: &str) -> bool {
    text.match_indices("://").any(|(index, _)| {
        let scheme = text[..index]
            .rsplit(|character: char| {
                !(character.is_ascii_alphanumeric() || "+.-".contains(character))
            })
            .next()
            .unwrap_or_default();
        let authority = text[index + 3..]
            .split(|character: char| character == '/' || character.is_whitespace())
            .next()
            .unwrap_or_default();
        authority.rsplit_once('@').is_some_and(|(userinfo, _)| {
            userinfo.contains(':') || !matches!(scheme, "ssh" | "git+ssh" | "ssh+git")
        })
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn userinfo_urls_are_detected() {
        for (text, expected) in [
            ("url = https://github.com/example/repo.git", false),
            ("url = git@github.com:example/repo.git", false),
            ("url = ssh://git@github.com/example/repo.git", false),
            ("url = ssh://git:pw@github.com/example/repo.git", true),
            ("url = https://user:pw@example.com/repo", true),
            ("url = https://abc123@example.com/repo", true),
        ] {
            assert_eq!(super::url_with_userinfo(text), expected, "{text}");
        }
    }
}
