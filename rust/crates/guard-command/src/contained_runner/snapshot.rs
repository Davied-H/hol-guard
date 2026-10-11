//! Complete bounded workspace snapshots for result-only contained commands.
//!
//! Faithful port of `runtime/workspace_snapshot_inputs.py`.

use std::fs::{self, DirEntry, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::time::Instant;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::common::{canonical_workspace, framed_digest};
use super::contract::Input;
use crate::shell_secret_read_support::classify_secret_path;

const MAX_FILES: usize = 20_000;
const MAX_BYTES: u64 = 256 * 1024 * 1024;
pub(super) const MAX_ENTRIES: usize = 50_000;
pub(super) const DISCOVERY_TIMEOUT_SECONDS: f64 = 5.0;
const SKIPPED_STATE_NAMES: &[&str] = &[".git", ".guard"];
const PROTECTED_NAMES: &[&str] = &[
    ".aws",
    ".azure",
    ".docker",
    ".gnupg",
    ".kube",
    ".netrc",
    ".npmrc",
    ".pypirc",
    ".ssh",
    ".vault-token",
    "auth.json",
    "credentials",
    "credentials.json",
    "guard-home",
    "secrets.json",
];
const PROTECTED_SUFFIXES: &[&str] = &[".jks", ".key", ".keystore", ".p12", ".pem", ".pfx"];
const SOURCE_SUFFIXES: &[&str] = &[".cjs", ".cts", ".js", ".jsx", ".mjs", ".mts", ".ts", ".tsx"];
const PROTECTED_WORDS: &[&str] = &[
    "credential",
    "credentials",
    "passwd",
    "password",
    "passwords",
    "secret",
    "secrets",
    "token",
    "tokens",
];
const PROTECTED_WORD_PAIRS: &[(&str, &str)] =
    &[("api", "key"), ("private", "key"), ("service", "account")];
const SSH_PRIVATE_KEY_NAMES: &[&str] = &["id_dsa", "id_ecdsa", "id_ed25519", "id_rsa"];

/// Entry and wall-clock discovery budget shared by one tree walk.
pub(super) struct Budget {
    started_at: Instant,
    pub(super) visited: usize,
}

impl Budget {
    pub(super) fn new() -> Self {
        Self {
            started_at: Instant::now(),
            visited: 0,
        }
    }

    pub(super) fn check(&self, entry_message: &str, time_message: &str) -> Result<(), String> {
        if self.visited > MAX_ENTRIES {
            return Err(entry_message.to_owned());
        }
        if self.started_at.elapsed().as_secs_f64() > DISCOVERY_TIMEOUT_SECONDS {
            return Err(time_message.to_owned());
        }
        Ok(())
    }
}

type DirectoryIdentity = (u64, u64);

fn directory_identity(path: &Path) -> Result<DirectoryIdentity, String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    Ok((metadata.dev(), metadata.ino()))
}

fn bounded_entries(
    directory: &Path,
    expected: DirectoryIdentity,
    budget: &mut Budget,
) -> Result<Vec<DirEntry>, String> {
    let failed = || "workspace snapshot discovery failed".to_owned();
    let handle = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(directory)
        .map_err(|_| failed())?;
    let metadata = handle.metadata().map_err(|_| failed())?;
    if (metadata.dev(), metadata.ino()) != expected {
        return Err("workspace directory identity changed during discovery".to_owned());
    }
    let mut entries = Vec::new();
    for entry in fs::read_dir(directory).map_err(|_| failed())? {
        let entry = entry.map_err(|_| failed())?;
        budget.visited += 1;
        budget.check(
            "workspace discovery entry budget exceeded",
            "workspace discovery time budget exceeded",
        )?;
        entries.push(entry);
    }
    Ok(entries)
}

fn snapshot_file_digest(path: &Path, expected: &fs::Metadata) -> Result<String, String> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| error.to_string())?;
    let identity = |metadata: &fs::Metadata| {
        (
            metadata.dev(),
            metadata.ino(),
            metadata.size(),
            metadata.mtime(),
            metadata.mtime_nsec(),
        )
    };
    let before = file.metadata().map_err(|error| error.to_string())?;
    let changed = "workspace file identity changed during discovery";
    if identity(&before) != identity(expected) || before.nlink() != 1 {
        return Err(changed.to_owned());
    }
    let mut digest = Sha256::new();
    let mut buffer = vec![0u8; 1024 * 1024];
    let mut consumed: u64 = 0;
    loop {
        let count = file.read(&mut buffer).map_err(|error| error.to_string())?;
        if count == 0 {
            break;
        }
        consumed += count as u64;
        if consumed > MAX_BYTES {
            return Err("workspace snapshot exceeds containment identity budget".to_owned());
        }
        digest.update(&buffer[..count]);
    }
    let after = file.metadata().map_err(|error| error.to_string())?;
    if identity(&after) != identity(&before) {
        return Err(changed.to_owned());
    }
    Ok(hex::encode(digest.finalize()))
}

fn components(relative: &Path) -> Vec<String> {
    relative
        .components()
        .map(|part| part.as_os_str().to_string_lossy().into_owned())
        .collect()
}

fn posix(relative: &Path) -> String {
    components(relative).join("/")
}

/// Capture every eligible workspace file or reject the command for review.
///
/// Returns the framed snapshot digest and the inputs sorted by snapshot path.
pub(crate) fn complete_workspace_snapshot(
    workspace: &Path,
    exclude_protected: bool,
) -> Result<(String, Vec<Input>), String> {
    let canonical = canonical_workspace(workspace)?;
    let mut captured: Vec<(String, String, Input)> = Vec::new();
    let mut exclusions: Vec<(String, &'static str)> = Vec::new();
    let mut total_bytes: u64 = 0;
    let mut budget = Budget::new();
    let mut directories = vec![(canonical.clone(), directory_identity(&canonical)?)];
    while let Some((directory, expected)) = directories.pop() {
        for entry in bounded_entries(&directory, expected, &mut budget)? {
            let path = directory.join(entry.file_name());
            let relative = path
                .strip_prefix(&canonical)
                .map_err(|_| "workspace snapshot discovery failed".to_owned())?;
            let relative_text = posix(relative);
            let lowered: Vec<String> = components(relative)
                .iter()
                .map(|part| part.to_lowercase())
                .collect();
            let file_type = entry.file_type().map_err(|error| error.to_string())?;
            if lowered
                .iter()
                .any(|part| SKIPPED_STATE_NAMES.contains(&part.as_str()))
            {
                exclusions.push((relative_text, "protected-state"));
                continue;
            }
            if is_protected(relative, file_type.is_dir()) {
                if exclude_protected {
                    exclusions.push((relative_text, "protected-content"));
                    continue;
                }
                return Err("protected workspace content requires Guard review".to_owned());
            }
            if file_type.is_dir()
                && entry.file_name() == ".bin"
                && lowered.iter().any(|part| part == "node_modules")
            {
                exclusions.push((relative_text, "package-bin-links"));
                continue;
            }
            if file_type.is_symlink() {
                return Err("workspace snapshot cannot contain symlinks".to_owned());
            }
            let metadata = fs::symlink_metadata(&path).map_err(|error| error.to_string())?;
            if file_type.is_dir() {
                directories.push((path, (metadata.dev(), metadata.ino())));
                continue;
            }
            if !file_type.is_file() {
                return Err("workspace snapshot inputs must be regular files".to_owned());
            }
            if metadata.nlink() != 1 {
                return Err("workspace snapshot cannot contain hard-linked files".to_owned());
            }
            total_bytes += metadata.size();
            if captured.len() >= MAX_FILES || total_bytes > MAX_BYTES {
                return Err("workspace snapshot exceeds containment identity budget".to_owned());
            }
            let digest = snapshot_file_digest(&path, &metadata)?;
            budget.check(
                "workspace discovery entry budget exceeded",
                "workspace discovery time budget exceeded",
            )?;
            let input = Input::new(&path.to_string_lossy(), &relative_text, &digest)?;
            captured.push((relative_text, digest, input));
        }
    }
    captured.sort_by(|left, right| left.0.cmp(&right.0));
    exclusions.sort();
    let files: Vec<Value> = captured
        .iter()
        .map(|(path, digest, _)| json!([path, digest]))
        .collect();
    let skipped: Vec<Value> = exclusions
        .iter()
        .map(|(path, reason)| json!([path, reason]))
        .collect();
    let digest = framed_digest(&json!({"exclusions": skipped, "files": files}))?;
    Ok((
        digest,
        captured.into_iter().map(|(_, _, input)| input).collect(),
    ))
}

/// Reject Node resolution roots outside the captured workspace.
pub(crate) fn reject_external_node_modules(workspace: &Path) -> Result<(), String> {
    for ancestor in workspace.ancestors().skip(1) {
        match fs::symlink_metadata(ancestor.join("node_modules")) {
            Ok(_) => return Err("external Node dependencies require Guard review".to_owned()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => {
                return Err("external Node dependency identity is unavailable".to_owned());
            }
        }
    }
    Ok(())
}

fn is_protected(relative: &Path, is_directory: bool) -> bool {
    let text = posix(relative);
    if classify_secret_path(&text, None, None).is_some() {
        return true;
    }
    let parts = components(relative);
    let mut package_directory_expected = false;
    let mut in_dependency_tree = false;
    for (index, part) in parts.iter().enumerate() {
        let lowered = part.to_lowercase();
        if lowered == "node_modules" {
            package_directory_expected = true;
            in_dependency_tree = true;
            continue;
        }
        let directory_component = index + 1 < parts.len() || is_directory;
        let package_directory = package_directory_expected && directory_component;
        let skip_generic_words = package_directory
            || (in_dependency_tree
                && !directory_component
                && SOURCE_SUFFIXES
                    .iter()
                    .any(|suffix| lowered.ends_with(suffix)));
        if is_protected_part(part, !skip_generic_words) {
            return true;
        }
        if package_directory_expected {
            package_directory_expected = package_directory && part.starts_with('@');
        }
    }
    false
}

fn is_protected_part(part: &str, include_generic_words: bool) -> bool {
    let lowered = part.to_lowercase();
    PROTECTED_NAMES.contains(&lowered.as_str())
        || SSH_PRIVATE_KEY_NAMES.contains(&lowered.as_str())
        || lowered.starts_with(".env")
        || PROTECTED_SUFFIXES
            .iter()
            .any(|suffix| lowered.ends_with(suffix))
        || (include_generic_words && has_protected_words(part))
}

fn has_protected_words(part: &str) -> bool {
    let chars: Vec<char> = part.chars().collect();
    let mut split = String::new();
    for (index, current) in chars.iter().enumerate() {
        if index > 0 {
            let previous = chars[index - 1];
            let lower_or_digit = previous.is_ascii_lowercase() || previous.is_ascii_digit();
            let acronym_end = previous.is_ascii_uppercase()
                && current.is_ascii_uppercase()
                && chars.get(index + 1).is_some_and(char::is_ascii_lowercase);
            if (lower_or_digit && current.is_ascii_uppercase()) || acronym_end {
                split.push('-');
            }
        }
        split.push(*current);
    }
    let lowered = split.to_lowercase();
    let words: Vec<&str> = lowered
        .split(|character: char| !(character.is_ascii_lowercase() || character.is_ascii_digit()))
        .filter(|word| !word.is_empty())
        .collect();
    words.iter().any(|word| PROTECTED_WORDS.contains(word))
        || words
            .windows(2)
            .any(|pair| PROTECTED_WORD_PAIRS.contains(&(pair[0], pair[1])))
}
