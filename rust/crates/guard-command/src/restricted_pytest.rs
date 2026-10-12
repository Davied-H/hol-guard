//! Restricted execution admission, environment filtering and runtime read grants.

use std::collections::HashSet;
use std::env;
use std::ffi::OsStr;
use std::fs;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use regex::Regex;

// ---------------------------------------------------------------------------
// `restricted_pytest_model.py` literals consumed by this module (:31-89).
// ---------------------------------------------------------------------------

pub const PYTEST_SANDBOX_UNAVAILABLE_REASON_CODE: &str = "pytest_restricted_sandbox_unavailable";
pub const PYTEST_INVALID_COMMAND_REASON_CODE: &str = "pytest_restricted_invalid_command";
pub const PYTEST_INVALID_WORKSPACE_REASON_CODE: &str = "pytest_restricted_invalid_workspace";
pub const PYTEST_EXTERNAL_PYTHONPATH_REASON_CODE: &str = "pytest_restricted_external_pythonpath";

/// `RestrictedPytestBackend` (:37).
pub type RestrictedPytestBackend = &'static str;

static PYTEST_EXECUTABLE_NAMES: LazyLock<HashSet<&'static str>> =
    LazyLock::new(|| HashSet::from(["pytest", "py.test", "pytest.exe", "py.test.exe"]));

static PYTHON_EXECUTABLE_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^(?:python|pythonw)(?:\d+(?:\.\d+)*)?(?:\.exe)?$").unwrap());

const PROJECT_WORKSPACE_MARKERS: &[&str] = &[
    ".git",
    "pyproject.toml",
    "pytest.ini",
    "setup.cfg",
    "setup.py",
    "tox.ini",
    "package.json",
];

static SENSITIVE_HOME_ROOT_NAMES: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    HashSet::from([
        ".aws", ".azure", ".config", ".docker", ".gnupg", ".kube", ".ssh", "Library",
    ])
});

static TRUSTED_EXECUTABLE_ROOTS: LazyLock<Vec<PathBuf>> = LazyLock::new(|| {
    vec![
        PathBuf::from("/bin"),
        PathBuf::from("/opt/homebrew"),
        PathBuf::from("/opt/hostedtoolcache/Python"),
        PathBuf::from("/System"),
        PathBuf::from("/usr/bin"),
        PathBuf::from("/usr/local"),
    ]
});

// ---------------------------------------------------------------------------
// `RestrictedPytestError` (restricted_pytest_model.py :95).
// ---------------------------------------------------------------------------

/// `RestrictedPytestError` — reason-coded fail-closed error.
use crate::restricted_command::{normalized_command, RestrictedPytestError};

// ---------------------------------------------------------------------------
// Path/executable primitives used below.
// ---------------------------------------------------------------------------

/// `Path.expanduser`: POSIX `~`/`~/` expansion against `$HOME`.
fn expand_user(path: &Path) -> PathBuf {
    let text = path.to_string_lossy();
    if text == "~" {
        if let Some(home) = env::var_os("HOME") {
            return PathBuf::from(home);
        }
        return path.to_path_buf();
    }
    if let Some(rest) = text.strip_prefix("~/") {
        if let Some(home) = env::var_os("HOME") {
            return Path::new(&home).join(rest);
        }
    }
    path.to_path_buf()
}

/// `Path.absolute()`: anchor to cwd without resolving parent components.
fn path_absolute(path: &Path) -> PathBuf {
    let joined = if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("/"))
            .join(path)
    };
    let absolute: PathBuf = joined.components().collect();
    if joined.to_string_lossy().starts_with("//") && !joined.to_string_lossy().starts_with("///") {
        PathBuf::from(format!("/{}", absolute.display()))
    } else {
        absolute
    }
}

/// POSIX `os.path.normpath`: collapse `.`, redundant separators, and `..`
/// lexically (no filesystem access).
fn normpath(path: &Path) -> PathBuf {
    let text = path.to_string_lossy();
    let rooted = text.starts_with('/');
    let mut stack: Vec<String> = Vec::new();
    for part in text.split('/') {
        match part {
            "" | "." => continue,
            ".." => {
                if stack.last().map(|p| p.as_str() != "..").unwrap_or(false) {
                    stack.pop();
                } else if !rooted {
                    stack.push("..".to_owned());
                }
            }
            other => stack.push(other.to_owned()),
        }
    }
    let body = stack.join("/");
    if rooted {
        PathBuf::from(format!("/{body}"))
    } else if body.is_empty() {
        PathBuf::from(".")
    } else {
        PathBuf::from(body)
    }
}

/// `Path.resolve(strict=False)` — POSIX canonicalize that tolerates missing
/// trailing components (lexically normalizes the unresolved tail).
fn resolve_nonstrict(path: &Path) -> Result<PathBuf, std::io::Error> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir()?.join(path)
    };
    let mut current = absolute.as_path();
    let mut tail = Vec::new();
    loop {
        match fs::canonicalize(current) {
            Ok(mut resolved) => {
                for part in tail.iter().rev() {
                    resolved.push(part);
                }
                return Ok(normpath(&resolved));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let Some(name) = current.file_name() else {
                    return Err(error);
                };
                tail.push(name.to_os_string());
                let Some(parent) = current.parent() else {
                    return Err(error);
                };
                current = parent;
            }
            Err(error) => return Err(error),
        }
    }
}

/// `shutil.which(value)`: locate `value` on `PATH` honoring PATHEXT-free
/// POSIX semantics (existence + executable bit).
fn shutil_which(value: &str, path_env: Option<&str>) -> Option<PathBuf> {
    if value.contains('/') || value.contains('\\') {
        let candidate = Path::new(value);
        return executable_file(candidate).then(|| candidate.to_path_buf());
    }
    let path = path_env
        .map(|p| p.to_owned())
        .or_else(|| env::var("PATH").ok())
        .unwrap_or_else(|| "/bin:/usr/bin".to_owned());
    for entry in path.split(':') {
        let directory = if entry.is_empty() { "." } else { entry };
        let candidate = Path::new(directory).join(value);
        if executable_file(&candidate) {
            return Some(candidate);
        }
    }
    None
}

fn executable_file(candidate: &Path) -> bool {
    match candidate.metadata() {
        Ok(metadata) => metadata.is_file() && metadata.mode() & 0o111 != 0,
        Err(_) => false,
    }
}

mod authority;
mod environment;
mod executables;
mod paths;
mod validation;
pub use authority::evaluate;
#[cfg(test)]
mod parity_tests;
use executables::*;
use paths::*;
use validation::*;
