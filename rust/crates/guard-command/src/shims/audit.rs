//! The package-shim audit stamp (`record_package_shim_audit_result`).
//!
//! Unlike the shim lifecycle, the audit stamp rewrites a manifest the lifecycle
//! owns and never validates, so it keeps the Python reader's permissive load and
//! the no-follow atomic publication of `write_text_atomic_no_follow`.

use std::io;

use serde_json::{json, Map, Value};

use super::pyfs::ReadError;
use super::values::py_json_dumps;
use super::{ShimContext, ShimResult};

/// `_load_package_shim_manifest` (the audit reader): any JSON object, else empty.
fn load_any(context: &ShimContext) -> ShimResult<Map<String, Value>> {
    let facts = &context.facts;
    let path = context.manifest_path();
    if !facts.exists(&path) {
        return Ok(Map::new());
    }
    let text = match facts.read_text(&path) {
        Ok(text) => text,
        Err(ReadError::Io(_)) => return Ok(Map::new()),
        Err(error) => return Err(error.message(&path)),
    };
    match serde_json::from_str::<Value>(&text) {
        Ok(Value::Object(map)) => Ok(map),
        _ => Ok(Map::new()),
    }
}

/// `record_package_shim_audit_result`: stamp `last_audit_at` into the manifest.
pub fn record_package_shim_audit_result(
    context: &ShimContext,
    audited_at: Option<&str>,
) -> ShimResult<Value> {
    let facts = &context.facts;
    let mut manifest = load_any(context)?;
    let stamp = audited_at.unwrap_or(&facts.now).to_owned();
    manifest.insert("last_audit_at".to_owned(), Value::String(stamp.clone()));
    let path = context.manifest_path();
    let within = match (facts.resolve(&context.guard_home), facts.resolve(&path)) {
        (Ok(root), Ok(target)) => facts.is_within(&target, &root),
        _ => false,
    };
    if !within {
        return Err("package shim manifest escapes the Guard home".to_owned());
    }
    let payload = py_json_dumps(&Value::Object(manifest), true);
    write_no_follow(&path, payload.as_bytes())
        .map_err(|error| format!("cannot write {path}: {error}"))?;
    Ok(json!({ "last_audit_at": stamp }))
}

#[cfg(unix)]
fn errno_io(error: nix::errno::Errno) -> io::Error {
    io::Error::from_raw_os_error(error as i32)
}

/// Atomically replace `path` without following any symlink on the way to it:
/// every directory is opened relative to its parent with `O_NOFOLLOW` (and
/// created `0o755` when missing), and the bytes land in an exclusive `0o600`
/// sibling that is renamed over the target.
#[cfg(unix)]
fn write_no_follow(path: &str, payload: &[u8]) -> io::Result<()> {
    use std::fs::File;
    use std::io::Write;
    use std::os::fd::AsFd;
    use std::path::{Component, Path};

    use nix::errno::Errno;
    use nix::fcntl::{open, openat, renameat, OFlag};
    use nix::sys::stat::{fchmod, mkdirat, Mode};
    use nix::unistd::{fsync, unlinkat, UnlinkatFlags};

    let target = Path::new(path);
    let name = target
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"))?
        .to_owned();
    let parent = target
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no parent"))?;
    let directory_flags =
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
    let root = open("/", directory_flags, Mode::empty()).map_err(errno_io)?;
    let mut directory = File::from(root);
    for component in parent.components() {
        let part = match component {
            Component::RootDir => continue,
            Component::Normal(part) => part,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "path is not normalised",
                ))
            }
        };
        let child = match openat(&directory, part, directory_flags, Mode::empty()) {
            Ok(child) => child,
            Err(Errno::ENOENT) => {
                mkdirat(&directory, part, Mode::from_bits_truncate(0o755)).map_err(errno_io)?;
                openat(&directory, part, directory_flags, Mode::empty()).map_err(errno_io)?
            }
            Err(error) => return Err(errno_io(error)),
        };
        directory = File::from(child);
    }

    let mut token = [0_u8; 16];
    getrandom::fill(&mut token).map_err(|error| io::Error::other(error.to_string()))?;
    let suffix = hex::encode(token);
    let temporary = format!(".{}.{suffix}", name.to_string_lossy());
    let descriptor = openat(
        &directory,
        temporary.as_str(),
        OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::from_bits_truncate(0o600),
    )
    .map_err(errno_io)?;
    let mut file = File::from(descriptor);
    let written = (|| -> io::Result<()> {
        fchmod(&file, Mode::from_bits_truncate(0o600)).map_err(errno_io)?;
        file.write_all(payload)?;
        file.flush()?;
        fsync(&file).map_err(errno_io)
    })();
    drop(file);
    let published = written
        .and_then(|()| {
            renameat(
                directory.as_fd(),
                temporary.as_str(),
                directory.as_fd(),
                name.as_os_str(),
            )
            .map_err(errno_io)
        })
        .and_then(|()| fsync(&directory).map_err(errno_io));
    if published.is_err() {
        let _ = unlinkat(&directory, temporary.as_str(), UnlinkatFlags::NoRemoveDir);
    }
    published
}

/// Windows has no `openat`; every directory below the root is created plainly
/// and a reparse point anywhere on the path is refused before the write.
#[cfg(not(unix))]
fn write_no_follow(path: &str, payload: &[u8]) -> io::Result<()> {
    use std::fs;
    use std::path::Path;

    let target = Path::new(path);
    let parent = target
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no parent"))?;
    fs::create_dir_all(parent)?;
    let mut current = std::path::PathBuf::new();
    for component in target.components() {
        current.push(component);
        if let Ok(meta) = fs::symlink_metadata(&current) {
            if meta.file_type().is_symlink() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("refusing symlinked output path: {}", current.display()),
                ));
            }
        }
    }
    let mut token = [0_u8; 16];
    getrandom::fill(&mut token).map_err(|error| io::Error::other(error.to_string()))?;
    let suffix = hex::encode(token);
    let name = target
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"))?;
    let temporary = parent.join(format!(".{}.{suffix}", name.to_string_lossy()));
    let written = fs::write(&temporary, payload).and_then(|()| fs::rename(&temporary, target));
    if written.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    written
}

#[cfg(all(test, unix))]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::super::{ShimContext, ShimFacts};
    use super::record_package_shim_audit_result;

    fn facts() -> ShimFacts {
        ShimFacts {
            environ: BTreeMap::new(),
            home: "/Users/home".to_owned(),
            cwd: "/".to_owned(),
            executable: "/usr/bin/python3".to_owned(),
            frozen: false,
            frozen_cli: String::new(),
            trusted_frozen_cli_paths: Vec::new(),
            python_version: (3, 12),
            import_root: "/Users/src".to_owned(),
            argv0: None,
            windows: false,
            sqlite_connect_timeout_seconds: 30.0,
            now: "2026-01-01T00:00:00+00:00".to_owned(),
            shim_dir_transient: None,
        }
    }

    fn scratch(label: &str) -> std::path::PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let root = fs::canonicalize(std::env::temp_dir())
            .expect("temp dir")
            .join(format!("hol-guard-shim-audit-{label}-{stamp}"));
        fs::create_dir_all(&root).expect("scratch");
        root
    }

    #[test]
    fn stamps_a_missing_manifest_and_preserves_other_keys() {
        let root = scratch("stamp");
        let home = root.join("guard-home");
        let context = ShimContext::new(home.to_str().expect("utf8"), None, None, facts());
        let result = record_package_shim_audit_result(&context, None).expect("stamp");
        assert_eq!(result["last_audit_at"], "2026-01-01T00:00:00+00:00");
        let manifest = home.join("package-shims").join("manifest.json");
        assert_eq!(
            fs::read_to_string(&manifest).expect("manifest"),
            "{\"last_audit_at\": \"2026-01-01T00:00:00+00:00\"}"
        );
        let mode = fs::metadata(&manifest).expect("meta").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        fs::write(&manifest, "{\"b\": 1, \"a\": [true]}").expect("seed");
        record_package_shim_audit_result(&context, Some("2026-02-02T00:00:00+00:00"))
            .expect("restamp");
        assert_eq!(
            fs::read_to_string(&manifest).expect("manifest"),
            "{\"a\": [true], \"b\": 1, \"last_audit_at\": \"2026-02-02T00:00:00+00:00\"}"
        );
        fs::write(&manifest, "[1]").expect("non-object");
        record_package_shim_audit_result(&context, None).expect("replace");
        assert_eq!(
            fs::read_to_string(&manifest).expect("manifest"),
            "{\"last_audit_at\": \"2026-01-01T00:00:00+00:00\"}"
        );
        fs::remove_dir_all(&root).expect("cleanup");
    }

    #[test]
    fn refuses_a_symlinked_manifest_directory_and_leaves_the_target_alone() {
        let root = scratch("symlink");
        let home = root.join("guard-home");
        let outside = root.join("outside");
        fs::create_dir_all(&home).expect("home");
        fs::create_dir_all(&outside).expect("outside");
        symlink(&outside, home.join("package-shims")).expect("link");
        let context = ShimContext::new(home.to_str().expect("utf8"), None, None, facts());
        let error = record_package_shim_audit_result(&context, None).expect_err("escape");
        assert!(error.contains("escapes the Guard home"), "{error}");
        assert_eq!(fs::read_dir(&outside).expect("outside").count(), 0);
        fs::remove_dir_all(&root).expect("cleanup");
    }
}
