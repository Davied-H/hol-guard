//! Owned, private descriptor handoff for indexes larger than an IPC frame.
use super::*;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::ffi::CString;
use std::fs::OpenOptions;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::OpenOptionsExt;

pub(super) fn read(input: &Value) -> Result<Value, &'static str> {
    let error = "Invalid executable mapping snapshot.";
    if input.as_object().is_none_or(|v| v.len() != 3) {
        return Err(error);
    }
    let path = Path::new(input["mapping_snapshot"].as_str().ok_or(error)?);
    let parent = path.parent().ok_or(error)?;
    if path.file_name() != Some(OsStr::new("mapping-index.json"))
        || !parent.is_absolute()
        || !parent
            .file_name()
            .and_then(OsStr::to_str)
            .is_some_and(|p| p.starts_with("hol-guard-mapping-"))
        || parent.canonicalize().map_err(|_| error)? != parent
    {
        return Err(error);
    }
    let length = input["decoded_bytes"]
        .as_u64()
        .filter(|v| *v <= 256 * 1024 * 1024)
        .ok_or(error)?;
    let digest = input["sha256"]
        .as_str()
        .filter(|v| {
            v.len() == 64
                && v.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
        .ok_or(error)?;
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(parent)
        .map_err(|_| error)?;
    let metadata = directory.metadata().map_err(|_| error)?;
    if metadata.uid() != nix::unistd::getuid().as_raw() || metadata.mode() & 0o077 != 0 {
        return Err(error);
    }
    let name = CString::new("mapping-index.json").unwrap();
    // SAFETY: the live directory descriptor anchors the NUL-terminated leaf.
    let descriptor = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        return Err(error);
    }
    // SAFETY: openat returned a new descriptor owned only by this File.
    let mut file = unsafe { fs::File::from_raw_fd(descriptor) };
    let before = file.metadata().map_err(|_| error)?;
    if !before.is_file()
        || before.uid() != nix::unistd::getuid().as_raw()
        || before.mode() & 0o077 != 0
        || before.nlink() != 1
        || before.len() != length
    {
        return Err(error);
    }
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(length + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| error)?;
    let after = file.metadata().map_err(|_| error)?;
    if bytes.len() as u64 != length
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || format!("{:x}", Sha256::digest(&bytes)) != digest
    {
        return Err(error);
    }
    serde_json::from_slice(&bytes).map_err(|_| error)
}
