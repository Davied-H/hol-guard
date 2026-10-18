//! Bounded, private record of why a managed resident stopped.
//!
//! A one-shot CLI client spawns a supervisor and exits before the resident
//! it asked for has finished its life, so a resident that dies during
//! startup used to leave nothing behind: its stderr went to the null device
//! and the client that would have reported it was already gone. The
//! supervisor owns the resident until it exits, so it writes that stderr and
//! the exit it waited for into one private, size-bounded file next to the
//! rest of the runtime scope state.

use std::fs::File;
#[cfg(not(windows))]
use std::io::Read;
use std::io::{Seek, Write};
use std::path::{Path, PathBuf};

/// One supervisor-owned file per runtime scope, beside `restart-budget.json`
/// in `<guard-home>/native-runtime/resident-v3-<digest>/`.
pub(crate) const RESIDENT_FAILURE_FILE_NAME: &str = "resident-stderr.v1.log";
/// A resident that floods stderr must not fill the home. Past this the run's
/// record keeps its first bytes, which hold the startup failure, and drops
/// the rest.
const MAX_RESIDENT_FAILURE_BYTES: u64 = 64 * 1024;
#[cfg(not(windows))]
const DRAIN_CHUNK_BYTES: usize = 4096;

/// The record of one supervised resident run. Nothing is created until the
/// run has something to report, so a resident that starts, serves and exits
/// cleanly leaves the previous failure in place instead of erasing it.
pub(crate) struct ResidentFailureLog {
    scope: PathBuf,
    file: Option<File>,
    written: u64,
    refused: bool,
}

impl ResidentFailureLog {
    pub(crate) fn for_scope(scope: &Path) -> Self {
        Self {
            scope: scope.to_owned(),
            file: None,
            written: 0,
            refused: false,
        }
    }

    pub(crate) fn path(scope: &Path) -> PathBuf {
        scope.join(RESIDENT_FAILURE_FILE_NAME)
    }

    /// Open this run's record on its first byte, replacing the previous run's
    /// record. The newest failure is the one that explains the denied call.
    fn open(&mut self) -> Option<&mut File> {
        if self.refused {
            return None;
        }
        if self.file.is_none() {
            let Some(file) = self.create() else {
                self.refused = true;
                return None;
            };
            self.file = Some(file);
            self.written = 0;
        }
        self.file.as_mut()
    }

    fn create(&self) -> Option<File> {
        let private_root = crate::resident_state::private_root_for_scope(&self.scope).ok()?;
        let path = Self::path(&self.scope);
        #[cfg(windows)]
        let mut file = {
            let (file, directory_binding) =
                crate::resident_state::private_lock_file(&path, &private_root).ok()?;
            // The supervisor must not hold a directory barrier for the
            // resident's lifetime; other clients still bind this ancestry.
            drop(directory_binding);
            file
        };
        #[cfg(not(windows))]
        let mut file = crate::resident_state::private_lock_file(&path, &private_root).ok()?;
        file.set_len(0).ok()?;
        file.rewind().ok()?;
        Some(file)
    }

    pub(crate) fn append(&mut self, bytes: &[u8]) {
        let remaining = MAX_RESIDENT_FAILURE_BYTES.saturating_sub(self.written);
        if bytes.is_empty() || remaining == 0 {
            return;
        }
        let accepted = usize::try_from(remaining)
            .unwrap_or(usize::MAX)
            .min(bytes.len());
        let Some(file) = self.open() else {
            return;
        };
        if file.write_all(&bytes[..accepted]).is_err() {
            // A broken record must never change the supervised exit result.
            self.file = None;
            self.refused = true;
            return;
        }
        self.written = self.written.saturating_add(accepted as u64);
    }

    /// Append one `native_`-prefixed line of the supervisor's own evidence.
    pub(crate) fn note(&mut self, line: &str) {
        let mut rendered = String::with_capacity(line.len() + 1);
        rendered.push_str(line);
        rendered.push('\n');
        self.append(rendered.as_bytes());
    }

    /// Read a resident's stderr to end of file. The pipe is drained even
    /// after the record refuses a write, so a resident never blocks on a
    /// stderr write that nobody is reading.
    #[cfg(not(windows))]
    pub(crate) fn drain(&mut self, mut reader: impl Read) {
        let mut buffer = [0u8; DRAIN_CHUNK_BYTES];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => self.append(&buffer[..read]),
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => break,
            }
        }
    }
}

#[cfg(test)]
#[path = "resident_failure_log_tests.rs"]
mod tests;
