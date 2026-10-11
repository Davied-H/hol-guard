//! Deadline-bound writes hold their own file handle through late completion.
//!
//! A timed-out worker can only write the original unlinked inode; it cannot
//! reuse a caller's descriptor or follow a replaced blob path.

use super::restricted_archive::RestrictedDownloadError;
use std::fs::File;
use std::io::Write;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

static ACTIVE_WRITES: AtomicUsize = AtomicUsize::new(0);
const MAX_ACTIVE_WRITES: usize = 4;

struct WriteAdmission;
impl WriteAdmission {
    fn acquire() -> Option<Self> {
        ACTIVE_WRITES
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |count| {
                (count < MAX_ACTIVE_WRITES).then_some(count + 1)
            })
            .ok()
            .map(|_| Self)
    }
}
impl Drop for WriteAdmission {
    fn drop(&mut self) {
        ACTIVE_WRITES.fetch_sub(1, Ordering::SeqCst);
    }
}

pub(super) fn write(
    file: &File,
    chunk: &[u8],
    deadline: Instant,
) -> Result<(), RestrictedDownloadError> {
    let mut owned = file.try_clone().map_err(|_| failure())?;
    let bytes = chunk.to_vec();
    run(deadline, move || owned.write_all(&bytes))
}

fn run(
    deadline: Instant,
    operation: impl FnOnce() -> std::io::Result<()> + Send + 'static,
) -> Result<(), RestrictedDownloadError> {
    if Instant::now() >= deadline {
        return Err(timeout());
    }
    let Some(slot) = WriteAdmission::acquire() else {
        return Err(RestrictedDownloadError::new(
            "external_archive_download_timeout",
            "External archive operation capacity is unavailable.",
        ));
    };
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("guard-archive-write".into())
        .spawn(move || {
            let _slot = slot;
            let _ = sender.send(operation());
        })
        .map_err(|_| failure())?;
    match receiver.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
        Ok(Ok(())) => Ok(()),
        Ok(Err(_)) | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => Err(failure()),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Err(timeout()),
    }
}

fn timeout() -> RestrictedDownloadError {
    RestrictedDownloadError::new(
        "external_archive_download_timeout",
        "External archive download exceeded Guard's time limit.",
    )
}
fn failure() -> RestrictedDownloadError {
    RestrictedDownloadError::new(
        "external_archive_connection_failed",
        "External archive temporary blob could not be written completely.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::Duration;

    #[test]
    fn late_write_stays_on_unlinked_inode_and_keeps_admission() {
        let mut nonce = [0; 16];
        getrandom::fill(&mut nonce).unwrap();
        let path = std::env::temp_dir().join(format!("guard-late-write-{}", hex::encode(nonce)));
        let mut file = File::create_new(&path).unwrap();
        let mut owned = file.try_clone().unwrap();
        let (release, wait) = mpsc::channel();
        let (finished, completion) = mpsc::channel();
        let error = run(Instant::now() + Duration::from_millis(20), move || {
            wait.recv().unwrap();
            owned.write_all(b"late archive bytes")?;
            finished.send(()).unwrap();
            Ok(())
        })
        .unwrap_err();
        assert_eq!(error.code, "external_archive_download_timeout");
        assert_eq!(ACTIVE_WRITES.load(Ordering::SeqCst), 1);
        drop(file);
        // Windows does not unlink an open file; a sibling file still proves
        // that the late worker never opens another pathname/descriptor.
        #[cfg(unix)]
        std::fs::remove_file(&path).unwrap();
        let protected = path.with_extension("protected");
        file = File::create_new(&protected).unwrap();
        file.write_all(b"protected database bytes").unwrap();
        release.send(()).unwrap();
        completion.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(
            std::fs::read(&protected).unwrap(),
            b"protected database bytes"
        );
        drop(file);
        std::fs::remove_file(protected).unwrap();
        #[cfg(windows)]
        std::fs::remove_file(path).unwrap();
    }
}
