//! A record of each time a native hook bridge handed a hook to Python.
//!
//! The native bridges answer hooks themselves. When one cannot, it runs the
//! Python bridge instead, and this module appends one short line naming the
//! harness and the reason to `<guard home>/logs/native-fallbacks.log`. The
//! count of those lines is how often the Python path still runs, so it can be
//! driven to zero and removed.
//!
//! Recording is best effort and runs only on the fallback path: a failure to
//! write never changes how the hook is settled. The line holds a timestamp,
//! the harness name and a fixed reason label; the hook's own payload, paths
//! and commands are never written. The file stops growing at a fixed size.

use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

const LOG_DIR: &str = "logs";
const LOG_FILE: &str = "native-fallbacks.log";
/// The log stops growing once it reaches this size.
const MAX_LOG_BYTES: u64 = 64 * 1024;

/// Why a native bridge handed a hook to Python.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Fallback {
    /// The hook input was not a request the bridge could parse.
    InputUnparsed,
    /// The client runs in a mode the native bridge does not serve.
    ClientMode,
    /// No daemon was reachable.
    DaemonUnavailable,
    /// The daemon did not answer.
    DaemonUnanswered,
    /// The daemon reported a process failure.
    DaemonFailed,
    /// The answer could not be rendered for the harness.
    AnswerUnrendered,
    /// The answer needs Python to finish it.
    SemanticHandoff,
    /// The hook input did not match the native contract.
    ContractDrift,
}

impl Fallback {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::InputUnparsed => "input_unparsed",
            Self::ClientMode => "client_mode",
            Self::DaemonUnavailable => "daemon_unavailable",
            Self::DaemonUnanswered => "daemon_unanswered",
            Self::DaemonFailed => "daemon_failed",
            Self::AnswerUnrendered => "answer_unrendered",
            Self::SemanticHandoff => "semantic_handoff",
            Self::ContractDrift => "contract_drift",
        }
    }
}

/// Appends one line for a fallback, ignoring every error.
pub(crate) fn note(guard_home: &Path, harness: &str, reason: Fallback) {
    let _ = append(guard_home, harness, reason);
}

fn append(guard_home: &Path, harness: &str, reason: Fallback) -> std::io::Result<()> {
    let dir = guard_home.join(LOG_DIR);
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(LOG_FILE);
    if std::fs::symlink_metadata(&path).is_ok_and(|meta| meta.len() >= MAX_LOG_BYTES) {
        return Ok(());
    }
    let mut options = std::fs::OpenOptions::new();
    options.append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(path)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_millis());
    file.write_all(format!("{now} {} {}\n", harness_name(harness), reason.label()).as_bytes())
}

/// The harness name when it is a short plain name, else `other`.
fn harness_name(harness: &str) -> &str {
    let plain = !harness.is_empty()
        && harness.len() <= 32
        && harness
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_');
    if plain {
        harness
    } else {
        "other"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn note_appends_one_line_per_fallback() {
        let home = tempfile::tempdir().unwrap();
        note(home.path(), "grok", Fallback::DaemonUnavailable);
        note(home.path(), "bad name\n", Fallback::SemanticHandoff);
        let text = std::fs::read_to_string(home.path().join(LOG_DIR).join(LOG_FILE)).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].ends_with(" grok daemon_unavailable"));
        assert!(lines[1].ends_with(" other semantic_handoff"));
    }

    #[test]
    fn note_stops_at_the_size_cap() {
        let home = tempfile::tempdir().unwrap();
        let dir = home.path().join(LOG_DIR);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(LOG_FILE);
        std::fs::write(&path, vec![b'x'; MAX_LOG_BYTES as usize]).unwrap();
        note(home.path(), "codex", Fallback::InputUnparsed);
        assert_eq!(std::fs::metadata(&path).unwrap().len(), MAX_LOG_BYTES);
    }

    #[test]
    fn note_ignores_an_unwritable_home() {
        let home = tempfile::tempdir().unwrap();
        let file = home.path().join("not-a-dir");
        std::fs::write(&file, b"").unwrap();
        note(&file, "codex", Fallback::InputUnparsed);
    }
}
