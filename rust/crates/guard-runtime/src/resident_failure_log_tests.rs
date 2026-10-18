use super::*;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_scope(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is after the Unix epoch")
        .as_nanos();
    let scope = std::env::temp_dir().join(format!(
        "hol-guard-resident-failure-{label}-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir(&scope).expect("create failure-log test scope");
    scope
}

#[test]
fn a_run_without_evidence_creates_no_record() {
    let scope = temp_scope("quiet");
    let mut log = ResidentFailureLog::for_scope(&scope);
    log.append(b"");
    drop(log);

    assert!(!ResidentFailureLog::path(&scope).exists());

    fs::remove_dir_all(scope).expect("remove failure-log test scope");
}

#[test]
fn supervisor_notes_land_in_the_scope_record() {
    let scope = temp_scope("note");
    let mut log = ResidentFailureLog::for_scope(&scope);
    log.note("native_resident_managed_exit_failed exit_code=101 ran_for_ms=42");
    drop(log);

    let recorded = fs::read_to_string(ResidentFailureLog::path(&scope)).expect("read record");
    assert_eq!(
        recorded,
        "native_resident_managed_exit_failed exit_code=101 ran_for_ms=42\n"
    );

    fs::remove_dir_all(scope).expect("remove failure-log test scope");
}

#[test]
fn a_later_run_replaces_the_previous_record() {
    let scope = temp_scope("replace");
    let mut first = ResidentFailureLog::for_scope(&scope);
    first.note("native_resident_first_failure");
    drop(first);
    let mut second = ResidentFailureLog::for_scope(&scope);
    second.note("native_resident_second_failure");
    drop(second);

    let recorded = fs::read_to_string(ResidentFailureLog::path(&scope)).expect("read record");
    assert_eq!(recorded, "native_resident_second_failure\n");

    fs::remove_dir_all(scope).expect("remove failure-log test scope");
}

#[test]
fn a_flooding_resident_cannot_grow_the_record_past_its_bound() {
    let scope = temp_scope("bounded");
    let mut log = ResidentFailureLog::for_scope(&scope);
    for _ in 0..64 {
        log.append(&[b'x'; 4096]);
    }
    log.append(b"dropped");
    drop(log);

    let recorded = fs::read(ResidentFailureLog::path(&scope)).expect("read record");
    assert_eq!(recorded.len() as u64, MAX_RESIDENT_FAILURE_BYTES);
    assert!(recorded.iter().all(|byte| *byte == b'x'));

    fs::remove_dir_all(scope).expect("remove failure-log test scope");
}

#[cfg(unix)]
#[test]
fn the_record_is_private_to_its_owner() {
    use std::os::unix::fs::PermissionsExt;

    let scope = temp_scope("private");
    let mut log = ResidentFailureLog::for_scope(&scope);
    log.note("native_resident_managed_exit_failed exit_code=1 ran_for_ms=1");
    drop(log);

    let metadata = fs::symlink_metadata(ResidentFailureLog::path(&scope)).expect("stat record");
    assert!(metadata.is_file());
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);

    fs::remove_dir_all(scope).expect("remove failure-log test scope");
}

#[cfg(not(windows))]
#[test]
fn resident_stderr_is_drained_into_the_record() {
    let scope = temp_scope("drain");
    let mut log = ResidentFailureLog::for_scope(&scope);
    log.drain(&b"thread 'main' panicked at resident.rs:1:1:\nnative_resident_startup_failed\n"[..]);
    log.note("native_resident_managed_exit_failed exit_code=101 ran_for_ms=12");
    drop(log);

    let recorded = fs::read_to_string(ResidentFailureLog::path(&scope)).expect("read record");
    assert_eq!(
        recorded,
        concat!(
            "thread 'main' panicked at resident.rs:1:1:\n",
            "native_resident_startup_failed\n",
            "native_resident_managed_exit_failed exit_code=101 ran_for_ms=12\n",
        )
    );

    fs::remove_dir_all(scope).expect("remove failure-log test scope");
}
