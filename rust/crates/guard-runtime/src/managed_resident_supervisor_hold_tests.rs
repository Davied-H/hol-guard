use super::*;
use std::fs;
use std::sync::mpsc;
use std::thread;
use std::time::SystemTime;

/// A private scope with a private parent, which is what the hold's lock file
/// is opened against.
fn test_scope(label: &str) -> (PathBuf, PathBuf) {
    let root = std::env::temp_dir().join(format!(
        "hol-guard-supervisor-hold-{label}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    crate::resident_state::ensure_private_directory(&root, true)
        .expect("test root should be created");
    let scope = root.join("resident-v3-test");
    crate::resident_state::ensure_private_directory(&scope, true)
        .expect("test scope should be created");
    (root, scope)
}

#[test]
fn a_scope_no_supervisor_holds_is_already_quiesced() {
    let (root, scope) = test_scope("free");

    wait_for_supervisor_quiesce(&scope).expect("an unheld scope should be quiesced at once");

    fs::remove_dir_all(root).expect("test directory should be removable");
}

#[test]
fn a_stop_waits_for_the_supervisor_to_release_its_hold() {
    let (root, scope) = test_scope("waits");
    let hold = hold_scope(&scope).expect("a private scope should be holdable");
    let (released, release_seen) = mpsc::channel();
    let releaser = thread::spawn(move || {
        thread::sleep(Duration::from_millis(100));
        released.send(()).expect("the test should still be waiting");
        drop(hold);
    });

    wait_for_supervisor_quiesce(&scope).expect("a released hold should let the stop through");

    release_seen
        .try_recv()
        .expect("the stop must not return before the hold is released");
    releaser.join().expect("the releasing thread should finish");
    fs::remove_dir_all(root).expect("test directory should be removable");
}

#[test]
fn a_stop_reports_a_supervisor_that_never_finishes() {
    let (root, scope) = test_scope("pending");
    let hold = hold_scope(&scope).expect("a private scope should be holdable");

    assert_eq!(
        wait_for_supervisor_quiesce(&scope),
        Err("native_resident_supervisor_exit_pending".to_owned())
    );

    drop(hold);
    fs::remove_dir_all(root).expect("test directory should be removable");
}

/// Two supervisors can share a scope, and the stop waits for the last one.
#[test]
fn the_hold_is_shared_between_supervisors() {
    let (root, scope) = test_scope("shared");
    let first = hold_scope(&scope).expect("the first supervisor should hold the scope");
    let second = hold_scope(&scope).expect("a second supervisor should hold the same scope");

    drop(first);
    assert_eq!(
        wait_for_supervisor_quiesce(&scope),
        Err("native_resident_supervisor_exit_pending".to_owned())
    );
    drop(second);
    wait_for_supervisor_quiesce(&scope).expect("the last hold released should quiesce the scope");

    fs::remove_dir_all(root).expect("test directory should be removable");
}
