use super::*;
use std::sync::Arc;

#[test]
fn unprepared_pack_candidate_keeps_the_previous_authenticated_generation() {
    let root = test_root("command-pack-incomplete");
    let key = install_test_key(&root, 91);
    let store = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    let current = command_floor_tests::control_snapshot(1, 5, 9, "enabled", &key, &root);
    command_authority_tests::publish_marker(&store, &current, "committed");
    store
        .push(&serde_json::json!({"schema":POLICY_SNAPSHOT_PUSH_SCHEMA,"snapshot":current}))
        .unwrap();
    let before = store.state.lock().unwrap().snapshot.clone().unwrap();
    let mut candidate = current.clone();
    candidate.generation = 2;
    candidate
        .command_extensions
        .as_mut()
        .unwrap()
        .program_digest = "f".repeat(64);
    command_floor_tests::resign(&mut candidate, &key);
    let error = store
        .push(&serde_json::json!({"schema":POLICY_SNAPSHOT_PUSH_SCHEMA,"snapshot":candidate}))
        .unwrap_err();
    assert_eq!(error, "native_command_control_authority_not_current");
    assert_eq!(store.current_generation(), Some(1));
    assert!(Arc::ptr_eq(
        &before,
        store.state.lock().unwrap().snapshot.as_ref().unwrap()
    ));
    assert!(store.command_authority_lease(&before).unwrap().is_some());
    drop(before);
    drop(store);
    let restarted = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    assert_eq!(restarted.current_generation(), Some(1));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn pack_marker_authenticates_its_program_and_uses_a_distinct_domain() {
    let root = test_root("command-pack-marker");
    let key = install_test_key(&root, 92);
    let store = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    let snapshot = command_floor_tests::control_snapshot(1, 5, 9, "enabled", &key, &root);
    command_authority_tests::publish_marker(&store, &snapshot, "committed");
    let path = root.join("command-control-authority.v1.json");
    let mut value: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    value["schema"] = "guard.native-command-control-authority.v2".into();
    value["pack_program_digest"] = snapshot
        .command_extensions
        .as_ref()
        .unwrap()
        .program_digest
        .clone()
        .into();
    value.as_object_mut().unwrap().remove("mac");
    let mut bytes = b"hol-guard.native-command-control-authority.v2\0".to_vec();
    bytes.extend(canonical_json_bytes(&value).unwrap());
    value["mac"] = hex::encode(
        ring::hmac::sign(
            &ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &store.verifier_key),
            &bytes,
        )
        .as_ref(),
    )
    .into();
    fixture_file(&path, &canonical_json_bytes(&value).unwrap());
    assert!(store.command_authority_lease(&snapshot).unwrap().is_some());
    value["pack_program_digest"] = "f".repeat(64).into();
    fixture_file(&path, &canonical_json_bytes(&value).unwrap());
    assert!(store.command_authority_lease(&snapshot).is_err());
    fs::remove_dir_all(root).unwrap();
}
