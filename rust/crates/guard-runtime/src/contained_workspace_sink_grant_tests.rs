//! The sink asks the store for the grant itself and refuses one that moved.

use super::*;
use crate::local_cli_hook_op::tests::Fixture;

fn sandboxed(fixture: &Fixture) -> LocalCliHookRequestV1 {
    let mut request = fixture.request("npm run build", "sandbox-required", true);
    request.current_reason_code = Some(WORKSPACE_REASON.to_owned());
    request
}

fn message(outcome: Outcome<impl std::fmt::Debug>) -> String {
    outcome.expect_err("refused").message
}

#[test]
fn an_allowed_grant_is_decided_and_an_unset_one_runs_the_base_sandbox() {
    let fixture = Fixture::new("sink-grant-allowed");
    let request = sandboxed(&fixture);
    assert_eq!(decided(&request).unwrap(), None);
    let identity = fixture.identity();
    fixture.grant(&identity.cli_id, &identity.identity_hash, "allowed");
    let grant = decided(&request).unwrap().expect("the store's grant");
    assert_eq!(grant["identity_hash"], identity.identity_hash.as_str());
    let input = prepare_input(&grant);
    let mut keys: Vec<&str> = input
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(keys, ["capabilities", "identity_hash", "name"]);
    let expected = expected(&grant, "/").unwrap();
    assert_eq!(expected.identity_hash, identity.identity_hash);
    assert_eq!(expected.state_dir, None, "no state capability");
    assert_eq!(unchanged(&Some(grant), decided(&request)), Ok(()));
}

#[test]
fn a_blocked_cli_stops_the_run() {
    let fixture = Fixture::new("sink-grant-blocked");
    let identity = fixture.identity();
    fixture.grant(&identity.cli_id, &identity.identity_hash, "blocked");
    assert_eq!(message(decided(&sandboxed(&fixture))), GRANT_BLOCKED);
}

#[test]
fn a_tampered_or_revoked_grant_is_refused_before_launch() {
    let fixture = Fixture::new("sink-grant-tampered");
    let request = sandboxed(&fixture);
    let identity = fixture.identity();
    fixture.grant(&identity.cli_id, &identity.identity_hash, "allowed");
    let first = decided(&request).unwrap();
    // The grant the plan was prepared with differs from the store's now.
    for (field, value) in [
        ("identity_hash", json!("f".repeat(64))),
        ("capabilities", json!(["loopback-network"])),
        ("name", json!("lanectl")),
    ] {
        let mut tampered = first.clone().unwrap();
        tampered[field] = value;
        assert_eq!(
            message(unchanged(&Some(tampered), decided(&request))),
            GRANT_CHANGED,
            "{field}"
        );
    }
    // The state moved off `allowed` between plan and launch.
    fixture
        .connection
        .execute("update local_cli_grant set state = 'blocked'", [])
        .unwrap();
    assert_eq!(message(unchanged(&first, decided(&request))), GRANT_CHANGED);
    fixture
        .connection
        .execute("delete from local_cli_grant", [])
        .unwrap();
    assert_eq!(message(unchanged(&first, decided(&request))), GRANT_CHANGED);
    // A grant that appears only after planning is refused as well.
    fixture.grant(&identity.cli_id, &identity.identity_hash, "allowed");
    assert_eq!(message(unchanged(&None, decided(&request))), GRANT_CHANGED);
}

#[test]
fn the_expected_state_directory_follows_the_canonical_home() {
    let home = tempfile::tempdir().unwrap();
    let canonical = std::fs::canonicalize(home.path()).unwrap();
    let grant = json!({
        "identity_hash": "a".repeat(64),
        "name": "lanectl",
        "capabilities": ["loopback-network", "state-dir-read"],
    });
    let expected = expected(&grant, home.path().to_str().unwrap()).unwrap();
    assert_eq!(
        expected.state_dir.as_deref(),
        canonical.join(".lanectl").to_str()
    );
    let mut unsorted = grant;
    unsorted["capabilities"] = json!(["state-dir-read", "loopback-network"]);
    assert_eq!(
        message(super::expected(&unsorted, "/")),
        INVALID_PLAN.to_owned()
    );
}
