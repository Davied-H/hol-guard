use super::*;
use guard_contracts::{
    GuardExecutionEnvironmentV1, NativeExactActionPayloadV1, NativeExactActionQueryV1,
    NativeExactActionRequestV1, NativeExactActionResultV1, NATIVE_EXACT_ACTION_REQUEST_SCHEMA,
};

const SCRIPT: &str = include_str!("../../../../../tests/fixtures/script_approvals/maintenance.sh");
const HELPER: &str =
    include_str!("../../../../../tests/fixtures/script_approvals/fixture-registry");

fn fixture() -> (tempfile::TempDir, NativeBashCaptureV1) {
    let root = tempfile::tempdir().unwrap();
    let project = root.path().canonicalize().unwrap();
    let home = project.join("home");
    let guard_home = project.join("guard");
    std::fs::create_dir(&home).unwrap();
    std::fs::create_dir(&guard_home).unwrap();
    let entry = project.join("maintenance.sh");
    let helper = project.join("fixture-registry");
    std::fs::write(&entry, SCRIPT).unwrap();
    std::fs::write(&helper, HELPER).unwrap();
    std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o755)).unwrap();
    let request = NativeBashCaptureV1 {
        harness: "omp".into(),
        command: format!("/bin/bash '{}' dry", entry.display()),
        cwd: text(&project).unwrap(),
        workspace: text(&project).unwrap(),
        home_dir: text(&home).unwrap(),
        guard_home: text(&guard_home).unwrap(),
        execution_environment: GuardExecutionEnvironmentV1 {
            path: format!("{}:/usr/bin:/bin", project.display()),
            environment_names: vec!["HOME".into(), "PATH".into()],
            environment_digest: "a".repeat(64),
            home: Some(text(&home).unwrap()),
            ..GuardExecutionEnvironmentV1::unavailable()
        },
        environment: BTreeMap::new(),
        file_creation_mask: Some(0o022),
        budget_ms: 1000,
    };
    (root, request)
}

#[test]
fn bash_resident_inspection_preserves_helper_execution_spelling() {
    let (_root, request) = fixture();
    let cwd = Path::new(&request.cwd);
    let home = Path::new(&request.home_dir);
    let mut environment = environment(&request).unwrap();
    environment.insert("PATH".into(), ".:/usr/bin:/bin".into());
    let resolver = Resolver {
        cwd,
        home,
        environment: &environment,
        names: &[],
        deadline: Instant::now() + Duration::from_secs(1),
        captured: RefCell::new(BTreeMap::new()),
        source_snapshots: RefCell::new(BTreeMap::new()),
    };
    let graph::Executable::Bash(helper) = graph::Resolver::resolve(
        &resolver,
        &["./fixture-registry".into(), "list".into(), "alpha".into()],
    )
    .unwrap() else {
        panic!("expected captured Bash source");
    };
    assert_eq!(helper.original_path, "./fixture-registry");
    assert_eq!(
        helper.resolved_path,
        text(&cwd.join("fixture-registry")).unwrap()
    );
    let graph::Executable::Bash(helper) = graph::Resolver::resolve(
        &resolver,
        &["fixture-registry".into(), "list".into(), "alpha".into()],
    )
    .unwrap() else {
        panic!("expected captured Bash source");
    };
    assert_eq!(helper.original_path, "./fixture-registry");
}

#[test]
fn bash_resident_inspection_captures_nonexecutable_source_and_reevaluates_changes() {
    let (_root, request) = fixture();
    let project = Path::new(&request.cwd);
    std::fs::write(
        project.join("maintenance.sh"),
        "source ./settings.sh; printf '%s' \"$from_source\"",
    )
    .unwrap();
    let settings = project.join("settings.sh");
    std::fs::write(&settings, "from_source=reviewed").unwrap();
    std::fs::set_permissions(&settings, std::fs::Permissions::from_mode(0o600)).unwrap();
    let original = inspect(&request).unwrap();
    assert!(original
        .code_inputs
        .iter()
        .any(|input| input.kind == NativeScriptInputKindV1::Source));
    assert!(original
        .invocations
        .iter()
        .any(|call| call.argv == ["printf", "%s", "reviewed"]));
    std::fs::write(&settings, "from_source=changed").unwrap();
    let changed = inspect(&request).unwrap();
    assert_ne!(
        original.identity_sha256().unwrap(),
        changed.identity_sha256().unwrap()
    );
    assert!(changed
        .invocations
        .iter()
        .any(|call| call.argv == ["printf", "%s", "changed"]));
}

#[test]
fn bash_resident_inspection_captures_real_fixture_without_permission_token() {
    let (_root, mut capture) = fixture();
    let request = NativeExactActionRequestV1 {
        schema: NATIVE_EXACT_ACTION_REQUEST_SCHEMA.into(),
        request_id: "capture-fixture".into(),
        query: NativeExactActionQueryV1::BashSubject {
            capture: Box::new(capture.clone()),
        },
    };
    let bytes =
        crate::native_exact_action_op::evaluate_native_exact_action_request(&request).unwrap();
    let result: NativeExactActionResultV1 = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(result.status, "ok");
    let NativeExactActionPayloadV1::BashSubject {
        subject,
        unavailable_reason,
    } = result.payload.unwrap()
    else {
        panic!("inspection returned another operation's authority");
    };
    assert!(unavailable_reason.is_none(), "{unavailable_reason:?}");
    let subject = subject.unwrap();
    assert_eq!(subject.code_inputs.len(), 5);
    assert_eq!(subject.outputs.len(), 5);
    assert_eq!(subject.argv[1], "dry");
    assert!(!Path::new(&subject.outputs[0].resolved_path).exists());
    assert!(subject.identity_sha256().is_ok());
    // A changed opaque commitment to unrelated host values is not code drift.
    capture.execution_environment.environment_digest = "b".repeat(64);
    assert_eq!(
        subject.identity_sha256().unwrap(),
        inspect(&capture).unwrap().identity_sha256().unwrap()
    );
}

#[test]
fn bash_resident_inspection_never_treats_withheld_exports_as_unset() {
    let (_root, mut request) = fixture();
    let entry = Path::new(&request.cwd).join("maintenance.sh");
    for source in [
        "printf '%s' \"${mode:-dry}\"",
        "mode=dry; printf '%s' \"$mode\"",
        "for mode in dry; do printf '%s' \"$mode\"; done",
        ". ./settings.sh",
    ] {
        std::fs::write(&entry, source).unwrap();
        std::fs::write(
            Path::new(&request.cwd).join("settings.sh"),
            "printf '%s' \"${mode:-dry}\"",
        )
        .unwrap();
        let absent = inspect(&request).unwrap();
        request
            .execution_environment
            .environment_names
            .push("unrelated_export".into());
        assert_eq!(
            absent.identity_sha256().unwrap(),
            inspect(&request).unwrap().identity_sha256().unwrap()
        );
        request.execution_environment.environment_names.pop();
        request
            .execution_environment
            .environment_names
            .push("mode".into());
        assert!(
            matches!(
                inspect(&request),
                Err("bash_exported_environment_value_withheld"
                    | "bash_exported_environment_assignment_unproven")
            ),
            "accepted {source}"
        );
        request.execution_environment.environment_names.pop();
    }
}

#[test]
fn bash_resident_inspection_refuses_withheld_startup_and_function_values() {
    let (_root, mut request) = fixture();
    request
        .execution_environment
        .environment_names
        .push("BASH_ENV".into());
    assert_eq!(inspect(&request), Err("bash_startup_environment_unproven"));
    request.execution_environment.environment_names.pop();
    request.file_creation_mask = None;
    assert_eq!(
        inspect(&request),
        Err("native_bash_subject_creation_mask_unavailable")
    );
    request.file_creation_mask = Some(0o022);
    request
        .execution_environment
        .environment_names
        .push("LANG".into());
    assert_eq!(
        inspect(&request),
        Err("bash_host_environment_value_withheld")
    );
    request.execution_environment.environment_names.pop();
    request
        .execution_environment
        .environment_names
        .push("bash".into());
    // The invocation uses an absolute interpreter name, so this unrelated
    // variable cannot shadow it. A bare interpreter could be a Bash 3 function.
    request.command = request.command.replacen("/bin/bash", "bash", 1);
    assert_eq!(
        inspect(&request),
        Err("bash_command_environment_value_withheld")
    );
}

#[test]
fn bash_resident_inspection_rejects_sensitive_and_hardlinked_sources() {
    let (root, mut request) = fixture();
    let home = Path::new(&request.home_dir);
    std::fs::create_dir(home.join(".ssh")).unwrap();
    let sensitive = home.join(".ssh/id_rsa");
    std::fs::write(&sensitive, "printf synthetic").unwrap();
    request.command = format!("/bin/bash '{}'", sensitive.display());
    assert_eq!(inspect(&request), Err("bash_sensitive_code_path"));
    let alias = root.path().join("source-alias.sh");
    std::fs::hard_link(&sensitive, &alias).unwrap();
    request.command = format!("/bin/bash '{}'", alias.display());
    assert_eq!(inspect(&request), Err("bash_code_unreadable_or_oversized"));
}
