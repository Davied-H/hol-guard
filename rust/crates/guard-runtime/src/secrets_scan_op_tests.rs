//! Vectors recorded from the Python `guard/secrets` scanner and pre-commit
//! hook code this op replaced, by `scripts/record_secrets_vectors.py`
//! (gzipped). Each scenario rebuilds its repository under the pinned Git
//! identity and clock the recorder used, so commit ids match as well.

use super::*;
use guard_contracts::SecretsScanBoundsV1;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

const GIT_ENV: [(&str, &str); 8] = [
    ("GIT_AUTHOR_NAME", "Guard Test"),
    ("GIT_AUTHOR_EMAIL", "guard@example.invalid"),
    ("GIT_AUTHOR_DATE", "2026-01-02T03:04:05+00:00"),
    ("GIT_COMMITTER_NAME", "Guard Test"),
    ("GIT_COMMITTER_EMAIL", "guard@example.invalid"),
    ("GIT_COMMITTER_DATE", "2026-01-02T03:04:05+00:00"),
    ("GIT_CONFIG_GLOBAL", "/dev/null"),
    ("GIT_CONFIG_NOSYSTEM", "1"),
];

fn scratch(label: &str) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!(
        "guard-secrets-op-{label}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&path).unwrap();
    path.canonicalize().unwrap()
}

fn request(
    action: &str,
    target: &Path,
    bounds: Option<SecretsScanBoundsV1>,
) -> SecretsScanRequestV1 {
    SecretsScanRequestV1 {
        schema: SECRETS_SCAN_REQUEST_SCHEMA.to_owned(),
        request_id: "t-1".to_owned(),
        guard_home: "/tmp/guard-home".to_owned(),
        action: action.to_owned(),
        target: target.to_string_lossy().into_owned(),
        bounds,
    }
}

fn evaluate(request: &SecretsScanRequestV1) -> SecretsScanResultV1 {
    serde_json::from_slice(&evaluate_secrets_scan(request).unwrap()).unwrap()
}

fn run_steps(root: &Path, steps: &[Value]) {
    for step in steps {
        let step = step.as_array().unwrap();
        let text = |index: usize| step[index].as_str().unwrap();
        match text(0) {
            "write" => {
                let path = root.join(text(1));
                fs::create_dir_all(path.parent().unwrap()).unwrap();
                fs::write(path, text(2)).unwrap();
            }
            "rm" => {
                let path = root.join(text(1));
                let meta = fs::symlink_metadata(&path).unwrap();
                if meta.is_dir() {
                    fs::remove_dir_all(path).unwrap();
                } else {
                    fs::remove_file(path).unwrap();
                }
            }
            "mkdir" => fs::create_dir_all(root.join(text(1))).unwrap(),
            "chmod" => {
                use std::os::unix::fs::PermissionsExt;
                let mode = u32::try_from(step[2].as_u64().unwrap()).unwrap();
                fs::set_permissions(root.join(text(1)), fs::Permissions::from_mode(mode)).unwrap();
            }
            "symlink" => std::os::unix::fs::symlink(text(2), root.join(text(1))).unwrap(),
            "git" => {
                let mut command = Command::new("git");
                command
                    .arg("-C")
                    .arg(root)
                    .args(["-c", "commit.gpgsign=false"])
                    .envs(GIT_ENV);
                for index in 1..step.len() {
                    command.arg(text(index));
                }
                let output = command.output().unwrap();
                assert!(output.status.success(), "git {step:?}: {output:?}");
            }
            other => panic!("unknown step {other}"),
        }
    }
}

fn file_state(root: &Path) -> Value {
    let mut state = serde_json::Map::new();
    for relative in [
        ".git/hooks/pre-commit",
        ".git/hooks/pre-commit.hol-guard-user",
    ] {
        let path = root.join(relative);
        let value = match fs::read_to_string(&path) {
            Ok(content) if path.is_file() => {
                use std::os::unix::fs::PermissionsExt;
                let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
                json!({ "content": content, "mode": mode })
            }
            _ => Value::Null,
        };
        state.insert(relative.to_owned(), value);
    }
    Value::Object(state)
}

fn bounds(value: &Value) -> Option<SecretsScanBoundsV1> {
    (!value.is_null()).then(|| serde_json::from_value(value.clone()).unwrap())
}

#[cfg(unix)]
#[test]
fn parity_vectors_match_the_recorded_python_outputs() {
    // Recorded under isolated Git config (the hook refusal reads
    // `core.hooksPath`); the scan and hook code spawn Git with this process's
    // environment.
    for (key, value) in GIT_ENV {
        std::env::set_var(key, value);
    }
    let fixture = crate::store_vectors_support_tests::gunzip_json(include_bytes!(
        "../tests/fixtures/secrets_scan_vectors.json.gz"
    ));
    let vectors = fixture.as_array().unwrap();
    assert!(vectors.len() > 60);
    let mut mismatches = Vec::new();
    let mut compared = 0;
    for vector in vectors {
        let root = scratch("vector");
        run_steps(&root, vector["steps"].as_array().unwrap());
        for call in vector["calls"].as_array().unwrap() {
            let wire = request(
                call["action"].as_str().unwrap(),
                &root.join(call["target"].as_str().unwrap()),
                bounds(call.get("bounds").unwrap_or(&Value::Null)),
            );
            let wire = if call["action"] == "rules" {
                SecretsScanRequestV1 {
                    target: String::new(),
                    ..wire
                }
            } else {
                wire
            };
            let result = evaluate(&wire);
            let got = match (result.code.as_str(), result.payload, result.message) {
                ("ok", Some(payload), None) => json!({ "expected": payload }),
                (REFUSED, None, Some(message)) => json!({ "refused": message }),
                other => panic!("{}: unexpected result {other:?}", vector["name"]),
            };
            let want = if call.get("expected").is_some() {
                json!({ "expected": call["expected"] })
            } else {
                json!({ "refused": call["refused"] })
            };
            compared += 1;
            if got != want || file_state(&root) != call["files_after"] {
                mismatches.push(format!(
                    "{} {}\n  want {want}\n  got  {got}\n  files {} vs {}",
                    vector["name"],
                    call["action"],
                    call["files_after"],
                    file_state(&root)
                ));
            }
        }
        fs::remove_dir_all(&root).unwrap();
    }
    assert!(
        mismatches.is_empty(),
        "{} mismatches:\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
    assert_eq!(compared, 99);
}

#[test]
fn rules_match_the_recorded_public_catalog() {
    let result = evaluate(&request("rules", Path::new(""), None));
    assert_eq!((result.status.as_str(), result.code.as_str()), ("ok", "ok"));
    let payload = result.payload.unwrap();
    let text = payload["text"].as_str().unwrap();
    assert!(text.starts_with("HOL Guard Secrets detector guard-secrets-v1:"));
    assert!(text.contains("- GitHub token (critical, validates via github)\n"));
    assert!(text.contains("- PEM private key (critical)\n"));
    assert!(text.ends_with("\n\n"));
    let rules: Value = serde_json::from_str(payload["json"].as_str().unwrap()).unwrap();
    assert_eq!(rules["schema"], "guard-secret-rules.v1");
    assert_eq!(rules["detector_version"], detector_version());
    assert_eq!(rules["rules"].as_array().unwrap().len(), 18);
    assert!(payload["json"].as_str().unwrap().ends_with("}\n"));
}

#[test]
fn result_binds_to_the_request_digest() {
    let wire = request("rules", Path::new(""), None);
    let result = evaluate(&wire);
    assert_eq!(result.request_id, "t-1");
    assert_eq!(result.request_sha256, request_digest(&wire).unwrap());
}

#[test]
fn unknown_and_missing_fields_are_rejected() {
    let mut wire = serde_json::to_value(request("rules", Path::new(""), None)).unwrap();
    wire["extra"] = json!(1);
    assert!(serde_json::from_value::<SecretsScanRequestV1>(wire.clone()).is_err());
    wire.as_object_mut().unwrap().remove("extra");
    wire.as_object_mut().unwrap().remove("bounds");
    assert!(serde_json::from_value::<SecretsScanRequestV1>(wire).is_err());
}

#[test]
fn malformed_requests_fail_with_typed_errors() {
    let some_bounds = || {
        Some(SecretsScanBoundsV1 {
            include_history: false,
            max_commits: 1,
            max_files: 1,
            max_file_bytes: 1,
            max_total_bytes: 1,
            max_findings: 1,
        })
    };
    let mut wrong_schema = request("rules", Path::new(""), None);
    wrong_schema.schema = "other".to_owned();
    assert_eq!(evaluate(&wrong_schema).code, ERR_SCHEMA);

    let mut no_home = request("rules", Path::new(""), None);
    no_home.guard_home = String::new();
    assert_eq!(evaluate(&no_home).code, ERR_INVALID);

    assert_eq!(
        evaluate(&request("unknown", Path::new(""), None)).code,
        ERR_INVALID
    );
    // A scan needs bounds and an absolute target; hooks and rules take no bounds.
    assert_eq!(
        evaluate(&request("scan", Path::new("/tmp"), None)).code,
        ERR_INVALID
    );
    assert_eq!(
        evaluate(&request("scan", Path::new("relative"), some_bounds())).code,
        ERR_INVALID
    );
    assert_eq!(
        evaluate(&request("install_hook", Path::new("/tmp"), some_bounds())).code,
        ERR_INVALID
    );
    assert_eq!(
        evaluate(&request("rules", Path::new("/tmp"), None)).code,
        ERR_INVALID
    );
    let mut staged_history = some_bounds();
    staged_history.as_mut().unwrap().include_history = true;
    assert_eq!(
        evaluate(&request("staged", Path::new("/tmp"), staged_history)).code,
        ERR_INVALID
    );
}

#[test]
fn oversized_requests_fail_with_a_typed_error() {
    let wire = request(
        "rules",
        Path::new(&"x".repeat(SECRETS_SCAN_MAX_BYTES)),
        None,
    );
    let result = evaluate(&wire);
    assert_eq!(result.code, ERR_TOO_LARGE);
    assert_eq!(result.request_sha256, "");
}
